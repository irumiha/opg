package pgconn

// ----------------------------------------------------------------------------
// Socket deadline tests.
//
// Conn_Config advertises read_timeout and write_timeout, so a transport that
// merely records them leaves a documented setting doing nothing. These use a
// loopback listener that accepts and then stays silent: the only thing that can
// end the read is the deadline actually reaching the socket.
// ----------------------------------------------------------------------------

import "core:net"
import "core:testing"
import "core:thread"
import "core:time"
import "../pgerr"

// A peer that completes the TCP connection, consumes the client's first write,
// optionally answers the SSLRequest, and then goes quiet before closing.
//
// The eventual close is what makes a driver that ignores its deadline *fail*
// these tests rather than hang the suite: without a deadline the connect
// unblocks when the peer disappears, late and with the wrong error, which is
// something a test can assert on.
Stalled_Peer :: struct {
	listener:   net.TCP_Socket,
	accept_ssl: bool,
	hold:       time.Duration,
}

// Long enough that a connect which ignores its deadline blows the elapsed
// bound, short enough not to drag the offline suite.
STALLED_PEER_HOLD :: 1200 * time.Millisecond
STALLED_PEER_TIMEOUT :: 200 * time.Millisecond
STALLED_PEER_MAX_ELAPSED :: 800 * time.Millisecond

stalled_peer_proc :: proc(th: ^thread.Thread) {
	peer := (^Stalled_Peer)(th.data)

	client, _, aerr := net.accept_tcp(peer.listener)
	if aerr != nil do return
	defer net.close(client)

	// Whatever the client opens with: an SSLRequest, or a StartupMessage on a
	// host with no TLS backend.
	req: [64]byte
	_, _ = net.recv_tcp(client, req[:])

	if peer.accept_ssl {
		_, _ = net.send_tcp(client, []byte{'S'})
	}

	time.sleep(peer.hold)
}

@(test)
test_tcp_transport_applies_read_deadline :: proc(t: ^testing.T) {
	listener, lerr := net.listen_tcp(net.Endpoint{address = net.IP4_Loopback, port = 0})
	if lerr != nil {
		testing.fail_now(t, "could not open a loopback listener")
	}
	defer net.close(listener)

	endpoint, eerr := net.bound_endpoint(listener)
	if eerr != nil {
		testing.fail_now(t, "could not read the listener endpoint")
	}

	client, cerr := net.dial_tcp(endpoint)
	if cerr != nil {
		testing.fail_now(t, "could not dial the loopback listener")
	}

	data: TCP_Transport_Data
	transport := make_tcp_transport(&data, client)
	defer transport.close(transport.data)

	derr := transport.set_deadlines(transport.data, 50 * time.Millisecond, 50 * time.Millisecond)
	testing.expect_value(t, derr, nil)

	buf: [16]byte
	start := time.now()
	_, rerr := transport.read(transport.data, buf[:])
	elapsed := time.since(start)

	nerr, is_net := rerr.(pgerr.Net_Error)
	testing.expect(t, is_net, "expected a Net_Error from a read that outlives its deadline")
	testing.expect_value(t, nerr.type, pgerr.Net_Error_Type.Timeout)
	testing.expectf(
		t,
		elapsed < 2 * time.Second,
		"read returned after %v; the 50ms deadline was not applied to the socket",
		elapsed,
	)
}

@(test)
test_tcp_transport_clears_read_deadline :: proc(t: ^testing.T) {
	// A deadline must be removable, not just settable: pool connections are
	// reused, and a short timeout left behind on the socket would fire on the
	// next borrower. Skipping the setsockopt for a zero duration would leave
	// the previous deadline installed while the transport reported none.
	listener, lerr := net.listen_tcp(net.Endpoint{address = net.IP4_Loopback, port = 0})
	if lerr != nil {
		testing.fail_now(t, "could not open a loopback listener")
	}
	defer net.close(listener)

	endpoint, eerr := net.bound_endpoint(listener)
	if eerr != nil {
		testing.fail_now(t, "could not read the listener endpoint")
	}

	client, cerr := net.dial_tcp(endpoint)
	if cerr != nil {
		testing.fail_now(t, "could not dial the loopback listener")
	}

	server, _, aerr := net.accept_tcp(listener)
	if aerr != nil {
		testing.fail_now(t, "could not accept the loopback connection")
	}
	defer net.close(server)

	data: TCP_Transport_Data
	transport := make_tcp_transport(&data, client)
	defer transport.close(transport.data)

	// Set a deadline, confirm it bites, then clear it.
	testing.expect_value(t, transport.set_deadlines(transport.data, 50 * time.Millisecond, 0), nil)
	buf: [16]byte
	_, timed_out := transport.read(transport.data, buf[:])
	nerr, is_net := timed_out.(pgerr.Net_Error)
	testing.expect(t, is_net && nerr.type == .Timeout, "expected the deadline to fire before it was cleared")

	testing.expect_value(t, transport.set_deadlines(transport.data, 0, 0), nil)

	// With no deadline the read must wait for data rather than expiring.
	payload := []byte{'o', 'p', 'g'}
	_, serr := net.send_tcp(server, payload)
	testing.expect_value(t, serr, nil)

	n, rerr := transport.read(transport.data, buf[:])
	testing.expect_value(t, rerr, nil)
	testing.expect_value(t, n, 3)
	testing.expect_value(t, string(buf[:n]), "opg")
}

// ----------------------------------------------------------------------------
// Connect-path deadlines.
//
// conn_connect does two things before the transport is final: the SSLRequest
// exchange, and the TLS handshake. Both read from the socket. Applying the
// configured deadlines only once the transport exists leaves both of them
// blocking forever on a peer that accepts the connection and then goes quiet —
// read_timeout is documented on Conn_Config, so connect has to honour it too,
// not just the queries that follow.
//
// This is what turned the Windows Schannel failure into a 20-minute CI hang
// rather than a fast error, and it is a gap on every platform.
// ----------------------------------------------------------------------------

@(test)
test_connect_bounds_ssl_negotiation_with_read_timeout :: proc(t: ^testing.T) {
	listener, lerr := net.listen_tcp(net.Endpoint{address = net.IP4_Loopback, port = 0})
	if lerr != nil {
		testing.fail_now(t, "could not open a loopback listener")
	}
	defer net.close(listener)

	endpoint, eerr := net.bound_endpoint(listener)
	if eerr != nil {
		testing.fail_now(t, "could not read the listener endpoint")
	}

	// Never answers the SSLRequest, so the connect blocks reading the one-byte
	// reply. Holds regardless of whether a TLS backend is present: without one
	// the client sends a StartupMessage instead and blocks on its reply.
	peer := Stalled_Peer{listener = listener, accept_ssl = false, hold = STALLED_PEER_HOLD}
	th := thread.create(stalled_peer_proc)
	th.data = rawptr(&peer)
	thread.start(th)
	defer {
		thread.join(th)
		thread.destroy(th)
	}

	cfg := Conn_Config {
		host          = "127.0.0.1",
		port          = endpoint.port,
		user          = "opg",
		database      = "opg",
		read_timeout  = STALLED_PEER_TIMEOUT,
		write_timeout = STALLED_PEER_TIMEOUT,
	}

	start := time.now()
	conn, err := conn_connect(cfg, context.allocator)
	elapsed := time.since(start)

	if conn != nil {
		conn_close(conn)
		free(conn, context.allocator)
	}

	nerr, is_net := err.(pgerr.Net_Error)
	testing.expectf(t, is_net, "expected a Net_Error from a stalled connect, got %v", err)
	testing.expect_value(t, nerr.type, pgerr.Net_Error_Type.Timeout)
	testing.expectf(
		t,
		elapsed < STALLED_PEER_MAX_ELAPSED,
		"connect returned after %v; the %v read deadline never reached the socket",
		elapsed,
		STALLED_PEER_TIMEOUT,
	)
}

@(test)
test_connect_bounds_tls_handshake_with_read_timeout :: proc(t: ^testing.T) {
	// Needs a TLS backend to reach the handshake at all. Every platform the
	// suite runs on has one, asserted by
	// test_integration_tls_active_backend_matches_platform; this guard only
	// keeps the test honest on a host that has none.
	if !tls_ensure_loaded() {
		return
	}

	listener, lerr := net.listen_tcp(net.Endpoint{address = net.IP4_Loopback, port = 0})
	if lerr != nil {
		testing.fail_now(t, "could not open a loopback listener")
	}
	defer net.close(listener)

	endpoint, eerr := net.bound_endpoint(listener)
	if eerr != nil {
		testing.fail_now(t, "could not read the listener endpoint")
	}

	// Answers 'S' and then says nothing further, so the connect gets all the
	// way into the TLS handshake before stalling.
	peer := Stalled_Peer{listener = listener, accept_ssl = true, hold = STALLED_PEER_HOLD}
	th := thread.create(stalled_peer_proc)
	th.data = rawptr(&peer)
	thread.start(th)
	defer {
		thread.join(th)
		thread.destroy(th)
	}

	cfg := Conn_Config {
		host          = "127.0.0.1",
		port          = endpoint.port,
		user          = "opg",
		database      = "opg",
		read_timeout  = STALLED_PEER_TIMEOUT,
		write_timeout = STALLED_PEER_TIMEOUT,
		ssl_mode      = .Require,
	}

	start := time.now()
	conn, err := conn_connect(cfg, context.allocator)
	elapsed := time.since(start)

	if conn != nil {
		conn_close(conn)
		free(conn, context.allocator)
	}

	nerr, is_net := err.(pgerr.Net_Error)
	testing.expectf(t, is_net, "expected a Net_Error from a stalled handshake, got %v", err)
	testing.expect_value(t, nerr.type, pgerr.Net_Error_Type.Timeout)
	testing.expectf(
		t,
		elapsed < STALLED_PEER_MAX_ELAPSED,
		"TLS handshake returned after %v; the %v read deadline never bounded it",
		elapsed,
		STALLED_PEER_TIMEOUT,
	)
}

@(test)
test_connect_timeout_bounds_a_stalled_connect :: proc(t: ^testing.T) {
	// connect_timeout is the field named for this job, and it governs the
	// phase read_timeout cannot describe: the SSLRequest exchange, the TLS
	// handshake and the startup/auth round trips, which together are several
	// reads rather than one. A caller that sets it and nothing else must still
	// get a bounded connect.
	listener, lerr := net.listen_tcp(net.Endpoint{address = net.IP4_Loopback, port = 0})
	if lerr != nil {
		testing.fail_now(t, "could not open a loopback listener")
	}
	defer net.close(listener)

	endpoint, eerr := net.bound_endpoint(listener)
	if eerr != nil {
		testing.fail_now(t, "could not read the listener endpoint")
	}

	peer := Stalled_Peer{listener = listener, accept_ssl = false, hold = STALLED_PEER_HOLD}
	th := thread.create(stalled_peer_proc)
	th.data = rawptr(&peer)
	thread.start(th)
	defer {
		thread.join(th)
		thread.destroy(th)
	}

	cfg := Conn_Config {
		host            = "127.0.0.1",
		port            = endpoint.port,
		user            = "opg",
		database        = "opg",
		connect_timeout = STALLED_PEER_TIMEOUT,
	}

	start := time.now()
	conn, err := conn_connect(cfg, context.allocator)
	elapsed := time.since(start)

	if conn != nil {
		conn_close(conn)
		free(conn, context.allocator)
	}

	nerr, is_net := err.(pgerr.Net_Error)
	testing.expectf(t, is_net, "expected a Net_Error from a stalled connect, got %v", err)
	testing.expect_value(t, nerr.type, pgerr.Net_Error_Type.Timeout)
	testing.expectf(
		t,
		elapsed < STALLED_PEER_MAX_ELAPSED,
		"connect returned after %v; connect_timeout of %v did nothing",
		elapsed,
		STALLED_PEER_TIMEOUT,
	)
}
