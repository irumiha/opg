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
import "core:time"
import "../pgerr"

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
