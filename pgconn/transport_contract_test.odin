package pgconn

// ----------------------------------------------------------------------------
// Stream_Transport.read contract.
//
// stream_read_message hands read() the whole unused tail of its accumulation
// buffer and expects POSIX semantics: return what has arrived, do not wait for
// the buffer to be filled. A backend that instead tries to fill the buffer
// deadlocks as soon as the server has sent a complete response and is waiting
// for the next query — it wants more bytes, the server has none to send.
//
// That is exactly how the macOS SecureTransport backend hung: SSLRead fills its
// output buffer by repeatedly invoking the read callback, which blocks in recv.
// OpenSSL's SSL_read returns after one record, so Linux never showed it.
//
// This pins the contract for every backend that can be exercised here.
// ----------------------------------------------------------------------------

import "core:net"
import "core:testing"
import "core:time"

@(test)
test_tcp_read_returns_available_without_filling_buffer :: proc(t: ^testing.T) {
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

	// A short message, then silence — the shape of a server that has answered
	// and is now waiting for the next request.
	payload := []byte{'o', 'p', 'g'}
	_, serr := net.send_tcp(server, payload)
	testing.expect_value(t, serr, nil)

	// A deadline so a backend that waits to fill the buffer fails the test
	// instead of hanging the suite.
	testing.expect_value(t, transport.set_deadlines(transport.data, 2 * time.Second, 0), nil)

	// Deliberately far larger than what was sent.
	buf: [4096]byte
	n, rerr := transport.read(transport.data, buf[:])

	testing.expect_value(t, rerr, nil)
	testing.expect_value(t, n, len(payload))
	testing.expect_value(t, string(buf[:n]), "opg")
}
