package pgconn

import "core:mem"
import "core:testing"
import "../pgerr"

@(test)
test_ssl_negotiate_disable_sends_nothing :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	mock: Mock_Transport
	mock_transport_init(&mock)
	defer mock_transport_destroy(&mock)

	action, err := ssl_negotiate(make_mock_transport(&mock), .Disable, true)
	testing.expect(t, err == nil, "expected no error")
	testing.expect_value(t, action, SSL_Negotiation.Plaintext)
	testing.expect_value(t, len(mock.written_bytes), 0)
	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
test_ssl_negotiate_library_absent :: proc(t: ^testing.T) {
	mock: Mock_Transport
	mock_transport_init(&mock)
	defer mock_transport_destroy(&mock)

	// Prefer without a TLS library: plaintext, no SSLRequest on the wire.
	action, err := ssl_negotiate(make_mock_transport(&mock), .Prefer, false)
	testing.expect(t, err == nil, "expected no error")
	testing.expect_value(t, action, SSL_Negotiation.Plaintext)
	testing.expect_value(t, len(mock.written_bytes), 0)

	// Require without a TLS library: graceful TLS_Handshake_Failed.
	action2, err2 := ssl_negotiate(make_mock_transport(&mock), .Require, false)
	testing.expect_value(t, action2, SSL_Negotiation.Plaintext)
	nerr, ok := err2.(pgerr.Net_Error)
	testing.expect(t, ok, "expected Net_Error")
	testing.expect_value(t, nerr.type, pgerr.Net_Error_Type.TLS_Handshake_Failed)
	testing.expect_value(t, len(mock.written_bytes), 0)
}

@(test)
test_ssl_negotiate_server_accepts :: proc(t: ^testing.T) {
	mock: Mock_Transport
	mock_transport_init(&mock)
	defer mock_transport_destroy(&mock)
	s_byte := []byte{'S'}
	append(&mock.read_chunks, s_byte)

	action, err := ssl_negotiate(make_mock_transport(&mock), .Require, true)
	testing.expect(t, err == nil, "expected no error")
	testing.expect_value(t, action, SSL_Negotiation.Wrap_TLS)

	// SSLRequest: int32 len 8, int32 code 80877103 (0x04D2162F).
	testing.expect_value(t, len(mock.written_bytes), 8)
	testing.expect_value(t, mock.written_bytes[3], byte(8))
	testing.expect_value(t, mock.written_bytes[4], byte(0x04))
	testing.expect_value(t, mock.written_bytes[5], byte(0xD2))
	testing.expect_value(t, mock.written_bytes[6], byte(0x16))
	testing.expect_value(t, mock.written_bytes[7], byte(0x2F))
}

@(test)
test_ssl_negotiate_server_declines :: proc(t: ^testing.T) {
	// Prefer + 'N': plaintext fallback on the same socket.
	mock: Mock_Transport
	mock_transport_init(&mock)
	defer mock_transport_destroy(&mock)
	n_byte := []byte{'N'}
	append(&mock.read_chunks, n_byte)

	action, err := ssl_negotiate(make_mock_transport(&mock), .Prefer, true)
	testing.expect(t, err == nil, "expected no error")
	testing.expect_value(t, action, SSL_Negotiation.Plaintext)

	// Require + 'N': hard failure.
	mock2: Mock_Transport
	mock_transport_init(&mock2)
	defer mock_transport_destroy(&mock2)
	append(&mock2.read_chunks, n_byte)

	_, err2 := ssl_negotiate(make_mock_transport(&mock2), .Require, true)
	nerr, ok := err2.(pgerr.Net_Error)
	testing.expect(t, ok, "expected Net_Error")
	testing.expect_value(t, nerr.type, pgerr.Net_Error_Type.TLS_Handshake_Failed)
}

@(test)
test_ssl_negotiate_unexpected_byte :: proc(t: ^testing.T) {
	mock: Mock_Transport
	mock_transport_init(&mock)
	defer mock_transport_destroy(&mock)
	x_byte := []byte{'X'}
	append(&mock.read_chunks, x_byte)

	_, err := ssl_negotiate(make_mock_transport(&mock), .Prefer, true)
	perr, ok := err.(pgerr.Protocol_Error)
	testing.expect(t, ok, "expected Protocol_Error")
	testing.expect_value(t, perr.type, pgerr.Protocol_Error_Type.Unexpected_Message)
}

@(test)
test_tls_probe_bogus_paths_graceful :: proc(t: ^testing.T) {
	bogus := []string{"libopg_no_such_tls.so.999", "libopg_also_missing.so"}
	testing.expect(t, !tls_probe_paths(bogus), "expected probe failure for bogus paths")
}

@(test)
test_tls_probe_real_openssl :: proc(t: ^testing.T) {
	// This machine has libssl.so.3 (development requires it; the driver
	// itself degrades gracefully without it).
	when ODIN_OS == .Linux {
		probe: OpenSSL_API
		ok := tls_probe_into(&probe, TLS_PROBE_PATHS)
		testing.expect(t, ok, "expected OpenSSL to load on Linux dev machine")
		testing.expect(t, probe.SSL_CTX_new != nil, "expected SSL_CTX_new bound")
		testing.expect(t, probe.SSL_connect != nil, "expected SSL_connect bound")
		testing.expect(t, probe.SSL_ctrl != nil, "expected SSL_ctrl bound")
	}
}

@(test)
test_ssl_negotiate_transport_errors :: proc(t: ^testing.T) {
	// Write fails (closed transport).
	mock: Mock_Transport
	mock_transport_init(&mock)
	defer mock_transport_destroy(&mock)
	mock.is_closed = true

	_, err := ssl_negotiate(make_mock_transport(&mock), .Require, true)
	testing.expect(t, err != nil, "expected error from closed transport")

	// Read fails (no response queued -> Socket_Closed from mock).
	mock2: Mock_Transport
	mock_transport_init(&mock2)
	defer mock_transport_destroy(&mock2)

	_, err2 := ssl_negotiate(make_mock_transport(&mock2), .Require, true)
	testing.expect(t, err2 != nil, "expected error from read failure")
}
