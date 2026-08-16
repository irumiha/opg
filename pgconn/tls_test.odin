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
		ok := tls_probe_into(&probe, TLS_OPENSSL_PATHS)
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

// ----------------------------------------------------------------------------
// Backend Selection & Fallback Tests (OPG-502)
// ----------------------------------------------------------------------------

@(test)
test_tls_backend_selection_and_names :: proc(t: ^testing.T) {
	loaded := tls_ensure_loaded()
	btype := tls_backend_type()
	bname := tls_backend_name()

	if loaded {
		testing.expect(t, btype != .None, "expected loaded backend to not be .None")
		testing.expect(t, len(bname) > 0 && bname != "none", "expected non-empty backend name")
		when ODIN_OS == .Linux {
			testing.expect_value(t, btype, TLS_Backend_Type.OpenSSL)
			testing.expect_value(t, bname, "OpenSSL")
		} else when ODIN_OS == .Darwin {
			testing.expect(t, btype == .SecureTransport || btype == .OpenSSL, "expected SecureTransport or OpenSSL on macOS")
		} else when ODIN_OS == .Windows {
			testing.expect(t, btype == .Schannel || btype == .OpenSSL, "expected Schannel or OpenSSL on Windows")
		}
	} else {
		testing.expect_value(t, btype, TLS_Backend_Type.None)
		testing.expect_value(t, bname, "none")
	}
}

@(test)
test_tls_backend_injected_fallback_order :: proc(t: ^testing.T) {
	// Test injected empty backend list -> resolves to None
	none_result := tls_probe_backends([]TLS_Backend_Type{})
	testing.expect_value(t, none_result, TLS_Backend_Type.None)

	// Test injected None list -> resolves to None
	none_result2 := tls_probe_backends([]TLS_Backend_Type{.None})
	testing.expect_value(t, none_result2, TLS_Backend_Type.None)

	// On Linux, OpenSSL should resolve if requested
	when ODIN_OS == .Linux {
		openssl_result := tls_probe_backends([]TLS_Backend_Type{.OpenSSL})
		testing.expect_value(t, openssl_result, TLS_Backend_Type.OpenSSL)
	}
}

@(test)
test_tls_backend_falls_back_when_native_unavailable :: proc(t: ^testing.T) {
	// The per-OS priority lists put the native backend first and OpenSSL
	// second. Injecting a native-first list on a host where that native
	// backend cannot exist exercises the fallback leg specifically: selection
	// must walk past the unavailable entry rather than giving up at it.
	when ODIN_OS == .Linux {
		schannel_first := tls_probe_backends([]TLS_Backend_Type{.Schannel, .OpenSSL})
		testing.expect_value(t, schannel_first, TLS_Backend_Type.OpenSSL)

		darwin_first := tls_probe_backends([]TLS_Backend_Type{.SecureTransport, .OpenSSL})
		testing.expect_value(t, darwin_first, TLS_Backend_Type.OpenSSL)

		// Every candidate unavailable resolves to None rather than picking
		// something not asked for.
		native_only := tls_probe_backends([]TLS_Backend_Type{.Schannel, .SecureTransport})
		testing.expect_value(t, native_only, TLS_Backend_Type.None)
	}
}

@(test)
test_tls_backend_selection_respects_list_order :: proc(t: ^testing.T) {
	// First usable candidate wins: a list led by an available backend must not
	// be overtaken by a later one.
	when ODIN_OS == .Linux {
		result := tls_probe_backends([]TLS_Backend_Type{.OpenSSL, .Schannel})
		testing.expect_value(t, result, TLS_Backend_Type.OpenSSL)
	}
}

@(test)
test_tls_default_backend_list_is_native_first :: proc(t: ^testing.T) {
	// OPG-502 specifies the priority order per platform; assert the table
	// rather than the probe result, which depends on what the host has.
	when ODIN_OS == .Windows {
		testing.expect_value(t, len(TLS_DEFAULT_BACKENDS), 2)
		testing.expect_value(t, TLS_DEFAULT_BACKENDS[0], TLS_Backend_Type.Schannel)
		testing.expect_value(t, TLS_DEFAULT_BACKENDS[1], TLS_Backend_Type.OpenSSL)
	} else when ODIN_OS == .Darwin {
		testing.expect_value(t, len(TLS_DEFAULT_BACKENDS), 2)
		testing.expect_value(t, TLS_DEFAULT_BACKENDS[0], TLS_Backend_Type.SecureTransport)
		testing.expect_value(t, TLS_DEFAULT_BACKENDS[1], TLS_Backend_Type.OpenSSL)
	} else when ODIN_OS == .Linux {
		testing.expect_value(t, len(TLS_DEFAULT_BACKENDS), 1)
		testing.expect_value(t, TLS_DEFAULT_BACKENDS[0], TLS_Backend_Type.OpenSSL)
	}
}

// ----------------------------------------------------------------------------
// Record-buffer carry-over
//
// Both stream backends must keep ciphertext that arrived but has not been
// consumed yet: TLS records do not align with TCP reads, so one read can
// deliver a whole record plus the head of the next. Dropping that tail
// desynchronizes the stream, which is why the compaction is tested directly.
// ----------------------------------------------------------------------------

@(test)
test_tls_retain_tail_keeps_unconsumed_bytes :: proc(t: ^testing.T) {
	buf := make([dynamic]byte, 0, 8)
	defer delete(buf)
	append(&buf, 1, 2, 3, 4, 5)

	tls_retain_tail(&buf, 2)

	testing.expect_value(t, len(buf), 2)
	testing.expect_value(t, buf[0], byte(4))
	testing.expect_value(t, buf[1], byte(5))
}

@(test)
test_tls_retain_tail_zero_empties_buffer :: proc(t: ^testing.T) {
	buf := make([dynamic]byte, 0, 8)
	defer delete(buf)
	append(&buf, 1, 2, 3)

	tls_retain_tail(&buf, 0)

	testing.expect_value(t, len(buf), 0)
}

@(test)
test_tls_retain_tail_whole_buffer_is_unchanged :: proc(t: ^testing.T) {
	buf := make([dynamic]byte, 0, 8)
	defer delete(buf)
	append(&buf, 7, 8, 9)

	tls_retain_tail(&buf, 3)

	testing.expect_value(t, len(buf), 3)
	testing.expect_value(t, buf[0], byte(7))
	testing.expect_value(t, buf[2], byte(9))
}

@(test)
test_tls_retain_tail_clamps_oversized_request :: proc(t: ^testing.T) {
	buf := make([dynamic]byte, 0, 8)
	defer delete(buf)
	append(&buf, 1, 2)

	// A backend reporting more leftover than was supplied would otherwise
	// index out of bounds; retaining everything is the safe reading.
	tls_retain_tail(&buf, 99)

	testing.expect_value(t, len(buf), 2)
	testing.expect_value(t, buf[0], byte(1))
}

// ----------------------------------------------------------------------------
// Schannel context request flags
// ----------------------------------------------------------------------------

@(test)
test_schannel_requests_a_stream_context :: proc(t: ^testing.T) {
	// PostgreSQL speaks TLS over TCP. Schannel chooses between TLS and DTLS
	// from the context request flags, and the deciding bit has close
	// neighbours in sspi.h:
	//
	//     ISC_REQ_DATAGRAM    0x00000400   -> DTLS
	//     ISC_REQ_CONNECTION  0x00000800
	//     ISC_REQ_STREAM      0x00008000   -> TLS
	//
	// Asking for the wrong one fails silently at the API level: every SSPI
	// call returns success, a token comes back, and the mistake is visible
	// only on the wire, as a DTLS ClientHello (version 0xFEFD, 13-byte record
	// header carrying an epoch and sequence number) that a TCP server closes
	// the connection on. That is exactly what shipped, and it is why the
	// Windows backend never completed a handshake.
	//
	// The reference values below are transcribed from sspi.h so these
	// assertions check the driver against the ABI rather than against itself.
	when ODIN_OS == .Windows {
		SSPI_ISC_REQ_DATAGRAM :: 0x00000400
		SSPI_ISC_REQ_STREAM :: 0x00008000

		testing.expect_value(t, u32(ISC_REQ_STREAM), u32(SSPI_ISC_REQ_STREAM))
		testing.expect(
			t,
			SCHANNEL_REQ_FLAGS & SSPI_ISC_REQ_DATAGRAM == 0,
			"the Schannel context request must not ask for DTLS",
		)
		testing.expect(
			t,
			SCHANNEL_REQ_FLAGS & SSPI_ISC_REQ_STREAM != 0,
			"the Schannel context request must ask for a stream (TLS) context",
		)
	}
}
