package pgconn

import "core:sync"
import "../pgerr"
import "../pgproto"

/*
	SSL_Mode selects TLS behavior for conn_connect. The zero value is
	Prefer (libpq default): attempt TLS, fall back to plaintext when the
	server declines or no TLS library can be loaded.
*/
SSL_Mode :: enum {
	Prefer,
	Disable,
	Require,
}

SSL_Negotiation :: enum {
	Plaintext,
	Wrap_TLS,
}

TLS_Load_State :: enum {
	Unprobed,
	Loaded,
	Unavailable,
}

tls_mutex: sync.Mutex
tls_state: TLS_Load_State

/*
	ssl_negotiate runs the pre-startup SSLRequest exchange on a fresh
	transport, per the libpq mode semantics:

	- Disable, or Prefer without a loadable TLS library: plaintext, nothing
	  sent on the wire.
	- Require without a loadable TLS library: Net_Error{.TLS_Handshake_Failed}.
	- SSLRequest sent: 'S' -> Wrap_TLS; 'N' -> plaintext (Prefer) or
	  Net_Error{.TLS_Handshake_Failed} (Require); anything else ->
	  Protocol_Error{.Unexpected_Message}.
*/
ssl_negotiate :: proc(
	transport: Stream_Transport,
	mode: SSL_Mode,
	tls_loadable: bool,
) -> (
	action: SSL_Negotiation,
	err: pgerr.Error,
) {
	if mode == .Disable {
		return .Plaintext, nil
	}
	if !tls_loadable {
		if mode == .Require {
			return .Plaintext, pgerr.Net_Error{type = .TLS_Handshake_Failed}
		}
		return .Plaintext, nil
	}

	req := make([dynamic]byte, context.temp_allocator)
	defer delete(req)
	pgproto.encode_ssl_request(&req)
	if _, werr := transport.write(transport.data, req[:]); werr != nil {
		return .Plaintext, werr
	}

	answer: [1]byte
	n, rerr := transport.read(transport.data, answer[:])
	if rerr != nil {
		return .Plaintext, rerr
	}
	if n != 1 {
		return .Plaintext, pgerr.Net_Error{type = .Unexpected_EOF}
	}

	switch answer[0] {
	case 'S':
		return .Wrap_TLS, nil
	case 'N':
		if mode == .Require {
			return .Plaintext, pgerr.Net_Error{type = .TLS_Handshake_Failed}
		}
		return .Plaintext, nil
	}
	return .Plaintext, pgerr.Protocol_Error{
		type = .Unexpected_Message,
		message = "unexpected server response to SSLRequest",
	}
}
