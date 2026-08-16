package pgconn

import "core:net"
import "core:sync"
import "core:time"
import "../pgerr"
import "../pgproto"

// ============================================================================
// Multi-Platform Dynamic TLS Layer (Frontend/Backend Protocol 3.0)
// ============================================================================
// Architecture:
// 1. Dynamic Runtime Loading: Probes OS-native TLS APIs first, falling back to
//    OpenSSL via core:dynlib. Strictly no static link-time C library dependencies.
// 2. Priority Order per Platform:
//    - Windows: Schannel (secur32.dll / sspicli.dll) -> OpenSSL
//    - macOS (Darwin): SecureTransport (Security.framework) -> OpenSSL
//    - Linux / POSIX: OpenSSL (libssl.so.3 / libssl.so)
// 3. Graceful Absence: Degrades to plaintext (Prefer) or Net_Error (Require).
// ============================================================================

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

TLS_Backend_Type :: enum {
	None,
	OpenSSL,
	Schannel,
	SecureTransport,
}

/*
	TLS_Transport_Data is the concrete storage for an active TLS session.
	Embedded in Conn to avoid separate heap allocations.
*/
TLS_Transport_Data :: struct {
	backend:          TLS_Backend_Type,
	socket:           net.TCP_Socket,
	read_timeout:     time.Duration,
	write_timeout:    time.Duration,
	// OpenSSL backend state:
	openssl_ctx:      rawptr,
	openssl_ssl:      rawptr,
	// SecureTransport backend state:
	secure_transport: rawptr,
	// Schannel backend state:
	schannel_cred:    [2]uintptr,
	schannel_ctxt:    [2]uintptr,
	schannel_header:  u32,
	schannel_trailer: u32,
	schannel_max_msg: u32,
	// Plaintext decrypted from a record but not yet handed to the caller.
	schannel_buf:     [dynamic]byte,
	// Ciphertext received from the socket but not yet decrypted: the tail of a
	// partially received record, or whole records that arrived alongside the
	// one just consumed.
	schannel_enc:     [dynamic]byte,
}

/*
	tls_retain_tail discards everything but the last keep bytes of buf,
	preserving their order.

	TLS record boundaries do not line up with TCP reads: one read can deliver a
	complete record plus the beginning of the next, and the backends report that
	remainder as a trailing byte count. Keeping it is what lets the following
	read resume on a record boundary rather than mid-record.
*/
tls_retain_tail :: proc(buf: ^[dynamic]byte, keep: int) {
	if buf == nil do return
	if keep <= 0 {
		clear(buf)
		return
	}
	if keep >= len(buf) do return

	copy(buf[:keep], buf[len(buf) - keep:])
	resize(buf, keep)
}

tls_mutex: sync.Mutex
tls_state: TLS_Load_State
tls_active_backend: TLS_Backend_Type = .None

// Platform-specific OpenSSL candidate library paths
when ODIN_OS == .Linux {
	TLS_OPENSSL_PATHS :: []string{"libssl.so.3", "libssl.so", "libssl.so.1.1"}
} else when ODIN_OS == .Darwin {
	TLS_OPENSSL_PATHS :: []string{
		"libssl.3.dylib",
		"/opt/homebrew/opt/openssl@3/lib/libssl.3.dylib",
		"/usr/local/opt/openssl@3/lib/libssl.3.dylib",
	}
} else when ODIN_OS == .Windows {
	TLS_OPENSSL_PATHS :: []string{"libssl-3-x64.dll", "libssl-3.dll", "libssl-1_1-x64.dll"}
} else {
	TLS_OPENSSL_PATHS :: []string{}
}

// Default per-OS probing priority list
when ODIN_OS == .Windows {
	TLS_DEFAULT_BACKENDS :: []TLS_Backend_Type{.Schannel, .OpenSSL}
} else when ODIN_OS == .Darwin {
	TLS_DEFAULT_BACKENDS :: []TLS_Backend_Type{.SecureTransport, .OpenSSL}
} else when ODIN_OS == .Linux {
	TLS_DEFAULT_BACKENDS :: []TLS_Backend_Type{.OpenSSL}
} else {
	TLS_DEFAULT_BACKENDS :: []TLS_Backend_Type{}
}

/*
	tls_ensure_loaded probes the platform's candidate TLS backends exactly
	once per process and reports whether any backend is usable. Thread-safe.
*/
tls_ensure_loaded :: proc() -> bool {
	sync.mutex_lock(&tls_mutex)
	defer sync.mutex_unlock(&tls_mutex)

	if tls_state == .Unprobed {
		backend := tls_probe_backends_unlocked(TLS_DEFAULT_BACKENDS)
		if backend != .None {
			tls_state = .Loaded
			tls_active_backend = backend
		} else {
			tls_state = .Unavailable
			tls_active_backend = .None
		}
	}
	return tls_state == .Loaded
}

/*
	tls_backend_type returns the currently selected TLS backend type.
*/
tls_backend_type :: proc() -> TLS_Backend_Type {
	_ = tls_ensure_loaded()
	return tls_active_backend
}

/*
	tls_backend_name returns the human-readable name of the active TLS backend
	(e.g., "Schannel", "SecureTransport", "OpenSSL", or "none").
*/
tls_backend_name :: proc() -> string {
	switch tls_backend_type() {
	case .None:            return "none"
	case .OpenSSL:         return "OpenSSL"
	case .Schannel:        return "Schannel"
	case .SecureTransport: return "SecureTransport"
	}
	return "unknown"
}

/*
	tls_probe_backends probes each backend in candidate order, returning the
	first backend that successfully binds all required symbols. Thread-safe.
*/
tls_probe_backends :: proc(backends: []TLS_Backend_Type) -> TLS_Backend_Type {
	sync.mutex_lock(&tls_mutex)
	defer sync.mutex_unlock(&tls_mutex)
	return tls_probe_backends_unlocked(backends)
}

@(private="file")
tls_probe_backends_unlocked :: proc(backends: []TLS_Backend_Type) -> TLS_Backend_Type {
	for b in backends {
		switch b {
		case .Schannel:
			when ODIN_OS == .Windows {
				if schannel_probe() do return .Schannel
			}
		case .SecureTransport:
			when ODIN_OS == .Darwin {
				if secure_transport_probe() do return .SecureTransport
			}
		case .OpenSSL:
			if tls_probe_into(&openssl, TLS_OPENSSL_PATHS) do return .OpenSSL
		case .None:
		}
	}
	return .None
}

/*
	tls_probe_paths probes candidate library file paths into a temporary probe table. Thread-safe.
*/
tls_probe_paths :: proc(paths: []string) -> bool {
	probe: OpenSSL_API
	return tls_probe_into(&probe, paths)
}

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

/*
	make_tls_transport wraps an established TCP socket in a secure Stream_Transport
	using the platform's selected TLS backend.
*/
make_tls_transport :: proc(
	data: ^TLS_Transport_Data,
	socket: net.TCP_Socket,
	server_name: string,
) -> (
	transport: Stream_Transport,
	err: pgerr.Error,
) {
	switch tls_backend_type() {
	case .OpenSSL:
		return make_openssl_transport(data, socket, server_name)
	case .Schannel:
		when ODIN_OS == .Windows {
			return make_schannel_transport(data, socket, server_name)
		}
	case .SecureTransport:
		when ODIN_OS == .Darwin {
			return make_secure_transport(data, socket, server_name)
		}
	case .None:
	}
	return {}, pgerr.Net_Error{type = .TLS_Handshake_Failed}
}
