package pgconn

// Dynamically-loaded OpenSSL 3 backend. No link-time dependency: symbols
// are bound at runtime with core:dynlib; absence degrades per SSL_Mode.
// Native Schannel/SecureTransport backends are deferred (see the OPG-205
// design spec) - OpenSSL names are probed on every OS.

import "core:c"
import "core:dynlib"
import "core:net"
import "core:strings"
import "core:time"
import "../pgerr"

/*
	OpenSSL_API is bound by dynlib.initialize_symbols: each field name must
	exactly match an exported libssl symbol; the library handle lands in
	__handle. libssl.so.3 pulls libcrypto.so.3 in via its own dependencies.
*/
OpenSSL_API :: struct {
	__handle:          dynlib.Library,
	TLS_client_method: proc "c" () -> rawptr,
	SSL_CTX_new:       proc "c" (method: rawptr) -> rawptr,
	SSL_CTX_free:      proc "c" (ctx: rawptr),
	SSL_new:           proc "c" (ctx: rawptr) -> rawptr,
	SSL_free:          proc "c" (ssl: rawptr),
	SSL_set_fd:        proc "c" (ssl: rawptr, fd: c.int) -> c.int,
	SSL_connect:       proc "c" (ssl: rawptr) -> c.int,
	SSL_read:          proc "c" (ssl: rawptr, buf: rawptr, num: c.int) -> c.int,
	SSL_write:         proc "c" (ssl: rawptr, data: rawptr, num: c.int) -> c.int,
	SSL_shutdown:      proc "c" (ssl: rawptr) -> c.int,
	SSL_get_error:     proc "c" (ssl: rawptr, ret: c.int) -> c.int,
	SSL_ctrl:          proc "c" (ssl: rawptr, cmd: c.int, larg: c.long, parg: rawptr) -> c.long,
}

// One proc-pointer field per libssl symbol; __handle is not a symbol.
TLS_SYMBOL_COUNT :: 12

SSL_CTRL_SET_TLSEXT_HOSTNAME :: 55
TLSEXT_NAMETYPE_host_name :: 0

SSL_ERROR_WANT_READ :: 2
SSL_ERROR_WANT_WRITE :: 3
SSL_ERROR_ZERO_RETURN :: 6

openssl: OpenSSL_API

/*
	tls_probe_into loads the first library from `paths` that binds every
	OpenSSL_API symbol. initialize_symbols reports ok on load even if some
	symbols are missing, so the bound-symbol count is checked too.
*/
tls_probe_into :: proc(api: ^OpenSSL_API, paths: []string) -> bool {
	for path in paths {
		count, ok := dynlib.initialize_symbols(api, path)
		if ok && count == TLS_SYMBOL_COUNT {
			return true
		}
		if ok {
			_ = dynlib.unload_library(api.__handle)
			api^ = {}
		}
	}
	return false
}

// TLS_Transport_Data is the concrete state for an OpenSSL-wrapped socket.
TLS_Transport_Data :: struct {
	ctx:           rawptr, // SSL_CTX*
	ssl:           rawptr, // SSL*
	socket:        net.TCP_Socket,
	read_timeout:  time.Duration,
	write_timeout: time.Duration,
}

/*
	make_tls_transport performs the client TLS handshake over an already
	connected socket and returns a Stream_Transport backed by OpenSSL.
	On failure everything created here is freed and the caller keeps
	ownership of the (still open) socket. Requires a successful probe.
*/
make_tls_transport :: proc(
	data: ^TLS_Transport_Data,
	socket: net.TCP_Socket,
	server_name: string,
) -> (
	transport: Stream_Transport,
	err: pgerr.Error,
) {
	ctx := openssl.SSL_CTX_new(openssl.TLS_client_method())
	if ctx == nil {
		return {}, pgerr.Net_Error{type = .TLS_Handshake_Failed}
	}
	ssl := openssl.SSL_new(ctx)
	if ssl == nil {
		openssl.SSL_CTX_free(ctx)
		return {}, pgerr.Net_Error{type = .TLS_Handshake_Failed}
	}

	if openssl.SSL_set_fd(ssl, c.int(socket)) != 1 {
		openssl.SSL_free(ssl)
		openssl.SSL_CTX_free(ctx)
		return {}, pgerr.Net_Error{type = .TLS_Handshake_Failed}
	}

	// SNI (SSL_set_tlsext_host_name is a macro over SSL_ctrl).
	if len(server_name) > 0 {
		host_c := strings.clone_to_cstring(server_name, context.temp_allocator)
		_ = openssl.SSL_ctrl(ssl, SSL_CTRL_SET_TLSEXT_HOSTNAME, TLSEXT_NAMETYPE_host_name, rawptr(host_c))
	}

	if openssl.SSL_connect(ssl) != 1 {
		openssl.SSL_free(ssl)
		openssl.SSL_CTX_free(ctx)
		return {}, pgerr.Net_Error{type = .TLS_Handshake_Failed}
	}

	data.ctx = ctx
	data.ssl = ssl
	data.socket = socket
	return Stream_Transport{
		data = data,
		read = tls_read,
		write = tls_write,
		close = tls_close,
		set_deadlines = tls_set_deadlines,
	}, nil
}

tls_read :: proc(transport: rawptr, buf: []byte) -> (bytes_read: int, err: pgerr.Error) {
	data := (^TLS_Transport_Data)(transport)
	if len(buf) == 0 {
		return 0, nil
	}
	for {
		ret := openssl.SSL_read(data.ssl, raw_data(buf), c.int(len(buf)))
		if ret > 0 {
			return int(ret), nil
		}
		code := openssl.SSL_get_error(data.ssl, ret)
		switch code {
		case SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE:
			continue // blocking fd: retry
		case SSL_ERROR_ZERO_RETURN:
			return 0, pgerr.Net_Error{type = .Socket_Closed}
		}
		return 0, pgerr.Net_Error{type = .Recv_Failed, code = i32(code)}
	}
}

tls_write :: proc(transport: rawptr, data_bytes: []byte) -> (bytes_written: int, err: pgerr.Error) {
	data := (^TLS_Transport_Data)(transport)
	total := 0
	for total < len(data_bytes) {
		remaining := data_bytes[total:]
		ret := openssl.SSL_write(data.ssl, raw_data(remaining), c.int(len(remaining)))
		if ret > 0 {
			total += int(ret)
			continue
		}
		code := openssl.SSL_get_error(data.ssl, ret)
		if code == SSL_ERROR_WANT_READ || code == SSL_ERROR_WANT_WRITE {
			continue // blocking fd: retry
		}
		if code == SSL_ERROR_ZERO_RETURN {
			return total, pgerr.Net_Error{type = .Socket_Closed}
		}
		return total, pgerr.Net_Error{type = .Send_Failed, code = i32(code)}
	}
	return total, nil
}

tls_close :: proc(transport: rawptr) {
	data := (^TLS_Transport_Data)(transport)
	if data.ssl != nil {
		_ = openssl.SSL_shutdown(data.ssl) // best-effort close_notify
		openssl.SSL_free(data.ssl)
		data.ssl = nil
	}
	if data.ctx != nil {
		openssl.SSL_CTX_free(data.ctx)
		data.ctx = nil
	}
	net.close(data.socket)
}

tls_set_deadlines :: proc(transport: rawptr, read_timeout, write_timeout: time.Duration) -> pgerr.Error {
	data := (^TLS_Transport_Data)(transport)
	data.read_timeout = read_timeout
	data.write_timeout = write_timeout
	// Note: OS-level socket timeout configuration can be hooked here (same
	// stub level as tcp_set_deadlines).
	return nil
}
