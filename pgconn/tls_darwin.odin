package pgconn

import "base:runtime"
import "core:c"
import "core:dynlib"
import "core:net"
import "core:strings"
import "core:time"
import "../pgerr"

// ============================================================================
// macOS SecureTransport TLS Backend (Security.framework)
// ============================================================================

SSLReadFunc  :: #type proc "c" (connection: rawptr, data: rawptr, dataLength: ^c.size_t) -> c.int
SSLWriteFunc :: #type proc "c" (connection: rawptr, data: rawptr, dataLength: ^c.size_t) -> c.int

SecureTransport_API :: struct {
	__handle:             dynlib.Library,
	SSLCreateContext:     proc "c" (alloc: rawptr, protocolSide: c.int, connectionType: c.int) -> rawptr,
	SSLSetIOFuncs:        proc "c" (ctx: rawptr, readFunc: SSLReadFunc, writeFunc: SSLWriteFunc) -> c.int,
	SSLSetConnection:     proc "c" (ctx: rawptr, connection: rawptr) -> c.int,
	SSLSetPeerDomainName: proc "c" (ctx: rawptr, peerName: cstring, peerNameLen: c.size_t) -> c.int,
	SSLSetSessionOption:  proc "c" (ctx: rawptr, option: c.int, value: bool) -> c.int,
	SSLHandshake:         proc "c" (ctx: rawptr) -> c.int,
	SSLRead:              proc "c" (ctx: rawptr, data: rawptr, dataLength: c.size_t, processed: ^c.size_t) -> c.int,
	SSLWrite:             proc "c" (ctx: rawptr, data: rawptr, dataLength: c.size_t, processed: ^c.size_t) -> c.int,
	// Bytes already decrypted and waiting in the context. Reading these cannot
	// touch the socket, which is what lets sec_trans_read return everything
	// available without asking SSLRead to fill the caller's buffer.
	SSLGetBufferedReadSize: proc "c" (ctx: rawptr, bufSize: ^c.size_t) -> c.int,
	SSLClose:             proc "c" (ctx: rawptr) -> c.int,
	CFRelease:            proc "c" (cf: rawptr),
}

kSSLClientSide :: 1
kSSLStreamType :: 0
kSSLSessionOptionBreakOnServerAuth :: 0

errSSLWouldBlock           :: -9803
errSSLClosedGraceful       :: -9805
errSSLClosedAbort          :: -9806
errSSLServerAuthCompleted  :: -9841
noErr                      :: 0

sec_trans: SecureTransport_API
SEC_TRANS_SYMBOL_COUNT :: 11

secure_transport_probe :: proc() -> bool {
	if sec_trans.__handle != nil && sec_trans.SSLRead != nil {
		return true
	}
	paths := []string{
		"/System/Library/Frameworks/Security.framework/Security",
		"Security.framework/Security",
		"libsecurity.dylib",
	}
	for p in paths {
		count, ok := dynlib.initialize_symbols(&sec_trans, p)
		if ok && count == SEC_TRANS_SYMBOL_COUNT {
			return true
		}
		if ok {
			_ = dynlib.unload_library(sec_trans.__handle)
			sec_trans = {}
		}
	}
	return false
}

secure_transport_read_cb :: proc "c" (connection: rawptr, data: rawptr, dataLength: ^c.size_t) -> c.int {
	context = runtime.default_context()
	sock := net.TCP_Socket(uintptr(connection))
	wanted := int(dataLength^)
	if wanted == 0 {
		return noErr
	}
	buf := ([^]byte)(data)[:wanted]

	n: int
	for {
		rn, rerr := net.recv_tcp(sock, buf)
		if rerr == .None {
			n = rn
			break
		}
		#partial switch rerr {
		case .Interrupted:
			// A signal landed mid-recv. Retrying is the whole remedy; the
			// alternative below would abort a perfectly healthy session.
			continue
		case .Would_Block, .Timeout:
			dataLength^ = 0
			return errSSLWouldBlock
		case .Connection_Closed, .Not_Connected:
			dataLength^ = 0
			return errSSLClosedGraceful
		case:
			dataLength^ = 0
			return errSSLClosedAbort
		}
	}
	if n == 0 {
		dataLength^ = 0
		return errSSLClosedGraceful
	}
	dataLength^ = c.size_t(n)
	if n < wanted {
		return errSSLWouldBlock
	}
	return noErr
}

secure_transport_write_cb :: proc "c" (connection: rawptr, data: rawptr, dataLength: ^c.size_t) -> c.int {
	context = runtime.default_context()
	sock := net.TCP_Socket(uintptr(connection))
	to_send := int(dataLength^)
	if to_send == 0 {
		return noErr
	}
	buf := ([^]byte)(data)[:to_send]

	// net.send_tcp loops internally and reports how much it managed to write
	// *alongside* any error, so every exit here has to account for `sent`.
	// Resuming from the front after a partial write, or reporting fewer bytes
	// than actually reached the socket, makes SecureTransport send those bytes
	// a second time and corrupts the record stream.
	sent := 0
	for sent < to_send {
		sn, serr := net.send_tcp(sock, buf[sent:])
		sent += sn
		if serr == .None do continue

		#partial switch serr {
		case .Interrupted:
			// A signal, not a broken connection: resume where it stopped.
			continue
		case .Would_Block, .Timeout:
			dataLength^ = c.size_t(sent)
			return errSSLWouldBlock
		case:
			dataLength^ = c.size_t(sent)
			// Bytes already on the wire must be acknowledged even though the
			// connection is failing. Reporting a short write lets the next
			// call surface the failure with nothing left outstanding, rather
			// than having SecureTransport retransmit what already went out.
			if sent > 0 do return errSSLWouldBlock
			if serr == .Connection_Closed || serr == .Not_Connected {
				return errSSLClosedGraceful
			}
			return errSSLClosedAbort
		}
	}

	dataLength^ = c.size_t(sent)
	return noErr
}

make_secure_transport :: proc(
	data: ^TLS_Transport_Data,
	socket: net.TCP_Socket,
	server_name: string,
) -> (
	transport: Stream_Transport,
	err: pgerr.Error,
) {
	ctx := sec_trans.SSLCreateContext(nil, kSSLClientSide, kSSLStreamType)
	if ctx == nil {
		return {}, pgerr.Net_Error{type = .TLS_Handshake_Failed}
	}

	if sec_trans.SSLSetIOFuncs(ctx, secure_transport_read_cb, secure_transport_write_cb) != noErr {
		sec_trans.CFRelease(ctx)
		return {}, pgerr.Net_Error{type = .TLS_Handshake_Failed}
	}

	if sec_trans.SSLSetConnection(ctx, rawptr(uintptr(socket))) != noErr {
		sec_trans.CFRelease(ctx)
		return {}, pgerr.Net_Error{type = .TLS_Handshake_Failed}
	}

	if len(server_name) > 0 {
		host_c := strings.clone_to_cstring(server_name, context.temp_allocator)
		_ = sec_trans.SSLSetPeerDomainName(ctx, host_c, c.size_t(len(server_name)))
	}

	// Disable cert validation for local test instances with self-signed certs
	_ = sec_trans.SSLSetSessionOption(ctx, kSSLSessionOptionBreakOnServerAuth, true)

	// Bounded like the read and write paths. The read callback reports a
	// socket timeout as errSSLWouldBlock, so an unbounded loop here turns a
	// peer that goes quiet mid-handshake into a permanent hang inside connect.
	retries := 0
	start := time.now()
	for {
		status := sec_trans.SSLHandshake(ctx)
		if status == noErr {
			break
		}

		// A socket deadline surfaces here as errSSLWouldBlock, indistinguishable
		// from a peer that is merely slow. Counting retries alone multiplies the
		// configured timeout by the retry budget, so elapsed time is what bounds
		// a handshake against a deadline.
		if tls_deadline_exceeded(start, data.read_timeout) {
			sec_trans.CFRelease(ctx)
			return {}, pgerr.Net_Error{type = .Timeout}
		}

		retries += 1
		if retries > TLS_MAX_WANT_RETRIES {
			sec_trans.CFRelease(ctx)
			return {}, pgerr.Net_Error{type = .Timeout}
		}

		if status == errSSLWouldBlock {
			time.sleep(time.Millisecond)
			continue
		} else if status == errSSLServerAuthCompleted {
			// Raised once because cert validation is broken out below;
			// resuming completes the handshake.
			continue
		} else {
			sec_trans.CFRelease(ctx)
			return {}, pgerr.Net_Error{type = .TLS_Handshake_Failed, code = i32(status)}
		}
	}

	data.backend = .SecureTransport
	data.secure_transport = ctx
	data.socket = socket
	return Stream_Transport{
		data = data,
		read = sec_trans_read,
		write = sec_trans_write,
		close = sec_trans_close,
		set_deadlines = sec_trans_set_deadlines,
	}, nil
}

/*
	sec_trans_buffered drains bytes SecureTransport has already decrypted into
	dst, without touching the socket. Returns how many were moved.
*/
@(private = "file")
sec_trans_buffered :: proc(ctx: rawptr, dst: []byte) -> int {
	if len(dst) == 0 do return 0

	available: c.size_t = 0
	if sec_trans.SSLGetBufferedReadSize(ctx, &available) != noErr do return 0
	if available == 0 do return 0

	want := min(int(available), len(dst))
	processed: c.size_t = 0
	// Only ever asks for bytes already decrypted, so this cannot reach the
	// read callback and cannot block.
	sec_trans.SSLRead(ctx, raw_data(dst), c.size_t(want), &processed)
	return int(processed)
}

/*
	sec_trans_read implements the Stream_Transport contract: block until at
	least one byte is available, then return everything ready, up to len(buf).

	SSLRead fills the length it is given, calling the read callback repeatedly
	until it has that many bytes. The callback reads a blocking socket, so
	passing len(buf) — which the stream layer sizes as "the whole unused tail of
	my buffer", far larger than any response — deadlocks the moment the server
	has answered and is waiting for the next query: SSLRead wants more, the
	server sends nothing, recv never returns. OpenSSL's SSL_read returns after
	a single record, which is why only macOS hung.

	So: ask for exactly one byte (the blocking part callers expect), then drain
	whatever else SecureTransport already holds.
*/
sec_trans_read :: proc(transport: rawptr, buf: []byte) -> (bytes_read: int, err: pgerr.Error) {
	data := (^TLS_Transport_Data)(transport)
	if len(buf) == 0 do return 0, nil

	// Anything already decrypted satisfies the read outright.
	if n := sec_trans_buffered(data.secure_transport, buf); n > 0 {
		return n, nil
	}

	processed: c.size_t = 0
	retries := 0
	start := time.now()
	for {
		status := sec_trans.SSLRead(data.secure_transport, raw_data(buf), 1, &processed)
		if processed > 0 {
			total := int(processed)
			total += sec_trans_buffered(data.secure_transport, buf[total:])
			return total, nil
		}
		if status == noErr {
			return int(processed), nil
		} else if status == errSSLWouldBlock {
			// An expired socket receive deadline reaches here as would-block,
			// so elapsed time, not the retry count, has to bound it.
			if tls_deadline_exceeded(start, data.read_timeout) {
				return 0, pgerr.Net_Error{type = .Timeout}
			}
			retries += 1
			if retries > TLS_MAX_WANT_RETRIES {
				return 0, pgerr.Net_Error{type = .Timeout}
			}
			time.sleep(time.Millisecond)
			continue
		} else if status == errSSLClosedGraceful || status == errSSLClosedAbort {
			return 0, pgerr.Net_Error{type = .Socket_Closed}
		} else {
			return 0, pgerr.Net_Error{type = .Recv_Failed, code = i32(status)}
		}
	}
}

sec_trans_write :: proc(transport: rawptr, data_bytes: []byte) -> (bytes_written: int, err: pgerr.Error) {
	data := (^TLS_Transport_Data)(transport)
	total := 0
	retries := 0
	start := time.now()

	// SSLWrite's "processed" count is what it encrypted into its own buffer,
	// not what reached the socket. When it also reports errSSLWouldBlock those
	// bytes are already committed, so handing them to SSLWrite again would put
	// them on the wire twice. They are tracked here and drained by a
	// zero-length SSLWrite, which flushes without queueing anything new.
	pending := 0

	for total < len(data_bytes) || pending > 0 {
		processed: c.size_t = 0
		status: c.int

		if pending > 0 {
			status = sec_trans.SSLWrite(data.secure_transport, nil, 0, &processed)
			if status == noErr {
				total += pending
				pending = 0
				retries = 0
				continue
			}
		} else {
			remaining := data_bytes[total:]
			status = sec_trans.SSLWrite(data.secure_transport, raw_data(remaining), c.size_t(len(remaining)), &processed)
			if status == noErr {
				// SSLWrite reporting success without consuming anything would
				// leave the loop state unchanged and spin at full tilt; treat
				// it as the contract violation it is.
				if processed == 0 {
					return total, pgerr.Net_Error{type = .Send_Failed}
				}
				total += int(processed)
				retries = 0
				continue
			}
			if status == errSSLWouldBlock {
				pending = int(processed)
			}
		}

		if status == errSSLWouldBlock {
			// See sec_trans_read: a send deadline surfaces as would-block.
			if tls_deadline_exceeded(start, data.write_timeout) {
				return total, pgerr.Net_Error{type = .Timeout}
			}
			retries += 1
			if retries > TLS_MAX_WANT_RETRIES {
				return total, pgerr.Net_Error{type = .Timeout}
			}
			time.sleep(time.Millisecond)
			continue
		} else if status == errSSLClosedGraceful || status == errSSLClosedAbort {
			return total, pgerr.Net_Error{type = .Socket_Closed}
		} else {
			return total, pgerr.Net_Error{type = .Send_Failed, code = i32(status)}
		}
	}
	return total, nil
}

sec_trans_close :: proc(transport: rawptr) {
	data := (^TLS_Transport_Data)(transport)
	if data.secure_transport != nil {
		_ = sec_trans.SSLClose(data.secure_transport)
		sec_trans.CFRelease(data.secure_transport)
		data.secure_transport = nil
	}
	net.close(data.socket)
}

sec_trans_set_deadlines :: proc(transport: rawptr, read_timeout, write_timeout: time.Duration) -> pgerr.Error {
	data := (^TLS_Transport_Data)(transport)
	data.read_timeout = read_timeout
	data.write_timeout = write_timeout
	return apply_socket_deadlines(data.socket, read_timeout, write_timeout)
}
