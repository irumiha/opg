package pgconn

when ODIN_OS == .Darwin {

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
	SSLSetIOFuncs:        proc "c" (context: rawptr, readFunc: SSLReadFunc, writeFunc: SSLWriteFunc) -> c.int,
	SSLSetConnection:     proc "c" (context: rawptr, connection: rawptr) -> c.int,
	SSLSetPeerDomainName: proc "c" (context: rawptr, peerName: cstring, peerNameLen: c.size_t) -> c.int,
	SSLSetSessionOption:  proc "c" (context: rawptr, option: c.int, value: bool) -> c.int,
	SSLHandshake:         proc "c" (context: rawptr) -> c.int,
	SSLRead:              proc "c" (context: rawptr, data: rawptr, dataLength: c.size_t, processed: ^c.size_t) -> c.int,
	SSLWrite:             proc "c" (context: rawptr, data: rawptr, dataLength: c.size_t, processed: ^c.size_t) -> c.int,
	SSLClose:             proc "c" (context: rawptr) -> c.int,
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
SEC_TRANS_SYMBOL_COUNT :: 10

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
	sock := net.TCP_Socket(uintptr(connection))
	wanted := int(dataLength^)
	if wanted == 0 {
		return noErr
	}
	buf := ([^]byte)(data)[:wanted]
	n, rerr := net.recv_tcp(sock, buf)
	if rerr != .None {
		#partial switch rerr {
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
	sock := net.TCP_Socket(uintptr(connection))
	to_send := int(dataLength^)
	if to_send == 0 {
		return noErr
	}
	buf := ([^]byte)(data)[:to_send]
	n, serr := net.send_tcp(sock, buf)
	if serr != .None {
		#partial switch serr {
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
	dataLength^ = c.size_t(n)
	if n < to_send {
		return errSSLWouldBlock
	}
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

	for {
		status := sec_trans.SSLHandshake(ctx)
		if status == noErr {
			break
		} else if status == errSSLWouldBlock {
			time.sleep(time.Millisecond)
			continue
		} else if status == errSSLServerAuthCompleted {
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

sec_trans_read :: proc(transport: rawptr, buf: []byte) -> (bytes_read: int, err: pgerr.Error) {
	data := (^TLS_Transport_Data)(transport)
	if len(buf) == 0 do return 0, nil
	processed: c.size_t = 0
	retries := 0
	for {
		status := sec_trans.SSLRead(data.secure_transport, raw_data(buf), c.size_t(len(buf)), &processed)
		if processed > 0 {
			return int(processed), nil
		}
		if status == noErr {
			return int(processed), nil
		} else if status == errSSLWouldBlock {
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
	for total < len(data_bytes) {
		remaining := data_bytes[total:]
		processed: c.size_t = 0
		status := sec_trans.SSLWrite(data.secure_transport, raw_data(remaining), c.size_t(len(remaining)), &processed)
		if processed > 0 {
			total += int(processed)
			retries = 0
			continue
		}
		if status == errSSLWouldBlock {
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
	return nil
}

} // when ODIN_OS == .Darwin
