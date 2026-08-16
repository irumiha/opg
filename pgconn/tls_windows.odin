package pgconn

import "core:c"
import "core:dynlib"
import "core:net"
import "core:strings"
import "core:time"
import "../pgerr"

// ============================================================================
// Windows Schannel TLS Backend (SSPI via secur32.dll / sspicli.dll)
// ============================================================================

SecHandle :: struct {
	dwLower: uintptr,
	dwUpper: uintptr,
}
CredHandle :: SecHandle
CtxtHandle :: SecHandle

SecBuffer :: struct {
	cbBuffer:   c.ulong,
	BufferType: c.ulong,
	pvBuffer:   rawptr,
}

SecBufferDesc :: struct {
	ulVersion: c.ulong,
	cBuffers:  c.ulong,
	pBuffers:  ^SecBuffer,
}

SCHANNEL_CRED :: struct {
	dwVersion:               c.ulong,
	cCreds:                  c.ulong,
	paCred:                  rawptr,
	hRootStore:              rawptr,
	cMappers:                c.ulong,
	aphMappers:              rawptr,
	cSupportedAlgs:          c.ulong,
	palgSupportedAlgs:       rawptr,
	grbitEnabledProtocols:   c.ulong,
	dwMinimumCipherStrength: c.ulong,
	dwMaximumCipherStrength: c.ulong,
	dwSessionLifespan:       c.ulong,
	dwFlags:                 c.ulong,
	dwCredFormat:            c.ulong,
}

SecPkgContext_StreamSizes :: struct {
	cbHeader:         c.ulong,
	cbTrailer:        c.ulong,
	cbMaximumMessage: c.ulong,
	cBuffers:         c.ulong,
	cbBlockSize:      c.ulong,
}

SCHANNEL_CRED_VERSION :: 4
SCH_CRED_NO_DEFAULT_CREDS           :: 0x00000010
SCH_CRED_MANUAL_CRED_VALIDATION     :: 0x00000008
SCH_CRED_IGNORE_NO_REVOCATION_CHECK :: 0x00000800
SCH_CRED_IGNORE_REVOCATION_OFFLINE  :: 0x00001000

SECBUFFER_VERSION        :: 0
SECBUFFER_EMPTY          :: 0
SECBUFFER_DATA           :: 1
SECBUFFER_TOKEN          :: 2
SECBUFFER_EXTRA          :: 5
SECBUFFER_STREAM_TRAILER :: 6
SECBUFFER_STREAM_HEADER  :: 7

SECPKG_CRED_OUTBOUND     :: 2
SECPKG_ATTR_STREAM_SIZES :: 4

SEC_E_OK                    :: 0x00000000
SEC_I_CONTINUE_NEEDED       :: 0x00090312
SEC_I_COMPLETE_NEEDED       :: 0x00090313
SEC_I_COMPLETE_AND_CONTINUE :: 0x00090314
SEC_I_INCOMPLETE_CREDENTIALS:: 0x00090320
SEC_E_INCOMPLETE_MESSAGE    :: i32(-2146893032) // 0x80090318

ISC_REQ_SEQUENCE_DETECT        :: 0x00000008
ISC_REQ_REPLAY_DETECT          :: 0x00000004
ISC_REQ_CONFIDENTIALITY        :: 0x00000010
ISC_REQ_ALLOCATE_MEMORY        :: 0x00000100
ISC_REQ_STREAM                 :: 0x00000400
ISC_REQ_MANUAL_CRED_VALIDATION :: 0x00080000

Schannel_API :: struct {
	__handle:                   dynlib.Library,
	AcquireCredentialsHandleA:  proc "stdcall" (
		pszPrincipal:   cstring,
		pszPackage:     cstring,
		fCredentialUse: c.ulong,
		pvLogonID:      rawptr,
		pAuthData:      rawptr,
		pGetKeyFn:      rawptr,
		pvGetKeyArgument: rawptr,
		phCredential:   ^CredHandle,
		ptsExpiry:      rawptr,
	) -> c.long,
	FreeCredentialsHandle:      proc "stdcall" (phCredential: ^CredHandle) -> c.long,
	InitializeSecurityContextA: proc "stdcall" (
		phCredential:   ^CredHandle,
		phContext:      ^CtxtHandle,
		pszTargetName:  cstring,
		fContextReq:    c.ulong,
		Reserved1:      c.ulong,
		TargetDataRep:  c.ulong,
		pInput:         ^SecBufferDesc,
		Reserved2:      c.ulong,
		phNewContext:   ^CtxtHandle,
		pOutput:        ^SecBufferDesc,
		pfContextAttr:  ^c.ulong,
		ptsExpiry:      rawptr,
	) -> c.long,
	DeleteSecurityContext:      proc "stdcall" (phContext: ^CtxtHandle) -> c.long,
	EncryptMessage:             proc "stdcall" (phContext: ^CtxtHandle, fQOP: c.ulong, pMessage: ^SecBufferDesc, MessageSeqNo: c.ulong) -> c.long,
	DecryptMessage:             proc "stdcall" (phContext: ^CtxtHandle, pMessage: ^SecBufferDesc, MessageSeqNo: c.ulong, pfQOP: ^c.ulong) -> c.long,
	QueryContextAttributesA:    proc "stdcall" (phContext: ^CtxtHandle, ulAttribute: c.ulong, pBuffer: rawptr) -> c.long,
}

schannel: Schannel_API
SCHANNEL_SYMBOL_COUNT :: 7

schannel_probe :: proc() -> bool {
	if schannel.__handle != nil && schannel.EncryptMessage != nil {
		return true
	}
	paths := []string{"secur32.dll", "sspicli.dll"}
	for p in paths {
		count, ok := dynlib.initialize_symbols(&schannel, p)
		if ok && count == SCHANNEL_SYMBOL_COUNT {
			return true
		}
		if ok {
			_ = dynlib.unload_library(schannel.__handle)
			schannel = {}
		}
	}
	return false
}

make_schannel_transport :: proc(
	data: ^TLS_Transport_Data,
	socket: net.TCP_Socket,
	server_name: string,
) -> (
	transport: Stream_Transport,
	err: pgerr.Error,
) {
	cred: CredHandle
	ctxt: CtxtHandle

	s_cred: SCHANNEL_CRED
	s_cred.dwVersion = SCHANNEL_CRED_VERSION
	s_cred.dwFlags = SCH_CRED_NO_DEFAULT_CREDS | SCH_CRED_MANUAL_CRED_VALIDATION | SCH_CRED_IGNORE_NO_REVOCATION_CHECK | SCH_CRED_IGNORE_REVOCATION_OFFLINE

	pkg_name := cstring("Schannel")
	ret := schannel.AcquireCredentialsHandleA(nil, pkg_name, SECPKG_CRED_OUTBOUND, nil, &s_cred, nil, nil, &cred, nil)
	if ret != SEC_E_OK {
		return {}, pgerr.Net_Error{type = .TLS_Handshake_Failed, code = i32(ret)}
	}

	target_c: cstring = nil
	if len(server_name) > 0 {
		target_c = strings.clone_to_cstring(server_name, context.temp_allocator)
	}

	req_flags: c.ulong = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT | ISC_REQ_CONFIDENTIALITY | ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM | ISC_REQ_MANUAL_CRED_VALIDATION
	out_buf: SecBuffer = {cbBuffer = 0, BufferType = SECBUFFER_TOKEN, pvBuffer = nil}
	out_desc: SecBufferDesc = {ulVersion = SECBUFFER_VERSION, cBuffers = 1, pBuffers = &out_buf}
	attrs: c.ulong = 0

	status := schannel.InitializeSecurityContextA(
		&cred, nil, target_c, req_flags, 0, 0,
		nil, 0, &ctxt, &out_desc, &attrs, nil,
	)

	if status != SEC_I_CONTINUE_NEEDED && status != SEC_E_OK {
		schannel.FreeCredentialsHandle(&cred)
		return {}, pgerr.Net_Error{type = .TLS_Handshake_Failed, code = i32(status)}
	}

	// Send initial client token
	if out_buf.cbBuffer > 0 && out_buf.pvBuffer != nil {
		token_bytes := ([^]byte)(out_buf.pvBuffer)[:out_buf.cbBuffer]
		_, serr := net.send_tcp(socket, token_bytes)
		if serr != .None {
			schannel.DeleteSecurityContext(&ctxt)
			schannel.FreeCredentialsHandle(&cred)
			return {}, map_send_error(serr)
		}
	}

	recv_buf: [16384]byte
	recv_len := 0

	for status == SEC_I_CONTINUE_NEEDED || status == SEC_I_COMPLETE_NEEDED || status == SEC_I_COMPLETE_AND_CONTINUE {
		n, rerr := net.recv_tcp(socket, recv_buf[recv_len:])
		if rerr != .None {
			schannel.DeleteSecurityContext(&ctxt)
			schannel.FreeCredentialsHandle(&cred)
			return {}, map_recv_error(rerr)
		}
		if n == 0 {
			schannel.DeleteSecurityContext(&ctxt)
			schannel.FreeCredentialsHandle(&cred)
			return {}, pgerr.Net_Error{type = .Socket_Closed}
		}
		recv_len += n

		in_bufs: [2]SecBuffer
		in_bufs[0] = SecBuffer{cbBuffer = c.ulong(recv_len), BufferType = SECBUFFER_TOKEN, pvBuffer = raw_data(recv_buf[:])}
		in_bufs[1] = SecBuffer{cbBuffer = 0, BufferType = SECBUFFER_EMPTY, pvBuffer = nil}
		in_desc: SecBufferDesc = {ulVersion = SECBUFFER_VERSION, cBuffers = 2, pBuffers = &in_bufs[0]}

		out_buf = SecBuffer{cbBuffer = 0, BufferType = SECBUFFER_TOKEN, pvBuffer = nil}
		out_desc = SecBufferDesc{ulVersion = SECBUFFER_VERSION, cBuffers = 1, pBuffers = &out_buf}

		status = schannel.InitializeSecurityContextA(
			&cred, &ctxt, target_c, req_flags, 0, 0,
			&in_desc, 0, &ctxt, &out_desc, &attrs, nil,
		)

		if status == SEC_E_INCOMPLETE_MESSAGE {
			continue // Need more bytes from server
		}

		if out_buf.cbBuffer > 0 && out_buf.pvBuffer != nil {
			token_bytes := ([^]byte)(out_buf.pvBuffer)[:out_buf.cbBuffer]
			_, serr := net.send_tcp(socket, token_bytes)
			if serr != .None {
				schannel.DeleteSecurityContext(&ctxt)
				schannel.FreeCredentialsHandle(&cred)
				return {}, map_send_error(serr)
			}
		}

		if status == SEC_E_OK {
			// Handle any extra bytes left over from handshake
			if in_bufs[1].BufferType == SECBUFFER_EXTRA && in_bufs[1].cbBuffer > 0 {
				extra_start := recv_len - int(in_bufs[1].cbBuffer)
				data.schannel_buf = make([dynamic]byte, 0, in_bufs[1].cbBuffer)
				append(&data.schannel_buf, ..recv_buf[extra_start:recv_len])
			}
			break
		}

		if status != SEC_I_CONTINUE_NEEDED && status != SEC_I_COMPLETE_NEEDED && status != SEC_I_COMPLETE_AND_CONTINUE {
			schannel.DeleteSecurityContext(&ctxt)
			schannel.FreeCredentialsHandle(&cred)
			return {}, pgerr.Net_Error{type = .TLS_Handshake_Failed, code = i32(status)}
		}

		recv_len = 0
	}

	// Query stream sizes for framing
	sizes: SecPkgContext_StreamSizes
	sz_ret := schannel.QueryContextAttributesA(&ctxt, SECPKG_ATTR_STREAM_SIZES, &sizes)
	if sz_ret != SEC_E_OK {
		schannel.DeleteSecurityContext(&ctxt)
		schannel.FreeCredentialsHandle(&cred)
		return {}, pgerr.Net_Error{type = .TLS_Handshake_Failed, code = i32(sz_ret)}
	}

	data.backend = .Schannel
	data.socket = socket
	data.schannel_cred = [2]uintptr{cred.dwLower, cred.dwUpper}
	data.schannel_ctxt = [2]uintptr{ctxt.dwLower, ctxt.dwUpper}
	data.schannel_header = u32(sizes.cbHeader)
	data.schannel_trailer = u32(sizes.cbTrailer)
	data.schannel_max_msg = u32(sizes.cbMaximumMessage)

	return Stream_Transport{
		data = data,
		read = schannel_read,
		write = schannel_write,
		close = schannel_close,
		set_deadlines = schannel_set_deadlines,
	}, nil
}

schannel_read :: proc(transport: rawptr, buf: []byte) -> (bytes_read: int, err: pgerr.Error) {
	data := (^TLS_Transport_Data)(transport)
	if len(buf) == 0 do return 0, nil

	// Drain any previously decrypted data
	if len(data.schannel_buf) > 0 {
		n := min(len(buf), len(data.schannel_buf))
		copy(buf[:n], data.schannel_buf[:n])
		if n == len(data.schannel_buf) {
			clear(&data.schannel_buf)
		} else {
			copy(data.schannel_buf[:], data.schannel_buf[n:])
			resize(&data.schannel_buf, len(data.schannel_buf) - n)
		}
		return n, nil
	}

	ctxt := CtxtHandle{dwLower = data.schannel_ctxt[0], dwUpper = data.schannel_ctxt[1]}
	recv_buf: [32768]byte
	recv_len := 0

	for {
		n, rerr := net.recv_tcp(data.socket, recv_buf[recv_len:])
		if rerr != .None do return 0, map_recv_error(rerr)
		if n == 0 do return 0, pgerr.Net_Error{type = .Socket_Closed}
		recv_len += n

		bufs: [4]SecBuffer
		bufs[0] = SecBuffer{cbBuffer = c.ulong(recv_len), BufferType = SECBUFFER_DATA, pvBuffer = raw_data(recv_buf[:])}
		bufs[1] = SecBuffer{BufferType = SECBUFFER_EMPTY}
		bufs[2] = SecBuffer{BufferType = SECBUFFER_EMPTY}
		bufs[3] = SecBuffer{BufferType = SECBUFFER_EMPTY}
		desc := SecBufferDesc{ulVersion = SECBUFFER_VERSION, cBuffers = 4, pBuffers = &bufs[0]}

		status := schannel.DecryptMessage(&ctxt, &desc, 0, nil)
		if status == SEC_E_INCOMPLETE_MESSAGE {
			continue
		}
		if status != SEC_E_OK {
			return 0, pgerr.Net_Error{type = .Recv_Failed, code = i32(status)}
		}

		// Find decrypted data buffer
		for i in 0 ..< 4 {
			if bufs[i].BufferType == SECBUFFER_DATA && bufs[i].cbBuffer > 0 {
				dec_bytes := ([^]byte)(bufs[i].pvBuffer)[:bufs[i].cbBuffer]
				copied := min(len(buf), len(dec_bytes))
				copy(buf[:copied], dec_bytes[:copied])

				if copied < len(dec_bytes) {
					if data.schannel_buf == nil {
						data.schannel_buf = make([dynamic]byte, 0, len(dec_bytes) - copied)
					}
					append(&data.schannel_buf, ..dec_bytes[copied:])
				}
				return copied, nil
			}
		}

		// Empty decrypted message; loop for more
		recv_len = 0
	}
}

schannel_write :: proc(transport: rawptr, data_bytes: []byte) -> (bytes_written: int, err: pgerr.Error) {
	data := (^TLS_Transport_Data)(transport)
	ctxt := CtxtHandle{dwLower = data.schannel_ctxt[0], dwUpper = data.schannel_ctxt[1]}

	header_len := int(data.schannel_header)
	trailer_len := int(data.schannel_trailer)
	max_chunk := int(data.schannel_max_msg > 0 ? data.schannel_max_msg : 16384)

	total_written := 0
	for total_written < len(data_bytes) {
		chunk_len := min(len(data_bytes) - total_written, max_chunk)
		msg_buf := make([]byte, header_len + chunk_len + trailer_len, context.temp_allocator)
		defer delete(msg_buf, context.temp_allocator)

		copy(msg_buf[header_len:], data_bytes[total_written : total_written + chunk_len])

		bufs: [4]SecBuffer
		bufs[0] = SecBuffer{cbBuffer = c.ulong(header_len), BufferType = SECBUFFER_STREAM_HEADER, pvBuffer = raw_data(msg_buf[0:header_len])}
		bufs[1] = SecBuffer{cbBuffer = c.ulong(chunk_len), BufferType = SECBUFFER_DATA, pvBuffer = raw_data(msg_buf[header_len : header_len + chunk_len])}
		bufs[2] = SecBuffer{cbBuffer = c.ulong(trailer_len), BufferType = SECBUFFER_STREAM_TRAILER, pvBuffer = raw_data(msg_buf[header_len + chunk_len:])}
		bufs[3] = SecBuffer{BufferType = SECBUFFER_EMPTY}
		desc := SecBufferDesc{ulVersion = SECBUFFER_VERSION, cBuffers = 4, pBuffers = &bufs[0]}

		status := schannel.EncryptMessage(&ctxt, 0, &desc, 0)
		if status != SEC_E_OK {
			return total_written, pgerr.Net_Error{type = .Send_Failed, code = i32(status)}
		}

		send_len := int(bufs[0].cbBuffer + bufs[1].cbBuffer + bufs[2].cbBuffer)
		_, serr := net.send_tcp(data.socket, msg_buf[:send_len])
		if serr != .None {
			return total_written, map_send_error(serr)
		}

		total_written += chunk_len
	}

	return total_written, nil
}

schannel_close :: proc(transport: rawptr) {
	data := (^TLS_Transport_Data)(transport)
	ctxt := CtxtHandle{dwLower = data.schannel_ctxt[0], dwUpper = data.schannel_ctxt[1]}
	cred := CredHandle{dwLower = data.schannel_cred[0], dwUpper = data.schannel_cred[1]}

	if ctxt.dwLower != 0 || ctxt.dwUpper != 0 {
		_ = schannel.DeleteSecurityContext(&ctxt)
		data.schannel_ctxt = {}
	}
	if cred.dwLower != 0 || cred.dwUpper != 0 {
		_ = schannel.FreeCredentialsHandle(&cred)
		data.schannel_cred = {}
	}
	if data.schannel_buf != nil {
		delete(data.schannel_buf)
		data.schannel_buf = nil
	}
	net.close(data.socket)
}

schannel_set_deadlines :: proc(transport: rawptr, read_timeout, write_timeout: time.Duration) -> pgerr.Error {
	data := (^TLS_Transport_Data)(transport)
	data.read_timeout = read_timeout
	data.write_timeout = write_timeout
	return nil
}
