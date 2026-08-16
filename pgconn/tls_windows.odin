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
SEC_I_CONTEXT_EXPIRED       :: 0x00090317 // Peer sent close_notify: clean EOF
SEC_I_INCOMPLETE_CREDENTIALS:: 0x00090320
SEC_I_RENEGOTIATE           :: 0x00090321
SEC_E_INCOMPLETE_MESSAGE    :: i32(-2146893032) // 0x80090318

// Ceiling on ciphertext buffered while assembling one handshake or record.
// A TLS record caps at 16 KiB of payload plus expansion, but a handshake
// message (a long certificate chain) may span several records and must be
// held whole; 1 MiB is far above any real chain and still bounds a server
// that never stops sending.
SCHANNEL_MAX_BUFFER :: 1 << 20
// Size of a single socket read. One max-size record fits without regrowing.
SCHANNEL_READ_CHUNK :: 17 * 1024

ISC_REQ_SEQUENCE_DETECT        :: 0x00000008
ISC_REQ_REPLAY_DETECT          :: 0x00000004
ISC_REQ_CONFIDENTIALITY        :: 0x00000010
ISC_REQ_ALLOCATE_MEMORY        :: 0x00000100
// ISC_REQ_DATAGRAM selects DTLS and ISC_REQ_STREAM selects TLS. Both are
// listed, in their sspi.h order, because ISC_REQ_STREAM was once transcribed
// as 0x00000400 — the value belonging to ISC_REQ_DATAGRAM two entries above
// it. Schannel honoured the request and emitted a DTLS ClientHello (version
// 0xFEFD) over TCP, which PostgreSQL closed the connection on; no SSPI call
// reported an error anywhere along the way.
ISC_REQ_DATAGRAM               :: 0x00000400
ISC_REQ_CONNECTION             :: 0x00000800
ISC_REQ_STREAM                 :: 0x00008000
ISC_REQ_MANUAL_CRED_VALIDATION :: 0x00080000

/*
	SCHANNEL_REQ_FLAGS is the context request passed to
	InitializeSecurityContext for every connection.

	Named rather than assembled inline because this flag set decides which
	protocol Schannel speaks, and a wrong bit here does not fail at the API
	level: every SSPI call still returns success. One auditable value gives the
	tests something to assert against.
*/
SCHANNEL_REQ_FLAGS: c.ulong :
	ISC_REQ_SEQUENCE_DETECT |
	ISC_REQ_REPLAY_DETECT |
	ISC_REQ_CONFIDENTIALITY |
	ISC_REQ_ALLOCATE_MEMORY |
	ISC_REQ_STREAM |
	ISC_REQ_MANUAL_CRED_VALIDATION

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
	FreeContextBuffer:          proc "stdcall" (pvContextBuffer: rawptr) -> c.long,
}

schannel: Schannel_API
SCHANNEL_SYMBOL_COUNT :: 8

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

	req_flags := SCHANNEL_REQ_FLAGS
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
		schannel.FreeContextBuffer(out_buf.pvBuffer)
		if serr != .None {
			schannel.DeleteSecurityContext(&ctxt)
			schannel.FreeCredentialsHandle(&cred)
			return {}, map_send_error(serr)
		}
	}

	// Server tokens accumulate here. Whatever is still unconsumed when the
	// handshake completes is the first application ciphertext, so the read
	// path inherits this buffer rather than copying out of a local one.
	data.schannel_enc = make([dynamic]byte, 0, SCHANNEL_READ_CHUNK, context.allocator)

	handshake_failed :: proc(
		data: ^TLS_Transport_Data,
		ctxt: ^CtxtHandle,
		cred: ^CredHandle,
		err: pgerr.Error,
	) -> pgerr.Error {
		schannel.DeleteSecurityContext(ctxt)
		schannel.FreeCredentialsHandle(cred)
		delete(data.schannel_enc)
		data.schannel_enc = nil
		return err
	}

	need_more_data := true

	for {
		if need_more_data {
			if len(data.schannel_enc) > SCHANNEL_MAX_BUFFER {
				return {}, handshake_failed(data, &ctxt, &cred,
					pgerr.Net_Error{type = .TLS_Handshake_Failed})
			}

			chunk: [SCHANNEL_READ_CHUNK]byte
			n, rerr := net.recv_tcp(socket, chunk[:])
			if rerr != .None {
				return {}, handshake_failed(data, &ctxt, &cred, map_recv_error(rerr))
			}
			if n == 0 {
				return {}, handshake_failed(data, &ctxt, &cred,
					pgerr.Net_Error{type = .Socket_Closed})
			}
			append(&data.schannel_enc, ..chunk[:n])
		}

		in_bufs: [2]SecBuffer
		in_bufs[0] = SecBuffer{cbBuffer = c.ulong(len(data.schannel_enc)), BufferType = SECBUFFER_TOKEN, pvBuffer = raw_data(data.schannel_enc[:])}
		in_bufs[1] = SecBuffer{cbBuffer = 0, BufferType = SECBUFFER_EMPTY, pvBuffer = nil}
		in_desc: SecBufferDesc = {ulVersion = SECBUFFER_VERSION, cBuffers = 2, pBuffers = &in_bufs[0]}

		out_buf = SecBuffer{cbBuffer = 0, BufferType = SECBUFFER_TOKEN, pvBuffer = nil}
		out_desc = SecBufferDesc{ulVersion = SECBUFFER_VERSION, cBuffers = 1, pBuffers = &out_buf}

		status = schannel.InitializeSecurityContextA(
			&cred, &ctxt, target_c, req_flags, 0, 0,
			&in_desc, 0, &ctxt, &out_desc, &attrs, nil,
		)

		// A record split across TCP segments: keep what arrived and read the
		// rest. This must not fall through to the status checks below, which
		// would abandon a handshake that is merely incomplete.
		if status == SEC_E_INCOMPLETE_MESSAGE {
			need_more_data = true
			continue
		}

		if out_buf.cbBuffer > 0 && out_buf.pvBuffer != nil {
			token_bytes := ([^]byte)(out_buf.pvBuffer)[:out_buf.cbBuffer]
			_, serr := net.send_tcp(socket, token_bytes)
			// ISC_REQ_ALLOCATE_MEMORY makes each token Schannel's allocation.
			schannel.FreeContextBuffer(out_buf.pvBuffer)
			if serr != .None {
				return {}, handshake_failed(data, &ctxt, &cred, map_send_error(serr))
			}
		}

		if status != SEC_E_OK &&
		   status != SEC_I_CONTINUE_NEEDED &&
		   status != SEC_I_COMPLETE_NEEDED &&
		   status != SEC_I_COMPLETE_AND_CONTINUE {
			return {}, handshake_failed(data, &ctxt, &cred,
				pgerr.Net_Error{type = .TLS_Handshake_Failed, code = i32(status)})
		}

		// Bytes past the end of the token Schannel consumed. On completion
		// these are application data; mid-handshake they are the next token,
		// already in hand, so another read would block waiting for bytes the
		// server has finished sending.
		supplied := len(data.schannel_enc)
		extra := 0
		if in_bufs[1].BufferType == SECBUFFER_EXTRA {
			extra = int(in_bufs[1].cbBuffer)
		}
		tls_retain_tail(&data.schannel_enc, extra)

		if status == SEC_E_OK do break

		// Re-running over a buffer nothing was consumed from would spin without
		// touching the socket, so treat "no progress" as needing more input.
		need_more_data = extra == 0 || extra >= supplied
	}

	// Query stream sizes for framing
	sizes: SecPkgContext_StreamSizes
	sz_ret := schannel.QueryContextAttributesA(&ctxt, SECPKG_ATTR_STREAM_SIZES, &sizes)
	if sz_ret != SEC_E_OK {
		return {}, handshake_failed(data, &ctxt, &cred,
			pgerr.Net_Error{type = .TLS_Handshake_Failed, code = i32(sz_ret)})
	}

	// Bound to the connection allocator here rather than on first append, so
	// the buffer never inherits whatever short-lived allocator happens to be
	// installed during a read.
	data.schannel_buf = make([dynamic]byte, 0, 0, context.allocator)

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

	for {
		// Decrypt what is already held before going back to the socket. The
		// buffer routinely carries a whole record left over from an earlier
		// read, and reading first would block on a server with nothing more
		// to send until we consume what it already sent.
		supplied := len(data.schannel_enc)
		if supplied > 0 {
			bufs: [4]SecBuffer
			bufs[0] = SecBuffer{cbBuffer = c.ulong(len(data.schannel_enc)), BufferType = SECBUFFER_DATA, pvBuffer = raw_data(data.schannel_enc[:])}
			bufs[1] = SecBuffer{BufferType = SECBUFFER_EMPTY}
			bufs[2] = SecBuffer{BufferType = SECBUFFER_EMPTY}
			bufs[3] = SecBuffer{BufferType = SECBUFFER_EMPTY}
			desc := SecBufferDesc{ulVersion = SECBUFFER_VERSION, cBuffers = 4, pBuffers = &bufs[0]}

			status := schannel.DecryptMessage(&ctxt, &desc, 0, nil)

			switch status {
			case SEC_E_OK:
				// DecryptMessage rewrites in place, so both the plaintext and
				// the leftover ciphertext point into schannel_enc. Copy the
				// plaintext out before compacting, or compaction overwrites it.
				extra := 0
				copied := 0
				for i in 0 ..< 4 {
					switch bufs[i].BufferType {
					case SECBUFFER_DATA:
						if bufs[i].cbBuffer == 0 do continue
						dec := ([^]byte)(bufs[i].pvBuffer)[:bufs[i].cbBuffer]
						copied = min(len(buf), len(dec))
						copy(buf[:copied], dec[:copied])
						if copied < len(dec) {
							append(&data.schannel_buf, ..dec[copied:])
						}
					case SECBUFFER_EXTRA:
						extra = int(bufs[i].cbBuffer)
					}
				}

				tls_retain_tail(&data.schannel_enc, extra)

				// A record carrying no application data decrypts to nothing;
				// keep going rather than reporting a zero-length read as end
				// of stream. (Under TLS 1.3 Schannel reports post-handshake
				// messages as SEC_I_RENEGOTIATE instead — see below.)
				if copied > 0 do return copied, nil
				// Unless nothing was consumed either — re-decrypting the same
				// bytes would spin, so read more instead.
				if extra < supplied do continue

			case SEC_I_CONTEXT_EXPIRED:
				// Peer sent close_notify. An orderly end of stream, not a fault.
				clear(&data.schannel_enc)
				return 0, pgerr.Net_Error{type = .Socket_Closed}

			case SEC_I_RENEGOTIATE:
				// KNOWN LIMITATION, and the most likely reason Windows TLS
				// fails against a modern server: Schannel reports TLS 1.3
				// post-handshake messages this way, and PostgreSQL built on
				// OpenSSL 1.1.1+ sends a NewSessionTicket right after the
				// handshake — so this can fire on the very first read.
				//
				// Handling it means re-driving InitializeSecurityContext (with
				// no input buffer first, per SSPI) over the bytes still in
				// schannel_enc, then resuming. Deliberately not compacting the
				// buffer here leaves those bytes intact for that fix.
				//
				// Reporting it is still better than the alternative: treating
				// a handshake token as application data corrupts the stream
				// silently, whereas this fails loudly with the status code.
				return 0, pgerr.Net_Error{type = .TLS_Handshake_Failed, code = i32(status)}

			case SEC_E_INCOMPLETE_MESSAGE:
				// Partial record: fall through and read the remainder.

			case:
				return 0, pgerr.Net_Error{type = .Recv_Failed, code = i32(status)}
			}
		}

		if len(data.schannel_enc) > SCHANNEL_MAX_BUFFER {
			return 0, pgerr.Net_Error{type = .Recv_Failed}
		}

		chunk: [SCHANNEL_READ_CHUNK]byte
		n, rerr := net.recv_tcp(data.socket, chunk[:])
		if rerr != .None do return 0, map_recv_error(rerr)
		if n == 0 do return 0, pgerr.Net_Error{type = .Socket_Closed}
		append(&data.schannel_enc, ..chunk[:n])
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
	if data.schannel_enc != nil {
		delete(data.schannel_enc)
		data.schannel_enc = nil
	}
	net.close(data.socket)
}

schannel_set_deadlines :: proc(transport: rawptr, read_timeout, write_timeout: time.Duration) -> pgerr.Error {
	data := (^TLS_Transport_Data)(transport)
	data.read_timeout = read_timeout
	data.write_timeout = write_timeout
	return apply_socket_deadlines(data.socket, read_timeout, write_timeout)
}
