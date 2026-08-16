package win_tls_probe

/*
	Windows Schannel diagnostic.

	Every connect on the Windows CI runner fails with
	Net_Error{Socket_Closed, raw=Connection_Closed}, while Linux and macOS pass
	against the same SSL-enabled server. There is no Windows machine to attach a
	debugger to, so this tool is the instrument: it runs on the runner and
	reports facts rather than reproducing the failure behind a test harness.

	It answers, in order, the questions that separate the candidate causes:

	  1. Did every Schannel symbol bind, and which DLL supplied them? A short
	     count silently deselects the native backend, and SCHANNEL_SYMBOL_COUNT
	     was recently raised 7 -> 8 for FreeContextBuffer.
	  2. Which backend did the probe actually choose?
	  3. Did the server answer 'S' to SSLRequest? That separates "TLS never
	     started" from "TLS started and failed".
	  4. What did the server send back after our ClientHello? A TLS alert names
	     the reason in two bytes; a ServerHello means we got further. Either way
	     the hex says which, and guessing stops.

	Usage, from the repository root:

	    odin run tools/win-tls-probe

	Honors the same PG* variables as the test harness.
*/

import "core:c"
import "core:dynlib"
import "core:fmt"
import "core:net"
import "core:os"
import "core:strconv"
import "core:strings"
import "core:time"
import pg "../../pgconn"

main :: proc() {
	when ODIN_OS == .Windows {
		run_windows()
	} else {
		fmt.println("win-tls-probe: Windows-only diagnostic; nothing to do on this platform.")
	}
}

env_or :: proc(name, fallback: string) -> string {
	if v := os.get_env(name, context.allocator); v != "" do return v
	return fallback
}

/*
	hexdump prints at most `limit` bytes. The first handful of bytes of a TLS
	record carry everything needed to classify it: content type, version, and
	length, then the alert or handshake code.
*/
hexdump :: proc(label: string, buf: []byte, limit := 64) {
	n := min(len(buf), limit)
	sb := strings.builder_make(context.temp_allocator)
	for b in buf[:n] {
		fmt.sbprintf(&sb, "%02x ", b)
	}
	fmt.printfln("    %s (%d bytes): %s%s", label, len(buf), strings.to_string(sb), len(buf) > n ? "..." : "")
	describe_tls_record(buf)
}

/*
	describe_tls_record decodes the record header so the log reads as a
	conclusion rather than as bytes to interpret later.
*/
describe_tls_record :: proc(buf: []byte) {
	if len(buf) < 5 do return

	version := fmt.tprintf("0x%02x%02x", buf[1], buf[2])
	length := int(buf[3]) << 8 | int(buf[4])

	switch buf[0] {
	case 0x16:
		kind := "unknown"
		if len(buf) >= 6 {
			switch buf[5] {
			case 1:  kind = "ClientHello"
			case 2:  kind = "ServerHello"
			case 11: kind = "Certificate"
			case 12: kind = "ServerKeyExchange"
			case 14: kind = "ServerHelloDone"
			}
		}
		fmt.printfln("      -> TLS handshake record, version %s, length %d, type %s", version, length, kind)
	case 0x15:
		fmt.printfln("      -> TLS ALERT record, version %s, length %d", version, length)
		if len(buf) >= 7 {
			level := buf[5] == 2 ? "fatal" : "warning"
			fmt.printfln("      -> alert %s(%d), description %d (%s)", level, buf[5], buf[6], alert_name(buf[6]))
		}
	case 0x17:
		fmt.printfln("      -> TLS application data, version %s, length %d", version, length)
	case:
		fmt.printfln("      -> non-TLS content type 0x%02x", buf[0])
	}
}

alert_name :: proc(code: byte) -> string {
	switch code {
	case 0:   return "close_notify"
	case 10:  return "unexpected_message"
	case 20:  return "bad_record_mac"
	case 40:  return "handshake_failure"
	case 42:  return "bad_certificate"
	case 47:  return "illegal_parameter"
	case 48:  return "unknown_ca"
	case 50:  return "decode_error"
	case 51:  return "decrypt_error"
	case 70:  return "protocol_version"
	case 71:  return "insufficient_security"
	case 80:  return "internal_error"
	case 109: return "missing_extension"
	case 112: return "unrecognized_name"
	case 116: return "certificate_required"
	}
	return "unrecognized"
}

when ODIN_OS == .Windows {

	// Mirrors the values the driver uses, kept local so this tool reports what
	// the handshake actually did rather than depending on it.
	PROBE_RECV_TIMEOUT :: 10 * time.Second

	run_windows :: proc() {
		fmt.println("=== win-tls-probe ===")
		fmt.printfln("odin os=%v arch=%v", ODIN_OS, ODIN_ARCH)

		step_1_symbols()
		step_2_backend()

		host := env_or("PGHOST", "127.0.0.1")
		port := 5432
		if v := os.get_env("PGPORT", context.allocator); v != "" {
			if p, ok := strconv.parse_int(v); ok do port = p
		}

		socket, ok := step_3_ssl_request(host, port)
		if !ok do return
		defer net.close(socket)

		step_4_handshake(socket, host)
	}

	// ------------------------------------------------------------------
	// 1. Symbol binding
	// ------------------------------------------------------------------
	step_1_symbols :: proc() {
		fmt.println("\n[1] Schannel symbol binding")
		fmt.printfln("    SCHANNEL_SYMBOL_COUNT expected by the driver: %d", pg.SCHANNEL_SYMBOL_COUNT)

		for path in ([]string{"secur32.dll", "sspicli.dll"}) {
			api: pg.Schannel_API
			count, loaded := dynlib.initialize_symbols(&api, path)
			fmt.printfln("    %s: loaded=%v bound=%d/%d", path, loaded, count, pg.SCHANNEL_SYMBOL_COUNT)
			if !loaded do continue

			// Name the missing symbol outright: a count alone does not say
			// which one, and the whole backend is deselected over any single
			// miss.
			report := proc(name: string, bound: bool) {
				fmt.printfln("      %-28s %s", name, bound ? "ok" : "MISSING")
			}
			report("AcquireCredentialsHandleA", api.AcquireCredentialsHandleA != nil)
			report("FreeCredentialsHandle", api.FreeCredentialsHandle != nil)
			report("InitializeSecurityContextA", api.InitializeSecurityContextA != nil)
			report("DeleteSecurityContext", api.DeleteSecurityContext != nil)
			report("EncryptMessage", api.EncryptMessage != nil)
			report("DecryptMessage", api.DecryptMessage != nil)
			report("QueryContextAttributesA", api.QueryContextAttributesA != nil)
			report("FreeContextBuffer", api.FreeContextBuffer != nil)

			if api.__handle != nil {
				_ = dynlib.unload_library(api.__handle)
			}
		}
	}

	// ------------------------------------------------------------------
	// 2. Backend selection
	// ------------------------------------------------------------------
	step_2_backend :: proc() {
		fmt.println("\n[2] Backend selection")
		fmt.printfln("    schannel_probe(): %v", pg.schannel_probe())
		fmt.printfln("    tls_backend_name(): %s", pg.tls_backend_name())
	}

	// ------------------------------------------------------------------
	// 3. SSLRequest negotiation, on a raw socket
	// ------------------------------------------------------------------
	step_3_ssl_request :: proc(host: string, port: int) -> (socket: net.TCP_Socket, ok: bool) {
		fmt.println("\n[3] SSLRequest negotiation")
		endpoint := fmt.tprintf("%s:%d", host, port)
		fmt.printfln("    dialing %s", endpoint)

		sock, derr := net.dial_tcp_from_hostname_and_port_string(endpoint)
		if derr != nil {
			fmt.printfln("    FAIL: dial error %v", derr)
			return {}, false
		}

		// Without this a server that simply stops talking hangs the probe, and
		// a hang reports nothing.
		if oerr := net.set_option(sock, .Receive_Timeout, PROBE_RECV_TIMEOUT); oerr != nil {
			fmt.printfln("    warning: could not set receive timeout: %v", oerr)
		}

		// SSLRequest: int32 length 8, int32 code 80877103.
		req := [8]byte{0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f}
		if _, serr := net.send_tcp(sock, req[:]); serr != .None {
			fmt.printfln("    FAIL: could not send SSLRequest: %v", serr)
			net.close(sock)
			return {}, false
		}

		answer: [1]byte
		n, rerr := net.recv_tcp(sock, answer[:])
		if rerr != .None {
			fmt.printfln("    FAIL: recv error %v", rerr)
			net.close(sock)
			return {}, false
		}
		if n != 1 {
			fmt.printfln("    FAIL: server closed without answering (n=%d)", n)
			net.close(sock)
			return {}, false
		}

		fmt.printfln("    server answered '%c' (0x%02x)", answer[0], answer[0])
		if answer[0] != 'S' {
			fmt.println("    -> server declined TLS; the Schannel path is never reached")
			net.close(sock)
			return {}, false
		}
		return sock, true
	}

	// ------------------------------------------------------------------
	// 4. Instrumented Schannel handshake
	// ------------------------------------------------------------------
	step_4_handshake :: proc(socket: net.TCP_Socket, server_name: string) {
		fmt.println("\n[4] Schannel handshake")

		if !pg.schannel_probe() {
			fmt.println("    SKIP: Schannel symbols unavailable")
			return
		}

		cred: pg.CredHandle
		ctxt: pg.CtxtHandle

		s_cred: pg.SCHANNEL_CRED
		s_cred.dwVersion = pg.SCHANNEL_CRED_VERSION
		s_cred.dwFlags =
			pg.SCH_CRED_NO_DEFAULT_CREDS |
			pg.SCH_CRED_MANUAL_CRED_VALIDATION |
			pg.SCH_CRED_IGNORE_NO_REVOCATION_CHECK |
			pg.SCH_CRED_IGNORE_REVOCATION_OFFLINE

		acq := pg.schannel.AcquireCredentialsHandleA(
			nil, cstring("Schannel"), pg.SECPKG_CRED_OUTBOUND, nil, &s_cred, nil, nil, &cred, nil,
		)
		fmt.printfln("    AcquireCredentialsHandleA -> 0x%08x", u32(acq))
		if acq != pg.SEC_E_OK {
			fmt.println("    FAIL: credential acquisition failed")
			return
		}
		defer pg.schannel.FreeCredentialsHandle(&cred)

		target_c: cstring = nil
		if len(server_name) > 0 {
			target_c = strings.clone_to_cstring(server_name, context.temp_allocator)
		}
		fmt.printfln("    target name: %q", server_name)

		req_flags: c.ulong =
			pg.ISC_REQ_SEQUENCE_DETECT |
			pg.ISC_REQ_REPLAY_DETECT |
			pg.ISC_REQ_CONFIDENTIALITY |
			pg.ISC_REQ_ALLOCATE_MEMORY |
			pg.ISC_REQ_STREAM |
			pg.ISC_REQ_MANUAL_CRED_VALIDATION

		out_buf := pg.SecBuffer{cbBuffer = 0, BufferType = pg.SECBUFFER_TOKEN, pvBuffer = nil}
		out_desc := pg.SecBufferDesc{ulVersion = pg.SECBUFFER_VERSION, cBuffers = 1, pBuffers = &out_buf}
		attrs: c.ulong = 0

		status := pg.schannel.InitializeSecurityContextA(
			&cred, nil, target_c, req_flags, 0, 0, nil, 0, &ctxt, &out_desc, &attrs, nil,
		)
		fmt.printfln("    ISC #0 -> 0x%08x (%s), out token %d bytes", u32(status), sec_status_name(status), out_buf.cbBuffer)
		if status != pg.SEC_I_CONTINUE_NEEDED && status != pg.SEC_E_OK {
			fmt.println("    FAIL: initial ISC rejected")
			return
		}
		defer pg.schannel.DeleteSecurityContext(&ctxt)

		if out_buf.cbBuffer > 0 && out_buf.pvBuffer != nil {
			token := ([^]byte)(out_buf.pvBuffer)[:out_buf.cbBuffer]
			hexdump("ClientHello sent", token, 48)
			_, serr := net.send_tcp(socket, token)
			pg.schannel.FreeContextBuffer(out_buf.pvBuffer)
			if serr != .None {
				fmt.printfln("    FAIL: could not send ClientHello: %v", serr)
				return
			}
		} else {
			fmt.println("    FAIL: Schannel produced no ClientHello; nothing was sent")
			return
		}

		enc := make([dynamic]byte, 0, 17 * 1024)
		defer delete(enc)

		need_more_data := true
		round := 0

		for round < 16 {
			round += 1

			if need_more_data {
				chunk: [17 * 1024]byte
				n, rerr := net.recv_tcp(socket, chunk[:])
				if rerr != .None {
					fmt.printfln("    round %d: recv error %v  <-- server closed or timed out here", round, rerr)
					return
				}
				if n == 0 {
					fmt.printfln("    round %d: recv returned 0 (clean EOF)  <-- server closed here", round)
					return
				}
				fmt.printfln("    round %d: received %d bytes", round, n)
				hexdump("server bytes", chunk[:n], 48)
				append(&enc, ..chunk[:n])
			}

			in_bufs: [2]pg.SecBuffer
			in_bufs[0] = pg.SecBuffer {
				cbBuffer   = c.ulong(len(enc)),
				BufferType = pg.SECBUFFER_TOKEN,
				pvBuffer   = raw_data(enc[:]),
			}
			in_bufs[1] = pg.SecBuffer{cbBuffer = 0, BufferType = pg.SECBUFFER_EMPTY, pvBuffer = nil}
			in_desc := pg.SecBufferDesc{ulVersion = pg.SECBUFFER_VERSION, cBuffers = 2, pBuffers = &in_bufs[0]}

			out_buf = pg.SecBuffer{cbBuffer = 0, BufferType = pg.SECBUFFER_TOKEN, pvBuffer = nil}
			out_desc = pg.SecBufferDesc{ulVersion = pg.SECBUFFER_VERSION, cBuffers = 1, pBuffers = &out_buf}

			status = pg.schannel.InitializeSecurityContextA(
				&cred, &ctxt, target_c, req_flags, 0, 0, &in_desc, 0, &ctxt, &out_desc, &attrs, nil,
			)
			fmt.printfln(
				"    round %d: ISC(in=%d) -> 0x%08x (%s), out token %d bytes",
				round, len(enc), u32(status), sec_status_name(status), out_buf.cbBuffer,
			)

			if status == pg.SEC_E_INCOMPLETE_MESSAGE {
				need_more_data = true
				continue
			}

			if out_buf.cbBuffer > 0 && out_buf.pvBuffer != nil {
				token := ([^]byte)(out_buf.pvBuffer)[:out_buf.cbBuffer]
				hexdump("client token sent", token, 32)
				_, serr := net.send_tcp(socket, token)
				pg.schannel.FreeContextBuffer(out_buf.pvBuffer)
				if serr != .None {
					fmt.printfln("    FAIL: could not send token: %v", serr)
					return
				}
			}

			if status != pg.SEC_E_OK &&
			   status != pg.SEC_I_CONTINUE_NEEDED &&
			   status != pg.SEC_I_COMPLETE_NEEDED &&
			   status != pg.SEC_I_COMPLETE_AND_CONTINUE {
				fmt.printfln("    FAIL: handshake rejected with 0x%08x (%s)", u32(status), sec_status_name(status))
				return
			}

			supplied := len(enc)
			extra := 0
			if in_bufs[1].BufferType == pg.SECBUFFER_EXTRA {
				extra = int(in_bufs[1].cbBuffer)
			}
			fmt.printfln("      supplied=%d extra=%d", supplied, extra)
			pg.tls_retain_tail(&enc, extra)

			if status == pg.SEC_E_OK {
				fmt.println("    HANDSHAKE COMPLETE")
				sizes: pg.SecPkgContext_StreamSizes
				sz := pg.schannel.QueryContextAttributesA(&ctxt, pg.SECPKG_ATTR_STREAM_SIZES, &sizes)
				fmt.printfln(
					"    stream sizes -> 0x%08x header=%d trailer=%d max_msg=%d",
					u32(sz), sizes.cbHeader, sizes.cbTrailer, sizes.cbMaximumMessage,
				)
				fmt.printfln("    leftover ciphertext held: %d bytes", len(enc))
				return
			}

			need_more_data = extra == 0 || extra >= supplied
		}

		fmt.println("    FAIL: handshake did not settle within 16 rounds")
	}

	sec_status_name :: proc(status: c.long) -> string {
		switch status {
		case pg.SEC_E_OK:                     return "SEC_E_OK"
		case pg.SEC_I_CONTINUE_NEEDED:        return "SEC_I_CONTINUE_NEEDED"
		case pg.SEC_I_COMPLETE_NEEDED:        return "SEC_I_COMPLETE_NEEDED"
		case pg.SEC_I_COMPLETE_AND_CONTINUE:  return "SEC_I_COMPLETE_AND_CONTINUE"
		case pg.SEC_I_CONTEXT_EXPIRED:        return "SEC_I_CONTEXT_EXPIRED"
		case pg.SEC_I_INCOMPLETE_CREDENTIALS: return "SEC_I_INCOMPLETE_CREDENTIALS"
		case pg.SEC_I_RENEGOTIATE:            return "SEC_I_RENEGOTIATE"
		case pg.SEC_E_INCOMPLETE_MESSAGE:     return "SEC_E_INCOMPLETE_MESSAGE"
		}
		return "unknown"
	}
}
