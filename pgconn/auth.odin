package pgconn

import "core:crypto/legacy/md5"
import "../pgerr"
import "../pgproto"

/*
	compute_md5_password computes the PostgreSQL MD5 password challenge response:
	"md5" + hex(md5(hex(md5(password + user)) + salt))
*/
compute_md5_password :: proc(
	user: string,
	password: string,
	salt: [4]byte,
	allocator := context.temp_allocator,
) -> string {
	HEX_CHARS := "0123456789abcdef"

	// Stage 1: md5(password + user)
	var_ctx1: md5.Context
	md5.init(&var_ctx1)
	md5.update(&var_ctx1, transmute([]byte)password)
	md5.update(&var_ctx1, transmute([]byte)user)
	var_digest1: [16]byte
	md5.final(&var_ctx1, var_digest1[:])

	// Encode digest1 to lowercase hex
	hex_buf1: [32]byte
	for b, i in var_digest1 {
		hex_buf1[i * 2] = HEX_CHARS[b >> 4]
		hex_buf1[i * 2 + 1] = HEX_CHARS[b & 0x0F]
	}

	// Stage 2: md5(hex_buf1 + salt)
	local_salt := salt
	var_ctx2: md5.Context
	md5.init(&var_ctx2)
	md5.update(&var_ctx2, hex_buf1[:])
	md5.update(&var_ctx2, local_salt[:])
	var_digest2: [16]byte
	md5.final(&var_ctx2, var_digest2[:])

	// Stage 3: format "md5" + hex_buf2
	hex_buf2: [32]byte
	for b, i in var_digest2 {
		hex_buf2[i * 2] = HEX_CHARS[b >> 4]
		hex_buf2[i * 2 + 1] = HEX_CHARS[b & 0x0F]
	}

	out_bytes := make([]byte, 35, allocator)
	out_bytes[0] = 'm'
	out_bytes[1] = 'd'
	out_bytes[2] = '5'
	copy(out_bytes[3:], hex_buf2[:])

	return string(out_bytes)
}

/*
	auth_handle_challenge dispatches an incoming PostgreSQL Authentication backend message,
	encoding and transmitting the appropriate credential response.
*/
auth_handle_challenge :: proc(
	stream: ^Stream_Buffer,
	auth_msg: pgproto.Msg_Authentication,
	user: string,
	password: string,
	scram_state: ^Scram_State,
	temp_allocator := context.temp_allocator,
) -> (
	is_complete: bool,
	err: pgerr.Error,
) {
	switch auth_msg.auth_type {
	case .Ok:
		return true, nil

	case .Cleartext_Password:
		buf := make([dynamic]byte, temp_allocator)
		defer delete(buf)
		pgproto.encode_password(&buf, password)
		stream_write_messages(stream, buf[:]) or_return
		return false, nil

	case .MD5_Password:
		md5_pwd := compute_md5_password(user, password, auth_msg.salt, temp_allocator)
		defer delete(md5_pwd, temp_allocator)
		buf := make([dynamic]byte, temp_allocator)
		defer delete(buf)
		pgproto.encode_password(&buf, md5_pwd)
		stream_write_messages(stream, buf[:]) or_return
		return false, nil

	case .SASL:
		// Check for SCRAM-SHA-256 in mechanism list
		has_scram := false
		for mech in auth_msg.mechanisms {
			if mech == "SCRAM-SHA-256" {
				has_scram = true
				break
			}
		}
		if !has_scram {
			return false, pgerr.Auth_Error{
				type = .Unsupported_Auth_Mechanism,
				message = "Server did not offer SCRAM-SHA-256 mechanism",
			}
		}

		if scram_state == nil {
			return false, pgerr.Auth_Error{
				type = .Authentication_Failed,
				message = "SCRAM state not initialized",
			}
		}

		client_first := scram_client_first(scram_state, user, allocator = temp_allocator) or_return
		defer delete(client_first, temp_allocator)
		sasl_init_msg := pgproto.Msg_SASL_Initial_Response{
			mechanism = "SCRAM-SHA-256",
			data = transmute([]byte)client_first,
		}
		buf := make([dynamic]byte, temp_allocator)
		defer delete(buf)
		pgproto.encode_sasl_initial_response(&buf, sasl_init_msg)
		stream_write_messages(stream, buf[:]) or_return
		return false, nil

	case .SASL_Continue:
		if scram_state == nil {
			return false, pgerr.Auth_Error{
				type = .Authentication_Failed,
				message = "SCRAM state not initialized",
			}
		}

		client_final := scram_client_final(scram_state, auth_msg.sasl_data, password, temp_allocator) or_return
		defer delete(client_final, temp_allocator)
		buf := make([dynamic]byte, temp_allocator)
		defer delete(buf)
		pgproto.encode_sasl_response(&buf, transmute([]byte)client_final)
		stream_write_messages(stream, buf[:]) or_return
		return false, nil

	case .SASL_Final:
		if scram_state == nil {
			return false, pgerr.Auth_Error{
				type = .Authentication_Failed,
				message = "SCRAM state not initialized",
			}
		}

		scram_verify_server_final(scram_state, auth_msg.sasl_data, temp_allocator) or_return
		// AuthenticationOk will follow immediately from server
		return false, nil

	case .Kerberos_V5, .SCM_Credential, .GSS, .GSS_Continue, .SSPI:
		return false, pgerr.Auth_Error{
			type = .Unsupported_Auth_Mechanism,
			message = "Unsupported authentication type requested by server",
		}
	}

	return false, pgerr.Auth_Error{
		type = .Authentication_Failed,
		message = "Unrecognized authentication message from server",
	}
}

