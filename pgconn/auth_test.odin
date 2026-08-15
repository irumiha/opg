package pgconn

import "core:encoding/base64"
import "core:mem"
import "core:strings"
import "core:testing"
import "../pgerr"
import "../pgproto"

@(test)
test_auth_md5_password_computation :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	// Known PostgreSQL MD5 vector:
	// user: "postgres", password: "password", salt: [4]byte{1, 2, 3, 4}
	// md5("passwordpostgres") -> "368d40be2e68095b341f237f8f94943f"
	// md5("368d40be2e68095b341f237f8f94943f" + [1, 2, 3, 4])
	salt := [4]byte{1, 2, 3, 4}
	result := compute_md5_password("postgres", "password", salt, context.allocator)
	testing.expect_value(t, len(result), 35) // "md5" + 32 hex chars
	testing.expect(t, result[:3] == "md5", "expected md5 prefix")

	// Verify consistency across runs
	result2 := compute_md5_password("postgres", "password", salt, context.allocator)
	testing.expect_value(t, result, result2)

	delete(result, context.allocator)
	delete(result2, context.allocator)

	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
test_auth_scram_escape_username :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	e1 := scram_escape_username("user,name=test", context.allocator)
	testing.expect_value(t, e1, "user=2Cname=3Dtest")
	delete(e1, context.allocator)

	e2 := scram_escape_username("plain_user", context.allocator)
	testing.expect_value(t, e2, "plain_user")
	delete(e2, context.allocator)

	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
test_auth_scram_client_first_rfc7677 :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	state: Scram_State
	msg, err := scram_client_first(&state, "user", injected_nonce = "rOprNGfwEbeRWgbNEkqO", allocator = context.allocator)

	testing.expect(t, err == nil, "expected scram_client_first success")
	// RFC 7677 Client First message: "n,,n=user,r=rOprNGfwEbeRWgbNEkqO"
	testing.expect_value(t, msg, "n,,n=user,r=rOprNGfwEbeRWgbNEkqO")
	testing.expect_value(t, state.client_nonce, "rOprNGfwEbeRWgbNEkqO")
	testing.expect_value(t, state.client_first_bare, "n=user,r=rOprNGfwEbeRWgbNEkqO")

	delete(msg, context.allocator)
	delete(state.client_nonce, context.allocator)
	delete(state.client_first_bare, context.allocator)

	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
test_auth_scram_client_first_random_nonce :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	state: Scram_State
	msg, err := scram_client_first(&state, "postgres", allocator = context.allocator)

	testing.expect(t, err == nil, "expected scram_client_first success")
	testing.expect(t, len(state.client_nonce) >= 24, "expected random nonce length >= 24")
	testing.expect(t, strings.has_prefix(msg, "n,,n=postgres,r="), "expected valid client first prefix")

	delete(msg, context.allocator)
	delete(state.client_nonce, context.allocator)
	delete(state.client_first_bare, context.allocator)

	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
test_auth_scram_client_final_rfc7677 :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	state: Scram_State
	client_first, first_err := scram_client_first(
		&state,
		"user",
		injected_nonce = "rOprNGfwEbeRWgbNEkqO",
		allocator = context.allocator,
	)
	testing.expect(t, first_err == nil, "expected scram_client_first success")

	server_first := "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096"
	client_final, err := scram_client_final(&state, server_first, "pencil", allocator = context.allocator)

	testing.expect(t, err == nil, "expected scram_client_final success")

	// RFC 7677 Expected Client Final:
	// "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ="
	expected_client_final := "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ="
	testing.expect_value(t, client_final, expected_client_final)

	delete(client_first, context.allocator)
	delete(state.client_nonce, context.allocator)
	delete(state.client_first_bare, context.allocator)
	delete(client_final, context.allocator)
	delete(state.combined_nonce, context.allocator)
	delete(state.server_first, context.allocator)
	delete(state.auth_message, context.allocator)
	delete(state.salt, context.allocator)

	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
test_auth_scram_parse_server_first_errors :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	// Missing nonce
	{
		_, _, _, err := scram_parse_server_first("s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096", allocator = context.allocator)
		testing.expect(t, err != nil, "expected error on missing nonce")
		#partial switch aerr in err {
		case pgerr.Auth_Error:
			testing.expect_value(t, aerr.type, pgerr.Auth_Error_Type.SCRAM_Invalid_Server_First_Message)
		case:
			testing.expect(t, false, "expected Auth_Error")
		}
	}

	// Missing salt
	{
		_, _, _, err := scram_parse_server_first("r=rOprNGfwEbeRWgbNEkqO,i=4096", allocator = context.allocator)
		testing.expect(t, err != nil, "expected error on missing salt")
	}

	// Missing / invalid iterations
	{
		_, _, _, err := scram_parse_server_first("r=rOprNGfwEbeRWgbNEkqO,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=0", allocator = context.allocator)
		testing.expect(t, err != nil, "expected error on zero iterations")

		_, _, _, err2 := scram_parse_server_first("r=rOprNGfwEbeRWgbNEkqO,s=W22ZaJ0SNY7soEsUEjb6gQ==", allocator = context.allocator)
		testing.expect(t, err2 != nil, "expected error on missing iterations")
	}

	// Malformed base64 salt
	{
		_, _, _, err := scram_parse_server_first("r=rOprNGfwEbeRWgbNEkqO,s=invalid!!!b64,i=4096", allocator = context.allocator)
		testing.expect(t, err != nil, "expected error on invalid base64 salt")
	}

	// Short / malformed parts
	{
		_, _, _, err := scram_parse_server_first("r,s,i", allocator = context.allocator)
		testing.expect(t, err != nil, "expected error on malformed parts")
	}

	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
test_auth_scram_client_final_nonce_mismatch :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	state: Scram_State
	client_first, first_err := scram_client_first(
		&state,
		"user",
		injected_nonce = "clientNonce123",
		allocator = context.allocator,
	)
	testing.expect(t, first_err == nil, "expected scram_client_first success")

	// Server returns completely different nonce that doesn't start with clientNonce123
	server_first := "r=differentNonce456,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096"
	_, err := scram_client_final(&state, server_first, "pencil", allocator = context.allocator)
	testing.expect(t, err != nil, "expected error on nonce mismatch")
	#partial switch aerr in err {
	case pgerr.Auth_Error:
		testing.expect_value(t, aerr.type, pgerr.Auth_Error_Type.SCRAM_Invalid_Server_First_Message)
	case:
		testing.expect(t, false, "expected Auth_Error")
	}

	delete(client_first, context.allocator)
	delete(state.client_nonce, context.allocator)
	delete(state.client_first_bare, context.allocator)

	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
test_auth_scram_verify_server_final_rfc7677 :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	state: Scram_State
	client_first, first_err := scram_client_first(
		&state,
		"user",
		injected_nonce = "rOprNGfwEbeRWgbNEkqO",
		allocator = context.allocator,
	)
	testing.expect(t, first_err == nil, "expected scram_client_first success")

	server_first := "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096"
	client_final, final_err := scram_client_final(&state, server_first, "pencil", allocator = context.allocator)
	testing.expect(t, final_err == nil, "expected scram_client_final success")

	// RFC 7677 Expected Server Final: "v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4="
	server_final := "v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4="
	err := scram_verify_server_final(&state, server_final, allocator = context.allocator)
	testing.expect(t, err == nil, "expected valid server final verification")

	// Verify tampered signature fails
	tampered_server_final := "v=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	bad_err := scram_verify_server_final(&state, tampered_server_final, allocator = context.allocator)
	testing.expect(t, bad_err != nil, "expected error on tampered signature")
	#partial switch auth_err in bad_err {
	case pgerr.Auth_Error:
		testing.expect_value(t, auth_err.type, pgerr.Auth_Error_Type.SCRAM_Server_Signature_Mismatch)
	case:
		testing.expect(t, false, "expected Auth_Error")
	}

	// Server error (e=...)
	err_server_final := "e=other-error"
	err_res := scram_verify_server_final(&state, err_server_final, allocator = context.allocator)
	testing.expect(t, err_res != nil, "expected error on server error message")
	#partial switch e in err_res {
	case pgerr.Auth_Error:
		testing.expect_value(t, e.type, pgerr.Auth_Error_Type.Authentication_Failed)
		delete(e.message, context.allocator)
	case:
		testing.expect(t, false, "expected Auth_Error")
	}

	// Missing v= signature
	missing_v := "r=some-nonce"
	missing_err := scram_verify_server_final(&state, missing_v, allocator = context.allocator)
	testing.expect(t, missing_err != nil, "expected error on missing v=")
	#partial switch e in missing_err {
	case pgerr.Auth_Error:
		testing.expect_value(t, e.type, pgerr.Auth_Error_Type.SCRAM_Invalid_Server_Final_Message)
	case:
		testing.expect(t, false, "expected Auth_Error")
	}

	// Malformed base64
	bad_b64 := "v=invalid!base64"
	bad_b64_err := scram_verify_server_final(&state, bad_b64, allocator = context.allocator)
	testing.expect(t, bad_b64_err != nil, "expected error on bad base64")
	#partial switch e in bad_b64_err {
	case pgerr.Auth_Error:
		testing.expect_value(t, e.type, pgerr.Auth_Error_Type.SCRAM_Invalid_Server_Final_Message)
	case:
		testing.expect(t, false, "expected Auth_Error")
	}

	delete(client_first, context.allocator)
	delete(state.client_nonce, context.allocator)
	delete(state.client_first_bare, context.allocator)
	delete(client_final, context.allocator)
	delete(state.combined_nonce, context.allocator)
	delete(state.server_first, context.allocator)
	delete(state.auth_message, context.allocator)
	delete(state.salt, context.allocator)

	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
test_auth_handle_challenge_cleartext :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	{
		mock: Mock_Transport
		mock_transport_init(&mock)
		defer mock_transport_destroy(&mock)

		transport := make_mock_transport(&mock)
		stream: Stream_Buffer
		stream_init(&stream, transport)
		defer stream_destroy(&stream)

		auth_msg := pgproto.Msg_Authentication{auth_type = .Cleartext_Password}
		is_complete, err := auth_handle_challenge(&stream, auth_msg, "postgres", "secret", nil)
		testing.expect(t, err == nil, "expected cleartext auth success")
		testing.expect_value(t, is_complete, false)

		// Check password message was sent: 'p' + 4-byte length + "secret\0"
		testing.expect_value(t, mock.written_bytes[0], 'p')
		testing.expect_value(t, len(mock.written_bytes), 1 + 4 + len("secret") + 1)
	}

	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
test_auth_handle_challenge_md5 :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	{
		mock: Mock_Transport
		mock_transport_init(&mock)
		defer mock_transport_destroy(&mock)

		transport := make_mock_transport(&mock)
		stream: Stream_Buffer
		stream_init(&stream, transport)
		defer stream_destroy(&stream)

		auth_msg := pgproto.Msg_Authentication{
			auth_type = .MD5_Password,
			salt = [4]byte{1, 2, 3, 4},
		}
		is_complete, err := auth_handle_challenge(&stream, auth_msg, "postgres", "secret", nil)
		testing.expect(t, err == nil, "expected md5 auth success")
		testing.expect_value(t, is_complete, false)

		testing.expect_value(t, mock.written_bytes[0], 'p')
		testing.expect_value(t, len(mock.written_bytes), 1 + 4 + 35 + 1)
	}

	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
test_auth_handle_challenge_ok :: proc(t: ^testing.T) {
	mock: Mock_Transport
	mock_transport_init(&mock)
	defer mock_transport_destroy(&mock)

	transport := make_mock_transport(&mock)
	stream: Stream_Buffer
	stream_init(&stream, transport)
	defer stream_destroy(&stream)

	auth_msg := pgproto.Msg_Authentication{auth_type = .Ok}
	is_complete, err := auth_handle_challenge(&stream, auth_msg, "postgres", "secret", nil)
	testing.expect(t, err == nil, "expected auth ok")
	testing.expect_value(t, is_complete, true)
	testing.expect_value(t, len(mock.written_bytes), 0)
}

@(test)
test_auth_handle_challenge_sasl_full_conversation :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	{
		mock: Mock_Transport
		mock_transport_init(&mock)
		defer mock_transport_destroy(&mock)

		transport := make_mock_transport(&mock)
		stream: Stream_Buffer
		stream_init(&stream, transport)
		defer stream_destroy(&stream)

		state: Scram_State
		defer {
			delete(state.client_nonce, context.allocator)
			delete(state.client_first_bare, context.allocator)
			delete(state.combined_nonce, context.allocator)
			delete(state.server_first, context.allocator)
			delete(state.auth_message, context.allocator)
			delete(state.salt, context.allocator)
		}

		// 1. Server offers SASL mechanisms
		auth_sasl := pgproto.Msg_Authentication{
			auth_type = .SASL,
			mechanisms = []string{"SCRAM-SHA-256"},
		}
		done1, err1 := auth_handle_challenge(&stream, auth_sasl, "user", "pencil", &state, context.allocator)
		testing.expect(t, err1 == nil, "expected sasl init success")
		testing.expect_value(t, done1, false)
		testing.expect(t, len(mock.written_bytes) > 0)
		testing.expect_value(t, mock.written_bytes[0], 'p')

		// 2. Server sends SASL_Continue
		server_first := strings.concatenate(
			{"r=", state.client_nonce, "%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096"},
			context.temp_allocator,
		)
		auth_continue := pgproto.Msg_Authentication{
			auth_type = .SASL_Continue,
			sasl_data = server_first,
		}
		done2, err2 := auth_handle_challenge(&stream, auth_continue, "user", "pencil", &state, context.allocator)
		testing.expect(t, err2 == nil, "expected sasl continue success")
		testing.expect_value(t, done2, false)

		// 3. Server sends SASL_Final with valid server signature
		b64_sig := base64.encode(state.server_signature[:], allocator = context.temp_allocator)
		server_final := strings.concatenate({"v=", b64_sig}, context.temp_allocator)
		auth_final := pgproto.Msg_Authentication{
			auth_type = .SASL_Final,
			sasl_data = server_final,
		}
		done3, err3 := auth_handle_challenge(&stream, auth_final, "user", "pencil", &state, context.allocator)
		testing.expect(t, err3 == nil, "expected sasl final success")
		testing.expect_value(t, done3, false)

		// 4. Server sends AuthenticationOk
		auth_ok := pgproto.Msg_Authentication{
			auth_type = .Ok,
		}
		done4, err4 := auth_handle_challenge(&stream, auth_ok, "user", "pencil", &state, context.allocator)
		testing.expect(t, err4 == nil, "expected ok success")
		testing.expect_value(t, done4, true)
	}

	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
test_auth_handle_challenge_sasl_errors :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	{
		mock: Mock_Transport
		mock_transport_init(&mock)
		defer mock_transport_destroy(&mock)

		transport := make_mock_transport(&mock)
		stream: Stream_Buffer
		stream_init(&stream, transport)
		defer stream_destroy(&stream)

		// Case 1: Server offers SASL without SCRAM-SHA-256
		{
			auth_msg := pgproto.Msg_Authentication{
				auth_type = .SASL,
				mechanisms = []string{"GSSAPI", "PLAIN"},
			}
			_, err := auth_handle_challenge(&stream, auth_msg, "postgres", "secret", nil)
			testing.expect(t, err != nil, "expected error when SCRAM-SHA-256 not offered")
			#partial switch aerr in err {
			case pgerr.Auth_Error:
				testing.expect_value(t, aerr.type, pgerr.Auth_Error_Type.Unsupported_Auth_Mechanism)
			case:
				testing.expect(t, false, "expected Auth_Error")
			}
		}

		// Case 2: scram_state is nil for SASL
		{
			auth_msg := pgproto.Msg_Authentication{
				auth_type = .SASL,
				mechanisms = []string{"SCRAM-SHA-256"},
			}
			_, err := auth_handle_challenge(&stream, auth_msg, "postgres", "secret", nil)
			testing.expect(t, err != nil, "expected error when scram_state is nil")
			#partial switch aerr in err {
			case pgerr.Auth_Error:
				testing.expect_value(t, aerr.type, pgerr.Auth_Error_Type.Authentication_Failed)
			case:
				testing.expect(t, false, "expected Auth_Error")
			}
		}

		// Case 3: scram_state is nil for SASL_Continue
		{
			auth_msg := pgproto.Msg_Authentication{
				auth_type = .SASL_Continue,
				sasl_data = "r=dummy,s=c2FsdA==,i=4096",
			}
			_, err := auth_handle_challenge(&stream, auth_msg, "postgres", "secret", nil)
			testing.expect(t, err != nil, "expected error when scram_state is nil on continue")
			#partial switch aerr in err {
			case pgerr.Auth_Error:
				testing.expect_value(t, aerr.type, pgerr.Auth_Error_Type.Authentication_Failed)
			case:
				testing.expect(t, false, "expected Auth_Error")
			}
		}

		// Case 4: scram_state is nil for SASL_Final
		{
			auth_msg := pgproto.Msg_Authentication{
				auth_type = .SASL_Final,
				sasl_data = "v=AAAA",
			}
			_, err := auth_handle_challenge(&stream, auth_msg, "postgres", "secret", nil)
			testing.expect(t, err != nil, "expected error when scram_state is nil on final")
			#partial switch aerr in err {
			case pgerr.Auth_Error:
				testing.expect_value(t, aerr.type, pgerr.Auth_Error_Type.Authentication_Failed)
			case:
				testing.expect(t, false, "expected Auth_Error")
			}
		}
	}

	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
test_auth_handle_challenge_unsupported_and_unrecognized :: proc(t: ^testing.T) {
	mock: Mock_Transport
	mock_transport_init(&mock)
	defer mock_transport_destroy(&mock)

	transport := make_mock_transport(&mock)
	stream: Stream_Buffer
	stream_init(&stream, transport)
	defer stream_destroy(&stream)

	// Unsupported auth types: Kerberos_V5, SCM_Credential, GSS, GSS_Continue, SSPI
	unsupported := []pgproto.Auth_Type{
		.Kerberos_V5,
		.SCM_Credential,
		.GSS,
		.GSS_Continue,
		.SSPI,
	}

	for ut in unsupported {
		auth_msg := pgproto.Msg_Authentication{auth_type = ut}
		_, err := auth_handle_challenge(&stream, auth_msg, "user", "pass", nil)
		testing.expect(t, err != nil, "expected error for unsupported auth type")
		#partial switch aerr in err {
		case pgerr.Auth_Error:
			testing.expect_value(t, aerr.type, pgerr.Auth_Error_Type.Unsupported_Auth_Mechanism)
		case:
			testing.expect(t, false, "expected Auth_Error")
		}
	}

	// Unrecognized auth type
	{
		auth_msg := pgproto.Msg_Authentication{auth_type = pgproto.Auth_Type(999)}
		_, err := auth_handle_challenge(&stream, auth_msg, "user", "pass", nil)
		testing.expect(t, err != nil, "expected error for unrecognized auth type")
		#partial switch aerr in err {
		case pgerr.Auth_Error:
			testing.expect_value(t, aerr.type, pgerr.Auth_Error_Type.Authentication_Failed)
		case:
			testing.expect(t, false, "expected Auth_Error")
		}
	}
}
