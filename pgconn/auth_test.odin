package pgconn

import "core:mem"
import "core:strings"
import "core:testing"
import "../pgerr"

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

