package pgproto

import "core:mem"
import "core:os"
import "core:slice"
import "core:testing"

@(test)
test_golden_frontend_encoders :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	check_fe_golden :: proc(t: ^testing.T, msg: Frontend_Message, fixture_path: string) {
		buf: [dynamic]byte
		defer delete(buf)
		encode_frontend_message(&buf, msg)

		golden_bytes, err_file := os.read_entire_file(fixture_path, context.temp_allocator)
		testing.expect_value(t, err_file, nil)
		testing.expectf(
			t,
			slice.equal(buf[:], golden_bytes),
			"mismatch for %v: got %v, expected %v",
			fixture_path,
			buf[:],
			golden_bytes,
		)
	}

	// 1. SSLRequest
	check_fe_golden(t, Msg_SSL_Request{}, "pgproto/tests_golden_files/fe_ssl_request.bin")

	// 2. CancelRequest
	check_fe_golden(
		t,
		Msg_Cancel_Request{process_id = 1234, secret_key = 5678},
		"pgproto/tests_golden_files/fe_cancel_request.bin",
	)

	// 3. StartupMessage
	check_fe_golden(
		t,
		Msg_Startup{
			protocol_version = 196608,
			params = []Startup_Param{
				{name = "user", value = "postgres"},
				{name = "database", value = "testdb"},
			},
		},
		"pgproto/tests_golden_files/fe_startup_message.bin",
	)

	// 4. PasswordMessage
	check_fe_golden(
		t,
		Msg_Password{password = "secret_pass"},
		"pgproto/tests_golden_files/fe_password_message.bin",
	)

	// 5. SASLInitialResponse
	check_fe_golden(
		t,
		Msg_SASL_Initial_Response{
			mechanism = "SCRAM-SHA-256",
			data = transmute([]byte)string("n,,n=user,r=fyko+d2lbbFgAQKaQraW"),
		},
		"pgproto/tests_golden_files/fe_sasl_initial_response.bin",
	)

	// 6. SASLResponse
	check_fe_golden(
		t,
		Msg_SASL_Response{
			data = transmute([]byte)string("c=biws,r=fyko+d2lbbFgAQKaQraW,p=v0X8v3Bz2T0CJGbJQybpwg=="),
		},
		"pgproto/tests_golden_files/fe_sasl_response.bin",
	)

	// 7. Query
	check_fe_golden(
		t,
		Msg_Query{query = "SELECT 1;"},
		"pgproto/tests_golden_files/fe_query.bin",
	)

	// 8. Parse
	check_fe_golden(
		t,
		Msg_Parse{
			statement_name = "stmt1",
			query = "SELECT $1::int4",
			param_oids = []u32{23},
		},
		"pgproto/tests_golden_files/fe_parse.bin",
	)

	// 9. Bind
	check_fe_golden(
		t,
		Msg_Bind{
			portal_name = "portal1",
			statement_name = "stmt1",
			param_format_codes = []Field_Format{.Text},
			param_values = []Bind_Param{
				{is_null = false, value = transmute([]byte)string("42")},
				{is_null = true, value = nil},
			},
			result_format_codes = []Field_Format{.Binary},
		},
		"pgproto/tests_golden_files/fe_bind.bin",
	)

	// 10. Describe Statement
	check_fe_golden(
		t,
		Msg_Describe{target_type = .Statement, name = "stmt1"},
		"pgproto/tests_golden_files/fe_describe_statement.bin",
	)

	// 11. Describe Portal
	check_fe_golden(
		t,
		Msg_Describe{target_type = .Portal, name = "portal1"},
		"pgproto/tests_golden_files/fe_describe_portal.bin",
	)

	// 12. Execute
	check_fe_golden(
		t,
		Msg_Execute{portal_name = "portal1", max_rows = 100},
		"pgproto/tests_golden_files/fe_execute.bin",
	)

	// 13. Sync
	check_fe_golden(t, Msg_Sync{}, "pgproto/tests_golden_files/fe_sync.bin")

	// 14. Flush
	check_fe_golden(t, Msg_Flush{}, "pgproto/tests_golden_files/fe_flush.bin")

	// 15. Close Statement
	check_fe_golden(
		t,
		Msg_Close{target_type = .Statement, name = "stmt1"},
		"pgproto/tests_golden_files/fe_close_statement.bin",
	)

	// 16. Close Portal
	check_fe_golden(
		t,
		Msg_Close{target_type = .Portal, name = "portal1"},
		"pgproto/tests_golden_files/fe_close_portal.bin",
	)

	// 17. Terminate
	check_fe_golden(t, Msg_Terminate{}, "pgproto/tests_golden_files/fe_terminate.bin")

	// 18. CopyData
	check_fe_golden(
		t,
		Msg_Copy_Data{data = transmute([]byte)string("101\tJohn Doe\tDeveloper\n")},
		"pgproto/tests_golden_files/fe_copy_data.bin",
	)

	// 19. CopyDone
	check_fe_golden(t, Msg_Copy_Done{}, "pgproto/tests_golden_files/fe_copy_done.bin")

	// 20. CopyFail
	check_fe_golden(
		t,
		Msg_Copy_Fail{message = "error during copy stream"},
		"pgproto/tests_golden_files/fe_copy_fail.bin",
	)

	testing.expect_value(t, len(track.allocation_map), 0)
}
