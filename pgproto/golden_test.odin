package pgproto

import "core:encoding/endian"
import "core:mem"
import "core:os"
import "core:slice"
import "core:testing"
import opg ".."

BACKEND_FIXTURES :: [?]string{
	"pgproto/tests_golden_files/be_auth_ok.bin",
	"pgproto/tests_golden_files/be_auth_md5.bin",
	"pgproto/tests_golden_files/be_auth_sasl.bin",
	"pgproto/tests_golden_files/be_auth_sasl_continue.bin",
	"pgproto/tests_golden_files/be_auth_sasl_final.bin",
	"pgproto/tests_golden_files/be_backend_key_data.bin",
	"pgproto/tests_golden_files/be_parameter_status.bin",
	"pgproto/tests_golden_files/be_ready_for_query_idle.bin",
	"pgproto/tests_golden_files/be_ready_for_query_tx.bin",
	"pgproto/tests_golden_files/be_ready_for_query_err.bin",
	"pgproto/tests_golden_files/be_row_description.bin",
	"pgproto/tests_golden_files/be_data_row.bin",
	"pgproto/tests_golden_files/be_command_complete_select.bin",
	"pgproto/tests_golden_files/be_command_complete_insert.bin",
	"pgproto/tests_golden_files/be_error_response.bin",
	"pgproto/tests_golden_files/be_notice_response.bin",
	"pgproto/tests_golden_files/be_empty_query_response.bin",
	"pgproto/tests_golden_files/be_parse_complete.bin",
	"pgproto/tests_golden_files/be_bind_complete.bin",
	"pgproto/tests_golden_files/be_close_complete.bin",
	"pgproto/tests_golden_files/be_no_data.bin",
	"pgproto/tests_golden_files/be_portal_suspended.bin",
	"pgproto/tests_golden_files/be_parameter_description.bin",
	"pgproto/tests_golden_files/be_notification_response.bin",
	"pgproto/tests_golden_files/be_copy_in_response.bin",
	"pgproto/tests_golden_files/be_copy_out_response.bin",
	"pgproto/tests_golden_files/be_copy_both_response.bin",
	"pgproto/tests_golden_files/be_copy_data.bin",
	"pgproto/tests_golden_files/be_copy_done.bin",
	"pgproto/tests_golden_files/be_function_call_response.bin",
	"pgproto/tests_golden_files/be_negotiate_protocol_version.bin",
}

FRONTEND_FIXTURES :: [?]string{
	"pgproto/tests_golden_files/fe_ssl_request.bin",
	"pgproto/tests_golden_files/fe_cancel_request.bin",
	"pgproto/tests_golden_files/fe_startup_message.bin",
	"pgproto/tests_golden_files/fe_password_message.bin",
	"pgproto/tests_golden_files/fe_sasl_initial_response.bin",
	"pgproto/tests_golden_files/fe_sasl_response.bin",
	"pgproto/tests_golden_files/fe_query.bin",
	"pgproto/tests_golden_files/fe_parse.bin",
	"pgproto/tests_golden_files/fe_bind.bin",
	"pgproto/tests_golden_files/fe_describe_statement.bin",
	"pgproto/tests_golden_files/fe_describe_portal.bin",
	"pgproto/tests_golden_files/fe_execute.bin",
	"pgproto/tests_golden_files/fe_sync.bin",
	"pgproto/tests_golden_files/fe_flush.bin",
	"pgproto/tests_golden_files/fe_close_statement.bin",
	"pgproto/tests_golden_files/fe_close_portal.bin",
	"pgproto/tests_golden_files/fe_terminate.bin",
	"pgproto/tests_golden_files/fe_copy_data.bin",
	"pgproto/tests_golden_files/fe_copy_done.bin",
	"pgproto/tests_golden_files/fe_copy_fail.bin",
}

is_valid_backend_type :: proc(b: u8) -> bool {
	#partial switch Backend_Message_Type(b) {
	case .Authentication,
	     .Backend_Key_Data,
	     .Bind_Complete,
	     .Close_Complete,
	     .Command_Complete,
	     .Copy_Data,
	     .Copy_Done,
	     .Copy_In_Response,
	     .Copy_Out_Response,
	     .Copy_Both_Response,
	     .Data_Row,
	     .Empty_Query_Response,
	     .Error_Response,
	     .Function_Call_Response,
	     .Negotiate_Protocol_Ver,
	     .No_Data,
	     .Notice_Response,
	     .Notification_Response,
	     .Parameter_Description,
	     .Parameter_Status,
	     .Parse_Complete,
	     .Portal_Suspended,
	     .Ready_For_Query,
	     .Row_Description:
		return true
	case:
		return false
	}
}

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
			data = bytes("n,,n=user,r=fyko+d2lbbFgAQKaQraW"),
		},
		"pgproto/tests_golden_files/fe_sasl_initial_response.bin",
	)

	// 6. SASLResponse
	check_fe_golden(
		t,
		Msg_SASL_Response{
			data = bytes("c=biws,r=fyko+d2lbbFgAQKaQraW,p=v0X8v3Bz2T0CJGbJQybpwg=="),
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
				{is_null = false, value = bytes("42")},
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
		Msg_Copy_Data{data = bytes("101\tJohn Doe\tDeveloper\n")},
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
	for _, leak in track.allocation_map {
		testing.expectf(t, false, "Memory leak: %v bytes at %v", leak.size, leak.location)
	}
}

@(test)
test_golden_backend_parsers :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	// Helper to load file and parse
	load_and_parse :: proc(
		t: ^testing.T,
		fixture_path: string,
	) -> (
		msg: Backend_Message,
		bytes_consumed: int,
	) {
		raw, err_file := os.read_entire_file(fixture_path, context.temp_allocator)
		testing.expect_value(t, err_file, nil)
		parsed_msg, n, err_parse := parse_message(raw, context.temp_allocator)
		testing.expect_value(t, err_parse, nil)
		testing.expect_value(t, n, len(raw))
		return parsed_msg, n
	}

	// 1. be_auth_ok.bin
	{
		msg, n := load_and_parse(t, "pgproto/tests_golden_files/be_auth_ok.bin")
		testing.expect_value(t, n, 9)
		auth, ok := msg.(Msg_Authentication)
		testing.expect(t, ok, "expected Msg_Authentication")
		testing.expect_value(t, auth.auth_type, Auth_Type.Ok)
	}

	// 2. be_auth_md5.bin
	{
		msg, n := load_and_parse(t, "pgproto/tests_golden_files/be_auth_md5.bin")
		testing.expect_value(t, n, 13)
		auth, ok := msg.(Msg_Authentication)
		testing.expect(t, ok, "expected Msg_Authentication")
		testing.expect_value(t, auth.auth_type, Auth_Type.MD5_Password)
		testing.expect_value(t, auth.salt, [4]u8{1, 2, 3, 4})
	}

	// 3. be_auth_sasl.bin
	{
		msg, n := load_and_parse(t, "pgproto/tests_golden_files/be_auth_sasl.bin")
		testing.expect_value(t, n, 43)
		auth, ok := msg.(Msg_Authentication)
		testing.expect(t, ok, "expected Msg_Authentication")
		testing.expect_value(t, auth.auth_type, Auth_Type.SASL)
		testing.expect_value(t, len(auth.mechanisms), 2)
		testing.expect_value(t, auth.mechanisms[0], "SCRAM-SHA-256")
		testing.expect_value(t, auth.mechanisms[1], "SCRAM-SHA-256-PLUS")
	}

	// 4. be_auth_sasl_continue.bin
	{
		msg, n := load_and_parse(t, "pgproto/tests_golden_files/be_auth_sasl_continue.bin")
		testing.expect_value(t, n, 28)
		auth, ok := msg.(Msg_Authentication)
		testing.expect(t, ok, "expected Msg_Authentication")
		testing.expect_value(t, auth.auth_type, Auth_Type.SASL_Continue)
		testing.expect_value(t, auth.sasl_data, "r=fy3,s=1234,i=4096")
	}

	// 5. be_auth_sasl_final.bin
	{
		msg, n := load_and_parse(t, "pgproto/tests_golden_files/be_auth_sasl_final.bin")
		testing.expect_value(t, n, 20)
		auth, ok := msg.(Msg_Authentication)
		testing.expect(t, ok, "expected Msg_Authentication")
		testing.expect_value(t, auth.auth_type, Auth_Type.SASL_Final)
		testing.expect_value(t, auth.sasl_data, "v=rmExample")
	}

	// 6. be_backend_key_data.bin
	{
		msg, n := load_and_parse(t, "pgproto/tests_golden_files/be_backend_key_data.bin")
		testing.expect_value(t, n, 13)
		key, ok := msg.(Msg_Backend_Key_Data)
		testing.expect(t, ok, "expected Msg_Backend_Key_Data")
		testing.expect_value(t, key.process_id, i32(1234))
		testing.expect_value(t, key.secret_key, i32(5678))
	}

	// 7. be_parameter_status.bin
	{
		msg, n := load_and_parse(t, "pgproto/tests_golden_files/be_parameter_status.bin")
		testing.expect_value(t, n, 25)
		param, ok := msg.(Msg_Parameter_Status)
		testing.expect(t, ok, "expected Msg_Parameter_Status")
		testing.expect_value(t, param.name, "server_version")
		testing.expect_value(t, param.value, "16.1")
	}

	// 8. be_ready_for_query_idle.bin
	{
		msg, n := load_and_parse(t, "pgproto/tests_golden_files/be_ready_for_query_idle.bin")
		testing.expect_value(t, n, 6)
		rfq, ok := msg.(Msg_Ready_For_Query)
		testing.expect(t, ok, "expected Msg_Ready_For_Query")
		testing.expect_value(t, rfq.status, Transaction_Status.Idle)
	}

	// 9. be_ready_for_query_tx.bin
	{
		msg, n := load_and_parse(t, "pgproto/tests_golden_files/be_ready_for_query_tx.bin")
		testing.expect_value(t, n, 6)
		rfq, ok := msg.(Msg_Ready_For_Query)
		testing.expect(t, ok, "expected Msg_Ready_For_Query")
		testing.expect_value(t, rfq.status, Transaction_Status.In_Transaction)
	}

	// 10. be_ready_for_query_err.bin
	{
		msg, n := load_and_parse(t, "pgproto/tests_golden_files/be_ready_for_query_err.bin")
		testing.expect_value(t, n, 6)
		rfq, ok := msg.(Msg_Ready_For_Query)
		testing.expect(t, ok, "expected Msg_Ready_For_Query")
		testing.expect_value(t, rfq.status, Transaction_Status.Failed_Transaction)
	}

	// 11. be_row_description.bin
	{
		msg, n := load_and_parse(t, "pgproto/tests_golden_files/be_row_description.bin")
		testing.expect_value(t, n, 51)
		rd, ok := msg.(Msg_Row_Description)
		testing.expect(t, ok, "expected Msg_Row_Description")
		testing.expect_value(t, len(rd.fields), 2)
		testing.expect_value(t, rd.fields[0].name, "id")
		testing.expect_value(t, rd.fields[0].table_oid, u32(1234))
		testing.expect_value(t, rd.fields[0].column_attr_num, i16(1))
		testing.expect_value(t, rd.fields[0].type_oid, u32(23))
		testing.expect_value(t, rd.fields[0].type_size, i16(4))
		testing.expect_value(t, rd.fields[0].type_modifier, i32(-1))
		testing.expect_value(t, rd.fields[0].format_code, Field_Format.Text)
		testing.expect_value(t, rd.fields[1].name, "name")
		testing.expect_value(t, rd.fields[1].table_oid, u32(1234))
		testing.expect_value(t, rd.fields[1].column_attr_num, i16(2))
		testing.expect_value(t, rd.fields[1].type_oid, u32(25))
		testing.expect_value(t, rd.fields[1].type_size, i16(-1))
		testing.expect_value(t, rd.fields[1].type_modifier, i32(-1))
		testing.expect_value(t, rd.fields[1].format_code, Field_Format.Text)
	}

	// 12. be_data_row.bin
	{
		msg, n := load_and_parse(t, "pgproto/tests_golden_files/be_data_row.bin")
		testing.expect_value(t, n, 17)
		dr, ok := msg.(Msg_Data_Row)
		testing.expect(t, ok, "expected Msg_Data_Row")
		testing.expect_value(t, len(dr.values), 2)
		testing.expect_value(t, dr.values[0].is_null, false)
		testing.expect_value(t, string(dr.values[0].data), "42")
		testing.expect_value(t, dr.values[1].is_null, true)
		testing.expect_value(t, len(dr.values[1].data), 0)
	}

	// 13. be_command_complete_select.bin
	{
		msg, n := load_and_parse(t, "pgproto/tests_golden_files/be_command_complete_select.bin")
		testing.expect_value(t, n, 14)
		cc, ok := msg.(Msg_Command_Complete)
		testing.expect(t, ok, "expected Msg_Command_Complete")
		testing.expect_value(t, cc.tag, "SELECT 1")
	}

	// 14. be_command_complete_insert.bin
	{
		msg, n := load_and_parse(t, "pgproto/tests_golden_files/be_command_complete_insert.bin")
		testing.expect_value(t, n, 16)
		cc, ok := msg.(Msg_Command_Complete)
		testing.expect(t, ok, "expected Msg_Command_Complete")
		testing.expect_value(t, cc.tag, "INSERT 0 1")
	}

	// 15. be_error_response.bin
	{
		msg, n := load_and_parse(t, "pgproto/tests_golden_files/be_error_response.bin")
		testing.expect(t, n > 0, "expected positive bytes consumed")
		pg_err, ok := msg.(opg.Postgres_Error)
		testing.expect(t, ok, "expected opg.Postgres_Error")
		testing.expect_value(t, pg_err.severity, "ERROR")
		testing.expect_value(t, pg_err.code, "42P01")
		testing.expect_value(t, pg_err.message, "relation \"nonexistent\" does not exist")
		testing.expect_value(t, pg_err.position, "15")
		testing.expect_value(t, pg_err.file, "parse_relation.c")
		testing.expect_value(t, pg_err.line, "1374")
		testing.expect_value(t, pg_err.routine, "parserOpenTable")
	}

	// 16. be_notice_response.bin
	{
		msg, n := load_and_parse(t, "pgproto/tests_golden_files/be_notice_response.bin")
		testing.expect_value(t, n, 42)
		notice, ok := msg.(Msg_Notice_Response)
		testing.expect(t, ok, "expected Msg_Notice_Response")
		testing.expect_value(t, notice.error.severity, "NOTICE")
		testing.expect_value(t, notice.error.message, "table created successfully")
	}

	// 17. be_empty_query_response.bin
	{
		msg, n := load_and_parse(t, "pgproto/tests_golden_files/be_empty_query_response.bin")
		testing.expect_value(t, n, 5)
		_, ok := msg.(Msg_Empty_Query_Response)
		testing.expect(t, ok, "expected Msg_Empty_Query_Response")
	}

	// 18. be_parse_complete.bin
	{
		msg, n := load_and_parse(t, "pgproto/tests_golden_files/be_parse_complete.bin")
		testing.expect_value(t, n, 5)
		_, ok := msg.(Msg_Parse_Complete)
		testing.expect(t, ok, "expected Msg_Parse_Complete")
	}

	// 19. be_bind_complete.bin
	{
		msg, n := load_and_parse(t, "pgproto/tests_golden_files/be_bind_complete.bin")
		testing.expect_value(t, n, 5)
		_, ok := msg.(Msg_Bind_Complete)
		testing.expect(t, ok, "expected Msg_Bind_Complete")
	}

	// 20. be_close_complete.bin
	{
		msg, n := load_and_parse(t, "pgproto/tests_golden_files/be_close_complete.bin")
		testing.expect_value(t, n, 5)
		_, ok := msg.(Msg_Close_Complete)
		testing.expect(t, ok, "expected Msg_Close_Complete")
	}

	// 21. be_no_data.bin
	{
		msg, n := load_and_parse(t, "pgproto/tests_golden_files/be_no_data.bin")
		testing.expect_value(t, n, 5)
		_, ok := msg.(Msg_No_Data)
		testing.expect(t, ok, "expected Msg_No_Data")
	}

	// 22. be_portal_suspended.bin
	{
		msg, n := load_and_parse(t, "pgproto/tests_golden_files/be_portal_suspended.bin")
		testing.expect_value(t, n, 5)
		_, ok := msg.(Msg_Portal_Suspended)
		testing.expect(t, ok, "expected Msg_Portal_Suspended")
	}

	// 23. be_parameter_description.bin
	{
		msg, n := load_and_parse(t, "pgproto/tests_golden_files/be_parameter_description.bin")
		testing.expect_value(t, n, 15)
		pd, ok := msg.(Msg_Parameter_Description)
		testing.expect(t, ok, "expected Msg_Parameter_Description")
		testing.expect_value(t, len(pd.param_oids), 2)
		testing.expect_value(t, pd.param_oids[0], u32(23))
		testing.expect_value(t, pd.param_oids[1], u32(25))
	}

	// 24. be_notification_response.bin
	{
		msg, n := load_and_parse(t, "pgproto/tests_golden_files/be_notification_response.bin")
		testing.expect_value(t, n, 44)
		notif, ok := msg.(Msg_Notification_Response)
		testing.expect(t, ok, "expected Msg_Notification_Response")
		testing.expect_value(t, notif.process_id, i32(9999))
		testing.expect_value(t, notif.channel, "events_channel")
		testing.expect_value(t, notif.payload, "{\"action\":\"insert\"}")
	}

	// 25. be_copy_in_response.bin
	{
		msg, n := load_and_parse(t, "pgproto/tests_golden_files/be_copy_in_response.bin")
		testing.expect_value(t, n, 12)
		ci, ok := msg.(Msg_Copy_In_Response)
		testing.expect(t, ok, "expected Msg_Copy_In_Response")
		testing.expect_value(t, ci.overall_format, Field_Format.Text)
		testing.expect_value(t, len(ci.column_format_codes), 2)
		testing.expect_value(t, ci.column_format_codes[0], Field_Format.Text)
		testing.expect_value(t, ci.column_format_codes[1], Field_Format.Binary)
	}

	// 26. be_copy_out_response.bin
	{
		msg, n := load_and_parse(t, "pgproto/tests_golden_files/be_copy_out_response.bin")
		testing.expect_value(t, n, 10)
		co, ok := msg.(Msg_Copy_Out_Response)
		testing.expect(t, ok, "expected Msg_Copy_Out_Response")
		testing.expect_value(t, co.overall_format, Field_Format.Binary)
		testing.expect_value(t, len(co.column_format_codes), 1)
		testing.expect_value(t, co.column_format_codes[0], Field_Format.Binary)
	}

	// 27. be_copy_both_response.bin
	{
		msg, n := load_and_parse(t, "pgproto/tests_golden_files/be_copy_both_response.bin")
		testing.expect_value(t, n, 8)
		cb, ok := msg.(Msg_Copy_Both_Response)
		testing.expect(t, ok, "expected Msg_Copy_Both_Response")
		testing.expect_value(t, cb.overall_format, Field_Format.Text)
		testing.expect_value(t, len(cb.column_format_codes), 0)
	}

	// 28. be_copy_data.bin
	{
		msg, n := load_and_parse(t, "pgproto/tests_golden_files/be_copy_data.bin")
		testing.expect_value(t, n, 28)
		cd, ok := msg.(Msg_Copy_Data_Backend)
		testing.expect(t, ok, "expected Msg_Copy_Data_Backend")
		testing.expect_value(t, string(cd.data), "101\tJohn Doe\tDeveloper\n")
	}

	// 29. be_copy_done.bin
	{
		msg, n := load_and_parse(t, "pgproto/tests_golden_files/be_copy_done.bin")
		testing.expect_value(t, n, 5)
		_, ok := msg.(Msg_Copy_Done_Backend)
		testing.expect(t, ok, "expected Msg_Copy_Done_Backend")
	}

	// 30. be_function_call_response.bin
	{
		msg, n := load_and_parse(t, "pgproto/tests_golden_files/be_function_call_response.bin")
		testing.expect_value(t, n, 13)
		fc, ok := msg.(Msg_Function_Call_Response)
		testing.expect(t, ok, "expected Msg_Function_Call_Response")
		testing.expect_value(t, fc.is_null, false)
		testing.expect_value(t, string(fc.data), "test")
	}

	// 31. be_negotiate_protocol_version.bin
	{
		msg, n := load_and_parse(t, "pgproto/tests_golden_files/be_negotiate_protocol_version.bin")
		testing.expect_value(t, n, 23)
		npv, ok := msg.(Msg_Negotiate_Protocol_Version)
		testing.expect(t, ok, "expected Msg_Negotiate_Protocol_Version")
		testing.expect_value(t, npv.minor_version, i32(1))
		testing.expect_value(t, len(npv.unrecognized_options), 2)
		testing.expect_value(t, npv.unrecognized_options[0], "opt1")
		testing.expect_value(t, npv.unrecognized_options[1], "opt2")
	}

	testing.expect_value(t, len(track.allocation_map), 0)
	for _, leak in track.allocation_map {
		testing.expectf(t, false, "Memory leak: %v bytes at %v", leak.size, leak.location)
	}
}

@(test)
test_golden_fuzzing_truncation_matrix :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	testing.expect_value(t, len(BACKEND_FIXTURES), 31)
	testing.expect_value(t, len(FRONTEND_FIXTURES), 20)

	// Test backend truncation matrix: every prefix 0 ..< len(raw) must return typed Protocol_Error
	for path in BACKEND_FIXTURES {
		raw, err_file := os.read_entire_file(path, context.temp_allocator)
		testing.expect_value(t, err_file, nil)

		// Sanity check full parse
		_, full_n, full_err := parse_message(raw, context.temp_allocator)
		testing.expect_value(t, full_err, nil)
		testing.expect_value(t, full_n, len(raw))

		for prefix in 0 ..< len(raw) {
			truncated := raw[:prefix]
			msg, n, err := parse_message(truncated, context.temp_allocator)
			testing.expect(t, err != nil, "expected error on truncated packet")
			testing.expect_value(t, n, 0)
			testing.expect(t, msg == nil, "expected nil message on truncated packet")
			proto_err, is_proto_err := err.(opg.Protocol_Error)
			testing.expectf(
				t,
				is_proto_err,
				"expected opg.Protocol_Error for %s prefix %d/%d, got %v",
				path,
				prefix,
				len(raw),
				err,
			)
			testing.expect(t, proto_err.type != .None, "expected non-None Protocol_Error_Type")
		}
	}

	// Test frontend decoding via Reader cursor underflow methods
	for path in FRONTEND_FIXTURES {
		raw, err_file := os.read_entire_file(path, context.temp_allocator)
		testing.expect_value(t, err_file, nil)

		for prefix in 0 ..< len(raw) {
			truncated := raw[:prefix]

			r: Reader
			reader_init(&r, truncated)

			// 1. Read single bytes until exhaustion then beyond
			for {
				_, ok := reader_read_u8(&r)
				if !ok do break
			}
			_, ok_eof := reader_read_u8(&r)
			testing.expect(t, !ok_eof, "expected underflow on reader_read_u8 past EOF")

			// 2. Multi-byte integer reads on underflowed buffer
			if prefix < 2 {
				reader_init(&r, truncated)
				_, ok_i16 := reader_read_i16(&r)
				testing.expect(t, !ok_i16, "expected false on reader_read_i16")
				reader_init(&r, truncated)
				_, ok_u16 := reader_read_u16(&r)
				testing.expect(t, !ok_u16, "expected false on reader_read_u16")
			}
			if prefix < 4 {
				reader_init(&r, truncated)
				_, ok_i32 := reader_read_i32(&r)
				testing.expect(t, !ok_i32, "expected false on reader_read_i32")
				reader_init(&r, truncated)
				_, ok_u32 := reader_read_u32(&r)
				testing.expect(t, !ok_u32, "expected false on reader_read_u32")
			}
			if prefix < 8 {
				reader_init(&r, truncated)
				_, ok_i64 := reader_read_i64(&r)
				testing.expect(t, !ok_i64, "expected false on reader_read_i64")
			}

			// 3. Reading more bytes than available
			reader_init(&r, truncated)
			_, ok_bytes := reader_read_bytes(&r, len(raw) + 1)
			testing.expect(t, !ok_bytes, "expected false on reader_read_bytes over length")

			// 4. String reading
			reader_init(&r, truncated)
			_, _ = reader_read_string_nt(&r)
			reader_init(&r, truncated)
			_, _ = reader_read_string_nt_clone(&r, context.temp_allocator)
		}
	}

	testing.expect_value(t, len(track.allocation_map), 0)
	for _, leak in track.allocation_map {
		testing.expectf(t, false, "Memory leak: %v bytes at %v", leak.size, leak.location)
	}
}

@(test)
test_golden_corrupted_headers :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	invalid_types := [?]u8{
		0x00, 0xFF, 0xFE, 0x80, 0x7F, 0x01, '?', '!', 'x', 'y', 'z', 'a', 'b', 'M', 'Q',
	}

	negative_lengths := [?]i32{
		-1, -100, -2147483648, -4, -5, 0, 1, 2, 3,
	}

	exceeding_lengths := [?]i32{
		2147483647, // 2^31 - 1
		1000000,
		65536,
		2000,
	}

	for path in BACKEND_FIXTURES {
		raw, err_file := os.read_entire_file(path, context.temp_allocator)
		testing.expect_value(t, err_file, nil)
		testing.expect(t, len(raw) >= 5, "expected golden vector to have at least 5 bytes")

		// 1. Bit-flipped and mutated message types
		// Bit-flip test across all 8 bit positions
		for bit in 0 ..< 8 {
			mutated := slice.clone(raw, context.temp_allocator)
			flipped_type := raw[0] ~ u8(1 << u8(bit))
			mutated[0] = flipped_type
			_, _, err := parse_message(mutated, context.temp_allocator)
			if is_valid_backend_type(flipped_type) {
				if err != nil {
					_, is_proto := err.(opg.Protocol_Error)
					testing.expect(t, is_proto, "expected opg.Protocol_Error on bit-flipped msg type")
				}
			} else {
				testing.expectf(
					t,
					err != nil,
					"expected error on unknown message type 0x%02x from bit flip %d on %s",
					flipped_type,
					bit,
					path,
				)
				proto_err, is_proto := err.(opg.Protocol_Error)
				testing.expectf(
					t,
					is_proto,
					"expected opg.Protocol_Error for unknown type 0x%02x on %s, got %v",
					flipped_type,
					path,
					err,
				)
				testing.expect_value(t, proto_err.type, opg.Protocol_Error_Type.Unknown_Message_Type)
			}
		}

		// Explicit invalid message type identifiers
		for inv_type in invalid_types {
			mutated := slice.clone(raw, context.temp_allocator)
			mutated[0] = inv_type
			msg, n, err := parse_message(mutated, context.temp_allocator)
			testing.expect(t, err != nil, "expected error on invalid message type")
			testing.expect_value(t, n, 0)
			testing.expect(t, msg == nil, "expected nil message on invalid message type")
			proto_err, is_proto := err.(opg.Protocol_Error)
			testing.expectf(
				t,
				is_proto,
				"expected opg.Protocol_Error for invalid type 0x%02x on %s, got %v",
				inv_type,
				path,
				err,
			)
			testing.expect_value(t, proto_err.type, opg.Protocol_Error_Type.Unknown_Message_Type)
		}

		// 2. Negative & sub-minimum length values in header
		for neg_len in negative_lengths {
			mutated := slice.clone(raw, context.temp_allocator)
			len_bytes: [4]byte
			endian.put_i32(len_bytes[:], .Big, neg_len)
			copy(mutated[1:5], len_bytes[:])

			msg, n, err := parse_message(mutated, context.temp_allocator)
			testing.expect(t, err != nil, "expected error on invalid negative length")
			testing.expect_value(t, n, 0)
			testing.expect(t, msg == nil, "expected nil message on invalid negative length")
			proto_err, is_proto := err.(opg.Protocol_Error)
			testing.expectf(
				t,
				is_proto,
				"expected opg.Protocol_Error for length %d on %s, got %v",
				neg_len,
				path,
				err,
			)
			testing.expect_value(t, proto_err.type, opg.Protocol_Error_Type.Invalid_Length)
		}

		// 3. Lengths exceeding payload size (including 2^31 - 1)
		for exc_len in exceeding_lengths {
			if int(exc_len) + 1 <= len(raw) do continue
			mutated := slice.clone(raw, context.temp_allocator)
			len_bytes: [4]byte
			endian.put_i32(len_bytes[:], .Big, exc_len)
			copy(mutated[1:5], len_bytes[:])

			msg, n, err := parse_message(mutated, context.temp_allocator)
			testing.expect(t, err != nil, "expected error on exceeding length")
			testing.expect_value(t, n, 0)
			testing.expect(t, msg == nil, "expected nil message on exceeding length")
			proto_err, is_proto := err.(opg.Protocol_Error)
			testing.expectf(
				t,
				is_proto,
				"expected opg.Protocol_Error for exceeding length %d on %s, got %v",
				exc_len,
				path,
				err,
			)
			testing.expect_value(t, proto_err.type, opg.Protocol_Error_Type.Buffer_Underflow)
		}
	}

	// 4. Payload-level field mutations on specific golden messages
	// DataRow: negative column count and invalid column length (-2)
	{
		raw, _ := os.read_entire_file("pgproto/tests_golden_files/be_data_row.bin", context.temp_allocator)
		// Corrupt column count to -1
		mut_cols := slice.clone(raw, context.temp_allocator)
		mut_cols[5] = 0xFF
		mut_cols[6] = 0xFF
		_, _, err_cols := parse_message(mut_cols, context.temp_allocator)
		testing.expect(t, err_cols != nil, "expected error on negative col count in DataRow")

		// Corrupt column length to -2
		mut_len := slice.clone(raw, context.temp_allocator)
		len_bytes: [4]byte
		endian.put_i32(len_bytes[:], .Big, -2)
		copy(mut_len[7:11], len_bytes[:])
		_, _, err_len := parse_message(mut_len, context.temp_allocator)
		testing.expect(t, err_len != nil, "expected error on invalid negative col length in DataRow")
	}

	// RowDescription: negative field count
	{
		raw, _ := os.read_entire_file("pgproto/tests_golden_files/be_row_description.bin", context.temp_allocator)
		mut_rd := slice.clone(raw, context.temp_allocator)
		mut_rd[5] = 0xFF
		mut_rd[6] = 0xFF
		_, _, err_rd := parse_message(mut_rd, context.temp_allocator)
		testing.expect(t, err_rd != nil, "expected error on negative field count in RowDescription")
	}

	// ReadyForQuery: invalid transaction status character
	{
		raw, _ := os.read_entire_file("pgproto/tests_golden_files/be_ready_for_query_idle.bin", context.temp_allocator)
		mut_rfq := slice.clone(raw, context.temp_allocator)
		mut_rfq[5] = 'X'
		_, _, err_rfq := parse_message(mut_rfq, context.temp_allocator)
		testing.expect(t, err_rfq != nil, "expected error on invalid status in ReadyForQuery")
	}

	// ParameterDescription: negative parameter count
	{
		raw, _ := os.read_entire_file("pgproto/tests_golden_files/be_parameter_description.bin", context.temp_allocator)
		mut_pd := slice.clone(raw, context.temp_allocator)
		mut_pd[5] = 0xFF
		mut_pd[6] = 0xFF
		_, _, err_pd := parse_message(mut_pd, context.temp_allocator)
		testing.expect(t, err_pd != nil, "expected error on negative param count in ParameterDescription")
	}

	// ErrorResponse: unterminated string
	{
		raw, _ := os.read_entire_file("pgproto/tests_golden_files/be_error_response.bin", context.temp_allocator)
		mut_err := slice.clone(raw, context.temp_allocator)
		for i in 5 ..< len(mut_err) {
			if mut_err[i] == 0x00 {
				mut_err[i] = 'A'
			}
		}
		_, _, err_unterm := parse_message(mut_err, context.temp_allocator)
		testing.expect(t, err_unterm != nil, "expected error on unterminated string in ErrorResponse")
	}

	testing.expect_value(t, len(track.allocation_map), 0)
	for _, leak in track.allocation_map {
		testing.expectf(t, false, "Memory leak: %v bytes at %v", leak.size, leak.location)
	}
}
