package pgproto

import "core:mem"
import "core:os"
import "core:testing"
import "../pgerr"

@(test)
test_parse_handshake_messages :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	// 1. ReadyForQuery ('Z') from golden capture
	rfq_raw, err_file_rfq := os.read_entire_file("pgproto/tests_golden_files/ready_for_query_idle.bin", context.temp_allocator)
	testing.expect_value(t, err_file_rfq, nil)
	msg_rfq, n_rfq, err_rfq := parse_message(rfq_raw)
	testing.expect_value(t, err_rfq, nil)
	testing.expect_value(t, n_rfq, 6)
	rfq, is_rfq := msg_rfq.(Msg_Ready_For_Query)
	testing.expect(t, is_rfq, "expected Msg_Ready_For_Query")
	testing.expect_value(t, rfq.status, Transaction_Status.Idle)

	// 2. AuthenticationOk from golden capture
	auth_raw, err_file_auth := os.read_entire_file("pgproto/tests_golden_files/auth_ok.bin", context.temp_allocator)
	testing.expect_value(t, err_file_auth, nil)
	msg_auth, n_auth, err_auth := parse_message(auth_raw)
	testing.expect_value(t, err_auth, nil)
	testing.expect_value(t, n_auth, 9)
	auth, is_auth := msg_auth.(Msg_Authentication)
	testing.expect(t, is_auth, "expected Msg_Authentication")
	testing.expect_value(t, auth.auth_type, Auth_Type.Ok)

	// 3. BackendKeyData ('K') from golden capture
	key_raw, err_file_key := os.read_entire_file("pgproto/tests_golden_files/backend_key_data.bin", context.temp_allocator)
	testing.expect_value(t, err_file_key, nil)
	msg_key, n_key, err_key := parse_message(key_raw)
	testing.expect_value(t, err_key, nil)
	testing.expect_value(t, n_key, 13)
	key, is_key := msg_key.(Msg_Backend_Key_Data)
	testing.expect(t, is_key, "expected Msg_Backend_Key_Data")
	testing.expect_value(t, key.process_id, i32(1234))
	testing.expect_value(t, key.secret_key, i32(5678))

	// 4. AuthenticationMD5Password with salt
	md5_packet := []byte{'R', 0x00, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04}
	msg_md5, n_md5, err_md5 := parse_message(md5_packet)
	testing.expect_value(t, err_md5, nil)
	testing.expect_value(t, n_md5, 13)
	md5_auth, is_md5 := msg_md5.(Msg_Authentication)
	testing.expect(t, is_md5, "expected Msg_Authentication MD5")
	testing.expect_value(t, md5_auth.auth_type, Auth_Type.MD5_Password)
	testing.expect_value(t, md5_auth.salt, [4]u8{0x01, 0x02, 0x03, 0x04})

	// 5. AuthenticationSASL with multiple mechanisms
	sasl_packet := []byte{
		'R', 0x00, 0x00, 0x00, 0x2A, 0x00, 0x00, 0x00, 0x0A,
		'S', 'C', 'R', 'A', 'M', '-', 'S', 'H', 'A', '-', '2', '5', '6', 0x00,
		'S', 'C', 'R', 'A', 'M', '-', 'S', 'H', 'A', '-', '2', '5', '6', '-', 'P', 'L', 'U', 'S', 0x00,
		0x00,
	}
	msg_sasl, n_sasl, err_sasl := parse_message(sasl_packet)
	testing.expect_value(t, err_sasl, nil)
	testing.expect_value(t, n_sasl, len(sasl_packet))
	sasl_auth, is_sasl := msg_sasl.(Msg_Authentication)
	testing.expect(t, is_sasl, "expected Msg_Authentication SASL")
	testing.expect_value(t, sasl_auth.auth_type, Auth_Type.SASL)
	testing.expect_value(t, len(sasl_auth.mechanisms), 2)
	testing.expect_value(t, sasl_auth.mechanisms[0], "SCRAM-SHA-256")
	testing.expect_value(t, sasl_auth.mechanisms[1], "SCRAM-SHA-256-PLUS")

	// 6. AuthenticationSASLContinue
	sasl_cont_packet := []byte{
		'R', 0x00, 0x00, 0x00, 0x1B, 0x00, 0x00, 0x00, 0x0B,
		'r', '=', 'f', 'y', '3', ',', 's', '=', '1', '2', '3', '4', ',', 'i', '=', '4', '0', '9', '6',
	}
	msg_sc, n_sc, err_sc := parse_message(sasl_cont_packet)
	testing.expect_value(t, err_sc, nil)
	testing.expect_value(t, n_sc, len(sasl_cont_packet))
	sc_auth, is_sc := msg_sc.(Msg_Authentication)
	testing.expect(t, is_sc, "expected Msg_Authentication SASL_Continue")
	testing.expect_value(t, sc_auth.auth_type, Auth_Type.SASL_Continue)
	testing.expect_value(t, sc_auth.sasl_data, "r=fy3,s=1234,i=4096")

	// 7. AuthenticationSASLFinal
	sasl_final_packet := []byte{
		'R', 0x00, 0x00, 0x00, 0x13, 0x00, 0x00, 0x00, 0x0C,
		'v', '=', 'r', 'm', 'E', 'x', 'a', 'm', 'p', 'l', 'e',
	}
	msg_sf, n_sf, err_sf := parse_message(sasl_final_packet)
	testing.expect_value(t, err_sf, nil)
	testing.expect_value(t, n_sf, len(sasl_final_packet))
	sf_auth, is_sf := msg_sf.(Msg_Authentication)
	testing.expect(t, is_sf, "expected Msg_Authentication SASL_Final")
	testing.expect_value(t, sf_auth.auth_type, Auth_Type.SASL_Final)
	testing.expect_value(t, sf_auth.sasl_data, "v=rmExample")

	// 8. ParameterStatus ('S')
	param_packet := []byte{
		'S', 0x00, 0x00, 0x00, 0x18,
		's', 'e', 'r', 'v', 'e', 'r', '_', 'v', 'e', 'r', 's', 'i', 'o', 'n', 0x00,
		'1', '6', '.', '1', 0x00,
	}
	msg_param, n_param, err_param := parse_message(param_packet)
	testing.expect_value(t, err_param, nil)
	testing.expect_value(t, n_param, len(param_packet))
	param, is_param := msg_param.(Msg_Parameter_Status)
	testing.expect(t, is_param, "expected Msg_Parameter_Status")
	testing.expect_value(t, param.name, "server_version")
	testing.expect_value(t, param.value, "16.1")

	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
test_parse_query_result_messages :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	// 1. CommandComplete ('C')
	cc_pkt := []byte{'C', 0x00, 0x00, 0x00, 0x0D, 'S', 'E', 'L', 'E', 'C', 'T', ' ', '1', 0x00}
	msg_cc, n_cc, err_cc := parse_message(cc_pkt)
	testing.expect_value(t, err_cc, nil)
	testing.expect_value(t, n_cc, len(cc_pkt))
	cc, is_cc := msg_cc.(Msg_Command_Complete)
	testing.expect(t, is_cc, "expected Msg_Command_Complete")
	testing.expect_value(t, cc.tag, "SELECT 1")

	// 2. EmptyQueryResponse ('I')
	eq_pkt := []byte{'I', 0x00, 0x00, 0x00, 0x04}
	msg_eq, n_eq, err_eq := parse_message(eq_pkt)
	testing.expect_value(t, err_eq, nil)
	testing.expect_value(t, n_eq, 5)
	_, is_eq := msg_eq.(Msg_Empty_Query_Response)
	testing.expect(t, is_eq, "expected Msg_Empty_Query_Response")

	// 3. RowDescription ('T') with 2 columns
	// Field 1: "id", table_oid 1234, col_attr 1, type_oid 23 (INT4), type_size 4, typmod -1, format 0
	// Field 2: "name", table_oid 1234, col_attr 2, type_oid 25 (TEXT), type_size -1, typmod -1, format 0
	var_rd: [dynamic]byte
	len_pos := write_packet_header(&var_rd, 'T')
	write_i16(&var_rd, 2) // 2 fields
	// Col 1
	write_string_nt(&var_rd, "id")
	write_u32(&var_rd, 1234)
	write_i16(&var_rd, 1)
	write_u32(&var_rd, 23)
	write_i16(&var_rd, 4)
	write_i32(&var_rd, -1)
	write_i16(&var_rd, 0)
	// Col 2
	write_string_nt(&var_rd, "name")
	write_u32(&var_rd, 1234)
	write_i16(&var_rd, 2)
	write_u32(&var_rd, 25)
	write_i16(&var_rd, -1)
	write_i32(&var_rd, -1)
	write_i16(&var_rd, 0)
	finish_packet(&var_rd, len_pos)

	msg_rd, n_rd, err_rd := parse_message(var_rd[:])
	testing.expect_value(t, err_rd, nil)
	testing.expect_value(t, n_rd, len(var_rd))
	rd, is_rd := msg_rd.(Msg_Row_Description)
	testing.expect(t, is_rd, "expected Msg_Row_Description")
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

	// 4. DataRow ('D') with 1 valid value and 1 NULL value
	var_dr: [dynamic]byte
	dr_pos := write_packet_header(&var_dr, 'D')
	write_i16(&var_dr, 2) // 2 columns
	// Col 1: length 2, bytes "42"
	write_i32(&var_dr, 2)
	write_bytes(&var_dr, transmute([]byte)string("42"))
	// Col 2: NULL (length -1)
	write_i32(&var_dr, -1)
	finish_packet(&var_dr, dr_pos)

	msg_dr, n_dr, err_dr := parse_message(var_dr[:])
	testing.expect_value(t, err_dr, nil)
	testing.expect_value(t, n_dr, len(var_dr))
	dr, is_dr := msg_dr.(Msg_Data_Row)
	testing.expect(t, is_dr, "expected Msg_Data_Row")
	testing.expect_value(t, len(dr.values), 2)
	testing.expect_value(t, dr.values[0].is_null, false)
	testing.expect_value(t, string(dr.values[0].data), "42")
	testing.expect_value(t, dr.values[1].is_null, true)
	testing.expect_value(t, len(dr.values[1].data), 0)

	delete(var_rd)
	delete(var_dr)

	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
test_parse_query_result_edge_cases :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	// RowDescription with 0 fields
	var_rd0: [dynamic]byte
	pos := write_packet_header(&var_rd0, 'T')
	write_i16(&var_rd0, 0)
	finish_packet(&var_rd0, pos)
	msg_rd0, _, err_rd0 := parse_message(var_rd0[:])
	testing.expect_value(t, err_rd0, nil)
	rd0, is_rd0 := msg_rd0.(Msg_Row_Description)
	testing.expect(t, is_rd0, "expected Msg_Row_Description")
	testing.expect_value(t, len(rd0.fields), 0)

	// Direct call to parse_row_description with invalid/negative field count
	bad_rd_payload := []byte{0xFF, 0xFF} // -1 fields
	_, err_bad_rd := parse_row_description(bad_rd_payload)
	testing.expect(t, err_bad_rd != nil, "expected error on negative field count")

	// Direct call to parse_row_description truncated payload
	short_rd := []byte{0x00}
	_, err_short_rd := parse_row_description(short_rd)
	testing.expect(t, err_short_rd != nil, "expected error on short row description payload")

	// RowDescription truncated in field data
	var_rd_trunc: [dynamic]byte
	pos_t := write_packet_header(&var_rd_trunc, 'T')
	write_i16(&var_rd_trunc, 1)
	write_string_nt(&var_rd_trunc, "col1")
	write_u32(&var_rd_trunc, 100)
	// truncated before remaining field metadata
	finish_packet(&var_rd_trunc, pos_t)
	_, _, err_rd_trunc := parse_message(var_rd_trunc[:])
	testing.expect(t, err_rd_trunc != nil, "expected error on truncated field description")

	// DataRow with 0 columns
	var_dr0: [dynamic]byte
	dr0_pos := write_packet_header(&var_dr0, 'D')
	write_i16(&var_dr0, 0)
	finish_packet(&var_dr0, dr0_pos)
	msg_dr0, _, err_dr0 := parse_message(var_dr0[:])
	testing.expect_value(t, err_dr0, nil)
	dr0, is_dr0 := msg_dr0.(Msg_Data_Row)
	testing.expect(t, is_dr0, "expected Msg_Data_Row")
	testing.expect_value(t, len(dr0.values), 0)

	// Direct call to parse_data_row with negative column count
	bad_dr_payload := []byte{0xFF, 0xFF} // -1 cols
	_, err_bad_dr := parse_data_row(bad_dr_payload)
	testing.expect(t, err_bad_dr != nil, "expected error on negative column count")

	// Direct call to parse_data_row truncated payload
	short_dr := []byte{0x00}
	_, err_short_dr := parse_data_row(short_dr)
	testing.expect(t, err_short_dr != nil, "expected error on short data row payload")

	// DataRow with invalid negative length (< -1, e.g. -2)
	var_dr_bad_len: [dynamic]byte
	dr_bl_pos := write_packet_header(&var_dr_bad_len, 'D')
	write_i16(&var_dr_bad_len, 1)
	write_i32(&var_dr_bad_len, -2)
	finish_packet(&var_dr_bad_len, dr_bl_pos)
	_, _, err_dr_bad_len := parse_message(var_dr_bad_len[:])
	testing.expect(t, err_dr_bad_len != nil, "expected error on col_len < -1")

	// DataRow truncated column value
	var_dr_trunc: [dynamic]byte
	dr_tr_pos := write_packet_header(&var_dr_trunc, 'D')
	write_i16(&var_dr_trunc, 1)
	write_i32(&var_dr_trunc, 10) // specifies 10 bytes
	write_bytes(&var_dr_trunc, transmute([]byte)string("abc")) // only 3 bytes written
	finish_packet(&var_dr_trunc, dr_tr_pos)
	_, _, err_dr_trunc := parse_message(var_dr_trunc[:])
	testing.expect(t, err_dr_trunc != nil, "expected error on truncated column value")

	// CommandComplete unterminated
	bad_cc := []byte{'C', 0x00, 0x00, 0x00, 0x08, 'S', 'E', 'L', 'E'}
	_, _, err_bad_cc := parse_message(bad_cc)
	testing.expect(t, err_bad_cc != nil, "expected error on unterminated CommandComplete")

	delete(var_rd0)
	delete(var_rd_trunc)
	delete(var_dr0)
	delete(var_dr_bad_len)
	delete(var_dr_trunc)

	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
test_parse_error_and_notice_messages :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	// ErrorResponse ('E') with SQLSTATE 42P01 (undefined table)
	var_err: [dynamic]byte
	pos := write_packet_header(&var_err, 'E')
	write_u8(&var_err, 'S'); write_string_nt(&var_err, "ERROR")
	write_u8(&var_err, 'V'); write_string_nt(&var_err, "ERROR")
	write_u8(&var_err, 'C'); write_string_nt(&var_err, "42P01")
	write_u8(&var_err, 'M'); write_string_nt(&var_err, "relation \"nonexistent\" does not exist")
	write_u8(&var_err, 'P'); write_string_nt(&var_err, "15")
	write_u8(&var_err, 'F'); write_string_nt(&var_err, "parse_relation.c")
	write_u8(&var_err, 'L'); write_string_nt(&var_err, "1374")
	write_u8(&var_err, 'R'); write_string_nt(&var_err, "parserOpenTable")
	write_u8(&var_err, 0x00) // terminating null
	finish_packet(&var_err, pos)

	msg_e, n_e, err_e := parse_message(var_err[:])
	testing.expect_value(t, err_e, nil)
	testing.expect_value(t, n_e, len(var_err))
	err_resp, is_err := msg_e.(Msg_Error_Response)
	testing.expect(t, is_err, "expected Msg_Error_Response")
	pg_err := err_resp.error
	testing.expect_value(t, pg_err.severity, "ERROR")
	testing.expect_value(t, pg_err.severity_unlocalized, "ERROR")
	testing.expect_value(t, pg_err.code, "42P01")
	testing.expect_value(t, pg_err.message, "relation \"nonexistent\" does not exist")
	testing.expect_value(t, pg_err.position, "15")
	testing.expect_value(t, pg_err.file, "parse_relation.c")
	testing.expect_value(t, pg_err.line, "1374")
	testing.expect_value(t, pg_err.routine, "parserOpenTable")

	// NoticeResponse ('N')
	var_n: [dynamic]byte
	n_pos := write_packet_header(&var_n, 'N')
	write_u8(&var_n, 'S'); write_string_nt(&var_n, "NOTICE")
	write_u8(&var_n, 'M'); write_string_nt(&var_n, "table created successfully")
	write_u8(&var_n, 0x00)
	finish_packet(&var_n, n_pos)

	msg_n, n_n, err_n := parse_message(var_n[:])
	testing.expect_value(t, err_n, nil)
	testing.expect_value(t, n_n, len(var_n))
	notice, is_notice := msg_n.(Msg_Notice_Response)
	testing.expect(t, is_notice, "expected Msg_Notice_Response")
	testing.expect_value(t, notice.error.severity, "NOTICE")
	testing.expect_value(t, notice.error.message, "table created successfully")

	// All structured error fields
	var_all: [dynamic]byte
	all_pos := write_packet_header(&var_all, 'E')
	write_u8(&var_all, 'S'); write_string_nt(&var_all, "FATAL")
	write_u8(&var_all, 'V'); write_string_nt(&var_all, "FATAL")
	write_u8(&var_all, 'C'); write_string_nt(&var_all, "28P01")
	write_u8(&var_all, 'M'); write_string_nt(&var_all, "password authentication failed")
	write_u8(&var_all, 'D'); write_string_nt(&var_all, "User does not exist")
	write_u8(&var_all, 'H'); write_string_nt(&var_all, "Check your credentials")
	write_u8(&var_all, 'P'); write_string_nt(&var_all, "1")
	write_u8(&var_all, 'p'); write_string_nt(&var_all, "2")
	write_u8(&var_all, 'q'); write_string_nt(&var_all, "SELECT 1")
	write_u8(&var_all, 'W'); write_string_nt(&var_all, "PL/pgSQL function auth()")
	write_u8(&var_all, 's'); write_string_nt(&var_all, "public")
	write_u8(&var_all, 't'); write_string_nt(&var_all, "users")
	write_u8(&var_all, 'c'); write_string_nt(&var_all, "password")
	write_u8(&var_all, 'd'); write_string_nt(&var_all, "varchar")
	write_u8(&var_all, 'n'); write_string_nt(&var_all, "users_pkey")
	write_u8(&var_all, 'F'); write_string_nt(&var_all, "auth.c")
	write_u8(&var_all, 'L'); write_string_nt(&var_all, "42")
	write_u8(&var_all, 'R'); write_string_nt(&var_all, "CheckPassword")
	write_u8(&var_all, 0x00)
	finish_packet(&var_all, all_pos)

	msg_all, n_all, err_all := parse_message(var_all[:])
	testing.expect_value(t, err_all, nil)
	testing.expect_value(t, n_all, len(var_all))
	all_resp, is_all_err := msg_all.(Msg_Error_Response)
	testing.expect(t, is_all_err, "expected Msg_Error_Response for all fields")
	all_err := all_resp.error
	testing.expect_value(t, all_err.severity, "FATAL")
	testing.expect_value(t, all_err.severity_unlocalized, "FATAL")
	testing.expect_value(t, all_err.code, "28P01")
	testing.expect_value(t, all_err.message, "password authentication failed")
	testing.expect_value(t, all_err.detail, "User does not exist")
	testing.expect_value(t, all_err.hint, "Check your credentials")
	testing.expect_value(t, all_err.position, "1")
	testing.expect_value(t, all_err.internal_position, "2")
	testing.expect_value(t, all_err.internal_query, "SELECT 1")
	testing.expect_value(t, all_err.where_context, "PL/pgSQL function auth()")
	testing.expect_value(t, all_err.schema_name, "public")
	testing.expect_value(t, all_err.table_name, "users")
	testing.expect_value(t, all_err.column_name, "password")
	testing.expect_value(t, all_err.data_type_name, "varchar")
	testing.expect_value(t, all_err.constraint_name, "users_pkey")
	testing.expect_value(t, all_err.file, "auth.c")
	testing.expect_value(t, all_err.line, "42")
	testing.expect_value(t, all_err.routine, "CheckPassword")

	delete(var_err)
	delete(var_n)
	delete(var_all)

	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
test_parse_error_and_notice_edge_cases :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	// 1. Unknown field code should be ignored gracefully
	var_unk: [dynamic]byte
	unk_pos := write_packet_header(&var_unk, 'E')
	write_u8(&var_unk, 'S'); write_string_nt(&var_unk, "ERROR")
	write_u8(&var_unk, 'Z'); write_string_nt(&var_unk, "future_field_value")
	write_u8(&var_unk, 'M'); write_string_nt(&var_unk, "msg")
	write_u8(&var_unk, 0x00)
	finish_packet(&var_unk, unk_pos)

	msg_unk, _, err_unk := parse_message(var_unk[:])
	testing.expect_value(t, err_unk, nil)
	unk_resp, is_unk := msg_unk.(Msg_Error_Response)
	testing.expect(t, is_unk, "expected Msg_Error_Response")
	testing.expect_value(t, unk_resp.error.severity, "ERROR")
	testing.expect_value(t, unk_resp.error.severity_unlocalized, "")
	testing.expect_value(t, unk_resp.error.message, "msg")

	// 2. Unterminated field string
	var_unterm: [dynamic]byte
	unterm_pos := write_packet_header(&var_unterm, 'E')
	write_u8(&var_unterm, 'M')
	write_bytes(&var_unterm, transmute([]byte)string("unterminated message"))
	// no null byte written
	finish_packet(&var_unterm, unterm_pos)

	_, _, err_unterm := parse_message(var_unterm[:])
	testing.expect(t, err_unterm != nil, "expected error on unterminated field string")

	// 3. Missing packet terminating null byte
	var_no_null: [dynamic]byte
	nn_pos := write_packet_header(&var_no_null, 'E')
	write_u8(&var_no_null, 'M'); write_string_nt(&var_no_null, "valid message")
	// missing 0x00 terminating null byte
	finish_packet(&var_no_null, nn_pos)

	_, _, err_nn := parse_message(var_no_null[:])
	testing.expect(t, err_nn != nil, "expected error on missing terminating null byte")

	// 4. Direct call to parse_error_or_notice_fields with empty payload
	_, err_empty := parse_error_or_notice_fields([]byte{})
	testing.expect(t, err_empty != nil, "expected error on empty payload")

	delete(var_unk)
	delete(var_unterm)
	delete(var_no_null)

	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
test_parse_extended_and_copy_messages :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	// 1. Completion & Suspended signals
	sig_1 := []byte{'1', 0, 0, 0, 4}
	m1, n1, err1 := parse_message(sig_1)
	testing.expect_value(t, err1, nil)
	testing.expect_value(t, n1, 5)
	_, is_pc := m1.(Msg_Parse_Complete); testing.expect(t, is_pc, "expected Msg_Parse_Complete")

	sig_2 := []byte{'2', 0, 0, 0, 4}
	m2, n2, err2 := parse_message(sig_2)
	testing.expect_value(t, err2, nil)
	testing.expect_value(t, n2, 5)
	_, is_bc := m2.(Msg_Bind_Complete); testing.expect(t, is_bc, "expected Msg_Bind_Complete")

	sig_3 := []byte{'3', 0, 0, 0, 4}
	m3, n3, err3 := parse_message(sig_3)
	testing.expect_value(t, err3, nil)
	testing.expect_value(t, n3, 5)
	_, is_cc := m3.(Msg_Close_Complete); testing.expect(t, is_cc, "expected Msg_Close_Complete")

	sig_n := []byte{'n', 0, 0, 0, 4}
	mn, nn, errn := parse_message(sig_n)
	testing.expect_value(t, errn, nil)
	testing.expect_value(t, nn, 5)
	_, is_nd := mn.(Msg_No_Data); testing.expect(t, is_nd, "expected Msg_No_Data")

	sig_s := []byte{'s', 0, 0, 0, 4}
	ms, ns, errs := parse_message(sig_s)
	testing.expect_value(t, errs, nil)
	testing.expect_value(t, ns, 5)
	_, is_ps := ms.(Msg_Portal_Suspended); testing.expect(t, is_ps, "expected Msg_Portal_Suspended")

	// 2. ParameterDescription ('t') with 2 OIDs (23, 25)
	pd_pkt := []byte{'t', 0, 0, 0, 14, 0, 2, 0, 0, 0, 23, 0, 0, 0, 25}
	m_pd, n_pd, err_pd := parse_message(pd_pkt)
	testing.expect_value(t, err_pd, nil)
	testing.expect_value(t, n_pd, len(pd_pkt))
	pd, is_pd := m_pd.(Msg_Parameter_Description)
	testing.expect(t, is_pd, "expected Msg_Parameter_Description")
	testing.expect_value(t, len(pd.param_oids), 2)
	testing.expect_value(t, pd.param_oids[0], u32(23))
	testing.expect_value(t, pd.param_oids[1], u32(25))

	// 3. NotificationResponse ('A')
	var_a: [dynamic]byte
	a_pos := write_packet_header(&var_a, 'A')
	write_i32(&var_a, 9999)
	write_string_nt(&var_a, "events_channel")
	write_string_nt(&var_a, "{\"action\":\"insert\"}")
	finish_packet(&var_a, a_pos)

	m_a, n_a, err_a := parse_message(var_a[:])
	testing.expect_value(t, err_a, nil)
	testing.expect_value(t, n_a, len(var_a))
	notif, is_notif := m_a.(Msg_Notification_Response)
	testing.expect(t, is_notif, "expected Msg_Notification_Response")
	testing.expect_value(t, notif.process_id, i32(9999))
	testing.expect_value(t, notif.channel, "events_channel")
	testing.expect_value(t, notif.payload, "{\"action\":\"insert\"}")

	// 4. CopyInResponse ('G'), CopyOutResponse ('H'), CopyBothResponse ('W')
	var_g: [dynamic]byte
	g_pos := write_packet_header(&var_g, 'G')
	write_u8(&var_g, 0) // overall format text
	write_i16(&var_g, 2)
	write_i16(&var_g, 0)
	write_i16(&var_g, 1)
	finish_packet(&var_g, g_pos)

	m_g, n_g, err_g := parse_message(var_g[:])
	testing.expect_value(t, err_g, nil)
	testing.expect_value(t, n_g, len(var_g))
	copy_in, is_ci := m_g.(Msg_Copy_In_Response)
	testing.expect(t, is_ci, "expected Msg_Copy_In_Response")
	testing.expect_value(t, copy_in.overall_format, Field_Format.Text)
	testing.expect_value(t, len(copy_in.column_format_codes), 2)
	testing.expect_value(t, copy_in.column_format_codes[0], Field_Format.Text)
	testing.expect_value(t, copy_in.column_format_codes[1], Field_Format.Binary)

	var_h: [dynamic]byte
	h_pos := write_packet_header(&var_h, 'H')
	write_u8(&var_h, 1) // overall format binary
	write_i16(&var_h, 1)
	write_i16(&var_h, 1)
	finish_packet(&var_h, h_pos)

	m_h, n_h, err_h := parse_message(var_h[:])
	testing.expect_value(t, err_h, nil)
	testing.expect_value(t, n_h, len(var_h))
	copy_out, is_co := m_h.(Msg_Copy_Out_Response)
	testing.expect(t, is_co, "expected Msg_Copy_Out_Response")
	testing.expect_value(t, copy_out.overall_format, Field_Format.Binary)
	testing.expect_value(t, len(copy_out.column_format_codes), 1)
	testing.expect_value(t, copy_out.column_format_codes[0], Field_Format.Binary)

	var_w: [dynamic]byte
	w_pos := write_packet_header(&var_w, 'W')
	write_u8(&var_w, 0) // overall format text
	write_i16(&var_w, 0)
	finish_packet(&var_w, w_pos)

	m_w, n_w, err_w := parse_message(var_w[:])
	testing.expect_value(t, err_w, nil)
	testing.expect_value(t, n_w, len(var_w))
	copy_both, is_cb := m_w.(Msg_Copy_Both_Response)
	testing.expect(t, is_cb, "expected Msg_Copy_Both_Response")
	testing.expect_value(t, copy_both.overall_format, Field_Format.Text)
	testing.expect_value(t, len(copy_both.column_format_codes), 0)

	// 5. CopyData ('d') and CopyDone ('c')
	cd_pkt := []byte{'d', 0, 0, 0, 9, 'c', 'o', 'p', 'y', '1'}
	m_cd, n_cd, err_cd := parse_message(cd_pkt)
	testing.expect_value(t, err_cd, nil)
	testing.expect_value(t, n_cd, len(cd_pkt))
	cd, is_cd := m_cd.(Msg_Copy_Data_Backend)
	testing.expect(t, is_cd, "expected Msg_Copy_Data_Backend")
	testing.expect_value(t, string(cd.data), "copy1")

	cdo_pkt := []byte{'c', 0, 0, 0, 4}
	m_cdo, n_cdo, err_cdo := parse_message(cdo_pkt)
	testing.expect_value(t, err_cdo, nil)
	testing.expect_value(t, n_cdo, len(cdo_pkt))
	_, is_cdo := m_cdo.(Msg_Copy_Done_Backend)
	testing.expect(t, is_cdo, "expected Msg_Copy_Done_Backend")

	// 6. FunctionCallResponse ('V')
	fc_pkt := []byte{'V', 0, 0, 0, 12, 0, 0, 0, 4, 't', 'e', 's', 't'}
	m_fc, n_fc, err_fc := parse_message(fc_pkt)
	testing.expect_value(t, err_fc, nil)
	testing.expect_value(t, n_fc, len(fc_pkt))
	fc, is_fc := m_fc.(Msg_Function_Call_Response)
	testing.expect(t, is_fc, "expected Msg_Function_Call_Response")
	testing.expect_value(t, fc.is_null, false)
	testing.expect_value(t, string(fc.data), "test")

	// FunctionCallResponse with NULL value
	fc_null_pkt := []byte{'V', 0, 0, 0, 8, 0xFF, 0xFF, 0xFF, 0xFF}
	m_fcn, n_fcn, err_fcn := parse_message(fc_null_pkt)
	testing.expect_value(t, err_fcn, nil)
	testing.expect_value(t, n_fcn, len(fc_null_pkt))
	fcn, is_fcn := m_fcn.(Msg_Function_Call_Response)
	testing.expect(t, is_fcn, "expected Msg_Function_Call_Response NULL")
	testing.expect_value(t, fcn.is_null, true)
	testing.expect_value(t, len(fcn.data), 0)

	// 7. NegotiateProtocolVersion ('v')
	var_v: [dynamic]byte
	v_pos := write_packet_header(&var_v, 'v')
	write_i32(&var_v, 1) // minor version 1
	write_i32(&var_v, 2) // 2 unrecognized options
	write_string_nt(&var_v, "opt1")
	write_string_nt(&var_v, "opt2")
	finish_packet(&var_v, v_pos)

	m_v, n_v, err_v := parse_message(var_v[:])
	testing.expect_value(t, err_v, nil)
	testing.expect_value(t, n_v, len(var_v))
	npv, is_npv := m_v.(Msg_Negotiate_Protocol_Version)
	testing.expect(t, is_npv, "expected Msg_Negotiate_Protocol_Version")
	testing.expect_value(t, npv.minor_version, i32(1))
	testing.expect_value(t, len(npv.unrecognized_options), 2)
	testing.expect_value(t, npv.unrecognized_options[0], "opt1")
	testing.expect_value(t, npv.unrecognized_options[1], "opt2")

	delete(var_a)
	delete(var_g)
	delete(var_h)
	delete(var_w)
	delete(var_v)

	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
test_parse_extended_and_copy_edge_cases :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	// 1. ParameterDescription edge cases
	pd_zero := []byte{'t', 0, 0, 0, 6, 0, 0}
	m_pd0, _, err_pd0 := parse_message(pd_zero)
	testing.expect_value(t, err_pd0, nil)
	pd0, is_pd0 := m_pd0.(Msg_Parameter_Description)
	testing.expect(t, is_pd0, "expected Msg_Parameter_Description")
	testing.expect_value(t, len(pd0.param_oids), 0)

	// Direct call to parse_parameter_description with negative count
	bad_pd_payload := []byte{0xFF, 0xFF}
	_, err_bad_pd := parse_parameter_description(bad_pd_payload)
	testing.expect(t, err_bad_pd != nil, "expected error on negative param count")

	// Direct call to parse_parameter_description truncated
	short_pd := []byte{0x00}
	_, err_short_pd := parse_parameter_description(short_pd)
	testing.expect(t, err_short_pd != nil, "expected error on short pd payload")

	// Truncated param OID
	trunc_pd := []byte{'t', 0, 0, 0, 8, 0, 1, 0, 0}
	_, _, err_trunc_pd := parse_message(trunc_pd)
	testing.expect(t, err_trunc_pd != nil, "expected error on truncated param OID")

	// 2. NotificationResponse edge cases
	// Direct call to parse_notification with short payload
	_, err_short_notif := parse_notification([]byte{0, 0})
	testing.expect(t, err_short_notif != nil, "expected error on short notification payload")

	// Unterminated channel
	bad_notif_chan := []byte{'A', 0, 0, 0, 8, 0, 0, 0, 1, 'x'}
	_, _, err_bnc := parse_message(bad_notif_chan)
	testing.expect(t, err_bnc != nil, "expected error on unterminated channel")

	// Unterminated payload
	bad_notif_pl := []byte{'A', 0, 0, 0, 10, 0, 0, 0, 1, 'x', 0, 'y'}
	_, _, err_bnpl := parse_message(bad_notif_pl)
	testing.expect(t, err_bnpl != nil, "expected error on unterminated payload")

	// 3. COPY response edge cases
	// Direct call to parse_copy_response with short payload
	_, _, err_short_cr := parse_copy_response([]byte{0})
	testing.expect(t, err_short_cr != nil, "expected error on short copy response payload")

	// Direct call to parse_copy_response with negative column count
	_, _, err_neg_cols := parse_copy_response([]byte{0, 0xFF, 0xFF})
	testing.expect(t, err_neg_cols != nil, "expected error on negative col count in copy response")

	// Truncated column format code
	bad_cr_fmt := []byte{'G', 0, 0, 0, 8, 0, 0, 1, 0}
	_, _, err_bad_crf := parse_message(bad_cr_fmt)
	testing.expect(t, err_bad_crf != nil, "expected error on truncated column format code")

	// 4. FunctionCallResponse edge cases
	// Direct call to parse_message with truncated FunctionCallResponse
	bad_fc := []byte{'V', 0, 0, 0, 5, 0}
	_, _, err_bad_fc := parse_message(bad_fc)
	testing.expect(t, err_bad_fc != nil, "expected error on truncated FunctionCallResponse")

	// col_len < -1
	bad_fc_len := []byte{'V', 0, 0, 0, 8, 0xFF, 0xFF, 0xFF, 0xFE}
	_, _, err_bad_fcl := parse_message(bad_fc_len)
	testing.expect(t, err_bad_fcl != nil, "expected error on fc col_len < -1")

	// Truncated value data
	bad_fc_data := []byte{'V', 0, 0, 0, 9, 0, 0, 0, 5, 'a'}
	_, _, err_bad_fcd := parse_message(bad_fc_data)
	testing.expect(t, err_bad_fcd != nil, "expected error on truncated fc data")

	// 5. NegotiateProtocolVersion edge cases
	// Direct call to parse_message with truncated NegotiateProtocolVersion
	bad_npv_hdr := []byte{'v', 0, 0, 0, 6, 0, 0}
	_, _, err_npv_hdr := parse_message(bad_npv_hdr)
	testing.expect(t, err_npv_hdr != nil, "expected error on truncated NegotiateProtocolVersion header")

	// Negative unrecognized options count
	bad_npv_neg := []byte{'v', 0, 0, 0, 12, 0, 0, 0, 1, 0xFF, 0xFF, 0xFF, 0xFF}
	_, _, err_npv_neg := parse_message(bad_npv_neg)
	testing.expect(t, err_npv_neg != nil, "expected error on negative options count")

	// Unterminated option string
	bad_npv_unterm := []byte{'v', 0, 0, 0, 13, 0, 0, 0, 1, 0, 0, 0, 1, 'o'}
	_, _, err_npv_unterm := parse_message(bad_npv_unterm)
	testing.expect(t, err_npv_unterm != nil, "expected error on unterminated option string")

	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
test_parse_malformed_and_underflow_packets :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	// 1. Header underflow (< 5 bytes)
	_, _, err1 := parse_message([]byte{'Z', 0, 0})
	p_err1, ok1 := err1.(pgerr.Protocol_Error)
	testing.expect(t, ok1, "expected Protocol_Error")
	testing.expect_value(t, p_err1.type, pgerr.Protocol_Error_Type.Buffer_Underflow)

	// 2. Invalid length header (< 4)
	_, _, err2 := parse_message([]byte{'Z', 0, 0, 0, 2, 'I'})
	p_err2, ok2 := err2.(pgerr.Protocol_Error)
	testing.expect(t, ok2, "expected Protocol_Error")
	testing.expect_value(t, p_err2.type, pgerr.Protocol_Error_Type.Invalid_Length)

	// 3. Payload underflow
	_, _, err3 := parse_message([]byte{'Z', 0, 0, 0, 10, 'I'})
	p_err3, ok3 := err3.(pgerr.Protocol_Error)
	testing.expect(t, ok3, "expected Protocol_Error")
	testing.expect_value(t, p_err3.type, pgerr.Protocol_Error_Type.Buffer_Underflow)

	// 4. Unknown message type
	_, _, err4 := parse_message([]byte{'?', 0, 0, 0, 4})
	p_err4, ok4 := err4.(pgerr.Protocol_Error)
	testing.expect(t, ok4, "expected Protocol_Error")
	testing.expect_value(t, p_err4.type, pgerr.Protocol_Error_Type.Unknown_Message_Type)

	// 5. Malformed ReadyForQuery (payload length 0)
	_, _, err5 := parse_message([]byte{'Z', 0, 0, 0, 4})
	p_err5, ok5 := err5.(pgerr.Protocol_Error)
	testing.expect(t, ok5, "expected Protocol_Error")
	testing.expect_value(t, p_err5.type, pgerr.Protocol_Error_Type.Malformed_Packet)

	// 6. Invalid ReadyForQuery status character (not 'I', 'T', 'E')
	_, _, err6 := parse_message([]byte{'Z', 0, 0, 0, 5, 'X'})
	p_err6, ok6 := err6.(pgerr.Protocol_Error)
	testing.expect(t, ok6, "expected Protocol_Error")
	testing.expect_value(t, p_err6.type, pgerr.Protocol_Error_Type.Malformed_Packet)

	// 7. Authentication payload too short (< 4 bytes for auth type)
	_, _, err7 := parse_message([]byte{'R', 0, 0, 0, 6, 0, 0})
	p_err7, ok7 := err7.(pgerr.Protocol_Error)
	testing.expect(t, ok7, "expected Protocol_Error")
	testing.expect_value(t, p_err7.type, pgerr.Protocol_Error_Type.Malformed_Packet)

	// 8. Authentication MD5 missing salt (< 4 bytes salt)
	_, _, err8 := parse_message([]byte{'R', 0, 0, 0, 10, 0, 0, 0, 5, 1, 2})
	p_err8, ok8 := err8.(pgerr.Protocol_Error)
	testing.expect(t, ok8, "expected Protocol_Error")
	testing.expect_value(t, p_err8.type, pgerr.Protocol_Error_Type.Malformed_Packet)

	// 9. Authentication SASL unterminated mechanism string
	_, _, err9 := parse_message([]byte{'R', 0, 0, 0, 13, 0, 0, 0, 10, 'S', 'C', 'R', 'A', 'M'})
	p_err9, ok9 := err9.(pgerr.Protocol_Error)
	testing.expect(t, ok9, "expected Protocol_Error")
	testing.expect_value(t, p_err9.type, pgerr.Protocol_Error_Type.Malformed_Packet)

	// 10. BackendKeyData too short (< 8 bytes payload)
	_, _, err10 := parse_message([]byte{'K', 0, 0, 0, 8, 0, 0, 0, 1})
	p_err10, ok10 := err10.(pgerr.Protocol_Error)
	testing.expect(t, ok10, "expected Protocol_Error")
	testing.expect_value(t, p_err10.type, pgerr.Protocol_Error_Type.Malformed_Packet)

	// 11. ParameterStatus malformed / unterminated strings
	_, _, err11 := parse_message([]byte{'S', 0, 0, 0, 8, 'k', 'e', 'y', 0})
	p_err11, ok11 := err11.(pgerr.Protocol_Error)
	testing.expect(t, ok11, "expected Protocol_Error")
	testing.expect_value(t, p_err11.type, pgerr.Protocol_Error_Type.Malformed_Packet)

	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
test_parse_authentication_unknown_code :: proc(t: ^testing.T) {
	// Auth code 4 (obsolete crypt password) is not a recognized Auth_Type.
	pkt := []byte{'R', 0, 0, 0, 8, 0, 0, 0, 4}
	msg, n, err := parse_message(pkt)
	testing.expect(t, msg == nil, "expected nil message for unknown auth code")
	testing.expect_value(t, n, 0)
	p_err, is_proto := err.(pgerr.Protocol_Error)
	testing.expect(t, is_proto, "expected Protocol_Error")
	testing.expect_value(t, p_err.type, pgerr.Protocol_Error_Type.Unknown_Auth_Type)

	pkt_hi := []byte{'R', 0, 0, 0, 8, 0, 0, 0, 99}
	_, _, err_hi := parse_message(pkt_hi)
	p_err_hi, is_proto_hi := err_hi.(pgerr.Protocol_Error)
	testing.expect(t, is_proto_hi, "expected Protocol_Error")
	testing.expect_value(t, p_err_hi.type, pgerr.Protocol_Error_Type.Unknown_Auth_Type)
}

@(test)
test_parse_unsupported_format_codes :: proc(t: ^testing.T) {
	buf: [dynamic]byte
	defer delete(buf)

	// 1. RowDescription field with format code 7
	pos := write_packet_header(&buf, 'T')
	write_i16(&buf, 1)
	write_string_nt(&buf, "id")
	write_u32(&buf, 0)
	write_i16(&buf, 0)
	write_u32(&buf, 23)
	write_i16(&buf, 4)
	write_i32(&buf, -1)
	write_i16(&buf, 7) // invalid: only 0 (text) and 1 (binary) exist
	finish_packet(&buf, pos)
	_, _, err_rd := parse_message(buf[:])
	p_rd, is_rd := err_rd.(pgerr.Protocol_Error)
	testing.expect(t, is_rd, "expected Protocol_Error for RowDescription format code")
	testing.expect_value(t, p_rd.type, pgerr.Protocol_Error_Type.Unsupported_Format_Code)

	// 2. CopyInResponse with invalid overall format 2
	clear(&buf)
	pos = write_packet_header(&buf, 'G')
	write_u8(&buf, 2)
	write_i16(&buf, 0)
	finish_packet(&buf, pos)
	_, _, err_ov := parse_message(buf[:])
	p_ov, is_ov := err_ov.(pgerr.Protocol_Error)
	testing.expect(t, is_ov, "expected Protocol_Error for overall copy format")
	testing.expect_value(t, p_ov.type, pgerr.Protocol_Error_Type.Unsupported_Format_Code)

	// 3. CopyOutResponse with invalid column format code 9
	clear(&buf)
	pos = write_packet_header(&buf, 'H')
	write_u8(&buf, 0)
	write_i16(&buf, 1)
	write_i16(&buf, 9)
	finish_packet(&buf, pos)
	_, _, err_col := parse_message(buf[:])
	p_col, is_col := err_col.(pgerr.Protocol_Error)
	testing.expect(t, is_col, "expected Protocol_Error for column copy format")
	testing.expect_value(t, p_col.type, pgerr.Protocol_Error_Type.Unsupported_Format_Code)
}
