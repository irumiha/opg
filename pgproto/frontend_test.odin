package pgproto

import "core:mem"
import "core:testing"

/*
	bytes converts a string to a byte slice.
*/
bytes :: proc(s: string) -> []byte {
	return transmute([]byte)s
}

@(test)
test_encode_handshake_messages :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	buf: [dynamic]byte
	defer delete(buf)

	// 1. SSLRequest
	ssl_len := encode_ssl_request(&buf)
	testing.expect_value(t, ssl_len, 8)
	testing.expect_value(t, len(buf), 8)
	expected_ssl := []byte{0x00, 0x00, 0x00, 0x08, 0x04, 0xD2, 0x16, 0x2F}
	for i in 0 ..< 8 {
		testing.expect_value(t, buf[i], expected_ssl[i])
	}

	// 2. CancelRequest
	clear(&buf)
	cancel_len := encode_cancel_request(&buf, 1234, 5678)
	testing.expect_value(t, cancel_len, 16)
	testing.expect_value(t, len(buf), 16)
	r: Reader
	reader_init(&r, buf[:])
	c_len, _ := reader_read_i32(&r)
	c_code, _ := reader_read_i32(&r)
	c_pid, _ := reader_read_i32(&r)
	c_key, _ := reader_read_i32(&r)
	testing.expect_value(t, c_len, 16)
	testing.expect_value(t, c_code, i32(80877102))
	testing.expect_value(t, c_pid, 1234)
	testing.expect_value(t, c_key, 5678)

	// 3. StartupMessage
	clear(&buf)
	startup := Msg_Startup{
		protocol_version = 196608,
		params = []Startup_Param{
			{name = "user", value = "postgres"},
			{name = "database", value = "app_db"},
		},
	}
	s_len := encode_startup(&buf, startup)
	testing.expect_value(t, s_len, len(buf))
	reader_init(&r, buf[:])
	dec_len, _ := reader_read_i32(&r)
	dec_ver, _ := reader_read_i32(&r)
	p1_k, _ := reader_read_string_nt(&r)
	p1_v, _ := reader_read_string_nt(&r)
	p2_k, _ := reader_read_string_nt(&r)
	p2_v, _ := reader_read_string_nt(&r)
	term, _ := reader_read_u8(&r)
	testing.expect_value(t, dec_len, i32(len(buf)))
	testing.expect_value(t, dec_ver, 196608)
	testing.expect_value(t, p1_k, "user")
	testing.expect_value(t, p1_v, "postgres")
	testing.expect_value(t, p2_k, "database")
	testing.expect_value(t, p2_v, "app_db")
	testing.expect_value(t, term, u8(0x00))

	// 3b. StartupMessage with default protocol_version (0 -> 196608)
	clear(&buf)
	startup_default := Msg_Startup{
		protocol_version = 0,
		params = []Startup_Param{
			{name = "user", value = "postgres"},
		},
	}
	s_len_def := encode_startup(&buf, startup_default)
	testing.expect_value(t, s_len_def, len(buf))
	reader_init(&r, buf[:])
	dec_len_def, _ := reader_read_i32(&r)
	dec_ver_def, _ := reader_read_i32(&r)
	testing.expect_value(t, dec_len_def, i32(len(buf)))
	testing.expect_value(t, dec_ver_def, 196608)

	// 4. PasswordMessage
	clear(&buf)
	p_len := encode_password(&buf, "secret")
	testing.expect_value(t, p_len, len(buf))
	reader_init(&r, buf[:])
	p_type, _ := reader_read_u8(&r)
	p_pkt_len, _ := reader_read_i32(&r)
	p_pwd, _ := reader_read_string_nt(&r)
	testing.expect_value(t, p_type, u8('p'))
	testing.expect_value(t, p_pkt_len, 4 + 7) // 4 + len("secret\0")
	testing.expect_value(t, p_pwd, "secret")

	// 5. SASLInitialResponse
	clear(&buf)
	sasl_init := Msg_SASL_Initial_Response{
		mechanism = "SCRAM-SHA-256",
		data = bytes("n,,n=user,r=nonce"),
	}
	sasl_len := encode_sasl_initial_response(&buf, sasl_init)
	testing.expect_value(t, sasl_len, len(buf))
	reader_init(&r, buf[:])
	s_type, _ := reader_read_u8(&r)
	s_pkt_len, _ := reader_read_i32(&r)
	s_mech, _ := reader_read_string_nt(&r)
	s_data_len, _ := reader_read_i32(&r)
	s_data, _ := reader_read_bytes(&r, int(s_data_len))
	testing.expect_value(t, s_type, u8('p'))
	testing.expect_value(t, s_pkt_len, i32(len(buf) - 1))
	testing.expect_value(t, s_mech, "SCRAM-SHA-256")
	testing.expect_value(t, s_data_len, i32(len("n,,n=user,r=nonce")))
	testing.expect_value(t, string(s_data), "n,,n=user,r=nonce")

	// 5b. SASLInitialResponse without data (data == nil)
	clear(&buf)
	sasl_init_nodata := Msg_SASL_Initial_Response{
		mechanism = "SCRAM-SHA-256",
		data = nil,
	}
	sasl_len_nodata := encode_sasl_initial_response(&buf, sasl_init_nodata)
	testing.expect_value(t, sasl_len_nodata, len(buf))
	reader_init(&r, buf[:])
	s_type_nd, _ := reader_read_u8(&r)
	s_pkt_len_nd, _ := reader_read_i32(&r)
	s_mech_nd, _ := reader_read_string_nt(&r)
	s_data_len_nd, _ := reader_read_i32(&r)
	testing.expect_value(t, s_type_nd, u8('p'))
	testing.expect_value(t, s_pkt_len_nd, i32(len(buf) - 1))
	testing.expect_value(t, s_mech_nd, "SCRAM-SHA-256")
	testing.expect_value(t, s_data_len_nd, i32(-1))

	// 6. SASLResponse
	clear(&buf)
	sasl_resp_len := encode_sasl_response(&buf, bytes("c=biws,r=nonce,p=proof"))
	testing.expect_value(t, sasl_resp_len, len(buf))
	reader_init(&r, buf[:])
	sr_type, _ := reader_read_u8(&r)
	sr_pkt_len, _ := reader_read_i32(&r)
	sr_data, _ := reader_read_bytes(&r, int(sr_pkt_len - 4))
	testing.expect_value(t, sr_type, u8('p'))
	testing.expect_value(t, sr_pkt_len, i32(len(buf) - 1))
	testing.expect_value(t, string(sr_data), "c=biws,r=nonce,p=proof")

	delete(buf)
	buf = nil

	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
test_encode_query_and_terminate :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	buf: [dynamic]byte
	defer delete(buf)

	// 1. Query
	q_len := encode_query(&buf, "SELECT 1;")
	testing.expect_value(t, q_len, len(buf))
	r: Reader
	reader_init(&r, buf[:])
	q_type, _ := reader_read_u8(&r)
	q_pkt_len, _ := reader_read_i32(&r)
	q_str, _ := reader_read_string_nt(&r)
	testing.expect_value(t, q_type, u8('Q'))
	testing.expect_value(t, q_pkt_len, 4 + 10) // 4 + len("SELECT 1;\0")
	testing.expect_value(t, q_str, "SELECT 1;")

	// 2. Terminate
	clear(&buf)
	term_len := encode_terminate(&buf)
	testing.expect_value(t, term_len, 5)
	testing.expect_value(t, len(buf), 5)
	reader_init(&r, buf[:])
	t_type, _ := reader_read_u8(&r)
	t_pkt_len, _ := reader_read_i32(&r)
	testing.expect_value(t, t_type, u8('X'))
	testing.expect_value(t, t_pkt_len, 4)

	delete(buf)
	buf = nil

	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
test_encode_extended_query_messages :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	buf: [dynamic]byte
	defer delete(buf)

	// 1. Parse
	p_len := encode_parse(&buf, "stmt_1", "SELECT $1::int4", []u32{23})
	testing.expect_value(t, p_len, len(buf))
	r: Reader
	reader_init(&r, buf[:])
	p_type, _ := reader_read_u8(&r)
	p_pkt_len, _ := reader_read_i32(&r)
	p_stmt, _ := reader_read_string_nt(&r)
	p_sql, _ := reader_read_string_nt(&r)
	p_num_oids, _ := reader_read_i16(&r)
	p_oid, _ := reader_read_u32(&r)
	testing.expect_value(t, p_type, u8('P'))
	testing.expect_value(t, p_pkt_len, i32(len(buf) - 1))
	testing.expect_value(t, p_stmt, "stmt_1")
	testing.expect_value(t, p_sql, "SELECT $1::int4")
	testing.expect_value(t, p_num_oids, 1)
	testing.expect_value(t, p_oid, 23)

	// 2. Bind (with 1 non-null value and 1 null value)
	clear(&buf)
	bind_msg := Msg_Bind{
		portal_name = "portal_1",
		statement_name = "stmt_1",
		param_format_codes = []Field_Format{.Text},
		param_values = []Bind_Param{
			{is_null = false, value = bytes("42")},
			{is_null = true, value = nil},
		},
		result_format_codes = []Field_Format{.Binary},
	}
	b_len := encode_bind(&buf, bind_msg)
	testing.expect_value(t, b_len, len(buf))
	reader_init(&r, buf[:])
	b_type, _ := reader_read_u8(&r)
	b_pkt_len, _ := reader_read_i32(&r)
	b_portal, _ := reader_read_string_nt(&r)
	b_stmt, _ := reader_read_string_nt(&r)
	b_num_fc, _ := reader_read_i16(&r)
	b_fc, _ := reader_read_i16(&r)
	b_num_pv, _ := reader_read_i16(&r)
	b_v1_len, _ := reader_read_i32(&r)
	b_v1_val, _ := reader_read_bytes(&r, int(b_v1_len))
	b_v2_len, _ := reader_read_i32(&r)
	b_num_rfc, _ := reader_read_i16(&r)
	b_rfc, _ := reader_read_i16(&r)
	testing.expect_value(t, b_type, u8('B'))
	testing.expect_value(t, b_pkt_len, i32(len(buf) - 1))
	testing.expect_value(t, b_portal, "portal_1")
	testing.expect_value(t, b_stmt, "stmt_1")
	testing.expect_value(t, b_num_fc, 1)
	testing.expect_value(t, b_fc, 0)
	testing.expect_value(t, b_num_pv, 2)
	testing.expect_value(t, b_v1_len, 2)
	testing.expect_value(t, string(b_v1_val), "42")
	testing.expect_value(t, b_v2_len, -1)
	testing.expect_value(t, b_num_rfc, 1)
	testing.expect_value(t, b_rfc, 1)

	// 3. Describe Statement & Portal
	clear(&buf)
	d_len := encode_describe(&buf, .Statement, "stmt_1")
	testing.expect_value(t, d_len, len(buf))
	reader_init(&r, buf[:])
	d_type, _ := reader_read_u8(&r)
	d_pkt_len, _ := reader_read_i32(&r)
	d_target, _ := reader_read_u8(&r)
	d_name, _ := reader_read_string_nt(&r)
	testing.expect_value(t, d_type, u8('D'))
	testing.expect_value(t, d_pkt_len, i32(len(buf) - 1))
	testing.expect_value(t, d_target, u8('S'))
	testing.expect_value(t, d_name, "stmt_1")

	// 4. Execute
	clear(&buf)
	e_len := encode_execute(&buf, "portal_1", 100)
	testing.expect_value(t, e_len, len(buf))
	reader_init(&r, buf[:])
	e_type, _ := reader_read_u8(&r)
	e_pkt_len, _ := reader_read_i32(&r)
	e_portal, _ := reader_read_string_nt(&r)
	e_rows, _ := reader_read_i32(&r)
	testing.expect_value(t, e_type, u8('E'))
	testing.expect_value(t, e_pkt_len, i32(len(buf) - 1))
	testing.expect_value(t, e_portal, "portal_1")
	testing.expect_value(t, e_rows, 100)

	// 5. Sync & Flush
	clear(&buf)
	encode_sync(&buf)
	encode_flush(&buf)
	testing.expect_value(t, len(buf), 10)
	reader_init(&r, buf[:])
	s1_t, _ := reader_read_u8(&r)
	s1_l, _ := reader_read_i32(&r)
	f1_t, _ := reader_read_u8(&r)
	f1_l, _ := reader_read_i32(&r)
	testing.expect_value(t, s1_t, u8('S'))
	testing.expect_value(t, s1_l, 4)
	testing.expect_value(t, f1_t, u8('H'))
	testing.expect_value(t, f1_l, 4)

	// 6. Close
	clear(&buf)
	encode_close(&buf, .Portal, "portal_1")
	testing.expect_value(t, len(buf), 1 + 4 + 1 + len("portal_1") + 1)
	reader_init(&r, buf[:])
	c_type, _ := reader_read_u8(&r)
	c_pkt_len, _ := reader_read_i32(&r)
	c_target, _ := reader_read_u8(&r)
	c_name, _ := reader_read_string_nt(&r)
	testing.expect_value(t, c_type, u8('C'))
	testing.expect_value(t, c_pkt_len, i32(len(buf) - 1))
	testing.expect_value(t, c_target, u8('P'))
	testing.expect_value(t, c_name, "portal_1")

	delete(buf)
	buf = nil

	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
test_encode_extended_query_defaults_and_edge_cases :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	buf: [dynamic]byte
	defer delete(buf)

	// 1. Parse with unnamed statement and no parameter OIDs
	p_len := encode_parse(&buf, "", "SELECT 1")
	testing.expect_value(t, p_len, len(buf))
	r: Reader
	reader_init(&r, buf[:])
	p_type, _ := reader_read_u8(&r)
	p_pkt_len, _ := reader_read_i32(&r)
	p_stmt, _ := reader_read_string_nt(&r)
	p_sql, _ := reader_read_string_nt(&r)
	p_num_oids, _ := reader_read_i16(&r)
	testing.expect_value(t, p_type, u8('P'))
	testing.expect_value(t, p_pkt_len, 4 + 1 + 9 + 2) // 4 + "\0" + "SELECT 1\0" + 2 (num_oids = 0)
	testing.expect_value(t, p_stmt, "")
	testing.expect_value(t, p_sql, "SELECT 1")
	testing.expect_value(t, p_num_oids, 0)

	// 2. Bind with empty values/format codes (unnamed portal & statement)
	clear(&buf)
	empty_bind := Msg_Bind{
		portal_name = "",
		statement_name = "",
		param_format_codes = nil,
		param_values = nil,
		result_format_codes = nil,
	}
	b_len := encode_bind(&buf, empty_bind)
	testing.expect_value(t, b_len, len(buf))
	reader_init(&r, buf[:])
	b_type, _ := reader_read_u8(&r)
	b_pkt_len, _ := reader_read_i32(&r)
	b_portal, _ := reader_read_string_nt(&r)
	b_stmt, _ := reader_read_string_nt(&r)
	b_num_fc, _ := reader_read_i16(&r)
	b_num_pv, _ := reader_read_i16(&r)
	b_num_rfc, _ := reader_read_i16(&r)
	testing.expect_value(t, b_type, u8('B'))
	testing.expect_value(t, b_pkt_len, 4 + 1 + 1 + 2 + 2 + 2)
	testing.expect_value(t, b_portal, "")
	testing.expect_value(t, b_stmt, "")
	testing.expect_value(t, b_num_fc, 0)
	testing.expect_value(t, b_num_pv, 0)
	testing.expect_value(t, b_num_rfc, 0)

	// 3. Describe unnamed statement and portal with default name
	clear(&buf)
	encode_describe(&buf, .Statement)
	reader_init(&r, buf[:])
	d1_type, _ := reader_read_u8(&r)
	d1_pkt_len, _ := reader_read_i32(&r)
	d1_target, _ := reader_read_u8(&r)
	d1_name, _ := reader_read_string_nt(&r)
	testing.expect_value(t, d1_type, u8('D'))
	testing.expect_value(t, d1_pkt_len, 4 + 1 + 1)
	testing.expect_value(t, d1_target, u8('S'))
	testing.expect_value(t, d1_name, "")

	clear(&buf)
	encode_describe(&buf, .Portal, "")
	reader_init(&r, buf[:])
	d2_type, _ := reader_read_u8(&r)
	d2_pkt_len, _ := reader_read_i32(&r)
	d2_target, _ := reader_read_u8(&r)
	d2_name, _ := reader_read_string_nt(&r)
	testing.expect_value(t, d2_type, u8('D'))
	testing.expect_value(t, d2_pkt_len, 4 + 1 + 1)
	testing.expect_value(t, d2_target, u8('P'))
	testing.expect_value(t, d2_name, "")

	// 4. Execute with default args
	clear(&buf)
	encode_execute(&buf)
	reader_init(&r, buf[:])
	e_type, _ := reader_read_u8(&r)
	e_pkt_len, _ := reader_read_i32(&r)
	e_portal, _ := reader_read_string_nt(&r)
	e_rows, _ := reader_read_i32(&r)
	testing.expect_value(t, e_type, u8('E'))
	testing.expect_value(t, e_pkt_len, 4 + 1 + 4)
	testing.expect_value(t, e_portal, "")
	testing.expect_value(t, e_rows, 0)

	// 5. Close unnamed statement and portal
	clear(&buf)
	encode_close(&buf, .Statement)
	reader_init(&r, buf[:])
	c1_type, _ := reader_read_u8(&r)
	c1_pkt_len, _ := reader_read_i32(&r)
	c1_target, _ := reader_read_u8(&r)
	c1_name, _ := reader_read_string_nt(&r)
	testing.expect_value(t, c1_type, u8('C'))
	testing.expect_value(t, c1_pkt_len, 4 + 1 + 1)
	testing.expect_value(t, c1_target, u8('S'))
	testing.expect_value(t, c1_name, "")

	delete(buf)
	buf = nil

	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
test_encode_copy_and_dispatcher :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	buf: [dynamic]byte
	defer delete(buf)

	// 1. CopyData
	cd_len := encode_copy_data(&buf, bytes("raw_row_bytes"))
	testing.expect_value(t, cd_len, len(buf))
	r: Reader
	reader_init(&r, buf[:])
	cd_type, _ := reader_read_u8(&r)
	cd_pkt_len, _ := reader_read_i32(&r)
	cd_bytes, _ := reader_read_bytes(&r, int(cd_pkt_len - 4))
	testing.expect_value(t, cd_type, u8('d'))
	testing.expect_value(t, string(cd_bytes), "raw_row_bytes")

	// 2. CopyDone
	clear(&buf)
	encode_copy_done(&buf)
	reader_init(&r, buf[:])
	cdo_type, _ := reader_read_u8(&r)
	cdo_len, _ := reader_read_i32(&r)
	testing.expect_value(t, cdo_type, u8('c'))
	testing.expect_value(t, cdo_len, 4)

	// 3. CopyFail
	clear(&buf)
	encode_copy_fail(&buf, "disk full")
	reader_init(&r, buf[:])
	cf_type, _ := reader_read_u8(&r)
	cf_pkt_len, _ := reader_read_i32(&r)
	cf_msg, _ := reader_read_string_nt(&r)
	testing.expect_value(t, cf_type, u8('f'))
	testing.expect_value(t, cf_pkt_len, i32(len(buf) - 1))
	testing.expect_value(t, cf_msg, "disk full")

	// 4. Master Dispatcher (sample)
	clear(&buf)
	m1 := Frontend_Message(Msg_Query{query = "SELECT 42;"})
	m2 := Frontend_Message(Msg_Sync{})
	encode_frontend_message(&buf, m1)
	encode_frontend_message(&buf, m2)

	reader_init(&r, buf[:])
	m1_t, _ := reader_read_u8(&r)
	m1_l, _ := reader_read_i32(&r)
	m1_q, _ := reader_read_string_nt(&r)
	m2_t, _ := reader_read_u8(&r)
	m2_l, _ := reader_read_i32(&r)
	testing.expect_value(t, m1_t, u8('Q'))
	testing.expect_value(t, m1_l, 4 + 11) // 4 + len("SELECT 42;\0")
	testing.expect_value(t, m1_q, "SELECT 42;")
	testing.expect_value(t, m2_t, u8('S'))
	testing.expect_value(t, m2_l, 4)

	delete(buf)
	buf = nil

	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
test_encode_frontend_message_all_variants :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	buf: [dynamic]byte
	defer delete(buf)

	messages := []Frontend_Message{
		Msg_Startup{protocol_version = 196608, params = []Startup_Param{{name = "user", value = "postgres"}}},
		Msg_SSL_Request{},
		Msg_Cancel_Request{process_id = 123, secret_key = 456},
		Msg_Password{password = "secret"},
		Msg_SASL_Initial_Response{mechanism = "SCRAM-SHA-256", data = bytes("client-first")},
		Msg_SASL_Response{data = bytes("client-final")},
		Msg_Query{query = "SELECT 1"},
		Msg_Parse{statement_name = "s1", query = "SELECT $1", param_oids = []u32{23}},
		Msg_Bind{portal_name = "p1", statement_name = "s1"},
		Msg_Describe{target_type = .Statement, name = "s1"},
		Msg_Execute{portal_name = "p1", max_rows = 10},
		Msg_Sync{},
		Msg_Flush{},
		Msg_Close{target_type = .Portal, name = "p1"},
		Msg_Terminate{},
		Msg_Copy_Data{data = bytes("row-data")},
		Msg_Copy_Done{},
		Msg_Copy_Fail{message = "abort copy"},
	}

	for msg in messages {
		clear(&buf)
		encoded_len := encode_frontend_message(&buf, msg)
		testing.expect_value(t, encoded_len, len(buf))
		testing.expect(t, encoded_len > 0)
	}

	delete(buf)
	buf = nil

	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
test_extended_query_pipelining :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	buf: [dynamic]byte
	defer delete(buf)

	// Pipeline: Parse ('P') + Bind ('B') + Describe ('D') + Execute ('E') + Sync ('S')
	encode_parse(&buf, "stmt", "SELECT $1", []u32{23})
	encode_bind(&buf, Msg_Bind{
		portal_name = "p",
		statement_name = "stmt",
		param_values = []Bind_Param{{is_null = false, value = bytes("100")}},
	})
	encode_describe(&buf, .Portal, "p")
	encode_execute(&buf, "p", 0)
	encode_sync(&buf)

	r: Reader
	reader_init(&r, buf[:])

	// Validate sequence of 5 packets
	t1, _ := reader_read_u8(&r); l1, _ := reader_read_i32(&r); reader_read_bytes(&r, int(l1 - 4))
	t2, _ := reader_read_u8(&r); l2, _ := reader_read_i32(&r); reader_read_bytes(&r, int(l2 - 4))
	t3, _ := reader_read_u8(&r); l3, _ := reader_read_i32(&r); reader_read_bytes(&r, int(l3 - 4))
	t4, _ := reader_read_u8(&r); l4, _ := reader_read_i32(&r); reader_read_bytes(&r, int(l4 - 4))
	t5, _ := reader_read_u8(&r); l5, _ := reader_read_i32(&r)

	testing.expect_value(t, t1, u8('P'))
	testing.expect_value(t, t2, u8('B'))
	testing.expect_value(t, t3, u8('D'))
	testing.expect_value(t, t4, u8('E'))
	testing.expect_value(t, t5, u8('S'))
	testing.expect_value(t, l5, 4)
	testing.expect_value(t, reader_remaining(&r), 0)

	delete(buf)
	buf = nil

	testing.expect_value(t, len(track.allocation_map), 0)
}


