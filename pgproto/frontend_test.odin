package pgproto

import "core:mem"
import "core:testing"

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
		data = transmute([]byte)string("n,,n=user,r=nonce"),
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
	sasl_resp_len := encode_sasl_response(&buf, transmute([]byte)string("c=biws,r=nonce,p=proof"))
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

