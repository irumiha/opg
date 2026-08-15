package pgproto

import "core:mem"
import "core:os"
import "core:testing"

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
