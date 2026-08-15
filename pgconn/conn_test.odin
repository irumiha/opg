package pgconn

import "core:crypto/hmac"
import "core:crypto/pbkdf2"
import "core:encoding/base64"
import "core:encoding/endian"
import "core:mem"
import "core:strings"
import "core:testing"
import "core:time"
import "../pgerr"
import "../pgproto"

@(test)
test_conn_struct_and_teardown :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	mock: Mock_Transport
	mock_transport_init(&mock)

	transport := make_mock_transport(&mock)

	conn := new(Conn, context.allocator)
	conn.allocator = context.allocator
	conn.config = Conn_Config{
		host = "localhost",
		port = 5432,
		user = "postgres",
		database = "testdb",
	}
	conn.status = .Ready
	conn.parameters = make(map[string]string, 16, context.allocator)
	stream_init(&conn.stream, transport, allocator = context.allocator)

	testing.expect(t, conn_is_alive(conn), "expected ready connection to be alive")

	conn_close(conn)
	testing.expect_value(t, conn.status, Conn_Status.Closed)
	testing.expect(t, !conn_is_alive(conn), "expected closed connection to not be alive")
	testing.expect(t, mock.is_closed, "expected transport closed on conn_close")

	free(conn, context.allocator)
	mock_transport_destroy(&mock)
	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
test_conn_is_alive_all_statuses :: proc(t: ^testing.T) {
	// nil connection check
	testing.expect(t, !conn_is_alive(nil), "nil conn should not be alive")

	c: Conn
	c.status = .Disconnected
	testing.expect(t, !conn_is_alive(&c), "Disconnected conn should not be alive")

	c.status = .Connecting
	testing.expect(t, !conn_is_alive(&c), "Connecting conn should not be alive")

	c.status = .Authenticating
	testing.expect(t, !conn_is_alive(&c), "Authenticating conn should not be alive")

	c.status = .Ready
	testing.expect(t, conn_is_alive(&c), "Ready conn should be alive")

	c.status = .In_Transaction
	testing.expect(t, conn_is_alive(&c), "In_Transaction conn should be alive")

	c.status = .Failed_Transaction
	testing.expect(t, conn_is_alive(&c), "Failed_Transaction conn should be alive")

	c.status = .Busy
	testing.expect(t, !conn_is_alive(&c), "Busy conn should not be alive")

	c.status = .Closed
	testing.expect(t, !conn_is_alive(&c), "Closed conn should not be alive")
}

@(test)
test_conn_close_edge_cases :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	// 1. conn_close(nil) should not panic
	conn_close(nil)

	// 2. conn_close when status is already Closed (idempotency)
	conn1 := new(Conn, context.allocator)
	conn1.allocator = context.allocator
	conn1.status = .Closed
	conn_close(conn1)
	testing.expect_value(t, conn1.status, Conn_Status.Closed)
	free(conn1, context.allocator)

	// 3. conn_close when Disconnected (no transport write attempt)
	conn2 := new(Conn, context.allocator)
	conn2.allocator = context.allocator
	conn2.status = .Disconnected
	conn_close(conn2)
	testing.expect_value(t, conn2.status, Conn_Status.Closed)
	free(conn2, context.allocator)

	// 4. conn_close with allocated parameter key-values
	mock: Mock_Transport
	mock_transport_init(&mock)

	transport := make_mock_transport(&mock)

	conn3 := new(Conn, context.allocator)
	conn3.allocator = context.allocator
	conn3.status = .Ready
	conn3.parameters = make(map[string]string, 4, context.allocator)
	k1 := strings.clone("server_version", context.allocator)
	v1 := strings.clone("16.0", context.allocator)
	conn3.parameters[k1] = v1
	k2 := strings.clone("client_encoding", context.allocator)
	v2 := strings.clone("UTF8", context.allocator)
	conn3.parameters[k2] = v2

	stream_init(&conn3.stream, transport, allocator = context.allocator)

	conn_close(conn3)
	testing.expect_value(t, conn3.status, Conn_Status.Closed)
	testing.expect(t, conn3.parameters == nil, "expected parameters map to be nil after conn_close")
	testing.expect(t, mock.is_closed, "expected transport closed")
	// Verify terminate message ('X') was written to transport
	testing.expect(t, len(mock.written_bytes) == 5, "expected 5 bytes written for terminate message")
	testing.expect_value(t, mock.written_bytes[0], byte('X'))

	// Re-closing conn3 is safe
	conn_close(conn3)
	testing.expect_value(t, conn3.status, Conn_Status.Closed)

	free(conn3, context.allocator)
	mock_transport_destroy(&mock)

	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
test_conn_handlers_assignment :: proc(t: ^testing.T) {
	notice_called := false
	notif_called := false

	dummy_notice_handler :: proc(user_data: rawptr, notice: pgproto.Msg_Notice_Response) {
		flag := (^bool)(user_data)
		flag^ = true
	}

	dummy_notif_handler :: proc(user_data: rawptr, notif: pgproto.Msg_Notification_Response) {
		flag := (^bool)(user_data)
		flag^ = true
	}

	conn: Conn
	conn.on_notice = dummy_notice_handler
	conn.on_notice_data = &notice_called
	conn.on_notification = dummy_notif_handler
	conn.on_notif_data = &notif_called

	notice: pgproto.Msg_Notice_Response
	conn.on_notice(conn.on_notice_data, notice)
	testing.expect(t, notice_called, "expected notice handler to be invoked")

	notif: pgproto.Msg_Notification_Response
	conn.on_notification(conn.on_notif_data, notif)
	testing.expect(t, notif_called, "expected notification handler to be invoked")
}

@(test)
test_conn_handshake_cleartext_success :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	mock: Mock_Transport
	mock_transport_init(&mock)

	// Server responses:
	// 1. AuthenticationCleartextPassword: 'R', len 8, auth_type 3 -> [ 'R', 0,0,0,8, 0,0,0,3 ]
	// 2. AuthenticationOk: 'R', len 8, auth_type 0 -> [ 'R', 0,0,0,8, 0,0,0,0 ]
	// 3. ReadyForQuery: 'Z', len 5, 'I' -> [ 'Z', 0,0,0,5, 'I' ]
	auth_cleartext := []byte{'R', 0, 0, 0, 8, 0, 0, 0, 3}
	auth_ok := []byte{'R', 0, 0, 0, 8, 0, 0, 0, 0}
	rfq := []byte{'Z', 0, 0, 0, 5, 'I'}

	append(&mock.read_chunks, auth_cleartext)
	append(&mock.read_chunks, auth_ok)
	append(&mock.read_chunks, rfq)

	transport := make_mock_transport(&mock)
	config := Conn_Config{
		host = "localhost",
		port = 5432,
		user = "postgres",
		password = "secretpassword",
		database = "testdb",
		application_name = "opg_app",
	}

	conn, err := conn_connect_with_transport(config, transport, context.allocator)
	testing.expect(t, err == nil, "expected handshake success")
	testing.expect(t, conn != nil, "expected conn not nil")
	if conn != nil {
		testing.expect_value(t, conn.status, Conn_Status.Ready)
		testing.expect_value(t, conn.transaction_status, pgproto.Transaction_Status.Idle)
		conn_close(conn)
		free(conn, context.allocator)
	}

	// Verify StartupMessage was written, followed by PasswordMessage
	testing.expect(t, len(mock.written_bytes) > 0, "expected outbound writes")

	mock_transport_destroy(&mock)
	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
test_conn_handshake_md5_success :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	mock: Mock_Transport
	mock_transport_init(&mock)

	// Server responses:
	// 1. AuthenticationMD5Password: 'R', len 12, auth_type 5, salt: [4]byte{1,2,3,4}
	auth_md5 := []byte{'R', 0, 0, 0, 12, 0, 0, 0, 5, 1, 2, 3, 4}
	auth_ok := []byte{'R', 0, 0, 0, 8, 0, 0, 0, 0}
	rfq := []byte{'Z', 0, 0, 0, 5, 'I'}

	append(&mock.read_chunks, auth_md5)
	append(&mock.read_chunks, auth_ok)
	append(&mock.read_chunks, rfq)

	transport := make_mock_transport(&mock)
	config := Conn_Config{
		host = "localhost",
		port = 5432,
		user = "postgres",
		password = "secretpassword",
		database = "testdb",
	}

	conn, err := conn_connect_with_transport(config, transport, context.allocator)
	testing.expect(t, err == nil, "expected md5 handshake success")
	testing.expect(t, conn != nil, "expected conn not nil")
	if conn != nil {
		testing.expect_value(t, conn.status, Conn_Status.Ready)
		conn_close(conn)
		free(conn, context.allocator)
	}

	mock_transport_destroy(&mock)
	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
test_conn_handshake_with_params_backend_keys_and_notices :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	mock: Mock_Transport
	mock_transport_init(&mock)

	auth_ok := []byte{'R', 0, 0, 0, 8, 0, 0, 0, 0}
	// ParameterStatus 'server_version' = '16.0' (len = 4 + 15 + 5 = 24)
	param1 := []byte{'S', 0, 0, 0, 24, 's', 'e', 'r', 'v', 'e', 'r', '_', 'v', 'e', 'r', 's', 'i', 'o', 'n', 0, '1', '6', '.', '0', 0}
	// ParameterStatus update 'server_version' = '16.1' (len = 4 + 15 + 5 = 24)
	param1_dup := []byte{'S', 0, 0, 0, 24, 's', 'e', 'r', 'v', 'e', 'r', '_', 'v', 'e', 'r', 's', 'i', 'o', 'n', 0, '1', '6', '.', '1', 0}
	// BackendKeyData: pid = 1234, secret = 5678
	key_data := []byte{'K', 0, 0, 0, 12, 0, 0, 4, 210, 0, 0, 22, 46}
	// NoticeResponse: S=NOTICE\0 M=hello\0\0 (len = 4 + 8 + 7 + 1 = 20)
	notice_bytes := []byte{'N', 0, 0, 0, 20, 'S', 'N', 'O', 'T', 'I', 'C', 'E', 0, 'M', 'h', 'e', 'l', 'l', 'o', 0, 0}
	// NotificationResponse: pid=1234, channel="ch"\0, payload="data"\0 (len = 4 + 4 + 3 + 5 = 16)
	notif_bytes := []byte{'A', 0, 0, 0, 16, 0, 0, 4, 210, 'c', 'h', 0, 'd', 'a', 't', 'a', 0}
	rfq := []byte{'Z', 0, 0, 0, 5, 'I'}

	append(&mock.read_chunks, auth_ok)
	append(&mock.read_chunks, param1)
	append(&mock.read_chunks, param1_dup)
	append(&mock.read_chunks, key_data)
	append(&mock.read_chunks, notice_bytes)
	append(&mock.read_chunks, notif_bytes)
	append(&mock.read_chunks, rfq)

	transport := make_mock_transport(&mock)
	config := Conn_Config{
		host = "localhost",
		port = 5432,
		user = "postgres",
	}

	conn, err := conn_connect_with_transport(config, transport, context.allocator)
	testing.expect(t, err == nil, "expected handshake success")
	testing.expect(t, conn != nil, "expected conn to not be nil")
	if conn != nil {
		testing.expect_value(t, conn.backend_pid, 1234)
		testing.expect_value(t, conn.backend_secret, 5678)
		testing.expect_value(t, conn.parameters["server_version"], "16.1")
		conn_close(conn)
		free(conn, context.allocator)
	}

	mock_transport_destroy(&mock)
	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
test_conn_handshake_error_response :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	mock: Mock_Transport
	mock_transport_init(&mock)

	// Server returns ErrorResponse: 'E', len 32, S=FATAL\0 C=28P01\0 M=auth failed\0\0
	err_bytes := []byte{
		'E', 0, 0, 0, 32,
		'S', 'F', 'A', 'T', 'A', 'L', 0,
		'C', '2', '8', 'P', '0', '1', 0,
		'M', 'a', 'u', 't', 'h', ' ', 'f', 'a', 'i', 'l', 'e', 'd', 0,
		0,
	}
	append(&mock.read_chunks, err_bytes)

	transport := make_mock_transport(&mock)
	config := Conn_Config{
		host = "localhost",
		port = 5432,
		user = "postgres",
	}

	conn, err := conn_connect_with_transport(config, transport, context.allocator)
	testing.expect(t, conn == nil, "expected conn to be nil on error")
	testing.expect(t, err != nil, "expected error from handshake")

	#partial switch e in err {
	case pgerr.Postgres_Error:
		testing.expect_value(t, e.code, "28P01")
		testing.expect_value(t, e.message, "auth failed")
	case:
		testing.expect(t, false, "expected Postgres_Error")
	}

	mock_transport_destroy(&mock)
	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
test_conn_handshake_unexpected_message :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	mock: Mock_Transport
	mock_transport_init(&mock)

	// Server sends unexpected message CommandComplete 'C' (len = 4 + 9 = 13)
	cmd_bytes := []byte{'C', 0, 0, 0, 13, 'S', 'E', 'L', 'E', 'C', 'T', ' ', '1', 0}
	append(&mock.read_chunks, cmd_bytes)

	transport := make_mock_transport(&mock)
	config := Conn_Config{
		host = "localhost",
		port = 5432,
		user = "postgres",
	}

	conn, err := conn_connect_with_transport(config, transport, context.allocator)
	testing.expect(t, conn == nil, "expected conn to be nil on unexpected message")
	testing.expect(t, err != nil, "expected error")

	#partial switch e in err {
	case pgerr.Protocol_Error:
		testing.expect_value(t, e.type, pgerr.Protocol_Error_Type.Unexpected_Message)
	case:
		testing.expect(t, false, "expected Protocol_Error")
	}

	mock_transport_destroy(&mock)
	testing.expect_value(t, len(track.allocation_map), 0)
}

// Scram_Server_Mock simulates a PostgreSQL backend performing SCRAM-SHA-256 authentication
Scram_Server_Mock :: struct {
	password:            string,
	salt:                [16]byte,
	step:                int,
	client_nonce:        string,
	server_first:        string,
	auth_message:        string,
	read_buffer:         [dynamic]byte,
	read_offset:         int,
	written_bytes:       [dynamic]byte,
	is_closed:           bool,
	corrupt_signature:   bool,
	allocator:           mem.Allocator,
}

scram_server_mock_init :: proc(m: ^Scram_Server_Mock, password: string, allocator := context.allocator) {
	m.password = password
	m.salt = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	m.step = 0
	m.allocator = allocator
	m.read_buffer = make([dynamic]byte, allocator)
	m.written_bytes = make([dynamic]byte, allocator)
}

scram_server_mock_destroy :: proc(m: ^Scram_Server_Mock) {
	delete(m.read_buffer)
	delete(m.written_bytes)
	if len(m.client_nonce) > 0 do delete(m.client_nonce, m.allocator)
	if len(m.server_first) > 0 do delete(m.server_first, m.allocator)
	if len(m.auth_message) > 0 do delete(m.auth_message, m.allocator)
}

scram_mock_read :: proc(transport: rawptr, buf: []byte) -> (bytes_read: int, err: pgerr.Error) {
	m := (^Scram_Server_Mock)(transport)
	if m.is_closed {
		return 0, pgerr.Net_Error{type = .Socket_Closed}
	}

	if m.read_offset >= len(m.read_buffer) {
		clear(&m.read_buffer)
		m.read_offset = 0

		switch m.step {
		case 0:
			// 1. Send AuthenticationSASL offering SCRAM-SHA-256
			auth_sasl := []byte{
				'R', 0, 0, 0, 23,
				0, 0, 0, 10,
				'S', 'C', 'R', 'A', 'M', '-', 'S', 'H', 'A', '-', '2', '5', '6', 0, 0,
			}
			append(&m.read_buffer, ..auth_sasl)
			m.step = 1

		case 1:
			// Client responded with SASL Initial Response. Find "r=" to get client nonce.
			written_str := string(m.written_bytes[:])
			r_idx := strings.index(written_str, ",r=")
			if r_idx == -1 {
				r_idx = strings.index(written_str, "r=")
			}
			if r_idx != -1 {
				r_start := r_idx + (3 if strings.has_prefix(written_str[r_idx:], ",r=") else 2)
				r_end := strings.index_byte(written_str[r_start:], 0)
				client_nonce_str: string
				if r_end != -1 {
					client_nonce_str = written_str[r_start : r_start+r_end]
				} else {
					client_nonce_str = written_str[r_start:]
				}
				m.client_nonce = strings.clone(client_nonce_str, m.allocator)
			}

			combined_nonce := strings.concatenate({m.client_nonce, "SERVEREXTRA1234567890"}, context.temp_allocator)
			salt_b64 := base64.encode(m.salt[:], allocator = context.temp_allocator)
			m.server_first = strings.concatenate({"r=", combined_nonce, ",s=", salt_b64, ",i=4096"}, m.allocator)

			append(&m.read_buffer, 'R')
			append(&m.read_buffer, 0, 0, 0, 0)
			append(&m.read_buffer, 0, 0, 0, 11)
			append(&m.read_buffer, m.server_first)
			endian.put_i32(m.read_buffer[1:5], .Big, i32(len(m.read_buffer) - 1))
			m.step = 2

		case 2:
			// Client responded with SASL Response (client-final).
			// Compute auth-message and ServerSignature.
			combined_nonce := strings.concatenate({m.client_nonce, "SERVEREXTRA1234567890"}, context.temp_allocator)
			client_first_bare := strings.concatenate({"n=postgres,r=", m.client_nonce}, context.temp_allocator)
			client_final_without_proof := strings.concatenate({"c=biws,r=", combined_nonce}, context.temp_allocator)
			m.auth_message = strings.concatenate({client_first_bare, ",", m.server_first, ",", client_final_without_proof}, m.allocator)

			server_final: string
			if m.corrupt_signature {
				server_final = "v=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
			} else {
				salted_password: [32]byte
				pbkdf2.derive(.SHA256, transmute([]byte)m.password, m.salt[:], 4096, salted_password[:])
				server_key: [32]byte
				hmac.sum(.SHA256, server_key[:], transmute([]byte)string("Server Key"), salted_password[:])
				server_sig: [32]byte
				hmac.sum(.SHA256, server_sig[:], transmute([]byte)m.auth_message, server_key[:])
				b64_sig := base64.encode(server_sig[:], allocator = context.temp_allocator)
				server_final = strings.concatenate({"v=", b64_sig}, context.temp_allocator)
			}

			append(&m.read_buffer, 'R')
			append(&m.read_buffer, 0, 0, 0, 0)
			append(&m.read_buffer, 0, 0, 0, 12)
			append(&m.read_buffer, server_final)
			endian.put_i32(m.read_buffer[1:5], .Big, i32(len(m.read_buffer) - 1))
			m.step = 3

		case 3:
			// Send AuthenticationOk, ParameterStatuses, BackendKeyData, ReadyForQuery
			append(&m.read_buffer, 'R', 0, 0, 0, 8, 0, 0, 0, 0)

			append_param :: proc(buf: ^[dynamic]byte, k, v: string) {
				start := len(buf)
				append(buf, 'S', 0, 0, 0, 0)
				append(buf, k)
				append(buf, 0)
				append(buf, v)
				append(buf, 0)
				endian.put_i32(buf[start+1:start+5], .Big, i32(len(buf) - start - 1))
			}

			append_param(&m.read_buffer, "server_version", "16.1")
			append_param(&m.read_buffer, "client_encoding", "UTF8")
			append_param(&m.read_buffer, "TimeZone", "UTC")
			append_param(&m.read_buffer, "integer_datetimes", "on")

			// BackendKeyData: pid=1234, secret=5678
			append(&m.read_buffer, 'K', 0, 0, 0, 12, 0, 0, 4, 210, 0, 0, 22, 46)

			// ReadyForQuery ('I')
			append(&m.read_buffer, 'Z', 0, 0, 0, 5, 'I')
			m.step = 4

		case:
			return 0, pgerr.Net_Error{type = .Socket_Closed}
		}
	}

	remaining := m.read_buffer[m.read_offset:]
	to_copy := min(len(buf), len(remaining))
	copy(buf[:to_copy], remaining[:to_copy])
	m.read_offset += to_copy
	return to_copy, nil
}

scram_mock_write :: proc(transport: rawptr, data: []byte) -> (int, pgerr.Error) {
	m := (^Scram_Server_Mock)(transport)
	if m.is_closed {
		return 0, pgerr.Net_Error{type = .Socket_Closed}
	}
	for b in data {
		append(&m.written_bytes, b)
	}
	return len(data), nil
}

scram_mock_close :: proc(transport: rawptr) {
	m := (^Scram_Server_Mock)(transport)
	m.is_closed = true
}

scram_mock_set_deadlines :: proc(transport: rawptr, read_timeout, write_timeout: time.Duration) -> pgerr.Error {
	return nil
}

make_scram_mock_transport :: proc(m: ^Scram_Server_Mock) -> Stream_Transport {
	return Stream_Transport{
		data = m,
		read = scram_mock_read,
		write = scram_mock_write,
		close = scram_mock_close,
		set_deadlines = scram_mock_set_deadlines,
	}
}

@(test)
test_conn_handshake_scram_and_parameters :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	mock: Scram_Server_Mock
	scram_server_mock_init(&mock, "secretpassword", context.allocator)

	transport := make_scram_mock_transport(&mock)
	config := Conn_Config{
		host = "localhost",
		port = 5432,
		user = "postgres",
		password = "secretpassword",
		database = "testdb",
		application_name = "test_app",
	}

	conn, err := conn_connect_with_transport(config, transport, context.allocator)
	testing.expect(t, err == nil, "expected SCRAM handshake success")
	testing.expect(t, conn != nil, "expected non-nil conn")

	if conn != nil {
		testing.expect_value(t, conn.status, Conn_Status.Ready)
		testing.expect_value(t, conn.transaction_status, pgproto.Transaction_Status.Idle)
		testing.expect_value(t, conn.backend_pid, 1234)
		testing.expect_value(t, conn.backend_secret, 5678)
		testing.expect_value(t, conn.parameters["server_version"], "16.1")
		testing.expect_value(t, conn.parameters["client_encoding"], "UTF8")
		testing.expect_value(t, conn.parameters["TimeZone"], "UTC")
		testing.expect_value(t, conn.parameters["integer_datetimes"], "on")

		conn_close(conn)
		free(conn, context.allocator)
	}

	scram_server_mock_destroy(&mock)
	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
test_conn_handshake_scram_server_signature_mismatch :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	mock: Scram_Server_Mock
	scram_server_mock_init(&mock, "secretpassword", context.allocator)
	mock.corrupt_signature = true

	transport := make_scram_mock_transport(&mock)
	config := Conn_Config{
		host = "localhost",
		port = 5432,
		user = "postgres",
		password = "secretpassword",
		database = "testdb",
	}

	conn, err := conn_connect_with_transport(config, transport, context.allocator)
	testing.expect(t, conn == nil, "expected conn to be nil on SCRAM signature mismatch")
	testing.expect(t, err != nil, "expected error on SCRAM signature mismatch")

	#partial switch e in err {
	case pgerr.Auth_Error:
		testing.expect_value(t, e.type, pgerr.Auth_Error_Type.SCRAM_Server_Signature_Mismatch)
	case:
		testing.expect(t, false, "expected Auth_Error")
	}

	scram_server_mock_destroy(&mock)
	testing.expect_value(t, len(track.allocation_map), 0)
}

Test_Notice_Context :: struct {
	received_notice: bool,
	notice_message:  string,
	notice_severity: string,
}

on_test_notice :: proc(user_data: rawptr, notice: pgproto.Msg_Notice_Response) {
	ctx := (^Test_Notice_Context)(user_data)
	ctx.received_notice = true
	ctx.notice_message = notice.error.message
	ctx.notice_severity = notice.error.severity
}

@(test)
test_conn_notice_callback :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	mock: Mock_Transport
	mock_transport_init(&mock)

	auth_ok := []byte{'R', 0, 0, 0, 8, 0, 0, 0, 0}

	// Notice message: 'N', len, 'S', "NOTICE\0", 'M', "test notice message\0", '\0'
	notice_builder := make([dynamic]byte, context.temp_allocator)
	append(&notice_builder, 'N')
	append(&notice_builder, 0, 0, 0, 0)
	append(&notice_builder, 'S')
	append(&notice_builder, "NOTICE")
	append(&notice_builder, 0)
	append(&notice_builder, 'M')
	append(&notice_builder, "test notice message")
	append(&notice_builder, 0)
	append(&notice_builder, 0)
	endian.put_i32(notice_builder[1:5], .Big, i32(len(notice_builder) - 1))

	rfq := []byte{'Z', 0, 0, 0, 5, 'I'}

	append(&mock.read_chunks, auth_ok)
	append(&mock.read_chunks, notice_builder[:])
	append(&mock.read_chunks, rfq)

	transport := make_mock_transport(&mock)
	notice_ctx: Test_Notice_Context
	config := Conn_Config{
		host = "localhost",
		port = 5432,
		user = "postgres",
		on_notice = on_test_notice,
		on_notice_data = &notice_ctx,
	}

	conn, err := conn_connect_with_transport(config, transport, context.allocator)
	testing.expect(t, err == nil, "expected handshake success")
	testing.expect(t, conn != nil, "expected conn not nil")
	if conn != nil {
		testing.expect_value(t, conn.status, Conn_Status.Ready)
		testing.expect(t, notice_ctx.received_notice, "expected notice callback to be called")
		testing.expect_value(t, notice_ctx.notice_message, "test notice message")
		testing.expect_value(t, notice_ctx.notice_severity, "NOTICE")
		conn_close(conn)
		free(conn, context.allocator)
	}

	mock_transport_destroy(&mock)
	testing.expect_value(t, len(track.allocation_map), 0)
}

Test_Notification_Context :: struct {
	received_notification: bool,
	channel:               string,
	payload:               string,
	pid:                   i32,
}

on_test_notification :: proc(user_data: rawptr, notification: pgproto.Msg_Notification_Response) {
	ctx := (^Test_Notification_Context)(user_data)
	ctx.received_notification = true
	ctx.channel = notification.channel
	ctx.payload = notification.payload
	ctx.pid = notification.process_id
}

@(test)
test_conn_notification_callback :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	mock: Mock_Transport
	mock_transport_init(&mock)

	auth_ok := []byte{'R', 0, 0, 0, 8, 0, 0, 0, 0}

	// Notification message: 'A', len, pid=1234, "chat_channel\0", "new_message\0"
	notif_builder := make([dynamic]byte, context.temp_allocator)
	append(&notif_builder, 'A')
	append(&notif_builder, 0, 0, 0, 0)
	append(&notif_builder, 0, 0, 4, 210) // pid 1234
	append(&notif_builder, "chat_channel")
	append(&notif_builder, 0)
	append(&notif_builder, "new_message")
	append(&notif_builder, 0)
	endian.put_i32(notif_builder[1:5], .Big, i32(len(notif_builder) - 1))

	rfq := []byte{'Z', 0, 0, 0, 5, 'I'}

	append(&mock.read_chunks, auth_ok)
	append(&mock.read_chunks, notif_builder[:])
	append(&mock.read_chunks, rfq)

	transport := make_mock_transport(&mock)
	notif_ctx: Test_Notification_Context
	config := Conn_Config{
		host = "localhost",
		port = 5432,
		user = "postgres",
		on_notification = on_test_notification,
		on_notif_data = &notif_ctx,
	}

	conn, err := conn_connect_with_transport(config, transport, context.allocator)
	testing.expect(t, err == nil, "expected handshake success")
	testing.expect(t, conn != nil, "expected conn not nil")
	if conn != nil {
		testing.expect_value(t, conn.status, Conn_Status.Ready)
		testing.expect(t, notif_ctx.received_notification, "expected notification callback to be called")
		testing.expect_value(t, notif_ctx.channel, "chat_channel")
		testing.expect_value(t, notif_ctx.payload, "new_message")
		testing.expect_value(t, notif_ctx.pid, 1234)
		conn_close(conn)
		free(conn, context.allocator)
	}

	mock_transport_destroy(&mock)
	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
test_conn_cancel_with_transport :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	mock: Mock_Transport
	mock_transport_init(&mock)

	transport := make_mock_transport(&mock)

	err := conn_cancel_with_transport(1234, 5678, transport)
	testing.expect(t, err == nil, "expected successful cancel request dispatch")

	// CancelRequest packet is 16 bytes: length 16, code 80877102, pid 1234, secret 5678
	testing.expect_value(t, len(mock.written_bytes), 16)
	len_i32, _ := endian.get_i32(mock.written_bytes[0:4], .Big)
	testing.expect_value(t, len_i32, 16)
	code_i32, _ := endian.get_i32(mock.written_bytes[4:8], .Big)
	testing.expect_value(t, code_i32, pgproto.CANCEL_REQUEST_CODE)
	pid_i32, _ := endian.get_i32(mock.written_bytes[8:12], .Big)
	testing.expect_value(t, pid_i32, 1234)
	sec_i32, _ := endian.get_i32(mock.written_bytes[12:16], .Big)
	testing.expect_value(t, sec_i32, 5678)

	testing.expect(t, mock.is_closed, "expected ephemeral cancel transport closed")

	mock_transport_destroy(&mock)
	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
test_conn_cancel_invalid_conn :: proc(t: ^testing.T) {
	// nil conn
	err_nil := conn_cancel(nil)
	testing.expect(t, err_nil != nil, "expected error for nil conn")
	#partial switch e in err_nil {
	case pgerr.Net_Error:
		testing.expect_value(t, e.type, pgerr.Net_Error_Type.Socket_Closed)
	case:
		testing.expect(t, false, "expected Net_Error")
	}

	// uninitialized pid/secret
	c: Conn
	c.backend_pid = 0
	c.backend_secret = 0
	err_uninit := conn_cancel(&c)
	testing.expect(t, err_uninit != nil, "expected error for uninitialized conn")
	#partial switch e in err_uninit {
	case pgerr.Net_Error:
		testing.expect_value(t, e.type, pgerr.Net_Error_Type.Socket_Closed)
	case:
		testing.expect(t, false, "expected Net_Error")
	}
}

@(test)
test_conn_cancel_with_transport_write_error :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	mock: Mock_Transport
	mock_transport_init(&mock)
	mock.is_closed = true

	transport := make_mock_transport(&mock)
	err := conn_cancel_with_transport(1234, 5678, transport)
	testing.expect(t, err != nil, "expected write error when transport is closed")

	mock_transport_destroy(&mock)
	testing.expect_value(t, len(track.allocation_map), 0)
}




