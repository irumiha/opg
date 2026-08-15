package pgconn

import "core:mem"
import "core:strings"
import "core:testing"
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


