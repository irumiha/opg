package pgconn

import "core:mem"
import "core:strings"
import "core:testing"
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
