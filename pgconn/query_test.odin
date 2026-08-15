package pgconn

import "core:encoding/endian"
import "core:mem"
import "core:strings"
import "core:testing"
import "../pgerr"
import "../pgproto"

Test_Query_Collector :: struct {
	column_count:  int,
	rows:          [dynamic][dynamic]string,
	command_tag:   string,
	rows_affected: i64,
	allocator:     mem.Allocator,
}

test_on_desc :: proc(user_data: rawptr, desc: pgproto.Msg_Row_Description) {
	c := (^Test_Query_Collector)(user_data)
	c.column_count = len(desc.fields)
}

test_on_row :: proc(user_data: rawptr, row: pgproto.Msg_Data_Row) -> bool {
	c := (^Test_Query_Collector)(user_data)
	row_strings := make([dynamic]string, c.allocator)
	for val in row.values {
		if val.is_null {
			append(&row_strings, strings.clone("NULL", c.allocator))
		} else {
			append(&row_strings, strings.clone(string(val.data), c.allocator))
		}
	}
	append(&c.rows, row_strings)
	return true
}

test_on_row_abort :: proc(user_data: rawptr, row: pgproto.Msg_Data_Row) -> bool {
	c := (^Test_Query_Collector)(user_data)
	row_strings := make([dynamic]string, c.allocator)
	for val in row.values {
		if val.is_null {
			append(&row_strings, strings.clone("NULL", c.allocator))
		} else {
			append(&row_strings, strings.clone(string(val.data), c.allocator))
		}
	}
	append(&c.rows, row_strings)
	return false // Stop streaming
}

test_on_command :: proc(user_data: rawptr, tag: string, rows_affected: i64) {
	c := (^Test_Query_Collector)(user_data)
	c.command_tag = strings.clone(tag, c.allocator)
	c.rows_affected = rows_affected
}

@(test)
test_extract_rows_affected :: proc(t: ^testing.T) {
	testing.expect_value(t, extract_rows_affected("SELECT 1"), 1)
	testing.expect_value(t, extract_rows_affected("SELECT 42"), 42)
	testing.expect_value(t, extract_rows_affected("INSERT 0 1"), 1)
	testing.expect_value(t, extract_rows_affected("INSERT 12345 5"), 5)
	testing.expect_value(t, extract_rows_affected("UPDATE 10"), 10)
	testing.expect_value(t, extract_rows_affected("DELETE 3"), 3)
	testing.expect_value(t, extract_rows_affected("MOVE 7"), 7)
	testing.expect_value(t, extract_rows_affected("FETCH 99"), 99)
	testing.expect_value(t, extract_rows_affected("COPY 1000"), 1000)
	testing.expect_value(t, extract_rows_affected("CREATE TABLE"), 0)
	testing.expect_value(t, extract_rows_affected("BEGIN"), 0)
	testing.expect_value(t, extract_rows_affected("COMMIT"), 0)
	testing.expect_value(t, extract_rows_affected(""), 0)
}

@(test)
test_conn_query_simple_select :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	mock: Mock_Transport
	mock_transport_init(&mock)

	transport := make_mock_transport(&mock)
	conn := new(Conn, context.allocator)
	conn.allocator = context.allocator
	conn.status = .Ready
	conn.parameters = make(map[string]string, 16, context.allocator)
	stream_init(&conn.stream, transport, allocator = context.allocator)

	// Server responses:
	// 1. RowDescription ('T'): 1 field ("val", oid 23, format 0)
	// 2. DataRow ('D'): 1 col ("42")
	// 3. CommandComplete ('C'): "SELECT 1"
	// 4. ReadyForQuery ('Z'): 'I'
	row_desc := []byte{
		'T', 0, 0, 0, 28,
		0, 1, // 1 field
		'v', 'a', 'l', 0, // field name
		0, 0, 0, 0, // table OID
		0, 0, // col attr
		0, 0, 0, 23, // data type OID (int4)
		0, 4, // data type size
		255, 255, 255, 255, // type modifier
		0, 0, // format text
	}
	data_row := []byte{
		'D', 0, 0, 0, 12,
		0, 1, // 1 column
		0, 0, 0, 2, // length 2
		'4', '2',
	}
	cmd_complete := []byte{
		'C', 0, 0, 0, 13,
		'S', 'E', 'L', 'E', 'C', 'T', ' ', '1', 0,
	}
	rfq := []byte{'Z', 0, 0, 0, 5, 'I'}

	append(&mock.read_chunks, row_desc)
	append(&mock.read_chunks, data_row)
	append(&mock.read_chunks, cmd_complete)
	append(&mock.read_chunks, rfq)

	collector: Test_Query_Collector
	collector.allocator = context.allocator
	collector.rows = make([dynamic][dynamic]string, context.allocator)

	err := conn_query(
		conn = conn,
		sql = "SELECT 42 AS val;",
		on_row = test_on_row,
		on_command = test_on_command,
		on_desc = test_on_desc,
		user_data = &collector,
	)

	testing.expect(t, err == nil, "expected query success")
	testing.expect_value(t, collector.column_count, 1)
	testing.expect_value(t, len(collector.rows), 1)
	testing.expect_value(t, collector.rows[0][0], "42")
	testing.expect_value(t, collector.command_tag, "SELECT 1")
	testing.expect_value(t, collector.rows_affected, 1)
	testing.expect_value(t, conn.status, Conn_Status.Ready)

	// Verify 'Q' packet written to mock
	testing.expect_value(t, mock.written_bytes[0], 'Q')

	conn_close(conn)
	free(conn, context.allocator)

	for r in collector.rows {
		for str in r {
			delete(str, context.allocator)
		}
		delete(r)
	}
	delete(collector.rows)
	delete(collector.command_tag, context.allocator)

	mock_transport_destroy(&mock)

	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
test_conn_query_not_alive :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	// 1. nil connection
	err_nil := conn_query(nil, "SELECT 1;")
	net_err, is_net_err := err_nil.(pgerr.Net_Error)
	testing.expect(t, is_net_err, "expected Net_Error on nil conn")
	testing.expect_value(t, net_err.type, pgerr.Net_Error_Type.Socket_Closed)

	// 2. closed connection
	conn := new(Conn, context.allocator)
	conn.allocator = context.allocator
	conn.status = .Closed
	err_closed := conn_query(conn, "SELECT 1;")
	net_err2, is_net_err2 := err_closed.(pgerr.Net_Error)
	testing.expect(t, is_net_err2, "expected Net_Error on closed conn")
	testing.expect_value(t, net_err2.type, pgerr.Net_Error_Type.Socket_Closed)
	free(conn, context.allocator)

	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
test_conn_query_row_callback_abort :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	mock: Mock_Transport
	mock_transport_init(&mock)

	transport := make_mock_transport(&mock)
	conn := new(Conn, context.allocator)
	conn.allocator = context.allocator
	conn.status = .Ready
	conn.parameters = make(map[string]string, 16, context.allocator)
	stream_init(&conn.stream, transport, allocator = context.allocator)

	// Send 2 DataRows, but callback aborts on row 1
	row_desc := []byte{
		'T', 0, 0, 0, 28,
		0, 1,
		'v', 'a', 'l', 0,
		0, 0, 0, 0,
		0, 0,
		0, 0, 0, 23,
		0, 4,
		255, 255, 255, 255,
		0, 0,
	}
	data_row1 := []byte{
		'D', 0, 0, 0, 12,
		0, 1,
		0, 0, 0, 2,
		'1', '0',
	}
	data_row2 := []byte{
		'D', 0, 0, 0, 12,
		0, 1,
		0, 0, 0, 2,
		'2', '0',
	}
	cmd_complete := []byte{
		'C', 0, 0, 0, 13,
		'S', 'E', 'L', 'E', 'C', 'T', ' ', '2', 0,
	}
	rfq := []byte{'Z', 0, 0, 0, 5, 'I'}

	append(&mock.read_chunks, row_desc)
	append(&mock.read_chunks, data_row1)
	append(&mock.read_chunks, data_row2)
	append(&mock.read_chunks, cmd_complete)
	append(&mock.read_chunks, rfq)

	collector: Test_Query_Collector
	collector.allocator = context.allocator
	collector.rows = make([dynamic][dynamic]string, context.allocator)

	err := conn_query(
		conn = conn,
		sql = "SELECT val FROM generate_series(10, 20, 10);",
		on_row = test_on_row_abort,
		on_command = test_on_command,
		on_desc = test_on_desc,
		user_data = &collector,
	)

	testing.expect(t, err == nil, "expected query success despite aborting rows")
	testing.expect_value(t, len(collector.rows), 1) // Only first row collected
	testing.expect_value(t, collector.rows[0][0], "10")
	testing.expect_value(t, collector.command_tag, "SELECT 2")
	testing.expect_value(t, collector.rows_affected, 2)
	testing.expect_value(t, conn.status, Conn_Status.Ready)

	conn_close(conn)
	free(conn, context.allocator)

	for r in collector.rows {
		for str in r {
			delete(str, context.allocator)
		}
		delete(r)
	}
	delete(collector.rows)
	delete(collector.command_tag, context.allocator)

	mock_transport_destroy(&mock)

	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
test_conn_query_error_response :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	mock: Mock_Transport
	mock_transport_init(&mock)

	transport := make_mock_transport(&mock)
	conn := new(Conn, context.allocator)
	conn.allocator = context.allocator
	conn.status = .Ready
	conn.parameters = make(map[string]string, 16, context.allocator)
	stream_init(&conn.stream, transport, allocator = context.allocator)

	// ErrorResponse packet ('E')
	err_packet := []byte{
		'E', 0, 0, 0, 33,
		'S', 'E', 'R', 'R', 'O', 'R', 0,
		'C', '4', '2', '6', '0', '1', 0,
		'M', 's', 'y', 'n', 't', 'a', 'x', ' ', 'e', 'r', 'r', 'o', 'r', 0,
		0,
	}
	rfq := []byte{'Z', 0, 0, 0, 5, 'E'} // Failed_Transaction ('E')

	append(&mock.read_chunks, err_packet)
	append(&mock.read_chunks, rfq)

	collector: Test_Query_Collector
	collector.allocator = context.allocator
	collector.rows = make([dynamic][dynamic]string, context.allocator)

	err := conn_query(
		conn = conn,
		sql = "INVALID SQL;",
		on_row = test_on_row,
		on_command = test_on_command,
		on_desc = test_on_desc,
		user_data = &collector,
	)

	testing.expect(t, err != nil, "expected query error")
	pg_err, is_pg_err := err.(pgerr.Postgres_Error)
	testing.expect(t, is_pg_err, "expected Postgres_Error")
	testing.expect_value(t, pg_err.severity, "ERROR")
	testing.expect_value(t, pg_err.code, "42601")
	testing.expect_value(t, pg_err.message, "syntax error")
	testing.expect_value(t, conn.status, Conn_Status.Failed_Transaction)
	testing.expect_value(t, conn.transaction_status, pgproto.Transaction_Status.Failed_Transaction)

	conn_close(conn)
	free(conn, context.allocator)

	for r in collector.rows {
		for str in r {
			delete(str, context.allocator)
		}
		delete(r)
	}
	delete(collector.rows)
	delete(collector.command_tag, context.allocator)

	mock_transport_destroy(&mock)

	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
test_conn_query_empty_query :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	mock: Mock_Transport
	mock_transport_init(&mock)

	transport := make_mock_transport(&mock)
	conn := new(Conn, context.allocator)
	conn.allocator = context.allocator
	conn.status = .Ready
	conn.parameters = make(map[string]string, 16, context.allocator)
	stream_init(&conn.stream, transport, allocator = context.allocator)

	empty_response := []byte{'I', 0, 0, 0, 4}
	rfq := []byte{'Z', 0, 0, 0, 5, 'I'}

	append(&mock.read_chunks, empty_response)
	append(&mock.read_chunks, rfq)

	err := conn_query(conn, ";")
	testing.expect(t, err == nil, "expected empty query success")
	testing.expect_value(t, conn.status, Conn_Status.Ready)

	conn_close(conn)
	free(conn, context.allocator)
	mock_transport_destroy(&mock)

	testing.expect_value(t, len(track.allocation_map), 0)
}

Test_Query_Notice_Context :: struct {
	notice_count: int,
	notif_count:  int,
}

test_query_notice_handler :: proc(user_data: rawptr, notice: pgproto.Msg_Notice_Response) {
	ctx := (^Test_Query_Notice_Context)(user_data)
	ctx.notice_count += 1
}

test_query_notif_handler :: proc(user_data: rawptr, notification: pgproto.Msg_Notification_Response) {
	ctx := (^Test_Query_Notice_Context)(user_data)
	ctx.notif_count += 1
}

@(test)
test_conn_query_notice_and_notification :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	mock: Mock_Transport
	mock_transport_init(&mock)

	notice_ctx := Test_Query_Notice_Context{}

	transport := make_mock_transport(&mock)
	conn := new(Conn, context.allocator)
	conn.allocator = context.allocator
	conn.status = .Ready
	conn.parameters = make(map[string]string, 16, context.allocator)
	conn.on_notice = test_query_notice_handler
	conn.on_notice_data = &notice_ctx
	conn.on_notification = test_query_notif_handler
	conn.on_notif_data = &notice_ctx
	stream_init(&conn.stream, transport, allocator = context.allocator)

	notice_packet := []byte{
		'N', 0, 0, 0, 17,
		'S', 'N', 'O', 'T', 'I', 'C', 'E', 0,
		'M', 'h', 'i', 0,
		0,
	}
	notif_packet := []byte{
		'A', 0, 0, 0, 17,
		0, 0, 0, 42,
		'c', 'h', 'a', 'n', 0,
		'p', 'a', 'y', 0,
	}
	cmd_complete := []byte{
		'C', 0, 0, 0, 8,
		'S', 'E', 'T', 0,
	}
	rfq := []byte{'Z', 0, 0, 0, 5, 'I'}

	append(&mock.read_chunks, notice_packet)
	append(&mock.read_chunks, notif_packet)
	append(&mock.read_chunks, cmd_complete)
	append(&mock.read_chunks, rfq)

	err := conn_query(conn, "SET timezone = 'UTC';")
	testing.expect(t, err == nil, "expected success")
	testing.expect_value(t, notice_ctx.notice_count, 1)
	testing.expect_value(t, notice_ctx.notif_count, 1)

	conn_close(conn)
	free(conn, context.allocator)
	mock_transport_destroy(&mock)

	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
test_conn_query_in_transaction_status :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	mock: Mock_Transport
	mock_transport_init(&mock)

	transport := make_mock_transport(&mock)
	conn := new(Conn, context.allocator)
	conn.allocator = context.allocator
	conn.status = .Ready
	conn.parameters = make(map[string]string, 16, context.allocator)
	stream_init(&conn.stream, transport, allocator = context.allocator)

	cmd_complete := []byte{
		'C', 0, 0, 0, 10,
		'B', 'E', 'G', 'I', 'N', 0,
	}
	rfq := []byte{'Z', 0, 0, 0, 5, 'T'} // In_Transaction

	append(&mock.read_chunks, cmd_complete)
	append(&mock.read_chunks, rfq)

	err := conn_query(conn, "BEGIN;")
	testing.expect(t, err == nil, "expected begin success")
	testing.expect_value(t, conn.status, Conn_Status.In_Transaction)
	testing.expect_value(t, conn.transaction_status, pgproto.Transaction_Status.In_Transaction)

	conn_close(conn)
	free(conn, context.allocator)
	mock_transport_destroy(&mock)

	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
test_conn_query_unexpected_message :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	mock: Mock_Transport
	mock_transport_init(&mock)

	transport := make_mock_transport(&mock)
	conn := new(Conn, context.allocator)
	conn.allocator = context.allocator
	conn.status = .Ready
	conn.parameters = make(map[string]string, 16, context.allocator)
	stream_init(&conn.stream, transport, allocator = context.allocator)

	// AuthOk ('R') during simple query is unexpected
	auth_ok := []byte{'R', 0, 0, 0, 8, 0, 0, 0, 0}
	append(&mock.read_chunks, auth_ok)

	err := conn_query(conn, "SELECT 1;")
	proto_err, is_proto_err := err.(pgerr.Protocol_Error)
	testing.expect(t, is_proto_err, "expected Protocol_Error")
	testing.expect_value(t, proto_err.type, pgerr.Protocol_Error_Type.Unexpected_Message)

	conn_close(conn)
	free(conn, context.allocator)
	mock_transport_destroy(&mock)

	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
test_conn_query_null_column_and_nil_callbacks :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	mock: Mock_Transport
	mock_transport_init(&mock)

	transport := make_mock_transport(&mock)
	conn := new(Conn, context.allocator)
	conn.allocator = context.allocator
	conn.status = .Ready
	conn.parameters = make(map[string]string, 16, context.allocator)
	stream_init(&conn.stream, transport, allocator = context.allocator)

	// 1 col, NULL value (len -1)
	row_desc := []byte{
		'T', 0, 0, 0, 28,
		0, 1,
		'v', 'a', 'l', 0,
		0, 0, 0, 0,
		0, 0,
		0, 0, 0, 23,
		0, 4,
		255, 255, 255, 255,
		0, 0,
	}
	data_row := []byte{
		'D', 0, 0, 0, 10,
		0, 1,
		255, 255, 255, 255,
	}
	cmd_complete := []byte{
		'C', 0, 0, 0, 13,
		'S', 'E', 'L', 'E', 'C', 'T', ' ', '1', 0,
	}
	rfq := []byte{'Z', 0, 0, 0, 5, 'I'}

	append(&mock.read_chunks, row_desc)
	append(&mock.read_chunks, data_row)
	append(&mock.read_chunks, cmd_complete)
	append(&mock.read_chunks, rfq)

	collector: Test_Query_Collector
	collector.allocator = context.allocator
	collector.rows = make([dynamic][dynamic]string, context.allocator)

	err := conn_query(
		conn = conn,
		sql = "SELECT NULL;",
		on_row = test_on_row,
		on_command = nil,
		on_desc = nil,
		user_data = &collector,
	)

	testing.expect(t, err == nil, "expected query success")
	testing.expect_value(t, len(collector.rows), 1)
	testing.expect_value(t, collector.rows[0][0], "NULL")

	conn_close(conn)
	free(conn, context.allocator)

	for r in collector.rows {
		for str in r {
			delete(str, context.allocator)
		}
		delete(r)
	}
	delete(collector.rows)

	mock_transport_destroy(&mock)

	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
test_conn_query_error_response_and_drain :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	mock: Mock_Transport
	mock_transport_init(&mock)

	transport := make_mock_transport(&mock)
	conn := new(Conn, context.allocator)
	conn.allocator = context.allocator
	conn.status = .In_Transaction
	conn.parameters = make(map[string]string, 16, context.allocator)
	stream_init(&conn.stream, transport, allocator = context.allocator)

	// Server responses:
	// 1. ErrorResponse: 'E', len, 'S', "ERROR\0", 'C', "42P01\0", 'M', "relation does not exist\0", '\0'
	// 2. ReadyForQuery: 'Z', len 5, 'E' (Failed_Transaction)
	err_builder := make([dynamic]byte, context.temp_allocator)
	append(&err_builder, 'E')
	append(&err_builder, 0, 0, 0, 0)
	append(&err_builder, 'S')
	append(&err_builder, "ERROR")
	append(&err_builder, 0)
	append(&err_builder, 'C')
	append(&err_builder, "42P01")
	append(&err_builder, 0)
	append(&err_builder, 'M')
	append(&err_builder, "relation does not exist")
	append(&err_builder, 0)
	append(&err_builder, 0)
	endian.put_i32(err_builder[1:5], .Big, i32(len(err_builder) - 1))

	rfq := []byte{'Z', 0, 0, 0, 5, 'E'}

	append(&mock.read_chunks, err_builder[:])
	append(&mock.read_chunks, rfq)

	err := conn_query(conn, "SELECT * FROM nonexistent;")
	testing.expect(t, err != nil, "expected error")
	pg_err, ok := err.(pgerr.Postgres_Error)
	testing.expect(t, ok, "expected Postgres_Error")
	testing.expect_value(t, pg_err.code, "42P01")
	testing.expect_value(t, pg_err.message, "relation does not exist")

	// Connection status transitioned to Failed_Transaction on ReadyForQuery
	testing.expect_value(t, conn.status, Conn_Status.Failed_Transaction)
	testing.expect_value(t, conn.transaction_status, pgproto.Transaction_Status.Failed_Transaction)

	conn_close(conn)
	free(conn, context.allocator)
	mock_transport_destroy(&mock)

	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
test_conn_query_early_abort_row_streaming :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	mock: Mock_Transport
	mock_transport_init(&mock)

	transport := make_mock_transport(&mock)
	conn := new(Conn, context.allocator)
	conn.allocator = context.allocator
	conn.status = .Ready
	conn.parameters = make(map[string]string, 16, context.allocator)
	stream_init(&conn.stream, transport, allocator = context.allocator)

	// 2 rows sent by server, but callback returns false after first row
	row1 := []byte{'D', 0, 0, 0, 11, 0, 1, 0, 0, 0, 1, '1'}
	row2 := []byte{'D', 0, 0, 0, 11, 0, 1, 0, 0, 0, 1, '2'}
	cmd := []byte{'C', 0, 0, 0, 13, 'S', 'E', 'L', 'E', 'C', 'T', ' ', '2', 0}
	rfq := []byte{'Z', 0, 0, 0, 5, 'I'}

	append(&mock.read_chunks, row1)
	append(&mock.read_chunks, row2)
	append(&mock.read_chunks, cmd)
	append(&mock.read_chunks, rfq)

	row_count := 0
	on_aborting_row :: proc(user_data: rawptr, row: pgproto.Msg_Data_Row) -> bool {
		count := (^int)(user_data)
		count^ += 1
		return false // Abort after first
	}

	err := conn_query(conn, "SELECT generate_series(1,2);", on_row = on_aborting_row, user_data = &row_count)
	testing.expect(t, err == nil, "expected clean return even on early abort")
	testing.expect_value(t, row_count, 1)
	testing.expect_value(t, conn.status, Conn_Status.Ready)

	conn_close(conn)
	free(conn, context.allocator)
	mock_transport_destroy(&mock)

	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
test_conn_exec_params_success :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	mock: Mock_Transport
	mock_transport_init(&mock)

	transport := make_mock_transport(&mock)
	conn := new(Conn, context.allocator)
	conn.allocator = context.allocator
	conn.status = .Ready
	conn.parameters = make(map[string]string, 16, context.allocator)
	stream_init(&conn.stream, transport, allocator = context.allocator)

	// Server pipeline response:
	// 1. ParseComplete ('1', len 4)
	// 2. BindComplete ('2', len 4)
	// 3. RowDescription ('T')
	// 4. DataRow ('D')
	// 5. CommandComplete ('C')
	// 6. ReadyForQuery ('Z')
	parse_ok := []byte{'1', 0, 0, 0, 4}
	bind_ok := []byte{'2', 0, 0, 0, 4}
	row_desc := []byte{
		'T', 0, 0, 0, 28,
		0, 1,
		'v', 'a', 'l', 0,
		0, 0, 0, 0,
		0, 0,
		0, 0, 0, 25, // text
		255, 255,
		255, 255, 255, 255,
		0, 0,
	}
	data_row := []byte{
		'D', 0, 0, 0, 15,
		0, 1,
		0, 0, 0, 5,
		'h', 'e', 'l', 'l', 'o',
	}
	cmd := []byte{'C', 0, 0, 0, 13, 'S', 'E', 'L', 'E', 'C', 'T', ' ', '1', 0}
	rfq := []byte{'Z', 0, 0, 0, 5, 'I'}

	append(&mock.read_chunks, parse_ok)
	append(&mock.read_chunks, bind_ok)
	append(&mock.read_chunks, row_desc)
	append(&mock.read_chunks, data_row)
	append(&mock.read_chunks, cmd)
	append(&mock.read_chunks, rfq)

	params := []pgproto.Bind_Param{
		{is_null = false, value = transmute([]byte)string("hello")},
	}

	collector: Test_Query_Collector
	collector.allocator = context.allocator
	collector.rows = make([dynamic][dynamic]string, context.allocator)

	err := conn_exec_params(
		conn = conn,
		query = "SELECT $1::text AS val;",
		params = params,
		on_row = test_on_row,
		on_command = test_on_command,
		on_desc = test_on_desc,
		user_data = &collector,
	)

	testing.expect(t, err == nil, "expected exec_params success")
	testing.expect_value(t, len(collector.rows), 1)
	testing.expect_value(t, collector.rows[0][0], "hello")
	testing.expect_value(t, conn.status, Conn_Status.Ready)

	conn_close(conn)
	free(conn, context.allocator)

	for r in collector.rows {
		for str in r {
			delete(str, context.allocator)
		}
		delete(r)
	}
	delete(collector.rows)
	delete(collector.command_tag, context.allocator)

	mock_transport_destroy(&mock)

	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
test_conn_exec_params_not_alive :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	params := []pgproto.Bind_Param{}

	// 1. nil connection
	err_nil := conn_exec_params(nil, "SELECT $1::text;", params)
	net_err, is_net_err := err_nil.(pgerr.Net_Error)
	testing.expect(t, is_net_err, "expected Net_Error on nil conn")
	testing.expect_value(t, net_err.type, pgerr.Net_Error_Type.Socket_Closed)

	// 2. closed connection
	conn := new(Conn, context.allocator)
	conn.allocator = context.allocator
	conn.status = .Closed
	err_closed := conn_exec_params(conn, "SELECT $1::text;", params)
	net_err2, is_net_err2 := err_closed.(pgerr.Net_Error)
	testing.expect(t, is_net_err2, "expected Net_Error on closed conn")
	testing.expect_value(t, net_err2.type, pgerr.Net_Error_Type.Socket_Closed)
	free(conn, context.allocator)

	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
test_conn_exec_params_null_param :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	mock: Mock_Transport
	mock_transport_init(&mock)

	transport := make_mock_transport(&mock)
	conn := new(Conn, context.allocator)
	conn.allocator = context.allocator
	conn.status = .Ready
	conn.parameters = make(map[string]string, 16, context.allocator)
	stream_init(&conn.stream, transport, allocator = context.allocator)

	parse_ok := []byte{'1', 0, 0, 0, 4}
	bind_ok := []byte{'2', 0, 0, 0, 4}
	row_desc := []byte{
		'T', 0, 0, 0, 28,
		0, 1,
		'v', 'a', 'l', 0,
		0, 0, 0, 0,
		0, 0,
		0, 0, 0, 25,
		255, 255,
		255, 255, 255, 255,
		0, 0,
	}
	data_row := []byte{
		'D', 0, 0, 0, 10,
		0, 1,
		255, 255, 255, 255, // NULL (-1)
	}
	cmd := []byte{'C', 0, 0, 0, 13, 'S', 'E', 'L', 'E', 'C', 'T', ' ', '1', 0}
	rfq := []byte{'Z', 0, 0, 0, 5, 'I'}

	append(&mock.read_chunks, parse_ok)
	append(&mock.read_chunks, bind_ok)
	append(&mock.read_chunks, row_desc)
	append(&mock.read_chunks, data_row)
	append(&mock.read_chunks, cmd)
	append(&mock.read_chunks, rfq)

	params := []pgproto.Bind_Param{
		{is_null = true, value = nil},
	}

	collector: Test_Query_Collector
	collector.allocator = context.allocator
	collector.rows = make([dynamic][dynamic]string, context.allocator)

	err := conn_exec_params(
		conn = conn,
		query = "SELECT $1::text AS val;",
		params = params,
		on_row = test_on_row,
		on_command = nil,
		on_desc = nil,
		user_data = &collector,
	)

	testing.expect(t, err == nil, "expected exec_params success")
	testing.expect_value(t, len(collector.rows), 1)
	testing.expect_value(t, collector.rows[0][0], "NULL")
	testing.expect_value(t, conn.status, Conn_Status.Ready)

	conn_close(conn)
	free(conn, context.allocator)

	for r in collector.rows {
		for str in r {
			delete(str, context.allocator)
		}
		delete(r)
	}
	delete(collector.rows)

	mock_transport_destroy(&mock)

	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
test_conn_exec_params_error_response :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	mock: Mock_Transport
	mock_transport_init(&mock)

	transport := make_mock_transport(&mock)
	conn := new(Conn, context.allocator)
	conn.allocator = context.allocator
	conn.status = .Ready
	conn.parameters = make(map[string]string, 16, context.allocator)
	stream_init(&conn.stream, transport, allocator = context.allocator)

	err_packet := []byte{
		'E', 0, 0, 0, 33,
		'S', 'E', 'R', 'R', 'O', 'R', 0,
		'C', '4', '2', '6', '0', '1', 0,
		'M', 's', 'y', 'n', 't', 'a', 'x', ' ', 'e', 'r', 'r', 'o', 'r', 0,
		0,
	}
	rfq := []byte{'Z', 0, 0, 0, 5, 'E'}

	append(&mock.read_chunks, err_packet)
	append(&mock.read_chunks, rfq)

	params := []pgproto.Bind_Param{}

	err := conn_exec_params(
		conn = conn,
		query = "INVALID SQL $1;",
		params = params,
	)

	testing.expect(t, err != nil, "expected error response")
	pg_err, ok := err.(pgerr.Postgres_Error)
	testing.expect(t, ok, "expected Postgres_Error")
	testing.expect_value(t, pg_err.code, "42601")
	testing.expect_value(t, pg_err.message, "syntax error")
	testing.expect_value(t, conn.status, Conn_Status.Failed_Transaction)
	testing.expect_value(t, conn.transaction_status, pgproto.Transaction_Status.Failed_Transaction)

	conn_close(conn)
	free(conn, context.allocator)
	mock_transport_destroy(&mock)

	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
test_conn_exec_params_unexpected_message :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	mock: Mock_Transport
	mock_transport_init(&mock)

	transport := make_mock_transport(&mock)
	conn := new(Conn, context.allocator)
	conn.allocator = context.allocator
	conn.status = .Ready
	conn.parameters = make(map[string]string, 16, context.allocator)
	stream_init(&conn.stream, transport, allocator = context.allocator)

	auth_ok := []byte{'R', 0, 0, 0, 8, 0, 0, 0, 0}
	append(&mock.read_chunks, auth_ok)

	params := []pgproto.Bind_Param{}

	err := conn_exec_params(
		conn = conn,
		query = "SELECT $1::text;",
		params = params,
	)

	proto_err, is_proto_err := err.(pgerr.Protocol_Error)
	testing.expect(t, is_proto_err, "expected Protocol_Error")
	testing.expect_value(t, proto_err.type, pgerr.Protocol_Error_Type.Unexpected_Message)

	conn_close(conn)
	free(conn, context.allocator)
	mock_transport_destroy(&mock)

	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
test_conn_exec_params_early_abort_row_streaming :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	mock: Mock_Transport
	mock_transport_init(&mock)

	transport := make_mock_transport(&mock)
	conn := new(Conn, context.allocator)
	conn.allocator = context.allocator
	conn.status = .Ready
	conn.parameters = make(map[string]string, 16, context.allocator)
	stream_init(&conn.stream, transport, allocator = context.allocator)

	parse_ok := []byte{'1', 0, 0, 0, 4}
	bind_ok := []byte{'2', 0, 0, 0, 4}
	row_desc := []byte{
		'T', 0, 0, 0, 28,
		0, 1,
		'v', 'a', 'l', 0,
		0, 0, 0, 0,
		0, 0,
		0, 0, 0, 23,
		0, 4,
		255, 255, 255, 255,
		0, 0,
	}
	row1 := []byte{'D', 0, 0, 0, 11, 0, 1, 0, 0, 0, 1, '1'}
	row2 := []byte{'D', 0, 0, 0, 11, 0, 1, 0, 0, 0, 1, '2'}
	cmd := []byte{'C', 0, 0, 0, 13, 'S', 'E', 'L', 'E', 'C', 'T', ' ', '2', 0}
	rfq := []byte{'Z', 0, 0, 0, 5, 'I'}

	append(&mock.read_chunks, parse_ok)
	append(&mock.read_chunks, bind_ok)
	append(&mock.read_chunks, row_desc)
	append(&mock.read_chunks, row1)
	append(&mock.read_chunks, row2)
	append(&mock.read_chunks, cmd)
	append(&mock.read_chunks, rfq)

	row_count := 0
	on_aborting_row :: proc(user_data: rawptr, row: pgproto.Msg_Data_Row) -> bool {
		count := (^int)(user_data)
		count^ += 1
		return false
	}

	params := []pgproto.Bind_Param{}

	err := conn_exec_params(
		conn = conn,
		query = "SELECT generate_series(1,2);",
		params = params,
		on_row = on_aborting_row,
		user_data = &row_count,
	)

	testing.expect(t, err == nil, "expected clean return even on early abort")
	testing.expect_value(t, row_count, 1)
	testing.expect_value(t, conn.status, Conn_Status.Ready)

	conn_close(conn)
	free(conn, context.allocator)
	mock_transport_destroy(&mock)

	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
test_conn_exec_params_notice_and_notification :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	mock: Mock_Transport
	mock_transport_init(&mock)

	notice_ctx := Test_Query_Notice_Context{}

	transport := make_mock_transport(&mock)
	conn := new(Conn, context.allocator)
	conn.allocator = context.allocator
	conn.status = .Ready
	conn.parameters = make(map[string]string, 16, context.allocator)
	conn.on_notice = test_query_notice_handler
	conn.on_notice_data = &notice_ctx
	conn.on_notification = test_query_notif_handler
	conn.on_notif_data = &notice_ctx
	stream_init(&conn.stream, transport, allocator = context.allocator)

	parse_ok := []byte{'1', 0, 0, 0, 4}
	bind_ok := []byte{'2', 0, 0, 0, 4}
	no_data := []byte{'n', 0, 0, 0, 4}
	notice_packet := []byte{
		'N', 0, 0, 0, 17,
		'S', 'N', 'O', 'T', 'I', 'C', 'E', 0,
		'M', 'h', 'i', 0,
		0,
	}
	notif_packet := []byte{
		'A', 0, 0, 0, 17,
		0, 0, 0, 42,
		'c', 'h', 'a', 'n', 0,
		'p', 'a', 'y', 0,
	}
	cmd_complete := []byte{
		'C', 0, 0, 0, 8,
		'S', 'E', 'T', 0,
	}
	rfq := []byte{'Z', 0, 0, 0, 5, 'T'} // In_Transaction

	append(&mock.read_chunks, parse_ok)
	append(&mock.read_chunks, bind_ok)
	append(&mock.read_chunks, no_data)
	append(&mock.read_chunks, notice_packet)
	append(&mock.read_chunks, notif_packet)
	append(&mock.read_chunks, cmd_complete)
	append(&mock.read_chunks, rfq)

	params := []pgproto.Bind_Param{}

	err := conn_exec_params(
		conn = conn,
		query = "SET timezone = $1;",
		params = params,
	)

	testing.expect(t, err == nil, "expected success")
	testing.expect_value(t, notice_ctx.notice_count, 1)
	testing.expect_value(t, notice_ctx.notif_count, 1)
	testing.expect_value(t, conn.status, Conn_Status.In_Transaction)

	conn_close(conn)
	free(conn, context.allocator)
	mock_transport_destroy(&mock)

	testing.expect_value(t, len(track.allocation_map), 0)
}


