package pgconn

import "core:strconv"
import "core:strings"
import "core:time"
import "../pgerr"
import "../pgproto"

Row_Desc_Callback :: #type proc(user_data: rawptr, desc: pgproto.Msg_Row_Description)
Row_Callback :: #type proc(user_data: rawptr, row: pgproto.Msg_Data_Row) -> (proceed: bool)
Command_Callback :: #type proc(user_data: rawptr, tag: string, rows_affected: i64)

extract_rows_affected :: proc(tag: string) -> i64 {
	last_space := strings.last_index_byte(tag, ' ')
	if last_space < 0 do return 0
	num_str := tag[last_space + 1:]
	val, ok := strconv.parse_i64(num_str)
	if !ok do return 0
	return val
}

/*
	conn_query executes a SQL query string using PostgreSQL Simple Query protocol ('Q').
	Streams rows, command completion tags, and descriptors to provided callbacks.

	MEMORY LIFETIME:
	If the server returns a Postgres_Error, its string fields are cloned into
	`context.temp_allocator` to survive the query execution loop. Callers wishing
	to retain the error beyond the current frame/temp-arena cycle must clone it
	using `pgerr.postgres_error_clone(err.(pgerr.Postgres_Error), allocator)`.
*/
conn_query :: proc(
	conn: ^Conn,
	sql: string,
	on_row: Row_Callback = nil,
	on_command: Command_Callback = nil,
	on_desc: Row_Desc_Callback = nil,
	user_data: rawptr = nil,
) -> pgerr.Error {
	if !conn_is_alive(conn) {
		return pgerr.Net_Error{type = .Socket_Closed}
	}

	conn.status = .Busy

	query_buf := make([dynamic]byte, context.temp_allocator)
	defer delete(query_buf)
	pgproto.encode_query(&query_buf, sql)
	stream_write_messages(&conn.stream, query_buf[:]) or_return

	var_proceed := true
	var_recorded_err: pgerr.Error = nil

	for {
		msg := stream_read_message(&conn.stream, context.temp_allocator) or_return

		#partial switch m in msg {
		case pgproto.Msg_Row_Description:
			if on_desc != nil && var_recorded_err == nil {
				on_desc(user_data, m)
			}

		case pgproto.Msg_Data_Row:
			if on_row != nil && var_proceed && var_recorded_err == nil {
				var_proceed = on_row(user_data, m)
			}

		case pgproto.Msg_Command_Complete:
			if on_command != nil && var_recorded_err == nil {
				rows_affected := extract_rows_affected(m.tag)
				on_command(user_data, m.tag, rows_affected)
			}

		case pgproto.Msg_Empty_Query_Response:
			// No action needed for empty queries

		case pgproto.Msg_Parameter_Status:
			conn_apply_parameter_status(conn, m.name, m.value)

		case pgproto.Msg_Notice_Response:
			if conn.on_notice != nil {
				conn.on_notice(conn.on_notice_data, m)
			}

		case pgproto.Msg_Notification_Response:
			if conn.on_notification != nil {
				conn.on_notification(conn.on_notif_data, m)
			}

		case pgproto.Msg_Error_Response:
			if var_recorded_err == nil {
				cloned_err, _ := pgerr.postgres_error_clone(m.error, context.temp_allocator)
				var_recorded_err = cloned_err
			}

		case pgproto.Msg_Ready_For_Query:
			conn.transaction_status = m.status
			switch m.status {
			case .Idle:
				conn.status = .Ready
			case .In_Transaction:
				conn.status = .In_Transaction
			case .Failed_Transaction:
				conn.status = .Failed_Transaction
			}
			conn.last_active = time.now()
			return var_recorded_err

		case:
			return pgerr.Protocol_Error{
				type = .Unexpected_Message,
				message = "Unexpected backend message during query execution",
			}
		}
	}
}
