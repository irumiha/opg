package pgconn

import "core:time"
import "../pgerr"
import "../pgproto"

Prepared_Statement :: struct {
	name:       string,
	query:      string,
	param_oids: []u32,
}

/*
	conn_exec_params executes an ad-hoc parameterized query using unnamed statement ("")
	and unnamed portal ("") via a single pipelined write: Parse + Bind + Describe + Execute + Sync.
*/
conn_exec_params :: proc(
	conn: ^Conn,
	query: string,
	params: []pgproto.Bind_Param,
	on_row: Row_Callback = nil,
	on_command: Command_Callback = nil,
	on_desc: Row_Desc_Callback = nil,
	user_data: rawptr = nil,
) -> pgerr.Error {
	if !conn_is_alive(conn) {
		return pgerr.Net_Error{type = .Socket_Closed}
	}

	conn.status = .Busy

	pipeline_buf := make([dynamic]byte, context.temp_allocator)
	defer delete(pipeline_buf)

	pgproto.encode_parse(&pipeline_buf, "", query, nil) or_return
	pgproto.encode_bind(&pipeline_buf, pgproto.Msg_Bind{
		portal_name = "",
		statement_name = "",
		param_format_codes = nil,
		param_values = params,
		result_format_codes = nil,
	}) or_return
	pgproto.encode_describe(&pipeline_buf, .Portal, "")
	pgproto.encode_execute(&pipeline_buf, "", 0)
	pgproto.encode_sync(&pipeline_buf)

	stream_write_messages(&conn.stream, pipeline_buf[:]) or_return

	var_proceed := true
	var_recorded_err: pgerr.Error = nil

	for {
		msg := stream_read_message(&conn.stream, context.temp_allocator) or_return

		#partial switch m in msg {
		case pgproto.Msg_Parse_Complete, pgproto.Msg_Bind_Complete, pgproto.Msg_No_Data:
			// Successful pipeline checkpoints

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
				message = "Unexpected backend message during extended query execution",
			}
		}
	}
}
