package pgconn

import "core:strings"
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

	MEMORY LIFETIME:
	If the server returns a Postgres_Error, its string fields are cloned into
	`context.temp_allocator` to survive the execution loop. Callers wishing
	to retain the error beyond the current frame/temp-arena cycle must clone it
	using `pgerr.postgres_error_clone(err.(pgerr.Postgres_Error), allocator)`.
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

	conn.status = .Busy
	stream_write_messages(&conn.stream, pipeline_buf[:]) or_return

	var_proceed := true
	var_recorded_err: pgerr.Error = nil

	for {
		msg := stream_read_message(&conn.stream, context.temp_allocator) or_return

		#partial switch m in msg {
		case pgproto.Msg_Parse_Complete, pgproto.Msg_Bind_Complete, pgproto.Msg_No_Data:
			// Successful pipeline checkpoints

		case pgproto.Msg_Empty_Query_Response:
			// Empty query (e.g. comment-only SQL) via extended protocol

		case pgproto.Msg_Parameter_Status:
			conn_apply_parameter_status(conn, m.name, m.value)

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

/*
	conn_prepare prepares a named SQL statement with optional parameter OIDs.
	Caches the prepared statement in conn.prepared_statements upon success.
*/
conn_prepare :: proc(
	conn: ^Conn,
	name: string,
	query: string,
	param_oids: []u32 = nil,
) -> pgerr.Error {
	if !conn_is_alive(conn) {
		return pgerr.Net_Error{type = .Socket_Closed}
	}

	pipeline_buf := make([dynamic]byte, context.temp_allocator)
	defer delete(pipeline_buf)

	// The server refuses Parse for an existing statement name (42P05):
	// named statements are only replaced after an explicit Close. Closing a
	// nonexistent statement is a legal no-op, so always close first.
	if name != "" {
		pgproto.encode_close(&pipeline_buf, .Statement, name)
	}
	pgproto.encode_parse(&pipeline_buf, name, query, param_oids) or_return
	pgproto.encode_sync(&pipeline_buf)

	conn.status = .Busy
	stream_write_messages(&conn.stream, pipeline_buf[:]) or_return

	var_recorded_err: pgerr.Error = nil

	for {
		msg := stream_read_message(&conn.stream, context.temp_allocator) or_return

		#partial switch m in msg {
		case pgproto.Msg_Close_Complete:
			// The server has closed the named statement. Remove the stale cache
			// entry NOW so a subsequent Parse failure cannot leave the client
			// referencing a server-side statement that no longer exists.
			if name != "" && conn.prepared_statements != nil && name in conn.prepared_statements {
				old := conn.prepared_statements[name]
				delete(old.name, conn.allocator)
				delete(old.query, conn.allocator)
				if old.param_oids != nil {
					delete(old.param_oids, conn.allocator)
				}
				delete_key(&conn.prepared_statements, name)
			}

		case pgproto.Msg_Parse_Complete:
			// Successfully parsed

		case pgproto.Msg_Empty_Query_Response:
			// Empty query (e.g. comment-only SQL) during prepare

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

			if var_recorded_err == nil && conn.prepared_statements != nil {
				name_clone := strings.clone(name, conn.allocator)
				query_clone := strings.clone(query, conn.allocator)
				oids_clone: []u32 = nil
				if param_oids != nil {
					oids_clone = make([]u32, len(param_oids), conn.allocator)
					copy(oids_clone, param_oids)
				}

				if old_stmt, exists := conn.prepared_statements[name]; exists {
					delete(old_stmt.name, conn.allocator)
					delete(old_stmt.query, conn.allocator)
					if old_stmt.param_oids != nil {
						delete(old_stmt.param_oids, conn.allocator)
					}
					delete_key(&conn.prepared_statements, name)
				}

				conn.prepared_statements[name_clone] = Prepared_Statement{
					name = name_clone,
					query = query_clone,
					param_oids = oids_clone,
				}
			}

			return var_recorded_err

		case:
			return pgerr.Protocol_Error{
				type = .Unexpected_Message,
				message = "Unexpected backend message during parse preparation",
			}
		}
	}
}

/*
	conn_exec_prepared executes a previously prepared named statement.
	Binds parameters, describes the portal, executes, and syncs.
*/
conn_exec_prepared :: proc(
	conn: ^Conn,
	name: string,
	params: []pgproto.Bind_Param,
	on_row: Row_Callback = nil,
	on_command: Command_Callback = nil,
	on_desc: Row_Desc_Callback = nil,
	user_data: rawptr = nil,
) -> pgerr.Error {
	if !conn_is_alive(conn) {
		return pgerr.Net_Error{type = .Socket_Closed}
	}

	pipeline_buf := make([dynamic]byte, context.temp_allocator)
	defer delete(pipeline_buf)

	pgproto.encode_bind(&pipeline_buf, pgproto.Msg_Bind{
		portal_name = "",
		statement_name = name,
		param_format_codes = nil,
		param_values = params,
		result_format_codes = nil,
	}) or_return
	pgproto.encode_describe(&pipeline_buf, .Portal, "")
	pgproto.encode_execute(&pipeline_buf, "", 0)
	pgproto.encode_sync(&pipeline_buf)

	conn.status = .Busy
	stream_write_messages(&conn.stream, pipeline_buf[:]) or_return

	var_proceed := true
	var_recorded_err: pgerr.Error = nil

	for {
		msg := stream_read_message(&conn.stream, context.temp_allocator) or_return

		#partial switch m in msg {
		case pgproto.Msg_Bind_Complete, pgproto.Msg_No_Data:
			// Successful pipeline checkpoints

		case pgproto.Msg_Empty_Query_Response:
			// Empty query (e.g. comment-only SQL) via prepared statement

		case pgproto.Msg_Parameter_Status:
			conn_apply_parameter_status(conn, m.name, m.value)

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
				message = "Unexpected backend message during prepared query execution",
			}
		}
	}
}

/*
	conn_close_statement closes a named prepared statement on the server and removes it from cache.
*/
conn_close_statement :: proc(conn: ^Conn, name: string) -> pgerr.Error {
	if !conn_is_alive(conn) {
		return pgerr.Net_Error{type = .Socket_Closed}
	}

	pipeline_buf := make([dynamic]byte, context.temp_allocator)
	defer delete(pipeline_buf)

	pgproto.encode_close(&pipeline_buf, .Statement, name)
	pgproto.encode_sync(&pipeline_buf)

	conn.status = .Busy
	stream_write_messages(&conn.stream, pipeline_buf[:]) or_return

	var_recorded_err: pgerr.Error = nil

	for {
		msg := stream_read_message(&conn.stream, context.temp_allocator) or_return

		#partial switch m in msg {
		case pgproto.Msg_Close_Complete:
			// Statement closed

		case pgproto.Msg_Empty_Query_Response:
			// No-op for close statement

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

			if conn.prepared_statements != nil && name in conn.prepared_statements {
				stmt := conn.prepared_statements[name]
				delete(stmt.name, conn.allocator)
				delete(stmt.query, conn.allocator)
				if stmt.param_oids != nil {
					delete(stmt.param_oids, conn.allocator)
				}
				delete_key(&conn.prepared_statements, name)
			}

			return var_recorded_err

		case:
			return pgerr.Protocol_Error{
				type = .Unexpected_Message,
				message = "Unexpected backend message during close statement",
			}
		}
	}
}

/*
	conn_close_portal closes a named portal on the server.
*/
conn_close_portal :: proc(conn: ^Conn, name: string) -> pgerr.Error {
	if !conn_is_alive(conn) {
		return pgerr.Net_Error{type = .Socket_Closed}
	}

	pipeline_buf := make([dynamic]byte, context.temp_allocator)
	defer delete(pipeline_buf)

	pgproto.encode_close(&pipeline_buf, .Portal, name)
	pgproto.encode_sync(&pipeline_buf)

	conn.status = .Busy
	stream_write_messages(&conn.stream, pipeline_buf[:]) or_return

	var_recorded_err: pgerr.Error = nil

	for {
		msg := stream_read_message(&conn.stream, context.temp_allocator) or_return

		#partial switch m in msg {
		case pgproto.Msg_Close_Complete:
			// Portal closed

		case pgproto.Msg_Empty_Query_Response:
			// No-op for close portal

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
				message = "Unexpected backend message during close portal",
			}
		}
	}
}

