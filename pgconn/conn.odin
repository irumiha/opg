package pgconn

import "core:fmt"
import "core:mem"
import "core:net"
import "core:strings"
import "core:time"
import "../pgerr"
import "../pgproto"

Conn_Status :: enum {
	Disconnected,
	Connecting,
	Authenticating,
	Ready,
	In_Transaction,
	Failed_Transaction,
	Busy,
	Closed,
}

Conn_Config :: struct {
	host:             string,
	port:             int,
	user:             string,
	password:         string,
	database:         string,
	application_name: string,
	connect_timeout:  time.Duration,
	read_timeout:     time.Duration,
	write_timeout:    time.Duration,
	on_notice:        Notice_Handler,
	on_notice_data:   rawptr,
	on_notification:  Notification_Handler,
	on_notif_data:    rawptr,
}

Notice_Handler :: #type proc(user_data: rawptr, notice: pgproto.Msg_Notice_Response)
Notification_Handler :: #type proc(user_data: rawptr, notification: pgproto.Msg_Notification_Response)

Conn :: struct {
	stream:             Stream_Buffer,
	tcp_data:           TCP_Transport_Data,
	status:             Conn_Status,
	config:             Conn_Config,
	backend_pid:        i32,
	backend_secret:     i32,
	transaction_status: pgproto.Transaction_Status,
	parameters:         map[string]string,
	allocator:          mem.Allocator,
	last_active:        time.Time,
	on_notice:          Notice_Handler,
	on_notice_data:     rawptr,
	on_notification:    Notification_Handler,
	on_notif_data:      rawptr,
}

conn_is_alive :: proc(conn: ^Conn) -> bool {
	if conn == nil do return false
	return conn.status == .Ready || conn.status == .In_Transaction || conn.status == .Failed_Transaction
}

conn_handshake :: proc(
	c: ^Conn,
	config: Conn_Config,
	transport: Stream_Transport,
	allocator := context.allocator,
) -> (
	conn: ^Conn,
	err: pgerr.Error,
) {
	c.allocator = allocator
	c.config = config
	c.status = .Connecting
	c.parameters = make(map[string]string, 16, allocator)
	c.on_notice = config.on_notice
	c.on_notice_data = config.on_notice_data
	c.on_notification = config.on_notification
	c.on_notif_data = config.on_notif_data
	stream_init(&c.stream, transport, allocator = allocator)

	// 1. Build and send StartupMessage
	startup_params := make([dynamic]pgproto.Startup_Param, context.temp_allocator)
	append(&startup_params, pgproto.Startup_Param{name = "user", value = config.user})
	if len(config.database) > 0 {
		append(&startup_params, pgproto.Startup_Param{name = "database", value = config.database})
	}
	append(&startup_params, pgproto.Startup_Param{name = "client_encoding", value = "UTF8"})
	if len(config.application_name) > 0 {
		append(&startup_params, pgproto.Startup_Param{name = "application_name", value = config.application_name})
	}

	startup_buf := make([dynamic]byte, context.temp_allocator)
	defer delete(startup_buf)
	pgproto.encode_startup(&startup_buf, pgproto.Msg_Startup{params = startup_params[:]})
	stream_write_messages(&c.stream, startup_buf[:]) or_return

	c.status = .Authenticating

	// 2. Initialize SCRAM state in case server requests SASL auth
	scram_state: Scram_State
	scram_state_init(&scram_state, allocator)
	defer scram_state_destroy(&scram_state)

	// 3. Read backend messages until ReadyForQuery
	for {
		msg := stream_read_message(&c.stream, context.temp_allocator) or_return

		#partial switch m in msg {
		case pgproto.Msg_Authentication:
			_, auth_err := auth_handle_challenge(
				&c.stream,
				m,
				config.user,
				config.password,
				&scram_state,
				context.temp_allocator,
			)
			if auth_err != nil {
				return nil, auth_err
			}

		case pgproto.Msg_Parameter_Status:
			if old_val, exists := c.parameters[m.name]; exists {
				delete(old_val, allocator)
				c.parameters[m.name] = strings.clone(m.value, allocator)
			} else {
				key_clone := strings.clone(m.name, allocator)
				val_clone := strings.clone(m.value, allocator)
				c.parameters[key_clone] = val_clone
			}

		case pgproto.Msg_Backend_Key_Data:
			c.backend_pid = m.process_id
			c.backend_secret = m.secret_key

		case pgproto.Msg_Notice_Response:
			if c.on_notice != nil {
				c.on_notice(c.on_notice_data, m)
			}

		case pgproto.Msg_Notification_Response:
			if c.on_notification != nil {
				c.on_notification(c.on_notif_data, m)
			}

		case pgproto.Msg_Ready_For_Query:
			c.transaction_status = m.status
			c.status = .Ready
			c.last_active = time.now()
			return c, nil

		case pgproto.Msg_Error_Response:
			cloned_err, _ := pgerr.postgres_error_clone(m.error, context.temp_allocator)
			return nil, cloned_err

		case:
			return nil, pgerr.Protocol_Error{
				type = .Unexpected_Message,
				message = "Unexpected backend message during startup handshake",
			}
		}
	}
}

conn_connect_with_transport :: proc(
	config: Conn_Config,
	transport: Stream_Transport,
	allocator := context.allocator,
) -> (
	conn: ^Conn,
	err: pgerr.Error,
) {
	c := new(Conn, allocator)
	defer if err != nil {
		if c != nil {
			conn_close(c)
			free(c, allocator)
		}
	}

	return conn_handshake(c, config, transport, allocator)
}

conn_connect :: proc(
	config: Conn_Config,
	allocator := context.allocator,
) -> (
	conn: ^Conn,
	err: pgerr.Error,
) {
	port := config.port
	if port <= 0 do port = 5432
	endpoint := fmt.tprintf("%s:%d", config.host, port)

	socket, nerr := net.dial_tcp_from_hostname_and_port_string(endpoint)
	if nerr != nil {
		return nil, pgerr.Net_Error{
			type = .Connection_Refused,
			raw_net_error = nerr,
		}
	}

	c := new(Conn, allocator)
	defer if err != nil {
		if c != nil {
			conn_close(c)
			free(c, allocator)
		}
	}

	transport := make_tcp_transport(&c.tcp_data, socket)
	return conn_handshake(c, config, transport, allocator)
}

conn_close :: proc(conn: ^Conn) {
	if conn == nil || conn.status == .Closed do return

	// If stream transport is open, send Terminate ('X')
	if conn.status != .Disconnected && conn.stream.transport.write != nil {
		buf := make([dynamic]byte, context.temp_allocator)
		defer delete(buf)
		pgproto.encode_terminate(&buf)
		_ = stream_write_messages(&conn.stream, buf[:])
	}

	// Close stream transport
	stream_close(&conn.stream)
	stream_destroy(&conn.stream)

	// Free parameters map
	if conn.parameters != nil {
		for k, v in conn.parameters {
			delete(k, conn.allocator)
			delete(v, conn.allocator)
		}
		delete(conn.parameters)
		conn.parameters = nil
	}

	conn.status = .Closed
}

conn_cancel_with_transport :: proc(
	pid: i32,
	secret: i32,
	transport: Stream_Transport,
) -> pgerr.Error {
	defer if transport.close != nil {
		transport.close(transport.data)
	}

	buf := make([dynamic]byte, context.temp_allocator)
	defer delete(buf)
	pgproto.encode_cancel_request(&buf, pid, secret)
	if transport.write != nil {
		_, err := transport.write(transport.data, buf[:])
		if err != nil {
			return err
		}
	}
	return nil
}

conn_cancel :: proc(conn: ^Conn) -> pgerr.Error {
	if conn == nil do return pgerr.Net_Error{type = .Socket_Closed}
	if conn.backend_pid == 0 && conn.backend_secret == 0 {
		return pgerr.Net_Error{
			type = .Socket_Closed,
			code = -1,
		}
	}

	port := conn.config.port
	if port <= 0 do port = 5432
	endpoint := fmt.tprintf("%s:%d", conn.config.host, port)

	socket, nerr := net.dial_tcp_from_hostname_and_port_string(endpoint)
	if nerr != nil {
		return pgerr.Net_Error{type = .Connection_Refused, raw_net_error = nerr}
	}

	tdata: TCP_Transport_Data
	transport := make_tcp_transport(&tdata, socket)
	return conn_cancel_with_transport(conn.backend_pid, conn.backend_secret, transport)
}

