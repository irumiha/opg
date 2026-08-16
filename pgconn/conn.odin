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
	ssl_mode:         SSL_Mode, // zero value = .Prefer (attempt TLS, fall back)
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
	tls_data:           TLS_Transport_Data,
	status:             Conn_Status,
	config:             Conn_Config,
	backend_pid:        i32,
	backend_secret:     i32,
	transaction_status:  pgproto.Transaction_Status,
	parameters:          map[string]string,
	prepared_statements: map[string]Prepared_Statement,
	allocator:           mem.Allocator,
	// Per-message parsing scratch, reset between messages. See
	// conn_scratch_allocator.
	scratch:             mem.Dynamic_Arena,
	last_active:         time.Time,
	on_notice:           Notice_Handler,
	on_notice_data:      rawptr,
	on_notification:     Notification_Handler,
	on_notif_data:       rawptr,
}

conn_is_alive :: proc(conn: ^Conn) -> bool {
	if conn == nil do return false
	return conn.status == .Ready || conn.status == .In_Transaction || conn.status == .Failed_Transaction
}

/*
	conn_apply_parameter_status records (or replaces) a server-pushed
	ParameterStatus into conn.parameters using the persistent allocator.
	Called from the handshake and every execution loop, since the server may
	re-push a ParameterStatus after `SET` statements before CommandComplete.
*/
conn_apply_parameter_status :: proc(conn: ^Conn, name, value: string) {
	if old_val, exists := conn.parameters[name]; exists {
		delete(old_val, conn.allocator)
		conn.parameters[name] = strings.clone(value, conn.allocator)
	} else {
		key_clone := strings.clone(name, conn.allocator)
		val_clone := strings.clone(value, conn.allocator)
		conn.parameters[key_clone] = val_clone
	}
}

/*
	conn_scratch_allocator returns the connection's per-message parsing arena,
	initializing it on first use.

	Parsing a message needs somewhere to put what it cannot borrow from the
	stream buffer — a row's column slice, most of all — and the caller's temp
	arena is the wrong place for it. The driver never frees those allocations,
	and a caller streaming a large result cannot reset the arena mid-stream
	because the row bytes point into the stream buffer. Live memory then grows
	with the row count, which is precisely what streaming exists to avoid.

	A per-connection arena reset between messages bounds it by the largest
	single message instead. Blocks are recycled on reset rather than returned,
	so a long stream settles instead of churning.

	This is also why every Postgres_Error is cloned into conn.allocator: an
	error recorded mid-loop has to outlive the reset that follows it.

	Lazily initialized so a Conn assembled field by field behaves like one
	returned by conn_connect.
*/
@(private)
conn_scratch_allocator :: proc(conn: ^Conn) -> mem.Allocator {
	if conn.scratch.block_size == 0 {
		backing := conn.allocator
		if backing.procedure == nil {
			backing = context.allocator
		}
		mem.dynamic_arena_init(&conn.scratch, backing, backing)
	}
	return mem.dynamic_arena_allocator(&conn.scratch)
}

/*
	conn_scratch_reset reclaims the previous message's parsing scratch.

	Call it at the top of a read loop rather than the bottom: everything the
	current message lent out — row values, field names, the command tag — stays
	valid until the next message is read, which is the contract the callbacks
	already document.
*/
@(private)
conn_scratch_reset :: proc(conn: ^Conn) {
	if conn.scratch.block_size != 0 {
		mem.dynamic_arena_reset(&conn.scratch)
	}
}

/*
	map_dial_error translates a core:net dial failure into a specific pgerr
	Net_Error so callers can distinguish DNS failures, unreachable hosts, and
	connection refusals instead of always seeing .Connection_Refused.
*/
map_dial_error :: proc(nerr: net.Network_Error) -> pgerr.Net_Error {
	#partial switch e in nerr {
	case net.DNS_Error:
		return pgerr.Net_Error{type = .DNS_Resolution_Failed, raw_net_error = nerr}
	case net.Resolve_Error, net.Parse_Endpoint_Error:
		return pgerr.Net_Error{type = .DNS_Resolution_Failed, raw_net_error = nerr}
	case net.Dial_Error:
		#partial switch e {
		case .Host_Unreachable, .Network_Unreachable:
			return pgerr.Net_Error{type = .Host_Unreachable, raw_net_error = nerr}
		case .Timeout, .Would_Block:
			return pgerr.Net_Error{type = .Timeout, raw_net_error = nerr}
		case .Refused, .Reset:
			return pgerr.Net_Error{type = .Connection_Refused, raw_net_error = nerr}
		case:
			return pgerr.Net_Error{type = .Connection_Refused, raw_net_error = nerr}
		}
	case:
		return pgerr.Net_Error{type = .Connection_Refused, raw_net_error = nerr}
	}
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
	c.prepared_statements = make(map[string]Prepared_Statement, 16, allocator)
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
			conn_apply_parameter_status(c, m.name, m.value)

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
			cloned_err, _ := pgerr.postgres_error_clone(m.error, allocator)
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

/*
	conn_connect dials the server, negotiates TLS per config.ssl_mode, and runs
	the startup and authentication exchange.

	ERROR OWNERSHIP:
	A Postgres_Error from the server (a rejected login, an unknown database) is
	cloned into `allocator` and belongs to the caller; free it with
	`pgerr.postgres_error_destroy(err.(pgerr.Postgres_Error), allocator)`.
	There is no Conn to read the allocator back from on this path, which is the
	one thing that distinguishes it from the execution paths — the rule itself
	is the same everywhere.
*/
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
		return nil, map_dial_error(nerr)
	}

	c := new(Conn, allocator)
	defer if err != nil {
		if c != nil {
			conn_close(c)
			free(c, allocator)
		}
	}

	// Bound the socket before anything reads from it. Connect runs two
	// exchanges before the transport is final — the SSLRequest reply and the
	// TLS handshake — and both block on a peer that completes the TCP
	// connection and then goes quiet. Deadlines applied only once the
	// transport exists leave those two unbounded, which is what turns a
	// failing TLS backend into a hung connect instead of an error.
	//
	// connect_timeout governs this phase when set. read_timeout stands in for
	// it otherwise, so a caller who configured only the latter still gets a
	// connect that ends — but the two describe different things, and this
	// phase is the several round trips of negotiation, handshake and auth
	// rather than any single read.
	connect_deadline := config.connect_timeout
	if connect_deadline <= 0 do connect_deadline = config.read_timeout
	if connect_deadline > 0 {
		derr := apply_socket_deadlines(socket, connect_deadline, connect_deadline)
		if derr != nil {
			net.close(socket)
			return nil, derr
		}
		// The TLS backends bound their own retry loops on elapsed time against
		// these fields, and the handshake runs before set_deadlines below has
		// recorded them.
		c.tls_data.read_timeout = connect_deadline
		c.tls_data.write_timeout = connect_deadline
	}

	transport := make_tcp_transport(&c.tcp_data, socket)

	// Pre-startup TLS negotiation (SSLRequest). On Wrap_TLS the socket is
	// handed to OpenSSL and the startup sequence runs over the encrypted
	// stream; the plaintext transport is discarded without closing.
	action, neg_err := ssl_negotiate(transport, config.ssl_mode, tls_ensure_loaded())
	if neg_err != nil {
		net.close(socket) // stream not initialized yet; close explicitly
		return nil, neg_err
	}
	if action == .Wrap_TLS {
		tls_transport, tls_err := make_tls_transport(&c.tls_data, socket, config.host)
		if tls_err != nil {
			net.close(socket)
			return nil, tls_err
		}
		transport = tls_transport
	}

	ready, herr := conn_handshake(c, config, transport, allocator)
	if herr != nil {
		return nil, herr
	}

	// Connect is over; hand the socket to the query deadlines.
	//
	// This has to run whenever a connect deadline was installed, even when both
	// query timeouts are zero. Otherwise a connection configured with
	// connect_timeout alone keeps that short deadline for the rest of its life
	// and the first slow query fails against a timeout the caller scoped to
	// connecting. set_deadlines passes a zero duration through as "clear".
	if connect_deadline > 0 || config.read_timeout > 0 || config.write_timeout > 0 {
		if derr := ready.stream.transport.set_deadlines(
			ready.stream.transport.data,
			config.read_timeout,
			config.write_timeout,
		); derr != nil {
			return nil, derr
		}
	}

	return ready, nil
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

	// Free prepared statements map
	if conn.prepared_statements != nil {
		for _, stmt in conn.prepared_statements {
			delete(stmt.name, conn.allocator)
			delete(stmt.query, conn.allocator)
			if stmt.param_oids != nil {
				delete(stmt.param_oids, conn.allocator)
			}
		}
		delete(conn.prepared_statements)
		conn.prepared_statements = nil
	}

	// Returns the recycled parsing blocks to the backing allocator.
	if conn.scratch.block_size != 0 {
		mem.dynamic_arena_destroy(&conn.scratch)
		conn.scratch = {}
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
		return map_dial_error(nerr)
	}

	tdata: TCP_Transport_Data
	transport := make_tcp_transport(&tdata, socket)
	return conn_cancel_with_transport(conn.backend_pid, conn.backend_secret, transport)
}

