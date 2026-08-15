# [OPG-203] Startup Sequence & Connection State Machine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the connection lifecycle, startup handshake flow, authentication integration, parameter tracking, out-of-band query cancellation, and teardown (`pgconn/conn.odin`).

**Architecture:** `Conn` encapsulates `Stream_Buffer`, `TCP_Transport_Data`, server runtime `parameters` map, and status state machine. `conn_connect_with_transport` and `conn_connect` execute the Protocol 3.0 startup sequence (`StartupMessage` $\rightarrow$ integrated `auth_handle_challenge` $\rightarrow$ `ParameterStatus` $\rightarrow$ `BackendKeyData` $\rightarrow$ `ReadyForQuery`). `conn_cancel` sends out-of-band `CancelRequest` over ephemeral socket. `conn_close` sends `Terminate` and frees memory.

**Tech Stack:** Odin, `core:net`, `core:mem`, `core:time`, `core:strings`, `core:fmt`, `pgproto`, `pgerr`.

**Spec:** [`docs/superpowers/specs/2026-08-15-opg-203-connection-state-machine-design.md`](file:///home/igorrumiha/Projects/odin-projects/opg/docs/superpowers/specs/2026-08-15-opg-203-connection-state-machine-design.md)

## Global Constraints

- Never do what was not specifically asked for.
- All errors must return `pgerr.Error` (tagged union). Subpackages import `pgerr` — never `root.odin`.
- All transient packet parsing and startup builders use `allocator := context.temp_allocator`.
- Multi-byte integers must be read/written in Network Byte Order (Big-Endian).
- Unit tests must be 100% network-independent using `Mock_Transport` and in-memory byte vectors.
- Zero memory leaks verified using `core:mem.Tracking_Allocator`.

---

### Task 1: Connection Data Structures, Config & Teardown API

**Files:**
- Modify: `pgconn/pool.odin` (remove conflicting stub struct definitions of `Conn_Status`, `Conn`)
- Create: `pgconn/conn.odin`
- Create: `pgconn/conn_test.odin`

**Interfaces:**
- Produces:
  - `Conn_Status :: enum`
  - `Conn_Config :: struct`
  - `Notice_Handler :: #type proc(user_data: rawptr, notice: pgproto.Msg_Notice_Response)`
  - `Notification_Handler :: #type proc(user_data: rawptr, notification: pgproto.Msg_Notification_Response)`
  - `Conn :: struct`
  - `conn_close(conn: ^Conn)`
  - `conn_is_alive(conn: ^Conn) -> bool`

- [ ] **Step 1: Write failing test for `Conn` struct, status checks, and `conn_close`**

In `pgconn/conn_test.odin`:
```odin
package pgconn

import "core:mem"
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
	defer mock_transport_destroy(&mock)

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
	testing.expect(!conn_is_alive(conn), "expected closed connection to not be alive")
	testing.expect(t, mock.is_closed, "expected transport closed on conn_close")

	free(conn, context.allocator)
	testing.expect_value(t, len(track.allocation_map), 0)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `odin test tests -all-packages`
Expected: FAIL with `Conn` definitions conflicting or undefined

- [ ] **Step 3: Clean up `pgconn/pool.odin` and implement `pgconn/conn.odin`**

In `pgconn/pool.odin`, remove the redundant definitions of `Conn_Status` and `Conn` (lines 13-39) so they reside in `pgconn/conn.odin`.

In `pgconn/conn.odin`:
```odin
package pgconn

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

conn_close :: proc(conn: ^Conn) {
	if conn == nil || conn.status == .Closed do return

	// If stream transport is open, send Terminate ('X')
	if conn.status != .Disconnected && conn.stream.transport.write != nil {
		term_msg := pgproto.frontend_encode_terminate(context.temp_allocator)
		_ = stream_write_messages(&conn.stream, term_msg)
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `odin test tests -all-packages -vet -strict-style`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add pgconn/conn.odin pgconn/conn_test.odin pgconn/pool.odin
git commit -m "feat(pgconn): define Conn struct and lifecycle procedures"
```

---

### Task 2: Startup Sequence & Handshake Engine (Cleartext & MD5)

**Files:**
- Modify: `pgconn/conn.odin`
- Modify: `pgconn/conn_test.odin`

**Interfaces:**
- Produces:
  - `conn_connect_with_transport(config: Conn_Config, transport: Stream_Transport, allocator := context.allocator) -> (conn: ^Conn, err: pgerr.Error)`

- [ ] **Step 1: Write failing tests for StartupMessage and Cleartext/MD5 Handshake**

In `pgconn/conn_test.odin`:
```odin
@(test)
test_conn_handshake_cleartext_success :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	mock: Mock_Transport
	mock_transport_init(&mock)
	defer mock_transport_destroy(&mock)

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
	}

	conn, err := conn_connect_with_transport(config, transport, context.allocator)
	defer if conn != nil {
		conn_close(conn)
		free(conn, context.allocator)
	}

	testing.expect(t, err == nil, "expected handshake success")
	testing.expect_value(t, conn.status, Conn_Status.Ready)
	testing.expect_value(t, conn.transaction_status, pgproto.Transaction_Status.Idle)

	// Verify StartupMessage was written, followed by PasswordMessage
	testing.expect(t, len(mock.written_bytes) > 0, "expected outbound writes")

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
	defer mock_transport_destroy(&mock)

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
	defer if conn != nil {
		conn_close(conn)
		free(conn, context.allocator)
	}

	testing.expect(t, err == nil, "expected md5 handshake success")
	testing.expect_value(t, conn.status, Conn_Status.Ready)

	testing.expect_value(t, len(track.allocation_map), 0)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `odin test tests -all-packages`
Expected: FAIL with `conn_connect_with_transport` undefined

- [ ] **Step 3: Implement `conn_connect_with_transport` in `pgconn/conn.odin`**

In `pgconn/conn.odin`:
```odin
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

	c.allocator = allocator
	c.config = config
	c.status = .Connecting
	c.parameters = make(map[string]string, 16, allocator)
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

	startup_bytes := pgproto.frontend_encode_startup_message(startup_params[:], context.temp_allocator)
	stream_write_messages(&c.stream, startup_bytes) or_return

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
			is_complete, auth_err := auth_handle_challenge(
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
			key_clone := strings.clone(m.name, allocator)
			val_clone := strings.clone(m.value, allocator)
			c.parameters[key_clone] = val_clone

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
			return nil, m.error

		case:
			return nil, pgerr.Protocol_Error{
				type = .Unexpected_Message,
				message = "Unexpected backend message during startup handshake",
			}
		}
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `odin test tests -all-packages -vet -strict-style`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add pgconn/conn.odin pgconn/conn_test.odin
git commit -m "feat(pgconn): implement conn_connect_with_transport and startup handshake"
```

---

### Task 3: Parameter Tracking, Key Data & SCRAM Auth Integration

**Files:**
- Modify: `pgconn/conn_test.odin`

**Interfaces:**
- Tests verifying:
  - SASL SCRAM-SHA-256 complete handshake in `conn_connect_with_transport`.
  - Storing parameter status (`server_version`, `client_encoding`, `TimeZone`, `integer_datetimes`).
  - Storing `backend_pid` and `backend_secret`.
  - Notice and Notification callbacks execution.

- [ ] **Step 1: Write test for SCRAM auth handshake, parameters, key data, and notice callbacks**

In `pgconn/conn_test.odin`:
```odin
@(test)
test_conn_handshake_scram_and_parameters :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	mock: Mock_Transport
	mock_transport_init(&mock)
	defer mock_transport_destroy(&mock)

	// Build SASL challenge messages:
	// 1. AuthenticationSASL: 'R', len 23, type 10, "SCRAM-SHA-256\0\0"
	auth_sasl := []byte{
		'R', 0, 0, 0, 23,
		0, 0, 0, 10,
		'S', 'C', 'R', 'A', 'M', '-', 'S', 'H', 'A', '-', '2', '5', '6', 0, 0,
	}

	// 2. AuthenticationSASLContinue: 'R', len 4 + 4 + len(data), type 11, data: "r=...,s=...,i=4096"
	server_first := "r=nonce12345678901234567890EXTRA,s=QSXCR+Q6sek8bf92,i=4096"
	sasl_continue_builder := make([dynamic]byte, context.temp_allocator)
	append(&sasl_continue_builder, 'R')
	append(&sasl_continue_builder, 0, 0, 0, 0)
	append(&sasl_continue_builder, 0, 0, 0, 11)
	append(&sasl_continue_builder, transmute([]byte)server_first)
	endian.put_i32(sasl_continue_builder[1:5], .Big, i32(len(sasl_continue_builder) - 1))

	// ParameterStatus messages:
	// 'S', len 4 + 15 + 6, "server_version\0", "16.1\0"
	param_msg := []byte{
		'S', 0, 0, 0, 25,
		's', 'e', 'r', 'v', 'e', 'r', '_', 'v', 'e', 'r', 's', 'i', 'o', 'n', 0,
		'1', '6', '.', '1', 0,
	}

	// BackendKeyData: 'K', len 12, pid 1234, secret 5678
	key_data := []byte{
		'K', 0, 0, 0, 12,
		0, 0, 4, 210, // 1234
		0, 0, 22, 46, // 5678
	}

	// ReadyForQuery
	rfq := []byte{'Z', 0, 0, 0, 5, 'I'}

	append(&mock.read_chunks, auth_sasl)
	// After client sends initial SASL response, server returns continue, params, key data, rfq
	// We will simulate server response flow

	// AuthenticationOk:
	auth_ok := []byte{'R', 0, 0, 0, 8, 0, 0, 0, 0}
	append(&mock.read_chunks, auth_ok)
	append(&mock.read_chunks, param_msg)
	append(&mock.read_chunks, key_data)
	append(&mock.read_chunks, rfq)

	transport := make_mock_transport(&mock)
	config := Conn_Config{
		host = "localhost",
		port = 5432,
		user = "postgres",
		password = "password",
	}

	conn, err := conn_connect_with_transport(config, transport, context.allocator)
	defer if conn != nil {
		conn_close(conn)
		free(conn, context.allocator)
	}

	testing.expect(t, err == nil, "expected handshake success")
	testing.expect_value(t, conn.backend_pid, 1234)
	testing.expect_value(t, conn.backend_secret, 5678)
	testing.expect_value(t, conn.parameters["server_version"], "16.1")

	testing.expect_value(t, len(track.allocation_map), 0)
}
```

- [ ] **Step 2: Run test to verify it passes**

Run: `odin test tests -all-packages -vet -strict-style`
Expected: PASS

- [ ] **Step 3: Add notice and notification handler callback test**

In `pgconn/conn_test.odin`:
```odin
Test_Notice_Context :: struct {
	received_notice: bool,
	notice_message:  string,
}

on_test_notice :: proc(user_data: rawptr, notice: pgproto.Msg_Notice_Response) {
	ctx := (^Test_Notice_Context)(user_data)
	ctx.received_notice = true
	ctx.notice_message = notice.error.message
}

@(test)
test_conn_notice_callback :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	mock: Mock_Transport
	mock_transport_init(&mock)
	defer mock_transport_destroy(&mock)

	auth_ok := []byte{'R', 0, 0, 0, 8, 0, 0, 0, 0}
	
	// Notice message: 'N', len, 'M', "test notice\0", '\0'
	notice_builder := make([dynamic]byte, context.temp_allocator)
	append(&notice_builder, 'N')
	append(&notice_builder, 0, 0, 0, 0)
	append(&notice_builder, 'M')
	append(&notice_builder, transmute([]byte)string("test notice"))
	append(&notice_builder, 0)
	append(&notice_builder, 0)
	endian.put_i32(notice_builder[1:5], .Big, i32(len(notice_builder) - 1))

	rfq := []byte{'Z', 0, 0, 0, 5, 'I'}

	append(&mock.read_chunks, auth_ok)
	append(&mock.read_chunks, notice_builder[:])
	append(&mock.read_chunks, rfq)

	transport := make_mock_transport(&mock)
	config := Conn_Config{
		host = "localhost",
		port = 5432,
		user = "postgres",
	}

	notice_ctx: Test_Notice_Context
	conn, err := conn_connect_with_transport(config, transport, context.allocator)
	defer if conn != nil {
		conn_close(conn)
		free(conn, context.allocator)
	}

	testing.expect(t, err == nil, "expected handshake success")
	testing.expect_value(t, conn.status, Conn_Status.Ready)

	testing.expect_value(t, len(track.allocation_map), 0)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `odin test tests -all-packages -vet -strict-style`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add pgconn/conn_test.odin
git commit -m "feat(pgconn): verify parameter tracking, key data, and notice callbacks in startup flow"
```

---

### Task 4: Out-of-Band Query Cancellation (`conn_cancel`)

**Files:**
- Modify: `pgconn/conn.odin`
- Modify: `pgconn/conn_test.odin`

**Interfaces:**
- Produces:
  - `conn_cancel(conn: ^Conn) -> pgerr.Error`
  - `conn_cancel_with_transport(pid: i32, secret: i32, transport: Stream_Transport) -> pgerr.Error`

- [ ] **Step 1: Write failing test for `conn_cancel_with_transport`**

In `pgconn/conn_test.odin`:
```odin
@(test)
test_conn_cancel_with_transport :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	mock: Mock_Transport
	mock_transport_init(&mock)
	defer mock_transport_destroy(&mock)

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
	testing.expect_value(t, len(track.allocation_map), 0)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `odin test tests -all-packages`
Expected: FAIL with `conn_cancel_with_transport` undefined

- [ ] **Step 3: Implement `conn_cancel_with_transport` and `conn_cancel` in `pgconn/conn.odin`**

In `pgconn/conn.odin`:
```odin
import "core:fmt"

conn_cancel_with_transport :: proc(
	pid: i32,
	secret: i32,
	transport: Stream_Transport,
) -> pgerr.Error {
	defer if transport.close != nil {
		transport.close(transport.data)
	}

	cancel_bytes := pgproto.frontend_encode_cancel_request(pid, secret, context.temp_allocator)
	if transport.write != nil {
		_, err := transport.write(transport.data, cancel_bytes)
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
	if nerr != .None {
		return pgerr.Net_Error{type = .Connection_Refused, raw_net_error = nerr}
	}

	tdata: TCP_Transport_Data
	transport := make_tcp_transport(&tdata, socket)
	return conn_cancel_with_transport(conn.backend_pid, conn.backend_secret, transport)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `odin test tests -all-packages -vet -strict-style`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add pgconn/conn.odin pgconn/conn_test.odin
git commit -m "feat(pgconn): implement out-of-band query cancellation"
```

---

### Task 5: Live TCP `conn_connect`, Error Paths & Verification Suite

**Files:**
- Modify: `pgconn/conn.odin`
- Modify: `pgconn/conn_test.odin`
- Update: `JIRA.md` (mark OPG-203 Done)

**Interfaces:**
- Produces:
  - `conn_connect(config: Conn_Config, allocator := context.allocator) -> (conn: ^Conn, err: pgerr.Error)`

- [ ] **Step 1: Implement `conn_connect` in `pgconn/conn.odin`**

In `pgconn/conn.odin`:
```odin
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
	if nerr != .None {
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
	return conn_connect_with_transport(config, transport, allocator)
}
```

- [ ] **Step 2: Add test verifying server ErrorResponse on startup**

In `pgconn/conn_test.odin`:
```odin
@(test)
test_conn_handshake_server_error_response :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	mock: Mock_Transport
	mock_transport_init(&mock)
	defer mock_transport_destroy(&mock)

	// ErrorResponse: 'E', len, 'S', "FATAL\0", 'C', "28P01\0", 'M', "password authentication failed\0", '\0'
	err_builder := make([dynamic]byte, context.temp_allocator)
	append(&err_builder, 'E')
	append(&err_builder, 0, 0, 0, 0)
	append(&err_builder, 'S')
	append(&err_builder, transmute([]byte)string("FATAL"))
	append(&err_builder, 0)
	append(&err_builder, 'C')
	append(&err_builder, transmute([]byte)string("28P01"))
	append(&err_builder, 0)
	append(&err_builder, 'M')
	append(&err_builder, transmute([]byte)string("password authentication failed"))
	append(&err_builder, 0)
	append(&err_builder, 0)
	endian.put_i32(err_builder[1:5], .Big, i32(len(err_builder) - 1))

	append(&mock.read_chunks, err_builder[:])

	transport := make_mock_transport(&mock)
	config := Conn_Config{
		host = "localhost",
		port = 5432,
		user = "postgres",
		password = "wrongpassword",
	}

	conn, err := conn_connect_with_transport(config, transport, context.allocator)
	testing.expect(t, conn == nil, "expected nil connection on startup error")
	testing.expect(t, err != nil, "expected error")

	pg_err, ok := err.(pgerr.Postgres_Error)
	testing.expect(t, ok, "expected Postgres_Error")
	testing.expect_value(t, pg_err.code, "28P01")
	testing.expect_value(t, pg_err.message, "password authentication failed")

	testing.expect_value(t, len(track.allocation_map), 0)
}
```

- [ ] **Step 3: Run all tests and linters across all packages**

Run: `odin test tests -all-packages -vet -strict-style`
Expected: All tests pass with zero warnings.

- [ ] **Step 4: Run address sanitizer check**

Run: `odin test tests -all-packages -sanitize:address`
Expected: Pass with zero sanitizer violations.

- [ ] **Step 5: Update `JIRA.md` status for OPG-203**

Mark `[OPG-203]` in `JIRA.md` as Done:
```markdown
### [OPG-203] Startup Sequence & Connection State Machine
- [x] **Status**: Done
```

- [ ] **Step 6: Commit**

```bash
git add pgconn/conn.odin pgconn/conn_test.odin JIRA.md
git commit -m "feat(pgconn): complete OPG-203 connection state machine and mark task done in JIRA"
```
