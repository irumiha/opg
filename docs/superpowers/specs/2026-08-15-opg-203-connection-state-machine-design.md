# Design Document: [OPG-203] Startup Sequence & Connection State Machine

- **Date**: 2026-08-15
- **Task ID**: `OPG-203`
- **Layer**: `pgconn`
- **Package**: `package pgconn`
- **Files**:
  - `pgconn/conn.odin`
  - `pgconn/conn_test.odin`
- **Status**: Approved

---

## 1. Overview & Objectives

`OPG-203` implements the connection lifecycle, startup handshake flow, authentication integration, parameter tracking, out-of-band cancellation, and teardown for `package pgconn`:
1. **Connection Establishment (`conn_connect` & `conn_connect_with_transport`)**: Dials TCP sockets via `core:net` (or accepts a pre-configured `Stream_Transport` for 100% network-independent unit tests).
2. **Startup Protocol 3.0**: Encodes and sends `StartupMessage` with connection configuration parameters (`user`, `database`, `client_encoding = "UTF8"`, `application_name`).
3. **Integrated Auth Loop**: Uses `auth_handle_challenge` from `OPG-202` to negotiate authentication (Cleartext, MD5, SCRAM-SHA-256) across multiple packet rounds.
4. **State Machine Transitions**: Manages transitions across `Disconnected` $\rightarrow$ `Connecting` $\rightarrow$ `Authenticating` $\rightarrow$ `Ready` $\leftrightarrow$ `In_Transaction` / `Busy` $\rightarrow$ `Closed`.
5. **Runtime Metadata Tracking**: Clones and stores server `ParameterStatus` (`server_version`, `client_encoding`, `TimeZone`, etc.) into `conn.parameters` using the persistent connection allocator.
6. **Backend Key Storage & Query Cancellation**: Captures `BackendKeyData` (`backend_pid` and `backend_secret`) and implements out-of-band query cancellation (`conn_cancel`).
7. **Notice & Notification Callbacks**: Routes asynchronous `NoticeResponse` and `NotificationResponse` to optional callbacks without breaking the read loop.
8. **Graceful Teardown (`conn_close`)**: Emits `Terminate ('X')` and frees all persistent connection resources without memory leaks.

---

## 2. Architecture & Data Structures

```odin
package pgconn

import "core:mem"
import "core:net"
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
```

---

## 3. Procedural API Specification

### 3.1 Connection Constructors & Handshake

```odin
// Connects to PostgreSQL over TCP and executes the startup handshake
conn_connect :: proc(
	config: Conn_Config,
	allocator := context.allocator,
) -> (
	conn: ^Conn,
	err: pgerr.Error,
)

// Connects using a pre-configured Stream_Transport (used for 100% network-independent unit tests)
conn_connect_with_transport :: proc(
	config: Conn_Config,
	transport: Stream_Transport,
	allocator := context.allocator,
) -> (
	conn: ^Conn,
	err: pgerr.Error,
)
```

#### Detailed Handshake Semantics:
1. Initialize `conn := new(Conn, allocator)`.
2. Configure `conn.allocator = allocator`, `conn.config = config`, `conn.parameters = make(map[string]string, 16, allocator)`, `conn.status = .Connecting`.
3. If transport not provided, dial `net.dial_tcp` and wrap with `make_tcp_transport(&conn.tcp_data, socket)`.
4. Initialize `Stream_Buffer` via `stream_init(&conn.stream, transport, allocator = allocator)`.
5. Build and send `StartupMessage`:
   - `params := []pgproto.Startup_Param{ {"user", config.user}, {"client_encoding", "UTF8"}, ... }`
   - `stream_write_messages(&conn.stream, startup_bytes)`
   - Set `conn.status = .Authenticating`.
6. Initialize `scram_state: Scram_State` with `scram_state_init(&scram_state, allocator)`.
7. Loop reading backend messages:
   - `Msg_Authentication`: `auth_handle_challenge(&conn.stream, msg, config.user, config.password, &scram_state)`.
   - `Msg_Parameter_Status`: `conn.parameters[strings.clone(msg.name, allocator)] = strings.clone(msg.value, allocator)`.
   - `Msg_Backend_Key_Data`: `conn.backend_pid = msg.process_id`, `conn.backend_secret = msg.secret_key`.
   - `Msg_Notice_Response`: invoke `conn.on_notice(conn.on_notice_data, msg)` if non-nil.
   - `Msg_Notification_Response`: invoke `conn.on_notification(conn.on_notif_data, msg)` if non-nil.
   - `Msg_Ready_For_Query`:
     - `conn.transaction_status = msg.status`
     - `conn.status = .Ready`
     - `conn.last_active = time.now()`
     - `scram_state_destroy(&scram_state)`
     - Handshake complete! Return `conn, nil`.
   - `Msg_Error_Response`:
     - Clean up and return `msg.error` (`pgerr.Postgres_Error`).
   - Any unexpected message: clean up and return `pgerr.Protocol_Error{type = .Unexpected_Message}`.

### 3.2 Cancellation, Teardown & Introspection

```odin
// Gracefully closes connection (sends Terminate 'X', closes transport, frees memory)
conn_close :: proc(conn: ^Conn)

// Checks if connection is alive and in ready/active state
conn_is_alive :: proc(conn: ^Conn) -> bool

// Sends an out-of-band CancelRequest over an ephemeral TCP connection
conn_cancel :: proc(conn: ^Conn) -> pgerr.Error

// Sends an out-of-band CancelRequest over a provided transport (for unit testing)
conn_cancel_with_transport :: proc(
	pid: i32,
	secret: i32,
	transport: Stream_Transport,
) -> pgerr.Error
```

---

## 4. Verification & Test Plan (`pgconn/conn_test.odin`)

1. **Cleartext Auth Handshake Flow**:
   - `StartupMessage` $\rightarrow$ `AuthenticationCleartextPassword` $\rightarrow$ `PasswordMessage` $\rightarrow$ `AuthenticationOk` $\rightarrow$ `ParameterStatus` $\rightarrow$ `BackendKeyData` $\rightarrow$ `ReadyForQuery`.
2. **MD5 Auth Handshake Flow**:
   - `StartupMessage` $\rightarrow$ `AuthenticationMD5Password` $\rightarrow$ `PasswordMessage(md5...)` $\rightarrow$ `AuthenticationOk` $\rightarrow$ `ParameterStatus` $\rightarrow$ `BackendKeyData` $\rightarrow$ `ReadyForQuery`.
3. **SCRAM-SHA-256 Handshake Flow**:
   - Full 4-step SASL handshake using `Mock_Transport`.
4. **Server Error on Startup (e.g. Invalid Credentials / Non-existent Database)**:
   - Server responds with `ErrorResponse` $\rightarrow$ assert `pgerr.Postgres_Error` returned, connection destroyed without leaks.
5. **Parameter Status Tracking**:
   - Verify `server_version`, `client_encoding`, `TimeZone`, `integer_datetimes` stored in `conn.parameters`.
6. **Notice & Notification Handlers**:
   - Verify callback execution upon receiving notice/notification during startup or idle state.
7. **Query Cancellation**:
   - Verify 16-byte `CancelRequest` payload formatting over ephemeral transport.
8. **Graceful Teardown (`conn_close`)**:
   - Verify `Terminate ('X')` sent, map and string memory freed, zero memory leaks via `core:mem.Tracking_Allocator`.
9. **Linters & Tooling**:
   - `odin test tests -all-packages -vet -strict-style`
   - `odin test tests -all-packages -sanitize:address`
