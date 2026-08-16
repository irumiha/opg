# Design Document: Epic 2 (`pgconn`) Transport, State Machine & Pool Layer

- **Date**: 2026-08-15
- **Layer**: `pgconn` (Layer 2)
- **Package**: `package pgconn`
- **Status**: Approved

---

## 1. Overview & Objectives

Epic 2 implements the transport, connection lifecycle, authentication, protocol execution, and connection pooling layer (`pgconn`). It bridges the wire codec layer (`pgproto`) with the reflection and high-level mapping layer (`pgmap`).

### Key Goals:
1. **Network Stream Buffering & Framing (`OPG-201`)**: Defragment TCP streams over `core:net.TCP_Socket` and frame PostgreSQL 3.0 backend packets without data corruption.
2. **Pluggable Stream Transport**: Abstract socket I/O behind a clean procedural interface (`Stream_Transport`) so plain TCP works immediately and dynamic TLS (`OPG-205`) can be plugged in seamlessly later.
3. **Pure-Odin Authentication (`OPG-202`)**: Implement SCRAM-SHA-256 (RFC 5802/7677) and MD5 authentication using `core:crypto` and `core:encoding`.
4. **State Machine & Lifecycle (`OPG-203`)**: Manage the full connection lifecycle (`Connecting` -> `Authenticating` -> `Ready` <-> `In_Transaction` -> `Closed`), parameter tracking, and out-of-band query cancellation.
5. **Streaming Query & Pipeline Engine (`OPG-204`)**: Implement both Simple Query (`'Q'`) and Extended Query (`Parse`, `Bind`, `Describe`, `Execute`, `Sync`) with callback-based row streaming and pipelining support.
6. **Thread-Safe Connection Pool (`OPG-206`)**: Concurrency-safe pooling with `sync.Mutex` and `sync.Cond`, pre-warming, timeouts, and automatic connection cleanup on release.
7. **Dynamic TLS Probing (`OPG-205`)**: Deferred until unencrypted live connections and query pipelines are verified.

---

## 2. Layer Boundaries & Memory Strategy

```
┌─────────────────────────────────────────────────────────────┐
│                    pgmap / Public Facade                    │
└───────────────▲─────────────────────────────┬───────────────┘
                │ Row & Result Stream         │ Queries & Commands
┌───────────────┴─────────────────────────────▼───────────────┐
│                           pgconn                            │
│  ┌──────────────────┐  ┌────────────────┐  ┌─────────────┐  │
│  │ Connection Pool  │  │  Query Engine  │  │    State    │  │
│  │ (Pool & Concurrency)│ (Simple/Extended)││   Machine   │  │
│  └────────┬─────────┘  └───────┬────────┘  └──────┬──────┘  │
│           │                    │                  │         │
│           └────────────────────┼──────────────────┘         │
│                                ▼                            │
│                  ┌──────────────────────────┐               │
│                  │ Stream Buffer & Codec I/O│               │
│                  └─────────────┬────────────┘               │
└────────────────────────────────┼────────────────────────────┘
                                 ▼
                     TCP Socket / Dynamic TLS
```

### Allocator Principles:
- **Persistent Allocations**: `Conn`, `Stream`, `Pool`, and long-lived server parameter strings use the caller's persistent allocator (`context.allocator` or dedicated pool arena).
- **Transient Message Parsing**: All `pgproto.parse_message` invocations pass `allocator := context.temp_allocator`.
- **Zero-Copy Borrowing**: Callback handlers receive zero-copy borrowed slices from `pgproto.Msg_Data_Row`. If a caller needs data to outlive the callback, they must explicitly clone it.

---

## 3. Subsystem Specifications

### 3.1 Transport & Stream Accumulator (`pgconn/stream.odin` - `OPG-201`)

#### Transport Interface:
```odin
Stream_Transport :: struct {
	data:  rawptr,
	read:  proc(transport: rawptr, buf: []byte) -> (bytes_read: int, err: pgerr.Error),
	write: proc(transport: rawptr, data: []byte) -> (bytes_written: int, err: pgerr.Error),
	close: proc(transport: rawptr),
}
```

#### Stream Buffer:
```odin
Stream_Buffer :: struct {
	transport:    Stream_Transport,
	buf:          [dynamic]byte,
	read_offset:  int,
	write_offset: int,
	allocator:    mem.Allocator,
}

stream_init(s: ^Stream_Buffer, transport: Stream_Transport, initial_capacity := 8192, allocator := context.allocator)
stream_destroy(s: ^Stream_Buffer)
stream_read_message(s: ^Stream_Buffer, temp_allocator := context.temp_allocator) -> (msg: pgproto.Backend_Message, err: pgerr.Error)
stream_write_messages(s: ^Stream_Buffer, msgs: ..[]byte) -> (err: pgerr.Error)
stream_flush(s: ^Stream_Buffer) -> (err: pgerr.Error)
```

#### Framing Logic:
1. Peek 5 bytes: 1-byte message type + 4-byte big-endian length.
2. If available bytes < (1 + length), read from `transport.read` into buffer until full message is present.
3. Pass exact packet slice to `pgproto.parse_message(slice, allocator = temp_allocator)`.
4. Advance `read_offset`. When unread bytes become small or offset reaches threshold, compact/shift buffer.

---

### 3.2 Authentication Engine (`pgconn/auth.odin`, `pgconn/auth_scram.odin` - `OPG-202`)

1. **Cleartext Password**: Sends `pgproto.frontend_encode_password_message(password)`.
2. **MD5 Password**:
   - `hash1 = hex(md5(password + user))`
   - `hash2 = hex(md5(hash1 + salt[0:4]))`
   - `response = "md5" + hash2`
3. **SCRAM-SHA-256 (RFC 5802 / RFC 7677)**:
   - Client sends initial nonce: `n,,n=,r=<client_nonce>`.
   - Parses server challenge: extracts server nonce `r=...`, salt `s=...`, iterations `i=...`.
   - Computes:
     - `SaltedPassword = PBKDF2-HMAC-SHA256(password, salt, i)`
     - `ClientKey = HMAC-SHA256(SaltedPassword, "Client Key")`
     - `StoredKey = SHA256(ClientKey)`
     - `AuthMessage = client_first_bare + "," + server_first + "," + client_final_without_proof`
     - `ClientSignature = HMAC-SHA256(StoredKey, AuthMessage)`
     - `ClientProof = ClientKey XOR ClientSignature`
     - `ServerKey = HMAC-SHA256(SaltedPassword, "Server Key")`
     - `ExpectedServerSignature = HMAC-SHA256(ServerKey, AuthMessage)`
   - Sends `c=biws,r=<combined_nonce>,p=<base64(ClientProof)>`.
   - Verifies `AuthenticationSASLFinal` against `ExpectedServerSignature`.

---

### 3.3 Connection State Machine & Lifecycle (`pgconn/conn.odin` - `OPG-203`)

#### Connection Struct:
```odin
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
	host:               string,
	port:               int,
	user:               string,
	password:           string,
	database:           string,
	application_name:   string,
	connect_timeout:    time.Duration,
	read_timeout:       time.Duration,
	write_timeout:      time.Duration,
}

Notice_Handler :: #type proc(user_data: rawptr, notice: pgproto.Msg_Notice_Response)
Notification_Handler :: #type proc(user_data: rawptr, notification: pgproto.Msg_Notification_Response)

Conn :: struct {
	stream:             Stream_Buffer,
	status:             Conn_Status,
	config:             Conn_Config,
	backend_pid:        i32,
	backend_secret:     i32,
	parameters:         map[string]string,
	allocator:          mem.Allocator,
	last_active:        time.Time,
	on_notice:          Notice_Handler,
	on_notice_data:     rawptr,
	on_notification:    Notification_Handler,
	on_notif_data:      rawptr,
}
```

#### Lifecycle Procedures:
- `conn_connect(config: Conn_Config, allocator := context.allocator) -> (conn: ^Conn, err: pgerr.Error)`
- `conn_close(conn: ^Conn)`
- `conn_cancel(conn: ^Conn) -> pgerr.Error` (dials ephemeral socket to deliver `CancelRequest`)
- `conn_is_alive(conn: ^Conn) -> bool`

---

### 3.4 Query & Pipeline Engines (`pgconn/query.odin`, `pgconn/extended.odin` - `OPG-204`)

#### Callbacks:
```odin
Row_Handler :: #type proc(user_data: rawptr, desc: pgproto.Msg_Row_Description, row: pgproto.Msg_Data_Row) -> (proceed: bool, err: pgerr.Error)
Command_Handler :: #type proc(user_data: rawptr, tag: string) -> (proceed: bool, err: pgerr.Error)
```

#### Simple Query Protocol:
- `conn_query_simple(conn: ^Conn, sql: string, on_row: Row_Handler, on_command: Command_Handler, user_data: rawptr = nil) -> pgerr.Error`

#### Extended Query Protocol & Pipelining:
- `conn_prepare(conn: ^Conn, name: string, sql: string, param_oids: []u32) -> pgerr.Error`
- `conn_exec_prepared(conn: ^Conn, name: string, params: []pgproto.Parameter_Value, param_formats: []pgproto.Format_Code, result_formats: []pgproto.Format_Code, on_row: Row_Handler, on_command: Command_Handler, user_data: rawptr = nil) -> pgerr.Error`
- `conn_close_prepared(conn: ^Conn, name: string) -> pgerr.Error`
- `conn_query_extended(conn: ^Conn, sql: string, params: []pgproto.Parameter_Value, on_row: Row_Handler, on_command: Command_Handler, user_data: rawptr = nil) -> pgerr.Error` (Uses unnamed statement `""` for single round-trip pipelined dispatch).

---

### 3.5 Thread-Safe Connection Pool (`pgconn/pool.odin` - `OPG-206`)

```odin
Pool_Config :: struct {
	conn_config:        Conn_Config,
	min_conns:          int,
	max_conns:          int,
	idle_timeout:       time.Duration,
	acquire_timeout:    time.Duration,
}

Pool :: struct {
	mutex:              sync.Mutex,
	cond:               sync.Cond,
	config:             Pool_Config,
	allocator:          mem.Allocator,
	available:          [dynamic]^Conn,
	in_use:             [dynamic]^Conn,
	is_closed:          bool,
}

pool_init(config: Pool_Config, allocator := context.allocator) -> (pool: ^Pool, err: pgerr.Error)
pool_acquire(pool: ^Pool, timeout := time.Duration(0)) -> (conn: ^Conn, err: pgerr.Error)
pool_release(pool: ^Pool, conn: ^Conn) -> (err: pgerr.Error)
pool_destroy(pool: ^Pool)
```

#### Pool Invariants:
- On `pool_release`, if `conn.status != .Ready`, pool issues `ROLLBACK` / `SYNC`. If reset fails or socket is broken, it is closed and destroyed.
- Concurrency safety verified with `-sanitize:thread`.

---

## 4. Implementation Task Breakdown

1. **OPG-201**: TCP Socket Stream Buffering & Message Accumulator (`pgconn/stream.odin`, `pgconn/stream_test.odin`)
2. **OPG-202**: SCRAM-SHA-256 & MD5 Authentication Handshake Engine (`pgconn/auth.odin`, `pgconn/auth_scram.odin`, `pgconn/auth_test.odin`)
3. **OPG-203**: Startup Sequence & Connection State Machine (`pgconn/conn.odin`, `pgconn/conn_test.odin`)
4. **OPG-204**: Simple & Extended Query Execution Engines & Pipelining (`pgconn/query.odin`, `pgconn/extended.odin`, `pgconn/query_test.odin`)
5. **OPG-206**: Thread-Safe Connection Pool (`pgconn/pool.odin`, `pgconn/pool_test.odin`)
6. **OPG-207**: Integration Tests & Concurrency Verification (`pgconn/integration_test.odin`)
7. **OPG-205**: Dynamic TLS Probing via `core:dynlib` (Milestone Stage - deferred until live unencrypted connections pass all tests)
