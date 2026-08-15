# JIRA.md – Project Implementation Roadmap

This roadmap breaks down the development of **opg** (Pure-Odin PostgreSQL Driver, Protocol 3.0) layer by layer into actionable, testable tasks.

---

## Roadmap Overview

```
Layer 1: pgproto (Wire Codec & Message Serialization)
  ├── OPG-101: Wire Buffer Reader / Writer & Big-Endian Codec Primitives
  ├── OPG-102: Frontend Wire Messages Encoding (Client -> Server)
  ├── OPG-103: Backend Wire Messages Decoding (Server -> Client)
  └── OPG-104: pgproto Vector Test Suite, Golden Files & Coverage Verification (>=95%)

Layer 2: pgconn (Connection State Machine, Auth, Transport & Pool)
  ├── OPG-201: TCP Socket Stream Buffering & Message Accumulator
  ├── OPG-202: SCRAM-SHA-256 & MD5 Authentication Handshake Engine
  ├── OPG-203: Startup Sequence & Connection State Machine
  ├── OPG-204: Simple & Extended Query Execution Engines
  ├── OPG-205: Dynamic TLS Probing via core:dynlib (Platform OS Probes)
  ├── OPG-206: Thread-Safe Connection Pool (Pool & Conn)
  └── OPG-207: pgconn Integration Tests & Concurrency Verification (TSan / ASan)

Layer 3: pgorm (Reflection Mapper & Type System)
  ├── OPG-301: PostgreSQL Data Types <-> Odin Type Binary/Text Codecs
  ├── OPG-302: Reflection Struct & Slice Mapper (core:reflect)
  ├── OPG-303: Parameter Binding & SQL Execution Helpers
  └── OPG-304: pgorm Reflection Unit Tests & Leak Verification

Layer 4: opg (Public Facade & End-to-End Integration)
  ├── OPG-401: Public Root Driver API & Ergonomic Facade
  └── OPG-402: Full End-to-End Integration, Stress & Coverage Audit (>=95%)

Epic 5: multi-platform (CI Matrix & Native TLS Backends)
  ├── OPG-501: GitHub Actions CI Matrix (Linux / macOS / Windows)
  └── OPG-502: Native TLS Backends via core:dynlib (Schannel & SecureTransport)
```

---

# Epic 1: `pgproto` Wire Codec Layer

> **Goal**: Complete, zero-network, bit-accurate serialization and deserialization of all PostgreSQL Frontend/Backend Protocol 3.0 messages.
> **Package**: `pgproto`
> **Memory Strategy**: `context.temp_allocator` strictly for all transient allocations.

---

### [OPG-101] Wire Buffer Reader / Writer & Big-Endian Codec Primitives
- [x] **Status**: Done
- **Layer**: `pgproto`
- **Files**:
  - `pgproto/buffer.odin`
  - `pgproto/buffer_test.odin`
- **Description**:
  Implement low-level Big-Endian byte reading and writing helpers using `core:encoding/endian`.
- **Requirements & Details**:
  - `read_i16(buf: []byte, offset: ^int) -> (i16, bool)`
  - `read_i32(buf: []byte, offset: ^int) -> (i32, bool)`
  - `read_u32(buf: []byte, offset: ^int) -> (u32, bool)`
  - `read_i64(buf: []byte, offset: ^int) -> (i64, bool)`
  - `read_string_nt(buf: []byte, offset: ^int, allocator := context.temp_allocator) -> (string, bool)` (reads null-terminated C-string)
  - `read_bytes_counted(buf: []byte, offset: ^int, count: int) -> ([]byte, bool)`
  - `write_i16(builder: ^[dynamic]byte, val: i16)`
  - `write_i32(builder: ^[dynamic]byte, val: i32)`
  - `write_string_nt(builder: ^[dynamic]byte, s: string)`
  - `write_bytes(builder: ^[dynamic]byte, b: []byte)`
- **Acceptance Criteria**:
  - All integers parsed/encoded strictly in Network Byte Order (Big-Endian).
  - Out-of-bounds reading returns `ok = false` without panicking.
  - Zero memory leaks using `core:mem.Tracking_Allocator`.
  - 100% test coverage on all reader/writer branches.

---

### [OPG-102] Frontend Wire Messages Encoding (Client $\rightarrow$ Server)
- [x] **Status**: Done
- **Layer**: `pgproto`
- **Files**:
  - `pgproto/frontend.odin`
  - `pgproto/frontend_test.odin`
- **Prerequisites**: `OPG-101`
- **Description**:
  Implement encoding functions that serialize Odin message structs into wire-protocol `[]byte` payloads.
- **Message Types**:
  1. `StartupMessage`: Protocol version (`196608` for 3.0), key-value pairs (`user`, `database`, `client_encoding`, `application_name`, etc.), terminated by final `\0`.
  2. `SSLRequest`: 8-byte fixed packet (`length = 8`, code = `80877103` / `0x04D2162F`).
  3. `PasswordMessage` (`'p'`): Cleartext password / MD5 response / SASL response.
  4. `SASLInitialResponse` (`'p'`): Mechanism name, initial client response with length prefix or `-1`.
  5. `SASLResponse` (`'p'`): Client final message.
  6. `Query` (`'Q'`): Simple SQL query string.
  7. `Parse` (`'P'`): Destination prepared statement name, SQL query string, slice of parameter data type OIDs.
  8. `Bind` (`'B'`): Destination portal name, source prepared statement name, parameter format codes (text/binary), parameter values (length + bytes or -1 for NULL), result-column format codes.
  9. `Describe` (`'D'`): Target type (`'S'` for statement, `'P'` for portal), name string.
  10. `Execute` (`'E'`): Portal name, max row count (`0` = all).
  11. `Sync` (`'S'`): 4-byte length packet (`0x00 0x00 0x00 0x04`).
  12. `Flush` (`'H'`): 4-byte length packet.
  13. `Close` (`'C'`): Target type (`'S'` statement, `'P'` portal), name string.
  14. `Terminate` (`'X'`): 4-byte length packet.
  15. `CancelRequest`: Length 16, code `80877102`, `backend_pid: i32`, `secret_key: i32`.
- **Acceptance Criteria**:
  - Every frontend message generates byte-accurate packets conforming to Protocol 3.0.
  - Length prefixes accurately include their own 4 bytes.
  - Unit tests compare generated bytes against known golden captures.

---

### [OPG-103] Backend Wire Messages Decoding (Server $\rightarrow$ Client)
- [x] **Status**: Done
- **Layer**: `pgproto`
- **Files**:
  - `pgproto/parser.odin`
  - `pgproto/backend.odin`
  - `pgproto/backend_test.odin`
- **Prerequisites**: `OPG-101`
- **Description**:
  Implement comprehensive parsing for all PostgreSQL backend messages from raw `[]byte`.
- **Message Types**:
  1. `Authentication` (`'R'`): Auth types: Ok (0), KerberosV5 (2), CleartextPassword (3), MD5Password (5, salt: [4]byte), SCM (6), GSS (7), GSSContinue (8), SSPI (9), SASL (10, mechanisms: []string), SASLContinue (11, data: string), SASLFinal (12, data: string).
  2. `BackendKeyData` (`'K'`): `process_id: i32`, `secret_key: i32`.
  3. `ParameterStatus` (`'S'`): `name: string`, `value: string`.
  4. `ReadyForQuery` (`'Z'`): `status: Transaction_Status` (`Idle = 'I'`, `In_Transaction = 'T'`, `Failed_Transaction = 'E'`).
  5. `RowDescription` (`'T'`): Field count `i16`, list of fields (`name`, `table_oid`, `column_attr_num`, `type_oid`, `type_size`, `type_modifier`, `format_code`).
  6. `DataRow` (`'D'`): Column count `i16`, array of `Column_Value` (`is_null: bool`, `data: []byte`).
  7. `CommandComplete` (`'C'`): Command tag string (e.g. `"SELECT 10"`, `"INSERT 0 1"`).
  8. `ErrorResponse` (`'E'`): Structured field map (`S`, `V`, `C`, `M`, `D`, `H`, `P`, `p`, `q`, `W`, `s`, `t`, `c`, `d`, `n`, `F`, `L`, `R`) mapped to `opg.Postgres_Error`.
  9. `NoticeResponse` (`'N'`): Same structure as ErrorResponse.
  10. `EmptyQueryResponse` (`'I'`).
  11. `ParseComplete` (`'1'`), `BindComplete` (`'2'`), `CloseComplete` (`'3'`), `NoData` (`'n'`), `PortalSuspended` (`'s'`), `ParameterDescription` (`'t'`).
  12. `NotificationResponse` (`'A'`): `process_id: i32`, `channel: string`, `payload: string`.
  13. `CopyInResponse` (`'G'`), `CopyOutResponse` (`'H'`), `CopyBothResponse` (`'W'`), `CopyData` (`'d'`), `CopyDone` (`'c'`).
- **Acceptance Criteria**:
  - `parse_message(data: []byte, allocator := context.temp_allocator)` correctly parses every message variant.
  - Truncated headers and payloads return `Protocol_Error{type = .Buffer_Underflow}`.
  - Invalid lengths or corrupted headers return `Protocol_Error{type = .Invalid_Length}`.
  - Uses `context.temp_allocator` exclusively.

---

### [OPG-104] `pgproto` Golden Vector Test Suite & Coverage Verification ($\ge 95\%$)
- [x] **Status**: Done
- **Layer**: `pgproto`
- **Files**:
  - `pgproto/tests_golden_files/*.bin`
  - `pgproto/golden_test.odin`
- **Prerequisites**: `OPG-101`, `OPG-102`, `OPG-103`
- **Description**:
  Create a complete test suite verifying every protocol packet against golden binary files and synthetic byte vectors.
- **Acceptance Criteria**:
  - Bit-for-bit validation of serialization and deserialization.
  - Fuzzing / malformed input tests (truncated packets, negative lengths, missing null terminators).
  - Every message variant, every parser error return, and every encoder has an explicit test
    (Odin has no coverage tooling; enumerate, don't estimate).
  - Zero memory leaks verified via `core:mem.Tracking_Allocator`, including parser error paths
    driven with a tracked allocator.

---

# Epic 2: `pgconn` Transport, State Machine & Pool Layer

> **Goal**: Socket I/O over TCP, secure authentication (SCRAM-SHA-256 / MD5), transaction state management, and thread-safe connection pooling.
> **Package**: `pgconn`
> **Memory Strategy**: Persistent allocator (`context.allocator` / dedicated arena) for long-lived socket and pool structures.

---

### [OPG-201] TCP Socket Stream Buffering & Message Accumulator
- [x] **Status**: Done
- **Layer**: `pgconn`
- **Files**:
  - `pgconn/stream.odin`
  - `pgconn/stream_test.odin`
- **Description**:
  Implement the network transport buffer over `core:net.TCP_Socket` to handle TCP fragmentation and message accumulation.
- **Requirements & Details**:
  - `Stream_Buffer`: Dynamic/ring buffer accumulating incoming TCP packets until a complete Postgres message (`1 byte type + 4 byte Big-Endian length`) is fully available.
  - `stream_read_message(conn: ^Conn) -> (msg: pgproto.Backend_Message, err: opg.Error)`
  - `stream_write_messages(conn: ^Conn, msgs: ..[]byte) -> (err: opg.Error)`
  - Handling `core:net` socket timeout, EOF, and disconnection states with mapping to `opg.Net_Error`.
- **Acceptance Criteria**:
  - Handles multi-packet messages and fragmented TCP chunks cleanly.
  - Returns `Net_Error{type = .Socket_Closed}` on graceful EOF and `.Timeout` on read timeouts.

---

### [OPG-202] SCRAM-SHA-256 & MD5 Authentication Handshake Engine
- [x] **Status**: Done
- **Layer**: `pgconn`
- **Files**:
  - `pgconn/auth.odin`
  - `pgconn/auth_scram.odin`
  - `pgconn/auth_test.odin`
- **Prerequisites**: `OPG-102`, `OPG-103`, `OPG-201`
- **Description**:
  Implement PostgreSQL authentication handshakes in pure Odin using `core:crypto` and `core:encoding`.
- **Mechanisms**:
  1. **Cleartext Password**: Sends `PasswordMessage` with plain password string.
  2. **MD5 Authentication**: Computes `concat("md5", hex(md5(concat(hex(md5(password + user)), salt))))` via `core:crypto/legacy/md5`.
  3. **SCRAM-SHA-256 (RFC 5802 / RFC 7677)**:
     - Client generates 24-byte cryptographic random nonce (`core:crypto.rand_bytes` + `core:encoding/base64`).
     - Builds `client-first-message-bare` (`n=,r=...`).
     - Parses `server-first-message` (extracts server nonce, base64 salt, iteration count `i`).
     - Computes PBKDF2 key derivation: `Hi(password, salt, i)` using `core:crypto/pbkdf2` + `core:crypto/hmac` + `core:crypto/sha2`.
     - Calculates `ClientKey`, `StoredKey`, `ClientSignature`, and `ClientProof`.
     - Sends `client-final-message` with `p=...`.
     - Validates `server-final-message` against `ServerSignature` before accepting authentication.
- **Acceptance Criteria**:
  - Matches RFC 5802 / RFC 7677 test vectors.
  - Authenticates successfully against PostgreSQL 14, 15, 16, 17 test instances.
  - Returns `opg.Auth_Error` on mismatched server signatures or bad credentials.

---

### [OPG-203] Startup Sequence & Connection State Machine
- [x] **Status**: Done
- **Layer**: `pgconn`
- **Files**:
  - `pgconn/conn.odin`
  - `pgconn/conn_test.odin`
- **Prerequisites**: `OPG-201`, `OPG-202`
- **Description**:
  Implement full connection initialization, handshake flow, parameter tracking, and connection lifecycle.
- **Flow**:
  1. Connect TCP socket via `core:net.dial_tcp`.
  2. (Optional) Negotiate SSL via `SSLRequest` if enabled.
  3. Send `StartupMessage` with user, database, and client params.
  4. Process `Authentication` messages until `AuthenticationOk`.
  5. Process incoming `ParameterStatus` messages into `conn.parameters` map.
  6. Store `BackendKeyData` (`pid` and `secret_key`) for query cancellation.
  7. Await `ReadyForQuery` message to transition to `Conn_Status.Ready`.
  8. Graceful termination: Send `Terminate ('X')` and close socket.
  9. Query cancellation: `conn_cancel(conn: ^Conn) -> opg.Error`.
- **Acceptance Criteria**:
  - Clean state transitions: `Disconnected` $\rightarrow$ `Connecting` $\rightarrow$ `Authenticating` $\rightarrow$ `Ready`.
  - Storing server parameters (`server_version`, `client_encoding`, `TimeZone`, etc.).

---

### [OPG-204] Simple & Extended Query Execution Engines
- [x] **Status**: Done
- **Layer**: `pgconn`
- **Files**:
  - `pgconn/query.odin`
  - `pgconn/extended.odin`
  - `pgconn/query_test.odin`
- **Prerequisites**: `OPG-203`
- **Description**:
  Implement both PostgreSQL query protocols: Simple Query ('Q') and Extended Query (Parse, Bind, Describe, Execute, Sync).
- **Sub-Features**:
  - **Simple Query**: Sends `Query ('Q')`, collects `RowDescription`, stream of `DataRow` messages, and `CommandComplete` until `ReadyForQuery`.
  - **Extended Query (Prepared Statements & Parameterized Queries)**:
    - Automatic caching of prepared statement names.
    - Parameter format encoding (Text / Binary).
    - Pipelined message dispatch (`P` + `B` + `D` + `E` + `S` sent in a single socket write buffer).
    - Error recovery: On error, server skips to `Sync` and returns `ReadyForQuery(Failed_Transaction)`.
- **Acceptance Criteria**:
  - Supports SQL parameter binding (`$1`, `$2`, etc.) avoiding SQL injection.
  - Pipelining reduces network round-trips to a single round-trip per parameterized execution.

---

### [OPG-205] Dynamic TLS Probing via `core:dynlib` (Milestone Stage)
- [x] **Status**: Done
- **Layer**: `pgconn`
- **Files**:
  - `pgconn/tls.odin`
  - `pgconn/tls_openssl.odin`
  - `pgconn/tls_test.odin`
- **Description**:
  Dynamic runtime probing of installed OpenSSL via `core:dynlib`, with libpq-style `ssl_mode` (`Prefer` default / `Disable` / `Require`) negotiated through SSLRequest before startup. Scope amended 2026-08-15 (see `docs/superpowers/specs/2026-08-15-opg-205-dynamic-tls-design.md`): OpenSSL-only backend, probed per-OS (`libssl.so.3` on Linux, Homebrew/system dylibs on macOS, `libssl-3*.dll` on Windows); native Schannel / SecureTransport backends deferred to a future task — untestable from this environment.
- **Acceptance Criteria**:
  - If no TLS library is present, `ssl_mode = .Require` returns `pgerr.Net_Error{type = .TLS_Handshake_Failed}` gracefully; `.Prefer` falls back to plaintext.
  - When loaded, wraps `core:net.TCP_Socket` in an encrypted TLS read/write stream behind `Stream_Transport`.
  - Integration tests pin the wire state via `pg_stat_ssl` for all three modes; full suite (incl. pool stress) runs over TLS by default, TSan/ASan clean.

---

### [OPG-206] Thread-Safe Connection Pool (`Pool`)
- [x] **Status**: Done
- **Layer**: `pgconn`
- **Files**:
  - `pgconn/pool.odin`
  - `pgconn/pool_test.odin`
- **Prerequisites**: `OPG-203`, `OPG-204`
- **Description**:
  Implement a production-grade, thread-safe PostgreSQL connection pool.
- **Features**:
  - Thread safety using `sync.Mutex` and `sync.Cond`.
  - `pool_init(config: Pool_Config, allocator := context.allocator) -> (^Pool, opg.Error)`
  - `pool_acquire(pool: ^Pool, timeout := time.Duration(0)) -> (^Conn, opg.Error)`
  - `pool_release(pool: ^Pool, conn: ^Conn) -> opg.Error`
  - `pool_destroy(pool: ^Pool)`
  - Health check & auto-reconnect on dropped sockets.
  - Max connection limits and connection queueing.
- **Acceptance Criteria**:
  - Passes concurrent acquisition and release stress tests across 50+ threads without deadlocks or race conditions.
  - Zero memory leaks upon pool destruction.

---

### [OPG-207] `pgconn` Integration Tests & Concurrency Verification
- [x] **Status**: Done
- **Layer**: `pgconn`
- **Files**:
  - `pgconn/integration_test.odin`
- **Prerequisites**: `OPG-201` through `OPG-206`
- **Description**:
  Run full integration test suite against live PostgreSQL instances (`PGHOST`, `PGPORT`, `PGUSER`, `PGPASSWORD`, `PGDATABASE`).
- **Acceptance Criteria**:
  - `odin test pgconn` passes all unit and integration tests.
  - `odin test pgconn -sanitize:thread` reports zero data races (also verified with `-sanitize:address`).
  - Coverage: manual audit (`docs/pgconn-coverage-audit.md`) — Odin has no coverage instrumentation; every public proc and error path is mapped to a covering test.

---

# Epic 3: `pgorm` Data Mapping & Reflection Layer

> **Goal**: High-level reflection mapper translating Postgres `DataRow` messages directly into user-defined Odin structs and native types with zero heap leaks.
> **Package**: `pgorm`
> **Memory Strategy**: `context.temp_allocator` strictly for all parsed strings, slices, and mapped structs.

---

### [OPG-301] PostgreSQL Data Types $\leftrightarrow$ Odin Type Binary/Text Codecs
- [x] **Status**: Done
- **Layer**: `pgorm`
- **Files**:
  - `pgorm/types.odin`
  - `pgorm/codecs.odin`
  - `pgorm/codecs_test.odin`
- **Description**:
  Implement decoders and encoders for standard PostgreSQL OIDs in both text and binary formats.
- **Supported Types**:
  - `INT2` (i16), `INT4` (i32), `INT8` (i64)
  - `FLOAT4` (f32), `FLOAT8` (f64), `NUMERIC`
  - `VARCHAR`, `TEXT`, `BPCHAR`, `NAME` (string)
  - `BOOL` (bool)
  - `BYTEA` ([]byte)
  - `DATE`, `TIME`, `TIMESTAMP`, `TIMESTAMPTZ` (`time.Time`)
  - `UUID` ([16]byte / string)
  - `JSON`, `JSONB` (string)
  - Arrays (`[]i32`, `[]string`, etc.)
- **Acceptance Criteria**:
  - Correct parsing for text representations and big-endian binary representations.
  - Correct handling of NULL values.

---

### [OPG-302] Reflection Struct & Slice Mapper (`core:reflect`)
- [x] **Status**: Done
- **Layer**: `pgorm`
- **Files**:
  - `pgorm/mapper.odin`
  - `pgorm/mapper_test.odin`
- **Prerequisites**: `OPG-301`
- **Description**:
  Implement generic reflection-based row-to-struct and rows-to-slice decoders.
- **Procedures**:
  - `map_row_to_struct($T: typeid, desc: pgproto.Msg_Row_Description, row: pgproto.Msg_Data_Row, allocator := context.temp_allocator) -> (result: T, err: opg.Error)`
  - `map_rows_to_slice($T: typeid, desc: pgproto.Msg_Row_Description, rows: []pgproto.Msg_Data_Row, allocator := context.temp_allocator) -> (result: []T, err: opg.Error)`
- **Features**:
  - Struct tag matching: `db:"column_name"`.
  - Case-insensitive field name fallback.
  - Support for `Maybe(T)` / nullable pointer fields.
  - Nested structs.
- **Acceptance Criteria**:
  - Maps synthetic and live `DataRow` messages to complex user structs accurately.
  - All allocated fields (strings, dynamic slices) use `context.temp_allocator`.
  - Zero memory leaks.

---

### [OPG-303] Parameter Binding & SQL Execution Helpers
- [x] **Status**: Done
- **Layer**: `pgorm`
- **Files**:
  - `pgorm/exec.odin`
  - `pgorm/exec_test.odin`
- **Prerequisites**: `OPG-301`, `OPG-302`, `OPG-204`
- **Description**:
  Provide ergonomic query and execution helper procedures.
- **API**:
  - `query_struct(conn: ^pgconn.Conn, $T: typeid, sql: string, args: ..any, allocator := context.temp_allocator) -> (T, opg.Error)`
  - `query_slice(conn: ^pgconn.Conn, $T: typeid, sql: string, args: ..any, allocator := context.temp_allocator) -> ([]T, opg.Error)`
  - `exec(conn: ^pgconn.Conn, sql: string, args: ..any) -> (rows_affected: int, err: opg.Error)`
- **Acceptance Criteria**:
  - Ergonomic caller syntax.
  - Automatically handles Extended Query protocol under the hood.

---

### [OPG-304] `pgorm` Reflection Unit Tests & Leak Verification
- [x] **Status**: Done
- **Layer**: `pgorm`
- **Files**:
  - `pgorm/mapper_test.odin`
- **Prerequisites**: `OPG-301` through `OPG-303`
- **Description**:
  Comprehensive unit tests verifying reflection mapping over all edge cases.
- **Acceptance Criteria**:
  - Tests covering nullable fields, mismatched column counts, unsupported type conversions, nested structs.
  - Line and branch coverage $\ge 95\%$.
  - Zero memory leaks using `core:mem.Tracking_Allocator`.

---

# Epic 4: `opg` Public Driver Facade & End-to-End Auditing

> **Goal**: Unified developer-facing API, documentation, stress testing, and final quality audit.
> **Package**: `opg`

---

### [OPG-401] Public Root Driver API & Ergonomic Facade
- [ ] **Status**: Open
- **Layer**: `opg`
- **Files**:
  - `root.odin`
  - `transaction.odin`
- **Prerequisites**: Epics 1, 2, 3
- **Description**:
  Unify `pgproto`, `pgconn`, and `pgorm` under the clean public facade `package opg`.
- **Features**:
  - `connect(config: Config) -> (^Conn, Error)`
  - `pool_create(config: Pool_Config) -> (^Pool, Error)`
  - Transaction helpers: `begin_transaction(conn: ^Conn) -> (^Tx, Error)`, `tx_commit(tx: ^Tx)`, `tx_rollback(tx: ^Tx)`
- **Acceptance Criteria**:
  - Clean root API without leaking internal wire packet mechanics to consumers.

---

### [OPG-402] Full End-to-End Integration, Stress & Coverage Audit ($\ge 95\%$)
- [ ] **Status**: Open
- **Layer**: Whole Project
- **Files**:
  - `tests/e2e_test.odin`
- **Prerequisites**: `OPG-401`
- **Description**:
  Full integration and stress test suite validating the entire driver against PostgreSQL under load.
- **Acceptance Criteria**:
  - High concurrency stress test (100 concurrent workers querying pool).
  - Large dataset streaming test (querying 100k+ rows without memory explosion).
  - Verification: `odin test tests -all-packages -vet -strict-style` passes (run from the repo root).
  - Verification: `odin test tests -all-packages -sanitize:address` passes.
  - Final audit: every message variant, error path, and public procedure has an explicit test
    (Odin has no coverage tooling; enumerate, don't estimate).

---

# Epic 5: multi-platform (CI Matrix & Native TLS Backends)

> **Goal**: Prove the driver builds, passes tests, and speaks TLS on Linux, macOS, and Windows — native OS TLS libraries first, OpenSSL as fallback.
> **Layer**: Infrastructure + `pgconn`
> **Ordering**: Independent of Epics 3–4; can proceed in parallel. OPG-502 requires OPG-501's runners to exist first — untestable platform code is not shipped (see the OPG-205 scope decision this epic lifts).

---

### [OPG-501] GitHub Actions CI Matrix (Linux / macOS / Windows)
- [ ] **Status**: Open
- **Layer**: Infrastructure
- **Files**:
  - `.github/workflows/ci.yml`
- **Prerequisites**: none (current `main`)
- **Description**:
  Set up a GitHub Actions workflow with a three-OS runner matrix (`ubuntu-latest`, `macos-latest`, `windows-latest`). Every job installs the pinned Odin nightly for its platform and runs the offline gate; the Linux job additionally runs the full dockerized integration suite and sanitizers. This is the first time the tree compiles anywhere but Linux — portability fixes surfaced by the macOS/Windows compiles (e.g. `core:net` / `core:os` differences) are **in scope** for this task.
- **Features**:
  - Trigger on push and pull_request to `main`.
  - Pinned Odin nightly per OS (document the pin; bumping it is a one-line change).
  - All three OSes: `odin test tests -all-packages -vet -strict-style`.
  - Linux job: `scripts/integration-test.sh` (docker compose harness), plus `odin test pgconn -define:OPG_INTEGRATION=true -sanitize:thread` and `-sanitize:address`.
  - macOS/Windows integration testing intentionally deferred to OPG-502, which provisions runner-local PostgreSQL anyway (the harness's `PGHOST` override — which skips docker entirely — was built for exactly this).
- **Acceptance Criteria**:
  - Workflow green on all three OSes for the offline gate.
  - Linux job green on integration + TSan + ASan.
  - A failing test on any OS fails the workflow (no `continue-on-error` masking).

---

### [OPG-502] Native TLS Backends via `core:dynlib` (Schannel & SecureTransport)
- [ ] **Status**: Open
- **Layer**: `pgconn`
- **Files**:
  - `pgconn/tls.odin` (backend-selection refactor)
  - `pgconn/tls_windows.odin` (Schannel via `secur32.dll` / `sspicli.dll`)
  - `pgconn/tls_darwin.odin` (SecureTransport via `Security.framework`)
  - `.github/workflows/ci.yml` (macOS/Windows integration jobs)
- **Prerequisites**: `OPG-501`, `OPG-205`
- **Description**:
  Implement and test the native OS TLS backends deferred from OPG-205. Refactor the probe into a backend-selection architecture: probing returns a `TLS_Backend` (name + `wrap(socket, server_name) -> (Stream_Transport, Error)`), tried in per-OS priority order — **Windows**: Schannel (SSPI: `AcquireCredentialsHandle` / `InitializeSecurityContext` / `EncryptMessage` / `DecryptMessage`), fallback OpenSSL; **macOS**: SecureTransport (`SSLCreateContext` / `SSLSetIOFuncs` / `SSLHandshake` / `SSLRead` / `SSLWrite` — deprecated by Apple but the only dlopen-able C API that wraps a raw fd; Network.framework is not viable for this), fallback OpenSSL; **Linux**: OpenSSL (unchanged). Expose the selected backend name so tests can pin which library actually performed the handshake.
- **Features**:
  - CI provisions runner-local TLS-enabled PostgreSQL on macOS (Homebrew) and Windows (runner-image service), reusing the auth-scenario and ssl setup from `scripts/pg-init/` in native form; integration tests target it via the `PGHOST`/`PGPORT`/... overrides.
  - Backend-order unit tests with injected probe lists: native missing → OpenSSL fallback; all missing → graceful `TLS_Handshake_Failed` under `require`, plaintext under `prefer`.
- **Acceptance Criteria**:
  - `windows-latest`: TLS integration tests pass with the **Schannel** backend selected (asserted via backend name, not inferred — the runner may also carry an OpenSSL DLL).
  - `macos-latest`: TLS integration tests pass with the **SecureTransport** backend selected.
  - `ubuntu-latest`: OpenSSL backend still selected; full suite stays green.
  - `pg_stat_ssl` pins `ssl = t` for `require` mode on all three OSes.
  - Backend fallback ordering covered by unit tests; graceful-absence semantics from OPG-205 preserved.
