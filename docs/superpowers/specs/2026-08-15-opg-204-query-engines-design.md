# Design Document: [OPG-204] Simple & Extended Query Execution Engines

- **Date**: 2026-08-15
- **Task ID**: `OPG-204`
- **Layer**: `pgconn`
- **Package**: `package pgconn`
- **Files**:
  - `pgconn/query.odin`
  - `pgconn/extended.odin`
  - `pgconn/query_test.odin`
- **Status**: Approved

---

## 1. Overview & Objectives

`OPG-204` implements both the **Simple Query** and **Extended Query** protocol engines for `package pgconn`:
1. **Simple Query Protocol (`'Q'`)**:
   - `conn_query(conn, sql, on_row, on_command, on_desc, user_data)` executes SQL strings directly.
   - Dispatches `RowDescription`, `DataRow`, `CommandComplete`, `EmptyQueryResponse`, `NoticeResponse`, `NotificationResponse`.
2. **Extended Query Protocol (`Parse` $\rightarrow$ `Bind` $\rightarrow$ `Describe` $\rightarrow$ `Execute` $\rightarrow$ `Sync` / `Flush`)**:
   - `conn_exec_params`: Executes ad-hoc parameterized queries using the unnamed statement (`""`) and unnamed portal (`""`) with a single pipeline flush.
   - `conn_prepare`: Explicitly prepares named statements (`Parse` + `Sync`) and caches metadata.
   - `conn_exec_prepared`: Executes named prepared statements with bound parameters.
   - `conn_close_statement` & `conn_close_portal`: Deallocates server-side statement/portal resources (`Close` + `Sync`).
3. **Pipelining & Multi-Write Support**:
   - Outbound commands are batched into single network writes via `stream_write_messages`.
4. **Resilient Error Synchronization (`pgx` / `asyncpg` Pattern)**:
   - When an `ErrorResponse ('E')` is encountered mid-stream, the error is captured and reading continues until `ReadyForQuery ('Z')` is processed to synchronize the connection state before returning `pgerr.Postgres_Error`.
5. **Zero-Copy Row Streaming**:
   - `Msg_Data_Row` borrows directly from the `Stream_Buffer` slice during callback execution.

---

## 2. Architecture & Data Structures

```odin
package pgconn

import "core:mem"
import "core:time"
import "../pgerr"
import "../pgproto"

// Invoked when a RowDescription message is received
Row_Desc_Callback :: #type proc(user_data: rawptr, desc: pgproto.Msg_Row_Description)

// Invoked for each DataRow received. Returning false terminates row streaming.
Row_Callback :: #type proc(user_data: rawptr, row: pgproto.Msg_Data_Row) -> (proceed: bool)

// Invoked when CommandComplete is received with command tag and rows affected count
Command_Callback :: #type proc(user_data: rawptr, tag: string, rows_affected: i64)

Prepared_Statement :: struct {
	name:       string,
	query:      string,
	param_oids: []u32,
}
```

---

## 3. Procedural API Specification

### 3.1 Simple Query Protocol (`pgconn/query.odin`)

```odin
// Executes a simple SQL string, streaming rows and command tags to callbacks
conn_query :: proc(
	conn: ^Conn,
	sql: string,
	on_row: Row_Callback = nil,
	on_command: Command_Callback = nil,
	on_desc: Row_Desc_Callback = nil,
	user_data: rawptr = nil,
) -> pgerr.Error
```

#### Detailed Execution Flow:
1. Verify `conn_is_alive(conn)`. If closed/invalid, return `pgerr.Net_Error{type = .Socket_Closed}`.
2. Mark `conn.status = .Busy`.
3. Encode `Msg_Query` using `pgproto.frontend_encode_query(sql, temp_allocator)`.
4. Write message via `stream_write_messages(&conn.stream, query_bytes)`.
5. Loop reading backend messages:
   - `Msg_Row_Description`: Call `on_desc(user_data, m)` if set.
   - `Msg_Data_Row`: If no prior error occurred and streaming not aborted, call `on_row(user_data, m)`. If `on_row` returns `false`, stop invoking further row callbacks for this query.
   - `Msg_Command_Complete`: Call `on_command(user_data, m.tag, m.rows_affected)` if set.
   - `Msg_Empty_Query_Response`: Ignore/continue.
   - `Msg_Notice_Response`: Invoke `conn.on_notice` if set.
   - `Msg_Notification_Response`: Invoke `conn.on_notification` if set.
   - `Msg_Error_Response`: Capture cloned `pgerr.Postgres_Error` into `recorded_err`.
   - `Msg_Ready_For_Query`:
     - Update `conn.transaction_status = m.status`.
     - Update `conn.status`: `.Idle` $\rightarrow$ `.Ready`, `.In_Transaction` $\rightarrow$ `.In_Transaction`, `.Failed_Transaction` $\rightarrow$ `.Failed_Transaction`.
     - Update `conn.last_active = time.now()`.
     - Return `recorded_err` (or `nil` if successful).
   - Any fatal socket error (`Net_Error`) or wire corruption (`Protocol_Error`): mark `conn.status = .Closed` and return error immediately.

---

### 3.2 Extended Query Protocol (`pgconn/extended.odin`)

```odin
// Prepares a named statement: sends Parse + Sync, awaits ParseComplete + ReadyForQuery
conn_prepare :: proc(
	conn: ^Conn,
	name: string,
	query: string,
	param_oids: []u32 = nil,
) -> pgerr.Error

// Executes an ad-hoc query with parameters using unnamed statement & portal
conn_exec_params :: proc(
	conn: ^Conn,
	query: string,
	params: []pgproto.Bind_Param,
	on_row: Row_Callback = nil,
	on_command: Command_Callback = nil,
	on_desc: Row_Desc_Callback = nil,
	user_data: rawptr = nil,
) -> pgerr.Error

// Executes a previously prepared named statement
conn_exec_prepared :: proc(
	conn: ^Conn,
	name: string,
	params: []pgproto.Bind_Param,
	on_row: Row_Callback = nil,
	on_command: Command_Callback = nil,
	on_desc: Row_Desc_Callback = nil,
	user_data: rawptr = nil,
) -> pgerr.Error

// Closes a statement or portal on the server
conn_close_statement :: proc(conn: ^Conn, name: string) -> pgerr.Error
conn_close_portal :: proc(conn: ^Conn, name: string) -> pgerr.Error
```

#### Detailed Extended Execution Flow (`conn_exec_params`):
1. Verify `conn_is_alive(conn)`.
2. Mark `conn.status = .Busy`.
3. Build batched pipeline:
   - `Parse`: `statement_name = ""`, `query = query`, `param_oids = nil`
   - `Bind`: `portal_name = ""`, `statement_name = ""`, `params = params`
   - `Describe`: `target_type = .Portal`, `name = ""`
   - `Execute`: `portal_name = ""`, `max_rows = 0`
   - `Sync`
4. Flush all 5 messages in a single multi-write call via `stream_write_messages`.
5. Read responses:
   - `Msg_Parse_Complete`, `Msg_Bind_Complete`: Process confirmation.
   - `Msg_Row_Description` / `Msg_No_Data`: Process descriptor.
   - `Msg_Data_Row`: Stream to `on_row`.
   - `Msg_Command_Complete`: Stream to `on_command`.
   - `Msg_Error_Response`: Capture `Postgres_Error` and drain remaining pipeline responses.
   - `Msg_Ready_For_Query`: Synchronize transaction/connection status and return `recorded_err`.

---

## 4. Verification & Test Plan (`pgconn/query_test.odin`)

1. **Simple Query Happy Path**:
   - `Query` $\rightarrow$ `RowDescription` + multiple `DataRow` + `CommandComplete` (`SELECT 2`) + `ReadyForQuery`.
   - Verify column names, row string views, rows affected.
2. **Simple Query Error Handling & Drain**:
   - `Query` $\rightarrow$ `ErrorResponse` (`42P01` table does not exist) + `ReadyForQuery`.
   - Verify error returned, connection status updated to `.Ready` (or `.Failed_Transaction`), no socket corruption.
3. **Empty Query Response**:
   - `Query("")` $\rightarrow$ `EmptyQueryResponse` + `ReadyForQuery`.
4. **Parameterized Extended Query (`conn_exec_params`)**:
   - Verify 5-message pipeline serialization (`Parse`, `Bind`, `Describe`, `Execute`, `Sync`).
   - Verify parameter formats (text/binary) and NULL parameter handling.
5. **Named Prepared Statements (`conn_prepare` $\rightarrow$ `conn_exec_prepared` $\rightarrow$ `conn_close_statement`)**:
   - Verify preparation, execution, and deallocation lifecycle.
6. **Notice & Notification Routing During Query**:
   - Verify asynchronous notices interleaved with data rows do not interrupt the data stream.
7. **Early Abort**:
   - `on_row` returning `false` stops further callback invocations while safely draining the remainder of the result stream.
8. **Memory Safety & Leaks**:
   - Verified with `core:mem.Tracking_Allocator` (zero memory leaks across all test runs).
9. **Linters & Tooling**:
   - `odin test tests -all-packages -vet -strict-style`
   - `odin test tests -all-packages -sanitize:address`
