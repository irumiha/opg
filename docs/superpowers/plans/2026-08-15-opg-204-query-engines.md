# [OPG-204] Simple & Extended Query Execution Engines Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement both Simple Query (`'Q'`) and Extended Query (`Parse` $\rightarrow$ `Bind` $\rightarrow$ `Describe` $\rightarrow$ `Execute` $\rightarrow$ `Sync` / `Flush`) protocol engines with streaming callbacks, zero-copy row borrowing, prepared statement caching, and `pgx`/`asyncpg`-style error stream draining.

**Architecture:** `conn_query` in `pgconn/query.odin` handles simple SQL execution. `conn_exec_params`, `conn_prepare`, `conn_exec_prepared`, `conn_close_statement`, and `conn_close_portal` in `pgconn/extended.odin` handle extended query pipelining and prepared statements. Both engines route notices/notifications, update transaction status on `ReadyForQuery`, and drain errors cleanly.

**Tech Stack:** Odin, `pgproto`, `pgerr`, `core:time`, `core:strings`, `core:mem`.

**Spec:** [`docs/superpowers/specs/2026-08-15-opg-204-query-engines-design.md`](file:///home/igorrumiha/Projects/odin-projects/opg/docs/superpowers/specs/2026-08-15-opg-204-query-engines-design.md)

## Global Constraints

- Never do what was not specifically asked for.
- All errors must return `pgerr.Error` (tagged union). Subpackages import `pgerr` — never `root.odin`.
- All transient packet parsing and encoding use `allocator := context.temp_allocator`.
- Multi-byte integers must be read/written in Network Byte Order (Big-Endian).
- Unit tests must be 100% network-independent using `Mock_Transport` and in-memory byte vectors.
- Zero memory leaks verified using `core:mem.Tracking_Allocator`.

---

### Task 1: Simple Query Protocol Engine (`conn_query`)

**Files:**
- Create: `pgconn/query.odin`
- Create: `pgconn/query_test.odin`

**Interfaces:**
- Produces:
  - `Row_Desc_Callback :: #type proc(user_data: rawptr, desc: pgproto.Msg_Row_Description)`
  - `Row_Callback :: #type proc(user_data: rawptr, row: pgproto.Msg_Data_Row) -> (proceed: bool)`
  - `Command_Callback :: #type proc(user_data: rawptr, tag: string, rows_affected: i64)`
  - `conn_query(conn: ^Conn, sql: string, on_row: Row_Callback = nil, on_command: Command_Callback = nil, on_desc: Row_Desc_Callback = nil, user_data: rawptr = nil) -> pgerr.Error`

- [ ] **Step 1: Write failing test for `conn_query` streaming rows, command complete, and descriptor**

In `pgconn/query_test.odin`:
```odin
package pgconn

import "core:mem"
import "core:testing"
import "core:time"
import "../pgerr"
import "../pgproto"

Test_Query_Collector :: struct {
	column_count:  int,
	rows:          [dynamic][dynamic]string,
	command_tag:   string,
	rows_affected: i64,
	allocator:     mem.Allocator,
}

test_on_desc :: proc(user_data: rawptr, desc: pgproto.Msg_Row_Description) {
	c := (^Test_Query_Collector)(user_data)
	c.column_count = len(desc.fields)
}

test_on_row :: proc(user_data: rawptr, row: pgproto.Msg_Data_Row) -> bool {
	c := (^Test_Query_Collector)(user_data)
	row_strings := make([dynamic]string, c.allocator)
	for val in row.values {
		if val.is_null {
			append(&row_strings, "NULL")
		} else {
			append(&row_strings, strings.clone(string(val.data), c.allocator))
		}
	}
	append(&c.rows, row_strings)
	return true
}

test_on_command :: proc(user_data: rawptr, tag: string, rows_affected: i64) {
	c := (^Test_Query_Collector)(user_data)
	c.command_tag = strings.clone(tag, c.allocator)
	c.rows_affected = rows_affected
}

@(test)
test_conn_query_simple_select :: proc(t: ^testing.T) {
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
	conn.status = .Ready
	conn.parameters = make(map[string]string, 16, context.allocator)
	stream_init(&conn.stream, transport, allocator = context.allocator)
	defer {
		conn_close(conn)
		free(conn, context.allocator)
	}

	// Server responses:
	// 1. RowDescription ('T'): 1 field ("val", oid 23, format 0)
	// 2. DataRow ('D'): 1 col ("42")
	// 3. CommandComplete ('C'): "SELECT 1"
	// 4. ReadyForQuery ('Z'): 'I'
	row_desc := []byte{
		'T', 0, 0, 0, 27,
		0, 1, // 1 field
		'v', 'a', 'l', 0, // field name
		0, 0, 0, 0, // table OID
		0, 0, // col attr
		0, 0, 0, 23, // data type OID (int4)
		0, 4, // data type size
		255, 255, 255, 255, // type modifier
		0, 0, // format text
	}
	data_row := []byte{
		'D', 0, 0, 0, 12,
		0, 1, // 1 column
		0, 0, 0, 2, // length 2
		'4', '2',
	}
	cmd_complete := []byte{
		'C', 0, 0, 0, 13,
		'S', 'E', 'L', 'E', 'C', 'T', ' ', '1', 0,
	}
	rfq := []byte{'Z', 0, 0, 0, 5, 'I'}

	append(&mock.read_chunks, row_desc)
	append(&mock.read_chunks, data_row)
	append(&mock.read_chunks, cmd_complete)
	append(&mock.read_chunks, rfq)

	collector: Test_Query_Collector
	collector.allocator = context.allocator
	collector.rows = make([dynamic][dynamic]string, context.allocator)
	defer {
		for r in collector.rows {
			for str in r {
				delete(str, context.allocator)
			}
			delete(r)
		}
		delete(collector.rows)
		delete(collector.command_tag, context.allocator)
	}

	err := conn_query(
		conn,
		"SELECT 42 AS val;",
		on_row = test_on_row,
		on_command = test_on_command,
		on_desc = test_on_desc,
		user_data = &collector,
	)

	testing.expect(t, err == nil, "expected query success")
	testing.expect_value(t, collector.column_count, 1)
	testing.expect_value(t, len(collector.rows), 1)
	testing.expect_value(t, collector.rows[0][0], "42")
	testing.expect_value(t, collector.command_tag, "SELECT 1")
	testing.expect_value(t, collector.rows_affected, 1)
	testing.expect_value(t, conn.status, Conn_Status.Ready)

	// Verify 'Q' packet written to mock
	testing.expect_value(t, mock.written_bytes[0], 'Q')

	testing.expect_value(t, len(track.allocation_map), 0)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `odin test tests -all-packages`
Expected: FAIL with `conn_query` undefined

- [ ] **Step 3: Implement `conn_query` in `pgconn/query.odin`**

In `pgconn/query.odin`:
```odin
package pgconn

import "core:mem"
import "core:time"
import "../pgerr"
import "../pgproto"

Row_Desc_Callback :: #type proc(user_data: rawptr, desc: pgproto.Msg_Row_Description)
Row_Callback :: #type proc(user_data: rawptr, row: pgproto.Msg_Data_Row) -> (proceed: bool)
Command_Callback :: #type proc(user_data: rawptr, tag: string, rows_affected: i64)

/*
	conn_query executes a SQL query string using PostgreSQL Simple Query protocol ('Q').
	Streams rows, command completion tags, and descriptors to provided callbacks.
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

	query_msg := pgproto.frontend_encode_query(sql, context.temp_allocator)
	stream_write_messages(&conn.stream, query_msg) or_return

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
				on_command(user_data, m.tag, m.rows_affected)
			}

		case pgproto.Msg_Empty_Query_Response:
			// No action needed for empty queries

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
				var_recorded_err = pgerr.postgres_error_clone(m.error, context.temp_allocator)
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `odin test tests -all-packages -vet -strict-style`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add pgconn/query.odin pgconn/query_test.odin
git commit -m "feat(pgconn): implement simple query protocol engine"
```

---

### Task 2: Simple Query Error Draining, Notices & Early Abort

**Files:**
- Modify: `pgconn/query_test.odin`

**Interfaces:**
- Tests verifying:
  - ErrorResponse capture and drain to ReadyForQuery (updating transaction status to `.Failed_Transaction` or `.Ready`).
  - EmptyQueryResponse handling.
  - Asynchronous Notice / Notification messages during simple query.
  - Early abort when `on_row` returns `false`.

- [ ] **Step 1: Write test for ErrorResponse drain in simple query**

In `pgconn/query_test.odin`:
```odin
@(test)
test_conn_query_error_response_and_drain :: proc(t: ^testing.T) {
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
	conn.status = .In_Transaction
	conn.parameters = make(map[string]string, 16, context.allocator)
	stream_init(&conn.stream, transport, allocator = context.allocator)
	defer {
		conn_close(conn)
		free(conn, context.allocator)
	}

	// Server responses:
	// 1. ErrorResponse: 'E', len, 'S', "ERROR\0", 'C', "42P01\0", 'M', "relation does not exist\0", '\0'
	// 2. ReadyForQuery: 'Z', len 5, 'E' (Failed_Transaction)
	err_builder := make([dynamic]byte, context.temp_allocator)
	append(&err_builder, 'E')
	append(&err_builder, 0, 0, 0, 0)
	append(&err_builder, 'S')
	append(&err_builder, transmute([]byte)string("ERROR"))
	append(&err_builder, 0)
	append(&err_builder, 'C')
	append(&err_builder, transmute([]byte)string("42P01"))
	append(&err_builder, 0)
	append(&err_builder, 'M')
	append(&err_builder, transmute([]byte)string("relation does not exist"))
	append(&err_builder, 0)
	append(&err_builder, 0)
	endian.put_i32(err_builder[1:5], .Big, i32(len(err_builder) - 1))

	rfq := []byte{'Z', 0, 0, 0, 5, 'E'}

	append(&mock.read_chunks, err_builder[:])
	append(&mock.read_chunks, rfq)

	err := conn_query(conn, "SELECT * FROM nonexistent;")
	testing.expect(t, err != nil, "expected error")
	pg_err, ok := err.(pgerr.Postgres_Error)
	testing.expect(t, ok, "expected Postgres_Error")
	testing.expect_value(t, pg_err.code, "42P01")
	testing.expect_value(t, pg_err.message, "relation does not exist")

	// Connection status transitioned to Failed_Transaction on ReadyForQuery
	testing.expect_value(t, conn.status, Conn_Status.Failed_Transaction)
	testing.expect_value(t, conn.transaction_status, pgproto.Transaction_Status.In_Failed_Transaction)

	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
test_conn_query_early_abort_row_streaming :: proc(t: ^testing.T) {
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
	conn.status = .Ready
	conn.parameters = make(map[string]string, 16, context.allocator)
	stream_init(&conn.stream, transport, allocator = context.allocator)
	defer {
		conn_close(conn)
		free(conn, context.allocator)
	}

	// 2 rows sent by server, but callback returns false after first row
	row1 := []byte{'D', 0, 0, 0, 11, 0, 1, 0, 0, 0, 1, '1'}
	row2 := []byte{'D', 0, 0, 0, 11, 0, 1, 0, 0, 0, 1, '2'}
	cmd := []byte{'C', 0, 0, 0, 13, 'S', 'E', 'L', 'E', 'C', 'T', ' ', '2', 0}
	rfq := []byte{'Z', 0, 0, 0, 5, 'I'}

	append(&mock.read_chunks, row1)
	append(&mock.read_chunks, row2)
	append(&mock.read_chunks, cmd)
	append(&mock.read_chunks, rfq)

	row_count := 0
	on_aborting_row :: proc(user_data: rawptr, row: pgproto.Msg_Data_Row) -> bool {
		count := (^int)(user_data)
		count^ += 1
		return false // Abort after first
	}

	err := conn_query(conn, "SELECT generate_series(1,2);", on_row = on_aborting_row, user_data = &row_count)
	testing.expect(t, err == nil, "expected clean return even on early abort")
	testing.expect_value(t, row_count, 1)
	testing.expect_value(t, conn.status, Conn_Status.Ready)

	testing.expect_value(t, len(track.allocation_map), 0)
}
```

- [ ] **Step 2: Run test to verify it passes**

Run: `odin test tests -all-packages -vet -strict-style`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add pgconn/query_test.odin
git commit -m "feat(pgconn): add tests for query error draining and row abort"
```

---

### Task 3: Parameterized Extended Query Execution (`conn_exec_params`)

**Files:**
- Create: `pgconn/extended.odin`
- Modify: `pgconn/query_test.odin`

**Interfaces:**
- Produces:
  - `conn_exec_params(conn: ^Conn, query: string, params: []pgproto.Bind_Param, on_row: Row_Callback = nil, on_command: Command_Callback = nil, on_desc: Row_Desc_Callback = nil, user_data: rawptr = nil) -> pgerr.Error`

- [ ] **Step 1: Write failing test for `conn_exec_params` with parameterized SELECT and NULL values**

In `pgconn/query_test.odin`:
```odin
@(test)
test_conn_exec_params_success :: proc(t: ^testing.T) {
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
	conn.status = .Ready
	conn.parameters = make(map[string]string, 16, context.allocator)
	stream_init(&conn.stream, transport, allocator = context.allocator)
	defer {
		conn_close(conn)
		free(conn, context.allocator)
	}

	// Server pipeline response:
	// 1. ParseComplete ('1', len 4)
	// 2. BindComplete ('2', len 4)
	// 3. RowDescription ('T')
	// 4. DataRow ('D')
	// 5. CommandComplete ('C')
	// 6. ReadyForQuery ('Z')
	parse_ok := []byte{'1', 0, 0, 0, 4}
	bind_ok := []byte{'2', 0, 0, 0, 4}
	row_desc := []byte{
		'T', 0, 0, 0, 27,
		0, 1,
		'v', 'a', 'l', 0,
		0, 0, 0, 0,
		0, 0,
		0, 0, 0, 25, // text
		255, 255,
		255, 255, 255, 255,
		0, 0,
	}
	data_row := []byte{
		'D', 0, 0, 0, 15,
		0, 1,
		0, 0, 0, 5,
		'h', 'e', 'l', 'l', 'o',
	}
	cmd := []byte{'C', 0, 0, 0, 13, 'S', 'E', 'L', 'E', 'C', 'T', ' ', '1', 0}
	rfq := []byte{'Z', 0, 0, 0, 5, 'I'}

	append(&mock.read_chunks, parse_ok)
	append(&mock.read_chunks, bind_ok)
	append(&mock.read_chunks, row_desc)
	append(&mock.read_chunks, data_row)
	append(&mock.read_chunks, cmd)
	append(&mock.read_chunks, rfq)

	params := []pgproto.Bind_Param{
		{is_null = false, value = transmute([]byte)string("hello")},
	}

	collector: Test_Query_Collector
	collector.allocator = context.allocator
	collector.rows = make([dynamic][dynamic]string, context.allocator)
	defer {
		for r in collector.rows {
			for str in r {
				delete(str, context.allocator)
			}
			delete(r)
		}
		delete(collector.rows)
		delete(collector.command_tag, context.allocator)
	}

	err := conn_exec_params(
		conn,
		"SELECT $1::text AS val;",
		params,
		on_row = test_on_row,
		on_command = test_on_command,
		on_desc = test_on_desc,
		user_data = &collector,
	)

	testing.expect(t, err == nil, "expected exec_params success")
	testing.expect_value(t, len(collector.rows), 1)
	testing.expect_value(t, collector.rows[0][0], "hello")
	testing.expect_value(t, conn.status, Conn_Status.Ready)

	testing.expect_value(t, len(track.allocation_map), 0)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `odin test tests -all-packages`
Expected: FAIL with `conn_exec_params` undefined

- [ ] **Step 3: Implement `conn_exec_params` in `pgconn/extended.odin`**

In `pgconn/extended.odin`:
```odin
package pgconn

import "core:mem"
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

	// Build batched pipeline: Parse + Bind + Describe + Execute + Sync
	parse_msg := pgproto.frontend_encode_parse("", query, nil, context.temp_allocator)
	bind_msg := pgproto.frontend_encode_bind("", "", nil, params, nil, context.temp_allocator)
	desc_msg := pgproto.frontend_encode_describe(.Portal, "", context.temp_allocator)
	exec_msg := pgproto.frontend_encode_execute("", 0, context.temp_allocator)
	sync_msg := pgproto.frontend_encode_sync(context.temp_allocator)

	stream_write_messages(&conn.stream, parse_msg, bind_msg, desc_msg, exec_msg, sync_msg) or_return

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
				on_command(user_data, m.tag, m.rows_affected)
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
				var_recorded_err = pgerr.postgres_error_clone(m.error, context.temp_allocator)
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `odin test tests -all-packages -vet -strict-style`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add pgconn/extended.odin pgconn/query_test.odin
git commit -m "feat(pgconn): implement parameterized extended query execution engine"
```

---

### Task 4: Named Prepared Statements & Lifecycle Management

**Files:**
- Modify: `pgconn/conn.odin` (add `prepared_statements: map[string]Prepared_Statement` to `Conn`, clean up in `conn_close`)
- Modify: `pgconn/extended.odin`
- Modify: `pgconn/query_test.odin`

**Interfaces:**
- Produces:
  - `conn_prepare(conn: ^Conn, name: string, query: string, param_oids: []u32 = nil) -> pgerr.Error`
  - `conn_exec_prepared(conn: ^Conn, name: string, params: []pgproto.Bind_Param, on_row: Row_Callback = nil, on_command: Command_Callback = nil, on_desc: Row_Desc_Callback = nil, user_data: rawptr = nil) -> pgerr.Error`
  - `conn_close_statement(conn: ^Conn, name: string) -> pgerr.Error`
  - `conn_close_portal(conn: ^Conn, name: string) -> pgerr.Error`

- [ ] **Step 1: Write failing test for `conn_prepare` $\rightarrow$ `conn_exec_prepared` $\rightarrow$ `conn_close_statement`**

In `pgconn/query_test.odin`:
```odin
@(test)
test_conn_prepared_statement_lifecycle :: proc(t: ^testing.T) {
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
	conn.status = .Ready
	conn.parameters = make(map[string]string, 16, context.allocator)
	conn.prepared_statements = make(map[string]Prepared_Statement, 16, context.allocator)
	stream_init(&conn.stream, transport, allocator = context.allocator)
	defer {
		conn_close(conn)
		free(conn, context.allocator)
	}

	// 1. Response for conn_prepare (Parse + Sync): ParseComplete + ReadyForQuery
	parse_ok := []byte{'1', 0, 0, 0, 4}
	rfq := []byte{'Z', 0, 0, 0, 5, 'I'}
	append(&mock.read_chunks, parse_ok)
	append(&mock.read_chunks, rfq)

	prep_err := conn_prepare(conn, "stmt1", "SELECT $1::int4 AS num;", []u32{23})
	testing.expect(t, prep_err == nil, "expected prepare success")
	testing.expect(t, "stmt1" in conn.prepared_statements, "expected stmt1 in cache")

	// 2. Response for conn_exec_prepared (Bind + Describe + Execute + Sync): BindComplete + RowDesc + DataRow + CmdComplete + RFQ
	bind_ok := []byte{'2', 0, 0, 0, 4}
	row_desc := []byte{
		'T', 0, 0, 0, 27,
		0, 1,
		'n', 'u', 'm', 0,
		0, 0, 0, 0,
		0, 0,
		0, 0, 0, 23,
		0, 4,
		255, 255, 255, 255,
		0, 0,
	}
	data_row := []byte{'D', 0, 0, 0, 13, 0, 1, 0, 0, 0, 3, '1', '0', '0'}
	cmd := []byte{'C', 0, 0, 0, 13, 'S', 'E', 'L', 'E', 'C', 'T', ' ', '1', 0}

	append(&mock.read_chunks, bind_ok)
	append(&mock.read_chunks, row_desc)
	append(&mock.read_chunks, data_row)
	append(&mock.read_chunks, cmd)
	append(&mock.read_chunks, rfq)

	collector: Test_Query_Collector
	collector.allocator = context.allocator
	collector.rows = make([dynamic][dynamic]string, context.allocator)
	defer {
		for r in collector.rows {
			for str in r {
				delete(str, context.allocator)
			}
			delete(r)
		}
		delete(collector.rows)
		delete(collector.command_tag, context.allocator)
	}

	exec_err := conn_exec_prepared(
		conn,
		"stmt1",
		[]pgproto.Bind_Param{{is_null = false, value = transmute([]byte)string("100")}},
		on_row = test_on_row,
		on_command = test_on_command,
		user_data = &collector,
	)
	testing.expect(t, exec_err == nil, "expected exec_prepared success")
	testing.expect_value(t, len(collector.rows), 1)
	testing.expect_value(t, collector.rows[0][0], "100")

	// 3. Response for conn_close_statement (Close + Sync): CloseComplete ('3') + RFQ
	close_ok := []byte{'3', 0, 0, 0, 4}
	append(&mock.read_chunks, close_ok)
	append(&mock.read_chunks, rfq)

	close_err := conn_close_statement(conn, "stmt1")
	testing.expect(t, close_err == nil, "expected close_statement success")
	testing.expect(!("stmt1" in conn.prepared_statements), "expected stmt1 removed from cache")

	testing.expect_value(t, len(track.allocation_map), 0)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `odin test tests -all-packages`
Expected: FAIL with `conn_prepare` / `conn_exec_prepared` undefined

- [ ] **Step 3: Implement prepared statement procedures in `pgconn/extended.odin` and update `pgconn/conn.odin`**

In `pgconn/conn.odin`:
Add `prepared_statements: map[string]Prepared_Statement` to `Conn`.
In `conn_close`:
```odin
if conn.prepared_statements != nil {
	for k, stmt in conn.prepared_statements {
		delete(k, conn.allocator)
		delete(stmt.query, conn.allocator)
		if stmt.param_oids != nil {
			delete(stmt.param_oids, conn.allocator)
		}
	}
	delete(conn.prepared_statements)
	conn.prepared_statements = nil
}
```

In `pgconn/extended.odin`:
```odin
conn_prepare :: proc(
	conn: ^Conn,
	name: string,
	query: string,
	param_oids: []u32 = nil,
) -> pgerr.Error {
	if !conn_is_alive(conn) {
		return pgerr.Net_Error{type = .Socket_Closed}
	}

	conn.status = .Busy

	parse_msg := pgproto.frontend_encode_parse(name, query, param_oids, context.temp_allocator)
	sync_msg := pgproto.frontend_encode_sync(context.temp_allocator)
	stream_write_messages(&conn.stream, parse_msg, sync_msg) or_return

	var_recorded_err: pgerr.Error = nil

	for {
		msg := stream_read_message(&conn.stream, context.temp_allocator) or_return

		#partial switch m in msg {
		case pgproto.Msg_Parse_Complete:
			// Successfully parsed

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
				var_recorded_err = pgerr.postgres_error_clone(m.error, context.temp_allocator)
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
				var oids_clone: []u32 = nil
				if param_oids != nil {
					oids_clone = make([]u32, len(param_oids), conn.allocator)
					copy(oids_clone, param_oids)
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

	conn.status = .Busy

	bind_msg := pgproto.frontend_encode_bind("", name, nil, params, nil, context.temp_allocator)
	desc_msg := pgproto.frontend_encode_describe(.Portal, "", context.temp_allocator)
	exec_msg := pgproto.frontend_encode_execute("", 0, context.temp_allocator)
	sync_msg := pgproto.frontend_encode_sync(context.temp_allocator)

	stream_write_messages(&conn.stream, bind_msg, desc_msg, exec_msg, sync_msg) or_return

	var_proceed := true
	var_recorded_err: pgerr.Error = nil

	for {
		msg := stream_read_message(&conn.stream, context.temp_allocator) or_return

		#partial switch m in msg {
		case pgproto.Msg_Bind_Complete, pgproto.Msg_No_Data:
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
				on_command(user_data, m.tag, m.rows_affected)
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
				var_recorded_err = pgerr.postgres_error_clone(m.error, context.temp_allocator)
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

conn_close_statement :: proc(conn: ^Conn, name: string) -> pgerr.Error {
	if !conn_is_alive(conn) {
		return pgerr.Net_Error{type = .Socket_Closed}
	}

	conn.status = .Busy

	close_msg := pgproto.frontend_encode_close(.Statement, name, context.temp_allocator)
	sync_msg := pgproto.frontend_encode_sync(context.temp_allocator)
	stream_write_messages(&conn.stream, close_msg, sync_msg) or_return

	var_recorded_err: pgerr.Error = nil

	for {
		msg := stream_read_message(&conn.stream, context.temp_allocator) or_return

		#partial switch m in msg {
		case pgproto.Msg_Close_Complete:
			// Statement closed

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
				var_recorded_err = pgerr.postgres_error_clone(m.error, context.temp_allocator)
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

conn_close_portal :: proc(conn: ^Conn, name: string) -> pgerr.Error {
	if !conn_is_alive(conn) {
		return pgerr.Net_Error{type = .Socket_Closed}
	}

	conn.status = .Busy

	close_msg := pgproto.frontend_encode_close(.Portal, name, context.temp_allocator)
	sync_msg := pgproto.frontend_encode_sync(context.temp_allocator)
	stream_write_messages(&conn.stream, close_msg, sync_msg) or_return

	var_recorded_err: pgerr.Error = nil

	for {
		msg := stream_read_message(&conn.stream, context.temp_allocator) or_return

		#partial switch m in msg {
		case pgproto.Msg_Close_Complete:
			// Portal closed

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
				var_recorded_err = pgerr.postgres_error_clone(m.error, context.temp_allocator)
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `odin test tests -all-packages -vet -strict-style`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add pgconn/conn.odin pgconn/extended.odin pgconn/query_test.odin
git commit -m "feat(pgconn): implement prepared statement lifecycle and caching"
```

---

### Task 5: Comprehensive Error Handling, Pipeline Edge Cases & Verification Suite

**Files:**
- Modify: `pgconn/query_test.odin`
- Update: `JIRA.md` (mark OPG-204 Done)

**Interfaces:**
- Tests verifying:
  - Extended Query error drain on bad parameter types or missing columns.
  - Closed / dead connection checks before writing.
  - Tracking allocator 0 memory leaks across all query paths.

- [ ] **Step 1: Write tests for extended query error drain and dead connection check**

In `pgconn/query_test.odin`:
```odin
@(test)
test_conn_exec_params_error_drain :: proc(t: ^testing.T) {
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
	conn.status = .Ready
	conn.parameters = make(map[string]string, 16, context.allocator)
	stream_init(&conn.stream, transport, allocator = context.allocator)
	defer {
		conn_close(conn)
		free(conn, context.allocator)
	}

	// Server pipeline error response:
	// ParseComplete -> ErrorResponse on Bind -> ReadyForQuery
	parse_ok := []byte{'1', 0, 0, 0, 4}
	err_builder := make([dynamic]byte, context.temp_allocator)
	append(&err_builder, 'E')
	append(&err_builder, 0, 0, 0, 0)
	append(&err_builder, 'S')
	append(&err_builder, transmute([]byte)string("ERROR"))
	append(&err_builder, 0)
	append(&err_builder, 'C')
	append(&err_builder, transmute([]byte)string("22P02"))
	append(&err_builder, 0)
	append(&err_builder, 'M')
	append(&err_builder, transmute([]byte)string("invalid input syntax for type integer"))
	append(&err_builder, 0)
	append(&err_builder, 0)
	endian.put_i32(err_builder[1:5], .Big, i32(len(err_builder) - 1))

	rfq := []byte{'Z', 0, 0, 0, 5, 'I'}

	append(&mock.read_chunks, parse_ok)
	append(&mock.read_chunks, err_builder[:])
	append(&mock.read_chunks, rfq)

	err := conn_exec_params(conn, "SELECT $1::int4;", []pgproto.Bind_Param{{is_null = false, value = transmute([]byte)string("notanumber")}})
	testing.expect(t, err != nil, "expected error")
	pg_err, ok := err.(pgerr.Postgres_Error)
	testing.expect(t, ok, "expected Postgres_Error")
	testing.expect_value(t, pg_err.code, "22P02")
	testing.expect_value(t, conn.status, Conn_Status.Ready)

	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
test_conn_query_dead_connection :: proc(t: ^testing.T) {
	conn: Conn
	conn.status = .Closed

	err := conn_query(&conn, "SELECT 1;")
	testing.expect(t, err != nil, "expected error on closed conn")
	net_err, ok := err.(pgerr.Net_Error)
	testing.expect(t, ok, "expected Net_Error")
	testing.expect_value(t, net_err.type, pgerr.Net_Error_Type.Socket_Closed)
}
```

- [ ] **Step 2: Run all tests and linters across all packages**

Run: `odin test tests -all-packages -vet -strict-style`
Expected: All tests pass with zero warnings.

- [ ] **Step 3: Run address sanitizer check**

Run: `odin test tests -all-packages -sanitize:address`
Expected: Pass with zero sanitizer violations.

- [ ] **Step 4: Update `JIRA.md` status for OPG-204**

Mark `[OPG-204]` in `JIRA.md` as Done:
```markdown
### [OPG-204] Simple & Extended Query Execution Engines
- [x] **Status**: Done
```

- [ ] **Step 5: Commit**

```bash
git add pgconn/query_test.odin JIRA.md
git commit -m "feat(pgconn): complete OPG-204 query execution engines and mark task done in JIRA"
```
