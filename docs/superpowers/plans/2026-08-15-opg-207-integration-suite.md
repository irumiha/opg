# OPG-207 Integration Suite Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete the `pgconn` integration test suite against live PostgreSQL (auth, simple/extended query, prepared statements, cancel, pool), verify with TSan/ASan, and produce the manual coverage audit that replaces the unmeasurable ≥95% criterion.

**Architecture:** All tests go into the existing `when OPG_INTEGRATION` block in `pgconn/integration_test.odin`, using `integration_conn_config(t)` (docker-compose harness from the previous task) for real connections. Tests must be parallel-safe (the runner uses ~20 threads): TEMP tables (per-connection), unique channel names, no shared server state. The audit is a matrix document mapping every public `pgconn` proc and behavior to its covering tests; gaps found while writing it become tests in the same task.

**Tech Stack:** Odin nightly dev-2026-08, docker compose harness (`docker-compose.yml`), `core:thread` for cancel/stress tests, PostgreSQL 17.

**Spec:** JIRA.md task [OPG-207] + `docs/superpowers/specs/2026-08-15-epic-2-pgconn-architecture-design.md` §4. Coverage criterion amended per Igor's decision (2026-08-15): manual audit instead of numeric coverage — no Odin coverage tooling exists.

## Global Constraints

- These tasks write tests for ALREADY-IMPLEMENTED code: the normal cycle is write → run → PASS. A failing test here is a driver bug — stop, apply superpowers:systematic-debugging, fix the driver (its own commit), then continue.
- Run everything from the repo root. Integration runs: `odin test pgconn -vet -strict-style -define:OPG_INTEGRATION=true` (add `-define:ODIN_TEST_NAMES=...` to target new tests while iterating).
- Offline gate must stay green after every task: `odin test tests -all-packages -vet -strict-style` (no Docker).
- Tests must pass when run in parallel with each other: TEMP tables only (never CREATE TABLE), LISTEN channels named per-test, no ALTER SYSTEM / role changes.
- Postgres_Error strings are cloned into `context.temp_allocator` — assert on them within the test only; never store them.
- Every connection allocated with `context.allocator` must be `conn_close`d and `free`d before the test ends (tracking allocator is active in the runner).
- Never call `testing.fail_now` while holding a mutex (it does not return; deferred unlocks are skipped).
- Commit per task, message style `test(pgconn): ...`, ending with `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`.

## Execution Notes (workspace)

Branch in place (`git checkout -b opg-207-integration-suite`), inline execution, merge to main locally after the final gate, delete branch (Igor's standing workflow).

## Shared helper (defined in Task 1, used by all tasks)

```odin
// Connects, fails the test on error, returns a ready conn the caller must
// integration_disconnect. Callbacks reuse Test_Query_Collector and
// test_on_row/test_on_command/test_on_desc from query_test.odin.
integration_connect :: proc(t: ^testing.T) -> ^Conn {
	cfg := integration_conn_config(t)
	conn, err := conn_connect(cfg, context.allocator)
	testing.expectf(t, err == nil, "expected successful connect, got %v", err)
	if conn == nil {
		testing.fail_now(t, "no connection")
	}
	return conn
}

integration_disconnect :: proc(conn: ^Conn) {
	conn_close(conn)
	free(conn, context.allocator)
}
```

---

### Task 1: Connection lifecycle & auth failure integration tests

**Files:**
- Modify: `pgconn/integration_test.odin` (append inside the `when OPG_INTEGRATION` block; add `import "core:thread"` with `@(require)` to the import list)

**Interfaces:**
- Consumes: `integration_conn_config(t)`, `conn_connect`, `conn_close`, `conn_cancel`, `conn_query`, `Test_Query_Collector` + `test_on_row`/`test_on_command`/`test_on_desc` (query_test.odin).
- Produces: `integration_connect(t) -> ^Conn` and `integration_disconnect(conn)` helpers used by Tasks 2–4.

- [ ] **Step 1: Add the helpers and tests**

Add the two shared helpers from the header above, then:

```odin
@(test)
test_integration_auth_wrong_password :: proc(t: ^testing.T) {
	cfg := integration_conn_config(t)
	cfg.password = "definitely-wrong"

	conn, err := conn_connect(cfg, context.allocator)
	testing.expect(t, conn == nil, "expected nil conn on auth failure")
	pg_err, ok := err.(pgerr.Postgres_Error)
	testing.expectf(t, ok, "expected Postgres_Error, got %v", err)
	if ok {
		testing.expect_value(t, pg_err.code, "28P01") // invalid_password
	}
}

@(test)
test_integration_unknown_database :: proc(t: ^testing.T) {
	cfg := integration_conn_config(t)
	cfg.database = "opg_no_such_db"

	conn, err := conn_connect(cfg, context.allocator)
	testing.expect(t, conn == nil, "expected nil conn for unknown database")
	pg_err, ok := err.(pgerr.Postgres_Error)
	testing.expectf(t, ok, "expected Postgres_Error, got %v", err)
	if ok {
		testing.expect_value(t, pg_err.code, "3D000") // invalid_catalog_name
	}
}

@(test)
test_integration_server_parameters_and_appname :: proc(t: ^testing.T) {
	conn := integration_connect(t)
	defer integration_disconnect(conn)

	_, has_version := conn.parameters["server_version"]
	testing.expect(t, has_version, "expected server_version parameter")
	testing.expect_value(t, conn.parameters["client_encoding"], "UTF8")
	testing.expect(t, conn.backend_pid > 0, "expected positive backend pid")
	testing.expect_value(t, conn.transaction_status, pgproto.Transaction_Status.Idle)

	// application_name from Conn_Config must be visible server-side.
	collector: Test_Query_Collector
	collector.allocator = context.allocator
	collector.rows = make([dynamic][dynamic]string, context.allocator)
	defer integration_collector_destroy(&collector)

	qerr := conn_query(conn, "SHOW application_name;", test_on_row, test_on_command, test_on_desc, &collector)
	testing.expectf(t, qerr == nil, "expected query success, got %v", qerr)
	if len(collector.rows) == 1 && len(collector.rows[0]) == 1 {
		testing.expect_value(t, collector.rows[0][0], "opg-integration")
	} else {
		testing.fail_now(t, "expected exactly one row from SHOW application_name")
	}
}

Cancel_State :: struct {
	conn: ^Conn,
	err:  pgerr.Error,
}

cancel_after_delay_proc :: proc(s: ^Cancel_State) {
	time.sleep(200 * time.Millisecond)
	s.err = conn_cancel(s.conn)
}

@(test)
test_integration_cancel_running_query :: proc(t: ^testing.T) {
	conn := integration_connect(t)
	defer integration_disconnect(conn)

	// conn_cancel only reads immutable fields (pid, secret, config), so
	// running it from another thread while conn_query blocks is race-free.
	state := Cancel_State{conn = conn}
	th := thread.create_and_start_with_poly_data(&state, cancel_after_delay_proc)

	qerr := conn_query(conn, "SELECT pg_sleep(30);")
	thread.join(th)
	thread.destroy(th)

	testing.expectf(t, state.err == nil, "expected cancel request send success, got %v", state.err)
	pg_err, ok := qerr.(pgerr.Postgres_Error)
	testing.expectf(t, ok, "expected Postgres_Error from canceled query, got %v", qerr)
	if ok {
		testing.expect_value(t, pg_err.code, "57014") // query_canceled
	}

	// Connection must be fully usable afterward.
	testing.expect_value(t, conn.status, Conn_Status.Ready)
	qerr2 := conn_query(conn, "SELECT 1;")
	testing.expectf(t, qerr2 == nil, "expected query success after cancel, got %v", qerr2)
}
```

Also add the collector-cleanup helper (used by every test with a collector):

```odin
integration_collector_destroy :: proc(collector: ^Test_Query_Collector) {
	for r in collector.rows {
		for s in r {
			delete(s, context.allocator)
		}
		delete(r)
	}
	delete(collector.rows)
	if len(collector.command_tag) > 0 {
		delete(collector.command_tag, context.allocator)
	}
}
```

- [ ] **Step 2: Run the new tests**

Run: `odin test pgconn -vet -strict-style -define:OPG_INTEGRATION=true -define:ODIN_TEST_NAMES=pgconn.test_integration_auth_wrong_password,pgconn.test_integration_unknown_database,pgconn.test_integration_server_parameters_and_appname,pgconn.test_integration_cancel_running_query`
Expected: 4 PASS (cancel test takes ~300ms). A failure means a driver bug — systematic-debugging, fix, separate commit.

- [ ] **Step 3: Offline gate**

Run: `odin test tests -all-packages -vet -strict-style`
Expected: PASS (integration compiled out).

- [ ] **Step 4: Commit**

```bash
git add pgconn/integration_test.odin
git commit -m "test(pgconn): integration tests for auth failures, params, cancel"
```

---

### Task 2: Simple query protocol integration tests

**Files:**
- Modify: `pgconn/integration_test.odin` (append)

**Interfaces:**
- Consumes: Task 1 helpers, `conn_query`, `Conn_Config.on_notice`/`on_notification` handlers, `pgproto.Transaction_Status`.
- Produces: nothing new for later tasks.

- [ ] **Step 1: Add the tests**

```odin
@(test)
test_integration_multi_row_select :: proc(t: ^testing.T) {
	conn := integration_connect(t)
	defer integration_disconnect(conn)

	collector: Test_Query_Collector
	collector.allocator = context.allocator
	collector.rows = make([dynamic][dynamic]string, context.allocator)
	defer integration_collector_destroy(&collector)

	qerr := conn_query(conn, "SELECT generate_series(1, 5);", test_on_row, test_on_command, test_on_desc, &collector)
	testing.expectf(t, qerr == nil, "expected query success, got %v", qerr)
	testing.expect_value(t, len(collector.rows), 5)
	testing.expect_value(t, collector.command_tag, "SELECT 5")
	testing.expect_value(t, collector.rows_affected, 5)
	if len(collector.rows) == 5 {
		testing.expect_value(t, collector.rows[0][0], "1")
		testing.expect_value(t, collector.rows[4][0], "5")
	}
}

@(test)
test_integration_dml_rows_affected :: proc(t: ^testing.T) {
	conn := integration_connect(t)
	defer integration_disconnect(conn)

	// TEMP table: per-connection, parallel-safe, dropped on disconnect.
	qerr := conn_query(conn, "CREATE TEMP TABLE itest_dml (id int, val text);")
	testing.expectf(t, qerr == nil, "expected create success, got %v", qerr)

	collector: Test_Query_Collector
	collector.allocator = context.allocator
	collector.rows = make([dynamic][dynamic]string, context.allocator)
	defer integration_collector_destroy(&collector)

	ins_err := conn_query(conn, "INSERT INTO itest_dml VALUES (1,'a'), (2,'b'), (3,'c');", nil, test_on_command, nil, &collector)
	testing.expectf(t, ins_err == nil, "expected insert success, got %v", ins_err)
	testing.expect_value(t, collector.command_tag, "INSERT 0 3")
	testing.expect_value(t, collector.rows_affected, 3)

	delete(collector.command_tag, context.allocator)
	collector.command_tag = ""
	upd_err := conn_query(conn, "UPDATE itest_dml SET val = 'x' WHERE id <= 2;", nil, test_on_command, nil, &collector)
	testing.expectf(t, upd_err == nil, "expected update success, got %v", upd_err)
	testing.expect_value(t, collector.command_tag, "UPDATE 2")
	testing.expect_value(t, collector.rows_affected, 2)
}

@(test)
test_integration_multi_statement_and_empty_query :: proc(t: ^testing.T) {
	conn := integration_connect(t)
	defer integration_disconnect(conn)

	collector: Test_Query_Collector
	collector.allocator = context.allocator
	collector.rows = make([dynamic][dynamic]string, context.allocator)
	defer integration_collector_destroy(&collector)

	// Two statements in one simple query: rows from both accumulate.
	qerr := conn_query(conn, "SELECT 1; SELECT 2;", test_on_row, test_on_command, test_on_desc, &collector)
	testing.expectf(t, qerr == nil, "expected multi-statement success, got %v", qerr)
	testing.expect_value(t, len(collector.rows), 2)
	testing.expect_value(t, conn.status, Conn_Status.Ready)

	// Empty query string: EmptyQueryResponse path, no error.
	empty_err := conn_query(conn, "")
	testing.expectf(t, empty_err == nil, "expected empty query success, got %v", empty_err)
	testing.expect_value(t, conn.status, Conn_Status.Ready)
}

@(test)
test_integration_error_response_and_recovery :: proc(t: ^testing.T) {
	conn := integration_connect(t)
	defer integration_disconnect(conn)

	qerr := conn_query(conn, "SELECT * FROM itest_no_such_table;")
	pg_err, ok := qerr.(pgerr.Postgres_Error)
	testing.expectf(t, ok, "expected Postgres_Error, got %v", qerr)
	if ok {
		testing.expect_value(t, pg_err.code, "42P01") // undefined_table
	}

	// The connection drained to ReadyForQuery and stays usable.
	testing.expect_value(t, conn.status, Conn_Status.Ready)
	qerr2 := conn_query(conn, "SELECT 1;")
	testing.expectf(t, qerr2 == nil, "expected recovery query success, got %v", qerr2)
}

@(test)
test_integration_transaction_status_transitions :: proc(t: ^testing.T) {
	conn := integration_connect(t)
	defer integration_disconnect(conn)

	testing.expect(t, conn_query(conn, "BEGIN;") == nil, "expected BEGIN success")
	testing.expect_value(t, conn.status, Conn_Status.In_Transaction)
	testing.expect_value(t, conn.transaction_status, pgproto.Transaction_Status.In_Transaction)

	// An error inside a transaction moves it to failed state.
	bad_err := conn_query(conn, "SELECT 1/0;")
	testing.expect(t, bad_err != nil, "expected division by zero error")
	testing.expect_value(t, conn.status, Conn_Status.Failed_Transaction)

	testing.expect(t, conn_query(conn, "ROLLBACK;") == nil, "expected ROLLBACK success")
	testing.expect_value(t, conn.status, Conn_Status.Ready)

	// Commit path.
	testing.expect(t, conn_query(conn, "BEGIN;") == nil, "expected BEGIN success")
	testing.expect(t, conn_query(conn, "SELECT 1;") == nil, "expected in-tx query success")
	testing.expect_value(t, conn.status, Conn_Status.In_Transaction)
	testing.expect(t, conn_query(conn, "COMMIT;") == nil, "expected COMMIT success")
	testing.expect_value(t, conn.status, Conn_Status.Ready)
}

Notice_Capture :: struct {
	count:   int,
	message: [256]byte,
	msg_len: int,
}

integration_on_notice :: proc(user_data: rawptr, notice: pgproto.Msg_Notice_Response) {
	cap_state := (^Notice_Capture)(user_data)
	cap_state.count += 1
	n := copy(cap_state.message[:], notice.error.message)
	cap_state.msg_len = n
}

@(test)
test_integration_raise_notice_handler :: proc(t: ^testing.T) {
	captured: Notice_Capture
	cfg := integration_conn_config(t)
	cfg.on_notice = integration_on_notice
	cfg.on_notice_data = &captured

	conn, err := conn_connect(cfg, context.allocator)
	testing.expectf(t, err == nil, "expected connect success, got %v", err)
	if conn == nil {
		testing.fail_now(t, "no connection")
	}
	defer integration_disconnect(conn)

	qerr := conn_query(conn, "DO $$ BEGIN RAISE NOTICE 'opg notice test'; END $$;")
	testing.expectf(t, qerr == nil, "expected DO block success, got %v", qerr)
	testing.expect_value(t, captured.count, 1)
	testing.expect_value(t, string(captured.message[:captured.msg_len]), "opg notice test")
}

Notification_Capture :: struct {
	count:   int,
	channel: [128]byte,
	chan_len: int,
	payload: [128]byte,
	payload_len: int,
}

integration_on_notification :: proc(user_data: rawptr, notification: pgproto.Msg_Notification_Response) {
	cap_state := (^Notification_Capture)(user_data)
	cap_state.count += 1
	cap_state.chan_len = copy(cap_state.channel[:], notification.channel)
	cap_state.payload_len = copy(cap_state.payload[:], notification.payload)
}

@(test)
test_integration_listen_notify :: proc(t: ^testing.T) {
	captured: Notification_Capture
	cfg := integration_conn_config(t)
	cfg.on_notification = integration_on_notification
	cfg.on_notif_data = &captured

	listener, lerr := conn_connect(cfg, context.allocator)
	testing.expectf(t, lerr == nil, "expected listener connect success, got %v", lerr)
	if listener == nil {
		testing.fail_now(t, "no listener connection")
	}
	defer integration_disconnect(listener)

	notifier := integration_connect(t)
	defer integration_disconnect(notifier)

	testing.expect(t, conn_query(listener, "LISTEN opg_itest_chan;") == nil, "expected LISTEN success")
	testing.expect(t, conn_query(notifier, "NOTIFY opg_itest_chan, 'hello';") == nil, "expected NOTIFY success")

	// The notification is delivered when the listener next reads from the
	// socket; any query triggers that read loop.
	testing.expect(t, conn_query(listener, "SELECT 1;") == nil, "expected wakeup query success")

	testing.expect_value(t, captured.count, 1)
	testing.expect_value(t, string(captured.channel[:captured.chan_len]), "opg_itest_chan")
	testing.expect_value(t, string(captured.payload[:captured.payload_len]), "hello")
}
```

- [ ] **Step 2: Run the new tests**

Run: `odin test pgconn -vet -strict-style -define:OPG_INTEGRATION=true -define:ODIN_TEST_NAMES=pgconn.test_integration_multi_row_select,pgconn.test_integration_dml_rows_affected,pgconn.test_integration_multi_statement_and_empty_query,pgconn.test_integration_error_response_and_recovery,pgconn.test_integration_transaction_status_transitions,pgconn.test_integration_raise_notice_handler,pgconn.test_integration_listen_notify`
Expected: 7 PASS.

- [ ] **Step 3: Full integration + offline gates**

Run: `odin test pgconn -vet -strict-style -define:OPG_INTEGRATION=true` then `odin test tests -all-packages -vet -strict-style`
Expected: both PASS.

- [ ] **Step 4: Commit**

```bash
git add pgconn/integration_test.odin
git commit -m "test(pgconn): simple query protocol integration tests"
```

---

### Task 3: Extended query & prepared statement integration tests

**Files:**
- Modify: `pgconn/integration_test.odin` (append)

**Interfaces:**
- Consumes: Task 1 helpers; `conn_exec_params(conn, query, params: []pgproto.Bind_Param, on_row, on_command, on_desc, user_data)`, `conn_prepare(conn, name, query, param_oids := nil)`, `conn_exec_prepared(conn, name, params, on_row, on_command, on_desc, user_data)`, `conn_close_statement(conn, name)`, `conn_close_portal(conn, name)`; `pgproto.Bind_Param{is_null: bool, value: []byte}`.
- Produces: nothing new for later tasks.

- [ ] **Step 1: Add the tests**

```odin
@(test)
test_integration_exec_params_text :: proc(t: ^testing.T) {
	conn := integration_connect(t)
	defer integration_disconnect(conn)

	collector: Test_Query_Collector
	collector.allocator = context.allocator
	collector.rows = make([dynamic][dynamic]string, context.allocator)
	defer integration_collector_destroy(&collector)

	params := []pgproto.Bind_Param{
		{value = transmute([]byte)string("40")},
		{value = transmute([]byte)string("2")},
	}
	qerr := conn_exec_params(conn, "SELECT $1::int + $2::int;", params, test_on_row, test_on_command, test_on_desc, &collector)
	testing.expectf(t, qerr == nil, "expected exec_params success, got %v", qerr)
	testing.expect_value(t, len(collector.rows), 1)
	if len(collector.rows) == 1 && len(collector.rows[0]) == 1 {
		testing.expect_value(t, collector.rows[0][0], "42")
	}
	testing.expect_value(t, conn.status, Conn_Status.Ready)
}

@(test)
test_integration_exec_params_null :: proc(t: ^testing.T) {
	conn := integration_connect(t)
	defer integration_disconnect(conn)

	collector: Test_Query_Collector
	collector.allocator = context.allocator
	collector.rows = make([dynamic][dynamic]string, context.allocator)
	defer integration_collector_destroy(&collector)

	params := []pgproto.Bind_Param{{is_null = true}}
	qerr := conn_exec_params(conn, "SELECT $1::text IS NULL;", params, test_on_row, test_on_command, test_on_desc, &collector)
	testing.expectf(t, qerr == nil, "expected exec_params success, got %v", qerr)
	if len(collector.rows) == 1 && len(collector.rows[0]) == 1 {
		testing.expect_value(t, collector.rows[0][0], "t")
	} else {
		testing.fail_now(t, "expected exactly one row")
	}
}

@(test)
test_integration_exec_params_type_error_recovery :: proc(t: ^testing.T) {
	conn := integration_connect(t)
	defer integration_disconnect(conn)

	params := []pgproto.Bind_Param{{value = transmute([]byte)string("not-a-number")}}
	qerr := conn_exec_params(conn, "SELECT $1::int;", params)
	pg_err, ok := qerr.(pgerr.Postgres_Error)
	testing.expectf(t, ok, "expected Postgres_Error, got %v", qerr)
	if ok {
		testing.expect_value(t, pg_err.code, "22P02") // invalid_text_representation
	}

	// Extended-protocol errors drain through Sync back to Ready.
	testing.expect_value(t, conn.status, Conn_Status.Ready)
	qerr2 := conn_query(conn, "SELECT 1;")
	testing.expectf(t, qerr2 == nil, "expected recovery query success, got %v", qerr2)
}

@(test)
test_integration_prepared_statement_lifecycle :: proc(t: ^testing.T) {
	conn := integration_connect(t)
	defer integration_disconnect(conn)

	collector: Test_Query_Collector
	collector.allocator = context.allocator
	collector.rows = make([dynamic][dynamic]string, context.allocator)
	defer integration_collector_destroy(&collector)

	perr := conn_prepare(conn, "itest_stmt", "SELECT $1::int * 2;")
	testing.expectf(t, perr == nil, "expected prepare success, got %v", perr)
	_, cached := conn.prepared_statements["itest_stmt"]
	testing.expect(t, cached, "expected statement in cache")

	// Execute twice with different parameters.
	params1 := []pgproto.Bind_Param{{value = transmute([]byte)string("21")}}
	e1 := conn_exec_prepared(conn, "itest_stmt", params1, test_on_row, test_on_command, test_on_desc, &collector)
	testing.expectf(t, e1 == nil, "expected first exec success, got %v", e1)

	params2 := []pgproto.Bind_Param{{value = transmute([]byte)string("50")}}
	e2 := conn_exec_prepared(conn, "itest_stmt", params2, test_on_row, test_on_command, test_on_desc, &collector)
	testing.expectf(t, e2 == nil, "expected second exec success, got %v", e2)

	testing.expect_value(t, len(collector.rows), 2)
	if len(collector.rows) == 2 {
		testing.expect_value(t, collector.rows[0][0], "42")
		testing.expect_value(t, collector.rows[1][0], "100")
	}

	// Re-preparing the same name must replace the server statement and cache.
	rerr := conn_prepare(conn, "itest_stmt", "SELECT $1::int * 3;")
	testing.expectf(t, rerr == nil, "expected re-prepare success, got %v", rerr)

	// Close removes it server-side and from the cache; executing afterward
	// fails with invalid_sql_statement_name.
	cerr := conn_close_statement(conn, "itest_stmt")
	testing.expectf(t, cerr == nil, "expected close statement success, got %v", cerr)
	_, still_cached := conn.prepared_statements["itest_stmt"]
	testing.expect(t, !still_cached, "expected statement removed from cache")

	e3 := conn_exec_prepared(conn, "itest_stmt", params1)
	pg_err, ok := e3.(pgerr.Postgres_Error)
	if ok {
		testing.expect_value(t, pg_err.code, "26000") // invalid_sql_statement_name
	} else {
		// Driver may reject unknown statements client-side before touching
		// the server; any error is acceptable, silence is not.
		testing.expect(t, e3 != nil, "expected error executing closed statement")
	}
	testing.expect_value(t, conn.status, Conn_Status.Ready)
}

@(test)
test_integration_close_portal_noop :: proc(t: ^testing.T) {
	conn := integration_connect(t)
	defer integration_disconnect(conn)

	// Closing the (nonexistent) unnamed portal is a legal no-op round-trip.
	cerr := conn_close_portal(conn, "")
	testing.expectf(t, cerr == nil, "expected close portal success, got %v", cerr)
	testing.expect_value(t, conn.status, Conn_Status.Ready)
}
```

- [ ] **Step 2: Run the new tests**

Run: `odin test pgconn -vet -strict-style -define:OPG_INTEGRATION=true -define:ODIN_TEST_NAMES=pgconn.test_integration_exec_params_text,pgconn.test_integration_exec_params_null,pgconn.test_integration_exec_params_type_error_recovery,pgconn.test_integration_prepared_statement_lifecycle,pgconn.test_integration_close_portal_noop`
Expected: 5 PASS.

- [ ] **Step 3: Full integration + offline gates**

Run: `odin test pgconn -vet -strict-style -define:OPG_INTEGRATION=true` then `odin test tests -all-packages -vet -strict-style`
Expected: both PASS.

- [ ] **Step 4: Commit**

```bash
git add pgconn/integration_test.odin
git commit -m "test(pgconn): extended query and prepared statement integration tests"
```

---

### Task 4: Pool against live PostgreSQL

**Files:**
- Modify: `pgconn/integration_test.odin` (append)

**Interfaces:**
- Consumes: `pool_init`/`pool_acquire`/`pool_release`/`pool_destroy` with default (real TCP) `connect_fn`; `integration_conn_config(t)`; `core:thread`.
- Produces: nothing new.

- [ ] **Step 1: Add the tests**

```odin
integration_pool_config :: proc(t: ^testing.T, min_conns, max_conns: int) -> Pool_Config {
	return Pool_Config{
		conn_config = integration_conn_config(t), // connect_fn nil => real conn_connect
		min_conns = min_conns,
		max_conns = max_conns,
	}
}

@(test)
test_integration_pool_acquire_query_release :: proc(t: ^testing.T) {
	pool, perr := pool_init(integration_pool_config(t, 1, 2), context.allocator)
	testing.expectf(t, perr == nil, "expected pool_init success, got %v", perr)
	if pool == nil {
		testing.fail_now(t, "no pool")
	}

	conn, aerr := pool_acquire(pool, 5 * time.Second)
	testing.expectf(t, aerr == nil, "expected acquire success, got %v", aerr)
	testing.expect_value(t, conn.status, Conn_Status.Ready)

	qerr := conn_query(conn, "SELECT 1;")
	testing.expectf(t, qerr == nil, "expected query success, got %v", qerr)

	rerr := pool_release(pool, conn)
	testing.expectf(t, rerr == nil, "expected release success, got %v", rerr)

	// Reuse: same physical connection comes back.
	conn2, aerr2 := pool_acquire(pool, 5 * time.Second)
	testing.expectf(t, aerr2 == nil, "expected re-acquire success, got %v", aerr2)
	testing.expect(t, conn2 == conn, "expected pooled connection reuse")
	testing.expect(t, pool_release(pool, conn2) == nil, "expected release success")

	pool_destroy(pool)
}

@(test)
test_integration_pool_release_resets_real_transaction :: proc(t: ^testing.T) {
	pool, perr := pool_init(integration_pool_config(t, 1, 1), context.allocator)
	testing.expectf(t, perr == nil, "expected pool_init success, got %v", perr)
	if pool == nil {
		testing.fail_now(t, "no pool")
	}

	conn, aerr := pool_acquire(pool, 5 * time.Second)
	testing.expectf(t, aerr == nil, "expected acquire success, got %v", aerr)

	testing.expect(t, conn_query(conn, "BEGIN;") == nil, "expected BEGIN success")
	testing.expect_value(t, conn.status, Conn_Status.In_Transaction)

	// Release must issue a real ROLLBACK and pool the connection back.
	testing.expect(t, pool_release(pool, conn) == nil, "expected release success")

	conn2, aerr2 := pool_acquire(pool, 5 * time.Second)
	testing.expectf(t, aerr2 == nil, "expected re-acquire success, got %v", aerr2)
	testing.expect(t, conn2 == conn, "expected same connection back after reset")
	testing.expect_value(t, conn2.status, Conn_Status.Ready)
	testing.expect_value(t, conn2.transaction_status, pgproto.Transaction_Status.Idle)

	testing.expect(t, pool_release(pool, conn2) == nil, "expected release success")
	pool_destroy(pool)
}

Live_Stress_Worker :: struct {
	pool:      ^Pool,
	iters:     int,
	failures:  int,
}

live_stress_proc :: proc(w: ^Live_Stress_Worker) {
	for _ in 0 ..< w.iters {
		conn, err := pool_acquire(w.pool, 10 * time.Second)
		if err != nil || conn == nil {
			w.failures += 1
			continue
		}
		if conn_query(conn, "SELECT 1;") != nil {
			w.failures += 1
		}
		if pool_release(w.pool, conn) != nil {
			w.failures += 1
		}
	}
}

@(test)
test_integration_pool_concurrent_live :: proc(t: ^testing.T) {
	pool, perr := pool_init(integration_pool_config(t, 2, 4), context.allocator)
	testing.expectf(t, perr == nil, "expected pool_init success, got %v", perr)
	if pool == nil {
		testing.fail_now(t, "no pool")
	}

	NUM_THREADS :: 16
	ITERS :: 10

	workers: [NUM_THREADS]Live_Stress_Worker
	threads: [NUM_THREADS]^thread.Thread
	for i in 0 ..< NUM_THREADS {
		workers[i] = Live_Stress_Worker{pool = pool, iters = ITERS}
		threads[i] = thread.create_and_start_with_poly_data(&workers[i], live_stress_proc)
	}
	for i in 0 ..< NUM_THREADS {
		thread.join(threads[i])
		thread.destroy(threads[i])
	}

	total_failures := 0
	for i in 0 ..< NUM_THREADS {
		total_failures += workers[i].failures
	}
	testing.expect_value(t, total_failures, 0)
	testing.expect_value(t, len(pool.in_use), 0)

	pool_destroy(pool)
}
```

- [ ] **Step 2: Run the new tests**

Run: `odin test pgconn -vet -strict-style -define:OPG_INTEGRATION=true -define:ODIN_TEST_NAMES=pgconn.test_integration_pool_acquire_query_release,pgconn.test_integration_pool_release_resets_real_transaction,pgconn.test_integration_pool_concurrent_live`
Expected: 3 PASS (stress test runs 160 real queries over 4 connections; a few seconds).

- [ ] **Step 3: Full integration + offline gates**

Run: `odin test pgconn -vet -strict-style -define:OPG_INTEGRATION=true` then `odin test tests -all-packages -vet -strict-style`
Expected: both PASS.

- [ ] **Step 4: Commit**

```bash
git add pgconn/integration_test.odin
git commit -m "test(pgconn): pool integration tests against live PostgreSQL"
```

---

### Task 5: Coverage audit, sanitizers, JIRA closure, merge

**Files:**
- Create: `docs/pgconn-coverage-audit.md`
- Modify: `JIRA.md` (OPG-207 status + coverage criterion annotation)
- Possibly modify: `pgconn/integration_test.odin` (tests for any gap the audit finds)

- [ ] **Step 1: Write the audit matrix**

Create `docs/pgconn-coverage-audit.md`: a table with one row per public proc / distinct behavior in `pgconn` (source of truth: `grep -n ":: proc" pgconn/*.odin`, excluding `*_test.odin`), columns: Proc/Behavior · Unit test(s) · Integration test(s) · Notes. Enumerate at minimum: every proc in `conn.odin`, `query.odin`, `extended.odin`, `pool.odin`, `stream.odin`, `auth.odin`, `auth_scram.odin`, and per-proc error paths (dead-conn guard, server error, unexpected message, protocol drain). Mark intentionally uncovered items explicitly (e.g. `conn_connect` DNS-failure branch, TLS — deferred with OPG-205). While filling the matrix, any behavior with NO covering test in either column gets a test added in this task (unit if reachable with mocks, integration otherwise) — that is the audit's teeth.

- [ ] **Step 2: Run sanitizer verification**

Run (all with the compose stack available):
1. `odin test pgconn -define:OPG_INTEGRATION=true -sanitize:thread` — expect PASS, zero `WARNING: ThreadSanitizer` lines.
2. `odin test pgconn -define:OPG_INTEGRATION=true -sanitize:address` — expect PASS, zero AddressSanitizer reports.
Fix any finding before proceeding (driver fix = separate commit).

- [ ] **Step 3: Final gates**

Run: `./scripts/integration-test.sh` and `odin test tests -all-packages -vet -strict-style`
Expected: both PASS.

- [ ] **Step 4: Update JIRA.md**

In `### [OPG-207]`: change `- [ ] **Status**: Open` to `- [x] **Status**: Done`, and replace the coverage bullet `Line and branch coverage $\ge 95\%$.` with `Coverage: manual audit (docs/pgconn-coverage-audit.md) — Odin has no coverage instrumentation; every public proc and error path is mapped to a covering test.`

- [ ] **Step 5: Commit and merge**

```bash
git add docs/pgconn-coverage-audit.md JIRA.md pgconn/integration_test.odin
git commit -m "test(pgconn): complete OPG-207 integration suite, sanitizers, coverage audit"
git checkout main
git merge opg-207-integration-suite
git branch -d opg-207-integration-suite
./scripts/integration-test.sh   # green gate on merged main
```

---

## Self-Review Notes

- **Spec coverage:** JIRA criterion 1 (`odin test pgconn` passes unit+integration) ✓ every task's Step 3; criterion 2 (TSan zero races) ✓ Task 5 Step 2 (+ ASan per the epic tree's "TSan / ASan" title); criterion 3 (≥95% coverage) → manual audit per Igor's 2026-08-15 decision, Task 5 Steps 1+4.
- **Parallel-safety:** TEMP tables (Task 2), unique LISTEN channel used by exactly one test, pool tests use ≤4 real conns each — fine against max_connections=100 even with the runner's 20 threads.
- **Type consistency:** `Bind_Param{is_null, value}` matches `pgproto/frontend.odin:61`; callback signatures match `query.odin:9-11`; `Notice_Capture`/`Notification_Capture` use fixed buffers (no allocations escaping the test, and handler writes happen on the test's own thread during `conn_query`).
- **Known accepted risk:** `test_integration_cancel_running_query` sleeps 200ms before cancel — if the cancel request loses the race with query start (never observed at 200ms), the query would run 30s and the test would flag; acceptable, not flaky under normal load.
