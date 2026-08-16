package pgconn

// ----------------------------------------------------------------------------
// Integration test harness: real PostgreSQL via docker compose.
//
// Compiled out unless run with -define:OPG_INTEGRATION=true (from the repo
// root, so `docker compose` finds ./docker-compose.yml):
//
//     odin test pgconn -define:OPG_INTEGRATION=true
//
// The first integration test to run brings the compose stack up (idempotent,
// health-checked) and discovers the randomly allocated host port from docker.
// The container is left running between runs; `docker compose down` resets it.
//
// PG* environment variables override the compose defaults; setting PGHOST
// skips docker entirely and targets that server instead.
// ----------------------------------------------------------------------------

@(require) import "core:fmt"
@(require) import "core:os"
@(require) import "core:strconv"
@(require) import "core:strings"
@(require) import "core:sync"
@(require) import "core:testing"
@(require) import "core:thread"
@(require) import "core:time"
@(require) import "../pgerr"
@(require) import "../pgproto"

OPG_INTEGRATION :: #config(OPG_INTEGRATION, false)

when OPG_INTEGRATION {

	integration_mutex: sync.Mutex
	integration_started: bool
	integration_failed: bool
	integration_port: int
	integration_fail_msg_buf: [1024]byte
	integration_fail_msg: string

	/*
		integration_start_compose brings the docker compose postgres service
		up (idempotent) and discovers its randomly allocated host port. All
		shared state lives under integration_mutex; failures are RETURNED,
		never raised, because testing.fail_now does not return and would
		leave the mutex locked, deadlocking every other integration test.
	*/
	integration_start_compose :: proc() -> (port: int, ok: bool, fail_msg: string) {
		sync.mutex_lock(&integration_mutex)
		defer sync.mutex_unlock(&integration_mutex)

		if integration_failed {
			return 0, false, integration_fail_msg
		}
		if integration_started {
			return integration_port, true, ""
		}

		up_state, _, up_stderr, up_err := os.process_exec(
			{command = {"docker", "compose", "up", "-d", "--wait", "postgres"}},
			context.temp_allocator,
		)
		if up_err != nil || !up_state.success {
			integration_failed = true
			integration_fail_msg = fmt.bprintf(
				integration_fail_msg_buf[:],
				"docker compose up failed (%v): %s",
				up_err,
				string(up_stderr),
			)
			return 0, false, integration_fail_msg
		}

		port_state, port_out, port_stderr, port_err := os.process_exec(
			{command = {"docker", "compose", "port", "postgres", "5432"}},
			context.temp_allocator,
		)
		if port_err != nil || !port_state.success {
			integration_failed = true
			integration_fail_msg = fmt.bprintf(
				integration_fail_msg_buf[:],
				"docker compose port failed (%v): %s",
				port_err,
				string(port_stderr),
			)
			return 0, false, integration_fail_msg
		}

		// Output has the form "127.0.0.1:32768\n".
		endpoint := strings.trim_space(string(port_out))
		colon := strings.last_index_byte(endpoint, ':')
		parsed := 0
		parse_ok := false
		if colon >= 0 {
			parsed, parse_ok = strconv.parse_int(endpoint[colon + 1:])
		}
		if !parse_ok || parsed <= 0 {
			integration_failed = true
			integration_fail_msg = fmt.bprintf(
				integration_fail_msg_buf[:],
				"could not parse allocated port from %q",
				endpoint,
			)
			return 0, false, integration_fail_msg
		}

		integration_port = parsed
		integration_started = true
		return integration_port, true, ""
	}

	/*
		integration_endpoint returns the host and port of the integration
		database, starting the docker compose postgres service on first use.
		Fails the calling test if docker compose cannot deliver a healthy
		server. PGHOST/PGPORT skip docker and target an external server.
	*/
	integration_endpoint :: proc(t: ^testing.T) -> (host: string, port: int) {
		if env_host := os.get_env("PGHOST", context.temp_allocator); env_host != "" {
			port = 5432
			if env_port := os.get_env("PGPORT", context.temp_allocator); env_port != "" {
				if p, penv_ok := strconv.parse_int(env_port); penv_ok {
					port = p
				}
			}
			return env_host, port
		}

		compose_port, ok, fail_msg := integration_start_compose()
		if !ok {
			testing.fail_now(t, fail_msg)
		}
		return "127.0.0.1", compose_port
	}

	/*
		integration_conn_config builds a Conn_Config for the integration
		database: compose defaults, overridable via PG* environment variables.
	*/
	integration_conn_config :: proc(t: ^testing.T) -> Conn_Config {
		host, port := integration_endpoint(t)
		cfg := Conn_Config {
			host = host,
			port = port,
			user = "opg",
			password = "opg",
			database = "opg_test",
			application_name = "opg-integration",
		}
		if v := os.get_env("PGUSER", context.temp_allocator); v != "" {
			cfg.user = v
		}
		if v := os.get_env("PGPASSWORD", context.temp_allocator); v != "" {
			cfg.password = v
		}
		if v := os.get_env("PGDATABASE", context.temp_allocator); v != "" {
			cfg.database = v
		}
		// PGSSLMODE mirrors libpq and exists so a whole run can be forced onto
		// one negotiation path. That makes "is this a TLS problem?" a single
		// command rather than a guess — useful when a platform backend
		// misbehaves only under load. Tests that pin a mode assign ssl_mode
		// after this call and are unaffected.
		if v := os.get_env("PGSSLMODE", context.temp_allocator); v != "" {
			switch v {
			case "disable":
				cfg.ssl_mode = .Disable
			case "prefer":
				cfg.ssl_mode = .Prefer
			case "require":
				cfg.ssl_mode = .Require
			}
		}
		return cfg
	}

	// ------------------------------------------------------------------------
	// Harness smoke tests (the full OPG-207 suite builds on these)
	// ------------------------------------------------------------------------

	@(test)
	test_integration_connect_and_close :: proc(t: ^testing.T) {
		cfg := integration_conn_config(t)

		conn, err := conn_connect(cfg, context.allocator)
		testing.expectf(t, err == nil, "expected successful connect, got %v", err)
		if conn == nil {
			return
		}

		testing.expect_value(t, conn.status, Conn_Status.Ready)
		testing.expect(t, conn.backend_pid != 0, "expected backend pid from BackendKeyData")
		testing.expect(t, len(conn.parameters) > 0, "expected server parameters from startup")

		conn_close(conn)
		free(conn, context.allocator)
	}

	@(test)
	test_integration_select_roundtrip :: proc(t: ^testing.T) {
		cfg := integration_conn_config(t)

		conn, err := conn_connect(cfg, context.allocator)
		testing.expectf(t, err == nil, "expected successful connect, got %v", err)
		if conn == nil {
			return
		}
		defer {
			conn_close(conn)
			free(conn, context.allocator)
		}

		collector: Test_Query_Collector
		collector.allocator = context.allocator
		collector.rows = make([dynamic][dynamic]string, context.allocator)
		defer {
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

		qerr := conn_query(
			conn = conn,
			sql = "SELECT 42 AS answer;",
			on_row = test_on_row,
			on_command = test_on_command,
			on_desc = test_on_desc,
			user_data = &collector,
		)
		testing.expectf(t, qerr == nil, "expected query success, got %v", qerr)
		testing.expect_value(t, collector.column_count, 1)
		testing.expect_value(t, len(collector.rows), 1)
		if len(collector.rows) == 1 && len(collector.rows[0]) == 1 {
			testing.expect_value(t, collector.rows[0][0], "42")
		}
		testing.expect_value(t, collector.command_tag, "SELECT 1")
		testing.expect_value(t, conn.status, Conn_Status.Ready)
	}

	// ------------------------------------------------------------------------
	// Shared test helpers
	// ------------------------------------------------------------------------

	/*
		integration_connect connects to the integration database and fails the
		test on any error. Callers must integration_disconnect the result.
	*/
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

	// ------------------------------------------------------------------------
	// Connection lifecycle & authentication
	// ------------------------------------------------------------------------

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
			pgerr.postgres_error_destroy(pg_err, context.allocator)
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
			pgerr.postgres_error_destroy(pg_err, context.allocator)
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

	/*
		integration_auth_scenario connects as a user whose pg_hba rule forces
		a specific auth method, then pins the actual wire method via
		PostgreSQL's system_user ('auth_method:user_name', PG16+) so a silent
		SCRAM fallback cannot fake a pass.
	*/
	integration_auth_scenario :: proc(t: ^testing.T, user: string, expected_system_user: string) {
		cfg := integration_conn_config(t)
		cfg.user = user
		cfg.password = "opg"

		conn, err := conn_connect(cfg, context.allocator)
		testing.expectf(t, err == nil, "expected %s connect success, got %v", user, err)
		if conn == nil {
			return
		}
		defer integration_disconnect(conn)

		collector: Test_Query_Collector
		collector.allocator = context.allocator
		collector.rows = make([dynamic][dynamic]string, context.allocator)
		defer integration_collector_destroy(&collector)

		qerr := conn_query(conn, "SELECT system_user;", test_on_row, test_on_command, test_on_desc, &collector)
		testing.expectf(t, qerr == nil, "expected system_user query success, got %v", qerr)
		if len(collector.rows) == 1 && len(collector.rows[0]) == 1 {
			testing.expect_value(t, collector.rows[0][0], expected_system_user)
		} else {
			testing.fail_now(t, "expected exactly one row from SELECT system_user")
		}

		// Wrong password must fail with invalid_password on this method too.
		bad_cfg := cfg
		bad_cfg.password = "definitely-wrong"
		bad_conn, bad_err := conn_connect(bad_cfg, context.allocator)
		testing.expect(t, bad_conn == nil, "expected nil conn on wrong password")
		pg_err, ok := bad_err.(pgerr.Postgres_Error)
		testing.expectf(t, ok, "expected Postgres_Error, got %v", bad_err)
		if ok {
			testing.expect_value(t, pg_err.code, "28P01")
			pgerr.postgres_error_destroy(pg_err, context.allocator)
		}
	}

	@(test)
	test_integration_auth_cleartext_password :: proc(t: ^testing.T) {
		integration_auth_scenario(t, "opg_clear", "password:opg_clear")
	}

	@(test)
	test_integration_auth_md5_password :: proc(t: ^testing.T) {
		integration_auth_scenario(t, "opg_md5", "md5:opg_md5")
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

	// ------------------------------------------------------------------------
	// Simple query protocol
	// ------------------------------------------------------------------------

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
		cap_state.msg_len = copy(cap_state.message[:], notice.error.message)
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
		count:       int,
		channel:     [128]byte,
		chan_len:    int,
		payload:     [128]byte,
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

	// ------------------------------------------------------------------------
	// Extended query protocol & prepared statements
	// ------------------------------------------------------------------------

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

	// ------------------------------------------------------------------------
	// Connection pool against live PostgreSQL (real TCP dial path)
	// ------------------------------------------------------------------------

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
		pool:     ^Pool,
		iters:    int,
		failures: int,
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

	// ------------------------------------------------------------------------
	// TLS (OPG-205)
	// ------------------------------------------------------------------------

	/*
		integration_expect_ssl connects with the given mode and pins the
		wire state via pg_stat_ssl for the connection's own backend.
	*/
	integration_expect_ssl :: proc(t: ^testing.T, mode: SSL_Mode, expected: string) {
		cfg := integration_conn_config(t)
		cfg.ssl_mode = mode

		conn, err := conn_connect(cfg, context.allocator)
		testing.expectf(t, err == nil, "expected connect success (mode %v), got %v", mode, err)
		if conn == nil {
			return
		}
		defer integration_disconnect(conn)

		collector: Test_Query_Collector
		collector.allocator = context.allocator
		collector.rows = make([dynamic][dynamic]string, context.allocator)
		defer integration_collector_destroy(&collector)

		qerr := conn_query(conn, "SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid();", test_on_row, test_on_command, test_on_desc, &collector)
		testing.expectf(t, qerr == nil, "expected pg_stat_ssl query success, got %v", qerr)
		if len(collector.rows) == 1 && len(collector.rows[0]) == 1 {
			testing.expect_value(t, collector.rows[0][0], expected)
		} else {
			testing.fail_now(t, "expected exactly one row from pg_stat_ssl")
		}
	}

	@(test)
	test_integration_tls_require :: proc(t: ^testing.T) {
		integration_expect_ssl(t, .Require, "t")
	}

	@(test)
	test_integration_tls_prefer_default :: proc(t: ^testing.T) {
		// Zero value of SSL_Mode is Prefer: the default upgrades to TLS
		// against an ssl-enabled server.
		integration_expect_ssl(t, .Prefer, "t")
	}

	@(test)
	test_integration_tls_disable :: proc(t: ^testing.T) {
		integration_expect_ssl(t, .Disable, "f")
	}

	@(test)
	test_integration_tls_query_roundtrip :: proc(t: ^testing.T) {
		cfg := integration_conn_config(t)
		cfg.ssl_mode = .Require

		conn, err := conn_connect(cfg, context.allocator)
		testing.expectf(t, err == nil, "expected TLS connect success, got %v", err)
		if conn == nil {
			return
		}
		defer integration_disconnect(conn)

		collector: Test_Query_Collector
		collector.allocator = context.allocator
		collector.rows = make([dynamic][dynamic]string, context.allocator)
		defer integration_collector_destroy(&collector)

		qerr := conn_query(conn, "SELECT generate_series(1, 100);", test_on_row, test_on_command, test_on_desc, &collector)
		testing.expectf(t, qerr == nil, "expected TLS query success, got %v", qerr)
		testing.expect_value(t, len(collector.rows), 100)
		testing.expect_value(t, conn.status, Conn_Status.Ready)
	}

	@(test)
	test_integration_tls_active_backend_matches_platform :: proc(t: ^testing.T) {
		loaded := tls_ensure_loaded()
		testing.expect(t, loaded, "expected TLS to load on integration test host")
		btype := tls_backend_type()
		bname := tls_backend_name()

		when ODIN_OS == .Linux {
			testing.expect_value(t, btype, TLS_Backend_Type.OpenSSL)
			testing.expect_value(t, bname, "OpenSSL")
		} else when ODIN_OS == .Darwin {
			testing.expect_value(t, btype, TLS_Backend_Type.SecureTransport)
			testing.expect_value(t, bname, "SecureTransport")
		} else when ODIN_OS == .Windows {
			testing.expect_value(t, btype, TLS_Backend_Type.Schannel)
			testing.expect_value(t, bname, "Schannel")
		}
	}

	@(test)
	test_integration_read_timeout_is_enforced :: proc(t: ^testing.T) {
		// Conn_Config's read_timeout has to reach the socket, not just be
		// recorded on the transport. pg_sleep outlasts the deadline, so a
		// working timeout is the only thing that can end this query.
		cfg := integration_conn_config(t)
		cfg.read_timeout = 250 * time.Millisecond

		conn, err := conn_connect(cfg, context.allocator)
		testing.expectf(t, err == nil, "expected connect success, got %v", err)
		if conn == nil {
			return
		}
		defer integration_disconnect(conn)

		start := time.now()
		qerr := conn_query(conn, "SELECT pg_sleep(5);", nil, nil, nil, nil)
		elapsed := time.since(start)

		nerr, is_net := qerr.(pgerr.Net_Error)
		testing.expectf(t, is_net, "expected a Net_Error from the read deadline, got %v", qerr)
		testing.expect_value(t, nerr.type, pgerr.Net_Error_Type.Timeout)
		testing.expectf(
			t,
			elapsed < 3 * time.Second,
			"query ran %v against a 250ms read timeout; the deadline was not applied",
			elapsed,
		)
	}

	@(test)
	test_integration_no_timeout_outlasts_slow_query :: proc(t: ^testing.T) {
		// The complement: with no timeout configured (the zero value) a query
		// slower than any default must still complete, so the deadline work
		// cannot have introduced a spurious one.
		cfg := integration_conn_config(t)

		conn, err := conn_connect(cfg, context.allocator)
		testing.expectf(t, err == nil, "expected connect success, got %v", err)
		if conn == nil {
			return
		}
		defer integration_disconnect(conn)

		qerr := conn_query(conn, "SELECT pg_sleep(1);", nil, nil, nil, nil)
		testing.expectf(t, qerr == nil, "expected the slow query to complete, got %v", qerr)
	}

} // when OPG_INTEGRATION
