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

} // when OPG_INTEGRATION
