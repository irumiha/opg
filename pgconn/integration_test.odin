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

} // when OPG_INTEGRATION
