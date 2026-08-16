package tests

@(require) import "core:mem"
@(require) import "core:os"
@(require) import "core:strconv"
@(require) import "core:strings"
@(require) import "core:sync"
@(require) import "core:testing"
@(require) import "core:thread"
@(require) import "core:time"
@(require) import ".."
@(require) import "../pgconn"
@(require) import "../pgerr"
@(require) import "../pgmap"
@(require) import "../pgproto"

OPG_INTEGRATION :: #config(OPG_INTEGRATION, false)

when OPG_INTEGRATION {

	get_integration_port :: proc() -> int {
		if env_port := os.get_env("PGPORT", context.temp_allocator); env_port != "" {
			if p, ok := strconv.parse_int(env_port); ok do return p
		}
		port_state, port_out, _, port_err := os.process_exec(
			{command = {"docker", "compose", "port", "postgres", "5432"}},
			context.temp_allocator,
		)
		if port_err == nil && port_state.success {
			endpoint := strings.trim_space(string(port_out))
			colon := strings.last_index_byte(endpoint, ':')
			if colon >= 0 {
				if parsed, ok := strconv.parse_int(endpoint[colon + 1:]); ok {
					return parsed
				}
			}
		}
		return 5432
	}

	get_test_conn_config :: proc() -> opg.Conn_Config {
		return opg.Conn_Config{
			host     = "127.0.0.1",
			port     = get_integration_port(),
			user     = "opg",
			password = "opg",
			database = "opg_test",
		}
	}

	// ------------------------------------------------------------------------
	// 1. High Concurrency Pool Stress Test (100 Concurrent Workers)
	// ------------------------------------------------------------------------

	Worker_Task :: struct {
		pool:        ^opg.Pool,
		worker_id:   int,
		iterations:  int,
		success_cnt: int,
		err_occurred: bool,
	}

	worker_proc :: proc(t: ^thread.Thread) {
		task := (^Worker_Task)(t.data)
		for i in 0 ..< task.iterations {
			conn, err := opg.pool_acquire(task.pool, time.Second * 10)
			if err != nil {
				task.err_occurred = true
				return
			}

			Number_Row :: struct {
				val: i32 `db:"val"`,
			}
			row, qerr := opg.query_struct(conn, Number_Row, "SELECT $1::int AS val;", i32(task.worker_id * 1000 + i))
			opg.pool_release(task.pool, conn)

			if qerr != nil || row.val != i32(task.worker_id * 1000 + i) {
				task.err_occurred = true
				return
			}
			task.success_cnt += 1
		}
	}

	@(test)
	test_e2e_high_concurrency_pool_stress :: proc(t: ^testing.T) {
		pool_cfg := opg.Pool_Config{
			conn_config     = get_test_conn_config(),
			min_conns       = 2,
			max_conns       = 8,
			acquire_timeout = time.Second * 10,
		}

		pool, perr := opg.pool_create(pool_cfg, context.allocator)
		testing.expect(t, perr == nil, "pool_create failed")
		if perr != nil do return
		defer opg.pool_destroy(pool)

		NUM_WORKERS :: 100
		ITERATIONS_PER_WORKER :: 5

		threads: [NUM_WORKERS]^thread.Thread
		tasks: [NUM_WORKERS]Worker_Task

		for i in 0 ..< NUM_WORKERS {
			tasks[i] = Worker_Task{
				pool        = pool,
				worker_id   = i,
				iterations  = ITERATIONS_PER_WORKER,
			}
			threads[i] = thread.create(worker_proc)
			threads[i].data = rawptr(&tasks[i])
			thread.start(threads[i])
		}

		for i in 0 ..< NUM_WORKERS {
			thread.join(threads[i])
			thread.destroy(threads[i])
			testing.expect(t, !tasks[i].err_occurred, "worker encountered error")
			testing.expect_value(t, tasks[i].success_cnt, ITERATIONS_PER_WORKER)
		}
	}

	// ------------------------------------------------------------------------
	// 2. Large Dataset Streaming Test (100,000 Rows)
	// ------------------------------------------------------------------------

	Large_Stream_Collector :: struct {
		row_count: int,
		sum:       i64,
	}

	large_stream_on_row :: proc(user_data: rawptr, row: pgproto.Msg_Data_Row) -> bool {
		c := (^Large_Stream_Collector)(user_data)
		c.row_count += 1
		if len(row.values) > 0 && !row.values[0].is_null {
			val, _ := strconv.parse_i64(string(row.values[0].data))
			c.sum += val
		}
		return true
	}

	@(test)
	test_e2e_large_dataset_streaming :: proc(t: ^testing.T) {
		conn, cerr := opg.connect(get_test_conn_config(), context.allocator)
		testing.expect(t, cerr == nil, "connect failed")
		if cerr != nil do return
		defer opg.disconnect(conn)

		collector: Large_Stream_Collector
		qerr := pgconn.conn_query(
			conn       = conn,
			sql        = "SELECT generate_series(1, 100000) AS n;",
			on_row     = large_stream_on_row,
			user_data  = &collector,
		)
		testing.expect_value(t, qerr, nil)
		testing.expect_value(t, collector.row_count, 100000)
		// Sum of 1..100,000 = (100000 * 100001) / 2 = 5000050000
		testing.expect_value(t, collector.sum, i64(5000050000))
	}

	// ------------------------------------------------------------------------
	// 3. Error Handling & SQLSTATE Verification
	// ------------------------------------------------------------------------

	@(test)
	test_e2e_sqlstate_syntax_error :: proc(t: ^testing.T) {
		conn, cerr := opg.connect(get_test_conn_config(), context.allocator)
		testing.expect(t, cerr == nil, "connect failed")
		if cerr != nil do return
		defer opg.disconnect(conn)

		_, err := opg.exec(conn, "SELEC INVALID SYNTAX;")
		pg_err, is_pg := err.(opg.Postgres_Error)
		testing.expect(t, is_pg, "expected Postgres_Error")
		testing.expect_value(t, pg_err.severity, "ERROR")
		testing.expect_value(t, pg_err.code, "42601") // syntax_error
	}

	// ------------------------------------------------------------------------
	// 4. Query Cancellation
	// ------------------------------------------------------------------------

	Cancel_Task :: struct {
		conn:         ^opg.Conn,
		err_occurred: bool,
	}

	cancel_worker_proc :: proc(t: ^thread.Thread) {
		task := (^Cancel_Task)(t.data)
		_, err := opg.exec(task.conn, "SELECT pg_sleep(5);")
		if err != nil {
			task.err_occurred = true
		}
	}

	@(test)
	test_e2e_query_cancellation :: proc(t: ^testing.T) {
		conn, cerr := opg.connect(get_test_conn_config(), context.allocator)
		testing.expect(t, cerr == nil, "connect failed")
		if cerr != nil do return
		defer opg.disconnect(conn)

		task := Cancel_Task{conn = conn}
		worker := thread.create(cancel_worker_proc)
		worker.data = rawptr(&task)
		thread.start(worker)

		// Give the query a moment to reach pg_sleep
		time.sleep(time.Millisecond * 100)

		// Send cancel request via out-of-band TCP connection
		cancel_err := pgconn.conn_cancel(conn)
		testing.expect_value(t, cancel_err, nil)

		thread.join(worker)
		thread.destroy(worker)

		testing.expect(t, task.err_occurred, "expected query to be cancelled")
	}
}
