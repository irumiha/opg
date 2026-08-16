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

	/*
		get_test_conn_config resolves the integration endpoint through the
		pgconn harness, so every suite in a run targets the same server:
		compose defaults, overridden by PG* environment variables. Keeping the
		resolution in one place is what stops PGHOST from being honored by some
		suites and ignored by others.
	*/
	get_test_conn_config :: proc(t: ^testing.T) -> opg.Conn_Config {
		return pgconn.integration_conn_config(t)
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
			rel_err := opg.pool_release(task.pool, conn)

			if qerr != nil || rel_err != nil || row.val != i32(task.worker_id * 1000 + i) {
				task.err_occurred = true
				return
			}
			task.success_cnt += 1
		}
	}

	@(test)
	test_e2e_high_concurrency_pool_stress :: proc(t: ^testing.T) {
		pool_cfg := opg.Pool_Config{
			conn_config     = get_test_conn_config(t),
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
		row_count:   int,
		sum:         i64,
		column_name: string,
		command_tag: string,
		peak_bytes:  int,
	}

	large_stream_on_row :: proc(user_data: rawptr, row: opg.Data_Row) -> bool {
		c := (^Large_Stream_Collector)(user_data)
		c.row_count += 1
		if len(row.values) > 0 && !row.values[0].is_null {
			val, _ := strconv.parse_i64(string(row.values[0].data))
			c.sum += val
		}
		return true
	}

	large_stream_on_desc :: proc(user_data: rawptr, desc: opg.Row_Description) {
		c := (^Large_Stream_Collector)(user_data)
		if len(desc.fields) > 0 {
			c.column_name = strings.clone(desc.fields[0].name, context.allocator)
		}
	}

	large_stream_on_command :: proc(user_data: rawptr, tag: string, rows_affected: i64) {
		c := (^Large_Stream_Collector)(user_data)
		c.command_tag = strings.clone(tag, context.allocator)
	}

	@(test)
	test_e2e_large_dataset_streaming :: proc(t: ^testing.T) {
		// Deliberately routed through the public opg.query_stream rather than
		// pgconn.conn_query: streaming 100k rows through the facade is the
		// thing OPG-402 asks for, and calling the layer underneath would leave
		// the facade's callback forwarding untested.
		track: mem.Tracking_Allocator
		mem.tracking_allocator_init(&track, context.allocator)
		defer mem.tracking_allocator_destroy(&track)
		context.allocator = mem.tracking_allocator(&track)

		conn, cerr := opg.connect(get_test_conn_config(t), context.allocator)
		testing.expect(t, cerr == nil, "connect failed")
		if cerr != nil do return
		defer opg.disconnect(conn)

		baseline := track.current_memory_allocated

		collector: Large_Stream_Collector
		qerr := opg.query_stream(
			conn       = conn,
			sql        = "SELECT generate_series(1, 100000) AS n;",
			on_row     = large_stream_on_row,
			on_command = large_stream_on_command,
			on_desc    = large_stream_on_desc,
			user_data  = &collector,
		)
		defer delete(collector.column_name, context.allocator)
		defer delete(collector.command_tag, context.allocator)

		testing.expect_value(t, qerr, nil)
		testing.expect_value(t, collector.row_count, 100000)
		// Sum of 1..100,000 = (100000 * 100001) / 2 = 5000050000
		testing.expect_value(t, collector.sum, i64(5000050000))

		// The optional callbacks must reach the caller, not be dropped by the
		// facade's forwarding.
		testing.expect_value(t, collector.column_name, "n")
		testing.expect_value(t, collector.command_tag, "SELECT 100000")

		// "Without memory explosion" is the actual acceptance criterion, so
		// measure it: streaming must not retain per-row allocations. The bound
		// is generous — the point is to catch accumulation proportional to
		// 100k rows, which would run to megabytes.
		growth := track.peak_memory_allocated - baseline
		testing.expectf(
			t,
			growth < 1 << 20,
			"streaming 100k rows grew peak memory by %d bytes; expected the stream buffer not to accumulate rows",
			growth,
		)
	}

	// ------------------------------------------------------------------------
	// 3. Error Handling & SQLSTATE Verification
	// ------------------------------------------------------------------------

	@(test)
	test_e2e_sqlstate_syntax_error :: proc(t: ^testing.T) {
		conn, cerr := opg.connect(get_test_conn_config(t), context.allocator)
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
		// SQLSTATE is always five characters, so it is captured inline. An
		// allocated copy would be owned by this worker's allocator and freed
		// by the test's, which are not the same one.
		sqlstate:     [5]byte,
	}

	cancel_worker_proc :: proc(t: ^thread.Thread) {
		task := (^Cancel_Task)(t.data)
		_, err := opg.exec(task.conn, "SELECT pg_sleep(5);")
		if err != nil {
			task.err_occurred = true
			if pg_err, is_pg := err.(opg.Postgres_Error); is_pg {
				// Errors raised during execution are cloned into the temp
				// allocator (unlike connect errors, which the caller owns), so
				// the code is copied out here and the original is not freed.
				copy(task.sqlstate[:], pg_err.code)
			}
		}
	}

	@(test)
	test_e2e_query_cancellation :: proc(t: ^testing.T) {
		cfg := get_test_conn_config(t)

		conn, cerr := opg.connect(cfg, context.allocator)
		testing.expect(t, cerr == nil, "connect failed")
		if cerr != nil do return
		defer opg.disconnect(conn)

		// A second connection watches for the sleep to actually start. Timing
		// the cancel off a fixed sleep races in both directions: too early and
		// the cancel arrives before the query, too late on a loaded runner and
		// the query may already be gone.
		observer, oerr := opg.connect(cfg, context.allocator)
		testing.expect(t, oerr == nil, "observer connect failed")
		if oerr != nil do return
		defer opg.disconnect(observer)

		task := Cancel_Task{conn = conn}
		worker := thread.create(cancel_worker_proc)
		worker.data = rawptr(&task)
		thread.start(worker)

		Active_Count :: struct {
			cnt: i64,
		}
		running := false
		for _ in 0 ..< 250 {
			row, qerr := opg.query_struct(
				observer,
				Active_Count,
				"SELECT count(*) AS cnt FROM pg_stat_activity WHERE pid = $1 AND state = 'active' AND query LIKE '%pg_sleep%';",
				conn.backend_pid,
			)
			if qerr == nil && row.cnt > 0 {
				running = true
				break
			}
			time.sleep(time.Millisecond * 20)
		}
		testing.expect(t, running, "query never became active on the server")

		// Send cancel request via out-of-band TCP connection
		cancel_err := pgconn.conn_cancel(conn)
		testing.expect_value(t, cancel_err, nil)

		thread.join(worker)
		thread.destroy(worker)

		testing.expect(t, task.err_occurred, "expected query to be cancelled")
		// Assert the specific SQLSTATE. Accepting any error would also pass on
		// a dropped connection or a syntax error, which is not what this test
		// is about.
		testing.expect_value(t, string(task.sqlstate[:]), "57014") // query_canceled
	}
}
