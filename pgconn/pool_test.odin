package pgconn

import "core:mem"
import "core:sync"
import "core:testing"
import "core:thread"
import "core:time"
import "../pgerr"

// ----------------------------------------------------------------------------
// Mock dialer: creates ready connections backed by Mock_Transport, no network.
// Safe for concurrent use (pool_acquire dials outside the pool lock).
// ----------------------------------------------------------------------------

Mock_Pool_Dialer :: struct {
	mutex:        sync.Mutex,
	transports:   [dynamic]^Mock_Transport,
	allocator:    mem.Allocator,
	dial_count:   int,
	fail_at_dial: int, // one-shot: fail the Nth dial (1-based); 0 = never fail
}

mock_dialer_init :: proc(d: ^Mock_Pool_Dialer, allocator := context.allocator) {
	d.allocator = allocator
	d.transports = make([dynamic]^Mock_Transport, allocator)
}

mock_dialer_destroy :: proc(d: ^Mock_Pool_Dialer) {
	for m in d.transports {
		mock_transport_destroy(m)
		free(m, d.allocator)
	}
	delete(d.transports)
}

mock_pool_dial :: proc(data: rawptr, config: Conn_Config, allocator: mem.Allocator) -> (conn: ^Conn, err: pgerr.Error) {
	d := (^Mock_Pool_Dialer)(data)
	sync.mutex_lock(&d.mutex)
	defer sync.mutex_unlock(&d.mutex)

	if d.fail_at_dial > 0 && d.dial_count + 1 == d.fail_at_dial {
		d.fail_at_dial = 0
		return nil, pgerr.Net_Error{type = .Connection_Refused}
	}

	m := new(Mock_Transport, d.allocator)
	mock_transport_init(m, d.allocator)
	append(&d.transports, m)
	d.dial_count += 1

	c := new(Conn, allocator)
	c.allocator = allocator
	c.status = .Ready
	c.last_active = time.now()
	c.parameters = make(map[string]string, 4, allocator)
	c.prepared_statements = make(map[string]Prepared_Statement, 4, allocator)
	stream_init(&c.stream, make_mock_transport(m), allocator = allocator)
	return c, nil
}

make_test_pool_config :: proc(d: ^Mock_Pool_Dialer, min_conns, max_conns: int) -> Pool_Config {
	return Pool_Config{
		conn_config = Conn_Config{host = "mock", port = 5432, user = "test", database = "testdb"},
		min_conns = min_conns,
		max_conns = max_conns,
		connect_fn = mock_pool_dial,
		connect_data = d,
	}
}

// ----------------------------------------------------------------------------
// pool_init / pool_destroy
// ----------------------------------------------------------------------------

@(test)
test_pool_init_invalid_config :: proc(t: ^testing.T) {
	dialer: Mock_Pool_Dialer
	mock_dialer_init(&dialer)
	defer mock_dialer_destroy(&dialer)

	// max_conns == 0
	cfg := make_test_pool_config(&dialer, 0, 0)
	p, err := pool_init(cfg)
	testing.expect(t, p == nil, "expected nil pool for max_conns == 0")
	perr, ok := err.(pgerr.Pool_Error)
	testing.expect(t, ok, "expected Pool_Error")
	testing.expect_value(t, perr.type, pgerr.Pool_Error_Type.Invalid_Config)

	// min_conns < 0
	cfg2 := make_test_pool_config(&dialer, -1, 4)
	p2, err2 := pool_init(cfg2)
	testing.expect(t, p2 == nil, "expected nil pool for negative min_conns")
	perr2, ok2 := err2.(pgerr.Pool_Error)
	testing.expect(t, ok2, "expected Pool_Error")
	testing.expect_value(t, perr2.type, pgerr.Pool_Error_Type.Invalid_Config)

	// min_conns > max_conns
	cfg3 := make_test_pool_config(&dialer, 5, 4)
	p3, err3 := pool_init(cfg3)
	testing.expect(t, p3 == nil, "expected nil pool for min > max")
	perr3, ok3 := err3.(pgerr.Pool_Error)
	testing.expect(t, ok3, "expected Pool_Error")
	testing.expect_value(t, perr3.type, pgerr.Pool_Error_Type.Invalid_Config)

	testing.expect_value(t, dialer.dial_count, 0)
}

@(test)
test_pool_init_prewarm_and_destroy :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	dialer: Mock_Pool_Dialer
	mock_dialer_init(&dialer)

	pool, err := pool_init(make_test_pool_config(&dialer, 2, 4))
	testing.expect(t, err == nil, "expected pool_init success")
	testing.expect(t, pool != nil, "expected non-nil pool")
	testing.expect_value(t, dialer.dial_count, 2)
	testing.expect_value(t, len(pool.available), 2)
	testing.expect_value(t, len(pool.in_use), 0)
	for c in pool.available {
		testing.expect_value(t, c.status, Conn_Status.Ready)
	}

	pool_destroy(pool)
	for m in dialer.transports {
		testing.expect(t, m.is_closed, "expected transport closed after pool_destroy")
	}

	mock_dialer_destroy(&dialer)
	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
test_pool_init_prewarm_failure_cleanup :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	dialer: Mock_Pool_Dialer
	mock_dialer_init(&dialer)
	dialer.fail_at_dial = 2 // first dial succeeds, second fails

	pool, err := pool_init(make_test_pool_config(&dialer, 2, 4))
	testing.expect(t, pool == nil, "expected nil pool on pre-warm failure")
	nerr, ok := err.(pgerr.Net_Error)
	testing.expect(t, ok, "expected Net_Error from failed dial")
	testing.expect_value(t, nerr.type, pgerr.Net_Error_Type.Connection_Refused)
	testing.expect_value(t, dialer.dial_count, 1)
	testing.expect(t, dialer.transports[0].is_closed, "expected first conn cleaned up")

	mock_dialer_destroy(&dialer)
	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
test_pool_destroy_nil :: proc(t: ^testing.T) {
	pool_destroy(nil) // must not crash
	testing.expect(t, true, "pool_destroy(nil) is a no-op")
}

// ----------------------------------------------------------------------------
// pool_acquire / pool_release fast path
// ----------------------------------------------------------------------------

@(test)
test_pool_acquire_reuse_and_dial :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	dialer: Mock_Pool_Dialer
	mock_dialer_init(&dialer)

	pool, err := pool_init(make_test_pool_config(&dialer, 1, 2))
	testing.expect(t, err == nil, "expected pool_init success")

	// Reuses the pre-warmed connection, no new dial.
	c1, err1 := pool_acquire(pool)
	testing.expect(t, err1 == nil, "expected acquire success")
	testing.expect(t, c1 != nil, "expected connection")
	testing.expect_value(t, dialer.dial_count, 1)
	testing.expect_value(t, len(pool.in_use), 1)

	// Second acquire dials a fresh connection (pool empty, below max).
	c2, err2 := pool_acquire(pool)
	testing.expect(t, err2 == nil, "expected acquire success")
	testing.expect(t, c2 != nil && c2 != c1, "expected distinct second connection")
	testing.expect_value(t, dialer.dial_count, 2)
	testing.expect_value(t, len(pool.in_use), 2)
	testing.expect_value(t, len(pool.available), 0)

	// Release both; LIFO reuse returns the most recently released.
	testing.expect(t, pool_release(pool, c1) == nil, "expected release success")
	testing.expect(t, pool_release(pool, c2) == nil, "expected release success")
	testing.expect_value(t, len(pool.available), 2)
	testing.expect_value(t, len(pool.in_use), 0)

	c3, err3 := pool_acquire(pool)
	testing.expect(t, err3 == nil, "expected acquire success")
	testing.expect(t, c3 == c2, "expected LIFO reuse of last released conn")
	testing.expect_value(t, dialer.dial_count, 2)
	testing.expect(t, pool_release(pool, c3) == nil, "expected release success")

	pool_destroy(pool)
	mock_dialer_destroy(&dialer)
	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
test_pool_acquire_timeout_when_exhausted :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	dialer: Mock_Pool_Dialer
	mock_dialer_init(&dialer)

	cfg := make_test_pool_config(&dialer, 0, 1)
	cfg.acquire_timeout = 20 * time.Millisecond // default used when param is 0
	pool, err := pool_init(cfg)
	testing.expect(t, err == nil, "expected pool_init success")

	c1, err1 := pool_acquire(pool)
	testing.expect(t, err1 == nil, "expected first acquire success")

	// Explicit timeout param.
	c2, err2 := pool_acquire(pool, 20 * time.Millisecond)
	testing.expect(t, c2 == nil, "expected nil conn on timeout")
	perr, ok := err2.(pgerr.Pool_Error)
	testing.expect(t, ok, "expected Pool_Error")
	testing.expect_value(t, perr.type, pgerr.Pool_Error_Type.Acquire_Timeout)

	// Config default timeout (param 0).
	c3, err3 := pool_acquire(pool)
	testing.expect(t, c3 == nil, "expected nil conn on default timeout")
	perr3, ok3 := err3.(pgerr.Pool_Error)
	testing.expect(t, ok3, "expected Pool_Error")
	testing.expect_value(t, perr3.type, pgerr.Pool_Error_Type.Acquire_Timeout)

	testing.expect(t, pool_release(pool, c1) == nil, "expected release success")
	pool_destroy(pool)
	mock_dialer_destroy(&dialer)
	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
test_pool_acquire_dial_failure :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	dialer: Mock_Pool_Dialer
	mock_dialer_init(&dialer)
	dialer.fail_at_dial = 1

	pool, err := pool_init(make_test_pool_config(&dialer, 0, 2))
	testing.expect(t, err == nil, "expected pool_init success (no pre-warm)")

	c1, err1 := pool_acquire(pool)
	testing.expect(t, c1 == nil, "expected nil conn on dial failure")
	nerr, ok := err1.(pgerr.Net_Error)
	testing.expect(t, ok, "expected Net_Error")
	testing.expect_value(t, nerr.type, pgerr.Net_Error_Type.Connection_Refused)
	testing.expect_value(t, pool.pending_dials, 0)

	// One-shot failure cleared: next acquire succeeds.
	c2, err2 := pool_acquire(pool)
	testing.expect(t, err2 == nil, "expected acquire success after failure")
	testing.expect(t, c2 != nil, "expected connection")
	testing.expect(t, pool_release(pool, c2) == nil, "expected release success")

	pool_destroy(pool)
	mock_dialer_destroy(&dialer)
	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
test_pool_acquire_idle_recycle :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	dialer: Mock_Pool_Dialer
	mock_dialer_init(&dialer)

	cfg := make_test_pool_config(&dialer, 1, 2)
	cfg.idle_timeout = time.Millisecond
	pool, err := pool_init(cfg)
	testing.expect(t, err == nil, "expected pool_init success")

	time.sleep(10 * time.Millisecond)

	// Pre-warmed conn exceeded idle_timeout: destroyed, fresh one dialed.
	c1, err1 := pool_acquire(pool)
	testing.expect(t, err1 == nil, "expected acquire success")
	testing.expect(t, c1 != nil, "expected connection")
	testing.expect_value(t, dialer.dial_count, 2)
	testing.expect(t, dialer.transports[0].is_closed, "expected stale conn closed")

	testing.expect(t, pool_release(pool, c1) == nil, "expected release success")
	pool_destroy(pool)
	mock_dialer_destroy(&dialer)
	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
test_pool_acquire_nil_pool :: proc(t: ^testing.T) {
	c, err := pool_acquire(nil)
	testing.expect(t, c == nil, "expected nil conn from nil pool")
	perr, ok := err.(pgerr.Pool_Error)
	testing.expect(t, ok, "expected Pool_Error")
	testing.expect_value(t, perr.type, pgerr.Pool_Error_Type.Pool_Closed)
}

// ----------------------------------------------------------------------------
// pool_release reset & destruction paths
// ----------------------------------------------------------------------------

@(test)
test_pool_release_resets_in_transaction :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	dialer: Mock_Pool_Dialer
	mock_dialer_init(&dialer)

	pool, err := pool_init(make_test_pool_config(&dialer, 1, 1))
	testing.expect(t, err == nil, "expected pool_init success")

	c1, err1 := pool_acquire(pool)
	testing.expect(t, err1 == nil, "expected acquire success")

	// Simulate a query that left an open transaction, with the mock server
	// ready to answer the pool's ROLLBACK:
	//   CommandComplete "ROLLBACK" + ReadyForQuery 'I'
	c1.status = .In_Transaction
	rollback_complete := []byte{'C', 0, 0, 0, 13, 'R', 'O', 'L', 'L', 'B', 'A', 'C', 'K', 0}
	rfq_idle := []byte{'Z', 0, 0, 0, 5, 'I'}
	append(&dialer.transports[0].read_chunks, rollback_complete)
	append(&dialer.transports[0].read_chunks, rfq_idle)

	testing.expect(t, pool_release(pool, c1) == nil, "expected release success")

	// The pool must have sent a simple query ('Q') containing ROLLBACK.
	written := dialer.transports[0].written_bytes
	testing.expect(t, len(written) > 0 && written[0] == 'Q', "expected simple query sent on release")

	// Connection was reset and pooled, not destroyed.
	testing.expect_value(t, len(pool.available), 1)
	testing.expect_value(t, pool.pending_resets, 0)

	c2, err2 := pool_acquire(pool)
	testing.expect(t, err2 == nil, "expected re-acquire success")
	testing.expect(t, c2 == c1, "expected same connection back after reset")
	testing.expect_value(t, c2.status, Conn_Status.Ready)
	testing.expect(t, pool_release(pool, c2) == nil, "expected release success")

	pool_destroy(pool)
	mock_dialer_destroy(&dialer)
	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
test_pool_release_destroys_on_failed_reset :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	dialer: Mock_Pool_Dialer
	mock_dialer_init(&dialer)

	pool, err := pool_init(make_test_pool_config(&dialer, 1, 1))
	testing.expect(t, err == nil, "expected pool_init success")

	c1, err1 := pool_acquire(pool)
	testing.expect(t, err1 == nil, "expected acquire success")

	// Open transaction but the socket delivers nothing: ROLLBACK read fails
	// with Socket_Closed, so the pool must destroy the connection.
	c1.status = .In_Transaction

	testing.expect(t, pool_release(pool, c1) == nil, "expected release to succeed even when conn is destroyed")
	testing.expect_value(t, len(pool.available), 0)
	testing.expect_value(t, len(pool.in_use), 0)
	testing.expect_value(t, pool.pending_resets, 0)
	testing.expect(t, dialer.transports[0].is_closed, "expected broken conn closed")

	// Slot was freed: a fresh acquire dials a new connection.
	c2, err2 := pool_acquire(pool)
	testing.expect(t, err2 == nil, "expected acquire success after destroy")
	testing.expect_value(t, dialer.dial_count, 2)
	testing.expect(t, pool_release(pool, c2) == nil, "expected release success")

	pool_destroy(pool)
	mock_dialer_destroy(&dialer)
	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
test_pool_release_foreign_connection :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	dialer: Mock_Pool_Dialer
	mock_dialer_init(&dialer)

	pool, err := pool_init(make_test_pool_config(&dialer, 0, 2))
	testing.expect(t, err == nil, "expected pool_init success")

	// A connection the pool never dialed.
	foreign_mock: Mock_Transport
	mock_transport_init(&foreign_mock)
	outsider := new(Conn, context.allocator)
	outsider.allocator = context.allocator
	outsider.status = .Ready
	stream_init(&outsider.stream, make_mock_transport(&foreign_mock), allocator = context.allocator)

	rerr := pool_release(pool, outsider)
	perr, ok := rerr.(pgerr.Pool_Error)
	testing.expect(t, ok, "expected Pool_Error")
	testing.expect_value(t, perr.type, pgerr.Pool_Error_Type.Foreign_Connection)
	testing.expect_value(t, len(pool.available), 0)

	// nil connection
	rerr2 := pool_release(pool, nil)
	perr2, ok2 := rerr2.(pgerr.Pool_Error)
	testing.expect(t, ok2, "expected Pool_Error")
	testing.expect_value(t, perr2.type, pgerr.Pool_Error_Type.Foreign_Connection)

	// Double release
	c1, err1 := pool_acquire(pool)
	testing.expect(t, err1 == nil, "expected acquire success")
	testing.expect(t, pool_release(pool, c1) == nil, "expected first release success")
	rerr3 := pool_release(pool, c1)
	perr3, ok3 := rerr3.(pgerr.Pool_Error)
	testing.expect(t, ok3, "expected Pool_Error on double release")
	testing.expect_value(t, perr3.type, pgerr.Pool_Error_Type.Foreign_Connection)

	conn_close(outsider)
	free(outsider, context.allocator)
	mock_transport_destroy(&foreign_mock)

	pool_destroy(pool)
	mock_dialer_destroy(&dialer)
	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
test_pool_release_destroys_dead_conn :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	dialer: Mock_Pool_Dialer
	mock_dialer_init(&dialer)

	pool, err := pool_init(make_test_pool_config(&dialer, 0, 1))
	testing.expect(t, err == nil, "expected pool_init success")

	c1, err1 := pool_acquire(pool)
	testing.expect(t, err1 == nil, "expected acquire success")

	// Simulate a detected socket drop: no reset attempted, conn destroyed.
	c1.status = .Disconnected

	testing.expect(t, pool_release(pool, c1) == nil, "expected release success")
	testing.expect_value(t, len(pool.available), 0)
	testing.expect_value(t, len(pool.in_use), 0)
	// No ROLLBACK was attempted on a dead conn.
	testing.expect_value(t, len(dialer.transports[0].written_bytes), 0)

	pool_destroy(pool)
	mock_dialer_destroy(&dialer)
	testing.expect_value(t, len(track.allocation_map), 0)
}

// ----------------------------------------------------------------------------
// Concurrency
// ----------------------------------------------------------------------------

Blocked_Acquire_State :: struct {
	pool:      ^Pool,
	got_conn:  bool,
	got_error: bool,
}

blocked_acquire_proc :: proc(s: ^Blocked_Acquire_State) {
	conn, err := pool_acquire(s.pool, 5 * time.Second)
	if err != nil || conn == nil {
		s.got_error = true
		return
	}
	s.got_conn = true
	_ = pool_release(s.pool, conn)
}

@(test)
test_pool_acquire_blocks_until_release :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	dialer: Mock_Pool_Dialer
	mock_dialer_init(&dialer)

	pool, err := pool_init(make_test_pool_config(&dialer, 0, 1))
	testing.expect(t, err == nil, "expected pool_init success")

	c1, err1 := pool_acquire(pool)
	testing.expect(t, err1 == nil, "expected acquire success")

	state := Blocked_Acquire_State{pool = pool}
	th := thread.create_and_start_with_poly_data(&state, blocked_acquire_proc)

	time.sleep(20 * time.Millisecond) // let the worker block at capacity
	testing.expect(t, pool_release(pool, c1) == nil, "expected release success")

	thread.join(th)
	thread.destroy(th)

	testing.expect(t, state.got_conn, "expected blocked acquirer to obtain the released conn")
	testing.expect_value(t, dialer.dial_count, 1) // max_conns respected: never dialed a second conn
	testing.expect_value(t, len(pool.in_use), 0)

	pool_destroy(pool)
	mock_dialer_destroy(&dialer)
	testing.expect_value(t, len(track.allocation_map), 0)
}

destroy_pool_proc :: proc(s: ^Blocked_Acquire_State) {
	pool_destroy(s.pool)
}

@(test)
test_pool_destroy_waits_for_in_use :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	dialer: Mock_Pool_Dialer
	mock_dialer_init(&dialer)

	pool, err := pool_init(make_test_pool_config(&dialer, 0, 1))
	testing.expect(t, err == nil, "expected pool_init success")

	c1, err1 := pool_acquire(pool)
	testing.expect(t, err1 == nil, "expected acquire success")

	// Worker B blocks waiting for a conn; worker C destroys the pool while
	// c1 is still borrowed. Destroy must wake B (Pool_Closed or, if B wins
	// the race with a released conn, a normal acquire+release) and must not
	// return until c1 is released.
	waiter := Blocked_Acquire_State{pool = pool}
	th_b := thread.create_and_start_with_poly_data(&waiter, blocked_acquire_proc)
	time.sleep(20 * time.Millisecond)

	destroyer := Blocked_Acquire_State{pool = pool}
	th_c := thread.create_and_start_with_poly_data(&destroyer, destroy_pool_proc)
	time.sleep(20 * time.Millisecond)

	// Releasing the borrowed conn lets pool_destroy finish draining.
	testing.expect(t, pool_release(pool, c1) == nil, "expected release success")

	thread.join(th_b)
	thread.join(th_c)
	thread.destroy(th_b)
	thread.destroy(th_c)

	testing.expect(t, waiter.got_conn || waiter.got_error, "expected waiter to finish either way")
	for m in dialer.transports {
		testing.expect(t, m.is_closed, "expected all transports closed after destroy")
	}

	mock_dialer_destroy(&dialer)
	testing.expect_value(t, len(track.allocation_map), 0)
}

Stress_Worker :: struct {
	pool:      ^Pool,
	iters:     int,
	successes: int,
	failures:  int,
}

stress_worker_proc :: proc(w: ^Stress_Worker) {
	for _ in 0 ..< w.iters {
		conn, err := pool_acquire(w.pool, 5 * time.Second)
		if err != nil || conn == nil {
			w.failures += 1
			continue
		}
		w.successes += 1
		if pool_release(w.pool, conn) != nil {
			w.failures += 1
		}
	}
}

@(test)
test_pool_stress_concurrent_acquire_release :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	dialer: Mock_Pool_Dialer
	mock_dialer_init(&dialer)

	pool, err := pool_init(make_test_pool_config(&dialer, 2, 8))
	testing.expect(t, err == nil, "expected pool_init success")

	NUM_THREADS :: 50
	ITERS :: 40

	workers: [NUM_THREADS]Stress_Worker
	threads: [NUM_THREADS]^thread.Thread
	for i in 0 ..< NUM_THREADS {
		workers[i] = Stress_Worker{pool = pool, iters = ITERS}
		threads[i] = thread.create_and_start_with_poly_data(&workers[i], stress_worker_proc)
	}
	for i in 0 ..< NUM_THREADS {
		thread.join(threads[i])
		thread.destroy(threads[i])
	}

	total_success, total_failure := 0, 0
	for i in 0 ..< NUM_THREADS {
		total_success += workers[i].successes
		total_failure += workers[i].failures
	}
	testing.expect_value(t, total_failure, 0)
	testing.expect_value(t, total_success, NUM_THREADS * ITERS)

	testing.expect_value(t, len(pool.in_use), 0)
	testing.expect_value(t, pool.pending_dials, 0)
	testing.expect_value(t, pool.pending_resets, 0)
	testing.expect(t, len(pool.available) <= 8, "expected max_conns respected")
	testing.expect(t, dialer.dial_count <= 8, "expected at most max_conns dials")

	pool_destroy(pool)
	for m in dialer.transports {
		testing.expect(t, m.is_closed, "expected all transports closed")
	}
	mock_dialer_destroy(&dialer)
	testing.expect_value(t, len(track.allocation_map), 0)
}
