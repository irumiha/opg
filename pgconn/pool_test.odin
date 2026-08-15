package pgconn

import "core:mem"
import "core:sync"
import "core:testing"
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
