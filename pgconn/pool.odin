package pgconn

import "core:mem"
import "core:sync"
import "core:time"
import "../pgerr"

// ----------------------------------------------------------------------------
// Connection Pool State and Configuration
// ----------------------------------------------------------------------------

/*
	Pool_Connect_Proc dials and hands back a ready connection. `data` is the
	Pool_Config.connect_data pointer. Implementations must be safe to call
	from multiple threads concurrently: pool_acquire dials outside the pool
	lock so a slow handshake does not serialize other acquirers.
*/
Pool_Connect_Proc :: #type proc(data: rawptr, config: Conn_Config, allocator: mem.Allocator) -> (conn: ^Conn, err: pgerr.Error)

Pool_Config :: struct {
	conn_config:     Conn_Config,
	min_conns:       int,           // connections pre-warmed at init; must be in [0, max_conns]
	max_conns:       int,           // hard upper bound; must be > 0
	idle_timeout:    time.Duration, // 0 = pooled idle connections never expire
	acquire_timeout: time.Duration, // default when pool_acquire's timeout param is 0; 0 = wait forever
	connect_fn:      Pool_Connect_Proc, // nil = default_pool_connect (real TCP dial)
	connect_data:    rawptr,
}

/*
	Pool is a thread-safe connection pool. All list state is guarded by
	`mutex`; `cond` wakes blocked acquirers on release/slot-free and wakes
	pool_destroy's drain wait. Connections are dialed and reset outside the
	lock; `pending_dials`/`pending_resets` keep max_conns accounting and
	shutdown draining correct while those operations are in flight.

	Contract: pool_destroy must be called exactly once, must not race with
	new pool_acquire calls, and blocks until every borrowed connection has
	been released.
*/
Pool :: struct {
	mutex:          sync.Mutex,
	cond:           sync.Cond,
	config:         Pool_Config,
	allocator:      mem.Allocator, // persistent allocator (never context.temp_allocator)
	available:      [dynamic]^Conn,
	in_use:         [dynamic]^Conn,
	pending_dials:  int,
	pending_resets: int,
	is_closed:      bool,
}

default_pool_connect :: proc(data: rawptr, config: Conn_Config, allocator: mem.Allocator) -> (conn: ^Conn, err: pgerr.Error) {
	return conn_connect(config, allocator)
}

// Callers must hold pool.mutex.
pool_total_conns :: proc(pool: ^Pool) -> int {
	return len(pool.available) + len(pool.in_use) + pool.pending_dials
}

pool_destroy_conn :: proc(pool: ^Pool, conn: ^Conn) {
	conn_close(conn)
	free(conn, pool.allocator)
}

// ----------------------------------------------------------------------------
// Pool Management API
// ----------------------------------------------------------------------------

/*
	pool_init validates the configuration, pre-warms min_conns connections,
	and returns a ready pool. On any pre-warm dial failure the partially
	constructed pool is torn down and the dial error is returned.
*/
pool_init :: proc(
	config: Pool_Config,
	allocator := context.allocator,
) -> (
	pool: ^Pool,
	err: pgerr.Error,
) {
	if config.max_conns <= 0 || config.min_conns < 0 || config.min_conns > config.max_conns {
		return nil, pgerr.Pool_Error{
			type = .Invalid_Config,
			message = "pool config requires max_conns > 0 and 0 <= min_conns <= max_conns",
		}
	}

	p := new(Pool, allocator)
	p.config = config
	p.allocator = allocator
	if p.config.connect_fn == nil {
		p.config.connect_fn = default_pool_connect
	}
	p.available = make([dynamic]^Conn, 0, config.max_conns, allocator)
	p.in_use = make([dynamic]^Conn, 0, config.max_conns, allocator)

	for _ in 0 ..< config.min_conns {
		c, cerr := p.config.connect_fn(p.config.connect_data, p.config.conn_config, allocator)
		if cerr != nil {
			pool_destroy(p)
			return nil, cerr
		}
		append(&p.available, c)
	}
	return p, nil
}

/*
	pool_acquire is implemented in Task 2. Stub keeps the package compiling.
*/
pool_acquire :: proc(
	pool: ^Pool,
	timeout := time.Duration(0),
) -> (
	conn: ^Conn,
	err: pgerr.Error,
) {
	return nil, pgerr.Pool_Error{type = .Pool_Closed, message = "pool_acquire not implemented"}
}

/*
	pool_release is implemented in Tasks 2-3. Stub keeps the package compiling.
*/
pool_release :: proc(
	pool: ^Pool,
	conn: ^Conn,
) -> (
	err: pgerr.Error,
) {
	return pgerr.Pool_Error{type = .Foreign_Connection, message = "pool_release not implemented"}
}

/*
	pool_destroy closes the pool: wakes all blocked acquirers (they fail with
	Pool_Closed), waits until borrowed connections are released and in-flight
	dials/resets finish, then closes every idle connection and frees all pool
	memory. Safe on nil. Must be called exactly once per pool.
*/
pool_destroy :: proc(pool: ^Pool) {
	if pool == nil do return

	sync.mutex_lock(&pool.mutex)
	pool.is_closed = true
	sync.cond_broadcast(&pool.cond)

	for len(pool.in_use) > 0 || pool.pending_dials > 0 || pool.pending_resets > 0 {
		sync.cond_wait(&pool.cond, &pool.mutex)
	}

	for conn in pool.available {
		pool_destroy_conn(pool, conn)
	}
	delete(pool.available)
	delete(pool.in_use)
	sync.mutex_unlock(&pool.mutex)

	free(pool, pool.allocator)
}
