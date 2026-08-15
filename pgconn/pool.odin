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
	pool_acquire returns a healthy connection: reuses idle ones (LIFO,
	destroying any that died or exceeded idle_timeout), dials a new one when
	below max_conns, and otherwise blocks until a connection is released or
	the timeout elapses. timeout == 0 falls back to config.acquire_timeout;
	if that is also 0 the call waits indefinitely.

	The dial itself runs without the pool lock; pending_dials reserves the
	slot so concurrent acquirers cannot exceed max_conns.
*/
pool_acquire :: proc(
	pool: ^Pool,
	timeout := time.Duration(0),
) -> (
	conn: ^Conn,
	err: pgerr.Error,
) {
	if pool == nil {
		return nil, pgerr.Pool_Error{type = .Pool_Closed, message = "pool is nil"}
	}

	effective := timeout
	if effective <= 0 {
		effective = pool.config.acquire_timeout
	}
	deadline: time.Time
	if effective > 0 {
		deadline = time.time_add(time.now(), effective)
	}

	sync.mutex_lock(&pool.mutex)
	defer sync.mutex_unlock(&pool.mutex)

	for {
		if pool.is_closed {
			return nil, pgerr.Pool_Error{type = .Pool_Closed, message = "pool is closed"}
		}

		// 1. Reuse an idle connection if it is still healthy.
		for len(pool.available) > 0 {
			c := pop(&pool.available)
			stale := pool.config.idle_timeout > 0 && time.since(c.last_active) > pool.config.idle_timeout
			if !conn_is_alive(c) || stale {
				pool_destroy_conn(pool, c)
				continue
			}
			append(&pool.in_use, c)
			return c, nil
		}

		// 2. Below capacity: dial a new connection outside the lock.
		if pool_total_conns(pool) < pool.config.max_conns {
			pool.pending_dials += 1
			sync.mutex_unlock(&pool.mutex)
			c, cerr := pool.config.connect_fn(pool.config.connect_data, pool.config.conn_config, pool.allocator)
			sync.mutex_lock(&pool.mutex)
			pool.pending_dials -= 1
			if cerr != nil {
				sync.cond_broadcast(&pool.cond) // slot freed: a waiter may retry the dial
				return nil, cerr
			}
			if pool.is_closed {
				pool_destroy_conn(pool, c)
				sync.cond_broadcast(&pool.cond) // pool_destroy may be draining on pending_dials
				return nil, pgerr.Pool_Error{type = .Pool_Closed, message = "pool is closed"}
			}
			append(&pool.in_use, c)
			return c, nil
		}

		// 3. At capacity: wait for a release or freed slot.
		if effective > 0 {
			remaining := time.diff(time.now(), deadline)
			if remaining <= 0 {
				return nil, pgerr.Pool_Error{type = .Acquire_Timeout, message = "timed out waiting for a pooled connection"}
			}
			// Timed-out wait falls through to the loop; the deadline check
			// above produces the error after one final availability re-check.
			_ = sync.cond_wait_with_timeout(&pool.cond, &pool.mutex, remaining)
		} else {
			sync.cond_wait(&pool.cond, &pool.mutex)
		}
	}
}

/*
	pool_release returns a borrowed connection. Ready connections go back to
	the idle list; connections in any other state are destroyed (Task 3 adds
	a ROLLBACK reset for in-transaction states before giving up on them).
	Releasing a connection the pool does not currently track (including nil
	or a double release) fails with Foreign_Connection.
*/
pool_release :: proc(
	pool: ^Pool,
	conn: ^Conn,
) -> (
	err: pgerr.Error,
) {
	if pool == nil || conn == nil {
		return pgerr.Pool_Error{type = .Foreign_Connection, message = "nil pool or connection"}
	}

	sync.mutex_lock(&pool.mutex)

	found := false
	for c, idx in pool.in_use {
		if c == conn {
			unordered_remove(&pool.in_use, idx)
			found = true
			break
		}
	}
	if !found {
		sync.mutex_unlock(&pool.mutex)
		return pgerr.Pool_Error{type = .Foreign_Connection, message = "connection does not belong to this pool"}
	}

	if conn.status == .Ready && !pool.is_closed {
		conn.last_active = time.now()
		append(&pool.available, conn)
	} else {
		pool_destroy_conn(pool, conn)
	}
	sync.cond_broadcast(&pool.cond)
	sync.mutex_unlock(&pool.mutex)
	return nil
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
