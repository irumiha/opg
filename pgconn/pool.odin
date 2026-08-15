package pgconn

import "core:mem"
import "core:sync"
import "core:time"
import "../pgerr" // Imports driver error types

// ----------------------------------------------------------------------------
// Connection Pool State and Configuration
// ----------------------------------------------------------------------------

Pool_Config :: struct {
	host:               string,
	port:               int,
	user:               string,
	password:           string,
	database:           string,
	min_conns:          int,
	max_conns:          int,
	idle_timeout:       time.Duration,
	connection_timeout: time.Duration,
}

/*
	Pool represents a thread-safe connection pool for PostgreSQL connections.
	
	Thread safety is guaranteed via `sync.Mutex` and `sync.Cond` synchronization primitives.
	Persistent allocator is used for all pool-allocated connections and slices.
*/
Pool :: struct {
	mutex:       sync.Mutex,
	cond:        sync.Cond,
	config:      Pool_Config,
	allocator:   mem.Allocator, // Persistent allocator (never context.temp_allocator)
	available:   [dynamic]^Conn,
	in_use:      [dynamic]^Conn,
	is_closed:   bool,
}

// ----------------------------------------------------------------------------
// Pool Management API Stubs
// ----------------------------------------------------------------------------

/*
	pool_init initializes a new thread-safe connection pool.
	Uses the provided persistent allocator for all pool structures.
*/
pool_init :: proc(
	config: Pool_Config,
	allocator := context.allocator,
) -> (
	pool: ^Pool,
	err: pgerr.Error,
) {
	// Allocate pool using persistent allocator
	p := new(Pool, allocator)
	p.config = config
	p.allocator = allocator
	p.available = make([dynamic]^Conn, allocator)
	p.in_use = make([dynamic]^Conn, allocator)

	// Pre-warm pool with min_conns if configured (stub)
	return p, nil
}

/*
	pool_acquire retrieves an idle connection from the pool or creates a new one
	if below max_conns. Blocks or times out if all connections are active.
*/
pool_acquire :: proc(
	pool: ^Pool,
	timeout := time.Duration(0),
) -> (
	conn: ^Conn,
	err: pgerr.Error,
) {
	sync.mutex_lock(&pool.mutex)
	defer sync.mutex_unlock(&pool.mutex)

	if pool.is_closed {
		return nil, pgerr.Net_Error{
			type = .Socket_Closed,
		}
	}

	// Check if an available connection exists
	if len(pool.available) > 0 {
		c := pop(&pool.available)
		append(&pool.in_use, c)
		return c, nil
	}

	// Stub: If capacity allows, dial a new TCP socket using core:net / core:nbio
	return nil, pgerr.Net_Error{
		type = .Timeout,
	}
}

/*
	pool_release returns a borrowed connection back to the available pool.
*/
pool_release :: proc(
	pool: ^Pool,
	conn: ^Conn,
) -> (
	err: pgerr.Error,
) {
	sync.mutex_lock(&pool.mutex)
	defer sync.mutex_unlock(&pool.mutex)

	if pool.is_closed {
		return pgerr.Net_Error{
			type = .Socket_Closed,
		}
	}

	// Move connection from in_use to available
	for c, idx in pool.in_use {
		if c == conn {
			unordered_remove(&pool.in_use, idx)
			append(&pool.available, conn)
			sync.cond_signal(&pool.cond)
			return nil
		}
	}

	return nil
}

/*
	pool_destroy gracefully closes all sockets and frees persistent memory.
*/
pool_destroy :: proc(pool: ^Pool) {
	if pool == nil do return

	sync.mutex_lock(&pool.mutex)
	pool.is_closed = true

	// Close all idle connections
	for conn in pool.available {
		conn_close(conn)
		free(conn, pool.allocator)
	}
	delete(pool.available)

	// Close all in-use connections
	for conn in pool.in_use {
		conn_close(conn)
		free(conn, pool.allocator)
	}
	delete(pool.in_use)

	sync.cond_broadcast(&pool.cond)
	sync.mutex_unlock(&pool.mutex)

	free(pool, pool.allocator)
}
