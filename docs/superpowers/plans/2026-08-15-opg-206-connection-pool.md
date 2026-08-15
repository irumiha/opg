# OPG-206 Thread-Safe Connection Pool Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement a production-grade, thread-safe PostgreSQL connection pool (`pool_init` / `pool_acquire` / `pool_release` / `pool_destroy`) in `pgconn`, verified leak-free and race-free.

**Architecture:** The pool guards `available` / `in_use` connection lists with one `sync.Mutex` + `sync.Cond`. Slow operations (dialing a new connection, ROLLBACK reset on release) run *outside* the lock, with `pending_dials` / `pending_resets` counters keeping slot accounting and shutdown draining correct. A `connect_fn` hook in `Pool_Config` (defaulting to real TCP `conn_connect`) is the test seam — all tests run against `Mock_Transport`, no live server.

**Tech Stack:** Odin (nightly dev-2026-08), `core:sync` (Mutex/Cond), `core:thread` (tests only), `core:time`, existing `pgconn` Conn/Stream/query APIs, `pgerr` error union.

**Spec:** `docs/superpowers/specs/2026-08-15-epic-2-pgconn-architecture-design.md` §3.5 + JIRA.md task [OPG-206].

## Global Constraints

- Run all verification from the repo root: `odin test tests -all-packages -vet -strict-style` must pass after every task.
- Every test uses `mem.Tracking_Allocator` and asserts `len(track.allocation_map) == 0` at the end (zero leaks). The tracking allocator is internally mutex-guarded, so it is safe as the pool allocator in multi-threaded tests.
- Persistent allocations (Pool, Conn, dynamic arrays) use the pool's persistent allocator; transient allocations use `context.temp_allocator` (existing pattern).
- Error values come from the `pgerr` union. Pool-specific failures use the new `pgerr.Pool_Error` with **static string messages only** (never allocated — nothing to free).
- Tests must not require a live PostgreSQL server; use `Mock_Transport` (defined in `pgconn/stream_test.odin`) via the `connect_fn` hook.
- No I/O while holding `pool.mutex` except `pool_destroy_conn` on already-broken/idle conns (bounded: one Terminate write to an in-memory mock or dead socket).
- Concurrency acceptance: `odin test pgconn -sanitize:thread` reports zero data races (Task 4).
- Commit after each task with a `feat(pgconn):`/`fix(pgconn):`/`test(pgconn):` conventional message ending with `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`.

## Execution Notes (workspace)

Per Igor's workflow preference: create branch **in place** before Task 1 (`git checkout -b opg-206-connection-pool`), execute inline, commit per task; after all tasks pass the gate, merge to `main` locally with `--no-ff` not required (plain merge/ff fine), delete the branch, and re-run the gate on merged `main`.

## API Contract (final shape, referenced by all tasks)

```odin
// pgerr/errors.odin additions
Pool_Error_Type :: enum {
	None,
	Invalid_Config,
	Pool_Closed,
	Acquire_Timeout,
	Foreign_Connection,
}

Pool_Error :: struct {
	type:    Pool_Error_Type,
	message: string, // always a static string literal; never freed
}

// added as 5th variant of pgerr.Error union
```

```odin
// pgconn/pool.odin final public API
Pool_Connect_Proc :: #type proc(data: rawptr, config: Conn_Config, allocator: mem.Allocator) -> (conn: ^Conn, err: pgerr.Error)

Pool_Config :: struct {
	conn_config:     Conn_Config,
	min_conns:       int,           // pre-warmed at init; must be in [0, max_conns]
	max_conns:       int,           // must be > 0
	idle_timeout:    time.Duration, // 0 = pooled idle conns never expire
	acquire_timeout: time.Duration, // default for pool_acquire when its param is 0; 0 = wait forever
	connect_fn:      Pool_Connect_Proc, // nil = default_pool_connect (real TCP)
	connect_data:    rawptr,
}

Pool :: struct {
	mutex:          sync.Mutex,
	cond:           sync.Cond,
	config:         Pool_Config,
	allocator:      mem.Allocator,
	available:      [dynamic]^Conn,
	in_use:         [dynamic]^Conn,
	pending_dials:  int, // dials in flight outside the lock; counts toward max_conns
	pending_resets: int, // releases doing ROLLBACK outside the lock; blocks pool_destroy drain
	is_closed:      bool,
}

pool_init    :: proc(config: Pool_Config, allocator := context.allocator) -> (pool: ^Pool, err: pgerr.Error)
pool_acquire :: proc(pool: ^Pool, timeout := time.Duration(0)) -> (conn: ^Conn, err: pgerr.Error)
pool_release :: proc(pool: ^Pool, conn: ^Conn) -> (err: pgerr.Error)
pool_destroy :: proc(pool: ^Pool)
```

**Contracts:**
- `pool_acquire`: reuses healthy idle conns (LIFO); destroys stale (`idle_timeout` exceeded) or dead (`!conn_is_alive`) idle conns; dials new when total (`available + in_use + pending_dials`) < `max_conns`; otherwise blocks on cond until release/slot or timeout (`Pool_Error{.Acquire_Timeout}`). Closed/nil pool → `Pool_Error{.Pool_Closed}`.
- `pool_release`: conn not in `in_use` (incl. nil / double release) → `Pool_Error{.Foreign_Connection}`. `.Ready` conn → pooled (fast path, `last_active` refreshed). `.In_Transaction`/`.Failed_Transaction` → `ROLLBACK` via `conn_query` outside the lock; on failure or non-Ready result → destroyed. Any other status, or pool closed → destroyed. Always broadcasts cond.
- `pool_destroy`: nil-safe; sets `is_closed`, broadcasts (wakes blocked acquirers → they error with `.Pool_Closed`), waits until `in_use`, `pending_dials`, `pending_resets` all drain to zero (in-use conns must be released by their holders), then closes/frees all idle conns and the pool. Must be called exactly once and must not race with *new* `pool_acquire` calls (documented contract; concurrent releases and already-blocked acquirers are safe).

---

### Task 1: `Pool_Error` + pool skeleton + `pool_init`/`pool_destroy` with pre-warm

**Files:**
- Modify: `pgerr/errors.odin` (add `Pool_Error_Type`, `Pool_Error`, union variant)
- Rewrite: `pgconn/pool.odin`
- Create: `pgconn/pool_test.odin`

**Interfaces:**
- Consumes: `Conn`, `conn_close`, `conn_connect`, `Conn_Config`, `Prepared_Statement`, `stream_init`, `Mock_Transport` + `mock_transport_init/destroy` + `make_mock_transport` (from `stream_test.odin`), `pgerr.Error`.
- Produces: everything in "API Contract" above except `pool_acquire`/`pool_release` bodies (stubs return `Pool_Error{.Pool_Closed}` / `Pool_Error{.Foreign_Connection}` for now); test infra `Mock_Pool_Dialer`, `mock_dialer_init`, `mock_dialer_destroy`, `mock_pool_dial`, `make_test_pool_config` used by Tasks 2–4.

- [ ] **Step 1: Add `Pool_Error` to `pgerr/errors.odin`**

Append after `Postgres_Error` and extend the union:

```odin
Pool_Error_Type :: enum {
	None,
	Invalid_Config,
	Pool_Closed,
	Acquire_Timeout,
	Foreign_Connection,
}

/*
	Pool_Error reports connection pool lifecycle and usage failures.
	`message` is always a static string literal — it is never allocated
	and must never be freed.
*/
Pool_Error :: struct {
	type:    Pool_Error_Type,
	message: string,
}
```

```odin
// Master tagged union for all driver errors
Error :: union {
	Net_Error,
	Protocol_Error,
	Auth_Error,
	Postgres_Error,
	Pool_Error,
}
```

- [ ] **Step 2: Write failing tests in `pgconn/pool_test.odin`**

```odin
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
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `odin test pgconn -vet -strict-style`
Expected: compile errors (old `Pool_Config` fields don't match `make_test_pool_config`) — that counts as the failing state.

- [ ] **Step 4: Rewrite `pgconn/pool.odin`**

Replace the whole file:

```odin
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
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `odin test pgconn -vet -strict-style`
Expected: all pool tests PASS (existing pgconn tests still PASS).

- [ ] **Step 6: Full gate**

Run from repo root: `odin test tests -all-packages -vet -strict-style`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add pgerr/errors.odin pgconn/pool.odin pgconn/pool_test.odin
git commit -m "feat(pgconn): pool config, Pool_Error, init pre-warm and destroy"
```

---

### Task 2: `pool_acquire` + fast-path `pool_release`

**Files:**
- Modify: `pgconn/pool.odin` (replace both stubs)
- Modify: `pgconn/pool_test.odin` (append tests)

**Interfaces:**
- Consumes: Task 1's pool skeleton, `conn_is_alive`, `sync.cond_wait_with_timeout` (returns false on timeout), `time.time_add` / `time.diff` / `time.since`.
- Produces: final `pool_acquire`; `pool_release` fast path (`.Ready` conn → pooled; anything else → destroyed; not-in-`in_use` → `Foreign_Connection`). Task 3 only adds the ROLLBACK-reset branch.

- [ ] **Step 1: Write failing tests (append to `pgconn/pool_test.odin`)**

```odin
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `odin test pgconn -vet -strict-style`
Expected: new tests FAIL (stubs return errors).

- [ ] **Step 3: Implement `pool_acquire` and fast-path `pool_release`**

Replace the two stubs in `pgconn/pool.odin`:

```odin
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `odin test pgconn -vet -strict-style`
Expected: PASS.

- [ ] **Step 5: Full gate**

Run from repo root: `odin test tests -all-packages -vet -strict-style`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add pgconn/pool.odin pgconn/pool_test.odin
git commit -m "feat(pgconn): pool_acquire with dial-outside-lock, timeouts, idle recycling"
```

---

### Task 3: `pool_release` reset & destruction paths

**Files:**
- Modify: `pgconn/pool.odin` (`pool_release` only)
- Modify: `pgconn/pool_test.odin` (append tests)

**Interfaces:**
- Consumes: `conn_query(conn, "ROLLBACK")` (simple query, nil callbacks — drives conn back to `.Ready` on `ReadyForQuery('I')`), `pool.pending_resets` from Task 1's struct.
- Produces: final `pool_release` per API Contract; nothing else changes.

- [ ] **Step 1: Write failing tests (append to `pgconn/pool_test.odin`)**

```odin
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
	foreign := new(Conn, context.allocator)
	foreign.allocator = context.allocator
	foreign.status = .Ready
	stream_init(&foreign.stream, make_mock_transport(&foreign_mock), allocator = context.allocator)

	rerr := pool_release(pool, foreign)
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

	conn_close(foreign)
	free(foreign, context.allocator)
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `odin test pgconn -vet -strict-style`
Expected: `test_pool_release_resets_in_transaction` and `test_pool_release_destroys_on_failed_reset` FAIL (fast path destroys in-transaction conns without reset; reset test expects conn pooled). The other two may already pass — fine.

- [ ] **Step 3: Add the reset branch to `pool_release`**

Replace `pool_release` in `pgconn/pool.odin`:

```odin
/*
	pool_release returns a borrowed connection to the pool.

	- .Ready conns are pooled immediately (fast path, no I/O).
	- .In_Transaction / .Failed_Transaction conns are reset with ROLLBACK
	  outside the lock (the conn is invisible to other threads once removed
	  from in_use); if the reset fails or does not end .Ready, the conn is
	  destroyed. pending_resets keeps pool_destroy from freeing the pool
	  while the reset is in flight.
	- Any other status (or a closing pool) destroys the connection.

	Releasing a connection the pool does not track (nil, foreign, or double
	release) fails with Foreign_Connection.
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

	// Fast path: healthy idle connection, no reset I/O required.
	if conn.status == .Ready && !pool.is_closed {
		conn.last_active = time.now()
		append(&pool.available, conn)
		sync.cond_broadcast(&pool.cond)
		sync.mutex_unlock(&pool.mutex)
		return nil
	}

	needs_reset := !pool.is_closed && (conn.status == .In_Transaction || conn.status == .Failed_Transaction)
	healthy := false
	if needs_reset {
		pool.pending_resets += 1
		sync.mutex_unlock(&pool.mutex)
		reset_err := conn_query(conn, "ROLLBACK")
		healthy = reset_err == nil && conn.status == .Ready
		sync.mutex_lock(&pool.mutex)
		pool.pending_resets -= 1
	}

	if healthy && !pool.is_closed {
		conn.last_active = time.now()
		append(&pool.available, conn)
	} else {
		pool_destroy_conn(pool, conn)
	}
	sync.cond_broadcast(&pool.cond)
	sync.mutex_unlock(&pool.mutex)
	return nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `odin test pgconn -vet -strict-style`
Expected: PASS.

- [ ] **Step 5: Full gate**

Run from repo root: `odin test tests -all-packages -vet -strict-style`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add pgconn/pool.odin pgconn/pool_test.odin
git commit -m "feat(pgconn): pool_release ROLLBACK reset and broken-conn destruction"
```

---

### Task 4: Concurrency — blocked acquirers, destroy drain, 50-thread stress, TSan

**Files:**
- Modify: `pgconn/pool_test.odin` (append tests; add `import "core:thread"`)
- Modify: `pgconn/pool.odin` only if a test exposes a bug

**Interfaces:**
- Consumes: full pool API from Tasks 1–3; `thread.create_and_start_with_poly_data`, `thread.join`, `thread.destroy`.
- Produces: verified concurrency behavior; no new API.

- [ ] **Step 1: Write the concurrency tests (append to `pgconn/pool_test.odin`; add `import "core:thread"` to the file's import block)**

```odin
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
```

- [ ] **Step 2: Run the tests**

Run: `odin test pgconn -vet -strict-style`
Expected: PASS (implementation from Tasks 1–3 should already satisfy these; if any test fails or hangs, fix `pool.odin` — hang points to a missed `cond_broadcast`, leak points to a missed `pool_destroy_conn`).

- [ ] **Step 3: ThreadSanitizer verification**

Run: `odin test pgconn -sanitize:thread`
Expected: all tests PASS, zero TSan `WARNING: ThreadSanitizer` reports. Fix any reported race before proceeding (accesses to pool fields must all happen under `pool.mutex`).

- [ ] **Step 4: Full gate**

Run from repo root: `odin test tests -all-packages -vet -strict-style`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add pgconn/pool_test.odin pgconn/pool.odin
git commit -m "test(pgconn): pool concurrency, destroy drain, and 50-thread stress tests"
```

---

### Task 5: Mark OPG-206 done, merge

**Files:**
- Modify: `JIRA.md` (OPG-206 status line)

- [ ] **Step 1: Update JIRA.md**

In the `### [OPG-206]` section change:

```markdown
- [ ] **Status**: Open
```

to:

```markdown
- [x] **Status**: Done
```

- [ ] **Step 2: Final verification**

Run from repo root: `odin test tests -all-packages -vet -strict-style`
Expected: PASS.
Also re-run: `odin test pgconn -sanitize:thread` — zero races.

- [ ] **Step 3: Commit**

```bash
git add JIRA.md
git commit -m "feat(pgconn): complete OPG-206 thread-safe connection pool and mark task done in JIRA"
```

- [ ] **Step 4: Merge to main (Igor's workflow)**

```bash
git checkout main
git merge opg-206-connection-pool
git branch -d opg-206-connection-pool
odin test tests -all-packages -vet -strict-style   # green gate on merged main
```

---

## Self-Review Notes

- **Spec coverage:** §3.5 signatures ✓ (`connect_fn`/`connect_data` added as the documented test seam; `pending_dials`/`pending_resets` added for lock-free dial/reset — both are internal fields, public API matches spec). Pool invariant "release of non-Ready conn issues ROLLBACK, broken conns destroyed" ✓ Task 3. "Concurrency verified with -sanitize:thread" ✓ Task 4. JIRA features: mutex+cond ✓, all four procs ✓, health check & auto-reconnect (dead/stale idle conns destroyed and re-dialed in acquire) ✓, max limits & queueing ✓. Acceptance: 50-thread stress ✓, zero leaks ✓ (tracking allocator in every test).
- **Type consistency:** `Pool_Connect_Proc` signature identical in contract, pool.odin, and mock; `Pool_Error_Type` variants used in tests match the enum; `blocked_acquire_proc` reused by both Task 4 thread tests via `Blocked_Acquire_State`.
- **Known contract limits (documented in doc comments):** `pool_destroy` is call-once and must not race with new `pool_acquire` calls; in-use conns must be released for destroy to return. These mirror pgx/database-sql semantics.
