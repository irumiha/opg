# Epic 2 — `pgconn` Code Review Report

> **Scope**: All code in OPG-201 through OPG-207 (`pgconn/` + `pgerr/`)
> **Date**: 2026-08-15
> **Build Status**: ✅ `odin check pgconn -no-entry-point -vet -strict-style` — clean
> **Test Status**: ✅ `odin test tests -all-packages -vet -strict-style` — **142/142 passed** (45ms)

---

## Executive Summary

Epic 2 is architecturally sound. The 3-layer separation is respected, big-endian wire encoding uses `core:encoding/endian` consistently, and the tagged union error model propagates cleanly. SCRAM-SHA-256 faithfully implements RFC 5802/7677, the connection pool is well-designed with robust timeout handling, and test coverage is excellent with rigorous `Tracking_Allocator` usage throughout.

That said, the review uncovered **3 critical issues**, **5 high-severity bugs**, **5 medium-severity concerns**, and **5 low-severity nits** across the 16 source files. The critical issues involve use-after-free risks on error objects and a pool capacity bypass under concurrency.

---

## Findings by Severity

### 🔴 CRITICAL (3)

| # | File | Lines | Finding |
|---|------|-------|---------|
| C1 | [`conn.odin`](file:///home/igorrumiha/Projects/odin-projects/opg/pgconn/conn.odin#L158-L159) | ~158-159 | **Lifetime bug: `Postgres_Error` cloned into `context.temp_allocator`** |
| C2 | [`query.odin`](file:///home/igorrumiha/Projects/odin-projects/opg/pgconn/query.odin#L48-L106), [`extended.odin`](file:///home/igorrumiha/Projects/odin-projects/opg/pgconn/extended.odin#L53-L111) | multiple | **Missing `ParameterStatus` handling in query loops breaks `SET` statements** |
| C3 | [`pool.odin`](file:///home/igorrumiha/Projects/odin-projects/opg/pgconn/pool.odin#L58-L60) | ~58-60 | **`max_conns` limit bypass via `pending_resets` not counted in total** |

---

#### C1: `Postgres_Error` Cloned into `context.temp_allocator` → Use-After-Free

**Location:** [`conn.odin:158-159`](file:///home/igorrumiha/Projects/odin-projects/opg/pgconn/conn.odin#L158-L159)

In `conn_handshake`, when the server returns a `Msg_Error_Response` (e.g. invalid password, wrong database), the error is cloned using `context.temp_allocator`. Because `conn_connect` returns this error directly to the caller, the cloned strings become dangling pointers as soon as `free_all(context.temp_allocator)` is called.

```diff
 case pgproto.Msg_Error_Response:
-    cloned_err, _ := pgerr.postgres_error_clone(m.error, context.temp_allocator)
+    cloned_err, _ := pgerr.postgres_error_clone(m.error, allocator)
     return nil, cloned_err
```

> [!CAUTION]
> This affects every failed connection attempt. The error message the user receives will contain freed memory.

---

#### C2: Missing `ParameterStatus` Handling in Query Engines

**Location:** [`query.odin:48-106`](file:///home/igorrumiha/Projects/odin-projects/opg/pgconn/query.odin#L48-L106), [`extended.odin:53-111`](file:///home/igorrumiha/Projects/odin-projects/opg/pgconn/extended.odin#L53-L111), [`extended.odin:146-217`](file:///home/igorrumiha/Projects/odin-projects/opg/pgconn/extended.odin#L146-L217), [`extended.odin:258-316`](file:///home/igorrumiha/Projects/odin-projects/opg/pgconn/extended.odin#L258-L316)

While `conn_handshake` correctly processes `Msg_Parameter_Status`, the execution loops in `conn_query`, `conn_exec_params`, and `conn_exec_prepared` do **not**. If a user executes `SET timezone = 'UTC'`, PostgreSQL returns a `ParameterStatus` message before `CommandComplete`. Hitting the `case:` default block will abort the loop and return a spurious `Unexpected_Message` protocol error.

**Fix:** Add a `pgproto.Msg_Parameter_Status` handler to all read loops, updating `conn.parameters` identically to the handshake logic.

---

#### C3: `max_conns` Limit Bypass via `pending_resets`

**Location:** [`pool.odin:58-60`](file:///home/igorrumiha/Projects/odin-projects/opg/pgconn/pool.odin#L58-L60) (`pool_total_conns`), [`pool.odin:246-252`](file:///home/igorrumiha/Projects/odin-projects/opg/pgconn/pool.odin#L246-L252) (`pool_release`)

When a connection is released while in a transaction, it is removed from `in_use` and `pending_resets` is incremented. The thread then drops the lock to execute the `ROLLBACK`. During this out-of-lock reset, the connection is not counted by `pool_total_conns`, so a concurrent `pool_acquire` sees the pool below capacity and dials a new connection, pushing actual count to `max_conns + 1`.

```diff
 pool_total_conns :: proc(pool: ^Pool) -> int {
-    return len(pool.available) + len(pool.in_use) + pool.pending_dials
+    return len(pool.available) + len(pool.in_use) + pool.pending_dials + pool.pending_resets
 }
```

---

### 🟠 HIGH (5)

| # | File | Lines | Finding |
|---|------|-------|---------|
| H1 | [`root.odin`](file:///home/igorrumiha/Projects/odin-projects/opg/root.odin#L16-L24) | 16-24 | `Pool_Error` / `Pool_Error_Type` not re-exported — consumers can't match them |
| H2 | [`extended.odin`](file:///home/igorrumiha/Projects/odin-projects/opg/pgconn/extended.odin#L184-L207) | ~184-207 | Prepared statement cache desync on `Parse` failure after `Close` |
| H3 | [`extended.odin`](file:///home/igorrumiha/Projects/odin-projects/opg/pgconn/extended.odin#L57) | ~57, 150, 262 | Missing `EmptyQueryResponse` handling in extended protocol |
| H4 | [`tls_openssl.odin`](file:///home/igorrumiha/Projects/odin-projects/opg/pgconn/tls_openssl.odin#L53-L65) | ~53-65 | Library handle leak in `tls_probe_into` — `__handle` stays `nil` |
| H5 | [`tls_openssl.odin`](file:///home/igorrumiha/Projects/odin-projects/opg/pgconn/tls_openssl.odin#L130-L172) | ~130-172 | 100% CPU busy loop on `SSL_ERROR_WANT_READ/WRITE` with socket timeouts |

---

#### H1: Missing `Pool_Error` Re-exports in `root.odin`

**Location:** [`root.odin:16-24`](file:///home/igorrumiha/Projects/odin-projects/opg/root.odin#L16-L24)

`Pool_Error` and `Pool_Error_Type` are defined in `pgerr` and part of the `Error` union, but not re-exported. Consumers matching `opg.Error` can't catch pool-specific errors without importing `pgerr` directly, violating the facade.

```diff
 Postgres_Error      :: pgerr.Postgres_Error
+Pool_Error          :: pgerr.Pool_Error
+Pool_Error_Type     :: pgerr.Pool_Error_Type
```

---

#### H2: Prepared Statement Cache Desynchronization

**Location:** [`extended.odin:184-207`](file:///home/igorrumiha/Projects/odin-projects/opg/pgconn/extended.odin#L184-L207)

In `conn_prepare`, the client sends `Close` to invalidate a named statement on the server. If the subsequent `Parse` fails, the old statement is not removed from `conn.prepared_statements`. The server has closed it, but the client thinks it still exists — next call to `conn_exec_prepared` will reference a non-existent server-side statement.

**Fix:** Unconditionally remove `name` from `conn.prepared_statements` after the `Close` succeeds, regardless of whether `Parse` succeeds.

---

#### H3: Missing `EmptyQueryResponse` in Extended Protocol

**Location:** [`extended.odin`](file:///home/igorrumiha/Projects/odin-projects/opg/pgconn/extended.odin) (lines ~57, 150, 262)

Passing an empty/comment-only SQL string via the extended protocol produces `EmptyQueryResponse` instead of `ParseComplete`/`CommandComplete`. Since it's not handled, it hits the `case:` default and crashes the connection with `Unexpected_Message`.

**Fix:** Add `pgproto.Msg_Empty_Query_Response` to the handled cases in all extended query loops.

---

#### H4: Library Handle Leak in OpenSSL Probe

**Location:** [`tls_openssl.odin:53-65`](file:///home/igorrumiha/Projects/odin-projects/opg/pgconn/tls_openssl.odin#L53-L65)

`dynlib.initialize_symbols(api, path)` loads the library but doesn't auto-assign the handle to `api.__handle`. On probe failure, `dynlib.unload_library(api.__handle)` unloads `nil`, leaking the OS library handle.

**Fix:** Explicitly load via `dynlib.load_library(path)`, then initialize symbols from the handle, and assign it manually.

---

#### H5: CPU Spin on OpenSSL `WANT_READ`/`WANT_WRITE`

**Location:** [`tls_openssl.odin:130-172`](file:///home/igorrumiha/Projects/odin-projects/opg/pgconn/tls_openssl.odin#L130-L172)

`tls_read`/`tls_write` spin-retry on `SSL_ERROR_WANT_READ`/`WANT_WRITE`. If a socket timeout (`SO_RCVTIMEO`) fires, OpenSSL propagates `EAGAIN` as `WANT_READ`. The infinite retry loop defeats the timeout, consuming 100% CPU indefinitely.

**Fix:** Map these to `pgerr.Net_Error{type = .Timeout}` so the caller can handle it gracefully.

---

### 🟡 MEDIUM (5)

| # | File | Lines | Finding |
|---|------|-------|---------|
| M1 | [`clone.odin`](file:///home/igorrumiha/Projects/odin-projects/opg/pgerr/clone.odin#L20-L38) | 20-38 | `postgres_error_clone` leaks partial allocations on mid-clone failure |
| M2 | [`conn.odin`](file:///home/igorrumiha/Projects/odin-projects/opg/pgconn/conn.odin#L202-L206) | ~202-206 | `.Connection_Refused` hardcoded for all dial errors (masks DNS/unreachable) |
| M3 | [`extended.odin`](file:///home/igorrumiha/Projects/odin-projects/opg/pgconn/extended.odin#L128-L142) | ~128-142 | Conn state left as `.Busy` on encoding errors before socket write |
| M4 | [`stream.odin`](file:///home/igorrumiha/Projects/odin-projects/opg/pgconn/stream.odin#L178-L214) | ~178-214 | Unbounded allocation on malicious packet length (no `MAX_PACKET_SIZE` guard) |
| M5 | [`pool.odin`](file:///home/igorrumiha/Projects/odin-projects/opg/pgconn/pool.odin#L153) | ~153, 258, 283 | Blocking network I/O (`conn_close`) inside pool mutex |

---

#### M1: Partial Leak in `postgres_error_clone`

If one of the `strings.clone()` calls fails mid-way via `or_return`, all previously cloned fields leak (unless caller uses an arena).

**Fix:** Add `defer if err != nil { postgres_error_destroy(res, allocator) }` at the top.

---

#### M2: All Dial Errors Mapped to `.Connection_Refused`

`net.dial_tcp_from_hostname_and_port_string` failures are unconditionally mapped to `.Connection_Refused`, even for DNS failures or unreachable hosts. This misleads debugging.

**Fix:** Inspect the underlying `net.Network_Error` variant and map to `.DNS_Resolution_Failed`, `.Host_Unreachable`, etc.

---

#### M3: `.Busy` State Stuck on Encoding Error

Connection status is set to `.Busy` **before** encoding. If encoding fails (e.g., `pgproto.encode_parse(...) or_return`), the connection is permanently stuck as `.Busy`, rendering a healthy socket unusable.

**Fix:** Move `conn.status = .Busy` to immediately before the `stream_write_messages` call.

---

#### M4: Unbounded Buffer Allocation on Malicious Length

`stream_read_message` reads a 4-byte length from the wire and immediately resizes the buffer. A malicious server sending length `0x7FFFFFFF` triggers a ~2GB allocation attempt.

**Fix:** Validate `total_packet_len` against a configurable `MAX_PACKET_SIZE` (e.g., 128MB) and return `Protocol_Error{type = .Invalid_Length}` if exceeded.

---

#### M5: Blocking I/O Inside Pool Mutex

`pool_destroy_conn` calls `conn_close` (which writes a Terminate packet over TCP) while holding `pool.mutex`. This can stall all concurrent acquires/releases if the TCP buffer blocks.

**Fix:** Collect connections to destroy, release the lock, then close them outside the critical section.

---

### 🔵 LOW (5)

| # | File | Lines | Finding |
|---|------|-------|---------|
| L1 | [`errors.odin`](file:///home/igorrumiha/Projects/odin-projects/opg/pgerr/errors.odin#L46-L66) | 46-66 | Missing lifetime docs on `Protocol_Error.message` / `Auth_Error.message` |
| L2 | [`errors.odin`](file:///home/igorrumiha/Projects/odin-projects/opg/pgerr/errors.odin#L22-L24) | 22-24 | `Unexpected_EOF`, `DNS_Resolution_Failed`, `Network_Down` defined but unused |
| L3 | [`auth_scram.odin`](file:///home/igorrumiha/Projects/odin-projects/opg/pgconn/auth_scram.odin#L302-L308) | ~302-308 | Signature comparison may not be constant-time under LLVM optimization |
| L4 | [`auth_scram.odin`](file:///home/igorrumiha/Projects/odin-projects/opg/pgconn/auth_scram.odin#L64-L77) | ~64-77 | `scram_escape_username` allocates builder even when no escaping needed |
| L5 | [`stream.odin`](file:///home/igorrumiha/Projects/odin-projects/opg/pgconn/stream.odin#L210) | ~210 | Convoluted capacity math simplifies to just `total_packet_len` |

---

#### L3: Non-Constant-Time Signature Comparison

The server signature comparison uses a loop with `matches = false` (no early break), which is better than `==`. However, LLVM may auto-vectorize or short-circuit it. Safer to use bitwise XOR accumulation:

```odin
diff: u8 = 0
for i in 0 ..< 32 {
    diff |= decoded_sig[i] ~ state.server_signature[i]
}
if diff != 0 { /* mismatch */ }
```

---

## Commendations ✅

The review team highlighted several excellent patterns:

- **Zero-copy stream buffer**: `stream_compact` fires at entry of read, ensuring borrowed `[]byte` slices from the previous message aren't shifted mid-use — perfectly adhering to the borrowing contract
- **Robust timeout handling**: Pool acquire loop handles spurious wakeups and checks for available connections *before* timeout, avoiding a subtle race
- **O(1) pool release**: `unordered_remove` avoids slice shift costs
- **Thread-safe cancellation**: `conn_cancel` uses only immutable handshake data (`backend_pid`, `backend_secret`), making it inherently TSan-clean
- **Rigorous tracking allocator tests**: Every test file uses `mem.Tracking_Allocator` with explicit leak assertions
- **Clean `or_return` propagation**: Tagged union errors flow naturally through the call stack
- **Pipelined extended query**: `Parse+Bind+Describe+Execute+Sync` grouped into single socket writes, minimizing round-trips
- **`extract_rows_affected`**: Zero-allocation command tag parsing without regex

---

## Summary Statistics

| Severity | Count | Actionable? |
|----------|-------|-------------|
| 🔴 CRITICAL | 3 | Must fix before any production use |
| 🟠 HIGH | 5 | Should fix before Epic 3 |
| 🟡 MEDIUM | 5 | Should fix, can be scheduled |
| 🔵 LOW | 5 | Nice-to-have improvements |
| **Total** | **18** | |
