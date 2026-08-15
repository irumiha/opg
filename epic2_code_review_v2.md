# Epic 2 — Second-Pass Code Review (Corrected)

> **Scope**: Verify fixes for all 18 first-review findings + fresh pass on all `pgconn/` and `pgerr/` code
> **Date**: 2026-08-16
> **Build Status**: ✅ `odin check pgconn -no-entry-point -vet -strict-style` — clean
> **Test Status**: ✅ `odin test tests -all-packages -vet -strict-style` — **148/148 passed** (58ms, +6 new regression tests)

---

## Part 1: Fix Verification

### 🔴 CRITICAL Fixes — All 3 Correct

| # | Finding | Verdict | Notes |
|---|---------|---------|-------|
| C1 | `Postgres_Error` cloned into temp allocator | ✅ **CORRECT** | [`conn.odin:192`](file:///home/igorrumiha/Projects/odin-projects/opg/pgconn/conn.odin#L192) now passes the persistent `allocator` to `postgres_error_clone`. |
| C2 | Missing `ParameterStatus` in query loops | ✅ **CORRECT** | `conn_apply_parameter_status` helper extracted in [`conn.odin:120-132`](file:///home/igorrumiha/Projects/odin-projects/opg/pgconn/conn.odin#L120-L132), called from **all 7 read loops**. Regression test in [`query_test.odin`](file:///home/igorrumiha/Projects/odin-projects/opg/pgconn/query_test.odin) verifies `SET TIMEZONE` end-to-end. |
| C3 | `max_conns` bypass via `pending_resets` | ✅ **CORRECT** | [`pool.odin:59`](file:///home/igorrumiha/Projects/odin-projects/opg/pgconn/pool.odin#L59) now sums `available + in_use + pending_dials + pending_resets`. Excellent concurrency regression test in [`pool_test.odin`](file:///home/igorrumiha/Projects/odin-projects/opg/pgconn/pool_test.odin) with `Blocking_Reset_Transport`. |

---

### 🟠 HIGH Fixes — All 5 Correct

| # | Finding | Verdict | Notes |
|---|---------|---------|-------|
| H1 | `Pool_Error` not re-exported | ✅ **CORRECT** | [`root.odin:25-26`](file:///home/igorrumiha/Projects/odin-projects/opg/root.odin#L25-L26) re-exports both types. |
| H2 | Prepared statement cache desync | ✅ **CORRECT** | [`extended.odin:155-163`](file:///home/igorrumiha/Projects/odin-projects/opg/pgconn/extended.odin#L155-L163) deletes cache on `Msg_Close_Complete`. Regression test verifies cache empty after Close→Parse failure. |
| H3 | Missing `EmptyQueryResponse` | ✅ **CORRECT** | Handled in all 5 extended protocol loops. Regression test verifies. |
| H4 | TLS library handle leak | ✅ **NOT A BUG** | See retraction below. |
| H5 | CPU spin on WANT_READ/WRITE | ✅ **CORRECT** | `time.sleep(time.Millisecond)` added to both `tls_read` and `tls_write`. |

> [!IMPORTANT]
> **H4 Retraction**: The first review claimed `dynlib.initialize_symbols` does not auto-assign `__handle`. This is **incorrect**. Per [Odin's `core:dynlib` documentation](https://pkg.odin-lang.org/core/dynlib/), `initialize_symbols` automatically assigns the loaded library handle to the struct field named `__handle`. The [`OpenSSL_API`](file:///home/igorrumiha/Projects/odin-projects/opg/pgconn/tls_openssl.odin#L20-L34) struct declares `__handle: dynlib.Library` on line 21, so the handle IS correctly assigned. The `unload_library(api.__handle)` cleanup on line 60 works as intended. **No leak exists.**

---

### 🟡 MEDIUM Fixes — All 5 Correct

| # | Finding | Verdict | Notes |
|---|---------|---------|-------|
| M1 | Partial leak in `postgres_error_clone` | ✅ **CORRECT** | [`clone.odin:20-23`](file:///home/igorrumiha/Projects/odin-projects/opg/pgerr/clone.odin#L20-L23) adds `defer if err != nil { postgres_error_destroy(res, allocator) }`. |
| M2 | All dial errors mapped to `.Connection_Refused` | ✅ **CORRECT** | [`conn.odin:134-165`](file:///home/igorrumiha/Projects/odin-projects/opg/pgconn/conn.odin#L134-L165) introduces `map_dial_error` with exhaustive `#partial switch`. |
| M3 | `.Busy` stuck on encoding error | ✅ **CORRECT** | `conn.status = .Busy` moved to after encoding in all 5 extended protocol procs. |
| M4 | Unbounded allocation on malicious length | ✅ **CORRECT** | [`stream.odin:10-17`](file:///home/igorrumiha/Projects/odin-projects/opg/pgconn/stream.odin#L10-L17) defines `MAX_PACKET_SIZE :: 1 << 27` (128 MiB) with validation. Regression test verifies. |
| M5 | Blocking I/O inside pool mutex | ✅ **CORRECT** | [`pool.odin:274-306`](file:///home/igorrumiha/Projects/odin-projects/opg/pgconn/pool.odin#L274-L306) snapshots `available` into local `to_close`, unlocks, then closes connections. |

---

### 🔵 LOW Fixes — All 5 Correct

| # | Finding | Verdict | Notes |
|---|---------|---------|-------|
| L1 | Missing lifetime docs | ✅ **CORRECT** | Ownership semantics documented on both `Protocol_Error.message` and `Auth_Error.message`. |
| L2 | Unused `Net_Error_Type` variants | ✅ **CONSUMED** | `DNS_Resolution_Failed` and `Host_Unreachable` now used by `map_dial_error`. |
| L3 | Non-constant-time signature comparison | ✅ **CORRECT** | XOR accumulation in [`auth_scram.odin:315-318`](file:///home/igorrumiha/Projects/odin-projects/opg/pgconn/auth_scram.odin#L315-L318). |
| L4 | Inefficient `scram_escape_username` | ✅ **CORRECT** | Fast-path scan in [`auth_scram.odin:63-72`](file:///home/igorrumiha/Projects/odin-projects/opg/pgconn/auth_scram.odin#L63-L72). |
| L5 | Convoluted capacity math | ✅ **CORRECT** | Simplified in [`stream.odin:228-230`](file:///home/igorrumiha/Projects/odin-projects/opg/pgconn/stream.odin#L228-L230). |

---

## Fix Verification Summary

| Status | Count |
|--------|-------|
| ✅ Correct | 17 / 18 |
| ✅ Retracted (false positive) | 1 (H4 was not a bug) |
| **All original findings resolved** | **18 / 18** |

---

## Part 2: New Findings (Fresh Pass)

### Retracted Finding

> [!NOTE]
> **N1 (from subagent review) — RETRACTED / FALSE POSITIVE**: The subagent claimed `pool_destroy`'s `defer` block captures `to_close` by value at declaration time, meaning the `defer` would see a zero-initialized slice and never close connections. This is **incorrect**. Odin's `defer` does **not** capture values — it simply schedules the statement to execute at scope exit, where it sees the current value of all local variables. When the `defer` fires, `to_close` has already been assigned and populated on lines 297-300. The `pool_destroy` code is correct as written.

---

### 🟡 MEDIUM (2)

**N2: `pool_destroy` blocking contract undocumented**

**Location:** [`pool.odin:293-295`](file:///home/igorrumiha/Projects/odin-projects/opg/pgconn/pool.odin#L293-L295)

`pool_destroy` waits indefinitely on `len(pool.in_use) > 0 || pool.pending_dials > 0 || pool.pending_resets > 0`. If called while connections are still checked out, this blocks forever. This is a reasonable design choice, but the blocking contract should be documented in the proc's doc comment so callers know they must release all connections before calling destroy.

---

**N3: TLS `WANT_READ`/`WANT_WRITE` retry has no upper bound**

**Location:** [`tls_openssl.odin:143-148`](file:///home/igorrumiha/Projects/odin-projects/opg/pgconn/tls_openssl.odin#L143-L148), [`tls_openssl.odin:168-170`](file:///home/igorrumiha/Projects/odin-projects/opg/pgconn/tls_openssl.odin#L168-L170)

The H5 fix added `time.sleep(time.Millisecond)` which eliminates CPU waste. However, the loop still has no upper bound on retries. If a TLS renegotiation is permanently stuck, the loop will sleep-retry forever. Consider adding a max retry count (e.g., 5000 = ~5 seconds) with a `Net_Error{.Timeout}` return as a safety net. The existing comment acknowledges this is incomplete pending OS-level deadline wiring.

---

### 🔵 LOW (1)

**N4: Pool `is_closed` idempotency guard not implemented**

**Location:** [`pool.odin:271`](file:///home/igorrumiha/Projects/odin-projects/opg/pgconn/pool.odin#L271)

Double-calling `pool_destroy` would double-free the pool. Adding `if pool.is_closed { unlock; return }` after acquiring the lock is cheap defensive insurance. The `nil` check on line 272 already guards against nil pool pointers, so adding the closed check would complete the defensive pattern.

---

## Part 3: Commendations ✅

The fixes are uniformly well-implemented. Specific highlights:

- **`conn_apply_parameter_status` extraction** — Clean DRY refactor. One helper called from 7 sites, properly handling both the update (delete old value) and insert (clone key + value) paths with the persistent allocator
- **`map_dial_error`** — Well-structured `#partial switch` with proper variant matching and sensible fallback to `.Connection_Refused`
- **Pool C3 regression test** — The `Blocking_Reset_Transport` gate pattern is creative and effective for testing concurrent timing windows without flaky sleeps
- **H2 cache cleanup** — Properly frees `name`, `query`, and `param_oids` from the old entry before deletion, preventing leaks
- **M3 state ordering** — Consistent application across all 5 extended protocol procs (`exec_params`, `prepare`, `exec_prepared`, `close_statement`, `close_portal`)
- **6 new regression tests** — Each targets the exact edge case from the original finding, uses `Tracking_Allocator`, and verifies both the happy path and error path

---

## Final Summary

| Category | Count |
|----------|-------|
| Original Fixes Verified ✅ | 18 / 18 (including 1 retracted false positive) |
| New Findings | 3 (0 critical, 0 high, 2 medium, 1 low) |
| False Positives Retracted | 2 (H4, N1) |

### Remaining Action Items

| Priority | Item | Description |
|----------|------|-------------|
| 🟡 MEDIUM | N2 | Document `pool_destroy` blocking contract in doc comment |
| 🟡 MEDIUM | N3 | Add retry limit to TLS WANT_READ/WRITE loops |
| 🔵 LOW | N4 | Add `is_closed` idempotency guard in `pool_destroy` |

> [!TIP]
> Epic 2 is in excellent shape. All critical and high-severity issues from the first review have been correctly fixed. The 3 remaining items are defensive hardening — none represent correctness bugs in normal operation.
