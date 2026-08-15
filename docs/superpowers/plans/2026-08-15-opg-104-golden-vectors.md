# [OPG-104] `pgproto` Golden Vector Test Suite & Coverage Verification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Create a comprehensive, bit-for-bit golden binary test suite and mutation fuzzing harness in `pgproto/golden_test.odin` covering all 19 frontend and 31 backend protocol message types with $\ge 95\%$ coverage and zero memory leaks.

**Architecture:** Binary `.bin` files stored in `pgproto/tests_golden_files/` representing PostgreSQL Frontend/Backend Protocol 3.0 captures. Tested via bit-exact serialization comparison, field deserialization, and automated prefix truncation matrices.

**Tech Stack:** Odin, `core:os`, `core:slice`, `core:mem`, `core:testing`.

## Global Constraints

- **Strict Adherence**: Follow Odin idioms (tabs for indentation, Pascal_Case types, snake_case procs).
- **Network Byte Order (Big-Endian)**: Multi-byte integers must strictly use `core:encoding/endian` / `pgproto` primitives. Raw transmute is strictly forbidden.
- **Zero Memory Leaks**: All tests must verify zero leaks with `core:mem.Tracking_Allocator`.
- **Safety**: Corrupted and truncated packets must return typed `opg.Protocol_Error` without runtime panics.
- **Quality Gates**: Must pass `odin test pgproto -vet -strict-style` and `odin test pgproto -sanitize:address` with 0 memory leaks.

---

### Task 1: Frontend Golden Binary Fixtures & Encoder Tests

**Files:**
- Create: `pgproto/tests_golden_files/fe_*.bin` (19 binary fixtures)
- Create: `pgproto/golden_test.odin`

**Interfaces:**
- Produces:
  ```odin
  test_golden_frontend_encoders :: proc(t: ^testing.T)
  ```

- [ ] **Step 1: Create all 19 Frontend `.bin` fixtures in `pgproto/tests_golden_files/`**

Create `fe_ssl_request.bin`, `fe_cancel_request.bin`, `fe_startup_message.bin`, `fe_password_message.bin`, `fe_sasl_initial_response.bin`, `fe_sasl_response.bin`, `fe_query.bin`, `fe_parse.bin`, `fe_bind.bin`, `fe_describe_statement.bin`, `fe_describe_portal.bin`, `fe_execute.bin`, `fe_sync.bin`, `fe_flush.bin`, `fe_close_statement.bin`, `fe_close_portal.bin`, `fe_terminate.bin`, `fe_copy_data.bin`, `fe_copy_done.bin`, `fe_copy_fail.bin`.

- [ ] **Step 2: Write failing test in `pgproto/golden_test.odin` comparing encoder output against golden files**

```odin
package pgproto

import "core:mem"
import "core:os"
import "core:slice"
import "core:testing"
import ".." // opg

@(test)
test_golden_frontend_encoders :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	// Helper procedure to compare encoded message against disk fixture
	check_fe_golden :: proc(t: ^testing.T, msg: Frontend_Message, fixture_path: string) {
		buf: [dynamic]byte
		defer delete(buf)
		encode_frontend_message(&buf, msg)

		golden_bytes, ok := os.read_entire_file(fixture_path, context.temp_allocator)
		testing.expectf(t, ok, "failed to read golden file %v", fixture_path)
		testing.expectf(t, slice.equal(buf[:], golden_bytes), "mismatch for %v: got %v, expected %v", fixture_path, buf[:], golden_bytes)
	}

	// Verify all frontend messages against disk fixtures...
}
```

- [ ] **Step 3: Run test to verify it passes**

Run: `odin test pgproto`
Expected: PASS

- [ ] **Step 4: Commit Task 1**

```bash
git add pgproto/tests_golden_files/fe_*.bin pgproto/golden_test.odin
git commit -m "feat(pgproto): add frontend golden fixtures and bit-accurate encoder tests"
```

---

### Task 2: Backend Golden Binary Fixtures & Parser Tests

**Files:**
- Create: `pgproto/tests_golden_files/be_*.bin` (31 binary fixtures)
- Modify: `pgproto/golden_test.odin`

**Interfaces:**
- Produces:
  ```odin
  test_golden_backend_parsers :: proc(t: ^testing.T)
  ```

- [ ] **Step 1: Create all 31 Backend `.bin` fixtures in `pgproto/tests_golden_files/`**

Create `be_auth_ok.bin`, `be_auth_md5.bin`, `be_auth_sasl.bin`, `be_auth_sasl_continue.bin`, `be_auth_sasl_final.bin`, `be_backend_key_data.bin`, `be_parameter_status.bin`, `be_ready_for_query_idle.bin`, `be_ready_for_query_tx.bin`, `be_ready_for_query_err.bin`, `be_row_description.bin`, `be_data_row.bin`, `be_command_complete_select.bin`, `be_command_complete_insert.bin`, `be_error_response.bin`, `be_notice_response.bin`, `be_empty_query_response.bin`, `be_parse_complete.bin`, `be_bind_complete.bin`, `be_close_complete.bin`, `be_no_data.bin`, `be_portal_suspended.bin`, `be_parameter_description.bin`, `be_notification_response.bin`, `be_copy_in_response.bin`, `be_copy_out_response.bin`, `be_copy_both_response.bin`, `be_copy_data.bin`, `be_copy_done.bin`, `be_function_call_response.bin`, `be_negotiate_protocol_version.bin`.

- [ ] **Step 2: Implement `test_golden_backend_parsers` in `pgproto/golden_test.odin`**

Test all 31 fixtures by reading from disk, calling `parse_message`, verifying exact field values and 0 memory leaks.

- [ ] **Step 3: Run test to verify it passes**

Run: `odin test pgproto`
Expected: PASS

- [ ] **Step 4: Commit Task 2**

```bash
git add pgproto/tests_golden_files/be_*.bin pgproto/golden_test.odin
git commit -m "feat(pgproto): add backend golden fixtures and deserialization parser tests"
```

---

### Task 3: Exhaustive Truncation Fuzzing & Header Mutation Test Suite

**Files:**
- Modify: `pgproto/golden_test.odin`

**Interfaces:**
- Produces:
  ```odin
  test_golden_fuzzing_truncation_matrix :: proc(t: ^testing.T)
  test_golden_corrupted_headers :: proc(t: ^testing.T)
  ```

- [ ] **Step 1: Implement `test_golden_fuzzing_truncation_matrix`**

For every `.bin` golden file, loop through all prefix lengths $0 \dots N-1$, calling `parse_message` and asserting typed `opg.Protocol_Error` without crashes or memory leaks.

- [ ] **Step 2: Implement `test_golden_corrupted_headers`**

Test bit-flipped packet type identifiers, negative length values, and length fields exceeding payload size.

- [ ] **Step 3: Run tests to verify they pass**

Run: `odin test pgproto`
Expected: PASS

- [ ] **Step 4: Commit Task 3**

```bash
git add pgproto/golden_test.odin
git commit -m "test(pgproto): add systematic truncation fuzzing and header mutation test suite"
```

---

### Task 4: Quality Audits, Coverage Verification & JIRA Update

**Files:**
- Modify: `JIRA.md`

- [ ] **Step 1: Run comprehensive tests with styling and AddressSanitizer**

Run:
1. `odin test pgproto -vet -strict-style`
2. `odin test pgproto -sanitize:address`
3. `odin check . -no-entry-point`

- [ ] **Step 2: Verify coverage and update `JIRA.md`**

Mark `[OPG-104]` as completed `[x] **Status**: Done`.

- [ ] **Step 3: Commit Task 4**

```bash
git add JIRA.md
git commit -m "docs(jira): mark OPG-104 golden vector test suite as done"
```
