# Code Review Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement all fixes from the 2026-08-15 project review: break the future root-package import cycle, fix the latent `pgorm` compile error, harden wire-value validation, make leak checks real, add encoder guards, formalize the zero-copy contract, consolidate the buffer API, and repair the documented test invocation.

**Architecture:** Error types move from the root `opg` package into a new leaf package `pgerr` that every package (including root) imports downward — this removes the `root ↔ pgconn` cycle that OPG-401 would otherwise create. The buffer API keeps the `Reader` struct for reads and the stateless `write_*` procedures for writes; the stateless `read_*` functions and the `Writer` wrapper are deleted. All parser enum casts from wire data gain explicit validation. Parsers free partial allocations on error paths so they are correct under any allocator, not just arenas.

**Tech Stack:** Odin (nightly `dev-2026-08`), `core:encoding/endian`, `core:testing`, `core:mem.Tracking_Allocator`, `base:intrinsics`.

## Global Constraints

- Every package must pass `odin check <pkg> -no-entry-point -vet -strict-style` when its task completes (exception: `pgorm` stays vet-dirty until Task 3, which fixes it).
- `odin test pgproto` (and from Task 3 on, `odin test pgorm`) must be green after every task, including with `-vet -strict-style` and `-sanitize:address`.
- Golden fixture files in `pgproto/tests_golden_files/` are byte-frozen: no task may change encoder output for any value representable today (counts ≤ 32767 encode identically as u16/i16).
- Style per `AGENTS.md` §3: tabs for indentation, trailing commas, `Pascal_Case` types, `snake_case` procs, `ALL_CAPS` constants, no `using`.
- Commit after every task with a conventional-commit message (`fix(pgproto): ...` style, matching git history). End every commit message with:
  `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`
- Working directory for all commands is the repo root `/home/igorrumiha/Projects/odin-projects/opg`.
- Out of scope (conscious decisions, do NOT implement): rejecting trailing bytes inside declared payloads; rejecting a SASL mechanism list missing its final terminator; frontend `FunctionCall`/`GSSENCRequest`/`GSSResponse` messages; `MAX_PACKET_SIZE` enforcement (OPG-201's job).

---

### Task 1: Create `pgerr` leaf package and migrate all error types

**Files:**
- Create: `pgerr/errors.odin`
- Modify: `root.odin` (full rewrite to aliases)
- Modify: `pgproto/parser.odin` (import + ~30 `opg.` references)
- Modify: `pgproto/backend.odin` (import + 2 references)
- Modify: `pgproto/backend_test.odin`, `pgproto/golden_test.odin` (imports + references)
- Modify: `pgconn/pool.odin` (imports + references; drop unused `pgproto` import)
- Modify: `pgorm/mapper.odin` (import + references only — body bug is Task 3)

**Interfaces:**
- Consumes: nothing (first task).
- Produces: package `pgerr` with types `Error`, `Net_Error`, `Net_Error_Type`, `Protocol_Error`, `Protocol_Error_Type`, `Auth_Error`, `Auth_Error_Type`, `Postgres_Error` — identical field layouts to the current `root.odin` versions. Root package `opg` re-exports all of them as aliases. All later tasks refer to `pgerr.X` inside subpackages.

- [ ] **Step 1: Create `pgerr/errors.odin`**

Move the entire error section of `root.odin` (lines 19–103) verbatim into the new file, changing only the package line:

```odin
package pgerr

import "core:net"

Net_Error_Type :: enum {
	None,
	Timeout,
	Socket_Closed,
	Connection_Refused,
	Host_Unreachable,
	Network_Down,
	Send_Failed,
	Recv_Failed,
	DNS_Resolution_Failed,
	TLS_Handshake_Failed,
	Unexpected_EOF,
}

Net_Error :: struct {
	type:          Net_Error_Type,
	code:          i32,
	raw_net_error: net.Network_Error,
}

Protocol_Error_Type :: enum {
	None,
	Malformed_Packet,
	Invalid_Length,
	Unknown_Message_Type,
	Unexpected_Message,
	Buffer_Underflow,
	Invalid_Column_Count,
	Unsupported_Format_Code,
	Unsupported_Protocol_Version,
}

Protocol_Error :: struct {
	type:        Protocol_Error_Type,
	message:     string,
	byte_offset: int,
}

Auth_Error_Type :: enum {
	None,
	Unsupported_Auth_Mechanism,
	SCRAM_Invalid_Server_First_Message,
	SCRAM_Invalid_Server_Final_Message,
	SCRAM_Server_Signature_Mismatch,
	SCRAM_Channel_Binding_Failed,
	Authentication_Failed,
	Invalid_Credentials,
}

Auth_Error :: struct {
	type:    Auth_Error_Type,
	message: string,
}

/*
	Postgres_Error contains the structured error fields returned directly
	from the PostgreSQL engine inside an ErrorResponse ('E') message.
*/
Postgres_Error :: struct {
	severity:          string, // 'S' (FATAL, ERROR, PANIC, etc.)
	code:              string, // 'C' SQLSTATE error code (e.g. "42P01", "28P01")
	message:           string, // 'M' Primary human-readable error message
	detail:            string, // 'D' Optional secondary error detail
	hint:              string, // 'H' Optional suggestion what to do
	position:          string, // 'P' Decimal ASCII integer index into query string
	internal_position: string, // 'p' Internal query position
	internal_query:    string, // 'q' Internal query text
	where_context:     string, // 'W' Call stack / context
	schema_name:       string, // 's' Schema name
	table_name:        string, // 't' Table name
	column_name:       string, // 'c' Column name
	data_type_name:    string, // 'd' Data type name
	constraint_name:   string, // 'n' Constraint name
	file:              string, // 'F' Source file name in PostgreSQL engine
	line:              string, // 'L' Source line number in PostgreSQL engine
	routine:           string, // 'R' Source routine name in PostgreSQL engine
}

// Master tagged union for all driver errors
Error :: union {
	Net_Error,
	Protocol_Error,
	Auth_Error,
	Postgres_Error,
}
```

- [ ] **Step 2: Rewrite `root.odin` as a pure alias facade**

```odin
package opg

import "pgerr"

// PostgreSQL Database Driver (Frontend/Backend Protocol 3.0)

// Architectural Rules:
// 1. 3-Layer Architecture: pgproto (wire codec), pgconn (TCP & pool), pgorm (reflection).
// 2. Big-Endian: Explicit endian-swapping for all network integers via core:encoding/endian.
// 3. Allocator Boundaries: context.temp_allocator for pgproto/pgorm, persistent for pgconn.
// 4. Tagged Union Errors: Unified Error union defined in the pgerr leaf package;
//    re-exported here so consumers only need `import "opg"`.

Error               :: pgerr.Error
Net_Error           :: pgerr.Net_Error
Net_Error_Type      :: pgerr.Net_Error_Type
Protocol_Error      :: pgerr.Protocol_Error
Protocol_Error_Type :: pgerr.Protocol_Error_Type
Auth_Error          :: pgerr.Auth_Error
Auth_Error_Type     :: pgerr.Auth_Error_Type
Postgres_Error      :: pgerr.Postgres_Error
```

- [ ] **Step 3: Repoint all subpackage imports**

In each file below, replace the parent import and every `opg.` qualifier with `pgerr.`:

- `pgproto/parser.odin`: `import ".."` → `import "../pgerr"`; all `opg.Error`, `opg.Protocol_Error`, `opg.Postgres_Error` → `pgerr.*`. Also update the doc comments that mention `opg.Error`.
- `pgproto/backend.odin`: `import ".."` → `import "../pgerr"`; `opg.Postgres_Error` → `pgerr.Postgres_Error` (in `Msg_Notice_Response` and the `Backend_Message` union).
- `pgproto/backend_test.odin`: `import ".."` → `import "../pgerr"`; `opg.` → `pgerr.`.
- `pgproto/golden_test.odin`: `import opg ".."` → `import "../pgerr"`; `opg.` → `pgerr.`.
- `pgconn/pool.odin`: delete `import ".."` and the unused `import "../pgproto"`; add `import "../pgerr"`; `opg.` → `pgerr.`.
- `pgorm/mapper.odin`: `import ".."` → `import "../pgerr"`; `opg.` → `pgerr.` (the `.Malformed_Data` body bug remains — Task 3).

- [ ] **Step 4: Verify checks and tests**

Run:
```bash
odin check . -no-entry-point -vet -strict-style
odin check pgerr -no-entry-point -vet -strict-style
odin check pgproto -no-entry-point -vet -strict-style
odin check pgconn -no-entry-point -vet -strict-style
odin check pgorm -no-entry-point
odin test pgproto -vet -strict-style
```
Expected: all checks exit 0; 28 tests pass. (`pgorm` is checked WITHOUT `-vet` — its unused-import vet failure is fixed in Task 3.)

- [ ] **Step 5: Commit**

```bash
git add pgerr/ root.odin pgproto/ pgconn/ pgorm/
git commit -m "refactor: move error types into pgerr leaf package to prevent import cycle"
```

---

### Task 2: Consolidate the buffer API (keep `Reader` + stateless writers, drop the rest)

**Files:**
- Modify: `pgproto/buffer.odin` (delete stateless `read_*` procs and `Writer`; inline logic into `reader_*`; add `reader_peek_u8`; `err != .None` → `err != nil`)
- Modify: `pgproto/parser.odin` (SASL loop uses `reader_peek_u8`)
- Modify: `pgproto/buffer_test.odin`, `pgproto/backend_test.odin` (rewrite to surviving API)

**Interfaces:**
- Consumes: Task 1's `pgerr` imports (unchanged here).
- Produces: the final buffer API used by ALL later tasks:
  - Reads: `Reader`, `reader_init(r: ^Reader, buf: []byte)`, `reader_remaining(r: ^Reader) -> int`, `reader_has_bytes(r: ^Reader, count: int) -> bool`, `reader_peek_u8(r: ^Reader) -> (u8, bool)`, `reader_read_u8/i16/u16/i32/u32/i64`, `reader_read_bytes(r: ^Reader, count: int) -> ([]byte, bool)`, `reader_read_string_nt(r: ^Reader) -> (string, bool)`, `reader_read_string_nt_clone(r: ^Reader, allocator := context.temp_allocator) -> (string, bool)`.
  - Writes: `write_u8/i16/u16/i32/u32/i64(builder: ^[dynamic]byte, val)`, `write_bytes`, `write_string_nt`, `write_packet_header(builder, msg_type: u8) -> int`, `write_packet_header_untyped(builder) -> int`, `finish_packet(builder, length_pos: int) -> int`.
  - Deleted (do not reference anywhere after this task): `read_u8`, `read_i16`, `read_u16`, `read_i32`, `read_u32`, `read_i64`, `read_bytes_counted`, `read_string_nt`, `read_string_nt_clone`, `Writer`, `writer_init`, all `writer_*` procs.

- [ ] **Step 1: Rewrite the read side of `pgproto/buffer.odin`**

Replace each `reader_read_*` delegation with the inlined body; delete the stateless procs and the whole `Writer` section. The read side becomes exactly:

```odin
/*
	Reader holds a read-only buffer slice and an internal read offset cursor.
*/
Reader :: struct {
	buf:    []byte,
	offset: int,
}

/*
	reader_init initializes a Reader with the given buffer slice, resetting offset to 0.
*/
reader_init :: proc(r: ^Reader, buf: []byte) {
	r.buf = buf
	r.offset = 0
}

/*
	reader_remaining returns the number of unread bytes remaining in the buffer.
*/
reader_remaining :: proc(r: ^Reader) -> int {
	return max(0, len(r.buf) - r.offset)
}

/*
	reader_has_bytes checks if at least `count` bytes are available from current offset.
*/
reader_has_bytes :: proc(r: ^Reader, count: int) -> bool {
	return count >= 0 && r.offset + count <= len(r.buf)
}

/*
	reader_peek_u8 returns the byte at the current offset without advancing the cursor.
*/
reader_peek_u8 :: proc(r: ^Reader) -> (val: u8, ok: bool) {
	if r.offset < 0 || r.offset >= len(r.buf) {
		return 0, false
	}
	return r.buf[r.offset], true
}

/*
	reader_read_u8 reads a single byte and advances the cursor.
*/
reader_read_u8 :: proc(r: ^Reader) -> (val: u8, ok: bool) {
	if r.offset < 0 || r.offset + 1 > len(r.buf) {
		return 0, false
	}
	val = r.buf[r.offset]
	r.offset += 1
	return val, true
}

/*
	reader_read_i16 reads a big-endian 16-bit signed integer and advances the cursor.
*/
reader_read_i16 :: proc(r: ^Reader) -> (val: i16, ok: bool) {
	if r.offset < 0 || r.offset + 2 > len(r.buf) {
		return 0, false
	}
	val = endian.get_i16(r.buf[r.offset:r.offset + 2], .Big) or_return
	r.offset += 2
	return val, true
}

/*
	reader_read_u16 reads a big-endian 16-bit unsigned integer and advances the cursor.
*/
reader_read_u16 :: proc(r: ^Reader) -> (val: u16, ok: bool) {
	if r.offset < 0 || r.offset + 2 > len(r.buf) {
		return 0, false
	}
	val = endian.get_u16(r.buf[r.offset:r.offset + 2], .Big) or_return
	r.offset += 2
	return val, true
}

/*
	reader_read_i32 reads a big-endian 32-bit signed integer and advances the cursor.
*/
reader_read_i32 :: proc(r: ^Reader) -> (val: i32, ok: bool) {
	if r.offset < 0 || r.offset + 4 > len(r.buf) {
		return 0, false
	}
	val = endian.get_i32(r.buf[r.offset:r.offset + 4], .Big) or_return
	r.offset += 4
	return val, true
}

/*
	reader_read_u32 reads a big-endian 32-bit unsigned integer and advances the cursor.
*/
reader_read_u32 :: proc(r: ^Reader) -> (val: u32, ok: bool) {
	if r.offset < 0 || r.offset + 4 > len(r.buf) {
		return 0, false
	}
	val = endian.get_u32(r.buf[r.offset:r.offset + 4], .Big) or_return
	r.offset += 4
	return val, true
}

/*
	reader_read_i64 reads a big-endian 64-bit signed integer and advances the cursor.
*/
reader_read_i64 :: proc(r: ^Reader) -> (val: i64, ok: bool) {
	if r.offset < 0 || r.offset + 8 > len(r.buf) {
		return 0, false
	}
	val = endian.get_i64(r.buf[r.offset:r.offset + 8], .Big) or_return
	r.offset += 8
	return val, true
}

/*
	reader_read_bytes slices `count` bytes from the buffer and advances the cursor. Zero-copy.
*/
reader_read_bytes :: proc(r: ^Reader, count: int) -> (val: []byte, ok: bool) {
	if r.offset < 0 || count < 0 || r.offset + count > len(r.buf) {
		return nil, false
	}
	val = r.buf[r.offset:r.offset + count]
	r.offset += count
	return val, true
}

/*
	reader_read_string_nt reads a null-terminated UTF-8 string view and advances the
	cursor past the null terminator. Zero-copy: the string borrows from r.buf.
*/
reader_read_string_nt :: proc(r: ^Reader) -> (val: string, ok: bool) {
	if r.offset < 0 || r.offset >= len(r.buf) {
		return "", false
	}
	start := r.offset
	for i in start ..< len(r.buf) {
		if r.buf[i] == 0x00 {
			val = string(r.buf[start:i])
			r.offset = i + 1
			return val, true
		}
	}
	return "", false
}

/*
	reader_read_string_nt_clone reads a null-terminated UTF-8 string, cloning it using
	the provided allocator (defaults to context.temp_allocator). The cursor is not
	advanced if the read or the allocation fails.
*/
reader_read_string_nt_clone :: proc(
	r: ^Reader,
	allocator := context.temp_allocator,
) -> (
	val: string,
	ok: bool,
) {
	saved_offset := r.offset
	str_slice := reader_read_string_nt(r) or_return
	cloned, err := strings.clone(str_slice, allocator)
	if err != nil {
		r.offset = saved_offset
		return "", false
	}
	return cloned, true
}
```

The write side (`write_u8` ... `finish_packet`) stays byte-for-byte as it is today. Delete `Writer`, `writer_init`, and every `writer_*` proc.

- [ ] **Step 2: Switch the SASL peek in `pgproto/parser.odin`**

In `parse_authentication`, replace:

```odin
if reader_remaining(&r) == 0 {
	break
}
if r.buf[r.offset] == 0x00 {
	r.offset += 1
	break
}
```

with:

```odin
next_byte, has_next := reader_peek_u8(&r)
if !has_next {
	break
}
if next_byte == 0x00 {
	_, _ = reader_read_u8(&r)
	break
}
```

- [ ] **Step 3: Rewrite `pgproto/buffer_test.odin` against the surviving API**

Mechanical conversion rules (apply to every test; semantics of each assertion must be preserved):
- `read_X(data, &offset)` → `reader_init` a `Reader` over `data` once, then `reader_read_X(&r)`; assertions on `offset` become assertions on `r.offset`.
- Negative-offset cases set `r.offset = -1` directly before the read and assert the read fails and `r.offset` is unchanged.
- `read_bytes_counted(data, &offset, n)` → `reader_read_bytes(&r, n)`.
- `read_string_nt_clone(data, &offset, alloc)` → `reader_read_string_nt_clone(&r, alloc)` (this covers `test_read_string_nt_clone_allocator_failure` — keep the failing-allocator sub-tests, asserting `r.offset` rollback).
- `w: Writer; writer_init(&w, &buf); writer_write_X(&w, v)` → `write_X(&buf, v)`; `writer_begin_packet(&w, t)` → `write_packet_header(&buf, t)`; `writer_begin_packet_untyped` → `write_packet_header_untyped`; `writer_end_packet(&w, pos)` → `finish_packet(&buf, pos)`.
- Add one new test for the peek primitive:

```odin
@(test)
test_reader_peek_u8 :: proc(t: ^testing.T) {
	data := []byte{0xAB, 0xCD}
	r: Reader
	reader_init(&r, data)

	v1, ok1 := reader_peek_u8(&r)
	testing.expect(t, ok1, "peek should succeed")
	testing.expect_value(t, v1, u8(0xAB))
	testing.expect_value(t, r.offset, 0) // peek must not advance

	_, _ = reader_read_u8(&r)
	_, _ = reader_read_u8(&r)
	_, ok_eof := reader_peek_u8(&r)
	testing.expect(t, !ok_eof, "peek at EOF should fail")

	r.offset = -1
	_, ok_neg := reader_peek_u8(&r)
	testing.expect(t, !ok_neg, "peek at negative offset should fail")
}
```

- [ ] **Step 4: Convert `Writer` usage in `pgproto/backend_test.odin`**

Same mechanical rules as Step 3. Example — the RowDescription builder in `test_parse_query_result_messages` becomes:

```odin
var_rd: [dynamic]byte
len_pos := write_packet_header(&var_rd, 'T')
write_i16(&var_rd, 2) // 2 fields
write_string_nt(&var_rd, "id")
write_u32(&var_rd, 1234)
write_i16(&var_rd, 1)
write_u32(&var_rd, 23)
write_i16(&var_rd, 4)
write_i32(&var_rd, -1)
write_i16(&var_rd, 0)
write_string_nt(&var_rd, "name")
write_u32(&var_rd, 1234)
write_i16(&var_rd, 2)
write_u32(&var_rd, 25)
write_i16(&var_rd, -1)
write_i32(&var_rd, -1)
write_i16(&var_rd, 0)
finish_packet(&var_rd, len_pos)
```

(`golden_test.odin` and `frontend_test.odin` never used `Writer` — only `Reader` and encoders — so they need no changes; the `reader_*` calls in the truncation-matrix test keep working.)

- [ ] **Step 5: Verify**

Run:
```bash
odin check pgproto -no-entry-point -vet -strict-style
odin test pgproto -vet -strict-style
odin test pgproto -sanitize:address
```
Expected: all pass, 29 tests (28 + the new peek test).

- [ ] **Step 6: Commit**

```bash
git add pgproto/
git commit -m "refactor(pgproto): consolidate buffer API around Reader and stateless writers"
```

---

### Task 3: Fix `pgorm` latent compile error and add instantiating smoke tests

**Files:**
- Modify: `pgorm/mapper.odin`
- Create: `pgorm/mapper_test.odin`

**Interfaces:**
- Consumes: `pgproto.Msg_Row_Description`, `pgproto.Field_Description`, `pgproto.Msg_Data_Row`, `pgproto.Column_Value`, `pgerr.Error`, `pgerr.Protocol_Error`.
- Produces: `map_row_to_struct :: proc($T: typeid, desc, row, allocator := context.temp_allocator) -> (result: T, err: pgerr.Error) where intrinsics.type_is_struct(T)` and `map_rows_to_slice` with the same `where` clause. Non-struct `T` is now a compile error, not a runtime error.

- [ ] **Step 1: Write the failing smoke tests (`pgorm/mapper_test.odin`)**

```odin
package pgorm

import "core:mem"
import "core:testing"
import "../pgproto"

Test_User :: struct {
	id:     i64,
	name:   string,
	active: bool,
	score:  f64 `db:"points"`,
}

text_col :: proc(s: string) -> pgproto.Column_Value {
	return pgproto.Column_Value{is_null = false, data = transmute([]byte)s}
}

@(test)
test_map_row_to_struct_text_format :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	desc := pgproto.Msg_Row_Description{
		fields = []pgproto.Field_Description{
			{name = "id"},
			{name = "name"},
			{name = "points"},
			{name = "active"},
		},
	}
	row := pgproto.Msg_Data_Row{
		values = []pgproto.Column_Value{
			text_col("42"),
			text_col("alice"),
			text_col("3.5"),
			text_col("t"),
		},
	}

	u, err := map_row_to_struct(Test_User, desc, row)
	testing.expect_value(t, err, nil)
	testing.expect_value(t, u.id, i64(42))
	testing.expect_value(t, u.name, "alice")
	testing.expect_value(t, u.score, 3.5)
	testing.expect_value(t, u.active, true)

	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
test_map_row_to_struct_null_and_missing_columns :: proc(t: ^testing.T) {
	desc := pgproto.Msg_Row_Description{
		fields = []pgproto.Field_Description{
			{name = "id"},
			{name = "name"},
		},
	}
	row := pgproto.Msg_Data_Row{
		values = []pgproto.Column_Value{
			text_col("7"),
			{is_null = true, data = nil},
		},
	}

	// NULL column and struct fields without matching columns stay zero-valued.
	u, err := map_row_to_struct(Test_User, desc, row)
	testing.expect_value(t, err, nil)
	testing.expect_value(t, u.id, i64(7))
	testing.expect_value(t, u.name, "")
	testing.expect_value(t, u.active, false)
	testing.expect_value(t, u.score, 0.0)
}

@(test)
test_map_row_to_struct_column_count_mismatch :: proc(t: ^testing.T) {
	desc := pgproto.Msg_Row_Description{
		fields = []pgproto.Field_Description{
			{name = "id"},
			{name = "name"},
		},
	}
	row := pgproto.Msg_Data_Row{
		values = []pgproto.Column_Value{
			text_col("1"),
		},
	}

	_, err := map_row_to_struct(Test_User, desc, row)
	p_err, is_proto := err.(pgerr.Protocol_Error)
	testing.expect(t, is_proto, "expected pgerr.Protocol_Error")
	testing.expect_value(t, p_err.type, pgerr.Protocol_Error_Type.Invalid_Column_Count)
}

@(test)
test_map_rows_to_slice :: proc(t: ^testing.T) {
	desc := pgproto.Msg_Row_Description{
		fields = []pgproto.Field_Description{
			{name = "id"},
			{name = "name"},
		},
	}
	rows := []pgproto.Msg_Data_Row{
		{values = []pgproto.Column_Value{text_col("1"), text_col("a")}},
		{values = []pgproto.Column_Value{text_col("2"), text_col("b")}},
	}

	out, err := map_rows_to_slice(Test_User, desc, rows)
	testing.expect_value(t, err, nil)
	testing.expect_value(t, len(out), 2)
	testing.expect_value(t, out[0].id, i64(1))
	testing.expect_value(t, out[0].name, "a")
	testing.expect_value(t, out[1].id, i64(2))
	testing.expect_value(t, out[1].name, "b")
}
```

This test file also needs `import "../pgerr"`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `odin test pgorm`
Expected: FAIL at compile time with `Undeclared name 'Malformed_Data' for type 'Protocol_Error_Type'` (the instantiation now forces checking of the polymorphic body — exactly the latent bug).

- [ ] **Step 3: Fix `pgorm/mapper.odin`**

- Add `import "base:intrinsics"`; remove `import "core:mem"` (unused).
- Add `where intrinsics.type_is_struct(T)` to BOTH `map_row_to_struct` and `map_rows_to_slice` signatures (after the return list, before the body).
- Delete the runtime non-struct check entirely (the `ti` / `struct_info, is_struct` preamble and the `.Malformed_Data` error return) — the `where` clause makes it a compile-time guarantee.
- Change the field loop from `#no_bounds_check for field, i in reflect.struct_fields_zipped(T)` to `for field in reflect.struct_fields_zipped(T)` (`i` is unused; the bounds-check suppression buys nothing here).

Resulting head of the proc:

```odin
map_row_to_struct :: proc(
	$T: typeid,
	desc: pgproto.Msg_Row_Description,
	row: pgproto.Msg_Data_Row,
	allocator := context.temp_allocator,
) -> (
	result: T,
	err: pgerr.Error,
) where intrinsics.type_is_struct(T) {
	// Verify column count matches expected struct fields or handle partial mapping
	if len(row.values) != len(desc.fields) {
		return result, pgerr.Protocol_Error{
			type = .Invalid_Column_Count,
			message = "Mismatch between DataRow value count and RowDescription field count",
		}
	}

	for field in reflect.struct_fields_zipped(T) {
		...unchanged body...
	}

	return result, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run:
```bash
odin test pgorm -vet -strict-style
odin check pgorm -no-entry-point -vet -strict-style
```
Expected: 4 tests pass; vet is now clean (all imports used by the instantiated body).

- [ ] **Step 5: Commit**

```bash
git add pgorm/
git commit -m "fix(pgorm): repair uninstantiated mapper body and add instantiating smoke tests"
```

---

### Task 4: Wire-value validation — unknown auth codes, format codes, 32-bit length guard

**Files:**
- Modify: `pgerr/errors.odin` (one new enum variant)
- Modify: `pgproto/parser.odin` (`parse_authentication`, `parse_row_description`, `parse_copy_response`, `parse_message` header check)
- Modify: `pgproto/backend_test.odin` (new tests)

**Interfaces:**
- Consumes: Task 2's buffer API for test packet building.
- Produces: `pgerr.Protocol_Error_Type.Unknown_Auth_Type`; parsers now reject invalid `Auth_Type` and `Field_Format` wire values.

- [ ] **Step 1: Write the failing tests (append to `pgproto/backend_test.odin`)**

```odin
@(test)
test_parse_authentication_unknown_code :: proc(t: ^testing.T) {
	// Auth code 4 (obsolete crypt password) is not a recognized Auth_Type.
	pkt := []byte{'R', 0, 0, 0, 8, 0, 0, 0, 4}
	msg, n, err := parse_message(pkt)
	testing.expect(t, msg == nil, "expected nil message for unknown auth code")
	testing.expect_value(t, n, 0)
	p_err, is_proto := err.(pgerr.Protocol_Error)
	testing.expect(t, is_proto, "expected Protocol_Error")
	testing.expect_value(t, p_err.type, pgerr.Protocol_Error_Type.Unknown_Auth_Type)

	pkt_hi := []byte{'R', 0, 0, 0, 8, 0, 0, 0, 99}
	_, _, err_hi := parse_message(pkt_hi)
	p_err_hi, is_proto_hi := err_hi.(pgerr.Protocol_Error)
	testing.expect(t, is_proto_hi, "expected Protocol_Error")
	testing.expect_value(t, p_err_hi.type, pgerr.Protocol_Error_Type.Unknown_Auth_Type)
}

@(test)
test_parse_unsupported_format_codes :: proc(t: ^testing.T) {
	buf: [dynamic]byte
	defer delete(buf)

	// 1. RowDescription field with format code 7
	pos := write_packet_header(&buf, 'T')
	write_i16(&buf, 1)
	write_string_nt(&buf, "id")
	write_u32(&buf, 0)
	write_i16(&buf, 0)
	write_u32(&buf, 23)
	write_i16(&buf, 4)
	write_i32(&buf, -1)
	write_i16(&buf, 7) // invalid: only 0 (text) and 1 (binary) exist
	finish_packet(&buf, pos)
	_, _, err_rd := parse_message(buf[:])
	p_rd, is_rd := err_rd.(pgerr.Protocol_Error)
	testing.expect(t, is_rd, "expected Protocol_Error for RowDescription format code")
	testing.expect_value(t, p_rd.type, pgerr.Protocol_Error_Type.Unsupported_Format_Code)

	// 2. CopyInResponse with invalid overall format 2
	clear(&buf)
	pos = write_packet_header(&buf, 'G')
	write_u8(&buf, 2)
	write_i16(&buf, 0)
	finish_packet(&buf, pos)
	_, _, err_ov := parse_message(buf[:])
	p_ov, is_ov := err_ov.(pgerr.Protocol_Error)
	testing.expect(t, is_ov, "expected Protocol_Error for overall copy format")
	testing.expect_value(t, p_ov.type, pgerr.Protocol_Error_Type.Unsupported_Format_Code)

	// 3. CopyOutResponse with invalid column format code 9
	clear(&buf)
	pos = write_packet_header(&buf, 'H')
	write_u8(&buf, 0)
	write_i16(&buf, 1)
	write_i16(&buf, 9)
	finish_packet(&buf, pos)
	_, _, err_col := parse_message(buf[:])
	p_col, is_col := err_col.(pgerr.Protocol_Error)
	testing.expect(t, is_col, "expected Protocol_Error for column copy format")
	testing.expect_value(t, p_col.type, pgerr.Protocol_Error_Type.Unsupported_Format_Code)
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `odin test pgproto`
Expected: FAIL — first test compiles only after the enum variant exists, so add `Unknown_Auth_Type,` to `pgerr.Protocol_Error_Type` (after `Unknown_Message_Type,`) first, then observe both tests fail on assertions (parsers currently accept the bad values).

- [ ] **Step 3: Implement the validations in `pgproto/parser.odin`**

a) `parse_authentication` — add a default case to the switch and delete the now-unreachable trailing `return msg, nil` after the switch (if the compiler still demands a terminating statement, keep it; `-vet` decides):

```odin
case:
	return {}, pgerr.Protocol_Error{
		type = .Unknown_Auth_Type,
		message = "Unrecognized authentication type code",
		byte_offset = 0,
	}
```

b) `parse_row_description` — before constructing `Field_Description`, validate:

```odin
if fmt_code != 0 && fmt_code != 1 {
	return {}, pgerr.Protocol_Error{
		type = .Unsupported_Format_Code,
		message = "Field format code must be 0 (text) or 1 (binary)",
		byte_offset = r.offset,
	}
}
```

c) `parse_copy_response` — validate `fmt_byte` right after reading it, and each `col_fmt` inside the loop, with the same `.Unsupported_Format_Code` error (return `.Text, nil, ...` as the other error paths do).

d) `parse_message` — make the header bounds check overflow-proof on 32-bit targets. Replace:

```odin
total_msg_len := 1 + int(payload_len_i32)
if len(data) < total_msg_len {
```

with:

```odin
if i64(len(data)) < i64(payload_len_i32) + 1 {
	return nil, 0, pgerr.Protocol_Error{
		type = .Buffer_Underflow,
		message = "Incomplete packet payload received",
		byte_offset = len(data),
	}
}
total_msg_len := 1 + int(payload_len_i32)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `odin test pgproto -vet -strict-style`
Expected: all tests pass (31 total). The existing truncation/mutation suites must stay green — they only ever feed valid format codes.

- [ ] **Step 5: Commit**

```bash
git add pgerr/errors.odin pgproto/
git commit -m "fix(pgproto): reject unknown auth type codes and invalid format codes"
```

---

### Task 5: Error payload modeling — `severity_unlocalized` + `Msg_Error_Response` wrapper

**Files:**
- Modify: `pgerr/errors.odin` (new field)
- Modify: `pgproto/backend.odin` (new wrapper struct, union variant swap)
- Modify: `pgproto/parser.odin` (field routing, wrapper return)
- Modify: `pgproto/backend_test.odin`, `pgproto/golden_test.odin` (assertions)

**Interfaces:**
- Consumes: `pgerr.Postgres_Error`.
- Produces: `pgerr.Postgres_Error.severity_unlocalized: string` (field code 'V'); `pgproto.Msg_Error_Response :: struct { error: pgerr.Postgres_Error }` replacing the bare `pgerr.Postgres_Error` variant in `Backend_Message`. Task 8's clone helper must clone the new field too.

- [ ] **Step 1: Update the failing tests first**

In `backend_test.odin` `test_parse_error_and_notice_messages`:
- Change both `msg_e.(pgerr.Postgres_Error)` / `msg_all.(pgerr.Postgres_Error)` type assertions to `.(Msg_Error_Response)` and read fields via `.error.`.
- Add after the existing severity asserts:

```odin
testing.expect_value(t, pg_err.error.severity, "ERROR")
testing.expect_value(t, pg_err.error.severity_unlocalized, "ERROR")
```

(and for the FATAL case: `severity_unlocalized == "FATAL"`). The builders already write both 'S' and 'V'.
- In `test_parse_error_and_notice_edge_cases`, the packet writing only 'S' and 'M' must now assert `severity == "ERROR"` and `severity_unlocalized == ""`.
- In `golden_test.odin` fixture 15 (`be_error_response.bin`): change `msg.(pgerr.Postgres_Error)` to `msg.(Msg_Error_Response)`, read via `.error.`, and add `testing.expect_value(t, pg_err.error.severity_unlocalized, "ERROR")` (the fixture contains both 'S' and 'V' fields with value "ERROR").

Run: `odin test pgproto` — Expected: compile FAIL (`Msg_Error_Response` undeclared).

- [ ] **Step 2: Implement**

a) `pgerr/errors.odin` — in `Postgres_Error`, after `severity`:

```odin
severity_unlocalized: string, // 'V' Non-localized severity (PostgreSQL 9.6+)
```

(update the `severity` comment to say `// 'S'` only).

b) `pgproto/backend.odin` — add next to `Msg_Notice_Response`:

```odin
Msg_Error_Response :: struct {
	error: pgerr.Postgres_Error,
}
```

and in the `Backend_Message` union replace `pgerr.Postgres_Error,` with `Msg_Error_Response,` (keep alphabetical position: after `Msg_Empty_Query_Response`, before `Msg_Function_Call_Response`).

c) `pgproto/parser.odin`:
- In `parse_error_or_notice_fields`, route `case 'S': pg_err.severity = str_val` and `case 'V': pg_err.severity_unlocalized = str_val`.
- In `parse_message` `.Error_Response` case: `return Msg_Error_Response{error = err_resp}, total_msg_len, nil`.

- [ ] **Step 3: Run tests to verify they pass**

Run: `odin test pgproto -vet -strict-style`
Expected: all pass.

- [ ] **Step 4: Commit**

```bash
git add pgerr/errors.odin pgproto/
git commit -m "feat(pgproto): distinguish localized/unlocalized severity and wrap ErrorResponse"
```

---

### Task 6: Parser allocator hygiene — free partial allocations on error, real leak tests

**Files:**
- Modify: `pgproto/parser.odin` (deferred frees in 6 parsers)
- Modify: `pgproto/backend_test.odin` (new tracked-allocator test)

**Interfaces:**
- Consumes: everything above.
- Produces: guarantee "parsers never leak under any allocator, on success (caller frees) or failure (parser frees)". No signature changes.

- [ ] **Step 1: Write the failing test (append to `pgproto/backend_test.odin`)**

```odin
@(test)
test_parse_allocations_with_tracked_allocator :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	tracked := mem.tracking_allocator(&track)

	// --- Success paths: allocations must be exactly the documented containers,
	// and freeing them must leave zero live allocations.
	{
		buf: [dynamic]byte
		defer delete(buf)
		pos := write_packet_header(&buf, 'T')
		write_i16(&buf, 1)
		write_string_nt(&buf, "id")
		write_u32(&buf, 0)
		write_i16(&buf, 0)
		write_u32(&buf, 23)
		write_i16(&buf, 4)
		write_i32(&buf, -1)
		write_i16(&buf, 0)
		finish_packet(&buf, pos)

		msg, _, err := parse_message(buf[:], tracked)
		testing.expect_value(t, err, nil)
		rd, ok := msg.(Msg_Row_Description)
		testing.expect(t, ok, "expected Msg_Row_Description")
		delete(rd.fields, tracked)
	}
	testing.expect_value(t, len(track.allocation_map), 0)

	// --- Error paths: the parser must free its own partial allocations.

	// RowDescription: field count passes the pre-check, name string is unterminated,
	// so the failure happens AFTER the fields slice is allocated.
	{
		payload := make([]byte, 22, context.temp_allocator)
		payload[0] = 0x00
		payload[1] = 0x01 // 1 field
		for i in 2 ..< len(payload) {
			payload[i] = 'a' // no null terminator anywhere
		}
		_, err := parse_row_description(payload, tracked)
		testing.expect(t, err != nil, "expected error on unterminated field name")
	}
	testing.expect_value(t, len(track.allocation_map), 0)

	// DataRow: column count passes the pre-check, column length is invalid (-2),
	// failing after the values slice is allocated.
	{
		buf: [dynamic]byte
		defer delete(buf)
		pos := write_packet_header(&buf, 'D')
		write_i16(&buf, 1)
		write_i32(&buf, -2)
		finish_packet(&buf, pos)
		_, _, err := parse_message(buf[:], tracked)
		testing.expect(t, err != nil, "expected error on col_len -2")
	}
	testing.expect_value(t, len(track.allocation_map), 0)

	// Authentication SASL: one valid mechanism (allocates via append), then an
	// unterminated second mechanism triggers the error path.
	{
		payload := []byte{0, 0, 0, 10, 'M', '1', 0x00, 'A', 'B'}
		_, err := parse_authentication(payload, tracked)
		testing.expect(t, err != nil, "expected error on unterminated SASL mechanism")
	}
	testing.expect_value(t, len(track.allocation_map), 0)

	// NegotiateProtocolVersion: option string unterminated after opts slice allocated.
	{
		payload := []byte{0, 0, 0, 1, 0, 0, 0, 1, 'o'}
		_, err := parse_negotiate_protocol_version(payload, tracked)
		testing.expect(t, err != nil, "expected error on unterminated option string")
	}
	testing.expect_value(t, len(track.allocation_map), 0)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `odin test pgproto`
Expected: FAIL on the `len(track.allocation_map) == 0` assertions after the error-path blocks (parsers currently leak the container on error).

- [ ] **Step 3: Add deferred frees in `pgproto/parser.odin`**

Immediately after each container allocation, add a deferred conditional free (the named return `err` holds its final value when defers run):

- `parse_row_description`: after `fields := make(...)` → `defer if err != nil { delete(fields, allocator) }`
- `parse_data_row`: after `values := make(...)` → `defer if err != nil { delete(values, allocator) }`
- `parse_parameter_description`: after `oids := make(...)` → `defer if err != nil { delete(oids, allocator) }`
- `parse_copy_response`: after `col_fmts := make(...)` → `defer if err != nil { delete(col_fmts, allocator) }`
- `parse_negotiate_protocol_version`: after `opts := make(...)` → `defer if err != nil { delete(opts, allocator) }`
- `parse_authentication` (`.SASL` case): after `mechs := make([dynamic]string, allocator)` → `defer if err != nil { delete(mechs) }`

- [ ] **Step 4: Run tests to verify they pass**

Run:
```bash
odin test pgproto -vet -strict-style
odin test pgproto -sanitize:address
```
Expected: all pass, zero leaks, no double frees.

- [ ] **Step 5: Commit**

```bash
git add pgproto/
git commit -m "fix(pgproto): free partial allocations on parser error paths, add tracked-allocator tests"
```

---

### Task 7: Encoder guards, error returns for fallible encoders, named protocol constants

**Files:**
- Modify: `pgproto/frontend.odin`
- Modify: `pgproto/buffer.odin` (`finish_packet` assert)
- Modify: `pgproto/frontend_test.odin`, `pgproto/golden_test.odin` (call sites + new tests)

**Interfaces:**
- Consumes: `pgerr.Protocol_Error`.
- Produces:
  - Constants in `pgproto`: `PROTOCOL_VERSION_3_0 :: 196608`, `SSL_REQUEST_CODE :: 80877103`, `CANCEL_REQUEST_CODE :: 80877102`, `MAX_MESSAGE_FIELD_COUNT :: 65535`.
  - Changed signatures: `encode_parse(...) -> (bytes_written: int, err: pgerr.Error)`, `encode_bind(...) -> (bytes_written: int, err: pgerr.Error)`, `encode_frontend_message(...) -> (bytes_written: int, err: pgerr.Error)`. All other encoders keep `-> int`.
  - Count fields (Parse OID count; Bind format/value/result-format counts) are written with `write_u16` and validated `<= MAX_MESSAGE_FIELD_COUNT`. On validation failure the builder is untouched.

- [ ] **Step 1: Write the failing tests (append to `pgproto/frontend_test.odin`)**

```odin
@(test)
test_encoder_count_guards :: proc(t: ^testing.T) {
	buf: [dynamic]byte
	defer delete(buf)

	too_many_oids := make([]u32, 65536, context.temp_allocator)
	n, err := encode_parse(&buf, "s", "SELECT 1", too_many_oids)
	testing.expect_value(t, n, 0)
	testing.expect(t, err != nil, "expected error for 65536 param OIDs")
	p_err, is_proto := err.(pgerr.Protocol_Error)
	testing.expect(t, is_proto, "expected Protocol_Error")
	testing.expect_value(t, p_err.type, pgerr.Protocol_Error_Type.Invalid_Length)
	testing.expect_value(t, len(buf), 0) // builder must be untouched on error

	too_many_params := make([]Bind_Param, 65536, context.temp_allocator)
	n_b, err_b := encode_bind(&buf, Msg_Bind{param_values = too_many_params})
	testing.expect_value(t, n_b, 0)
	testing.expect(t, err_b != nil, "expected error for 65536 bind params")
	testing.expect_value(t, len(buf), 0)

	// Dispatcher propagates the error.
	n_d, err_d := encode_frontend_message(&buf, Msg_Parse{query = "q", param_oids = too_many_oids})
	testing.expect_value(t, n_d, 0)
	testing.expect(t, err_d != nil, "expected dispatcher to propagate encoder error")
	testing.expect_value(t, len(buf), 0)

	// Boundary: exactly 65535 format codes is legal (count wire-encodes as u16 0xFFFF).
	max_codes := make([]Field_Format, 65535, context.temp_allocator)
	n_ok, err_ok := encode_bind(&buf, Msg_Bind{param_format_codes = max_codes})
	testing.expect_value(t, err_ok, nil)
	testing.expect(t, n_ok > 0, "expected successful encode at the 65535 boundary")
	// Count field lives right after portal "" (1) + statement "" (1): bytes 7..8.
	testing.expect_value(t, buf[6], u8(0xFF))
	testing.expect_value(t, buf[7], u8(0xFF))
}
```

This test file needs `import "../pgerr"` added.

- [ ] **Step 2: Run tests to verify they fail**

Run: `odin test pgproto`
Expected: compile FAIL (`encode_parse` returns 1 value). That is the red state for a signature change.

- [ ] **Step 3: Implement in `pgproto/frontend.odin`**

a) Constants at the top of the file (after the package line / imports):

```odin
// PostgreSQL Frontend/Backend Protocol 3.0 magic numbers.
PROTOCOL_VERSION_3_0 :: 196608   // 3 << 16
SSL_REQUEST_CODE     :: 80877103 // 1234 << 16 | 5679
CANCEL_REQUEST_CODE  :: 80877102 // 1234 << 16 | 5678

// Wire counts in Parse/Bind are 16-bit; PostgreSQL's own limit is 65535.
MAX_MESSAGE_FIELD_COUNT :: 65535
```

Use them in `encode_ssl_request`, `encode_cancel_request`, `encode_startup` (`else 196608` → `else PROTOCOL_VERSION_3_0`).

b) `encode_parse` — new signature `-> (bytes_written: int, err: pgerr.Error)`; guard FIRST (before any write):

```odin
if len(param_oids) > MAX_MESSAGE_FIELD_COUNT {
	return 0, pgerr.Protocol_Error{
		type = .Invalid_Length,
		message = "Parse parameter OID count exceeds 65535",
	}
}
```

then the existing body with `write_i16(builder, i16(len(param_oids)))` → `write_u16(builder, u16(len(param_oids)))`, and final `return len(builder) - start_len, nil`.

c) `encode_bind` — same pattern; guard all three of `len(msg.param_format_codes)`, `len(msg.param_values)`, `len(msg.result_format_codes)` before any write (message: "Bind format code count exceeds 65535" / "Bind parameter count exceeds 65535" / "Bind result format code count exceeds 65535"); switch the three count writes to `write_u16(builder, u16(len(...)))`. The per-format-code writes (`write_i16(builder, i16(fc))`) stay i16.

d) `encode_frontend_message` — new signature `-> (bytes_written: int, err: pgerr.Error)`. Fallible cases forward directly (`return encode_parse(...)`, `return encode_bind(builder, m)`); all other cases wrap: `return encode_query(builder, m.query), nil` etc. The final unreachable `return 0` becomes `return 0, nil`.

e) `pgproto/buffer.odin` `finish_packet` — before writing the length:

```odin
assert(packet_len <= int(max(i32)), "pgproto: packet length exceeds i32 range")
```

f) Update existing call sites:
- `frontend_test.odin`: `p_len := encode_parse(...)` → `p_len, p_parse_err := encode_parse(...)` + `testing.expect_value(t, p_parse_err, nil)`; same for every `encode_bind` call; in `test_encode_frontend_message_all_variants` the loop becomes `encoded_len, enc_err := encode_frontend_message(&buf, msg)` + `testing.expect_value(t, enc_err, nil)`; the two dispatcher calls in `test_encode_copy_and_dispatcher` likewise; `test_extended_query_pipelining` `encode_parse`/`encode_bind` calls likewise.
- `golden_test.odin` `check_fe_golden`: `encode_frontend_message(&buf, msg)` → `_, enc_err := encode_frontend_message(&buf, msg)` + `testing.expect_value(t, enc_err, nil)`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `odin test pgproto -vet -strict-style`
Expected: all pass — including every golden byte-comparison (u16 vs i16 count encoding is identical for all fixture values).

- [ ] **Step 5: Commit**

```bash
git add pgproto/
git commit -m "feat(pgproto): guard encoder counts, add error returns to fallible encoders, name protocol constants"
```

---

### Task 8: Zero-copy contract — clone/destroy helpers and honest comments

**Files:**
- Create: `pgerr/clone.odin`
- Modify: `pgproto/backend.odin` (clone helper + comment fixes)
- Create/Modify tests: `pgerr/clone_test.odin`, `pgproto/backend_test.odin`

**Interfaces:**
- Consumes: `pgerr.Postgres_Error` (incl. Task 5's `severity_unlocalized`), `pgproto.Msg_Parameter_Status`.
- Produces:
  - `pgerr.postgres_error_clone(e: Postgres_Error, allocator := context.allocator) -> (res: Postgres_Error, err: mem.Allocator_Error)`
  - `pgerr.postgres_error_destroy(e: Postgres_Error, allocator := context.allocator)`
  - `pgproto.parameter_status_clone(msg: Msg_Parameter_Status, allocator := context.allocator) -> (res: Msg_Parameter_Status, err: mem.Allocator_Error)`
  - `pgproto.parameter_status_destroy(msg: Msg_Parameter_Status, allocator := context.allocator)`

- [ ] **Step 1: Write the failing tests**

`pgerr/clone_test.odin`:

```odin
package pgerr

import "core:mem"
import "core:testing"

@(test)
test_postgres_error_clone_and_destroy :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	tracked := mem.tracking_allocator(&track)

	src := Postgres_Error{
		severity             = "ERROR",
		severity_unlocalized = "ERROR",
		code                 = "42P01",
		message              = "relation does not exist",
		hint                 = "check the table name",
	}

	cloned, err := postgres_error_clone(src, tracked)
	testing.expect_value(t, err, nil)
	testing.expect_value(t, cloned.severity, "ERROR")
	testing.expect_value(t, cloned.severity_unlocalized, "ERROR")
	testing.expect_value(t, cloned.code, "42P01")
	testing.expect_value(t, cloned.message, "relation does not exist")
	testing.expect_value(t, cloned.hint, "check the table name")
	testing.expect_value(t, cloned.detail, "")

	// Cloned strings must not alias the source memory.
	testing.expect(t, raw_data(cloned.severity) != raw_data(src.severity), "severity must be a copy")
	testing.expect(t, raw_data(cloned.message) != raw_data(src.message), "message must be a copy")

	postgres_error_destroy(cloned, tracked)
	testing.expect_value(t, len(track.allocation_map), 0)
}
```

`pgproto/backend_test.odin` addition:

```odin
@(test)
test_parameter_status_clone_and_destroy :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	tracked := mem.tracking_allocator(&track)

	src := Msg_Parameter_Status{name = "server_version", value = "16.1"}
	cloned, err := parameter_status_clone(src, tracked)
	testing.expect_value(t, err, nil)
	testing.expect_value(t, cloned.name, "server_version")
	testing.expect_value(t, cloned.value, "16.1")
	testing.expect(t, raw_data(cloned.name) != raw_data(src.name), "name must be a copy")
	testing.expect(t, raw_data(cloned.value) != raw_data(src.value), "value must be a copy")

	parameter_status_destroy(cloned, tracked)
	testing.expect_value(t, len(track.allocation_map), 0)
}
```

Run `odin test pgerr` and `odin test pgproto` — Expected: compile FAIL (procs undeclared).

- [ ] **Step 2: Implement `pgerr/clone.odin`**

```odin
package pgerr

import "core:mem"
import "core:strings"

/*
	postgres_error_clone deep-copies every string field of a Postgres_Error into
	`allocator`. Parsed Postgres_Error values borrow from the network read buffer;
	clone anything that must outlive the next socket read.
	On allocation failure, already-cloned fields are NOT freed — use an arena or
	tracking allocator if partial-failure cleanup matters.
*/
postgres_error_clone :: proc(
	e: Postgres_Error,
	allocator := context.allocator,
) -> (
	res: Postgres_Error,
	err: mem.Allocator_Error,
) {
	res.severity = strings.clone(e.severity, allocator) or_return
	res.severity_unlocalized = strings.clone(e.severity_unlocalized, allocator) or_return
	res.code = strings.clone(e.code, allocator) or_return
	res.message = strings.clone(e.message, allocator) or_return
	res.detail = strings.clone(e.detail, allocator) or_return
	res.hint = strings.clone(e.hint, allocator) or_return
	res.position = strings.clone(e.position, allocator) or_return
	res.internal_position = strings.clone(e.internal_position, allocator) or_return
	res.internal_query = strings.clone(e.internal_query, allocator) or_return
	res.where_context = strings.clone(e.where_context, allocator) or_return
	res.schema_name = strings.clone(e.schema_name, allocator) or_return
	res.table_name = strings.clone(e.table_name, allocator) or_return
	res.column_name = strings.clone(e.column_name, allocator) or_return
	res.data_type_name = strings.clone(e.data_type_name, allocator) or_return
	res.constraint_name = strings.clone(e.constraint_name, allocator) or_return
	res.file = strings.clone(e.file, allocator) or_return
	res.line = strings.clone(e.line, allocator) or_return
	res.routine = strings.clone(e.routine, allocator) or_return
	return res, nil
}

/*
	postgres_error_destroy frees every string field previously cloned with
	postgres_error_clone using the same allocator.
*/
postgres_error_destroy :: proc(e: Postgres_Error, allocator := context.allocator) {
	delete(e.severity, allocator)
	delete(e.severity_unlocalized, allocator)
	delete(e.code, allocator)
	delete(e.message, allocator)
	delete(e.detail, allocator)
	delete(e.hint, allocator)
	delete(e.position, allocator)
	delete(e.internal_position, allocator)
	delete(e.internal_query, allocator)
	delete(e.where_context, allocator)
	delete(e.schema_name, allocator)
	delete(e.table_name, allocator)
	delete(e.column_name, allocator)
	delete(e.data_type_name, allocator)
	delete(e.constraint_name, allocator)
	delete(e.file, allocator)
	delete(e.line, allocator)
	delete(e.routine, allocator)
}
```

- [ ] **Step 3: Implement the pgproto helper and fix the borrowing comments in `pgproto/backend.odin`**

Add (needs `import "core:mem"` and `import "core:strings"`):

```odin
/*
	parameter_status_clone deep-copies a Msg_Parameter_Status. Parsed messages
	borrow from the network read buffer; ParameterStatus values are typically
	stored for the connection lifetime, so clone them before the buffer is reused.
*/
parameter_status_clone :: proc(
	msg: Msg_Parameter_Status,
	allocator := context.allocator,
) -> (
	res: Msg_Parameter_Status,
	err: mem.Allocator_Error,
) {
	res.name = strings.clone(msg.name, allocator) or_return
	res.value = strings.clone(msg.value, allocator) or_return
	return res, nil
}

/*
	parameter_status_destroy frees strings previously cloned with parameter_status_clone.
*/
parameter_status_destroy :: proc(msg: Msg_Parameter_Status, allocator := context.allocator) {
	delete(msg.name, allocator)
	delete(msg.value, allocator)
}
```

Comment corrections in `backend.odin` (the strings are views, only containers are allocated):
- `Msg_Authentication.mechanisms`: `// Mechanism name views into the packet; slice allocated via allocator`
- `Msg_Authentication.sasl_data`: `// View into the packet buffer`
- `Msg_Row_Description.fields`: `// Slice allocated via allocator; field name strings are views into the packet`
- `Msg_Data_Row.values`: `// Slice allocated via allocator; column data are views into the packet`
- `Msg_Parameter_Description.param_oids`, `Msg_Copy_*_Response.column_format_codes`: `// Slice allocated via allocator`
- Add one block comment above `Backend_Message`:

```odin
/*
	ZERO-COPY CONTRACT: parsed messages BORROW from the input packet buffer.
	Every string and []byte field is a view into the `data` slice passed to
	parse_message; only container slices (fields, values, mechanisms, oids,
	format codes) are allocated via the provided allocator. Anything that must
	outlive the buffer (e.g. ParameterStatus, Postgres_Error) must be cloned —
	see parameter_status_clone and pgerr.postgres_error_clone.
*/
```

Also update the `parse_message` doc comment Rule 3 line in `parser.odin` to match ("container slices use `allocator`; strings/bytes are zero-copy views into `data`").

- [ ] **Step 4: Run tests to verify they pass**

Run:
```bash
odin test pgerr -vet -strict-style
odin test pgproto -vet -strict-style
```
Expected: all pass, zero leaks.

- [ ] **Step 5: Commit**

```bash
git add pgerr/ pgproto/
git commit -m "feat: add clone/destroy helpers and document the zero-copy borrowing contract"
```

---

### Task 9: Cosmetics — merge Describe/Close target enums, derive `is_valid_backend_type`

**Files:**
- Modify: `pgproto/frontend.odin` (`Target_Kind`)
- Modify: `pgproto/golden_test.odin` (`is_valid_backend_type`)
- Modify: `pgproto/frontend_test.odin` (only if any spelled-out enum type names appear — `.Statement` / `.Portal` literals need no change)

**Interfaces:**
- Consumes: nothing new.
- Produces: `pgproto.Target_Kind :: enum u8 { Statement = 'S', Portal = 'P' }` replacing BOTH `Describe_Target` and `Close_Target`; `Msg_Describe.target_type: Target_Kind`, `Msg_Close.target_type: Target_Kind`; `encode_describe(builder, target_type: Target_Kind, name := "")`, `encode_close(builder, target_type: Target_Kind, name := "")`.

- [ ] **Step 1: Implement**

In `pgproto/frontend.odin` replace the two enums with:

```odin
// Target of a Describe ('D') or Close ('C') message.
Target_Kind :: enum u8 {
	Statement = 'S',
	Portal    = 'P',
}
```

Update `Msg_Describe`, `Msg_Close`, `encode_describe`, `encode_close` signatures accordingly. All call sites use implicit selector syntax (`.Statement`, `.Portal`), so they compile unchanged.

In `pgproto/golden_test.odin` replace `is_valid_backend_type` with a derived version:

```odin
is_valid_backend_type :: proc(b: u8) -> bool {
	for v in Backend_Message_Type {
		if u8(v) == b {
			return true
		}
	}
	return false
}
```

- [ ] **Step 2: Verify**

Run: `odin test pgproto -vet -strict-style`
Expected: all pass (behavior identical).

- [ ] **Step 3: Commit**

```bash
git add pgproto/
git commit -m "refactor(pgproto): merge Describe/Close targets into Target_Kind, derive backend type check from enum"
```

---

### Task 10: Test aggregator package, working documented commands, docs refresh

**Files:**
- Create: `tests/tests.odin`
- Modify: `AGENTS.md` (§1.5 error location, new zero-copy rule, §5 commands)
- Modify: `JIRA.md` (OPG-104/OPG-402 criteria, verification commands)
- Modify: `pgproto/tests_golden_files/README.md` (complete fixture listing, typo fix)

**Interfaces:**
- Consumes: all previous tasks.
- Produces: `odin test tests -all-packages` as the single command that runs every test in the repository.

- [ ] **Step 1: Create `tests/tests.odin`**

```odin
// Aggregator package: exists so `odin test tests -all-packages` discovers and
// runs the tests of every subpackage. @(require) forces inclusion of packages
// this file does not otherwise reference.
package tests

@(require) import "../pgerr"
@(require) import "../pgproto"
@(require) import "../pgconn"
@(require) import "../pgorm"
```

- [ ] **Step 2: Verify the aggregator actually runs everything**

Run from the repo root:
```bash
odin test tests -all-packages
```
Expected: the summary line reports ALL tests (pgproto ~36 + pgorm 4 + pgerr 1 — count must match the sum of per-package runs, NOT "No tests to run"). If `-all-packages` does not pick up imported-package tests on this compiler version, fall back to documenting per-package invocations in AGENTS.md instead (`odin test pgproto && odin test pgorm && odin test pgerr`) and note the limitation — do not ship a command that silently runs nothing.

Golden-file paths are relative to the process working directory, and tests read `pgproto/tests_golden_files/...`, so the command must be documented as "run from the repo root".

- [ ] **Step 3: Update `AGENTS.md`**

- §1 item 5 (Tagged Union Error Handling): change "defined in `root.odin`" to "defined in the leaf package `pgerr` and re-exported by `root.odin`; subpackages import `pgerr` (never the root package — that would create an import cycle)".
- §1 add a new principle after the allocator rule:

```markdown
6. **Zero-Copy Borrowing Contract (`pgproto`)**:
   - Parsed backend messages BORROW from the input packet buffer: strings and
     `[]byte` fields are views into the `data` slice given to `parse_message`.
   - Only container slices (`fields`, `values`, `mechanisms`, `param_oids`,
     format-code slices) are allocated via the `allocator` parameter.
   - Anything that must outlive the next socket read MUST be cloned:
     `pgproto.parameter_status_clone`, `pgerr.postgres_error_clone`.
```

- §5 Running Tests: replace the `odin test . -all-packages` forms with the working commands:

```bash
# Run all tests across all packages (MUST be run from the repo root)
odin test tests -all-packages

# With strict style and linter vetting
odin test tests -all-packages -vet -strict-style

# Address sanitizer
odin test tests -all-packages -sanitize:address
```

- [ ] **Step 4: Update `JIRA.md`**

- OPG-104 acceptance criteria: replace "Line coverage and branch coverage individually ≥ 95% on `pgproto`" with "Every message variant, every parser error return, and every encoder has an explicit test (Odin has no coverage tooling; enumerate, don't estimate)."
- OPG-402 acceptance criteria: replace both `odin test . -all-packages ...` commands with the `odin test tests -all-packages ...` forms.

- [ ] **Step 5: Rewrite `pgproto/tests_golden_files/README.md`**

```markdown
# PostgreSQL Protocol 3.0 Golden Test Vectors

Raw binary captures of PostgreSQL Frontend/Backend Protocol 3.0 messages used by
`pgproto/golden_test.odin` for bit-accurate, zero-network codec verification.

## Packet framing

- Typed messages: `1 byte` message type + `4 byte` big-endian i32 length
  (length includes its own 4 bytes, excludes the type byte) + payload.
- Untyped startup-family messages (`fe_startup_message`, `fe_ssl_request`,
  `fe_cancel_request`): `4 byte` length + payload, no type byte.

## Naming convention

- `fe_*.bin` — frontend (client → server) messages, compared byte-for-byte
  against encoder output in `test_golden_frontend_encoders`.
- `be_*.bin` — backend (server → client) messages, parsed and field-asserted in
  `test_golden_backend_parsers`, and used as the mutation corpus by the
  truncation / corrupted-header fuzz tests.
- `ready_for_query_idle.bin`, `auth_ok.bin`, `backend_key_data.bin` — legacy
  aliases of the corresponding `be_*` fixtures kept for the OPG-103 tests
  (e.g. `ready_for_query_idle.bin` is the 6-byte frame `5a 00 00 00 05 49`).

The expected decoded values for every fixture are asserted in
`pgproto/golden_test.odin`; treat that file as the fixture manifest.
```

- [ ] **Step 6: Final verification gate (whole repo)**

Run:
```bash
odin check . -no-entry-point -vet -strict-style
odin check pgerr -no-entry-point -vet -strict-style
odin check pgproto -no-entry-point -vet -strict-style
odin check pgconn -no-entry-point -vet -strict-style
odin check pgorm -no-entry-point -vet -strict-style
odin test tests -all-packages -vet -strict-style
odin test tests -all-packages -sanitize:address
```
Expected: everything exits 0; the aggregate test count matches the per-package sum.

- [ ] **Step 7: Commit**

```bash
git add tests/ AGENTS.md JIRA.md pgproto/tests_golden_files/README.md
git commit -m "test: add aggregator package and repair documented test commands; refresh docs"
```

---

## Self-Review Notes

- **Spec coverage:** All six items of the review's attack list are covered (T1 error move; T3 pgorm; T4 auth/format codes; T10+T6 test invocation & real leak checks; T8 zero-copy contract & clones; T7/T9/T10 cosmetics), plus the agreed buffer consolidation (T2), `severity_unlocalized` and `Msg_Error_Response` (T5), and the 32-bit guard (T4d). Lenient-parsing items are explicitly declared out of scope in Global Constraints.
- **Ordering rationale:** T2 (buffer API) runs before all tasks that add new test code, so no test is written twice against two APIs. T5 runs before T8 so the clone helper includes `severity_unlocalized` from the start.
- **Type consistency check:** `pgerr.Error` naming used consistently in signatures from T1 on; `encode_parse`/`encode_bind`/`encode_frontend_message` two-value returns introduced only in T7 and all call sites (frontend_test, golden_test) updated in the same task; `Target_Kind` rename (T9) deliberately runs after T7 so the two tasks never edit the same signatures concurrently.
- **Known judgment calls encoded here:** unknown auth code → new `Protocol_Error_Type.Unknown_Auth_Type` (protocol-level rejection, distinct from `Auth_Error.Unsupported_Auth_Mechanism` which remains for pgconn's "known but unsupported" case); encoder count guard uses `.Invalid_Length`; counts wire-encode as u16 with a 65535 cap (matches PostgreSQL's real limit; byte-identical for all existing fixtures).
