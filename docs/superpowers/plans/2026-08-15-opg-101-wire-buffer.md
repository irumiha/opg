# [OPG-101] Wire Buffer Reader / Writer & Big-Endian Codec Primitives Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement robust, bounds-checked, Big-Endian wire buffer reading, writing, framing, and cursor primitives in `pgproto` following PostgreSQL Protocol 3.0 requirements.

**Architecture:** A 2-tier wire buffer codec: (1) low-level stateless procedural primitives operating on `buf: []byte` with explicit `offset: ^int` and `builder: ^[dynamic]byte`, and (2) lightweight `Reader` and `Writer` struct wrappers providing ergonomic cursor management without heap allocation overhead.

**Tech Stack:** Odin, `core:encoding/endian`, `core:strings`, `core:mem`, `core:testing`.

## Global Constraints

- **Strict Adherence**: Follow Odin idioms (tabs for indentation, Pascal_Case for types, snake_case for procs, explicit allocators).
- **Network Byte Order (Big-Endian)**: Multi-byte integers must strictly use `core:encoding/endian`. Raw transmute is strictly forbidden.
- **Safety**: Out-of-bounds reads return `ok = false` without mutating `offset^` and without panicking.
- **Strict Allocators**: Zero heap allocations in transient reads; temp allocator or caller-provided allocator for cloned strings.
- **Quality Gates**: Must pass `odin test pgproto -vet -strict-style` and `odin test pgproto -sanitize:address` with 0 memory leaks tracked by `core:mem.Tracking_Allocator`.

---

### Task 1: Stateless Reader Primitives

**Files:**
- Create: `pgproto/buffer.odin`
- Create: `pgproto/buffer_test.odin`

**Interfaces:**
- Produces:
  ```odin
  read_u8(buf: []byte, offset: ^int) -> (val: u8, ok: bool)
  read_i16(buf: []byte, offset: ^int) -> (val: i16, ok: bool)
  read_u16(buf: []byte, offset: ^int) -> (val: u16, ok: bool)
  read_i32(buf: []byte, offset: ^int) -> (val: i32, ok: bool)
  read_u32(buf: []byte, offset: ^int) -> (val: u32, ok: bool)
  read_i64(buf: []byte, offset: ^int) -> (val: i64, ok: bool)
  read_bytes_counted(buf: []byte, offset: ^int, count: int) -> (val: []byte, ok: bool)
  read_string_nt(buf: []byte, offset: ^int) -> (val: string, ok: bool)
  read_string_nt_clone(buf: []byte, offset: ^int, allocator := context.temp_allocator) -> (val: string, ok: bool)
  ```

- [ ] **Step 1: Write failing unit tests for stateless readers**

```odin
// pgproto/buffer_test.odin
package pgproto

import "core:mem"
import "core:testing"

@(test)
test_stateless_readers :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	// Sample payload:
	// u8(0x42), i16(0x0102), u16(0x0304), i32(0x05060708), u32(0x090A0B0C), i64(0x0102030405060708),
	// string "hello\0", counted bytes [0xAA, 0xBB]
	data := []byte{
		0x42,
		0x01, 0x02,
		0x03, 0x04,
		0x05, 0x06, 0x07, 0x08,
		0x09, 0x0A, 0x0B, 0x0C,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		'h', 'e', 'l', 'l', 'o', 0x00,
		0xAA, 0xBB,
	}

	offset := 0
	v_u8, ok_u8 := read_u8(data, &offset)
	testing.expect(t, ok_u8, "read_u8 failed")
	testing.expect_value(t, v_u8, u8(0x42))
	testing.expect_value(t, offset, 1)

	v_i16, ok_i16 := read_i16(data, &offset)
	testing.expect(t, ok_i16, "read_i16 failed")
	testing.expect_value(t, v_i16, i16(0x0102))
	testing.expect_value(t, offset, 3)

	v_u16, ok_u16 := read_u16(data, &offset)
	testing.expect(t, ok_u16, "read_u16 failed")
	testing.expect_value(t, v_u16, u16(0x0304))
	testing.expect_value(t, offset, 5)

	v_i32, ok_i32 := read_i32(data, &offset)
	testing.expect(t, ok_i32, "read_i32 failed")
	testing.expect_value(t, v_i32, i32(0x05060708))
	testing.expect_value(t, offset, 9)

	v_u32, ok_u32 := read_u32(data, &offset)
	testing.expect(t, ok_u32, "read_u32 failed")
	testing.expect_value(t, v_u32, u32(0x090A0B0C))
	testing.expect_value(t, offset, 13)

	v_i64, ok_i64 := read_i64(data, &offset)
	testing.expect(t, ok_i64, "read_i64 failed")
	testing.expect_value(t, v_i64, i64(0x0102030405060708))
	testing.expect_value(t, offset, 21)

	v_str, ok_str := read_string_nt(data, &offset)
	testing.expect(t, ok_str, "read_string_nt failed")
	testing.expect_value(t, v_str, "hello")
	testing.expect_value(t, offset, 27)

	v_bytes, ok_bytes := read_bytes_counted(data, &offset, 2)
	testing.expect(t, ok_bytes, "read_bytes_counted failed")
	testing.expect_value(t, len(v_bytes), 2)
	testing.expect_value(t, v_bytes[0], u8(0xAA))
	testing.expect_value(t, v_bytes[1], u8(0xBB))
	testing.expect_value(t, offset, 29)

	// Bounds checking tests: offset must not advance on failure
	saved_offset := offset
	_, ok_underflow := read_i32(data, &offset)
	testing.expect(t, !ok_underflow, "read_i32 should have failed on underflow")
	testing.expect_value(t, offset, saved_offset)

	_, ok_bad_str := read_string_nt(data[saved_offset:], &offset)
	testing.expect(t, !ok_bad_str, "read_string_nt should have failed without null terminator")

	testing.expect_value(t, len(track.allocation_map), 0)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `odin test pgproto`
Expected: FAIL with undefined identifiers (`read_u8`, `read_i16`, etc.)

- [ ] **Step 3: Implement stateless readers in `pgproto/buffer.odin`**

```odin
// pgproto/buffer.odin
package pgproto

import "core:encoding/endian"
import "core:strings"

read_u8 :: proc(buf: []byte, offset: ^int) -> (val: u8, ok: bool) {
	if offset^ + 1 > len(buf) {
		return 0, false
	}
	val = buf[offset^]
	offset^ += 1
	return val, true
}

read_i16 :: proc(buf: []byte, offset: ^int) -> (val: i16, ok: bool) {
	if offset^ + 2 > len(buf) {
		return 0, false
	}
	val = endian.get_i16(buf[offset^:offset^ + 2], .Big) or_return
	offset^ += 2
	return val, true
}

read_u16 :: proc(buf: []byte, offset: ^int) -> (val: u16, ok: bool) {
	if offset^ + 2 > len(buf) {
		return 0, false
	}
	val = endian.get_u16(buf[offset^:offset^ + 2], .Big) or_return
	offset^ += 2
	return val, true
}

read_i32 :: proc(buf: []byte, offset: ^int) -> (val: i32, ok: bool) {
	if offset^ + 4 > len(buf) {
		return 0, false
	}
	val = endian.get_i32(buf[offset^:offset^ + 4], .Big) or_return
	offset^ += 4
	return val, true
}

read_u32 :: proc(buf: []byte, offset: ^int) -> (val: u32, ok: bool) {
	if offset^ + 4 > len(buf) {
		return 0, false
	}
	val = endian.get_u32(buf[offset^:offset^ + 4], .Big) or_return
	offset^ += 4
	return val, true
}

read_i64 :: proc(buf: []byte, offset: ^int) -> (val: i64, ok: bool) {
	if offset^ + 8 > len(buf) {
		return 0, false
	}
	val = endian.get_i64(buf[offset^:offset^ + 8], .Big) or_return
	offset^ += 8
	return val, true
}

read_bytes_counted :: proc(buf: []byte, offset: ^int, count: int) -> (val: []byte, ok: bool) {
	if count < 0 || offset^ + count > len(buf) {
		return nil, false
	}
	val = buf[offset^ : offset^ + count]
	offset^ += count
	return val, true
}

read_string_nt :: proc(buf: []byte, offset: ^int) -> (val: string, ok: bool) {
	start := offset^
	for i in start ..< len(buf) {
		if buf[i] == 0x00 {
			val = string(buf[start:i])
			offset^ = i + 1
			return val, true
		}
	}
	return "", false
}

read_string_nt_clone :: proc(
	buf: []byte,
	offset: ^int,
	allocator := context.temp_allocator,
) -> (
	val: string,
	ok: bool,
) {
	str_slice := read_string_nt(buf, offset) or_return
	cloned, err := strings.clone(str_slice, allocator)
	if err != .None {
		return "", false
	}
	return cloned, true
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `odin test pgproto`
Expected: PASS

- [ ] **Step 5: Commit Task 1**

```bash
git add pgproto/buffer.odin pgproto/buffer_test.odin
git commit -m "feat(pgproto): implement stateless wire buffer readers"
```

---

### Task 2: Stateless Writer Primitives

**Files:**
- Modify: `pgproto/buffer.odin`
- Modify: `pgproto/buffer_test.odin`

**Interfaces:**
- Produces:
  ```odin
  write_u8(builder: ^[dynamic]byte, val: u8)
  write_i16(builder: ^[dynamic]byte, val: i16)
  write_u16(builder: ^[dynamic]byte, val: u16)
  write_i32(builder: ^[dynamic]byte, val: i32)
  write_u32(builder: ^[dynamic]byte, val: u32)
  write_i64(builder: ^[dynamic]byte, val: i64)
  write_bytes(builder: ^[dynamic]byte, b: []byte)
  write_string_nt(builder: ^[dynamic]byte, s: string)
  ```

- [ ] **Step 1: Write failing unit tests for stateless writers**

```odin
// In pgproto/buffer_test.odin
@(test)
test_stateless_writers :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	buf: [dynamic]byte
	defer delete(buf)

	write_u8(&buf, 0x42)
	write_i16(&buf, 0x0102)
	write_u16(&buf, 0x0304)
	write_i32(&buf, 0x05060708)
	write_u32(&buf, 0x090A0B0C)
	write_i64(&buf, 0x0102030405060708)
	write_string_nt(&buf, "hello")
	write_bytes(&buf, []byte{0xAA, 0xBB})

	// Validate bytes directly
	expected := []byte{
		0x42,
		0x01, 0x02,
		0x03, 0x04,
		0x05, 0x06, 0x07, 0x08,
		0x09, 0x0A, 0x0B, 0x0C,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		'h', 'e', 'l', 'l', 'o', 0x00,
		0xAA, 0xBB,
	}

	testing.expect_value(t, len(buf), len(expected))
	for i in 0 ..< len(expected) {
		testing.expect_value(t, buf[i], expected[i])
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `odin test pgproto`
Expected: FAIL with undefined identifiers (`write_u8`, `write_i16`, etc.)

- [ ] **Step 3: Implement stateless writers in `pgproto/buffer.odin`**

```odin
write_u8 :: proc(builder: ^[dynamic]byte, val: u8) {
	append(builder, val)
}

write_i16 :: proc(builder: ^[dynamic]byte, val: i16) {
	raw: [2]byte
	endian.put_i16(raw[:], .Big, val)
	append(builder, ..raw[:])
}

write_u16 :: proc(builder: ^[dynamic]byte, val: u16) {
	raw: [2]byte
	endian.put_u16(raw[:], .Big, val)
	append(builder, ..raw[:])
}

write_i32 :: proc(builder: ^[dynamic]byte, val: i32) {
	raw: [4]byte
	endian.put_i32(raw[:], .Big, val)
	append(builder, ..raw[:])
}

write_u32 :: proc(builder: ^[dynamic]byte, val: u32) {
	raw: [4]byte
	endian.put_u32(raw[:], .Big, val)
	append(builder, ..raw[:])
}

write_i64 :: proc(builder: ^[dynamic]byte, val: i64) {
	raw: [8]byte
	endian.put_i64(raw[:], .Big, val)
	append(builder, ..raw[:])
}

write_bytes :: proc(builder: ^[dynamic]byte, b: []byte) {
	append(builder, ..b)
}

write_string_nt :: proc(builder: ^[dynamic]byte, s: string) {
	append(builder, ..transmute([]byte)s)
	append(builder, u8(0x00))
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `odin test pgproto`
Expected: PASS

- [ ] **Step 5: Commit Task 2**

```bash
git add pgproto/buffer.odin pgproto/buffer_test.odin
git commit -m "feat(pgproto): implement stateless wire buffer writers"
```

---

### Task 3: Packet Framing & Length Patching Procedures

**Files:**
- Modify: `pgproto/buffer.odin`
- Modify: `pgproto/buffer_test.odin`

**Interfaces:**
- Produces:
  ```odin
  write_packet_header(builder: ^[dynamic]byte, msg_type: u8) -> (length_pos: int)
  write_packet_header_untyped(builder: ^[dynamic]byte) -> (length_pos: int)
  finish_packet(builder: ^[dynamic]byte, length_pos: int) -> int
  ```

- [ ] **Step 1: Write failing unit tests for packet framing**

```odin
// In pgproto/buffer_test.odin
@(test)
test_packet_framing :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	buf: [dynamic]byte
	defer delete(buf)

	// Test 1: Typed packet 'Q' (Query message) with payload "SELECT 1;\0"
	len_pos := write_packet_header(&buf, 'Q')
	testing.expect_value(t, len_pos, 1) // 1 byte type, then length placeholder
	write_string_nt(&buf, "SELECT 1;")
	pkt_len := finish_packet(&buf, len_pos)

	// Length includes 4 length bytes + 10 bytes ("SELECT 1;\0") = 14
	testing.expect_value(t, pkt_len, 14)
	testing.expect_value(t, len(buf), 15) // 'Q' + 14 bytes
	testing.expect_value(t, buf[0], u8('Q'))

	offset := 1
	decoded_len, _ := read_i32(buf[:], &offset)
	testing.expect_value(t, decoded_len, 14)

	query_str, _ := read_string_nt(buf[:], &offset)
	testing.expect_value(t, query_str, "SELECT 1;")

	// Test 2: Untyped packet (StartupMessage)
	clear(&buf)
	u_len_pos := write_packet_header_untyped(&buf)
	testing.expect_value(t, u_len_pos, 0)
	write_i32(&buf, 196608) // Protocol 3.0
	write_string_nt(&buf, "user")
	write_string_nt(&buf, "postgres")
	write_u8(&buf, 0x00) // terminating null
	u_pkt_len := finish_packet(&buf, u_len_pos)

	testing.expect_value(t, u_pkt_len, len(buf))
	u_offset := 0
	u_decoded_len, _ := read_i32(buf[:], &u_offset)
	testing.expect_value(t, u_decoded_len, i32(u_pkt_len))
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `odin test pgproto`
Expected: FAIL with undefined identifiers (`write_packet_header`, `finish_packet`, etc.)

- [ ] **Step 3: Implement framing in `pgproto/buffer.odin`**

```odin
write_packet_header :: proc(builder: ^[dynamic]byte, msg_type: u8) -> (length_pos: int) {
	append(builder, msg_type)
	length_pos = len(builder)
	placeholder := [4]byte{0, 0, 0, 0}
	append(builder, ..placeholder[:])
	return length_pos
}

write_packet_header_untyped :: proc(builder: ^[dynamic]byte) -> (length_pos: int) {
	length_pos = len(builder)
	placeholder := [4]byte{0, 0, 0, 0}
	append(builder, ..placeholder[:])
	return length_pos
}

finish_packet :: proc(builder: ^[dynamic]byte, length_pos: int) -> int {
	packet_len := len(builder) - length_pos
	raw: [4]byte
	endian.put_i32(raw[:], .Big, i32(packet_len))
	copy(builder[length_pos : length_pos + 4], raw[:])
	return packet_len
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `odin test pgproto`
Expected: PASS

- [ ] **Step 5: Commit Task 3**

```bash
git add pgproto/buffer.odin pgproto/buffer_test.odin
git commit -m "feat(pgproto): implement wire packet framing and length patching"
```

---

### Task 4: Stateful `Reader` and `Writer` Cursor Wrappers

**Files:**
- Modify: `pgproto/buffer.odin`
- Modify: `pgproto/buffer_test.odin`

**Interfaces:**
- Produces:
  ```odin
  Reader :: struct {
  	buf:    []byte,
  	offset: int,
  }

  Writer :: struct {
  	buf: ^[dynamic]byte,
  }

  reader_init(r: ^Reader, buf: []byte)
  reader_remaining(r: ^Reader) -> int
  reader_has_bytes(r: ^Reader, count: int) -> bool
  reader_read_u8(r: ^Reader) -> (u8, bool)
  reader_read_i16(r: ^Reader) -> (i16, bool)
  reader_read_u16(r: ^Reader) -> (u16, bool)
  reader_read_i32(r: ^Reader) -> (i32, bool)
  reader_read_u32(r: ^Reader) -> (u32, bool)
  reader_read_i64(r: ^Reader) -> (i64, bool)
  reader_read_bytes(r: ^Reader, count: int) -> ([]byte, bool)
  reader_read_string_nt(r: ^Reader) -> (string, bool)
  reader_read_string_nt_clone(r: ^Reader, allocator := context.temp_allocator) -> (string, bool)

  writer_init(w: ^Writer, builder: ^[dynamic]byte)
  writer_write_u8(w: ^Writer, val: u8)
  writer_write_i16(w: ^Writer, val: i16)
  writer_write_u16(w: ^Writer, val: u16)
  writer_write_i32(w: ^Writer, val: i32)
  writer_write_u32(w: ^Writer, val: u32)
  writer_write_i64(w: ^Writer, val: i64)
  writer_write_bytes(w: ^Writer, b: []byte)
  writer_write_string_nt(w: ^Writer, s: string)
  writer_begin_packet(w: ^Writer, msg_type: u8) -> (length_pos: int)
  writer_begin_packet_untyped(w: ^Writer) -> (length_pos: int)
  writer_end_packet(w: ^Writer, length_pos: int) -> int
  ```

- [ ] **Step 1: Write failing unit tests for `Reader` and `Writer`**

```odin
// In pgproto/buffer_test.odin
@(test)
test_reader_writer_structs :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	buf: [dynamic]byte
	defer delete(buf)

	w: Writer
	writer_init(&w, &buf)

	l_pos := writer_begin_packet(&w, 'P')
	writer_write_string_nt(&w, "stmt_1")
	writer_write_string_nt(&w, "SELECT $1::int4;")
	writer_write_i16(&w, 1)
	writer_write_u32(&w, 23) // INT4OID
	writer_end_packet(&w, l_pos)

	r: Reader
	reader_init(&r, buf[:])
	testing.expect_value(t, reader_remaining(&r), len(buf))
	testing.expect(t, reader_has_bytes(&r, 5), "should have at least 5 bytes")

	msg_type, ok_t := reader_read_u8(&r)
	testing.expect(t, ok_t, "read msg_type failed")
	testing.expect_value(t, msg_type, u8('P'))

	msg_len, ok_l := reader_read_i32(&r)
	testing.expect(t, ok_l, "read msg_len failed")
	testing.expect_value(t, msg_len, i32(len(buf) - 1))

	stmt_name, ok_s := reader_read_string_nt(&r)
	testing.expect(t, ok_s, "read stmt_name failed")
	testing.expect_value(t, stmt_name, "stmt_1")

	query, ok_q := reader_read_string_nt(&r)
	testing.expect(t, ok_q, "read query failed")
	testing.expect_value(t, query, "SELECT $1::int4;")

	num_params, ok_np := reader_read_i16(&r)
	testing.expect(t, ok_np, "read num_params failed")
	testing.expect_value(t, num_params, 1)

	param_oid, ok_oid := reader_read_u32(&r)
	testing.expect(t, ok_oid, "read param_oid failed")
	testing.expect_value(t, param_oid, 23)

	testing.expect_value(t, reader_remaining(&r), 0)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `odin test pgproto`
Expected: FAIL with undefined types/procedures (`Reader`, `Writer`, etc.)

- [ ] **Step 3: Implement `Reader` and `Writer` in `pgproto/buffer.odin`**

```odin
Reader :: struct {
	buf:    []byte,
	offset: int,
}

Writer :: struct {
	buf: ^[dynamic]byte,
}

reader_init :: proc(r: ^Reader, buf: []byte) {
	r.buf = buf
	r.offset = 0
}

reader_remaining :: proc(r: ^Reader) -> int {
	return max(0, len(r.buf) - r.offset)
}

reader_has_bytes :: proc(r: ^Reader, count: int) -> bool {
	return count >= 0 && r.offset + count <= len(r.buf)
}

reader_read_u8 :: proc(r: ^Reader) -> (u8, bool) {
	return read_u8(r.buf, &r.offset)
}

reader_read_i16 :: proc(r: ^Reader) -> (i16, bool) {
	return read_i16(r.buf, &r.offset)
}

reader_read_u16 :: proc(r: ^Reader) -> (u16, bool) {
	return read_u16(r.buf, &r.offset)
}

reader_read_i32 :: proc(r: ^Reader) -> (i32, bool) {
	return read_i32(r.buf, &r.offset)
}

reader_read_u32 :: proc(r: ^Reader) -> (u32, bool) {
	return read_u32(r.buf, &r.offset)
}

reader_read_i64 :: proc(r: ^Reader) -> (i64, bool) {
	return read_i64(r.buf, &r.offset)
}

reader_read_bytes :: proc(r: ^Reader, count: int) -> ([]byte, bool) {
	return read_bytes_counted(r.buf, &r.offset, count)
}

reader_read_string_nt :: proc(r: ^Reader) -> (string, bool) {
	return read_string_nt(r.buf, &r.offset)
}

reader_read_string_nt_clone :: proc(
	r: ^Reader,
	allocator := context.temp_allocator,
) -> (
	string,
	bool,
) {
	return read_string_nt_clone(r.buf, &r.offset, allocator)
}

writer_init :: proc(w: ^Writer, builder: ^[dynamic]byte) {
	w.buf = builder
}

writer_write_u8 :: proc(w: ^Writer, val: u8) {
	write_u8(w.buf, val)
}

writer_write_i16 :: proc(w: ^Writer, val: i16) {
	write_i16(w.buf, val)
}

writer_write_u16 :: proc(w: ^Writer, val: u16) {
	write_u16(w.buf, val)
}

writer_write_i32 :: proc(w: ^Writer, val: i32) {
	write_i32(w.buf, val)
}

writer_write_u32 :: proc(w: ^Writer, val: u32) {
	write_u32(w.buf, val)
}

writer_write_i64 :: proc(w: ^Writer, val: i64) {
	write_i64(w.buf, val)
}

writer_write_bytes :: proc(w: ^Writer, b: []byte) {
	write_bytes(w.buf, b)
}

writer_write_string_nt :: proc(w: ^Writer, s: string) {
	write_string_nt(w.buf, s)
}

writer_begin_packet :: proc(w: ^Writer, msg_type: u8) -> (length_pos: int) {
	return write_packet_header(w.buf, msg_type)
}

writer_begin_packet_untyped :: proc(w: ^Writer) -> (length_pos: int) {
	return write_packet_header_untyped(w.buf)
}

writer_end_packet :: proc(w: ^Writer, length_pos: int) -> int {
	return finish_packet(w.buf, length_pos)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `odin test pgproto`
Expected: PASS

- [ ] **Step 5: Commit Task 4**

```bash
git add pgproto/buffer.odin pgproto/buffer_test.odin
git commit -m "feat(pgproto): implement Reader and Writer cursor wrappers"
```

---

### Task 5: Edge Cases, Quality Audits & JIRA Update

**Files:**
- Modify: `pgproto/buffer_test.odin`
- Modify: `JIRA.md`

- [ ] **Step 1: Add extensive edge case tests in `pgproto/buffer_test.odin`**

```odin
// Add edge case tests: negative bounds in read_bytes_counted, empty string null terminator,
// boundary integer values (min/max i16, i32, i64), and zero-length buffer behavior.
@(test)
test_buffer_edge_cases :: proc(t: ^testing.T) {
	empty := []byte{}
	offset := 0
	_, ok := read_u8(empty, &offset)
	testing.expect(t, !ok, "empty read_u8 should fail")

	_, ok_str := read_string_nt(empty, &offset)
	testing.expect(t, !ok_str, "empty read_string_nt should fail")

	only_null := []byte{0x00}
	offset = 0
	str, ok_null := read_string_nt(only_null, &offset)
	testing.expect(t, ok_null, "null-only string should succeed")
	testing.expect_value(t, str, "")
	testing.expect_value(t, offset, 1)

	neg_bytes := []byte{1, 2, 3}
	offset = 0
	_, ok_neg := read_bytes_counted(neg_bytes, &offset, -5)
	testing.expect(t, !ok_neg, "negative count should fail")
	testing.expect_value(t, offset, 0)
}
```

- [ ] **Step 2: Run all compiler checks, linters, and sanitizers**

Run:
1. `odin test pgproto -vet -strict-style`
2. `odin test pgproto -sanitize:address`
3. `odin check . -no-entry-point`

Expected: All checks pass cleanly with 0 errors and 0 leaks.

- [ ] **Step 3: Update `JIRA.md` status for `OPG-101`**

Mark `[OPG-101]` as completed `[x]` in `JIRA.md`.

- [ ] **Step 4: Commit Task 5**

```bash
git add pgproto/buffer_test.odin JIRA.md
git commit -m "test(pgproto): add edge cases and mark OPG-101 completed in JIRA.md"
```
