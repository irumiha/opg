# Design Document: [OPG-101] Wire Buffer Reader / Writer & Big-Endian Codec Primitives

- **Date**: 2026-08-15
- **Task ID**: `OPG-101`
- **Layer**: `pgproto`
- **Package**: `package pgproto`
- **Files**:
  - `pgproto/buffer.odin`
  - `pgproto/buffer_test.odin`
- **Status**: Approved

---

## 1. Overview & Objectives

PostgreSQL Frontend/Backend Protocol 3.0 communicates strictly in **Network Byte Order (Big-Endian)**. `OPG-101` provides the foundational buffer reading, writing, and packet-framing primitives that all higher-level message encoders (`OPG-102`) and parsers (`OPG-103`) rely upon.

### Key Goals:
1. **Network Byte Order**: All multi-byte numeric values (`i16`, `u16`, `i32`, `u32`, `i64`) encoded and decoded via `core:encoding/endian`. Raw transmute is strictly avoided.
2. **Memory Safety & Zero-Panic**: Bounds checks validate buffer space prior to any access. Out-of-bounds reads return `ok = false` leaving read offsets unmodified.
3. **Zero Allocation Default**: Reads for strings (`read_string_nt`) and byte slices (`read_bytes_counted`) return zero-copy sub-slices of the original buffer. A dedicated cloning helper (`read_string_nt_clone`) is provided for callers needing owned copies.
4. **Packet Framing**: Helpers to reserve length prefixes and patch calculated Big-Endian lengths after building variable-length packets.
5. **Ergonomic Cursor Wrappers**: Lightweight `Reader` and `Writer` struct wrappers that manage cursor position and buffer references without dynamic overhead.

---

## 2. Architecture & Data Structures

### 2.1 Core Types (`pgproto/buffer.odin`)

```odin
package pgproto

// Reader is a cursor over an immutable byte slice for reading protocol primitives.
Reader :: struct {
	buf:    []byte,
	offset: int,
}

// Writer is a helper over a dynamic byte slice for building protocol packets.
Writer :: struct {
	buf: ^[dynamic]byte,
}
```

---

## 3. Procedural API Specification

### 3.1 Stateless Reader Procedures

Every read procedure takes `buf: []byte` and `offset: ^int`.
- On success: Returns the parsed value, sets `ok = true`, and advances `offset^` by the byte length of the value.
- On failure: Returns zero value, sets `ok = false`, and leaves `offset^` unchanged.

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

#### Detailed Semantics:
- `read_bytes_counted`:
  - Returns `buf[offset^ : offset^ + count]`.
  - Returns `ok = false` if `count < 0` or `offset^ + count > len(buf)`.
- `read_string_nt`:
  - Scans from `offset^` for a null terminator `0x00`.
  - Returns zero-copy slice `string(buf[start : null_idx])` and advances `offset^ = null_idx + 1`.
  - Returns `ok = false` if no null byte is found.
- `read_string_nt_clone`:
  - Scans for null terminator, clones string via `strings.clone_from_bytes(..., allocator)`.

---

### 3.2 Stateless Writer Procedures

Appends big-endian encoded values to `builder: ^[dynamic]byte`.

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

#### Detailed Semantics:
- `write_string_nt`: Appends bytes of `s` followed by a single null byte `0x00`.

---

### 3.3 Packet Framing & Length Patching Procedures

PostgreSQL message packets use 4-byte big-endian length prefixes that include the 4 length bytes themselves.

```odin
// Appends 1-byte message type and 4 zero bytes placeholder.
// Returns the index in builder where the 4-byte length starts.
write_packet_header(builder: ^[dynamic]byte, msg_type: u8) -> (length_pos: int)

// Appends 4 zero bytes placeholder without a type byte (e.g. for StartupMessage / SSLRequest).
// Returns the index in builder where the 4-byte length starts.
write_packet_header_untyped(builder: ^[dynamic]byte) -> (length_pos: int)

// Calculates packet length (len(builder) - length_pos) and writes it in big-endian into builder[length_pos : length_pos + 4].
// Returns the written packet length.
finish_packet(builder: ^[dynamic]byte, length_pos: int) -> int
```

---

### 3.4 Stateful `Reader` and `Writer` Wrapper API

```odin
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

---

## 4. Error Handling & Memory Safety

1. **Non-destructive Failure**: When any reader operation fails due to insufficient buffer data, `offset` remains unmodified.
2. **Zero Leaks**: All dynamic allocations in tests are tracked using `core:mem.Tracking_Allocator`. `pgproto/buffer.odin` itself performs no heap allocations except dynamic slice appends in writer operations managed by the caller.

---

## 5. Verification & Test Plan

Test suite in `pgproto/buffer_test.odin` will verify:
1. **Network Byte Order Conversions**: Bit-accurate big-endian encoding/decoding for `i16`, `u16`, `i32`, `u32`, `i64`, negative integers, and boundary values (`max(i32)`, `min(i32)`, `0`, etc.).
2. **String Operations**: Empty null-terminated strings (`"\0"`), standard strings, strings without null terminator (underflow), multi-string sequences.
3. **Counted Bytes Operations**: Exact slices, 0 count, negative count, and out-of-bounds requests.
4. **Packet Framing**: Typed (`'Q'`, `'P'`, etc.) and untyped packet headers, length patching calculations, and nested/sequential packets.
5. **Cursor Wrapper Behavior**: `Reader` and `Writer` methods, `reader_remaining`, `reader_has_bytes`.
6. **Bounds Safety**: Testing truncated buffers for every read primitive to confirm `ok = false` without runtime panic.
7. **Coverage & Style Checks**:
   - `odin test pgproto -vet -strict-style`
   - `odin test pgproto -sanitize:address`
   - Zero memory leaks verified with `core:mem.Tracking_Allocator`.
