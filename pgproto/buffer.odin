package pgproto

import "core:encoding/endian"
import "core:strings"

// ----------------------------------------------------------------------------
// Write Primitives (stateless, append to a dynamic byte builder)
// ----------------------------------------------------------------------------

/*
	write_u8 appends a single byte to the dynamic byte builder.
*/
write_u8 :: proc(builder: ^[dynamic]byte, val: u8) {
	append(builder, val)
}

/*
	write_i16 appends a big-endian 16-bit signed integer to builder.
*/
write_i16 :: proc(builder: ^[dynamic]byte, val: i16) {
	raw: [2]byte
	endian.put_i16(raw[:], .Big, val)
	append(builder, ..raw[:])
}

/*
	write_u16 appends a big-endian 16-bit unsigned integer to builder.
*/
write_u16 :: proc(builder: ^[dynamic]byte, val: u16) {
	raw: [2]byte
	endian.put_u16(raw[:], .Big, val)
	append(builder, ..raw[:])
}

/*
	write_i32 appends a big-endian 32-bit signed integer to builder.
*/
write_i32 :: proc(builder: ^[dynamic]byte, val: i32) {
	raw: [4]byte
	endian.put_i32(raw[:], .Big, val)
	append(builder, ..raw[:])
}

/*
	write_u32 appends a big-endian 32-bit unsigned integer to builder.
*/
write_u32 :: proc(builder: ^[dynamic]byte, val: u32) {
	raw: [4]byte
	endian.put_u32(raw[:], .Big, val)
	append(builder, ..raw[:])
}

/*
	write_i64 appends a big-endian 64-bit signed integer to builder.
*/
write_i64 :: proc(builder: ^[dynamic]byte, val: i64) {
	raw: [8]byte
	endian.put_i64(raw[:], .Big, val)
	append(builder, ..raw[:])
}

/*
	write_bytes appends a byte slice to builder.
*/
write_bytes :: proc(builder: ^[dynamic]byte, b: []byte) {
	append(builder, ..b)
}

/*
	write_string_nt appends a null-terminated UTF-8 string to builder.
*/
write_string_nt :: proc(builder: ^[dynamic]byte, s: string) {
	append(builder, s)
	append(builder, u8(0x00))
}

/*
	write_packet_header appends a 1-byte message type and a 4-byte big-endian
	length placeholder (initialized to 0) to builder. Returns the starting offset
	of the 4-byte length field within builder.
*/
write_packet_header :: proc(builder: ^[dynamic]byte, msg_type: u8) -> (length_pos: int) {
	append(builder, msg_type)
	length_pos = len(builder)
	placeholder := [4]byte{0, 0, 0, 0}
	append(builder, ..placeholder[:])
	return length_pos
}

/*
	write_packet_header_untyped appends a 4-byte big-endian length placeholder
	(initialized to 0) to builder without a message type byte (for StartupMessage,
	SSLRequest, CancelRequest). Returns the starting offset of the 4-byte length field.
*/
write_packet_header_untyped :: proc(builder: ^[dynamic]byte) -> (length_pos: int) {
	length_pos = len(builder)
	placeholder := [4]byte{0, 0, 0, 0}
	append(builder, ..placeholder[:])
	return length_pos
}

/*
	finish_packet calculates the total packet length (from length_pos to the end of builder,
	which includes the 4-byte length field itself) and writes the length as big-endian i32
	at length_pos. Returns the calculated packet length.
*/
finish_packet :: proc(builder: ^[dynamic]byte, length_pos: int) -> int {
	packet_len := len(builder) - length_pos
	assert(packet_len <= int(max(i32)), "pgproto: packet length exceeds i32 range")
	raw: [4]byte
	endian.put_i32(raw[:], .Big, i32(packet_len))
	copy(builder[length_pos:length_pos + 4], raw[:])
	return packet_len
}

// ----------------------------------------------------------------------------
// Read Primitives (cursor-based Reader)
// ----------------------------------------------------------------------------

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
	v, ok_get := endian.get_i16(r.buf[r.offset:r.offset + 2], .Big)
	if !ok_get {
		return 0, false
	}
	val = v
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
	v, ok_get := endian.get_u16(r.buf[r.offset:r.offset + 2], .Big)
	if !ok_get {
		return 0, false
	}
	val = v
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
	v, ok_get := endian.get_i32(r.buf[r.offset:r.offset + 4], .Big)
	if !ok_get {
		return 0, false
	}
	val = v
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
	v, ok_get := endian.get_u32(r.buf[r.offset:r.offset + 4], .Big)
	if !ok_get {
		return 0, false
	}
	val = v
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
	v, ok_get := endian.get_i64(r.buf[r.offset:r.offset + 8], .Big)
	if !ok_get {
		return 0, false
	}
	val = v
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
	str_slice, ok_read := reader_read_string_nt(r)
	if !ok_read {
		return "", false
	}
	cloned, clone_err := strings.clone(str_slice, allocator)
	if clone_err != .None {
		r.offset = saved_offset
		return "", false
	}
	return cloned, true
}
