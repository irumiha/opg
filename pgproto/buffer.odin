package pgproto

import "core:encoding/endian"
import "core:strings"

/*
	read_u8 reads a single byte from buf at *offset, advancing *offset by 1 on success.
*/
read_u8 :: proc(buf: []byte, offset: ^int) -> (val: u8, ok: bool) {
	if offset^ < 0 || offset^ + 1 > len(buf) {
		return 0, false
	}
	val = buf[offset^]
	offset^ += 1
	return val, true
}

/*
	read_i16 reads a big-endian 16-bit signed integer from buf at *offset,
	advancing *offset by 2 on success.
*/
read_i16 :: proc(buf: []byte, offset: ^int) -> (val: i16, ok: bool) {
	if offset^ < 0 || offset^ + 2 > len(buf) {
		return 0, false
	}
	val = endian.get_i16(buf[offset^:offset^ + 2], .Big) or_return
	offset^ += 2
	return val, true
}

/*
	read_u16 reads a big-endian 16-bit unsigned integer from buf at *offset,
	advancing *offset by 2 on success.
*/
read_u16 :: proc(buf: []byte, offset: ^int) -> (val: u16, ok: bool) {
	if offset^ < 0 || offset^ + 2 > len(buf) {
		return 0, false
	}
	val = endian.get_u16(buf[offset^:offset^ + 2], .Big) or_return
	offset^ += 2
	return val, true
}

/*
	read_i32 reads a big-endian 32-bit signed integer from buf at *offset,
	advancing *offset by 4 on success.
*/
read_i32 :: proc(buf: []byte, offset: ^int) -> (val: i32, ok: bool) {
	if offset^ < 0 || offset^ + 4 > len(buf) {
		return 0, false
	}
	val = endian.get_i32(buf[offset^:offset^ + 4], .Big) or_return
	offset^ += 4
	return val, true
}

/*
	read_u32 reads a big-endian 32-bit unsigned integer from buf at *offset,
	advancing *offset by 4 on success.
*/
read_u32 :: proc(buf: []byte, offset: ^int) -> (val: u32, ok: bool) {
	if offset^ < 0 || offset^ + 4 > len(buf) {
		return 0, false
	}
	val = endian.get_u32(buf[offset^:offset^ + 4], .Big) or_return
	offset^ += 4
	return val, true
}

/*
	read_i64 reads a big-endian 64-bit signed integer from buf at *offset,
	advancing *offset by 8 on success.
*/
read_i64 :: proc(buf: []byte, offset: ^int) -> (val: i64, ok: bool) {
	if offset^ < 0 || offset^ + 8 > len(buf) {
		return 0, false
	}
	val = endian.get_i64(buf[offset^:offset^ + 8], .Big) or_return
	offset^ += 8
	return val, true
}

/*
	read_bytes_counted slices `count` bytes from buf at *offset,
	advancing *offset by count on success. Zero-copy.
*/
read_bytes_counted :: proc(buf: []byte, offset: ^int, count: int) -> (val: []byte, ok: bool) {
	if offset^ < 0 || count < 0 || offset^ + count > len(buf) {
		return nil, false
	}
	val = buf[offset^ : offset^ + count]
	offset^ += count
	return val, true
}

/*
	read_string_nt reads a null-terminated UTF-8 string view from buf starting at *offset,
	advancing *offset past the null terminator on success. Zero-copy.
*/
read_string_nt :: proc(buf: []byte, offset: ^int) -> (val: string, ok: bool) {
	if offset^ < 0 || offset^ >= len(buf) {
		return "", false
	}
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

/*
	read_string_nt_clone reads a null-terminated UTF-8 string from buf starting at *offset,
	allocating a cloned string using allocator (defaults to context.temp_allocator),
	and advancing *offset past the null terminator on success.
*/
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
	append(builder, ..transmute([]byte)s)
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
	raw: [4]byte
	endian.put_i32(raw[:], .Big, i32(packet_len))
	copy(builder[length_pos:length_pos + 4], raw[:])
	return packet_len
}

/*
	Reader holds a read-only buffer slice and an internal read offset cursor.
*/
Reader :: struct {
	buf:    []byte,
	offset: int,
}

/*
	Writer holds a pointer to a dynamic byte buffer builder.
*/
Writer :: struct {
	buf: ^[dynamic]byte,
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
	reader_read_u8 reads a single byte and advances cursor.
*/
reader_read_u8 :: proc(r: ^Reader) -> (u8, bool) {
	return read_u8(r.buf, &r.offset)
}

/*
	reader_read_i16 reads a big-endian 16-bit signed integer and advances cursor.
*/
reader_read_i16 :: proc(r: ^Reader) -> (i16, bool) {
	return read_i16(r.buf, &r.offset)
}

/*
	reader_read_u16 reads a big-endian 16-bit unsigned integer and advances cursor.
*/
reader_read_u16 :: proc(r: ^Reader) -> (u16, bool) {
	return read_u16(r.buf, &r.offset)
}

/*
	reader_read_i32 reads a big-endian 32-bit signed integer and advances cursor.
*/
reader_read_i32 :: proc(r: ^Reader) -> (i32, bool) {
	return read_i32(r.buf, &r.offset)
}

/*
	reader_read_u32 reads a big-endian 32-bit unsigned integer and advances cursor.
*/
reader_read_u32 :: proc(r: ^Reader) -> (u32, bool) {
	return read_u32(r.buf, &r.offset)
}

/*
	reader_read_i64 reads a big-endian 64-bit signed integer and advances cursor.
*/
reader_read_i64 :: proc(r: ^Reader) -> (i64, bool) {
	return read_i64(r.buf, &r.offset)
}

/*
	reader_read_bytes reads `count` bytes from buffer and advances cursor. Zero-copy.
*/
reader_read_bytes :: proc(r: ^Reader, count: int) -> ([]byte, bool) {
	return read_bytes_counted(r.buf, &r.offset, count)
}

/*
	reader_read_string_nt reads a null-terminated UTF-8 string view and advances cursor past null terminator. Zero-copy.
*/
reader_read_string_nt :: proc(r: ^Reader) -> (string, bool) {
	return read_string_nt(r.buf, &r.offset)
}

/*
	reader_read_string_nt_clone reads a null-terminated UTF-8 string, cloning it using the provided allocator.
*/
reader_read_string_nt_clone :: proc(
	r: ^Reader,
	allocator := context.temp_allocator,
) -> (
	string,
	bool,
) {
	return read_string_nt_clone(r.buf, &r.offset, allocator)
}

/*
	writer_init initializes a Writer pointing to the provided dynamic byte buffer builder.
*/
writer_init :: proc(w: ^Writer, builder: ^[dynamic]byte) {
	w.buf = builder
}

/*
	writer_write_u8 appends a single byte.
*/
writer_write_u8 :: proc(w: ^Writer, val: u8) {
	write_u8(w.buf, val)
}

/*
	writer_write_i16 appends a big-endian 16-bit signed integer.
*/
writer_write_i16 :: proc(w: ^Writer, val: i16) {
	write_i16(w.buf, val)
}

/*
	writer_write_u16 appends a big-endian 16-bit unsigned integer.
*/
writer_write_u16 :: proc(w: ^Writer, val: u16) {
	write_u16(w.buf, val)
}

/*
	writer_write_i32 appends a big-endian 32-bit signed integer.
*/
writer_write_i32 :: proc(w: ^Writer, val: i32) {
	write_i32(w.buf, val)
}

/*
	writer_write_u32 appends a big-endian 32-bit unsigned integer.
*/
writer_write_u32 :: proc(w: ^Writer, val: u32) {
	write_u32(w.buf, val)
}

/*
	writer_write_i64 appends a big-endian 64-bit signed integer.
*/
writer_write_i64 :: proc(w: ^Writer, val: i64) {
	write_i64(w.buf, val)
}

/*
	writer_write_bytes appends a byte slice.
*/
writer_write_bytes :: proc(w: ^Writer, b: []byte) {
	write_bytes(w.buf, b)
}

/*
	writer_write_string_nt appends a null-terminated UTF-8 string.
*/
writer_write_string_nt :: proc(w: ^Writer, s: string) {
	write_string_nt(w.buf, s)
}

/*
	writer_begin_packet appends a 1-byte message type and a 4-byte length placeholder.
	Returns the offset of the 4-byte length field.
*/
writer_begin_packet :: proc(w: ^Writer, msg_type: u8) -> (length_pos: int) {
	return write_packet_header(w.buf, msg_type)
}

/*
	writer_begin_packet_untyped appends a 4-byte length placeholder without a type byte.
	Returns the offset of the 4-byte length field.
*/
writer_begin_packet_untyped :: proc(w: ^Writer) -> (length_pos: int) {
	return write_packet_header_untyped(w.buf)
}

/*
	writer_end_packet finishes the packet framing by calculating packet length and writing
	it at length_pos in big-endian format.
*/
writer_end_packet :: proc(w: ^Writer, length_pos: int) -> int {
	return finish_packet(w.buf, length_pos)
}


