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
