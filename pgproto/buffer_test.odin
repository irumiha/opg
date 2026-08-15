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

@(test)
test_stateless_readers_edge_cases :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	empty := []byte{}
	offset := 0

	_, ok_u8 := read_u8(empty, &offset)
	testing.expect(t, !ok_u8, "read_u8 empty")
	testing.expect_value(t, offset, 0)

	_, ok_i16 := read_i16(empty, &offset)
	testing.expect(t, !ok_i16, "read_i16 empty")
	testing.expect_value(t, offset, 0)

	_, ok_u16 := read_u16(empty, &offset)
	testing.expect(t, !ok_u16, "read_u16 empty")
	testing.expect_value(t, offset, 0)

	_, ok_u32 := read_u32(empty, &offset)
	testing.expect(t, !ok_u32, "read_u32 empty")
	testing.expect_value(t, offset, 0)

	_, ok_i64 := read_i64(empty, &offset)
	testing.expect(t, !ok_i64, "read_i64 empty")
	testing.expect_value(t, offset, 0)

	_, ok_cnt_neg := read_bytes_counted(empty, &offset, -1)
	testing.expect(t, !ok_cnt_neg, "read_bytes_counted negative")
	testing.expect_value(t, offset, 0)

	_, ok_cnt_overflow := read_bytes_counted(empty, &offset, 5)
	testing.expect(t, !ok_cnt_overflow, "read_bytes_counted overflow")
	testing.expect_value(t, offset, 0)

	// String clone test
	str_data := []byte{'w', 'o', 'r', 'l', 'd', 0x00}
	str_offset := 0
	cloned, ok_clone := read_string_nt_clone(str_data, &str_offset, context.temp_allocator)
	testing.expect(t, ok_clone, "read_string_nt_clone failed")
	testing.expect_value(t, cloned, "world")
	testing.expect_value(t, str_offset, 6)

	_, ok_clone_fail := read_string_nt_clone(str_data, &str_offset, context.temp_allocator)
	testing.expect(t, !ok_clone_fail, "read_string_nt_clone should fail at end")

	testing.expect_value(t, len(track.allocation_map), 0)
}

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

	// Additional writer edge cases: empty string (just null terminator), empty byte slice
	write_string_nt(&buf, "")
	write_bytes(&buf, nil)
	testing.expect_value(t, len(buf), len(expected) + 1)
	testing.expect_value(t, buf[len(expected)], u8(0x00))

	// Test negative numbers & round-trip with stateless readers
	clear(&buf)
	write_i16(&buf, -1)
	write_i32(&buf, -42)
	write_i64(&buf, -100_000_000_000)

	offset := 0
	val_i16, ok_i16 := read_i16(buf[:], &offset)
	testing.expect(t, ok_i16, "read_i16 failed for negative")
	testing.expect_value(t, val_i16, i16(-1))

	val_i32, ok_i32 := read_i32(buf[:], &offset)
	testing.expect(t, ok_i32, "read_i32 failed for negative")
	testing.expect_value(t, val_i32, i32(-42))

	val_i64, ok_i64 := read_i64(buf[:], &offset)
	testing.expect(t, ok_i64, "read_i64 failed for negative")
	testing.expect_value(t, val_i64, i64(-100_000_000_000))
	testing.expect_value(t, offset, len(buf))

	delete(buf)
	buf = nil

	testing.expect_value(t, len(track.allocation_map), 0)
}

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

	delete(buf)
	buf = nil

	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
test_reader_writer_structs :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	buf: [dynamic]byte

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

	delete(buf)
	buf = nil

	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
test_reader_writer_extended :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	buf: [dynamic]byte

	w: Writer
	writer_init(&w, &buf)

	l_pos := writer_begin_packet_untyped(&w)
	writer_write_u8(&w, 0x11)
	writer_write_u16(&w, 0x2233)
	writer_write_i64(&w, 0x0102030405060708)
	writer_write_bytes(&w, []byte{0xDE, 0xAD, 0xBE, 0xEF})
	writer_write_string_nt(&w, "cloned_str")
	writer_end_packet(&w, l_pos)

	r: Reader
	reader_init(&r, buf[:])
	testing.expect(t, reader_has_bytes(&r, 4), "has 4 bytes for length")
	testing.expect(t, !reader_has_bytes(&r, len(buf) + 1), "exceeds buffer")
	testing.expect(t, !reader_has_bytes(&r, -1), "negative count should return false")

	total_len, ok_len := reader_read_i32(&r)
	testing.expect(t, ok_len, "read total_len failed")
	testing.expect_value(t, total_len, i32(len(buf)))

	b_val, ok_b := reader_read_u8(&r)
	testing.expect(t, ok_b, "read_u8 failed")
	testing.expect_value(t, b_val, u8(0x11))

	u16_val, ok_u16 := reader_read_u16(&r)
	testing.expect(t, ok_u16, "read_u16 failed")
	testing.expect_value(t, u16_val, u16(0x2233))

	i64_val, ok_i64 := reader_read_i64(&r)
	testing.expect(t, ok_i64, "read_i64 failed")
	testing.expect_value(t, i64_val, i64(0x0102030405060708))

	bytes_val, ok_bytes := reader_read_bytes(&r, 4)
	testing.expect(t, ok_bytes, "read_bytes failed")
	testing.expect_value(t, len(bytes_val), 4)
	testing.expect_value(t, bytes_val[0], u8(0xDE))
	testing.expect_value(t, bytes_val[1], u8(0xAD))
	testing.expect_value(t, bytes_val[2], u8(0xBE))
	testing.expect_value(t, bytes_val[3], u8(0xEF))

	cloned_s, ok_clone := reader_read_string_nt_clone(&r, context.temp_allocator)
	testing.expect(t, ok_clone, "read_string_nt_clone failed")
	testing.expect_value(t, cloned_s, "cloned_str")

	testing.expect_value(t, reader_remaining(&r), 0)
	testing.expect(t, !reader_has_bytes(&r, 1), "should have 0 bytes remaining")

	_, ok_underflow := reader_read_u8(&r)
	testing.expect(t, !ok_underflow, "read past end should fail")

	delete(buf)
	buf = nil

	testing.expect_value(t, len(track.allocation_map), 0)
}


