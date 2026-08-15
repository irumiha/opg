package pgproto

import "core:mem"
import "core:testing"

@(test)
test_reader_sequential_reads :: proc(t: ^testing.T) {
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

	r: Reader
	reader_init(&r, data)

	v_u8, ok_u8 := reader_read_u8(&r)
	testing.expect(t, ok_u8, "reader_read_u8 failed")
	testing.expect_value(t, v_u8, u8(0x42))
	testing.expect_value(t, r.offset, 1)

	v_i16, ok_i16 := reader_read_i16(&r)
	testing.expect(t, ok_i16, "reader_read_i16 failed")
	testing.expect_value(t, v_i16, i16(0x0102))
	testing.expect_value(t, r.offset, 3)

	v_u16, ok_u16 := reader_read_u16(&r)
	testing.expect(t, ok_u16, "reader_read_u16 failed")
	testing.expect_value(t, v_u16, u16(0x0304))
	testing.expect_value(t, r.offset, 5)

	v_i32, ok_i32 := reader_read_i32(&r)
	testing.expect(t, ok_i32, "reader_read_i32 failed")
	testing.expect_value(t, v_i32, i32(0x05060708))
	testing.expect_value(t, r.offset, 9)

	v_u32, ok_u32 := reader_read_u32(&r)
	testing.expect(t, ok_u32, "reader_read_u32 failed")
	testing.expect_value(t, v_u32, u32(0x090A0B0C))
	testing.expect_value(t, r.offset, 13)

	v_i64, ok_i64 := reader_read_i64(&r)
	testing.expect(t, ok_i64, "reader_read_i64 failed")
	testing.expect_value(t, v_i64, i64(0x0102030405060708))
	testing.expect_value(t, r.offset, 21)

	v_str, ok_str := reader_read_string_nt(&r)
	testing.expect(t, ok_str, "reader_read_string_nt failed")
	testing.expect_value(t, v_str, "hello")
	testing.expect_value(t, r.offset, 27)

	v_bytes, ok_bytes := reader_read_bytes(&r, 2)
	testing.expect(t, ok_bytes, "reader_read_bytes failed")
	testing.expect_value(t, len(v_bytes), 2)
	testing.expect_value(t, v_bytes[0], u8(0xAA))
	testing.expect_value(t, v_bytes[1], u8(0xBB))
	testing.expect_value(t, r.offset, 29)

	// Bounds checking: offset must not advance on failure
	saved_offset := r.offset
	_, ok_underflow := reader_read_i32(&r)
	testing.expect(t, !ok_underflow, "reader_read_i32 should have failed on underflow")
	testing.expect_value(t, r.offset, saved_offset)

	_, ok_bad_str := reader_read_string_nt(&r)
	testing.expect(t, !ok_bad_str, "reader_read_string_nt should have failed at end of buffer")
	testing.expect_value(t, r.offset, saved_offset)

	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
test_reader_empty_buffer_edge_cases :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	empty := []byte{}
	r: Reader
	reader_init(&r, empty)

	_, ok_u8 := reader_read_u8(&r)
	testing.expect(t, !ok_u8, "reader_read_u8 empty")
	testing.expect_value(t, r.offset, 0)

	_, ok_i16 := reader_read_i16(&r)
	testing.expect(t, !ok_i16, "reader_read_i16 empty")
	testing.expect_value(t, r.offset, 0)

	_, ok_u16 := reader_read_u16(&r)
	testing.expect(t, !ok_u16, "reader_read_u16 empty")
	testing.expect_value(t, r.offset, 0)

	_, ok_i32 := reader_read_i32(&r)
	testing.expect(t, !ok_i32, "reader_read_i32 empty")
	testing.expect_value(t, r.offset, 0)

	_, ok_u32 := reader_read_u32(&r)
	testing.expect(t, !ok_u32, "reader_read_u32 empty")
	testing.expect_value(t, r.offset, 0)

	_, ok_i64 := reader_read_i64(&r)
	testing.expect(t, !ok_i64, "reader_read_i64 empty")
	testing.expect_value(t, r.offset, 0)

	_, ok_cnt_neg := reader_read_bytes(&r, -1)
	testing.expect(t, !ok_cnt_neg, "reader_read_bytes negative count")
	testing.expect_value(t, r.offset, 0)

	_, ok_cnt_overflow := reader_read_bytes(&r, 5)
	testing.expect(t, !ok_cnt_overflow, "reader_read_bytes overflow")
	testing.expect_value(t, r.offset, 0)

	_, ok_str := reader_read_string_nt(&r)
	testing.expect(t, !ok_str, "reader_read_string_nt empty")
	testing.expect_value(t, r.offset, 0)

	_, ok_str_cl := reader_read_string_nt_clone(&r, context.temp_allocator)
	testing.expect(t, !ok_str_cl, "reader_read_string_nt_clone empty")
	testing.expect_value(t, r.offset, 0)

	// String clone success and end-of-buffer failure
	str_data := []byte{'w', 'o', 'r', 'l', 'd', 0x00}
	reader_init(&r, str_data)
	cloned, ok_clone := reader_read_string_nt_clone(&r, context.temp_allocator)
	testing.expect(t, ok_clone, "reader_read_string_nt_clone failed")
	testing.expect_value(t, cloned, "world")
	testing.expect_value(t, r.offset, 6)

	_, ok_clone_fail := reader_read_string_nt_clone(&r, context.temp_allocator)
	testing.expect(t, !ok_clone_fail, "reader_read_string_nt_clone should fail at end")

	testing.expect_value(t, len(track.allocation_map), 0)
}

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
	v2, ok2 := reader_peek_u8(&r)
	testing.expect(t, ok2, "peek at second byte should succeed")
	testing.expect_value(t, v2, u8(0xCD))

	_, _ = reader_read_u8(&r)
	_, ok_eof := reader_peek_u8(&r)
	testing.expect(t, !ok_eof, "peek at EOF should fail")

	r.offset = -1
	_, ok_neg := reader_peek_u8(&r)
	testing.expect(t, !ok_neg, "peek at negative offset should fail")
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

	// Test negative numbers & round-trip with the Reader
	clear(&buf)
	write_i16(&buf, -1)
	write_i32(&buf, -42)
	write_i64(&buf, -100_000_000_000)

	r: Reader
	reader_init(&r, buf[:])
	val_i16, ok_i16 := reader_read_i16(&r)
	testing.expect(t, ok_i16, "reader_read_i16 failed for negative")
	testing.expect_value(t, val_i16, i16(-1))

	val_i32, ok_i32 := reader_read_i32(&r)
	testing.expect(t, ok_i32, "reader_read_i32 failed for negative")
	testing.expect_value(t, val_i32, i32(-42))

	val_i64, ok_i64 := reader_read_i64(&r)
	testing.expect(t, ok_i64, "reader_read_i64 failed for negative")
	testing.expect_value(t, val_i64, i64(-100_000_000_000))
	testing.expect_value(t, r.offset, len(buf))

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

	r: Reader
	reader_init(&r, buf[:])
	msg_type, _ := reader_read_u8(&r)
	testing.expect_value(t, msg_type, u8('Q'))
	decoded_len, _ := reader_read_i32(&r)
	testing.expect_value(t, decoded_len, 14)

	query_str, _ := reader_read_string_nt(&r)
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
	reader_init(&r, buf[:])
	u_decoded_len, _ := reader_read_i32(&r)
	testing.expect_value(t, u_decoded_len, i32(u_pkt_len))

	delete(buf)
	buf = nil

	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
test_packet_build_and_read_back :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	buf: [dynamic]byte

	l_pos := write_packet_header(&buf, 'P')
	write_string_nt(&buf, "stmt_1")
	write_string_nt(&buf, "SELECT $1::int4;")
	write_i16(&buf, 1)
	write_u32(&buf, 23) // INT4OID
	finish_packet(&buf, l_pos)

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
test_packet_untyped_mixed_reads :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	buf: [dynamic]byte

	l_pos := write_packet_header_untyped(&buf)
	write_u8(&buf, 0x11)
	write_u16(&buf, 0x2233)
	write_i64(&buf, 0x0102030405060708)
	write_bytes(&buf, []byte{0xDE, 0xAD, 0xBE, 0xEF})
	write_string_nt(&buf, "cloned_str")
	finish_packet(&buf, l_pos)

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
	testing.expect(t, ok_clone, "reader_read_string_nt_clone failed")
	testing.expect_value(t, cloned_s, "cloned_str")

	testing.expect_value(t, reader_remaining(&r), 0)
	testing.expect(t, !reader_has_bytes(&r, 1), "should have 0 bytes remaining")

	_, ok_underflow := reader_read_u8(&r)
	testing.expect(t, !ok_underflow, "read past end should fail")

	delete(buf)
	buf = nil

	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
test_buffer_edge_cases :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	// 1. Null-only string
	only_null := []byte{0x00}
	r: Reader
	reader_init(&r, only_null)
	str, ok_null := reader_read_string_nt(&r)
	testing.expect(t, ok_null, "null-only string should succeed")
	testing.expect_value(t, str, "")
	testing.expect_value(t, r.offset, 1)

	reader_init(&r, only_null)
	str_cl, ok_null_cl := reader_read_string_nt_clone(&r, context.temp_allocator)
	testing.expect(t, ok_null_cl, "null-only string clone should succeed")
	testing.expect_value(t, str_cl, "")
	testing.expect_value(t, r.offset, 1)

	// 2. Negative count in reader_read_bytes
	neg_bytes := []byte{1, 2, 3}
	reader_init(&r, neg_bytes)
	_, ok_neg := reader_read_bytes(&r, -5)
	testing.expect(t, !ok_neg, "negative count should fail")
	testing.expect_value(t, r.offset, 0)

	// 3. Zero count in reader_read_bytes
	zero_bytes, ok_zero := reader_read_bytes(&r, 0)
	testing.expect(t, ok_zero, "zero count should succeed")
	testing.expect_value(t, len(zero_bytes), 0)
	testing.expect_value(t, r.offset, 0)

	// 4. Negative cursor offset
	reader_init(&r, neg_bytes)
	r.offset = -1
	_, ok_neg_off := reader_read_u8(&r)
	testing.expect(t, !ok_neg_off, "negative offset should fail")
	testing.expect_value(t, r.offset, -1)

	_, ok_neg_off_str := reader_read_string_nt(&r)
	testing.expect(t, !ok_neg_off_str, "negative offset string should fail")
	testing.expect_value(t, r.offset, -1)

	_, ok_neg_off_bytes := reader_read_bytes(&r, 1)
	testing.expect(t, !ok_neg_off_bytes, "negative offset bytes should fail")
	testing.expect_value(t, r.offset, -1)

	// 5. Empty reader bounds queries
	empty := []byte{}
	reader_init(&r, empty)
	testing.expect_value(t, reader_remaining(&r), 0)
	testing.expect(t, !reader_has_bytes(&r, 1), "empty reader has no bytes")
	testing.expect(t, reader_has_bytes(&r, 0), "empty reader has 0 bytes")
	testing.expect(t, !reader_has_bytes(&r, -1), "negative count has_bytes returns false")

	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
test_boundary_integers_roundtrip :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	buf: [dynamic]byte
	defer delete(buf)

	// Write minimum and maximum boundary values for each integer type
	write_u8(&buf, 0)
	write_u8(&buf, 255)

	write_i16(&buf, min(i16))
	write_i16(&buf, max(i16))

	write_u16(&buf, min(u16))
	write_u16(&buf, max(u16))

	write_i32(&buf, min(i32))
	write_i32(&buf, max(i32))

	write_u32(&buf, min(u32))
	write_u32(&buf, max(u32))

	write_i64(&buf, min(i64))
	write_i64(&buf, max(i64))

	r: Reader
	reader_init(&r, buf[:])

	v_u8_min, ok_u8_min := reader_read_u8(&r)
	testing.expect(t, ok_u8_min, "read min u8")
	testing.expect_value(t, v_u8_min, u8(0))

	v_u8_max, ok_u8_max := reader_read_u8(&r)
	testing.expect(t, ok_u8_max, "read max u8")
	testing.expect_value(t, v_u8_max, u8(255))

	v_i16_min, ok_i16_min := reader_read_i16(&r)
	testing.expect(t, ok_i16_min, "read min i16")
	testing.expect_value(t, v_i16_min, min(i16))

	v_i16_max, ok_i16_max := reader_read_i16(&r)
	testing.expect(t, ok_i16_max, "read max i16")
	testing.expect_value(t, v_i16_max, max(i16))

	v_u16_min, ok_u16_min := reader_read_u16(&r)
	testing.expect(t, ok_u16_min, "read min u16")
	testing.expect_value(t, v_u16_min, min(u16))

	v_u16_max, ok_u16_max := reader_read_u16(&r)
	testing.expect(t, ok_u16_max, "read max u16")
	testing.expect_value(t, v_u16_max, max(u16))

	v_i32_min, ok_i32_min := reader_read_i32(&r)
	testing.expect(t, ok_i32_min, "read min i32")
	testing.expect_value(t, v_i32_min, min(i32))

	v_i32_max, ok_i32_max := reader_read_i32(&r)
	testing.expect(t, ok_i32_max, "read max i32")
	testing.expect_value(t, v_i32_max, max(i32))

	v_u32_min, ok_u32_min := reader_read_u32(&r)
	testing.expect(t, ok_u32_min, "read min u32")
	testing.expect_value(t, v_u32_min, min(u32))

	v_u32_max, ok_u32_max := reader_read_u32(&r)
	testing.expect(t, ok_u32_max, "read max u32")
	testing.expect_value(t, v_u32_max, max(u32))

	v_i64_min, ok_i64_min := reader_read_i64(&r)
	testing.expect(t, ok_i64_min, "read min i64")
	testing.expect_value(t, v_i64_min, min(i64))

	v_i64_max, ok_i64_max := reader_read_i64(&r)
	testing.expect(t, ok_i64_max, "read max i64")
	testing.expect_value(t, v_i64_max, max(i64))

	testing.expect_value(t, reader_remaining(&r), 0)

	delete(buf)
	buf = nil

	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
test_read_string_nt_clone_allocator_failure :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	failing_allocator_proc :: proc(
		allocator_data: rawptr,
		mode: mem.Allocator_Mode,
		size, alignment: int,
		old_memory: rawptr,
		old_size: int,
		location := #caller_location,
	) -> ([]byte, mem.Allocator_Error) {
		return nil, .Out_Of_Memory
	}

	failing_allocator := mem.Allocator{
		procedure = failing_allocator_proc,
		data = nil,
	}

	data := []byte{'h', 'e', 'l', 'l', 'o', 0x00, 'w', 'o', 'r', 'l', 'd', 0x00}

	// Failing allocator must not advance the cursor
	r: Reader
	reader_init(&r, data)
	_, ok_r := reader_read_string_nt_clone(&r, failing_allocator)
	testing.expect(t, !ok_r, "reader_read_string_nt_clone should fail with failing_allocator")
	testing.expect_value(t, r.offset, 0)

	// Valid allocator succeeds and advances past the terminator
	val_r, ok_r_valid := reader_read_string_nt_clone(&r, context.temp_allocator)
	testing.expect(t, ok_r_valid, "reader_read_string_nt_clone should succeed with valid allocator")
	testing.expect_value(t, val_r, "hello")
	testing.expect_value(t, r.offset, 6)

	// Second string on the same reader
	val_r2, ok_r2 := reader_read_string_nt_clone(&r, context.temp_allocator)
	testing.expect(t, ok_r2, "second clone should succeed")
	testing.expect_value(t, val_r2, "world")
	testing.expect_value(t, r.offset, 12)

	testing.expect_value(t, len(track.allocation_map), 0)
}
