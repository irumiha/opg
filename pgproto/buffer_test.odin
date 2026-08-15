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


