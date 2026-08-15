package pgorm

import "core:mem"
import "core:testing"
import "core:time"

// ----------------------------------------------------------------------------
// Text Decoders Test Suite
// ----------------------------------------------------------------------------

tb :: proc(s: string) -> []byte {
	return transmute([]byte)s
}

@(test)
test_decode_text_bool :: proc(t: ^testing.T) {
	val, ok := decode_text_bool(tb("t"))
	testing.expect(t, ok)
	testing.expect_value(t, val, true)

	val, ok = decode_text_bool(tb("true"))
	testing.expect(t, ok)
	testing.expect_value(t, val, true)

	val, ok = decode_text_bool(tb("1"))
	testing.expect(t, ok)
	testing.expect_value(t, val, true)

	val, ok = decode_text_bool(tb("f"))
	testing.expect(t, ok)
	testing.expect_value(t, val, false)

	val, ok = decode_text_bool(tb("false"))
	testing.expect(t, ok)
	testing.expect_value(t, val, false)

	val, ok = decode_text_bool(tb("0"))
	testing.expect(t, ok)
	testing.expect_value(t, val, false)

	_, ok = decode_text_bool(tb("invalid"))
	testing.expect(t, !ok)
}

@(test)
test_decode_text_integers :: proc(t: ^testing.T) {
	// INT2 (i16)
	v16, ok16 := decode_text_i16(tb("32767"))
	testing.expect(t, ok16)
	testing.expect_value(t, v16, i16(32767))

	v16_neg, ok16_neg := decode_text_i16(tb("-32768"))
	testing.expect(t, ok16_neg)
	testing.expect_value(t, v16_neg, i16(-32768))

	_, ok16_bad := decode_text_i16(tb("99999"))
	testing.expect(t, !ok16_bad, "overflow should fail")

	// INT4 (i32)
	v32, ok32 := decode_text_i32(tb("2147483647"))
	testing.expect(t, ok32)
	testing.expect_value(t, v32, i32(2147483647))

	v32_neg, ok32_neg := decode_text_i32(tb("-2147483648"))
	testing.expect(t, ok32_neg)
	testing.expect_value(t, v32_neg, i32(-2147483648))

	// INT8 (i64)
	v64, ok64 := decode_text_i64(tb("9223372036854775807"))
	testing.expect(t, ok64)
	testing.expect_value(t, v64, i64(9223372036854775807))

	v64_neg, ok64_neg := decode_text_i64(tb("-9223372036854775808"))
	testing.expect(t, ok64_neg)
	testing.expect_value(t, v64_neg, i64(-9223372036854775808))
}

@(test)
test_decode_text_floats :: proc(t: ^testing.T) {
	f32_val, ok32 := decode_text_f32(tb("3.14159"))
	testing.expect(t, ok32)
	testing.expect(t, abs(f32_val - 3.14159) < 0.0001)

	f64_val, ok64 := decode_text_f64(tb("-123456.789012"))
	testing.expect(t, ok64)
	testing.expect(t, abs(f64_val - (-123456.789012)) < 0.000001)
}

@(test)
test_decode_text_strings_and_bytea :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	tracked := mem.tracking_allocator(&track)

	// String
	str_val, ok_str := decode_text_string(tb("Hello, 世界!"), tracked)
	testing.expect(t, ok_str)
	testing.expect_value(t, str_val, "Hello, 世界!")
	delete(str_val, tracked)

	// Bytea hex format (\xDEADBEEF)
	hex_raw := tb("\\xdeadbeef0102")
	bytes_val, ok_hex := decode_text_bytea(hex_raw, tracked)
	testing.expect(t, ok_hex)
	testing.expect_value(t, len(bytes_val), 6)
	testing.expect_value(t, bytes_val[0], u8(0xde))
	testing.expect_value(t, bytes_val[1], u8(0xad))
	testing.expect_value(t, bytes_val[2], u8(0xbe))
	testing.expect_value(t, bytes_val[3], u8(0xef))
	testing.expect_value(t, bytes_val[4], u8(0x01))
	testing.expect_value(t, bytes_val[5], u8(0x02))
	delete(bytes_val, tracked)

	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
test_decode_text_uuid :: proc(t: ^testing.T) {
	uuid_str := "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"
	uuid_bytes, ok := decode_text_uuid(tb(uuid_str))
	testing.expect(t, ok)
	expected := [16]u8{
		0xa0, 0xee, 0xbc, 0x99, 0x9c, 0x0b, 0x4e, 0xf8,
		0xbb, 0x6d, 0x6b, 0xb9, 0xbd, 0x38, 0x0a, 0x11,
	}
	testing.expect_value(t, uuid_bytes, expected)

	_, ok_bad := decode_text_uuid(tb("invalid-uuid-string-here"))
	testing.expect(t, !ok_bad)
}

@(test)
test_decode_text_date_and_timestamp :: proc(t: ^testing.T) {
	// Date "2024-03-15"
	d, ok_date := decode_text_date(tb("2024-03-15"))
	testing.expect(t, ok_date)
	year, month, day := time.date(d)
	testing.expect_value(t, year, 2024)
	testing.expect_value(t, int(month), 3)
	testing.expect_value(t, day, 15)

	// Timestamp "2024-03-15 13:45:30"
	ts, ok_ts := decode_text_timestamp(tb("2024-03-15 13:45:30"))
	testing.expect(t, ok_ts)
	ty, tm, td := time.date(ts)
	th, tmin, tsec := time.clock(ts)
	testing.expect_value(t, ty, 2024)
	testing.expect_value(t, int(tm), 3)
	testing.expect_value(t, td, 15)
	testing.expect_value(t, th, 13)
	testing.expect_value(t, tmin, 45)
	testing.expect_value(t, tsec, 30)
}

@(test)
test_decode_text_arrays :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	tracked := mem.tracking_allocator(&track)

	// i32 array: "{1,2,3,4}"
	arr_i32, ok_i32 := decode_text_array_i32(tb("{1,2,3,4}"), tracked)
	testing.expect(t, ok_i32)
	testing.expect_value(t, len(arr_i32), 4)
	testing.expect_value(t, arr_i32[0], i32(1))
	testing.expect_value(t, arr_i32[1], i32(2))
	testing.expect_value(t, arr_i32[2], i32(3))
	testing.expect_value(t, arr_i32[3], i32(4))
	delete(arr_i32, tracked)

	// string array: `{"alice","bob","charlie"}`
	arr_str, ok_str := decode_text_array_string(tb("{\"alice\",\"bob\",\"charlie\"}"), tracked)
	testing.expect(t, ok_str)
	testing.expect_value(t, len(arr_str), 3)
	testing.expect_value(t, arr_str[0], "alice")
	testing.expect_value(t, arr_str[1], "bob")
	testing.expect_value(t, arr_str[2], "charlie")
	for s in arr_str {
		delete(s, tracked)
	}
	delete(arr_str, tracked)

	testing.expect_value(t, len(track.allocation_map), 0)
}

// ----------------------------------------------------------------------------
// Binary Decoders Test Suite (Big-Endian Wire Protocol)
// ----------------------------------------------------------------------------

@(test)
test_decode_binary_bool_and_integers :: proc(t: ^testing.T) {
	// BOOL (1 byte: 1 = true, 0 = false)
	b_true, ok_bt := decode_binary_bool([]byte{0x01})
	testing.expect(t, ok_bt)
	testing.expect_value(t, b_true, true)

	b_false, ok_bf := decode_binary_bool([]byte{0x00})
	testing.expect(t, ok_bf)
	testing.expect_value(t, b_false, false)

	_, ok_bad_b := decode_binary_bool([]byte{})
	testing.expect(t, !ok_bad_b)

	// INT2 (2 bytes Big-Endian)
	v16, ok16 := decode_binary_i16([]byte{0x12, 0x34})
	testing.expect(t, ok16)
	testing.expect_value(t, v16, i16(0x1234))

	// INT4 (4 bytes Big-Endian)
	v32, ok32 := decode_binary_i32([]byte{0x12, 0x34, 0x56, 0x78})
	testing.expect(t, ok32)
	testing.expect_value(t, v32, i32(0x12345678))

	// INT8 (8 bytes Big-Endian)
	v64, ok64 := decode_binary_i64([]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef})
	testing.expect(t, ok64)
	testing.expect_value(t, v64, i64(0x0123456789abcdef))
}

@(test)
test_decode_binary_floats :: proc(t: ^testing.T) {
	// FLOAT4 (4 bytes Big-Endian IEEE-754: 1.0f = 0x3F800000)
	f32_bytes := []byte{0x3F, 0x80, 0x00, 0x00}
	f32_val, ok32 := decode_binary_f32(f32_bytes)
	testing.expect(t, ok32)
	testing.expect_value(t, f32_val, f32(1.0))

	// FLOAT8 (8 bytes Big-Endian IEEE-754: 1.0 = 0x3FF0000000000000)
	f64_bytes := []byte{0x3F, 0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	f64_val, ok64 := decode_binary_f64(f64_bytes)
	testing.expect(t, ok64)
	testing.expect_value(t, f64_val, f64(1.0))
}

@(test)
test_decode_binary_uuid :: proc(t: ^testing.T) {
	raw := [16]u8{
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
	}
	uuid_val, ok := decode_binary_uuid(raw[:])
	testing.expect(t, ok)
	testing.expect_value(t, uuid_val, raw)

	_, ok_bad := decode_binary_uuid([]byte{1, 2, 3})
	testing.expect(t, !ok_bad, "underflow UUID must fail")
}

@(test)
test_decode_binary_jsonb :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	tracked := mem.tracking_allocator(&track)

	// JSONB binary format: 1 byte version (0x01) + UTF-8 JSON text
	jsonb_raw := []byte{0x01, '{', '"', 'a', '"', ':', '1', '}'}
	json_str, ok := decode_binary_jsonb(jsonb_raw, tracked)
	testing.expect(t, ok)
	testing.expect_value(t, json_str, "{\"a\":1}")
	delete(json_str, tracked)

	testing.expect_value(t, len(track.allocation_map), 0)
}

// ----------------------------------------------------------------------------
// Encoders Test Suite (Odin Native Types -> Wire Bytes)
// ----------------------------------------------------------------------------

@(test)
test_encode_text_types :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	tracked := mem.tracking_allocator(&track)

	// Bool
	b_t := encode_text_bool(true, tracked)
	testing.expect_value(t, string(b_t), "TRUE")
	delete(b_t, tracked)

	b_f := encode_text_bool(false, tracked)
	testing.expect_value(t, string(b_f), "FALSE")
	delete(b_f, tracked)

	// Integers
	i_bytes := encode_text_i64(12345, tracked)
	testing.expect_value(t, string(i_bytes), "12345")
	delete(i_bytes, tracked)

	// Float
	f_bytes := encode_text_f64(3.1415, tracked)
	testing.expect(t, len(f_bytes) > 0)
	delete(f_bytes, tracked)

	// UUID
	raw_uuid := [16]u8{
		0xa0, 0xee, 0xbc, 0x99, 0x9c, 0x0b, 0x4e, 0xf8,
		0xbb, 0x6d, 0x6b, 0xb9, 0xbd, 0x38, 0x0a, 0x11,
	}
	uuid_str := encode_text_uuid(raw_uuid, tracked)
	testing.expect_value(t, string(uuid_str), "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11")
	delete(uuid_str, tracked)

	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
test_encode_binary_types :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	tracked := mem.tracking_allocator(&track)

	// Bool
	b1 := encode_binary_bool(true, tracked)
	testing.expect_value(t, b1[0], u8(1))
	delete(b1, tracked)

	// INT2
	i16_b := encode_binary_i16(i16(0x1234), tracked)
	testing.expect_value(t, i16_b[0], u8(0x12))
	testing.expect_value(t, i16_b[1], u8(0x34))
	delete(i16_b, tracked)

	// INT4
	i32_b := encode_binary_i32(i32(0x12345678), tracked)
	testing.expect_value(t, i32_b[0], u8(0x12))
	testing.expect_value(t, i32_b[1], u8(0x34))
	testing.expect_value(t, i32_b[2], u8(0x56))
	testing.expect_value(t, i32_b[3], u8(0x78))
	delete(i32_b, tracked)

	// INT8
	i64_b := encode_binary_i64(i64(0x0123456789abcdef), tracked)
	testing.expect_value(t, i64_b[0], u8(0x01))
	testing.expect_value(t, i64_b[7], u8(0xef))
	delete(i64_b, tracked)

	// FLOAT4 (1.0 = 0x3F800000)
	f32_b := encode_binary_f32(1.0, tracked)
	testing.expect_value(t, f32_b[0], u8(0x3F))
	testing.expect_value(t, f32_b[1], u8(0x80))
	delete(f32_b, tracked)

	// FLOAT8 (1.0 = 0x3FF0000000000000)
	f64_b := encode_binary_f64(1.0, tracked)
	testing.expect_value(t, f64_b[0], u8(0x3F))
	testing.expect_value(t, f64_b[1], u8(0xF0))
	delete(f64_b, tracked)

	testing.expect_value(t, len(track.allocation_map), 0)
}
