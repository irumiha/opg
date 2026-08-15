package pgorm

import "core:encoding/endian"
import "core:fmt"
import "core:slice"
import "core:strconv"
import "core:strings"
import "core:time"

// ============================================================================
// PostgreSQL Data Type Codecs (Text & Binary Formats)
// ============================================================================
// Big-Endian Wire Protocol Rule: All binary integer and float operations
// strictly use core:encoding/endian.
// Allocator Boundary Rule: Allocator parameter defaults to context.temp_allocator.
// ============================================================================

// ----------------------------------------------------------------------------
// Text Decoders (Wire Text Format -> Odin Native Types)
// ----------------------------------------------------------------------------

decode_text_bool :: proc(data: []byte) -> (val: bool, ok: bool) {
	if len(data) == 0 do return false, false
	s := string(data)
	if strings.equal_fold(s, "t") || strings.equal_fold(s, "true") || s == "1" || strings.equal_fold(s, "y") || strings.equal_fold(s, "yes") || strings.equal_fold(s, "on") {
		return true, true
	}
	if strings.equal_fold(s, "f") || strings.equal_fold(s, "false") || s == "0" || strings.equal_fold(s, "n") || strings.equal_fold(s, "no") || strings.equal_fold(s, "off") {
		return false, true
	}
	return false, false
}

decode_text_i16 :: proc(data: []byte) -> (val: i16, ok: bool) {
	if len(data) == 0 do return 0, false
	parsed, parse_ok := strconv.parse_i64(string(data))
	if !parse_ok || parsed < i64(min(i16)) || parsed > i64(max(i16)) {
		return 0, false
	}
	return i16(parsed), true
}

decode_text_i32 :: proc(data: []byte) -> (val: i32, ok: bool) {
	if len(data) == 0 do return 0, false
	parsed, parse_ok := strconv.parse_i64(string(data))
	if !parse_ok || parsed < i64(min(i32)) || parsed > i64(max(i32)) {
		return 0, false
	}
	return i32(parsed), true
}

decode_text_i64 :: proc(data: []byte) -> (val: i64, ok: bool) {
	if len(data) == 0 do return 0, false
	return strconv.parse_i64(string(data))
}

decode_text_f32 :: proc(data: []byte) -> (val: f32, ok: bool) {
	if len(data) == 0 do return 0, false
	return strconv.parse_f32(string(data))
}

decode_text_f64 :: proc(data: []byte) -> (val: f64, ok: bool) {
	if len(data) == 0 do return 0, false
	return strconv.parse_f64(string(data))
}

decode_text_string :: proc(data: []byte, allocator := context.temp_allocator) -> (val: string, ok: bool) {
	cloned, err := strings.clone_from_bytes(data, allocator)
	if err != .None do return "", false
	return cloned, true
}

decode_text_bytea :: proc(data: []byte, allocator := context.temp_allocator) -> (val: []byte, ok: bool) {
	if len(data) == 0 do return make([]byte, 0, allocator), true

	// Hex format: starts with \x or \X
	if len(data) >= 2 && data[0] == '\\' && (data[1] == 'x' || data[1] == 'X') {
		hex_slice := data[2:]
		if len(hex_slice) % 2 != 0 do return nil, false
		out := make([]byte, len(hex_slice) / 2, allocator)
		for i in 0 ..< len(out) {
			hi := hex_val(hex_slice[i * 2]) or_return
			lo := hex_val(hex_slice[i * 2 + 1]) or_return
			out[i] = (hi << 4) | lo
		}
		return out, true
	}

	// Escape format fallback
	return slice.clone(data, allocator), true
}

@(private="file")
hex_val :: proc(b: u8) -> (val: u8, ok: bool) {
	switch b {
	case '0' ..= '9': return b - '0', true
	case 'a' ..= 'f': return b - 'a' + 10, true
	case 'A' ..= 'F': return b - 'A' + 10, true
	case: return 0, false
	}
}

decode_text_uuid :: proc(data: []byte) -> (val: [16]u8, ok: bool) {
	s := string(data)
	idx := 0
	for i in 0 ..< len(s) {
		if s[i] == '-' do continue
		if idx >= 32 do return val, false
		hv := hex_val(s[i]) or_return
		if idx % 2 == 0 {
			val[idx / 2] = hv << 4
		} else {
			val[idx / 2] |= hv
		}
		idx += 1
	}
	if idx != 32 do return val, false
	return val, true
}

decode_text_date :: proc(data: []byte) -> (val: time.Time, ok: bool) {
	s := string(data)
	parts := strings.split(s, "-", context.temp_allocator)
	if len(parts) != 3 do return val, false

	y := strconv.parse_int(parts[0]) or_return
	m := strconv.parse_int(parts[1]) or_return
	d := strconv.parse_int(parts[2]) or_return

	if m < 1 || m > 12 || d < 1 || d > 31 do return val, false
	return time.datetime_to_time(y, time.Month(m), d, 0, 0, 0, 0)
}

decode_text_timestamp :: proc(data: []byte) -> (val: time.Time, ok: bool) {
	s := string(data)
	space_idx := strings.index_byte(s, ' ')
	if space_idx < 0 do return decode_text_date(data)

	date_part := s[:space_idx]
	time_part := s[space_idx + 1:]

	d_parts := strings.split(date_part, "-", context.temp_allocator)
	if len(d_parts) != 3 do return val, false
	y := strconv.parse_int(d_parts[0]) or_return
	m := strconv.parse_int(d_parts[1]) or_return
	d := strconv.parse_int(d_parts[2]) or_return

	// Time part: HH:MM:SS[.microseconds]
	dot_idx := strings.index_byte(time_part, '.')
	main_time := dot_idx >= 0 ? time_part[:dot_idx] : time_part
	t_parts := strings.split(main_time, ":", context.temp_allocator)
	if len(t_parts) != 3 do return val, false
	h := strconv.parse_int(t_parts[0]) or_return
	min_val := strconv.parse_int(t_parts[1]) or_return
	sec := strconv.parse_int(t_parts[2]) or_return

	return time.datetime_to_time(y, time.Month(m), d, h, min_val, sec, 0)
}

decode_text_json :: proc(data: []byte, allocator := context.temp_allocator) -> (val: string, ok: bool) {
	return decode_text_string(data, allocator)
}

decode_text_array_i32 :: proc(data: []byte, allocator := context.temp_allocator) -> (val: []i32, ok: bool) {
	s := string(data)
	if len(s) < 2 || s[0] != '{' || s[len(s) - 1] != '}' do return nil, false
	inner := s[1 : len(s) - 1]
	if len(inner) == 0 do return make([]i32, 0, allocator), true

	parts := strings.split(inner, ",", context.temp_allocator)
	out := make([]i32, len(parts), allocator)
	for p, idx in parts {
		item, parse_ok := strconv.parse_i64(strings.trim_space(p))
		if !parse_ok {
			delete(out, allocator)
			return nil, false
		}
		out[idx] = i32(item)
	}
	return out, true
}

decode_text_array_string :: proc(data: []byte, allocator := context.temp_allocator) -> (val: []string, ok: bool) {
	s := string(data)
	if len(s) < 2 || s[0] != '{' || s[len(s) - 1] != '}' do return nil, false
	inner := s[1 : len(s) - 1]
	if len(inner) == 0 do return make([]string, 0, allocator), true

	res := make([dynamic]string, 0, 8, allocator)
	i := 0
	for i < len(inner) {
		if inner[i] == '"' {
			i += 1
			b := strings.builder_make(context.temp_allocator)
			for i < len(inner) && inner[i] != '"' {
				if inner[i] == '\\' && i + 1 < len(inner) {
					i += 1
				}
				strings.write_byte(&b, inner[i])
				i += 1
			}
			if i < len(inner) && inner[i] == '"' {
				i += 1
			}
			cloned, _ := strings.clone(strings.to_string(b), allocator)
			append(&res, cloned)
		} else {
			start := i
			for i < len(inner) && inner[i] != ',' {
				i += 1
			}
			elem := strings.trim_space(inner[start:i])
			cloned, _ := strings.clone(elem, allocator)
			append(&res, cloned)
		}
		if i < len(inner) && inner[i] == ',' {
			i += 1
		}
	}
	return res[:], true
}

// ----------------------------------------------------------------------------
// Binary Decoders (Big-Endian Wire Protocol)
// ----------------------------------------------------------------------------

decode_binary_bool :: proc(data: []byte) -> (val: bool, ok: bool) {
	if len(data) != 1 do return false, false
	return data[0] != 0, true
}

decode_binary_i16 :: proc(data: []byte) -> (val: i16, ok: bool) {
	if len(data) != 2 do return 0, false
	return endian.get_i16(data, .Big)
}

decode_binary_i32 :: proc(data: []byte) -> (val: i32, ok: bool) {
	if len(data) != 4 do return 0, false
	return endian.get_i32(data, .Big)
}

decode_binary_i64 :: proc(data: []byte) -> (val: i64, ok: bool) {
	if len(data) != 8 do return 0, false
	return endian.get_i64(data, .Big)
}

decode_binary_f32 :: proc(data: []byte) -> (val: f32, ok: bool) {
	if len(data) != 4 do return 0, false
	return endian.get_f32(data, .Big)
}

decode_binary_f64 :: proc(data: []byte) -> (val: f64, ok: bool) {
	if len(data) != 8 do return 0, false
	return endian.get_f64(data, .Big)
}

decode_binary_string :: proc(data: []byte, allocator := context.temp_allocator) -> (val: string, ok: bool) {
	return decode_text_string(data, allocator)
}

decode_binary_bytea :: proc(data: []byte, allocator := context.temp_allocator) -> (val: []byte, ok: bool) {
	return slice.clone(data, allocator), true
}

decode_binary_uuid :: proc(data: []byte) -> (val: [16]u8, ok: bool) {
	if len(data) != 16 do return val, false
	copy(val[:], data)
	return val, true
}

decode_binary_jsonb :: proc(data: []byte, allocator := context.temp_allocator) -> (val: string, ok: bool) {
	if len(data) < 1 || data[0] != 0x01 do return "", false
	return decode_text_string(data[1:], allocator)
}

// ----------------------------------------------------------------------------
// Encoders (Odin Native Types -> Wire Bytes)
// ----------------------------------------------------------------------------

encode_text_bool :: proc(val: bool, allocator := context.temp_allocator) -> []byte {
	return slice.clone(val ? transmute([]byte)string("TRUE") : transmute([]byte)string("FALSE"), allocator)
}

encode_text_i64 :: proc(val: i64, allocator := context.temp_allocator) -> []byte {
	s := fmt.aprintf("%d", val, allocator = allocator)
	return transmute([]byte)s
}

encode_text_f64 :: proc(val: f64, allocator := context.temp_allocator) -> []byte {
	s := fmt.aprintf("%f", val, allocator = allocator)
	return transmute([]byte)s
}

encode_text_string :: proc(val: string, allocator := context.temp_allocator) -> []byte {
	return slice.clone(transmute([]byte)val, allocator)
}

encode_text_uuid :: proc(val: [16]u8, allocator := context.temp_allocator) -> []byte {
	s := fmt.aprintf(
		"%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		val[0], val[1], val[2], val[3],
		val[4], val[5], val[6], val[7],
		val[8], val[9], val[10], val[11],
		val[12], val[13], val[14], val[15],
		allocator = allocator,
	)
	return transmute([]byte)s
}

encode_binary_bool :: proc(val: bool, allocator := context.temp_allocator) -> []byte {
	out := make([]byte, 1, allocator)
	out[0] = val ? 1 : 0
	return out
}

encode_binary_i16 :: proc(val: i16, allocator := context.temp_allocator) -> []byte {
	out := make([]byte, 2, allocator)
	endian.put_i16(out, .Big, val)
	return out
}

encode_binary_i32 :: proc(val: i32, allocator := context.temp_allocator) -> []byte {
	out := make([]byte, 4, allocator)
	endian.put_i32(out, .Big, val)
	return out
}

encode_binary_i64 :: proc(val: i64, allocator := context.temp_allocator) -> []byte {
	out := make([]byte, 8, allocator)
	endian.put_i64(out, .Big, val)
	return out
}

encode_binary_f32 :: proc(val: f32, allocator := context.temp_allocator) -> []byte {
	out := make([]byte, 4, allocator)
	endian.put_f32(out, .Big, val)
	return out
}

encode_binary_f64 :: proc(val: f64, allocator := context.temp_allocator) -> []byte {
	out := make([]byte, 8, allocator)
	endian.put_f64(out, .Big, val)
	return out
}

encode_binary_string :: proc(val: string, allocator := context.temp_allocator) -> []byte {
	return slice.clone(transmute([]byte)val, allocator)
}

encode_binary_bytea :: proc(val: []byte, allocator := context.temp_allocator) -> []byte {
	return slice.clone(val, allocator)
}

encode_binary_uuid :: proc(val: [16]u8, allocator := context.temp_allocator) -> []byte {
	out := make([]byte, 16, allocator)
	v := val
	copy(out, v[:])
	return out
}
