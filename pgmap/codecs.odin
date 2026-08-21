package pgmap

import "core:encoding/endian"
import "core:fmt"
import "core:slice"
import "core:strconv"
import "core:strings"
import "core:time"

// PostgreSQL Data Type Codecs (Text & Binary Formats)

// Big-Endian Wire Protocol Rule: All binary integer and float operations
// strictly use core:encoding/endian.
// Allocator Boundary Rule: Allocator parameter defaults to context.temp_allocator.

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

/*
	encode_text_bytea encodes bytes as a PostgreSQL text-format bytea literal
	(`\x` + lowercase hex). All bind parameters travel in text format, so raw
	bytes must never be sent directly — the server would parse them as UTF-8
	text and reject or misdecode them.
*/
encode_text_bytea :: proc(val: []byte, allocator := context.temp_allocator) -> []byte {
	hex_digits := "0123456789abcdef"
	out := make([]byte, 2 + len(val) * 2, allocator)
	out[0] = '\\'
	out[1] = 'x'
	for b, i in val {
		out[2 + i * 2] = hex_digits[b >> 4]
		out[2 + i * 2 + 1] = hex_digits[b & 0x0F]
	}
	return out
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

/*
	decode_text_uuid parses the canonical 8-4-4-4-12 hyphenated hex layout.
*/
decode_text_uuid :: proc(data: []byte) -> (val: [16]u8, ok: bool) {
	if len(data) != 36 do return val, false
	hex_idx := 0
	for c, i in data {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' do return val, false
			continue
		}
		hv := hex_val(c) or_return
		if hex_idx % 2 == 0 {
			val[hex_idx / 2] = hv << 4
		} else {
			val[hex_idx / 2] |= hv
		}
		hex_idx += 1
	}
	return val, true
}

decode_text_date :: proc(data: []byte) -> (val: time.Time, ok: bool) {
	s := string(data)
	// `infinity` / `-infinity` cannot be represented in time.Time.
	if s == "infinity" || s == "-infinity" do return val, false
	parts := strings.split(s, "-", context.temp_allocator)
	if len(parts) != 3 do return val, false

	y := strconv.parse_int(parts[0]) or_return
	m := strconv.parse_int(parts[1]) or_return
	d := strconv.parse_int(parts[2]) or_return

	// datetime_to_time validates month/day ranges (rejects e.g. Feb 31).
	return time.datetime_to_time(y, time.Month(m), d, 0, 0, 0, 0)
}

/*
	decode_text_timestamp parses PostgreSQL text-format timestamps:

		YYYY-MM-DD[ HH:MM:SS[.fraction][(+|-)HH[:MM[:SS]] | Z]]

	The fractional part carries up to nanosecond precision (PostgreSQL itself
	emits at most microseconds). A trailing timezone offset shifts the parsed
	wall clock to the UTC instant; without an offset the wall clock is taken
	as UTC. `infinity` / `-infinity` fail the decode.
*/
decode_text_timestamp :: proc(data: []byte) -> (val: time.Time, ok: bool) {
	s := string(data)
	if s == "infinity" || s == "-infinity" do return val, false
	space_idx := strings.index_byte(s, ' ')
	if space_idx < 0 do return decode_text_date(data)

	date_part := s[:space_idx]
	rest := s[space_idx + 1:]

	d_parts := strings.split(date_part, "-", context.temp_allocator)
	if len(d_parts) != 3 do return val, false
	y := strconv.parse_int(d_parts[0]) or_return
	m := strconv.parse_int(d_parts[1]) or_return
	d := strconv.parse_int(d_parts[2]) or_return

	// Locate the timezone suffix: the first '+', '-' or 'Z' after the time.
	tz_start := -1
	for c, i in rest {
		if c == '+' || c == '-' || c == 'Z' || c == 'z' {
			tz_start = i
			break
		}
	}
	time_part := tz_start >= 0 ? rest[:tz_start] : rest
	tz_part := tz_start >= 0 ? rest[tz_start:] : ""

	// Fractional seconds.
	nsec := 0
	main_time := time_part
	dot_idx := strings.index_byte(time_part, '.')
	if dot_idx >= 0 {
		main_time = time_part[:dot_idx]
		frac := time_part[dot_idx + 1:]
		if len(frac) == 0 || len(frac) > 9 do return val, false
		for c in frac {
			if c < '0' || c > '9' do return val, false
		}
		f, fok := strconv.parse_int(frac)
		if !fok do return val, false
		// Right-pad the fraction to nanosecond scale (9 digits).
		nsec = f
		for i := len(frac); i < 9; i += 1 {
			nsec *= 10
		}
	}

	// HH:MM:SS
	t_parts := strings.split(main_time, ":", context.temp_allocator)
	if len(t_parts) != 3 do return val, false
	h := strconv.parse_int(t_parts[0]) or_return
	min_val := strconv.parse_int(t_parts[1]) or_return
	sec := strconv.parse_int(t_parts[2]) or_return

	ts, dt_ok := time.datetime_to_time(y, time.Month(m), d, h, min_val, sec, nsec)
	if !dt_ok do return val, false

	// Apply the timezone offset: UTC instant = wall clock - offset.
	if tz_part != "" && tz_part != "Z" && tz_part != "z" {
		sign := 1
		if tz_part[0] == '-' do sign = -1
		off_parts := strings.split(tz_part[1:], ":", context.temp_allocator)
		if len(off_parts) < 1 || len(off_parts) > 3 do return val, false
		oh := strconv.parse_int(off_parts[0]) or_return
		om := 0
		os_val := 0
		if len(off_parts) >= 2 do om = strconv.parse_int(off_parts[1]) or_return
		if len(off_parts) == 3 do os_val = strconv.parse_int(off_parts[2]) or_return
		offset_secs := sign * (oh * 3600 + om * 60 + os_val)
		ts = time.time_add(ts, time.Duration(-offset_secs) * time.Second)
	}
	return ts, true
}

decode_text_json :: proc(data: []byte, allocator := context.temp_allocator) -> (val: string, ok: bool) {
	return decode_text_string(data, allocator)
}

// ----------------------------------------------------------------------------
// Text Array Decoding
// ----------------------------------------------------------------------------
// PostgreSQL text array format: `{elem,elem,...}` where elements are either
// bare (anything except `,` `}` `"` `\` and curly braces) or double-quoted
// with `\"` and `\\` escapes. SQL NULL is the bare literal `NULL`.
// ----------------------------------------------------------------------------

Array_Element :: struct {
	text:    string, // Borrowed view into the input; quoted elements keep their escape backslashes
	quoted:  bool,
	is_null: bool,
}

/*
	parse_text_array_elements splits a text-format array literal into element
	descriptors. Only the descriptor slice is allocated (`allocator`); element
	text borrows from `s`. Returns `ok = false` on malformed input.
*/
parse_text_array_elements :: proc(
	s: string,
	allocator := context.temp_allocator,
) -> (
	elems: []Array_Element,
	ok:     bool,
) {
	if len(s) < 2 || s[0] != '{' || s[len(s) - 1] != '}' do return nil, false
	inner := s[1 : len(s) - 1]
	if len(inner) == 0 do return make([]Array_Element, 0, allocator), true

	res := make([dynamic]Array_Element, 0, 4, allocator)
	defer if !ok do delete(res)

	i := 0
	for i < len(inner) {
		if inner[i] == '"' {
			start := i + 1
			i += 1
			for i < len(inner) {
				if inner[i] == '\\' {
					i += 2
					continue
				}
				if inner[i] == '"' do break
				i += 1
			}
			if i >= len(inner) do return nil, false // Unterminated quote
			append(&res, Array_Element{text = inner[start:i], quoted = true})
			i += 1 // Closing quote
		} else {
			start := i
			for i < len(inner) && inner[i] != ',' {
				i += 1
			}
			elem := strings.trim_space(inner[start:i])
			if len(elem) == 0 do return nil, false // Empty bare element is malformed
			append(&res, Array_Element{text = elem, is_null = elem == "NULL"})
		}
		if i < len(inner) {
			if inner[i] != ',' do return nil, false
			i += 1
			if i == len(inner) do return nil, false // Trailing comma
		}
	}
	return res[:], true
}

@(private="file")
decode_text_array_integer :: proc(
	$T: typeid,
	data: []byte,
	allocator := context.temp_allocator,
) -> (
	val: []T,
	ok:  bool,
) {
	elems := parse_text_array_elements(string(data), context.temp_allocator) or_return
	out := make([]T, len(elems), allocator)
	for e, idx in elems {
		// PostgreSQL never quotes numeric array elements in output; a quoted
		// or NULL element cannot be represented in a non-nullable []T.
		if e.quoted || e.is_null {
			delete(out, allocator)
			return nil, false
		}
		parsed, parse_ok := strconv.parse_i64(e.text)
		if !parse_ok || parsed < i64(min(T)) || parsed > i64(max(T)) {
			delete(out, allocator)
			return nil, false
		}
		out[idx] = T(parsed)
	}
	return out, true
}

decode_text_array_i16 :: proc(data: []byte, allocator := context.temp_allocator) -> (val: []i16, ok: bool) {
	return decode_text_array_integer(i16, data, allocator)
}

decode_text_array_i32 :: proc(data: []byte, allocator := context.temp_allocator) -> (val: []i32, ok: bool) {
	return decode_text_array_integer(i32, data, allocator)
}

decode_text_array_i64 :: proc(data: []byte, allocator := context.temp_allocator) -> (val: []i64, ok: bool) {
	return decode_text_array_integer(i64, data, allocator)
}

@(private="file")
decode_text_array_float :: proc(
	$T: typeid,
	data: []byte,
	allocator := context.temp_allocator,
) -> (
	val: []T,
	ok:  bool,
) {
	elems := parse_text_array_elements(string(data), context.temp_allocator) or_return
	out := make([]T, len(elems), allocator)
	for e, idx in elems {
		if e.quoted || e.is_null {
			delete(out, allocator)
			return nil, false
		}
		elem_ok: bool
		when T == f32 {
			v, vok := strconv.parse_f32(e.text)
			out[idx] = v
			elem_ok = vok
		} else {
			v, vok := strconv.parse_f64(e.text)
			out[idx] = v
			elem_ok = vok
		}
		if !elem_ok {
			delete(out, allocator)
			return nil, false
		}
	}
	return out, true
}

decode_text_array_f32 :: proc(data: []byte, allocator := context.temp_allocator) -> (val: []f32, ok: bool) {
	return decode_text_array_float(f32, data, allocator)
}

decode_text_array_f64 :: proc(data: []byte, allocator := context.temp_allocator) -> (val: []f64, ok: bool) {
	return decode_text_array_float(f64, data, allocator)
}

decode_text_array_bool :: proc(data: []byte, allocator := context.temp_allocator) -> (val: []bool, ok: bool) {
	elems := parse_text_array_elements(string(data), context.temp_allocator) or_return
	out := make([]bool, len(elems), allocator)
	for e, idx in elems {
		if e.quoted || e.is_null {
			delete(out, allocator)
			return nil, false
		}
		parsed, parse_ok := decode_text_bool(transmute([]byte)e.text)
		if !parse_ok {
			delete(out, allocator)
			return nil, false
		}
		out[idx] = parsed
	}
	return out, true
}

/*
	decode_text_array_string decodes a text-format array into cloned strings.
	Quoted elements are unescaped; NULL elements fail the decode because a
	non-nullable []string cannot represent them.
*/
decode_text_array_string :: proc(data: []byte, allocator := context.temp_allocator) -> (val: []string, ok: bool) {
	elems := parse_text_array_elements(string(data), context.temp_allocator) or_return
	out := make([]string, len(elems), allocator)
	for e, idx in elems {
		if e.is_null {
			for s in out[:idx] do delete(s, allocator)
			delete(out, allocator)
			return nil, false
		}
		elem_text: string
		if e.quoted {
			b := strings.builder_make(context.temp_allocator)
			defer strings.builder_destroy(&b)
			for i := 0; i < len(e.text); i += 1 {
				if e.text[i] == '\\' && i + 1 < len(e.text) {
					i += 1
				}
				strings.write_byte(&b, e.text[i])
			}
			elem_text = strings.to_string(b)
		} else {
			elem_text = e.text
		}
		cloned, clone_err := strings.clone(elem_text, allocator)
		if clone_err != .None {
			for s in out[:idx] do delete(s, allocator)
			delete(out, allocator)
			return nil, false
		}
		out[idx] = cloned
	}
	return out, true
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

decode_binary_timestamp :: proc(data: []byte) -> (val: time.Time, ok: bool) {
	if len(data) != 8 do return val, false
	// Length verified above; the endian read cannot fail.
	pg_micros, _ := endian.get_i64(data, .Big)
	// PostgreSQL encodes `infinity` / `-infinity` as the i64 extremes.
	if pg_micros == max(i64) || pg_micros == min(i64) do return val, false
	unix_micros := pg_micros + 946_684_800_000_000
	unix_nanos := unix_micros * 1000
	return time.from_nanoseconds(unix_nanos), true
}

decode_binary_date :: proc(data: []byte) -> (val: time.Time, ok: bool) {
	if len(data) != 4 do return val, false
	// Length verified above; the endian read cannot fail.
	pg_days, _ := endian.get_i32(data, .Big)
	// PostgreSQL encodes `infinity` / `-infinity` as the i32 extremes.
	if pg_days == max(i32) || pg_days == min(i32) do return val, false
	unix_days := i64(pg_days) + 10957
	unix_nanos := unix_days * 86400 * 1_000_000_000
	return time.from_nanoseconds(unix_nanos), true
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
	// %v renders the shortest decimal representation that round-trips to the
	// exact f64 value; fixed "%f" truncated parameters to 6 decimal places.
	s := fmt.aprintf("%v", val, allocator = allocator)
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
