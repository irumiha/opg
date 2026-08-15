package pgorm

import "base:intrinsics"
import "core:mem"
import "core:reflect"
import "core:strings"
import "core:time"
import "../pgerr"
import "../pgproto"

// ============================================================================
// High-Level Reflection-Based ORM Mapper
// ============================================================================

/*
	map_row_to_struct maps a single PostgreSQL DataRow into an Odin struct using reflection.

	Supports:
	- Struct tag matching: `db:"column_name"`
	- Case-insensitive field name fallback
	- Text (0) and Binary (1) column formats
	- Nullable types via `Maybe(T)` and pointer fields (`^T`)
	- Time and UUID types (`time.Time`, `[16]u8`)
	- Arrays and Slices (`[]i32`, `[]string`, `[]byte`)
	- Nested structs
*/
map_row_to_struct :: proc(
	$T: typeid,
	desc: pgproto.Msg_Row_Description,
	row: pgproto.Msg_Data_Row,
	allocator := context.temp_allocator,
) -> (
	result: T,
	err: pgerr.Error,
) where intrinsics.type_is_struct(T) {
	if len(row.values) != len(desc.fields) {
		return result, pgerr.Protocol_Error{
			type = .Invalid_Column_Count,
			message = "Mismatch between DataRow value count and RowDescription field count",
		}
	}

	map_fields_to_struct(rawptr(&result), typeid_of(T), desc, row, allocator) or_return
	return result, nil
}

/*
	map_rows_to_slice maps an array of PostgreSQL DataRows into a slice of Odin structs.
	Allocates the returned slice and all nested strings using `allocator` (defaults to `context.temp_allocator`).
*/
map_rows_to_slice :: proc(
	$T: typeid,
	desc: pgproto.Msg_Row_Description,
	rows: []pgproto.Msg_Data_Row,
	allocator := context.temp_allocator,
) -> (
	result: []T,
	err: pgerr.Error,
) where intrinsics.type_is_struct(T) {
	out := make([]T, len(rows), allocator)
	defer if err != nil {
		delete(out, allocator)
	}
	for row, i in rows {
		item, map_err := map_row_to_struct(T, desc, row, allocator)
		if map_err != nil {
			return nil, map_err
		}
		out[i] = item
	}
	return out, nil
}

@(private="file")
map_fields_to_struct :: proc(
	struct_ptr: rawptr,
	struct_type_id: typeid,
	desc: pgproto.Msg_Row_Description,
	row: pgproto.Msg_Data_Row,
	allocator: mem.Allocator,
) -> pgerr.Error {
	field_count := reflect.struct_field_count(struct_type_id)

	for i in 0 ..< field_count {
		field := reflect.struct_field_at(struct_type_id, i)
		field_ptr := rawptr(uintptr(struct_ptr) + field.offset)
		base_ti := reflect.type_info_base(field.type)

		// Check for nested struct (excluding special types like time.Time)
		if !is_time_type(field.type) && is_nested_struct(base_ti) {
			map_fields_to_struct(field_ptr, field.type.id, desc, row, allocator) or_return
			continue
		}

		// 1. Determine target column name (check struct tag `db:"..."` first, fallback to field name)
		col_name := field.name
		if db_tag, has_tag := reflect.struct_tag_lookup(field.tag, "db"); has_tag {
			col_name = db_tag
		}

		// 2. Find corresponding column in desc.fields (case-insensitive)
		col_idx := -1
		for f, idx in desc.fields {
			if strings.equal_fold(f.name, col_name) {
				col_idx = idx
				break
			}
		}

		if col_idx < 0 || col_idx >= len(row.values) {
			continue // Skip unmapped fields
		}

		col_val := row.values[col_idx]
		col_format := desc.fields[col_idx].format_code

		// 3. Decode into target field
		decode_value_into_target(field_ptr, field.type, col_val, col_format, allocator)
	}

	return nil
}

@(private="file")
is_time_type :: proc(ti: ^reflect.Type_Info) -> bool {
	if ti == nil do return false
	if ti.id == typeid_of(time.Time) do return true
	#partial switch variant in ti.variant {
	case reflect.Type_Info_Named:
		return variant.base.id == typeid_of(time.Time) || (variant.pkg == "core:time" && variant.name == "Time")
	}
	return false
}

@(private="file")
is_nested_struct :: proc(ti: ^reflect.Type_Info) -> bool {
	if is_time_type(ti) do return false
	#partial switch variant in ti.variant {
	case reflect.Type_Info_Struct:
		return true
	}
	return false
}

@(private="file")
decode_value_into_target :: proc(
	dst: rawptr,
	ti: ^reflect.Type_Info,
	col_val: pgproto.Column_Value,
	format: pgproto.Field_Format,
	allocator: mem.Allocator,
) -> bool {
	if is_time_type(ti) {
		if col_val.is_null do return true
		if format == .Binary {
			ts, ok := decode_binary_timestamp(col_val.data)
			if ok do (^time.Time)(dst)^ = ts
			return ok
		} else {
			ts, ok := decode_text_timestamp(col_val.data)
			if ok do (^time.Time)(dst)^ = ts
			return ok
		}
	}

	#partial switch variant in ti.variant {
	case reflect.Type_Info_Named:
		if ti.id == typeid_of(time.Time) {
			if col_val.is_null do return true
			ts, ok := decode_text_timestamp(col_val.data)
			if ok do (^time.Time)(dst)^ = ts
			return ok
		}
		return decode_value_into_target(dst, variant.base, col_val, format, allocator)

	case reflect.Type_Info_Union:
		if col_val.is_null {
			// Leave as zero-value (tag = 0, nil)
			return true
		}
		if len(variant.variants) == 0 do return false
		non_nil_ti := variant.variants[0]

		ok := decode_value_into_target(dst, non_nil_ti, col_val, format, allocator)
		if ok {
			union_any := any{data = dst, id = ti.id}
			reflect.set_union_variant_type_info(union_any, non_nil_ti)
		}
		return ok

	case reflect.Type_Info_Pointer:
		if col_val.is_null {
			(^rawptr)(dst)^ = nil
			return true
		}
		elem_ti := variant.elem
		elem_mem, alloc_err := mem.alloc(elem_ti.size, elem_ti.align, allocator)
		if alloc_err != .None do return false
		ok := decode_value_into_target(elem_mem, elem_ti, col_val, format, allocator)
		if !ok {
			mem.free(elem_mem, allocator)
			(^rawptr)(dst)^ = nil
			return false
		}
		(^rawptr)(dst)^ = elem_mem
		return true

	case reflect.Type_Info_String:
		if col_val.is_null do return true
		if format == .Binary {
			s, ok := decode_binary_string(col_val.data, allocator)
			if ok do (^string)(dst)^ = s
			return ok
		} else {
			s, ok := decode_text_string(col_val.data, allocator)
			if ok do (^string)(dst)^ = s
			return ok
		}

	case reflect.Type_Info_Integer:
		if col_val.is_null do return true
		if format == .Binary {
			switch ti.size {
			case 1:
				if len(col_val.data) >= 1 {
					(^i8)(dst)^ = i8(col_val.data[0])
					return true
				}
				return false
			case 2:
				v, ok := decode_binary_i16(col_val.data)
				if ok do (^i16)(dst)^ = v
				return ok
			case 4:
				v, ok := decode_binary_i32(col_val.data)
				if ok do (^i32)(dst)^ = v
				return ok
			case 8:
				v, ok := decode_binary_i64(col_val.data)
				if ok do (^i64)(dst)^ = v
				return ok
			}
		} else {
			switch ti.size {
			case 1:
				v, ok := decode_text_i16(col_val.data)
				if ok do (^i8)(dst)^ = i8(v)
				return ok
			case 2:
				v, ok := decode_text_i16(col_val.data)
				if ok do (^i16)(dst)^ = v
				return ok
			case 4:
				v, ok := decode_text_i32(col_val.data)
				if ok do (^i32)(dst)^ = v
				return ok
			case 8:
				v, ok := decode_text_i64(col_val.data)
				if ok do (^i64)(dst)^ = v
				return ok
			}
		}
		return false

	case reflect.Type_Info_Float:
		if col_val.is_null do return true
		if format == .Binary {
			switch ti.size {
			case 4:
				v, ok := decode_binary_f32(col_val.data)
				if ok do (^f32)(dst)^ = v
				return ok
			case 8:
				v, ok := decode_binary_f64(col_val.data)
				if ok do (^f64)(dst)^ = v
				return ok
			}
		} else {
			switch ti.size {
			case 4:
				v, ok := decode_text_f32(col_val.data)
				if ok do (^f32)(dst)^ = v
				return ok
			case 8:
				v, ok := decode_text_f64(col_val.data)
				if ok do (^f64)(dst)^ = v
				return ok
			}
		}
		return false

	case reflect.Type_Info_Boolean:
		if col_val.is_null do return true
		if format == .Binary {
			b, ok := decode_binary_bool(col_val.data)
			if ok do (^bool)(dst)^ = b
			return ok
		} else {
			b, ok := decode_text_bool(col_val.data)
			if ok do (^bool)(dst)^ = b
			return ok
		}

	case reflect.Type_Info_Array:
		if variant.count == 16 && variant.elem.id == typeid_of(u8) {
			if format == .Binary {
				u, ok := decode_binary_uuid(col_val.data)
				if ok do (^[16]u8)(dst)^ = u
				return ok
			} else {
				u, ok := decode_text_uuid(col_val.data)
				if ok do (^[16]u8)(dst)^ = u
				return ok
			}
		}

	case reflect.Type_Info_Slice:
		if col_val.is_null do return true
		elem_base := reflect.type_info_base(variant.elem)
		#partial switch el in elem_base.variant {
		case reflect.Type_Info_Integer:
			arr, ok := decode_text_array_i32(col_val.data, allocator)
			if ok do (^[]i32)(dst)^ = arr
			return ok
		case reflect.Type_Info_String:
			arr, ok := decode_text_array_string(col_val.data, allocator)
			if ok do (^[]string)(dst)^ = arr
			return ok
		case reflect.Type_Info_Rune:
			if format == .Binary {
				bytes, ok := decode_binary_bytea(col_val.data, allocator)
				if ok do (^[]byte)(dst)^ = bytes
				return ok
			} else {
				bytes, ok := decode_text_bytea(col_val.data, allocator)
				if ok do (^[]byte)(dst)^ = bytes
				return ok
			}
		}
		if variant.elem.id == typeid_of(u8) {
			if format == .Binary {
				bytes, ok := decode_binary_bytea(col_val.data, allocator)
				if ok do (^[]byte)(dst)^ = bytes
				return ok
			} else {
				bytes, ok := decode_text_bytea(col_val.data, allocator)
				if ok do (^[]byte)(dst)^ = bytes
				return ok
			}
		}
	}

	return false
}
