package pgorm

import "base:intrinsics"
import "core:reflect"
import "core:strconv"
import "core:strings"
import "../pgerr"   // Imports driver error types
import "../pgproto" // Imports wire protocol definitions

// ----------------------------------------------------------------------------
// High-Level Reflection-Based ORM Mapper
// ----------------------------------------------------------------------------

/*
	map_row_to_struct maps a single PostgreSQL DataRow into an Odin struct using reflection.

	ARCHITECTURAL RULES:
	- Rule 1 (3-Layer Architecture): pgorm is the high-level mapping layer using `core:reflect`.
	- Rule 3 (Strict Allocator Boundaries): MUST strictly use `allocator` (defaults to `context.temp_allocator`)
	  for all dynamically mapped strings, slices, or temporary buffers.
	- Rule 4 (Tagged Union Error Handling): Returns `pgerr.Error` on mapping or type mismatch failures.
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
	// Verify column count matches expected struct fields or handle partial mapping
	if len(row.values) != len(desc.fields) {
		return result, pgerr.Protocol_Error{
			type = .Invalid_Column_Count,
			message = "Mismatch between DataRow value count and RowDescription field count",
		}
	}

	// Iterate over struct fields via core:reflect
	for field in reflect.struct_fields_zipped(T) {
		// 1. Determine target column name (check struct tag `db:"..."` first, fallback to field name)
		col_name := field.name
		if db_tag, has_tag := reflect.struct_tag_lookup(field.tag, "db"); has_tag {
			col_name = db_tag
		}

		// 2. Find corresponding column in desc.fields
		col_idx := -1
		for f, idx in desc.fields {
			if strings.equal_fold(f.name, col_name) {
				col_idx = idx
				break
			}
		}

		if col_idx < 0 || col_idx >= len(row.values) {
			continue // Skip unmapped fields or handle missing columns
		}

		col_val := row.values[col_idx]
		if col_val.is_null {
			// Handle nullable fields / zero-value
			continue
		}

		// 3. Reflectively decode and set value at (rawptr(uintptr(&result) + field.offset))
		// Strings and slices are allocated using the provided `allocator` (context.temp_allocator)
		field_ptr := rawptr(uintptr(&result) + field.offset)
		field_ti := reflect.type_info_base(field.type)

		#partial switch variant in field_ti.variant {
		case reflect.Type_Info_String:
			// Copy string slice into temp_allocator
			str_val := strings.clone_from_bytes(col_val.data, allocator)
			(^string)(field_ptr)^ = str_val

		case reflect.Type_Info_Integer:
			// Parse text-format or binary-format integer into target field (stub)
			val_str := string(col_val.data)
			if parsed_int, ok := strconv.parse_i64(val_str); ok {
				// Assign based on size
				switch field_ti.size {
				case 1: (^i8)(field_ptr)^ = i8(parsed_int)
				case 2: (^i16)(field_ptr)^ = i16(parsed_int)
				case 4: (^i32)(field_ptr)^ = i32(parsed_int)
				case 8: (^i64)(field_ptr)^ = parsed_int
				}
			}

		case reflect.Type_Info_Boolean:
			if len(col_val.data) > 0 {
				(^bool)(field_ptr)^ = (col_val.data[0] == 't' || col_val.data[0] == '1')
			}

		case reflect.Type_Info_Float:
			val_str := string(col_val.data)
			if parsed_f64, ok := strconv.parse_f64(val_str); ok {
				switch field_ti.size {
				case 4: (^f32)(field_ptr)^ = f32(parsed_f64)
				case 8: (^f64)(field_ptr)^ = parsed_f64
				}
			}
		}
	}

	return result, nil
}

/*
	map_rows_to_slice maps an array of PostgreSQL DataRows into a slice of Odin structs.
	Allocates the returned slice and all nested strings using `context.temp_allocator`.
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
	for row, i in rows {
		item, map_err := map_row_to_struct(T, desc, row, allocator)
		if map_err != nil {
			return nil, map_err
		}
		out[i] = item
	}
	return out, nil
}
