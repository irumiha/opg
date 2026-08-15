package pgorm

import "base:intrinsics"
import "core:fmt"
import "core:mem"
import "core:reflect"
import "core:slice"
import "core:time"
import "../pgconn"
import "../pgerr"
import "../pgproto"

// ============================================================================
// High-Level Ergonomic SQL Execution & Parameter Binding API
// ============================================================================

null_bind_param_value: []byte = nil

/*
	to_bind_param translates an arbitrary Odin value into a PostgreSQL Bind_Param.
	Supports integers, floats, booleans, strings, UUIDs, time.Time, Maybe(T), and pointers.
*/
to_bind_param :: proc(arg: any, allocator := context.temp_allocator) -> pgproto.Bind_Param {
	if arg == nil || arg.id == nil {
		return pgproto.Bind_Param{is_null = true, value = null_bind_param_value}
	}

	ti := type_info_of(arg.id)
	base_ti := reflect.type_info_base(ti)

	if is_time_type(ti) || is_time_type(base_ti) {
		ts := (^time.Time)(arg.data)^
		y, m, d := time.date(ts)
		h, min_val, s := time.clock(ts)
		s_str := fmt.aprintf("%04d-%02d-%02d %02d:%02d:%02d", y, int(m), d, h, min_val, s, allocator = allocator)
		return pgproto.Bind_Param{
			is_null = false,
			value   = transmute([]byte)s_str,
		}
	}

	#partial switch variant in base_ti.variant {
	case reflect.Type_Info_Boolean:
		val := (^bool)(arg.data)^
		return pgproto.Bind_Param{
			is_null = false,
			value   = encode_text_bool(val, allocator),
		}

	case reflect.Type_Info_Integer:
		val := get_any_int(arg)
		return pgproto.Bind_Param{
			is_null = false,
			value   = encode_text_i64(val, allocator),
		}

	case reflect.Type_Info_Float:
		val := get_any_float(arg)
		return pgproto.Bind_Param{
			is_null = false,
			value   = encode_text_f64(val, allocator),
		}

	case reflect.Type_Info_String:
		val := (^string)(arg.data)^
		return pgproto.Bind_Param{
			is_null = false,
			value   = encode_text_string(val, allocator),
		}

	case reflect.Type_Info_Union:
		val_any := reflect.get_union_variant(arg)
		if val_any == nil do return pgproto.Bind_Param{is_null = true, value = null_bind_param_value}
		return to_bind_param(val_any, allocator)

	case reflect.Type_Info_Pointer:
		ptr := (^rawptr)(arg.data)^
		if ptr == nil do return pgproto.Bind_Param{is_null = true, value = null_bind_param_value}
		elem_any := any{data = ptr, id = variant.elem.id}
		return to_bind_param(elem_any, allocator)

	case reflect.Type_Info_Array:
		if variant.count == 16 && variant.elem.id == typeid_of(u8) {
			val := (^[16]u8)(arg.data)^
			return pgproto.Bind_Param{
				is_null = false,
				value   = encode_text_uuid(val, allocator),
			}
		}

	case reflect.Type_Info_Slice:
		if variant.elem.id == typeid_of(u8) {
			bytes := (^[]byte)(arg.data)^
			return pgproto.Bind_Param{
				is_null = false,
				value   = encode_binary_bytea(bytes, allocator),
			}
		}
	}

	return pgproto.Bind_Param{is_null = true, value = null_bind_param_value}
}

@(private="file")
get_any_int :: proc(a: any) -> i64 {
	ti := reflect.type_info_base(type_info_of(a.id))
	#partial switch variant in ti.variant {
	case reflect.Type_Info_Integer:
		if variant.signed {
			switch ti.size {
			case 1: return i64((^i8)(a.data)^)
			case 2: return i64((^i16)(a.data)^)
			case 4: return i64((^i32)(a.data)^)
			case 8: return i64((^i64)(a.data)^)
			case 16: return i64((^i128)(a.data)^)
			}
		} else {
			switch ti.size {
			case 1: return i64((^u8)(a.data)^)
			case 2: return i64((^u16)(a.data)^)
			case 4: return i64((^u32)(a.data)^)
			case 8: return i64((^u64)(a.data)^)
			case 16: return i64((^u128)(a.data)^)
			}
		}
	}
	return 0
}

@(private="file")
get_any_float :: proc(a: any) -> f64 {
	ti := reflect.type_info_base(type_info_of(a.id))
	#partial switch variant in ti.variant {
	case reflect.Type_Info_Float:
		switch ti.size {
		case 4: return f64((^f32)(a.data)^)
		case 8: return f64((^f64)(a.data)^)
		}
	}
	return 0
}

/*
	to_bind_params translates a slice of arguments into a slice of PostgreSQL Bind_Params.
*/
to_bind_params :: proc(args: []any, allocator := context.temp_allocator) -> []pgproto.Bind_Param {
	params := make([]pgproto.Bind_Param, len(args), allocator)
	for arg, i in args {
		params[i] = to_bind_param(arg, allocator)
	}
	return params
}

@(private="file")
Query_Collector :: struct {
	desc:          pgproto.Msg_Row_Description,
	rows:          [dynamic]pgproto.Msg_Data_Row,
	command_tag:   string,
	rows_affected: i64,
	allocator:     mem.Allocator,
}

@(private="file")
on_exec_desc :: proc(user_data: rawptr, desc: pgproto.Msg_Row_Description) {
	c := (^Query_Collector)(user_data)
	c.desc = desc
}

@(private="file")
on_exec_row :: proc(user_data: rawptr, row: pgproto.Msg_Data_Row) -> bool {
	c := (^Query_Collector)(user_data)
	cloned_row: pgproto.Msg_Data_Row
	cloned_row.values = make([]pgproto.Column_Value, len(row.values), c.allocator)
	for val, i in row.values {
		if val.is_null {
			cloned_row.values[i] = pgproto.Column_Value{is_null = true, data = null_bind_param_value}
		} else {
			cloned_row.values[i] = pgproto.Column_Value{
				is_null = false,
				data    = slice.clone(val.data, c.allocator),
			}
		}
	}
	append(&c.rows, cloned_row)
	return true
}

@(private="file")
on_exec_command :: proc(user_data: rawptr, tag: string, rows_affected: i64) {
	c := (^Query_Collector)(user_data)
	c.command_tag = tag
	c.rows_affected = rows_affected
}

/*
	query_struct executes a query with arguments and maps the first returned row into struct type T.
	Fails with Protocol_Error{.No_Data} if no rows were returned.
*/
query_struct :: proc(
	conn: ^pgconn.Conn,
	$T: typeid,
	sql: string,
	args: ..any,
	allocator := context.temp_allocator,
) -> (
	result: T,
	err: pgerr.Error,
) where intrinsics.type_is_struct(T) {
	collector := Query_Collector{
		allocator = allocator,
		rows      = make([dynamic]pgproto.Msg_Data_Row, 0, 1, allocator),
	}
	bind_params := to_bind_params(args, allocator)

	qerr := pgconn.conn_exec_params(
		conn = conn,
		query = sql,
		params = bind_params,
		on_row = on_exec_row,
		on_command = on_exec_command,
		on_desc = on_exec_desc,
		user_data = &collector,
	)
	if qerr != nil do return result, qerr

	if len(collector.rows) == 0 {
		return result, pgerr.Protocol_Error{
			type    = .No_Data,
			message = "query_struct expected at least 1 row, got 0",
		}
	}

	return map_row_to_struct(T, collector.desc, collector.rows[0], allocator)
}

/*
	query_slice executes a query with arguments and maps all returned rows into a slice of struct type T.
*/
query_slice :: proc(
	conn: ^pgconn.Conn,
	$T: typeid,
	sql: string,
	args: ..any,
	allocator := context.temp_allocator,
) -> (
	result: []T,
	err: pgerr.Error,
) where intrinsics.type_is_struct(T) {
	collector := Query_Collector{
		allocator = allocator,
		rows      = make([dynamic]pgproto.Msg_Data_Row, 0, 16, allocator),
	}
	bind_params := to_bind_params(args, allocator)

	qerr := pgconn.conn_exec_params(
		conn = conn,
		query = sql,
		params = bind_params,
		on_row = on_exec_row,
		on_command = on_exec_command,
		on_desc = on_exec_desc,
		user_data = &collector,
	)
	if qerr != nil do return nil, qerr

	if len(collector.rows) == 0 {
		return make([]T, 0, allocator), nil
	}

	return map_rows_to_slice(T, collector.desc, collector.rows[:], allocator)
}

/*
	exec executes a SQL command (e.g. INSERT, UPDATE, DELETE, DDL) with parameter arguments
	and returns the count of rows affected.
*/
exec :: proc(
	conn: ^pgconn.Conn,
	sql: string,
	args: ..any,
) -> (
	rows_affected: int,
	err: pgerr.Error,
) {
	collector := Query_Collector{
		allocator = context.temp_allocator,
		rows      = make([dynamic]pgproto.Msg_Data_Row, 0, 0, context.temp_allocator),
	}
	bind_params := to_bind_params(args, context.temp_allocator)

	qerr := pgconn.conn_exec_params(
		conn = conn,
		query = sql,
		params = bind_params,
		on_row = nil,
		on_command = on_exec_command,
		on_desc = nil,
		user_data = &collector,
	)
	if qerr != nil do return 0, qerr

	return int(collector.rows_affected), nil
}
