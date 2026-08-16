package pgmap

import "base:intrinsics"
import "core:fmt"
import "core:mem"
import "core:reflect"
import "core:slice"
import "core:strings"
import "core:time"
import "../pgconn"
import "../pgerr"
import "../pgproto"

// ============================================================================
// High-Level Ergonomic SQL Execution & Parameter Binding API
// ============================================================================

// Odin rejects returning compound literals containing an untyped nil slice
// ("unsafe to return ... uses the current stack frame's memory"), so NULL
// bind parameters and NULL column values reference this shared empty slice.
null_bind_param_value: []byte = nil

/*
	to_bind_param translates an arbitrary Odin value into a PostgreSQL Bind_Param.
	Supports integers (within i64 range), floats, booleans, strings, UUIDs,
	time.Time, []byte (bytea hex), Maybe(T), and pointers. NULL arguments bind
	as SQL NULL; unsupported types return Unsupported_Parameter_Type instead of
	silently binding NULL.
*/
to_bind_param :: proc(
	arg: any,
	allocator := context.temp_allocator,
) -> (
	param: pgproto.Bind_Param,
	err:   pgerr.Error,
) {
	if arg == nil || arg.id == nil {
		return pgproto.Bind_Param{is_null = true, value = null_bind_param_value}, nil
	}

	ti := type_info_of(arg.id)
	base_ti := reflect.type_info_base(ti)

	if is_time_type(ti) || is_time_type(base_ti) {
		ts := (^time.Time)(arg.data)^
		y, m, d := time.date(ts)
		h, min_val, s, nanos := time.precise_clock_from_time(ts)
		s_str: string
		if nanos != 0 {
			// PostgreSQL accepts at most microsecond precision (6 fractional
			// digits); nanoseconds beyond that are truncated.
			s_str = fmt.aprintf(
				"%04d-%02d-%02d %02d:%02d:%02d.%06d",
				y, int(m), d, h, min_val, s, nanos / 1000,
				allocator = allocator,
			)
		} else {
			s_str = fmt.aprintf(
				"%04d-%02d-%02d %02d:%02d:%02d",
				y, int(m), d, h, min_val, s,
				allocator = allocator,
			)
		}
		return pgproto.Bind_Param{
			is_null = false,
			value   = transmute([]byte)s_str,
		}, nil
	}

	#partial switch variant in base_ti.variant {
	case reflect.Type_Info_Boolean:
		val := (^bool)(arg.data)^
		return pgproto.Bind_Param{
			is_null = false,
			value   = encode_text_bool(val, allocator),
		}, nil

	case reflect.Type_Info_Integer:
		val, int_ok := get_any_int(arg)
		if !int_ok {
			return pgproto.Bind_Param{is_null = true, value = null_bind_param_value}, pgerr.Protocol_Error{
				type    = .Unsupported_Parameter_Type,
				message = "Integer parameter value out of i64 range",
			}
		}
		return pgproto.Bind_Param{
			is_null = false,
			value   = encode_text_i64(val, allocator),
		}, nil

	case reflect.Type_Info_Float:
		val := get_any_float(arg)
		return pgproto.Bind_Param{
			is_null = false,
			value   = encode_text_f64(val, allocator),
		}, nil

	case reflect.Type_Info_String:
		val := (^string)(arg.data)^
		return pgproto.Bind_Param{
			is_null = false,
			value   = encode_text_string(val, allocator),
		}, nil

	case reflect.Type_Info_Union:
		val_any := reflect.get_union_variant(arg)
		if val_any == nil {
			return pgproto.Bind_Param{is_null = true, value = null_bind_param_value}, nil
		}
		return to_bind_param(val_any, allocator)

	case reflect.Type_Info_Pointer:
		ptr := (^rawptr)(arg.data)^
		if ptr == nil {
			return pgproto.Bind_Param{is_null = true, value = null_bind_param_value}, nil
		}
		elem_any := any{data = ptr, id = variant.elem.id}
		return to_bind_param(elem_any, allocator)

	case reflect.Type_Info_Array:
		if variant.count == 16 && variant.elem.id == typeid_of(u8) {
			val := (^[16]u8)(arg.data)^
			return pgproto.Bind_Param{
				is_null = false,
				value   = encode_text_uuid(val, allocator),
			}, nil
		}

	case reflect.Type_Info_Slice:
		if variant.elem.id == typeid_of(u8) {
			bytes := (^[]byte)(arg.data)^
			return pgproto.Bind_Param{
				is_null = false,
				value   = encode_text_bytea(bytes, allocator),
			}, nil
		}
	}

	return pgproto.Bind_Param{is_null = true, value = null_bind_param_value}, pgerr.Protocol_Error{
		type    = .Unsupported_Parameter_Type,
		message = "Unsupported Odin type for SQL parameter binding",
	}
}

@(private="file")
get_any_int :: proc(a: any) -> (val: i64, ok: bool) {
	ti := reflect.type_info_base(type_info_of(a.id))
	#partial switch variant in ti.variant {
	case reflect.Type_Info_Integer:
		if variant.signed {
			switch ti.size {
			case 1: return i64((^i8)(a.data)^), true
			case 2: return i64((^i16)(a.data)^), true
			case 4: return i64((^i32)(a.data)^), true
			case 8: return i64((^i64)(a.data)^), true
			case 16: {
				v := (^i128)(a.data)^
				if v < i128(min(i64)) || v > i128(max(i64)) do return 0, false
				return i64(v), true
			}
			}
		} else {
			switch ti.size {
			case 1: return i64((^u8)(a.data)^), true
			case 2: return i64((^u16)(a.data)^), true
			case 4: return i64((^u32)(a.data)^), true
			case 8: return i64((^u64)(a.data)^), true
			case 16: {
				v := (^u128)(a.data)^
				if v > u128(max(i64)) do return 0, false
				return i64(v), true
			}
			}
		}
	}
	return 0, false
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
	to_bind_params translates a slice of arguments into a slice of PostgreSQL
	Bind_Params. On the first unsupported argument it frees every value already
	encoded into `allocator` and returns the error.
*/
to_bind_params :: proc(
	args: []any,
	allocator := context.temp_allocator,
) -> (
	params: []pgproto.Bind_Param,
	err:     pgerr.Error,
) {
	params = make([]pgproto.Bind_Param, len(args), allocator)
	for arg, i in args {
		p, perr := to_bind_param(arg, allocator)
		if perr != nil {
			for prev in params[:i] {
				if !prev.is_null do delete(prev.value, allocator)
			}
			delete(params, allocator)
			return nil, perr
		}
		params[i] = p
	}
	return params, nil
}

/*
	destroy_bind_params frees parameter values encoded by to_bind_params.
	NULL parameters reference a shared empty slice and are skipped.
*/
@(private="file")
destroy_bind_params :: proc(params: []pgproto.Bind_Param, allocator: mem.Allocator) {
	for p in params {
		if !p.is_null do delete(p.value, allocator)
	}
	delete(params, allocator)
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
	// Field names borrow from the stream accumulation buffer, which is
	// compacted/reused by subsequent reads; mapping happens after the
	// execution loop, so the description must be deep-copied here.
	// Clone failure (OOM) follows the conn_exec_params precedent of
	// tolerating allocator errors on the clone path.
	c.desc, _ = pgproto.row_description_clone(desc, c.allocator)
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
	// The tag borrows from the packet buffer; clone it to survive the next read.
	c.command_tag, _ = strings.clone(tag, c.allocator)
	c.rows_affected = rows_affected
}

/*
	query_collector_destroy frees everything the collector cloned into its
	allocator: the row description, all cloned row data, and the command tag.
*/
@(private="file")
query_collector_destroy :: proc(c: ^Query_Collector) {
	pgproto.row_description_destroy(c.desc, c.allocator)
	c.desc = {}
	for row in c.rows[:] {
		for val in row.values {
			if !val.is_null do delete(val.data, c.allocator)
		}
		delete(row.values, c.allocator)
	}
	delete(c.rows)
	delete(c.command_tag, c.allocator)
	c.command_tag = ""
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
	bind_params, bp_err := to_bind_params(args, allocator)
	if bp_err != nil {
		query_collector_destroy(&collector)
		return result, bp_err
	}
	defer destroy_bind_params(bind_params, allocator)

	qerr := pgconn.conn_exec_params(
		conn = conn,
		query = sql,
		params = bind_params,
		on_row = on_exec_row,
		on_command = on_exec_command,
		on_desc = on_exec_desc,
		user_data = &collector,
	)
	defer query_collector_destroy(&collector)
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

	MEMORY LIFETIME: the returned slice and all inner strings/slices are
	allocated on `allocator` (default `context.temp_allocator`) and are
	invalidated when that allocator resets.
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
	bind_params, bp_err := to_bind_params(args, allocator)
	if bp_err != nil {
		query_collector_destroy(&collector)
		return nil, bp_err
	}
	defer destroy_bind_params(bind_params, allocator)

	qerr := pgconn.conn_exec_params(
		conn = conn,
		query = sql,
		params = bind_params,
		on_row = on_exec_row,
		on_command = on_exec_command,
		on_desc = on_exec_desc,
		user_data = &collector,
	)
	defer query_collector_destroy(&collector)
	if qerr != nil do return nil, qerr

	if len(collector.rows) == 0 {
		return make([]T, 0, allocator), nil
	}

	return map_rows_to_slice(T, collector.desc, collector.rows[:], allocator)
}

/*
	exec executes a SQL command (e.g. INSERT, UPDATE, DELETE, DDL) with parameter arguments
	and returns the count of rows affected.

	ERROR OWNERSHIP: a returned Postgres_Error is cloned into `conn.allocator`
	and belongs to the caller; free it with `pgerr.postgres_error_destroy`.
	This is unrelated to the `allocator` parameter on the query procs above,
	which governs row data.
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
	bind_params, bp_err := to_bind_params(args, context.temp_allocator)
	if bp_err != nil {
		query_collector_destroy(&collector)
		return 0, bp_err
	}
	defer destroy_bind_params(bind_params, context.temp_allocator)

	qerr := pgconn.conn_exec_params(
		conn = conn,
		query = sql,
		params = bind_params,
		on_row = nil,
		on_command = on_exec_command,
		on_desc = nil,
		user_data = &collector,
	)
	defer query_collector_destroy(&collector)
	if qerr != nil do return 0, qerr

	return int(collector.rows_affected), nil
}
