package pgmap

import "core:mem"
import "core:testing"
@(require) import "core:time"
@(require) import "../pgconn"
@(require) import "../pgerr"
@(require) import "../pgproto"

@(test)
test_to_bind_param_primitives :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	tracked := mem.tracking_allocator(&track)

	// Bool
	p_bool, err_bool := to_bind_param(true, tracked)
	testing.expect_value(t, err_bool, nil)
	testing.expect(t, !p_bool.is_null)
	testing.expect_value(t, string(p_bool.value), "TRUE")
	delete(p_bool.value, tracked)

	// Integer
	p_int, err_int := to_bind_param(i32(42), tracked)
	testing.expect_value(t, err_int, nil)
	testing.expect(t, !p_int.is_null)
	testing.expect_value(t, string(p_int.value), "42")
	delete(p_int.value, tracked)

	// Float
	p_float, err_float := to_bind_param(3.14, tracked)
	testing.expect_value(t, err_float, nil)
	testing.expect(t, !p_float.is_null)
	testing.expect(t, len(p_float.value) > 0)
	delete(p_float.value, tracked)

	// String
	p_str, err_str := to_bind_param("hello postgres", tracked)
	testing.expect_value(t, err_str, nil)
	testing.expect(t, !p_str.is_null)
	testing.expect_value(t, string(p_str.value), "hello postgres")
	delete(p_str.value, tracked)

	// UUID
	uuid_raw := [16]u8{
		0xa0, 0xee, 0xbc, 0x99, 0x9c, 0x0b, 0x4e, 0xf8,
		0xbb, 0x6d, 0x6b, 0xb9, 0xbd, 0x38, 0x0a, 0x11,
	}
	p_uuid, err_uuid := to_bind_param(uuid_raw, tracked)
	testing.expect_value(t, err_uuid, nil)
	testing.expect(t, !p_uuid.is_null)
	testing.expect_value(t, string(p_uuid.value), "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11")
	delete(p_uuid.value, tracked)

	// Maybe(T) non-nil
	m_str: Maybe(string) = "optional text"
	p_m, err_m := to_bind_param(m_str, tracked)
	testing.expect_value(t, err_m, nil)
	testing.expect(t, !p_m.is_null)
	testing.expect_value(t, string(p_m.value), "optional text")
	delete(p_m.value, tracked)

	// Maybe(T) nil
	m_nil: Maybe(string) = nil
	p_mnil, err_mnil := to_bind_param(m_nil, tracked)
	testing.expect_value(t, err_mnil, nil)
	testing.expect(t, p_mnil.is_null)
	testing.expect_value(t, len(p_mnil.value), 0)

	// Pointer non-nil
	val_i := i64(999)
	ptr_i := &val_i
	p_ptr, err_ptr := to_bind_param(ptr_i, tracked)
	testing.expect_value(t, err_ptr, nil)
	testing.expect(t, !p_ptr.is_null)
	testing.expect_value(t, string(p_ptr.value), "999")
	delete(p_ptr.value, tracked)

	// Pointer nil
	ptr_nil: ^i64 = nil
	p_ptrnil, err_ptrnil := to_bind_param(ptr_nil, tracked)
	testing.expect_value(t, err_ptrnil, nil)
	testing.expect(t, p_ptrnil.is_null)

	testing.expect_value(t, len(track.allocation_map), 0)
}

// Regression (code review M1): unsupported argument types used to bind as
// silent NULLs. They must now return Unsupported_Parameter_Type.
@(test)
test_to_bind_param_unsupported_types :: proc(t: ^testing.T) {
	Bad_Target :: struct {
		x: i32,
	}

	bad_struct := Bad_Target{x = 1}
	_, err_struct := to_bind_param(bad_struct)
	p_err, is_proto := err_struct.(pgerr.Protocol_Error)
	testing.expect(t, is_proto, "struct parameter must error")
	testing.expect_value(t, p_err.type, pgerr.Protocol_Error_Type.Unsupported_Parameter_Type)

	bad_slice := []i32{1, 2, 3}
	_, err_slice := to_bind_param(bad_slice)
	p_err_slice, is_proto_slice := err_slice.(pgerr.Protocol_Error)
	testing.expect(t, is_proto_slice, "non-bytea slice parameter must error")
	testing.expect_value(t, p_err_slice.type, pgerr.Protocol_Error_Type.Unsupported_Parameter_Type)

	bad_array := [4]byte{1, 2, 3, 4}
	_, err_array := to_bind_param(bad_array)
	p_err_array, is_proto_array := err_array.(pgerr.Protocol_Error)
	testing.expect(t, is_proto_array, "non-UUID array parameter must error")
	testing.expect_value(t, p_err_array.type, pgerr.Protocol_Error_Type.Unsupported_Parameter_Type)

	// i128 outside the i64 range must error instead of truncating.
	big := i128(max(i64)) + 1
	_, err_big := to_bind_param(big)
	p_err_big, is_proto_big := err_big.(pgerr.Protocol_Error)
	testing.expect(t, is_proto_big, "out-of-range i128 parameter must error")
	testing.expect_value(t, p_err_big.type, pgerr.Protocol_Error_Type.Unsupported_Parameter_Type)

	// In-range i128 still binds.
	small := i128(12345)
	p_small, err_small := to_bind_param(small)
	testing.expect_value(t, err_small, nil)
	testing.expect_value(t, string(p_small.value), "12345")
}

@(test)
test_to_bind_params_slice :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	tracked := mem.tracking_allocator(&track)

	params, err := to_bind_params([]any{10, "bob", true}, tracked)
	testing.expect_value(t, err, nil)
	testing.expect_value(t, len(params), 3)
	testing.expect_value(t, string(params[0].value), "10")
	testing.expect_value(t, string(params[1].value), "bob")
	testing.expect_value(t, string(params[2].value), "TRUE")

	for p in params {
		if !p.is_null do delete(p.value, tracked)
	}
	delete(params, tracked)

	testing.expect_value(t, len(track.allocation_map), 0)
}

// Regression (code review M1): a failing argument mid-list must free every
// value encoded before it and propagate the error.
@(test)
test_to_bind_params_error_cleanup :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	tracked := mem.tracking_allocator(&track)

	Bad :: struct {
		x: i32,
	}
	params, err := to_bind_params([]any{10, "bob", Bad{}}, tracked)
	testing.expect(t, err != nil, "expected error for unsupported third argument")
	testing.expect(t, params == nil)

	testing.expect_value(t, len(track.allocation_map), 0)
}

// ----------------------------------------------------------------------------
// Integration Tests with Live PostgreSQL
// ----------------------------------------------------------------------------

OPG_INTEGRATION :: #config(OPG_INTEGRATION, false)

when OPG_INTEGRATION {

	Item :: struct {
		id:     i32,
		name:   string,
		price:  f64,
		active: bool,
	}

	@(test)
	test_integration_query_struct_and_slice :: proc(t: ^testing.T) {
		cfg := pgconn.integration_conn_config(t)

		conn, cerr := pgconn.conn_connect(cfg)
		if cerr != nil {
			if pg_err, is_pg := cerr.(pgerr.Postgres_Error); is_pg {
				pgerr.postgres_error_destroy(pg_err, context.allocator)
			}
			testing.expect(t, cerr == nil, "conn_connect failed")
			return
		}
		defer {
			pgconn.conn_close(conn)
			free(conn, context.allocator)
		}

		// 1. exec DDL
		_, ddl_err := exec(conn, "CREATE TEMP TABLE test_orm_items (id serial primary key, name text, price float8, active bool)")
		testing.expect_value(t, ddl_err, nil)

		// 2. exec INSERT with parameters
		aff1, ins_err1 := exec(conn, "INSERT INTO test_orm_items (name, price, active) VALUES ($1, $2, $3)", "widget", 19.99, true)
		testing.expect_value(t, ins_err1, nil)
		testing.expect_value(t, aff1, 1)

		aff2, ins_err2 := exec(conn, "INSERT INTO test_orm_items (name, price, active) VALUES ($1, $2, $3)", "gadget", 49.50, false)
		testing.expect_value(t, ins_err2, nil)
		testing.expect_value(t, aff2, 1)

		// 3. query_struct
		widget, qs_err := query_struct(conn, Item, "SELECT id, name, price, active FROM test_orm_items WHERE name = $1", "widget")
		testing.expect_value(t, qs_err, nil)
		testing.expect_value(t, widget.name, "widget")
		testing.expect(t, abs(widget.price - 19.99) < 0.001)
		testing.expect_value(t, widget.active, true)

		// 4. query_slice
		items, qsl_err := query_slice(conn, Item, "SELECT id, name, price, active FROM test_orm_items ORDER BY id")
		testing.expect_value(t, qsl_err, nil)
		testing.expect_value(t, len(items), 2)
		testing.expect_value(t, items[0].name, "widget")
		testing.expect_value(t, items[1].name, "gadget")

		// 5. exec UPDATE
		aff3, up_err := exec(conn, "UPDATE test_orm_items SET active = $1 WHERE price > $2", true, 20.0)
		testing.expect_value(t, up_err, nil)
		testing.expect_value(t, aff3, 1)
	}

	// Regression (code review C2): the collector retained a RowDescription
	// whose field names borrowed from the stream accumulation buffer. Once a
	// response exceeded the 4KB compaction threshold, every column match read
	// reused memory and all rows mapped to zero values with err == nil.
	@(test)
	test_integration_large_result_set_mapping :: proc(t: ^testing.T) {
		cfg := pgconn.integration_conn_config(t)

		conn, cerr := pgconn.conn_connect(cfg)
		if cerr != nil {
			testing.expect(t, cerr == nil, "conn_connect failed")
			return
		}
		defer {
			pgconn.conn_close(conn)
			free(conn, context.allocator)
		}

		Wide_Row :: struct {
			pad:  string,
			id:   i64,
			name: string,
		}

		rows, err := query_slice(
			conn,
			Wide_Row,
			"SELECT repeat('x', 500) AS pad, g AS id, 'item_' || g AS name FROM generate_series(1, 40) g",
		)
		testing.expect_value(t, err, nil)
		testing.expect_value(t, len(rows), 40)
		for r, i in rows {
			testing.expect_value(t, r.id, i64(i + 1))
			testing.expect_value(t, len(r.pad), 500)
		}
		testing.expect_value(t, rows[0].name, "item_1")
		testing.expect_value(t, rows[39].name, "item_40")
	}

	// Regression (code review H2): []byte parameters were sent as raw bytes
	// under text parameter format; the server rejected them. They are now
	// hex-encoded and must round-trip through a bytea column exactly.
	@(test)
	test_integration_bytea_param_round_trip :: proc(t: ^testing.T) {
		cfg := pgconn.integration_conn_config(t)

		conn, cerr := pgconn.conn_connect(cfg)
		if cerr != nil {
			testing.expect(t, cerr == nil, "conn_connect failed")
			return
		}
		defer {
			pgconn.conn_close(conn)
			free(conn, context.allocator)
		}

		_, ddl_err := exec(conn, "CREATE TEMP TABLE probe_bytea (data bytea)")
		testing.expect_value(t, ddl_err, nil)

		payload := []byte{0xDE, 0xAD, 0x00, 0xBE, 0xEF}
		aff, ins_err := exec(conn, "INSERT INTO probe_bytea (data) VALUES ($1)", payload)
		testing.expect_value(t, ins_err, nil)
		testing.expect_value(t, aff, 1)

		Blob_Row :: struct {
			data: []byte,
		}
		res, sel_err := query_struct(conn, Blob_Row, "SELECT data FROM probe_bytea")
		testing.expect_value(t, sel_err, nil)
		testing.expect_value(t, len(res.data), 5)
		if len(res.data) == 5 {
			for b, i in payload {
				testing.expect_value(t, res.data[i], b)
			}
		}
	}

	// Regression (code review H1): f64 parameters were truncated to 6 decimal
	// places by "%f" encoding; the bound value must round-trip bit-exactly.
	@(test)
	test_integration_f64_param_round_trip :: proc(t: ^testing.T) {
		cfg := pgconn.integration_conn_config(t)

		conn, cerr := pgconn.conn_connect(cfg)
		if cerr != nil {
			testing.expect(t, cerr == nil, "conn_connect failed")
			return
		}
		defer {
			pgconn.conn_close(conn)
			free(conn, context.allocator)
		}

		Float_Row :: struct {
			val: f64,
		}
		in_val := 0.123456789012345
		res, err := query_struct(conn, Float_Row, "SELECT $1::float8 AS val", in_val)
		testing.expect_value(t, err, nil)
		testing.expect_value(t, res.val, in_val)
	}

	// Regression (code reviews H3/H4): bound timestamps lost sub-second
	// precision and decoded timestamps dropped their fractional part. A
	// microsecond-precision value must now survive the round trip exactly.
	@(test)
	test_integration_timestamp_round_trip :: proc(t: ^testing.T) {
		cfg := pgconn.integration_conn_config(t)

		conn, cerr := pgconn.conn_connect(cfg)
		if cerr != nil {
			testing.expect(t, cerr == nil, "conn_connect failed")
			return
		}
		defer {
			pgconn.conn_close(conn)
			free(conn, context.allocator)
		}

		_, ddl_err := exec(conn, "CREATE TEMP TABLE probe_ts (ts timestamp)")
		testing.expect_value(t, ddl_err, nil)

		ts_in, ts_ok := time.datetime_to_time(2024, 3, 15, 13, 45, 30, 123_456_000)
		testing.expect(t, ts_ok)
		aff, ins_err := exec(conn, "INSERT INTO probe_ts (ts) VALUES ($1)", ts_in)
		testing.expect_value(t, ins_err, nil)
		testing.expect_value(t, aff, 1)

		Time_Row :: struct {
			ts: time.Time,
		}
		res, sel_err := query_struct(conn, Time_Row, "SELECT ts FROM probe_ts")
		testing.expect_value(t, sel_err, nil)
		testing.expect_value(t, time.to_unix_nanoseconds(res.ts), time.to_unix_nanoseconds(ts_in))
	}
}
