package pgorm

import "core:mem"
@(require) import "core:os"
@(require) import "core:strconv"
@(require) import "core:strings"
import "core:testing"
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
	p_bool := to_bind_param(true, tracked)
	testing.expect(t, !p_bool.is_null)
	testing.expect_value(t, string(p_bool.value), "TRUE")
	delete(p_bool.value, tracked)

	// Integer
	p_int := to_bind_param(i32(42), tracked)
	testing.expect(t, !p_int.is_null)
	testing.expect_value(t, string(p_int.value), "42")
	delete(p_int.value, tracked)

	// Float
	p_float := to_bind_param(3.14, tracked)
	testing.expect(t, !p_float.is_null)
	testing.expect(t, len(p_float.value) > 0)
	delete(p_float.value, tracked)

	// String
	p_str := to_bind_param("hello postgres", tracked)
	testing.expect(t, !p_str.is_null)
	testing.expect_value(t, string(p_str.value), "hello postgres")
	delete(p_str.value, tracked)

	// UUID
	uuid_raw := [16]u8{
		0xa0, 0xee, 0xbc, 0x99, 0x9c, 0x0b, 0x4e, 0xf8,
		0xbb, 0x6d, 0x6b, 0xb9, 0xbd, 0x38, 0x0a, 0x11,
	}
	p_uuid := to_bind_param(uuid_raw, tracked)
	testing.expect(t, !p_uuid.is_null)
	testing.expect_value(t, string(p_uuid.value), "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11")
	delete(p_uuid.value, tracked)

	// Maybe(T) non-nil
	m_str: Maybe(string) = "optional text"
	p_m := to_bind_param(m_str, tracked)
	testing.expect(t, !p_m.is_null)
	testing.expect_value(t, string(p_m.value), "optional text")
	delete(p_m.value, tracked)

	// Maybe(T) nil
	m_nil: Maybe(string) = nil
	p_mnil := to_bind_param(m_nil, tracked)
	testing.expect(t, p_mnil.is_null)
	testing.expect_value(t, len(p_mnil.value), 0)

	// Pointer non-nil
	val_i := i64(999)
	ptr_i := &val_i
	p_ptr := to_bind_param(ptr_i, tracked)
	testing.expect(t, !p_ptr.is_null)
	testing.expect_value(t, string(p_ptr.value), "999")
	delete(p_ptr.value, tracked)

	// Pointer nil
	ptr_nil: ^i64 = nil
	p_ptrnil := to_bind_param(ptr_nil, tracked)
	testing.expect(t, p_ptrnil.is_null)

	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
test_to_bind_params_slice :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	tracked := mem.tracking_allocator(&track)

	params := to_bind_params([]any{10, "bob", true}, tracked)
	testing.expect_value(t, len(params), 3)
	testing.expect_value(t, string(params[0].value), "10")
	testing.expect_value(t, string(params[1].value), "bob")
	testing.expect_value(t, string(params[2].value), "TRUE")

	for p in params {
		delete(p.value, tracked)
	}
	delete(params, tracked)

	testing.expect_value(t, len(track.allocation_map), 0)
}

// ----------------------------------------------------------------------------
// Integration Tests with Live PostgreSQL
// ----------------------------------------------------------------------------

OPG_INTEGRATION :: #config(OPG_INTEGRATION, false)

when OPG_INTEGRATION {

	get_integration_port :: proc() -> int {
		if env_port := os.get_env("PGPORT", context.temp_allocator); env_port != "" {
			if p, ok := strconv.parse_int(env_port); ok do return p
		}
		port_state, port_out, _, port_err := os.process_exec(
			{command = {"docker", "compose", "port", "postgres", "5432"}},
			context.temp_allocator,
		)
		if port_err == nil && port_state.success {
			endpoint := strings.trim_space(string(port_out))
			colon := strings.last_index_byte(endpoint, ':')
			if colon >= 0 {
				if parsed, ok := strconv.parse_int(endpoint[colon + 1:]); ok {
					return parsed
				}
			}
		}
		return 5432
	}

	Item :: struct {
		id:     i32,
		name:   string,
		price:  f64,
		active: bool,
	}

	@(test)
	test_integration_query_struct_and_slice :: proc(t: ^testing.T) {
		cfg := pgconn.Conn_Config{
			host     = "127.0.0.1",
			port     = get_integration_port(),
			user     = "opg",
			password = "opg",
			database = "opg_test",
		}

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
}
