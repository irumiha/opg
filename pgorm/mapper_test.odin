package pgorm

import "core:mem"
import "core:testing"
import "../pgerr"
import "../pgproto"

Test_User :: struct {
	id:     i64,
	name:   string,
	active: bool,
	score:  f64 `db:"points"`,
}

text_col :: proc(s: string) -> pgproto.Column_Value {
	return pgproto.Column_Value{is_null = false, data = transmute([]byte)s}
}

@(test)
test_map_row_to_struct_text_format :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	desc := pgproto.Msg_Row_Description{
		fields = []pgproto.Field_Description{
			{name = "id"},
			{name = "name"},
			{name = "points"},
			{name = "active"},
		},
	}
	row := pgproto.Msg_Data_Row{
		values = []pgproto.Column_Value{
			text_col("42"),
			text_col("alice"),
			text_col("3.5"),
			text_col("t"),
		},
	}

	u, err := map_row_to_struct(Test_User, desc, row)
	testing.expect_value(t, err, nil)
	testing.expect_value(t, u.id, i64(42))
	testing.expect_value(t, u.name, "alice")
	testing.expect_value(t, u.score, 3.5)
	testing.expect_value(t, u.active, true)

	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
test_map_row_to_struct_null_and_missing_columns :: proc(t: ^testing.T) {
	desc := pgproto.Msg_Row_Description{
		fields = []pgproto.Field_Description{
			{name = "id"},
			{name = "name"},
		},
	}
	row := pgproto.Msg_Data_Row{
		values = []pgproto.Column_Value{
			text_col("7"),
			{is_null = true, data = nil},
		},
	}

	// NULL columns and struct fields without matching columns stay zero-valued.
	u, err := map_row_to_struct(Test_User, desc, row)
	testing.expect_value(t, err, nil)
	testing.expect_value(t, u.id, i64(7))
	testing.expect_value(t, u.name, "")
	testing.expect_value(t, u.active, false)
	testing.expect_value(t, u.score, 0.0)
}

@(test)
test_map_row_to_struct_column_count_mismatch :: proc(t: ^testing.T) {
	desc := pgproto.Msg_Row_Description{
		fields = []pgproto.Field_Description{
			{name = "id"},
			{name = "name"},
		},
	}
	row := pgproto.Msg_Data_Row{
		values = []pgproto.Column_Value{
			text_col("1"),
		},
	}

	_, err := map_row_to_struct(Test_User, desc, row)
	p_err, is_proto := err.(pgerr.Protocol_Error)
	testing.expect(t, is_proto, "expected pgerr.Protocol_Error")
	testing.expect_value(t, p_err.type, pgerr.Protocol_Error_Type.Invalid_Column_Count)
}

@(test)
test_map_rows_to_slice :: proc(t: ^testing.T) {
	desc := pgproto.Msg_Row_Description{
		fields = []pgproto.Field_Description{
			{name = "id"},
			{name = "name"},
		},
	}
	rows := []pgproto.Msg_Data_Row{
		{values = []pgproto.Column_Value{text_col("1"), text_col("a")}},
		{values = []pgproto.Column_Value{text_col("2"), text_col("b")}},
	}

	out, err := map_rows_to_slice(Test_User, desc, rows)
	testing.expect_value(t, err, nil)
	testing.expect_value(t, len(out), 2)
	testing.expect_value(t, out[0].id, i64(1))
	testing.expect_value(t, out[0].name, "a")
	testing.expect_value(t, out[1].id, i64(2))
	testing.expect_value(t, out[1].name, "b")
}
