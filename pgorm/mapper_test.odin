package pgorm

import "core:mem"
import "core:testing"
import "core:time"
import "../pgerr"
import "../pgproto"

Test_User :: struct {
	id:     i64,
	name:   string,
	active: bool,
	score:  f64 `db:"points"`,
}

Test_Complex_User :: struct {
	id:          i32,
	name:        string,
	email:       Maybe(string),
	age:         Maybe(int),
	is_admin:    Maybe(bool),
	created_at:  time.Time,
	updated_at:  Maybe(time.Time),
	avatar_uuid: [16]u8 `db:"uuid"`,
	tags:        []string,
	scores:      []i32,
}

Test_Pointer_User :: struct {
	id:    i64,
	bio:   ^string,
	coins: ^i32,
}

Test_Profile :: struct {
	bio:     string,
	website: string,
}

Test_User_With_Profile :: struct {
	id:      i64,
	name:    string,
	profile: Test_Profile,
}

text_col :: proc(s: string) -> pgproto.Column_Value {
	return pgproto.Column_Value{is_null = false, data = transmute([]byte)s}
}

bin_col :: proc(b: []byte) -> pgproto.Column_Value {
	return pgproto.Column_Value{is_null = false, data = b}
}

null_slice: []byte = nil

null_col :: proc() -> pgproto.Column_Value {
	return pgproto.Column_Value{is_null = true, data = null_slice}
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
			null_col(),
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
test_map_row_to_struct_maybe_and_complex_types :: proc(t: ^testing.T) {
	desc := pgproto.Msg_Row_Description{
		fields = []pgproto.Field_Description{
			{name = "id"},
			{name = "name"},
			{name = "email"},
			{name = "age"},
			{name = "is_admin"},
			{name = "created_at"},
			{name = "updated_at"},
			{name = "uuid"},
			{name = "tags"},
			{name = "scores"},
		},
	}
	row := pgproto.Msg_Data_Row{
		values = []pgproto.Column_Value{
			text_col("101"),
			text_col("bob"),
			text_col("bob@example.com"),
			text_col("30"),
			null_col(), // is_admin is NULL -> nil Maybe
			text_col("2024-03-15 10:00:00"),
			null_col(), // updated_at is NULL -> nil Maybe
			text_col("a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"),
			text_col("{\"dev\",\"admin\"}"),
			text_col("{10,20,30}"),
		},
	}

	u, err := map_row_to_struct(Test_Complex_User, desc, row)
	testing.expect_value(t, err, nil)
	testing.expect_value(t, u.id, i32(101))
	testing.expect_value(t, u.name, "bob")
	testing.expect_value(t, u.email.(string), "bob@example.com")
	testing.expect_value(t, u.age.(int), 30)
	testing.expect(t, u.is_admin == nil, "expected nil Maybe for is_admin")
	testing.expect(t, u.updated_at == nil, "expected nil Maybe for updated_at")

	cy, cm, cd := time.date(u.created_at)
	testing.expect_value(t, cy, 2024)
	testing.expect_value(t, int(cm), 3)
	testing.expect_value(t, cd, 15)

	expected_uuid := [16]u8{
		0xa0, 0xee, 0xbc, 0x99, 0x9c, 0x0b, 0x4e, 0xf8,
		0xbb, 0x6d, 0x6b, 0xb9, 0xbd, 0x38, 0x0a, 0x11,
	}
	testing.expect_value(t, u.avatar_uuid, expected_uuid)
	testing.expect_value(t, len(u.tags), 2)
	testing.expect_value(t, u.tags[0], "dev")
	testing.expect_value(t, u.tags[1], "admin")
	testing.expect_value(t, len(u.scores), 3)
	testing.expect_value(t, u.scores[0], i32(10))
	testing.expect_value(t, u.scores[1], i32(20))
	testing.expect_value(t, u.scores[2], i32(30))
}

@(test)
test_map_row_to_struct_pointers :: proc(t: ^testing.T) {
	desc := pgproto.Msg_Row_Description{
		fields = []pgproto.Field_Description{
			{name = "id"},
			{name = "bio"},
			{name = "coins"},
		},
	}
	row := pgproto.Msg_Data_Row{
		values = []pgproto.Column_Value{
			text_col("99"),
			text_col("odin developer"),
			null_col(),
		},
	}

	u, err := map_row_to_struct(Test_Pointer_User, desc, row)
	testing.expect_value(t, err, nil)
	testing.expect_value(t, u.id, i64(99))
	testing.expect(t, u.bio != nil, "expected non-nil bio pointer")
	if u.bio != nil {
		testing.expect_value(t, u.bio^, "odin developer")
	}
	testing.expect(t, u.coins == nil, "expected nil coins pointer on NULL")
}

@(test)
test_map_row_to_struct_nested_struct :: proc(t: ^testing.T) {
	desc := pgproto.Msg_Row_Description{
		fields = []pgproto.Field_Description{
			{name = "id"},
			{name = "name"},
			{name = "bio"},
			{name = "website"},
		},
	}
	row := pgproto.Msg_Data_Row{
		values = []pgproto.Column_Value{
			text_col("1"),
			text_col("carol"),
			text_col("software engineer"),
			text_col("https://odin-lang.org"),
		},
	}

	u, err := map_row_to_struct(Test_User_With_Profile, desc, row)
	testing.expect_value(t, err, nil)
	testing.expect_value(t, u.id, i64(1))
	testing.expect_value(t, u.name, "carol")
	testing.expect_value(t, u.profile.bio, "software engineer")
	testing.expect_value(t, u.profile.website, "https://odin-lang.org")
}

@(test)
test_map_row_to_struct_binary_format :: proc(t: ^testing.T) {
	desc := pgproto.Msg_Row_Description{
		fields = []pgproto.Field_Description{
			{name = "id", format_code = .Binary, type_oid = u32(OID_INT8)},
			{name = "name", format_code = .Binary, type_oid = u32(OID_TEXT)},
			{name = "points", format_code = .Binary, type_oid = u32(OID_FLOAT8)},
			{name = "active", format_code = .Binary, type_oid = u32(OID_BOOL)},
		},
	}

	id_buf := encode_binary_i64(123456)
	score_buf := encode_binary_f64(98.75)
	active_buf := encode_binary_bool(true)

	row := pgproto.Msg_Data_Row{
		values = []pgproto.Column_Value{
			bin_col(id_buf),
			text_col("dave"),
			bin_col(score_buf),
			bin_col(active_buf),
		},
	}

	u, err := map_row_to_struct(Test_User, desc, row)
	testing.expect_value(t, err, nil)
	testing.expect_value(t, u.id, i64(123456))
	testing.expect_value(t, u.name, "dave")
	testing.expect_value(t, u.score, 98.75)
	testing.expect_value(t, u.active, true)
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

Test_Numeric_And_Bytes :: struct {
	i8_val:   i8,
	i16_val:  i16,
	i32_val:  i32,
	i64_val:  i64,
	f32_val:  f32,
	f64_val:  f64,
	raw_data: []byte `db:"data"`,
}

@(test)
test_map_row_to_struct_numeric_and_bytea :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	tracked := mem.tracking_allocator(&track)

	desc := pgproto.Msg_Row_Description{
		fields = []pgproto.Field_Description{
			{name = "i8_val"},
			{name = "i16_val"},
			{name = "i32_val"},
			{name = "i64_val"},
			{name = "f32_val"},
			{name = "f64_val"},
			{name = "data"},
		},
	}
	row := pgproto.Msg_Data_Row{
		values = []pgproto.Column_Value{
			text_col("127"),
			text_col("32000"),
			text_col("100000"),
			text_col("5000000000"),
			text_col("1.25"),
			text_col("2.5"),
			text_col("\\xdeadbeef"),
		},
	}

	res, err := map_row_to_struct(Test_Numeric_And_Bytes, desc, row, tracked)
	testing.expect_value(t, err, nil)
	testing.expect_value(t, res.i8_val, i8(127))
	testing.expect_value(t, res.i16_val, i16(32000))
	testing.expect_value(t, res.i32_val, i32(100000))
	testing.expect_value(t, res.i64_val, i64(5000000000))
	testing.expect_value(t, res.f32_val, f32(1.25))
	testing.expect_value(t, res.f64_val, f64(2.5))
	testing.expect_value(t, len(res.raw_data), 4)
	testing.expect_value(t, res.raw_data[0], u8(0xde))
	testing.expect_value(t, res.raw_data[3], u8(0xef))

	delete(res.raw_data, tracked)
	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
test_map_rows_to_slice_tracking_allocator :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	tracked := mem.tracking_allocator(&track)

	desc := pgproto.Msg_Row_Description{
		fields = []pgproto.Field_Description{
			{name = "id"},
			{name = "name"},
		},
	}
	rows := []pgproto.Msg_Data_Row{
		{values = []pgproto.Column_Value{text_col("10"), text_col("item1")}},
		{values = []pgproto.Column_Value{text_col("20"), text_col("item2")}},
	}

	slice_res, err := map_rows_to_slice(Test_User, desc, rows, tracked)
	testing.expect_value(t, err, nil)
	testing.expect_value(t, len(slice_res), 2)
	testing.expect_value(t, slice_res[0].id, i64(10))
	testing.expect_value(t, slice_res[0].name, "item1")
	testing.expect_value(t, slice_res[1].id, i64(20))
	testing.expect_value(t, slice_res[1].name, "item2")

	for item in slice_res {
		delete(item.name, tracked)
	}
	delete(slice_res, tracked)

	testing.expect_value(t, len(track.allocation_map), 0)
}
