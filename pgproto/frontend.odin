package pgproto

Startup_Param :: struct {
	name:  string,
	value: string,
}

Msg_Startup :: struct {
	protocol_version: i32,
	params:           []Startup_Param,
}

Msg_SSL_Request :: struct {}

Msg_Cancel_Request :: struct {
	process_id: i32,
	secret_key: i32,
}

Msg_Password :: struct {
	password: string,
}

Msg_SASL_Initial_Response :: struct {
	mechanism: string,
	data:      []byte,
}

Msg_SASL_Response :: struct {
	data: []byte,
}

Msg_Query :: struct {
	query: string,
}

Msg_Terminate :: struct {}

Describe_Target :: enum u8 {
	Statement = 'S',
	Portal    = 'P',
}

Close_Target :: enum u8 {
	Statement = 'S',
	Portal    = 'P',
}

Msg_Parse :: struct {
	statement_name: string,
	query:          string,
	param_oids:     []u32,
}

Bind_Param :: struct {
	is_null: bool,
	value:   []byte,
}

Msg_Bind :: struct {
	portal_name:         string,
	statement_name:      string,
	param_format_codes:  []Field_Format,
	param_values:        []Bind_Param,
	result_format_codes: []Field_Format,
}

Msg_Describe :: struct {
	target_type: Describe_Target,
	name:        string,
}

Msg_Execute :: struct {
	portal_name: string,
	max_rows:    i32,
}

Msg_Sync :: struct {}
Msg_Flush :: struct {}

Msg_Close :: struct {
	target_type: Close_Target,
	name:        string,
}


encode_ssl_request :: proc(builder: ^[dynamic]byte) -> int {
	start_len := len(builder)
	pos := write_packet_header_untyped(builder)
	write_i32(builder, 80877103)
	finish_packet(builder, pos)
	return len(builder) - start_len
}

encode_cancel_request :: proc(builder: ^[dynamic]byte, pid: i32, secret_key: i32) -> int {
	start_len := len(builder)
	pos := write_packet_header_untyped(builder)
	write_i32(builder, 80877102)
	write_i32(builder, pid)
	write_i32(builder, secret_key)
	finish_packet(builder, pos)
	return len(builder) - start_len
}

encode_startup :: proc(builder: ^[dynamic]byte, msg: Msg_Startup) -> int {
	start_len := len(builder)
	pos := write_packet_header_untyped(builder)
	version := msg.protocol_version if msg.protocol_version != 0 else 196608
	write_i32(builder, version)
	for p in msg.params {
		write_string_nt(builder, p.name)
		write_string_nt(builder, p.value)
	}
	write_u8(builder, 0x00)
	finish_packet(builder, pos)
	return len(builder) - start_len
}

encode_password :: proc(builder: ^[dynamic]byte, password: string) -> int {
	start_len := len(builder)
	pos := write_packet_header(builder, 'p')
	write_string_nt(builder, password)
	finish_packet(builder, pos)
	return len(builder) - start_len
}

encode_sasl_initial_response :: proc(builder: ^[dynamic]byte, msg: Msg_SASL_Initial_Response) -> int {
	start_len := len(builder)
	pos := write_packet_header(builder, 'p')
	write_string_nt(builder, msg.mechanism)
	if msg.data != nil {
		write_i32(builder, i32(len(msg.data)))
		write_bytes(builder, msg.data)
	} else {
		write_i32(builder, -1)
	}
	finish_packet(builder, pos)
	return len(builder) - start_len
}

encode_sasl_response :: proc(builder: ^[dynamic]byte, data: []byte) -> int {
	start_len := len(builder)
	pos := write_packet_header(builder, 'p')
	write_bytes(builder, data)
	finish_packet(builder, pos)
	return len(builder) - start_len
}

encode_query :: proc(builder: ^[dynamic]byte, query: string) -> int {
	start_len := len(builder)
	pos := write_packet_header(builder, 'Q')
	write_string_nt(builder, query)
	finish_packet(builder, pos)
	return len(builder) - start_len
}

encode_terminate :: proc(builder: ^[dynamic]byte) -> int {
	start_len := len(builder)
	pos := write_packet_header(builder, 'X')
	finish_packet(builder, pos)
	return len(builder) - start_len
}

encode_parse :: proc(
	builder: ^[dynamic]byte,
	statement_name: string,
	query: string,
	param_oids: []u32 = nil,
) -> int {
	start_len := len(builder)
	pos := write_packet_header(builder, 'P')
	write_string_nt(builder, statement_name)
	write_string_nt(builder, query)
	write_i16(builder, i16(len(param_oids)))
	for oid in param_oids {
		write_u32(builder, oid)
	}
	finish_packet(builder, pos)
	return len(builder) - start_len
}

encode_bind :: proc(builder: ^[dynamic]byte, msg: Msg_Bind) -> int {
	start_len := len(builder)
	pos := write_packet_header(builder, 'B')
	write_string_nt(builder, msg.portal_name)
	write_string_nt(builder, msg.statement_name)

	write_i16(builder, i16(len(msg.param_format_codes)))
	for fc in msg.param_format_codes {
		write_i16(builder, i16(fc))
	}

	write_i16(builder, i16(len(msg.param_values)))
	for pv in msg.param_values {
		if pv.is_null {
			write_i32(builder, -1)
		} else {
			write_i32(builder, i32(len(pv.value)))
			write_bytes(builder, pv.value)
		}
	}

	write_i16(builder, i16(len(msg.result_format_codes)))
	for rfc in msg.result_format_codes {
		write_i16(builder, i16(rfc))
	}

	finish_packet(builder, pos)
	return len(builder) - start_len
}

encode_describe :: proc(
	builder: ^[dynamic]byte,
	target_type: Describe_Target,
	name: string = "",
) -> int {
	start_len := len(builder)
	pos := write_packet_header(builder, 'D')
	write_u8(builder, u8(target_type))
	write_string_nt(builder, name)
	finish_packet(builder, pos)
	return len(builder) - start_len
}

encode_execute :: proc(
	builder: ^[dynamic]byte,
	portal_name: string = "",
	max_rows: i32 = 0,
) -> int {
	start_len := len(builder)
	pos := write_packet_header(builder, 'E')
	write_string_nt(builder, portal_name)
	write_i32(builder, max_rows)
	finish_packet(builder, pos)
	return len(builder) - start_len
}

encode_sync :: proc(builder: ^[dynamic]byte) -> int {
	start_len := len(builder)
	pos := write_packet_header(builder, 'S')
	finish_packet(builder, pos)
	return len(builder) - start_len
}

encode_flush :: proc(builder: ^[dynamic]byte) -> int {
	start_len := len(builder)
	pos := write_packet_header(builder, 'H')
	finish_packet(builder, pos)
	return len(builder) - start_len
}

encode_close :: proc(
	builder: ^[dynamic]byte,
	target_type: Close_Target,
	name: string = "",
) -> int {
	start_len := len(builder)
	pos := write_packet_header(builder, 'C')
	write_u8(builder, u8(target_type))
	write_string_nt(builder, name)
	finish_packet(builder, pos)
	return len(builder) - start_len
}

