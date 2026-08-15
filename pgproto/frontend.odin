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

