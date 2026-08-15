package pgproto

import "../pgerr"

// PostgreSQL Frontend/Backend Protocol 3.0 magic numbers.
PROTOCOL_VERSION_3_0 :: 196608 // 3 << 16
SSL_REQUEST_CODE :: 80877103 // 1234 << 16 | 5679
CANCEL_REQUEST_CODE :: 80877102 // 1234 << 16 | 5678

// Wire counts in Parse/Bind are 16-bit; PostgreSQL's own limit is 65535.
MAX_MESSAGE_FIELD_COUNT :: 65535

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

// Target of a Describe ('D') or Close ('C') message.
Target_Kind :: enum u8 {
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
	target_type: Target_Kind,
	name:        string,
}

Msg_Execute :: struct {
	portal_name: string,
	max_rows:    i32,
}

Msg_Sync :: struct {}
Msg_Flush :: struct {}

Msg_Close :: struct {
	target_type: Target_Kind,
	name:        string,
}

Msg_Copy_Data :: struct {
	data: []byte,
}

Msg_Copy_Done :: struct {}

Msg_Copy_Fail :: struct {
	message: string,
}

Frontend_Message :: union {
	Msg_Startup,
	Msg_SSL_Request,
	Msg_Cancel_Request,
	Msg_Password,
	Msg_SASL_Initial_Response,
	Msg_SASL_Response,
	Msg_Query,
	Msg_Parse,
	Msg_Bind,
	Msg_Describe,
	Msg_Execute,
	Msg_Sync,
	Msg_Flush,
	Msg_Close,
	Msg_Terminate,
	Msg_Copy_Data,
	Msg_Copy_Done,
	Msg_Copy_Fail,
}


encode_ssl_request :: proc(builder: ^[dynamic]byte) -> int {
	start_len := len(builder)
	pos := write_packet_header_untyped(builder)
	write_i32(builder, SSL_REQUEST_CODE)
	finish_packet(builder, pos)
	return len(builder) - start_len
}

encode_cancel_request :: proc(builder: ^[dynamic]byte, pid: i32, secret_key: i32) -> int {
	start_len := len(builder)
	pos := write_packet_header_untyped(builder)
	write_i32(builder, CANCEL_REQUEST_CODE)
	write_i32(builder, pid)
	write_i32(builder, secret_key)
	finish_packet(builder, pos)
	return len(builder) - start_len
}

encode_startup :: proc(builder: ^[dynamic]byte, msg: Msg_Startup) -> int {
	start_len := len(builder)
	pos := write_packet_header_untyped(builder)
	version := msg.protocol_version if msg.protocol_version != 0 else PROTOCOL_VERSION_3_0
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
) -> (
	bytes_written: int,
	err: pgerr.Error,
) {
	if len(param_oids) > MAX_MESSAGE_FIELD_COUNT {
		return 0, pgerr.Protocol_Error{
			type = .Invalid_Length,
			message = "Parse parameter OID count exceeds 65535",
		}
	}
	start_len := len(builder)
	pos := write_packet_header(builder, 'P')
	write_string_nt(builder, statement_name)
	write_string_nt(builder, query)
	write_u16(builder, u16(len(param_oids)))
	for oid in param_oids {
		write_u32(builder, oid)
	}
	finish_packet(builder, pos)
	return len(builder) - start_len, nil
}

encode_bind :: proc(builder: ^[dynamic]byte, msg: Msg_Bind) -> (bytes_written: int, err: pgerr.Error) {
	if len(msg.param_format_codes) > MAX_MESSAGE_FIELD_COUNT {
		return 0, pgerr.Protocol_Error{
			type = .Invalid_Length,
			message = "Bind format code count exceeds 65535",
		}
	}
	if len(msg.param_values) > MAX_MESSAGE_FIELD_COUNT {
		return 0, pgerr.Protocol_Error{
			type = .Invalid_Length,
			message = "Bind parameter count exceeds 65535",
		}
	}
	if len(msg.result_format_codes) > MAX_MESSAGE_FIELD_COUNT {
		return 0, pgerr.Protocol_Error{
			type = .Invalid_Length,
			message = "Bind result format code count exceeds 65535",
		}
	}

	start_len := len(builder)
	pos := write_packet_header(builder, 'B')
	write_string_nt(builder, msg.portal_name)
	write_string_nt(builder, msg.statement_name)

	write_u16(builder, u16(len(msg.param_format_codes)))
	for fc in msg.param_format_codes {
		write_i16(builder, i16(fc))
	}

	write_u16(builder, u16(len(msg.param_values)))
	for pv in msg.param_values {
		if pv.is_null {
			write_i32(builder, -1)
		} else {
			if len(pv.value) > int(max(i32)) {
				return 0, pgerr.Protocol_Error{
					type = .Invalid_Length,
					message = "Parameter value length exceeds maximum 32-bit integer size",
				}
			}
			write_i32(builder, i32(len(pv.value)))
			write_bytes(builder, pv.value)
		}
	}

	write_u16(builder, u16(len(msg.result_format_codes)))
	for rfc in msg.result_format_codes {
		write_i16(builder, i16(rfc))
	}

	finish_packet(builder, pos)
	return len(builder) - start_len, nil
}

encode_describe :: proc(
	builder: ^[dynamic]byte,
	target_type: Target_Kind,
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
	target_type: Target_Kind,
	name: string = "",
) -> int {
	start_len := len(builder)
	pos := write_packet_header(builder, 'C')
	write_u8(builder, u8(target_type))
	write_string_nt(builder, name)
	finish_packet(builder, pos)
	return len(builder) - start_len
}

encode_copy_data :: proc(builder: ^[dynamic]byte, data: []byte) -> int {
	start_len := len(builder)
	pos := write_packet_header(builder, 'd')
	write_bytes(builder, data)
	finish_packet(builder, pos)
	return len(builder) - start_len
}

encode_copy_done :: proc(builder: ^[dynamic]byte) -> int {
	start_len := len(builder)
	pos := write_packet_header(builder, 'c')
	finish_packet(builder, pos)
	return len(builder) - start_len
}

encode_copy_fail :: proc(builder: ^[dynamic]byte, message: string) -> int {
	start_len := len(builder)
	pos := write_packet_header(builder, 'f')
	write_string_nt(builder, message)
	finish_packet(builder, pos)
	return len(builder) - start_len
}

encode_frontend_message :: proc(
	builder: ^[dynamic]byte,
	msg: Frontend_Message,
) -> (
	bytes_written: int,
	err: pgerr.Error,
) {
	switch m in msg {
	case Msg_Startup:
		return encode_startup(builder, m), nil
	case Msg_SSL_Request:
		return encode_ssl_request(builder), nil
	case Msg_Cancel_Request:
		return encode_cancel_request(builder, m.process_id, m.secret_key), nil
	case Msg_Password:
		return encode_password(builder, m.password), nil
	case Msg_SASL_Initial_Response:
		return encode_sasl_initial_response(builder, m), nil
	case Msg_SASL_Response:
		return encode_sasl_response(builder, m.data), nil
	case Msg_Query:
		return encode_query(builder, m.query), nil
	case Msg_Parse:
		return encode_parse(builder, m.statement_name, m.query, m.param_oids)
	case Msg_Bind:
		return encode_bind(builder, m)
	case Msg_Describe:
		return encode_describe(builder, m.target_type, m.name), nil
	case Msg_Execute:
		return encode_execute(builder, m.portal_name, m.max_rows), nil
	case Msg_Sync:
		return encode_sync(builder), nil
	case Msg_Flush:
		return encode_flush(builder), nil
	case Msg_Close:
		return encode_close(builder, m.target_type, m.name), nil
	case Msg_Terminate:
		return encode_terminate(builder), nil
	case Msg_Copy_Data:
		return encode_copy_data(builder, m.data), nil
	case Msg_Copy_Done:
		return encode_copy_done(builder), nil
	case Msg_Copy_Fail:
		return encode_copy_fail(builder, m.message), nil
	}
	return 0, nil
}


