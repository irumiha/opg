package pgproto

import "core:encoding/endian"
import ".." // Imports root package for opg.Error types

// ----------------------------------------------------------------------------
// Sub-Parsers for Handshake & Lifecycle Messages
// ----------------------------------------------------------------------------

/*
	parse_authentication parses an Authentication ('R') message payload.
	Extracts auth_type, salt for MD5, mechanism lists for SASL, or data for SASL Continue/Final.
*/
parse_authentication :: proc(
	payload: []byte,
	allocator := context.temp_allocator,
) -> (
	msg: Msg_Authentication,
	err: opg.Error,
) {
	r: Reader
	reader_init(&r, payload)

	auth_code, ok := reader_read_i32(&r)
	if !ok {
		return {}, opg.Protocol_Error{
			type = .Malformed_Packet,
			message = "Authentication payload too short",
			byte_offset = 0,
		}
	}

	auth_type := Auth_Type(auth_code)
	msg.auth_type = auth_type

	switch auth_type {
	case .Ok, .Cleartext_Password, .Kerberos_V5, .SCM_Credential, .GSS, .SSPI:
		return msg, nil

	case .MD5_Password:
		salt_bytes, salt_ok := reader_read_bytes(&r, 4)
		if !salt_ok {
			return {}, opg.Protocol_Error{
				type = .Malformed_Packet,
				message = "MD5 Authentication missing 4-byte salt",
				byte_offset = r.offset,
			}
		}
		copy(msg.salt[:], salt_bytes)
		return msg, nil

	case .SASL:
		mechs := make([dynamic]string, allocator)
		for {
			if reader_remaining(&r) == 0 {
				break
			}
			if r.buf[r.offset] == 0x00 {
				r.offset += 1
				break
			}
			mech_str, str_ok := reader_read_string_nt(&r)
			if !str_ok {
				return {}, opg.Protocol_Error{
					type = .Malformed_Packet,
					message = "Unterminated SASL mechanism string",
					byte_offset = r.offset,
				}
			}
			append(&mechs, mech_str)
		}
		msg.mechanisms = mechs[:]
		return msg, nil

	case .SASL_Continue, .SASL_Final, .GSS_Continue:
		rem := reader_remaining(&r)
		rem_bytes, _ := reader_read_bytes(&r, rem)
		msg.sasl_data = string(rem_bytes)
		return msg, nil
	}

	return msg, nil
}

/*
	parse_backend_key_data parses a BackendKeyData ('K') message payload (process ID and secret key).
*/
parse_backend_key_data :: proc(payload: []byte) -> (msg: Msg_Backend_Key_Data, err: opg.Error) {
	r: Reader
	reader_init(&r, payload)

	pid, ok_pid := reader_read_i32(&r)
	secret, ok_secret := reader_read_i32(&r)
	if !ok_pid || !ok_secret {
		return {}, opg.Protocol_Error{
			type = .Malformed_Packet,
			message = "BackendKeyData payload too short",
			byte_offset = r.offset,
		}
	}
	return Msg_Backend_Key_Data{process_id = pid, secret_key = secret}, nil
}

/*
	parse_parameter_status parses a ParameterStatus ('S') message payload (name and value strings).
*/
parse_parameter_status :: proc(payload: []byte) -> (msg: Msg_Parameter_Status, err: opg.Error) {
	r: Reader
	reader_init(&r, payload)

	name, ok_name := reader_read_string_nt(&r)
	value, ok_value := reader_read_string_nt(&r)
	if !ok_name || !ok_value {
		return {}, opg.Protocol_Error{
			type = .Malformed_Packet,
			message = "Malformed ParameterStatus payload",
			byte_offset = r.offset,
		}
	}
	return Msg_Parameter_Status{name = name, value = value}, nil
}

/*
	parse_ready_for_query parses a ReadyForQuery ('Z') message payload (transaction status character).
*/
parse_ready_for_query :: proc(payload: []byte) -> (msg: Msg_Ready_For_Query, err: opg.Error) {
	r: Reader
	reader_init(&r, payload)

	status_byte, ok := reader_read_u8(&r)
	if !ok {
		return {}, opg.Protocol_Error{
			type = .Malformed_Packet,
			message = "ReadyForQuery payload too short",
			byte_offset = 0,
		}
	}
	status := Transaction_Status(status_byte)
	if status != .Idle && status != .In_Transaction && status != .Failed_Transaction {
		return {}, opg.Protocol_Error{
			type = .Malformed_Packet,
			message = "Invalid transaction status in ReadyForQuery",
			byte_offset = 0,
		}
	}
	return Msg_Ready_For_Query{status = status}, nil
}

/*
	parse_command_complete parses a CommandComplete ('C') message payload (tag string).
*/
parse_command_complete :: proc(payload: []byte) -> (msg: Msg_Command_Complete, err: opg.Error) {
	r: Reader
	reader_init(&r, payload)

	tag, ok := reader_read_string_nt(&r)
	if !ok {
		return {}, opg.Protocol_Error{
			type = .Malformed_Packet,
			message = "Malformed CommandComplete payload",
			byte_offset = 0,
		}
	}
	return Msg_Command_Complete{tag = tag}, nil
}

/*
	parse_row_description parses a RowDescription ('T') message payload.
	Allocates field description slice using allocator (defaults to context.temp_allocator).
*/
parse_row_description :: proc(
	payload: []byte,
	allocator := context.temp_allocator,
) -> (
	msg: Msg_Row_Description,
	err: opg.Error,
) {
	r: Reader
	reader_init(&r, payload)

	num_fields, ok_num := reader_read_i16(&r)
	if !ok_num {
		return {}, opg.Protocol_Error{
			type = .Malformed_Packet,
			message = "RowDescription payload too short",
			byte_offset = 0,
		}
	}
	if num_fields < 0 {
		return {}, opg.Protocol_Error{
			type = .Malformed_Packet,
			message = "Invalid negative field count in RowDescription",
			byte_offset = 0,
		}
	}
	if int(num_fields) * 18 > reader_remaining(&r) {
		return {}, opg.Protocol_Error{
			type = .Malformed_Packet,
			message = "RowDescription payload too short for field count",
			byte_offset = r.offset,
		}
	}

	fields := make([]Field_Description, int(num_fields), allocator)
	for i in 0 ..< int(num_fields) {
		name, ok_name := reader_read_string_nt(&r)
		table_oid, ok_toid := reader_read_u32(&r)
		col_attr, ok_attr := reader_read_i16(&r)
		type_oid, ok_type := reader_read_u32(&r)
		type_size, ok_tsize := reader_read_i16(&r)
		type_mod, ok_tmod := reader_read_i32(&r)
		fmt_code, ok_fmt := reader_read_i16(&r)

		if !ok_name || !ok_toid || !ok_attr || !ok_type || !ok_tsize || !ok_tmod || !ok_fmt {
			return {}, opg.Protocol_Error{
				type = .Malformed_Packet,
				message = "Truncated field description in RowDescription",
				byte_offset = r.offset,
			}
		}

		fields[i] = Field_Description{
			name            = name,
			table_oid       = table_oid,
			column_attr_num = col_attr,
			type_oid        = type_oid,
			type_size       = type_size,
			type_modifier   = type_mod,
			format_code     = Field_Format(fmt_code),
		}
	}

	msg.fields = fields
	return msg, nil
}

/*
	parse_data_row parses a DataRow ('D') message payload.
	Allocates column value slice using allocator (defaults to context.temp_allocator).
	Handles NULL column representation (length == -1 -> is_null: true, data: nil).
*/
parse_data_row :: proc(
	payload: []byte,
	allocator := context.temp_allocator,
) -> (
	msg: Msg_Data_Row,
	err: opg.Error,
) {
	r: Reader
	reader_init(&r, payload)

	num_cols, ok_num := reader_read_i16(&r)
	if !ok_num {
		return {}, opg.Protocol_Error{
			type = .Malformed_Packet,
			message = "DataRow payload too short",
			byte_offset = 0,
		}
	}
	if num_cols < 0 {
		return {}, opg.Protocol_Error{
			type = .Malformed_Packet,
			message = "Invalid negative column count in DataRow",
			byte_offset = 0,
		}
	}
	if int(num_cols) * 4 > reader_remaining(&r) {
		return {}, opg.Protocol_Error{
			type = .Malformed_Packet,
			message = "DataRow payload too short for column count",
			byte_offset = r.offset,
		}
	}

	values := make([]Column_Value, int(num_cols), allocator)
	for i in 0 ..< int(num_cols) {
		col_len, ok_len := reader_read_i32(&r)
		if !ok_len {
			return {}, opg.Protocol_Error{
				type = .Malformed_Packet,
				message = "Truncated column length in DataRow",
				byte_offset = r.offset,
			}
		}

		if col_len == -1 {
			values[i] = Column_Value{
				is_null = true,
				data    = nil,
			}
		} else if col_len < -1 {
			return {}, opg.Protocol_Error{
				type = .Malformed_Packet,
				message = "Invalid negative column length in DataRow",
				byte_offset = r.offset,
			}
		} else {
			col_data, ok_data := reader_read_bytes(&r, int(col_len))
			if !ok_data {
				return {}, opg.Protocol_Error{
					type = .Malformed_Packet,
					message = "Truncated column data in DataRow",
					byte_offset = r.offset,
				}
			}
			values[i] = Column_Value{
				is_null = false,
				data    = col_data,
			}
		}
	}

	msg.values = values
	return msg, nil
}

/*
	parse_error_or_notice_fields parses structured error/notice fields from ErrorResponse ('E')
	or NoticeResponse ('N') message payloads.
	Extracts zero-copy string fields for codes 'S', 'V', 'C', 'M', 'D', 'H', 'P', 'p', 'q',
	'W', 's', 't', 'c', 'd', 'n', 'F', 'L', 'R'.
	Unknown field codes are quietly ignored per PostgreSQL 3.0 protocol specification.
*/
parse_error_or_notice_fields :: proc(payload: []byte) -> (pg_err: opg.Postgres_Error, err: opg.Error) {
	if len(payload) == 0 {
		return {}, opg.Protocol_Error{
			type = .Malformed_Packet,
			message = "Error/Notice payload is empty",
			byte_offset = 0,
		}
	}

	r: Reader
	reader_init(&r, payload)

	for {
		code_byte, ok := reader_read_u8(&r)
		if !ok {
			return {}, opg.Protocol_Error{
				type = .Malformed_Packet,
				message = "Error/Notice packet missing terminating null byte",
				byte_offset = r.offset,
			}
		}

		if code_byte == 0x00 {
			// Terminating null byte reached
			return pg_err, nil
		}

		str_val, str_ok := reader_read_string_nt(&r)
		if !str_ok {
			return {}, opg.Protocol_Error{
				type = .Malformed_Packet,
				message = "Unterminated string in Error/Notice field",
				byte_offset = r.offset,
			}
		}

		switch code_byte {
		case 'S':
			pg_err.severity = str_val
		case 'V':
			pg_err.severity = str_val
		case 'C':
			pg_err.code = str_val
		case 'M':
			pg_err.message = str_val
		case 'D':
			pg_err.detail = str_val
		case 'H':
			pg_err.hint = str_val
		case 'P':
			pg_err.position = str_val
		case 'p':
			pg_err.internal_position = str_val
		case 'q':
			pg_err.internal_query = str_val
		case 'W':
			pg_err.where_context = str_val
		case 's':
			pg_err.schema_name = str_val
		case 't':
			pg_err.table_name = str_val
		case 'c':
			pg_err.column_name = str_val
		case 'd':
			pg_err.data_type_name = str_val
		case 'n':
			pg_err.constraint_name = str_val
		case 'F':
			pg_err.file = str_val
		case 'L':
			pg_err.line = str_val
		case 'R':
			pg_err.routine = str_val
		case:
			// Quietly ignore unrecognized field codes per Protocol 3.0 spec
		}
	}
}

/*
	parse_parameter_description parses a ParameterDescription ('t') message payload.
	Extracts parameter type OIDs into a slice allocated using allocator (defaults to context.temp_allocator).
*/
parse_parameter_description :: proc(
	payload: []byte,
	allocator := context.temp_allocator,
) -> (
	msg: Msg_Parameter_Description,
	err: opg.Error,
) {
	r: Reader
	reader_init(&r, payload)

	num_params, ok_num := reader_read_i16(&r)
	if !ok_num {
		return {}, opg.Protocol_Error{
			type = .Malformed_Packet,
			message = "ParameterDescription payload too short",
			byte_offset = 0,
		}
	}
	if num_params < 0 {
		return {}, opg.Protocol_Error{
			type = .Malformed_Packet,
			message = "Invalid negative parameter count in ParameterDescription",
			byte_offset = 0,
		}
	}
	if int(num_params) * 4 > reader_remaining(&r) {
		return {}, opg.Protocol_Error{
			type = .Malformed_Packet,
			message = "ParameterDescription payload too short for parameter count",
			byte_offset = r.offset,
		}
	}

	oids := make([]u32, int(num_params), allocator)
	for i in 0 ..< int(num_params) {
		oid, ok_oid := reader_read_u32(&r)
		if !ok_oid {
			return {}, opg.Protocol_Error{
				type = .Malformed_Packet,
				message = "Truncated parameter OID in ParameterDescription",
				byte_offset = r.offset,
			}
		}
		oids[i] = oid
	}

	msg.param_oids = oids
	return msg, nil
}

/*
	parse_notification parses a NotificationResponse ('A') message payload.
	Extracts process ID, channel name, and notification payload. Zero-copy string views.
*/
parse_notification :: proc(payload: []byte) -> (msg: Msg_Notification_Response, err: opg.Error) {
	r: Reader
	reader_init(&r, payload)

	pid, ok_pid := reader_read_i32(&r)
	if !ok_pid {
		return {}, opg.Protocol_Error{
			type = .Malformed_Packet,
			message = "NotificationResponse payload too short",
			byte_offset = 0,
		}
	}

	channel, ok_chan := reader_read_string_nt(&r)
	if !ok_chan {
		return {}, opg.Protocol_Error{
			type = .Malformed_Packet,
			message = "Unterminated channel string in NotificationResponse",
			byte_offset = r.offset,
		}
	}

	notif_payload, ok_payload := reader_read_string_nt(&r)
	if !ok_payload {
		return {}, opg.Protocol_Error{
			type = .Malformed_Packet,
			message = "Unterminated payload string in NotificationResponse",
			byte_offset = r.offset,
		}
	}

	return Msg_Notification_Response{
		process_id = pid,
		channel    = channel,
		payload    = notif_payload,
	}, nil
}

/*
	parse_copy_response parses CopyInResponse ('G'), CopyOutResponse ('H'), or CopyBothResponse ('W') payload.
	Returns overall format (Text/Binary) and a slice of column format codes allocated using allocator.
*/
parse_copy_response :: proc(
	payload: []byte,
	allocator := context.temp_allocator,
) -> (
	overall_format: Field_Format,
	column_format_codes: []Field_Format,
	err: opg.Error,
) {
	r: Reader
	reader_init(&r, payload)

	fmt_byte, ok_fmt := reader_read_u8(&r)
	if !ok_fmt {
		return .Text, nil, opg.Protocol_Error{
			type = .Malformed_Packet,
			message = "CopyResponse payload too short",
			byte_offset = 0,
		}
	}
	overall_format = Field_Format(fmt_byte)

	num_cols, ok_num := reader_read_i16(&r)
	if !ok_num {
		return .Text, nil, opg.Protocol_Error{
			type = .Malformed_Packet,
			message = "CopyResponse missing column count",
			byte_offset = r.offset,
		}
	}
	if num_cols < 0 {
		return .Text, nil, opg.Protocol_Error{
			type = .Malformed_Packet,
			message = "Invalid negative column count in CopyResponse",
			byte_offset = r.offset,
		}
	}
	if int(num_cols) * 2 > reader_remaining(&r) {
		return .Text, nil, opg.Protocol_Error{
			type = .Malformed_Packet,
			message = "CopyResponse payload too short for column format count",
			byte_offset = r.offset,
		}
	}

	col_fmts := make([]Field_Format, int(num_cols), allocator)
	for i in 0 ..< int(num_cols) {
		col_fmt, ok_col := reader_read_i16(&r)
		if !ok_col {
			return .Text, nil, opg.Protocol_Error{
				type = .Malformed_Packet,
				message = "Truncated column format code in CopyResponse",
				byte_offset = r.offset,
			}
		}
		col_fmts[i] = Field_Format(col_fmt)
	}

	return overall_format, col_fmts, nil
}

/*
	parse_function_call_response parses a FunctionCallResponse ('V') message payload.
	Handles NULL result (length == -1) and result byte slice.
*/
parse_function_call_response :: proc(payload: []byte) -> (msg: Msg_Function_Call_Response, err: opg.Error) {
	r: Reader
	reader_init(&r, payload)

	data_len, ok_len := reader_read_i32(&r)
	if !ok_len {
		return {}, opg.Protocol_Error{
			type = .Malformed_Packet,
			message = "FunctionCallResponse payload too short",
			byte_offset = 0,
		}
	}

	if data_len == -1 {
		msg.is_null = true
		return msg, nil
	}
	if data_len < -1 {
		return {}, opg.Protocol_Error{
			type = .Malformed_Packet,
			message = "Invalid negative result length in FunctionCallResponse",
			byte_offset = r.offset,
		}
	}

	data_bytes, ok_data := reader_read_bytes(&r, int(data_len))
	if !ok_data {
		return {}, opg.Protocol_Error{
			type = .Malformed_Packet,
			message = "Truncated result data in FunctionCallResponse",
			byte_offset = r.offset,
		}
	}

	msg.is_null = false
	msg.data = data_bytes
	return msg, nil
}

/*
	parse_negotiate_protocol_version parses a NegotiateProtocolVersion ('v') message payload.
	Extracts minor version and unrecognized options slice.
*/
parse_negotiate_protocol_version :: proc(
	payload: []byte,
	allocator := context.temp_allocator,
) -> (
	msg: Msg_Negotiate_Protocol_Version,
	err: opg.Error,
) {
	r: Reader
	reader_init(&r, payload)

	minor_ver, ok_ver := reader_read_i32(&r)
	num_opts, ok_opts := reader_read_i32(&r)
	if !ok_ver || !ok_opts {
		return {}, opg.Protocol_Error{
			type = .Malformed_Packet,
			message = "NegotiateProtocolVersion header too short",
			byte_offset = r.offset,
		}
	}
	if num_opts < 0 {
		return {}, opg.Protocol_Error{
			type = .Malformed_Packet,
			message = "Invalid negative options count in NegotiateProtocolVersion",
			byte_offset = r.offset,
		}
	}
	if int(num_opts) > reader_remaining(&r) {
		return {}, opg.Protocol_Error{
			type = .Malformed_Packet,
			message = "NegotiateProtocolVersion payload too short for options count",
			byte_offset = r.offset,
		}
	}

	opts := make([]string, int(num_opts), allocator)
	for i in 0 ..< int(num_opts) {
		opt_str, ok_str := reader_read_string_nt(&r)
		if !ok_str {
			return {}, opg.Protocol_Error{
				type = .Malformed_Packet,
				message = "Unterminated option string in NegotiateProtocolVersion",
				byte_offset = r.offset,
			}
		}
		opts[i] = opt_str
	}

	return Msg_Negotiate_Protocol_Version{
		minor_version        = minor_ver,
		unrecognized_options = opts,
	}, nil
}

// ----------------------------------------------------------------------------
// Main Message Parser
// ----------------------------------------------------------------------------

/*
	parse_message parses a single complete Postgres backend message from `data`.

	ARCHITECTURAL RULES:
	- Rule 1 (3-Layer Architecture): pgproto does NO socket or I/O operations. It only transforms []byte.
	- Rule 2 (Mandatory Big-Endian Byte Swapping): All header and payload integers (lengths, OIDs, counts)
	  MUST be parsed using `endian.get_i16(..., .Big)`, `endian.get_i32(..., .Big)`, or `Reader` primitives.
	  NEVER use raw transmute on numeric wire bytes.
	- Rule 3 (Strict Allocator Boundaries): All dynamically allocated fields (strings, slices)
	  MUST use `allocator` which defaults to `context.temp_allocator`. Zero-copy views for strings where applicable.
	- Rule 4 (Tagged Union Error Handling): Returns `opg.Error` on parse/protocol failures.
*/
parse_message :: proc(
	data: []byte,
	allocator := context.temp_allocator,
) -> (
	msg: Backend_Message,
	bytes_consumed: int,
	err: opg.Error,
) {
	// A standard Postgres backend packet starts with:
	// - 1 byte: Message type identifier (e.g. 'R', 'Z', 'D', 'T', 'E')
	// - 4 bytes: Big-Endian i32 packet length (includes the 4 length bytes, but NOT the 1 identifier byte)
	if len(data) < 5 {
		return nil, 0, opg.Protocol_Error{
			type = .Buffer_Underflow,
			message = "Header requires at least 5 bytes",
			byte_offset = 0,
		}
	}

	msg_type := Backend_Message_Type(data[0])

	// Explicit Big-Endian conversion using core:encoding/endian
	payload_len_i32, ok := endian.get_i32(data[1:5], .Big)
	if !ok || payload_len_i32 < 4 {
		return nil, 0, opg.Protocol_Error{
			type = .Invalid_Length,
			message = "Invalid message length in packet header",
			byte_offset = 1,
		}
	}

	total_msg_len := 1 + int(payload_len_i32)
	if len(data) < total_msg_len {
		return nil, 0, opg.Protocol_Error{
			type = .Buffer_Underflow,
			message = "Incomplete packet payload received",
			byte_offset = len(data),
		}
	}

	payload := data[5:total_msg_len]

	// Branch on message type and decode payload with temp_allocator and big-endian decoding
	switch msg_type {
	case .Ready_For_Query:
		rfq := parse_ready_for_query(payload) or_return
		return rfq, total_msg_len, nil

	case .Backend_Key_Data:
		key := parse_backend_key_data(payload) or_return
		return key, total_msg_len, nil

	case .Authentication:
		auth := parse_authentication(payload, allocator) or_return
		return auth, total_msg_len, nil

	case .Parameter_Status:
		param := parse_parameter_status(payload) or_return
		return param, total_msg_len, nil

	case .Command_Complete:
		cc := parse_command_complete(payload) or_return
		return cc, total_msg_len, nil

	case .Row_Description:
		rd := parse_row_description(payload, allocator) or_return
		return rd, total_msg_len, nil

	case .Data_Row:
		dr := parse_data_row(payload, allocator) or_return
		return dr, total_msg_len, nil

	case .Empty_Query_Response:
		return Msg_Empty_Query_Response{}, total_msg_len, nil

	case .Error_Response:
		err_resp := parse_error_or_notice_fields(payload) or_return
		return err_resp, total_msg_len, nil

	case .Notice_Response:
		notice_err := parse_error_or_notice_fields(payload) or_return
		return Msg_Notice_Response{error = notice_err}, total_msg_len, nil

	case .Parse_Complete:
		return Msg_Parse_Complete{}, total_msg_len, nil

	case .Bind_Complete:
		return Msg_Bind_Complete{}, total_msg_len, nil

	case .Close_Complete:
		return Msg_Close_Complete{}, total_msg_len, nil

	case .No_Data:
		return Msg_No_Data{}, total_msg_len, nil

	case .Portal_Suspended:
		return Msg_Portal_Suspended{}, total_msg_len, nil

	case .Parameter_Description:
		pd := parse_parameter_description(payload, allocator) or_return
		return pd, total_msg_len, nil

	case .Notification_Response:
		notif := parse_notification(payload) or_return
		return notif, total_msg_len, nil

	case .Copy_In_Response:
		fmt, cols := parse_copy_response(payload, allocator) or_return
		return Msg_Copy_In_Response{overall_format = fmt, column_format_codes = cols}, total_msg_len, nil

	case .Copy_Out_Response:
		fmt, cols := parse_copy_response(payload, allocator) or_return
		return Msg_Copy_Out_Response{overall_format = fmt, column_format_codes = cols}, total_msg_len, nil

	case .Copy_Both_Response:
		fmt, cols := parse_copy_response(payload, allocator) or_return
		return Msg_Copy_Both_Response{overall_format = fmt, column_format_codes = cols}, total_msg_len, nil

	case .Copy_Data:
		return Msg_Copy_Data_Backend{data = payload}, total_msg_len, nil

	case .Copy_Done:
		return Msg_Copy_Done_Backend{}, total_msg_len, nil

	case .Function_Call_Response:
		fcr := parse_function_call_response(payload) or_return
		return fcr, total_msg_len, nil

	case .Negotiate_Protocol_Ver:
		npv := parse_negotiate_protocol_version(payload, allocator) or_return
		return npv, total_msg_len, nil
	}

	return nil, 0, opg.Protocol_Error{
		type = .Unknown_Message_Type,
		message = "Unrecognized backend message identifier",
		byte_offset = 0,
	}
}

