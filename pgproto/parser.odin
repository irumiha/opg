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

	case .Row_Description,
	     .Data_Row,
	     .Error_Response,
	     .Notice_Response,
	     .Bind_Complete,
	     .Close_Complete,
	     .Copy_Data,
	     .Copy_Done,
	     .Copy_In_Response,
	     .Copy_Out_Response,
	     .Copy_Both_Response,
	     .Empty_Query_Response,
	     .Function_Call_Response,
	     .Negotiate_Protocol_Ver,
	     .No_Data,
	     .Notification_Response,
	     .Parameter_Description,
	     .Parse_Complete,
	     .Portal_Suspended:
		// Stubs for remaining backend messages - implemented in Tasks 2, 3, 4
		return nil, total_msg_len, nil
	}

	return nil, 0, opg.Protocol_Error{
		type = .Unknown_Message_Type,
		message = "Unrecognized backend message identifier",
		byte_offset = 0,
	}
}
