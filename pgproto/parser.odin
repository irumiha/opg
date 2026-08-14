package pgproto

import "core:encoding/endian"
import "core:mem"
import ".." // Imports root package for opg.Error types

// ----------------------------------------------------------------------------
// PostgreSQL Backend Message Identifiers (Protocol 3.0)
// ----------------------------------------------------------------------------

Backend_Message_Type :: enum u8 {
	Authentication         = 'R',
	Backend_Key_Data        = 'K',
	Bind_Complete          = '2',
	Close_Complete         = '3',
	Command_Complete       = 'C',
	Copy_Data              = 'd',
	Copy_Done              = 'c',
	Copy_In_Response       = 'G',
	Copy_Out_Response      = 'H',
	Copy_Both_Response     = 'W',
	Data_Row               = 'D',
	Empty_Query_Response   = 'I',
	Error_Response         = 'E',
	Function_Call_Response = 'V',
	Negotiate_Protocol_Ver = 'v',
	No_Data                = 'n',
	Notice_Response        = 'N',
	Notification_Response  = 'A',
	Parameter_Description  = 't',
	Parameter_Status       = 'S',
	Parse_Complete         = '1',
	Portal_Suspended       = 's',
	Ready_For_Query        = 'Z',
	Row_Description        = 'T',
}

// ----------------------------------------------------------------------------
// Backend Message Payloads
// ----------------------------------------------------------------------------

Auth_Type :: enum i32 {
	Ok                = 0,
	Kerberos_V5       = 2,
	Cleartext_Password = 3,
	MD5_Password      = 5,
	SCM_Credential    = 6,
	GSS               = 7,
	GSS_Continue      = 8,
	SSPI              = 9,
	SASL              = 10,
	SASL_Continue     = 11,
	SASL_Final        = 12,
}

Msg_Authentication :: struct {
	auth_type: Auth_Type,
	salt:      [4]u8,        // Used when auth_type == .MD5_Password
	mechanisms: []string,    // Used when auth_type == .SASL (allocated in temp_allocator)
	sasl_data: string,       // Used for SASL_Continue / SASL_Final
}

Msg_Backend_Key_Data :: struct {
	process_id: i32,
	secret_key: i32,
}

Msg_Command_Complete :: struct {
	tag: string, // e.g., "SELECT 1", "INSERT 0 1" (allocated in temp_allocator)
}

Transaction_Status :: enum u8 {
	Idle               = 'I', // Not in a transaction block
	In_Transaction     = 'T', // In a transaction block
	Failed_Transaction = 'E', // In a failed transaction block (queries ignored until ROLLBACK)
}

Msg_Ready_For_Query :: struct {
	status: Transaction_Status,
}

Field_Format :: enum i16 {
	Text   = 0,
	Binary = 1,
}

Field_Description :: struct {
	name:            string,       // Column name (allocated in temp_allocator)
	table_oid:       u32,          // If column belongs to table, table's OID, else 0
	column_attr_num: i16,          // Attribute number of column in table, else 0
	type_oid:        u32,          // Data type OID
	type_size:       i16,          // Data type size (negative if variable-length)
	type_modifier:   i32,          // Type modifier
	format_code:     Field_Format, // 0 = text, 1 = binary
}

Msg_Row_Description :: struct {
	fields: []Field_Description, // Slice allocated in temp_allocator
}

Column_Value :: struct {
	is_null: bool,
	data:    []byte, // Slice into the packet or copied via temp_allocator
}

Msg_Data_Row :: struct {
	values: []Column_Value, // Slice allocated in temp_allocator
}

Msg_Parameter_Status :: struct {
	name:  string, // e.g., "server_version", "client_encoding"
	value: string, // e.g., "16.1", "UTF8"
}

// Tagged union of all possible Backend Messages
Backend_Message :: union {
	Msg_Authentication,
	Msg_Backend_Key_Data,
	Msg_Command_Complete,
	Msg_Ready_For_Query,
	Msg_Row_Description,
	Msg_Data_Row,
	Msg_Parameter_Status,
	opg.Postgres_Error,
}

// ----------------------------------------------------------------------------
// Protocol Parser Stub
// ----------------------------------------------------------------------------

/*
	parse_message parses a single complete Postgres backend message from `data`.

	ARCHITECTURAL RULES:
	- Rule 1 (3-Layer Architecture): pgproto does NO socket or I/O operations. It only transforms []byte.
	- Rule 2 (Mandatory Big-Endian Byte Swapping): All header and payload integers (lengths, OIDs, counts)
	  MUST be parsed using `endian.get_i16(..., .Big)`, `endian.get_i32(..., .Big)`, etc. NEVER use raw transmute.
	- Rule 3 (Strict Allocator Boundaries): All dynamically allocated fields (strings, slices)
	  MUST use `allocator` which defaults to `context.temp_allocator`.
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

	// MANDATORY RULE 2: Explicit Big-Endian conversion using core:encoding/endian
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
		if len(payload) < 1 {
			return nil, 0, opg.Protocol_Error{
				type = .Malformed_Packet,
				message = "ReadyForQuery payload too short",
			}
		}
		status := Transaction_Status(payload[0])
		return Msg_Ready_For_Query{status = status}, total_msg_len, nil

	case .Backend_Key_Data:
		if len(payload) < 8 {
			return nil, 0, opg.Protocol_Error{
				type = .Malformed_Packet,
				message = "BackendKeyData payload too short",
			}
		}
		pid, _ := endian.get_i32(payload[0:4], .Big)
		key, _ := endian.get_i32(payload[4:8], .Big)
		return Msg_Backend_Key_Data{process_id = pid, secret_key = key}, total_msg_len, nil

	case .Authentication:
		if len(payload) < 4 {
			return nil, 0, opg.Protocol_Error{
				type = .Malformed_Packet,
				message = "Authentication payload too short",
			}
		}
		auth_code, _ := endian.get_i32(payload[0:4], .Big)
		auth_msg := Msg_Authentication{
			auth_type = Auth_Type(auth_code),
		}
		// Additional SASL / MD5 salt decoding goes here using allocator
		return auth_msg, total_msg_len, nil

	case .Command_Complete:
		// Null-terminated string tag (allocated via temp_allocator)
		tag_str := string(payload[:max(0, len(payload)-1)])
		return Msg_Command_Complete{tag = tag_str}, total_msg_len, nil

	case .Row_Description,
	     .Data_Row,
	     .Error_Response,
	     .Notice_Response,
	     .Parameter_Status,
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
		// Stubs for remaining backend messages - to be fully implemented with temp_allocator and endian decoding
		return nil, total_msg_len, nil
	}

	return nil, 0, opg.Protocol_Error{
		type = .Unknown_Message_Type,
		message = "Unrecognized backend message identifier",
		byte_offset = 0,
	}
}
