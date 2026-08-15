package pgproto

import "core:mem"
import "core:strings"
import "../pgerr"

// ----------------------------------------------------------------------------
// PostgreSQL Backend Message Identifiers (Protocol 3.0)
// ----------------------------------------------------------------------------

Backend_Message_Type :: enum u8 {
	Authentication         = 'R',
	Backend_Key_Data       = 'K',
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
// Backend Authentication & Handshake Payloads
// ----------------------------------------------------------------------------

Auth_Type :: enum i32 {
	Ok                 = 0,
	Kerberos_V5        = 2,
	Cleartext_Password = 3,
	MD5_Password       = 5,
	SCM_Credential     = 6,
	GSS                = 7,
	GSS_Continue       = 8,
	SSPI               = 9,
	SASL               = 10,
	SASL_Continue      = 11,
	SASL_Final         = 12,
}

Msg_Authentication :: struct {
	auth_type:  Auth_Type,
	salt:       [4]u8,    // Used when auth_type == .MD5_Password
	mechanisms: []string, // .SASL only: name views into the packet; slice allocated via allocator
	sasl_data:  string,   // SASL_Continue / SASL_Final / GSS_Continue: view into the packet
}

Msg_Backend_Key_Data :: struct {
	process_id: i32,
	secret_key: i32,
}

Msg_Parameter_Status :: struct {
	name:  string, // e.g., "server_version", "client_encoding"
	value: string, // e.g., "16.1", "UTF8"
}

/*
	parameter_status_clone deep-copies a Msg_Parameter_Status. Parsed messages
	borrow from the network read buffer; ParameterStatus values are typically
	stored for the connection lifetime, so clone them before the buffer is reused.
*/
parameter_status_clone :: proc(
	msg: Msg_Parameter_Status,
	allocator := context.allocator,
) -> (
	res: Msg_Parameter_Status,
	err: mem.Allocator_Error,
) {
	defer if err != nil {
		delete(res.name, allocator)
		res = {}
	}
	res.name = strings.clone(msg.name, allocator) or_return
	res.value = strings.clone(msg.value, allocator) or_return
	return res, nil
}

/*
	parameter_status_destroy frees strings previously cloned with parameter_status_clone.
*/
parameter_status_destroy :: proc(msg: Msg_Parameter_Status, allocator := context.allocator) {
	delete(msg.name, allocator)
	delete(msg.value, allocator)
}

Transaction_Status :: enum u8 {
	Idle               = 'I', // Not in a transaction block
	In_Transaction     = 'T', // In a transaction block
	Failed_Transaction = 'E', // In a failed transaction block (queries ignored until ROLLBACK)
}

Msg_Ready_For_Query :: struct {
	status: Transaction_Status,
}

// ----------------------------------------------------------------------------
// Query & Data Payloads
// ----------------------------------------------------------------------------

Msg_Command_Complete :: struct {
	tag: string, // e.g., "SELECT 1", "INSERT 0 1"
}

Msg_Empty_Query_Response :: struct {}

Field_Format :: enum i16 {
	Text   = 0,
	Binary = 1,
}

Field_Description :: struct {
	name:            string,       // Column name
	table_oid:       u32,          // If column belongs to table, table's OID, else 0
	column_attr_num: i16,          // Attribute number of column in table, else 0
	type_oid:        u32,          // Data type OID
	type_size:       i16,          // Data type size (negative if variable-length)
	type_modifier:   i32,          // Type modifier
	format_code:     Field_Format, // 0 = text, 1 = binary
}

Msg_Row_Description :: struct {
	fields: []Field_Description, // Slice allocated via allocator; field name strings are views into the packet
}

Column_Value :: struct {
	is_null: bool,
	data:    []byte, // View into the packet buffer
}

Msg_Data_Row :: struct {
	values: []Column_Value, // Slice allocated via allocator; column data are views into the packet
}

// ----------------------------------------------------------------------------
// Error, Notice & Notification Payloads
// ----------------------------------------------------------------------------

Msg_Error_Response :: struct {
	error: pgerr.Postgres_Error,
}

Msg_Notice_Response :: struct {
	error: pgerr.Postgres_Error,
}

Msg_Notification_Response :: struct {
	process_id: i32,
	channel:    string,
	payload:    string,
}

// ----------------------------------------------------------------------------
// Extended Query Protocol Signals & Descriptions
// ----------------------------------------------------------------------------

Msg_Parse_Complete :: struct {}

Msg_Bind_Complete :: struct {}

Msg_Close_Complete :: struct {}

Msg_No_Data :: struct {}

Msg_Portal_Suspended :: struct {}

Msg_Parameter_Description :: struct {
	param_oids: []u32, // Slice allocated via allocator
}

// ----------------------------------------------------------------------------
// COPY Protocol Payloads
// ----------------------------------------------------------------------------

Msg_Copy_In_Response :: struct {
	overall_format:      Field_Format,
	column_format_codes: []Field_Format, // Slice allocated via allocator
}

Msg_Copy_Out_Response :: struct {
	overall_format:      Field_Format,
	column_format_codes: []Field_Format, // Slice allocated via allocator
}

Msg_Copy_Both_Response :: struct {
	overall_format:      Field_Format,
	column_format_codes: []Field_Format, // Slice allocated via allocator
}

Msg_Copy_Data_Backend :: struct {
	data: []byte, // Slice into the packet
}

Msg_Copy_Done_Backend :: struct {}

// ----------------------------------------------------------------------------
// Miscellaneous Backend Payloads
// ----------------------------------------------------------------------------

Msg_Function_Call_Response :: struct {
	is_null: bool,
	data:    []byte, // Result byte slice (empty if is_null is true)
}

Msg_Negotiate_Protocol_Version :: struct {
	minor_version:        i32,
	unrecognized_options: []string, // Option string views into the packet; slice allocated via allocator
}

// ----------------------------------------------------------------------------
// Master Backend Message Tagged Union
// ----------------------------------------------------------------------------

/*
	ZERO-COPY CONTRACT: parsed messages BORROW from the input packet buffer.
	Every string and []byte field is a view into the `data` slice passed to
	parse_message; only container slices (fields, values, mechanisms, oids,
	format codes) are allocated via the provided allocator. Anything that must
	outlive the buffer (e.g. ParameterStatus, Postgres_Error) must be cloned —
	see parameter_status_clone and pgerr.postgres_error_clone.
*/
Backend_Message :: union {
	Msg_Authentication,
	Msg_Backend_Key_Data,
	Msg_Bind_Complete,
	Msg_Close_Complete,
	Msg_Command_Complete,
	Msg_Copy_Both_Response,
	Msg_Copy_Data_Backend,
	Msg_Copy_Done_Backend,
	Msg_Copy_In_Response,
	Msg_Copy_Out_Response,
	Msg_Data_Row,
	Msg_Empty_Query_Response,
	Msg_Error_Response,
	Msg_Function_Call_Response,
	Msg_Negotiate_Protocol_Version,
	Msg_No_Data,
	Msg_Notice_Response,
	Msg_Notification_Response,
	Msg_Parameter_Description,
	Msg_Parameter_Status,
	Msg_Parse_Complete,
	Msg_Portal_Suspended,
	Msg_Ready_For_Query,
	Msg_Row_Description,
}
