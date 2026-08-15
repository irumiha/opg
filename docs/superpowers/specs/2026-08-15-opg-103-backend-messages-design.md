# Design Document: [OPG-103] Backend Wire Messages Decoding (Server -> Client)

- **Date**: 2026-08-15
- **Task ID**: `OPG-103`
- **Layer**: `pgproto`
- **Package**: `package pgproto`
- **Files**:
  - `pgproto/backend.odin`
  - `pgproto/parser.odin`
  - `pgproto/backend_test.odin`
- **Status**: Approved

---

## 1. Overview & Objectives

PostgreSQL Frontend/Backend Protocol 3.0 sends framed, Big-Endian wire packets from the database server to the client. `OPG-103` provides comprehensive parsing of all backend message types from raw byte slices into typed Odin data structures.

### Key Goals:
1. **Full Protocol 3.0 Coverage**: Parsing for all authentication responses, session lifecycle packets, simple/extended query packets (`RowDescription`, `DataRow`, `CommandComplete`, `ReadyForQuery`), errors/notices (`ErrorResponse`, `NoticeResponse`), asynchronous notifications, COPY protocol, and completion signals.
2. **Zero Transient Heap Allocations**: Strings and raw byte payloads (`Column_Value.data`, `tag`, `name`, `value`, `channel`, etc.) are returned as zero-copy views directly referencing the packet buffer. Dynamic arrays (`[]Field_Description`, `[]Column_Value`, `[]u32`, `[]string`) use `allocator := context.temp_allocator`.
3. **Strict Bounds Checking & Protocol Safety**: Malformed or truncated packets return typed `opg.Protocol_Error` tagged variants (`Buffer_Underflow`, `Invalid_Length`, `Malformed_Packet`, `Unknown_Message_Type`) without runtime panics.
4. **Clean Layer Separation**: Message struct declarations and the `Backend_Message` union reside in `pgproto/backend.odin`, while parser procedures and `parse_message` reside in `pgproto/parser.odin`.

---

## 2. Architecture & Data Structures (`pgproto/backend.odin`)

### 2.1 Enums & Types

```odin
package pgproto

import ".." // opg root for Error types

Backend_Message_Type :: enum u8 {
	Authentication         = 'R',
	Backend_Key_Data       = 'K',
	Bind_Complete          = '2',
	Close_Complete         = '3',
	Command_Complete       = 'C',
	Copy_Both_Response     = 'W',
	Copy_Data              = 'd',
	Copy_Done              = 'c',
	Copy_In_Response       = 'G',
	Copy_Out_Response      = 'H',
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

Transaction_Status :: enum u8 {
	Idle               = 'I',
	In_Transaction     = 'T',
	Failed_Transaction = 'E',
}
```

### 2.2 Backend Message Structs

```odin
Msg_Authentication :: struct {
	auth_type:  Auth_Type,
	salt:       [4]u8,
	mechanisms: []string,
	sasl_data:  string,
}

Msg_Backend_Key_Data :: struct {
	process_id: i32,
	secret_key: i32,
}

Msg_Bind_Complete :: struct {}
Msg_Close_Complete :: struct {}
Msg_Parse_Complete :: struct {}
Msg_Empty_Query_Response :: struct {}
Msg_No_Data :: struct {}
Msg_Portal_Suspended :: struct {}

Msg_Command_Complete :: struct {
	tag: string,
}

Msg_Ready_For_Query :: struct {
	status: Transaction_Status,
}

Field_Description :: struct {
	name:            string,
	table_oid:       u32,
	column_attr_num: i16,
	type_oid:        u32,
	type_size:       i16,
	type_modifier:   i32,
	format_code:     Field_Format,
}

Msg_Row_Description :: struct {
	fields: []Field_Description,
}

Column_Value :: struct {
	is_null: bool,
	data:    []byte,
}

Msg_Data_Row :: struct {
	values: []Column_Value,
}

Msg_Parameter_Status :: struct {
	name:  string,
	value: string,
}

Msg_Parameter_Description :: struct {
	param_oids: []u32,
}

Msg_Notification_Response :: struct {
	process_id: i32,
	channel:    string,
	payload:    string,
}

Msg_Notice_Response :: struct {
	error: opg.Postgres_Error,
}

Msg_Copy_In_Response :: struct {
	overall_format:      Field_Format,
	column_format_codes: []Field_Format,
}

Msg_Copy_Out_Response :: struct {
	overall_format:      Field_Format,
	column_format_codes: []Field_Format,
}

Msg_Copy_Both_Response :: struct {
	overall_format:      Field_Format,
	column_format_codes: []Field_Format,
}

Msg_Copy_Data_Backend :: struct {
	data: []byte,
}

Msg_Copy_Done_Backend :: struct {}

Msg_Negotiate_Protocol_Version :: struct {
	minor_version:        i32,
	unrecognized_options: []string,
}

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
	opg.Postgres_Error,
}
```

---

## 3. Parser Specification (`pgproto/parser.odin`)

### 3.1 Main Parser Entrypoint

```odin
parse_message :: proc(
	data: []byte,
	allocator := context.temp_allocator,
) -> (
	msg: Backend_Message,
	bytes_consumed: int,
	err: opg.Error,
)
```

### 3.2 Header Validation & Framing
- `len(data) < 5`: Returns `Protocol_Error{type = .Buffer_Underflow}`.
- `payload_len_i32 < 4`: Returns `Protocol_Error{type = .Invalid_Length}`.
- `len(data) < 1 + payload_len_i32`: Returns `Protocol_Error{type = .Buffer_Underflow}`.
- `bytes_consumed = 1 + int(payload_len_i32)`.

### 3.3 Sub-Parsers
- `parse_authentication(payload: []byte, allocator: mem.Allocator) -> (Msg_Authentication, opg.Error)`
- `parse_row_description(payload: []byte, allocator: mem.Allocator) -> (Msg_Row_Description, opg.Error)`
- `parse_data_row(payload: []byte, allocator: mem.Allocator) -> (Msg_Data_Row, opg.Error)`
- `parse_error_or_notice_fields(payload: []byte) -> (opg.Postgres_Error, opg.Error)`
- `parse_parameter_description(payload: []byte, allocator: mem.Allocator) -> (Msg_Parameter_Description, opg.Error)`
- `parse_copy_response(payload: []byte, allocator: mem.Allocator) -> (format: Field_Format, col_formats: []Field_Format, err: opg.Error)`
- `parse_notification(payload: []byte) -> (Msg_Notification_Response, opg.Error)`

---

## 4. Verification Plan

1. **Golden Files**: Bit-accurate validation against `auth_ok.bin`, `backend_key_data.bin`, `ready_for_query_idle.bin`.
2. **Synthetic Tests**: Matrix of all 23 Backend_Message types and error fields.
3. **Malformed & Fuzz Vectors**: Truncated headers, underflow payloads, missing string null-terminators.
4. **Memory Verification**: `core:mem.Tracking_Allocator` verifying 0 memory leaks across all parser branches.
5. **Tooling Checks**: Passes `odin test pgproto -vet -strict-style` and `odin test pgproto -sanitize:address`.
