# Design Document: [OPG-102] Frontend Wire Messages Encoding (Client -> Server)

- **Date**: 2026-08-15
- **Task ID**: `OPG-102`
- **Layer**: `pgproto`
- **Package**: `package pgproto`
- **Files**:
  - `pgproto/frontend.odin`
  - `pgproto/frontend_test.odin`
- **Status**: Approved

---

## 1. Overview & Objectives

PostgreSQL Frontend/Backend Protocol 3.0 requires the client (frontend) to send framed, Big-Endian wire packets to the database server. `OPG-102` implements the complete serialization layer for all client-to-server messages.

### Key Goals:
1. **Full Protocol 3.0 Message Coverage**: Support for all startup, authentication, simple query, extended query (Parse/Bind/Describe/Execute/Sync), COPY, and cancellation messages.
2. **Zero Transient Allocations**: All encoders append directly to a dynamic byte buffer (`^[dynamic]byte`) using the Big-Endian framing primitives in `pgproto/buffer.odin`.
3. **Pipelining Friendly**: Multiple messages (e.g. `Parse` + `Bind` + `Describe` + `Execute` + `Sync`) can be encoded consecutively into a single socket write buffer without intermediate allocations.
4. **Strong Typing & Tagged Union**: Clean message struct definitions and a unified `Frontend_Message` union.

---

## 2. Architecture & Data Structures (`pgproto/frontend.odin`)

### 2.1 Identifiers & Enums

```odin
package pgproto

Frontend_Message_Type :: enum u8 {
	Bind                  = 'B',
	Close                 = 'C',
	Copy_Data             = 'd',
	Copy_Done             = 'c',
	Copy_Fail             = 'f',
	Describe              = 'D',
	Execute               = 'E',
	Flush                 = 'H',
	Function_Call         = 'F',
	GSS_Response          = 'p',
	Parse                 = 'P',
	Password_Message      = 'p',
	Query                 = 'Q',
	SASL_Initial_Response = 'p',
	SASL_Response         = 'p',
	Sync                  = 'S',
	Terminate             = 'X',
}

Describe_Target :: enum u8 {
	Statement = 'S',
	Portal    = 'P',
}

Close_Target :: enum u8 {
	Statement = 'S',
	Portal    = 'P',
}
```

### 2.2 Message Structs

```odin
Startup_Param :: struct {
	name:  string,
	value: string,
}

Msg_Startup :: struct {
	protocol_version: i32, // Default 196608 (3.0)
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
	data:      []byte, // nil if no initial response
}

Msg_SASL_Response :: struct {
	data: []byte,
}

Msg_Query :: struct {
	query: string,
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
	param_format_codes:  []Field_Format, // 0=Text, 1=Binary (empty = text for all)
	param_values:        []Bind_Param,
	result_format_codes: []Field_Format, // empty = all text, 1 item = all columns, or per-column
}

Msg_Describe :: struct {
	target_type: Describe_Target,
	name:        string,
}

Msg_Execute :: struct {
	portal_name: string,
	max_rows:    i32, // 0 = all
}

Msg_Sync :: struct {}
Msg_Flush :: struct {}

Msg_Close :: struct {
	target_type: Close_Target,
	name:        string,
}

Msg_Terminate :: struct {}

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
```

---

## 3. Encoding Procedures Specification

### 3.1 Procedural Helpers

```odin
// Startup & Cancellation (Untyped Packets)
encode_startup :: proc(builder: ^[dynamic]byte, msg: Msg_Startup) -> int
encode_ssl_request :: proc(builder: ^[dynamic]byte) -> int
encode_cancel_request :: proc(builder: ^[dynamic]byte, pid: i32, secret_key: i32) -> int

// Authentication
encode_password :: proc(builder: ^[dynamic]byte, password: string) -> int
encode_sasl_initial_response :: proc(builder: ^[dynamic]byte, msg: Msg_SASL_Initial_Response) -> int
encode_sasl_response :: proc(builder: ^[dynamic]byte, data: []byte) -> int

// Simple Query
encode_query :: proc(builder: ^[dynamic]byte, query: string) -> int

// Extended Query Protocol
encode_parse :: proc(builder: ^[dynamic]byte, statement_name: string, query: string, param_oids: []u32 = nil) -> int
encode_bind :: proc(builder: ^[dynamic]byte, msg: Msg_Bind) -> int
encode_describe :: proc(builder: ^[dynamic]byte, target_type: Describe_Target, name: string = "") -> int
encode_execute :: proc(builder: ^[dynamic]byte, portal_name: string = "", max_rows: i32 = 0) -> int
encode_sync :: proc(builder: ^[dynamic]byte) -> int
encode_flush :: proc(builder: ^[dynamic]byte) -> int
encode_close :: proc(builder: ^[dynamic]byte, target_type: Close_Target, name: string = "") -> int

// Termination
encode_terminate :: proc(builder: ^[dynamic]byte) -> int

// COPY Protocol
encode_copy_data :: proc(builder: ^[dynamic]byte, data: []byte) -> int
encode_copy_done :: proc(builder: ^[dynamic]byte) -> int
encode_copy_fail :: proc(builder: ^[dynamic]byte, message: string) -> int

// Master Dispatcher
encode_frontend_message :: proc(builder: ^[dynamic]byte, msg: Frontend_Message) -> int
```

---

## 4. Exact Packet Formats

1. **`StartupMessage`**: `[4-byte len][4-byte ver = 196608][(name\0, val\0)...][\0]`
2. **`SSLRequest`**: `[4-byte len = 8][4-byte code = 80877103]`
3. **`CancelRequest`**: `[4-byte len = 16][4-byte code = 80877102][4-byte pid][4-byte key]`
4. **`PasswordMessage` ('p')**: `['p'][4-byte len][password\0]`
5. **`SASLInitialResponse` ('p')**: `['p'][4-byte len][mechanism\0][4-byte data_len (-1 if nil)][data]`
6. **`SASLResponse` ('p')**: `['p'][4-byte len][data]`
7. **`Query` ('Q')**: `['Q'][4-byte len][query\0]`
8. **`Parse` ('P')**: `['P'][4-byte len][stmt\0][query\0][2-byte num_oids][oids...]`
9. **`Bind` ('B')**: `['B'][4-byte len][portal\0][stmt\0][2-byte num_formats][formats...][2-byte num_values][(4-byte len (-1 for null), data)...][2-byte num_result_formats][result_formats...]`
10. **`Describe` ('D')**: `['D'][4-byte len][1-byte 'S'|'P'][name\0]`
11. **`Execute` ('E')**: `['E'][4-byte len][portal\0][4-byte max_rows]`
12. **`Sync` ('S')**: `['S'][4-byte len = 4]`
13. **`Flush` ('H')**: `['H'][4-byte len = 4]`
14. **`Close` ('C')**: `['C'][4-byte len][1-byte 'S'|'P'][name\0]`
15. **`Terminate` ('X')**: `['X'][4-byte len = 4]`
16. **`CopyData` ('d')**: `['d'][4-byte len][data]`
17. **`CopyDone` ('c')**: `['c'][4-byte len = 4]`
18. **`CopyFail` ('f')**: `['f'][4-byte len][message\0]`

---

## 5. Verification & Test Plan

Unit test suite in `pgproto/frontend_test.odin` will verify:
1. Bit-for-bit comparison against known golden vectors for every message variant.
2. Round-trip validation using `pgproto.Reader` to verify symmetrical decoding.
3. Extended Query pipelining (`Parse` + `Bind` + `Describe` + `Execute` + `Sync` in a single buffer).
4. Full memory tracking asserting zero leaks with `core:mem.Tracking_Allocator`.
5. Code checks: `odin test pgproto -vet -strict-style` and `odin test pgproto -sanitize:address`.
