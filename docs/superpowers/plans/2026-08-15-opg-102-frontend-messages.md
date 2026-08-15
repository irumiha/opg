# [OPG-102] Frontend Wire Messages Encoding Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement zero-allocation PostgreSQL Protocol 3.0 frontend message encoders and structured message types in `pgproto`.

**Architecture:** Typed message structs and tagged union `Frontend_Message` with buffer-appending encoder procedures that serialize messages into big-endian network packets using framing helpers from `pgproto/buffer.odin`.

**Tech Stack:** Odin, `core:encoding/endian`, `core:mem`, `core:testing`.

## Global Constraints

- **Strict Adherence**: Follow Odin idioms (tabs for indentation, Pascal_Case types, snake_case procs).
- **Network Byte Order (Big-Endian)**: Multi-byte integers must strictly use `core:encoding/endian` / `pgproto/buffer.odin` primitives. Raw transmute on numeric wire bytes is strictly forbidden.
- **Zero Heap Allocations**: All encoders append directly into a caller-supplied dynamic byte buffer (`^[dynamic]byte`).
- **Framing Accuracy**: Length prefixes must accurately include their own 4 bytes.
- **Quality Gates**: Must pass `odin test pgproto -vet -strict-style` and `odin test pgproto -sanitize:address` with 0 memory leaks tracked by `core:mem.Tracking_Allocator`.

---

### Task 1: Struct Definitions & Handshake Encoders

**Files:**
- Create: `pgproto/frontend.odin`
- Create: `pgproto/frontend_test.odin`

**Interfaces:**
- Produces:
  ```odin
  Startup_Param :: struct { name: string, value: string }
  Msg_Startup :: struct { protocol_version: i32, params: []Startup_Param }
  Msg_SSL_Request :: struct {}
  Msg_Cancel_Request :: struct { process_id: i32, secret_key: i32 }
  Msg_Password :: struct { password: string }
  Msg_SASL_Initial_Response :: struct { mechanism: string, data: []byte }
  Msg_SASL_Response :: struct { data: []byte }

  encode_startup :: proc(builder: ^[dynamic]byte, msg: Msg_Startup) -> int
  encode_ssl_request :: proc(builder: ^[dynamic]byte) -> int
  encode_cancel_request :: proc(builder: ^[dynamic]byte, pid: i32, secret_key: i32) -> int
  encode_password :: proc(builder: ^[dynamic]byte, password: string) -> int
  encode_sasl_initial_response :: proc(builder: ^[dynamic]byte, msg: Msg_SASL_Initial_Response) -> int
  encode_sasl_response :: proc(builder: ^[dynamic]byte, data: []byte) -> int
  ```

- [ ] **Step 1: Write failing tests for handshake encoders**

```odin
// pgproto/frontend_test.odin
package pgproto

import "core:mem"
import "core:testing"

@(test)
test_encode_handshake_messages :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	buf: [dynamic]byte
	defer delete(buf)

	// 1. SSLRequest
	ssl_len := encode_ssl_request(&buf)
	testing.expect_value(t, ssl_len, 8)
	testing.expect_value(t, len(buf), 8)
	expected_ssl := []byte{0x00, 0x00, 0x00, 0x08, 0x04, 0xD2, 0x16, 0x2F}
	for i in 0 ..< 8 {
		testing.expect_value(t, buf[i], expected_ssl[i])
	}

	// 2. CancelRequest
	clear(&buf)
	cancel_len := encode_cancel_request(&buf, 1234, 5678)
	testing.expect_value(t, cancel_len, 16)
	testing.expect_value(t, len(buf), 16)
	r: Reader
	reader_init(&r, buf[:])
	c_len, _ := reader_read_i32(&r)
	c_code, _ := reader_read_i32(&r)
	c_pid, _ := reader_read_i32(&r)
	c_key, _ := reader_read_i32(&r)
	testing.expect_value(t, c_len, 16)
	testing.expect_value(t, c_code, i32(80877102))
	testing.expect_value(t, c_pid, 1234)
	testing.expect_value(t, c_key, 5678)

	// 3. StartupMessage
	clear(&buf)
	startup := Msg_Startup{
		protocol_version = 196608,
		params = []Startup_Param{
			{name = "user", value = "postgres"},
			{name = "database", value = "app_db"},
		},
	}
	s_len := encode_startup(&buf, startup)
	testing.expect_value(t, s_len, len(buf))
	reader_init(&r, buf[:])
	dec_len, _ := reader_read_i32(&r)
	dec_ver, _ := reader_read_i32(&r)
	p1_k, _ := reader_read_string_nt(&r)
	p1_v, _ := reader_read_string_nt(&r)
	p2_k, _ := reader_read_string_nt(&r)
	p2_v, _ := reader_read_string_nt(&r)
	term, _ := reader_read_u8(&r)
	testing.expect_value(t, dec_len, i32(len(buf)))
	testing.expect_value(t, dec_ver, 196608)
	testing.expect_value(t, p1_k, "user")
	testing.expect_value(t, p1_v, "postgres")
	testing.expect_value(t, p2_k, "database")
	testing.expect_value(t, p2_v, "app_db")
	testing.expect_value(t, term, u8(0x00))

	// 4. PasswordMessage
	clear(&buf)
	p_len := encode_password(&buf, "secret")
	testing.expect_value(t, p_len, len(buf))
	reader_init(&r, buf[:])
	p_type, _ := reader_read_u8(&r)
	p_pkt_len, _ := reader_read_i32(&r)
	p_pwd, _ := reader_read_string_nt(&r)
	testing.expect_value(t, p_type, u8('p'))
	testing.expect_value(t, p_pkt_len, 4 + 7) // 4 + len("secret\0")
	testing.expect_value(t, p_pwd, "secret")

	// 5. SASLInitialResponse
	clear(&buf)
	sasl_init := Msg_SASL_Initial_Response{
		mechanism = "SCRAM-SHA-256",
		data = []byte("n,,n=user,r=nonce"),
	}
	sasl_len := encode_sasl_initial_response(&buf, sasl_init)
	testing.expect_value(t, sasl_len, len(buf))
	reader_init(&r, buf[:])
	s_type, _ := reader_read_u8(&r)
	s_pkt_len, _ := reader_read_i32(&r)
	s_mech, _ := reader_read_string_nt(&r)
	s_data_len, _ := reader_read_i32(&r)
	s_data, _ := reader_read_bytes(&r, int(s_data_len))
	testing.expect_value(t, s_type, u8('p'))
	testing.expect_value(t, s_mech, "SCRAM-SHA-256")
	testing.expect_value(t, s_data_len, i32(len("n,,n=user,r=nonce")))
	testing.expect_value(t, string(s_data), "n,,n=user,r=nonce")

	// 6. SASLResponse
	clear(&buf)
	sasl_resp_len := encode_sasl_response(&buf, []byte("c=biws,r=nonce,p=proof"))
	testing.expect_value(t, sasl_resp_len, len(buf))
	reader_init(&r, buf[:])
	sr_type, _ := reader_read_u8(&r)
	sr_pkt_len, _ := reader_read_i32(&r)
	sr_data, _ := reader_read_bytes(&r, int(sr_pkt_len - 4))
	testing.expect_value(t, sr_type, u8('p'))
	testing.expect_value(t, string(sr_data), "c=biws,r=nonce,p=proof")

	testing.expect_value(t, len(track.allocation_map), 0)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `odin test pgproto`
Expected: FAIL with undefined identifiers (`encode_ssl_request`, `Msg_Startup`, etc.)

- [ ] **Step 3: Implement handshake encoders in `pgproto/frontend.odin`**

```odin
// pgproto/frontend.odin
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `odin test pgproto`
Expected: PASS

- [ ] **Step 5: Commit Task 1**

```bash
git add pgproto/frontend.odin pgproto/frontend_test.odin
git commit -m "feat(pgproto): implement frontend handshake encoders"
```

---

### Task 2: Simple Query & Termination Encoders

**Files:**
- Modify: `pgproto/frontend.odin`
- Modify: `pgproto/frontend_test.odin`

**Interfaces:**
- Produces:
  ```odin
  Msg_Query :: struct { query: string }
  Msg_Terminate :: struct {}

  encode_query :: proc(builder: ^[dynamic]byte, query: string) -> int
  encode_terminate :: proc(builder: ^[dynamic]byte) -> int
  ```

- [ ] **Step 1: Write failing tests for Query and Terminate**

```odin
// In pgproto/frontend_test.odin
@(test)
test_encode_query_and_terminate :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	buf: [dynamic]byte
	defer delete(buf)

	// 1. Query
	q_len := encode_query(&buf, "SELECT 1;")
	testing.expect_value(t, q_len, len(buf))
	r: Reader
	reader_init(&r, buf[:])
	q_type, _ := reader_read_u8(&r)
	q_pkt_len, _ := reader_read_i32(&r)
	q_str, _ := reader_read_string_nt(&r)
	testing.expect_value(t, q_type, u8('Q'))
	testing.expect_value(t, q_pkt_len, 4 + 10) // 4 + len("SELECT 1;\0")
	testing.expect_value(t, q_str, "SELECT 1;")

	// 2. Terminate
	clear(&buf)
	term_len := encode_terminate(&buf)
	testing.expect_value(t, term_len, 5)
	testing.expect_value(t, len(buf), 5)
	reader_init(&r, buf[:])
	t_type, _ := reader_read_u8(&r)
	t_pkt_len, _ := reader_read_i32(&r)
	testing.expect_value(t, t_type, u8('X'))
	testing.expect_value(t, t_pkt_len, 4)

	testing.expect_value(t, len(track.allocation_map), 0)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `odin test pgproto`
Expected: FAIL with undefined identifiers (`encode_query`, `encode_terminate`)

- [ ] **Step 3: Implement Query and Terminate in `pgproto/frontend.odin`**

```odin
Msg_Query :: struct {
	query: string,
}

Msg_Terminate :: struct {}

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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `odin test pgproto`
Expected: PASS

- [ ] **Step 5: Commit Task 2**

```bash
git add pgproto/frontend.odin pgproto/frontend_test.odin
git commit -m "feat(pgproto): implement Query and Terminate encoders"
```

---

### Task 3: Extended Query Protocol Encoders

**Files:**
- Modify: `pgproto/frontend.odin`
- Modify: `pgproto/frontend_test.odin`

**Interfaces:**
- Produces:
  ```odin
  Describe_Target :: enum u8 { Statement = 'S', Portal = 'P' }
  Close_Target :: enum u8 { Statement = 'S', Portal = 'P' }

  Msg_Parse :: struct { statement_name: string, query: string, param_oids: []u32 }
  Bind_Param :: struct { is_null: bool, value: []byte }
  Msg_Bind :: struct {
  	portal_name:         string,
  	statement_name:      string,
  	param_format_codes:  []Field_Format,
  	param_values:        []Bind_Param,
  	result_format_codes: []Field_Format,
  }
  Msg_Describe :: struct { target_type: Describe_Target, name: string }
  Msg_Execute :: struct { portal_name: string, max_rows: i32 }
  Msg_Sync :: struct {}
  Msg_Flush :: struct {}
  Msg_Close :: struct { target_type: Close_Target, name: string }

  encode_parse :: proc(builder: ^[dynamic]byte, statement_name: string, query: string, param_oids: []u32 = nil) -> int
  encode_bind :: proc(builder: ^[dynamic]byte, msg: Msg_Bind) -> int
  encode_describe :: proc(builder: ^[dynamic]byte, target_type: Describe_Target, name: string = "") -> int
  encode_execute :: proc(builder: ^[dynamic]byte, portal_name: string = "", max_rows: i32 = 0) -> int
  encode_sync :: proc(builder: ^[dynamic]byte) -> int
  encode_flush :: proc(builder: ^[dynamic]byte) -> int
  encode_close :: proc(builder: ^[dynamic]byte, target_type: Close_Target, name: string = "") -> int
  ```

- [ ] **Step 1: Write failing tests for Extended Query encoders**

```odin
// In pgproto/frontend_test.odin
@(test)
test_encode_extended_query_messages :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	buf: [dynamic]byte
	defer delete(buf)

	// 1. Parse
	p_len := encode_parse(&buf, "stmt_1", "SELECT $1::int4", []u32{23})
	testing.expect_value(t, p_len, len(buf))
	r: Reader
	reader_init(&r, buf[:])
	p_type, _ := reader_read_u8(&r)
	p_pkt_len, _ := reader_read_i32(&r)
	p_stmt, _ := reader_read_string_nt(&r)
	p_sql, _ := reader_read_string_nt(&r)
	p_num_oids, _ := reader_read_i16(&r)
	p_oid, _ := reader_read_u32(&r)
	testing.expect_value(t, p_type, u8('P'))
	testing.expect_value(t, p_stmt, "stmt_1")
	testing.expect_value(t, p_sql, "SELECT $1::int4")
	testing.expect_value(t, p_num_oids, 1)
	testing.expect_value(t, p_oid, 23)

	// 2. Bind (with 1 non-null value and 1 null value)
	clear(&buf)
	bind_msg := Msg_Bind{
		portal_name = "portal_1",
		statement_name = "stmt_1",
		param_format_codes = []Field_Format{.Text},
		param_values = []Bind_Param{
			{is_null = false, value = []byte("42")},
			{is_null = true, value = nil},
		},
		result_format_codes = []Field_Format{.Binary},
	}
	b_len := encode_bind(&buf, bind_msg)
	testing.expect_value(t, b_len, len(buf))
	reader_init(&r, buf[:])
	b_type, _ := reader_read_u8(&r)
	b_pkt_len, _ := reader_read_i32(&r)
	b_portal, _ := reader_read_string_nt(&r)
	b_stmt, _ := reader_read_string_nt(&r)
	b_num_fc, _ := reader_read_i16(&r)
	b_fc, _ := reader_read_i16(&r)
	b_num_pv, _ := reader_read_i16(&r)
	b_v1_len, _ := reader_read_i32(&r)
	b_v1_val, _ := reader_read_bytes(&r, int(b_v1_len))
	b_v2_len, _ := reader_read_i32(&r)
	b_num_rfc, _ := reader_read_i16(&r)
	b_rfc, _ := reader_read_i16(&r)
	testing.expect_value(t, b_type, u8('B'))
	testing.expect_value(t, b_portal, "portal_1")
	testing.expect_value(t, b_stmt, "stmt_1")
	testing.expect_value(t, b_num_fc, 1)
	testing.expect_value(t, b_fc, 0)
	testing.expect_value(t, b_num_pv, 2)
	testing.expect_value(t, b_v1_len, 2)
	testing.expect_value(t, string(b_v1_val), "42")
	testing.expect_value(t, b_v2_len, -1)
	testing.expect_value(t, b_num_rfc, 1)
	testing.expect_value(t, b_rfc, 1)

	// 3. Describe Statement & Portal
	clear(&buf)
	d_len := encode_describe(&buf, .Statement, "stmt_1")
	testing.expect_value(t, d_len, len(buf))
	reader_init(&r, buf[:])
	d_type, _ := reader_read_u8(&r)
	d_pkt_len, _ := reader_read_i32(&r)
	d_target, _ := reader_read_u8(&r)
	d_name, _ := reader_read_string_nt(&r)
	testing.expect_value(t, d_type, u8('D'))
	testing.expect_value(t, d_target, u8('S'))
	testing.expect_value(t, d_name, "stmt_1")

	// 4. Execute
	clear(&buf)
	e_len := encode_execute(&buf, "portal_1", 100)
	testing.expect_value(t, e_len, len(buf))
	reader_init(&r, buf[:])
	e_type, _ := reader_read_u8(&r)
	e_pkt_len, _ := reader_read_i32(&r)
	e_portal, _ := reader_read_string_nt(&r)
	e_rows, _ := reader_read_i32(&r)
	testing.expect_value(t, e_type, u8('E'))
	testing.expect_value(t, e_portal, "portal_1")
	testing.expect_value(t, e_rows, 100)

	// 5. Sync & Flush
	clear(&buf)
	encode_sync(&buf)
	encode_flush(&buf)
	testing.expect_value(t, len(buf), 10)
	reader_init(&r, buf[:])
	s1_t, _ := reader_read_u8(&r)
	s1_l, _ := reader_read_i32(&r)
	f1_t, _ := reader_read_u8(&r)
	f1_l, _ := reader_read_i32(&r)
	testing.expect_value(t, s1_t, u8('S'))
	testing.expect_value(t, s1_l, 4)
	testing.expect_value(t, f1_t, u8('H'))
	testing.expect_value(t, f1_l, 4)

	// 6. Close
	clear(&buf)
	encode_close(&buf, .Portal, "portal_1")
	testing.expect_value(t, len(buf), 1 + 4 + 1 + len("portal_1\0"))
	reader_init(&r, buf[:])
	c_type, _ := reader_read_u8(&r)
	c_pkt_len, _ := reader_read_i32(&r)
	c_target, _ := reader_read_u8(&r)
	c_name, _ := reader_read_string_nt(&r)
	testing.expect_value(t, c_type, u8('C'))
	testing.expect_value(t, c_target, u8('P'))
	testing.expect_value(t, c_name, "portal_1")

	testing.expect_value(t, len(track.allocation_map), 0)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `odin test pgproto`
Expected: FAIL with undefined identifiers (`encode_parse`, `encode_bind`, etc.)

- [ ] **Step 3: Implement Extended Query encoders in `pgproto/frontend.odin`**

```odin
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `odin test pgproto`
Expected: PASS

- [ ] **Step 5: Commit Task 3**

```bash
git add pgproto/frontend.odin pgproto/frontend_test.odin
git commit -m "feat(pgproto): implement Extended Query protocol encoders"
```

---

### Task 4: COPY Protocol Encoders & Master Dispatcher

**Files:**
- Modify: `pgproto/frontend.odin`
- Modify: `pgproto/frontend_test.odin`

**Interfaces:**
- Produces:
  ```odin
  Msg_Copy_Data :: struct { data: []byte }
  Msg_Copy_Done :: struct {}
  Msg_Copy_Fail :: struct { message: string }
  Frontend_Message :: union { ... }

  encode_copy_data :: proc(builder: ^[dynamic]byte, data: []byte) -> int
  encode_copy_done :: proc(builder: ^[dynamic]byte) -> int
  encode_copy_fail :: proc(builder: ^[dynamic]byte, message: string) -> int
  encode_frontend_message :: proc(builder: ^[dynamic]byte, msg: Frontend_Message) -> int
  ```

- [ ] **Step 1: Write failing tests for COPY encoders and master dispatcher**

```odin
// In pgproto/frontend_test.odin
@(test)
test_encode_copy_and_dispatcher :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	buf: [dynamic]byte
	defer delete(buf)

	// 1. CopyData
	cd_len := encode_copy_data(&buf, []byte("raw_row_bytes"))
	testing.expect_value(t, cd_len, len(buf))
	r: Reader
	reader_init(&r, buf[:])
	cd_type, _ := reader_read_u8(&r)
	cd_pkt_len, _ := reader_read_i32(&r)
	cd_bytes, _ := reader_read_bytes(&r, int(cd_pkt_len - 4))
	testing.expect_value(t, cd_type, u8('d'))
	testing.expect_value(t, string(cd_bytes), "raw_row_bytes")

	// 2. CopyDone
	clear(&buf)
	encode_copy_done(&buf)
	reader_init(&r, buf[:])
	cdo_type, _ := reader_read_u8(&r)
	cdo_len, _ := reader_read_i32(&r)
	testing.expect_value(t, cdo_type, u8('c'))
	testing.expect_value(t, cdo_len, 4)

	// 3. CopyFail
	clear(&buf)
	encode_copy_fail(&buf, "disk full")
	reader_init(&r, buf[:])
	cf_type, _ := reader_read_u8(&r)
	cf_pkt_len, _ := reader_read_i32(&r)
	cf_msg, _ := reader_read_string_nt(&r)
	testing.expect_value(t, cf_type, u8('f'))
	testing.expect_value(t, cf_msg, "disk full")

	// 4. Master Dispatcher
	clear(&buf)
	m1 := Frontend_Message(Msg_Query{query = "SELECT 42;"})
	m2 := Frontend_Message(Msg_Sync{})
	encode_frontend_message(&buf, m1)
	encode_frontend_message(&buf, m2)

	reader_init(&r, buf[:])
	m1_t, _ := reader_read_u8(&r)
	m1_l, _ := reader_read_i32(&r)
	m1_q, _ := reader_read_string_nt(&r)
	m2_t, _ := reader_read_u8(&r)
	m2_l, _ := reader_read_i32(&r)
	testing.expect_value(t, m1_t, u8('Q'))
	testing.expect_value(t, m1_q, "SELECT 42;")
	testing.expect_value(t, m2_t, u8('S'))
	testing.expect_value(t, m2_l, 4)

	testing.expect_value(t, len(track.allocation_map), 0)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `odin test pgproto`
Expected: FAIL with undefined identifiers (`encode_copy_data`, `encode_frontend_message`, etc.)

- [ ] **Step 3: Implement COPY and master dispatcher in `pgproto/frontend.odin`**

```odin
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

encode_frontend_message :: proc(builder: ^[dynamic]byte, msg: Frontend_Message) -> int {
	switch m in msg {
	case Msg_Startup:
		return encode_startup(builder, m)
	case Msg_SSL_Request:
		return encode_ssl_request(builder)
	case Msg_Cancel_Request:
		return encode_cancel_request(builder, m.process_id, m.secret_key)
	case Msg_Password:
		return encode_password(builder, m.password)
	case Msg_SASL_Initial_Response:
		return encode_sasl_initial_response(builder, m)
	case Msg_SASL_Response:
		return encode_sasl_response(builder, m.data)
	case Msg_Query:
		return encode_query(builder, m.query)
	case Msg_Parse:
		return encode_parse(builder, m.statement_name, m.query, m.param_oids)
	case Msg_Bind:
		return encode_bind(builder, m)
	case Msg_Describe:
		return encode_describe(builder, m.target_type, m.name)
	case Msg_Execute:
		return encode_execute(builder, m.portal_name, m.max_rows)
	case Msg_Sync:
		return encode_sync(builder)
	case Msg_Flush:
		return encode_flush(builder)
	case Msg_Close:
		return encode_close(builder, m.target_type, m.name)
	case Msg_Terminate:
		return encode_terminate(builder)
	case Msg_Copy_Data:
		return encode_copy_data(builder, m.data)
	case Msg_Copy_Done:
		return encode_copy_done(builder)
	case Msg_Copy_Fail:
		return encode_copy_fail(builder, m.message)
	}
	return 0
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `odin test pgproto`
Expected: PASS

- [ ] **Step 5: Commit Task 4**

```bash
git add pgproto/frontend.odin pgproto/frontend_test.odin
git commit -m "feat(pgproto): implement COPY encoders and master Frontend_Message dispatcher"
```

---

### Task 5: Pipelining Tests, Quality Audits & JIRA Update

**Files:**
- Modify: `pgproto/frontend_test.odin`
- Modify: `JIRA.md`

- [ ] **Step 1: Add extended query pipeline integration test in `pgproto/frontend_test.odin`**

```odin
// In pgproto/frontend_test.odin
@(test)
test_extended_query_pipelining :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	buf: [dynamic]byte
	defer delete(buf)

	// Pipeline: Parse ('P') + Bind ('B') + Describe ('D') + Execute ('E') + Sync ('S')
	encode_parse(&buf, "stmt", "SELECT $1", []u32{23})
	encode_bind(&buf, Msg_Bind{
		portal_name = "p",
		statement_name = "stmt",
		param_values = []Bind_Param{{is_null = false, value = []byte("100")}},
	})
	encode_describe(&buf, .Portal, "p")
	encode_execute(&buf, "p", 0)
	encode_sync(&buf)

	r: Reader
	reader_init(&r, buf[:])

	// Validate sequence of 5 packets
	t1, _ := reader_read_u8(&r); l1, _ := reader_read_i32(&r); reader_read_bytes(&r, int(l1 - 4))
	t2, _ := reader_read_u8(&r); l2, _ := reader_read_i32(&r); reader_read_bytes(&r, int(l2 - 4))
	t3, _ := reader_read_u8(&r); l3, _ := reader_read_i32(&r); reader_read_bytes(&r, int(l3 - 4))
	t4, _ := reader_read_u8(&r); l4, _ := reader_read_i32(&r); reader_read_bytes(&r, int(l4 - 4))
	t5, _ := reader_read_u8(&r); l5, _ := reader_read_i32(&r)

	testing.expect_value(t, t1, u8('P'))
	testing.expect_value(t, t2, u8('B'))
	testing.expect_value(t, t3, u8('D'))
	testing.expect_value(t, t4, u8('E'))
	testing.expect_value(t, t5, u8('S'))
	testing.expect_value(t, reader_remaining(&r), 0)

	testing.expect_value(t, len(track.allocation_map), 0)
}
```

- [ ] **Step 2: Run all compiler checks, linters, and sanitizers**

Run:
1. `odin test pgproto -vet -strict-style`
2. `odin test pgproto -sanitize:address`
3. `odin check . -no-entry-point`

Expected: All pass cleanly with 0 errors and 0 memory leaks.

- [ ] **Step 3: Update `JIRA.md` status for `OPG-102`**

Mark `[OPG-102]` as completed `[x] **Status**: Done`.

- [ ] **Step 4: Commit Task 5**

```bash
git add pgproto/frontend_test.odin JIRA.md
git commit -m "test(pgproto): add extended query pipelining tests and mark OPG-102 done in JIRA.md"
```
