# [OPG-103] Backend Wire Messages Decoding Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement comprehensive, zero-copy, bounds-checked decoding for all PostgreSQL Backend Protocol 3.0 messages in `pgproto`.

**Architecture:** Separation of backend message structs in `pgproto/backend.odin` and parsing logic in `pgproto/parser.odin`. Sub-parsers utilize `pgproto.Reader` over payload slices for safe, big-endian decoding with zero heap leaks.

**Tech Stack:** Odin, `core:encoding/endian`, `core:os`, `core:mem`, `core:testing`.

## Global Constraints

- **Strict Adherence**: Follow Odin idioms (tabs for indentation, Pascal_Case types, snake_case procs).
- **Network Byte Order (Big-Endian)**: Multi-byte integers must strictly use `core:encoding/endian` / `pgproto/buffer.odin` primitives. Raw transmute is strictly forbidden.
- **Zero Transient Heap Allocations**: Strings and raw byte payloads are zero-copy views into the packet buffer. Dynamic arrays use `allocator := context.temp_allocator`.
- **Safety**: Truncated or malformed packets must return typed `opg.Protocol_Error` without runtime panics.
- **Quality Gates**: Must pass `odin test pgproto -vet -strict-style` and `odin test pgproto -sanitize:address` with 0 memory leaks tracked by `core:mem.Tracking_Allocator`.

---

### Task 1: Separate `pgproto/backend.odin` & Handshake Parsers

**Files:**
- Create: `pgproto/backend.odin`
- Modify: `pgproto/parser.odin`
- Create: `pgproto/backend_test.odin`

**Interfaces:**
- Produces:
  ```odin
  Backend_Message_Type :: enum u8 { ... }
  Auth_Type :: enum i32 { ... }
  Transaction_Status :: enum u8 { ... }
  Msg_Authentication :: struct { ... }
  Msg_Backend_Key_Data :: struct { process_id: i32, secret_key: i32 }
  Msg_Parameter_Status :: struct { name: string, value: string }
  Msg_Ready_For_Query :: struct { status: Transaction_Status }
  Backend_Message :: union { ... }

  parse_message :: proc(data: []byte, allocator := context.temp_allocator) -> (msg: Backend_Message, bytes_consumed: int, err: opg.Error)
  ```

- [ ] **Step 1: Write failing tests for handshake & lifecycle message parsing**

```odin
// pgproto/backend_test.odin
package pgproto

import "core:mem"
import "core:os"
import "core:testing"
import ".." // opg

@(test)
test_parse_handshake_messages :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	// 1. ReadyForQuery ('Z') from golden capture
	rfq_raw, ok_rfq := os.read_entire_file("pgproto/tests_golden_files/ready_for_query_idle.bin", context.temp_allocator)
	testing.expect(t, ok_rfq, "failed to read ready_for_query_idle.bin")
	msg_rfq, n_rfq, err_rfq := parse_message(rfq_raw)
	testing.expect_value(t, err_rfq, nil)
	testing.expect_value(t, n_rfq, 6)
	rfq, is_rfq := msg_rfq.(Msg_Ready_For_Query)
	testing.expect(t, is_rfq, "expected Msg_Ready_For_Query")
	testing.expect_value(t, rfq.status, Transaction_Status.Idle)

	// 2. AuthenticationOk from golden capture
	auth_raw, ok_auth := os.read_entire_file("pgproto/tests_golden_files/auth_ok.bin", context.temp_allocator)
	testing.expect(t, ok_auth, "failed to read auth_ok.bin")
	msg_auth, n_auth, err_auth := parse_message(auth_raw)
	testing.expect_value(t, err_auth, nil)
	testing.expect_value(t, n_auth, 9)
	auth, is_auth := msg_auth.(Msg_Authentication)
	testing.expect(t, is_auth, "expected Msg_Authentication")
	testing.expect_value(t, auth.auth_type, Auth_Type.Ok)

	// 3. BackendKeyData ('K') from golden capture
	key_raw, ok_key := os.read_entire_file("pgproto/tests_golden_files/backend_key_data.bin", context.temp_allocator)
	testing.expect(t, ok_key, "failed to read backend_key_data.bin")
	msg_key, n_key, err_key := parse_message(key_raw)
	testing.expect_value(t, err_key, nil)
	testing.expect_value(t, n_key, 13)
	key, is_key := msg_key.(Msg_Backend_Key_Data)
	testing.expect(t, is_key, "expected Msg_Backend_Key_Data")
	testing.expect_value(t, key.process_id, i32(12345))
	testing.expect_value(t, key.secret_key, i32(67890))

	// 4. AuthenticationMD5Password with salt
	md5_packet := []byte{'R', 0x00, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04}
	msg_md5, n_md5, err_md5 := parse_message(md5_packet)
	testing.expect_value(t, err_md5, nil)
	testing.expect_value(t, n_md5, 13)
	md5_auth, is_md5 := msg_md5.(Msg_Authentication)
	testing.expect(t, is_md5, "expected Msg_Authentication MD5")
	testing.expect_value(t, md5_auth.auth_type, Auth_Type.MD5_Password)
	testing.expect_value(t, md5_auth.salt, [4]u8{0x01, 0x02, 0x03, 0x04})

	// 5. AuthenticationSASL with multiple mechanisms
	sasl_packet := []byte{
		'R', 0x00, 0x00, 0x00, 0x23, 0x00, 0x00, 0x00, 0x0A,
		'S', 'C', 'R', 'A', 'M', '-', 'S', 'H', 'A', '-', '2', '5', '6', 0x00,
		'S', 'C', 'R', 'A', 'M', '-', 'S', 'H', 'A', '-', '2', '5', '6', '-', 'P', 'L', 'U', 'S', 0x00,
		0x00,
	}
	msg_sasl, n_sasl, err_sasl := parse_message(sasl_packet)
	testing.expect_value(t, err_sasl, nil)
	testing.expect_value(t, n_sasl, len(sasl_packet))
	sasl_auth, is_sasl := msg_sasl.(Msg_Authentication)
	testing.expect(t, is_sasl, "expected Msg_Authentication SASL")
	testing.expect_value(t, sasl_auth.auth_type, Auth_Type.SASL)
	testing.expect_value(t, len(sasl_auth.mechanisms), 2)
	testing.expect_value(t, sasl_auth.mechanisms[0], "SCRAM-SHA-256")
	testing.expect_value(t, sasl_auth.mechanisms[1], "SCRAM-SHA-256-PLUS")

	// 6. ParameterStatus ('S')
	param_packet := []byte{
		'S', 0x00, 0x00, 0x00, 0x1A,
		's', 'e', 'r', 'v', 'e', 'r', '_', 'v', 'e', 'r', 's', 'i', 'o', 'n', 0x00,
		'1', '6', '.', '1', 0x00,
	}
	msg_param, n_param, err_param := parse_message(param_packet)
	testing.expect_value(t, err_param, nil)
	testing.expect_value(t, n_param, len(param_packet))
	param, is_param := msg_param.(Msg_Parameter_Status)
	testing.expect(t, is_param, "expected Msg_Parameter_Status")
	testing.expect_value(t, param.name, "server_version")
	testing.expect_value(t, param.value, "16.1")

	testing.expect_value(t, len(track.allocation_map), 0)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `odin test pgproto`
Expected: FAIL with missing SASL mechanism parsing in `parser.odin`

- [ ] **Step 3: Define `pgproto/backend.odin` and implement handshake parsers in `pgproto/parser.odin`**

Create `pgproto/backend.odin` with all structs and tagged union `Backend_Message`.
Implement `parse_authentication` supporting Ok, MD5, SASL, SASL_Continue, SASL_Final in `pgproto/parser.odin`.

- [ ] **Step 4: Run test to verify it passes**

Run: `odin test pgproto`
Expected: PASS

- [ ] **Step 5: Commit Task 1**

```bash
git add pgproto/backend.odin pgproto/parser.odin pgproto/backend_test.odin
git commit -m "feat(pgproto): separate backend structs and implement handshake message parsers"
```

---

### Task 2: Query Result Parsers (`RowDescription`, `DataRow`, `CommandComplete`, `EmptyQueryResponse`)

**Files:**
- Modify: `pgproto/parser.odin`
- Modify: `pgproto/backend_test.odin`

**Interfaces:**
- Produces:
  ```odin
  parse_row_description :: proc(payload: []byte, allocator: mem.Allocator) -> (Msg_Row_Description, opg.Error)
  parse_data_row :: proc(payload: []byte, allocator: mem.Allocator) -> (Msg_Data_Row, opg.Error)
  ```

- [ ] **Step 1: Write failing tests for Query results**

```odin
// In pgproto/backend_test.odin
@(test)
test_parse_query_result_messages :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	// 1. CommandComplete ('C')
	cc_pkt := []byte{'C', 0x00, 0x00, 0x00, 0x0D, 'S', 'E', 'L', 'E', 'C', 'T', ' ', '1', 0x00}
	msg_cc, n_cc, err_cc := parse_message(cc_pkt)
	testing.expect_value(t, err_cc, nil)
	testing.expect_value(t, n_cc, len(cc_pkt))
	cc, is_cc := msg_cc.(Msg_Command_Complete)
	testing.expect(t, is_cc, "expected Msg_Command_Complete")
	testing.expect_value(t, cc.tag, "SELECT 1")

	// 2. EmptyQueryResponse ('I')
	eq_pkt := []byte{'I', 0x00, 0x00, 0x00, 0x04}
	msg_eq, n_eq, err_eq := parse_message(eq_pkt)
	testing.expect_value(t, err_eq, nil)
	testing.expect_value(t, n_eq, 5)
	_, is_eq := msg_eq.(Msg_Empty_Query_Response)
	testing.expect(t, is_eq, "expected Msg_Empty_Query_Response")

	// 3. RowDescription ('T') with 2 columns
	// Field 1: "id", table_oid 1234, col_attr 1, type_oid 23 (INT4), type_size 4, typmod -1, format 0
	// Field 2: "name", table_oid 1234, col_attr 2, type_oid 25 (TEXT), type_size -1, typmod -1, format 0
	var_rd: [dynamic]byte
	defer delete(var_rd)
	w: Writer
	writer_init(&w, &var_rd)
	len_pos := writer_begin_packet(&w, 'T')
	writer_write_i16(&w, 2) // 2 fields
	// Col 1
	writer_write_string_nt(&w, "id")
	writer_write_u32(&w, 1234)
	writer_write_i16(&w, 1)
	writer_write_u32(&w, 23)
	writer_write_i16(&w, 4)
	writer_write_i32(&w, -1)
	writer_write_i16(&w, 0)
	// Col 2
	writer_write_string_nt(&w, "name")
	writer_write_u32(&w, 1234)
	writer_write_i16(&w, 2)
	writer_write_u32(&w, 25)
	writer_write_i16(&w, -1)
	writer_write_i32(&w, -1)
	writer_write_i16(&w, 0)
	writer_end_packet(&w, len_pos)

	msg_rd, n_rd, err_rd := parse_message(var_rd[:])
	testing.expect_value(t, err_rd, nil)
	testing.expect_value(t, n_rd, len(var_rd))
	rd, is_rd := msg_rd.(Msg_Row_Description)
	testing.expect(t, is_rd, "expected Msg_Row_Description")
	testing.expect_value(t, len(rd.fields), 2)
	testing.expect_value(t, rd.fields[0].name, "id")
	testing.expect_value(t, rd.fields[0].type_oid, u32(23))
	testing.expect_value(t, rd.fields[1].name, "name")
	testing.expect_value(t, rd.fields[1].type_oid, u32(25))

	// 4. DataRow ('D') with 1 valid value and 1 NULL value
	var_dr: [dynamic]byte
	defer delete(var_dr)
	writer_init(&w, &var_dr)
	dr_pos := writer_begin_packet(&w, 'D')
	writer_write_i16(&w, 2) // 2 columns
	// Col 1: length 2, bytes "42"
	writer_write_i32(&w, 2)
	writer_write_bytes(&w, []byte("42"))
	// Col 2: NULL (length -1)
	writer_write_i32(&w, -1)
	writer_end_packet(&w, dr_pos)

	msg_dr, n_dr, err_dr := parse_message(var_dr[:])
	testing.expect_value(t, err_dr, nil)
	testing.expect_value(t, n_dr, len(var_dr))
	dr, is_dr := msg_dr.(Msg_Data_Row)
	testing.expect(t, is_dr, "expected Msg_Data_Row")
	testing.expect_value(t, len(dr.values), 2)
	testing.expect_value(t, dr.values[0].is_null, false)
	testing.expect_value(t, string(dr.values[0].data), "42")
	testing.expect_value(t, dr.values[1].is_null, true)
	testing.expect_value(t, len(dr.values[1].data), 0)

	testing.expect_value(t, len(track.allocation_map), 0)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `odin test pgproto`
Expected: FAIL with unparsed RowDescription / DataRow stubs

- [ ] **Step 3: Implement `parse_row_description` and `parse_data_row` in `pgproto/parser.odin`**

Implement sub-parsers using `pgproto.Reader` and allocator for dynamic slices.

- [ ] **Step 4: Run test to verify it passes**

Run: `odin test pgproto`
Expected: PASS

- [ ] **Step 5: Commit Task 2**

```bash
git add pgproto/parser.odin pgproto/backend_test.odin
git commit -m "feat(pgproto): implement RowDescription and DataRow message parsers"
```

---

### Task 3: Error & Notice Structured Field Parsers (`ErrorResponse`, `NoticeResponse`)

**Files:**
- Modify: `pgproto/parser.odin`
- Modify: `pgproto/backend_test.odin`

**Interfaces:**
- Produces:
  ```odin
  parse_error_or_notice_fields :: proc(payload: []byte) -> (opg.Postgres_Error, opg.Error)
  ```

- [ ] **Step 1: Write failing tests for ErrorResponse and NoticeResponse**

```odin
// In pgproto/backend_test.odin
@(test)
test_parse_error_and_notice_messages :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	// ErrorResponse ('E') with SQLSTATE 42P01 (undefined table)
	var_err: [dynamic]byte
	defer delete(var_err)
	w: Writer
	writer_init(&w, &var_err)
	pos := writer_begin_packet(&w, 'E')
	writer_write_u8(&w, 'S'); writer_write_string_nt(&w, "ERROR")
	writer_write_u8(&w, 'V'); writer_write_string_nt(&w, "ERROR")
	writer_write_u8(&w, 'C'); writer_write_string_nt(&w, "42P01")
	writer_write_u8(&w, 'M'); writer_write_string_nt(&w, "relation \"nonexistent\" does not exist")
	writer_write_u8(&w, 'P'); writer_write_string_nt(&w, "15")
	writer_write_u8(&w, 'F'); writer_write_string_nt(&w, "parse_relation.c")
	writer_write_u8(&w, 'L'); writer_write_string_nt(&w, "1374")
	writer_write_u8(&w, 'R'); writer_write_string_nt(&w, "parserOpenTable")
	writer_write_u8(&w, 0x00) // terminating null
	writer_end_packet(&w, pos)

	msg_e, n_e, err_e := parse_message(var_err[:])
	testing.expect_value(t, err_e, nil)
	testing.expect_value(t, n_e, len(var_err))
	pg_err, is_err := msg_e.(opg.Postgres_Error)
	testing.expect(t, is_err, "expected opg.Postgres_Error")
	testing.expect_value(t, pg_err.severity, "ERROR")
	testing.expect_value(t, pg_err.code, "42P01")
	testing.expect_value(t, pg_err.message, "relation \"nonexistent\" does not exist")
	testing.expect_value(t, pg_err.position, "15")
	testing.expect_value(t, pg_err.file, "parse_relation.c")
	testing.expect_value(t, pg_err.line, "1374")
	testing.expect_value(t, pg_err.routine, "parserOpenTable")

	// NoticeResponse ('N')
	var_n: [dynamic]byte
	defer delete(var_n)
	writer_init(&w, &var_n)
	n_pos := writer_begin_packet(&w, 'N')
	writer_write_u8(&w, 'S'); writer_write_string_nt(&w, "NOTICE")
	writer_write_u8(&w, 'M'); writer_write_string_nt(&w, "table created successfully")
	writer_write_u8(&w, 0x00)
	writer_end_packet(&w, n_pos)

	msg_n, n_n, err_n := parse_message(var_n[:])
	testing.expect_value(t, err_n, nil)
	testing.expect_value(t, n_n, len(var_n))
	notice, is_notice := msg_n.(Msg_Notice_Response)
	testing.expect(t, is_notice, "expected Msg_Notice_Response")
	testing.expect_value(t, notice.error.severity, "NOTICE")
	testing.expect_value(t, notice.error.message, "table created successfully")

	testing.expect_value(t, len(track.allocation_map), 0)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `odin test pgproto`
Expected: FAIL with unparsed ErrorResponse / NoticeResponse

- [ ] **Step 3: Implement `parse_error_or_notice_fields` in `pgproto/parser.odin`**

Implement zero-copy extraction of all structured field codes (`S`, `V`, `C`, `M`, `D`, `H`, `P`, `p`, `q`, `W`, `s`, `t`, `c`, `d`, `n`, `F`, `L`, `R`).

- [ ] **Step 4: Run test to verify it passes**

Run: `odin test pgproto`
Expected: PASS

- [ ] **Step 5: Commit Task 3**

```bash
git add pgproto/parser.odin pgproto/backend_test.odin
git commit -m "feat(pgproto): implement ErrorResponse and NoticeResponse parsers"
```

---

### Task 4: Extended Signals, Parameters & COPY Protocol Parsers

**Files:**
- Modify: `pgproto/parser.odin`
- Modify: `pgproto/backend_test.odin`

**Interfaces:**
- Produces:
  ```odin
  parse_parameter_description :: proc(payload: []byte, allocator: mem.Allocator) -> (Msg_Parameter_Description, opg.Error)
  parse_copy_response :: proc(payload: []byte, allocator: mem.Allocator) -> (Field_Format, []Field_Format, opg.Error)
  parse_notification :: proc(payload: []byte) -> (Msg_Notification_Response, opg.Error)
  ```

- [ ] **Step 1: Write failing tests for Extended signals, Notifications & COPY**

```odin
// In pgproto/backend_test.odin
@(test)
test_parse_extended_and_copy_messages :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	// 1. Completion & Suspended signals
	sig_1 := []byte{'1', 0, 0, 0, 4}
	m1, _, _ := parse_message(sig_1)
	_, is_pc := m1.(Msg_Parse_Complete); testing.expect(t, is_pc, "expected Msg_Parse_Complete")

	sig_2 := []byte{'2', 0, 0, 0, 4}
	m2, _, _ := parse_message(sig_2)
	_, is_bc := m2.(Msg_Bind_Complete); testing.expect(t, is_bc, "expected Msg_Bind_Complete")

	sig_3 := []byte{'3', 0, 0, 0, 4}
	m3, _, _ := parse_message(sig_3)
	_, is_cc := m3.(Msg_Close_Complete); testing.expect(t, is_cc, "expected Msg_Close_Complete")

	sig_n := []byte{'n', 0, 0, 0, 4}
	mn, _, _ := parse_message(sig_n)
	_, is_nd := mn.(Msg_No_Data); testing.expect(t, is_nd, "expected Msg_No_Data")

	sig_s := []byte{'s', 0, 0, 0, 4}
	ms, _, _ := parse_message(sig_s)
	_, is_ps := ms.(Msg_Portal_Suspended); testing.expect(t, is_ps, "expected Msg_Portal_Suspended")

	// 2. ParameterDescription ('t') with 2 OIDs (23, 25)
	pd_pkt := []byte{'t', 0, 0, 0, 14, 0, 2, 0, 0, 0, 23, 0, 0, 0, 25}
	m_pd, n_pd, err_pd := parse_message(pd_pkt)
	testing.expect_value(t, err_pd, nil)
	testing.expect_value(t, n_pd, len(pd_pkt))
	pd, is_pd := m_pd.(Msg_Parameter_Description)
	testing.expect(t, is_pd, "expected Msg_Parameter_Description")
	testing.expect_value(t, len(pd.param_oids), 2)
	testing.expect_value(t, pd.param_oids[0], u32(23))
	testing.expect_value(t, pd.param_oids[1], u32(25))

	// 3. NotificationResponse ('A')
	var_a: [dynamic]byte
	defer delete(var_a)
	w: Writer
	writer_init(&w, &var_a)
	a_pos := writer_begin_packet(&w, 'A')
	writer_write_i32(&w, 9999)
	writer_write_string_nt(&w, "events_channel")
	writer_write_string_nt(&w, "{\"action\":\"insert\"}")
	writer_end_packet(&w, a_pos)

	m_a, n_a, err_a := parse_message(var_a[:])
	testing.expect_value(t, err_a, nil)
	testing.expect_value(t, n_a, len(var_a))
	notif, is_notif := m_a.(Msg_Notification_Response)
	testing.expect(t, is_notif, "expected Msg_Notification_Response")
	testing.expect_value(t, notif.process_id, i32(9999))
	testing.expect_value(t, notif.channel, "events_channel")
	testing.expect_value(t, notif.payload, "{\"action\":\"insert\"}")

	// 4. CopyInResponse ('G')
	var_g: [dynamic]byte
	defer delete(var_g)
	writer_init(&w, &var_g)
	g_pos := writer_begin_packet(&w, 'G')
	writer_write_u8(&w, 0) // overall format text
	writer_write_i16(&w, 2)
	writer_write_i16(&w, 0)
	writer_write_i16(&w, 1)
	writer_end_packet(&w, g_pos)

	m_g, n_g, err_g := parse_message(var_g[:])
	testing.expect_value(t, err_g, nil)
	testing.expect_value(t, n_g, len(var_g))
	copy_in, is_ci := m_g.(Msg_Copy_In_Response)
	testing.expect(t, is_ci, "expected Msg_Copy_In_Response")
	testing.expect_value(t, copy_in.overall_format, Field_Format.Text)
	testing.expect_value(t, len(copy_in.column_format_codes), 2)
	testing.expect_value(t, copy_in.column_format_codes[0], Field_Format.Text)
	testing.expect_value(t, copy_in.column_format_codes[1], Field_Format.Binary)

	// 5. CopyData ('d') and CopyDone ('c')
	cd_pkt := []byte{'d', 0, 0, 0, 9, 'c', 'o', 'p', 'y', '1'}
	m_cd, n_cd, _ := parse_message(cd_pkt)
	cd, is_cd := m_cd.(Msg_Copy_Data_Backend)
	testing.expect(t, is_cd, "expected Msg_Copy_Data_Backend")
	testing.expect_value(t, string(cd.data), "copy1")

	cdo_pkt := []byte{'c', 0, 0, 0, 4}
	m_cdo, _, _ := parse_message(cdo_pkt)
	_, is_cdo := m_cdo.(Msg_Copy_Done_Backend)
	testing.expect(t, is_cdo, "expected Msg_Copy_Done_Backend")

	testing.expect_value(t, len(track.allocation_map), 0)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `odin test pgproto`
Expected: FAIL with unparsed signals and COPY messages

- [ ] **Step 3: Implement remaining message parsers in `pgproto/parser.odin`**

Implement sub-parsers for ParameterDescription, NotificationResponse, CopyIn, CopyOut, CopyBoth, CopyData, CopyDone, FunctionCallResponse, and NegotiateProtocolVersion.

- [ ] **Step 4: Run test to verify it passes**

Run: `odin test pgproto`
Expected: PASS

- [ ] **Step 5: Commit Task 4**

```bash
git add pgproto/parser.odin pgproto/backend_test.odin
git commit -m "feat(pgproto): implement Extended signals, Notification, and COPY backend parsers"
```

---

### Task 5: Malformed Inputs, Quality Audits & JIRA Update

**Files:**
- Modify: `pgproto/backend_test.odin`
- Modify: `JIRA.md`

- [ ] **Step 1: Add error edge case & fuzz tests in `pgproto/backend_test.odin`**

```odin
// In pgproto/backend_test.odin
@(test)
test_parse_malformed_and_underflow_packets :: proc(t: ^testing.T) {
	// 1. Header underflow (< 5 bytes)
	_, _, err1 := parse_message([]byte{'Z', 0, 0})
	p_err1, ok1 := err1.(opg.Protocol_Error)
	testing.expect(t, ok1, "expected Protocol_Error")
	testing.expect_value(t, p_err1.type, opg.Protocol_Error_Type.Buffer_Underflow)

	// 2. Invalid length header (< 4)
	_, _, err2 := parse_message([]byte{'Z', 0, 0, 0, 2, 'I'})
	p_err2, ok2 := err2.(opg.Protocol_Error)
	testing.expect(t, ok2, "expected Protocol_Error")
	testing.expect_value(t, p_err2.type, opg.Protocol_Error_Type.Invalid_Length)

	// 3. Payload underflow
	_, _, err3 := parse_message([]byte{'Z', 0, 0, 0, 10, 'I'})
	p_err3, ok3 := err3.(opg.Protocol_Error)
	testing.expect(t, ok3, "expected Protocol_Error")
	testing.expect_value(t, p_err3.type, opg.Protocol_Error_Type.Buffer_Underflow)

	// 4. Unknown message type
	_, _, err4 := parse_message([]byte{'?', 0, 0, 0, 4})
	p_err4, ok4 := err4.(opg.Protocol_Error)
	testing.expect(t, ok4, "expected Protocol_Error")
	testing.expect_value(t, p_err4.type, opg.Protocol_Error_Type.Unknown_Message_Type)

	// 5. Malformed ReadyForQuery (payload length 0)
	_, _, err5 := parse_message([]byte{'Z', 0, 0, 0, 4})
	p_err5, ok5 := err5.(opg.Protocol_Error)
	testing.expect(t, ok5, "expected Protocol_Error")
	testing.expect_value(t, p_err5.type, opg.Protocol_Error_Type.Malformed_Packet)
}
```

- [ ] **Step 2: Run all compiler checks, linters, and sanitizers**

Run:
1. `odin test pgproto -vet -strict-style`
2. `odin test pgproto -sanitize:address`
3. `odin check . -no-entry-point`

Expected: All pass cleanly with 0 errors and 0 memory leaks.

- [ ] **Step 3: Update `JIRA.md` status for `OPG-103`**

Mark `[OPG-103]` as completed `[x] **Status**: Done`.

- [ ] **Step 4: Commit Task 5**

```bash
git add pgproto/backend_test.odin JIRA.md
git commit -m "test(pgproto): add malformed packet tests and mark OPG-103 done in JIRA.md"
```
