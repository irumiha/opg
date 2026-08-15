# Design Document: [OPG-104] `pgproto` Golden Vector Test Suite & Coverage Verification (>= 95%)

- **Date**: 2026-08-15
- **Task ID**: `OPG-104`
- **Layer**: `pgproto`
- **Package**: `package pgproto`
- **Files**:
  - `pgproto/tests_golden_files/*.bin`
  - `pgproto/golden_test.odin`
  - `JIRA.md`
- **Status**: Approved

---

## 1. Overview & Objectives

`OPG-104` validates the complete `pgproto` codec suite (`buffer.odin`, `frontend.odin`, `backend.odin`, `parser.odin`) against an exhaustive catalog of bit-accurate binary golden files (`.bin`) and mutation fuzzing vectors.

### Key Goals:
1. **Golden Binary Fixture Catalog**: Pre-built `.bin` captures representing all 19 Frontend and 31 Backend protocol message variations stored on disk in `pgproto/tests_golden_files/`.
2. **Bit-for-Bit Golden Serialization & Deserialization**: Asserting exact byte equality (`slice.equal`) on serialization and bit-accurate field deserialization on parsing.
3. **Exhaustive Byte-Offset Truncation & Mutation Fuzzing**: Automatically iterating over all $N$ byte prefixes for every golden file to prove crash-free, panic-free `Protocol_Error` responses with zero leaks.
4. **Coverage Target $\ge 95\%$**: Achieving $\ge 95\%$ Line and Branch Coverage across the entire `pgproto` package with zero memory leaks.

---

## 2. Golden Fixtures Specification (`pgproto/tests_golden_files/`)

### 2.1 Frontend Golden Files (`fe_*.bin`)
- `fe_ssl_request.bin`: Untyped 8-byte SSLRequest (`00 00 00 08 04 D2 16 2F`)
- `fe_cancel_request.bin`: Untyped 16-byte CancelRequest (`00 00 00 10 04 D2 16 2E` + PID `1234` + Secret `5678`)
- `fe_startup_message.bin`: Untyped StartupMessage (`user: "postgres"`, `database: "testdb"`, `application_name: "opg"`)
- `fe_password_message.bin`: Typed `'p'` PasswordMessage (`"secret123"`)
- `fe_sasl_initial_response.bin`: Typed `'p'` SASLInitialResponse (`"SCRAM-SHA-256"`, `"n,,n=user,r=fyko..."`)
- `fe_sasl_response.bin`: Typed `'p'` SASLResponse (`"c=biws,r=fyko...,p=v0X8..."`)
- `fe_query.bin`: Typed `'Q'` Simple Query (`"SELECT * FROM users WHERE active = true;"`)
- `fe_parse.bin`: Typed `'P'` Parse (`stmt: "stmt_find_user"`, `query: "SELECT id FROM users WHERE email = $1"`, OIDs: `[25]`)
- `fe_bind.bin`: Typed `'B'` Bind (`portal: ""`, `stmt: "stmt_find_user"`, format: Text, params: `["alice@example.com"]`, result format: Text)
- `fe_describe_statement.bin`: Typed `'D'` Describe (`'S'`, `"stmt_find_user"`)
- `fe_describe_portal.bin`: Typed `'D'` Describe (`'P'`, `""`)
- `fe_execute.bin`: Typed `'E'` Execute (`portal: ""`, `max_rows: 100`)
- `fe_sync.bin`: Typed `'S'` Sync
- `fe_flush.bin`: Typed `'H'` Flush
- `fe_close_statement.bin`: Typed `'C'` Close (`'S'`, `"stmt_find_user"`)
- `fe_terminate.bin`: Typed `'X'` Terminate
- `fe_copy_data.bin`: Typed `'d'` CopyData (`"csv_row_1,100,200\n"`)
- `fe_copy_done.bin`: Typed `'c'` CopyDone
- `fe_copy_fail.bin`: Typed `'f'` CopyFail (`"client abortion: disk full"`)

### 2.2 Backend Golden Files (`be_*.bin`)
- `be_auth_ok.bin`: `'R'` AuthOk (`00 00 00 08 00 00 00 00`)
- `be_auth_md5.bin`: `'R'` AuthMD5Password with salt `[0xAA, 0xBB, 0xCC, 0xDD]`
- `be_auth_sasl.bin`: `'R'` AuthSASL (`"SCRAM-SHA-256"`, `"SCRAM-SHA-256-PLUS"`)
- `be_auth_sasl_continue.bin`: `'R'` AuthSASLContinue (`"r=fyko+...,s=...,i=4096"`)
- `be_auth_sasl_final.bin`: `'R'` AuthSASLFinal (`"v=rmhAn落..."`)
- `be_backend_key_data.bin`: `'K'` BackendKeyData (pid: 12345, key: 67890)
- `be_parameter_status.bin`: `'S'` ParameterStatus (`"server_version"`, `"16.1"`)
- `be_ready_for_query_idle.bin`: `'Z'` ReadyForQuery Idle (`'I'`)
- `be_ready_for_query_tx.bin`: `'Z'` ReadyForQuery InTransaction (`'T'`)
- `be_ready_for_query_err.bin`: `'Z'` ReadyForQuery FailedTransaction (`'E'`)
- `be_row_description.bin`: `'T'` RowDescription (3 columns: `id: int4`, `email: text`, `created_at: timestamptz`)
- `be_data_row.bin`: `'D'` DataRow (3 values: `1`, `"alice@example.com"`, `NULL`)
- `be_command_complete_select.bin`: `'C'` CommandComplete (`"SELECT 42"`)
- `be_command_complete_insert.bin`: `'C'` CommandComplete (`"INSERT 0 1"`)
- `be_error_response.bin`: `'E'` ErrorResponse (SQLSTATE `23505`, duplicate key error with all 18 standard fields)
- `be_notice_response.bin`: `'N'` NoticeResponse (Severity `NOTICE`, message `"relation created"`)
- `be_empty_query_response.bin`: `'I'` EmptyQueryResponse
- `be_parse_complete.bin`: `'1'` ParseComplete
- `be_bind_complete.bin`: `'2'` BindComplete
- `be_close_complete.bin`: `'3'` CloseComplete
- `be_no_data.bin`: `'n'` NoData
- `be_portal_suspended.bin`: `'s'` PortalSuspended
- `be_parameter_description.bin`: `'t'` ParameterDescription (`[23, 25, 1184]`)
- `be_notification_response.bin`: `'A'` NotificationResponse (pid: 4321, channel: `"events"`, payload: `"item_created"`)
- `be_copy_in_response.bin`: `'G'` CopyInResponse (Format: Text, columns: `[Text, Text, Binary]`)
- `be_copy_out_response.bin`: `'H'` CopyOutResponse
- `be_copy_both_response.bin`: `'W'` CopyBothResponse
- `be_copy_data.bin`: `'d'` CopyData
- `be_copy_done.bin`: `'c'` CopyDone
- `be_function_call_response.bin`: `'V'` FunctionCallResponse (binary result)
- `be_negotiate_protocol_version.bin`: `'v'` NegotiateProtocolVersion (minor: 1, options: `["opt1", "opt2"]`)

---

## 3. Test Suite Architecture (`pgproto/golden_test.odin`)

1. **`test_golden_frontend_encoders`**: Compares `encode_frontend_message` output byte-for-byte against each `fe_*.bin` golden file.
2. **`test_golden_backend_parsers`**: Reads each `be_*.bin` golden file, invokes `parse_message`, and verifies all fields.
3. **`test_golden_fuzzing_truncation_matrix`**: Iterates through all $N$ prefixes of every single golden binary file ($0 \dots \text{len}-1$), asserting typed `Protocol_Error` without crashes or memory leaks.
4. **`test_golden_corrupted_headers`**: Tests bit-flipped bytes and invalid length headers on golden packets.

---

## 4. Verification & Quality Gates

- Passes `odin test pgproto -vet -strict-style`
- Passes `odin test pgproto -sanitize:address`
- Zero allocations leaked under `core:mem.Tracking_Allocator`
- Total Line and Branch Coverage $\ge 95\%$ on `pgproto`
