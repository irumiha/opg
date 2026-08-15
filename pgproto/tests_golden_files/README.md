# PostgreSQL Protocol 3.0 Golden Test Vectors

Raw binary captures of PostgreSQL Frontend/Backend Protocol 3.0 messages used by
`pgproto/golden_test.odin` for bit-accurate, zero-network codec verification.

## Packet framing

- Typed messages: `1 byte` message type + `4 byte` big-endian i32 length
  (length includes its own 4 bytes, excludes the type byte) + payload.
- Untyped startup-family messages (`fe_startup_message`, `fe_ssl_request`,
  `fe_cancel_request`): `4 byte` length + payload, no type byte.

## Naming convention

- `fe_*.bin` — frontend (client → server) messages, compared byte-for-byte
  against encoder output in `test_golden_frontend_encoders`.
- `be_*.bin` — backend (server → client) messages, parsed and field-asserted in
  `test_golden_backend_parsers`, and used as the mutation corpus by the
  truncation / corrupted-header fuzz tests.
- `ready_for_query_idle.bin`, `auth_ok.bin`, `backend_key_data.bin` — legacy
  aliases of the corresponding `be_*` fixtures kept for the OPG-103 tests
  (e.g. `ready_for_query_idle.bin` is the 6-byte frame `5a 00 00 00 05 49`).

The expected decoded values for every fixture are asserted in
`pgproto/golden_test.odin`; treat that file as the fixture manifest. Tests
resolve fixture paths relative to the process working directory, so run the
test suite from the repository root.
