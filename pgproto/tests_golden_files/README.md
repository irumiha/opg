# PostgreSQL Protocol 3.0 Golden Test Vectors

This directory contains raw binary byte captures of PostgreSQL Frontend/Backend Protocol 3.0 messages for unit testing the `pgproto` parser and serializer without requiring a running database server.

## Vector Structure

Postgres Backend messages follow the standard packet format:
- `1 byte`: Message Type (`'R'`, `'Z'`, `'T'`, `'D'`, `'E'`, `'C'`, etc.)
- `4 bytes`: Big-Endian `i32` length of payload including the 4 length bytes (excluding the 1 identifier byte)
- `N bytes`: Message-specific payload

## Included Test Fixtures

- `ready_for_query_idle.bin`: `Z` packet (5 bytes: `5a 00 00 00 05 49` -> `ReadyForQuery(Idle)`)
- `auth_ok.bin`: `R` packet (9 bytes: `52 00 00 00 08 00 00 00 00` -> `AuthenticationOk`)
- `backend_key_data.bin`: `K` packet (13 bytes -> `BackendKeyData(pid=1234, secret=5678)`)
