# pgconn Coverage Audit (OPG-207)

Odin has no coverage instrumentation, so OPG-207's numeric coverage criterion is
replaced by this manual audit (decision: Igor, 2026-08-15). Every public proc
and distinct behavior in `pgconn` is mapped to its covering tests. Unit tests
run against `Mock_Transport` (no network); integration tests
(`-define:OPG_INTEGRATION=true`) run against live PostgreSQL 17 via the
docker compose harness.

Test counts at audit time: 95 unit + 21 integration = 116 (`odin test pgconn -define:OPG_INTEGRATION=true`).

## conn.odin

| Proc / behavior | Unit tests | Integration tests |
|---|---|---|
| `conn_is_alive` (all statuses, nil) | `test_conn_is_alive_all_statuses` | exercised by every integration test |
| `conn_handshake` cleartext / md5 / SCRAM success | `test_conn_handshake_cleartext_success`, `test_conn_handshake_md5_success`, `test_conn_handshake_scram_and_parameters` | `test_integration_connect_and_close` (real SCRAM) |
| `conn_handshake` params, backend keys, notices during startup | `test_conn_handshake_with_params_backend_keys_and_notices` | `test_integration_server_parameters_and_appname` |
| `conn_handshake` server ErrorResponse | `test_conn_handshake_error_response`, `test_conn_handshake_server_error_response` | `test_integration_auth_wrong_password` (28P01), `test_integration_unknown_database` (3D000) |
| `conn_handshake` SCRAM signature mismatch | `test_conn_handshake_scram_server_signature_mismatch` | — (requires hostile server) |
| `conn_handshake` unexpected message | `test_conn_handshake_unexpected_message` | — |
| `conn_connect_with_transport` incl. cleanup-on-failure defer | `test_conn_handshake_*` suite (10 call sites) | — |
| `conn_connect` real TCP dial + failure branch | `test_conn_connect_invalid_port_or_host`, `test_conn_connect_default_port_invalid_host` | all integration tests (success path) |
| `conn_close` idempotency, Terminate, map cleanup | `test_conn_struct_and_teardown`, `test_conn_close_edge_cases` | every integration test teardown |
| `conn_cancel_with_transport` | `test_conn_cancel_with_transport`, `test_conn_cancel_with_transport_write_error` | — |
| `conn_cancel` (real second socket, observable cancellation) | `test_conn_cancel_invalid_conn` (guard paths) | `test_integration_cancel_running_query` (57014 + reuse) |
| Notice / notification dispatch | `test_conn_notice_callback`, `test_conn_notification_callback`, `test_conn_handlers_assignment` | `test_integration_raise_notice_handler`, `test_integration_listen_notify` |

## query.odin

| Proc / behavior | Unit tests | Integration tests |
|---|---|---|
| `extract_rows_affected` | `test_extract_rows_affected` | via every command-tag assertion |
| `conn_query` rows + desc + tag | `test_conn_query_simple_select` | `test_integration_multi_row_select`, `test_integration_dml_rows_affected` |
| dead-connection guard | `test_conn_query_not_alive`, `test_conn_query_dead_connection` | — |
| row-callback abort / streaming stop | `test_conn_query_row_callback_abort`, `test_conn_query_early_abort_row_streaming` | — |
| ErrorResponse + drain to RFQ | `test_conn_query_error_response`, `test_conn_query_error_response_and_drain` | `test_integration_error_response_and_recovery` (42P01) |
| empty query | `test_conn_query_empty_query` | `test_integration_multi_statement_and_empty_query` |
| multi-statement accumulation | — | `test_integration_multi_statement_and_empty_query` |
| notices/notifications mid-query | `test_conn_query_notice_and_notification` | `test_integration_raise_notice_handler`, `test_integration_listen_notify` |
| transaction status transitions | `test_conn_query_in_transaction_status` | `test_integration_transaction_status_transitions` (Idle → InTx → Failed → Idle, commit path) |
| unexpected message | `test_conn_query_unexpected_message` | — |
| NULL column, nil callbacks | `test_conn_query_null_column_and_nil_callbacks` | — |

## extended.odin

| Proc / behavior | Unit tests | Integration tests |
|---|---|---|
| `conn_exec_params` success, params | `test_conn_exec_params_success` | `test_integration_exec_params_text` |
| NULL parameter | `test_conn_exec_params_null_param` | `test_integration_exec_params_null` |
| dead-conn guard | `test_conn_exec_params_not_alive` | — |
| ErrorResponse + Sync drain | `test_conn_exec_params_error_response`, `test_conn_exec_params_error_drain` | `test_integration_exec_params_type_error_recovery` (22P02) |
| unexpected message / early abort / notices | `test_conn_exec_params_unexpected_message`, `test_conn_exec_params_early_abort_row_streaming`, `test_conn_exec_params_notice_and_notification` | — |
| `conn_prepare` + cache | `test_conn_prepared_statement_lifecycle` | `test_integration_prepared_statement_lifecycle` |
| re-prepare same name (Close-before-Parse, 42P05 regression) | `test_conn_prepared_statement_overwrite_and_conn_close_cleanup` | `test_integration_prepared_statement_lifecycle` |
| `conn_exec_prepared` incl. errors | `test_conn_exec_prepared_errors_and_edge_cases` | `test_integration_prepared_statement_lifecycle` (2 executions, 26000 after close) |
| `conn_close_statement` / `conn_close_portal` | `test_conn_close_portal_and_close_statement_variations` | `test_integration_prepared_statement_lifecycle`, `test_integration_close_portal_noop` |
| prepare on dead conn / server error | `test_conn_prepared_dead_connection`, `test_conn_prepare_server_error_and_unexpected` | — |

## pool.odin

| Proc / behavior | Unit tests | Integration tests |
|---|---|---|
| `pool_init` validation / pre-warm / pre-warm failure | `test_pool_init_invalid_config`, `test_pool_init_prewarm_and_destroy`, `test_pool_init_prewarm_failure_cleanup` | `test_integration_pool_acquire_query_release` (pre-warm 1) |
| `default_pool_connect` (real dial path) | — (mock dialer in unit tests) | all three `test_integration_pool_*` tests (connect_fn nil) |
| `pool_acquire` reuse / dial / LIFO | `test_pool_acquire_reuse_and_dial` | `test_integration_pool_acquire_query_release` |
| timeout (param + config default) | `test_pool_acquire_timeout_when_exhausted` | — |
| dial failure slot release | `test_pool_acquire_dial_failure` | — |
| idle-timeout recycling | `test_pool_acquire_idle_recycle` | — |
| nil pool guard | `test_pool_acquire_nil_pool` | — |
| blocked acquirer wake-up | `test_pool_acquire_blocks_until_release` | — |
| `pool_release` ROLLBACK reset | `test_pool_release_resets_in_transaction` | `test_integration_pool_release_resets_real_transaction` (real ROLLBACK, tx status Idle) |
| failed reset / dead conn destruction | `test_pool_release_destroys_on_failed_reset`, `test_pool_release_destroys_dead_conn` | — |
| foreign / nil / double release | `test_pool_release_foreign_connection` | — |
| `pool_destroy` nil / drain-wait | `test_pool_destroy_nil`, `test_pool_destroy_waits_for_in_use` | every pool integration test teardown |
| concurrency (50-thread mock, 16-thread live) | `test_pool_stress_concurrent_acquire_release` | `test_integration_pool_concurrent_live` |
| `pool_total_conns` / `pool_destroy_conn` (internal helpers) | exercised by all pool tests | exercised by all pool integration tests |

## stream.odin

| Proc / behavior | Unit tests | Integration tests |
|---|---|---|
| `stream_init` / `stream_destroy` / `stream_close` / `stream_unread_bytes` | `test_stream_buffer_lifecycle_and_compaction` | all integration tests |
| `stream_compact` (threshold + growth paths) | `test_stream_buffer_lifecycle_and_compaction`, `test_stream_read_large_message_buffer_growth_and_compaction`, `test_stream_read_borrowed_string_validity_with_compaction` | — |
| `stream_read_message` single / fragmented / batched | `test_stream_read_single_message`, `test_stream_read_fragmented_message`, `test_stream_read_multiple_messages_in_single_chunk` | all integration tests |
| invalid length / parse error / EOF / timeout | `test_stream_read_invalid_length`, `test_stream_read_invalid_length_error`, `test_stream_read_parse_error`, `test_stream_read_eof_closed_error`, `test_stream_read_timeout_error`, `test_stream_read_transport_error_and_closed` | — |
| large packet growth | `test_stream_large_packet_buffer_expansion` | — |
| `stream_write_messages` pipelining | `test_stream_write_messages_pipelined` | all integration tests |
| `map_recv_error` / `map_send_error` (all enum branches) | `test_stream_error_mappers` | — |
| `tcp_read` / `tcp_write` / `tcp_close` / `tcp_set_deadlines` / `make_tcp_transport` | `test_make_tcp_transport` (construction) | all integration tests (real socket I/O) |

## auth.odin / auth_scram.odin

| Proc / behavior | Unit tests | Integration tests |
|---|---|---|
| `auth_handle_challenge` cleartext / md5 / ok | `test_auth_handle_challenge_cleartext`, `test_auth_handle_challenge_md5`, `test_auth_handle_challenge_ok` | — (server uses SCRAM) |
| SASL full conversation / errors / unsupported | `test_auth_handle_challenge_sasl_full_conversation`, `test_auth_handle_challenge_sasl_errors`, `test_auth_handle_challenge_unsupported_and_unrecognized` | every integration connect (real SCRAM-SHA-256) |
| SCRAM primitives (RFC 7677 vectors, nonce, escaping, state lifecycle) | `test_auth_scram_*` (7 tests), `test_auth_md5_password_computation` | every integration connect |

## Intentionally uncovered

- **TLS negotiation** — deferred with OPG-205 (not implemented).
- **MD5 auth against a live server** — compose server enforces SCRAM (PG17
  default); md5 is fully covered at unit level with golden vectors.
- **SCRAM server-signature forgery live** — requires a hostile server;
  covered at unit level.
- **`tcp_set_deadlines` OS-level socket timeouts** — currently stores values
  only (noted in stream.odin); behavior covered when implemented.

## Verification commands

- `odin test pgconn -define:OPG_INTEGRATION=true` — 116/116 pass.
- `odin test pgconn -define:OPG_INTEGRATION=true -sanitize:thread` — zero races.
- `odin test pgconn -define:OPG_INTEGRATION=true -sanitize:address` — zero reports.
