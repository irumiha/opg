# Design Document: OPG-205 Dynamic TLS via `core:dynlib` (OpenSSL Backend)

Date: 2026-08-15
Status: Approved (Igor, 2026-08-15)

## 1. Scope

Add opt-out TLS support to `pgconn` by dynamically loading OpenSSL 3 at
runtime via `core:dynlib` — no link-time dependency. Scope decisions made
during brainstorming:

- **Backends**: probe-list architecture with per-OS library names; only the
  OpenSSL backend is implemented and tested. Native Schannel (Windows) and
  SecureTransport (macOS) are explicitly deferred — untestable code is not
  shipped. OpenSSL names are probed on all three OSes.
- **Modes**: `disable` / `prefer` / `require` (libpq semantics, no
  certificate verification in `require`, matching libpq). `verify-ca` /
  `verify-full` are a future task.
- **Default**: `Prefer` — every `conn_connect` attempts TLS and falls back
  to plaintext if the server declines or no TLS library is present. This
  matches libpq and means the whole existing integration suite runs over
  TLS once the test server enables `ssl=on`.

## 2. Public API

```odin
// tls.odin — zero value is the default mode.
SSL_Mode :: enum {
	Prefer,  // try TLS, fall back to plaintext ('N' or no TLS library)
	Disable, // never attempt TLS (previous behavior)
	Require, // fail with Net_Error{.TLS_Handshake_Failed} unless TLS established
}

// conn.odin
Conn_Config :: struct {
	// ... existing fields ...
	ssl_mode: SSL_Mode,
}

Conn :: struct {
	// ... existing fields ...
	tls_data: TLS_Transport_Data, // sibling of tcp_data; unused when plaintext
}
```

The pool needs no changes: TLS flows through `Pool_Config.conn_config`.

## 3. Dynamic OpenSSL binding (`tls_openssl.odin`)

One struct of `proc "c"` pointers bound with `dynlib.initialize_symbols`
(field name == exported symbol; handle stored in `__handle`):

```odin
OpenSSL_API :: struct {
	__handle:          dynlib.Library,
	TLS_client_method: proc "c" () -> rawptr,
	SSL_CTX_new:       proc "c" (method: rawptr) -> rawptr,
	SSL_CTX_free:      proc "c" (ctx: rawptr),
	SSL_new:           proc "c" (ctx: rawptr) -> rawptr,
	SSL_free:          proc "c" (ssl: rawptr),
	SSL_set_fd:        proc "c" (ssl: rawptr, fd: c.int) -> c.int,
	SSL_connect:       proc "c" (ssl: rawptr) -> c.int,
	SSL_read:          proc "c" (ssl: rawptr, buf: rawptr, num: c.int) -> c.int,
	SSL_write:         proc "c" (ssl: rawptr, buf: rawptr, num: c.int) -> c.int,
	SSL_shutdown:      proc "c" (ssl: rawptr) -> c.int,
	SSL_get_error:     proc "c" (ssl: rawptr, ret: c.int) -> c.int,
	SSL_ctrl:          proc "c" (ssl: rawptr, cmd: c.int, larg: c.long, parg: rawptr) -> c.long,
}
TLS_SYMBOL_COUNT :: 12
```

Constants: `SSL_CTRL_SET_TLSEXT_HOSTNAME = 55`, `TLSEXT_NAMETYPE_host_name = 0`
(SNI via `SSL_ctrl`), `SSL_ERROR_ZERO_RETURN = 6`, `SSL_ERROR_WANT_READ = 2`,
`SSL_ERROR_WANT_WRITE = 3`.

`initialize_symbols` returns `ok` when the library loads; a missing symbol
just stays nil — so a successful probe additionally requires
`count == TLS_SYMBOL_COUNT`.

## 4. Probe (`tls.odin`)

Process-global, mutex-guarded, probed at most once:

```odin
TLS_Load_State :: enum { Unprobed, Loaded, Unavailable }
```

`tls_ensure_loaded() -> bool` locks, probes `TLS_PROBE_PATHS` on first call,
returns `state == .Loaded`. `tls_probe_paths(paths: []string) -> bool` is the
injectable core (unit tests pass a bogus list to prove graceful absence).

Per-OS default lists (`when ODIN_OS` blocks):

- Linux: `libssl.so.3`, `libssl.so`, `libssl.so.1.1`
- macOS: `libssl.3.dylib`, `/opt/homebrew/opt/openssl@3/lib/libssl.3.dylib`, `/usr/local/opt/openssl@3/lib/libssl.3.dylib`
- Windows: `libssl-3-x64.dll`, `libssl-3.dll`, `libssl-1_1-x64.dll`

Thread-safety: `openssl` globals are written once under `tls_mutex`; every
consumer thread passes through `tls_ensure_loaded()` (or a pool-mutex
happens-before chain) before touching them — TSan-clean.

## 5. TLS transport (`tls_openssl.odin`)

Implements the existing `Stream_Transport` interface — the seam built for
this in OPG-201:

```odin
TLS_Transport_Data :: struct {
	ctx:    rawptr, // SSL_CTX*, per-connection
	ssl:    rawptr, // SSL*
	socket: net.TCP_Socket,
}

make_tls_transport :: proc(data: ^TLS_Transport_Data, socket: net.TCP_Socket, server_name: string) -> (Stream_Transport, pgerr.Error)
```

`make_tls_transport`: `SSL_CTX_new(TLS_client_method())` → `SSL_new` →
`SSL_set_fd` → SNI via `SSL_ctrl(ssl, 55, 0, hostname_cstring)` →
`SSL_connect`. Any failure frees what was created, and the caller closes the
socket; error is `Net_Error{type = .TLS_Handshake_Failed}`.

- `tls_read`/`tls_write`: retry on `WANT_READ`/`WANT_WRITE` (blocking fd
  makes these rare); `SSL_ERROR_ZERO_RETURN` → `Net_Error{.Socket_Closed}`;
  anything else → `.Recv_Failed`/`.Send_Failed`.
- `tls_close`: `SSL_shutdown` (best-effort, ignore result), `SSL_free`,
  `SSL_CTX_free`, `net.close(socket)`. No Odin heap allocations to free.
- `tls_set_deadlines`: stores values (same stub level as the TCP transport).

## 6. Negotiation (`tls.odin`)

Unit-testable core over `Stream_Transport` (works with `Mock_Transport`):

```odin
SSL_Negotiation :: enum { Plaintext, Wrap_TLS }

ssl_negotiate :: proc(transport: Stream_Transport, mode: SSL_Mode, tls_loadable: bool) -> (SSL_Negotiation, pgerr.Error)
```

Truth table:

| mode | library | wire | result |
|---|---|---|---|
| Disable | — | nothing sent | Plaintext |
| Prefer | absent | nothing sent | Plaintext |
| Require | absent | nothing sent | `Net_Error{.TLS_Handshake_Failed}` |
| Prefer/Require | present | SSLRequest → `'S'` | Wrap_TLS |
| Prefer | present | SSLRequest → `'N'` | Plaintext (same socket, nothing buffered) |
| Require | present | SSLRequest → `'N'` | `Net_Error{.TLS_Handshake_Failed}` |
| any | present | SSLRequest → other byte | `Protocol_Error{.Unexpected_Message}` |

SSLRequest bytes come from the existing `pgproto.encode_ssl_request`.

`conn_connect` flow: dial TCP → build tcp transport → `ssl_negotiate` (with
`tls_ensure_loaded()` result) → on `Wrap_TLS`, `make_tls_transport` replaces
the transport → `conn_handshake` proceeds unchanged over whichever transport
won. Early failures close the socket explicitly (the stream doesn't own it
yet).

`conn_connect_with_transport` and `conn_handshake` are untouched — callers
supplying their own transport (all mock tests) bypass negotiation entirely.

## 7. Test server

- `scripts/pg-certs/generate.sh` creates a self-signed cert
  (`CN=localhost`, SAN `DNS:localhost,IP:127.0.0.1`, RSA 2048, 36500 days);
  `server.crt`/`server.key` are **committed** — test-only material, labeled
  as such (postgres:17-alpine has no openssl CLI, so initdb-time generation
  is not an option).
- `scripts/pg-init/02-ssl.sh` copies the mounted certs into `$PGDATA`,
  `chmod 600` the key, appends `ssl = on` + cert paths to `postgresql.conf`
  (picked up when the entrypoint starts the real server after initdb).
- `docker-compose.yml` mounts `./scripts/pg-certs` at `/opg-certs:ro`.
- Existing `host` hba rules match TLS and plaintext alike — no hba changes.

## 8. Testing

Unit (`tls_test.odin`, mock transport — no network, no OpenSSL):
- every `ssl_negotiate` row of the truth table, including SSLRequest bytes
  written (8 bytes, code 80877103) and nothing-written cases;
- `tls_probe_paths` with bogus names → false (graceful absence, JIRA
  acceptance criterion); with the real Linux list → true on this machine.

Integration (`integration_test.odin`):
- `Require` connect → `SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()`
  returns `t` (wire-pinned, like `system_user` for auth) + query roundtrip;
- default `Prefer` connect → also `t` against the ssl-enabled server;
- `Disable` connect → `f` (plaintext path stays covered);
- the rest of the suite upgrades to TLS implicitly via the `Prefer` default.

Verification: full gates, `-sanitize:thread` and `-sanitize:address` with
integration on, coverage audit updated (TLS leaves "intentionally
uncovered"; `tcp_set_deadlines`-style stub note applies to
`tls_set_deadlines`).

## 9. JIRA amendment

OPG-205's entry is rewritten: files `pgconn/tls.odin`, `pgconn/tls_openssl.odin`,
`pgconn/tls_test.odin`; description notes the OpenSSL-only decision and defers
native Schannel/SecureTransport backends to a future task; acceptance criteria
keep graceful absence + socket wrapping and add the wire-pinned sslmode tests.
