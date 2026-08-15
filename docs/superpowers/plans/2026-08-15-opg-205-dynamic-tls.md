# OPG-205 Dynamic TLS Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Opt-out TLS for `pgconn` via runtime-loaded OpenSSL 3 (`core:dynlib`), with libpq-style `disable`/`prefer`/`require` modes, `Prefer` default, wire-pinned integration tests.

**Architecture:** A mutex-guarded, once-per-process probe binds an `OpenSSL_API` struct of `proc "c"` pointers with `dynlib.initialize_symbols`. `ssl_negotiate` (pure `Stream_Transport` logic, fully mockable) decides Plaintext vs Wrap_TLS per the spec truth table; `conn_connect` wraps the socket in a `TLS_Transport_Data`-backed `Stream_Transport` on `'S'`. Test server gets `ssl=on` with a committed self-signed cert.

**Tech Stack:** Odin nightly dev-2026-08, `core:dynlib`, `core:c`, OpenSSL 3 (`libssl.so.3`, runtime only), docker compose harness, PostgreSQL 17.

**Spec:** `docs/superpowers/specs/2026-08-15-opg-205-dynamic-tls-design.md` (approved). Read it first — the truth table and symbol list there are normative.

## Global Constraints

- No link-time OpenSSL dependency; `dynlib` only. Absence of the library must degrade per the truth table (never crash).
- `SSL_Mode` zero value MUST be `Prefer` (enum member order: `Prefer, Disable, Require`).
- `conn_handshake` / `conn_connect_with_transport` signatures unchanged — all existing mock tests must pass untouched.
- Gates after every task: `odin test pgconn -vet -strict-style` and `odin test tests -all-packages -vet -strict-style`; integration tasks also `-define:OPG_INTEGRATION=true`.
- Tracking-allocator zero-leak assertions in every unit test; never `testing.fail_now` while holding a mutex.
- `net.Socket :: distinct i64` → fd cast is `c.int(socket)`.
- Branch `opg-205-dynamic-tls` (already created, spec committed on it); commit per task; merge to main after final gate (Igor's workflow).

---

### Task 1: `SSL_Mode`, probe state, `ssl_negotiate` (mock-tested truth table)

**Files:**
- Create: `pgconn/tls.odin`
- Create: `pgconn/tls_test.odin`

**Interfaces:**
- Consumes: `Stream_Transport`, `Mock_Transport` (stream_test.odin), `pgproto.encode_ssl_request`, `pgerr`.
- Produces: `SSL_Mode :: enum { Prefer, Disable, Require }`; `SSL_Negotiation :: enum { Plaintext, Wrap_TLS }`; `ssl_negotiate(transport: Stream_Transport, mode: SSL_Mode, tls_loadable: bool) -> (SSL_Negotiation, pgerr.Error)`; `TLS_Load_State`, `tls_state`, `tls_mutex` globals (probe wiring lands in Task 2).

- [ ] **Step 1: Write failing tests (`pgconn/tls_test.odin`)**

```odin
package pgconn

import "core:mem"
import "core:testing"
import "../pgerr"

@(test)
test_ssl_negotiate_disable_sends_nothing :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	mock: Mock_Transport
	mock_transport_init(&mock)
	defer mock_transport_destroy(&mock)

	action, err := ssl_negotiate(make_mock_transport(&mock), .Disable, true)
	testing.expect(t, err == nil, "expected no error")
	testing.expect_value(t, action, SSL_Negotiation.Plaintext)
	testing.expect_value(t, len(mock.written_bytes), 0)
	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
test_ssl_negotiate_library_absent :: proc(t: ^testing.T) {
	mock: Mock_Transport
	mock_transport_init(&mock)
	defer mock_transport_destroy(&mock)

	// Prefer without a TLS library: plaintext, no SSLRequest on the wire.
	action, err := ssl_negotiate(make_mock_transport(&mock), .Prefer, false)
	testing.expect(t, err == nil, "expected no error")
	testing.expect_value(t, action, SSL_Negotiation.Plaintext)
	testing.expect_value(t, len(mock.written_bytes), 0)

	// Require without a TLS library: graceful TLS_Handshake_Failed.
	action2, err2 := ssl_negotiate(make_mock_transport(&mock), .Require, false)
	testing.expect_value(t, action2, SSL_Negotiation.Plaintext)
	nerr, ok := err2.(pgerr.Net_Error)
	testing.expect(t, ok, "expected Net_Error")
	testing.expect_value(t, nerr.type, pgerr.Net_Error_Type.TLS_Handshake_Failed)
	testing.expect_value(t, len(mock.written_bytes), 0)
}

@(test)
test_ssl_negotiate_server_accepts :: proc(t: ^testing.T) {
	mock: Mock_Transport
	mock_transport_init(&mock)
	defer mock_transport_destroy(&mock)
	s_byte := []byte{'S'}
	append(&mock.read_chunks, s_byte)

	action, err := ssl_negotiate(make_mock_transport(&mock), .Require, true)
	testing.expect(t, err == nil, "expected no error")
	testing.expect_value(t, action, SSL_Negotiation.Wrap_TLS)

	// SSLRequest: int32 len 8, int32 code 80877103 (0x04D2162F).
	testing.expect_value(t, len(mock.written_bytes), 8)
	testing.expect_value(t, mock.written_bytes[3], byte(8))
	testing.expect_value(t, mock.written_bytes[4], byte(0x04))
	testing.expect_value(t, mock.written_bytes[5], byte(0xD2))
	testing.expect_value(t, mock.written_bytes[6], byte(0x16))
	testing.expect_value(t, mock.written_bytes[7], byte(0x2F))
}

@(test)
test_ssl_negotiate_server_declines :: proc(t: ^testing.T) {
	// Prefer + 'N': plaintext fallback on the same socket.
	mock: Mock_Transport
	mock_transport_init(&mock)
	defer mock_transport_destroy(&mock)
	n_byte := []byte{'N'}
	append(&mock.read_chunks, n_byte)

	action, err := ssl_negotiate(make_mock_transport(&mock), .Prefer, true)
	testing.expect(t, err == nil, "expected no error")
	testing.expect_value(t, action, SSL_Negotiation.Plaintext)

	// Require + 'N': hard failure.
	mock2: Mock_Transport
	mock_transport_init(&mock2)
	defer mock_transport_destroy(&mock2)
	append(&mock2.read_chunks, n_byte)

	_, err2 := ssl_negotiate(make_mock_transport(&mock2), .Require, true)
	nerr, ok := err2.(pgerr.Net_Error)
	testing.expect(t, ok, "expected Net_Error")
	testing.expect_value(t, nerr.type, pgerr.Net_Error_Type.TLS_Handshake_Failed)
}

@(test)
test_ssl_negotiate_unexpected_byte :: proc(t: ^testing.T) {
	mock: Mock_Transport
	mock_transport_init(&mock)
	defer mock_transport_destroy(&mock)
	x_byte := []byte{'X'}
	append(&mock.read_chunks, x_byte)

	_, err := ssl_negotiate(make_mock_transport(&mock), .Prefer, true)
	perr, ok := err.(pgerr.Protocol_Error)
	testing.expect(t, ok, "expected Protocol_Error")
	testing.expect_value(t, perr.type, pgerr.Protocol_Error_Type.Unexpected_Message)
}

@(test)
test_ssl_negotiate_transport_errors :: proc(t: ^testing.T) {
	// Write fails (closed transport).
	mock: Mock_Transport
	mock_transport_init(&mock)
	defer mock_transport_destroy(&mock)
	mock.is_closed = true

	_, err := ssl_negotiate(make_mock_transport(&mock), .Require, true)
	testing.expect(t, err != nil, "expected error from closed transport")

	// Read fails (no response queued -> Socket_Closed from mock).
	mock2: Mock_Transport
	mock_transport_init(&mock2)
	defer mock_transport_destroy(&mock2)

	_, err2 := ssl_negotiate(make_mock_transport(&mock2), .Require, true)
	testing.expect(t, err2 != nil, "expected error from read failure")
}
```

- [ ] **Step 2: Run to verify failure**

Run: `odin test pgconn -vet -strict-style`
Expected: compile error — `ssl_negotiate` undefined.

- [ ] **Step 3: Implement `pgconn/tls.odin`**

```odin
package pgconn

import "core:sync"
import "../pgerr"
import "../pgproto"

/*
	SSL_Mode selects TLS behavior for conn_connect. The zero value is
	Prefer (libpq default): attempt TLS, fall back to plaintext when the
	server declines or no TLS library can be loaded.
*/
SSL_Mode :: enum {
	Prefer,
	Disable,
	Require,
}

SSL_Negotiation :: enum {
	Plaintext,
	Wrap_TLS,
}

TLS_Load_State :: enum {
	Unprobed,
	Loaded,
	Unavailable,
}

tls_mutex: sync.Mutex
tls_state: TLS_Load_State

/*
	ssl_negotiate runs the pre-startup SSLRequest exchange on a fresh
	transport, per the libpq mode semantics:

	- Disable, or Prefer without a loadable TLS library: plaintext, nothing
	  sent on the wire.
	- Require without a loadable TLS library: Net_Error{.TLS_Handshake_Failed}.
	- SSLRequest sent: 'S' -> Wrap_TLS; 'N' -> plaintext (Prefer) or
	  Net_Error{.TLS_Handshake_Failed} (Require); anything else ->
	  Protocol_Error{.Unexpected_Message}.
*/
ssl_negotiate :: proc(
	transport: Stream_Transport,
	mode: SSL_Mode,
	tls_loadable: bool,
) -> (
	action: SSL_Negotiation,
	err: pgerr.Error,
) {
	if mode == .Disable {
		return .Plaintext, nil
	}
	if !tls_loadable {
		if mode == .Require {
			return .Plaintext, pgerr.Net_Error{type = .TLS_Handshake_Failed}
		}
		return .Plaintext, nil
	}

	req := make([dynamic]byte, context.temp_allocator)
	defer delete(req)
	pgproto.encode_ssl_request(&req)
	if _, werr := transport.write(transport.data, req[:]); werr != nil {
		return .Plaintext, werr
	}

	answer: [1]byte
	n, rerr := transport.read(transport.data, answer[:])
	if rerr != nil {
		return .Plaintext, rerr
	}
	if n != 1 {
		return .Plaintext, pgerr.Net_Error{type = .Unexpected_EOF}
	}

	switch answer[0] {
	case 'S':
		return .Wrap_TLS, nil
	case 'N':
		if mode == .Require {
			return .Plaintext, pgerr.Net_Error{type = .TLS_Handshake_Failed}
		}
		return .Plaintext, nil
	}
	return .Plaintext, pgerr.Protocol_Error{
		type = .Unexpected_Message,
		message = "unexpected server response to SSLRequest",
	}
}
```

- [ ] **Step 4: Run to verify pass**

Run: `odin test pgconn -vet -strict-style`
Expected: all PASS (existing 95 + 6 new).

- [ ] **Step 5: Full gate + commit**

Run: `odin test tests -all-packages -vet -strict-style` — PASS, then:

```bash
git add pgconn/tls.odin pgconn/tls_test.odin
git commit -m "feat(pgconn): SSL_Mode and SSLRequest negotiation core"
```

---

### Task 2: OpenSSL dynamic binding, probe, TLS transport

**Files:**
- Create: `pgconn/tls_openssl.odin`
- Modify: `pgconn/tls.odin` (add `tls_ensure_loaded`, `tls_probe_paths`, probe path lists)
- Modify: `pgconn/tls_test.odin` (probe tests)

**Interfaces:**
- Consumes: `dynlib.initialize_symbols`, `core:c`, `net.TCP_Socket`, Task 1 globals (`tls_mutex`, `tls_state`).
- Produces: `openssl: OpenSSL_API` global; `tls_ensure_loaded() -> bool`; `tls_probe_paths(paths: []string) -> bool`; `TLS_Transport_Data :: struct {ctx, ssl: rawptr, socket: net.TCP_Socket, read_timeout, write_timeout: time.Duration}`; `make_tls_transport(data: ^TLS_Transport_Data, socket: net.TCP_Socket, server_name: string) -> (Stream_Transport, pgerr.Error)`.

- [ ] **Step 1: Write failing probe tests (append to `pgconn/tls_test.odin`)**

```odin
@(test)
test_tls_probe_bogus_paths_graceful :: proc(t: ^testing.T) {
	bogus := []string{"libopg_no_such_tls.so.999", "libopg_also_missing.so"}
	testing.expect(t, !tls_probe_paths(bogus), "expected probe failure for bogus paths")
}

@(test)
test_tls_probe_real_openssl :: proc(t: ^testing.T) {
	// This machine has libssl.so.3 (development requires it; the driver
	// itself degrades gracefully without it).
	when ODIN_OS == .Linux {
		probe: OpenSSL_API
		ok := tls_probe_into(&probe, TLS_PROBE_PATHS)
		testing.expect(t, ok, "expected OpenSSL to load on Linux dev machine")
		testing.expect(t, probe.SSL_CTX_new != nil, "expected SSL_CTX_new bound")
		testing.expect(t, probe.SSL_connect != nil, "expected SSL_connect bound")
		testing.expect(t, probe.SSL_ctrl != nil, "expected SSL_ctrl bound")
	}
}
```

- [ ] **Step 2: Run to verify failure**

Run: `odin test pgconn -vet -strict-style`
Expected: compile error — `tls_probe_paths` / `OpenSSL_API` undefined.

- [ ] **Step 3: Implement `pgconn/tls_openssl.odin`**

```odin
package pgconn

// Dynamically-loaded OpenSSL 3 backend. No link-time dependency: symbols
// are bound at runtime with core:dynlib; absence degrades per SSL_Mode.

import "core:c"
import "core:dynlib"
import "core:net"
import "core:strings"
import "core:time"
import "../pgerr"

/*
	OpenSSL_API is bound by dynlib.initialize_symbols: each field name must
	exactly match an exported libssl symbol; the library handle lands in
	__handle. libssl.so.3 pulls libcrypto.so.3 in via its own dependencies.
*/
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
	SSL_write:         proc "c" (ssl: rawptr, data: rawptr, num: c.int) -> c.int,
	SSL_shutdown:      proc "c" (ssl: rawptr) -> c.int,
	SSL_get_error:     proc "c" (ssl: rawptr, ret: c.int) -> c.int,
	SSL_ctrl:          proc "c" (ssl: rawptr, cmd: c.int, larg: c.long, parg: rawptr) -> c.long,
}

// One proc-pointer field per libssl symbol; __handle is not a symbol.
TLS_SYMBOL_COUNT :: 12

SSL_CTRL_SET_TLSEXT_HOSTNAME :: 55
TLSEXT_NAMETYPE_host_name :: 0

SSL_ERROR_WANT_READ :: 2
SSL_ERROR_WANT_WRITE :: 3
SSL_ERROR_ZERO_RETURN :: 6

openssl: OpenSSL_API

/*
	tls_probe_into loads the first library from `paths` that binds every
	OpenSSL_API symbol. initialize_symbols reports ok on load even if some
	symbols are missing, so the bound-symbol count is checked too.
*/
tls_probe_into :: proc(api: ^OpenSSL_API, paths: []string) -> bool {
	for path in paths {
		count, ok := dynlib.initialize_symbols(api, path)
		if ok && count == TLS_SYMBOL_COUNT {
			return true
		}
		if ok {
			_ = dynlib.unload_library(api.__handle)
			api^ = {}
		}
	}
	return false
}

// TLS_Transport_Data is the concrete state for an OpenSSL-wrapped socket.
TLS_Transport_Data :: struct {
	ctx:           rawptr, // SSL_CTX*
	ssl:           rawptr, // SSL*
	socket:        net.TCP_Socket,
	read_timeout:  time.Duration,
	write_timeout: time.Duration,
}

/*
	make_tls_transport performs the client TLS handshake over an already
	connected socket and returns a Stream_Transport backed by OpenSSL.
	On failure everything created here is freed and the caller keeps
	ownership of the (still open) socket. Requires a successful probe.
*/
make_tls_transport :: proc(
	data: ^TLS_Transport_Data,
	socket: net.TCP_Socket,
	server_name: string,
) -> (
	transport: Stream_Transport,
	err: pgerr.Error,
) {
	ctx := openssl.SSL_CTX_new(openssl.TLS_client_method())
	if ctx == nil {
		return {}, pgerr.Net_Error{type = .TLS_Handshake_Failed}
	}
	ssl := openssl.SSL_new(ctx)
	if ssl == nil {
		openssl.SSL_CTX_free(ctx)
		return {}, pgerr.Net_Error{type = .TLS_Handshake_Failed}
	}

	if openssl.SSL_set_fd(ssl, c.int(socket)) != 1 {
		openssl.SSL_free(ssl)
		openssl.SSL_CTX_free(ctx)
		return {}, pgerr.Net_Error{type = .TLS_Handshake_Failed}
	}

	// SNI (SSL_set_tlsext_host_name is a macro over SSL_ctrl).
	if len(server_name) > 0 {
		host_c := strings.clone_to_cstring(server_name, context.temp_allocator)
		_ = openssl.SSL_ctrl(ssl, SSL_CTRL_SET_TLSEXT_HOSTNAME, TLSEXT_NAMETYPE_host_name, rawptr(host_c))
	}

	if openssl.SSL_connect(ssl) != 1 {
		openssl.SSL_free(ssl)
		openssl.SSL_CTX_free(ctx)
		return {}, pgerr.Net_Error{type = .TLS_Handshake_Failed}
	}

	data.ctx = ctx
	data.ssl = ssl
	data.socket = socket
	return Stream_Transport{
		data = data,
		read = tls_read,
		write = tls_write,
		close = tls_close,
		set_deadlines = tls_set_deadlines,
	}, nil
}

tls_read :: proc(transport: rawptr, buf: []byte) -> (bytes_read: int, err: pgerr.Error) {
	data := (^TLS_Transport_Data)(transport)
	if len(buf) == 0 {
		return 0, nil
	}
	for {
		ret := openssl.SSL_read(data.ssl, raw_data(buf), c.int(len(buf)))
		if ret > 0 {
			return int(ret), nil
		}
		code := openssl.SSL_get_error(data.ssl, ret)
		switch code {
		case SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE:
			continue // blocking fd: retry
		case SSL_ERROR_ZERO_RETURN:
			return 0, pgerr.Net_Error{type = .Socket_Closed}
		}
		return 0, pgerr.Net_Error{type = .Recv_Failed, code = i32(code)}
	}
}

tls_write :: proc(transport: rawptr, data_bytes: []byte) -> (bytes_written: int, err: pgerr.Error) {
	data := (^TLS_Transport_Data)(transport)
	total := 0
	for total < len(data_bytes) {
		remaining := data_bytes[total:]
		ret := openssl.SSL_write(data.ssl, raw_data(remaining), c.int(len(remaining)))
		if ret > 0 {
			total += int(ret)
			continue
		}
		code := openssl.SSL_get_error(data.ssl, ret)
		if code == SSL_ERROR_WANT_READ || code == SSL_ERROR_WANT_WRITE {
			continue // blocking fd: retry
		}
		if code == SSL_ERROR_ZERO_RETURN {
			return total, pgerr.Net_Error{type = .Socket_Closed}
		}
		return total, pgerr.Net_Error{type = .Send_Failed, code = i32(code)}
	}
	return total, nil
}

tls_close :: proc(transport: rawptr) {
	data := (^TLS_Transport_Data)(transport)
	if data.ssl != nil {
		_ = openssl.SSL_shutdown(data.ssl) // best-effort close_notify
		openssl.SSL_free(data.ssl)
		data.ssl = nil
	}
	if data.ctx != nil {
		openssl.SSL_CTX_free(data.ctx)
		data.ctx = nil
	}
	net.close(data.socket)
}

tls_set_deadlines :: proc(transport: rawptr, read_timeout, write_timeout: time.Duration) -> pgerr.Error {
	data := (^TLS_Transport_Data)(transport)
	data.read_timeout = read_timeout
	data.write_timeout = write_timeout
	// Note: OS-level socket timeout configuration can be hooked here (same
	// stub level as tcp_set_deadlines).
	return nil
}
```

- [ ] **Step 4: Add probe wiring to `pgconn/tls.odin`**

Append:

```odin
when ODIN_OS == .Linux {
	TLS_PROBE_PATHS :: []string{"libssl.so.3", "libssl.so", "libssl.so.1.1"}
} else when ODIN_OS == .Darwin {
	TLS_PROBE_PATHS :: []string{
		"libssl.3.dylib",
		"/opt/homebrew/opt/openssl@3/lib/libssl.3.dylib",
		"/usr/local/opt/openssl@3/lib/libssl.3.dylib",
	}
} else when ODIN_OS == .Windows {
	TLS_PROBE_PATHS :: []string{"libssl-3-x64.dll", "libssl-3.dll", "libssl-1_1-x64.dll"}
} else {
	TLS_PROBE_PATHS :: []string{}
}

/*
	tls_ensure_loaded probes the platform's OpenSSL library list exactly
	once per process and reports whether the backend is usable. Safe to
	call from any thread.
*/
tls_ensure_loaded :: proc() -> bool {
	sync.mutex_lock(&tls_mutex)
	defer sync.mutex_unlock(&tls_mutex)

	if tls_state == .Unprobed {
		tls_state = tls_probe_paths(TLS_PROBE_PATHS) ? .Loaded : .Unavailable
	}
	return tls_state == .Loaded
}

// tls_probe_paths probes into the process-global `openssl` table.
tls_probe_paths :: proc(paths: []string) -> bool {
	return tls_probe_into(&openssl, paths)
}
```

(Note: Odin has no `?:` ternary — use `if`/`else` assignment; the executor writes it as a plain `if`.)

- [ ] **Step 5: Run to verify pass**

Run: `odin test pgconn -vet -strict-style`
Expected: all PASS, including `test_tls_probe_real_openssl` binding 12 symbols from `libssl.so.3`.

- [ ] **Step 6: Full gate + commit**

Run: `odin test tests -all-packages -vet -strict-style` — PASS, then:

```bash
git add pgconn/tls.odin pgconn/tls_openssl.odin pgconn/tls_test.odin
git commit -m "feat(pgconn): dynamic OpenSSL probe and TLS stream transport"
```

---

### Task 3: `conn_connect` wiring + ssl-enabled test server + integration tests

**Files:**
- Modify: `pgconn/conn.odin` (`Conn_Config.ssl_mode`, `Conn.tls_data`, `conn_connect`)
- Create: `scripts/pg-certs/generate.sh`, `scripts/pg-certs/server.crt`, `scripts/pg-certs/server.key` (generated)
- Create: `scripts/pg-init/02-ssl.sh`
- Modify: `docker-compose.yml` (mount `./scripts/pg-certs:/opg-certs:ro`)
- Modify: `pgconn/integration_test.odin` (TLS tests)

**Interfaces:**
- Consumes: Task 1 `ssl_negotiate`, Task 2 `tls_ensure_loaded` + `make_tls_transport` + `TLS_Transport_Data`; `integration_conn_config`, `integration_connect` helpers.
- Produces: nothing new for later tasks.

- [ ] **Step 1: Write failing integration tests (append inside `when OPG_INTEGRATION`)**

```odin
	// ------------------------------------------------------------------------
	// TLS (OPG-205)
	// ------------------------------------------------------------------------

	/*
		integration_expect_ssl connects with the given mode and pins the
		wire state via pg_stat_ssl for the connection's own backend.
	*/
	integration_expect_ssl :: proc(t: ^testing.T, mode: SSL_Mode, expected: string) {
		cfg := integration_conn_config(t)
		cfg.ssl_mode = mode

		conn, err := conn_connect(cfg, context.allocator)
		testing.expectf(t, err == nil, "expected connect success (mode %v), got %v", mode, err)
		if conn == nil {
			return
		}
		defer integration_disconnect(conn)

		collector: Test_Query_Collector
		collector.allocator = context.allocator
		collector.rows = make([dynamic][dynamic]string, context.allocator)
		defer integration_collector_destroy(&collector)

		qerr := conn_query(conn, "SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid();", test_on_row, test_on_command, test_on_desc, &collector)
		testing.expectf(t, qerr == nil, "expected pg_stat_ssl query success, got %v", qerr)
		if len(collector.rows) == 1 && len(collector.rows[0]) == 1 {
			testing.expect_value(t, collector.rows[0][0], expected)
		} else {
			testing.fail_now(t, "expected exactly one row from pg_stat_ssl")
		}
	}

	@(test)
	test_integration_tls_require :: proc(t: ^testing.T) {
		integration_expect_ssl(t, .Require, "t")
	}

	@(test)
	test_integration_tls_prefer_default :: proc(t: ^testing.T) {
		// Zero value of SSL_Mode is Prefer: the default upgrades to TLS
		// against an ssl-enabled server.
		integration_expect_ssl(t, .Prefer, "t")
	}

	@(test)
	test_integration_tls_disable :: proc(t: ^testing.T) {
		integration_expect_ssl(t, .Disable, "f")
	}

	@(test)
	test_integration_tls_query_roundtrip :: proc(t: ^testing.T) {
		cfg := integration_conn_config(t)
		cfg.ssl_mode = .Require

		conn, err := conn_connect(cfg, context.allocator)
		testing.expectf(t, err == nil, "expected TLS connect success, got %v", err)
		if conn == nil {
			return
		}
		defer integration_disconnect(conn)

		collector: Test_Query_Collector
		collector.allocator = context.allocator
		collector.rows = make([dynamic][dynamic]string, context.allocator)
		defer integration_collector_destroy(&collector)

		qerr := conn_query(conn, "SELECT generate_series(1, 100);", test_on_row, test_on_command, test_on_desc, &collector)
		testing.expectf(t, qerr == nil, "expected TLS query success, got %v", qerr)
		testing.expect_value(t, len(collector.rows), 100)
		testing.expect_value(t, conn.status, Conn_Status.Ready)
	}
```

- [ ] **Step 2: Run to verify failure**

Run: `odin test pgconn -vet -strict-style -define:OPG_INTEGRATION=true -define:ODIN_TEST_NAMES=pgconn.test_integration_tls_require,pgconn.test_integration_tls_prefer_default,pgconn.test_integration_tls_disable,pgconn.test_integration_tls_query_roundtrip`
Expected: compile error — `Conn_Config` has no `ssl_mode` field.

- [ ] **Step 3: Wire `conn.odin`**

Add to `Conn_Config` (after `write_timeout`): `ssl_mode: SSL_Mode,`
Add to `Conn` (after `tcp_data`): `tls_data: TLS_Transport_Data,`

Replace the body of `conn_connect` between the dial and the handshake:

```odin
conn_connect :: proc(
	config: Conn_Config,
	allocator := context.allocator,
) -> (
	conn: ^Conn,
	err: pgerr.Error,
) {
	port := config.port
	if port <= 0 do port = 5432
	endpoint := fmt.tprintf("%s:%d", config.host, port)

	socket, nerr := net.dial_tcp_from_hostname_and_port_string(endpoint)
	if nerr != nil {
		return nil, pgerr.Net_Error{
			type = .Connection_Refused,
			raw_net_error = nerr,
		}
	}

	c := new(Conn, allocator)
	defer if err != nil {
		if c != nil {
			conn_close(c)
			free(c, allocator)
		}
	}

	transport := make_tcp_transport(&c.tcp_data, socket)

	// Pre-startup TLS negotiation (SSLRequest). On Wrap_TLS the socket is
	// handed to OpenSSL and the startup sequence runs over the encrypted
	// stream; the plaintext transport is discarded without closing.
	action, neg_err := ssl_negotiate(transport, config.ssl_mode, tls_ensure_loaded())
	if neg_err != nil {
		net.close(socket) // stream not initialized yet; close explicitly
		return nil, neg_err
	}
	if action == .Wrap_TLS {
		tls_transport, tls_err := make_tls_transport(&c.tls_data, socket, config.host)
		if tls_err != nil {
			net.close(socket)
			return nil, tls_err
		}
		transport = tls_transport
	}

	return conn_handshake(c, config, transport, allocator)
}
```

- [ ] **Step 4: Generate and commit test certificates**

Create `scripts/pg-certs/generate.sh`:

```bash
#!/usr/bin/env bash
# Regenerates the committed self-signed TEST certificate for the docker
# compose PostgreSQL. This key is intentionally public test material -
# never use it anywhere real.
set -euo pipefail
cd "$(dirname "$0")"
openssl req -x509 -newkey rsa:2048 -nodes -days 36500 \
	-keyout server.key -out server.crt \
	-subj "/CN=localhost" \
	-addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
```

Run: `chmod +x scripts/pg-certs/generate.sh && ./scripts/pg-certs/generate.sh`

Create `scripts/pg-init/02-ssl.sh`:

```bash
#!/bin/bash
# Enables TLS on the test server using the committed self-signed cert.
# Runs at initdb time as the postgres user; the settings take effect when
# the entrypoint starts the real server.
set -e
cp /opg-certs/server.crt /opg-certs/server.key "$PGDATA/"
chmod 600 "$PGDATA/server.key"
cat >> "$PGDATA/postgresql.conf" <<-EOF
	ssl = on
	ssl_cert_file = 'server.crt'
	ssl_key_file = 'server.key'
EOF
```

Run: `chmod +x scripts/pg-init/02-ssl.sh`

In `docker-compose.yml`, extend `volumes`:

```yaml
    volumes:
      # Creates the opg_clear (cleartext) and opg_md5 (md5) auth-scenario
      # users and their pg_hba rules at initdb time.
      - ./scripts/pg-init:/docker-entrypoint-initdb.d:ro
      # Self-signed TEST certificate for ssl=on (see scripts/pg-init/02-ssl.sh).
      - ./scripts/pg-certs:/opg-certs:ro
```

- [ ] **Step 5: Recreate server, run TLS tests**

Run: `docker compose down`, then:
`odin test pgconn -vet -strict-style -define:OPG_INTEGRATION=true -define:ODIN_TEST_NAMES=pgconn.test_integration_tls_require,pgconn.test_integration_tls_prefer_default,pgconn.test_integration_tls_disable,pgconn.test_integration_tls_query_roundtrip`
Expected: 4 PASS.

- [ ] **Step 6: Full suites (everything now runs over TLS by default)**

Run: `odin test pgconn -vet -strict-style -define:OPG_INTEGRATION=true` (all integration tests, now TLS-upgraded via Prefer default) and `odin test tests -all-packages -vet -strict-style` (offline, no behavior change — mock transports bypass negotiation).
Expected: both PASS, zero leaks.

- [ ] **Step 7: Commit**

```bash
git add pgconn/conn.odin pgconn/integration_test.odin docker-compose.yml scripts/pg-certs scripts/pg-init/02-ssl.sh
git commit -m "feat(pgconn): TLS negotiation in conn_connect and ssl-enabled test server"
```

---

### Task 4: Sanitizers, audit, JIRA amendment, merge

**Files:**
- Modify: `docs/pgconn-coverage-audit.md`
- Modify: `JIRA.md` (OPG-205 entry)

- [ ] **Step 1: Sanitizer runs**

`odin test pgconn -define:OPG_INTEGRATION=true -sanitize:thread` — zero `WARNING: ThreadSanitizer`.
`odin test pgconn -define:OPG_INTEGRATION=true -sanitize:address` — zero AddressSanitizer reports.
(Now exercises OpenSSL handshakes on every integration connect.)

- [ ] **Step 2: Update `docs/pgconn-coverage-audit.md`**

- New section "tls.odin / tls_openssl.odin" mapping: `ssl_negotiate` truth table → the six `test_ssl_negotiate_*` unit tests; probe → `test_tls_probe_bogus_paths_graceful` / `test_tls_probe_real_openssl`; `make_tls_transport` + `tls_read`/`tls_write`/`tls_close` → the four `test_integration_tls_*` tests plus every TLS-upgraded integration test.
- Remove "TLS negotiation — deferred with OPG-205" from *Intentionally uncovered*; add: "Native Schannel/SecureTransport backends — deferred (OpenSSL-only per 2026-08-15 decision)" and "`tls_set_deadlines` OS-level timeouts — same stub level as `tcp_set_deadlines`".
- Update test counts.

- [ ] **Step 3: Amend JIRA.md OPG-205 entry**

Status `- [x] **Status**: Done`; files list → `pgconn/tls.odin`, `pgconn/tls_openssl.odin`, `pgconn/tls_test.odin`; description notes OpenSSL-backend-only decision with native OS backends deferred; acceptance criteria: graceful absence (✓ probe failure honors mode semantics), wraps `core:net.TCP_Socket` in TLS stream (✓), `disable`/`prefer`/`require` with `Prefer` default, wire-pinned via `pg_stat_ssl`.

- [ ] **Step 4: Final gates + merge**

```bash
./scripts/integration-test.sh                      # PASS
odin test tests -all-packages -vet -strict-style   # PASS
git add docs/pgconn-coverage-audit.md JIRA.md docs/superpowers/plans/2026-08-15-opg-205-dynamic-tls.md
git commit -m "feat(pgconn): complete OPG-205 dynamic TLS and mark task done in JIRA"
git checkout main
git merge opg-205-dynamic-tls
git branch -d opg-205-dynamic-tls
./scripts/integration-test.sh                      # green gate on merged main
```

---

## Self-Review Notes

- **Spec coverage:** §2 API → Task 3; §3 binding → Task 2; §4 probe → Task 2; §5 transport → Task 2; §6 negotiation + truth table → Task 1 (all seven rows tested); §7 server → Task 3 Step 4; §8 tests → Tasks 1–4; §9 JIRA → Task 4.
- **Type consistency:** `ssl_negotiate(transport, mode, tls_loadable)` identical in Task 1 impl and Task 3 call site; `make_tls_transport(data, socket, server_name)` identical in Task 2 impl and Task 3 call site; `tls_probe_into(&probe, TLS_PROBE_PATHS)` used in Task 2 test matches Task 2 impl.
- **Known risks called out to the executor:** Odin has no ternary — `tls_ensure_loaded` must use plain `if`; `[]string` constant with `::` may need `TLS_PROBE_PATHS := []string{...}` (global slice literal) if the compiler rejects a constant slice — either form is acceptable; if `initialize_symbols`'s temp-allocator default interacts badly with `-vet`, pass `context.temp_allocator` explicitly.
