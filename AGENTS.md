# AGENTS.md – Project Guidelines & Developer Manual

Welcome to **opg** — a high-performance, pure-Odin PostgreSQL database driver implemented from scratch directly over TCP following the **PostgreSQL Frontend/Backend Protocol 3.0**.

---

## 1. Core Architectural Principles

1. **Native Wire Protocol & Dynamic TLS Loading via `core:dynlib` (No `libpq`)**:
   - Strictly **no** `libpq`. The PostgreSQL Frontend/Backend Protocol 3.0 is implemented natively from scratch over TCP.
   - Wire protocol serialization (`pgproto`), connection pooling (`pgconn`), and data mapping (`pgorm`) are written natively in Odin.
   - **TLS Strategy (Dynamic Runtime Probing)**:
     - The driver does not statically link external TLS libraries.
     - If TLS is required, the driver utilizes Odin's `core:dynlib` to probe for the presence of **OpenSSL** (`libssl` / `libcrypto`) and dynamically loads symbol hooks if available.
     - If loading OpenSSL fails, it falls back to probing and loading **mbedTLS** (`libmbedtls` / `libmbedcrypto`).
     - If both probes fail, TLS encrypted connections become unavailable (returning an explicit `Net_Error` / `Auth_Error`), while standard unencrypted TCP connections continue to operate normally. (Note: TLS implementation is deferred to later milestones).

2. **3-Layer Separation of Concerns**:
   - `pgproto/`: Pure data-transformation layer. Encodes and decodes PostgreSQL wire messages (`[]byte` $\leftrightarrow$ Odin structs). Agnostic to sockets, files, or network I/O.
   - `pgconn/`: Transport & Connection management layer. Utilizes `core:net` and `core:nbio` to manage TCP connections, state machines, TLS negotiation, and thread-safe connection pooling.
   - `pgorm/`: High-level data mapping layer. Utilizes `core:reflect` to seamlessly map PostgreSQL `DataRow` messages into user-defined Odin structs and basic types.

3. **Mandatory Big-Endian Byte Swapping**:
   - The PostgreSQL wire protocol operates strictly in **Network Byte Order (Big-Endian)**.
   - **NEVER** use raw `transmute` on numeric wire bytes.
   - **ALWAYS** use `core:encoding/endian` (e.g., `endian.get_i16(buf, .Big)`, `endian.get_i32(buf, .Big)`, `endian.put_i32(buf, .Big, val)`) for all packet lengths, OIDs, counts, and numeric payloads.

4. **Strict Allocator Boundaries**:
   - `pgproto` and `pgorm`: Transient parsing must strictly use `allocator := context.temp_allocator`. Never leak memory onto the heap during row parsing.
   - `pgconn`: Persistent states (socket handles, connection pools, prepared statement caches, type metadata caches) must use a persistent allocator (`context.allocator` or a dedicated custom arena).

5. **Tagged Union Error Handling**:
   - **NEVER** return raw booleans or generic error strings.
   - All errors must be modeled in the overarching tagged union `Error` defined in `root.odin`:
     - `Net_Error`: Sockets, timeouts, disconnections, DNS resolution failures.
     - `Protocol_Error`: Malformed byte packets, invalid lengths, buffer underflows, unsupported protocol versions.
     - `Auth_Error`: SCRAM-SHA-256 validation errors, signature mismatches, bad credentials.
     - `Postgres_Error`: Server-side SQLSTATE errors and message fields (`ErrorResponse`).

---

## 2. Protocol Authority & Specification Compliance

- **Single Source of Truth**: The [PostgreSQL Frontend/Backend Protocol 3.0 Specification](https://www.postgresql.org/docs/current/protocol.html) is the definitive authority.
- **Rule of Precedence**: The Protocol Specification wins over assumptions or personal conventions.
- **Ambiguity Escalation**: Agents must only ask the user for clarification when the specification itself is genuinely ambiguous or when there is a direct conflict between user requirements and protocol safety. Otherwise, follow the specification faithfully.

---

## 3. Odin Idioms & Coding Style

All code written in this repository must conform to standard Odin practices and pass strict compiler checks (`-vet`, `-strict-style`):

### Naming Conventions
- **Types / Structs / Enums / Unions**: `Pascal_Case` (e.g., `Backend_Message_Type`, `Field_Description`, `Pool_Config`, `Net_Error`).
- **Procedures & Variables**: `snake_case` (e.g., `parse_message`, `pool_acquire`, `map_row_to_struct`, `bytes_consumed`).
- **Constants**: `ALL_CAPS` or `Pascal_Case` (e.g., `DEFAULT_PORT :: 5432`, `MAX_PACKET_SIZE :: 1024 * 1024`).
- **Package Names**: Short, lower-case single words (e.g., `opg`, `pgproto`, `pgconn`, `pgorm`).

### Idiomatic Practices
- **Error Propagation**: Use Odin's `or_return` idiom with tagged union returns.
  ```odin
  len_i32 := endian.get_i32(data[1:5], .Big) or_return
  ```
- **Trailing Commas**: Always include trailing commas in multi-line struct literals, enums, unions, and argument lists.
- **Tabs for Indentation**: Use real tabs (`\t`) for indentation, spaces for alignment.
- **No `using` Statements**: Avoid `using` on procedure parameters or as statements (`-vet-using-stmt`, `-vet-using-param`).
- **Explicit Allocator Parameters**: Procedures allocating memory must accept an explicit `allocator := context.temp_allocator` or `allocator := context.allocator` parameter.

---

## 4. Testing & Test-Driven Development (TDD)

### TDD Workflow Mandate
1. **Red**: Before implementing any feature or parser branch, write a failing unit test with corresponding test fixtures or byte vectors.
2. **Green**: Write the minimal, cleanest code required to make the test pass.
3. **Refactor**: Clean up the implementation, optimize memory layouts, verify no allocations leak, and confirm style compliance.

### Test Coverage Requirements
- **$\ge$ 95% Line Coverage** and **$\ge$ 95% Branch Coverage** individually across all packages.
- Every protocol message variant, error path, truncated packet edge case, and NULL column condition must have explicit test coverage.

### Test Strategy by Layer
1. **`pgproto` (Wire Codec Tests)**:
   - **Zero-Network Unit Tests**: Must run entirely without a database.
   - Use golden binary files in `pgproto/tests_golden_files/` (e.g., `ready_for_query_idle.bin`, `auth_ok.bin`, `row_description.bin`) to verify bit-accurate parsing and serialization.
2. **`pgconn` (Connection & Pool Tests)**:
   - Mocked socket / loopback tests and integration tests against a live PostgreSQL instance (configured via `PGHOST`, `PGPORT`, `PGUSER`, `PGPASSWORD`, `PGDATABASE`).
3. **`pgorm` (Reflection Tests)**:
   - Reflection unit tests verifying mapping from synthetic `DataRow` messages into various Odin structs (nested structs, arrays, primitive types, nullable fields).

---

## 5. Odin Development, Testing & Debugging Tooling

### Semantic Checking & Compilation
```bash
# Check entire module without requiring an entrypoint
odin check . -no-entry-point

# Check individual subpackages
odin check pgproto -no-entry-point
odin check pgconn -no-entry-point
odin check pgorm -no-entry-point
```

### Running Tests
```bash
# Run all tests across all packages
odin test . -all-packages

# Run tests with strict style and linter vetting
odin test . -all-packages -vet -strict-style

# Run tests for a specific subpackage
odin test pgproto

# Keep test executable for external inspection
odin test . -keep-executable -out:build/tests.bin
```

### Memory Tracking & Leak Detection
All tests should utilize `core:mem.Tracking_Allocator` to ensure zero memory leaks:
```odin
import "core:mem"
import "core:testing"

@(test)
test_parser_no_leaks :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	// Execute parser or pool procedures...

	testing.expect_value(t, len(track.allocation_map), 0)
	for _, leak in track.allocation_map {
		testing.errorf(t, "Memory leak: %v bytes at %v", leak.size, leak.location)
	}
}
```

### Sanitizers
Detect memory corruption, data races, and out-of-bounds access:
```bash
# Address Sanitizer (ASan)
odin test . -all-packages -sanitize:address

# Thread Sanitizer (TSan) for pool concurrency testing
odin test pgconn -sanitize:thread
```

### Debugging with GDB / LLDB
Compile with debug symbols (`-debug`):
```bash
# Build test binary with debug symbols
odin test pgproto -debug -out:debug_test.bin

# Debug with LLDB
lldb ./debug_test.bin
(lldb) breakpoint set --file parser.odin --line 150
(lldb) run

# Debug with GDB
gdb ./debug_test.bin
(gdb) break pgproto/parser.odin:150
(gdb) run
```
