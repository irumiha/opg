# opg – Pure-Odin PostgreSQL Database Driver

**opg** is a high-performance, pure-Odin PostgreSQL database driver implemented natively from scratch over TCP following the **PostgreSQL Frontend/Backend Protocol 3.0**.

It has **zero link-time C dependencies** (strictly no `libpq`) and dynamically loads platform-native TLS backends at runtime via `core:dynlib`.

---

## Key Features

- **Pure Odin Wire Protocol**: Native serialization and deserialization of the PostgreSQL 3.0 wire protocol in Network Byte Order (Big-Endian).
- **Multi-Platform Dynamic TLS**: Dynamically probes and loads OS-native cryptographic libraries at runtime:
  - **Windows**: Windows SSPI **Schannel** (`secur32.dll` / `sspicli.dll`)
  - **macOS (Darwin)**: Apple Security Framework **SecureTransport** (`Security.framework`)
  - **Linux / POSIX**: **OpenSSL** 3.x / 1.1 (`libssl.so.3` / `libssl.so`)
- **Thread-Safe Connection Pooling**: Concurrent connection leasing, min/max limits, health checks, max lifetime, and idle reclamation.
- **ORM & Reflection Data Mapping**: Seamless mapping from PostgreSQL `DataRow` messages directly into Odin structs (`core:reflect`), including nested structures, slices, timestamps, and nullable fields via `Maybe(T)`.
- **Streaming Row Consumption**: Low-memory streaming API (`query_stream`) capable of processing millions of rows without loading entire result sets into RAM.
- **ACID Transactions & Savepoints**: Comprehensive transaction lifecycle management with configurable isolation levels (`Read Committed`, `Repeatable Read`, `Serializable`), read-only modes, and nested savepoints.
- **Strict Allocator Boundaries**: Zero-allocation or temporary allocator (`context.temp_allocator`) guarantees on transient parsing; zero memory leaks verified via `core:mem.Tracking_Allocator`.
- **Tagged Union Error Handling**: Expressive, strongly typed tagged union errors (`pgerr.Error`) for network, protocol, authentication, database server (SQLSTATE), and pool failures.

---

## Architecture Overview

```
+-----------------------------------------------------------------------+
|                              opg (Root)                               |
|       Unified ergonomic facade: connect, pool, query, transactions    |
+-----------------------------------+-----------------------------------+
                                    |
         +--------------------------+--------------------------+
         |                                                     |
+--------v----------------------+             +----------------v--------+
|            pgmap              |             |            pgconn       |
|  Reflection, struct mapping,  |             |  TCP/TLS Transport,     |
|  parameter encoding/decoding  |             |  Connection Pools, Auth |
+--------+----------------------+             +----------------+--------+
         |                                                     |
         +--------------------------+--------------------------+
                                    |
                        +-----------v-----------+
                        |        pgproto        |
                        | Pure wire codec       |
                        | (Big-endian, packets) |
                        +-----------+-----------+
                                    |
                        +-----------v-----------+
                        |         pgerr         |
                        | Tagged Union Errors   |
                        +-----------------------+
```

---

## Installation & Import

Import the root package in your Odin project:

```odin
import "opg"
```

Subpackages can also be used directly if finer-grained control is desired:
- `opg:pgconn` — Connection management, transport streams, and pooling.
- `opg:pgmap` — Reflection and data mapping utilities.
- `opg:pgproto` — Wire protocol packet codec.
- `opg:pgerr` — Tagged union error definitions.

---

## Quick Start Example

```odin
package main

import "core:fmt"
import "core:time"
import "opg"

User :: struct {
	id:         i64,
	username:   string,
	is_active:  bool,
	created_at: time.Time,
}

main :: proc() {
	// 1. Connect to PostgreSQL
	conn, err := opg.connect({
		host     = "127.0.0.1",
		port     = 5432,
		user     = "postgres",
		password = "secretpassword",
		database = "mydb",
		ssl_mode = .Prefer,
	})
	if err != nil {
		fmt.eprintln("Connection error:", err)
		return
	}
	defer opg.disconnect(conn)

	// 2. Execute DDL
	opg.exec(conn, `
		CREATE TABLE IF NOT EXISTS users (
			id BIGSERIAL PRIMARY KEY,
			username TEXT NOT NULL,
			is_active BOOLEAN NOT NULL DEFAULT true,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		);
	`)

	// 3. Insert records with parameterized arguments
	opg.exec(conn, "INSERT INTO users (username, is_active) VALUES ($1, $2);", "alice", true)
	opg.exec(conn, "INSERT INTO users (username, is_active) VALUES ($1, $2);", "bob", false)

	// 4. Query a single row into an Odin struct
	user, qerr := opg.query_struct(conn, User, "SELECT id, username, is_active, created_at FROM users WHERE username = $1;", "alice")
	if qerr != nil {
		fmt.eprintln("Query error:", qerr)
		return
	}
	fmt.println("User:", user.username, "Active:", user.is_active, "Created:", user.created_at)

	// 5. Query multiple rows into a slice of structs
	users, sl_err := opg.query_slice(conn, User, "SELECT id, username, is_active, created_at FROM users ORDER BY id ASC;")
	if sl_err == nil {
		for u in users {
			fmt.printf("ID: %v, Name: %s, Active: %v\n", u.id, u.username, u.is_active)
		}
	}
}
```

---

## Detailed Usage Guide

### 1. Connecting & Configuration

Establish a single connection with `opg.connect`:

```odin
config := opg.Conn_Config {
	host             = "127.0.0.1",
	port             = 5432,
	user             = "postgres",
	password         = "secretpassword",
	database         = "mydb",
	application_name = "my_odin_app",
	connect_timeout  = 10 * time.Second,
	read_timeout     = 30 * time.Second,
	write_timeout    = 30 * time.Second,
	ssl_mode         = .Prefer, // .Prefer, .Disable, or .Require
}

conn, err := opg.connect(config)
if err != nil {
	// Inspect typed error
	#partial switch e in err {
	case opg.Net_Error:
		fmt.eprintln("Network error:", e.type)
	case opg.Auth_Error:
		fmt.eprintln("Authentication failed:", e.message)
	case opg.Postgres_Error:
		fmt.eprintln("Postgres SQLSTATE:", e.code, "Message:", e.message)
	}
	return
}
defer opg.disconnect(conn)
```

#### SSL Modes
- `.Prefer` *(default)*: Sends an `SSLRequest` packet. If the server accepts and a TLS library is available, wraps the connection in TLS. Otherwise, falls back to unencrypted TCP.
- `.Disable`: Plaintext TCP only; no TLS negotiation is attempted.
- `.Require`: Requires TLS encryption. If the server refuses or no TLS backend can be loaded, connection fails with `Net_Error{.TLS_Handshake_Failed}`.

---

### 2. Connection Pooling

For multi-threaded services and web servers, use `opg.pool_create`:

```odin
pool_cfg := opg.Pool_Config {
	conn_config  = config,
	min_conns    = 2,              // Minimum idle connections kept warm
	max_conns    = 20,             // Maximum concurrent connections
	idle_timeout = 5 * time.Minute, // Close idle connections after duration
	max_lifetime = 1 * time.Hour,   // Recycle connections after lifetime
}

pool, err := opg.pool_create(pool_cfg)
if err != nil {
	fmt.eprintln("Pool initialization failed:", err)
	return
}
defer opg.pool_destroy(pool)

// Acquire a connection for a task
conn, acq_err := opg.pool_acquire(pool, 5 * time.Second)
if acq_err != nil {
	fmt.eprintln("Pool acquisition timed out:", acq_err)
	return
}
defer opg.pool_release(pool, conn)

// Use conn normally...
```

---

### 3. Query Parameter Bindings

`opg` uses PostgreSQL extended query protocol parameters (`$1, $2, ...`) which protect against SQL injection and automatically convert Odin native types to PostgreSQL wire formats:

| Odin Type | PostgreSQL Type | Example Binding |
|---|---|---|
| `i8`, `i16`, `i32`, `i64`, `int` | `INT2`, `INT4`, `INT8` | `42`, `i64(1000)` |
| `u8`, `u16`, `u32`, `u64`, `uint`| `INT2`, `INT4`, `INT8` | `u32(100)` |
| `f32`, `f64` | `FLOAT4`, `FLOAT8`, `NUMERIC` | `3.14159` |
| `bool` | `BOOLEAN` | `true`, `false` |
| `string` | `TEXT`, `VARCHAR` | `"hello world"` |
| `[]byte` | `BYTEA` | `[]byte{0xDE, 0xAD, 0xBE, 0xEF}` |
| `time.Time` | `TIMESTAMP`, `TIMESTAMPTZ`, `DATE` | `time.now()` |
| `Maybe(T)` | `NULL` or typed value | `Maybe(string)("optional")`, `Maybe(int)(nil)` |
| `^T` / `rawptr` | `NULL` or dereferenced value | `nil` $\rightarrow$ `SQL NULL` |
| `[]T` (Slices) | `INT[]`, `TEXT[]`, `FLOAT8[]` | `[]int{1, 2, 3}`, `[]string{"a", "b"}` |

#### Parameterized Example:
```odin
opg.exec(conn, `
	INSERT INTO events (
		title,
		tags,
		scores,
		payload,
		scheduled_at,
		notes
	) VALUES ($1, $2, $3, $4, $5, $6);
`,
	"Conference 2026",
	[]string{"tech", "database", "odin"},
	[]f64{9.8, 8.5, 9.2},
	[]byte{0x01, 0x02, 0x03},
	time.now(),
	Maybe(string)(nil), // Inserts SQL NULL
)
```

---

### 4. Struct Reflection & Data Mapping

`opg.query_struct` and `opg.query_slice` use compile-time type reflection to map SQL column names to Odin struct fields:

```odin
Post :: struct {
	id:           i64,
	title:        string,
	author_id:    i32,
	tags:         []string,       // Mapped from TEXT[]
	is_published: bool,
	published_at: Maybe(time.Time), // NULL in DB becomes nil in Maybe
}

// Fetch a single row (errors with Protocol_Error{.No_Data} if 0 rows returned)
post, err := opg.query_struct(conn, Post, "SELECT * FROM posts WHERE id = $1;", 10)

// Fetch all rows into a slice
posts, err := opg.query_slice(conn, Post, "SELECT * FROM posts WHERE is_published = $1 ORDER BY id DESC;", true)
```

#### Field Naming Conventions:
- Columns in SQL match struct fields case-insensitively and support `snake_case` $\leftrightarrow$ `camelCase` / `PascalCase` mapping automatically.
- Unmatched struct fields or extra SQL columns are gracefully ignored.

---

### 5. Fetching All Rows vs. Streaming Large Datasets

#### In-Memory (`query_slice`)
Use `opg.query_slice` for small to medium query results where having the entire slice in memory is convenient:
```odin
users, err := opg.query_slice(conn, User, "SELECT * FROM users LIMIT 100;")
```

#### Streaming API (`query_stream`)
For large result sets (e.g. streaming 100,000+ rows, exporting CSVs, or processing large tables), use `opg.query_stream`. Rows are processed incrementally as TCP packets arrive from the network, with constant memory overhead:

```odin
Stream_State :: struct {
	row_count: int,
	total_val: i64,
}

on_each_row :: proc(user_data: rawptr, row: pgproto.Msg_Data_Row) -> bool {
	state := (^Stream_State)(user_data)
	state.row_count += 1

	if len(row.values) > 0 && !row.values[0].is_null {
		// Read column value directly from zero-copy wire bytes
		val, _ := strconv.parse_i64(string(row.values[0].data))
		state.total_val += val
	}

	return true // Return false to abort streaming early
}

state: Stream_State
err := opg.query_stream(
	conn      = conn,
	sql       = "SELECT generate_series(1, 1000000) AS num;",
	on_row    = on_each_row,
	user_data = &state,
)
fmt.printf("Processed %v rows, total: %v\n", state.row_count, state.total_val)
```

---

### 6. Transactions & Savepoints

Transactions provide ACID guarantees and can be rolled back safely using Odin's `defer` statement:

```odin
// Begin a transaction
tx, err := opg.begin_transaction(conn, {
	isolation = .Serializable,
	access    = .Read_Write,
})
if err != nil do return err
defer opg.tx_rollback(&tx) // Safe & idempotent: no-op if tx_commit succeeds!

// Execute operations inside the transaction
opg.tx_exec(&tx, "UPDATE accounts SET balance = balance - $1 WHERE id = $2;", 50, 1) or_return
opg.tx_exec(&tx, "UPDATE accounts SET balance = balance + $1 WHERE id = $2;", 50, 2) or_return

// Commit the transaction
err = opg.tx_commit(&tx)
```

#### Savepoint Example:
```odin
tx, _ := opg.begin_transaction(conn)
defer opg.tx_rollback(&tx)

opg.tx_exec(&tx, "INSERT INTO logs (entry) VALUES ($1);", "Step 1") or_return

// Create a savepoint
opg.tx_savepoint(&tx, "sp1") or_return

// Attempt an operation
_, try_err := opg.tx_exec(&tx, "INSERT INTO risky_table (val) VALUES ($1);", "invalid")
if try_err != nil {
	// Rollback only the failed operation; parent transaction remains intact!
	opg.tx_rollback_to_savepoint(&tx, "sp1") or_return
} else {
	opg.tx_release_savepoint(&tx, "sp1") or_return
}

opg.tx_exec(&tx, "INSERT INTO logs (entry) VALUES ($1);", "Step 2") or_return
opg.tx_commit(&tx)
```

---

### 7. Multi-Platform Dynamic TLS

`opg` dynamically probes for installed cryptographic libraries when TLS is requested (`.Prefer` or `.Require`):

```odin
// Query which TLS backend was loaded on the current machine
backend_type := opg.tls_backend_type() // .Schannel, .SecureTransport, .OpenSSL, or .None
backend_name := opg.tls_backend_name() // "Schannel", "SecureTransport", "OpenSSL", or "none"

fmt.println("Active TLS Backend:", backend_name)
```

- **Windows**: Loads `secur32.dll` / `sspicli.dll` and uses Microsoft Schannel SSPI.
- **macOS**: Loads `Security.framework` and uses Apple SecureTransport.
- **Linux**: Loads `libssl.so.3` / `libssl.so.1.1` and uses OpenSSL.

If no TLS library is present on the host system:
- `ssl_mode = .Prefer` gracefully proceeds with unencrypted TCP.
- `ssl_mode = .Require` returns `Net_Error{.TLS_Handshake_Failed}`.

---

### 8. Advanced Row Streaming Examples

When using `opg.query_stream` for high-throughput streaming, you can decode multi-column rows in two ways:

#### Option A: Automatic Struct Mapping via `pgmap.map_row_to_struct`
Combine `on_desc` (which receives column names and metadata) with `on_row` to automatically map each row into an Odin struct using reflection:

```odin
package main

import "core:fmt"
import "core:time"
import "opg"
import "opg:pgmap"
import "opg:pgproto"

User :: struct {
	id:         i64,
	name:       string,
	email:      Maybe(string),
	score:      f64 `db:"points"`,
	is_active:  bool,
	created_at: time.Time,
}

Stream_Context :: struct {
	desc:       pgproto.Msg_Row_Description,
	users_seen: int,
}

// 1. Capture column metadata (column names, OIDs, formats)
on_desc :: proc(user_data: rawptr, desc: pgproto.Msg_Row_Description) {
	ctx := (^Stream_Context)(user_data)
	ctx.desc = desc
}

// 2. Map each incoming row directly into the struct
on_row :: proc(user_data: rawptr, row: pgproto.Msg_Data_Row) -> (proceed: bool) {
	ctx := (^Stream_Context)(user_data)

	// Automatically maps fields by name and `db:"..."` struct tags
	user, err := pgmap.map_row_to_struct(User, ctx.desc, row, context.temp_allocator)
	if err != nil {
		fmt.eprintln("Mapping error:", err)
		return false // Abort streaming on error
	}

	ctx.users_seen += 1
	fmt.printf(
		"[%d] User #%v: name=%q, email=%v, score=%.2f, active=%v\n",
		ctx.users_seen,
		user.id,
		user.name,
		user.email,
		user.score,
		user.is_active,
	)

	return true // Continue streaming next row
}

main :: proc() {
	conn, _ := opg.connect(...)
	defer opg.disconnect(conn)

	ctx: Stream_Context
	err := opg.query_stream(
		conn      = conn,
		sql       = "SELECT id, name, email, points, is_active, created_at FROM users;",
		on_row    = on_row,
		on_desc   = on_desc,
		user_data = &ctx,
	)
	if err != nil {
		fmt.eprintln("Query error:", err)
	}
}
```

#### Option B: Direct Zero-Copy Column Decoding
For maximum execution speed without reflection overhead, read positional columns directly from `row.values`:

```odin
package main

import "core:fmt"
import "core:strconv"
import "opg"
import "opg:pgproto"

on_row_manual :: proc(user_data: rawptr, row: pgproto.Msg_Data_Row) -> bool {
	if len(row.values) < 4 do return false

	// Column 0: id (INT8 / text) -> i64
	id: i64
	if !row.values[0].is_null {
		id, _ = strconv.parse_i64(string(row.values[0].data))
	}

	// Column 1: name (TEXT / text) -> string (zero-copy view)
	name: string
	if !row.values[1].is_null {
		name = string(row.values[1].data)
	}

	// Column 2: email (Nullable TEXT) -> Maybe(string)
	email: Maybe(string) = nil
	if !row.values[2].is_null {
		email = string(row.values[2].data)
	}

	// Column 3: score (FLOAT8 / text) -> f64
	score: f64
	if !row.values[3].is_null {
		score, _ = strconv.parse_f64(string(row.values[3].data))
	}

	fmt.printf("Manual row: id=%v, name=%q, email=%v, score=%v\n", id, name, email, score)
	return true
}
```

---

## Testing & Verification

### Running Unit Tests (Zero-Network)
All unit tests run offline without requiring a database:

```bash
odin test tests -all-packages -vet -strict-style
```

### Running Integration Tests Locally
The integration test suite can be run using either the automated Docker Compose harness or an existing PostgreSQL instance:

#### Option A: Docker Compose (Default)
When `PGHOST` is unset, `scripts/integration-test.sh` automatically starts a PostgreSQL 17 container with TLS certificates and authentication test scenarios:

```bash
# Standard integration tests
scripts/integration-test.sh

# Integration tests with AddressSanitizer (leak detection)
scripts/integration-test.sh --asan

# Pool concurrency stress tests with ThreadSanitizer (data race detection)
scripts/integration-test.sh --tsan

# Run all test suites and sanitizers
scripts/integration-test.sh --all
```

#### Option B: External or Native PostgreSQL Instance
If `PGHOST` is set, test scripts and harnesses bypass Docker and connect directly to the specified PostgreSQL instance:

```bash
PGHOST=127.0.0.1 PGPORT=5432 PGUSER=opg PGPASSWORD=opg PGDATABASE=opg_test \
  odin test tests -all-packages -vet -strict-style -define:OPG_INTEGRATION=true
```

### Multi-OS Continuous Integration (GitHub Actions)
Every commit and pull request is validated across a 3-platform matrix (**Ubuntu**, **macOS**, **Windows**):

1. **Offline Gate**: Strict compilation check (`odin check . -no-entry-point -vet -strict-style`) and zero-network unit test validation on all 3 operating systems.
2. **Multi-OS Integration Matrix**: Automated native PostgreSQL 17 provisioning with SSL enabled via `ikalnytskyi/action-setup-postgres@v8` on Linux, macOS, and Windows runners. `scripts/ci-setup-postgres.sh` configures test authentication roles (`opg_clear`, `opg_md5`).
3. **Platform-Native TLS Verification**: Live integration tests exercise each OS's native cryptographic backend over TLS:
   - **Linux**: OpenSSL 3.x (`libssl.so.3`)
   - **macOS**: Apple SecureTransport (`Security.framework`)
   - **Windows**: Microsoft SSPI Schannel (`secur32.dll` / `sspicli.dll`)
4. **Sanitizers**: Linux CI runs AddressSanitizer (`-sanitize:address`) for memory safety and ThreadSanitizer (`-sanitize:thread`) on `pgconn` for connection pool concurrency and race detection.

---

## License

MIT License. See [LICENSE](LICENSE) for details.
