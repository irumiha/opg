package opg

/*
	opg – Pure-Odin PostgreSQL Database Driver (Protocol 3.0)

	opg is a high-performance, pure-Odin PostgreSQL database driver implemented
	from scratch directly over TCP following the PostgreSQL Frontend/Backend
	Protocol 3.0. It requires strictly no libpq or external C library link-time
	dependencies.

	Architecture (3-Layer Separation of Concerns):
	  1. pgproto: Pure wire-protocol data transformation (Odin structs <-> []byte).
	  2. pgconn:  TCP transport, connection state machine, connection pool, and dynamic TLS.
	  3. pgmap:   High-level data mapping and reflection for Odin structs and query parameters.
	  4. opg:     Ergonomic root facade providing unified access to all driver features.

	Key Features:
	  - Native wire-protocol codec with Network Byte Order (Big-Endian) compliance.
	  - Dynamic TLS probing via core:dynlib (Schannel on Windows, SecureTransport on macOS, OpenSSL on Linux).
	  - Thread-safe connection pooling with idle timeouts, max lifetimes, and health checks.
	  - Tagged union error handling (Net_Error, Protocol_Error, Auth_Error, Postgres_Error, Pool_Error).
	  - Parameterized queries ($1, $2, ...) protecting against SQL injection across all basic types,
	    slices/arrays, timestamps, UUIDs, JSON/JSONB, and Maybe(T) nullables.
	  - Automatic struct reflection mapping for single-row (query_struct) and multi-row (query_slice) queries.
	  - Streaming row consumption via callbacks for multi-gigabyte/hundred-thousand row result sets.
	  - Full transaction support with configurable isolation levels and nested savepoints.
*/

import "base:intrinsics"
import "core:time"
import "pgconn"
import "pgerr"
import "pgmap"
import "pgproto"

// ============================================================================
// 1. Re-exported Errors & Tagged Unions
// ============================================================================

/*
	Error is the overarching tagged union returned by all opg driver operations.
	Includes:
	  - Net_Error: Sockets, timeouts, disconnections, DNS resolution failures.
	  - Protocol_Error: Malformed packets, invalid lengths, unsupported versions.
	  - Auth_Error: Authentication failures (SCRAM-SHA-256, MD5, Cleartext).
	  - Postgres_Error: Server-side SQLSTATE errors and messages (ErrorResponse).
	  - Pool_Error: Connection pool exhaustion, timeout, or closed state.
*/
Error                  :: pgerr.Error
Net_Error              :: pgerr.Net_Error
Net_Error_Type         :: pgerr.Net_Error_Type
Protocol_Error         :: pgerr.Protocol_Error
Protocol_Error_Type    :: pgerr.Protocol_Error_Type
Auth_Error             :: pgerr.Auth_Error
Auth_Error_Type        :: pgerr.Auth_Error_Type
Postgres_Error         :: pgerr.Postgres_Error
Pool_Error             :: pgerr.Pool_Error
Pool_Error_Type        :: pgerr.Pool_Error_Type

/*
	POSTGRES_ERROR OWNERSHIP

	Every Postgres_Error this driver returns is yours to free, and there is only
	one rule for all of them:

	    conn, err := opg.connect(cfg)                 // cloned into the allocator
	    if pg, ok := err.(opg.Postgres_Error); ok {   // you passed to connect
	        opg.postgres_error_destroy(pg, context.allocator)
	    }

	    _, err := opg.exec(conn, "...")               // cloned into conn.allocator,
	    if pg, ok := err.(opg.Postgres_Error); ok {   // which is that same allocator
	        opg.postgres_error_destroy(pg, conn.allocator)
	    }

	The strings hang off the allocator the connection was opened with, so the
	same call frees an error raised on any thread that shares the connection.
	A connect failure has no Conn to read it from, so use the allocator you
	passed to connect (context.allocator by default).

	The other error variants — Net_Error, Protocol_Error, Auth_Error, Pool_Error
	— carry no allocations and need no teardown.
*/
postgres_error_destroy :: pgerr.postgres_error_destroy
postgres_error_clone   :: pgerr.postgres_error_clone

// ============================================================================
// 2. Re-exported Connection, TLS & Pool Types
// ============================================================================

/*
	Conn represents an established, stateful connection to a PostgreSQL database server.
*/
Conn                   :: pgconn.Conn

/*
	Conn_Config defines connection parameters for establishing a PostgreSQL session.
*/
Conn_Config            :: pgconn.Conn_Config

/*
	Conn_Status represents the live lifecycle state of a connection.
*/
Conn_Status            :: pgconn.Conn_Status

/*
	SSL_Mode determines the TLS negotiation behavior during connection startup:
	  - Prefer: Attempt TLS; fall back to unencrypted TCP if unsupported. (Default)
	  - Disable: Connect using unencrypted plaintext TCP only.
	  - Require: Require TLS encryption; fail connection if TLS cannot be established.
*/
SSL_Mode               :: pgconn.SSL_Mode

/*
	TLS_Backend_Type represents the active runtime cryptographic library backend:
	  - None: No TLS backend loaded.
	  - OpenSSL: Dynamically loaded OpenSSL (libssl).
	  - Schannel: Windows native SSPI Schannel (secur32.dll / sspicli.dll).
	  - SecureTransport: macOS native Security.framework.
*/
TLS_Backend_Type       :: pgconn.TLS_Backend_Type

/*
	Pool represents a thread-safe, concurrent connection pool managing reusable Conn handles.
*/
Pool                   :: pgconn.Pool

/*
	Pool_Config defines connection pooling limits, timeouts, and factory configurations.
*/
Pool_Config            :: pgconn.Pool_Config

/*
	Data_Row is one row delivered to a Row_Callback during streaming.
	`values` holds one Column_Value per column, in the order described by
	Row_Description. The byte slices borrow the stream buffer and are only
	valid for the duration of the callback: copy anything you need to keep.
*/
Data_Row               :: pgproto.Msg_Data_Row

/*
	Column_Value is a single column within a Data_Row. When `is_null` is set,
	`data` carries no meaning.
*/
Column_Value           :: pgproto.Column_Value

/*
	Row_Description is the column metadata delivered to a Row_Desc_Callback
	before the first row. Field names borrow the stream buffer, as in Data_Row.
*/
Row_Description        :: pgproto.Msg_Row_Description

/*
	Field_Description describes one column: its name, type OID, size and
	format code.
*/
Field_Description      :: pgproto.Field_Description

/*
	Field_Format distinguishes text from binary column encoding.
*/
Field_Format           :: pgproto.Field_Format

/*
	Row_Callback is invoked per row during streaming query execution.
	Returning false aborts row streaming early.
*/
Row_Callback           :: pgconn.Row_Callback

/*
	Command_Callback is invoked upon query completion with the server command tag and affected rows.
*/
Command_Callback       :: pgconn.Command_Callback

/*
	Row_Desc_Callback is invoked when column metadata is received from the server.
*/
Row_Desc_Callback      :: pgconn.Row_Desc_Callback

/*
	tls_backend_type returns the active TLS backend type discovered via dynamic probing.
*/
tls_backend_type       :: pgconn.tls_backend_type

/*
	tls_backend_name returns the human-readable name of the active TLS backend
	(e.g., "Schannel", "SecureTransport", "OpenSSL", or "none").
*/
tls_backend_name       :: pgconn.tls_backend_name

// ============================================================================
// 3. Re-exported Mapping & PostgreSQL Type OIDs
// ============================================================================

Oid                    :: pgmap.Oid
OID_BOOL               :: pgmap.OID_BOOL
OID_BYTEA              :: pgmap.OID_BYTEA
OID_INT8               :: pgmap.OID_INT8
OID_INT2               :: pgmap.OID_INT2
OID_INT4               :: pgmap.OID_INT4
OID_TEXT               :: pgmap.OID_TEXT
OID_JSON               :: pgmap.OID_JSON
OID_FLOAT4             :: pgmap.OID_FLOAT4
OID_FLOAT8             :: pgmap.OID_FLOAT8
OID_VARCHAR            :: pgmap.OID_VARCHAR
OID_DATE               :: pgmap.OID_DATE
OID_TIME               :: pgmap.OID_TIME
OID_TIMESTAMP          :: pgmap.OID_TIMESTAMP
OID_TIMESTAMPTZ        :: pgmap.OID_TIMESTAMPTZ
OID_NUMERIC            :: pgmap.OID_NUMERIC
OID_UUID               :: pgmap.OID_UUID
OID_JSONB              :: pgmap.OID_JSONB

// ============================================================================
// 4. Connection Lifecycle Management
// ============================================================================

/*
	connect establishes a new TCP connection to PostgreSQL, completes TLS negotiation
	(if configured), and executes the authentication handshake (SCRAM-SHA-256, MD5, Cleartext).

	Parameters:
	  - config: Connection options (host, port, user, password, database, timeouts, ssl_mode).
	  - allocator: Allocator used for persistent connection state (default context.allocator).

	Returns:
	  - A pointer to the initialized Conn, or an Error on failure.
	    A Postgres_Error here is allocated from `allocator` and is yours to
	    free — see POSTGRES_ERROR OWNERSHIP above.

	Example:
	  conn, err := opg.connect({
	      host     = "127.0.0.1",
	      port     = 5432,
	      user     = "postgres",
	      password = "secretpassword",
	      database = "mydb",
	      ssl_mode = .Prefer,
	  })
	  if err != nil {
	      fmt.eprintln("Failed to connect:", err)
	      return
	  }
	  defer opg.disconnect(conn)
*/
connect :: proc(config: Conn_Config, allocator := context.allocator) -> (^Conn, Error) {
	return pgconn.conn_connect(config, allocator)
}

/*
	disconnect sends a Terminate message ('X') to the PostgreSQL server, gracefully
	closes the transport stream, and frees all memory associated with the Conn handle.
*/
disconnect :: proc(conn: ^Conn) {
	if conn == nil do return
	alloc := conn.allocator
	pgconn.conn_close(conn)
	free(conn, alloc)
}

/*
	is_alive returns true if the connection is currently connected, idle, and ready for queries.
*/
is_alive :: proc(conn: ^Conn) -> bool {
	return pgconn.conn_is_alive(conn)
}

// ============================================================================
// 5. Connection Pool API
// ============================================================================

/*
	pool_create initializes a new thread-safe connection pool with the specified configuration.
	The pool maintains min_conns active connections, scales up to max_conns on demand,
	and automatically cleans up stale or expired connections.

	Parameters:
	  - config: Pool configuration including connection factory options, min/max limits,
	            idle timeout, and max lifetime.
	  - allocator: Allocator for pool state (default context.allocator).

	Example:
	  pool, err := opg.pool_create({
	      conn_config  = my_conn_config,
	      min_conns    = 2,
	      max_conns    = 10,
	      idle_timeout = 5 * time.Minute,
	  })
	  if err != nil {
	      log.errorf("Pool creation failed: %v", err)
	      return
	  }
	  defer opg.pool_destroy(pool)
*/
pool_create :: proc(config: Pool_Config, allocator := context.allocator) -> (^Pool, Error) {
	return pgconn.pool_init(config, allocator)
}

/*
	pool_init is an alias for pool_create.
*/
pool_init :: pool_create

/*
	pool_destroy gracefully closes and terminates all connections in the pool and frees pool state.
*/
pool_destroy :: proc(pool: ^Pool) {
	pgconn.pool_destroy(pool)
}

/*
	pool_acquire leases an idle connection from the pool, or creates a new connection if
	the current count is below max_conns. If all connections are busy, blocks up to timeout.

	Parameters:
	  - pool: The connection pool.
	  - timeout: Maximum duration to wait for an available connection (0 = indefinite).

	Returns:
	  - A leased Conn handle, or Pool_Error{.Timeout} / Pool_Error{.Pool_Exhausted}.

	Note:
	  Always return the connection to the pool using pool_release.
*/
pool_acquire :: proc(pool: ^Pool, timeout := time.Duration(0)) -> (^Conn, Error) {
	return pgconn.pool_acquire(pool, timeout)
}

/*
	pool_release returns a leased connection back to the connection pool for reuse.

	Returns:
	  - Pool_Error{.Foreign_Connection} if the connection was not leased from
	    this pool, which also covers releasing the same connection twice.
	  - Error from the reset performed on a connection left mid-transaction.
*/
pool_release :: proc(pool: ^Pool, conn: ^Conn) -> Error {
	return pgconn.pool_release(pool, conn)
}

// ============================================================================
// 6. High-Level Query & Execution Helpers
// ============================================================================

/*
	query_struct executes a parameterized SQL query and maps the first returned row
	directly into an Odin struct of type T using core:reflect.

	Parameters:
	  - conn: Active database connection.
	  - $T: Target Odin struct typeid.
	  - sql: Parameterized SQL query (using $1, $2, ... placeholders).
	  - args: Variadic bind parameters.
	  - allocator: Allocator for string/slice fields inside T (default context.temp_allocator).

	Returns:
	  - Populated struct of type T.
	  - Protocol_Error{.No_Data} if no rows were returned.
	  - Error on query or mapping failure.

	Example:
	  User :: struct {
	      id:         i64,
	      username:   string,
	      is_active:  bool,
	      bio:        Maybe(string),
	      created_at: time.Time,
	  }

	  user, err := opg.query_struct(conn, User, "SELECT id, username, is_active, bio, created_at FROM users WHERE id = $1;", 42)
*/
query_struct :: proc(
	conn: ^Conn,
	$T: typeid,
	sql: string,
	args: ..any,
	allocator := context.temp_allocator,
) -> (
	result: T,
	err: Error,
) where intrinsics.type_is_struct(T) {
	return pgmap.query_struct(conn, T, sql, ..args, allocator = allocator)
}

/*
	query_slice executes a parameterized SQL query and maps all returned rows into
	an allocated slice of Odin structs ([]T).

	Parameters:
	  - conn: Active database connection.
	  - $T: Target Odin struct typeid.
	  - sql: Parameterized SQL query (using $1, $2, ... placeholders).
	  - args: Variadic bind parameters.
	  - allocator: Allocator for the returned slice and row fields (default context.temp_allocator).

	Returns:
	  - A slice []T containing mapped rows (empty slice if 0 rows matched).
	  - Error on query or mapping failure.

	Example:
	  users, err := opg.query_slice(conn, User, "SELECT id, username, is_active FROM users WHERE is_active = $1 ORDER BY id;", true)
*/
query_slice :: proc(
	conn: ^Conn,
	$T: typeid,
	sql: string,
	args: ..any,
	allocator := context.temp_allocator,
) -> (
	result: []T,
	err: Error,
) where intrinsics.type_is_struct(T) {
	return pgmap.query_slice(conn, T, sql, ..args, allocator = allocator)
}

/*
	exec executes a parameterized SQL statement (such as INSERT, UPDATE, DELETE, or DDL)
	and returns the number of rows affected by the command.

	Parameters:
	  - conn: Active database connection.
	  - sql: Parameterized SQL statement (using $1, $2, ... placeholders).
	  - args: Variadic bind parameters.

	Returns:
	  - rows_affected: Number of rows modified (e.g. from "INSERT 0 1" or "UPDATE 5").
	  - Error on failure. A Postgres_Error here is allocated from
	    conn.allocator and is yours to free — see POSTGRES_ERROR OWNERSHIP above.

	Example:
	  rows, err := opg.exec(conn, "UPDATE users SET is_active = $1 WHERE last_login < $2;", false, cutoff_time)
*/
exec :: proc(
	conn: ^Conn,
	sql: string,
	args: ..any,
) -> (
	rows_affected: int,
	err: Error,
) {
	return pgmap.exec(conn, sql, ..args)
}

/*
	query_stream executes a query with row streaming, invoking on_row for each DataRow
	received directly from the network stream without accumulating all rows in memory.

	Parameters:
	  - conn: Active database connection.
	  - sql: Simple query string.
	  - on_row: Callback invoked per DataRow. Return false to stop streaming.
	  - on_command: Optional callback invoked with the command completion tag.
	  - on_desc: Optional callback invoked when column descriptions arrive.
	  - user_data: User pointer passed directly to all callbacks.
*/
query_stream :: proc(
	conn: ^Conn,
	sql: string,
	on_row: Row_Callback,
	on_command: Command_Callback = nil,
	on_desc: Row_Desc_Callback = nil,
	user_data: rawptr = nil,
) -> Error {
	return pgconn.conn_query(conn, sql, on_row, on_command, on_desc, user_data)
}
