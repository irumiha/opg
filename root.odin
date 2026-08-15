package opg

import "base:intrinsics"
import "core:time"
import "pgconn"
import "pgerr"
import "pgorm"

// ============================================================================
// PostgreSQL Database Driver (Frontend/Backend Protocol 3.0) - Root Facade
// ============================================================================

// ----------------------------------------------------------------------------
// Re-exported Core Errors
// ----------------------------------------------------------------------------

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

postgres_error_destroy :: pgerr.postgres_error_destroy
postgres_error_clone   :: pgerr.postgres_error_clone

// ----------------------------------------------------------------------------
// Re-exported Connection & Pool Types
// ----------------------------------------------------------------------------

Conn                   :: pgconn.Conn
Conn_Config            :: pgconn.Conn_Config
Conn_Status            :: pgconn.Conn_Status
SSL_Mode               :: pgconn.SSL_Mode
Pool                   :: pgconn.Pool
Pool_Config            :: pgconn.Pool_Config

// ----------------------------------------------------------------------------
// Re-exported ORM & OID Types
// ----------------------------------------------------------------------------

Oid                    :: pgorm.Oid
OID_BOOL               :: pgorm.OID_BOOL
OID_BYTEA              :: pgorm.OID_BYTEA
OID_INT8               :: pgorm.OID_INT8
OID_INT2               :: pgorm.OID_INT2
OID_INT4               :: pgorm.OID_INT4
OID_TEXT               :: pgorm.OID_TEXT
OID_JSON               :: pgorm.OID_JSON
OID_FLOAT4             :: pgorm.OID_FLOAT4
OID_FLOAT8             :: pgorm.OID_FLOAT8
OID_VARCHAR            :: pgorm.OID_VARCHAR
OID_DATE               :: pgorm.OID_DATE
OID_TIME               :: pgorm.OID_TIME
OID_TIMESTAMP          :: pgorm.OID_TIMESTAMP
OID_TIMESTAMPTZ        :: pgorm.OID_TIMESTAMPTZ
OID_NUMERIC            :: pgorm.OID_NUMERIC
OID_UUID               :: pgorm.OID_UUID
OID_JSONB              :: pgorm.OID_JSONB

// ----------------------------------------------------------------------------
// Connection Lifecycle Management
// ----------------------------------------------------------------------------

/*
	connect establishes a new TCP connection to PostgreSQL and completes the handshake.
*/
connect :: proc(config: Conn_Config, allocator := context.allocator) -> (^Conn, Error) {
	return pgconn.conn_connect(config, allocator)
}

/*
	disconnect gracefully closes the connection and frees the connection handle.
*/
disconnect :: proc(conn: ^Conn) {
	if conn == nil do return
	alloc := conn.allocator
	pgconn.conn_close(conn)
	free(conn, alloc)
}

/*
	is_alive checks if the connection socket is open and ready.
*/
is_alive :: proc(conn: ^Conn) -> bool {
	return pgconn.conn_is_alive(conn)
}

// ----------------------------------------------------------------------------
// Connection Pool API
// ----------------------------------------------------------------------------

pool_create :: proc(config: Pool_Config, allocator := context.allocator) -> (^Pool, Error) {
	return pgconn.pool_init(config, allocator)
}

pool_init :: pool_create

pool_destroy :: proc(pool: ^Pool) {
	pgconn.pool_destroy(pool)
}

pool_acquire :: proc(pool: ^Pool, timeout := time.Duration(0)) -> (^Conn, Error) {
	return pgconn.pool_acquire(pool, timeout)
}

pool_release :: proc(pool: ^Pool, conn: ^Conn) {
	pgconn.pool_release(pool, conn)
}

// ----------------------------------------------------------------------------
// High-Level Query & Execution Helpers
// ----------------------------------------------------------------------------

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
	return pgorm.query_struct(conn, T, sql, ..args, allocator = allocator)
}

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
	return pgorm.query_slice(conn, T, sql, ..args, allocator = allocator)
}

exec :: proc(
	conn: ^Conn,
	sql: string,
	args: ..any,
) -> (
	rows_affected: int,
	err: Error,
) {
	return pgorm.exec(conn, sql, ..args)
}
