package pgerr

import "core:net"

// ============================================================================
// opg Error Domain (leaf package)
// ============================================================================
// All driver error types live here so that every layer (pgproto, pgconn,
// pgorm, and the root opg facade) can import them WITHOUT creating an import
// cycle. Subpackages must import "pgerr" — never the root package.
// ============================================================================

Net_Error_Type :: enum {
	None,
	Timeout,
	Socket_Closed,
	Connection_Refused,
	Host_Unreachable,
	Network_Down,
	Send_Failed,
	Recv_Failed,
	DNS_Resolution_Failed,
	TLS_Handshake_Failed,
	Unexpected_EOF,
}

Net_Error :: struct {
	type:          Net_Error_Type,
	code:          i32,
	raw_net_error: net.Network_Error,
}

Protocol_Error_Type :: enum {
	None,
	Malformed_Packet,
	Invalid_Length,
	Unknown_Message_Type,
	Unknown_Auth_Type,
	Unexpected_Message,
	Buffer_Underflow,
	Invalid_Column_Count,
	Unsupported_Format_Code,
	Unsupported_Protocol_Version,
}

Protocol_Error :: struct {
	type:        Protocol_Error_Type,
	// `message` is a static string literal set at the call site (never
	// allocated, never borrowed from the wire buffer); it must not be freed.
	message:     string,
	byte_offset: int,
}

Auth_Error_Type :: enum {
	None,
	Unsupported_Auth_Mechanism,
	SCRAM_Invalid_Server_First_Message,
	SCRAM_Invalid_Server_Final_Message,
	SCRAM_Server_Signature_Mismatch,
	SCRAM_Channel_Binding_Failed,
	Authentication_Failed,
	Invalid_Credentials,
}

Auth_Error :: struct {
	type:    Auth_Error_Type,
	// `message` is either a static string literal (set at the call site,
	// never freed) or a clone allocated by the caller with the persistent
	// allocator (e.g. the `e=` attribute echoed from a SCRAM server-final
	// message — see scram_verify_server_final). Inspect the type to decide;
	// the SCRAM error-message variants own a heap clone the caller must free.
	message: string,
}

/*
	Postgres_Error contains the structured error fields returned directly
	from the PostgreSQL engine inside an ErrorResponse ('E') message.
*/
Postgres_Error :: struct {
	severity:             string, // 'S' Localized severity (FATAL, ERROR, PANIC, etc.)
	severity_unlocalized: string, // 'V' Non-localized severity (PostgreSQL 9.6+)
	code:                 string, // 'C' SQLSTATE error code (e.g. "42P01", "28P01")
	message:              string, // 'M' Primary human-readable error message
	detail:               string, // 'D' Optional secondary error detail
	hint:                 string, // 'H' Optional suggestion what to do
	position:             string, // 'P' Decimal ASCII integer index into query string
	internal_position:    string, // 'p' Internal query position
	internal_query:       string, // 'q' Internal query text
	where_context:        string, // 'W' Call stack / context
	schema_name:          string, // 's' Schema name
	table_name:           string, // 't' Table name
	column_name:          string, // 'c' Column name
	data_type_name:       string, // 'd' Data type name
	constraint_name:      string, // 'n' Constraint name
	file:                 string, // 'F' Source file name in PostgreSQL engine
	line:                 string, // 'L' Source line number in PostgreSQL engine
	routine:              string, // 'R' Source routine name in PostgreSQL engine
}

Pool_Error_Type :: enum {
	None,
	Invalid_Config,
	Pool_Closed,
	Acquire_Timeout,
	Foreign_Connection,
}

/*
	Pool_Error reports connection pool lifecycle and usage failures.
	`message` is always a static string literal — it is never allocated
	and must never be freed.
*/
Pool_Error :: struct {
	type:    Pool_Error_Type,
	message: string,
}

// Master tagged union for all driver errors
Error :: union {
	Net_Error,
	Protocol_Error,
	Auth_Error,
	Postgres_Error,
	Pool_Error,
}
