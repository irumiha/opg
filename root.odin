package opg

import "core:net"

// ============================================================================
// PostgreSQL Database Driver (Frontend/Backend Protocol 3.0)
// ============================================================================
// Architectural Rules:
// 1. 3-Layer Architecture: pgproto (wire codec), pgconn (TCP & pool), pgorm (reflection).
// 2. Big-Endian: Explicit endian-swapping for all network integers via core:encoding/endian.
// 3. Allocator Boundaries: context.temp_allocator for pgproto/pgorm, persistent for pgconn.
// 4. Tagged Union Errors: Unified Error union with typed domain variants.
// ============================================================================

// ----------------------------------------------------------------------------
// 4. TAGGED UNION ERROR HANDLING
// ----------------------------------------------------------------------------

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
	Unexpected_Message,
	Buffer_Underflow,
	Invalid_Column_Count,
	Unsupported_Format_Code,
	Unsupported_Protocol_Version,
}

Protocol_Error :: struct {
	type:        Protocol_Error_Type,
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
	message: string,
}

/*
	Postgres_Error contains the structured error fields returned directly
	from the PostgreSQL engine inside an ErrorResponse ('E') message.
*/
Postgres_Error :: struct {
	severity:          string, // 'S' / 'V' (FATAL, ERROR, PANIC, etc.)
	code:              string, // 'C' SQLSTATE error code (e.g. "42P01", "28P01")
	message:           string, // 'M' Primary human-readable error message
	detail:            string, // 'D' Optional secondary error detail
	hint:              string, // 'H' Optional suggestion what to do
	position:          string, // 'P' Decimal ASCII integer index into query string
	internal_position: string, // 'p' Internal query position
	internal_query:    string, // 'q' Internal query text
	where_context:     string, // 'W' Call stack / context
	schema_name:       string, // 's' Schema name
	table_name:        string, // 't' Table name
	column_name:       string, // 'c' Column name
	data_type_name:    string, // 'd' Data type name
	constraint_name:   string, // 'n' Constraint name
	file:              string, // 'F' Source file name in PostgreSQL engine
	line:              string, // 'L' Source line number in PostgreSQL engine
	routine:           string, // 'R' Source routine name in PostgreSQL engine
}

// Master tagged union for all driver errors
Error :: union {
	Net_Error,
	Protocol_Error,
	Auth_Error,
	Postgres_Error,
}
