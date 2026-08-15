package opg

import "pgerr"

// ============================================================================
// PostgreSQL Database Driver (Frontend/Backend Protocol 3.0)
// ============================================================================
// Architectural Rules:
// 1. 3-Layer Architecture: pgproto (wire codec), pgconn (TCP & pool), pgorm (reflection).
// 2. Big-Endian: Explicit endian-swapping for all network integers via core:encoding/endian.
// 3. Allocator Boundaries: context.temp_allocator for pgproto/pgorm, persistent for pgconn.
// 4. Tagged Union Errors: Unified Error union defined in the pgerr leaf package;
//    re-exported here so consumers only need `import "opg"`.
// ============================================================================

Error               :: pgerr.Error
Net_Error           :: pgerr.Net_Error
Net_Error_Type      :: pgerr.Net_Error_Type
Protocol_Error      :: pgerr.Protocol_Error
Protocol_Error_Type :: pgerr.Protocol_Error_Type
Auth_Error          :: pgerr.Auth_Error
Auth_Error_Type     :: pgerr.Auth_Error_Type
Postgres_Error      :: pgerr.Postgres_Error
