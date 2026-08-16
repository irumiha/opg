package pgmap

// ----------------------------------------------------------------------------
// PostgreSQL Data Type OIDs
// ----------------------------------------------------------------------------
// Reference table of standard PostgreSQL type OIDs. The current pgmap mapper
// decodes by the *target Odin type*, not by OID, so these constants are not
// consulted at runtime yet; they are reserved for the OID-driven codec paths
// (NUMERIC, JSON/JSONB, binary arrays) planned for the public facade epic.
// ----------------------------------------------------------------------------

Oid :: distinct u32

// Primitive & Core Types
OID_BOOL        :: Oid(16)
OID_BYTEA       :: Oid(17)
OID_CHAR        :: Oid(18)
OID_NAME        :: Oid(19)
OID_INT8        :: Oid(20)
OID_INT2        :: Oid(21)
OID_INT4        :: Oid(23)
OID_TEXT        :: Oid(25)
OID_OID         :: Oid(26)
OID_JSON        :: Oid(114)
OID_XML         :: Oid(142)
OID_FLOAT4      :: Oid(700)
OID_FLOAT8      :: Oid(701)
OID_MONEY       :: Oid(790)
OID_BPCHAR      :: Oid(1042)
OID_VARCHAR     :: Oid(1043)
OID_DATE        :: Oid(1082)
OID_TIME        :: Oid(1083)
OID_TIMESTAMP   :: Oid(1114)
OID_TIMESTAMPTZ :: Oid(1184)
OID_INTERVAL    :: Oid(1186)
OID_TIMETZ      :: Oid(1266)
OID_BIT         :: Oid(1560)
OID_VARBIT      :: Oid(1562)
OID_NUMERIC     :: Oid(1700)
OID_UUID        :: Oid(2950)
OID_JSONB       :: Oid(3802)

// Standard Array Types
OID_BOOL_ARRAY    :: Oid(1000)
OID_BYTEA_ARRAY   :: Oid(1001)
OID_CHAR_ARRAY    :: Oid(1002)
OID_INT2_ARRAY    :: Oid(1005)
OID_INT4_ARRAY    :: Oid(1007)
OID_TEXT_ARRAY    :: Oid(1009)
OID_VARCHAR_ARRAY :: Oid(1015)
OID_INT8_ARRAY    :: Oid(1016)
OID_FLOAT4_ARRAY  :: Oid(1021)
OID_FLOAT8_ARRAY  :: Oid(1022)
OID_UUID_ARRAY    :: Oid(2951)
OID_JSONB_ARRAY   :: Oid(3807)
