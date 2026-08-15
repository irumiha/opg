package opg

import "core:testing"

@(test)
test_root_facade_constants_and_types :: proc(t: ^testing.T) {
	// Verify re-exported OIDs
	testing.expect_value(t, u32(OID_BOOL), u32(16))
	testing.expect_value(t, u32(OID_INT4), u32(23))
	testing.expect_value(t, u32(OID_INT8), u32(20))
	testing.expect_value(t, u32(OID_TEXT), u32(25))
	testing.expect_value(t, u32(OID_UUID), u32(2950))
	testing.expect_value(t, u32(OID_JSONB), u32(3802))

	// Verify Tx_Options defaults
	opts: Tx_Options = {}
	testing.expect_value(t, opts.isolation, Isolation_Level.Default)
	testing.expect_value(t, opts.access, Tx_Access_Mode.Read_Write)
	testing.expect_value(t, opts.deferrable, false)
}

@(test)
test_root_facade_nil_connection_safety :: proc(t: ^testing.T) {
	// Ensure calling tx procedures on nil Tx does not crash and returns appropriate errors
	var_tx: Tx = {}
	err := tx_commit(&var_tx)
	testing.expect(t, err != nil)

	err_rb := tx_rollback(&var_tx)
	testing.expect_value(t, err_rb, nil) // idempotent rollback on uninitialized tx returns nil

	err_sp := tx_savepoint(&var_tx, "sp")
	testing.expect(t, err_sp != nil)

	// Ensure disconnect on nil does not panic
	disconnect(nil)
}
