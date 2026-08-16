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

@(test)
test_pool_release_reports_foreign_connection :: proc(t: ^testing.T) {
	// Releasing a connection the pool never handed out, or releasing one
	// twice, is a caller bug that corrupts pool accounting. The pool layer
	// detects it, so the facade must not swallow the verdict.
	err := pool_release(nil, nil)

	perr, is_pool := err.(Pool_Error)
	testing.expect(t, is_pool, "pool_release must report a foreign connection rather than ignoring it")
	testing.expect_value(t, perr.type, Pool_Error_Type.Foreign_Connection)
}

@(test)
test_is_alive_reflects_connection_state :: proc(t: ^testing.T) {
	testing.expect(t, !is_alive(nil), "a nil connection is not alive")

	ready := Conn{status = .Ready}
	testing.expect(t, is_alive(&ready), "a ready connection is alive")

	in_tx := Conn{status = .In_Transaction}
	testing.expect(t, is_alive(&in_tx), "a connection inside a transaction is alive")

	// An aborted transaction still has a working socket; it needs a ROLLBACK,
	// not a reconnect, so it must not be reported as dead.
	failed_tx := Conn{status = .Failed_Transaction}
	testing.expect(t, is_alive(&failed_tx), "an aborted transaction is still connected")

	closed := Conn{status = .Closed}
	testing.expect(t, !is_alive(&closed), "a closed connection is not alive")

	disconnected := Conn{status = .Disconnected}
	testing.expect(t, !is_alive(&disconnected), "a disconnected connection is not alive")
}
