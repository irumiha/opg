package opg

/*
	Offline guard tests for the transaction facade.

	These exercise the state checks that must reject a call *before* any SQL
	reaches the wire, so they run without a live server: a zero-valued Conn has
	no transport, and any statement that slipped past a guard would surface as
	Net_Error{.Socket_Closed} from the stream layer. Asserting on the specific
	Protocol_Error is therefore what distinguishes "refused by the guard" from
	"attempted and failed for lack of a socket".
*/

import "core:testing"

@(test)
test_tx_commit_refuses_aborted_transaction :: proc(t: ^testing.T) {
	conn := Conn{status = .Failed_Transaction, transaction_status = .Failed_Transaction}
	tx := Tx{conn = &conn}

	err := tx_commit(&tx)

	perr, is_protocol := err.(Protocol_Error)
	testing.expect(t, is_protocol, "COMMIT on an aborted transaction must be refused, not reported as success")
	testing.expect_value(t, perr.type, Protocol_Error_Type.Unexpected_Message)
	testing.expect_value(t, tx.committed, false)
}

@(test)
test_tx_commit_leaves_tx_open_for_rollback_after_refusal :: proc(t: ^testing.T) {
	conn := Conn{status = .Failed_Transaction, transaction_status = .Failed_Transaction}
	tx := Tx{conn = &conn}

	_ = tx_commit(&tx)

	// The refusal must not mark the transaction finished, so a deferred
	// tx_rollback still issues the ROLLBACK that clears the aborted state.
	testing.expect_value(t, tx.committed, false)
	testing.expect_value(t, tx.rolled_back, false)
}

@(test)
test_begin_transaction_refuses_nested :: proc(t: ^testing.T) {
	conn := Conn{status = .In_Transaction, transaction_status = .In_Transaction}

	_, err := begin_transaction(&conn)

	perr, is_protocol := err.(Protocol_Error)
	testing.expect(t, is_protocol, "nested begin_transaction must be refused rather than silently overlapping")
	testing.expect_value(t, perr.type, Protocol_Error_Type.Unexpected_Message)
}

@(test)
test_begin_transaction_refuses_aborted_connection :: proc(t: ^testing.T) {
	conn := Conn{status = .Failed_Transaction, transaction_status = .Failed_Transaction}

	_, err := begin_transaction(&conn)

	perr, is_protocol := err.(Protocol_Error)
	testing.expect(t, is_protocol, "begin_transaction on an aborted transaction must be refused")
	testing.expect_value(t, perr.type, Protocol_Error_Type.Unexpected_Message)
}

@(test)
test_tx_exec_refuses_finished_transaction :: proc(t: ^testing.T) {
	conn := Conn{status = .Ready, transaction_status = .Idle}
	tx := Tx{conn = &conn, rolled_back = true}

	_, err := tx_exec(&tx, "INSERT INTO accounts (id) VALUES (1);")

	perr, is_protocol := err.(Protocol_Error)
	testing.expect(t, is_protocol, "tx_exec after rollback must be refused, not run in autocommit")
	testing.expect_value(t, perr.type, Protocol_Error_Type.Unexpected_Message)
}

@(test)
test_tx_query_struct_refuses_finished_transaction :: proc(t: ^testing.T) {
	Row :: struct {
		id: i32,
	}
	conn := Conn{status = .Ready, transaction_status = .Idle}
	tx := Tx{conn = &conn, committed = true}

	_, err := tx_query_struct(&tx, Row, "SELECT id FROM accounts;")

	perr, is_protocol := err.(Protocol_Error)
	testing.expect(t, is_protocol, "tx_query_struct after commit must be refused")
	testing.expect_value(t, perr.type, Protocol_Error_Type.Unexpected_Message)
}

@(test)
test_tx_query_slice_refuses_finished_transaction :: proc(t: ^testing.T) {
	Row :: struct {
		id: i32,
	}
	conn := Conn{status = .Ready, transaction_status = .Idle}
	tx := Tx{conn = &conn, committed = true}

	_, err := tx_query_slice(&tx, Row, "SELECT id FROM accounts;")

	perr, is_protocol := err.(Protocol_Error)
	testing.expect(t, is_protocol, "tx_query_slice after commit must be refused")
	testing.expect_value(t, perr.type, Protocol_Error_Type.Unexpected_Message)
}

@(test)
test_quote_identifier_wraps_and_escapes :: proc(t: ^testing.T) {
	testing.expect_value(t, quote_identifier("sp1", context.temp_allocator), `"sp1"`)
	testing.expect_value(t, quote_identifier("my savepoint", context.temp_allocator), `"my savepoint"`)
	testing.expect_value(t, quote_identifier("select", context.temp_allocator), `"select"`)
	// An embedded double quote is escaped by doubling, per SQL identifier rules.
	testing.expect_value(t, quote_identifier(`we"ird`, context.temp_allocator), `"we""ird"`)
}
