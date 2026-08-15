package opg

import "base:intrinsics"
import "core:fmt"
import "pgorm"

// ============================================================================
// High-Level Database Transactions API
// ============================================================================

Isolation_Level :: enum {
	Default,
	Read_Committed,
	Repeatable_Read,
	Serializable,
}

Tx_Access_Mode :: enum {
	Read_Write,
	Read_Only,
}

Tx_Options :: struct {
	isolation:  Isolation_Level,
	access:     Tx_Access_Mode,
	deferrable: bool,
}

Tx :: struct {
	conn:        ^Conn,
	committed:   bool,
	rolled_back: bool,
}

/*
	begin_transaction begins a transaction on the connection with the given options.
*/
begin_transaction :: proc(
	conn: ^Conn,
	options: Tx_Options = {},
	allocator := context.temp_allocator,
) -> (
	tx: Tx,
	err: Error,
) {
	if conn == nil || !is_alive(conn) {
		return tx, Net_Error{type = .Socket_Closed}
	}

	begin_sql: string
	switch options.isolation {
	case .Default:
		begin_sql = (options.access == .Read_Only) ? "BEGIN READ ONLY;" : "BEGIN;"
	case .Read_Committed:
		begin_sql = (options.access == .Read_Only) ? "BEGIN ISOLATION LEVEL READ COMMITTED READ ONLY;" : "BEGIN ISOLATION LEVEL READ COMMITTED;"
	case .Repeatable_Read:
		begin_sql = (options.access == .Read_Only) ? "BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;" : "BEGIN ISOLATION LEVEL REPEATABLE READ;"
	case .Serializable:
		if options.deferrable && options.access == .Read_Only {
			begin_sql = "BEGIN ISOLATION LEVEL SERIALIZABLE READ ONLY DEFERRABLE;"
		} else if options.access == .Read_Only {
			begin_sql = "BEGIN ISOLATION LEVEL SERIALIZABLE READ ONLY;"
		} else {
			begin_sql = "BEGIN ISOLATION LEVEL SERIALIZABLE;"
		}
	}

	_, exec_err := pgorm.exec(conn, begin_sql)
	if exec_err != nil do return tx, exec_err

	tx.conn = conn
	return tx, nil
}

/*
	tx_commit commits the active transaction.
*/
tx_commit :: proc(tx: ^Tx) -> Error {
	if tx == nil || tx.conn == nil do return Net_Error{type = .Socket_Closed}
	if tx.committed || tx.rolled_back do return nil

	_, err := pgorm.exec(tx.conn, "COMMIT;")
	if err != nil do return err

	tx.committed = true
	return nil
}

/*
	tx_rollback rolls back the transaction. Safe to call multiple times or via defer.
*/
tx_rollback :: proc(tx: ^Tx) -> Error {
	if tx == nil || tx.conn == nil do return nil
	if tx.committed || tx.rolled_back do return nil

	_, err := pgorm.exec(tx.conn, "ROLLBACK;")
	tx.rolled_back = true
	return err
}

/*
	tx_savepoint creates a savepoint inside the transaction.
*/
tx_savepoint :: proc(tx: ^Tx, name: string) -> Error {
	if tx == nil || tx.conn == nil do return Net_Error{type = .Socket_Closed}
	if tx.committed || tx.rolled_back do return Protocol_Error{type = .Unexpected_Message, message = "Transaction is closed"}
	sql := fmt.tprintf("SAVEPOINT %s;", name)
	_, err := pgorm.exec(tx.conn, sql)
	return err
}

/*
	tx_rollback_to_savepoint rolls back to a named savepoint.
*/
tx_rollback_to_savepoint :: proc(tx: ^Tx, name: string) -> Error {
	if tx == nil || tx.conn == nil do return Net_Error{type = .Socket_Closed}
	if tx.committed || tx.rolled_back do return Protocol_Error{type = .Unexpected_Message, message = "Transaction is closed"}
	sql := fmt.tprintf("ROLLBACK TO SAVEPOINT %s;", name)
	_, err := pgorm.exec(tx.conn, sql)
	return err
}

/*
	tx_release_savepoint destroys a named savepoint.
*/
tx_release_savepoint :: proc(tx: ^Tx, name: string) -> Error {
	if tx == nil || tx.conn == nil do return Net_Error{type = .Socket_Closed}
	if tx.committed || tx.rolled_back do return Protocol_Error{type = .Unexpected_Message, message = "Transaction is closed"}
	sql := fmt.tprintf("RELEASE SAVEPOINT %s;", name)
	_, err := pgorm.exec(tx.conn, sql)
	return err
}

/*
	tx_query_struct executes a query inside the transaction and maps the first row to struct T.
*/
tx_query_struct :: proc(
	tx: ^Tx,
	$T: typeid,
	sql: string,
	args: ..any,
	allocator := context.temp_allocator,
) -> (
	result: T,
	err: Error,
) where intrinsics.type_is_struct(T) {
	if tx == nil || tx.conn == nil do return result, Net_Error{type = .Socket_Closed}
	return pgorm.query_struct(tx.conn, T, sql, ..args, allocator = allocator)
}

/*
	tx_query_slice executes a query inside the transaction and maps all rows to []T.
*/
tx_query_slice :: proc(
	tx: ^Tx,
	$T: typeid,
	sql: string,
	args: ..any,
	allocator := context.temp_allocator,
) -> (
	result: []T,
	err: Error,
) where intrinsics.type_is_struct(T) {
	if tx == nil || tx.conn == nil do return nil, Net_Error{type = .Socket_Closed}
	return pgorm.query_slice(tx.conn, T, sql, ..args, allocator = allocator)
}

/*
	tx_exec executes a command inside the transaction.
*/
tx_exec :: proc(
	tx: ^Tx,
	sql: string,
	args: ..any,
) -> (
	rows_affected: int,
	err: Error,
) {
	if tx == nil || tx.conn == nil do return 0, Net_Error{type = .Socket_Closed}
	return pgorm.exec(tx.conn, sql, ..args)
}
