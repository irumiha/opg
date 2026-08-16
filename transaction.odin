package opg

/*
	opg – Database Transactions & Savepoints API

	Provides ACID transaction lifecycle management over PostgreSQL connections,
	including configurable transaction isolation levels, read-only/read-write
	access modes, deferrable serializable transactions, and nested savepoints.

	Standard Usage Pattern:
	  tx, err := opg.begin_transaction(conn)
	  if err != nil do return err
	  defer opg.tx_rollback(&tx) // Safe & idempotent: no-op if committed

	  opg.tx_exec(&tx, "INSERT INTO accounts (id, balance) VALUES ($1, $2);", 1, 100) or_return
	  opg.tx_exec(&tx, "INSERT INTO audit_log (action) VALUES ($1);", "account_created") or_return

	  return opg.tx_commit(&tx)
*/

import "base:intrinsics"
import "core:fmt"
import "pgmap"

// ============================================================================
// 1. Transaction Options & Modes
// ============================================================================

/*
	Isolation_Level controls the transaction isolation level in PostgreSQL:
	  - Default: Uses server-default isolation level (typically Read Committed).
	  - Read_Committed: Statements see data committed before the statement began.
	  - Repeatable_Read: All statements in the current transaction see a snapshot
	                     as of the first query in the transaction.
	  - Serializable: Strict serializable execution simulating sequential transactions.
*/
Isolation_Level :: enum {
	Default,
	Read_Committed,
	Repeatable_Read,
	Serializable,
}

/*
	Tx_Access_Mode specifies whether the transaction allows write operations:
	  - Read_Write: Allows INSERT, UPDATE, DELETE, and DDL operations. (Default)
	  - Read_Only: Disallows non-temporary table modifications.
*/
Tx_Access_Mode :: enum {
	Read_Write,
	Read_Only,
}

/*
	Tx_Options configures isolation level, access mode, and deferrable attributes
	for a new transaction.
*/
Tx_Options :: struct {
	isolation:  Isolation_Level,
	access:     Tx_Access_Mode,
	deferrable: bool,
}

/*
	Tx is a handle representing an active database transaction.
	Guarantees idempotency: multiple calls to commit or rollback after
	completion are safe no-ops.
*/
Tx :: struct {
	conn:        ^Conn,
	committed:   bool,
	rolled_back: bool,
}

// ============================================================================
// 2. Transaction Lifecycle
// ============================================================================

/*
	begin_transaction begins a new transaction on the given connection with the
	specified options (or default READ WRITE isolation).

	Parameters:
	  - conn: Active database connection.
	  - options: Transaction options (isolation level, access mode, deferrable).
	  - allocator: Allocator used for temporary query formatting.

	Returns:
	  - An active Tx handle, or an Error on failure.

	Example:
	  tx, err := opg.begin_transaction(conn, {
	      isolation = .Serializable,
	      access    = .Read_Write,
	  })
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

	_, exec_err := pgmap.exec(conn, begin_sql)
	if exec_err != nil do return tx, exec_err

	tx.conn = conn
	return tx, nil
}

/*
	tx_commit commits all changes made within the active transaction to the database.
	Marks the transaction as committed. Calling tx_commit on an already finished
	transaction is a safe no-op.

	Returns:
	  - Error if the COMMIT command fails on the server.
*/
tx_commit :: proc(tx: ^Tx) -> Error {
	if tx == nil || tx.conn == nil do return Net_Error{type = .Socket_Closed}
	if tx.committed || tx.rolled_back do return nil

	_, err := pgmap.exec(tx.conn, "COMMIT;")
	if err != nil do return err

	tx.committed = true
	return nil
}

/*
	tx_rollback rolls back and aborts all changes made within the transaction.
	Marks the transaction as rolled back. Designed to be safely called inside
	a `defer opg.tx_rollback(&tx)` block; if the transaction was already committed,
	this is an immediate no-op.
*/
tx_rollback :: proc(tx: ^Tx) -> Error {
	if tx == nil || tx.conn == nil do return nil
	if tx.committed || tx.rolled_back do return nil

	_, err := pgmap.exec(tx.conn, "ROLLBACK;")
	tx.rolled_back = true
	return err
}

// ============================================================================
// 3. Savepoint Management
// ============================================================================

/*
	tx_savepoint establishes a new named savepoint within the active transaction.
	Savepoints allow partial rollbacks of operations executed after the savepoint
	without rolling back the entire transaction.

	Parameters:
	  - tx: Active transaction handle.
	  - name: Identifier name for the savepoint.
*/
tx_savepoint :: proc(tx: ^Tx, name: string) -> Error {
	if tx == nil || tx.conn == nil do return Net_Error{type = .Socket_Closed}
	if tx.committed || tx.rolled_back do return Protocol_Error{type = .Unexpected_Message, message = "Transaction is closed"}
	sql := fmt.tprintf("SAVEPOINT %s;", name)
	_, err := pgmap.exec(tx.conn, sql)
	return err
}

/*
	tx_rollback_to_savepoint rolls back all statements executed after the specified
	savepoint was established, keeping the surrounding transaction alive.

	Parameters:
	  - tx: Active transaction handle.
	  - name: Identifier name of the savepoint to roll back to.
*/
tx_rollback_to_savepoint :: proc(tx: ^Tx, name: string) -> Error {
	if tx == nil || tx.conn == nil do return Net_Error{type = .Socket_Closed}
	if tx.committed || tx.rolled_back do return Protocol_Error{type = .Unexpected_Message, message = "Transaction is closed"}
	sql := fmt.tprintf("ROLLBACK TO SAVEPOINT %s;", name)
	_, err := pgmap.exec(tx.conn, sql)
	return err
}

/*
	tx_release_savepoint destroys a previously established savepoint within the
	active transaction, making rollback to that savepoint impossible while preserving
	the changes made before or after it.

	Parameters:
	  - tx: Active transaction handle.
	  - name: Identifier name of the savepoint to release.
*/
tx_release_savepoint :: proc(tx: ^Tx, name: string) -> Error {
	if tx == nil || tx.conn == nil do return Net_Error{type = .Socket_Closed}
	if tx.committed || tx.rolled_back do return Protocol_Error{type = .Unexpected_Message, message = "Transaction is closed"}
	sql := fmt.tprintf("RELEASE SAVEPOINT %s;", name)
	_, err := pgmap.exec(tx.conn, sql)
	return err
}

// ============================================================================
// 4. Transactional Query Execution
// ============================================================================

/*
	tx_query_struct executes a parameterized query within the transaction and maps
	the first returned row directly into an Odin struct of type T.

	Parameters:
	  - tx: Active transaction handle.
	  - $T: Target Odin struct typeid.
	  - sql: Parameterized SQL query ($1, $2, ...).
	  - args: Variadic bind parameters.
	  - allocator: Allocator for string/slice fields inside T (default context.temp_allocator).
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
	return pgmap.query_struct(tx.conn, T, sql, ..args, allocator = allocator)
}

/*
	tx_query_slice executes a parameterized query within the transaction and maps
	all returned rows into a newly allocated slice of Odin structs ([]T).

	Parameters:
	  - tx: Active transaction handle.
	  - $T: Target Odin struct typeid.
	  - sql: Parameterized SQL query ($1, $2, ...).
	  - args: Variadic bind parameters.
	  - allocator: Allocator for the returned slice and row fields (default context.temp_allocator).
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
	return pgmap.query_slice(tx.conn, T, sql, ..args, allocator = allocator)
}

/*
	tx_exec executes a parameterized SQL command (e.g. INSERT, UPDATE, DELETE)
	within the active transaction and returns the count of rows affected.

	Parameters:
	  - tx: Active transaction handle.
	  - sql: Parameterized SQL command ($1, $2, ...).
	  - args: Variadic bind parameters.
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
	return pgmap.exec(tx.conn, sql, ..args)
}
