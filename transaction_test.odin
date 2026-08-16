package opg

@(require) import "core:testing"
@(require) import "pgconn"

OPG_INTEGRATION :: #config(OPG_INTEGRATION, false)

when OPG_INTEGRATION {

	Test_Tx_Account :: struct {
		id:      i32,
		name:    string,
		balance: f64,
	}

	@(test)
	test_transaction_commit_and_rollback :: proc(t: ^testing.T) {
		cfg := pgconn.integration_conn_config(t)

		conn, cerr := connect(cfg)
		if cerr != nil {
			if pg_err, is_pg := cerr.(Postgres_Error); is_pg {
				postgres_error_destroy(pg_err, context.allocator)
			}
			testing.expect(t, cerr == nil, "connect failed")
			return
		}
		defer disconnect(conn)

		// 1. Setup table
		_, ddl_err := exec(conn, "CREATE TEMP TABLE test_accounts (id int primary key, name text, balance float8);")
		testing.expect_value(t, ddl_err, nil)

		// 2. Commit transaction
		tx, tx_err := begin_transaction(conn)
		testing.expect_value(t, tx_err, nil)
		defer tx_rollback(&tx)

		_, ins1_err := tx_exec(&tx, "INSERT INTO test_accounts (id, name, balance) VALUES ($1, $2, $3);", 1, "Alice", 100.0)
		testing.expect_value(t, ins1_err, nil)

		commit_err := tx_commit(&tx)
		testing.expect_value(t, commit_err, nil)

		// Verify row committed
		alice, q_err := query_struct(conn, Test_Tx_Account, "SELECT id, name, balance FROM test_accounts WHERE id = 1;")
		testing.expect_value(t, q_err, nil)
		testing.expect_value(t, alice.name, "Alice")
		testing.expect_value(t, alice.balance, 100.0)

		// 3. Rollback transaction
		tx2, tx2_err := begin_transaction(conn)
		testing.expect_value(t, tx2_err, nil)

		_, ins2_err := tx_exec(&tx2, "INSERT INTO test_accounts (id, name, balance) VALUES ($1, $2, $3);", 2, "Bob", 50.0)
		testing.expect_value(t, ins2_err, nil)

		rb_err := tx_rollback(&tx2)
		testing.expect_value(t, rb_err, nil)

		// Verify Bob was not committed
		accounts, all_err := query_slice(conn, Test_Tx_Account, "SELECT id, name, balance FROM test_accounts ORDER BY id;")
		testing.expect_value(t, all_err, nil)
		testing.expect_value(t, len(accounts), 1)
		testing.expect_value(t, accounts[0].id, i32(1))
	}

	@(test)
	test_transaction_savepoints :: proc(t: ^testing.T) {
		cfg := pgconn.integration_conn_config(t)

		conn, cerr := connect(cfg)
		if cerr != nil {
			if pg_err, is_pg := cerr.(Postgres_Error); is_pg {
				postgres_error_destroy(pg_err, context.allocator)
			}
			testing.expect(t, cerr == nil, "connect failed")
			return
		}
		defer disconnect(conn)

		_, ddl_err := exec(conn, "CREATE TEMP TABLE test_savepoints (id int primary key, val text);")
		testing.expect_value(t, ddl_err, nil)

		tx, tx_err := begin_transaction(conn)
		testing.expect_value(t, tx_err, nil)
		defer tx_rollback(&tx)

		_, err1 := tx_exec(&tx, "INSERT INTO test_savepoints (id, val) VALUES (1, 'initial');")
		testing.expect_value(t, err1, nil)

		sp_err := tx_savepoint(&tx, "sp1")
		testing.expect_value(t, sp_err, nil)

		_, err2 := tx_exec(&tx, "INSERT INTO test_savepoints (id, val) VALUES (2, 'intermediate');")
		testing.expect_value(t, err2, nil)

		rb_sp_err := tx_rollback_to_savepoint(&tx, "sp1")
		testing.expect_value(t, rb_sp_err, nil)

		commit_err := tx_commit(&tx)
		testing.expect_value(t, commit_err, nil)

		Item :: struct { id: i32, val: string }
		rows, q_err := query_slice(conn, Item, "SELECT id, val FROM test_savepoints ORDER BY id;")
		testing.expect_value(t, q_err, nil)
		testing.expect_value(t, len(rows), 1)
		testing.expect_value(t, rows[0].id, i32(1))
		testing.expect_value(t, rows[0].val, "initial")
	}
}
