package tls_stress

/*
	Minimal reproduction harness for the TLS-under-concurrency hang.

	The test suite showed the fault only when many connections are established
	at once: every test passes in isolation, and the whole suite passes with
	PGSSLMODE=disable. This strips the test framework away and does nothing but
	open TLS connections concurrently, so a hang here is unambiguously in the
	driver's TLS path.

	Each worker publishes the stage it is in. The main thread prints a heartbeat
	of per-worker stages, so a stall names the operation that is stuck (connect,
	query, or disconnect) without attaching a debugger.

	Usage, from the repository root:

	    odin run tools/tls-stress -- [threads] [iterations]

	Honors the same PG* variables as the test harness, including PGSSLMODE.
*/

import "base:intrinsics"
import "core:fmt"
import "core:os"
import "core:strconv"
import "core:strings"
import "core:thread"
import "core:time"
import opg "../.."

Stage :: enum i32 {
	Idle,
	Connecting,
	Querying,
	Disconnecting,
	Done,
	Failed,
}

Worker :: struct {
	id:         int,
	iterations: int,
	config:     opg.Conn_Config,
	stage:      i32, // Stage, read across threads
	completed:  i32,
	failure:    string,
}

worker_proc :: proc(t: ^thread.Thread) {
	w := (^Worker)(t.data)

	for i in 0 ..< w.iterations {
		intrinsics.atomic_store(&w.stage, i32(Stage.Connecting))
		conn, cerr := opg.connect(w.config, context.allocator)
		if cerr != nil {
			w.failure = fmt.aprintf("connect: %s", describe_error(cerr))
			intrinsics.atomic_store(&w.stage, i32(Stage.Failed))
			return
		}

		intrinsics.atomic_store(&w.stage, i32(Stage.Querying))
		Row :: struct {
			val: i32,
		}
		row, qerr := opg.query_struct(conn, Row, "SELECT $1::int AS val;", i32(i))
		if qerr != nil || row.val != i32(i) {
			w.failure = fmt.aprintf("query: %s (val=%d want=%d)", describe_error(qerr), row.val, i)
			opg.disconnect(conn)
			intrinsics.atomic_store(&w.stage, i32(Stage.Failed))
			return
		}

		intrinsics.atomic_store(&w.stage, i32(Stage.Disconnecting))
		opg.disconnect(conn)
		intrinsics.atomic_add(&w.completed, 1)
	}

	intrinsics.atomic_store(&w.stage, i32(Stage.Done))
}

env_or :: proc(name, fallback: string) -> string {
	if v := os.get_env(name, context.allocator); v != "" do return v
	return fallback
}

/*
	resolve_port mirrors the integration harness: PGPORT wins, otherwise ask
	docker for the compose service's mapped port. docker-compose.yml binds an
	ephemeral host port, so assuming 5432 lands on whatever other PostgreSQL
	the machine happens to run — which shows up as an authentication failure
	against an unrelated server rather than anything to do with this driver.
*/
resolve_port :: proc() -> int {
	if v := os.get_env("PGPORT", context.allocator); v != "" {
		if p, ok := strconv.parse_int(v); ok do return p
	}
	// An explicit host means an external server; do not consult docker.
	if os.get_env("PGHOST", context.allocator) != "" do return 5432

	state, out, _, err := os.process_exec(
		{command = {"docker", "compose", "port", "postgres", "5432"}},
		context.allocator,
	)
	if err == nil && state.success {
		endpoint := strings.trim_space(string(out))
		if colon := strings.last_index_byte(endpoint, ':'); colon >= 0 {
			if p, ok := strconv.parse_int(endpoint[colon + 1:]); ok {
				return p
			}
		}
	}
	return 5432
}

/*
	describe_error keeps the heartbeat readable. A server-side failure repeated
	across every worker is one fact, not thirty-two.
*/
describe_error :: proc(err: opg.Error) -> string {
	if pg_err, is_pg := err.(opg.Postgres_Error); is_pg {
		msg := fmt.aprintf("%s %s: %s", pg_err.severity, pg_err.code, pg_err.message)
		opg.postgres_error_destroy(pg_err, context.allocator)
		return msg
	}
	return fmt.aprintf("%v", err)
}

main :: proc() {
	threads_n := 32
	iterations := 20
	args := os.args[1:]
	if len(args) > 0 do threads_n, _ = strconv.parse_int(args[0])
	if len(args) > 1 do iterations, _ = strconv.parse_int(args[1])

	port := resolve_port()

	config := opg.Conn_Config {
		host             = env_or("PGHOST", "127.0.0.1"),
		port             = port,
		user             = env_or("PGUSER", "opg"),
		password         = env_or("PGPASSWORD", "opg"),
		database         = env_or("PGDATABASE", "opg_test"),
		application_name = "opg-tls-stress",
	}
	switch env_or("PGSSLMODE", "prefer") {
	case "disable":
		config.ssl_mode = .Disable
	case "require":
		config.ssl_mode = .Require
	case:
		config.ssl_mode = .Prefer
	}

	fmt.printfln(
		"tls-stress: %d threads x %d iterations against %s:%d (sslmode=%v, backend=%s)",
		threads_n, iterations, config.host, config.port, config.ssl_mode, opg.tls_backend_name(),
	)

	workers := make([]Worker, threads_n)
	threads := make([]^thread.Thread, threads_n)
	for i in 0 ..< threads_n {
		workers[i] = Worker{id = i, iterations = iterations, config = config}
		threads[i] = thread.create(worker_proc)
		threads[i].data = rawptr(&workers[i])
		thread.start(threads[i])
	}

	// Heartbeat until every worker settles. A stalled run keeps printing, and
	// the stage counts say which operation is stuck.
	start := time.now()
	for {
		time.sleep(time.Second)

		counts: [Stage]int
		total_done := 0
		settled := 0
		for i in 0 ..< threads_n {
			s := Stage(intrinsics.atomic_load(&workers[i].stage))
			counts[s] += 1
			total_done += int(intrinsics.atomic_load(&workers[i].completed))
			if s == .Done || s == .Failed do settled += 1
		}

		fmt.printfln(
			"[%4.0fs] completed=%d/%d  connecting=%d querying=%d disconnecting=%d done=%d failed=%d",
			time.duration_seconds(time.since(start)),
			total_done, threads_n * iterations,
			counts[.Connecting], counts[.Querying], counts[.Disconnecting],
			counts[.Done], counts[.Failed],
		)

		if settled == threads_n do break

		if time.since(start) > 120 * time.Second {
			fmt.println("STALLED - workers still in flight after 120s:")
			for i in 0 ..< threads_n {
				s := Stage(intrinsics.atomic_load(&workers[i].stage))
				if s != .Done && s != .Failed {
					fmt.printfln(
						"  worker %d stuck in %v after %d completed iterations",
						i, s, intrinsics.atomic_load(&workers[i].completed),
					)
				}
			}
			os.exit(1)
		}
	}

	failures := 0
	tally := make(map[string]int)
	for i in 0 ..< threads_n {
		thread.join(threads[i])
		if workers[i].failure != "" {
			tally[workers[i].failure] += 1
			failures += 1
		}
	}
	for msg, count in tally {
		fmt.printfln("  %d workers failed: %s", count, msg)
	}
	fmt.printfln("tls-stress: finished in %.1fs with %d failed workers", time.duration_seconds(time.since(start)), failures)
	if failures > 0 do os.exit(1)
}
