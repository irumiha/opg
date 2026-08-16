# Multi-OS Native PostgreSQL CI Integration Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enable live PostgreSQL integration and end-to-end TLS testing across all three operating systems (Linux, macOS, Windows) in GitHub Actions CI using native PostgreSQL provisioning via `ikalnytskyi/action-setup-postgres`.

**Architecture:** Replace the single-OS Docker-only integration job with a multi-OS matrix (`ubuntu-latest`, `macos-latest`, `windows-latest`). On each runner, `ikalnytskyi/action-setup-postgres` provisions a native PostgreSQL 17 instance with SSL enabled. A cross-platform setup step configures the test authentication scenarios (`opg_clear`, `opg_md5`). Integration tests consume `PGHOST`, `PGPORT`, `PGUSER`, `PGPASSWORD`, `PGDATABASE`, bypassing Docker and exercising platform-native TLS backends (OpenSSL on Linux, SecureTransport on macOS, Schannel on Windows).

**Tech Stack:** GitHub Actions, Odin (nightly), PostgreSQL 17, `ikalnytskyi/action-setup-postgres@v8`, Bash.

---

## Global Constraints

- Must maintain 100% test pass rate across all packages with `-vet -strict-style`.
- Local developer workflow using `docker compose` and `scripts/integration-test.sh` must continue to work without changes when `PGHOST` is unset.
- When `PGHOST` is set, test runners must bypass Docker calls completely and target the external/native PostgreSQL server.
- All 3 platform native TLS backends must be exercised against live PostgreSQL:
  - Linux: OpenSSL (`libssl`)
  - macOS: SecureTransport (`Security.framework`)
  - Windows: Schannel (`secur32.dll` / `sspicli.dll`)

---

### Task 1: Harden test environment variable handling in `tests/e2e_test.odin` and `scripts/integration-test.sh`

**Files:**
- Modify: `tests/e2e_test.odin:41-50`
- Modify: `scripts/integration-test.sh:16-18`

**Interfaces:**
- Consumes: Environment variables `PGHOST`, `PGPORT`, `PGUSER`, `PGPASSWORD`, `PGDATABASE`.
- Produces: `get_test_conn_config() -> opg.Conn_Config` reading `PGHOST` and `PG*` env vars consistently with `pgconn/integration_test.odin`.

- [ ] **Step 1: Update `get_test_conn_config` in `tests/e2e_test.odin`**

```odin
	get_test_conn_config :: proc() -> opg.Conn_Config {
		host := "127.0.0.1"
		if env_host := os.get_env("PGHOST", context.temp_allocator); env_host != "" {
			host = env_host
		}
		cfg := opg.Conn_Config{
			host     = host,
			port     = get_integration_port(),
			user     = "opg",
			password = "opg",
			database = "opg_test",
		}
		if v := os.get_env("PGUSER", context.temp_allocator); v != "" {
			cfg.user = v
		}
		if v := os.get_env("PGPASSWORD", context.temp_allocator); v != "" {
			cfg.password = v
		}
		if v := os.get_env("PGDATABASE", context.temp_allocator); v != "" {
			cfg.database = v
		}
		return cfg
	}
```

- [ ] **Step 2: Update `scripts/integration-test.sh` to only start Docker when `PGHOST` is unset**

```bash
# Ensure docker compose postgres is up only if targeting local docker (PGHOST unset)
if [ -z "${PGHOST:-}" ]; then
  docker compose up -d --wait postgres
fi
```

- [ ] **Step 3: Test local integration suite**

Run: `scripts/integration-test.sh`
Expected: PASS (192 tests pass against local Docker instance).

- [ ] **Step 4: Commit**

```bash
git add tests/e2e_test.odin scripts/integration-test.sh
git commit -m "fix(tests): make e2e harness respect PGHOST and PG* environment variables"
```

---

### Task 2: Create cross-platform database configuration helper script for CI

**Files:**
- Create: `scripts/ci-setup-postgres.sh`

**Interfaces:**
- Consumes: Running PostgreSQL instance accessible via `psql` using standard `PG*` environment variables or defaults (`-h 127.0.0.1 -p 5432 -U opg -d opg_test`).
- Produces: Configured `opg_clear` (cleartext password) and `opg_md5` (md5) roles, prepended `pg_hba.conf` rules, reloaded config via `SELECT pg_reload_conf();`.

- [ ] **Step 1: Write `scripts/ci-setup-postgres.sh`**

```bash
#!/usr/bin/env bash
set -euo pipefail

echo "=== Initializing test roles and auth scenarios ==="

PGHOST="${PGHOST:-127.0.0.1}"
PGPORT="${PGPORT:-5432}"
PGUSER="${PGUSER:-opg}"
PGDATABASE="${PGDATABASE:-opg_test}"
export PGPASSWORD="${PGPASSWORD:-opg}"

# Create the test users for cleartext and MD5 authentication tests
psql -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d "$PGDATABASE" -v ON_ERROR_STOP=1 <<-'SQL'
	DO $$
	BEGIN
		IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'opg_clear') THEN
			CREATE USER opg_clear PASSWORD 'opg';
		END IF;
		IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'opg_md5') THEN
			SET password_encryption = 'md5';
			CREATE USER opg_md5 PASSWORD 'opg';
		END IF;
	END
	$$;
SQL

# Locate and update pg_hba.conf to route opg_clear and opg_md5 to their respective auth methods
HBA_FILE=$(psql -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d "$PGDATABASE" -t -A -c "SHOW hba_file;")
echo "Found pg_hba.conf at: $HBA_FILE"

TEMP_HBA="$(mktemp)"
{
	printf 'host all opg_clear 127.0.0.1/32 password\n'
	printf 'host all opg_clear ::1/128 password\n'
	printf 'host all opg_md5 127.0.0.1/32 md5\n'
	printf 'host all opg_md5 ::1/128 md5\n'
	cat "$HBA_FILE"
} > "$TEMP_HBA"

cat "$TEMP_HBA" > "$HBA_FILE"
rm "$TEMP_HBA"

# Reload configuration
psql -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d "$PGDATABASE" -c "SELECT pg_reload_conf();"
echo "=== PostgreSQL test configuration reloaded successfully ==="
```

- [ ] **Step 2: Make executable**

```bash
chmod +x scripts/ci-setup-postgres.sh
```

- [ ] **Step 3: Commit**

```bash
git add scripts/ci-setup-postgres.sh
git commit -m "ci: add cross-platform postgresql initialization script"
```

---

### Task 3: Update GitHub Actions `.github/workflows/ci.yml` to run integration tests on Linux, macOS, and Windows

**Files:**
- Modify: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: `ikalnytskyi/action-setup-postgres@v8`, `scripts/ci-setup-postgres.sh`, `laytan/setup-odin@v2`.
- Produces: Multi-OS matrix integration job running `odin test tests -all-packages -define:OPG_INTEGRATION=true` on Ubuntu, macOS, and Windows.

- [ ] **Step 1: Update `.github/workflows/ci.yml`**

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  # --------------------------------------------------------------------------
  # Offline gate: compile check + offline unit tests on all 3 OS platforms.
  # --------------------------------------------------------------------------
  offline:
    strategy:
      fail-fast: false
      matrix:
        os: [ubuntu-latest, macos-latest, windows-latest]

    runs-on: ${{ matrix.os }}
    name: offline (${{ matrix.os }})
    steps:
      - uses: actions/checkout@v7

      - name: Install Odin
        uses: laytan/setup-odin@v2
        with:
          release: nightly

      - name: Verify Odin installation
        shell: bash
        run: odin version

      - name: Compile check (no entry point)
        shell: bash
        run: odin check . -no-entry-point -vet -strict-style

      - name: Run offline tests
        shell: bash
        run: odin test tests -all-packages -vet -strict-style

  # --------------------------------------------------------------------------
  # Multi-OS Integration: native PostgreSQL on Linux, macOS, and Windows.
  # Exercises live database queries, authentication scenarios, and platform
  # TLS backends (OpenSSL on Linux, SecureTransport on macOS, Schannel on Windows).
  # --------------------------------------------------------------------------
  integration:
    strategy:
      fail-fast: false
      matrix:
        os: [ubuntu-latest, macos-latest, windows-latest]

    runs-on: ${{ matrix.os }}
    name: integration (${{ matrix.os }})
    needs: offline
    steps:
      - uses: actions/checkout@v7

      - name: Install Odin
        uses: laytan/setup-odin@v2
        with:
          release: nightly

      - name: Setup Native PostgreSQL
        uses: ikalnytskyi/action-setup-postgres@v8
        id: postgres
        with:
          postgres-version: '17'
          username: opg
          password: opg
          database: opg_test
          port: 5432
          ssl: true

      - name: Configure Test Auth Scenarios
        shell: bash
        env:
          PGHOST: '127.0.0.1'
          PGPORT: '5432'
          PGUSER: 'opg'
          PGPASSWORD: 'opg'
          PGDATABASE: 'opg_test'
        run: ./scripts/ci-setup-postgres.sh

      - name: Run Integration Tests
        shell: bash
        env:
          PGHOST: '127.0.0.1'
          PGPORT: '5432'
          PGUSER: 'opg'
          PGPASSWORD: 'opg'
          PGDATABASE: 'opg_test'
        run: odin test tests -all-packages -vet -strict-style -define:OPG_INTEGRATION=true

      # Sanitizers on Linux runner
      - name: Integration tests (AddressSanitizer)
        if: runner.os == 'Linux'
        shell: bash
        env:
          PGHOST: '127.0.0.1'
          PGPORT: '5432'
          PGUSER: 'opg'
          PGPASSWORD: 'opg'
          PGDATABASE: 'opg_test'
        run: odin test tests -all-packages -vet -strict-style -define:OPG_INTEGRATION=true -sanitize:address

      - name: Pool concurrency tests (ThreadSanitizer)
        if: runner.os == 'Linux'
        shell: bash
        env:
          PGHOST: '127.0.0.1'
          PGPORT: '5432'
          PGUSER: 'opg'
          PGPASSWORD: 'opg'
          PGDATABASE: 'opg_test'
        run: odin test pgconn -define:OPG_INTEGRATION=true -sanitize:thread
```

- [ ] **Step 2: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: enable multi-OS native PostgreSQL integration testing on Linux, macOS, and Windows"
```

---

### Task 4: Documentation & JIRA Updates

**Files:**
- Modify: `JIRA.md`
- Modify: `README.md`

**Interfaces:**
- Consumes: New multi-OS integration workflow capabilities.
- Produces: Updated CI architecture documentation and task status tracking.

- [ ] **Step 1: Update `JIRA.md` Epic 5 / OPG-501 & OPG-502 documentation**
- [ ] **Step 2: Update `README.md` Testing & CI section**
- [ ] **Step 3: Commit**

```bash
git add JIRA.md README.md
git commit -m "docs: update CI documentation for multi-OS integration testing"
```
