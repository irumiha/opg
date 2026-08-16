#!/usr/bin/env bash
# Provisions the auth scenarios the integration tests need on an already-running
# PostgreSQL, for hosts where the docker-compose path is not used (the CI
# runners, or a developer's native server reached via PG* variables).
#
# This is the native-host counterpart of scripts/pg-init/01-auth-scenarios.sh,
# which the docker image runs once at initdb time. Keep the two in step: the
# roles and hba rules defined here are what the auth tests assert against.
#
# Test-provisioning only: it opens cleartext and md5 auth for two throwaway
# roles. Do not run it against a server holding real data.
#
# Safe to re-run: roles are refreshed in place and the hba edit is guarded by a
# sentinel comment, so repeated runs converge instead of stacking duplicates.
set -euo pipefail

echo "=== Initializing test roles and auth scenarios ==="

PGHOST="${PGHOST:-127.0.0.1}"
PGPORT="${PGPORT:-5432}"
PGUSER="${PGUSER:-opg}"
PGDATABASE="${PGDATABASE:-opg_test}"
export PGPASSWORD="${PGPASSWORD:-opg}"

psql_opg() {
	psql -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d "$PGDATABASE" "$@"
}

# Create the test users for cleartext and MD5 authentication tests.
#
# Passwords are (re)set on every run rather than only at creation time. An
# opg_md5 role left behind by a partial earlier run can hold a SCRAM secret,
# and a SCRAM-stored secret silently upgrades the md5 hba rule to SASL — the
# md5 test then fails with no indication of why.
psql_opg -v ON_ERROR_STOP=1 <<-'SQL'
	DO $$
	BEGIN
		IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'opg_clear') THEN
			CREATE ROLE opg_clear LOGIN;
		END IF;
		IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'opg_md5') THEN
			CREATE ROLE opg_md5 LOGIN;
		END IF;
	END
	$$;

	SET password_encryption = 'scram-sha-256';
	ALTER ROLE opg_clear PASSWORD 'opg';

	SET password_encryption = 'md5';
	ALTER ROLE opg_md5 PASSWORD 'opg';
SQL

# Locate pg_hba.conf. Native psql.exe on Windows ends lines with CRLF and
# command substitution strips only the newline; the carriage return has to go
# too, or every use below names a path that cannot exist on Windows.
HBA_FILE=$(psql_opg -t -A -c "SHOW hba_file;" | tr -d '\r')
echo "Found pg_hba.conf at: $HBA_FILE"

# pg_hba is first-match-wins, so these rules must precede the catch-all
# scram-sha-256 line: prepend them. The address is 'all' to match the docker
# path, so the forced auth method still applies when the suite runs from a
# different machine than the server.
HBA_SENTINEL='# opg test auth scenarios (managed by scripts/ci-setup-postgres.sh)'

if grep -qF "$HBA_SENTINEL" "$HBA_FILE"; then
	echo "Auth scenario rules already present; leaving pg_hba.conf unchanged."
else
	TEMP_HBA="$(mktemp)"
	{
		printf '%s\n' "$HBA_SENTINEL"
		printf 'host all opg_clear all password\n'
		printf 'host all opg_md5 all md5\n'
		cat "$HBA_FILE"
	} > "$TEMP_HBA"
	cat "$TEMP_HBA" > "$HBA_FILE"
	rm "$TEMP_HBA"
	echo "Prepended auth scenario rules to pg_hba.conf."
fi

# Reload configuration
psql_opg -c "SELECT pg_reload_conf();"
echo "=== PostgreSQL test configuration reloaded successfully ==="
