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
