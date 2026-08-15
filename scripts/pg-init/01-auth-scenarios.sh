#!/bin/bash
# Extra users for exercising the driver's non-SCRAM auth paths in
# integration tests. Runs once at initdb time (data dir is tmpfs, so every
# fresh container gets this).
set -e

psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" <<-'SQL'
	CREATE USER opg_clear PASSWORD 'opg';
	-- Store an md5 secret so the server actually issues an MD5 challenge;
	-- a SCRAM-stored secret would silently upgrade the md5 hba rule to SASL.
	SET password_encryption = 'md5';
	CREATE USER opg_md5 PASSWORD 'opg';
SQL

# pg_hba is first-match-wins: these rules must precede the image's
# catch-all "host all all all scram-sha-256" line, so prepend them.
{
	printf 'host all opg_clear all password\n'
	printf 'host all opg_md5 all md5\n'
	cat "$PGDATA/pg_hba.conf"
} > /tmp/pg_hba.conf.new
cat /tmp/pg_hba.conf.new > "$PGDATA/pg_hba.conf"
rm /tmp/pg_hba.conf.new
