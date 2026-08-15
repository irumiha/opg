#!/bin/bash
# Enables TLS on the test server using the committed self-signed cert.
# Runs at initdb time as the postgres user; the settings take effect when
# the entrypoint starts the real server.
set -e
cp /opg-certs/server.crt /opg-certs/server.key "$PGDATA/"
chmod 600 "$PGDATA/server.key"
cat >> "$PGDATA/postgresql.conf" <<-EOF
	ssl = on
	ssl_cert_file = 'server.crt'
	ssl_key_file = 'server.key'
EOF
