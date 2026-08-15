#!/usr/bin/env bash
# Regenerates the committed self-signed TEST certificate for the docker
# compose PostgreSQL. This key is intentionally public test material -
# never use it anywhere real.
set -euo pipefail
cd "$(dirname "$0")"
openssl req -x509 -newkey rsa:2048 -nodes -days 36500 \
	-keyout server.key -out server.crt \
	-subj "/CN=localhost" \
	-addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
