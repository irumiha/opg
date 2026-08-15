#!/usr/bin/env bash
# Full test suite including integration tests. Starts PostgreSQL via docker
# compose automatically (idempotent, health-checked) and leaves it running
# for fast repeat runs; reset it with `docker compose down`.
set -euo pipefail
cd "$(dirname "$0")/.."
odin test tests -all-packages -vet -strict-style -define:OPG_INTEGRATION=true "$@"
