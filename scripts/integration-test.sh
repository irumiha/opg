#!/usr/bin/env bash
# Full test suite including integration tests. Starts PostgreSQL via docker
# compose automatically (idempotent, health-checked) and leaves it running
# for fast repeat runs; reset it with `docker compose down`.
#
# Usage:
#   scripts/integration-test.sh           # all integration tests
#   scripts/integration-test.sh --asan    # integration + AddressSanitizer
#   scripts/integration-test.sh --tsan    # pgconn ThreadSanitizer only
#   scripts/integration-test.sh --all     # integration + ASan + TSan
#
# Extra flags are forwarded to `odin test`.
set -euo pipefail
cd "$(dirname "$0")/.."

# Ensure docker compose postgres is up only if targeting local docker (PGHOST unset)
if [ -z "${PGHOST:-}" ]; then
  docker compose up -d --wait postgres
fi

# Parse arguments.
RUN_ASAN=false
RUN_TSAN=false
EXTRA_ARGS=()
for arg in "$@"; do
  case "$arg" in
    --asan) RUN_ASAN=true ;;
    --tsan) RUN_TSAN=true ;;
    --all)  RUN_ASAN=true; RUN_TSAN=true ;;
    *)      EXTRA_ARGS+=("$arg") ;;
  esac
done

echo "=== Integration tests ==="
odin test tests -all-packages -vet -strict-style -define:OPG_INTEGRATION=true "${EXTRA_ARGS[@]+"${EXTRA_ARGS[@]}"}"

if [ "$RUN_ASAN" = true ]; then
  echo "=== AddressSanitizer pass ==="
  odin test tests -all-packages -vet -strict-style -define:OPG_INTEGRATION=true -sanitize:address "${EXTRA_ARGS[@]+"${EXTRA_ARGS[@]}"}"
fi

if [ "$RUN_TSAN" = true ]; then
  echo "=== ThreadSanitizer pass (pgconn) ==="
  odin test pgconn -define:OPG_INTEGRATION=true -sanitize:thread "${EXTRA_ARGS[@]+"${EXTRA_ARGS[@]}"}"
fi

echo "=== All requested passes completed successfully ==="
