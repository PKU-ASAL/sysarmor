#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
TEST_PACKAGE="./apps/manager/internal/adapters/outbound/postgres/worker"

if [[ -n "${SYSARMOR_TEST_POSTGRES_DSN:-}" ]]; then
  cd "$ROOT"
  go test "$TEST_PACKAGE" -run '^TestTelemetryBatchesPostgres' -count=1 -v
  exit
fi

container="sysarmor-postgres-worker-test-$$"
cleanup() { docker rm -f "$container" >/dev/null 2>&1 || true; }
trap cleanup EXIT

docker run -d --rm --name "$container" -e POSTGRES_USER=sysarmor -e POSTGRES_PASSWORD=sysarmor \
  -e POSTGRES_DB=sysarmor -p 127.0.0.1::5432 postgres:16-alpine >/dev/null
port="$(docker port "$container" 5432/tcp | sed -n 's/.*://p')"
[[ "$port" =~ ^[0-9]+$ ]] || { echo "[postgres-worker-test][ERROR] invalid PostgreSQL port: $port" >&2; exit 1; }

deadline=$((SECONDS + 60))
until docker exec "$container" pg_isready -h 127.0.0.1 -p 5432 -U sysarmor -d sysarmor >/dev/null 2>&1; do
  (( SECONDS < deadline )) || { docker logs "$container" >&2; exit 1; }
  sleep 1
done

cd "$ROOT"
SYSARMOR_TEST_POSTGRES_DSN="postgres://sysarmor:sysarmor@127.0.0.1:$port/sysarmor?sslmode=disable" \
  go test "$TEST_PACKAGE" -run '^TestTelemetryBatchesPostgres' -count=1 -v
