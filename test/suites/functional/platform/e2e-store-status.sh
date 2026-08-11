#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../../../shared/harness/lib/common.sh"

sa_init_repo_paths
TMP="$(sa_make_tmp sysarmor-store-status)"
sa_pick_ports 58000 2000
SA_TEST_NAME="e2e-store-status"
SA_WAIT_LOGS=("$TMP/manager.log")

cleanup() {
  sa_kill_pid_ref MGR_PID
  sa_cleanup_tmp "$TMP"
}
trap cleanup EXIT

echo "[e2e-store-status] building binaries"
sa_build_go_bins sysarmor-manager sysarmorctl

sa_start_postgres_manager

wait_contains() {
  sa_wait_contains "$@"
}

sa_wait_url_contains "$MGR_URL/healthz" '"ok":true' "$RESULTS/e2e-store-status.health.json"

"$BIN/sysarmorctl" --manager-url "$MGR_URL" --json manager store status > "$RESULTS/e2e-store-status.store.json"
for want in '"backend":"memory"' '"state_version":1' '"migration_version":1' '"postgres_schema_version":2'; do
  if ! grep -Fq "$want" "$RESULTS/e2e-store-status.store.json"; then
    echo "[e2e-store-status][ERROR] store status missing $want" >&2
    cat "$RESULTS/e2e-store-status.store.json" >&2
    exit 1
  fi
done

cp "$TMP/manager.log" "$RESULTS/e2e-store-status.manager.log"
echo "[e2e-store-status] ok"
