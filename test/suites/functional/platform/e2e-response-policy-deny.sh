#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../../../shared/harness/lib/common.sh"

sa_init_repo_paths
TMP="$(sa_make_tmp sysarmor-response-deny)"
sa_pick_ports 44000 2000
AGENT_ID="response-deny-agent"
SA_TEST_NAME="e2e-response-policy-deny"
SA_WAIT_LOGS=("$TMP/manager.log")

cleanup() {
  sa_kill_pid_ref MGR_PID
  sa_cleanup_tmp "$TMP"
}
trap cleanup EXIT

echo "[e2e-response-policy-deny] building binaries"
sa_build_go_bins sysarmor-manager sysarmorctl

sa_start_postgres_manager

wait_contains() {
  sa_wait_contains "$@"
}

sa_wait_url_contains "$MGR_URL/healthz" '"ok":true' "$TMP/health.json"

cat > "$TMP/deny-command.json" <<JSON
{
  "response_id": "resp-deny-kill",
  "tenant_id": "default",
  "agent_id": "$AGENT_ID",
  "action": "kill",
  "mode": "observe",
  "target": "process:danger",
  "reason": "policy deny e2e",
  "actor": "e2e"
}
JSON

status="$(
  sa_manager_curl -sS -o "$RESULTS/e2e-response-policy-deny.create.json" \
    -w '%{http_code}' \
    -X POST "$MGR_URL/api/v1/responses" \
    -H 'Content-Type: application/json' \
    --data-binary @"$TMP/deny-command.json"
)"
if [[ "$status" != "403" ]]; then
  echo "[e2e-response-policy-deny][ERROR] create status = $status, want 403" >&2
  cat "$RESULTS/e2e-response-policy-deny.create.json" >&2
  exit 1
fi

"$BIN/sysarmorctl" --manager-url "$MGR_URL" --json manager responses list --tenant-id default --agent-id "$AGENT_ID" > "$RESULTS/e2e-response-policy-deny.audit.json"
for want in '"response_id":"resp-deny-kill"' '"status":"denied"' 'destructive response action requires explicit policy approval'; do
  if ! grep -Fq "$want" "$RESULTS/e2e-response-policy-deny.audit.json"; then
    echo "[e2e-response-policy-deny][ERROR] audit missing $want" >&2
    cat "$RESULTS/e2e-response-policy-deny.audit.json" >&2
    exit 1
  fi
done

"$BIN/sysarmorctl" --manager-url "$MGR_URL" --json manager responses list --tenant-id default --agent-id "$AGENT_ID" --pending > "$RESULTS/e2e-response-policy-deny.pending.json"
if grep -Fq 'resp-deny-kill' "$RESULTS/e2e-response-policy-deny.pending.json"; then
  echo "[e2e-response-policy-deny][ERROR] denied command is pending" >&2
  cat "$RESULTS/e2e-response-policy-deny.pending.json" >&2
  exit 1
fi

cp "$TMP/manager.log" "$RESULTS/e2e-response-policy-deny.manager.log"
echo "[e2e-response-policy-deny] ok"
