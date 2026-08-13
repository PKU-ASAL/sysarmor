#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../../../shared/harness/lib/common.sh"

sa_init_repo_paths
TMP="$(sa_make_tmp sysarmor-response-scope-deny)"
sa_pick_ports 46000 2000
AGENT_ID="response-scope-agent"
SA_TEST_NAME="e2e-response-scope-deny"
SA_WAIT_LOGS=("$TMP/manager.log")

cleanup() {
  sa_kill_pid_ref MGR_PID
  sa_cleanup_tmp "$TMP"
}
trap cleanup EXIT

echo "[e2e-response-scope-deny] building binaries"
sa_build_go_bins sysarmor-manager sysarmorctl

sa_start_postgres_manager

wait_contains() {
  sa_wait_contains "$@"
}

sa_wait_url_contains "$MGR_URL/healthz" '"ok":true' "$TMP/health.json"

cat > "$TMP/agent-health.json" <<JSON
{
  "agent_id": "$AGENT_ID",
  "host_id": "response-scope-host",
  "tenant_id": "default",
  "scope": {"type": "container", "selector": "abc123"},
  "status": "ok",
  "policy_id": "default-edr-policy",
  "policy_version": 1,
  "policy_mode": "observe",
  "sensor_health": {"backend": "fake", "installed": true, "running": true, "version": "test", "policy_loaded": true},
  "observed_at": "2026-06-16T00:00:00Z"
}
JSON

sa_manager_curl -sf -X POST "$MGR_URL/api/v1/agent-health" \
  -H 'Content-Type: application/json' \
  --data-binary @"$TMP/agent-health.json" > "$TMP/agent-health.result.json"

cat > "$TMP/scope-deny-command.json" <<JSON
{
  "response_id": "resp-deny-scope",
  "tenant_id": "default",
  "agent_id": "$AGENT_ID",
  "scope": {"type": "container", "selector": "wrong"},
  "action": "collect",
  "mode": "observe",
  "target": "process:fake",
  "reason": "scope deny e2e",
  "actor": "e2e"
}
JSON

status="$(
  sa_manager_curl -sS -o "$RESULTS/e2e-response-scope-deny.create.json" \
    -w '%{http_code}' \
    -X POST "$MGR_URL/api/v1/responses" \
    -H 'Content-Type: application/json' \
    --data-binary @"$TMP/scope-deny-command.json"
)"
if [[ "$status" != "403" ]]; then
  echo "[e2e-response-scope-deny][ERROR] create status = $status, want 403" >&2
  cat "$RESULTS/e2e-response-scope-deny.create.json" >&2
  exit 1
fi

"$BIN/sysarmorctl" --manager-url "$MGR_URL" --json manager responses list --tenant-id default --agent-id "$AGENT_ID" > "$RESULTS/e2e-response-scope-deny.audit.json"
for want in '"response_id":"resp-deny-scope"' '"status":"denied"' 'response command scope does not match agent runtime scope' '"scope":{"type":"container","selector":"wrong"}'; do
  if ! grep -Fq "$want" "$RESULTS/e2e-response-scope-deny.audit.json"; then
    echo "[e2e-response-scope-deny][ERROR] audit missing $want" >&2
    cat "$RESULTS/e2e-response-scope-deny.audit.json" >&2
    exit 1
  fi
done

"$BIN/sysarmorctl" --manager-url "$MGR_URL" --json manager responses list --tenant-id default --agent-id "$AGENT_ID" --pending > "$RESULTS/e2e-response-scope-deny.pending.json"
if grep -Fq 'resp-deny-scope' "$RESULTS/e2e-response-scope-deny.pending.json"; then
  echo "[e2e-response-scope-deny][ERROR] denied command is pending" >&2
  cat "$RESULTS/e2e-response-scope-deny.pending.json" >&2
  exit 1
fi

cp "$TMP/manager.log" "$RESULTS/e2e-response-scope-deny.manager.log"
echo "[e2e-response-scope-deny] ok"
