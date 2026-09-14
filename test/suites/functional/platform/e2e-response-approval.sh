#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../../../shared/harness/lib/common.sh"

sa_init_repo_paths
TMP="$(sa_make_tmp sysarmor-response-approval)"
sa_pick_ports 50000 2000
AGENT_ID="response-approval-agent"
SA_TEST_NAME="e2e-response-approval"
SA_WAIT_LOGS=("$TMP/manager.log")

cleanup() {
  sa_kill_pid_ref MGR_PID
  sa_cleanup_tmp "$TMP"
}
trap cleanup EXIT

echo "[e2e-response-approval] building binaries"
sa_build_go_bins sysarmor-manager sysarmorctl

sa_start_postgres_manager

wait_contains() {
  sa_wait_contains "$@"
}

sa_wait_url_contains "$MGR_URL/healthz" '"ok":true' "$TMP/health.json"

cat > "$TMP/response.json" <<JSON
{
  "response_id": "resp-approval-collect",
  "tenant_id": "default",
  "agent_id": "$AGENT_ID",
  "action": "collect",
  "mode": "observe",
  "target": "process:approval",
  "reason": "approval required e2e",
  "actor": "e2e",
  "approval_required": true
}
JSON

sa_manager_curl -sf -X POST "$MGR_URL/api/v1/responses" \
  -H 'Content-Type: application/json' \
  --data-binary @"$TMP/response.json" > "$RESULTS/e2e-response-approval.create.json"

for want in '"response_id":"resp-approval-collect"' '"status":"pending_approval"' '"approval_required":true' '"approval_status":"required"'; do
  if ! grep -Fq "$want" "$RESULTS/e2e-response-approval.create.json"; then
    echo "[e2e-response-approval][ERROR] create missing $want" >&2
    cat "$RESULTS/e2e-response-approval.create.json" >&2
    exit 1
  fi
done

"$BIN/sysarmorctl" --manager-url "$MGR_URL" --json manager responses list --tenant-id default --agent-id "$AGENT_ID" --pending > "$RESULTS/e2e-response-approval.pending-before.json"
if grep -Fq 'resp-approval-collect' "$RESULTS/e2e-response-approval.pending-before.json"; then
  echo "[e2e-response-approval][ERROR] pending_approval command is pending before approval" >&2
  cat "$RESULTS/e2e-response-approval.pending-before.json" >&2
  exit 1
fi

"$BIN/sysarmorctl" --manager-url "$MGR_URL" --json manager response approve \
  --tenant-id default \
  --agent-id "$AGENT_ID" \
  --response-id resp-approval-collect \
  --actor analyst \
  --reason "approved for evidence collection" > "$RESULTS/e2e-response-approval.approve.json"

for want in '"response_id":"resp-approval-collect"' '"status":"pending"' '"approval_status":"approved"' '"approved_by":"test-admin"'; do
  if ! grep -Fq "$want" "$RESULTS/e2e-response-approval.approve.json"; then
    echo "[e2e-response-approval][ERROR] approval missing $want" >&2
    cat "$RESULTS/e2e-response-approval.approve.json" >&2
    exit 1
  fi
done
if grep -Fq '"approved_by":"analyst"' "$RESULTS/e2e-response-approval.approve.json"; then
  echo "[e2e-response-approval][ERROR] approval trusted spoofed actor" >&2
  cat "$RESULTS/e2e-response-approval.approve.json" >&2
  exit 1
fi

"$BIN/sysarmorctl" --manager-url "$MGR_URL" --json manager responses list --tenant-id default --agent-id "$AGENT_ID" --pending > "$RESULTS/e2e-response-approval.pending-after.json"
if ! grep -Fq '"response_id":"resp-approval-collect"' "$RESULTS/e2e-response-approval.pending-after.json"; then
  echo "[e2e-response-approval][ERROR] approved command is not pending" >&2
  cat "$RESULTS/e2e-response-approval.pending-after.json" >&2
  exit 1
fi

cp "$TMP/manager.log" "$RESULTS/e2e-response-approval.manager.log"
echo "[e2e-response-approval] ok"
