#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../../../shared/harness/lib/common.sh"

sa_init_repo_paths
TMP="$(sa_make_tmp sysarmor-policy-publish)"
sa_pick_ports 53000 2000
AGENT_ID="policy-publish-agent"
SA_TEST_NAME="e2e-policy-publish"
SA_WAIT_LOGS=("$TMP/manager.log")

cleanup() {
  exec 3>&- 2>/dev/null || true
  sa_kill_pid_ref AGENT_PID
  sa_kill_pid_ref MGR_PID
  sa_cleanup_tmp "$TMP"
}
trap cleanup EXIT

echo "[e2e-policy-publish] building binaries"
sa_build_go_bins sysarmor-manager sysarmorctl

sa_start_postgres_manager

sa_wait_url_contains "$MGR_URL/healthz" '"ok":true' "$TMP/health.json"

cat > "$TMP/policy.json" <<'JSON'
{
  "policy_id": "draft-policy",
  "version": 2,
  "tenant_id": "default",
  "endpoint_rules": ["download_by_lolbin"],
  "cloud_rules": ["web_shell_chain"],
  "mode": "observe",
  "published": false
}
JSON

sa_manager_curl -sf -X POST "$MGR_URL/api/v1/policies?actor=e2e&reason=draft" \
  -H 'Content-Type: application/json' \
  --data-binary @"$TMP/policy.json" > "$RESULTS/e2e-policy-publish.draft.json"

for want in '"policy_id":"draft-policy"' '"published":false'; do
  if ! grep -Fq "$want" "$RESULTS/e2e-policy-publish.draft.json"; then
    echo "[e2e-policy-publish][ERROR] draft missing $want" >&2
    cat "$RESULTS/e2e-policy-publish.draft.json" >&2
    exit 1
  fi
done

cat > "$TMP/assignment.json" <<JSON
{
  "tenant_id": "default",
  "agent_id": "$AGENT_ID",
  "policy_id": "draft-policy",
  "policy_version": 2,
  "actor": "operator",
  "reason": "deploy"
}
JSON

status="$(
  sa_manager_curl -sS -o "$RESULTS/e2e-policy-publish.assignment-before.json" \
    -w '%{http_code}' \
    -X POST "$MGR_URL/api/v1/policy-assignments" \
    -H 'Content-Type: application/json' \
    --data-binary @"$TMP/assignment.json"
)"
if [[ "$status" != "400" ]]; then
  echo "[e2e-policy-publish][ERROR] draft assignment status = $status, want 400" >&2
  cat "$RESULTS/e2e-policy-publish.assignment-before.json" >&2
  exit 1
fi

"$BIN/sysarmorctl" --manager-url "$MGR_URL" --json manager policies publish \
  --tenant-id default \
  --policy-id draft-policy \
  --version 2 \
  --actor reviewer \
  --reason "ready for assignment" > "$RESULTS/e2e-policy-publish.publish.json"

for want in '"policy_id":"draft-policy"' '"published":true'; do
  if ! grep -Fq "$want" "$RESULTS/e2e-policy-publish.publish.json"; then
    echo "[e2e-policy-publish][ERROR] publish missing $want" >&2
    cat "$RESULTS/e2e-policy-publish.publish.json" >&2
    exit 1
  fi
done

sa_manager_curl -sf -X POST "$MGR_URL/api/v1/policy-assignments" \
  -H 'Content-Type: application/json' \
  --data-binary @"$TMP/assignment.json" > "$RESULTS/e2e-policy-publish.assignment-after.json"

sa_manager_curl -sf "$MGR_URL/api/v1/policy-rollouts?tenant_id=default&agent_id=$AGENT_ID" \
  > "$RESULTS/e2e-policy-publish.rollout-unknown.json"
jq -e 'length == 1 and .[0].status == "unknown" and .[0].desired_policy_id == "draft-policy" and .[0].desired_policy_version == 2' \
  "$RESULTS/e2e-policy-publish.rollout-unknown.json" >/dev/null

cat > "$TMP/health-pending.json" <<JSON
{
  "tenant_id": "default",
  "agent_id": "$AGENT_ID",
  "host_id": "policy-publish-host",
  "status": "degraded",
  "policy_id": "standalone-default",
  "policy_version": 1,
  "pending_policy": {
    "status": "pending",
    "source": "managed",
    "policy_id": "draft-policy",
    "version": 2,
    "digest": "sha256:e2e-pending"
  }
}
JSON
sa_manager_curl -sf -X POST "$MGR_URL/api/v1/agent-health" \
  -H 'Content-Type: application/json' --data-binary @"$TMP/health-pending.json" >/dev/null
sa_manager_curl -sf "$MGR_URL/api/v1/policy-rollouts?tenant_id=default&agent_id=$AGENT_ID" \
  > "$RESULTS/e2e-policy-publish.rollout-pending.json"
jq -e 'length == 1 and .[0].status == "pending" and .[0].drift == true and .[0].pending_policy.source == "managed"' \
  "$RESULTS/e2e-policy-publish.rollout-pending.json" >/dev/null

cat > "$TMP/rollout-command.json" <<JSON
{
  "command_id": "policy-rollout-failure",
  "tenant_id": "default",
  "agent_id": "$AGENT_ID",
  "type": "policy_update",
  "policy_id": "draft-policy",
  "policy_version": 2
}
JSON
sa_manager_curl -sf -X POST "$MGR_URL/api/v1/control-commands" \
  -H 'Content-Type: application/json' --data-binary @"$TMP/rollout-command.json" >/dev/null
sa_manager_curl -sf -X POST "$MGR_URL/api/v1/control-commands" \
  -H 'Content-Type: application/json' \
  --data '{"action":"expire","command_id":"policy-rollout-failure","tenant_id":"default","agent_id":"'"$AGENT_ID"'","reason":"e2e expiry"}' >/dev/null
sa_manager_curl -sf "$MGR_URL/api/v1/policy-rollouts?tenant_id=default&agent_id=$AGENT_ID" \
  > "$RESULTS/e2e-policy-publish.rollout-failed.json"
jq -e 'length == 1 and .[0].status == "failed" and .[0].command_status == "expired"' \
  "$RESULTS/e2e-policy-publish.rollout-failed.json" >/dev/null

cat > "$TMP/health-drifted.json" <<JSON
{
  "tenant_id": "default",
  "agent_id": "$AGENT_ID",
  "host_id": "policy-publish-host",
  "status": "degraded",
  "policy_id": "standalone-default",
  "policy_version": 1
}
JSON
sa_manager_curl -sf -X POST "$MGR_URL/api/v1/agent-health" \
  -H 'Content-Type: application/json' --data-binary @"$TMP/health-drifted.json" >/dev/null

sed 's/policy-rollout-failure/policy-rollout-canceled/' "$TMP/rollout-command.json" > "$TMP/rollout-command-canceled.json"
sa_manager_curl -sf -X POST "$MGR_URL/api/v1/control-commands" \
  -H 'Content-Type: application/json' --data-binary @"$TMP/rollout-command-canceled.json" >/dev/null
sa_manager_curl -sf -X POST "$MGR_URL/api/v1/control-commands" \
  -H 'Content-Type: application/json' \
  --data '{"action":"cancel","command_id":"policy-rollout-canceled","tenant_id":"default","agent_id":"'"$AGENT_ID"'","reason":"e2e canceled"}' >/dev/null
sa_manager_curl -sf "$MGR_URL/api/v1/policy-rollouts?tenant_id=default&agent_id=$AGENT_ID" \
  > "$RESULTS/e2e-policy-publish.rollout-drifted.json"
jq -e 'length == 1 and .[0].status == "drifted" and .[0].drift == true and .[0].command_status == "canceled"' \
  "$RESULTS/e2e-policy-publish.rollout-drifted.json" >/dev/null

cat > "$TMP/health-applied.json" <<JSON
{
  "tenant_id": "default",
  "agent_id": "$AGENT_ID",
  "host_id": "policy-publish-host",
  "status": "ok",
  "policy_id": "draft-policy",
  "policy_version": 2
}
JSON
sa_manager_curl -sf -X POST "$MGR_URL/api/v1/agent-health" \
  -H 'Content-Type: application/json' --data-binary @"$TMP/health-applied.json" >/dev/null
sa_manager_curl -sf "$MGR_URL/api/v1/policy-rollouts?tenant_id=default&agent_id=$AGENT_ID&status=applied" \
  > "$RESULTS/e2e-policy-publish.rollout-applied.json"
jq -e 'length == 1 and .[0].status == "applied" and .[0].drift == false and .[0].applied_policy_id == "draft-policy"' \
  "$RESULTS/e2e-policy-publish.rollout-applied.json" >/dev/null

sa_wait_contains "effective policy" '"policy_id":"draft-policy"' "$RESULTS/e2e-policy-publish.effective.json" \
  "$BIN/sysarmorctl" --manager-url "$MGR_URL" --json manager policies effective --tenant-id default --agent-id "$AGENT_ID"
if ! grep -Fq '"published":true' "$RESULTS/e2e-policy-publish.effective.json"; then
  echo "[e2e-policy-publish][ERROR] effective policy is not published" >&2
  cat "$RESULTS/e2e-policy-publish.effective.json" >&2
  exit 1
fi

"$BIN/sysarmorctl" --manager-url "$MGR_URL" --json manager policies audit \
  --tenant-id default \
  --policy-id draft-policy > "$RESULTS/e2e-policy-publish.audit.json"

for want in '"action":"policy.upsert"' '"action":"policy.publish"' '"action":"policy.assign"' '"actor":"test-admin"'; do
  if ! grep -Fq "$want" "$RESULTS/e2e-policy-publish.audit.json"; then
    echo "[e2e-policy-publish][ERROR] audit missing $want" >&2
    cat "$RESULTS/e2e-policy-publish.audit.json" >&2
    exit 1
  fi
done
for spoofed_actor in e2e reviewer operator; do
  if grep -Fq "\"actor\":\"$spoofed_actor\"" "$RESULTS/e2e-policy-publish.audit.json"; then
    echo "[e2e-policy-publish][ERROR] audit trusted spoofed actor: $spoofed_actor" >&2
    cat "$RESULTS/e2e-policy-publish.audit.json" >&2
    exit 1
  fi
done

cp "$TMP/manager.log" "$RESULTS/e2e-policy-publish.manager.log"
echo "[e2e-policy-publish] ok"
