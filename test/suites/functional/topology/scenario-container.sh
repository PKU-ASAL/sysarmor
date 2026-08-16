#!/usr/bin/env bash
set -euo pipefail

CASE="${1:?usage: scenario-container.sh <apt|staged|benign>}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
REPO="$(cd "$ROOT/.." && pwd)"
source "$ROOT/shared/harness/lib/common.sh"

case "$CASE" in
  apt) SCENARIO="apt-fileless-c2-managed"; WORKLOAD="apt-fileless-c2"; EVENT_BEHAVIOR="network.connect"; DUR="${DUR:-18}" ;;
  staged) SCENARIO="apt-staged-drop-managed"; WORKLOAD="apt-staged-drop"; EVENT_BEHAVIOR="network.connect"; DUR="${DUR:-10}" ;;
  benign) SCENARIO="benign-ci-noise-managed"; WORKLOAD="benign-ci-noise"; EVENT_BEHAVIOR="process.exec"; DUR="${DUR:-8}" ;;
  *) echo "unsupported topology case: $CASE" >&2; exit 2 ;;
esac

RESULTS="$ROOT/.results"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/sysarmor-topology-$CASE.XXXXXX")"
PKI_DIR="$RESULTS/container-runtime/pki"
AGENT_ID="container-node-a-$CASE"
MGR_URL="http://127.0.0.1:${SYSARMOR_TEST_MANAGER_PORT:-29443}"
TETRAGON_ARCHIVE="${SYSARMOR_TETRAGON_ARCHIVE:-}"
POLICY_ID="default-edr-policy"
mkdir -p "$RESULTS"

cleanup() {
  docker exec node-a sh -c 'test ! -f /opt/sysarmor/agent/runtime/agent.pid || kill "$(cat /opt/sysarmor/agent/runtime/agent.pid)" 2>/dev/null || true' >/dev/null 2>&1 || true
  rm -rf "$TMP"
}
trap cleanup EXIT

find_tetragon_archive() {
  if [[ -n "$TETRAGON_ARCHIVE" && -f "$TETRAGON_ARCHIVE" ]]; then return; fi
  for candidate in "$REPO/.cache/tetragon-v1.7.0-amd64.tar.gz" "$REPO/.scratchpad/.cache/tetragon-v1.7.0-amd64.tar.gz"; do
    if [[ -f "$candidate" ]]; then TETRAGON_ARCHIVE="$candidate"; return; fi
  done
  echo "[topology-$CASE][ERROR] SYSARMOR_TETRAGON_ARCHIVE is required" >&2
  exit 1
}

manager_ctl() {
  SYSARMOR_MANAGER_JWT="$MANAGER_JWT" "$REPO/dist/bin/sysarmorctl" --manager-url "$MGR_URL" --json manager "$@"
}

wait_manager() {
  local name="$1" needle="$2" output="$3"
  shift 3
  SA_TEST_NAME="topology-$CASE" SA_WAIT_TIMEOUT=90 SA_WAIT_LOGS=("$RESULTS/topology-$CASE.agent.log") \
    sa_wait_contains "$name" "$needle" "$output" "$@"
}

install_from_manager() {
  find_tetragon_archive
  "$REPO/deployments/agent/package-agent.sh" \
    --version "topology-$CASE" --output "$TMP/agent.tar.gz" \
    --agent-bin "$REPO/dist/bin/sysarmor-agent" --ctl-bin "$REPO/dist/bin/sysarmorctl" \
    --tetragon-archive "$TETRAGON_ARCHIVE" \
    --content-signing-key "$PKI_DIR/content-signing-key.pem" --content-key-id topology-test \
    --signing-key "$PKI_DIR/artifact-signing-key.pem" >/dev/null
  artifact_json="$(manager_ctl artifacts upload --file "$TMP/agent.tar.gz" --name sysarmor-agent --kind agent --version "topology-$CASE" --os linux --arch amd64 --status active)"
  artifact_id="$(jq -r '.artifact.artifact_id' <<<"$artifact_json")"
  enrollment_json="$(manager_ctl enrollments create --agent-id "$AGENT_ID" --host-id node-a \
    --gateway-addr gateway:9444 --gateway-sni gateway --profile linux-container \
    --artifact-id "$artifact_id" --ttl 1h --label scenario="$SCENARIO")"
  install_url="$(jq -r '.install_url' <<<"$enrollment_json" | sed -E 's#127\.0\.0\.1:[0-9]+#mgr:9443#')"
  docker exec node-a sh -c 'pkill -x sysarmor-agent 2>/dev/null || true; pkill -x tetragon 2>/dev/null || true; pkill -x tetra 2>/dev/null || true; rm -rf /opt/sysarmor/agent /etc/sysarmor/agent /var/lib/sysarmor/agent'
  docker exec node-a sh -c "curl -fsSL '$install_url' | bash"
}

apply_collection() {
  docker exec -i node-a sh -c 'cat > /tmp/sysarmor-collection.json' <<'JSON'
{"behaviors":["process.exec","process.exit","process.fork","network.connect","file.open","file.read","file.write","file.chmod"],"file_prefixes":["/dev/shm","/tmp","/var/tmp","/var/lib/app/plugins"],"observe_only":true}
JSON
  docker exec node-a sh -c '/opt/sysarmor/agent/bin/sysarmorctl --socket /run/sysarmor/agent/control.sock policy apply collection --file /tmp/sysarmor-collection.json --timeout 60s > /tmp/sysarmor-policy-apply.json'
}

run_workload() {
  case "$CASE" in
    apt) C2="${C2:-10.66.0.99}" bash "$ROOT/data/scenarios/container/$WORKLOAD/attack.sh" ;;
    staged) C2="${C2:-10.66.0.99}" GAP="${GAP:-3}" bash "$ROOT/data/scenarios/container/$WORKLOAD/attack.sh" ;;
    benign) CYCLES="${CYCLES:-3}" bash "$ROOT/data/scenarios/container/$WORKLOAD/attack.sh" ;;
  esac
  sleep "$DUR"
}

assert_results() {
  wait_manager events "\"scenario\":\"$SCENARIO\"" "$RESULTS/topology-$CASE.events.json" manager_ctl events list --label scenario="$SCENARIO" --label policy_id="$POLICY_ID" --behavior "$EVENT_BEHAVIOR" --limit 100
  if [[ "$CASE" == "benign" ]]; then
    [[ "$(manager_ctl signals list --label scenario="$SCENARIO" --label policy_id="$POLICY_ID")" == "[]" ]]
    [[ "$(manager_ctl incidents list --label scenario="$SCENARIO" --label policy_id="$POLICY_ID")" == "[]" ]]
    [[ "$(manager_ctl signals list --label scenario="$SCENARIO" --label policy_id="$POLICY_ID" --stage conclusion)" == "[]" ]]
    return
  fi
  wait_manager endpoint-signal payload_dropped "$RESULTS/topology-$CASE.signals.json" manager_ctl signals list --label scenario="$SCENARIO" --label policy_id="$POLICY_ID" --layer endpoint
  wait_manager cloud-signal dropped_payload_executed_and_connects "$RESULTS/topology-$CASE.cloud-signals.json" manager_ctl signals list --label scenario="$SCENARIO" --layer cloud
  wait_manager incident '"id":"inc-' "$RESULTS/topology-$CASE.incidents.json" manager_ctl incidents list --label scenario="$SCENARIO"
  grep -Fq '"method":"rarity+causal-topk"' "$RESULTS/topology-$CASE.incidents.json"
  if [[ "$CASE" == "staged" ]]; then
    grep -Fq '"crossLineage":true' "$RESULTS/topology-$CASE.cloud-signals.json"
    [[ "$(manager_ctl signals list --label scenario="$SCENARIO" --label policy_id="$POLICY_ID" --stage conclusion)" == "[]" ]]
  else
    grep -Fq reverse_shell_pattern "$RESULTS/topology-$CASE.signals.json"
  fi
}

if [[ "${SYSARMOR_SKIP_START_CONTAINER:-0}" != "1" ]]; then
  bash "$ROOT/shared/harness/start-container.sh" >/dev/null
fi
MANAGER_JWT="$($REPO/tools/auth/issue-manager-jwt.sh "$PKI_DIR/manager-jwt-private.pem" sysarmor-test sysarmor-manager)"
install_from_manager
apply_collection
wait_manager health '"backend":"tetragon"' "$RESULTS/topology-$CASE.health.json" manager_ctl health get --agent-id "$AGENT_ID" --tenant-id default
run_workload
assert_results
docker exec node-a cat /opt/sysarmor/agent/runtime/agent.log >"$RESULTS/topology-$CASE.agent.log"
echo "topology $CASE passed"
