#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
REPO="$(cd "$ROOT/.." && pwd)"
VM_ENV="${SYSARMOR_VM_ENV:-${ENV:-vm-endpoint}}"
ENVDIR="$(cd "$ROOT/environments/$VM_ENV" && pwd)"
RESULTS="$ROOT/.results"
RUN_ID="${SYSARMOR_BENCH_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
OUT_DIR="$RESULTS/performance-endpoint/$RUN_ID"
# shellcheck source=/dev/null
source "$ROOT/shared/agent/policy_runtime.sh"
# shellcheck source=/dev/null
source "$ROOT/shared/agent/managed_enrollment.sh"
# shellcheck source=/dev/null
source "$ROOT/shared/agent/managed_policy.sh"
BENCH_PROFILE="${SYSARMOR_BENCH_PROFILE:-quick}"
AGENT_SOCK="${SYSARMOR_AGENT_SOCK:-/run/sysarmor/agent/control.sock}"
AGENT_MODE="${SYSARMOR_BENCH_AGENT_MODE:-standalone}"
AGENT_ID=""
TENANT_ID=""
PKI_DIR="${SYSARMOR_VM_MTLS_DIR:-$RESULTS/pki/$VM_ENV}"
case "$AGENT_MODE" in
  standalone|managed) ;;
  *)
    echo "[performance-endpoint][ERROR] unsupported Agent mode: $AGENT_MODE" >&2
    exit 1
    ;;
esac
if [[ -v SYSARMOR_BENCH_WORKLOAD ]]; then
  WORKLOAD="$SYSARMOR_BENCH_WORKLOAD"
else
  WORKLOAD="${DIAG_SCENARIO:-edr-activity-heavy}"
fi
SCENARIO="${SYSARMOR_BENCH_SCENARIO:-}"
VARIANT="${SYSARMOR_BENCH_VARIANT:-}"
MATCHER_STRATEGY="${SYSARMOR_BENCH_MATCHER_STRATEGY:-${SYSARMOR_TEST_MATCHER_STRATEGY:-}}"
POLICIES_RAW="${SYSARMOR_BENCH_POLICIES:-${POLICIES:-test/data/policies/collection-minimal.json test/data/policies/collection-balanced.json test/data/policies/collection-deep.json}}"
CONTENT_DIR="${SYSARMOR_BENCH_CONTENT_DIR:-test/data/content}"
DETECTION_POLICY="${SYSARMOR_BENCH_DETECTION_POLICY:-test/data/policies/detection-cep-endpoint.json}"
APPLY_DETECTION="${SYSARMOR_BENCH_APPLY_DETECTION:-1}"
case "$BENCH_PROFILE" in
  quick|medium|long)
    # Profiles provide defaults only; SYSARMOR_BENCH_* env vars may override them.
    # shellcheck source=/dev/null
    source "$HERE/profiles/$BENCH_PROFILE.env"
    ;;
  *)
    echo "[performance-endpoint][ERROR] unsupported SYSARMOR_BENCH_PROFILE=$BENCH_PROFILE (expected quick|medium|long)" >&2
    exit 1
    ;;
esac
HOST_BASELINE_SECONDS="${SYSARMOR_BENCH_HOST_BASELINE_SECONDS:-0}"
AGENT_IDLE_SECONDS="${SYSARMOR_BENCH_AGENT_IDLE_SECONDS:-5}"
SENSOR_IDLE_SECONDS="${SYSARMOR_BENCH_SENSOR_IDLE_SECONDS:-5}"
BASELINE_SECONDS="${SYSARMOR_BENCH_BASELINE_SECONDS:-3}"
SETTLE_SECONDS="${SYSARMOR_BENCH_SETTLE_SECONDS:-8}"
STEADY_SECONDS="${SYSARMOR_BENCH_STEADY_SECONDS:-4}"
POLICY_SETTLE_SECONDS="${SYSARMOR_BENCH_POLICY_SETTLE_SECONDS:-10}"
WORKLOAD_SECONDS="${SYSARMOR_BENCH_WORKLOAD_SECONDS:-10}"
WORKLOAD_WARMUP_SECONDS="${SYSARMOR_BENCH_WORKLOAD_WARMUP_SECONDS:-2}"
WORKLOAD_REPEAT="${SYSARMOR_BENCH_WORKLOAD_REPEAT:-0}"
SCENARIO_OBSERVE_SECONDS="${SYSARMOR_BENCH_SCENARIO_OBSERVE_SECONDS:-5}"
COOLDOWN_SECONDS="${SYSARMOR_BENCH_COOLDOWN_SECONDS:-5}"
WORKLOAD_C2="${SYSARMOR_DIAG_WORKLOAD_C2:-10.66.0.99}"
PROFILE_ENABLED="${SYSARMOR_BENCH_PROFILE_AGENT:-${SYSARMOR_BENCH_PROFILE_AGENT_CPU:-0}}"
PROFILE_TYPES="${SYSARMOR_BENCH_PROFILE_TYPES:-cpu heap allocs goroutine runtime}"
PROFILE_PHASES="${SYSARMOR_BENCH_PROFILE_PHASES:-policy_apply activity persistence}"
ACTIVITY_PROFILE_SECONDS="${SYSARMOR_BENCH_ACTIVITY_PROFILE_SECONDS:-5}"
RECORDER_SEMANTIC_INTERVAL="${SYSARMOR_RECORDER_SEMANTIC_INTERVAL:-10}"
RECORDER_DURATION_SECONDS="${SYSARMOR_BENCH_RECORDER_DURATION_SECONDS:-$((HOST_BASELINE_SECONDS + AGENT_IDLE_SECONDS + SENSOR_IDLE_SECONDS + BASELINE_SECONDS + POLICY_SETTLE_SECONDS + SETTLE_SECONDS + STEADY_SECONDS + WORKLOAD_WARMUP_SECONDS + WORKLOAD_SECONDS + SCENARIO_OBSERVE_SECONDS + COOLDOWN_SECONDS + 300))}"
SYNC_VM_AGENT="${SYSARMOR_BENCH_SYNC_VM_AGENT:-1}"
BUILD_BINARIES="${SYSARMOR_BENCH_BUILD_BINARIES:-1}"
VM_FRESH="${SYSARMOR_BENCH_VM_FRESH:-1}"
VM_LIFECYCLE="reuse"
if [[ "$VM_FRESH" == "1" ]]; then
  VM_LIFECYCLE="fresh"
fi

mkdir -p "$OUT_DIR"
cat >"$OUT_DIR/manifest.json" <<EOF
{
  "suite": "endpoint",
  "tool": "performance-endpoint",
  "benchmark_profile": "$BENCH_PROFILE",
  "vm_env": "$VM_ENV",
  "run_id": "$RUN_ID",
  "workload": "$WORKLOAD",
  "scenario": "$SCENARIO",
  "agent_mode": "$AGENT_MODE",
  "policies": "$POLICIES_RAW",
  "host_baseline_seconds": $HOST_BASELINE_SECONDS,
  "agent_idle_seconds": $AGENT_IDLE_SECONDS,
  "sensor_idle_seconds": $SENSOR_IDLE_SECONDS,
  "baseline_seconds": $BASELINE_SECONDS,
  "settle_seconds": $SETTLE_SECONDS,
  "steady_seconds": $STEADY_SECONDS,
  "policy_settle_seconds": $POLICY_SETTLE_SECONDS,
  "workload_seconds": $WORKLOAD_SECONDS,
  "workload_warmup_seconds": $WORKLOAD_WARMUP_SECONDS,
  "workload_repeat": $WORKLOAD_REPEAT,
  "scenario_observe_seconds": $SCENARIO_OBSERVE_SECONDS,
  "cooldown_seconds": $COOLDOWN_SECONDS,
  "recorder_duration_seconds": $RECORDER_DURATION_SECONDS,
  "recorder_semantic_interval_seconds": $RECORDER_SEMANTIC_INTERVAL,
  "vm_lifecycle": "$VM_LIFECYCLE",
  "vm_lifecycle_steps": ["make build-binary", "vagrant destroy -f", "start-vm", "sync-agent"],
  "build_binaries": "$BUILD_BINARIES",
  "sync_vm_agent": "$SYNC_VM_AGENT",
  "vm_fresh": "$VM_FRESH",
  "profile_enabled": "$PROFILE_ENABLED",
  "profile_types": "$PROFILE_TYPES",
  "profile_phases": "$PROFILE_PHASES",
  "activity_profile_seconds": $ACTIVITY_PROFILE_SECONDS,
  "profile_semantics": "diagnostic agent pprof/runtime capture; disabled by default and not used for low-disturbance CPU/RSS conclusions; CPU profiles are serialized because the agent debug profile endpoint is mutually exclusive"
}
EOF

cd "$ENVDIR"

wait_agent_socket() {
  local deadline=$((SECONDS + 60))
  until vagrant ssh node-a -c "sudo test -S '$AGENT_SOCK'" >/dev/null 2>&1; do
    if (( SECONDS >= deadline )); then
      echo "[performance-endpoint][ERROR] timeout waiting for agent socket: $AGENT_SOCK" >&2
      vagrant ssh node-a -c "sudo systemctl status sysarmor-agent --no-pager -l || true" >&2 2>/dev/null || true
      exit 1
    fi
    sleep 1
  done
}

enroll_managed_agent() {
  [[ "$AGENT_MODE" == "managed" ]] || return 0
  [[ "$VM_ENV" == "vm-topology" ]] || {
    echo "[performance-endpoint][ERROR] managed benchmark requires vm-topology" >&2
    exit 1
  }
  sa_agent_enroll_managed_topology "$REPO" "$ENVDIR" "$PKI_DIR" \
    "$AGENT_SOCK" "$AGENT_ID"
}

apply_managed_policy() {
  local policy_out="$1" policy="$2"
  sa_agent_apply_managed_policy "$REPO" "$ENVDIR" "$PKI_DIR" "$AGENT_SOCK" \
    "$AGENT_ID" "$REPO/$policy" "$REPO/$DETECTION_POLICY" "$policy_out"
}

resolve_agent_identity() {
  local health
  health="$(vagrant ssh node-a -c "sudo sysarmorctl --socket '$AGENT_SOCK' --json agent health")"
  AGENT_ID="$(jq -r '.agentId // .agent_id // empty' <<<"$health")"
  TENANT_ID="$(jq -r '.tenantId // .tenant_id // empty' <<<"$health")"
  if [[ -z "$AGENT_ID" || -z "$TENANT_ID" ]]; then
    echo "[performance-endpoint][ERROR] Agent health did not expose runtime identity: $health" >&2
    exit 1
  fi
  echo "[performance-endpoint] runtime identity: tenant=$TENANT_ID agent=$AGENT_ID"
}

set_agent_labels() {
  local bench_run="$1"
  local policy_name="$2"
  local workload_name="${3:-}"
  local scenario_name="${4:-}"
  local labels_json
  local labels_b64
labels_json="$(python3 -c '
import json,sys
bench_run, workload_name, policy_name, scenario_name, variant, matcher_strategy = sys.argv[1:7]
labels = {"benchmark_run": bench_run, "policy_profile": policy_name}
if workload_name:
    labels["workload"] = workload_name
if scenario_name:
    labels["scenario"] = scenario_name
if variant:
    labels["variant"] = variant
if matcher_strategy:
    labels["matcher_strategy"] = matcher_strategy
print(json.dumps(labels))
' "$bench_run" "$workload_name" "$policy_name" "$scenario_name" "$VARIANT" "$MATCHER_STRATEGY")"
  labels_b64="$(printf '%s' "$labels_json" | base64 -w0)"
  vagrant ssh node-a -c "sudo SYSARMOR_LABELS_B64='$labels_b64' python3 - <<'PY'
import base64
import json
import os
from pathlib import Path
p = Path('/etc/sysarmor/agent/agent.yaml')
lines = p.read_text().splitlines()
labels = json.loads(base64.b64decode(os.environ['SYSARMOR_LABELS_B64']).decode())
out = []
managed_prefixes = (
    'scenario:',
    'label.benchmark_run:',
    'label.workload:',
    'label.scenario:',
    'label.policy_profile:',
    'label.variant:',
    'label.matcher_strategy:',
)
for line in lines:
    stripped = line.strip()
    if stripped.startswith(managed_prefixes):
        continue
    out.append(line)
next_section = next((i for i, line in enumerate(out) if line and not line.startswith(' ') and line.strip().endswith(':') and line.strip() != 'agent:'), len(out))
try:
    agent_idx = next(i for i, line in enumerate(out) if line.strip() == 'agent:')
except StopIteration:
    out.insert(0, 'agent:')
    agent_idx = 0
    next_section = 1
insert = [
    '  label.benchmark_run: ' + labels['benchmark_run'],
    '  label.policy_profile: ' + labels['policy_profile'],
]
if 'workload' in labels:
    insert.append('  label.workload: ' + labels['workload'])
if 'scenario' in labels:
    insert.append('  label.scenario: ' + labels['scenario'])
if 'variant' in labels:
    insert.append('  label.variant: ' + labels['variant'])
if 'matcher_strategy' in labels:
    insert.append('  label.matcher_strategy: ' + labels['matcher_strategy'])
next_section = next((i for i in range(agent_idx + 1, len(out)) if out[i] and not out[i].startswith(' ') and out[i].strip().endswith(':')), len(out))
out[next_section:next_section] = insert
p.write_text('\n'.join(out) + '\n')
PY
sudo systemctl restart sysarmor-agent" >/dev/null
  wait_agent_socket
}

set_runtime_feature_flags() {
  local matcher_strategy="${1:-}"
  if [[ -z "$matcher_strategy" ]]; then
    return 0
  fi
  case "$matcher_strategy" in
    linear|optimized) ;;
    *)
      echo "[performance-endpoint][ERROR] unsupported matcher strategy: $matcher_strategy" >&2
      exit 1
      ;;
  esac
  vagrant ssh node-a -c "sudo SYSARMOR_MATCHER_STRATEGY='$matcher_strategy' python3 - <<'PY'
import os
from pathlib import Path

p = Path('/etc/sysarmor/agent/agent.yaml')
strategy = os.environ['SYSARMOR_MATCHER_STRATEGY']
lines = p.read_text().splitlines()
out = []
skip_runtime = False
for line in lines:
    is_top = bool(line and not line.startswith(' ') and line.strip().endswith(':'))
    if is_top:
        skip_runtime = line.strip() == 'runtime:'
    if skip_runtime:
        continue
    out.append(line)
insert = [
    'runtime:',
    '  feature_flags:',
    '    matcher_strategy: ' + strategy,
]
insert_at = next((i for i, line in enumerate(out) if line.strip() == 'sensor:'), len(out))
out[insert_at:insert_at] = insert + ['']
p.write_text('\n'.join(out) + '\n')
PY
sudo systemctl restart sysarmor-agent" >/dev/null
  wait_agent_socket
}

policy_name() {
  local file="$1"
  basename "$file" | sed -E 's/\.(json|yaml|yml)$//'
}

recorder() {
  local rec_run_id="$1"
  local labels="${2:-}"
  shift
  shift || true
  RUN_ID="$rec_run_id" \
    SYSARMOR_RECORDER_AGENT_ID="$AGENT_ID" \
    SYSARMOR_RECORDER_TENANT_ID="$TENANT_ID" \
    SYSARMOR_AGENT_SOCK="$AGENT_SOCK" \
    SYSARMOR_RECORDER_SEMANTIC_INTERVAL="$RECORDER_SEMANTIC_INTERVAL" \
    SYSARMOR_RECORDER_LABELS="$labels" \
    bash "$ROOT/shared/recorder/recorder-vm.sh" "$@"
}

ACTIVE_REC_RUN_ID=""
ACTIVE_REC_LABELS=""
cleanup_active_recorder() {
  local status=$?
  trap - EXIT
  if [[ -n "$ACTIVE_REC_RUN_ID" ]]; then
    echo "[performance-endpoint][WARN] stopping recorder after early exit: $ACTIVE_REC_RUN_ID" >&2
    recorder "$ACTIVE_REC_RUN_ID" "$ACTIVE_REC_LABELS" stop >/dev/null 2>&1 || true
  fi
  exit "$status"
}
trap cleanup_active_recorder EXIT

mark() {
  local rec_run_id="$1"
  local phase="$2"
  local detail="${3:-}"
  PHASE="$phase" DETAIL="$detail" RUN_ID="$rec_run_id" bash "$ROOT/shared/recorder/recorder-vm.sh" mark
}

profile_phase_enabled() {
  local phase="$1"
  [[ "$PROFILE_ENABLED" == "1" ]] || return 1
  [[ " $PROFILE_PHASES " == *" $phase "* ]]
}

profile_ext() {
  case "$1" in
    runtime) printf 'json' ;;
    goroutine|threadcreate|block|mutex) printf 'txt' ;;
    *) printf 'pb.gz' ;;
  esac
}

declare -A PROFILE_PIDS=()
PROFILE_CPU_ACTIVE_PHASE=""

profile_type_enabled() {
  local profile_type="$1"
  [[ " $PROFILE_TYPES " == *" $profile_type "* ]]
}

profile_has_nested_phase() {
  profile_phase_enabled activity || profile_phase_enabled persistence
}

profile_cpu_should_start() {
  local phase="$1"
  profile_type_enabled cpu || return 1
  if [[ "$phase" == "workload" && -n "$SCENARIO" ]] && profile_has_nested_phase; then
    echo "[performance-endpoint][WARN] skipping workload cpu profile because activity/persistence profiling is enabled; recorder CPU/RSS still covers workload" >&2
    return 1
  fi
  if [[ -n "$PROFILE_CPU_ACTIVE_PHASE" ]]; then
    echo "[performance-endpoint][WARN] skipping $phase cpu profile because $PROFILE_CPU_ACTIVE_PHASE cpu profile is still running" >&2
    return 1
  fi
  return 0
}

start_agent_profile_window() {
  local policy_out="$1"
  local phase="$2"
  local seconds="$3"
  if ! profile_phase_enabled "$phase"; then
    return 0
  fi
  mkdir -p "$policy_out/profiles"
  printf '{"phase":"%s","profile_types":"%s","window_seconds":%s,"started_at":"%s"}\n' \
    "$phase" "$PROFILE_TYPES" "$seconds" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$policy_out/profiles/$phase.window.json"
  if profile_cpu_should_start "$phase"; then
    echo "[performance-endpoint] profiling agent cpu phase=$phase seconds=$seconds"
    vagrant ssh node-a -c "sudo sysarmorctl --socket '$AGENT_SOCK' --json debug profile cpu --seconds '$seconds' --label '$phase' --output '/tmp/sysarmor-agent-$phase.cpu.pb.gz' --agent-id '$AGENT_ID' --tenant-id '$TENANT_ID' --timeout '$((seconds + 10))s'" \
      > "$policy_out/profiles/$phase.cpu.profile.json" 2>"$policy_out/profiles/$phase.cpu.profile.err" &
    PROFILE_PIDS["$phase"]=$!
    PROFILE_CPU_ACTIVE_PHASE="$phase"
  fi
}

capture_instant_profile() {
  local policy_out="$1"
  local phase="$2"
  local profile_type="$3"
  local ext
  ext="$(profile_ext "$profile_type")"
  local remote="/tmp/sysarmor-agent-$phase.$profile_type.$ext"
  local local_path="$policy_out/profiles/$phase.$profile_type.$ext"
  echo "[performance-endpoint] capturing agent $profile_type profile phase=$phase"
  vagrant ssh node-a -c "sudo sysarmorctl --socket '$AGENT_SOCK' --json debug profile '$profile_type' --seconds 1 --label '$phase' --output '$remote' --agent-id '$AGENT_ID' --tenant-id '$TENANT_ID' --timeout 15s" \
    > "$policy_out/profiles/$phase.$profile_type.profile.json" \
    2>"$policy_out/profiles/$phase.$profile_type.profile.err" || {
      echo "[performance-endpoint][WARN] agent $profile_type profile failed for phase=$phase" >&2
      return 0
    }
  vagrant ssh node-a -c "sudo cat '$remote' 2>/dev/null || true" > "$local_path" 2>/dev/null || true
  vagrant ssh node-a -c "sudo rm -f '$remote'" >/dev/null 2>&1 || true
  if [[ -s "$local_path" && "$ext" == "pb.gz" && "$profile_type" != "allocs" ]] && command -v go >/dev/null 2>&1; then
    go tool pprof -top "$local_path" > "$policy_out/profiles/$phase.$profile_type.top.txt" 2>"$policy_out/profiles/$phase.$profile_type.top.err" || true
  fi
}

finish_agent_profile_window() {
  local policy_out="$1"
  local phase="$2"
  local rec_run_id="${3:-}"
  if ! profile_phase_enabled "$phase"; then
    return 0
  fi
  if [[ -n "$rec_run_id" ]]; then
    mark "$rec_run_id" "profile_${phase}_finish_start" "$phase"
  fi
  if [[ -z "${PROFILE_PIDS[$phase]:-}" ]]; then
    :
  else
    wait "${PROFILE_PIDS[$phase]}" || {
      echo "[performance-endpoint][WARN] agent cpu profile failed for phase=$phase" >&2
    }
    vagrant ssh node-a -c "sudo cat '/tmp/sysarmor-agent-$phase.cpu.pb.gz' 2>/dev/null || true" > "$policy_out/profiles/$phase.cpu.pb.gz" 2>/dev/null || true
    vagrant ssh node-a -c "sudo rm -f '/tmp/sysarmor-agent-$phase.cpu.pb.gz'" >/dev/null 2>&1 || true
    if [[ -s "$policy_out/profiles/$phase.cpu.pb.gz" ]] && command -v go >/dev/null 2>&1; then
      go tool pprof -top "$policy_out/profiles/$phase.cpu.pb.gz" > "$policy_out/profiles/$phase.cpu.top.txt" 2>"$policy_out/profiles/$phase.cpu.top.err" || true
    fi
    unset 'PROFILE_PIDS[$phase]'
    if [[ "$PROFILE_CPU_ACTIVE_PHASE" == "$phase" ]]; then
      PROFILE_CPU_ACTIVE_PHASE=""
    fi
  fi
  for profile_type in $PROFILE_TYPES; do
    [[ "$profile_type" == "cpu" ]] && continue
    capture_instant_profile "$policy_out" "$phase" "$profile_type"
  done
  printf '{"phase":"%s","finished_at":"%s"}\n' "$phase" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$policy_out/profiles/$phase.window.json"
  if [[ -n "$rec_run_id" ]]; then
    mark "$rec_run_id" "profile_${phase}_finish_done" "$phase"
  fi
}

run_workload() {
  local policy_out="$1"
  local workload_name="${2:-$WORKLOAD}"
  cd "$ENVDIR"
  if [[ -f "$ROOT/data/workloads/vm/$workload_name/run.sh" ]]; then
    vagrant upload "$ROOT/data/workloads/vm/$workload_name/run.sh" /tmp/sysarmor-workload-run.sh node-a >/dev/null
    vagrant ssh node-a -c "sudo bash -c 'DURATION=$WORKLOAD_SECONDS REPEAT=$WORKLOAD_REPEAT C2=$WORKLOAD_C2 bash /tmp/sysarmor-workload-run.sh'" \
      > "$policy_out/workload.out" 2>"$policy_out/workload.err"
  elif [[ -f "$ROOT/data/scenarios/vm/$workload_name/attack.sh" ]]; then
    vagrant upload "$ROOT/data/scenarios/vm/$workload_name/attack.sh" /tmp/sysarmor-scenario-attack.sh node-a >/dev/null
    vagrant ssh node-a -c "sudo bash -c 'GAP=1 C2=$WORKLOAD_C2 bash /tmp/sysarmor-scenario-attack.sh'" \
      > "$policy_out/workload.out" 2>"$policy_out/workload.err"
  else
    echo "[performance-endpoint][ERROR] workload not found: $workload_name" >&2
    exit 1
  fi
}

start_workload_background() {
  local policy_out="$1"
  local workload_name="$2"
  WORKLOAD_PID=""
  cd "$ENVDIR"
  if [[ ! -f "$ROOT/data/workloads/vm/$workload_name/run.sh" ]]; then
    echo "[performance-endpoint][ERROR] workload not found: $workload_name" >&2
    exit 1
  fi
  vagrant upload "$ROOT/data/workloads/vm/$workload_name/run.sh" /tmp/sysarmor-workload-run.sh node-a >/dev/null
  vagrant ssh node-a -c "sudo bash -c 'DURATION=$WORKLOAD_SECONDS REPEAT=$WORKLOAD_REPEAT C2=$WORKLOAD_C2 bash /tmp/sysarmor-workload-run.sh'" \
    > "$policy_out/workload.out" 2>"$policy_out/workload.err" &
  WORKLOAD_PID=$!
}

run_scenario() {
  local policy_out="$1"
  local scenario_name="$2"
  cd "$ENVDIR"
  if [[ ! -f "$ROOT/data/scenarios/vm/$scenario_name/attack.sh" ]]; then
    echo "[performance-endpoint][ERROR] scenario not found: $scenario_name" >&2
    exit 1
  fi
  vagrant upload "$ROOT/data/scenarios/vm/$scenario_name/attack.sh" /tmp/sysarmor-scenario-attack.sh node-a >/dev/null
  vagrant ssh node-a -c "sudo bash -c 'GAP=1 C2=$WORKLOAD_C2 bash /tmp/sysarmor-scenario-attack.sh'" \
    > "$policy_out/scenario.out" 2>"$policy_out/scenario.err"
}

run_case_activity() {
  local policy_out="$1"
  local workload_name="${2:-}"
  local scenario_name="${3:-}"
  local rec_run_id="${4:-}"
  local workload_pid=""

  if [[ -n "$workload_name" ]]; then
    start_workload_background "$policy_out" "$workload_name"
    workload_pid="$WORKLOAD_PID"
    sleep "$WORKLOAD_WARMUP_SECONDS"
  fi

  if [[ -n "$scenario_name" ]]; then
    start_agent_profile_window "$policy_out" activity "$ACTIVITY_PROFILE_SECONDS"
    if [[ -n "$rec_run_id" ]]; then
      mark "$rec_run_id" scenario_start "$scenario_name"
    fi
    run_scenario "$policy_out" "$scenario_name"
    if [[ -n "$rec_run_id" ]]; then
      mark "$rec_run_id" scenario_done "$scenario_name"
    fi
    finish_agent_profile_window "$policy_out" activity "$rec_run_id"
    if [[ -n "$rec_run_id" ]]; then
      mark "$rec_run_id" scenario_observe_start "$scenario_name"
    fi
    start_agent_profile_window "$policy_out" persistence "$SCENARIO_OBSERVE_SECONDS"
    sleep "$SCENARIO_OBSERVE_SECONDS"
    if [[ -n "$rec_run_id" ]]; then
      mark "$rec_run_id" scenario_observe_done "$scenario_name"
    fi
    finish_agent_profile_window "$policy_out" persistence "$rec_run_id"
  fi

  if [[ -n "$workload_pid" ]]; then
    wait "$workload_pid"
  fi
}

echo "[performance-endpoint] output: $OUT_DIR"
echo "[performance-endpoint] benchmark_profile: $BENCH_PROFILE"
echo "[performance-endpoint] variant: ${VARIANT:-default}"
echo "[performance-endpoint] matcher_strategy: ${MATCHER_STRATEGY:-config-default}"
echo "[performance-endpoint] sync_vm_agent: $SYNC_VM_AGENT"
echo "[performance-endpoint] profile_agent: $PROFILE_ENABLED types=${PROFILE_TYPES:-none} phases=${PROFILE_PHASES:-none}"
if [[ "$BUILD_BINARIES" == "1" ]]; then
  echo "[performance-endpoint] building current SysArmor binaries"
  make -C "$REPO" build-binary
else
  echo "[performance-endpoint] binary build disabled"
fi
if [[ "$VM_FRESH" == "1" ]]; then
  echo "[performance-endpoint] recreating fresh VM environment: $VM_ENV"
  vagrant destroy -f
  SYSARMOR_VM_ENV="$VM_ENV" SYSARMOR_VM_BUILD_BINARIES=0 bash "$ROOT/shared/harness/start-vm.sh" "$VM_ENV"
  cd "$ENVDIR"
else
  echo "[performance-endpoint] reusing existing VM environment: $VM_ENV"
fi
if [[ "$SYNC_VM_AGENT" == "1" ]]; then
  include_bench_content=0
  [[ "$AGENT_MODE" == "managed" ]] && include_bench_content=1
  SYSARMOR_VM_ENV="$VM_ENV" SYSARMOR_VM_INCLUDE_BENCH_CONTENT="$include_bench_content" \
    bash "$ROOT/shared/vm/sync-agent.sh"
  cd "$ENVDIR"
  vagrant rsync node-a >/dev/null 2>&1 || true
else
  echo "[performance-endpoint] VM agent sync disabled"
fi
wait_agent_socket
resolve_agent_identity
enroll_managed_agent
resolve_agent_identity
set_runtime_feature_flags "$MATCHER_STRATEGY"

echo "[performance-endpoint] uploading content packs and policies"
vagrant upload "$REPO/$CONTENT_DIR" /tmp/sysarmor-bench-content node-a >/dev/null
if [[ "$APPLY_DETECTION" == "1" && ! -f "$REPO/$DETECTION_POLICY" ]]; then
  echo "[performance-endpoint][ERROR] detection policy not found: $DETECTION_POLICY" >&2
  exit 1
fi
if [[ "$APPLY_DETECTION" == "1" ]]; then
  vagrant upload "$REPO/$DETECTION_POLICY" /tmp/sysarmor-bench-detection.policy node-a >/dev/null
fi

apply_content() {
  local policy_out="$1"
  local content_name
  for content in "$REPO/$CONTENT_DIR"/*.json; do
    content_name="$(basename "$content")"
    vagrant ssh node-a -c "sudo sysarmorctl --socket '$AGENT_SOCK' --json content apply --file '/tmp/sysarmor-bench-content/$content_name' --allow-unsigned --agent-id '$AGENT_ID' --tenant-id '$TENANT_ID'" \
      > "$policy_out/content.$content_name.apply.json" \
      2>"$policy_out/content.$content_name.apply.err" || {
        echo "[performance-endpoint][ERROR] content apply failed: $content_name" >&2
        cat "$policy_out/content.$content_name.apply.err" >&2 2>/dev/null || true
        exit 1
      }
  done
}

apply_detection() {
  local policy_out="$1"
  local policy_name="$2"
  if [[ "$APPLY_DETECTION" == "1" ]]; then
    echo "[performance-endpoint] applying detection policy: $DETECTION_POLICY"
    vagrant ssh node-a -c "sudo sysarmorctl --socket '$AGENT_SOCK' --json policy apply --type detection --file /tmp/sysarmor-bench-detection.policy --agent-id '$AGENT_ID' --tenant-id '$TENANT_ID' --timeout 60s" \
      > "$policy_out/detection-apply.json" \
      2>"$policy_out/detection-apply.err" || {
        echo "[performance-endpoint][ERROR] detection policy apply failed: $DETECTION_POLICY" >&2
        cat "$policy_out/detection-apply.err" >&2 2>/dev/null || true
        exit 1
      }
    if jq -e '.status == "applied"' "$policy_out/detection-apply.json" >/dev/null; then
      return
    fi
    if [[ "$policy_name" == "collection-minimal" ]] && jq -e '
      .status == "degraded" and
      ([.sections[]? | select(.name == "detection") | .reportJson | fromjson |
        .coverage.rules[]? | select(.status != "covered") |
        {rule_id, missing_behaviors}] ==
       [{"rule_id":"credential_file_read","missing_behaviors":["file.read"]},
        {"rule_id":"account_database_read","missing_behaviors":["file.read"]}])
    ' "$policy_out/detection-apply.json" >/dev/null; then
      echo "[performance-endpoint] expected minimal detection coverage gaps: account_database_read and credential_file_read require file.read"
    else
      echo "[performance-endpoint][ERROR] detection policy was not fully applied: $DETECTION_POLICY" >&2
      cat "$policy_out/detection-apply.json" >&2 2>/dev/null || true
      exit 1
    fi
  else
    echo "[performance-endpoint] detection policy apply disabled"
  fi
}

for policy in $POLICIES_RAW; do
  if [[ ! -f "$REPO/$policy" ]]; then
    echo "[performance-endpoint][ERROR] policy not found: $policy" >&2
    exit 1
  fi
  name="$(policy_name "$policy")"
  policy_out="$OUT_DIR/$name"
  rec_run_id="performance-endpoint/$RUN_ID/$name"
  rec_dir="$RESULTS/recordings/$rec_run_id"
  case_workload="$WORKLOAD"
  case_scenario="$SCENARIO"
  if [[ -z "$case_workload" && -z "$case_scenario" ]]; then
    echo "[performance-endpoint][ERROR] at least one of SYSARMOR_BENCH_WORKLOAD or SYSARMOR_BENCH_SCENARIO is required" >&2
    exit 1
  fi
  rec_labels="benchmark_run=$RUN_ID,policy_profile=$name"
  if [[ -n "$VARIANT" ]]; then
    rec_labels="$rec_labels,variant=$VARIANT"
  fi
  if [[ -n "$MATCHER_STRATEGY" ]]; then
    rec_labels="$rec_labels,matcher_strategy=$MATCHER_STRATEGY"
  fi
  if [[ -n "$case_workload" ]]; then
    rec_labels="$rec_labels,workload=$case_workload"
  fi
  if [[ -n "$case_scenario" ]]; then
    rec_labels="$rec_labels,scenario=$case_scenario"
  fi
  mkdir -p "$policy_out"
  cat >"$policy_out/manifest.json" <<EOF
{
  "suite": "endpoint",
  "tool": "performance-endpoint",
  "benchmark_profile": "$BENCH_PROFILE",
  "vm_env": "$VM_ENV",
  "run_id": "$RUN_ID",
  "recorder_run_id": "$rec_run_id",
  "policy_profile": "$name",
  "policy_file": "$policy",
  "baseline_policy_file": "deployments/agent/policy.json",
  "workload": "$case_workload",
  "scenario": "$case_scenario",
  "variant": "$VARIANT",
  "matcher_strategy": "$MATCHER_STRATEGY",
  "agent_id": "$AGENT_ID",
  "tenant_id": "$TENANT_ID",
  "phase_seconds": {
    "host_baseline": $HOST_BASELINE_SECONDS,
    "agent_idle": $AGENT_IDLE_SECONDS,
    "sensor_idle": $SENSOR_IDLE_SECONDS,
    "baseline": $BASELINE_SECONDS,
    "policy_settle": $POLICY_SETTLE_SECONDS,
    "settle": $SETTLE_SECONDS,
    "steady": $STEADY_SECONDS,
    "workload_warmup": $WORKLOAD_WARMUP_SECONDS,
    "workload": $WORKLOAD_SECONDS,
    "scenario_observe": $SCENARIO_OBSERVE_SECONDS,
    "cooldown": $COOLDOWN_SECONDS
  },
  "recorder": {
    "duration_seconds": $RECORDER_DURATION_SECONDS,
    "semantic_interval_seconds": $RECORDER_SEMANTIC_INTERVAL
  },
  "profiling": {
    "enabled": "$PROFILE_ENABLED",
    "types": "$PROFILE_TYPES",
    "phases": "$PROFILE_PHASES",
    "activity_profile_seconds": $ACTIVITY_PROFILE_SECONDS,
    "semantics": "diagnostic agent pprof/runtime capture; disabled by default and not used for low-disturbance CPU/RSS conclusions; CPU profiles are serialized because the agent debug profile endpoint is mutually exclusive"
  },
  "sync_vm_agent": "$SYNC_VM_AGENT",
  "vm_lifecycle": "fresh",
  "vm_lifecycle_steps": ["make build-binary", "vagrant destroy -f", "start-vm", "sync-agent"],
  "build_binaries": "$BUILD_BINARIES",
  "artifacts": {
    "timeline": "timeline.csv",
    "markers": "markers.ndjson",
    "summary": "summary.json",
    "events": "events.ndjson",
    "events_scope": "events.scope.ndjson",
    "signals": "signals.ndjson",
    "signals_scope": "signals.scope.ndjson",
    "scope_labels": "scope-labels.json",
    "raw_snapshots": "raw/",
    "raw_archive": "raw.tar",
    "profiles": "profiles/"
  }
}
EOF
  cat >"$policy_out/artifacts.json" <<EOF
{
  "timeline.csv": "per-second low-disturbance /proc CPU and RSS samples for agent, sensor, and total EDR cost",
  "markers.ndjson": "phase boundary markers used to align resource samples with benchmark phases",
  "summary.json": "recorder summary derived from timeline and markers",
  "events.ndjson": "continuous raw event watch stream captured for the full recorder lifecycle",
  "signals.ndjson": "continuous raw signal watch stream captured for the full recorder lifecycle",
  "events.scope.ndjson": "offline label-scoped event stream derived from events.ndjson",
  "signals.scope.ndjson": "offline label-scoped signal stream derived from signals.ndjson",
  "scope-labels.json": "labels used to derive *.scope.ndjson from the raw streams",
  "raw/": "raw low-frequency health semantic snapshots",
  "raw.tar": "archive of raw semantic snapshots pulled from the VM",
  "profiles/": "optional raw pprof/runtime diagnostic artifacts when profiling is enabled; CPU profiles are serialized and intended for root-cause attribution, not for low-disturbance resource conclusions"
}
EOF
  cat >"$policy_out/runtime-feature-flags.json" <<EOF
{
  "variant": "$VARIANT",
  "matcher_strategy": "$MATCHER_STRATEGY"
}
EOF

  echo "[performance-endpoint] recording policy=$name workload=${case_workload:-none} scenario=${case_scenario:-none}"
  set_agent_labels "$RUN_ID" "$name" "$case_workload" "$case_scenario"
  if [[ "$AGENT_MODE" == "standalone" ]]; then
    reset_endpoint_policy "$policy_out"
    apply_content "$policy_out"
  fi
  SYSARMOR_RECORDER_DURATION="$RECORDER_DURATION_SECONDS" recorder "$rec_run_id" "$rec_labels" start
  ACTIVE_REC_RUN_ID="$rec_run_id"
  ACTIVE_REC_LABELS="$rec_labels"
  if (( HOST_BASELINE_SECONDS > 0 )); then
    mark "$rec_run_id" host_baseline_start "$name"
    sleep "$HOST_BASELINE_SECONDS"
  fi
  mark "$rec_run_id" agent_idle_start "$name"
  sleep "$AGENT_IDLE_SECONDS"
  mark "$rec_run_id" sensor_idle_start "$name"
  sleep "$SENSOR_IDLE_SECONDS"
  mark "$rec_run_id" baseline_start "$name"
  sleep "$BASELINE_SECONDS"

  echo "[performance-endpoint] applying policy: $policy"
  mark "$rec_run_id" policy_apply_start "$policy"
  start_agent_profile_window "$policy_out" policy_apply "$((POLICY_SETTLE_SECONDS + 5))"
  if [[ "$AGENT_MODE" == "managed" ]]; then
    apply_managed_policy "$policy_out" "$policy"
  else
    vagrant upload "$REPO/$policy" "/tmp/sysarmor-bench-$name.policy" node-a >/dev/null
    vagrant ssh node-a -c "sudo sysarmorctl --socket '$AGENT_SOCK' --json policy apply collection --file '/tmp/sysarmor-bench-$name.policy' --agent-id '$AGENT_ID' --tenant-id '$TENANT_ID' --timeout 60s" \
      > "$policy_out/collection-apply.json" \
      2>"$policy_out/collection-apply.err" || {
        echo "[performance-endpoint][ERROR] policy apply failed: $policy" >&2
        cat "$policy_out/collection-apply.err" >&2 2>/dev/null || true
        exit 1
      }
    if ! grep -Fq 'generated_policy_hash' "$policy_out/collection-apply.json" && ! grep -Fq 'resolved_refs' "$policy_out/collection-apply.json"; then
      echo "[performance-endpoint][ERROR] policy apply did not report generated policy details: $policy" >&2
      cat "$policy_out/collection-apply.json" >&2 2>/dev/null || true
      exit 1
    fi
  fi
  mark "$rec_run_id" policy_apply_done "$policy"

  echo "[performance-endpoint] waiting ${POLICY_SETTLE_SECONDS}s for sensor BPF reload"
  sleep "$POLICY_SETTLE_SECONDS"
  finish_agent_profile_window "$policy_out" policy_apply "$rec_run_id"
  if [[ "$AGENT_MODE" == "standalone" ]]; then
    apply_detection "$policy_out" "$name"
  fi

  mark "$rec_run_id" settle_start "$name"
  sleep "$SETTLE_SECONDS"
  mark "$rec_run_id" steady_start "$name"
  sleep "$STEADY_SECONDS"
  mark "$rec_run_id" workload_start "${case_workload:-none}"
  start_agent_profile_window "$policy_out" workload "$((WORKLOAD_SECONDS + WORKLOAD_WARMUP_SECONDS + 5))"
  run_case_activity "$policy_out" "$case_workload" "$case_scenario" "$rec_run_id"
  mark "$rec_run_id" workload_done "${case_workload:-none}"
  finish_agent_profile_window "$policy_out" workload "$rec_run_id"
  mark "$rec_run_id" cooldown_start "$name"
  sleep "$COOLDOWN_SECONDS"
  mark "$rec_run_id" cooldown_done "$name"

  recorder "$rec_run_id" "$rec_labels" stop
  ACTIVE_REC_RUN_ID=""
  ACTIVE_REC_LABELS=""
  recorder "$rec_run_id" "$rec_labels" report

  cp "$rec_dir/timeline.csv" "$policy_out/timeline.csv"
  cp "$rec_dir/markers.ndjson" "$policy_out/markers.ndjson"
  cp "$rec_dir/summary.json" "$policy_out/summary.json"
  cp "$rec_dir/events.ndjson" "$policy_out/events.ndjson" 2>/dev/null || true
  cp "$rec_dir/events.scope.ndjson" "$policy_out/events.scope.ndjson" 2>/dev/null || true
  cp "$rec_dir/signals.ndjson" "$policy_out/signals.ndjson" 2>/dev/null || true
  cp "$rec_dir/signals.scope.ndjson" "$policy_out/signals.scope.ndjson" 2>/dev/null || true
  cp "$rec_dir/scope-labels.json" "$policy_out/scope-labels.json" 2>/dev/null || true
  cp "$rec_dir/event-watch.err" "$policy_out/event-watch.err" 2>/dev/null || true
  cp "$rec_dir/signal-watch.err" "$policy_out/signal-watch.err" 2>/dev/null || true
  mkdir -p "$policy_out/raw"
  if [[ -d "$rec_dir/raw" ]]; then
    cp -a "$rec_dir/raw/." "$policy_out/raw/" 2>/dev/null || true
  fi
  cp "$rec_dir/raw.tar" "$policy_out/raw.tar" 2>/dev/null || true
done

python3 "$HERE/report.py" "$OUT_DIR"

echo "[performance-endpoint] matrix written to $OUT_DIR/matrix.csv"
