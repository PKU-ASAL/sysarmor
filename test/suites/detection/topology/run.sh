#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
REPO="$(cd "$ROOT/.." && pwd)"
RESULTS="$ROOT/.results"
VM_ENV="${SYSARMOR_VM_ENV:-${ENV:-vm-topology}}"
ENVDIR="$ROOT/environments/$VM_ENV"
PKI_DIR="${SYSARMOR_VM_MTLS_DIR:-$RESULTS/pki/$VM_ENV}"
RUN_ID="${SYSARMOR_BENCH_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
OUT_DIR="$RESULTS/detection-topology/$RUN_ID"
# shellcheck source=/dev/null
source "$ROOT/shared/detection/runtime.sh"

POLICIES="${POLICIES-test/data/policies/collection-balanced.json test/data/policies/collection-deep.json}"
WORKLOADS="${WORKLOADS-business-normal}"
SCENARIOS="${SCENARIOS-apt-fileless-c2 apt-staged-drop benign-ci-noise}"
MATCHER_VARIANTS="${MATCHER_VARIANTS:-}"
MATRIX_MODE="${MATRIX_MODE:-cross}"
STOP_ON_ERROR="${STOP_ON_ERROR:-0}"
EVALUATION_SCOPE="${EVALUATION_SCOPE:-manager}"
AGENT_MODE="managed"
failed_cases=0

mkdir -p "$OUT_DIR"

cat >"$OUT_DIR/manifest.json" <<EOF
{
  "suite": "topology",
  "tool": "detection-topology",
  "evaluation_scope": "$EVALUATION_SCOPE",
  "agent_mode": "$AGENT_MODE",
  "topology": "vm",
  "run_id": "$RUN_ID",
  "policies": "$POLICIES",
  "workloads": "$WORKLOADS",
  "scenarios": "$SCENARIOS",
  "matcher_variants": "$MATCHER_VARIANTS",
  "matrix_mode": "$MATRIX_MODE",
  "vm_lifecycle": "fresh-per-case"
}
EOF

json_to_ndjson() {
  local src="$1"
  local dst="$2"
  python3 - "$src" "$dst" <<'PY'
import json
import pathlib
import sys

src, dst = map(pathlib.Path, sys.argv[1:3])
try:
    data = json.loads(src.read_text(errors="replace"))
except Exception:
    data = []
if isinstance(data, dict):
    for key in ("events", "signals", "incidents", "items", "data"):
        if isinstance(data.get(key), list):
            data = data[key]
            break
    else:
        data = [data] if data else []
if not isinstance(data, list):
    data = []
with dst.open("w") as f:
    for item in data:
        f.write(json.dumps(item, separators=(",", ":")) + "\n")
PY
}

manager_label_args() {
  local policy="$1"
  local workload="$2"
  local scenario="$3"
  local bench_run_id="$4"
  printf -- "--label benchmark_run=%s --label policy_profile=%s" "$bench_run_id" "$policy"
  if [[ -n "$workload" ]]; then
    printf -- " --label workload=%s" "$workload"
  fi
  if [[ -n "$scenario" ]]; then
    printf -- " --label scenario=%s" "$scenario"
  fi
}

capture_manager_case() {
  local bench_run_id="$1"
  local workload="$2"
  local scenario="$3"
  local bench_root="$RESULTS/performance-endpoint/$bench_run_id"
  local manager_jwt signal_required=1
  [[ -d "$bench_root" ]] || return 0
  [[ "$scenario" == benign-* ]] && signal_required=0
  manager_jwt="$("$REPO/tools/auth/issue-manager-jwt.sh" "$PKI_DIR/manager-jwt-private.pem" sysarmor-bff sysarmor-manager)"
  for policy_out in "$bench_root"/*; do
    [[ -d "$policy_out" && -f "$policy_out/summary.json" ]] || continue
    local policy
    policy="$(basename "$policy_out")"
    local labels
    labels="$(manager_label_args "$policy" "$workload" "$scenario" "$bench_run_id")"
    echo "[detection-topology] capturing manager telemetry policy=$policy workload=${workload:-none} scenario=${scenario:-none}"
    wait_manager_resource "$manager_jwt" "$ENVDIR" events "$labels" \
      "$policy_out/manager.events.json" 1 120 || return 1
    wait_manager_resource "$manager_jwt" "$ENVDIR" signals "$labels" \
      "$policy_out/manager.signals.json" "$signal_required" 120 || return 1
    wait_manager_resource "$manager_jwt" "$ENVDIR" incidents "$labels" \
      "$policy_out/manager.incidents.json" 0 10 || return 1
    json_to_ndjson "$policy_out/manager.events.json" "$policy_out/manager.events.ndjson"
    json_to_ndjson "$policy_out/manager.signals.json" "$policy_out/manager.signals.ndjson"
    json_to_ndjson "$policy_out/manager.incidents.json" "$policy_out/manager.incidents.ndjson"
  done
}

run_case() {
  local variant="${1:-}"
  local matcher_strategy="${2:-}"
  local workload="${3:-}"
  local scenario="${4:-}"
  local workload_label="${workload:-none}"
  local scenario_label="${scenario:-none}"
  local variant_label="${variant:-default}"
  local case_name="workload=${workload_label}__scenario=${scenario_label}"
  if [[ -n "$variant" ]]; then
    case_name="variant=${variant_label}__$case_name"
  fi
  local case_run_id="$RUN_ID/cases/$case_name"
  local case_dir="$OUT_DIR/cases/$case_name"
  local failure_rc=1
  mkdir -p "$case_dir"

  echo "[detection-topology] variant=$variant_label matcher_strategy=${matcher_strategy:-config-default} workload=$workload_label scenario=$scenario_label"
  if run_endpoint_benchmark "$ROOT/suites/performance/endpoint/run.sh" \
      "$case_run_id" "$POLICIES" "$variant" "$matcher_strategy" \
      "$workload" "$scenario" "$VM_ENV" "$AGENT_MODE" \
      >"$case_dir/run.out" 2>"$case_dir/run.err"; then
    if capture_manager_case "$case_run_id" "$workload" "$scenario"; then
      printf '{"name":"%s","variant":"%s","matcher_strategy":"%s","workload":"%s","scenario":"%s","status":"ok","bench_run_id":"%s"}\n' \
        "$case_name" "$variant" "$matcher_strategy" "$workload" "$scenario" "$case_run_id" >"$case_dir/status.json"
      return 0
    fi
    echo "[detection-topology][ERROR] Manager telemetry capture failed for $case_name" >&2
  else
    failure_rc=$?
    echo "[detection-topology][ERROR] benchmark failed for $case_name" >&2
  fi
  failed_cases=$((failed_cases + 1))
  printf '{"name":"%s","variant":"%s","matcher_strategy":"%s","workload":"%s","scenario":"%s","status":"failed","exit_code":%s,"bench_run_id":"%s"}\n' \
    "$case_name" "$variant" "$matcher_strategy" "$workload" "$scenario" "$failure_rc" "$case_run_id" >"$case_dir/status.json"
  if [[ "$STOP_ON_ERROR" == "1" ]]; then
    cat "$case_dir/run.err" >&2 2>/dev/null || true
    exit "$failure_rc"
  fi
}

echo "[detection-topology] output: $OUT_DIR"
echo "[detection-topology] evaluation_scope: $EVALUATION_SCOPE"
echo "[detection-topology] policies: $POLICIES"
echo "[detection-topology] workloads: $WORKLOADS"
echo "[detection-topology] scenarios: $SCENARIOS"
echo "[detection-topology] matcher_variants: ${MATCHER_VARIANTS:-default}"
echo "[detection-topology] matrix_mode: $MATRIX_MODE"

run_mode_for_variant() {
  local variant="${1:-}"
  local matcher_strategy="${2:-}"
  case "$MATRIX_MODE" in
    workload)
      for workload in $WORKLOADS; do
        run_case "$variant" "$matcher_strategy" "$workload" ""
      done
      ;;
    scenario)
      for scenario in $SCENARIOS; do
        run_case "$variant" "$matcher_strategy" "" "$scenario"
      done
      ;;
    cross)
      for workload in $WORKLOADS; do
        for scenario in $SCENARIOS; do
          run_case "$variant" "$matcher_strategy" "$workload" "$scenario"
        done
      done
      ;;
    all)
      for workload in $WORKLOADS; do
        run_case "$variant" "$matcher_strategy" "$workload" ""
      done
      for scenario in $SCENARIOS; do
        run_case "$variant" "$matcher_strategy" "" "$scenario"
      done
      for workload in $WORKLOADS; do
        for scenario in $SCENARIOS; do
          run_case "$variant" "$matcher_strategy" "$workload" "$scenario"
        done
      done
      ;;
    *)
      echo "[detection-topology][ERROR] unsupported MATRIX_MODE=$MATRIX_MODE (want workload|scenario|cross|all)" >&2
      exit 1
      ;;
  esac
}

if [[ -n "$MATCHER_VARIANTS" ]]; then
  for matcher_strategy in $MATCHER_VARIANTS; do
    case "$matcher_strategy" in
      linear|optimized) ;;
      *)
        echo "[detection-topology][ERROR] unsupported matcher variant: $matcher_strategy" >&2
        exit 1
        ;;
    esac
    run_mode_for_variant "matcher-$matcher_strategy" "$matcher_strategy"
  done
else
  run_mode_for_variant "" ""
fi

python3 "$HERE/report.py" "$OUT_DIR"
if (( failed_cases > 0 )); then
  echo "[detection-topology][ERROR] $failed_cases case(s) failed; see $OUT_DIR/matrix.csv" >&2
  exit 1
fi
python3 "$ROOT/shared/reports/detection_report.py" \
  --bench-matrix-dir "$OUT_DIR" \
  --output-dir "$RESULTS/detection/$RUN_ID" \
  --topology vm \
  --scope "$EVALUATION_SCOPE" \
  --scenarios $SCENARIOS \
  --workloads $WORKLOADS
python3 "$ROOT/shared/reports/assert_detection.py" \
  --matrix "$RESULTS/detection/$RUN_ID/matrix.csv" \
  --truth-steps "$RESULTS/detection/$RUN_ID/truth_steps.csv" \
  --min-score "${SYSARMOR_DETECTION_MIN_SCORE:-0.9}"

echo "[detection-topology] matrix written to $OUT_DIR/matrix.csv"
echo "[detection-topology] detection results written to $RESULTS/detection/$RUN_ID"
