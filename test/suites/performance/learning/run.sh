#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
REPO="$(cd "$ROOT/.." && pwd)"
RESULTS="$ROOT/.results"
RUN_ID="${SYSARMOR_LEARNING_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
OUT_DIR="$RESULTS/learning-detector/$RUN_ID"
TRAINING_DATA="${SYSARMOR_LEARNING_TRAINING_DATA:-${TRAINING_DATA:-}}"
CALIBRATION_DATA="${SYSARMOR_LEARNING_CALIBRATION_DATA:-${CALIBRATION_DATA:-}}"
PROFILE="${SYSARMOR_LEARNING_PROFILE:-${PROFILE:-medium}}"
AGENT_MODE="${SYSARMOR_LEARNING_AGENT_MODE:-managed}"
case "$AGENT_MODE" in
  managed) VM_ENV="vm-topology" ;;
  standalone) VM_ENV="vm-endpoint" ;;
  *)
    echo "[learning-performance][ERROR] unsupported Agent mode: $AGENT_MODE" >&2
    exit 1
    ;;
esac
MODEL_DIR="$OUT_DIR/model"
UNSIGNED_MODEL="$MODEL_DIR/model-bundle.json"
SIGNED_MODEL="$MODEL_DIR/model-bundle.signed.json"
PRIVATE_KEY="$MODEL_DIR/.model-signing.key"
ENDPOINT_RUNNER="$ROOT/suites/performance/endpoint/run.sh"
REPORTER="$HERE/report.py"

if [[ -z "$TRAINING_DATA" || -z "$CALIBRATION_DATA" ]]; then
  echo "[learning-performance][ERROR] training and calibration datasets are required" >&2
  exit 1
fi
if [[ ! -f "$TRAINING_DATA" || ! -f "$CALIBRATION_DATA" ]]; then
  echo "[learning-performance][ERROR] training/calibration dataset not found" >&2
  exit 1
fi
mkdir -p "$MODEL_DIR"

make -C "$REPO" build-binary
python3 "$REPO/tools/learning_detector/prepare_model.py" \
  --training "$TRAINING_DATA" --calibration "$CALIBRATION_DATA" --output "$UNSIGNED_MODEL" \
  > "$MODEL_DIR/calibration.json"
openssl genpkey -algorithm ED25519 -out "$PRIVATE_KEY" >/dev/null 2>&1
chmod 0600 "$PRIVATE_KEY"
PUBLIC_KEY="$(openssl pkey -in "$PRIVATE_KEY" -pubout -outform DER 2>/dev/null | tail -c 32 | base64 -w0)"
printf 'learning-experiment=%s\n' "$PUBLIC_KEY" > "$MODEL_DIR/trust-key.txt"
"$REPO/dist/bin/sysarmor-model-sign" --key "$PRIVATE_KEY" --key-id learning-experiment \
  --input "$UNSIGNED_MODEL" --output "$SIGNED_MODEL"
rm -f "$PRIVATE_KEY"
[[ -s "$SIGNED_MODEL" && -n "$PUBLIC_KEY" ]] || {
  echo "[learning-performance][ERROR] signed model verification material is missing" >&2
  exit 1
}

MODEL_REF="$(jq -r '.model_ref' "$SIGNED_MODEL")"
MODEL_VERSION="$(jq -r '.model_version' "$SIGNED_MODEL")"
MODEL_DIGEST="$(jq -r '.model_digest' "$SIGNED_MODEL")"
FEATURE_SCHEMA="$(jq -r '.feature_schema' "$SIGNED_MODEL")"
THRESHOLD="$(jq -r '.threshold' "$SIGNED_MODEL")"
TRAINING_DIGEST="$(jq -r '.datasets.training.sha256' "$MODEL_DIR/calibration.json")"
CALIBRATION_DIGEST="$(jq -r '.datasets.calibration.sha256' "$MODEL_DIR/calibration.json")"
GIT_COMMIT="$(git -C "$REPO" rev-parse HEAD)"
GIT_DIRTY=false
if [[ -n "$(git -C "$REPO" status --porcelain --untracked-files=normal)" ]]; then
  GIT_DIRTY=true
fi
cat > "$OUT_DIR/manifest.json" <<EOF
{
  "suite": "learning-detector-performance",
  "run_id": "$RUN_ID",
  "benchmark_profile": "$PROFILE",
  "agent_mode": "$AGENT_MODE",
  "policy": "mode-specific",
  "collection_policy_by_mode": {
    "rule-only": "test/data/policies/collection-balanced.json",
    "learning-only": "test/data/policies/collection-learning.json",
    "hybrid": "test/data/policies/collection-hybrid.json"
  },
  "activity_mode": "serial",
  "scenario": "apt-fileless-c2-local",
  "git_commit": "$GIT_COMMIT",
  "git_dirty": $GIT_DIRTY,
  "git_provenance_source": "captured-before-modes",
  "training_data": "$TRAINING_DATA",
  "training_digest": "$TRAINING_DIGEST",
  "calibration_data": "$CALIBRATION_DATA",
  "calibration_digest": "$CALIBRATION_DIGEST",
  "model_ref": "$MODEL_REF",
  "model_version": "$MODEL_VERSION",
  "model_digest": "$MODEL_DIGEST",
  "feature_schema": "$FEATURE_SCHEMA",
  "threshold": $THRESHOLD,
  "gate_config": {
    "learning_only_cpu_pct": 30.0,
    "hybrid_cpu_pct": 15.0,
    "rss_delta_mb": 16.0,
    "eps_relative": 0.90,
    "normal_candidate_rate": 0.01,
    "attack_campaign_seed_recall": 0.90,
    "stream_graph_recall": 0.90,
    "conclusion_recall": 0.90
  }
}
EOF

run_mode() {
  local protection_mode="$1"
  local child_run="${RUN_ID}-${protection_mode}"
  local child_dir="$RESULTS/performance-endpoint/$child_run"
  local status=0
  local model_args=()
  local collection_policy collection_name
  if [[ "$protection_mode" == "rule-only" ]]; then
    collection_policy="test/data/policies/collection-balanced.json"
  elif [[ "$protection_mode" == "hybrid" ]]; then
    collection_policy="test/data/policies/collection-hybrid.json"
  else
    collection_policy="test/data/policies/collection-learning.json"
  fi
  collection_name="${collection_policy##*/}"
  collection_name="${collection_name%.json}"
  if [[ "$protection_mode" != "rule-only" ]]; then
    model_args=(
      SYSARMOR_BENCH_LEARNING_MODEL="$SIGNED_MODEL"
      SYSARMOR_BENCH_LEARNING_TRUST_KEYS="learning-experiment=$PUBLIC_KEY"
    )
  fi
  if ! env \
    SYSARMOR_VM_ENV="$VM_ENV" \
    SYSARMOR_BENCH_AGENT_MODE="$AGENT_MODE" \
    SYSARMOR_BENCH_PROFILE="$PROFILE" \
    SYSARMOR_BENCH_RUN_ID="$child_run" \
    SYSARMOR_BENCH_VARIANT="$protection_mode" \
    SYSARMOR_BENCH_PROTECTION_MODE="$protection_mode" \
    SYSARMOR_BENCH_POLICIES="$collection_policy" \
    SYSARMOR_BENCH_WORKLOAD="business-normal" \
    SYSARMOR_BENCH_SCENARIO="apt-fileless-c2-local" \
    SYSARMOR_BENCH_ACTIVITY_MODE=serial \
    SYSARMOR_BENCH_VM_FRESH="${SYSARMOR_LEARNING_VM_FRESH:-1}" \
    "${model_args[@]}" \
    bash "$ENDPOINT_RUNNER" >"$child_dir/endpoint-run.log" 2>&1; then
    status=1
    {
      echo "mode=$protection_mode"
      echo "endpoint_log=$child_dir/endpoint-run.log"
      echo "vm_env=$VM_ENV"
      echo "vm_status:"
      (cd "$ROOT/test/environments/$VM_ENV" && vagrant status) || true
    } >"$child_dir/failure.txt"
  fi
  if [[ -d "$child_dir/$collection_name" ]]; then
    ln -sfn "$child_dir" "$OUT_DIR/$protection_mode"
  fi
  return "$status"
}

for protection_mode in rule-only learning-only hybrid; do
  if ! run_mode "$protection_mode"; then
    python3 "$REPORTER" "$OUT_DIR" --aggregate >/dev/null 2>&1 || true
    exit 1
  fi
done

python3 "$REPORTER" "$OUT_DIR" --aggregate
