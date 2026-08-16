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
cat > "$OUT_DIR/manifest.json" <<EOF
{
  "suite": "learning-detector-performance",
  "run_id": "$RUN_ID",
  "benchmark_profile": "$PROFILE",
  "policy": "test/data/policies/collection-balanced.json",
  "activity_mode": "serial",
  "scenario": "apt-fileless-c2-local",
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
    "cpu_absolute_pp": 1.0,
    "cpu_relative": 1.15,
    "rss_absolute_mb": 32.0,
    "rss_relative": 1.15,
    "eps_relative": 0.90
  }
}
EOF

run_variant() {
  local variant="$1"
  local child_run="${RUN_ID}-${variant}"
  local child_dir="$RESULTS/performance-endpoint/$child_run"
  local status=0
  local model_args=()
  if [[ "$variant" == "enabled" ]]; then
    model_args=(
      SYSARMOR_BENCH_LEARNING_MODEL="$SIGNED_MODEL"
      SYSARMOR_BENCH_LEARNING_TRUST_KEYS="learning-experiment=$PUBLIC_KEY"
    )
  fi
  if ! env \
    SYSARMOR_VM_ENV=vm-endpoint \
    SYSARMOR_BENCH_PROFILE="$PROFILE" \
    SYSARMOR_BENCH_RUN_ID="$child_run" \
    SYSARMOR_BENCH_VARIANT="learning-$variant" \
    SYSARMOR_BENCH_LEARNING_VARIANT="$variant" \
    SYSARMOR_BENCH_POLICIES="test/data/policies/collection-balanced.json" \
    SYSARMOR_BENCH_WORKLOAD="business-normal" \
    SYSARMOR_BENCH_SCENARIO="apt-fileless-c2-local" \
    SYSARMOR_BENCH_ACTIVITY_MODE=serial \
    SYSARMOR_BENCH_VM_FRESH=1 \
    "${model_args[@]}" \
    bash "$ENDPOINT_RUNNER"; then
    status=1
  fi
  if [[ -d "$child_dir/collection-balanced" ]]; then
    ln -sfn "$child_dir" "$OUT_DIR/$variant"
  fi
  return "$status"
}

if ! run_variant disabled; then
  python3 "$REPORTER" "$OUT_DIR" --aggregate >/dev/null 2>&1 || true
  exit 1
fi
if ! run_variant enabled; then
  python3 "$REPORTER" "$OUT_DIR" --aggregate >/dev/null 2>&1 || true
  exit 1
fi

python3 "$REPORTER" "$OUT_DIR" --aggregate
