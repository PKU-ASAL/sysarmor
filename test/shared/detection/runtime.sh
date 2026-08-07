#!/usr/bin/env bash

run_endpoint_benchmark() {
  local runner="$1"
  local run_id="$2"
  local policies="$3"
  local variant="$4"
  local matcher_strategy="$5"
  local workload="$6"
  local scenario="$7"
  local vm_env="$8"

  SYSARMOR_BENCH_RUN_ID="$run_id" \
    POLICIES="$policies" \
    SYSARMOR_BENCH_VARIANT="$variant" \
    SYSARMOR_BENCH_MATCHER_STRATEGY="$matcher_strategy" \
    SYSARMOR_BENCH_WORKLOAD="$workload" \
    SYSARMOR_BENCH_SCENARIO="$scenario" \
    SYSARMOR_BENCH_VM_FRESH=1 \
    SYSARMOR_VM_ENV="$vm_env" \
    bash "$runner"
}

capture_manager_resource() {
  local manager_jwt="$1"
  local env_dir="$2"
  local resource="$3"
  local labels="$4"
  case "$resource" in
    events|signals|incidents) ;;
    *)
      echo "[detection-topology][ERROR] unsupported manager resource: $resource" >&2
      return 2
      ;;
  esac

  printf '%s\n' "$manager_jwt" | (cd "$env_dir" && vagrant ssh mgr -c \
    "IFS= read -r SYSARMOR_MANAGER_JWT; export SYSARMOR_MANAGER_JWT; exec /tmp/sysarmorctl --manager-url 127.0.0.1:9443 --json manager $resource list $labels --limit 1000")
}
