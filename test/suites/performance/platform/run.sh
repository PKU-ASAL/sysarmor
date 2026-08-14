#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
REPO="$(cd "$ROOT/.." && pwd)"
ENV_NAME="${ENV:-vm-topology}"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
DURATION="${SYSARMOR_PLATFORM_PERF_DURATION:-120}"
INTERVAL="${SYSARMOR_PLATFORM_PERF_INTERVAL:-5}"
RESULTS="$ROOT/.results/performance-platform/$RUN_ID"
PKI_DIR="${SYSARMOR_VM_MTLS_DIR:-$ROOT/.results/pki/$ENV_NAME}"

mkdir -p "$RESULTS/raw"

if [[ "$ENV_NAME" != "vm-topology" ]]; then
  echo "[performance-platform][ERROR] ENV must be vm-topology, got $ENV_NAME" >&2
  exit 2
fi

echo "[performance-platform] output: $RESULTS"
echo "[performance-platform] env=$ENV_NAME duration=${DURATION}s interval=${INTERVAL}s"

bash "$ROOT/shared/harness/start-vm.sh" "$ENV_NAME"

MANAGER_JWT="$(
  "$REPO/tools/auth/issue-manager-jwt.sh" \
    "$PKI_DIR/manager-jwt-private.pem" \
    sysarmor-bff \
    sysarmor-manager
)"

pushd "$ROOT/environments/$ENV_NAME" >/dev/null

compose_command() {
  vagrant ssh mgr -c 'if sudo docker compose version >/dev/null 2>&1; then printf "sudo docker compose"; elif command -v docker-compose >/dev/null 2>&1; then printf "sudo docker-compose"; else exit 1; fi'
}

capture_manager_metrics() {
  local output_path="$1"

  printf '%s\n' "$MANAGER_JWT" | vagrant ssh mgr -c \
    'IFS= read -r SYSARMOR_MANAGER_JWT; export SYSARMOR_MANAGER_JWT; exec /tmp/sysarmorctl --manager-url 127.0.0.1:9443 --json manager metrics' \
    > "$output_path"
}

COMPOSE_COMMAND="$(compose_command)"

vagrant ssh mgr -c "curl -sf http://127.0.0.1:9443/healthz" \
  > "$RESULTS/raw/manager.healthz.start.json"
vagrant ssh mgr -c "curl -sf http://127.0.0.1:9445/healthz" \
  > "$RESULTS/raw/gateway.healthz.start.json"
capture_manager_metrics "$RESULTS/raw/manager.metrics.start.json"

cat > "$RESULTS/platform.resources.csv" <<'CSV'
sample_ts,container,cpu_pct,mem_usage,mem_limit,mem_pct,net_io,block_io,pids
CSV

end=$((SECONDS + DURATION))
while (( SECONDS < end )); do
  sample_ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  vagrant ssh mgr -c "sudo docker stats --no-stream --format '{{.Name}},{{.CPUPerc}},{{.MemUsage}},{{.MemPerc}},{{.NetIO}},{{.BlockIO}},{{.PIDs}}'" \
    | awk -v ts="$sample_ts" -F, '
      {
        split($3, mem, " / ")
        gsub(/%/, "", $2)
        gsub(/%/, "", $4)
        printf "%s,%s,%s,%s,%s,%s,%s,%s,%s\n", ts, $1, $2, mem[1], mem[2], $4, $5, $6, $7
      }
    ' >> "$RESULTS/platform.resources.csv"
  sleep "$INTERVAL"
done

vagrant ssh mgr -c "curl -sf http://127.0.0.1:9443/healthz" \
  > "$RESULTS/raw/manager.healthz.end.json"
vagrant ssh mgr -c "curl -sf http://127.0.0.1:9445/healthz" \
  > "$RESULTS/raw/gateway.healthz.end.json"
capture_manager_metrics "$RESULTS/raw/manager.metrics.end.json"
vagrant ssh mgr -c "cd /opt/sysarmor/platform && $COMPOSE_COMMAND -f deployments/compose.platform.yaml -f deployments/compose.vm-topology.yaml ps" \
  > "$RESULTS/raw/platform.compose.ps.txt"

popd >/dev/null

python3 - "$RESULTS/platform.resources.csv" "$RESULTS/platform.summary.json" <<'PY'
import csv, json, sys
from collections import defaultdict

csv_path, out_path = sys.argv[1], sys.argv[2]
by_name = defaultdict(lambda: {"samples": 0, "cpu_sum": 0.0, "cpu_max": 0.0, "mem_pct_sum": 0.0, "mem_pct_max": 0.0})
with open(csv_path, newline="") as f:
    for row in csv.DictReader(f):
        name = row["container"]
        item = by_name[name]
        item["samples"] += 1
        cpu = float(row["cpu_pct"] or 0)
        mem_pct = float(row["mem_pct"] or 0)
        item["cpu_sum"] += cpu
        item["cpu_max"] = max(item["cpu_max"], cpu)
        item["mem_pct_sum"] += mem_pct
        item["mem_pct_max"] = max(item["mem_pct_max"], mem_pct)

summary = []
for name, item in sorted(by_name.items()):
    samples = max(item["samples"], 1)
    summary.append({
        "container": name,
        "samples": item["samples"],
        "cpu_avg_pct": round(item["cpu_sum"] / samples, 3),
        "cpu_max_pct": round(item["cpu_max"], 3),
        "mem_avg_pct": round(item["mem_pct_sum"] / samples, 3),
        "mem_max_pct": round(item["mem_pct_max"], 3),
    })

with open(out_path, "w") as f:
    json.dump({"containers": summary}, f, indent=2)
PY

echo "[performance-platform] ok"
