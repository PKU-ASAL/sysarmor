#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)
cd "$ROOT"

output=$(go test ./apps/agent/internal/adapters/sqlite -run '^$' -bench '^BenchmarkAppendBatch1000EPS$' -benchtime=3s -count=1)
printf '%s\n' "$output"
rate=$(awk '/BenchmarkAppendBatch1000EPS/ {for (i=1; i<=NF; i++) if ($(i+1) == "events\/s") print $i}' <<<"$output" | tail -1)
awk -v rate="$rate" 'BEGIN {if (rate+0 < 1000) {printf "local store throughput %.2f events/s is below 1000 EPS\n", rate > "/dev/stderr"; exit 1}}'
