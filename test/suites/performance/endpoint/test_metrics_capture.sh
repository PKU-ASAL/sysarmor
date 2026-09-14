#!/usr/bin/env bash
set -euo pipefail

script="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/run.sh"
grep -q 'while (( SECONDS < deadline ))' "$script"
grep -q 'sysarmor.data.detection.metrics.v1' "$script"
grep -q 'nodlink-metrics.json' "$script"
echo "metrics capture contract passed"
