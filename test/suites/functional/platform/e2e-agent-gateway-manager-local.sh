#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
REPO="$(cd "$ROOT/.." && pwd)"

echo "[e2e-agent-gateway-manager-local] running gateway and streaming data path contracts"
cd "$REPO"
go test \
  ./apps/manager/internal/application/gateway/... \
  ./apps/manager/internal/adapters/inbound/grpc/dataplane \
  -count=1
python3 -m unittest test.contracts.test_streaming_architecture
echo "[e2e-agent-gateway-manager-local] ok"
