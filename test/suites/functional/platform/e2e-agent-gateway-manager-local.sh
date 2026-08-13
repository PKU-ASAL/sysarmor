#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
REPO="$(cd "$ROOT/.." && pwd)"

echo "[e2e-agent-gateway-manager-local] running layered gateway/worker data path contracts"
cd "$REPO"
go test \
  ./apps/manager/internal/application/gateway/... \
  ./apps/manager/internal/adapters/inbound/kafka \
  ./apps/manager/internal/application/worker/... \
  ./apps/manager/internal/adapters/outbound/opensearch/worker \
  -count=1
echo "[e2e-agent-gateway-manager-local] ok"
