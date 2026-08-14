#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
REPO="$(cd "$ROOT/.." && pwd)"

echo "[e2e-control-roundtrip-local] running gateway and agent control roundtrip contracts"
cd "$REPO"
go test ./apps/manager/internal/adapters/inbound/grpc/control ./apps/manager/internal/adapters/outbound/postgres/control ./apps/manager/internal/application/gateway/... -count=1
go test ./apps/agent/internal/bootstrap/runtime -run 'TestRuntimeControlChannel(ProcessesPendingResponse|AppliesContentUpdate)$' -count=1
echo "[e2e-control-roundtrip-local] ok"
