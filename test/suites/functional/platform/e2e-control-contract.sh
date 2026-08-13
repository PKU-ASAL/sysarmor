#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../../../.." && pwd)"

cd "$REPO"
go test ./apps/manager/internal/adapters/inbound/grpc/control ./apps/manager/internal/adapters/inbound/grpc/dataplane ./apps/manager/internal/application/gateway/... -count=1
go test ./apps/agent/internal/daemon -run 'Test(ControlChannelKeepsLongLivedContract|AgentRuntimeControlChannelProcessesPendingResponse)'
