#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../../../.." && pwd)"

cd "$REPO"
go test ./apps/manager/internal/adapters/outbound/postgres/... -count=1
