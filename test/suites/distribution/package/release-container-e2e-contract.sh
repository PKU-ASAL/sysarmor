#!/usr/bin/env bash
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
RELEASE="$REPO/test/suites/distribution/published"

for file in Makefile README.md config.sh doctor.sh run.sh assert.sh scenarios.sh test-assert.sh \
  attacks/web-runtime-shell.sh attacks/download-by-lolbin.sh attacks/payload-lifecycle.sh \
  attacks/reverse-shell.sh attacks/suspicious-exec-connect.sh \
  fixtures/web-app/server.js fixtures/payload-server/server.js fixtures/test-fixtures.sh; do
  test -f "$RELEASE/$file"
done

for file in doctor.sh run.sh assert.sh scenarios.sh test-assert.sh fixtures/test-fixtures.sh \
  attacks/web-runtime-shell.sh attacks/download-by-lolbin.sh attacks/payload-lifecycle.sh \
  attacks/reverse-shell.sh attacks/suspicious-exec-connect.sh; do
  test -x "$RELEASE/$file"
done

for image in ubuntu2204 ubuntu2404 debian12; do
  dockerfile="$RELEASE/images/$image/Dockerfile"
  test -f "$dockerfile"
  grep -Fq 'SHELL ["/bin/bash", "-o", "pipefail", "-c"]' "$dockerfile"
  grep -Fq 'ARG SYSARMOR_INSTALL_URL' "$dockerfile"
  grep -Fq 'ARG SYSARMOR_TETRAGON_URL' "$dockerfile"
  grep -Fq 'SYSARMOR_TETRAGON_URL="$SYSARMOR_TETRAGON_URL"' "$dockerfile"
  grep -Fq -- '--profile linux-container' "$dockerfile"
  grep -Fq 'nodejs' "$dockerfile"
  grep -Fq 'COPY fixtures /opt/sysarmor-release-test' "$dockerfile"
  grep -Fq 'ENTRYPOINT ["/usr/local/bin/sysarmor-container-entrypoint"]' "$dockerfile"
  grep -Fq 'CMD ["node", "/opt/sysarmor-release-test/web-app/server.js"]' "$dockerfile"
done

if grep -R -n -E "require\\([\"']node:" "$RELEASE/fixtures" >/dev/null; then
  echo "release fixtures must support Ubuntu 22.04 Node.js 12" >&2
  exit 1
fi

grep -Fq 'assert.sh' "$RELEASE/run.sh"
grep -Fq 'FRESH_DOWNLOAD="${FRESH_DOWNLOAD:-1}"' "$RELEASE/config.sh"
grep -Fq 'RELEASE_PROXY_URL="${RELEASE_PROXY_URL-https://gh-proxy.org}"' "$RELEASE/config.sh"
grep -Fq -- '--no-cache' "$RELEASE/run.sh"
grep -Fq -- '--build-arg "SYSARMOR_TETRAGON_URL=$TETRAGON_URL"' "$RELEASE/run.sh"
grep -Fq 'TETRAGON_URL="$(resolve_tetragon_url)"' "$RELEASE/run.sh"
grep -Fq 'deployments/sensors/tetragon/bundle.env' "$RELEASE/config.sh"
grep -Fq -- '--privileged' "$RELEASE/run.sh"
grep -Fq -- '--cgroupns=host' "$RELEASE/run.sh"
grep -Fq '/sys/kernel/btf/vmlinux:/sys/kernel/btf/vmlinux:ro' "$RELEASE/run.sh"
grep -Fq '/sys/fs/bpf:/sys/fs/bpf' "$RELEASE/run.sh"
grep -Fq 'prepare_result_root' "$RELEASE/run.sh"
grep -Fq 'docker network create' "$RELEASE/run.sh"
grep -Fq 'payload-server/server.js' "$RELEASE/run.sh"
grep -Fq 'http://127.0.0.1:3000/healthz' "$RELEASE/run.sh"
grep -Fq 'release_scenarios' "$RELEASE/run.sh"
grep -Fq 'scenario_attack' "$RELEASE/run.sh"
grep -Fq 'run_isolation_checks' "$RELEASE/run.sh"
grep -Fq -- '--connect-timeout "$DOWNLOAD_CONNECT_TIMEOUT"' "$RELEASE/config.sh"
grep -Fq 'sysarmorctl --json event watch' "$RELEASE/assert.sh"
grep -Fq 'sysarmorctl --json signal watch' "$RELEASE/assert.sh"
grep -Fq -- '--include-events' "$RELEASE/assert.sh"
grep -Fq '.missingEventRefs // []' "$RELEASE/assert.sh"
grep -Fq '.eventFrames[]?' "$RELEASE/assert.sh"
grep -Fq '.signalFrame.signal.severity == $severity' "$RELEASE/assert.sh"
grep -Fq '.signalFrame.signal.stage == $stage' "$RELEASE/assert.sh"
grep -Fq 'jq ' "$RELEASE/assert.sh"
grep -Fq 'web_runtime_spawns_shell' "$RELEASE/scenarios.sh"
grep -Fq 'download_by_lolbin' "$RELEASE/scenarios.sh"
grep -Fq 'payload_lifecycle' "$RELEASE/scenarios.sh"
grep -Fq 'reverse_shell_pattern' "$RELEASE/scenarios.sh"
grep -Fq 'suspicious_exec_connect' "$RELEASE/scenarios.sh"
grep -Fq 'scenario_stage' "$RELEASE/scenarios.sh"
grep -Fq "'file.write process.exec network.connect'" "$RELEASE/scenarios.sh"
grep -Eq 'payload-lifecycle\).*8443' "$RELEASE/scenarios.sh"

if grep -R -n -E 'RESTART_TEST|verify_restart_recovery|stopped-nonzero' "$RELEASE" >/dev/null; then
  echo "release tests must not contain restart test logic" >&2
  exit 1
fi

if grep -Eq 'sysarmorctl|jq ' "$RELEASE/run.sh"; then
  echo "run.sh must orchestrate without Event/Signal assertions" >&2
  exit 1
fi

for obsolete in common.sh inspect-state.go inspect_state_test.go test-contract.sh; do
  test ! -e "$RELEASE/$obsolete"
done

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
# shellcheck source=/dev/null
source "$RELEASE/run.sh"
mkdir -p "$tmp/results/repeat-run"
printf '%s\n' stale >"$tmp/results/repeat-run/stale.txt"
prepare_result_root "$tmp/results" repeat-run
test ! -e "$tmp/results/repeat-run/stale.txt"
test "$RESULT_ROOT" = "$tmp/results/repeat-run"
for invalid_run_id in '../escape' '/tmp/escape' 'bad id'; do
  if prepare_result_root "$tmp/results" "$invalid_run_id" >/dev/null 2>&1; then
    echo "invalid RUN_ID accepted: $invalid_run_id" >&2
    exit 1
  fi
done

echo "[release-container-e2e-contract] ok"
