#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
REPO="$(cd "$ROOT/.." && pwd)"
RESULTS="$ROOT/.results"
WORK="/tmp/sysarmor-agent-namespace-self-container"
SCENARIO="${SCENARIO:-namespace-self-container}"
OWNED_CONTAINER="tetragon-namespace-self"
AGENT_ID="${SYSARMOR_NAMESPACE_SELF_AGENT_ID:-agent-namespace-self-container}"
TARGET_IMAGE="${SYSARMOR_NAMESPACE_SELF_IMAGE:-sysarmor-test/vuln-web:latest}"
CHANNEL="${SYSARMOR_NAMESPACE_SELF_CHANNEL:-linux-container-dev}"
MANAGER_PORT="${SYSARMOR_MANAGER_PORT:-19443}"
GATEWAY_HEALTH_PORT="${SYSARMOR_GATEWAY_HEALTH_PORT:-19445}"
PKI_DIR="$REPO/deployments/pki/agent-plane-mtls/runtime"

mkdir -p "$RESULTS"

cleanup() {
  docker exec "$OWNED_CONTAINER" sh -c 'if [ -f /tmp/sysarmor-agent-namespace-self-container/agent.pid ]; then kill "$(cat /tmp/sysarmor-agent-namespace-self-container/agent.pid)" 2>/dev/null || true; fi' >/dev/null 2>&1 || true
  docker rm -f "$OWNED_CONTAINER" >/dev/null 2>&1 || true
}
trap cleanup EXIT

container_running() {
  [[ "$(docker inspect "$1" --format '{{.State.Running}}' 2>/dev/null || true)" == "true" ]]
}

require_platform() {
  local missing=0
  local signing_created=0
  signing_created="$(ensure_artifact_signing_material)"
  for name in sysarmor-manager sysarmor-gateway sysarmor-worker sysarmor-postgres sysarmor-kafka sysarmor-redis sysarmor-opensearch sysarmor-packages; do
    if ! container_running "$name"; then
      missing=1
      break
    fi
  done
  if (( missing == 1 || signing_created == 1 )); then
    echo "[e2e-agent-namespace-self-container] SysArmor platform missing or signing material changed; running make deploy"
    make -C "$REPO" deploy
  fi
}

wait_platform_ready() {
  local deadline=$((SECONDS + 120))
  until curl -sf "http://127.0.0.1:$MANAGER_PORT/healthz" >/dev/null && \
    curl -sf "http://127.0.0.1:$GATEWAY_HEALTH_PORT/healthz" >/dev/null; do
    if (( SECONDS >= deadline )); then
      echo "[e2e-agent-namespace-self-container][ERROR] SysArmor platform did not become ready" >&2
      docker logs sysarmor-manager --tail 120 >&2 2>/dev/null || true
      docker logs sysarmor-gateway --tail 120 >&2 2>/dev/null || true
      exit 1
    fi
    sleep 1
  done
}

container_network() {
  docker inspect sysarmor-gateway --format '{{range $k, $v := .NetworkSettings.Networks}}{{$k}}{{end}}'
}

gateway_ip() {
  local network="$1"
  docker inspect sysarmor-gateway --format "{{with index .NetworkSettings.Networks \"$network\"}}{{.IPAddress}}{{end}}"
}

manager_ip() {
  local network="$1"
  docker inspect sysarmor-manager --format "{{with index .NetworkSettings.Networks \"$network\"}}{{.IPAddress}}{{end}}"
}

json_value() {
  local file="$1"
  local expr="$2"
  python3 - "$file" "$expr" <<'PY'
import json
import sys

data = json.load(open(sys.argv[1]))
value = data
for part in sys.argv[2].split("."):
    value = value[part]
print(value)
PY
}

assert_event_present() {
  local file="$1"
  local agent_id="$2"
  local scenario="$3"
  local marker="$4"
  local argv_substring="$5"
  python3 - "$file" "$agent_id" "$scenario" "$marker" "$argv_substring" <<'PY'
import json
import sys

path, agent_id, scenario, marker, argv_substring = sys.argv[1:]
events = json.load(open(path))
for event in events:
    labels = event.get("labels") or {}
    proc = event.get("subjectProc") or {}
    argv = " ".join(str(v) for v in proc.get("argv") or [])
    if (
        event.get("agentId") == agent_id
        and event.get("behavior") == "process.exec"
        and labels.get("scenario") == scenario
        and marker in argv
        and argv_substring in argv
    ):
        print(json.dumps(event, indent=2, sort_keys=True))
        sys.exit(0)
raise SystemExit(
    "missing event with "
    f"agentId={agent_id} scenario={scenario} behavior=process.exec "
    f"marker={marker} argv_substring={argv_substring}"
)
PY
}

assert_event_absent() {
  local file="$1"
  local agent_id="$2"
  local scenario="$3"
  local marker="$4"
  python3 - "$file" "$agent_id" "$scenario" "$marker" <<'PY'
import json
import sys

path, agent_id, scenario, marker = sys.argv[1:]
events = json.load(open(path))
matches = []
for event in events:
    labels = event.get("labels") or {}
    proc = event.get("subjectProc") or {}
    argv = " ".join(str(v) for v in proc.get("argv") or [])
    if (
        event.get("agentId") == agent_id
        and event.get("behavior") == "process.exec"
        and labels.get("scenario") == scenario
        and marker in argv
    ):
        matches.append(event)
if matches:
    print(json.dumps(matches, indent=2, sort_keys=True), file=sys.stderr)
    raise SystemExit(
        f"unexpected host event captured by namespace scoped agent: marker={marker}"
    )
PY
}

wait_event_present() {
  local name="$1"
  local marker="$2"
  local cmd="$3"
  local argv_substring="$4"
  local deadline=$((SECONDS + 90))
  local out="$RESULTS/e2e-agent-namespace-self-container.events-$name.json"
  local match="$RESULTS/e2e-agent-namespace-self-container.$name-match.json"
  local assert_err="$RESULTS/e2e-agent-namespace-self-container.$name-assert.err"
  while true; do
    docker exec "$OWNED_CONTAINER" sh -c "$cmd"
    curl -sf "$MANAGER_URL/api/v1/events?label=scenario=$SCENARIO&behavior=process.exec&limit=200" > "$out"
    if assert_event_present "$out" "$AGENT_ID" "$SCENARIO" "$marker" "$argv_substring" > "$match" 2>"$assert_err"; then
      echo "--- $name events response ---"
      cat "$out"
      echo "--- $name matched event ---"
      cat "$match"
      return
    fi
    if (( SECONDS >= deadline )); then
      echo "[e2e-agent-namespace-self-container][ERROR] $name container event did not appear" >&2
      echo "--- $name input ---" >&2
      cat "$RESULTS/e2e-agent-namespace-self-container.$name-input.txt" >&2 2>/dev/null || true
      echo "--- last events response ---" >&2
      cat "$out" >&2 2>/dev/null || true
      echo "--- assertion ---" >&2
      cat "$assert_err" >&2 2>/dev/null || true
      echo "--- agent log ---" >&2
      docker exec "$OWNED_CONTAINER" cat "$WORK/agent.log" >&2 2>/dev/null || true
      exit 1
    fi
    sleep 1
  done
}

require_tetragon_archive() {
  local archive="${SYSARMOR_TETRAGON_ARCHIVE:-}"
  if [[ -z "$archive" && -f "$REPO/.cache/tetragon-v1.7.0-amd64.tar.gz" ]]; then
    archive="$REPO/.cache/tetragon-v1.7.0-amd64.tar.gz"
  fi
  if [[ -z "$archive" || ! -f "$archive" ]]; then
    echo "[e2e-agent-namespace-self-container][ERROR] SYSARMOR_TETRAGON_ARCHIVE or local tetragon-v1.7.0-amd64.tar.gz cache is required" >&2
    exit 1
  fi
  printf '%s\n' "$archive"
}

ensure_artifact_signing_material() {
  mkdir -p "$PKI_DIR"
  if [[ -f "$PKI_DIR/artifact-signing-key.pem" && -f "$PKI_DIR/artifact-public.pem" ]]; then
    printf '0\n'
    return
  fi
  openssl genrsa -out "$PKI_DIR/artifact-signing-key.pem" 3072 >/dev/null 2>&1
  openssl rsa -in "$PKI_DIR/artifact-signing-key.pem" -pubout -out "$PKI_DIR/artifact-public.pem" >/dev/null 2>&1
  chmod 0600 "$PKI_DIR/artifact-signing-key.pem"
  chmod 0644 "$PKI_DIR/artifact-public.pem"
  printf '1\n'
}

ensure_manager_install_profile_support() {
  local probe_json="$RESULTS/e2e-agent-namespace-self-container.profile-probe.json"
  local probe_script="$RESULTS/e2e-agent-namespace-self-container.profile-probe.sh"
  curl -sf -X POST "http://127.0.0.1:$MANAGER_PORT/api/v1/enrollments" \
    -H "Content-Type: application/json" \
    -d '{"tenant_id":"default","agent_id":"namespace-profile-probe","gateway_addr":"127.0.0.1:9444","artifact_url":"https://example.invalid/sysarmor-agent.tar.gz","profile":"linux-container","ttl":"5m"}' >"$probe_json"
  local install_url
  install_url="$(json_value "$probe_json" install_url)"
  curl -sf "$install_url" >"$probe_script"
  if ! grep -Fq 'SYSARMOR_INSTALL_PROFILE="${SYSARMOR_INSTALL_PROFILE:-linux-container}"' "$probe_script" || grep -Fq 'python3' "$probe_script" || ! grep -Fq 'BEGIN PUBLIC KEY' "$probe_script" || ! grep -Fq '},[[:space:]]*{' "$probe_script"; then
    echo "[e2e-agent-namespace-self-container] running manager does not expose current linux-container installer; running make deploy"
    make -C "$REPO" deploy
    wait_platform_ready
  fi
}

ensure_seeded_artifact_channel() {
  local channels_json="$RESULTS/e2e-agent-namespace-self-container.channels.json"
  local artifacts_json="$RESULTS/e2e-agent-namespace-self-container.artifacts.json"
  curl -sf "http://127.0.0.1:$MANAGER_PORT/api/v1/channels?tenant_id=default" >"$channels_json"
  curl -sf "http://127.0.0.1:$MANAGER_PORT/api/v1/artifacts?tenant_id=default&kind=agent&status=active" >"$artifacts_json"
  if ! python3 - "$channels_json" "$artifacts_json" "$CHANNEL" <<'PY'
import json
import sys

data = json.load(open(sys.argv[1]))
artifacts = json.load(open(sys.argv[2]))
want = sys.argv[3]
artifact_id = ""
for channel in data.get("channels", []):
    if channel.get("channel") == want:
        artifact_id = channel.get("artifact_id", "")
        break
if not artifact_id:
    raise SystemExit(1)
for artifact in artifacts.get("artifacts", []):
    if artifact.get("artifact_id") != artifact_id:
        continue
    download_url = (artifact.get("metadata") or {}).get("download_url", "")
    if "http://packages/" in download_url:
        sys.exit(0)
raise SystemExit(1)
PY
  then
    echo "[e2e-agent-namespace-self-container] manager missing seeded packages channel=$CHANNEL; running make deploy"
    make -C "$REPO" deploy
    wait_platform_ready
    curl -sf "http://127.0.0.1:$MANAGER_PORT/api/v1/channels?tenant_id=default" >"$channels_json"
    curl -sf "http://127.0.0.1:$MANAGER_PORT/api/v1/artifacts?tenant_id=default&kind=agent&status=active" >"$artifacts_json"
    python3 - "$channels_json" "$artifacts_json" "$CHANNEL" <<'PY'
import json
import sys

data = json.load(open(sys.argv[1]))
artifacts = json.load(open(sys.argv[2]))
want = sys.argv[3]
artifact_id = ""
for channel in data.get("channels", []):
    if channel.get("channel") == want:
        artifact_id = channel.get("artifact_id", "")
        break
if not artifact_id:
    raise SystemExit(f"seeded package channel not found: {want}")
for artifact in artifacts.get("artifacts", []):
    if artifact.get("artifact_id") != artifact_id:
        continue
    download_url = (artifact.get("metadata") or {}).get("download_url", "")
    if "http://packages/" in download_url:
        sys.exit(0)
raise SystemExit(f"seeded package channel does not use packages download URL: {want}")
PY
  fi
}

echo "[e2e-agent-namespace-self-container] checking SysArmor platform"
require_platform
wait_platform_ready
ensure_manager_install_profile_support
ensure_seeded_artifact_channel

NETWORK="$(container_network)"
GATEWAY_IP="$(gateway_ip "$NETWORK")"
MANAGER_IP="$(manager_ip "$NETWORK")"
if [[ -z "$NETWORK" || -z "$GATEWAY_IP" || -z "$MANAGER_IP" ]]; then
  echo "[e2e-agent-namespace-self-container][ERROR] failed to resolve platform network/ip: network=$NETWORK manager=$MANAGER_IP gateway=$GATEWAY_IP" >&2
  exit 1
fi
MANAGER_URL="http://$MANAGER_IP:9443"
echo "[e2e-agent-namespace-self-container] network=$NETWORK manager=$MANAGER_IP gateway=$GATEWAY_IP"

trap cleanup EXIT

ENROLLMENT_JSON="$RESULTS/e2e-agent-namespace-self-container.enrollment.json"
curl -sf -X POST "$MANAGER_URL/api/v1/enrollments" \
  -H "Content-Type: application/json" \
  -d "{\"tenant_id\":\"default\",\"agent_id\":\"$AGENT_ID\",\"host_id\":\"namespace-self-container\",\"gateway_addr\":\"$GATEWAY_IP:9444\",\"gateway_sni\":\"localhost\",\"channel\":\"$CHANNEL\",\"profile\":\"linux-container\",\"ttl\":\"1h\",\"labels\":{\"scenario\":\"$SCENARIO\"}}" >"$ENROLLMENT_JSON"
INSTALL_URL="$(json_value "$ENROLLMENT_JSON" install_url)"

docker rm -f "$OWNED_CONTAINER" >/dev/null 2>&1 || true

echo "[e2e-agent-namespace-self-container] starting owned privileged container"
docker run -d \
  --name "$OWNED_CONTAINER" \
  --entrypoint sh \
  --privileged \
  --cgroupns=host \
  --network "$NETWORK" \
  -v /sys/kernel/btf/vmlinux:/sys/kernel/btf/vmlinux:ro \
  -v /sys/fs/bpf:/sys/fs/bpf \
  "$TARGET_IMAGE" \
  -c 'tail -f /dev/null' >/dev/null

echo "[e2e-agent-namespace-self-container] installing agent from manager enrollment"
docker exec "$OWNED_CONTAINER" sh -c "rm -rf '$WORK'; mkdir -p '$WORK'"
if ! docker exec "$OWNED_CONTAINER" sh -c "curl -fsSL '$INSTALL_URL' | bash > '$WORK/install.log' 2>&1"; then
  docker exec "$OWNED_CONTAINER" cat "$WORK/install.log" > "$RESULTS/e2e-agent-namespace-self-container.install.log" 2>/dev/null || true
  echo "[e2e-agent-namespace-self-container][ERROR] agent install failed" >&2
  cat "$RESULTS/e2e-agent-namespace-self-container.install.log" >&2 2>/dev/null || true
  exit 1
fi

wait_contains() {
  local cmd_name="$1"
  local needle="$2"
  local out="$3"
  shift 3
  local deadline=$((SECONDS + 60))
  until "$@" >"$out" 2>"$out.err" && grep -Fq "$needle" "$out"; do
    if (( SECONDS >= deadline )); then
      echo "[e2e-agent-namespace-self-container][ERROR] timeout waiting for $needle via $cmd_name" >&2
      echo "--- last response ---" >&2
      cat "$out" >&2 2>/dev/null || true
      echo "--- last error ---" >&2
      cat "$out.err" >&2 2>/dev/null || true
      echo "--- agent log ---" >&2
      docker exec "$OWNED_CONTAINER" cat "$WORK/agent.log" >&2 2>/dev/null || true
      exit 1
    fi
    sleep 1
  done
}

docker exec "$OWNED_CONTAINER" sh -c "rm -f '$WORK/agent.log'; /opt/sysarmor/agent/bin/sysarmor-agent run --config /etc/sysarmor/agent/agent.yaml > '$WORK/agent.log' 2>&1 & echo \$! > '$WORK/agent.pid'"

wait_contains "agent-health backend" '"backend":"tetragon"' "$RESULTS/e2e-agent-namespace-self-container.health.json" \
  curl -sf "$MANAGER_URL/api/v1/agent-health?agent_id=$AGENT_ID&tenant_id=default"
wait_contains "agent-health scope" '"scope":{"type":"namespace","selector":"self"}' "$RESULTS/e2e-agent-namespace-self-container.health.json" \
  curl -sf "$MANAGER_URL/api/v1/agent-health?agent_id=$AGENT_ID&tenant_id=default"
wait_contains "agent-health policy" '"policyLoaded":true' "$RESULTS/e2e-agent-namespace-self-container.health.json" \
  curl -sf "$MANAGER_URL/api/v1/agent-health?agent_id=$AGENT_ID&tenant_id=default"
wait_contains "agent-owned tracing policy" 'sysarmor-runtime-collection' "$RESULTS/e2e-agent-namespace-self-container.tracingpolicy.txt" \
  docker exec "$OWNED_CONTAINER" /opt/sysarmor/agent/sensors/tetragon/current/bin/tetra tracingpolicy list
wait_contains "agent-owned tracing policy enabled" 'enabled' "$RESULTS/e2e-agent-namespace-self-container.tracingpolicy-loaded.txt" \
  docker exec "$OWNED_CONTAINER" /opt/sysarmor/agent/sensors/tetragon/current/bin/tetra tracingpolicy list

POSITIVE_MARKER="sysarmor-container-positive-$(date +%s%N)"
POSITIVE_CMD="/bin/sh -c 'id >/dev/null # $POSITIVE_MARKER'"
printf '%s\n' "$POSITIVE_CMD" > "$RESULTS/e2e-agent-namespace-self-container.positive-input.txt"
echo "[e2e-agent-namespace-self-container] positive container input: $POSITIVE_CMD"
wait_event_present "positive" "$POSITIVE_MARKER" "$POSITIVE_CMD" "id"

ECHO_POSITIVE_MARKER="sysarmor-container-echo-positive-$(date +%s%N)"
ECHO_POSITIVE_CMD="/bin/sh -c '/bin/echo $ECHO_POSITIVE_MARKER >/dev/null'"
printf '%s\n' "$ECHO_POSITIVE_CMD" > "$RESULTS/e2e-agent-namespace-self-container.echo-positive-input.txt"
echo "[e2e-agent-namespace-self-container] echo positive container input: $ECHO_POSITIVE_CMD"
wait_event_present "echo-positive" "$ECHO_POSITIVE_MARKER" "$ECHO_POSITIVE_CMD" "/bin/echo"

NEGATIVE_MARKER="sysarmor-host-negative-$(date +%s%N)"
NEGATIVE_CMD="/bin/sh -c '/bin/echo $NEGATIVE_MARKER >/dev/null'"
printf '%s\n' "$NEGATIVE_CMD" > "$RESULTS/e2e-agent-namespace-self-container.negative-input.txt"
echo "[e2e-agent-namespace-self-container] negative host input: $NEGATIVE_CMD"
sh -c "$NEGATIVE_CMD"
sleep 2
curl -sf "$MANAGER_URL/api/v1/events?label=scenario=$SCENARIO&behavior=process.exec&limit=200" \
  > "$RESULTS/e2e-agent-namespace-self-container.events-negative.json"
assert_event_absent "$RESULTS/e2e-agent-namespace-self-container.events-negative.json" "$AGENT_ID" "$SCENARIO" "$NEGATIVE_MARKER"
echo "--- negative events response ---"
cat "$RESULTS/e2e-agent-namespace-self-container.events-negative.json"

docker exec "$OWNED_CONTAINER" cat "$WORK/agent.log" > "$RESULTS/e2e-agent-namespace-self-container.agent.log"
docker exec "$OWNED_CONTAINER" cat "$WORK/install.log" > "$RESULTS/e2e-agent-namespace-self-container.install.log"

echo "[e2e-agent-namespace-self-container] ok"
