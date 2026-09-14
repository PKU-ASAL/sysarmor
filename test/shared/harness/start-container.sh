#!/usr/bin/env bash
# 启动容器拓扑: compose up
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
REPO="$(cd "$ROOT/.." && pwd)"

echo ">>> 构建 SysArmor binaries"
make -C "$REPO" build-binary

RUNTIME_DIR="$ROOT/.results/container-runtime"
PKI_DIR="$RUNTIME_DIR/pki"

SYSARMOR_GATEWAY_IPS="10.66.0.14" \
  "$REPO/tools/pki/gen-agent-plane-mtls.sh" "$PKI_DIR" default bootstrap gateway >/dev/null
"$REPO/tools/auth/init-bootstrap-admin.sh" "$PKI_DIR" >/dev/null
if [[ ! -f "$PKI_DIR/artifact-signing-key.pem" ]]; then
  openssl genrsa -out "$PKI_DIR/artifact-signing-key.pem" 3072 >/dev/null 2>&1
  openssl rsa -in "$PKI_DIR/artifact-signing-key.pem" -pubout -out "$PKI_DIR/artifact-public.pem" >/dev/null 2>&1
  chmod 0600 "$PKI_DIR/artifact-signing-key.pem"
  chmod 0644 "$PKI_DIR/artifact-public.pem"
fi
if [[ ! -f "$PKI_DIR/content-signing-key.pem" ]]; then
  openssl genpkey -algorithm ED25519 -out "$PKI_DIR/content-signing-key.pem" >/dev/null 2>&1
  chmod 0600 "$PKI_DIR/content-signing-key.pem"
fi
prepare_runtime_image() {
  local name="$1"
  local binary="$2"
  local listen_cmd="$3"
  local dir="$RUNTIME_DIR/$name"

  mkdir -p "$dir"
  install -m 0755 "$REPO/dist/bin/$binary" "$dir/$binary"
  cat >"$dir/Dockerfile" <<EOF
FROM scratch
COPY $binary /usr/local/bin/$binary
ENTRYPOINT ["/usr/local/bin/$binary"]
$listen_cmd
EOF
}

prepare_runtime_image manager sysarmor-manager 'CMD ["--listen", "0.0.0.0:9443"]'
prepare_runtime_image gateway sysarmor-gateway 'CMD ["--listen", "0.0.0.0:9444", "--health-listen", "0.0.0.0:9445"]'
required_images=(apache/kafka:latest sysarmor-opensearch:latest)
for image in "${required_images[@]}"; do
  if ! docker image inspect "$image" >/dev/null 2>&1; then
    echo "[start-container][ERROR] required local Docker image missing: $image" >&2
    exit 1
  fi
done

cd "$ROOT/environments/container"
docker compose up -d --build --force-recreate postgres kafka redis opensearch mgr gateway
docker compose up -d --build --force-recreate attacker node-a

echo ">>> 等待 manager health"
manager_ready=0
for i in $(seq 1 20); do
  if docker exec node-a curl -sf http://mgr:9443/healthz >/dev/null; then
    manager_ready=1
    break
  fi
  sleep 1
done
if [[ "$manager_ready" != "1" ]]; then
  echo "[start-container][ERROR] manager health did not become ready" >&2
  docker logs mgr --tail 120 >&2 2>/dev/null || true
  exit 1
fi

echo ">>> 等待 gateway health"
gateway_ready=0
for i in $(seq 1 20); do
  if docker exec node-a curl -sf http://gateway:9445/healthz >/dev/null; then
    gateway_ready=1
    break
  fi
  sleep 1
done
if [[ "$gateway_ready" != "1" ]]; then
  echo "[start-container][ERROR] gateway health did not become ready" >&2
  docker logs gateway --tail 120 >&2 2>/dev/null || true
  exit 1
fi

echo ">>> 等待 opensearch health"
opensearch_ready=0
for i in $(seq 1 60); do
  if docker exec sysarmor-test-opensearch curl -sf http://127.0.0.1:9200 >/dev/null; then
    opensearch_ready=1
    break
  fi
  sleep 1
done
if [[ "$opensearch_ready" != "1" ]]; then
  echo "[start-container][ERROR] opensearch health did not become ready" >&2
  docker logs sysarmor-test-opensearch --tail 120 >&2 2>/dev/null || true
  exit 1
fi
docker exec sysarmor-test-opensearch curl -sf -X DELETE 'http://127.0.0.1:9200/sysarmor-events-v*,sysarmor-signals-v*,sysarmor-incidents-v*,sysarmor-evidence-v*' >/dev/null 2>&1 || true
docker compose run --rm opensearch-init >/dev/null

echo "[start-container] done"
