#!/usr/bin/env bash
# Start a VM environment: vm-endpoint or vm-topology.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
REPO="$(cd "$ROOT/.." && pwd)"
ENV_NAME="${1:-${ENV:-vm-endpoint}}"
PKI_DIR="${SYSARMOR_VM_MTLS_DIR:-$ROOT/.results/pki/$ENV_NAME}"
VM_DEPLOY_DIR="${SYSARMOR_VM_DEPLOY_DIR:-$ROOT/environments/$ENV_NAME/deploy}"
PLATFORM_UPLOAD_DIR="${SYSARMOR_VM_PLATFORM_UPLOAD_DIR:-$VM_DEPLOY_DIR/platform}"
PLATFORM_IMAGES_DIR="${SYSARMOR_VM_PLATFORM_IMAGES_DIR:-$VM_DEPLOY_DIR/images}"
PLATFORM_SOURCE_BUNDLE="$VM_DEPLOY_DIR/platform.tar"
PLATFORM_IMAGE_BUNDLE="$PLATFORM_IMAGES_DIR/vm-images.tar"
PLATFORM_IMAGE_MANIFEST="$PLATFORM_IMAGES_DIR/images.manifest"
BUILD_BINARIES="${SYSARMOR_VM_BUILD_BINARIES:-1}"

ensure_image() {
  local image="$1"
  local mirror
  if docker image inspect "$image" >/dev/null 2>&1; then
    return
  fi
  mirror="${SYSARMOR_DOCKER_REGISTRY_MIRROR:-https://docker.1ms.run}"
  mirror="${mirror#https://}"
  mirror="${mirror#http://}"
  echo ">>> 通过 Docker registry mirror 拉取 $image"
  docker pull "${mirror%/}/$image"
  docker tag "${mirror%/}/$image" "$image"
}

case "$ENV_NAME" in
  vm-endpoint|vm-topology) ;;
  *) echo "[start-vm][ERROR] unsupported VM ENV=$ENV_NAME" >&2; exit 2 ;;
esac

if [[ "$BUILD_BINARIES" == "1" ]]; then
  echo ">>> 构建 SysArmor binaries"
  make -C "$REPO" build-binary
else
  echo ">>> 复用已构建 SysArmor binaries"
fi

cd "$ROOT/environments/$ENV_NAME"
vagrant up

if [[ "$ENV_NAME" == "vm-topology" ]]; then
  echo ">>> 生成 VM topology agent-plane mTLS 证书"
  SYSARMOR_GATEWAY_IPS="127.0.0.1,10.66.0.10" \
    "$REPO/tools/pki/gen-agent-plane-mtls.sh" "$PKI_DIR" default vm-owned-tetragon sysarmor-gateway.local >/dev/null
  "$REPO/tools/auth/init-bootstrap-admin.sh" "$PKI_DIR" >/dev/null
  if [[ ! -f "$PKI_DIR/artifact-signing-key.pem" || ! -f "$PKI_DIR/artifact-public.pem" ]]; then
    openssl genrsa -out "$PKI_DIR/artifact-signing-key.pem" 3072 >/dev/null 2>&1
    openssl rsa -in "$PKI_DIR/artifact-signing-key.pem" -pubout -out "$PKI_DIR/artifact-public.pem" >/dev/null 2>&1
    chmod 0600 "$PKI_DIR/artifact-signing-key.pem"
    chmod 0644 "$PKI_DIR/artifact-public.pem"
  fi
  if [[ ! -f "$PKI_DIR/content-signing-key.pem" ]]; then
    openssl genpkey -algorithm ED25519 -out "$PKI_DIR/content-signing-key.pem" >/dev/null 2>&1
    chmod 0600 "$PKI_DIR/content-signing-key.pem"
  fi

  echo ">>> 准备 VM topology deployment 源码包"
  mkdir -p "$PLATFORM_UPLOAD_DIR" "$PLATFORM_IMAGES_DIR"
  rsync -a --delete \
    --exclude '.agents/' \
    --exclude '.codex/' \
    --exclude '.git/' \
    --exclude '.vagrant/' \
    --exclude '.cache/' \
    --exclude '.run/' \
    --exclude '.scratchpad/' \
    --exclude '.superpowers/' \
    --exclude 'dist/' \
    --exclude 'test/.results/' \
    --exclude 'test/environments/vm-topology/deploy/' \
    --exclude 'third_party/references/code/' \
    "$REPO/" "$PLATFORM_UPLOAD_DIR/"
  mkdir -p \
    "$PLATFORM_UPLOAD_DIR/deployments/vm-build/manager" \
    "$PLATFORM_UPLOAD_DIR/deployments/vm-build/gateway" \
    "$PLATFORM_UPLOAD_DIR/deployments/vm-build"
  install -m 0755 "$REPO/dist/bin/sysarmor-manager" "$PLATFORM_UPLOAD_DIR/deployments/vm-build/manager/sysarmor-manager"
  install -m 0755 "$REPO/dist/bin/sysarmor-gateway" "$PLATFORM_UPLOAD_DIR/deployments/vm-build/gateway/sysarmor-gateway"
  mkdir -p "$PLATFORM_UPLOAD_DIR/deployments/pki/agent-plane-mtls/runtime"
  rsync -a --delete "$PKI_DIR/" "$PLATFORM_UPLOAD_DIR/deployments/pki/agent-plane-mtls/runtime/"
  tar -C "$PLATFORM_UPLOAD_DIR" -cf "$PLATFORM_SOURCE_BUNDLE" .
  required_images=(ubuntu:24.04 redis:7-alpine apache/kafka:latest opensearchproject/opensearch:2.14.0 nginx:alpine node:24-alpine rustfs/rustfs:1.0.0-alpha.84 flink:1.20.2-scala_2.12-java17 python:3.12-alpine)
  for image in "${required_images[@]}"; do
    ensure_image "$image"
  done
  docker compose -f "$REPO/deployments/compose.platform.yaml" build \
    postgres kafka redis opensearch manager manager-ui gateway
  docker build --network=host -t sysarmor-flink:1.20.2 -f "$REPO/deployments/streaming/Dockerfile" "$REPO"
  required_images+=(
    sysarmor-flink:1.20.2
    sysarmor-postgres:latest
    sysarmor-kafka:latest
    sysarmor-redis:latest
    sysarmor-opensearch:latest
    sysarmor-manager:latest
    sysarmor-manager-ui:latest
    sysarmor-gateway:latest
  )
  tmp_manifest="$PLATFORM_IMAGE_MANIFEST.tmp"
  : > "$tmp_manifest"
  for image in "${required_images[@]}"; do
    image_id="$(docker image inspect --format '{{.Id}}' "$image")"
    printf '%s %s\n' "$image" "$image_id" >> "$tmp_manifest"
  done
  if [[ ! -f "$PLATFORM_IMAGE_BUNDLE" ]] || [[ ! -f "$PLATFORM_IMAGE_MANIFEST" ]] || ! cmp -s "$tmp_manifest" "$PLATFORM_IMAGE_MANIFEST"; then
    echo ">>> 更新 VM topology image bundle"
    docker save -o "$PLATFORM_IMAGE_BUNDLE" "${required_images[@]}"
    mv "$tmp_manifest" "$PLATFORM_IMAGE_MANIFEST"
  else
    echo ">>> 复用 VM topology image bundle"
    rm -f "$tmp_manifest"
  fi

  echo ">>> 启动 VM topology platform services"
  if ! vagrant ssh mgr -c "command -v docker >/dev/null && (docker compose version >/dev/null 2>&1 || command -v docker-compose >/dev/null)" >/dev/null 2>&1; then
    vagrant provision mgr >/dev/null
  fi
  vagrant upload "$REPO/dist/bin/sysarmorctl" /tmp/sysarmorctl.upload mgr >/dev/null
  vagrant upload "$PLATFORM_SOURCE_BUNDLE" /tmp/sysarmor-platform.tar mgr >/dev/null
  vagrant upload "$PLATFORM_IMAGE_MANIFEST" /tmp/sysarmor-vm-images.manifest mgr >/dev/null
  image_upload=0
  if vagrant ssh mgr -c "test -f /opt/sysarmor/images/vm-images.tar && test -f /opt/sysarmor/images/images.manifest && cmp -s /tmp/sysarmor-vm-images.manifest /opt/sysarmor/images/images.manifest && sudo docker image inspect ubuntu:24.04 redis:7-alpine sysarmor-postgres:latest apache/kafka:latest sysarmor-opensearch:latest nginx:alpine node:24-alpine rustfs/rustfs:1.0.0-alpha.84 flink:1.20.2-scala_2.12-java17 python:3.12-alpine sysarmor-flink:1.20.2 sysarmor-kafka:latest sysarmor-redis:latest sysarmor-manager:latest sysarmor-manager-ui:latest sysarmor-gateway:latest >/dev/null" >/dev/null 2>&1; then
    echo ">>> 复用 mgr VM image bundle"
  else
    image_upload=1
    vagrant upload "$PLATFORM_IMAGE_BUNDLE" /tmp/sysarmor-vm-images.tar mgr >/dev/null
  fi
  vagrant ssh mgr -c "
set -euo pipefail
IMAGE_UPLOAD=$image_upload
sudo install -m 0755 /tmp/sysarmorctl.upload /tmp/sysarmorctl
sudo pkill -x sysarmor-manager 2>/dev/null || true
sudo pkill -x sysarmor-gateway 2>/dev/null || true
sudo rm -rf /tmp/sysarmor-platform.upload
sudo mkdir -p /tmp/sysarmor-platform.upload
sudo tar -xf /tmp/sysarmor-platform.tar -C /tmp/sysarmor-platform.upload
sudo rm -rf /opt/sysarmor/platform
sudo mkdir -p /opt/sysarmor /opt/sysarmor/images
sudo cp -a /tmp/sysarmor-platform.upload /opt/sysarmor/platform
if [ \"\$IMAGE_UPLOAD\" = '1' ]; then
  sudo install -m 0644 /tmp/sysarmor-vm-images.tar /opt/sysarmor/images/vm-images.tar
  sudo install -m 0644 /tmp/sysarmor-vm-images.manifest /opt/sysarmor/images/images.manifest
fi
cd /opt/sysarmor/platform
printf '%s\n' 'nameserver 1.1.1.1' 'nameserver 8.8.8.8' | sudo tee /etc/resolv.conf >/dev/null
sudo systemctl restart docker
if [ \"\$IMAGE_UPLOAD\" = '1' ]; then
  sudo docker load -i /opt/sysarmor/images/vm-images.tar >/tmp/sysarmor-docker-load.log 2>&1
else
  printf '%s\n' 'reused existing vm image bundle' >/tmp/sysarmor-docker-load.log
fi
if docker compose version >/dev/null 2>&1; then
  COMPOSE='docker compose'
else
  COMPOSE='docker-compose'
fi
sudo \$COMPOSE -f deployments/compose.platform.yaml -f deployments/compose.vm-topology.yaml down -v --remove-orphans >/tmp/sysarmor-compose-down.log 2>&1 || true
sudo \$COMPOSE -f deployments/compose.platform.yaml -f deployments/compose.vm-topology.yaml up -d --no-build >/tmp/sysarmor-compose-up.log 2>&1
" >/dev/null
  ready=0
  for _ in $(seq 1 120); do
    if vagrant ssh mgr -c "curl -sf http://127.0.0.1:9443/healthz >/dev/null && curl -sf http://127.0.0.1:9445/healthz | grep -F '\"mtls\":true' >/dev/null" >/dev/null 2>&1; then
      ready=1
      break
    fi
    sleep 1
  done
  if [[ "$ready" != "1" ]]; then
    echo "[start-vm][ERROR] manager/gateway health did not become ready" >&2
    vagrant ssh mgr -c "cat /tmp/sysarmor-docker-load.log 2>/dev/null || true" >&2 2>/dev/null || true
    vagrant ssh mgr -c "cat /tmp/sysarmor-compose-up.log 2>/dev/null || true" >&2 2>/dev/null || true
    vagrant ssh mgr -c "cd /opt/sysarmor/platform && if docker compose version >/dev/null 2>&1; then sudo docker compose -f deployments/compose.platform.yaml -f deployments/compose.vm-topology.yaml ps; else sudo docker-compose -f deployments/compose.platform.yaml -f deployments/compose.vm-topology.yaml ps; fi || true" >&2 2>/dev/null || true
    vagrant ssh mgr -c "sudo docker logs sysarmor-manager --tail 120 2>/dev/null || true" >&2 2>/dev/null || true
    vagrant ssh mgr -c "sudo docker logs sysarmor-gateway --tail 120 2>/dev/null || true" >&2 2>/dev/null || true
    exit 1
  fi
  flink_ready=0
  for _ in $(seq 1 120); do
    if vagrant ssh mgr -c "curl -sf http://127.0.0.1:18081/jobs/overview | python3 -c 'import json,sys; jobs=json.load(sys.stdin).get(\"jobs\", []); required={\"sysarmor-normalize-v1\",\"sysarmor-detection-v1\",\"sysarmor-projection-v1\"}; running={item.get(\"name\") for item in jobs if item.get(\"state\")==\"RUNNING\"}; raise SystemExit(0 if required <= running else 1)'" >/dev/null 2>&1; then
      flink_ready=1
      break
    fi
    sleep 1
  done
  if [[ "$flink_ready" != "1" ]]; then
    echo "[start-vm][ERROR] Flink jobs did not become RUNNING" >&2
    vagrant ssh mgr -c "curl -s http://127.0.0.1:18081/jobs/overview || true; sudo docker logs sysarmor-flink-jobmanager --tail 160 2>/dev/null || true" >&2 2>/dev/null || true
    exit 1
  fi
fi

echo "[start-vm] done ENV=$ENV_NAME"
