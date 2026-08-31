#!/usr/bin/env bash
# mgr VM: platform dependencies for deployment-shaped topology tests.
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

APT_MIRROR="${SYSARMOR_APT_MIRROR:-https://mirrors.edge.kernel.org/ubuntu}"
cat >/etc/apt/sources.list <<EOF
deb $APT_MIRROR jammy main restricted universe multiverse
EOF
cat >/etc/apt/apt.conf.d/99sysarmor-retry <<'EOF'
Acquire::ForceIPv4 "true";
Acquire::Retries "3";
Acquire::http::No-Cache "true";
Acquire::https::No-Cache "true";
EOF
apt-get clean
rm -rf /var/lib/apt/lists/*

apt_install() {
  local attempt
  for attempt in 1 2 3; do
    apt-get update -y
    if apt-get install -y "$@"; then
      return 0
    fi
    apt-get clean
    rm -rf /var/lib/apt/lists/*
    sleep 2
  done
  return 1
}

apt_install ca-certificates curl docker.io rsync

DOCKER_REGISTRY_MIRROR="${SYSARMOR_DOCKER_REGISTRY_MIRROR:-https://docker.1ms.run}"

rm -f /etc/resolv.conf
cat >/etc/resolv.conf <<'EOF'
nameserver 1.1.1.1
nameserver 8.8.8.8
EOF

mkdir -p /etc/docker
cat >/etc/docker/daemon.json <<EOF
{
  "dns": ["1.1.1.1", "8.8.8.8"],
  "registry-mirrors": ["$DOCKER_REGISTRY_MIRROR"]
}
EOF

systemctl enable docker >/dev/null
systemctl daemon-reload
systemctl restart docker.socket 2>/dev/null || true
systemctl restart docker

if ! docker compose version >/dev/null 2>&1 && ! command -v docker-compose >/dev/null 2>&1; then
  if apt-cache show docker-compose-plugin >/dev/null 2>&1; then
    apt_install docker-compose-plugin
  else
    apt_install docker-compose
  fi
fi

systemctl restart docker

echo "[platform] docker compose ready for sysarmor deployment stack"
