#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"

VERSION="dev"
OS_NAME="linux"
ARCH="amd64"
OUTPUT_DIR="$REPO/dist/release"
BASE_URL="http://packages"
CHANNELS="dev-agent linux-systemd-dev linux-container-dev"
AGENT_BIN="$REPO/dist/bin/sysarmor-agent"
CTL_BIN="$REPO/dist/bin/sysarmorctl"
TETRAGON_ARCHIVE=""
SIGNING_KEY="$REPO/deployments/pki/agent-plane-mtls/runtime/artifact-signing-key.pem"
PUBLIC_KEY="$REPO/deployments/pki/agent-plane-mtls/runtime/artifact-public.pem"
CONTENT_SIGNING_KEY="${SYSARMOR_CONTENT_SIGNING_KEY:-}"
CONTENT_KEY_ID="${SYSARMOR_CONTENT_KEY_ID:-sysarmor-release}"

usage() {
  cat <<EOF
usage: build-release.sh [--version VERSION] [--os OS] [--arch ARCH]
                        [--output-dir DIR] [--base-url URL]
                        [--channels "CHANNEL ..."] [--agent-bin FILE] [--ctl-bin FILE]
                        [--tetragon-archive FILE]
                        [--signing-key FILE] [--public-key FILE]
                        [--content-signing-key FILE] [--content-key-id ID]

Build a signed agent release package and package index.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) VERSION="$2"; shift 2 ;;
    --os) OS_NAME="$2"; shift 2 ;;
    --arch) ARCH="$2"; shift 2 ;;
    --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
    --base-url) BASE_URL="$2"; shift 2 ;;
    --channels) CHANNELS="$2"; shift 2 ;;
    --agent-bin) AGENT_BIN="$2"; shift 2 ;;
    --ctl-bin) CTL_BIN="$2"; shift 2 ;;
    --tetragon-archive) TETRAGON_ARCHIVE="$2"; shift 2 ;;
    --signing-key) SIGNING_KEY="$2"; shift 2 ;;
    --public-key) PUBLIC_KEY="$2"; shift 2 ;;
    --content-signing-key) CONTENT_SIGNING_KEY="$2"; shift 2 ;;
    --content-key-id) CONTENT_KEY_ID="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "[build-release][ERROR] unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ -z "$TETRAGON_ARCHIVE" && -f "$REPO/.cache/tetragon-v1.7.0-amd64.tar.gz" ]]; then
  TETRAGON_ARCHIVE="$REPO/.cache/tetragon-v1.7.0-amd64.tar.gz"
fi
if [[ -z "$TETRAGON_ARCHIVE" || ! -f "$TETRAGON_ARCHIVE" ]]; then
  echo "[build-release][ERROR] tetragon archive is required; set --tetragon-archive or cache tetragon-v1.7.0-amd64.tar.gz" >&2
  exit 1
fi

mkdir -p "$(dirname "$SIGNING_KEY")" "$OUTPUT_DIR"
if [[ ! -f "$SIGNING_KEY" || ! -f "$PUBLIC_KEY" ]]; then
  openssl genrsa -out "$SIGNING_KEY" 3072 >/dev/null 2>&1
  openssl rsa -in "$SIGNING_KEY" -pubout -out "$PUBLIC_KEY" >/dev/null 2>&1
  chmod 0600 "$SIGNING_KEY"
  chmod 0644 "$PUBLIC_KEY"
fi

package_file="sysarmor-agent-$OS_NAME-$ARCH-$VERSION.tar.gz"
package_path="$OUTPUT_DIR/$package_file"
"$REPO/deployments/agent/package-agent.sh" \
  --version "$VERSION" \
  --output "$package_path" \
  --agent-bin "$AGENT_BIN" \
  --ctl-bin "$CTL_BIN" \
  --tetragon-archive "$TETRAGON_ARCHIVE" \
  --content-signing-key "$CONTENT_SIGNING_KEY" \
  --content-key-id "$CONTENT_KEY_ID" \
  --signing-key "$SIGNING_KEY" >/dev/null

sha256="$(sha256sum "$package_path" | awk '{print $1}')"
size_bytes="$(stat -c '%s' "$package_path")"
artifact_id="release-sysarmor-agent-$OS_NAME-$ARCH-$VERSION"
download_url="${BASE_URL%/}/$package_file"

channel_json=""
for channel in $CHANNELS; do
  if [[ -z "$channel" ]]; then
    continue
  fi
  if [[ -n "$channel_json" ]]; then
    channel_json="$channel_json,"
  fi
  channel_json="$channel_json\"$channel\""
done

cat > "$OUTPUT_DIR/index.json" <<EOF
{
  "schema_version": "sysarmor.artifact.feed/v1",
  "artifacts": [
    {
      "artifact_id": "$artifact_id",
      "tenant_id": "default",
      "name": "sysarmor-agent",
      "kind": "agent",
      "version": "$VERSION",
      "os": "$OS_NAME",
      "arch": "$ARCH",
      "sha256": "$sha256",
      "size_bytes": $size_bytes,
      "status": "active",
      "download_url": "$download_url",
      "channels": [$channel_json]
    }
  ]
}
EOF

echo "$OUTPUT_DIR/index.json"
