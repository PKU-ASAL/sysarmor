#!/usr/bin/env bash

_sa_build_managed_policy() {
  local collection_file="$1" detection_file="$2" output_path="$3" agent_id="$4"
  python3 - "$collection_file" "$detection_file" "$output_path" "$agent_id" <<'PY'
import json
import pathlib
import re
import sys

collection_path, detection_path, output_path, agent_id = sys.argv[1:]
collection = json.loads(pathlib.Path(collection_path).read_text())
detection = json.loads(pathlib.Path(detection_path).read_text())
base_id = collection.get("policy_id", "benchmark")
if not re.fullmatch(r"[A-Za-z0-9._:-]+", base_id):
    raise SystemExit("invalid collection policy ID")
version = int(collection.get("version", 1))
policy_id = f"benchmark-{base_id}-{agent_id[:8]}"
document = {
    "policy_id": policy_id,
    "version": version,
    "tenant_id": "default",
    "collection": collection,
    "detection": detection,
    "telemetry": {
        "max_batch_items": 256,
        "max_batch_bytes": 262144,
        "flush_interval": "200ms",
    },
    "mode": "observe",
    "published": False,
}
pathlib.Path(output_path).write_text(json.dumps(document, separators=(",", ":")))
print(policy_id, version)
PY
}

_sa_wait_managed_policy() {
  local env_dir="$1" socket="$2" policy_id="$3" version="$4" output_dir="$5"
  local health deadline
  deadline=$((SECONDS + 120))
  until health="$(vagrant ssh node-a -c "sudo sysarmorctl --socket '$socket' --json agent health" 2>/dev/null)" && \
    jq -e --arg id "$policy_id" --arg version "$version" \
      '.policyId == $id and (.policyVersion | tostring) == $version' <<<"$health" >/dev/null; do
    if (( SECONDS >= deadline )); then
      echo "[managed-policy][ERROR] timeout waiting for managed policy $policy_id@$version" >&2
      echo "$health" >&2
      exit 1
    fi
    sleep 1
  done
  printf '%s\n' "$health" >"$output_dir/managed-policy-health.json"
}

sa_agent_apply_managed_policy() (
  set -euo pipefail
  umask 077
  local repo="${1:?repo required}" env_dir="${2:?environment directory required}"
  local pki_dir="${3:?PKI directory required}" socket="${4:?Agent socket required}"
  local agent_id="${5:?Agent ID required}" collection_file="${6:?collection policy required}"
  local detection_file="${7:?detection policy required}" output_dir="${8:?output directory required}"
  local manager_key="$pki_dir/manager-jwt-private.pem" temp_dir policy_file policy_id version manager_jwt remote_policy

  [[ -f "$manager_key" && -f "$collection_file" && -f "$detection_file" ]] || { echo "[managed-policy][ERROR] managed policy inputs are incomplete" >&2; exit 1; }
  [[ "$agent_id" =~ ^[A-Za-z0-9._:-]+$ && "$socket" =~ ^/[A-Za-z0-9._/-]+$ ]] || { echo "[managed-policy][ERROR] invalid Agent identity or socket path" >&2; exit 1; }
  temp_dir="$(mktemp -d)"; trap 'rm -rf "$temp_dir"' EXIT; policy_file="$temp_dir/policy.json"
  read -r policy_id version < <(_sa_build_managed_policy "$collection_file" "$detection_file" "$policy_file" "$agent_id")
  [[ "$policy_id" =~ ^[A-Za-z0-9._:-]+$ && "$version" =~ ^[0-9]+$ ]] || {
    echo "[managed-policy][ERROR] generated policy identity is invalid" >&2
    exit 1
  }
  remote_policy="/tmp/sysarmor-$policy_id.json"
  manager_jwt="$("$repo/tools/auth/issue-manager-jwt.sh" "$manager_key" sysarmor-bff sysarmor-manager)"
  mkdir -p "$output_dir"
  cd "$env_dir"
  vagrant upload "$policy_file" "$remote_policy" mgr >/dev/null
  printf '%s\n' "$manager_jwt" | vagrant ssh mgr -c \
    "set -euo pipefail; umask 077; IFS= read -r jwt; cfg=\$(mktemp); trap 'rm -f \"\$cfg\" \"$remote_policy\"' EXIT; printf 'header = \"Authorization: Bearer %s\"\\n' \"\$jwt\" >\"\$cfg\"; curl -sf --config \"\$cfg\" -H 'Content-Type: application/json' -X POST http://127.0.0.1:9443/api/v1/policies --data-binary '@$remote_policy'" \
    >"$output_dir/managed-policy-draft.json"
  printf '%s\n' "$manager_jwt" | vagrant ssh mgr -c \
    "IFS= read -r SYSARMOR_MANAGER_JWT; export SYSARMOR_MANAGER_JWT; exec /tmp/sysarmorctl --manager-url 127.0.0.1:9443 --json manager policies publish --tenant-id default --policy-id '$policy_id' --version '$version' --reason benchmark-managed-policy" \
    >"$output_dir/managed-policy-published.json"
  printf '%s\n' "$manager_jwt" | vagrant ssh mgr -c \
    "IFS= read -r SYSARMOR_MANAGER_JWT; export SYSARMOR_MANAGER_JWT; exec /tmp/sysarmorctl --manager-url 127.0.0.1:9443 --json manager policies assign --tenant-id default --agent '$agent_id' --policy-id '$policy_id' --version '$version' --downlink --command-id 'benchmark-$policy_id'" \
    >"$output_dir/managed-policy-assignment.json"

  _sa_wait_managed_policy "$env_dir" "$socket" "$policy_id" "$version" "$output_dir"
)
