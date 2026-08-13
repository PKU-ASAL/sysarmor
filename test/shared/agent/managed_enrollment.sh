#!/usr/bin/env bash

sa_manager_seed_policy_history() {
  local repo="$1" env_dir="$2" pki_dir="$3" output_dir="$4"
  local manager_key="$pki_dir/manager-jwt-private.pem" manager_jwt policy_file policy_id detection_id
  [[ -f "$manager_key" ]] || { echo "[managed-enrollment][ERROR] missing manager JWT key: $manager_key" >&2; return 1; }
  manager_jwt="$($repo/tools/auth/issue-manager-jwt.sh "$manager_key" sysarmor-bff sysarmor-manager)"
  policy_file="$(mktemp)"
  mkdir -p "$output_dir"
  for policy_id in standalone-default default-edr-policy; do
    if [[ "$policy_id" == standalone-default ]]; then detection_id=standalone-default-detection; else detection_id=default-endpoint-detection; fi
    cat >"$policy_file" <<JSON
{"policy_id":"$policy_id","version":1,"tenant_id":"default","collection":{"behaviors":["process.exec","process.exit","process.fork","file.read","file.write","file.chmod","network.connect"],"observe_only":true},"detection":{"policy_id":"$detection_id","version":1,"mode":"observe","rulesets":[{"ref":"ruleset:cep-endpoint","version":"v1","enabled":true}]},"telemetry":{"max_batch_items":256,"max_batch_bytes":262144,"flush_interval":"1s"},"cloud_rules":["dropped_payload_executed_and_connects","web_shell_chain"],"mode":"observe","converge":{"mode":"rarity_structural","cross_lineage":true,"top_k":8,"max_path_hops":6},"response_policy":{"allowed_actions":["collect","noop"],"allowed_modes":["observe"]},"published":false}
JSON
    vagrant upload "$policy_file" "/tmp/sysarmor-$policy_id.json" mgr >/dev/null
    if ! printf '%s\n' "$manager_jwt" | vagrant ssh mgr -c "set -euo pipefail; umask 077; IFS= read -r jwt; cfg=\$(mktemp); trap 'rm -f \"\$cfg\"' EXIT; printf 'header = \"Authorization: Bearer %s\"\\n' \"\$jwt\" >\"\$cfg\"; curl -sf --config \"\$cfg\" -H 'Content-Type: application/json' -X POST http://127.0.0.1:9443/api/v1/policies --data-binary @/tmp/sysarmor-$policy_id.json" >"$output_dir/$policy_id.json"; then
      echo "[managed-enrollment][ERROR] seed policy failed: $policy_id" >&2
      cat "$output_dir/$policy_id.json" >&2 || true
      return 1
    fi
    if ! jq -e --arg policy_id "$policy_id" '.policy_id == $policy_id' "$output_dir/$policy_id.json" >/dev/null; then
      echo "[managed-enrollment][ERROR] seed policy response is invalid: $policy_id" >&2
      cat "$output_dir/$policy_id.json" >&2
      return 1
    fi
    printf '%s\n' "$manager_jwt" | vagrant ssh mgr -c "IFS= read -r SYSARMOR_MANAGER_JWT; export SYSARMOR_MANAGER_JWT; exec /tmp/sysarmorctl --manager-url 127.0.0.1:9443 --json manager policies publish --tenant-id default --policy-id '$policy_id' --version 1 --reason topology-policy-history" >"$output_dir/$policy_id-published.json"
  done
  rm -f "$policy_file"
}

_sa_wait_managed_health() {
  local env_dir="$1" socket="$2" health deadline
  deadline=$((SECONDS + 90))
  until health="$(vagrant ssh node-a -c "sudo sysarmorctl --socket '$socket' --json agent health" 2>/dev/null)" && \
    jq -e '.localStore.mode == "managed" or .managementLifecycle.mode == "managed"' <<<"$health" >/dev/null; do
    if (( SECONDS >= deadline )); then
      echo "[managed-enrollment][ERROR] timeout waiting for managed Agent health" >&2
      echo "$health" >&2
      exit 1
    fi
    sleep 1
  done
  echo "[managed-enrollment] Agent is managed"
}

sa_agent_enroll_managed_topology() (
  set -euo pipefail
  umask 077
  local repo="${1:?repo required}" env_dir="${2:?environment directory required}"
  local pki_dir="${3:?PKI directory required}" socket="${4:?Agent socket required}"
  local agent_id="${5:?Agent ID required}" manager_url="http://10.66.0.10:9443"
  local manager_key="$pki_dir/manager-jwt-private.pem" response_dir response manager_jwt token
  [[ -f "$manager_key" ]] || { echo "[managed-enrollment][ERROR] missing manager JWT key: $manager_key" >&2; exit 1; }
  [[ "$agent_id" =~ ^[A-Za-z0-9._:-]+$ && "$socket" =~ ^/[A-Za-z0-9._/-]+$ ]] || {
    echo "[managed-enrollment][ERROR] invalid Agent identity or socket path" >&2; exit 1;
  }
  response_dir="$(mktemp -d)"; response="$response_dir/enrollment.json"; chmod 700 "$response_dir"
  cleanup() { rm -rf "$response_dir"; (cd "$env_dir" && vagrant ssh node-a -c "sudo rm -f /run/sysarmor/benchmark-enrollment-token") >/dev/null 2>&1 || true; }
  trap cleanup EXIT
  manager_jwt="$("$repo/tools/auth/issue-manager-jwt.sh" "$manager_key" sysarmor-bff sysarmor-manager)"
  cd "$env_dir"
  sa_manager_seed_policy_history "$repo" "$env_dir" "$pki_dir" "${SYSARMOR_MANAGED_POLICY_HISTORY_DIR:-$env_dir/.results/managed-policy-history}"
  printf '%s\n' "$manager_jwt" | vagrant ssh mgr -c \
    "IFS= read -r SYSARMOR_MANAGER_JWT; export SYSARMOR_MANAGER_JWT; exec /tmp/sysarmorctl --manager-url 127.0.0.1:9443 --json manager enrollments create --agent-id '$agent_id' --host-id benchmark-node-a --gateway-addr 10.66.0.10:9444 --gateway-sni sysarmor-gateway.local --ttl 1h --label suite=detection-topology" >"$response"
  token="$(jq -r '.token // empty' "$response")"
  [[ -n "$token" ]] || { echo "[managed-enrollment][ERROR] manager response did not contain a token" >&2; exit 1; }
  printf '%s' "$token" | vagrant ssh node-a -c "sudo install -m 0600 /dev/stdin /run/sysarmor/benchmark-enrollment-token"
  vagrant ssh node-a -c "sudo sysarmorctl --socket '$socket' enroll --manager-url '$manager_url' --token-file /run/sysarmor/benchmark-enrollment-token --timeout 60s"
  _sa_wait_managed_health "$env_dir" "$socket"
)
