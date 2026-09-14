#!/usr/bin/env bash

reset_endpoint_policy() {
  local policy_out="$1"
  local baseline_version
  local applied_version
  local baseline_policy="$policy_out/baseline.policy.json"
  vagrant ssh node-a -c "sudo sysarmorctl --socket '$AGENT_SOCK' --json policy current" \
    > "$policy_out/baseline-before.json" \
    2>"$policy_out/baseline-before.err" || {
      echo "[performance-endpoint][ERROR] failed to read endpoint policy before baseline reset" >&2
      cat "$policy_out/baseline-before.err" >&2 2>/dev/null || true
      exit 1
    }
  baseline_version="$(
    python3 "$ROOT/shared/agent/monotonic_policy.py" \
      "$policy_out/baseline-before.json" \
      "$REPO/deployments/agent/policy.json" \
      "$baseline_policy"
  )" || {
    echo "[performance-endpoint][ERROR] failed to generate monotonic baseline endpoint policy" >&2
    cat "$policy_out/baseline-before.json" >&2 2>/dev/null || true
    exit 1
  }
  vagrant upload "$baseline_policy" /tmp/sysarmor-bench-baseline.policy node-a >/dev/null
  echo "[performance-endpoint] restoring baseline endpoint policy: requested=$baseline_version"
  vagrant ssh node-a -c "sudo sysarmorctl --socket '$AGENT_SOCK' --json policy apply --file /tmp/sysarmor-bench-baseline.policy --agent-id '$AGENT_ID' --tenant-id '$TENANT_ID' --timeout 60s" \
    > "$policy_out/baseline-apply.json" \
    2>"$policy_out/baseline-apply.err" || {
      echo "[performance-endpoint][ERROR] baseline endpoint policy apply failed" >&2
      cat "$policy_out/baseline-apply.err" >&2 2>/dev/null || true
      exit 1
    }
  if ! jq -e '.status == "applied" or .status == "degraded"' "$policy_out/baseline-apply.json" >/dev/null; then
    echo "[performance-endpoint][ERROR] baseline endpoint policy was rejected" >&2
    cat "$policy_out/baseline-apply.json" >&2 2>/dev/null || true
    exit 1
  fi
  vagrant ssh node-a -c "sudo sysarmorctl --socket '$AGENT_SOCK' --json policy current" \
    > "$policy_out/baseline-current.json" \
    2>"$policy_out/baseline-current.err" || {
      echo "[performance-endpoint][ERROR] failed to read current baseline endpoint policy" >&2
      cat "$policy_out/baseline-current.err" >&2 2>/dev/null || true
      exit 1
    }
  applied_version="$(jq -er '.version | strings' "$policy_out/baseline-current.json")" || {
    echo "[performance-endpoint][ERROR] current endpoint policy has an invalid version" >&2
    cat "$policy_out/baseline-current.json" >&2 2>/dev/null || true
    exit 1
  }
  if ! jq -e '.policyId == "standalone-default"' "$policy_out/baseline-current.json" >/dev/null || \
    [[ "$applied_version" != "$baseline_version" ]]; then
    echo "[performance-endpoint][ERROR] current endpoint policy does not match the baseline" >&2
    cat "$policy_out/baseline-current.json" >&2 2>/dev/null || true
    exit 1
  fi
  sleep "$POLICY_SETTLE_SECONDS"
}
