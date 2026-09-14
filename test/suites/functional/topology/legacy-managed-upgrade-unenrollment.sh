#!/usr/bin/env bash

LEGACY_AGENT_ID="vm-legacy-rc5"
LEGACY_SOURCE="v0.1.0-rc.5"
LEGACY_PREFIX="e2e-agent-systemd-vm.legacy"

legacy_refresh_manager_credentials() {
  MANAGER_JWT="$("$REPO/tools/auth/issue-manager-jwt.sh" \
    "$PKI_DIR/manager-jwt-private.pem" \
    sysarmor-bff \
    sysarmor-manager)"
  MANAGER_CTL="SYSARMOR_MANAGER_JWT='$MANAGER_JWT' /tmp/sysarmorctl"
}

legacy_install_agent() {
  local install_url="$1"
  if ! vagrant ssh node-a -c "sudo systemctl stop sysarmor-agent 2>/dev/null || true; sudo rm -rf /opt/sysarmor/agent /etc/sysarmor/agent /var/lib/sysarmor/agent /etc/systemd/system/sysarmor-agent.service; curl -fsSL '$install_url' | sudo bash" >/dev/null; then
    echo "[e2e-agent-systemd-vm] legacy install is still completing enrollment; waiting for issued state" >&2
  fi
}

legacy_create_and_install() {
  local enrollment_json="$RESULTS/$LEGACY_PREFIX.enrollment.json"
  vagrant ssh mgr -c "$MANAGER_CTL --manager-url http://10.66.0.10:9443 --json manager enrollments create --agent-id $LEGACY_AGENT_ID --host-id vm-node-a --gateway-addr 10.66.0.10:9444 --gateway-sni sysarmor-gateway.local --channel topology-test --ttl 1h --label suite=functional-topology --label upgrade=$LEGACY_SOURCE" >"$enrollment_json"
  LEGACY_ENROLLMENT_ID="$(python3 - "$enrollment_json" <<'PY'
import json, sys
print(json.load(open(sys.argv[1]))["enrollment"]["enrollment_id"])
PY
)"
  local install_url
  install_url="$(python3 - "$enrollment_json" <<'PY'
import json, sys
print(json.load(open(sys.argv[1]))["install_url"])
PY
)"
  legacy_install_agent "$install_url"
  vagrant ssh node-a -c "printf '\nmanager:\n  tls_insecure: true\n' | sudo tee -a /etc/sysarmor/agent/agent.yaml >/dev/null; sudo systemctl restart sysarmor-agent"
  wait_contains "legacy enrollment issued" "\"enrollment_id\":\"$LEGACY_ENROLLMENT_ID\"" "$RESULTS/$LEGACY_PREFIX.enrollments-issued.json" \
    vagrant ssh mgr -c "$MANAGER_CTL --manager-url 127.0.0.1:9443 --json manager enrollments list --tenant-id default --status issued"
  local health_before="$RESULTS/$LEGACY_PREFIX.health-before-upgrade.json"
  wait_contains "legacy health before upgrade" "\"agentId\":\"$LEGACY_AGENT_ID\"" "$health_before" \
    vagrant ssh mgr -c "$MANAGER_CTL --manager-url 127.0.0.1:9443 --json manager health get --agent-id $LEGACY_AGENT_ID --tenant-id default"
  LEGACY_HEALTH_OBSERVED_BEFORE="$(python3 - "$health_before" <<'PY'
import json, sys
print(json.load(open(sys.argv[1]))["observedAt"])
PY
)"
  vagrant ssh node-a -c "sudo systemctl stop sysarmor-agent"
}

legacy_read_certificate_serial() {
  LEGACY_CERT_SERIAL="$(python3 - "$RESULTS/$LEGACY_PREFIX.enrollments-issued.json" "$LEGACY_ENROLLMENT_ID" <<'PY'
import json, sys
items = json.load(open(sys.argv[1]))["enrollments"]
match = next((item for item in items if item.get("enrollment_id") == sys.argv[2]), None)
if not match or not str(match.get("issued_serial_number", "")).isdigit():
    raise SystemExit("legacy enrollment certificate serial is missing or invalid")
print(match["issued_serial_number"])
PY
)"
}

legacy_import_rc5_state() {
  local fixture="$ROOT/fixtures/agent/upgrades/v0.1.0-rc.5/agent-managed-v1.sql"
  vagrant upload "$fixture" /tmp/sysarmor-agent-managed-v1.sql node-a >/dev/null
  vagrant ssh node-a -c "sudo env LEGACY_AGENT_ID='$LEGACY_AGENT_ID' LEGACY_ENROLLMENT_ID='$LEGACY_ENROLLMENT_ID' python3 -" <<'PY'
import os
import pathlib
import sqlite3
import time

state = pathlib.Path("/var/lib/sysarmor/agent")
db_path = state / "agent.db"
for suffix in ("", "-shm", "-wal"):
    try:
        pathlib.Path(str(db_path) + suffix).unlink()
    except FileNotFoundError:
        pass
db = sqlite3.connect(db_path)
try:
    db.executescript(pathlib.Path("/tmp/sysarmor-agent-managed-v1.sql").read_text())
    enrollment_id = os.environ["LEGACY_ENROLLMENT_ID"]
    credential_root = state / "credentials" / enrollment_id
    db.execute(
        """UPDATE enrollment SET tenant_id='default', agent_id=?, gateway_address='10.66.0.10:9444',
        tls_ca_path=?, tls_cert_path=?, tls_key_path=?, tls_server_name='sysarmor-gateway.local', updated_at_ns=?
        WHERE singleton=1""",
        (
            os.environ["LEGACY_AGENT_ID"],
            str(credential_root / "ca.pem"),
            str(credential_root / "agent.pem"),
            str(credential_root / "agent-key.pem"),
            time.time_ns(),
        ),
    )
    db.execute(
        "UPDATE device_identity SET device_id=?, host_id='vm-node-a' WHERE singleton=1",
        ("rc5-" + os.environ["LEGACY_AGENT_ID"],),
    )
    db.commit()
finally:
    db.close()
os.chmod(db_path, 0o600)
PY
}

legacy_mark_manager_certificate() {
  local sql updated
  sql="WITH changed AS (UPDATE agent_certificates SET data=data-'unenrollment_protocol' WHERE tenant_id='default' AND serial_number=:'serial' RETURNING 1) SELECT count(*) FROM changed;"
  updated="$(printf '%s\n' "$sql" | vagrant ssh mgr -c "sudo docker exec -i sysarmor-postgres psql -qAt -v ON_ERROR_STOP=1 -v serial='$LEGACY_CERT_SERIAL' -U sysarmor -d sysarmor" | tr -d '\r')"
  if [[ "$updated" != "1" ]]; then
    echo "[e2e-agent-systemd-vm][ERROR] legacy certificate projection updated $updated rows, want 1" >&2
    exit 1
  fi
}

legacy_assert_migration() {
  vagrant ssh node-a -c "sudo systemctl start sysarmor-agent"
  wait_contains "legacy agent health" "\"agentId\":\"$LEGACY_AGENT_ID\"" "$RESULTS/$LEGACY_PREFIX.health.json" \
    health_is_ready_after "$LEGACY_HEALTH_OBSERVED_BEFORE" "$LEGACY_AGENT_ID"
  vagrant ssh node-a -c "sudo python3 -" >"$RESULTS/$LEGACY_PREFIX.migration.json" <<'PY'
import json
import sqlite3

db = sqlite3.connect("file:/var/lib/sysarmor/agent/agent.db?mode=ro", uri=True)
try:
    version = db.execute("SELECT version FROM schema_meta").fetchone()[0]
    state, protocol = db.execute(
        "SELECT state, unenrollment_protocol FROM enrollment WHERE singleton=1"
    ).fetchone()
    source = db.execute(
        "SELECT source FROM policy_activation WHERE kind='endpoint'"
    ).fetchone()[0]
finally:
    db.close()
result = {"schema_version": version, "state": state, "protocol": protocol, "policy_source": source}
print(json.dumps(result, sort_keys=True))
if result != {"schema_version": 5, "state": "managed", "protocol": "legacy_mtls", "policy_source": "managed"}:
    raise SystemExit("unexpected migrated rc.5 state: " + json.dumps(result, sort_keys=True))
PY
}

legacy_unenroll_and_restart() {
  vagrant ssh node-a -c "sudo /usr/local/bin/sysarmorctl --json unenroll --timeout 60s" >"$RESULTS/$LEGACY_PREFIX.unenroll.json"
  grep -Fq '"status":"applied"' "$RESULTS/$LEGACY_PREFIX.unenroll.json"
  wait_contains "manager legacy unenrollment" '"unenrollment_status":"unknown_legacy"' "$RESULTS/$LEGACY_PREFIX.enrollments-after.json" \
    vagrant ssh mgr -c "$MANAGER_CTL --manager-url 127.0.0.1:9443 --json manager enrollments list --tenant-id default --status issued"
  python3 - "$RESULTS/$LEGACY_PREFIX.enrollments-after.json" "$LEGACY_ENROLLMENT_ID" <<'PY'
import json, sys
items = json.load(open(sys.argv[1]))["enrollments"]
match = next((item for item in items if item.get("enrollment_id") == sys.argv[2]), None)
if not match or match.get("unenrollment_status") != "unknown_legacy" or match.get("endpoint_completed_at"):
    raise SystemExit("legacy Manager state is not fail-closed unknown_legacy")
PY
  wait_contains "standalone policy after legacy unenrollment" '"policyId":"standalone-default"' "$RESULTS/$LEGACY_PREFIX.policy.json" \
    vagrant ssh node-a -c "sudo /usr/local/bin/sysarmorctl --json policy current"
  if vagrant ssh node-a -c "sudo find /var/lib/sysarmor/agent/credentials -type f \( -name ca.pem -o -name agent.pem -o -name agent-key.pem \) -print -quit" | grep -q .; then
    echo "[e2e-agent-systemd-vm][ERROR] legacy managed enrollment credentials remain" >&2
    exit 1
  fi
  echo "[e2e-agent-systemd-vm] legacy managed enrollment credentials removed"
  vagrant ssh node-a -c "sudo systemctl restart sysarmor-agent"
  wait_contains "standalone policy after legacy unenrollment restart" '"policyId":"standalone-default"' "$RESULTS/$LEGACY_PREFIX.policy-after-restart.json" \
    vagrant ssh node-a -c "sudo /usr/local/bin/sysarmorctl --json policy current"
}

run_legacy_managed_upgrade_unenrollment() {
  : "${ROOT:?}" "${RESULTS:?}" "${ENVDIR:?}" "${REPO:?}" "${PKI_DIR:?}"
  echo "[e2e-agent-systemd-vm] verifying $LEGACY_SOURCE managed state upgrade unenrollment"
  legacy_refresh_manager_credentials
  legacy_create_and_install
  legacy_read_certificate_serial
  legacy_import_rc5_state
  legacy_mark_manager_certificate
  legacy_assert_migration
  legacy_unenroll_and_restart
  python3 - "$RESULTS/$LEGACY_PREFIX.summary.json" <<'PY'
import json, sys
result = {
    "legacy_fixture_source": "v0.1.0-rc.5",
    "legacy_schema_migrated": True,
    "legacy_mtls_unenrollment_applied": True,
    "manager_legacy_status_unknown": True,
    "legacy_standalone_after_restart": True,
}
open(sys.argv[1], "w").write(json.dumps(result, indent=2, sort_keys=True) + "\n")
PY
}
