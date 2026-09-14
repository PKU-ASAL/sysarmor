import hashlib
import json
import sqlite3
import unittest
from pathlib import Path


def rc5_fixture_dir():
    return (
        Path(__file__).resolve().parents[3]
        / "fixtures/agent/upgrades/v0.1.0-rc.5"
    )


class TopologyE2EContractTest(unittest.TestCase):
    def test_vm_topology_authenticates_manager_operations(self):
        script = (Path(__file__).resolve().parent / "e2e-systemd-vm.sh").read_text()

        self.assertIn(
            'tools/auth/issue-manager-jwt.sh" "$PKI_DIR/manager-jwt-private.pem" sysarmor-bff sysarmor-manager',
            script,
        )
        self.assertIn("Authorization: Bearer $MANAGER_JWT", script)
        self.assertIn(
            'MANAGER_CTL="SYSARMOR_MANAGER_JWT=\'$MANAGER_JWT\' /tmp/sysarmorctl"',
            script,
        )

    def test_vm_topology_asserts_issued_enrollment(self):
        script = (Path(__file__).resolve().parent / "e2e-systemd-vm.sh").read_text()

        self.assertIn("enrollments list --tenant-id default --status issued", script)
        self.assertNotIn("enrollments list --tenant-id default --status active", script)

    def test_vm_topology_seeds_published_default_policy_before_enrollment(self):
        script = (Path(__file__).resolve().parent / "e2e-systemd-vm.sh").read_text()

        policy_seed = script.index("sa_manager_seed_policy_history")
        enrollment = script.index("manager enrollments create")
        self.assertIn('source "$ROOT/shared/agent/managed_enrollment.sh"', script)
        self.assertLess(policy_seed, enrollment)

    def test_container_harness_initializes_content_signing_key(self):
        harness = (
            Path(__file__).resolve().parents[3] / "shared/harness/start-container.sh"
        ).read_text()

        self.assertIn(
            'openssl genpkey -algorithm ED25519 -out "$PKI_DIR/content-signing-key.pem"',
            harness,
        )

    def test_agent_packages_use_test_content_signing_key(self):
        suite_dir = Path(__file__).resolve().parent

        for name in ("e2e-systemd-vm.sh", "scenario-container.sh"):
            with self.subTest(script=name):
                script = (suite_dir / name).read_text()
                self.assertIn(
                    '--content-signing-key "$PKI_DIR/content-signing-key.pem"', script
                )
                self.assertIn("--content-key-id topology-test", script)

    def test_vm_topology_closes_managed_policy_rollout(self):
        script = (Path(__file__).resolve().parent / "e2e-systemd-vm.sh").read_text()

        self.assertIn("manager policies assign", script)
        self.assertIn("--downlink", script)
        self.assertIn("topology-rollout-policy", script)
        self.assertIn("/api/v1/policy-rollouts", script)
        self.assertIn("rollout-pending.json", script)
        self.assertIn("rollout-applied.json", script)
        self.assertIn("rollout-after-restart.json", script)

    def test_vm_topology_waits_for_sensor_policy_before_workload(self):
        script = (Path(__file__).resolve().parent / "e2e-systemd-vm.sh").read_text()

        self.assertIn(r'\"agentId\":\"$AGENT_ID\"', script)
        self.assertEqual(script.count(r'\"agent_id\":\"$AGENT_ID\"'), 1)
        self.assertIn('health_after.get("agentId") == agent_id', script)
        self.assertIn('"policyLoaded":true', script)
        self.assertIn("sudo /bin/true", script)
        self.assertIn("SYSARMOR_TOPOLOGY_WAIT_SECONDS:-120", script)

    def test_vm_topology_closes_online_unenrollment_and_restart(self):
        script = (Path(__file__).resolve().parent / "e2e-systemd-vm.sh").read_text()

        self.assertIn("sysarmorctl --json unenroll --timeout 60s", script)
        self.assertIn('"status":"applied"', script)
        self.assertIn("manager.tls_insecure", script)
        self.assertIn('"unenrollment_status":"endpoint_completed"', script)
        self.assertIn("e2e-agent-systemd-vm.enrollment-after-unenroll.json", script)
        self.assertIn('"policyId":"standalone-default"', script)
        self.assertIn("managed enrollment credentials removed", script)
        self.assertIn("standalone policy after unenrollment restart", script)

    def test_legacy_upgrade_uses_current_wire_health(self):
        script = (Path(__file__).resolve().parent / "legacy-managed-upgrade-unenrollment.sh").read_text()

        self.assertIn("legacy_install_agent", script)
        self.assertIn("legacy_refresh_manager_credentials", script)
        self.assertEqual(script.count(r'\"agentId\":\"$LEGACY_AGENT_ID\"'), 2)
        self.assertNotIn(r'\"agent_id\":\"$LEGACY_AGENT_ID\"', script)
        self.assertIn('"observedAt"]', script)

    def test_rc5_managed_fixture_is_authentic_schema_v1(self):
        root = rc5_fixture_dir()
        manifest_path = root / "manifest.json"
        self.assertTrue(manifest_path.exists(), f"missing rc.5 manifest: {manifest_path}")

        manifest = json.loads(manifest_path.read_text())
        fixture = root / manifest["fixture_file"]
        self.assertTrue(fixture.exists(), f"missing rc.5 fixture: {fixture}")
        raw = fixture.read_bytes()

        self.assertEqual(manifest["format"], "sysarmor.agent-upgrade-fixture/v1")
        self.assertEqual(manifest["source_tag"], "v0.1.0-rc.5")
        self.assertEqual(
            manifest["source_commit"],
            "454b69d6c01f778add5836e0af1c9ba3299fd5b1",
        )
        self.assertEqual(manifest["schema_version"], 1)
        self.assertEqual(hashlib.sha256(raw).hexdigest(), manifest["sha256"])

        db = sqlite3.connect(":memory:")
        self.addCleanup(db.close)
        db.executescript(raw.decode())
        self.assertEqual(db.execute("SELECT version FROM schema_meta").fetchone(), (1,))
        self.assertEqual(
            db.execute("SELECT state FROM enrollment WHERE singleton=1").fetchone(),
            ("managed",),
        )
        document, digest = db.execute(
            "SELECT document_json, digest FROM policy WHERE kind='endpoint'"
        ).fetchone()
        if isinstance(document, str):
            document = document.encode()
        self.assertEqual(hashlib.sha256(document).hexdigest(), digest)
        columns = {row[1] for row in db.execute("PRAGMA table_info(enrollment)")}
        new_fields = {
            "enrollment_id",
            "certificate_serial",
            "manager_url",
            "unenrollment_protocol",
        }
        self.assertTrue(new_fields.isdisjoint(columns))

    def test_vm_topology_verifies_rc5_managed_state_upgrade_unenrollment(self):
        suite = Path(__file__).resolve().parent
        main = (suite / "e2e-systemd-vm.sh").read_text()
        legacy_path = suite / "legacy-managed-upgrade-unenrollment.sh"
        self.assertTrue(legacy_path.exists(), f"missing legacy scenario: {legacy_path}")
        legacy = legacy_path.read_text()

        self.assertIn("legacy-managed-upgrade-unenrollment.sh", main)
        for marker in (
            "v0.1.0-rc.5",
            "legacy_mtls",
            "unknown_legacy",
            "managed enrollment credentials removed",
            "standalone policy after legacy unenrollment restart",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, legacy)
        self.assertIn("LEGACY_HEALTH_OBSERVED_BEFORE", legacy)
        self.assertIn(
            'health_is_ready_after "$LEGACY_HEALTH_OBSERVED_BEFORE" "$LEGACY_AGENT_ID"',
            legacy,
        )

    def test_legacy_certificate_projection_passes_sql_via_psql_stdin(self):
        suite = Path(__file__).resolve().parent
        legacy = (suite / "legacy-managed-upgrade-unenrollment.sh").read_text()

        self.assertIn("printf '%s\\n' \"$sql\" | vagrant ssh mgr", legacy)
        self.assertIn("docker exec -i sysarmor-postgres psql", legacy)

    def test_systemd_restart_waits_for_fresh_ready_sensor_health(self):
        suite = Path(__file__).resolve().parent
        main = (suite / "e2e-systemd-vm.sh").read_text()

        self.assertIn("health_is_ready_after", main)
        self.assertIn("parse_timestamp(health.get(\"observedAt\", \"\"))", main)
        self.assertIn('sensor.get("running") is not True', main)
        self.assertIn('sensor.get("policyLoaded") is not True', main)


if __name__ == "__main__":
    unittest.main()
