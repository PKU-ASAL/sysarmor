import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
REPO = ROOT.parent
DETECTION_RUNTIME = ROOT / "shared/detection/runtime.sh"
POLICY_RUNTIME = ROOT / "shared/agent/policy_runtime.sh"
ENDPOINT_RUNNER = ROOT / "suites/performance/endpoint/run.sh"
MANAGED_ENROLLMENT = ROOT / "shared/agent/managed_enrollment.sh"
MANAGED_POLICY = ROOT / "shared/agent/managed_policy.sh"
SYNC_AGENT = ROOT / "shared/vm/sync-agent.sh"
VM_TOPOLOGY = ROOT / "environments/vm-topology/Vagrantfile"


class RuntimeContractTest(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.temp = Path(self.temporary_directory.name)
        self.bin = self.temp / "bin"
        self.bin.mkdir()

    def test_managed_topology_manager_has_medium_profile_capacity(self):
        self.assertRegex(
            VM_TOPOLOGY.read_text(),
            r'name: "mgr"[^\n]+mem: (?:[6-9]\d{3}|\d{5,})',
        )

    def test_benchmark_receives_fresh_vm_environment(self):
        calls = self.temp / "bash.calls"
        self.write_executable(
            "bash",
            '#!/bin/bash\nprintf "fresh=%s run=%s args=%s\\n" '
            '"${SYSARMOR_BENCH_VM_FRESH:-}" "${SYSARMOR_BENCH_RUN_ID:-}" "$*" '
            f'>"{calls}"\n',
        )

        result = self.run_shell(
            f'source "{DETECTION_RUNTIME}"; '
            'run_endpoint_benchmark /runner run-1 policies variant optimized workload scenario vm-topology'
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls.read_text().strip(), "fresh=1 run=run-1 args=/runner")

    def test_managed_benchmark_rejects_reused_vm_without_explicit_override(self):
        script = ENDPOINT_RUNNER.read_text()
        self.assertIn('SYSARMOR_BENCH_REUSE_MANAGED:-0', script)
        self.assertIn('managed benchmark requires fresh VM/enrollment', script)

    def test_benchmark_receives_managed_agent_mode(self):
        calls = self.temp / "bash.calls"
        self.write_executable(
            "bash",
            '#!/bin/bash\nprintf "mode=%s\\n" "${SYSARMOR_BENCH_AGENT_MODE:-}" '
            f'>"{calls}"\n',
        )

        result = self.run_shell(
            f'source "{DETECTION_RUNTIME}"; '
            'run_endpoint_benchmark /runner run-1 policies variant optimized workload scenario vm-topology managed'
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls.read_text().strip(), "mode=managed")

    def test_manager_queries_send_jwt_only_through_stdin(self):
        calls = self.temp / "vagrant.calls"
        stdin = self.temp / "vagrant.stdin"
        self.write_executable(
            "vagrant",
            '#!/bin/bash\nprintf "%s\\n" "$*" '
            f'>>"{calls}"\nIFS= read -r token\nprintf "%s\\n" "$token" '
            f'>>"{stdin}"\nprintf "[]\\n"\n',
        )
        env = {"TEST_JWT": "header.payload.signature"}

        result = self.run_shell(
            f'source "{DETECTION_RUNTIME}"; '
            'for resource in events signals incidents; do '
            'capture_manager_resource "$TEST_JWT" . "$resource" "--label benchmark_run=run-1"; '
            'done',
            env,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn(env["TEST_JWT"], calls.read_text())
        self.assertEqual(stdin.read_text().splitlines(), [env["TEST_JWT"]] * 3)
        for resource in ("events", "signals", "incidents"):
            self.assertIn(f"manager {resource} list", calls.read_text())

    def test_managed_benchmark_has_explicit_enrollment_boundary(self):
        script = ENDPOINT_RUNNER.read_text()
        self.assertIn('AGENT_MODE="${SYSARMOR_BENCH_AGENT_MODE:-standalone}"', script)
        self.assertIn("enroll_managed_agent", script)
        self.assertIn('[[ "$AGENT_MODE" == "managed" ]]', script)
        self.assertIn('source "$ROOT/shared/agent/managed_enrollment.sh"', script)
        managed = MANAGED_ENROLLMENT.read_text()
        self.assertIn('.localStore.mode == "managed"', managed)
        self.assertIn("/run/sysarmor/benchmark-enrollment-token", managed)
        self.assertIn("sa_manager_seed_policy_history", managed)
        self.assertIn("standalone-default", managed)
        self.assertIn("default-edr-policy", managed)
        self.assertIn("standalone-default-detection", managed)
        self.assertIn("default-endpoint-detection", managed)

    def test_managed_benchmark_uses_manager_policy_authority(self):
        script = ENDPOINT_RUNNER.read_text()
        self.assertIn('source "$ROOT/shared/agent/managed_policy.sh"', script)
        self.assertIn("apply_managed_policy", script)
        self.assertIn('if [[ "$AGENT_MODE" == "managed" ]]', script)
        managed = MANAGED_POLICY.read_text()
        self.assertIn("manager policies publish", managed)
        self.assertIn("manager policies assign", managed)
        self.assertIn('remote_policy\\"\' EXIT', managed)

    def test_learning_model_path_is_resolved_before_changing_directory(self):
        script = ENDPOINT_RUNNER.read_text()
        resolve = 'LEARNING_MODEL="$(cd "$(dirname "$LEARNING_MODEL")" && pwd)/$(basename "$LEARNING_MODEL")"'
        self.assertIn(resolve, script)
        self.assertLess(script.index(resolve), script.index('cd "$ENVDIR"'))

    def test_managed_benchmark_captures_stream_incidents_per_policy(self):
        script = ENDPOINT_RUNNER.read_text()

        self.assertIn('source "$ROOT/shared/detection/runtime.sh"', script)
        self.assertIn('"agent_mode": "$AGENT_MODE"', script)
        self.assertIn('capture_managed_incidents "$policy_out" "$name"', script)
        self.assertIn('"managed_incidents": "managed-incidents.json"', script)
        self.assertIn('"managed-incidents.json"', script)

    def test_managed_benchmark_captures_stream_candidate_lifecycle_artifacts(self):
        script = ENDPOINT_RUNNER.read_text()

        self.assertIn('capture_managed_stream_artifacts "$policy_out" "$name"', script)
        self.assertIn('"managed_signals": "managed-signals.json"', script)
        self.assertIn('"manager_metrics": "manager-metrics.json"', script)
        self.assertIn('"stream_processing": "stream-processing.json"', script)

    def test_managed_candidate_timeout_captures_flink_and_kafka_diagnostics(self):
        script = ENDPOINT_RUNNER.read_text()

        self.assertIn("capture_stream_diagnostics", script)
        self.assertIn('stream-jobs.json', script)
        self.assertIn('stream-lag.txt', script)
        self.assertIn("kafka-consumer-groups.sh", script)

    def test_managed_benchmark_builds_stream_projection_artifact(self):
        script = ENDPOINT_RUNNER.read_text()

        self.assertIn("capture_final_candidate_lifecycle", script)
        self.assertIn("build_stream_processing_artifact", script)
        self.assertIn('stream_processing', script)
        self.assertIn('eventSequenceCutoff', script)
        self.assertNotIn('stream_processing FROM', script)
        self.assertNotIn('docker exec -i sysarmor-postgres psql', script)

    def test_managed_candidate_capture_waits_for_frozen_gateway_cohort(self):
        script = ENDPOINT_RUNNER.read_text()
        function = script.split("capture_managed_stream_artifacts() {", 1)[1].split("\n}", 1)[0]
        wait_function = script.split("wait_manager_candidate_cohort() {", 1)[1].split("\n}", 1)[0]

        self.assertIn("gatewayAccepted", function)
        self.assertIn("wait_manager_candidate_cohort", function)
        self.assertIn("CANDIDATE_COHORT_WAIT_SECONDS", function)
        self.assertIn('CANDIDATE_COHORT_WAIT_SECONDS="${SYSARMOR_BENCH_CANDIDATE_COHORT_WAIT_SECONDS:-900}"', script)
        self.assertIn("issue-manager-jwt.sh", wait_function)
        self.assertIn("while ((", wait_function)

    def test_stream_processing_artifact_contains_only_model_candidates(self):
        script = ENDPOINT_RUNNER.read_text()
        function = script.split("build_stream_processing_artifact() {", 1)[1].split("\n}", 1)[0]
        wait_function = script.split("wait_manager_candidate_cohort() {", 1)[1].split("\n}", 1)[0]

        self.assertIn('detector_kind', function)
        self.assertIn('DETECTOR_KIND_MODEL', function)
        self.assertIn("--offset", wait_function)

    def test_managed_benchmark_freezes_agent_candidate_cohort_with_one_health_read(self):
        script = ENDPOINT_RUNNER.read_text()
        function = script.split("capture_final_candidate_lifecycle() {", 1)[1].split("\n}", 1)[0]

        self.assertIn('created="$(jq -er', script)
        self.assertIn('experimentCreated', script)
        self.assertIn('eventSequenceCutoff', script)
        self.assertIn('latestEventSequence', script)
        self.assertEqual(function.count("agent health"), 1)
        self.assertNotIn("while ((", function)

    def test_rule_only_freezes_an_explicit_empty_candidate_cohort(self):
        script = ENDPOINT_RUNNER.read_text()
        function = script.split("capture_final_candidate_lifecycle() {", 1)[1].split("\n}", 1)[0]

        self.assertIn('[[ "$PROTECTION_MODE" == "rule-only" ]]', function)
        self.assertIn("acceptedUniqueDelta = 0", function)
        self.assertNotIn("gatewayAccepted =", function)
        self.assertIn("experimentCreated = 0", function)

    def test_managed_learning_quiesces_candidate_production_before_freeze(self):
        script = ENDPOINT_RUNNER.read_text()

        self.assertIn("quiesce_managed_candidate_production", script)
        self.assertIn("candidate-drain", script)
        self.assertIn("SYSARMOR_BENCH_PROTECTION_MODE=rule-only", script)
        self.assertLess(
            script.index('quiesce_managed_candidate_production "$policy_out" "$policy"'),
            script.index('capture_managed_stream_artifacts "$policy_out" "$name"'),
        )

    def test_managed_sync_installs_signed_benchmark_content(self):
        script = SYNC_AGENT.read_text()
        self.assertIn("SYSARMOR_VM_INCLUDE_BENCH_CONTENT", script)
        self.assertIn("/tmp/sysarmor-bench-content.upload", script)

    def test_learning_sync_requires_a_complete_enabled_configuration(self):
        script = SYNC_AGENT.read_text()
        self.assertIn("SYSARMOR_LEARNING_MODEL", script)
        self.assertIn("SYSARMOR_LEARNING_TRUST_KEYS", script)
        self.assertIn("learning:", script)
        self.assertIn("model_path:", script)

    def test_endpoint_runner_records_learning_provenance(self):
        script = ENDPOINT_RUNNER.read_text()
        self.assertIn("SYSARMOR_BENCH_LEARNING_MODEL", script)
        self.assertIn("SYSARMOR_BENCH_LEARNING_TRUST_KEYS", script)
        self.assertIn("learning_model", script)

    def test_endpoint_runner_captures_effective_policy_after_application(self):
        script = ENDPOINT_RUNNER.read_text()
        self.assertIn("capture_effective_policy", script)
        self.assertIn('> "$policy_out/current-policy.json"', script)
        self.assertIn("effective-policy.json", script)
        self.assertGreater(
            script.index('capture_effective_policy "$policy_out"'),
            script.index('apply_detection "$policy_out" "$name"'),
        )

    def test_managed_policy_uses_manager_without_local_policy_apply(self):
        calls = self.temp / "vagrant.calls"
        self.write_executable(
            "vagrant",
            '#!/bin/bash\nprintf "%s\\n" "$*" '
            f'>>"{calls}"\n'
            'if [[ "$*" == *"read -r"* ]]; then read -r token; fi\n'
            'if [[ "$*" == *"agent health"* ]]; then\n'
            '  printf \'{"policyId":"benchmark-balanced-linux-agent-a","policyVersion":"2"}\\n\'\n'
            'else\n  printf \'{}\\n\'\nfi\n',
        )
        repo = self.temp / "repo"
        auth = repo / "tools/auth"
        auth.mkdir(parents=True)
        issuer = auth / "issue-manager-jwt.sh"
        issuer.write_text("#!/bin/bash\nprintf 'test-jwt\\n'\n")
        issuer.chmod(0o755)
        pki = self.temp / "pki"
        pki.mkdir()
        (pki / "manager-jwt-private.pem").write_text("test")
        collection = self.temp / "collection.json"
        collection.write_text(
            json.dumps({"policy_id": "balanced-linux", "version": 2, "behaviors": []})
        )
        detection = self.temp / "detection.json"
        detection.write_text(json.dumps({"policy_id": "detection", "version": 1}))
        output = self.temp / "output"

        result = self.run_shell(
            f'source "{MANAGED_POLICY}"; '
            f'sa_agent_apply_managed_policy "{repo}" "{self.temp}" "{pki}" '
            f'"/agent.sock" agent-a "{collection}" "{detection}" "{output}"'
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        invocation = calls.read_text()
        self.assertIn("manager policies publish", invocation)
        self.assertIn("manager policies assign", invocation)
        self.assertIn("rm -f", invocation)
        self.assertNotIn("policy apply", invocation)

    def test_invalid_current_version_stops_before_upload(self):
        result, calls = self.run_policy_reset({"version": "01"}, {"version": "2"})

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("canonical uint64", result.stderr)
        self.assertNotIn("upload", calls)
        self.assertNotIn("policy apply", calls)

    def test_version_mismatch_fails_after_apply(self):
        result, calls = self.run_policy_reset({"version": "1"}, {"version": "3"})

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("upload", calls)
        self.assertIn("policy apply", calls)

    def run_policy_reset(self, current, applied):
        calls = self.temp / "vagrant.calls"
        count = self.temp / "current.count"
        self.write_executable(
            "vagrant",
            '#!/bin/bash\nprintf "%s\\n" "$*" '
            f'>>"{calls}"\n'
            'if [[ "$*" == *"policy current"* ]]; then\n'
            f'  n=$(<"{count}" 2>/dev/null || printf 0)\n'
            f'  printf "%s" "$((n + 1))" >"{count}"\n'
            '  if (( n == 0 )); then printf "%s\\n" "$CURRENT_JSON"; '
            'else printf "%s\\n" "$APPLIED_JSON"; fi\n'
            'elif [[ "$*" == *"policy apply"* ]]; then\n'
            '  printf \'{"status":"applied"}\\n\'\n'
            'fi\n',
        )
        policy_out = self.temp / "policy"
        policy_out.mkdir()
        env = {
            "CURRENT_JSON": json.dumps(current),
            "APPLIED_JSON": json.dumps(
                {"policyId": "standalone-default", **applied}
            ),
        }
        result = self.run_shell(
            f'ROOT="{ROOT}" REPO="{REPO}" AGENT_SOCK=/agent.sock '
            'AGENT_ID=agent TENANT_ID=tenant POLICY_SETTLE_SECONDS=0; '
            f'source "{POLICY_RUNTIME}"; reset_endpoint_policy "{policy_out}"',
            env,
        )
        return result, calls.read_text() if calls.exists() else ""

    def run_shell(self, command, extra_env=None):
        env = os.environ.copy()
        env.update(extra_env or {})
        env["PATH"] = f"{self.bin}:{env['PATH']}"
        return subprocess.run(
            ["/bin/bash", "-c", command],
            capture_output=True,
            text=True,
            env=env,
            check=False,
        )

    def write_executable(self, name, content):
        path = self.bin / name
        path.write_text(content)
        path.chmod(0o755)


if __name__ == "__main__":
    unittest.main()
