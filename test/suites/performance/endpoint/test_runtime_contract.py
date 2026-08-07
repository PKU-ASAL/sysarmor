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


class RuntimeContractTest(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.temp = Path(self.temporary_directory.name)
        self.bin = self.temp / "bin"
        self.bin.mkdir()

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
