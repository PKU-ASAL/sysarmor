import unittest
from pathlib import Path


RUN_SCRIPT = Path(__file__).with_name("run.sh")


class PerformancePlatformContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.script = RUN_SCRIPT.read_text()

    def test_detects_available_compose_command_before_status_collection(self):
        self.assertIn("compose_command", self.script)
        detect = self.script.index("compose_command")
        status = self.script.index("platform.compose.ps.txt")
        self.assertLess(detect, status)
        self.assertIn("sudo docker compose version", self.script[detect:status])
        self.assertIn("sudo docker-compose", self.script[detect:status])

    def test_fails_when_compose_status_cannot_be_collected(self):
        self.assertIn("platform.compose.ps.txt", self.script)
        self.assertIn("cd /opt/sysarmor/platform", self.script)
        self.assertIn("deployments/compose.platform.yaml", self.script)
        self.assertIn("deployments/compose.vm-topology.yaml", self.script)
        self.assertNotIn("ps --format json", self.script)
        self.assertNotIn('platform.compose.ps.txt" || true', self.script)

    def test_requires_core_platform_samples_and_running_services(self):
        for container in (
            "sysarmor-manager",
            "sysarmor-gateway",
            "sysarmor-worker",
            "sysarmor-postgres",
            "sysarmor-kafka",
        ):
            self.assertIn(container, self.script)
        self.assertIn("missing required platform samples", self.script)
        self.assertIn("validate_compose_status", self.script)
        self.assertIn("is not running", self.script)

    def test_uses_privileged_docker_introspection_in_vm(self):
        self.assertIn("sudo docker stats --no-stream", self.script)
        self.assertNotIn('vagrant ssh mgr -c "docker stats', self.script)

    def test_authenticates_manager_metrics_without_exposing_jwt_as_argument(self):
        self.assertIn("tools/auth/issue-manager-jwt.sh", self.script)
        self.assertIn("capture_manager_metrics", self.script)
        self.assertIn("printf '%s\\n' \"$MANAGER_JWT\" | vagrant ssh", self.script)
        self.assertIn("IFS= read -r SYSARMOR_MANAGER_JWT", self.script)
        self.assertIn("export SYSARMOR_MANAGER_JWT", self.script)
        self.assertEqual(self.script.count("capture_manager_metrics "), 2)

        metrics_commands = [
            line
            for line in self.script.splitlines()
            if "manager metrics" in line
        ]
        self.assertEqual(len(metrics_commands), 1)
        self.assertNotIn("$MANAGER_JWT", metrics_commands[0])


if __name__ == "__main__":
    unittest.main()
