import unittest
from pathlib import Path


class MonorepoLayoutContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.repo = Path(__file__).resolve().parents[2]

    def test_executable_entrypoints_are_owned_by_apps(self):
        expected = (
            "apps/agent/cmd/sysarmor-agent",
            "apps/agent/cmd/sysarmor-content-sign",
            "apps/manager/cmd/sysarmor-manager",
            "apps/manager/cmd/sysarmor-gateway",
            "apps/manager/cmd/sysarmor-worker",
            "apps/cli/cmd/sysarmorctl",
        )

        for path in expected:
            with self.subTest(path=path):
                self.assertTrue((self.repo / path).is_dir(), f"missing {path}")

    def test_legacy_executable_entrypoints_are_absent(self):
        legacy = (
            "cmd/sysarmor-agent",
            "cmd/sysarmor-content-sign",
            "cmd/sysarmor-manager",
            "cmd/sysarmor-gateway",
            "cmd/sysarmor-worker",
            "cmd/sysarmorctl",
        )

        for path in legacy:
            with self.subTest(path=path):
                self.assertFalse((self.repo / path).exists(), f"legacy path remains: {path}")

    def test_shared_capabilities_are_owned_by_packages(self):
        expected = (
            "packages/contracts/proto",
            "packages/contracts/schema",
            "packages/contracts/controlmodel",
            "packages/contracts/health",
            "packages/eventmodel",
            "packages/policy",
            "packages/response",
            "packages/sensor-sdk/contract",
            "packages/tlsconfig",
        )

        for path in expected:
            with self.subTest(path=path):
                self.assertTrue((self.repo / path).is_dir(), f"missing {path}")

    def test_legacy_shared_capability_paths_are_absent(self):
        legacy = (
            "api/proto",
            "internal/contracts/schema",
            "internal/controlmodel",
            "internal/agent/health",
            "internal/eventmodel",
            "internal/policy",
            "internal/response",
            "internal/sensors/contract",
            "internal/tlsconfig",
        )

        for path in legacy:
            with self.subTest(path=path):
                self.assertFalse((self.repo / path).exists(), f"legacy path remains: {path}")

    def test_packages_do_not_import_apps(self):
        packages = self.repo / "packages"
        if not packages.exists():
            self.fail("missing packages directory")

        violations = []
        for source in packages.rglob("*.go"):
            if "github.com/sysarmor/sysarmor-next-project/apps/" in source.read_text():
                violations.append(str(source.relative_to(self.repo)))
        self.assertEqual([], violations, f"packages import apps: {violations}")

    def test_packages_governance_is_documented(self):
        readme = self.repo / "packages/README.md"
        self.assertTrue(readme.is_file())
        text = readme.read_text()
        for phrase in ("跨产品", "apps/", "稳定契约", "生命周期"):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, text)

    def test_agent_implementation_is_owned_by_agent_app(self):
        expected = (
            "apps/agent/internal/config",
            "apps/agent/internal/content",
            "apps/agent/internal/daemon",
            "apps/agent/internal/detection",
            "apps/agent/internal/event",
            "apps/agent/internal/localstore",
            "apps/agent/internal/policy",
            "apps/agent/internal/tamper",
            "apps/agent/internal/telemetry",
            "apps/agent/internal/sensors/fake",
            "apps/agent/internal/sensors/linux",
            "apps/agent/internal/sensors/runtime",
        )

        for path in expected:
            with self.subTest(path=path):
                self.assertTrue((self.repo / path).is_dir(), f"missing {path}")

    def test_agent_data_pipeline_layout(self):
        root = self.repo / "apps/agent/internal"
        expected = (
            "event/context",
            "event/normalize",
            "detection",
            "detection/matcher",
            "telemetry/dataappend",
            "telemetry/ringbuffer",
        )
        for path in expected:
            with self.subTest(path=path):
                self.assertTrue((root / path).is_dir(), f"missing {path}")
        self.assertFalse((root / "endpoint").exists(), "legacy endpoint path remains")

    def test_legacy_agent_implementation_paths_are_absent(self):
        legacy = (
            "internal/agent",
            "internal/endpoint",
            "internal/sensors/fake",
            "internal/sensors/linux",
            "internal/sensors/runtime",
        )

        for path in legacy:
            with self.subTest(path=path):
                self.assertFalse((self.repo / path).exists(), f"legacy path remains: {path}")

    def test_agent_does_not_import_manager_implementation(self):
        agent = self.repo / "apps/agent"
        violations = []
        for source in agent.rglob("*.go"):
            if "github.com/sysarmor/sysarmor-next-project/apps/manager/" in source.read_text():
                violations.append(str(source.relative_to(self.repo)))
        self.assertEqual([], violations, f"agent imports manager implementation: {violations}")

    def test_manager_implementation_is_owned_by_manager_app(self):
        expected = (
            "apps/manager/internal/api",
            "apps/manager/internal/auth",
            "apps/manager/internal/gateway",
            "apps/manager/internal/store",
            "apps/manager/internal/analytics",
            "apps/manager/internal/ingest",
            "apps/manager/internal/platform",
            "apps/manager/internal/distribution",
            "apps/manager/integration",
        )

        for path in expected:
            with self.subTest(path=path):
                self.assertTrue((self.repo / path).is_dir(), f"missing {path}")

    def test_manager_store_domain_files(self):
        root = self.repo / "apps/manager/internal/store"
        expected = (
            "models.go",
            "policy.go",
            "control.go",
            "enrollment.go",
            "artifact.go",
            "telemetry.go",
            "persistence.go",
        )
        for name in expected:
            with self.subTest(name=name):
                self.assertTrue((root / name).is_file(), f"missing store/{name}")

    def test_postgres_store_domain_files(self):
        root = self.repo / "apps/manager/internal/store/postgres"
        expected = (
            "policy.go",
            "control.go",
            "identity.go",
            "enrollment.go",
            "artifact.go",
            "telemetry.go",
        )
        for name in expected:
            with self.subTest(name=name):
                self.assertTrue((root / name).is_file(), f"missing postgres/{name}")

    def test_tetragon_backend_responsibility_files(self):
        root = self.repo / "apps/agent/internal/sensors/linux/tetragon"
        expected = (
            "capability.go",
            "tracing_policy.go",
            "tracing_policy_render.go",
            "runtime.go",
        )
        for name in expected:
            with self.subTest(name=name):
                self.assertTrue((root / name).is_file(), f"missing tetragon/{name}")

    def test_sysarmorctl_responsibility_files(self):
        root = self.repo / "apps/cli/cmd/sysarmorctl"
        expected = (
            "local.go",
            "payload.go",
            "manager.go",
            "manager_policy.go",
            "manager_control.go",
            "manager_artifact.go",
            "http.go",
        )
        for name in expected:
            with self.subTest(name=name):
                self.assertTrue((root / name).is_file(), f"missing sysarmorctl/{name}")

    def test_agent_control_contract_files(self):
        root = self.repo / "apps/agent/internal/control"
        expected = ("types.go", "policy.go", "content.go", "response.go", "enrollment.go")
        for name in expected:
            with self.subTest(name=name):
                self.assertTrue((root / name).is_file(), f"missing control/{name}")

    def test_agent_local_api_adapter_directory(self):
        root = self.repo / "apps/agent/internal"
        self.assertTrue((root / "localapi").is_dir(), "missing agent localapi")

    def test_agent_local_api_uses_narrow_read_services(self):
        localapi = self.repo / "apps/agent/internal/localapi"
        sources = "\n".join(path.read_text() for path in localapi.glob("*.go"))
        for declaration in (
            "type StatusService interface",
            "type TelemetryReader interface",
            "Status     StatusService",
            "Telemetry  TelemetryReader",
        ):
            with self.subTest(declaration=declaration):
                self.assertIn(declaration, sources)
        self.assertNotIn("Legacy", sources)

    def test_agent_remote_api_adapter_directory(self):
        root = self.repo / "apps/agent/internal"
        self.assertTrue((root / "remoteapi").is_dir(), "missing agent remoteapi")

    def test_agent_control_dependency_direction(self):
        root = self.repo / "apps/agent/internal"
        forbidden = {
            "control": ("localapi", "remoteapi"),
            "localapi": ("remoteapi",),
            "remoteapi": ("localapi",),
        }
        for owner, targets in forbidden.items():
            for source in (root / owner).rglob("*.go"):
                text = source.read_text()
                for target in targets:
                    path = f"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/{target}"
                    self.assertNotIn(path, text, f"{source} imports forbidden {target}")

    def test_response_use_case_is_owned_by_control(self):
        root = self.repo / "apps/agent/internal"
        response = (root / "control/response.go").read_text()
        self.assertIn("func NewResponseController", response)
        self.assertFalse((root / "daemon/response_controller.go").exists())

    def test_content_use_case_is_owned_by_control(self):
        root = self.repo / "apps/agent/internal"
        content = (root / "control/content.go").read_text()
        self.assertIn("func NewContentController", content)
        self.assertFalse((root / "daemon/content_controller.go").exists())
        self.assertFalse((root / "daemon/content_controller_runtime.go").exists())

    def test_enrollment_use_case_is_owned_by_control(self):
        root = self.repo / "apps/agent/internal"
        enrollment = (root / "control/enrollment.go").read_text()
        self.assertIn("func NewEnrollmentCoordinator", enrollment)
        self.assertFalse((root / "daemon/enrollment_controller.go").exists())
        self.assertFalse((root / "daemon/enrollment_coordinator.go").exists())

    def test_agent_daemon_does_not_own_local_api_watch_streams(self):
        daemon = self.repo / "apps/agent/internal/daemon"
        violations = []
        for source in daemon.glob("*.go"):
            if "AgentControlPlaneService_Watch" in source.read_text():
                violations.append(str(source.relative_to(self.repo)))
        self.assertEqual([], violations, f"daemon owns local API watch streams: {violations}")

    def test_agent_local_control_file_is_bounded(self):
        path = self.repo / "apps/agent/internal/daemon/local_control.go"
        self.assertLessEqual(len(path.read_text().splitlines()), 500)

    def test_agent_daemon_composition_root_is_bounded(self):
        path = self.repo / "apps/agent/internal/daemon/daemon.go"
        self.assertLessEqual(len(path.read_text().splitlines()), 500)

    def test_agent_daemon_tests_are_grouped_by_behavior(self):
        root = self.repo / "apps/agent/internal/daemon"
        expected = (
            "daemon_detection_test.go",
            "daemon_identity_test.go",
            "daemon_config_test.go",
            "daemon_telemetry_test.go",
            "daemon_transport_test.go",
            "daemon_sensor_test.go",
            "daemon_test_support_test.go",
        )
        for name in expected:
            with self.subTest(name=name):
                self.assertTrue((root / name).is_file(), f"missing daemon/{name}")

    def test_agent_local_control_tests_are_grouped_by_behavior(self):
        root = self.repo / "apps/agent/internal/daemon"
        expected = (
            "local_control_status_test.go",
            "local_control_policy_test.go",
            "local_control_content_test.go",
            "local_control_watch_test.go",
            "local_control_detection_test.go",
            "local_control_test_support_test.go",
        )
        for name in expected:
            with self.subTest(name=name):
                self.assertTrue((root / name).is_file(), f"missing daemon/{name}")

    def test_legacy_manager_implementation_paths_are_absent(self):
        legacy = (
            "internal/manager",
            "internal/gateway",
            "internal/store",
            "internal/analytics",
            "internal/workers/ingest",
            "internal/platform",
            "internal/distribution",
            "test/suites/functional/platform/agent_gateway_manager_test.go",
        )

        for path in legacy:
            with self.subTest(path=path):
                self.assertFalse((self.repo / path).exists(), f"legacy path remains: {path}")

    def test_manager_does_not_import_agent_implementation(self):
        manager = self.repo / "apps/manager"
        violations = []
        for source in manager.rglob("*.go"):
            if "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/" in source.read_text():
                violations.append(str(source.relative_to(self.repo)))
        self.assertEqual([], violations, f"manager imports agent implementation: {violations}")

    def test_console_is_owned_by_apps(self):
        self.assertTrue((self.repo / "apps/console").is_dir(), "missing apps/console")
        self.assertFalse((self.repo / "web/manager").exists(), "legacy path remains: web/manager")

    def test_legacy_product_roots_are_absent(self):
        for path in ("cmd", "api", "internal", "web"):
            with self.subTest(path=path):
                self.assertFalse((self.repo / path).exists(), f"legacy product root remains: {path}")

    def test_build_inputs_do_not_reference_legacy_command_paths(self):
        build_inputs = (
            "Makefile",
            ".github/workflows/release-build.yml",
            "test/shared/harness/lib/common.sh",
        )
        violations = []
        for path in build_inputs:
            content = (self.repo / path).read_text()
            if "./cmd/" in content or "$REPO_ROOT/cmd/" in content:
                violations.append(path)
        self.assertEqual([], violations, f"legacy command paths in build inputs: {violations}")


if __name__ == "__main__":
    unittest.main()
