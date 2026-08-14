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
            "packages/sensor-sdk/contract",
            "packages/tlsconfig",
        )

        for path in expected:
            with self.subTest(path=path):
                self.assertTrue((self.repo / path).is_dir(), f"missing {path}")

    def test_task11_retires_agent_owned_shared_business_models(self):
        retired = ("packages/eventmodel", "packages/policy", "packages/response")
        for path in retired:
            with self.subTest(path=path):
                self.assertFalse(
                    (self.repo / path).exists(), f"retired package remains: {path}"
                )

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
            "apps/agent/internal/adapters/config",
            "apps/agent/internal/domain/content",
            "apps/agent/internal/bootstrap/runtime",
            "apps/agent/internal/domain/detection/runtime",
            "apps/agent/internal/domain/event",
            "apps/agent/internal/domain/policy",
            "apps/agent/internal/adapters/policy",
            "apps/agent/internal/adapters/sensor/tetragon",
            "apps/agent/internal/adapters/sqlite",
            "apps/agent/internal/adapters/sensor/fake",
            "apps/agent/internal/adapters/sensor/runtime",
        )

        for path in expected:
            with self.subTest(path=path):
                self.assertTrue((self.repo / path).is_dir(), f"missing {path}")

    def test_agent_data_pipeline_layout(self):
        root = self.repo / "apps/agent/internal"
        expected = (
            "domain/event",
            "domain/detection/compiler",
            "domain/detection/matcher",
            "domain/content",
            "application/content",
            "adapters/content",
            "adapters/contracts",
            "adapters/sensor/tetragon",
            "domain/detection/runtime",
            "adapters/telemetry/dataappend",
            "adapters/telemetry/ringbuffer",
        )
        for path in expected:
            with self.subTest(path=path):
                self.assertTrue((root / path).is_dir(), f"missing {path}")
        self.assertFalse((root / "endpoint").exists(), "legacy endpoint path remains")
        self.assertFalse((root / "telemetry").exists(), "legacy telemetry path remains")

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

    def test_manager_does_not_import_agent_implementation(self):
        manager = self.repo / "apps/manager"
        violations = []
        for source in manager.rglob("*.go"):
            if "github.com/sysarmor/sysarmor-next-project/apps/agent/" in source.read_text():
                violations.append(str(source.relative_to(self.repo)))
        self.assertEqual([], violations, f"manager imports agent implementation: {violations}")

    def test_manager_implementation_is_owned_by_manager_app(self):
        expected = (
            "apps/manager/internal/adapters/inbound/http/manager",
            "apps/manager/internal/adapters/inbound/http/auth",
        )

        for path in expected:
            with self.subTest(path=path):
                self.assertTrue((self.repo / path).is_dir(), f"missing {path}")

    def test_manager_store_facades_are_absent(self):
        for path in (
            "apps/manager/internal/store",
            "apps/manager/internal/store/backend",
            "apps/manager/internal/store/postgres",
            "apps/manager/internal/store/migrations",
        ):
            with self.subTest(path=path):
                self.assertFalse((self.repo / path).exists(), f"store facade remains: {path}")

    def test_tetragon_backend_responsibility_files(self):
        root = self.repo / "apps/agent/internal/adapters/sensor/tetragon"
        expected = (
            "capability.go",
            "tracing_policy.go",
            "tracing_policy_render.go",
            "runtime.go",
        )
        for name in expected:
            with self.subTest(name=name):
                self.assertTrue((root / name).is_file(), f"missing tetragon/{name}")

    def test_tetragon_adapter_files_are_bounded(self):
        root = self.repo / "apps/agent/internal/adapters/sensor/tetragon"
        oversized = [
            str(path.relative_to(self.repo))
            for path in root.glob("*.go")
            if len(path.read_text().splitlines()) > 500
        ]
        self.assertEqual([], oversized, f"oversized tetragon adapter files: {oversized}")

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
        root = self.repo / "apps/agent/internal/application/control"
        expected = ("types.go", "policy.go", "content.go")
        for name in expected:
            with self.subTest(name=name):
                self.assertTrue((root / name).is_file(), f"missing control/{name}")

    def test_agent_local_api_adapter_directory(self):
        root = self.repo / "apps/agent/internal"
        self.assertTrue((root / "adapters/inbound/unix").is_dir(), "missing agent Unix inbound adapter")

    def test_agent_local_api_uses_narrow_read_services(self):
        localapi = self.repo / "apps/agent/internal/adapters/inbound/unix"
        sources = "\n".join(path.read_text() for path in localapi.glob("*.go"))
        for declaration in ("type StatusService interface", "type TelemetryReader interface"):
            with self.subTest(declaration=declaration):
                self.assertIn(declaration, sources)
        for declaration in (r"\bStatus\s+StatusService\b", r"\bTelemetry\s+TelemetryReader\b"):
            with self.subTest(declaration=declaration):
                self.assertRegex(sources, declaration)
        self.assertNotIn("Legacy", sources)

    def test_agent_remote_api_adapter_directory(self):
        root = self.repo / "apps/agent/internal"
        self.assertTrue((root / "adapters/inbound/grpc").is_dir(), "missing agent gRPC inbound adapter")

    def test_agent_control_dependency_direction(self):
        root = self.repo / "apps/agent/internal"
        for source in (root / "application/control").rglob("*.go"):
            text = source.read_text()
            self.assertNotIn("internal/adapters/", text, f"{source} imports adapter")
            self.assertNotIn("packages/", text, f"{source} imports shared boundary model")

    def test_response_use_case_is_layered(self):
        root = self.repo / "apps/agent/internal"
        response = (root / "application/response/service.go").read_text()
        self.assertIn("func NewService", response)
        self.assertTrue((root / "domain/response/model.go").is_file())
        self.assertTrue((root / "ports/response.go").is_file())
        self.assertTrue((root / "adapters/response/enforcer.go").is_file())
        self.assertFalse((root / "control/response.go").exists())
        self.assertFalse((root / "daemon/response_controller.go").exists())

    def test_content_use_case_is_owned_by_control(self):
        root = self.repo / "apps/agent/internal"
        content = (root / "application/control/content.go").read_text()
        self.assertIn("func NewContentController", content)
        self.assertFalse((root / "daemon/content_controller.go").exists())
        self.assertFalse((root / "daemon/content_controller_runtime.go").exists())

    def test_enrollment_use_case_is_layered(self):
        root = self.repo / "apps/agent/internal"

        service = (root / "application/enrollment/service.go").read_text()
        self.assertIn("func NewService", service)
        self.assertTrue((root / "ports/enrollment.go").is_file())
        self.assertTrue((root / "adapters/enrollment/store.go").is_file())
        self.assertFalse((root / "control/enrollment.go").exists())
        self.assertFalse((root / "daemon/enrollment_controller.go").exists())
        self.assertFalse((root / "daemon/enrollment_coordinator.go").exists())

    def test_endpoint_policy_use_case_is_owned_by_control(self):
        root = self.repo / "apps/agent/internal"
        endpoint = (root / "application/control/endpoint_policy.go").read_text()
        self.assertIn("func NewEndpointPolicyController", endpoint)
        self.assertFalse((root / "daemon/endpoint_policy_control.go").exists())

    def test_policy_orchestration_is_owned_by_control(self):
        root = self.repo / "apps/agent/internal"
        controller = (root / "application/control/policy_controller.go").read_text()
        self.assertIn("func NewApplicationPolicyController", controller)
        self.assertFalse((root / "daemon/policy_controller.go").exists())
        self.assertFalse((root / "daemon/policy_controller_runtime.go").exists())

    def test_agent_runtime_does_not_own_local_api_watch_streams(self):
        runtime = self.repo / "apps/agent/internal/bootstrap/runtime"
        violations = []
        for source in runtime.glob("*.go"):
            if "AgentControlPlaneService_Watch" in source.read_text():
                violations.append(str(source.relative_to(self.repo)))
        self.assertEqual([], violations, f"runtime owns local API watch streams: {violations}")

    def test_agent_local_control_file_is_bounded(self):
        path = self.repo / "apps/agent/internal/bootstrap/runtime/local_control.go"
        self.assertLessEqual(len(path.read_text().splitlines()), 500)

    def test_agent_runtime_composition_root_is_bounded(self):
        path = self.repo / "apps/agent/internal/bootstrap/runtime/runtime.go"
        self.assertLessEqual(len(path.read_text().splitlines()), 500)

    def test_agent_runtime_tests_are_grouped_by_behavior(self):
        root = self.repo / "apps/agent/internal/bootstrap/runtime"
        expected = (
            "runtime_detection_test.go",
            "runtime_identity_test.go",
            "runtime_config_test.go",
            "runtime_telemetry_test.go",
            "runtime_transport_test.go",
            "runtime_sensor_test.go",
            "runtime_test_support_test.go",
        )
        for name in expected:
            with self.subTest(name=name):
                self.assertTrue((root / name).is_file(), f"missing runtime/{name}")

    def test_agent_local_control_tests_are_grouped_by_behavior(self):
        root = self.repo / "apps/agent/internal/bootstrap/runtime"
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
                self.assertTrue((root / name).is_file(), f"missing runtime/{name}")

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

    def test_platform_functional_path_does_not_reference_removed_manager_integration(self):
        script = self.repo / "test/suites/functional/platform/e2e-agent-gateway-manager-local.sh"
        content = script.read_text()
        self.assertNotIn("./apps/manager/integration", content)
        for package in (
            "./apps/manager/internal/application/gateway/...",
            "./apps/manager/internal/adapters/inbound/kafka",
            "./apps/manager/internal/application/worker/...",
            "./apps/manager/internal/adapters/outbound/opensearch/worker",
        ):
            self.assertIn(package, content)

        platform = self.repo / "test/suites/functional/platform"
        for functional_script in platform.glob("*.sh"):
            with self.subTest(script=functional_script.name):
                self.assertNotIn('"backend":"memory"', functional_script.read_text())

    def test_functional_paths_do_not_call_removed_manager_reset(self):
        functional = self.repo / "test/suites/functional"
        violations = []
        for script in functional.rglob("*.sh"):
            if "/api/v1/reset" in script.read_text():
                violations.append(script.relative_to(self.repo).as_posix())
        self.assertEqual([], violations, f"removed manager reset endpoint remains in: {violations}")


if __name__ == "__main__":
    unittest.main()
