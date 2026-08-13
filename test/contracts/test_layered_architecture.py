import unittest
from pathlib import Path
import re
import json
import os
import subprocess


LAYERS = ("domain", "application", "ports", "adapters", "bootstrap")
MODULE = "github.com/sysarmor/sysarmor-next-project/"
ALLOWED = {
    "domain": {"domain"},
    "application": {"domain", "application", "ports"},
    "ports": {"domain", "ports"},
    "adapters": {"domain", "application", "ports", "adapters", "contracts"},
    "bootstrap": {
        "domain",
        "application",
        "ports",
        "adapters",
        "bootstrap",
        "contracts",
    },
}
AGENT_LEGACY_ROOTS = {
	"apps/agent/internal/config",
	"apps/agent/internal/control",
	"apps/agent/internal/daemon",
	"apps/agent/internal/localapi",
	"apps/agent/internal/localstore",
	"apps/agent/internal/remoteapi",
	"apps/agent/internal/sensors",
	"apps/agent/internal/tamper",
}
LEGACY_ROOTS = AGENT_LEGACY_ROOTS
STANDARD_LIBRARY = {
    "domain": {
        "crypto/sha256",
        "crypto/subtle",
        "bytes",
        "encoding/binary",
        "encoding/hex",
        "errors",
        "fmt",
        "math",
        "sort",
        "strconv",
        "strings",
        "path/filepath",
        "sync",
        "sync/atomic",
        "time",
    },
    "application": {"context", "errors", "fmt", "sort", "strings", "sync", "time"},
    "ports": {"context", "errors", "io", "time"},
}
ADAPTER_BRIDGE_IMPORTS = {
    f"{MODULE}apps/agent/internal/localstore",
    f"{MODULE}packages/policy",
    f"{MODULE}packages/response",
    f"{MODULE}packages/sensor-sdk/contract",
	f"{MODULE}packages/tlsconfig",
}
IMPORT_PATTERN = re.compile(r'^\s*(?:[._\w]+\s+)?"([^"]+)"', re.MULTILINE)


def target_layer(import_path, product):
    prefix = f"{MODULE}apps/{product}/internal/"
    if import_path.startswith(prefix):
        candidate = import_path.removeprefix(prefix).split("/", 1)[0]
        return candidate if candidate in LAYERS else None
    if import_path.startswith(f"{MODULE}packages/contracts/"):
        return "contracts"
    return None


def import_allowed(owner, imported, product):
    target = target_layer(imported, product)
    if target is not None:
        return target in ALLOWED[owner]
    if owner == "adapters" and imported in ADAPTER_BRIDGE_IMPORTS:
        return True
    if imported.startswith(MODULE):
        return False
    if "." in imported.split("/", 1)[0]:
        return owner in {"adapters", "bootstrap"}
    if owner in {"domain", "application", "ports"}:
        return imported in STANDARD_LIBRARY[owner]
    return True


def go_layered_packages(repo):
    result = subprocess.run(
        ["go", "list", "-mod=readonly", "-json", "./apps/agent/...", "./apps/manager/..."],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
        env={**os.environ, "GOCACHE": "/tmp/sysarmor-layered-go-cache"},
    )
    decoder = json.JSONDecoder()
    packages = []
    offset = 0
    while offset < len(result.stdout):
        while offset < len(result.stdout) and result.stdout[offset].isspace():
            offset += 1
        if offset == len(result.stdout):
            break
        package, offset = decoder.raw_decode(result.stdout, offset)
        packages.append(package)
    return packages


class LayeredArchitectureContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.repo = Path(__file__).resolve().parents[2]

    def test_product_layer_roots_exist(self):
        for product in ("agent", "manager"):
            for layer in LAYERS:
                path = self.repo / "apps" / product / "internal" / layer
                with self.subTest(product=product, layer=layer):
                    self.assertTrue(
                        path.is_dir(), f"missing {path.relative_to(self.repo)}"
                    )

    def test_legacy_exemptions_are_explicit_existing_roots(self):
        for relative in LEGACY_ROOTS:
            with self.subTest(relative=relative):
                self.assertTrue((self.repo / relative).is_dir())

    def test_agent_management_domain_is_layered(self):
        self.assertTrue(
            (self.repo / "apps/agent/internal/domain/management").is_dir()
        )
        self.assertFalse((self.repo / "apps/agent/internal/management").exists())

    def test_agent_event_domain_is_layered(self):
        self.assertTrue((self.repo / "apps/agent/internal/domain/event").is_dir())
        self.assertTrue(
            (self.repo / "apps/agent/internal/adapters/sensor/tetragon").is_dir()
        )
        self.assertFalse((self.repo / "apps/agent/internal/event").exists())

    def test_agent_sensor_adapter_does_not_forward_to_contract_adapter(self):
        source = (
            self.repo
            / "apps/agent/internal/adapters/sensor/tetragon/event_mapper.go"
        ).read_text()
        self.assertNotIn("internal/adapters/contracts", source)
        self.assertNotIn("packages/contracts/proto/event", source)

    def test_agent_policy_domain_is_layered(self):
        root = self.repo / "apps/agent/internal"
        self.assertTrue((root / "domain/policy").is_dir())
        self.assertTrue((root / "adapters/policy").is_dir())
        self.assertFalse((root / "policy").exists())
        for source in (root / "domain/policy").glob("*.go"):
            imports = IMPORT_PATTERN.findall(source.read_text())
            self.assertFalse(
                set(imports) & ADAPTER_BRIDGE_IMPORTS,
                f"policy domain imports adapter bridge: {source}",
            )

    def test_agent_content_activation_is_layered(self):
        root = self.repo / "apps/agent/internal"
        self.assertTrue((root / "domain/content").is_dir())
        self.assertTrue((root / "application/content").is_dir())
        self.assertTrue((root / "adapters/content").is_dir())
        self.assertFalse((root / "content").exists())

    def test_content_activation_contract_is_typed(self):
        for relative in ("apps/agent/internal/ports/content.go", "apps/agent/internal/application/content/activate.go"):
            source = (self.repo / relative).read_text()
            self.assertNotIn("any", source, f"untyped content contract remains: {relative}")

    def test_policy_application_contract_is_typed_and_inner(self):
        root = self.repo / "apps/agent/internal/application/policy"
        self.assertTrue(root.is_dir())
        for source in root.glob("*.go"):
            text = source.read_text()
            self.assertNotIn("packages/policy", text)
            self.assertNotIn("sensor-sdk/contract", text)
            self.assertNotIn("internal/adapters/", text)
            self.assertNotIn("any", text)

    def test_policy_application_uses_typed_services_only(self):
        root = self.repo / "apps/agent/internal/application/policy"
        self.assertFalse((root / "activate.go").exists())
        self.assertFalse((root / "activate_test.go").exists())
        self.assertTrue((root / "source.go").exists())
        for name in ("endpoint", "collection", "detection", "telemetry"):
            source = (root / f"{name}.go").read_text()
            self.assertIn(f"type {name.title()}Service struct", source)

    def test_policy_control_has_no_runtime_facades(self):
        root = self.repo / "apps/agent/internal"
        legacy_types = (
            "EndpointPolicyRuntime",
            "CollectionPolicyRuntime",
            "DetectionPolicyRuntime",
            "TelemetryPolicyRuntime",
        )
        for source in (root / "control").glob("*_policy.go"):
            text = source.read_text()
            for symbol in legacy_types:
                self.assertNotIn(symbol, text, f"legacy facade remains: {source}")
        for name in ("endpoint", "collection", "detection", "telemetry"):
            self.assertFalse((root / "daemon" / f"{name}_policy_runtime.go").exists())

    def test_migrated_policy_controls_do_not_import_infrastructure(self):
        root = self.repo / "apps/agent/internal/control"
        forbidden = ("internal/adapters/", "sensor-sdk/contract", "packages/policy")
        for name in ("endpoint", "collection", "detection", "telemetry"):
            source = (root / f"{name}_policy.go").read_text()
            for import_path in forbidden:
                self.assertNotIn(import_path, source, f"infrastructure import remains: {source}")

    def test_agent_detection_matcher_is_layered(self):
        root = self.repo / "apps/agent/internal"
        self.assertTrue((root / "domain/detection/matcher").is_dir())
        self.assertFalse((root / "detection/matcher").exists())

    def test_agent_detection_compiler_is_layered(self):
        root = self.repo / "apps/agent/internal"
        self.assertTrue((root / "domain/detection/compiler").is_dir())
        self.assertFalse((root / "detection/validation.go").exists())

    def test_agent_detection_signal_contract_is_layered(self):
        root = self.repo / "apps/agent/internal"
        self.assertTrue((root / "domain/detection/signal.go").is_file())
        self.assertTrue((root / "adapters/contracts/detection.go").is_file())
        for name in ("correlate.go", "evidence_entities.go"):
            source = (root / "domain/detection/runtime" / name).read_text()
            self.assertNotIn("packages/contracts/proto/signal", source)

    def test_agent_detection_runtime_uses_domain_events(self):
        root = self.repo / "apps/agent/internal/domain/detection/runtime"
        for source in root.glob("*.go"):
            if source.name.endswith("_test.go"):
                continue
            self.assertNotIn("packages/contracts/proto/event", source.read_text())

    def test_all_unlayered_roots_are_explicit_legacy(self):
        ungoverned = []
        for product in ("agent", "manager"):
            internal = self.repo / "apps" / product / "internal"
            for path in internal.iterdir():
                relative = str(path.relative_to(self.repo))
                if path.is_dir() and path.name not in LAYERS and relative not in LEGACY_ROOTS:
                    ungoverned.append(relative)
        self.assertEqual([], ungoverned, f"ungoverned internal roots: {ungoverned}")

    def test_inner_layers_reject_infrastructure_imports(self):
        forbidden = (
            f"{MODULE}apps/manager/internal/store",
            f"{MODULE}packages/policy",
            "github.com/segmentio/kafka-go",
            "net/http",
            "flag",
        )
        for imported in forbidden:
            with self.subTest(imported=imported):
                self.assertFalse(import_allowed("domain", imported, "manager"))

    def test_outer_layers_allow_technical_dependencies(self):
        self.assertTrue(import_allowed("adapters", "github.com/segmentio/kafka-go", "manager"))

    def test_go_import_syntax_is_parsed(self):
        source = '''
package sample

import "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
import (
    alias "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
    _ "github.com/segmentio/kafka-go"
)
'''
        self.assertEqual(
            [
                f"{MODULE}apps/manager/internal/domain/tenant",
                f"{MODULE}apps/manager/internal/ports",
                "github.com/segmentio/kafka-go",
            ],
            IMPORT_PATTERN.findall(source),
        )

    def test_layered_packages_obey_dependency_matrix(self):
        violations = []
        for package in go_layered_packages(self.repo):
            relative = Path(package["Dir"]).relative_to(self.repo)
            parts = relative.parts
            if len(parts) < 5 or parts[0] != "apps" or parts[2] != "internal":
                continue
            product, owner = parts[1], parts[3]
            if owner not in LAYERS:
                continue
            for imported in package.get("Imports", []):
                if not import_allowed(owner, imported, product):
                    violations.append(f"{relative}: {owner} imports {imported}")
        self.assertEqual([], violations, "forbidden layered imports:\n" + "\n".join(violations))

    def test_products_do_not_import_each_others_internals(self):
        violations = []
        for product, other in (("agent", "manager"), ("manager", "agent")):
            forbidden = f"{MODULE}apps/{other}/internal/"
            for source in (self.repo / "apps" / product).rglob("*.go"):
                if forbidden in source.read_text():
                    violations.append(str(source.relative_to(self.repo)))
        self.assertEqual([], violations, f"cross-product internal imports: {violations}")

    def test_manager_commands_depend_on_bootstrap_only(self):
        violations = []
        for command in ("sysarmor-manager", "sysarmor-gateway", "sysarmor-worker"):
            source = self.repo / "apps" / "manager" / "cmd" / command / "main.go"
            for imported in IMPORT_PATTERN.findall(source.read_text()):
                if imported == f"{MODULE}apps/manager/internal/bootstrap":
                    continue
                if imported.startswith(MODULE):
                    violations.append(f"{command}: {imported}")
                elif "." in imported.split("/", 1)[0]:
                    violations.append(f"{command}: {imported}")
        self.assertEqual([], violations, "command bypasses bootstrap:\n" + "\n".join(violations))

    def test_agent_commands_depend_on_bootstrap_only(self):
        violations = []
        for command in ("sysarmor-agent", "sysarmor-content-sign"):
            source = self.repo / "apps" / "agent" / "cmd" / command / "main.go"
            for imported in IMPORT_PATTERN.findall(source.read_text()):
                if imported == f"{MODULE}apps/agent/internal/bootstrap":
                    continue
                if imported.startswith(MODULE):
                    violations.append(f"{command}: {imported}")
                elif "." in imported.split("/", 1)[0]:
                    violations.append(f"{command}: {imported}")
        self.assertEqual([], violations, "command bypasses bootstrap:\n" + "\n".join(violations))

    def test_agent_daemon_does_not_own_policy_assembly(self):
        daemon = self.repo / "apps" / "agent" / "internal" / "daemon"
        self.assertFalse((daemon / "policy_assembly.go").exists())
        violations = []
        for source in daemon.glob("*.go"):
            if source.name.endswith("_test.go"):
                continue
            if "newApplicationPolicyController" in source.read_text():
                violations.append(str(source.relative_to(self.repo)))
        self.assertEqual([], violations, f"daemon owns policy assembly: {violations}")

    def test_agent_daemon_does_not_own_telemetry_delivery(self):
        daemon = self.repo / "apps" / "agent" / "internal" / "daemon"
        for retired in ("export_pipeline.go", "exporter.go"):
            with self.subTest(retired=retired):
                self.assertFalse((daemon / retired).exists())
        network = (daemon / "network_runtime.go").read_text()
        self.assertIn("applicationtelemetry.NewDelivery", network)
        self.assertNotIn("exportPipeline", network)

    def test_agent_endpoint_runtime_uses_pipeline_application(self):
        source = (
            self.repo / "apps" / "agent" / "internal" / "daemon" / "endpoint_runtime.go"
        ).read_text()
        self.assertIn("applicationpipeline.New", source)
        self.assertIn("pipeline.Process", source)
        self.assertNotIn("currentDetection().Process", source)
        self.assertNotIn("domainEvent.Labels = mergeLabels", source)

    def test_domain_does_not_import_protobuf(self):
        forbidden = f"{MODULE}packages/contracts/proto"
        violations = []
        for product in ("agent", "manager"):
            domain = self.repo / "apps" / product / "internal" / "domain"
            for source in domain.rglob("*.go"):
                if forbidden in source.read_text():
                    violations.append(str(source.relative_to(self.repo)))
        self.assertEqual([], violations, f"domain imports protobuf: {violations}")

    def test_architecture_contract_is_wired_into_make(self):
        makefile = (self.repo / "test" / "Makefile").read_text()
        self.assertIn("test-layered-architecture:", makefile)

    def test_architecture_contract_is_wired_into_ci(self):
        workflow = self.repo / ".github" / "workflows" / "architecture.yml"
        self.assertTrue(workflow.is_file(), "missing .github/workflows/architecture.yml")

    def test_layer_governance_links_resolve(self):
        for product in ("agent", "manager"):
            for layer in LAYERS:
                readme = self.repo / "apps" / product / "internal" / layer / "README.md"
                relative = re.search(r"\]\(([^)]+)\)", readme.read_text()).group(1)
                with self.subTest(product=product, layer=layer):
                    self.assertTrue((readme.parent / relative).is_file())
