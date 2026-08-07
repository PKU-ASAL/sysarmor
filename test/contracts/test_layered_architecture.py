import unittest
from pathlib import Path
import re


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
LEGACY_ROOTS = {
    "apps/agent/internal/daemon",
    "apps/manager/internal/store",
    "apps/manager/internal/api",
    "apps/manager/internal/gateway",
    "apps/manager/internal/ingest",
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
    if imported.startswith(MODULE):
        return False
    if "." in imported.split("/", 1)[0]:
        return owner in {"adapters", "bootstrap"}
    if owner in {"domain", "application", "ports"}:
        return imported not in {"database/sql", "net/http", "os", "os/exec", "syscall"}
    return True


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

    def test_inner_layers_reject_infrastructure_imports(self):
        forbidden = (
            f"{MODULE}apps/manager/internal/store",
            f"{MODULE}packages/policy",
            "github.com/segmentio/kafka-go",
            "net/http",
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
        for product in ("agent", "manager"):
            internal = self.repo / "apps" / product / "internal"
            for owner in LAYERS:
                for source in (internal / owner).rglob("*.go"):
                    for imported in IMPORT_PATTERN.findall(source.read_text()):
                        if not import_allowed(owner, imported, product):
                            relative = source.relative_to(self.repo)
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
