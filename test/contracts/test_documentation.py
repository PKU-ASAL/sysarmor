import re
import unittest
from pathlib import Path


REQUIRED_PATHS = (
    "CONTRIBUTING.md",
    "docs/README.md",
    "docs/quickstart.md",
    "docs/design-principles.md",
    "docs/architecture.md",
    "docs/roadmap.md",
    "docs/concepts/security-data-model.md",
    "docs/guides/agent-management.md",
    "docs/guides/policy.md",
    "docs/guides/investigation.md",
    "docs/operations/deployment.md",
    "docs/operations/maintenance.md",
    "docs/reference/configuration.md",
    "docs/reference/api.md",
    "docs/reference/cli.md",
    "docs/development/testing.md",
)

RETIRED_PATHS = (
    "CATALOG.md",
    "docs/index.md",
    "docs/design-principles.zh-CN.md",
    "docs/development/development.md",
    "docs/development/debug.md",
    "docs/business",
    "docs/superpowers",
    "tools/docs",
    "test/suites/docs",
)

CANONICAL_PHRASES = (
    "Event 是事实",
    "Signal 是发现",
    "Evidence 是依据",
    "Incident 是安全分析报告",
    "Rule Candidate",
    "Rule Conclusion",
    "Model Candidate",
    "Graph Conclusion",
    "System Conclusion",
)

RETIRED_DETECTION_LANGUAGE = re.compile(
    r"terminal signal|terminal state|Learning Signal|Model Signal", re.IGNORECASE
)


class DocumentationContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.repo = Path(__file__).resolve().parents[2]

    def test_public_document_tree_is_canonical(self):
        missing = [path for path in REQUIRED_PATHS if not (self.repo / path).is_file()]
        retired = [path for path in RETIRED_PATHS if (self.repo / path).exists()]
        self.assertEqual([], missing, f"missing public documents: {missing}")
        self.assertEqual([], retired, f"retired documents remain: {retired}")

    def test_security_data_model_is_canonical(self):
        concepts = self.repo / "docs/concepts/security-data-model.md"
        self.assertTrue(concepts.is_file(), "missing canonical security data model")
        text = concepts.read_text()
        for phrase in CANONICAL_PHRASES:
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, text)
        self.assertIn("生产生成器尚未实现", text)

    def test_formal_sources_do_not_use_retired_detection_language(self):
        violations = []
        for source in self._detection_language_sources():
            if RETIRED_DETECTION_LANGUAGE.search(source.read_text(errors="ignore")):
                violations.append(str(source.relative_to(self.repo)))
        self.assertEqual([], violations, f"retired Detection language: {violations}")

    def test_formal_build_paths_do_not_depend_on_scratchpad_cache(self):
        sources = (
            "Makefile",
            "test/Makefile",
            "deployments/packages/build-release.sh",
            "test/suites/functional/topology/scenario-container.sh",
            "test/suites/functional/endpoint/e2e-namespace-self-container.sh",
            "docs/operations/deployment.md",
            "docs/development/testing.md",
        )
        violations = [
            path for path in sources if ".scratchpad/.cache" in (self.repo / path).read_text()
        ]
        self.assertEqual([], violations, f"scratchpad cache dependencies: {violations}")

    def test_public_markdown_links_resolve(self):
        broken = []
        for source in self._public_markdown_sources():
            for target in re.findall(r"(?<!!)\[[^]]+\]\(([^)]+)\)", source.read_text()):
                path = target.split("#", 1)[0]
                if not path or "://" in path or path.startswith("mailto:"):
                    continue
                if not (source.parent / path).resolve().exists():
                    broken.append(f"{source.relative_to(self.repo)} -> {target}")
        self.assertEqual([], broken, f"broken public document links: {broken}")

    def test_commercial_document_tooling_is_retired(self):
        makefile = (self.repo / "Makefile").read_text()
        for token in ("business-docx", "BUSINESS_DOCX_SOURCE", "BUSINESS_DOCX_OUTPUT"):
            with self.subTest(token=token):
                self.assertNotIn(token, makefile)

    def _detection_language_sources(self):
        sources = list(self._maintained_docs())
        sources.append(self.repo / "test/contracts/agent-test-coverage.tsv")
        sources.extend((self.repo / "test/suites/performance/learning").glob("*.py"))
        sources.append(self.repo / "test/environments/container/images/attacker/payloads/helper")
        return sources

    def _public_markdown_sources(self):
        sources = [
            self.repo / "README.md",
            self.repo / "README.zh-CN.md",
            self.repo / "CONTRIBUTING.md",
        ]
        sources.extend(self._maintained_docs())
        sources.extend((self.repo / "apps").glob("*/internal/*/README.md"))
        return sources

    def _maintained_docs(self):
        docs = self.repo / "docs"
        return [
            source
            for source in docs.rglob("*.md")
            if "superpowers" not in source.parts and "business" not in source.parts
        ]


if __name__ == "__main__":
    unittest.main()
