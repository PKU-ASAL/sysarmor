import importlib
import unittest

from packages.contracts.proto.signal.v1 import signal_pb2


def load_factory():
    try:
        return importlib.import_module("streaming.detectors.registry")
    except ModuleNotFoundError as error:
        raise AssertionError("detector factory is not implemented") from error


def load_contracts():
    try:
        return importlib.import_module("streaming.detectors.contracts")
    except ModuleNotFoundError as error:
        raise AssertionError("detector contracts are not implemented") from error


class _StubDetector:
    name = "stub-v1"
    version = "1"
    required_inputs = ()
    state_requirements = None

    def __init__(self):
        contracts = load_contracts()
        self.state_requirements = contracts.StateRequirements()

    def analyze(self, inputs):
        return None

    def diagnostics(self):
        return {}


def isolated_registry(factory):
    """A fresh subclass so each test starts from an empty registry."""
    return type("Registry", (factory.DetectorRegistry,), {"_registry": {}})


class DetectorRegistryTest(unittest.TestCase):
    def test_affected_by_reports_any_registered_input_intersection(self):
        factory = load_factory()
        contracts = load_contracts()
        registry = isolated_registry(factory)
        graph_detector = type(
            "GraphDetector",
            (_StubDetector,),
            {"required_inputs": (contracts.RequiredInput.PROVENANCE_EDGE,)},
        )
        registry.register({"stub-v1": graph_detector})

        self.assertTrue(
            registry.affected_by(
                frozenset(
                    {
                        contracts.RequiredInput.NORMALIZED_EVENT,
                        contracts.RequiredInput.PROVENANCE_EDGE,
                    }
                )
            )
        )
        self.assertFalse(
            registry.affected_by(frozenset({contracts.RequiredInput.SIGNAL}))
        )

    def test_affected_by_requires_all_detector_inputs_to_be_available(self):
        factory = load_factory()
        contracts = load_contracts()
        registry = isolated_registry(factory)
        signal_graph_detector = type(
            "SignalGraphDetector",
            (_StubDetector,),
            {
                "required_inputs": (
                    contracts.RequiredInput.SIGNAL,
                    contracts.RequiredInput.PROVENANCE_EDGE,
                )
            },
        )
        registry.register({"stub-v1": signal_graph_detector})
        graph_change = frozenset({contracts.RequiredInput.PROVENANCE_EDGE})

        self.assertFalse(
            registry.affected_by(
                graph_change,
                frozenset({contracts.RequiredInput.PROVENANCE_EDGE}),
            )
        )
        self.assertTrue(
            registry.affected_by(
                graph_change,
                frozenset(
                    {
                        contracts.RequiredInput.SIGNAL,
                        contracts.RequiredInput.PROVENANCE_EDGE,
                    }
                ),
            )
        )

    def test_affected_by_respects_detector_signal_kinds(self):
        factory = load_factory()
        contracts = load_contracts()
        registry = isolated_registry(factory)
        rule_graph_detector = type(
            "RuleGraphDetector",
            (_StubDetector,),
            {
                "required_inputs": (
                    contracts.RequiredInput.SIGNAL,
                    contracts.RequiredInput.PROVENANCE_EDGE,
                ),
                "signal_kinds": frozenset({signal_pb2.DETECTOR_KIND_RULE}),
            },
        )
        registry.register({"stub-v1": rule_graph_detector})
        graph_change = frozenset({contracts.RequiredInput.PROVENANCE_EDGE})
        available = frozenset(
            {contracts.RequiredInput.SIGNAL, contracts.RequiredInput.PROVENANCE_EDGE}
        )

        self.assertFalse(
            registry.affected_by(
                graph_change,
                available,
                frozenset({signal_pb2.DETECTOR_KIND_MODEL}),
            )
        )
        self.assertTrue(
            registry.affected_by(
                graph_change,
                available,
                frozenset({signal_pb2.DETECTOR_KIND_RULE}),
            )
        )

    def test_build_instantiates_registered_detector(self):
        factory = load_factory()
        registry = isolated_registry(factory)
        registry.register({"stub-v1": _StubDetector})

        detectors = registry.build(["stub-v1"])

        self.assertEqual(1, len(detectors))
        self.assertIsInstance(detectors[0], _StubDetector)

    def test_unknown_detector_fails_loudly(self):
        factory = load_factory()
        registry = isolated_registry(factory)

        with self.assertRaises(ValueError):
            registry.build(["does-not-exist"])

    def test_empty_list_builds_nothing(self):
        factory = load_factory()
        registry = isolated_registry(factory)

        self.assertEqual([], registry.build([]))

    def test_known_reports_registered_names(self):
        factory = load_factory()
        registry = isolated_registry(factory)
        registry.register({"stub-v1": _StubDetector})

        self.assertEqual(frozenset({"stub-v1"}), registry.known())

    def test_builtin_registry_contains_nodlink(self):
        module = __import__("streaming.detectors", fromlist=["DetectorRegistry"])
        self.assertIn("nodlink", module.DetectorRegistry.known())


if __name__ == "__main__":
    unittest.main()
