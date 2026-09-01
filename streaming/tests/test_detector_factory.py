import importlib
import unittest


def load_factory():
    try:
        return importlib.import_module("sysarmor_streaming.detectors.factory")
    except ModuleNotFoundError as error:
        raise AssertionError("detector factory is not implemented") from error


def load_contracts():
    try:
        return importlib.import_module("sysarmor_streaming.detectors.contracts")
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
    return type("Registry", (factory.DetectorFactory,), {"_registry": {}})


class DetectorFactoryTest(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
