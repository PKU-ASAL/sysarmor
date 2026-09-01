import importlib
import unittest

from tests.test_provenance_graph import causal_events, signal


def load_module(name):
    try:
        return importlib.import_module(name)
    except ModuleNotFoundError as error:
        raise AssertionError(f"{name} is not implemented") from error


class ShortestPathDetectorTest(unittest.TestCase):
    def test_detector_metadata(self):
        detector = load_module("sysarmor_streaming.detectors.shortest_path").ShortestPathDetector()
        contracts = load_module("sysarmor_streaming.detectors.contracts")

        self.assertEqual("provenance-shortest-path-v1", detector.name)
        self.assertEqual("1", detector.version)
        self.assertEqual(
            (contracts.RequiredInput.SIGNAL, contracts.RequiredInput.PROVENANCE_EDGE),
            detector.required_inputs,
        )

    def test_analyze_returns_evidence_subgraph(self):
        detector = load_module("sysarmor_streaming.detectors.shortest_path").ShortestPathDetector()
        contracts = load_module("sysarmor_streaming.detectors.contracts")
        provenance = load_module("sysarmor_streaming.operators.provenance")
        graph = provenance.ProvenanceGraph.from_events(causal_events())
        inputs = contracts.DetectorInputs(
            signals=(
                signal("process", "p-shell"),
                signal("socket", "10.66.0.99:443"),
            ),
            graph=graph,
        )

        result = detector.analyze(inputs)

        self.assertEqual("provenance-shortest-path-v1", result.algorithm_name)
        self.assertIn("process:p-curl", {node.id for node in result.evidence.nodes})
        self.assertTrue(result.evidence.edges)
        self.assertTrue(result.edge_refs)
        self.assertTrue(result.event_refs)


if __name__ == "__main__":
    unittest.main()
