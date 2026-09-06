import importlib
import unittest

from tests.test_provenance_graph import causal_events, signal


def load_module(name):
    try:
        return importlib.import_module(name)
    except ModuleNotFoundError as error:
        raise AssertionError(f"{name} is not implemented") from error


class ShortestPathDetectorTest(unittest.TestCase):
    def test_connecting_evidence_returns_evidence_subgraph(self):
        shortest_path = load_module("streaming.detectors.shortest_path")
        contracts = load_module("streaming.detectors.contracts")
        provenance = load_module("streaming.engine.provenance")
        graph = provenance.ProvenanceGraph.from_events(causal_events())
        inputs = contracts.DetectorInputs(
            signals=(
                signal("process", "p-shell"),
                signal("socket", "10.66.0.99:443"),
            ),
            graph=graph,
        )

        evidence = shortest_path.connecting_evidence(inputs.graph, inputs.signals)

        self.assertIn("process:p-curl", {node.id for node in evidence.nodes})
        self.assertTrue(evidence.edges)


if __name__ == "__main__":
    unittest.main()
