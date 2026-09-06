import importlib
import unittest

from packages.contracts.proto.event.v1 import event_pb2
from packages.contracts.proto.signal.v1 import signal_pb2


def load_contracts():
    try:
        return importlib.import_module("streaming.detectors.contracts")
    except ModuleNotFoundError as error:
        raise AssertionError("detector contracts are not implemented") from error


class RequiredInputTest(unittest.TestCase):
    def test_open_input_enum(self):
        contracts = load_contracts()
        self.assertEqual(
            {"normalized_event", "signal", "provenance_edge"},
            {item.value for item in contracts.RequiredInput},
        )


class DetectionResultTest(unittest.TestCase):
    def test_result_carries_algorithm_identity_and_empty_scores(self):
        contracts = load_contracts()
        result = contracts.DetectionResult(
            algorithm_name="nodlink", algorithm_version="1"
        )
        self.assertEqual("nodlink", result.algorithm_name)
        self.assertEqual("1", result.algorithm_version)
        self.assertEqual({}, result.node_scores)
        self.assertEqual((), result.derived_signals)
        self.assertIsNone(result.evidence)

    def test_result_supports_self_contained_findings(self):
        contracts = load_contracts()
        signal = signal_pb2.Signal(id="conclusion-a")
        evidence = __import__(
            "packages.contracts.proto.incident.v1", fromlist=["incident_pb2"]
        ).incident_pb2.EvidenceSubgraph()
        finding = contracts.DetectionFinding(
            correlation_key="nodlink:campaign-a",
            conclusion=signal,
            evidence=evidence,
        )
        result = contracts.DetectionResult("nodlink", "1", findings=(finding,))
        self.assertEqual("nodlink:campaign-a", result.findings[0].correlation_key)


class DetectorInputsTest(unittest.TestCase):
    def test_delta_carries_only_current_changes(self):
        contracts = load_contracts()
        event = event_pb2.CanonicalEvent(id="event-a")
        signal = signal_pb2.Signal(id="signal-a")
        delta = contracts.DetectorDelta(
            new_events=(event,),
            new_signals=(signal,),
            expired_event_refs=("event-old",),
            expired_signal_refs=("signal-old",),
            changed_node_ids=("process:p1",),
            changed_edge_ids=("exec:process:p0->process:p1",),
            graph_rebuilt=True,
        )

        self.assertEqual(("event-a",), tuple(item.id for item in delta.new_events))
        self.assertEqual(("signal-a",), tuple(item.id for item in delta.new_signals))
        self.assertEqual(("event-old",), delta.expired_event_refs)
        self.assertEqual(("signal-old",), delta.expired_signal_refs)
        self.assertTrue(delta.graph_rebuilt)

    def test_candidates_derive_model_candidate_subset(self):
        contracts = load_contracts()
        model_candidate = signal_pb2.Signal(
            id="c1",
            detector_kind=signal_pb2.DETECTOR_KIND_MODEL,
            stage=signal_pb2.SIGNAL_STAGE_CANDIDATE,
        )
        rule_conclusion = signal_pb2.Signal(
            id="s1",
            detector_kind=signal_pb2.DETECTOR_KIND_RULE,
            stage=signal_pb2.SIGNAL_STAGE_CONCLUSION,
        )
        inputs = contracts.DetectorInputs(signals=(model_candidate, rule_conclusion))

        self.assertEqual(("c1",), tuple(s.id for s in inputs.candidates))
        self.assertEqual(("s1",), tuple(s.id for s in inputs.conclusions))

    def test_default_inputs_have_no_events_and_no_graph(self):
        contracts = load_contracts()
        inputs = contracts.DetectorInputs()

        self.assertEqual((), inputs.events)
        self.assertEqual((), inputs.signals)
        self.assertIsNone(inputs.graph)
        self.assertIsNone(inputs.context)
        self.assertEqual(contracts.DetectorDelta(), inputs.delta)


if __name__ == "__main__":
    unittest.main()
