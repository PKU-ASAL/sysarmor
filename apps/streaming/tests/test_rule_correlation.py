import importlib
import unittest

from packages.contracts.proto.policy.v1 import policy_pb2
from packages.contracts.proto.signal.v1 import signal_pb2

from tests.test_analysis import causal_events, endpoint_signal, file, process, socket


def load_module(name):
    try:
        return importlib.import_module(name)
    except ModuleNotFoundError as error:
        raise AssertionError(f"{name} is not implemented") from error


class RuleCorrelationDetectorTest(unittest.TestCase):
    def test_detector_metadata(self):
        detector = load_module("streaming.detectors.rule_correlation").RuleCorrelationDetector()
        contracts = load_module("streaming.detectors.contracts")

        self.assertEqual("rule-correlation-v1", detector.name)
        self.assertEqual("1", detector.version)
        self.assertEqual(
            (contracts.RequiredInput.SIGNAL, contracts.RequiredInput.PROVENANCE_EDGE),
            detector.required_inputs,
        )

    def test_analyze_emits_rule_conclusions(self):
        detector = load_module("streaming.detectors.rule_correlation").RuleCorrelationDetector()
        inputs = self._inputs(
            causal_events(),
            [
                endpoint_signal("web_runtime_spawns_shell", "lin-a", process("p-web")),
                endpoint_signal("payload_dropped", "lin-a", file("/dev/shm/x.sh")),
                endpoint_signal(
                    "reverse_shell_pattern",
                    "lin-a",
                    process("p-bash"),
                    socket("10.66.0.99:443"),
                    stage=signal_pb2.SIGNAL_STAGE_CONCLUSION,
                ),
            ],
            policy_pb2.DetectionPolicy(),
        )

        result = detector.analyze(inputs)

        self.assertEqual(
            {"dropped_payload_executed_and_connects", "web_shell_chain"},
            {signal.name for signal in result.derived_signals},
        )
        for signal in result.derived_signals:
            self.assertEqual(signal_pb2.SIGNAL_STAGE_CONCLUSION, signal.stage)
            self.assertEqual(signal_pb2.DETECTOR_KIND_RULE, signal.detector_kind)

    def test_analyze_returns_empty_without_match(self):
        detector = load_module("streaming.detectors.rule_correlation").RuleCorrelationDetector()
        inputs = self._inputs(
            [],
            [endpoint_signal("unrelated", "lin-a", process("p-x"))],
            policy_pb2.DetectionPolicy(),
        )

        result = detector.analyze(inputs)

        self.assertEqual((), result.derived_signals)
        self.assertEqual((), result.signal_refs)

    def test_unrelated_lineages_do_not_merge_into_one_attack_family(self):
        detector = load_module("streaming.detectors.rule_correlation").RuleCorrelationDetector()
        inputs = self._inputs(
            [],
            [
                endpoint_signal("payload_dropped", "lin-a", file("/dev/shm/a.sh")),
                endpoint_signal(
                    "reverse_shell_pattern",
                    "lin-b",
                    process("p-bash"),
                    socket("10.66.0.99:443"),
                    stage=signal_pb2.SIGNAL_STAGE_CONCLUSION,
                ),
            ],
            policy_pb2.DetectionPolicy(converge=policy_pb2.ConvergeParams(cross_lineage=True)),
        )

        result = detector.analyze(inputs)

        self.assertEqual((), result.derived_signals)

    def _inputs(self, events, signals, policy):
        contracts = load_module("streaming.detectors.contracts")
        provenance = load_module("streaming.engine.provenance")
        graph = provenance.ProvenanceGraph.from_events(events)
        return contracts.DetectorInputs(
            events=tuple(events),
            signals=tuple(signals),
            graph=graph,
            policy=policy,
        )


if __name__ == "__main__":
    unittest.main()
