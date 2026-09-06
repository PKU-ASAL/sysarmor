import unittest

from packages.contracts.proto.incident.v1 import incident_pb2
from packages.contracts.proto.policy.v1 import policy_pb2
from packages.contracts.proto.signal.v1 import signal_pb2

from streaming.detectors.contracts import DetectionResult
from streaming.detectors.contracts import DetectionFinding
from streaming.engine.correlation import build
from streaming.investigation.convergence import Decision
from streaming.investigation.investigation import investigate


class InvestigationTest(unittest.TestCase):
    def test_incident_uses_evidence_from_conclusion_result(self):
        conclusion = signal_pb2.Signal(
            id="conclusion-a", name="campaign",
            stage=signal_pb2.SIGNAL_STAGE_CONCLUSION,
            detector_kind=signal_pb2.DETECTOR_KIND_GRAPH,
        )
        relevant = DetectionResult(
            "trigger", "1", derived_signals=(conclusion,),
            findings=(DetectionFinding(
                correlation_key="trigger:relevant", conclusion=conclusion,
                evidence=evidence("relevant"),
            ),),
        )
        unrelated = DetectionResult("unrelated", "1")

        incident = investigate(
            build([], [], policy_pb2.DetectionPolicy()),
            (relevant, unrelated),
            Decision(True, "detector-conclusion", ()),
        )[0]

        self.assertEqual({"relevant"}, {item.id for item in incident.evidence.nodes})

    def test_each_finding_gets_a_stable_correlated_incident(self):
        findings = tuple(
            DetectionResult(
                "nodlink", "1",
                findings=(
                    __import__("streaming.detectors.contracts", fromlist=["DetectionFinding"]).DetectionFinding(
                        correlation_key=key,
                        conclusion=signal_pb2.Signal(
                            id=key, name="nodlink_campaign",
                            stage=signal_pb2.SIGNAL_STAGE_CONCLUSION,
                            detector_kind=signal_pb2.DETECTOR_KIND_GRAPH,
                        ),
                        evidence=evidence(key),
                    ),
                ),
            )
            for key in ("nodlink:campaign-a", "nodlink:campaign-b")
        )
        view = build([], [], policy_pb2.DetectionPolicy())
        decision = Decision(True, "detector-conclusion", ())

        first = investigate(view, findings, decision)
        second = investigate(view, findings, decision)

        self.assertEqual(2, len(first))
        self.assertEqual(
            [item.id for item in first], [item.id for item in second]
        )
        self.assertEqual(
            {"nodlink:campaign-a", "nodlink:campaign-b"},
            {item.correlation_key for item in first},
        )


def evidence(node_id):
    return incident_pb2.EvidenceSubgraph(nodes=[node(node_id)])


def node(node_id):
    return incident_pb2.GraphNode(id=node_id, kind="process", label=node_id)


if __name__ == "__main__":
    unittest.main()
