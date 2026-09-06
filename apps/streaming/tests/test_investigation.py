import unittest

from packages.contracts.proto.incident.v1 import incident_pb2
from packages.contracts.proto.policy.v1 import policy_pb2
from packages.contracts.proto.signal.v1 import signal_pb2

from streaming.detectors.contracts import DetectionResult
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
            evidence=evidence("relevant"),
        )
        unrelated = DetectionResult(
            "unrelated", "1",
            evidence=incident_pb2.EvidenceSubgraph(
                nodes=[node("wrong-a"), node("wrong-b")]
            ),
        )

        incident = investigate(
            build([], [], policy_pb2.DetectionPolicy()),
            (relevant, unrelated),
            Decision(True, "detector-conclusion", ()),
        )[0]

        self.assertEqual({"relevant"}, {item.id for item in incident.evidence.nodes})


def evidence(node_id):
    return incident_pb2.EvidenceSubgraph(nodes=[node(node_id)])


def node(node_id):
    return incident_pb2.GraphNode(id=node_id, kind="process", label=node_id)


if __name__ == "__main__":
    unittest.main()
