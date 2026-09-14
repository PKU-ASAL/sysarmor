import unittest

from packages.contracts.proto.policy.v1 import policy_pb2
from packages.contracts.proto.signal.v1 import signal_pb2
from streaming.graph.index import CorrelationView, build


class CorrelationTest(unittest.TestCase):
    def test_correlation_view_updates_incrementally_without_rebuilding(self):
        first = signal_pb2.Signal(id="s1", name="rule-a")
        second = signal_pb2.Signal(id="s2", name="rule-b")
        view = CorrelationView.empty().add((first,))
        updated = view.add((second,))
        self.assertEqual(["s1"], view.signal_refs("rule-a"))
        self.assertEqual(["s2"], updated.signal_refs("rule-b"))
        self.assertEqual([], updated.remove(("s1",)).signal_refs("rule-a"))
    def test_entities_are_normalized_before_deduplication(self):
        signals = [
            signal_pb2.Signal(
                name="rule",
                entities=[
                    signal_pb2.EntityRef(
                        kind=" Process ", key="p1", role=" Subject "
                    ),
                    signal_pb2.EntityRef(
                        kind="process", key="process:p1", role="subject"
                    ),
                ],
            )
        ]

        entities = build([], signals, policy_pb2.DetectionPolicy()).entities("rule")

        self.assertEqual(1, len(entities))
        self.assertEqual("process", entities[0].kind)
        self.assertEqual("process:p1", entities[0].key)
        self.assertEqual("subject", entities[0].role)

    def test_entities_without_kind_or_key_are_discarded(self):
        signals = [
            signal_pb2.Signal(
                name="rule",
                entities=[
                    signal_pb2.EntityRef(kind="", key="x"),
                    signal_pb2.EntityRef(kind="file", key=""),
                ],
            )
        ]

        entities = build([], signals, policy_pb2.DetectionPolicy()).entities("rule")

        self.assertEqual([], entities)


if __name__ == "__main__":
    unittest.main()
