import importlib
import unittest

from packages.contracts.proto.signal.v1 import signal_pb2


def load_rarity():
    try:
        return importlib.import_module("sysarmor_streaming.operators.rarity")
    except ModuleNotFoundError as error:
        raise AssertionError("rarity operator is not implemented") from error


class RarityTest(unittest.TestCase):
    def test_workload_score_prefers_container_baseline(self):
        baseline = load_rarity().Baseline(
            {"container:checkout": {"reverse_shell": 3}}
        )

        score = load_rarity().workload_score(
            [finding("reverse_shell", 50, container="checkout")], baseline
        )

        self.assertEqual(12.5, score)

    def test_workload_score_falls_back_to_global_baseline(self):
        baseline = load_rarity().Baseline({"global": {"reverse_shell": 1}})

        score = load_rarity().workload_score(
            [finding("reverse_shell", 80)], baseline
        )

        self.assertEqual(40, score)

    def test_observe_tracks_workload_and_global_without_sharing_snapshot(self):
        rarity = load_rarity()
        baseline = rarity.Baseline()
        baseline.observe([finding("exec", 20, host="host-a")])
        snapshot = baseline.snapshot()
        snapshot.add("host:host-a", "exec", 2)

        self.assertEqual(1, baseline.count("host:host-a", "exec"))
        self.assertEqual(1, baseline.count("global", "exec"))
        self.assertEqual(3, snapshot.count("host:host-a", "exec"))

    def test_count_score_downweights_repeated_findings(self):
        score = load_rarity().count_score(
            [finding("download", 50), finding("download", 50)]
        )

        self.assertEqual(75, score)

    def test_count_score_is_independent_of_arrival_order(self):
        rarity = load_rarity()
        signals = [finding("download", 100), finding("download", 10)]

        forward = rarity.count_score(signals)
        reverse = rarity.count_score(list(reversed(signals)))

        self.assertEqual(forward, reverse)


def finding(name, risk, container="", host=""):
    entities = []
    if container:
        entities.append(signal_pb2.EntityRef(kind="container", key=container))
    if host:
        entities.append(signal_pb2.EntityRef(kind="host", key=host))
    return signal_pb2.Signal(
        name=name,
        base_risk=risk,
        global_rarity=1,
        entities=entities,
    )


if __name__ == "__main__":
    unittest.main()
