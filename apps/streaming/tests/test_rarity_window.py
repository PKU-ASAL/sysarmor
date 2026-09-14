import importlib
import unittest

from packages.contracts.proto.signal.v1 import signal_pb2

from tests.test_detection_state import detection_policy, signal_record


def load_window():
    try:
        return importlib.import_module("streaming.preprocessing.rarity_window")
    except ModuleNotFoundError as error:
        raise AssertionError("rarity window is not implemented") from error


class RarityWindowTest(unittest.TestCase):
    def test_first_signal_is_full_rarity_and_repeat_is_downweighted(self):
        window = load_window().RarityWindow()
        policy = detection_policy("tenant-a", "policy-a", 7)
        policy.detection.rarity.baseline_window_ns = 1000
        first = finding(100, "first")
        second = finding(110, "second")

        first_result = window.process(first, policy)
        second_result = window.process(second, policy)

        self.assertEqual(1, first_result.signal.global_rarity)
        self.assertEqual(0.5, second_result.signal.global_rarity)
        self.assertEqual(2, window.observation_count())

    def test_expired_observation_does_not_reduce_rarity(self):
        window = load_window().RarityWindow()
        policy = detection_policy("tenant-a", "policy-a", 7)
        policy.detection.rarity.baseline_window_ns = 10

        window.process(finding(100, "first"), policy)
        result = window.process(finding(120, "second"), policy)

        self.assertEqual(1, result.signal.global_rarity)
        self.assertEqual(1, window.observation_count())

    def test_restored_observations_preserve_baseline(self):
        initial = load_window().RarityWindow()
        policy = detection_policy("tenant-a", "policy-a", 7)
        initial.process(finding(100, "first"), policy)
        restored = load_window().RarityWindow()
        restored.restore(initial.observations())

        result = restored.process(finding(110, "second"), policy)

        self.assertEqual(0.5, result.signal.global_rarity)


def finding(observed, signal_id):
    record = signal_record(
        "scope-a",
        "policy-a",
        7,
        observed,
        "download",
        signal_pb2.SIGNAL_STAGE_CANDIDATE,
    )
    record.signal.id = signal_id
    record.signal.base_risk = 50
    record.signal.global_rarity = 1
    record.signal.entities.append(
        signal_pb2.EntityRef(kind="container", key="checkout", role="scope")
    )
    return record


if __name__ == "__main__":
    unittest.main()
