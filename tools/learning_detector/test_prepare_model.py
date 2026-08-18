import json
import tempfile
import unittest
from pathlib import Path

from prepare_model import prepare, validate_dataset, validate_pair
from training import TrainingConfig, calibrated_threshold


def write_profiles(path: Path, prefix: str) -> Path:
    events = []
    for index, binary in enumerate(("bash", "curl", "cat", "echo"), 1):
        stable_id = f"{prefix}-p{index}"
        events.append({"id": f"{prefix}-e{index}", "behavior": "process.exec",
                       "subjectProc": {"stableId": stable_id, "binary": f"/bin/{binary}", "argv": [binary]}})
    path.write_text("".join(json.dumps(event) + "\n" for event in events))
    return path


def write_agent_profile(path: Path, agent_id: str) -> Path:

    event = {
        "agentId": agent_id,
        "id": f"{agent_id}-event",
        "behavior": "process.exec",
        "subjectProc": {"stableId": "shared-pid1", "binary": "/sbin/init", "argv": ["init"]},
    }
    path.write_text(json.dumps(event) + "\n")
    return path


class PrepareModelTest(unittest.TestCase):
    def test_rejects_duplicate_and_empty_event_ids(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.ndjson"
            path.write_text(json.dumps({"id": "", "subjectProc": {"stableId": "p1"}}) + "\n")
            with self.assertRaisesRegex(ValueError, "event ID"):
                validate_dataset(path)

    def test_rejects_training_calibration_profile_overlap(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            training = write_profiles(root / "training.ndjson", "same")
            calibration = write_profiles(root / "calibration.ndjson", "same")
            values = [json.loads(line) for line in calibration.read_text().splitlines()]
            for index, value in enumerate(values):
                value["id"] = f"cal-{index}"
            calibration.write_text("".join(json.dumps(value) + "\n" for value in values))
            with self.assertRaisesRegex(ValueError, "profile stable ID overlap"):
                validate_pair(training, calibration)

    def test_allows_same_host_local_stable_id_from_different_agents(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            training = write_agent_profile(root / "training.ndjson", "agent-a")
            calibration = write_agent_profile(root / "calibration.ndjson", "agent-b")

            metadata = validate_pair(training, calibration)

            self.assertEqual(metadata["training"]["profiles"], 1)
            self.assertEqual(metadata["calibration"]["profiles"], 1)

    def test_threshold_excludes_ties_and_respects_rate(self):
        threshold = calibrated_threshold([5.0, 5.0, 4.0, 2.0], 0.5)
        self.assertLessEqual(sum(score >= threshold for score in [5.0, 5.0, 4.0, 2.0]), 2)

    def test_prepare_is_reproducible_and_calibrated(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            training = write_profiles(root / "training.ndjson", "train")
            calibration = write_profiles(root / "calibration.ndjson", "cal")
            config = TrainingConfig(dimension=4, hidden_dimension=3, latent_dimension=2,
                                    bucket_count=16, epochs=20, seed=7, target_rate=0.25)
            first = prepare(training, calibration, root / "first.json", 0.25, config)
            second = prepare(training, calibration, root / "second.json", 0.25, config)
            self.assertEqual(first, second)
            self.assertEqual((root / "first.json").read_bytes(), (root / "second.json").read_bytes())
            self.assertLessEqual(first["calibration_candidate_rate"], 0.25)


if __name__ == "__main__":
    unittest.main()
