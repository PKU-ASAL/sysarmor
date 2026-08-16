import json
import tempfile
import unittest
from pathlib import Path

from pipeline import calibrate_threshold
from prepare_model import prepare, validate_dataset, validate_pair


def write_events(path: Path, events: list[dict]) -> Path:
    path.write_text("".join(json.dumps(event) + "\n" for event in events))
    return path


class PrepareModelTest(unittest.TestCase):
    def test_rejects_duplicate_and_empty_event_ids(self):
        with tempfile.TemporaryDirectory() as directory:
            path = write_events(Path(directory) / "events.ndjson", [{"id": ""}, {"id": "e1"}, {"id": "e1"}])
            with self.assertRaisesRegex(ValueError, "event id"):
                validate_dataset(path)

    def test_rejects_training_calibration_overlap(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            training = write_events(root / "training.ndjson", [{"id": "e1"}])
            calibration = write_events(root / "calibration.ndjson", [{"id": "e1"}])
            with self.assertRaisesRegex(ValueError, "overlap"):
                validate_pair(training, calibration)

    def test_threshold_excludes_ties_and_respects_rate(self):
        threshold, allowed = calibrate_threshold([5.0, 5.0, 4.0, 2.0], 0.5)
        self.assertEqual(allowed, 2)
        self.assertLessEqual(sum(score >= threshold for score in [5.0, 5.0, 4.0, 2.0]), allowed)

    def test_zero_allowed_candidates_are_excluded_by_successor_threshold(self):
        threshold, allowed = calibrate_threshold([5.0, 4.0], 0.1)
        self.assertEqual(allowed, 0)
        self.assertEqual(sum(score >= threshold for score in [5.0, 4.0]), 0)

    def test_prepare_is_reproducible_and_calibrated(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            training = write_events(root / "training.ndjson", [
                {"id": "train-1", "behavior": "process.exec"},
                {"id": "train-2", "behavior": "process.exec"},
            ])
            calibration = write_events(root / "calibration.ndjson", [
                {"id": "cal-1", "behavior": "process.exec"},
                {"id": "cal-2", "behavior": "network.connect", "object": {"socketAddr": "10.0.0.1:443"}},
            ])
            first = prepare(training, calibration, root / "first.json")
            second = prepare(training, calibration, root / "second.json")
            self.assertEqual(first, second)
            self.assertEqual((root / "first.json").read_bytes(), (root / "second.json").read_bytes())
            self.assertLessEqual(first["calibration_candidate_rate"], 0.005)


if __name__ == "__main__":
    unittest.main()
