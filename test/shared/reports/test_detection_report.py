import unittest
from datetime import datetime, timezone
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import detection_report


class DetectionReportWindowTest(unittest.TestCase):
    def test_manager_timestamp_is_used_for_workload_window(self):
        start = datetime(2026, 8, 11, 12, 35, 42, tzinfo=timezone.utc)
        end = datetime(2026, 8, 11, 12, 35, 53, tzinfo=timezone.utc)
        frames = [
            {"@timestamp": "2026-08-11T12:35:50.000Z", "id": "inside"},
            {"@timestamp": "2026-08-11T12:36:09.000Z", "id": "outside"},
        ]
        filtered = detection_report.filter_frames_by_window(frames, start, end)
        self.assertEqual([frame["id"] for frame in filtered], ["inside"])

    def test_signal_stage_uses_explicit_contract(self):
        self.assertEqual(
            detection_report.signal_stage({"stage": "SIGNAL_STAGE_CONCLUSION"}),
            "conclusion",
        )
        self.assertEqual(
            detection_report.signal_stage({"stage": "SIGNAL_STAGE_CANDIDATE"}),
            "candidate",
        )
        self.assertEqual(
            detection_report.signal_stage({"responseIntent": {"responseIntent": "isolate"}}),
            "",
        )


if __name__ == "__main__":
    unittest.main()
