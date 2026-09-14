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

    def test_payload_lifecycle_truth_matches_beacon_chain(self):
        labels = detection_report.load_yaml(
            Path(__file__).parents[2] / "data/scenarios/vm/apt-fileless-c2-local/labels.yaml"
        )
        events = [
            {"event": {"id": "write-beacon", "behavior": "file.write", "subjectProc": {"binary": "/bin/bash"}, "object": {"kind": "file", "filePath": "/dev/shm/.beacon"}}},
            {"event": {"id": "exec-payload", "behavior": "process.exec", "subjectProc": {"binary": "/usr/bin/bash", "argv": ["/usr/bin/bash", "/dev/shm/x.sh"]}, "object": {"kind": "process"}}},
            {"event": {"id": "reverse-c2", "behavior": "network.connect", "subjectProc": {"binary": "/bin/bash"}, "object": {"kind": "socket", "socketAddr": "10.66.0.99:443"}}},
        ]
        signals = [{"signal": {"id": "lifecycle-1", "name": "payload_lifecycle", "stage": "SIGNAL_STAGE_CANDIDATE", "entities": [
            {"kind": "file", "key": "/dev/shm/.beacon"},
            {"kind": "socket", "key": "10.66.0.99:443"},
        ], "eventRefs": ["write-beacon", "exec-payload", "reverse-c2"]}}]

        result = detection_report.evaluate_case(labels, events, signals, {})
        lifecycle = next(row for row in result["truth_steps"] if row["label_id"] == "payload_lifecycle")
        self.assertTrue(lifecycle["matched"])
        self.assertEqual(lifecycle["match_quality"], 1.0)

        wrong_signal = dict(signals[0]["signal"])
        wrong_signal["entities"] = [{"kind": "file", "key": "/dev/shm/x.sh"}]
        wrong = detection_report.evaluate_case(labels, events, [{"signal": wrong_signal}], {})
        wrong_lifecycle = next(row for row in wrong["truth_steps"] if row["label_id"] == "payload_lifecycle")
        self.assertFalse(wrong_lifecycle["matched"])


if __name__ == "__main__":
    unittest.main()
