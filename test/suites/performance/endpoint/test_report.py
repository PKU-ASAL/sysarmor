import csv
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("report.py")
SPEC = importlib.util.spec_from_file_location("endpoint_report", SCRIPT)
report = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(report)


class EndpointReportTest(unittest.TestCase):
    def test_managed_policy_directory_is_discovered_from_summary(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            managed = output / "collection-learning"
            managed.mkdir()
            (managed / "summary.json").write_text("{}")

            self.assertEqual(report.policy_directories(output), [managed])

    def test_normal_activity_uses_recorder_counter_delta(self):
        with tempfile.TemporaryDirectory() as directory:
            policy_dir = Path(directory) / "collection-balanced"
            policy_dir.mkdir()
            (policy_dir / "summary.json").write_text(json.dumps({
                "markers": [
                    {"phase": "normal_activity_start", "ts": "2026-08-18T00:00:00Z"},
                    {"phase": "normal_activity_done", "ts": "2026-08-18T00:00:10Z"},
                ],
                "raw_phases": {
                    "normal_activity": {
                        "duration_s": 10,
                        "samples": 3,
                        "events_delta": 50,
                        "eps": 5.0,
                    }
                },
            }))
            (policy_dir / "collection-apply.json").write_text("{}")
            (policy_dir / "runtime-feature-flags.json").write_text("{}")
            with (policy_dir / "timeline.csv").open("w", newline="") as stream:
                writer = csv.DictWriter(stream, fieldnames=("ts", "events_seen_since_cursor"))
                writer.writeheader()
                writer.writerows([
                    {"ts": "2026-08-18T00:00:00Z", "events_seen_since_cursor": 100},
                    {"ts": "2026-08-18T00:00:05Z", "events_seen_since_cursor": 120},
                    {"ts": "2026-08-18T00:00:09Z", "events_seen_since_cursor": 150},
                ])

            row = report.build_row(policy_dir)

            self.assertEqual(row["normal_activity_events_delta"], 50)
            self.assertEqual(row["normal_activity_eps"], 5.0)


if __name__ == "__main__":
    unittest.main()
