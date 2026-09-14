import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("human_report.py")
SPEC = importlib.util.spec_from_file_location("human_report", SCRIPT)
human_report = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(human_report)


class HumanReportTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "run"
        self.policy = self.root / "collection-balanced"
        self.policy.mkdir(parents=True)

    def tearDown(self):
        self.temp.cleanup()

    def write_json(self, path, value):
        path.write_text(json.dumps(value))

    def test_generates_run_report_with_policy_effect_and_samples(self):
        self.write_json(
            self.policy / "manifest.json",
            {
                "benchmark_profile": "medium",
                "vm_env": "vm-endpoint",
                "run_id": "run-1",
                "policy_profile": "collection-balanced",
                "policy_file": "policy.json",
                "workload": "business-normal",
                "agent_id": "agent-1",
                "tenant_id": "tenant-1",
                "phase_seconds": {"workload": 30},
            },
        )
        self.write_json(
            self.policy / "collection-apply.json",
            {
                "status": "applied",
                "policyId": "balanced-linux",
                "policyVersion": "2",
                "sections": [
                    {
                        "name": "collection",
                        "reportJson": json.dumps(
                            {
                                "resolved_refs": [{"ref": "ctx:credential"}],
                                "pushed_down_selectors": [{"behavior": "file.read"}],
                                "agent_side_selectors": [],
                                "unsupported_selectors": [],
                                "detection_coverage": {
                                    "status": "covered",
                                    "rules": [{"rule_id": "credential_file_read", "status": "covered"}],
                                },
                            }
                        ),
                    }
                ],
            },
        )
        self.write_json(
            self.policy / "summary.json",
            {
                "overall": {
                    "duration_s": 30,
                    "events_delta": 12,
                    "eps": 0.4,
                    "signals_delta": 1,
                    "dropped_events_delta": 0,
                    "parse_errors_delta": 0,
                    "agent_cpu_pct": {"avg": 2.0, "max": 5.0},
                    "agent_rss_mb": {"avg": 10.0, "max": 12.0},
                    "edr_cpu_pct": {"avg": 3.0, "max": 7.0},
                    "edr_rss_mb": {"avg": 20.0, "max": 22.0},
                },
                "signals_seen_total": 1,
                "events_seen_since_cursor_total": 12,
            },
        )
        (self.policy / "events.scope.ndjson").write_text(
            json.dumps({"event": {"id": "event-1", "behavior": "file.read"}}) + "\n"
        )
        (self.policy / "signals.scope.ndjson").write_text(
            json.dumps(
                {
                    "observedAt": "2026-08-16T00:00:00Z",
                    "signal": {
                        "id": "signal-1",
                        "name": "credential_file_read",
                        "stage": "SIGNAL_STAGE_CANDIDATE",
                        "detectorKind": "DETECTOR_KIND_RULE",
                        "severity": "medium",
                        "confidence": 55,
                        "eventRefs": ["event-1"],
                        "evidence": {"summary": "read credential file"},
                    },
                }
            )
            + "\n"
        )
        raw = self.policy / "raw"
        raw.mkdir()
        self.write_json(raw / "000001.health.json", {
            "status": "ok",
            "sensor": {"running": True, "policyLoaded": True, "eventsDropped": "0", "parseErrors": "0"},
            "telemetryBatcher": {"droppedEvents": "0", "droppedSignals": "0"},
            "telemetrySender": {"sentEvents": "12", "sentSignals": "1"},
            "streams": {"eventEvicted": "4", "signalEvicted": "0"},
            "detection": {"policyId": "detection", "lastApplyStatus": "applied"},
        })

        output = self.root / "report.md"
        result = human_report.generate_report(self.root, output)

        self.assertEqual(result.warning_count, 0)
        report = output.read_text()
        for text in (
            "# Endpoint Performance Report",
            "## Policy Comparison",
            "## collection-balanced",
            "business-normal",
            "credential_file_read",
            "read credential file",
            "file.read",
            "0.40",
            "Stream evictions",
            "4 / 0",
            "Batcher drops",
            "0 / 0",
        ):
            self.assertIn(text, report)

    def test_missing_artifact_is_warning_in_default_mode_and_error_in_strict_mode(self):
        output = self.root / "report.md"

        result = human_report.generate_report(self.root, output)

        self.assertGreater(result.warning_count, 0)
        self.assertTrue(output.exists())
        with self.assertRaises(human_report.ReportError):
            human_report.generate_report(self.root, output, strict=True)


if __name__ == "__main__":
    unittest.main()
