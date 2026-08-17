import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


REPORT_PATH = Path(__file__).with_name("report.py")
sys.path.insert(0, str(REPORT_PATH.parent))
REPORT_SPEC = importlib.util.spec_from_file_location("learning_performance_report", REPORT_PATH)
REPORT = importlib.util.module_from_spec(REPORT_SPEC)
REPORT_SPEC.loader.exec_module(REPORT)
DEFAULT_GATES = REPORT.DEFAULT_GATES
evaluate_ab = REPORT.evaluate_ab
health_number = REPORT.health_number
load_endpoint_run = REPORT.load_endpoint_run
model_recall = REPORT.model_recall
aggregate_runs = REPORT.aggregate_runs
require_records = REPORT.require_records
render_report = REPORT.render_report


def metrics(cpu=2.0, rss=64.0, eps=20.0, evictions=0):
    return {
        "health": {"status": "ok", "learning": "loaded"},
        "reliability": {"sensor_drop": 0, "batcher_drop": 0, "parse_errors": 0},
        "performance": {"agent_cpu_avg_pct": cpu, "agent_rss_max_mb": rss, "eps": eps},
        "stream_evictions": evictions,
        "model_signals": [],
        "expected_model": {
            "modelRef": "model:test",
            "modelVersion": "1",
            "modelDigest": "sha256:digest",
            "featureSchema": "FeatureSchemaV1",
        },
        "rule_refs_ok": True,
        "truth_steps": [
            {
                "label_type": "signal",
                "label_id": "payload_lifecycle",
                "required": True,
                "matched": False,
                "match_quality": 0.0,
            }
        ],
        "truth_baseline_ok": False,
        "events": {"e1"},
    }


def model_signal(event_ref="e1"):
    return {
        "stage": "SIGNAL_STAGE_CANDIDATE",
        "detectorKind": "DETECTOR_KIND_MODEL",
        "modelRef": "model:test",
        "modelVersion": "1",
        "modelDigest": "sha256:digest",
        "featureSchema": "FeatureSchemaV1",
        "localRarity": 12.5,
        "eventRefs": [event_ref],
    }


class LearningReportTest(unittest.TestCase):
    def test_omitted_zero_health_counter_is_zero_when_section_exists(self):
        self.assertEqual(health_number({"running": True}, "eventsDropped"), 0)
        self.assertIsNone(health_number({}, "eventsDropped"))

    def test_marks_cpu_overhead_as_failed(self):
        disabled = metrics(cpu=2.0)
        enabled = metrics(cpu=4.0)
        result = evaluate_ab(disabled, enabled, DEFAULT_GATES)
        self.assertEqual(result["gates"]["performance_cpu"]["status"], "failed")

    def test_stream_eviction_is_not_a_drop_failure(self):
        disabled = metrics(evictions=10)
        enabled = metrics(evictions=20)
        result = evaluate_ab(disabled, enabled, DEFAULT_GATES)
        self.assertEqual(result["gates"]["reliability"]["status"], "passed")
        self.assertEqual(result["observations"]["stream_evictions"], 30)

    def test_unavailable_metric_does_not_become_zero(self):
        disabled = metrics()
        enabled = metrics()
        enabled["performance"]["eps"] = None
        result = evaluate_ab(disabled, enabled, DEFAULT_GATES)
        self.assertEqual(result["gates"]["performance_eps"]["status"], "unavailable")
        self.assertNotEqual(result["verdict"], "passed")

    def test_unresolved_model_event_reference_fails_model_gate(self):
        disabled = metrics()
        enabled = metrics()
        disabled["health"]["learning"] = "disabled"
        enabled["model_signals"] = [model_signal("missing-event")]
        result = evaluate_ab(disabled, enabled, DEFAULT_GATES)
        self.assertEqual(result["gates"]["model"]["status"], "failed")

    def test_enabled_without_model_candidate_fails_model_gate(self):
        disabled = metrics()
        enabled = metrics()
        disabled["health"]["learning"] = "disabled"

        result = evaluate_ab(disabled, enabled, DEFAULT_GATES)

        self.assertEqual(result["gates"]["model"]["status"], "failed")

    def test_model_candidate_without_provenance_fails_model_gate(self):
        disabled = metrics()
        enabled = metrics()
        disabled["health"]["learning"] = "disabled"
        enabled["model_signals"] = [{"stage": "SIGNAL_STAGE_CANDIDATE", "detectorKind": "DETECTOR_KIND_MODEL", "eventRefs": ["e1"]}]

        result = evaluate_ab(disabled, enabled, DEFAULT_GATES)

        self.assertEqual(result["gates"]["model"]["status"], "failed")

    def test_model_candidate_must_match_experiment_model(self):
        disabled = metrics()
        enabled = metrics()
        disabled["health"]["learning"] = "disabled"
        enabled["model_signals"] = [model_signal() | {"modelDigest": "sha256:stale"}]

        result = evaluate_ab(disabled, enabled, DEFAULT_GATES)

        self.assertEqual(result["gates"]["model"]["status"], "failed")

    def test_model_candidate_rejects_boolean_and_negative_scores(self):
        for score in (True, -1):
            with self.subTest(score=score):
                disabled = metrics()
                enabled = metrics()
                disabled["health"]["learning"] = "disabled"
                enabled["model_signals"] = [model_signal() | {"localRarity": score}]

                result = evaluate_ab(disabled, enabled, DEFAULT_GATES)

                self.assertEqual(result["gates"]["model"]["status"], "failed")

    def test_attack_recall_is_observation_only(self):
        disabled = metrics()
        enabled = metrics()
        disabled["health"]["learning"] = "disabled"
        enabled["model_signals"] = [model_signal()]
        enabled["truth_events"] = {"e1"}
        result = evaluate_ab(disabled, enabled, DEFAULT_GATES)
        self.assertEqual(result["verdict"], "passed")
        self.assertEqual(result["observations"]["model_recall"], 1.0)

    def test_model_recall_is_unavailable_without_truth_events(self):
        self.assertIsNone(model_recall({"events": {"e1", "e2"}, "model_signals": [model_signal()]}))

    def test_missing_endpoint_artifacts_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(REPORT.ReportError):
                load_endpoint_run(Path(directory))

    def test_ndjson_record_without_expected_type_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.ndjson"
            path.write_text('{"garbage": true}\n')

            with self.assertRaises(REPORT.ReportError):
                require_records(path, "event")

    def test_ndjson_record_rejects_empty_or_wrong_typed_contract_fields(self):
        bad_records = {
            "event": {"event": {"id": None, "behavior": []}},
            "signal": {"signal": {"id": None, "detectorKind": None, "stage": None}},
        }
        for record_type, record in bad_records.items():
            with self.subTest(record_type=record_type), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / f"{record_type}s.ndjson"
                path.write_text(REPORT.json.dumps(record) + "\n")

                with self.assertRaises(REPORT.ReportError):
                    require_records(path, record_type)

    def test_incomplete_experiment_manifest_and_calibration_are_invalid(self):
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory)
            (run_dir / "disabled").mkdir()
            (run_dir / "enabled").mkdir()
            (run_dir / "model").mkdir()
            (run_dir / "manifest.json").write_text(REPORT.json.dumps({
                "model_ref": "model:test", "model_version": "1",
                "model_digest": "sha256:digest", "feature_schema": "FeatureSchemaV1",
            }))
            (run_dir / "model/calibration.json").write_text('{"garbage": true}')
            (run_dir / "disabled/manifest.json").write_text('{"vm_env": "vm-endpoint"}')
            disabled, enabled = metrics(), metrics()
            disabled["health"]["learning"] = "disabled"
            enabled["model_signals"] = [model_signal()]

            with mock.patch.object(REPORT, "load_endpoint_run", side_effect=[disabled, enabled]):
                summary = aggregate_runs(run_dir)

            self.assertEqual(summary["status"], "invalid")
            self.assertIn("manifest", summary["error"])

    def test_manifest_threshold_and_gates_require_native_json_numbers(self):
        self.assertFalse(REPORT.is_json_number("1.0"))
        self.assertFalse(REPORT.valid_gate_config(DEFAULT_GATES | {"cpu_absolute_pp": "1.0"}))

    def test_missing_top_level_artifacts_produce_invalid_report(self):
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory)
            (run_dir / "disabled").mkdir()
            (run_dir / "enabled").mkdir()

            with mock.patch.object(REPORT, "load_endpoint_run", side_effect=[metrics(), metrics()]):
                summary = aggregate_runs(run_dir)

            self.assertEqual(summary["status"], "invalid")
            self.assertIn("required JSON artifact", (run_dir / "report.md").read_text())

    def test_unexpected_aggregation_error_still_writes_invalid_report(self):
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory)
            (run_dir / "disabled").mkdir()
            (run_dir / "enabled").mkdir()

            with mock.patch.object(REPORT, "require_json", side_effect=TypeError("broken contract")):
                summary = aggregate_runs(run_dir)

            self.assertEqual(summary["status"], "invalid")
            self.assertIn("broken contract", (run_dir / "report.md").read_text())

    def test_identical_rule_truth_baseline_gap_is_not_learning_regression(self):
        disabled = metrics()
        enabled = metrics()
        disabled["health"]["learning"] = "disabled"

        result = evaluate_ab(disabled, enabled, DEFAULT_GATES)

        self.assertEqual(result["gates"]["rule_truth"]["status"], "passed")
        self.assertEqual(
            result["observations"]["rule_truth_baseline_status"],
            {"disabled": "failed", "enabled": "failed"},
        )

    def test_changed_rule_truth_outcome_fails_learning_regression_gate(self):
        disabled = metrics()
        enabled = metrics()
        disabled["health"]["learning"] = "disabled"
        enabled["truth_steps"][0]["matched"] = True
        enabled["truth_steps"][0]["match_quality"] = 1.0

        result = evaluate_ab(disabled, enabled, DEFAULT_GATES)

        self.assertEqual(result["gates"]["rule_truth"]["status"], "failed")

    def test_unresolved_rule_reference_fails_learning_regression_gate(self):
        disabled = metrics()
        enabled = metrics()
        disabled["health"]["learning"] = "disabled"
        enabled["rule_refs_ok"] = False

        result = evaluate_ab(disabled, enabled, DEFAULT_GATES)

        self.assertEqual(result["gates"]["rule_truth"]["status"], "failed")

    def test_human_report_contains_required_experiment_sections(self):
        summary = evaluate_ab(metrics(), metrics(), DEFAULT_GATES)
        summary["experiment"] = {
            "run_id": "run-1",
            "benchmark_profile": "medium",
            "git_commit": "abc123",
            "git_provenance_source": "captured-before-variants",
            "policy": "test/data/policies/collection-balanced.json",
            "training_data": "/results/training.ndjson",
            "training_digest": "sha256:train",
            "calibration_data": "/results/calibration.ndjson",
            "calibration_digest": "sha256:calibration",
        }
        summary["model"] = {"threshold": 13.47, "calibration_candidate_rate": 0.0049}

        report = render_report(summary)

        for heading in (
            "## 实验条件",
            "## 模型与校准",
            "## A/B 性能",
            "## 可靠性",
            "## Attack Truth 与 Rule 回归",
            "## 有界样本",
            "## 复现信息",
        ):
            self.assertIn(heading, report)
        self.assertIn("abc123", report)
        self.assertIn("captured-before-variants", report)
        self.assertIn("sha256:train", report)
        self.assertIn("TRAINING_DATA=/results/training.ndjson", report)

    def test_missing_git_revision_is_rendered_as_unavailable(self):
        report = render_report({"experiment": {"git_commit": None, "git_dirty": None}})

        self.assertNotIn("`None`", report)
        self.assertIn("Git commit：`unavailable`", report)

    def test_invalid_report_renders_failure_reason(self):
        report = render_report({"verdict": "failed", "status": "invalid", "error": "bad\nartifact`value"})

        self.assertIn("## 失败详情", report)
        self.assertIn("invalid", report)
        self.assertIn("bad<br>artifact\\`value", report)


if __name__ == "__main__":
    unittest.main()
