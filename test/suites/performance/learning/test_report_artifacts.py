import tempfile
import unittest
from pathlib import Path
from unittest import mock

from test.suites.performance.learning.test_report import (
    DEFAULT_GATES,
    REPORT,
    aggregate_runs,
    evaluate_mode,
    load_endpoint_run,
    metrics,
    model_candidate,
    render_report,
    require_records,
)


class LearningReportArtifactTest(unittest.TestCase):
    def test_endpoint_policy_directory_follows_protection_mode(self):
        expected = {
            "rule-only": "collection-balanced",
            "learning-only": "collection-learning",
            "hybrid": "collection-hybrid",
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for mode, name in expected.items():
                run = root / mode
                (run / name).mkdir(parents=True)
                (run / "manifest.json").write_text(REPORT.json.dumps({"protection_mode": mode}))
                self.assertEqual(REPORT.endpoint_policy_dir(run), run / name)

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
            for mode in REPORT.PROTECTION_MODES:
                (run_dir / mode).mkdir()
            (run_dir / "model").mkdir()
            (run_dir / "manifest.json").write_text(REPORT.json.dumps({
                "model_ref": "model:test", "model_version": "1",
                "model_digest": "sha256:digest", "feature_schema": "FeatureSchemaV2",
            }))
            (run_dir / "model/calibration.json").write_text('{"garbage": true}')
            (run_dir / "rule-only/manifest.json").write_text('{"vm_env": "vm-endpoint"}')

            summary = aggregate_runs(run_dir)

            self.assertEqual(summary["status"], "invalid")
            self.assertIn("manifest", summary["error"])

    def test_manifest_threshold_and_gates_require_native_json_numbers(self):
        self.assertFalse(REPORT.is_json_number("1.0"))
        self.assertFalse(REPORT.valid_gate_config(DEFAULT_GATES | {"cpu_relative": "1.0"}))

    def test_manifest_accepts_finite_negative_v2_threshold(self):
        manifest = {
            key: "value"
            for key in (
                "suite", "run_id", "benchmark_profile", "policy", "activity_mode", "scenario",
                "git_commit", "git_provenance_source", "training_data", "training_digest",
                "calibration_data", "calibration_digest", "model_ref", "model_version", "model_digest",
            )
        }
        manifest |= {
            "feature_schema": "FeatureSchemaV2",
            "threshold": -1.25,
            "gate_config": DEFAULT_GATES,
        }

        with mock.patch.object(REPORT, "validate_calibration"):
            REPORT.validate_experiment_artifacts(manifest, {})

    def test_missing_top_level_artifacts_produce_invalid_report(self):
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory)
            for mode in REPORT.PROTECTION_MODES:
                (run_dir / mode).mkdir()

            with mock.patch.object(REPORT, "load_endpoint_run", side_effect=[metrics()] * 3):
                summary = aggregate_runs(run_dir)

            self.assertEqual(summary["status"], "invalid")
            self.assertIn("required JSON artifact", (run_dir / "report.md").read_text())

    def test_unexpected_aggregation_error_still_writes_invalid_report(self):
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory)
            for mode in REPORT.PROTECTION_MODES:
                (run_dir / mode).mkdir()

            with mock.patch.object(REPORT, "require_json", side_effect=TypeError("broken contract")):
                summary = aggregate_runs(run_dir)

            self.assertEqual(summary["status"], "invalid")
            self.assertIn("broken contract", (run_dir / "report.md").read_text())

    def test_identical_rule_truth_baseline_gap_is_not_learning_regression(self):
        rule_only = metrics()
        hybrid = metrics()
        rule_only["health"]["learning"] = "disabled"

        result = evaluate_mode(rule_only, hybrid, "hybrid", DEFAULT_GATES)

        self.assertEqual(result["gates"]["rule_truth"]["status"], "passed")
        self.assertEqual(
            result["observations"]["rule_truth_baseline_status"],
            {"rule-only": "failed", "hybrid": "failed"},
        )

    def test_changed_rule_truth_outcome_fails_learning_regression_gate(self):
        rule_only = metrics()
        hybrid = metrics()
        rule_only["health"]["learning"] = "disabled"
        hybrid["truth_steps"][0]["matched"] = True
        hybrid["truth_steps"][0]["match_quality"] = 1.0

        result = evaluate_mode(rule_only, hybrid, "hybrid", DEFAULT_GATES)

        self.assertEqual(result["gates"]["rule_truth"]["status"], "failed")

    def test_unresolved_rule_reference_fails_learning_regression_gate(self):
        rule_only = metrics()
        hybrid = metrics()
        rule_only["health"]["learning"] = "disabled"
        hybrid["rule_refs_ok"] = False

        result = evaluate_mode(rule_only, hybrid, "hybrid", DEFAULT_GATES)

        self.assertEqual(result["gates"]["rule_truth"]["status"], "failed")

    def test_human_report_contains_required_experiment_sections(self):
        summary = evaluate_mode(metrics(), metrics(), "hybrid", DEFAULT_GATES)
        summary["experiment"] = {
            "run_id": "run-1",
            "benchmark_profile": "medium",
            "git_commit": "abc123",
            "git_provenance_source": "captured-before-modes",
            "policy": "test/data/policies/collection-learning.json",
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
            "## 模式性能比较",
            "## 可靠性",
            "## ProcessProfile 生命周期",
            "## Profile 检测效果",
            "## Attack Truth 与 Rule 回归",
            "## 有界样本",
            "## 复现信息",
        ):
            self.assertIn(heading, report)
        self.assertIn("abc123", report)
        self.assertIn("captured-before-modes", report)
        self.assertIn("sha256:train", report)
        self.assertIn("TRAINING_DATA=/results/training.ndjson", report)

    def test_human_report_renders_profile_level_effect_and_lifecycle(self):
        rule_only = metrics()
        hybrid = metrics()
        rule_only["health"]["learning"] = "disabled"
        hybrid["model_candidates"] = [model_candidate()]

        report = render_report(evaluate_mode(rule_only, hybrid, "hybrid", DEFAULT_GATES))

        self.assertIn("Normal profiles", report)
        self.assertIn("Attack campaigns seeded by Agent", report)
        self.assertIn("Capacity evictions", report)
        self.assertIn("EventRef evictions", report)
        self.assertIn("Stream projection artifacts", report)

    def test_human_report_renders_learning_semantic_scheduling(self):
        rule_only = metrics()
        hybrid = metrics()
        hybrid["profile_health"].update({
            "profile_observations": 100,
            "feature_updates": 20,
            "learning_score_calls": 18,
            "lifecycle_only_observations": 30,
            "suppressed_checkpoints": 82,
        })

        report = render_report(evaluate_mode(rule_only, hybrid, "hybrid", DEFAULT_GATES))

        self.assertIn("## Learning 语义调度", report)
        self.assertIn("Profile observations", report)
        self.assertIn("Learning score calls", report)
        self.assertIn("Suppressed checkpoints", report)
        self.assertIn("| Learning score calls | 0 | unavailable | 18 |", report)

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
