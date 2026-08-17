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
attack_campaign_seed_recall = REPORT.attack_campaign_seed_recall
aggregate_runs = REPORT.aggregate_runs
require_records = REPORT.require_records
render_report = REPORT.render_report
signal_sample = REPORT.signal_sample


def metrics(cpu=2.0, rss=64.0, eps=20.0, evictions=0, rss_peak=None):
    return {
        "health": {"status": "ok", "learning": "loaded"},
        "reliability": {"sensor_drop": 0, "batcher_drop": 0, "parse_errors": 0},
        "performance": {
            "agent_cpu_avg_pct": cpu,
            "agent_rss_steady_avg_mb": rss,
            "agent_rss_steady_max_mb": rss if rss_peak is None else rss_peak,
            "eps": eps,
        },
        "profile_health": {
            "active": 10,
            "exited": 2,
            "retained": 1,
            "compactions": 3,
            "expired": 4,
            "capacity_evictions": 5,
            "file_evictions": 6,
            "network_evictions": 7,
            "event_ref_evictions": 8,
        },
        "stream_evictions": evictions,
        "model_candidates": [],
        "expected_model": {
            "modelRef": "model:test",
            "modelVersion": "1",
            "modelDigest": "sha256:digest",
            "featureSchema": "FeatureSchemaV2",
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
        "profile_ids": {"p-normal", "p-attack"},
        "truth_profile_ids": {"p-attack"},
        "profile_campaign_ids": {"p-normal": "normal", "p-attack": "campaign-a"},
        "truth_campaign_ids": {"campaign-a"},
    }


def model_candidate(event_ref="e1"):
    return {
        "stage": "SIGNAL_STAGE_CANDIDATE",
        "detectorKind": "DETECTOR_KIND_MODEL",
        "where": "SIGNAL_WHERE_ENDPOINT",
        "modelRef": "model:test",
        "modelVersion": "1",
        "modelDigest": "sha256:digest",
        "featureSchema": "FeatureSchemaV2",
        "localRarity": 12.5,
        "eventRefs": [event_ref],
        "entities": [{"kind": "process", "role": "subject", "key": "p-attack"}],
    }


class LearningReportTest(unittest.TestCase):
    def test_model_candidate_sample_keeps_classification_dimensions(self):
        sample = signal_sample(model_candidate())
        self.assertEqual(
            {key: sample.get(key) for key in ("stage", "detectorKind", "where")},
            {
                "stage": "SIGNAL_STAGE_CANDIDATE",
                "detectorKind": "DETECTOR_KIND_MODEL",
                "where": "SIGNAL_WHERE_ENDPOINT",
            },
        )

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
        enabled["model_candidates"] = [model_candidate("missing-event")]
        result = evaluate_ab(disabled, enabled, DEFAULT_GATES)
        self.assertEqual(result["gates"]["model"]["status"], "failed")

    def test_model_candidate_allows_history_before_experiment_cursor(self):
        disabled = metrics()
        enabled = metrics()
        disabled["health"]["learning"] = "disabled"
        enabled["model_candidates"] = [model_candidate() | {"eventRefs": ["before-cursor", "e1"]}]

        result = evaluate_ab(disabled, enabled, DEFAULT_GATES)

        self.assertEqual(result["gates"]["model"]["status"], "passed")

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
        enabled["model_candidates"] = [{"stage": "SIGNAL_STAGE_CANDIDATE", "detectorKind": "DETECTOR_KIND_MODEL", "where": "SIGNAL_WHERE_ENDPOINT", "eventRefs": ["e1"]}]

        result = evaluate_ab(disabled, enabled, DEFAULT_GATES)

        self.assertEqual(result["gates"]["model"]["status"], "failed")

    def test_model_candidate_must_match_experiment_model(self):
        disabled = metrics()
        enabled = metrics()
        disabled["health"]["learning"] = "disabled"
        enabled["model_candidates"] = [model_candidate() | {"modelDigest": "sha256:stale"}]

        result = evaluate_ab(disabled, enabled, DEFAULT_GATES)

        self.assertEqual(result["gates"]["model"]["status"], "failed")

    def test_model_candidate_rejects_boolean_and_non_finite_scores(self):
        for score in (True, float("inf")):
            with self.subTest(score=score):
                disabled = metrics()
                enabled = metrics()
                disabled["health"]["learning"] = "disabled"
                enabled["model_candidates"] = [model_candidate() | {"localRarity": score}]

                result = evaluate_ab(disabled, enabled, DEFAULT_GATES)

                self.assertEqual(result["gates"]["model"]["status"], "failed")

    def test_model_candidate_accepts_finite_negative_anomaly_score(self):
        disabled = metrics()
        enabled = metrics()
        disabled["health"]["learning"] = "disabled"
        enabled["model_candidates"] = [model_candidate() | {"localRarity": -1}]

        result = evaluate_ab(disabled, enabled, DEFAULT_GATES)

        self.assertEqual(result["gates"]["model"]["status"], "passed")

    def test_attack_campaign_seed_recall_at_ninety_percent_passes(self):
        disabled = metrics()
        enabled = metrics()
        disabled["health"]["learning"] = "disabled"
        enabled["profile_ids"] = {"p-normal"} | {f"p-attack-{index}" for index in range(10)}
        enabled["truth_profile_ids"] = {f"p-attack-{index}" for index in range(10)}
        enabled["profile_campaign_ids"] = {f"p-attack-{index}": f"campaign-{index}" for index in range(10)}
        enabled["truth_campaign_ids"] = {f"campaign-{index}" for index in range(10)}
        enabled["model_candidates"] = [
            model_candidate() | {
                "entities": [{"kind": "process", "role": "subject", "key": f"p-attack-{index}"}]
            }
            for index in range(9)
        ]

        result = evaluate_ab(disabled, enabled, DEFAULT_GATES)

        self.assertEqual(result["verdict"], "passed")
        self.assertEqual(result["gates"]["attack_campaign_seed_recall"]["value"], 0.9)

    def test_attack_campaign_seed_recall_below_ninety_percent_fails(self):
        disabled = metrics()
        enabled = metrics()
        disabled["health"]["learning"] = "disabled"
        enabled["profile_ids"] = {"p-normal"} | {f"p-attack-{index}" for index in range(10)}
        enabled["truth_profile_ids"] = {f"p-attack-{index}" for index in range(10)}
        enabled["profile_campaign_ids"] = {f"p-attack-{index}": f"campaign-{index}" for index in range(10)}
        enabled["truth_campaign_ids"] = {f"campaign-{index}" for index in range(10)}
        enabled["model_candidates"] = [
            model_candidate() | {
                "entities": [{"kind": "process", "role": "subject", "key": f"p-attack-{index}"}]
            }
            for index in range(8)
        ]

        result = evaluate_ab(disabled, enabled, DEFAULT_GATES)

        self.assertEqual(result["gates"]["attack_campaign_seed_recall"]["status"], "failed")

    def test_worker_graph_recall_at_ninety_percent_is_blocking_and_passes(self):
        disabled = metrics()
        enabled = metrics()
        disabled["health"]["learning"] = "disabled"
        enabled["model_candidates"] = [model_candidate()]
        enabled["truth_graph_event_ids"] = {f"event-{index}" for index in range(10)}
        enabled["evidence_event_ids"] = {f"event-{index}" for index in range(9)}

        result = evaluate_ab(disabled, enabled, DEFAULT_GATES)

        self.assertEqual(result["gates"]["worker_graph_recall"]["status"], "passed")
        self.assertTrue(result["gates"]["worker_graph_recall"]["blocking"])

    def test_worker_graph_recall_below_ninety_percent_fails(self):
        disabled = metrics()
        enabled = metrics()
        disabled["health"]["learning"] = "disabled"
        enabled["model_candidates"] = [model_candidate()]
        enabled["truth_graph_event_ids"] = {f"event-{index}" for index in range(10)}
        enabled["evidence_event_ids"] = {f"event-{index}" for index in range(8)}

        result = evaluate_ab(disabled, enabled, DEFAULT_GATES)

        self.assertEqual(result["gates"]["worker_graph_recall"]["status"], "failed")
        self.assertEqual(result["verdict"], "failed")

    def test_missing_managed_conclusion_is_an_unavailable_observation(self):
        disabled = metrics()
        enabled = metrics()
        disabled["health"]["learning"] = "disabled"
        enabled["model_candidates"] = [model_candidate()]

        result = evaluate_ab(disabled, enabled, DEFAULT_GATES)

        self.assertEqual(result["gates"]["conclusion_recall"]["status"], "unavailable")
        self.assertFalse(result["gates"]["conclusion_recall"]["blocking"])
        self.assertEqual(result["verdict"], "passed")

    def test_available_managed_conclusion_is_a_blocking_gate(self):
        disabled = metrics()
        enabled = metrics()
        disabled["health"]["learning"] = "disabled"
        enabled["model_candidates"] = [model_candidate()]
        enabled["incident_campaign_ids"] = set()

        result = evaluate_ab(disabled, enabled, DEFAULT_GATES)

        self.assertEqual(result["gates"]["conclusion_recall"]["status"], "failed")
        self.assertTrue(result["gates"]["conclusion_recall"]["blocking"])
        self.assertEqual(result["verdict"], "failed")

    def test_missing_attack_campaigns_makes_seed_gate_unavailable(self):
        disabled = metrics()
        enabled = metrics()
        disabled["health"]["learning"] = "disabled"
        enabled["truth_profile_ids"] = set()
        enabled["truth_campaign_ids"] = set()
        enabled["model_candidates"] = [model_candidate()]

        result = evaluate_ab(disabled, enabled, DEFAULT_GATES)

        self.assertEqual(result["gates"]["attack_campaign_seed_recall"]["status"], "unavailable")
        self.assertEqual(result["verdict"], "failed")

    def test_normal_profile_candidate_rate_at_one_percent_passes(self):
        disabled = metrics()
        enabled = metrics()
        disabled["health"]["learning"] = "disabled"
        enabled["profile_ids"] = {f"p-normal-{index}" for index in range(100)} | {"p-attack"}
        enabled["truth_profile_ids"] = {"p-attack"}
        enabled["model_candidates"] = [
            model_candidate(),
            model_candidate() | {
                "entities": [{"kind": "process", "role": "subject", "key": "p-normal-0"}]
            },
        ]

        result = evaluate_ab(disabled, enabled, DEFAULT_GATES)

        self.assertEqual(result["gates"]["normal_candidate_rate"]["status"], "passed")
        self.assertEqual(result["gates"]["normal_candidate_rate"]["value"], 0.01)

    def test_normal_profile_candidate_rate_above_one_percent_fails(self):
        disabled = metrics()
        enabled = metrics()
        disabled["health"]["learning"] = "disabled"
        enabled["profile_ids"] = {f"p-normal-{index}" for index in range(100)} | {"p-attack"}
        enabled["truth_profile_ids"] = {"p-attack"}
        enabled["model_candidates"] = [
            model_candidate(),
            *[
                model_candidate() | {
                    "entities": [{"kind": "process", "role": "subject", "key": f"p-normal-{index}"}]
                }
                for index in range(2)
            ],
        ]

        result = evaluate_ab(disabled, enabled, DEFAULT_GATES)

        self.assertEqual(result["gates"]["normal_candidate_rate"]["status"], "failed")

    def test_normal_candidate_rate_excludes_every_profile_in_truth_campaigns(self):
        disabled = metrics()
        enabled = metrics()
        disabled["health"]["learning"] = "disabled"
        enabled["profile_ids"] = {"p-attack", "p-attack-child", "p-normal"}
        enabled["truth_profile_ids"] = {"p-attack"}
        enabled["profile_campaign_ids"] = {
            "p-attack": "campaign-a", "p-attack-child": "campaign-a", "p-normal": "normal",
        }
        enabled["truth_campaign_ids"] = {"campaign-a"}
        enabled["model_candidates"] = [
            model_candidate() | {"entities": [{"kind": "process", "role": "subject", "key": "p-attack-child"}]}
        ]

        result = evaluate_ab(disabled, enabled, DEFAULT_GATES)

        self.assertEqual(result["gates"]["normal_candidate_rate"]["value"], 0.0)
        self.assertEqual(result["gates"]["attack_campaign_seed_recall"]["value"], 1.0)
        self.assertEqual(result["variants"]["enabled"]["normal_profile_count"], 1)

    def test_steady_average_rss_delta_at_sixteen_mib_passes_and_above_fails(self):
        disabled = metrics(rss=64.0)
        disabled["health"]["learning"] = "disabled"
        for rss, expected in ((80.0, "passed"), (80.01, "failed")):
            with self.subTest(rss=rss):
                enabled = metrics(rss=rss)
                result = evaluate_ab(disabled, enabled, DEFAULT_GATES)
                self.assertEqual(result["gates"]["performance_rss"]["status"], expected)

    def test_steady_rss_peak_is_observed_but_does_not_replace_resident_gate(self):
        disabled = metrics(rss=64.0, rss_peak=65.0)
        enabled = metrics(rss=79.0, rss_peak=90.0)
        disabled["health"]["learning"] = "disabled"

        result = evaluate_ab(disabled, enabled, DEFAULT_GATES)

        self.assertEqual(result["gates"]["performance_rss"]["status"], "passed")
        self.assertEqual(result["variants"]["enabled"]["performance"]["agent_rss_steady_max_mb"], 90.0)

    def test_performance_metrics_use_activity_cpu_eps_and_steady_rss(self):
        phases = {
            "normal_activity": {"agent_cpu_avg_pct": 2.5, "agent_rss_avg_mb": 99.0, "agent_rss_max_mb": 100.0, "eps": 20.0},
            "steady": {"agent_cpu_avg_pct": 9.0, "agent_rss_avg_mb": 69.0, "agent_rss_max_mb": 70.0, "eps": 0.0},
        }

        with mock.patch.object(REPORT, "load_matrix_phase", side_effect=lambda _, phase: phases[phase]):
            result = REPORT.performance_metrics(Path("run"))

        self.assertEqual(result, {
            "agent_cpu_avg_pct": 2.5,
            "agent_rss_steady_avg_mb": 69.0,
            "agent_rss_steady_max_mb": 70.0,
            "eps": 20.0,
        })

    def test_model_candidate_requires_subject_process_entity(self):
        disabled = metrics()
        enabled = metrics()
        disabled["health"]["learning"] = "disabled"
        enabled["model_candidates"] = [model_candidate() | {"entities": []}]

        result = evaluate_ab(disabled, enabled, DEFAULT_GATES)

        self.assertEqual(result["gates"]["model"]["status"], "failed")

    def test_attack_campaign_seed_recall_is_unavailable_without_truth_campaigns(self):
        self.assertIsNone(attack_campaign_seed_recall({"profile_ids": {"p1"}, "model_candidates": [model_candidate()]}))

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
                "model_digest": "sha256:digest", "feature_schema": "FeatureSchemaV2",
            }))
            (run_dir / "model/calibration.json").write_text('{"garbage": true}')
            (run_dir / "disabled/manifest.json").write_text('{"vm_env": "vm-endpoint"}')
            disabled, enabled = metrics(), metrics()
            disabled["health"]["learning"] = "disabled"
            enabled["model_candidates"] = [model_candidate()]

            with mock.patch.object(REPORT, "load_endpoint_run", side_effect=[disabled, enabled]):
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
            "## ProcessProfile 生命周期",
            "## Profile 检测效果",
            "## Attack Truth 与 Rule 回归",
            "## 有界样本",
            "## 复现信息",
        ):
            self.assertIn(heading, report)
        self.assertIn("abc123", report)
        self.assertIn("captured-before-variants", report)
        self.assertIn("sha256:train", report)
        self.assertIn("TRAINING_DATA=/results/training.ndjson", report)

    def test_human_report_renders_profile_level_effect_and_lifecycle(self):
        disabled = metrics()
        enabled = metrics()
        disabled["health"]["learning"] = "disabled"
        enabled["model_candidates"] = [model_candidate()]

        report = render_report(evaluate_ab(disabled, enabled, DEFAULT_GATES))

        self.assertIn("Normal profiles", report)
        self.assertIn("Attack campaigns seeded by Agent", report)
        self.assertIn("Capacity evictions", report)
        self.assertIn("EventRef evictions", report)

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
