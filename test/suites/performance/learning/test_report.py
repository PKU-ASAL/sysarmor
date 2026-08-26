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
evaluate_mode = REPORT.evaluate_mode
health_number = REPORT.health_number
load_endpoint_run = REPORT.load_endpoint_run
attack_campaign_seed_recall = REPORT.attack_campaign_seed_recall
aggregate_runs = REPORT.aggregate_runs
validate_mode_matrix = REPORT.validate_mode_matrix
require_records = REPORT.require_records
render_report = REPORT.render_report
signal_sample = REPORT.signal_sample
managed_analysis_metrics = REPORT.managed_analysis_metrics
managed_candidate_artifacts = REPORT.managed_candidate_artifacts


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
            "profile_observations": 0,
            "feature_updates": 0,
            "learning_score_calls": 0,
            "lifecycle_only_observations": 0,
            "suppressed_checkpoints": 0,
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


class ManagedAnalysisArtifactTest(unittest.TestCase):
    def test_experiment_health_and_final_lifecycle_have_separate_evidence_sources(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            raw = path / "raw"
            raw.mkdir()
            (raw / "000001.health.json").write_text(REPORT.json.dumps({
                "status": "ok",
                "detection": {"learning": {"status": "loaded", "candidates": {"created": 7}}},
                "localStore": {"latestEventSequence": 10},
            }))
            final = {
                "status": "ok",
                "detection": {"learning": {"status": "disabled", "candidates": {
                    "created": 7, "experimentCreated": 7, "gatewayAccepted": 7,
                }}},
                "localStore": {"latestEventSequence": 12, "eventSequenceCutoff": 12},
            }
            (path / "candidate-lifecycle-final.json").write_text(REPORT.json.dumps(final))

            self.assertEqual(REPORT.latest_health(path)["detection"]["learning"]["status"], "loaded")
            self.assertEqual(REPORT.candidate_lifecycle_snapshot(path)["localStore"]["eventSequenceCutoff"], 12)

    def test_managed_candidate_artifacts_use_stream_projection_and_metrics(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / "managed-signals.json").write_text(REPORT.json.dumps([
                projected_model_candidate("agent-a-00000000000000000007")
            ]))
            (path / "stream-processing.json").write_text(REPORT.json.dumps([{
                "signal_id": "candidate-a", "agent_id": "agent-a", "batch_id": "batch-a",
                "subject_id": "p-attack", "trigger_event_id": "agent-a-00000000000000000007",
                "event_sequence": 7, "status": "projected", "failure_class": "",
            }]))
            (path / "manager-metrics.json").write_text(REPORT.json.dumps({
                "model_candidates_correlated": 1,
                "model_candidates_projected": 1,
                "model_candidates_reference_rejected": 0,
            }))

            result = managed_candidate_artifacts(path, "managed", "agent-a", 7)

            self.assertEqual(len(result["model_candidates"]), 1)
            self.assertEqual(result["model_candidates"][0]["detectorKind"], "DETECTOR_KIND_MODEL")
            self.assertEqual(result["model_candidates"][0]["modelRef"], "model:test")
            self.assertEqual(result["candidate_reference_integrity"]["source"], "stream_projection")
            self.assertEqual(result["candidate_reference_integrity"]["correlated"], 1)
            self.assertEqual(result["candidate_reference_integrity"]["projected"], 1)
            self.assertEqual(result["candidate_reference_integrity"]["reference_rejected"], 0)

    def test_managed_candidate_artifacts_reject_duplicate_projection_ids(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            candidate = projected_model_candidate("agent-a-00000000000000000007")
            (path / "managed-signals.json").write_text(REPORT.json.dumps([candidate, candidate]))
            (path / "stream-processing.json").write_text(REPORT.json.dumps([{
                "signal_id": "candidate-a", "agent_id": "agent-a", "batch_id": "batch-a",
                "subject_id": "p-attack", "trigger_event_id": "agent-a-00000000000000000007",
                "event_sequence": 7, "status": "projected", "failure_class": "",
            }]))

            result = managed_candidate_artifacts(path, "managed", "agent-a", 7)

            self.assertEqual(result["candidate_reference_integrity"]["source"], "missing_stream_processing")

    def test_stream_candidates_after_cutoff_do_not_fill_cohort(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            candidates = [
                projected_model_candidate("agent-a-00000000000000000007"),
                projected_model_candidate("agent-a-00000000000000000010") | {"id": "probe"},
            ]
            (path / "managed-signals.json").write_text(REPORT.json.dumps(candidates))
            (path / "stream-processing.json").write_text(REPORT.json.dumps([
                {"signal_id": "candidate-a", "agent_id": "agent-a", "batch_id": "batch-a", "subject_id": "p-attack", "trigger_event_id": "agent-a-00000000000000000007", "event_sequence": 7, "status": "projected", "failure_class": ""},
                {"signal_id": "probe", "agent_id": "agent-a", "batch_id": "batch-b", "subject_id": "probe", "trigger_event_id": "agent-a-00000000000000000010", "event_sequence": 10, "status": "projected", "failure_class": ""},
            ]))

            result = managed_candidate_artifacts(path, "managed", "agent-a", 7)

            self.assertEqual([item["id"] for item in result["model_candidates"]], ["candidate-a"])
            self.assertEqual(result["candidate_reference_integrity"]["projected"], 1)

    def test_missing_stream_processing_is_unavailable_not_zero(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / "managed-signals.json").write_text("[]")

            result = managed_candidate_artifacts(path, "managed", "agent-a", 7)

            integrity = result["candidate_reference_integrity"]
            self.assertEqual(integrity["source"], "missing_stream_processing")
            self.assertIsNone(integrity["correlated"])
            self.assertIsNone(integrity["projected"])
            self.assertIsNone(integrity["reference_rejected"])

    def test_managed_analysis_extracts_evidence_refs_and_lineages(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / "managed-incidents.json").write_text(REPORT.json.dumps({"incidents": [{
                "lineageIds": ["campaign-a"],
                "evidence": {"edges": [
                    {"eventRefs": ["event-a", "event-b"]},
                    {"event_refs": ["event-c"]},
                ]},
            }]}))

            result = managed_analysis_metrics(path, "managed", {"event-a", "event-b", "event-c"})

            self.assertEqual(result["truth_graph_event_ids"], {"event-a", "event-b", "event-c"})
            self.assertEqual(result["evidence_event_ids"], {"event-a", "event-b", "event-c"})
            self.assertEqual(result["incident_campaign_ids"], {"campaign-a"})
            self.assertEqual(result["managed_analysis"], {"required": True, "incident_artifact_present": True})

    def test_missing_managed_incidents_is_a_failed_measurement_not_unavailable(self):
        with tempfile.TemporaryDirectory() as directory:
            result = managed_analysis_metrics(Path(directory), "managed", {"event-a"})

            self.assertEqual(result["truth_graph_event_ids"], {"event-a"})
            self.assertEqual(result["evidence_event_ids"], set())
            self.assertEqual(result["incident_campaign_ids"], set())
            self.assertEqual(result["managed_analysis"], {"required": True, "incident_artifact_present": False})

    def test_standalone_analysis_does_not_claim_stream_coverage(self):
        self.assertEqual(
            managed_analysis_metrics(Path("/missing"), "standalone", {"event-a"}),
            {"managed_analysis": {"required": False, "incident_artifact_present": False}},
        )


class LearningSchedulingHealthTest(unittest.TestCase):
    def test_profile_health_extracts_semantic_scheduling_counters(self):
        result = REPORT.profile_health({
            "profileObservations": 11,
            "feature_updates": 7,
            "LearningScoreCalls": 5,
            "lifecycleOnlyObservations": 3,
            "suppressed_checkpoints": 6,
        })

        self.assertEqual(result["profile_observations"], 11)
        self.assertEqual(result["feature_updates"], 7)
        self.assertEqual(result["learning_score_calls"], 5)
        self.assertEqual(result["lifecycle_only_observations"], 3)
        self.assertEqual(result["suppressed_checkpoints"], 6)


def model_candidate(event_ref="e1"):
    return {
        "id": "candidate-a",
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


def projected_model_candidate(event_ref="e1"):
    return {
        "id": "candidate-a",
        "stage": "SIGNAL_STAGE_CANDIDATE",
        "detector_kind": "DETECTOR_KIND_MODEL",
        "where": "SIGNAL_WHERE_ENDPOINT",
        "model_ref": "model:test",
        "model_version": "1",
        "model_digest": "sha256:digest",
        "feature_schema": "FeatureSchemaV2",
        "local_rarity": 12.5,
        "event_refs": [event_ref],
        "entities": [{"kind": "process", "role": "subject", "key": "p-attack"}],
    }


def effective_policy(mode):
    detection = {"rulesets": [{"ref": "ruleset:test"}]}
    response = {"allowed_modes": ["observe", "enforce"]}
    if mode != "rule-only":
        detection["learning_model"] = {
            "ref": "model:test", "version": "1", "digest": "sha256:digest",
        }
    if mode == "learning-only":
        detection["rulesets"] = []
        response["allowed_modes"] = ["observe"]
    return {
        "collection": {"behaviors": ["process.exec"]},
        "detection": detection,
        "telemetry": {"max_batch_items": 256},
        "response": response,
    }


class LearningReportTest(unittest.TestCase):
    def test_mode_matrix_accepts_effective_capability_contracts(self):
        modes = {
            mode: {
                "manifest": {"protection_mode": mode},
                "effective_policy": effective_policy(mode),
            }
            for mode in REPORT.PROTECTION_MODES
        }

        validate_mode_matrix(modes)

    def test_mode_matrix_rejects_learning_only_with_rule_capability(self):
        modes = {
            mode: {
                "manifest": {"protection_mode": mode},
                "effective_policy": effective_policy(mode),
            }
            for mode in REPORT.PROTECTION_MODES
        }
        modes["learning-only"]["effective_policy"]["detection"]["rulesets"] = [
            {"ref": "ruleset:unexpected"}
        ]

        with self.assertRaises(REPORT.ReportError):
            validate_mode_matrix(modes)

    def test_mode_matrix_rejects_mislabeled_endpoint_run(self):
        modes = {
            "rule-only": {"manifest": {"protection_mode": "rule-only"}},
            "learning-only": {"manifest": {"protection_mode": "hybrid"}},
            "hybrid": {"manifest": {"protection_mode": "hybrid"}},
        }

        with self.assertRaises(REPORT.ReportError):
            validate_mode_matrix(modes)

    def test_aggregate_requires_complete_protection_mode_matrix(self):
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory)
            (run_dir / "rule-only").mkdir()

            summary = aggregate_runs(run_dir)

            self.assertEqual(summary["status"], "partial")
            self.assertEqual(summary["missing"], ["learning-only", "hybrid"])

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

    def test_missing_candidate_lifecycle_counter_is_unavailable(self):
        lifecycle = REPORT.candidate_lifecycle_health({"created": 1})

        self.assertIsNone(lifecycle["spooled"])

    def test_marks_cpu_overhead_as_failed(self):
        rule_only = metrics(cpu=2.0)
        hybrid = metrics(cpu=16.0)
        result = evaluate_mode(rule_only, hybrid, "hybrid", DEFAULT_GATES)
        self.assertEqual(result["gates"]["performance_cpu"]["status"], "failed")

    def test_uses_mode_specific_absolute_cpu_limits(self):
        rule_only = metrics(cpu=2.0)
        learning = evaluate_mode(rule_only, metrics(cpu=30.0), "learning-only", DEFAULT_GATES)
        hybrid = evaluate_mode(rule_only, metrics(cpu=15.0), "hybrid", DEFAULT_GATES)
        self.assertEqual(learning["gates"]["performance_cpu"]["status"], "passed")
        self.assertEqual(hybrid["gates"]["performance_cpu"]["status"], "passed")

    def test_stream_eviction_is_not_a_drop_failure(self):
        rule_only = metrics(evictions=10)
        hybrid = metrics(evictions=20)
        result = evaluate_mode(rule_only, hybrid, "hybrid", DEFAULT_GATES)
        self.assertEqual(result["gates"]["reliability"]["status"], "passed")
        self.assertEqual(result["observations"]["stream_evictions"], 30)

    def test_variant_summary_keeps_candidate_lifecycle_and_gap_reasons(self):
        value = metrics(evictions=10)
        value["candidate_lifecycle"] = {
            "created": 4, "spooled": 4, "gateway_accepted": 3,
            "gateway_duplicate_ack": 1, "stream_pending_backlog": 0,
        }
        value["reference_gaps"] = {
            "observation_gap": 10, "endpoint_storage_drop": 0,
            "gateway_reject": 1, "stream_reference_rejected": 0,
        }

        summary = REPORT.variant_summary(value)

        self.assertEqual(summary["candidate_lifecycle"]["gateway_accepted"], 3)
        self.assertEqual(summary["reference_gaps"]["gateway_reject"], 1)

    def test_candidate_lifecycle_reports_agent_spool_backlog(self):
        value = metrics()
        value["candidate_lifecycle"] = {
            "created": 9, "spooled": 7, "contract_rejected": 1,
            "gateway_accepted": 7, "gateway_rejected": 0,
        }
        value["reference_gaps"] = {"agent_spool_backlog": 1, "agent_delivery_backlog": 0}

        summary = REPORT.variant_summary(value)

        self.assertEqual(summary["reference_gaps"]["agent_spool_backlog"], 1)

    def test_candidate_lifecycle_keeps_raw_counters_after_freezing_created_watermark(self):
        lifecycle = REPORT.candidate_lifecycle_health({
            "created": 14,
            "experimentCreated": 9,
            "spooled": 12,
            "gatewayAccepted": 10,
        })

        self.assertEqual(lifecycle["created"], 9)
        self.assertEqual(lifecycle["spooled"], 12)
        self.assertEqual(lifecycle["gateway_accepted"], 10)

    def test_unavailable_metric_does_not_become_zero(self):
        rule_only = metrics()
        hybrid = metrics()
        hybrid["performance"]["eps"] = None
        result = evaluate_mode(rule_only, hybrid, "hybrid", DEFAULT_GATES)
        self.assertEqual(result["gates"]["performance_eps"]["status"], "unavailable")
        self.assertNotEqual(result["verdict"], "passed")

    def test_unresolved_model_event_reference_fails_model_gate(self):
        rule_only = metrics()
        hybrid = metrics()
        rule_only["health"]["learning"] = "disabled"
        hybrid["model_candidates"] = [model_candidate("missing-event")]
        result = evaluate_mode(rule_only, hybrid, "hybrid", DEFAULT_GATES)
        self.assertEqual(result["gates"]["model"]["status"], "failed")

    def test_stream_projection_does_not_depend_on_observation_ring_event(self):
        rule_only = metrics()
        hybrid = metrics(evictions=100)
        rule_only["health"]["learning"] = "disabled"
        hybrid["model_candidates"] = [model_candidate("event-not-in-observation-ring")]
        hybrid["candidate_reference_integrity"] = {
            "source": "stream_projection", "pending_backlog": 0,
            "reference_rejected": 0, "correlated": 1, "projected": 1,
        }

        result = evaluate_mode(rule_only, hybrid, "hybrid", DEFAULT_GATES)

        self.assertEqual(result["gates"]["model"]["status"], "passed")

    def test_stream_reference_rejection_and_backlog_are_independent_failures(self):
        for field in ("reference_rejected", "pending_backlog"):
            with self.subTest(field=field):
                rule_only = metrics()
                hybrid = metrics()
                rule_only["health"]["learning"] = "disabled"
                hybrid["model_candidates"] = [model_candidate()]
                hybrid["candidate_reference_integrity"] = {
                    "source": "stream_projection", "reference_rejected": 0,
                    "pending_backlog": 0, "correlated": 1, "projected": 1,
                }
                hybrid["candidate_lifecycle"] = {"contract_rejected": 0, "gateway_rejected": 0}
                hybrid["reference_gaps"] = {"agent_spool_backlog": 0, "agent_delivery_backlog": 0}
                hybrid["candidate_reference_integrity"][field] = 1

                result = evaluate_mode(rule_only, hybrid, "hybrid", DEFAULT_GATES)

                self.assertEqual(result["gates"]["candidate_lifecycle"]["status"], "failed")

    def test_stream_count_exceeding_gateway_accepted_fails_exact_cohort_contract(self):
        rule_only = metrics()
        hybrid = metrics()
        rule_only["health"]["learning"] = "disabled"
        hybrid["model_candidates"] = [model_candidate()]
        hybrid["candidate_lifecycle"] = {
            "created": 5, "spooled": 5, "gateway_accepted": 5,
            "contract_rejected": 0, "gateway_rejected": 0,
        }
        hybrid["candidate_reference_integrity"] = {
            "source": "stream_projection", "reference_rejected": 0,
            "pending_backlog": 0, "correlated": 6, "projected": 6,
            "projection_artifacts": 6,
        }
        hybrid["reference_gaps"] = {
            "endpoint_storage_drop": 0, "agent_spool_backlog": 0,
            "agent_delivery_backlog": 0,
        }

        result = evaluate_mode(rule_only, hybrid, "hybrid", DEFAULT_GATES)

        self.assertEqual(result["gates"]["candidate_lifecycle"]["status"], "failed")

    def test_negative_lifecycle_delta_is_preserved_for_diagnosis(self):
        self.assertEqual(REPORT.lifecycle_delta(5, 6, 0), -1)

    def test_agent_spool_backlog_fails_candidate_lifecycle_gate(self):
        rule_only = metrics()
        hybrid = metrics()
        rule_only["health"]["learning"] = "disabled"
        hybrid["model_candidates"] = [model_candidate()]
        hybrid["candidate_reference_integrity"] = {
            "source": "stream_projection", "reference_rejected": 0,
            "pending_backlog": 0, "correlated": 1, "projected": 1,
        }
        hybrid["candidate_lifecycle"] = {
            "created": 1, "spooled": 1, "gateway_accepted": 1,
            "contract_rejected": 0, "gateway_rejected": 0,
        }
        hybrid["reference_gaps"] = {"agent_spool_backlog": 1, "agent_delivery_backlog": 0}

        result = evaluate_mode(rule_only, hybrid, "hybrid", DEFAULT_GATES)

        self.assertEqual(result["gates"]["candidate_lifecycle"]["status"], "failed")

    def test_endpoint_storage_drop_fails_candidate_lifecycle_gate(self):
        rule_only = metrics()
        hybrid = metrics()
        rule_only["health"]["learning"] = "disabled"
        hybrid["model_candidates"] = [model_candidate()]
        hybrid["candidate_reference_integrity"] = {
            "source": "stream_projection", "reference_rejected": 0,
            "pending_backlog": 0, "correlated": 1, "projected": 1,
            "projection_artifacts": 1,
        }
        hybrid["candidate_lifecycle"] = {
            "created": 1, "spooled": 1, "gateway_accepted": 1,
            "contract_rejected": 0, "gateway_rejected": 0,
        }
        hybrid["reference_gaps"] = {
            "endpoint_storage_drop": 1, "observation_gap": 0,
            "agent_spool_backlog": 0, "agent_delivery_backlog": 0,
        }

        result = evaluate_mode(rule_only, hybrid, "hybrid", DEFAULT_GATES)

        self.assertEqual(result["gates"]["candidate_lifecycle"]["status"], "failed")

    def test_observation_gap_does_not_fail_candidate_lifecycle_gate(self):
        rule_only = metrics()
        hybrid = metrics()
        rule_only["health"]["learning"] = "disabled"
        hybrid["model_candidates"] = [model_candidate()]
        hybrid["candidate_reference_integrity"] = {
            "source": "stream_projection", "reference_rejected": 0,
            "pending_backlog": 0, "correlated": 1, "projected": 1,
            "projection_artifacts": 1,
        }
        hybrid["candidate_lifecycle"] = {
            "created": 1, "spooled": 1, "gateway_accepted": 1,
            "contract_rejected": 0, "gateway_rejected": 0,
        }
        hybrid["reference_gaps"] = {
            "endpoint_storage_drop": 0, "observation_gap": 99,
            "agent_spool_backlog": 0, "agent_delivery_backlog": 0,
        }

        result = evaluate_mode(rule_only, hybrid, "hybrid", DEFAULT_GATES)

        self.assertEqual(result["gates"]["candidate_lifecycle"]["status"], "passed")

    def test_projection_artifact_count_must_match_projected_signals(self):
        rule_only = metrics()
        hybrid = metrics()
        rule_only["health"]["learning"] = "disabled"
        hybrid["model_candidates"] = [model_candidate()]
        hybrid["candidate_reference_integrity"] = {
            "source": "stream_projection", "reference_rejected": 0,
            "pending_backlog": 0, "correlated": 1, "projected": 1,
            "projection_artifacts": 0,
        }
        hybrid["candidate_lifecycle"] = {
            "created": 1, "spooled": 1, "gateway_accepted": 1,
            "contract_rejected": 0, "gateway_rejected": 0,
        }
        hybrid["reference_gaps"] = {
            "endpoint_storage_drop": 0, "observation_gap": 0,
            "agent_spool_backlog": 0, "agent_delivery_backlog": 0,
        }

        result = evaluate_mode(rule_only, hybrid, "hybrid", DEFAULT_GATES)

        self.assertEqual(result["gates"]["candidate_lifecycle"]["status"], "failed")

    def test_model_candidate_allows_history_before_experiment_cursor(self):
        rule_only = metrics()
        hybrid = metrics()
        rule_only["health"]["learning"] = "disabled"
        hybrid["model_candidates"] = [model_candidate() | {"eventRefs": ["before-cursor", "e1"]}]

        result = evaluate_mode(rule_only, hybrid, "hybrid", DEFAULT_GATES)

        self.assertEqual(result["gates"]["model"]["status"], "passed")

    def test_hybrid_without_model_candidate_fails_model_gate(self):
        rule_only = metrics()
        hybrid = metrics()
        rule_only["health"]["learning"] = "disabled"

        result = evaluate_mode(rule_only, hybrid, "hybrid", DEFAULT_GATES)

        self.assertEqual(result["gates"]["model"]["status"], "failed")

    def test_model_candidate_without_provenance_fails_model_gate(self):
        rule_only = metrics()
        hybrid = metrics()
        rule_only["health"]["learning"] = "disabled"
        hybrid["model_candidates"] = [{"stage": "SIGNAL_STAGE_CANDIDATE", "detectorKind": "DETECTOR_KIND_MODEL", "where": "SIGNAL_WHERE_ENDPOINT", "eventRefs": ["e1"]}]

        result = evaluate_mode(rule_only, hybrid, "hybrid", DEFAULT_GATES)

        self.assertEqual(result["gates"]["model"]["status"], "failed")

    def test_model_candidate_must_match_experiment_model(self):
        rule_only = metrics()
        hybrid = metrics()
        rule_only["health"]["learning"] = "disabled"
        hybrid["model_candidates"] = [model_candidate() | {"modelDigest": "sha256:stale"}]

        result = evaluate_mode(rule_only, hybrid, "hybrid", DEFAULT_GATES)

        self.assertEqual(result["gates"]["model"]["status"], "failed")

    def test_model_candidate_rejects_boolean_and_non_finite_scores(self):
        for score in (True, float("inf")):
            with self.subTest(score=score):
                rule_only = metrics()
                hybrid = metrics()
                rule_only["health"]["learning"] = "disabled"
                hybrid["model_candidates"] = [model_candidate() | {"localRarity": score}]

                result = evaluate_mode(rule_only, hybrid, "hybrid", DEFAULT_GATES)

                self.assertEqual(result["gates"]["model"]["status"], "failed")

    def test_model_candidate_accepts_finite_negative_anomaly_score(self):
        rule_only = metrics()
        hybrid = metrics()
        rule_only["health"]["learning"] = "disabled"
        hybrid["model_candidates"] = [model_candidate() | {"localRarity": -1}]

        result = evaluate_mode(rule_only, hybrid, "hybrid", DEFAULT_GATES)

        self.assertEqual(result["gates"]["model"]["status"], "passed")

    def test_attack_campaign_seed_recall_at_ninety_percent_passes(self):
        rule_only = metrics()
        hybrid = metrics()
        rule_only["health"]["learning"] = "disabled"
        hybrid["profile_ids"] = {"p-normal"} | {f"p-attack-{index}" for index in range(10)}
        hybrid["truth_profile_ids"] = {f"p-attack-{index}" for index in range(10)}
        hybrid["profile_campaign_ids"] = {f"p-attack-{index}": f"campaign-{index}" for index in range(10)}
        hybrid["truth_campaign_ids"] = {f"campaign-{index}" for index in range(10)}
        hybrid["model_candidates"] = [
            model_candidate() | {
                "entities": [{"kind": "process", "role": "subject", "key": f"p-attack-{index}"}]
            }
            for index in range(9)
        ]
        hybrid["candidate_reference_integrity"] = {
            "source": "stream_projection", "reference_rejected": 0,
            "pending_backlog": 0, "correlated": 9, "projected": 9,
            "projection_artifacts": 9,
        }
        hybrid["candidate_lifecycle"] = {
            "created": 9, "spooled": 9, "gateway_accepted": 9,
            "contract_rejected": 0, "gateway_rejected": 0,
        }
        hybrid["reference_gaps"] = {
            "endpoint_storage_drop": 0,
            "agent_spool_backlog": 0,
            "agent_delivery_backlog": 0,
        }

        result = evaluate_mode(rule_only, hybrid, "hybrid", DEFAULT_GATES)

        self.assertEqual(result["verdict"], "passed")
        self.assertEqual(result["gates"]["attack_campaign_seed_recall"]["value"], 0.9)

    def test_attack_campaign_seed_recall_below_ninety_percent_fails(self):
        rule_only = metrics()
        hybrid = metrics()
        rule_only["health"]["learning"] = "disabled"
        hybrid["profile_ids"] = {"p-normal"} | {f"p-attack-{index}" for index in range(10)}
        hybrid["truth_profile_ids"] = {f"p-attack-{index}" for index in range(10)}
        hybrid["profile_campaign_ids"] = {f"p-attack-{index}": f"campaign-{index}" for index in range(10)}
        hybrid["truth_campaign_ids"] = {f"campaign-{index}" for index in range(10)}
        hybrid["model_candidates"] = [
            model_candidate() | {
                "entities": [{"kind": "process", "role": "subject", "key": f"p-attack-{index}"}]
            }
            for index in range(8)
        ]

        result = evaluate_mode(rule_only, hybrid, "hybrid", DEFAULT_GATES)

        self.assertEqual(result["gates"]["attack_campaign_seed_recall"]["status"], "failed")

    def test_stream_graph_recall_at_ninety_percent_is_blocking_and_passes(self):
        rule_only = metrics()
        hybrid = metrics()
        rule_only["health"]["learning"] = "disabled"
        hybrid["model_candidates"] = [model_candidate()]
        hybrid["managed_analysis"] = {"required": True, "incident_artifact_present": True}
        hybrid["truth_graph_event_ids"] = {f"event-{index}" for index in range(10)}
        hybrid["evidence_event_ids"] = {f"event-{index}" for index in range(9)}

        result = evaluate_mode(rule_only, hybrid, "hybrid", DEFAULT_GATES)

        self.assertEqual(result["gates"]["stream_graph_recall"]["status"], "passed")
        self.assertTrue(result["gates"]["stream_graph_recall"]["blocking"])

    def test_stream_graph_recall_below_ninety_percent_fails(self):
        rule_only = metrics()
        hybrid = metrics()
        rule_only["health"]["learning"] = "disabled"
        hybrid["model_candidates"] = [model_candidate()]
        hybrid["managed_analysis"] = {"required": True, "incident_artifact_present": True}
        hybrid["truth_graph_event_ids"] = {f"event-{index}" for index in range(10)}
        hybrid["evidence_event_ids"] = {f"event-{index}" for index in range(8)}

        result = evaluate_mode(rule_only, hybrid, "hybrid", DEFAULT_GATES)

        self.assertEqual(result["gates"]["stream_graph_recall"]["status"], "failed")
        self.assertEqual(result["verdict"], "failed")

    def test_missing_managed_conclusion_fails_hybrid_measurement(self):
        rule_only = metrics()
        hybrid = metrics()
        rule_only["health"]["learning"] = "disabled"
        hybrid["model_candidates"] = [model_candidate()]
        hybrid["managed_analysis"] = {"required": True, "incident_artifact_present": True}
        hybrid["truth_graph_event_ids"] = {"e1"}
        hybrid["evidence_event_ids"] = {"e1"}

        result = evaluate_mode(rule_only, hybrid, "hybrid", DEFAULT_GATES)

        self.assertEqual(result["gates"]["conclusion_recall"]["status"], "failed")
        self.assertTrue(result["gates"]["conclusion_recall"]["blocking"])
        self.assertEqual(result["verdict"], "failed")

    def test_missing_managed_incident_artifact_fails_hybrid_graph_and_conclusion(self):
        rule_only = metrics()
        hybrid = metrics()
        rule_only["health"]["learning"] = "disabled"
        hybrid["model_candidates"] = [model_candidate()]
        hybrid["managed_analysis"] = {"required": True, "incident_artifact_present": False}

        result = evaluate_mode(rule_only, hybrid, "hybrid", DEFAULT_GATES)

        for name in ("stream_graph_recall", "conclusion_recall"):
            self.assertEqual(result["gates"][name]["status"], "failed")
            self.assertTrue(result["gates"][name]["blocking"])

    def test_learning_only_does_not_claim_incident_backed_stream_measurements(self):
        rule_only = metrics()
        learning_only = metrics()
        rule_only["health"]["learning"] = "disabled"
        learning_only["model_candidates"] = [model_candidate()]
        learning_only["managed_analysis"] = {"required": True, "incident_artifact_present": True}
        learning_only["truth_graph_event_ids"] = {"e1"}
        learning_only["evidence_event_ids"] = set()
        learning_only["incident_campaign_ids"] = set()

        result = evaluate_mode(rule_only, learning_only, "learning-only", DEFAULT_GATES)

        for name in ("stream_graph_recall", "conclusion_recall"):
            self.assertEqual(result["gates"][name]["status"], "unavailable")
            self.assertFalse(result["gates"][name]["blocking"])

    def test_available_managed_conclusion_is_a_blocking_gate(self):
        rule_only = metrics()
        hybrid = metrics()
        rule_only["health"]["learning"] = "disabled"
        hybrid["model_candidates"] = [model_candidate()]
        hybrid["managed_analysis"] = {"required": True, "incident_artifact_present": True}
        hybrid["incident_campaign_ids"] = set()

        result = evaluate_mode(rule_only, hybrid, "hybrid", DEFAULT_GATES)

        self.assertEqual(result["gates"]["conclusion_recall"]["status"], "failed")
        self.assertTrue(result["gates"]["conclusion_recall"]["blocking"])
        self.assertEqual(result["verdict"], "failed")

    def test_missing_attack_campaigns_makes_seed_gate_unavailable(self):
        rule_only = metrics()
        hybrid = metrics()
        rule_only["health"]["learning"] = "disabled"
        hybrid["truth_profile_ids"] = set()
        hybrid["truth_campaign_ids"] = set()
        hybrid["model_candidates"] = [model_candidate()]

        result = evaluate_mode(rule_only, hybrid, "hybrid", DEFAULT_GATES)

        self.assertEqual(result["gates"]["attack_campaign_seed_recall"]["status"], "unavailable")
        self.assertEqual(result["verdict"], "failed")

    def test_normal_profile_candidate_rate_at_one_percent_passes(self):
        rule_only = metrics()
        hybrid = metrics()
        rule_only["health"]["learning"] = "disabled"
        hybrid["profile_ids"] = {f"p-normal-{index}" for index in range(100)} | {"p-attack"}
        hybrid["truth_profile_ids"] = {"p-attack"}
        hybrid["model_candidates"] = [
            model_candidate(),
            model_candidate() | {
                "entities": [{"kind": "process", "role": "subject", "key": "p-normal-0"}]
            },
        ]

        result = evaluate_mode(rule_only, hybrid, "hybrid", DEFAULT_GATES)

        self.assertEqual(result["gates"]["normal_candidate_rate"]["status"], "passed")
        self.assertEqual(result["gates"]["normal_candidate_rate"]["value"], 0.01)

    def test_normal_profile_candidate_rate_above_one_percent_fails(self):
        rule_only = metrics()
        hybrid = metrics()
        rule_only["health"]["learning"] = "disabled"
        hybrid["profile_ids"] = {f"p-normal-{index}" for index in range(100)} | {"p-attack"}
        hybrid["truth_profile_ids"] = {"p-attack"}
        hybrid["model_candidates"] = [
            model_candidate(),
            *[
                model_candidate() | {
                    "entities": [{"kind": "process", "role": "subject", "key": f"p-normal-{index}"}]
                }
                for index in range(2)
            ],
        ]

        result = evaluate_mode(rule_only, hybrid, "hybrid", DEFAULT_GATES)

        self.assertEqual(result["gates"]["normal_candidate_rate"]["status"], "failed")

    def test_normal_candidate_rate_excludes_every_profile_in_truth_campaigns(self):
        rule_only = metrics()
        hybrid = metrics()
        rule_only["health"]["learning"] = "disabled"
        hybrid["profile_ids"] = {"p-attack", "p-attack-child", "p-normal"}
        hybrid["truth_profile_ids"] = {"p-attack"}
        hybrid["profile_campaign_ids"] = {
            "p-attack": "campaign-a", "p-attack-child": "campaign-a", "p-normal": "normal",
        }
        hybrid["truth_campaign_ids"] = {"campaign-a"}
        hybrid["model_candidates"] = [
            model_candidate() | {"entities": [{"kind": "process", "role": "subject", "key": "p-attack-child"}]}
        ]

        result = evaluate_mode(rule_only, hybrid, "hybrid", DEFAULT_GATES)

        self.assertEqual(result["gates"]["normal_candidate_rate"]["value"], 0.0)
        self.assertEqual(result["gates"]["attack_campaign_seed_recall"]["value"], 1.0)
        self.assertEqual(result["variants"]["hybrid"]["normal_profile_count"], 1)

    def test_steady_average_rss_delta_at_sixteen_mib_passes_and_above_fails(self):
        rule_only = metrics(rss=64.0)
        rule_only["health"]["learning"] = "disabled"
        for rss, expected in ((80.0, "passed"), (80.01, "failed")):
            with self.subTest(rss=rss):
                hybrid = metrics(rss=rss)
                result = evaluate_mode(rule_only, hybrid, "hybrid", DEFAULT_GATES)
                self.assertEqual(result["gates"]["performance_rss"]["status"], expected)

    def test_steady_rss_peak_is_observed_but_does_not_replace_resident_gate(self):
        rule_only = metrics(rss=64.0, rss_peak=65.0)
        hybrid = metrics(rss=79.0, rss_peak=90.0)
        rule_only["health"]["learning"] = "disabled"

        result = evaluate_mode(rule_only, hybrid, "hybrid", DEFAULT_GATES)

        self.assertEqual(result["gates"]["performance_rss"]["status"], "passed")
        self.assertEqual(result["variants"]["hybrid"]["performance"]["agent_rss_steady_max_mb"], 90.0)

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
        rule_only = metrics()
        hybrid = metrics()
        rule_only["health"]["learning"] = "disabled"
        hybrid["model_candidates"] = [model_candidate() | {"entities": []}]

        result = evaluate_mode(rule_only, hybrid, "hybrid", DEFAULT_GATES)

        self.assertEqual(result["gates"]["model"]["status"], "failed")

    def test_attack_campaign_seed_recall_is_unavailable_without_truth_campaigns(self):
        self.assertIsNone(attack_campaign_seed_recall({"profile_ids": {"p1"}, "model_candidates": [model_candidate()]}))


if __name__ == "__main__":
    unittest.main()
