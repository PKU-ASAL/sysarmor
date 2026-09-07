import unittest

import managed_analysis


def event(event_id, profile_id=None):
    subject = {"stableId": profile_id} if profile_id else {}
    return {"id": event_id, "subjectProc": subject}


def candidate(candidate_id, profile_id, refs):
    return {
        "id": candidate_id,
        "localRarity": -6.5,
        "entities": [{"kind": "process", "key": profile_id, "role": "subject"}],
        "eventRefs": refs,
    }


class AttackProfileDiagnosticsTest(unittest.TestCase):
    def test_distinguishes_model_miss_projection_backlog_and_detection(self):
        events = [event("truth-a", "profile-a"), event("truth-b", "profile-b"), event("truth-c", "profile-c")]
        endpoint = [
            candidate("candidate-b", "profile-b", ["truth-b"]),
            candidate("candidate-c", "profile-c", ["truth-c"]),
        ]
        projected = [candidate("candidate-c", "profile-c", ["truth-c"])]

        result = managed_analysis.attack_profile_diagnostics(
            events, {"truth-a", "truth-b", "truth-c"}, endpoint, projected,
            expected_endpoint_candidates=2,
        )

        self.assertEqual(result["status_counts"], {
            "profile_not_candidate": 1,
            "candidate_not_projected": 1,
            "detected": 1,
        })
        self.assertEqual(
            {row["profile_id"]: row["status"] for row in result["profiles"]},
            {
                "profile-a": "profile_not_candidate",
                "profile-b": "candidate_not_projected",
                "profile-c": "detected",
            },
        )

    def test_reports_unmapped_truth_and_projected_candidate_without_truth_ref(self):
        events = [event("truth-unmapped"), event("truth-a", "profile-a")]
        endpoint = [candidate("candidate-a", "profile-a", ["normal-event"])]

        result = managed_analysis.attack_profile_diagnostics(
            events, {"truth-unmapped", "truth-a"}, endpoint, endpoint,
            expected_endpoint_candidates=1,
        )

        self.assertEqual(result["unmapped_truth_event_ids"], ["truth-unmapped"])
        self.assertEqual(result["status_counts"], {
            "truth_event_unmapped": 1,
            "candidate_missing_truth_ref": 1,
        })
        self.assertEqual(result["profiles"][0]["candidate_ids"], ["candidate-a"])
        self.assertEqual(result["profiles"][0]["candidate_scores"], [-6.5])

    def test_projected_candidate_is_detection_when_observation_stream_evicted_it(self):
        projected = [candidate("candidate-a", "profile-a", ["truth-a"])]

        result = managed_analysis.attack_profile_diagnostics(
            [event("truth-a", "profile-a")], {"truth-a"}, [], projected
        )

        self.assertEqual(result["status_counts"], {"detected": 1})

    def test_does_not_claim_model_miss_when_endpoint_candidate_observation_is_incomplete(self):
        result = managed_analysis.attack_profile_diagnostics(
            [event("truth-a", "profile-a")], {"truth-a"}, [], [], expected_endpoint_candidates=1
        )

        self.assertEqual(result["status_counts"], {"candidate_observation_incomplete": 1})
        self.assertFalse(result["endpoint_candidate_observation_complete"])

    def test_includes_every_profile_in_truth_campaign(self):
        events = [event("truth-a", "profile-a"), event("child-event", "profile-child")]
        projected = [candidate("candidate-child", "profile-child", ["child-event"])]

        result = managed_analysis.attack_profile_diagnostics(
            events,
            {"truth-a"},
            projected,
            projected,
            expected_endpoint_candidates=1,
            profile_campaign_ids={"profile-a": "campaign-a", "profile-child": "campaign-a"},
            truth_campaign_ids={"campaign-a"},
        )

        self.assertEqual(
            {row["profile_id"]: row["status"] for row in result["profiles"]},
            {"profile-a": "profile_not_candidate", "profile-child": "detected"},
        )

    def test_invalid_candidate_score_does_not_break_diagnostics(self):
        invalid = candidate("candidate-a", "profile-a", ["truth-a"])
        invalid["localRarity"] = None

        result = managed_analysis.attack_profile_diagnostics(
            [event("truth-a", "profile-a")], {"truth-a"}, [invalid], []
        )

        self.assertEqual(result["profiles"][0]["candidate_scores"], [])

    def test_missing_frozen_candidate_count_does_not_claim_complete_observation(self):
        result = managed_analysis.attack_profile_diagnostics(
            [event("truth-a", "profile-a")], {"truth-a"}, [], []
        )

        self.assertEqual(result["status_counts"], {"candidate_observation_unavailable": 1})
        self.assertIsNone(result["endpoint_candidate_observation_complete"])

    def test_truth_candidate_backlog_wins_over_unrelated_projected_candidate(self):
        projected = [candidate("candidate-old", "profile-a", ["normal-event"])]
        endpoint = [
            *projected,
            candidate("candidate-truth", "profile-a", ["truth-a"]),
        ]

        result = managed_analysis.attack_profile_diagnostics(
            [event("truth-a", "profile-a")], {"truth-a"}, endpoint, projected
        )

        self.assertEqual(result["status_counts"], {"candidate_not_projected": 1})


class NodlinkQualityMetricsTest(unittest.TestCase):
    def test_calculates_evidence_precision_campaign_duplication_and_latency(self):
        signals = [
            {"id": "candidate-a", "stage": "SIGNAL_STAGE_CANDIDATE", "detectorKind": "DETECTOR_KIND_MODEL", "observedAtUnixNano": 1_000_000_000},
            {"id": "candidate-b", "stage": "SIGNAL_STAGE_CANDIDATE", "detectorKind": "DETECTOR_KIND_MODEL", "observedAtUnixNano": 2_000_000_000},
            {"id": "cloud-a", "name": "nodlink_campaign", "stage": "SIGNAL_STAGE_CONCLUSION", "detectorKind": "DETECTOR_KIND_GRAPH", "observedAtUnixNano": 4_000_000_000, "signalRefs": ["candidate-a", "candidate-b"], "labels": {"campaign_id": "campaign-a"}},
        ]
        incidents = [{"lineageIds": ["campaign-a"], "evidence": {"edges": [{"eventRefs": ["truth-a", "noise-a"]}]}}]

        result = managed_analysis.nodlink_quality_metrics(
            signals, incidents, {"truth-a"}, ["campaign-a", "campaign-a"]
        )

        self.assertEqual(0.5, result["evidence_precision"])
        self.assertEqual(0.5, result["campaign_duplication_rate"])
        self.assertEqual({"count": 1, "p50_ms": 2000.0, "p95_ms": 2000.0, "p99_ms": 2000.0}, result["candidate_to_conclusion_latency"])

    def test_missing_runtime_metrics_is_explicitly_unavailable(self):
        result = managed_analysis.nodlink_quality_metrics([], [], {"truth-a"}, [])
        self.assertIsNone(result["candidate_to_conclusion_latency"])
        self.assertIsNone(result["detector_processing_ms"])
        self.assertIsNone(result["detector_state_bytes"])

    def test_campaign_seed_matches_gate_even_when_projected_candidate_predates_truth_ref(self):
        projected = [candidate("candidate-old", "profile-a", ["normal-event"])]
        endpoint = [*projected, candidate("candidate-truth", "profile-a", ["truth-a"])]

        result = managed_analysis.attack_profile_diagnostics(
            [event("truth-a", "profile-a")],
            {"truth-a"},
            endpoint,
            projected,
            profile_campaign_ids={"profile-a": "campaign-a"},
            truth_campaign_ids={"campaign-a"},
        )

        self.assertEqual(result["status_counts"], {"detected": 1})
        self.assertEqual(result["profiles"][0]["pending_truth_candidate_ids"], ["candidate-truth"])


if __name__ == "__main__":
    unittest.main()
