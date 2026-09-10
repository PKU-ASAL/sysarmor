import unittest
from unittest import mock

from packages.contracts.proto.policy.v1 import policy_pb2
from packages.contracts.proto.signal.v1 import signal_pb2
from packages.contracts.proto.event.v1 import event_pb2

from tests.test_analysis import causal_events, endpoint_signal, process
from streaming.detectors.nodlink.detector import NodlinkDetector
from streaming.detectors.contracts import DetectorInputs
from streaming.detectors.contracts import DetectorDelta
from streaming.engine.provenance import ProvenanceGraph
from streaming.engine.analysis import analyze
from streaming.detectors.nodlink.state import Campaign, NodlinkState
from streaming.detectors.nodlink.terminal import Terminal, terminals_from_signals
from streaming.detectors.nodlink.campaign import update_campaigns


class NodlinkDetectorTest(unittest.TestCase):
    def test_unrelated_graph_delta_does_not_rebuild_campaigns(self):
        graph = ProvenanceGraph.from_events(causal_events())
        detector = NodlinkDetector()
        candidate = model_signal("p-curl", "exec-curl")
        first = detector.analyze(DetectorInputs(
            events=tuple(causal_events()), signals=(candidate,), graph=graph,
            delta=DetectorDelta(new_signals=(candidate,)),
        ))
        with mock.patch(
            "streaming.detectors.nodlink.detector.update_campaigns",
            wraps=update_campaigns,
        ) as update:
            result = detector.analyze(DetectorInputs(
                signals=(candidate,), graph=graph, detector_state=first.state_update,
                delta=DetectorDelta(changed_node_ids=("process:unrelated",)),
            ))
        update.assert_not_called()
        self.assertEqual((), result.derived_signals)

    def test_graph_delta_rebuilds_only_affected_campaign(self):
        graph = ProvenanceGraph.from_events(causal_events())
        detector = NodlinkDetector()
        candidate = model_signal("p-curl", "exec-curl")
        first = detector.analyze(DetectorInputs(
            events=tuple(causal_events()), signals=(candidate,), graph=graph,
            delta=DetectorDelta(new_signals=(candidate,)),
        ))
        state = NodlinkState.decode(first.state_update)
        unrelated = Campaign(
            "campaign-other", "sha256:other", (), ("process:unrelated",), (), 0
        )
        encoded = NodlinkState((*state.campaigns, unrelated)).encode()
        with mock.patch(
            "streaming.detectors.nodlink.campaign._rebuild",
            wraps=__import__("streaming.detectors.nodlink.campaign", fromlist=["_rebuild"])._rebuild,
        ) as rebuild:
            detector.analyze(DetectorInputs(
                signals=(candidate,), graph=graph, detector_state=encoded,
                delta=DetectorDelta(changed_node_ids=("process:p-curl",)),
            ))
        self.assertEqual(1, rebuild.call_count)

    def test_incremental_analysis_only_maps_new_model_candidates(self):
        candidates = (model_signal("p-curl", "exec-curl"),)
        graph = ProvenanceGraph.from_events(causal_events())
        detector = NodlinkDetector()
        first = detector.analyze(DetectorInputs(
            signals=candidates, graph=graph,
            delta=DetectorDelta(new_signals=candidates),
        ))
        with mock.patch(
            "streaming.detectors.nodlink.detector.terminals_from_signals",
            wraps=__import__("streaming.detectors.nodlink.terminal", fromlist=["terminals_from_signals"]).terminals_from_signals,
        ) as mapped:
            detector.analyze(DetectorInputs(
                signals=candidates, graph=graph, detector_state=first.state_update,
                delta=DetectorDelta(new_events=tuple(causal_events())),
            ))
        self.assertEqual((), mapped.call_args.args[0])

    def test_maps_model_signals_to_terminal_scores_and_evidence(self):
        candidates = [
            model_signal("p-curl", "exec-curl"),
            model_signal("p-bash", "exec-bash"),
        ]
        inputs = DetectorInputs(
            events=tuple(causal_events()), signals=tuple(candidates),
            graph=ProvenanceGraph.from_events(causal_events()),
            policy=policy_pb2.DetectionPolicy(),
        )

        result = NodlinkDetector().analyze(inputs)

        self.assertEqual(
            {"process:p-curl", "process:p-bash"},
            set(result.findings[0].node_scores),
        )
        self.assertTrue(result.findings[0].evidence.nodes)
        self.assertTrue(result.findings[0].evidence.edges)
        self.assertEqual("nodlink", result.algorithm_name)

    def test_emits_graph_conclusion_for_connected_terminals(self):
        candidates = [
            model_signal("p-curl", "exec-curl"),
            model_signal("p-bash", "exec-bash"),
        ]
        result = NodlinkDetector().analyze(DetectorInputs(
            events=tuple(causal_events()), signals=tuple(candidates),
            graph=ProvenanceGraph.from_events(causal_events()),
            policy=policy_pb2.DetectionPolicy(),
        ))

        self.assertEqual(("nodlink_campaign",), tuple(s.name for s in result.derived_signals))
        self.assertEqual(signal_pb2.DETECTOR_KIND_GRAPH, result.derived_signals[0].detector_kind)
        self.assertEqual(signal_pb2.SIGNAL_STAGE_CONCLUSION, result.derived_signals[0].stage)
        self.assertEqual({"signal-p-curl", "signal-p-bash"}, set(result.derived_signals[0].signal_refs))
        self.assertEqual({"exec-curl", "exec-bash"}, set(result.derived_signals[0].event_refs))
        self.assertEqual("run-a", result.derived_signals[0].labels["benchmark_run"])
        self.assertEqual(1, len(result.findings))
        self.assertEqual("nodlink:", result.findings[0].correlation_key[:8])
        self.assertEqual(result.derived_signals[0].id, result.findings[0].conclusion.id)
        self.assertEqual(
            {"signal-p-curl", "signal-p-bash"},
            {item.id for item in result.findings[0].contributors},
        )

    def test_terminal_mapping_requires_model_identity_and_event_reference(self):
        signal = endpoint_signal(
            "model_anomaly", "lin-a", process("p-curl"),
            detector_kind=signal_pb2.DETECTOR_KIND_MODEL,
        )
        signal.model_ref = "model:process-profile-v2"
        signal.model_version = "2"
        signal.model_digest = "sha256:test"
        signal.feature_schema = "FeatureSchemaV2"
        signal.event_refs.append("exec-curl")

        terminals, rejected = terminals_from_signals((signal,))

        self.assertEqual(("process:p-curl",), tuple(item.node_id for item in terminals))
        self.assertEqual((), rejected)

    def test_terminal_mapping_rejects_incomplete_model_signal(self):
        signal = endpoint_signal(
            "model_anomaly", "lin-a", process("p-curl"),
            detector_kind=signal_pb2.DETECTOR_KIND_MODEL,
        )

        terminals, rejected = terminals_from_signals((signal,))

        self.assertEqual((), terminals)
        self.assertEqual("incomplete_model_identity", rejected[0].reason)

    def test_state_round_trip_is_deterministic(self):
        state = NodlinkState(
            campaigns=(Campaign(
                "campaign-a", "sha256:test",
                terminals=(
                    Terminal("process:b", "signal-b", 2, ("event-b",), "lin-b", "sha256:test"),
                    Terminal("process:a", "signal-a", 1, ("event-a",), "lin-a", "sha256:test"),
                ),
                node_ids=("process:b", "process:a"),
                edge_ids=("edge-b", "edge-a"),
            ),),
        )

        encoded = state.encode()

        self.assertEqual(encoded, NodlinkState.decode(encoded).encode())

    def test_graph_conclusion_creates_incident_through_generic_investigation(self):
        result = analyze(
            causal_events(),
            [model_signal("p-curl", "exec-curl"), model_signal("p-bash", "exec-bash")],
            policy_pb2.DetectionPolicy(detectors=["nodlink"]),
        )

        self.assertEqual(("nodlink_campaign",), tuple(item.name for item in result.cloud_signals))
        self.assertEqual(1, len(result.incidents))
        self.assertTrue(result.incidents[0].evidence.edges)

    def test_state_connects_terminals_across_batches(self):
        graph = ProvenanceGraph.from_events(causal_events())
        detector = NodlinkDetector()
        first = detector.analyze(DetectorInputs(
            signals=(model_signal("p-curl", "exec-curl"),), graph=graph,
            delta=DetectorDelta(new_signals=(model_signal("p-curl", "exec-curl"),)),
        ))
        second = detector.analyze(DetectorInputs(
            signals=(model_signal("p-bash", "exec-bash"),), graph=graph,
            detector_state=first.state_update,
            delta=DetectorDelta(new_signals=(model_signal("p-bash", "exec-bash"),)),
        ))

        self.assertEqual(("nodlink_campaign",), tuple(item.name for item in second.derived_signals))
        self.assertEqual(2, second.diagnostics["terminal_count"])

    def test_expired_signal_removes_terminal_from_state(self):
        graph = ProvenanceGraph.from_events(causal_events())
        detector = NodlinkDetector()
        first = detector.analyze(DetectorInputs(
            signals=(model_signal("p-curl", "exec-curl"),), graph=graph,
        ))

        second = detector.analyze(DetectorInputs(
            graph=graph, detector_state=first.state_update,
            delta=DetectorDelta(expired_signal_refs=("signal-p-curl",)),
        ))

        self.assertEqual(0, second.diagnostics["terminal_count"])
        self.assertEqual((), NodlinkState.decode(second.state_update).terminals)

    def test_graph_rebuild_discards_terminals_missing_from_snapshot(self):
        graph = ProvenanceGraph.from_events(causal_events())
        first = NodlinkDetector().analyze(DetectorInputs(
            signals=(model_signal("p-curl", "exec-curl"),), graph=graph,
        ))
        rebuilt = NodlinkDetector().analyze(DetectorInputs(
            graph=graph, detector_state=first.state_update,
            delta=DetectorDelta(graph_rebuilt=True),
        ))
        self.assertEqual(0, rebuilt.diagnostics["terminal_count"])

    def test_missing_graph_terminal_is_not_in_campaign(self):
        graph = ProvenanceGraph.from_events(causal_events())
        missing = model_signal("p-missing", "missing-event")
        result = NodlinkDetector().analyze(DetectorInputs(
            signals=(model_signal("p-curl", "exec-curl"), model_signal("p-bash", "exec-bash"), missing),
            graph=graph,
        ))
        conclusion = result.derived_signals[0]
        self.assertNotIn("signal-p-missing", conclusion.signal_refs)
        self.assertNotIn("process:p-missing", {item.key for item in conclusion.entities})

    def test_cross_lineage_campaign_obeys_policy(self):
        first = model_signal("p-curl", "exec-curl")
        second = model_signal("p-bash", "exec-bash")
        second.lineage_id = "lin-b"
        result = NodlinkDetector().analyze(DetectorInputs(
            signals=(first, second), graph=ProvenanceGraph.from_events(causal_events()),
            policy=policy_pb2.DetectionPolicy(),
        ))
        self.assertEqual((), result.derived_signals)

    def test_cloud_model_signal_is_not_a_terminal(self):
        signal = model_signal("p-curl", "exec-curl")
        signal.where = signal_pb2.SIGNAL_WHERE_CLOUD
        terminals, rejected = terminals_from_signals((signal,))
        self.assertEqual((), terminals)
        self.assertEqual("not_endpoint_signal", rejected[0].reason)

    def test_different_model_digests_do_not_merge(self):
        first = model_signal("p-curl", "exec-curl")
        second = model_signal("p-bash", "exec-bash")
        second.model_digest = "sha256:other"
        result = NodlinkDetector().analyze(DetectorInputs(
            signals=(first, second), graph=ProvenanceGraph.from_events(causal_events()),
        ))
        self.assertEqual((), result.derived_signals)
        self.assertEqual(2, result.diagnostics["campaign_count"])

    def test_unrelated_terminals_create_separate_campaigns(self):
        events = [
            *causal_events(),
            event_pb2.CanonicalEvent(
                id="observe-other", tenant_id="tenant-a", behavior="process.observe",
                subject_proc=event_pb2.ProcessRef(stable_id="p-other"),
            ),
        ]
        result = NodlinkDetector().analyze(DetectorInputs(
            signals=(model_signal("p-curl", "exec-curl"), model_signal("p-other", "observe-other")),
            graph=ProvenanceGraph.from_events(events),
        ))
        self.assertEqual((), result.derived_signals)
        self.assertEqual(2, result.diagnostics["campaign_count"])

    def test_newer_higher_score_signal_replaces_terminal(self):
        first = model_signal("p-curl", "exec-curl")
        second = model_signal("p-curl", "exec-curl")
        first.id, first.local_rarity = "signal-old", 1
        second.id, second.local_rarity = "signal-new", 2

        terminals, _ = terminals_from_signals((first, second))

        self.assertEqual("signal-new", terminals[0].signal_id)
        self.assertEqual(2, terminals[0].score)

    def test_model_rollout_keeps_same_process_per_digest(self):
        old = model_signal("p-curl", "exec-curl")
        new = model_signal("p-curl", "exec-curl")
        peer = model_signal("p-bash", "exec-bash")
        old.id, old.model_digest = "signal-old", "sha256:old"
        new.id, new.model_digest = "signal-new", "sha256:new"
        peer.model_digest = "sha256:new"

        result = NodlinkDetector().analyze(DetectorInputs(
            signals=(old, new, peer), graph=ProvenanceGraph.from_events(causal_events()),
        ))

        self.assertEqual(("nodlink_campaign",), tuple(item.name for item in result.derived_signals))
        self.assertEqual({"signal-new", "signal-p-bash"}, set(result.derived_signals[0].signal_refs))

    def test_unrelated_singleton_does_not_pollute_result_contributors(self):
        events = [
            *causal_events(),
            event_pb2.CanonicalEvent(
                id="observe-other", tenant_id="tenant-a", behavior="process.observe",
                subject_proc=event_pb2.ProcessRef(stable_id="p-other"),
            ),
        ]
        signals = (
            model_signal("p-curl", "exec-curl"),
            model_signal("p-bash", "exec-bash"),
            model_signal("p-other", "observe-other"),
        )
        result = NodlinkDetector().analyze(DetectorInputs(
            signals=signals, graph=ProvenanceGraph.from_events(events),
        ))

        self.assertEqual(
            {"signal-p-curl", "signal-p-bash"},
            set(result.findings[0].signal_refs),
        )
        self.assertEqual(
            {"signal-p-curl", "signal-p-bash"},
            {item.id for item in result.findings[0].contributors},
        )

    def test_campaign_limit_evicts_least_recently_updated(self):
        campaigns = tuple(
            Campaign(
                f"campaign-{index:02d}", f"digest-{index}",
                terminals=(Terminal(
                    f"process:{index}", f"signal-{index}", 1, (), "lin-a",
                    f"digest-{index}",
                ),),
                updated_ns=index,
            )
            for index in range(65)
        )

        retained = update_campaigns(ProvenanceGraph(), campaigns, (), updated_ns=999)

        self.assertEqual(64, len(retained))
        self.assertNotIn("campaign-00", {item.id for item in retained})
        self.assertEqual(64, max(item.updated_ns for item in retained))


def model_signal(process_id, event_id):
    signal = endpoint_signal(
        "model_anomaly", "lin-a", process(process_id),
        detector_kind=signal_pb2.DETECTOR_KIND_MODEL,
        signal_id="signal-" + process_id,
    )
    signal.model_ref = "model:process-profile-v2"
    signal.model_version = "2"
    signal.model_digest = "sha256:test"
    signal.feature_schema = "FeatureSchemaV2"
    signal.event_refs.append(event_id)
    signal.local_rarity = 1
    signal.labels["benchmark_run"] = "run-a"
    signal.labels["policy_profile"] = "collection-hybrid"
    return signal


if __name__ == "__main__":
    unittest.main()
