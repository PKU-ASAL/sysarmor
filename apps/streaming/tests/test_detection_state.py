import importlib
import unittest
from unittest import mock

from packages.contracts.proto.event.v1 import event_pb2
from packages.contracts.proto.policy.v1 import policy_pb2
from packages.contracts.proto.signal.v1 import signal_pb2
from packages.contracts.proto.streaming.v1 import streaming_pb2


def load_state():
    try:
        return importlib.import_module("streaming.detection.state")
    except ModuleNotFoundError as error:
        raise AssertionError("detection state is not implemented") from error


class DetectionStateTest(unittest.TestCase):
    def test_process_batch_analyzes_records_once_and_returns_all_artifacts(self):
        module = load_state()
        state = module.DetectionState()
        policy = detection_policy("tenant-a", "policy-a", 7)
        values = {policy_key(policy): policy}
        records = [
            signal_record(
                "scope-a", "policy-a", 7, 100, "first",
                signal_pb2.SIGNAL_STAGE_CANDIDATE,
            ),
            signal_record(
                "scope-a", "policy-a", 7, 110, "second",
                signal_pb2.SIGNAL_STAGE_CANDIDATE,
            ),
        ]

        with mock.patch.object(module, "analyze", wraps=module.analyze) as analyze:
            results = state.process_batch(records, 0, values)

        self.assertEqual(1, analyze.call_count)
        self.assertEqual(2, len(results))
    def test_event_without_signal_does_not_run_signal_graph_detectors(self):
        module = load_state()
        state = module.DetectionState()
        policy = detection_policy("tenant-a", "policy-a", 7)
        values = {policy_key(policy): policy}

        with mock.patch.object(module, "analyze", wraps=module.analyze) as analyze:
            state.process(
                event_record("scope-a", "policy-a", 7, 100, "event-a"),
                0,
                values,
            )

        self.assertEqual(0, analyze.call_count)

    def test_out_of_order_event_rebuilds_graph_and_keeps_memory_ordered(self):
        module = load_state()
        state = module.DetectionState()
        policy = detection_policy("tenant-a", "policy-a", 7)
        values = {policy_key(policy): policy}

        original = module.ProvenanceGraph.from_events
        with mock.patch.object(
            module.ProvenanceGraph,
            "from_events",
            autospec=True,
            side_effect=lambda events: original(events),
        ) as build_graph:
            state.process(
                event_record("scope-a", "policy-a", 7, 120, "later"),
                0,
                values,
            )
            state.process(
                event_record("scope-a", "policy-a", 7, 100, "earlier"),
                0,
                values,
            )
            state.mark_persisted("scope-a")
            middle = state.process(
                event_record("scope-a", "policy-a", 7, 110, "middle"),
                0,
                values,
            )

        self.assertEqual(3, build_graph.call_count)
        self.assertTrue(middle.state_rewrite_required)

    def test_deferred_detector_delta_forces_snapshot_rebuild(self):
        module = load_state()
        contracts = importlib.import_module("streaming.detectors.contracts")
        seen = []

        class Stateful:
            name = "stateful"
            version = "1"
            required_inputs = (
                contracts.RequiredInput.SIGNAL,
                contracts.RequiredInput.PROVENANCE_EDGE,
            )
            state_requirements = contracts.StateRequirements(
                keyed=True, ttl_ns=1_000, version=1
            )

            def analyze(self, inputs):
                seen.append((inputs.detector_state, inputs.delta.graph_rebuilt))
                return contracts.DetectionResult(
                    self.name, self.version, state_update=b"state"
                )

        state = module.DetectionState()
        policy = detection_policy("tenant-a", "policy-a", 7, state_retention_ns=15)
        values = {policy_key(policy): policy}
        first = signal_record(
            "scope-a", "policy-a", 7, 100, "first",
            signal_pb2.SIGNAL_STAGE_CANDIDATE,
        )
        event = event_record("scope-a", "policy-a", 7, 120, "event-a")
        second = signal_record(
            "scope-a", "policy-a", 7, 130, "second",
            signal_pb2.SIGNAL_STAGE_CANDIDATE,
        )
        with mock.patch.object(module.DetectorRegistry, "build", return_value=[Stateful()]), mock.patch.object(
            module.DetectorRegistry,
            "affected_by",
            wraps=module.DetectorRegistry.affected_by,
        ):
            state.process(first, 0, values)
            state.process(event, 0, values)
            state.process(second, 0, values)

        self.assertEqual([(b"", True), (b"state", True)], seen)

    def test_detector_state_uses_its_own_ttl(self):
        module = load_state()
        contracts = importlib.import_module("streaming.detectors.contracts")

        class Stateful:
            name = "stateful"
            version = "1"
            required_inputs = (contracts.RequiredInput.SIGNAL,)
            state_requirements = contracts.StateRequirements(
                keyed=True, ttl_ns=10, version=1
            )

            def analyze(self, inputs):
                return contracts.DetectionResult(
                    self.name, self.version, state_update=b"state"
                )

        state = module.DetectionState()
        policy = detection_policy("tenant-a", "policy-a", 7, state_retention_ns=1_000)
        values = {policy_key(policy): policy}
        with mock.patch.object(module.DetectorRegistry, "build", return_value=[Stateful()]):
            state.process(
                signal_record(
                    "scope-a", "policy-a", 7, 100, "first",
                    signal_pb2.SIGNAL_STAGE_CANDIDATE,
                ),
                0,
                values,
            )

        self.assertEqual({"stateful@1/state-1": 110}, state.detector_state_expiries("scope-a"))
        state.cleanup("scope-a", 111, policy)
        self.assertEqual({}, state.detector_states("scope-a"))

    def test_zero_detector_ttl_reuses_agent_retention(self):
        module = load_state()
        contracts = importlib.import_module("streaming.detectors.contracts")

        class Stateful:
            name = "stateful"
            version = "1"
            required_inputs = (contracts.RequiredInput.SIGNAL,)
            state_requirements = contracts.StateRequirements(keyed=True, version=1)

            def analyze(self, inputs):
                return contracts.DetectionResult(
                    self.name, self.version, state_update=b"state"
                )

        state = module.DetectionState()
        policy = detection_policy("tenant-a", "policy-a", 7, state_retention_ns=50)
        values = {policy_key(policy): policy}
        with mock.patch.object(module.DetectorRegistry, "build", return_value=[Stateful()]):
            state.process(
                signal_record(
                    "scope-a", "policy-a", 7, 100, "first",
                    signal_pb2.SIGNAL_STAGE_CANDIDATE,
                ),
                0,
                values,
            )

        self.assertEqual({"stateful@1/state-1": 150}, state.detector_state_expiries("scope-a"))

    def test_expired_detector_state_rebuilds_on_next_relevant_input(self):
        module = load_state()
        contracts = importlib.import_module("streaming.detectors.contracts")
        seen = []

        class Stateful:
            name = "stateful"
            version = "1"
            required_inputs = (contracts.RequiredInput.SIGNAL,)
            state_requirements = contracts.StateRequirements(
                keyed=True, ttl_ns=10, version=1
            )

            def analyze(self, inputs):
                seen.append((inputs.detector_state, inputs.delta.graph_rebuilt))
                return contracts.DetectionResult(
                    self.name, self.version, state_update=b"state"
                )

        state = module.DetectionState()
        policy = detection_policy("tenant-a", "policy-a", 7, state_retention_ns=1_000)
        values = {policy_key(policy): policy}
        first = signal_record(
            "scope-a", "policy-a", 7, 100, "first",
            signal_pb2.SIGNAL_STAGE_CANDIDATE,
        )
        second = signal_record(
            "scope-a", "policy-a", 7, 120, "second",
            signal_pb2.SIGNAL_STAGE_CANDIDATE,
        )
        with mock.patch.object(module.DetectorRegistry, "build", return_value=[Stateful()]):
            state.process(first, 0, values)
            state.process(second, 0, values)

        self.assertEqual([(b"", True), (b"", True)], seen)

    def test_restore_discards_expiry_without_matching_state(self):
        state = load_state().DetectionState()

        state.restore_detector_states(
            "scope-a",
            [("active@1/state-1", b"state")],
            [("active@1/state-1", 100), ("orphan@1/state-1", 200)],
        )

        self.assertEqual(
            {"active@1/state-1": 100},
            state.detector_state_expiries("scope-a"),
        )

    def test_restore_sorts_memory_before_following_middle_event(self):
        state = load_state().DetectionState()
        policy = detection_policy("tenant-a", "policy-a", 7)
        values = {policy_key(policy): policy}
        later = event_record("scope-a", "policy-a", 7, 120, "later")
        earlier = event_record("scope-a", "policy-a", 7, 100, "earlier")
        state.restore("scope-a", [later, earlier], values)
        state.mark_persisted("scope-a")

        result = state.process(
            event_record("scope-a", "policy-a", 7, 110, "middle"),
            0,
            values,
        )

        self.assertTrue(result.state_rewrite_required)

    def test_restore_accepts_ordered_interleaved_snapshot(self):
        state = load_state().DetectionState()
        policy = detection_policy("tenant-a", "policy-a", 7)
        values = {policy_key(policy): policy}
        event = event_record("scope-a", "policy-a", 7, 100, "event-a")
        signal = signal_record(
            "scope-a", "policy-a", 7, 110, "signal-a",
            signal_pb2.SIGNAL_STAGE_CANDIDATE,
        )
        middle_event = event_record(
            "scope-a", "policy-a", 7, 120, "event-b"
        )

        state.restore("scope-a", [event, signal, middle_event], values)
        result = state.process(
            event_record("scope-a", "policy-a", 7, 130, "event-c"),
            0,
            values,
        )

        self.assertFalse(result.state_rewrite_required)

    def test_provenance_graph_is_built_once_for_incremental_events(self):
        module = load_state()
        analysis = importlib.import_module("streaming.detection.analysis")
        state = module.DetectionState()
        policy = detection_policy("tenant-a", "policy-a", 7, state_retention_ns=10_000)
        values = {policy_key(policy): policy}

        original = analysis.ProvenanceGraph.from_events
        with mock.patch.object(
            analysis.ProvenanceGraph,
            "from_events",
            autospec=True,
            side_effect=lambda events: original(events),
        ) as build_graph:
            state.process(event_record("scope-a", "policy-a", 7, 100, "event-a"), 0, values)
            state.process(event_record("scope-a", "policy-a", 7, 110, "event-b"), 0, values)

        self.assertEqual(1, build_graph.call_count)

    def test_event_after_model_signal_runs_registered_model_graph_detector(self):
        module = load_state()
        state = module.DetectionState()
        policy = detection_policy("tenant-a", "policy-a", 7)
        values = {policy_key(policy): policy}
        candidate = signal_record(
            "scope-a", "policy-a", 7, 110, "model_anomaly",
            signal_pb2.SIGNAL_STAGE_CANDIDATE,
        )
        candidate.signal.detector_kind = signal_pb2.DETECTOR_KIND_MODEL

        state.process(event_record("scope-a", "policy-a", 7, 100, "event-a"), 0, values)
        state.process(candidate, 0, values)
        with mock.patch.object(module, "analyze", wraps=module.analyze) as analyze:
            result = state.process(
                event_record("scope-a", "policy-a", 7, 120, "event-b"), 0, values
            )

        self.assertEqual(0, analyze.call_count)
        self.assertEqual((), result.artifacts)
        self.assertEqual({"event-a", "event-b"}, state.event_ids("scope-a"))

    def test_event_after_model_candidate_does_not_trigger_signal_detector(self):
        module = load_state()
        contracts = importlib.import_module("streaming.detectors.contracts")
        calls = []

        class ModelGraphDetector:
            name = "model-graph"
            version = "1"
            required_inputs = (
                contracts.RequiredInput.SIGNAL,
                contracts.RequiredInput.PROVENANCE_EDGE,
            )
            signal_kinds = frozenset({signal_pb2.DETECTOR_KIND_MODEL})
            state_requirements = contracts.StateRequirements()

            def analyze(self, inputs):
                calls.append(inputs.delta)
                return contracts.DetectionResult(self.name, self.version)

        state = module.DetectionState()
        policy = detection_policy("tenant-a", "policy-a", 7)
        values = {policy_key(policy): policy}
        candidate = signal_record(
            "scope-a", "policy-a", 7, 110, "model_anomaly",
            signal_pb2.SIGNAL_STAGE_CANDIDATE,
        )
        candidate.signal.detector_kind = signal_pb2.DETECTOR_KIND_MODEL
        registry = {ModelGraphDetector.name: ModelGraphDetector}

        with mock.patch.object(module.DetectorRegistry, "_registry", registry):
            state.process(candidate, 0, values)
            calls.clear()
            state.process(
                event_record("scope-a", "policy-a", 7, 120, "event-b"),
                0,
                values,
            )

        self.assertEqual(0, len(calls))

    def test_signal_only_detector_keeps_event_fast_path(self):
        module = load_state()
        state = module.DetectionState()
        policy = detection_policy("tenant-a", "policy-a", 7)
        values = {policy_key(policy): policy}
        candidate = signal_record("scope-a", "policy-a", 7, 110, "model_anomaly", signal_pb2.SIGNAL_STAGE_CANDIDATE)
        candidate.signal.detector_kind = signal_pb2.DETECTOR_KIND_MODEL
        state.process(candidate, 0, values)

        with mock.patch.object(module.DetectorRegistry, "affected_by", return_value=False), mock.patch.object(
            module, "analyze", wraps=module.analyze
        ) as analyze:
            state.process(event_record("scope-a", "policy-a", 7, 120, "event-b"), 0, values)

        self.assertEqual(0, analyze.call_count)

    def test_analysis_receives_current_signal_delta(self):
        module = load_state()
        state = module.DetectionState()
        policy = detection_policy("tenant-a", "policy-a", 7)
        values = {policy_key(policy): policy}
        signal = signal_record(
            "scope-a", "policy-a", 7, 100, "reverse_shell_pattern",
            signal_pb2.SIGNAL_STAGE_CONCLUSION,
        )

        with mock.patch.object(module, "analyze", wraps=module.analyze) as analyze:
            state.process(signal, 0, values)

        delta = analyze.call_args.kwargs["delta"]
        self.assertEqual((signal.signal,), delta.new_signals)
        self.assertEqual((), delta.new_events)
        self.assertTrue(delta.graph_rebuilt)

    def test_analysis_delta_reports_expired_signal_refs(self):
        module = load_state()
        state = module.DetectionState()
        policy = detection_policy("tenant-a", "policy-a", 7, state_retention_ns=10)
        values = {policy_key(policy): policy}
        first = signal_record("scope-a", "policy-a", 7, 100, "first", signal_pb2.SIGNAL_STAGE_CANDIDATE)
        second = signal_record("scope-a", "policy-a", 7, 120, "second", signal_pb2.SIGNAL_STAGE_CANDIDATE)

        state.process(first, 0, values)
        with mock.patch.object(module, "analyze", wraps=module.analyze) as analyze:
            state.process(second, 0, values)

        delta = analyze.call_args.kwargs["delta"]
        self.assertEqual((first.signal.id,), delta.expired_signal_refs)
        self.assertEqual((second.signal,), delta.new_signals)

    def test_timer_expiry_delta_is_delivered_to_next_analysis(self):
        module = load_state()
        state = module.DetectionState()
        policy = detection_policy("tenant-a", "policy-a", 7, state_retention_ns=10)
        values = {policy_key(policy): policy}
        first = signal_record("scope-a", "policy-a", 7, 100, "first", signal_pb2.SIGNAL_STAGE_CANDIDATE)
        state.process(first, 0, values)
        state.cleanup("scope-a", 120, policy)
        second = signal_record("scope-a", "policy-a", 7, 130, "second", signal_pb2.SIGNAL_STAGE_CANDIDATE)

        with mock.patch.object(module, "analyze", wraps=module.analyze) as analyze:
            state.process(second, 0, values)

        delta = analyze.call_args.kwargs["delta"]
        self.assertEqual((first.signal.id,), delta.expired_signal_refs)
        self.assertTrue(delta.graph_rebuilt)

    def test_incremental_graph_matches_forced_full_rebuild(self):
        incremental = load_state().DetectionState()
        full = load_state().DetectionState()
        policy = detection_policy("tenant-a", "policy-a", 7, state_retention_ns=10_000)
        policy.detection.endpoint_rules.extend(["payload_dropped", "suspicious_exec_connect"])
        policy.detection.converge.cross_lineage = True
        values = {policy_key(policy): policy}
        records = causal_records()

        incremental_artifacts = []
        full_artifacts = []
        for record in records:
            incremental_artifacts.extend(incremental.process(record, 0, values).artifacts)
            if "scope-a" in full._scopes:
                full._scopes["scope-a"].graph = None
            full_artifacts.extend(full.process(record, 0, values).artifacts)

        self.assertEqual(
            [item.SerializeToString(deterministic=True) for item in full_artifacts],
            [item.SerializeToString(deterministic=True) for item in incremental_artifacts],
        )

    def test_missing_exact_policy_fails_without_state_mutation(self):
        state = load_state().DetectionState()
        record = event_record("scope-a", "policy-a", 7, 100, "event-a")

        result = state.process(record, watermark_ns=0, policies={})

        self.assertEqual("policy_version_unavailable", result.failure.reason_code)
        self.assertTrue(result.failure.retryable)
        self.assertEqual(0, state.event_count("scope-a"))
        self.assertEqual((), result.artifacts)

    def test_event_and_signal_share_scope_and_emit_analysis_artifacts(self):
        state = load_state().DetectionState()
        policy = detection_policy("tenant-a", "policy-a", 7)
        event = event_record("scope-a", "policy-a", 7, 100, "event-a")
        signal = signal_record(
            "scope-a",
            "policy-a",
            7,
            110,
            "reverse_shell_pattern",
            stage=signal_pb2.SIGNAL_STAGE_CONCLUSION,
        )

        first = state.process(event, watermark_ns=0, policies={policy_key(policy): policy})
        second = state.process(signal, watermark_ns=0, policies={policy_key(policy): policy})

        self.assertIsNone(first.failure)
        self.assertEqual(1, state.event_count("scope-a"))
        self.assertEqual(1, state.signal_count("scope-a"))
        self.assertTrue(any(item.WhichOneof("payload") == "incident" for item in second.artifacts))

    def test_endpoint_candidate_is_projected_as_analysis_artifact(self):
        state = load_state().DetectionState()
        policy = detection_policy("tenant-a", "policy-a", 7)
        candidate = signal_record(
            "scope-a", "policy-a", 7, 110, "model_anomaly",
            stage=signal_pb2.SIGNAL_STAGE_CANDIDATE,
        )
        candidate.signal.detector_kind = signal_pb2.DETECTOR_KIND_MODEL
        candidate.signal.where = signal_pb2.SIGNAL_WHERE_ENDPOINT

        result = state.process(candidate, watermark_ns=0, policies={policy_key(policy): policy})

        projected = [item.signal for item in result.artifacts if item.WhichOneof("payload") == "signal"]
        self.assertTrue(any(item.id == candidate.signal.id for item in projected))

    def test_late_record_is_side_output_and_does_not_mutate_detection_state(self):
        state = load_state().DetectionState()
        policy = detection_policy("tenant-a", "policy-a", 7)
        record = event_record("scope-a", "policy-a", 7, 100, "event-late")

        result = state.process(record, watermark_ns=101, policies={policy_key(policy): policy})

        self.assertIsNone(result.failure)
        self.assertEqual(100, result.late.telemetry.event.occurred_at_ns)
        self.assertEqual(101, result.late.watermark_unix_nano)
        self.assertEqual(0, state.event_count("scope-a"))

    def test_window_eviction_removes_old_events_before_next_analysis(self):
        state = load_state().DetectionState()
        policy = detection_policy("tenant-a", "policy-a", 7, state_retention_ns=10)
        values = {policy_key(policy): policy}

        state.process(event_record("scope-a", "policy-a", 7, 100, "old"), 0, values)
        state.process(event_record("scope-a", "policy-a", 7, 120, "new"), 0, values)

        self.assertEqual(1, state.event_count("scope-a"))
        self.assertEqual({"new"}, state.event_ids("scope-a"))

    def test_scope_capacity_is_bounded_independently_of_retention_window(self):
        state = load_state().DetectionState(max_scope_records=2)
        policy = detection_policy("tenant-a", "policy-a", 7, state_retention_ns=1000)
        values = {policy_key(policy): policy}

        for observed, event_id in ((100, "first"), (110, "second"), (120, "third")):
            state.process(
                event_record("scope-a", "policy-a", 7, observed, event_id), 0, values
            )

        self.assertEqual({"second", "third"}, state.event_ids("scope-a"))

    def test_duplicate_ids_cannot_bypass_scope_capacity(self):
        state = load_state().DetectionState(max_scope_records=2)
        policy = detection_policy("tenant-a", "policy-a", 7, state_retention_ns=1000)
        values = {policy_key(policy): policy}

        for observed in (100, 110, 120):
            state.process(event_record("scope-a", "policy-a", 7, observed, "same"), 0, values)

        self.assertEqual(2, state.event_count("scope-a"))

    def test_restore_marks_unsorted_persistent_records_for_rewrite(self):
        module = load_state()
        state = module.DetectionState()
        policy = detection_policy("tenant-a", "policy-a", 7)
        values = {policy_key(policy): policy}
        later = event_record("scope-a", "policy-a", 7, 120, "later")
        earlier = event_record("scope-a", "policy-a", 7, 100, "earlier")
        state.restore("scope-a", [later, earlier], values)

        candidate = signal_record("scope-a", "policy-a", 7, 130, "model_anomaly", signal_pb2.SIGNAL_STAGE_CANDIDATE)
        candidate.signal.detector_kind = signal_pb2.DETECTOR_KIND_MODEL
        result = state.process(candidate, 0, values)

        self.assertTrue(result.state_rewrite_required)

    def test_mixed_policy_retention_expires_each_record_independently(self):
        state = load_state().DetectionState()
        long_policy = detection_policy("tenant-a", "policy-a", 7, state_retention_ns=1_000)
        short_policy = detection_policy("tenant-a", "policy-b", 8, state_retention_ns=10)
        values = {policy_key(long_policy): long_policy, policy_key(short_policy): short_policy}

        state.process(
            event_record("scope-a", "policy-a", 7, 100, "long"), 0, values
        )
        state.process(
            event_record("scope-a", "policy-b", 8, 100, "short"), 0, values
        )
        state.cleanup("scope-a", 120, long_policy)

        self.assertEqual({"long"}, state.event_ids("scope-a"))

    def test_established_incident_is_not_reemitted_for_unrelated_event(self):
        state = load_state().DetectionState()
        policy = detection_policy("tenant-a", "policy-a", 7)
        values = {policy_key(policy): policy}
        conclusion = signal_record(
            "scope-a",
            "policy-a",
            7,
            100,
            "reverse_shell_pattern",
            signal_pb2.SIGNAL_STAGE_CONCLUSION,
        )

        first = state.process(conclusion, 0, values)
        second = state.process(
            event_record("scope-a", "policy-a", 7, 110, "unrelated"), 0, values
        )

        self.assertEqual(2, len(first.artifacts))
        self.assertEqual((), second.artifacts)
        self.assertEqual(2, len(state.emissions("scope-a")))


def detection_policy(tenant, policy_id, version, state_retention_ns=1000):
    return streaming_pb2.DetectionPolicySnapshot(
        schema_version="sysarmor.detection.policy/v1",
        tenant_id=tenant,
        policy_id=policy_id,
        policy_version=version,
        detection=policy_pb2.DetectionPolicy(
            endpoint_rules=["reverse_shell_pattern"],
            converge=policy_pb2.ConvergeParams(state_retention_ns=state_retention_ns),
            rarity=policy_pb2.RarityParams(baseline_window_ns=86_400_000_000_000),
        ),
    )


def policy_key(policy):
    return (policy.tenant_id, policy.policy_id, policy.policy_version)


def context(scope, policy_id, version, observed):
    return streaming_pb2.RecordContext(
        tenant_id="tenant-a",
        agent_id="agent-a",
        host_id="host-a",
        batch_id="batch-a",
        policy_id=policy_id,
        policy_version=version,
        policy_mode="rule-only",
        observed_at_unix_nano=observed,
        analysis_scope_key=scope,
    )


def event_record(scope, policy_id, version, observed, event_id):
    return streaming_pb2.NormalizedTelemetry(
        schema_version="sysarmor.telemetry.normalized/v1",
        context=context(scope, policy_id, version, observed),
        event=event_pb2.CanonicalEvent(
            id=event_id,
            tenant_id="tenant-a",
            occurred_at_ns=observed,
            behavior="process.exec",
            subject_proc=event_pb2.ProcessRef(stable_id="p-bash"),
        ),
    )


def signal_record(scope, policy_id, version, observed, name, stage):
    return streaming_pb2.NormalizedTelemetry(
        schema_version="sysarmor.telemetry.normalized/v1",
        context=context(scope, policy_id, version, observed),
        signal=signal_pb2.Signal(
            id="signal-" + name,
            name=name,
            where=signal_pb2.SIGNAL_WHERE_ENDPOINT,
            detector_kind=signal_pb2.DETECTOR_KIND_RULE,
            stage=stage,
            entities=[signal_pb2.EntityRef(kind="process", key="p-bash", role="subject")],
        ),
    )


def causal_records():
    dropped = signal_record("scope-a", "policy-a", 7, 100, "payload_dropped", signal_pb2.SIGNAL_STAGE_CANDIDATE)
    dropped.signal.lineage_id = "lin-a"
    dropped.signal.ClearField("entities")
    dropped.signal.entities.add(kind="file", key="/dev/shm/x.sh", role="object")
    connected = signal_record("scope-a", "policy-a", 7, 110, "suspicious_exec_connect", signal_pb2.SIGNAL_STAGE_CANDIDATE)
    connected.signal.lineage_id = "lin-b"
    connected.signal.ClearField("entities")
    connected.signal.entities.add(kind="socket", key="10.66.0.99:443", role="object")
    events = []
    for observed, event_id, behavior, subject, parent, path, address in (
        (120, "write", "file.write", "p-a", "", "/dev/shm/x.sh", ""),
        (130, "fork", "process.fork", "p-b", "p-a", "", ""),
        (140, "connect", "network.connect", "p-b", "", "", "10.66.0.99:443"),
    ):
        record = event_record("scope-a", "policy-a", 7, observed, event_id)
        record.event.behavior = behavior
        record.event.subject_proc.stable_id = subject
        record.event.parent_stable_id = parent
        record.event.object.file_path = path
        record.event.object.socket_addr = address
        events.append(record)
    return [dropped, connected, *events]


if __name__ == "__main__":
    unittest.main()
