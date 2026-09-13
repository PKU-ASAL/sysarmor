import unittest
from unittest import mock

from packages.contracts.proto.event.v1 import event_pb2
from packages.contracts.proto.streaming.v1 import streaming_pb2

from streaming.jobs import detection
from tests.test_detection_state import (
    detection_policy,
    event_record,
    signal_record,
)
from packages.contracts.proto.signal.v1 import signal_pb2


class DetectionFunctionTest(unittest.TestCase):
    def test_model_candidate_metric_predicate_uses_signal_contract(self):
        candidate = signal_pb2.Signal(
            detector_kind=signal_pb2.DETECTOR_KIND_MODEL,
            stage=signal_pb2.SIGNAL_STAGE_CANDIDATE,
        )
        conclusion = signal_pb2.Signal(
            detector_kind=signal_pb2.DETECTOR_KIND_GRAPH,
            stage=signal_pb2.SIGNAL_STAGE_CONCLUSION,
        )
        self.assertTrue(detection._is_model_candidate(candidate))
        self.assertFalse(detection._is_model_candidate(conclusion))

    def test_windowed_function_keeps_crossing_batch_in_separate_window_entries(self):
        first = event_record("scope-a", "policy-a", 7, 100, "event-a")
        second = event_record("scope-a", "policy-a", 7, 10_000_000_100, "event-b")
        grouped = detection._group_window_records((first, second), 10_000_000_000)
        self.assertEqual({0, 10_000_000_000}, set(grouped))
        self.assertEqual(("event-a",), tuple(item.event.id for item in grouped[0]))

    def test_windowed_function_buffers_until_event_time_timer(self):
        function, runtime = opened_windowed_function()
        policy = detection_policy("tenant-a", "policy-a", 7)
        context = ReadContext(
            {detection.policy_key(policy): policy.SerializeToString()}, watermark_ms=0
        )
        record = event_record("scope-a", "policy-a", 7, 100, "event-a")

        self.assertEqual([], list(function.process_element(
            input_bytes(record), context
        )))
        self.assertEqual(1, len(runtime._list_state("window-buffer").values))
        self.assertEqual(1, runtime.get_state(detection.WINDOW_BUFFER_COUNT_STATE).value())
        list(function.on_timer(10_000, context))
        self.assertEqual([], runtime._list_state("window-buffer").values)
        self.assertEqual(0, runtime.get_state(detection.WINDOW_BUFFER_COUNT_STATE).value())

    def test_windowed_function_flushes_previous_window_before_switching(self):
        function, runtime = opened_windowed_function()
        policy = detection_policy("tenant-a", "policy-a", 7)
        context = ReadContext(
            {detection.policy_key(policy): policy.SerializeToString()}, watermark_ms=0
        )
        first = event_record("scope-a", "policy-a", 7, 100, "event-a")
        second = event_record("scope-a", "policy-a", 7, 10_000_100_000, "event-b")
        list(function.process_element(input_bytes(first), context))
        list(function.process_element(input_bytes(second), context))
        self.assertEqual(1, function.metrics()["batches"])
        self.assertEqual(1, len(runtime._list_state("window-buffer").values))
    def test_detection_function_reports_batch_metrics(self):
        function, _ = opened_function()
        self.assertEqual(
            {"batches": 0, "records": 0, "analysis_ms": 0.0},
            function.metrics(),
        )
    def test_single_normalized_record_is_rejected(self):
        function, _ = opened_function()
        policy = detection_policy("tenant-a", "policy-a", 7)
        context = ReadContext(
            {detection.policy_key(policy): policy.SerializeToString()}, watermark_ms=0
        )
        output = list(
            function.process_element(
                event_record("scope-a", "policy-a", 7, 100, "event-a").SerializeToString(),
                context,
            )
        )
        self.assertEqual(detection.FAILURE_TAG.tag_id, output[0][0].tag_id)
        failure = streaming_pb2.DetectionFailure.FromString(output[0][1])
        self.assertEqual("invalid_normalized_telemetry", failure.reason_code)

    def test_normalized_batch_is_processed_once(self):
        function, runtime = opened_function()
        policy = detection_policy("tenant-a", "policy-a", 7)
        context = ReadContext(
            {detection.policy_key(policy): policy.SerializeToString()},
            watermark_ms=0,
        )
        first = event_record("scope-a", "policy-a", 7, 100, "first")
        second = event_record("scope-a", "policy-a", 7, 110, "second")
        signal = signal_record(
            "scope-a", "policy-a", 7, 120, "reverse_shell_pattern",
            signal_pb2.SIGNAL_STAGE_CONCLUSION,
        )
        batch = streaming_pb2.NormalizedTelemetryBatch(
            schema_version="sysarmor.telemetry.normalized.batch/v1",
            tenant_id="tenant-a",
            agent_id="agent-a",
            host_id="host-a",
            batch_id="batch-a",
            policy_id="policy-a",
            policy_version=7,
            policy_mode="rule-only",
            records=[first, second, signal],
        )

        with mock.patch.object(
            detection.DetectionState,
            "process_batch",
            autospec=True,
            side_effect=detection.DetectionState.process_batch,
        ) as process_batch:
            list(function.process_element(batch.SerializeToString(), context))

        self.assertEqual(1, process_batch.call_count)
        self.assertEqual(3, len(runtime.state.values))

    def test_normalized_batch_filters_late_records_individually(self):
        function, runtime = opened_function()
        policy = detection_policy("tenant-a", "policy-a", 7)
        context = ReadContext(
            {detection.policy_key(policy): policy.SerializeToString()},
            watermark_ms=2,
        )
        late = event_record("scope-a", "policy-a", 7, 2_000_000, "late")
        current = event_record("scope-a", "policy-a", 7, 3_000_000, "current")
        batch = streaming_pb2.NormalizedTelemetryBatch(
            schema_version="sysarmor.telemetry.normalized.batch/v1",
            tenant_id="tenant-a",
            agent_id="agent-a",
            host_id="host-a",
            batch_id="batch-a",
            policy_id="policy-a",
            policy_version=7,
            records=[late, current],
        )

        output = list(function.process_element(batch.SerializeToString(), context))

        self.assertEqual(detection.LATE_TAG.tag_id, output[0][0].tag_id)
        self.assertEqual(1, len(runtime.state.values))

    def test_rarity_batch_filters_late_signals_individually(self):
        runtime = RuntimeContext()
        function = detection.RarityFunction()
        function.open(runtime)
        policy = detection_policy("tenant-a", "policy-a", 7)
        policy.detection.rarity.baseline_window_ns = 1_000_000_000
        context = ReadContext(
            {detection.policy_key(policy): policy.SerializeToString()},
            watermark_ms=2,
        )
        late = signal_record(
            "scope-a", "policy-a", 7, 2_000_000, "late",
            signal_pb2.SIGNAL_STAGE_CANDIDATE,
        )
        current = signal_record(
            "scope-a", "policy-a", 7, 3_000_000, "current",
            signal_pb2.SIGNAL_STAGE_CANDIDATE,
        )
        batch = streaming_pb2.NormalizedTelemetryBatch(
            schema_version="sysarmor.telemetry.normalized.batch/v1",
            tenant_id="tenant-a",
            agent_id="agent-a",
            host_id="host-a",
            batch_id="batch-a",
            policy_id="policy-a",
            policy_version=7,
            records=[late, current],
        )

        output = list(function.process_element(batch.SerializeToString(), context))

        self.assertEqual(detection.LATE_TAG.tag_id, output[0][0].tag_id)
        processed = streaming_pb2.NormalizedTelemetryBatch.FromString(output[1])
        processed = processed.records[0]
        self.assertEqual("current", processed.signal.name)
        self.assertEqual(1, runtime._list_state("rarity-observations").values.__len__())
    def test_detection_coalesces_cleanup_timers_per_second(self):
        function, _ = opened_function()
        policy = detection_policy(
            "tenant-a", "policy-a", 7, state_retention_ns=10_000_000
        )
        context = ReadContext(
            {detection.policy_key(policy): policy.SerializeToString()},
            watermark_ms=0,
        )

        for observed, event_id in (
            (1_000_000, "first"),
            (2_000_000, "second"),
            (3_000_000, "third"),
        ):
            list(
                function.process_element(
                    input_bytes(event_record(
                        "scope-a", "policy-a", 7, observed, event_id
                    )),
                    context,
                )
            )

        self.assertEqual([1_000], context.timer_service().timers)

    def test_detection_timer_uses_cached_scope_without_list_state_restore(self):
        function, runtime = opened_function()
        policy = detection_policy(
            "tenant-a", "policy-a", 7, state_retention_ns=1_000_000
        )
        context = ReadContext(
            {detection.policy_key(policy): policy.SerializeToString()},
            watermark_ms=0,
        )
        candidate = signal_record(
            "scope-a", "policy-a", 7, 1_000_000, "model_anomaly",
            signal_pb2.SIGNAL_STAGE_CANDIDATE,
        )
        candidate.signal.detector_kind = signal_pb2.DETECTOR_KIND_MODEL
        list(function.process_element(input_bytes(candidate), context))
        restores_before_timer = runtime.state.get_calls

        function.on_timer(2, context)

        self.assertEqual(restores_before_timer, runtime.state.get_calls)

    def test_detector_cache_evicts_least_recently_used_scope(self):
        function = detection.DetectionFunction(max_cached_scopes=2)
        first, second, third = object(), object(), object()

        function._cache_detector("first", first, {})
        function._cache_detector("second", second, {})
        function._cached_detector("first")
        function._cache_detector("third", third, {})

        self.assertEqual(["first", "third"], list(function._detectors))
        self.assertNotIn("second", function._detector_policies)

    def test_detector_cache_bounds_total_cached_records(self):
        function = detection.DetectionFunction(
            max_cached_scopes=10, max_cached_records=3
        )

        function._cache_detector("first", object(), {}, record_count=2)
        function._cache_detector("second", object(), {}, record_count=2)

        self.assertEqual(["second"], list(function._detectors))
        self.assertEqual(2, sum(function._cached_record_counts.values()))

    def test_event_without_signal_uses_job_fast_path(self):
        function, runtime = opened_function()
        policy = detection_policy("tenant-a", "policy-a", 7)
        context = ReadContext(
            {detection.policy_key(policy): policy.SerializeToString()},
            watermark_ms=0,
        )

        list(
            function.process_element(
                input_bytes(event_record(
                    "scope-a", "policy-a", 7, 100, "event-a"
                )),
                context,
            )
        )

        self.assertEqual({}, function._detectors)
        self.assertEqual(1, len(runtime.state.values))

    def test_event_after_model_signal_runs_nodlink_graph_analysis(self):
        function, runtime = opened_function()
        policy = detection_policy("tenant-a", "policy-a", 7)
        context = ReadContext(
            {detection.policy_key(policy): policy.SerializeToString()},
            watermark_ms=0,
        )
        candidate = signal_record(
            "scope-a", "policy-a", 7, 100, "model_anomaly",
            signal_pb2.SIGNAL_STAGE_CANDIDATE,
        )
        candidate.signal.detector_kind = signal_pb2.DETECTOR_KIND_MODEL
        list(function.process_element(input_bytes(candidate), context))
        list(
            function.process_element(
                input_bytes(event_record(
                    "scope-a", "policy-a", 7, 110, "event-a"
                )),
                context,
            )
        )

        self.assertEqual(1, len(function._detectors))
        self.assertEqual(2, len(runtime.state.values))

    def test_timer_removes_expired_detector_state_from_managed_state(self):
        contracts = __import__(
            "streaming.detectors.contracts", fromlist=["DetectorInputs"]
        )

        class Stateful:
            name = "stateful"
            version = "1"
            required_inputs = (contracts.RequiredInput.SIGNAL,)
            state_requirements = contracts.StateRequirements(
                keyed=True, ttl_ns=1_000_000, version=1
            )

            def analyze(self, inputs):
                return contracts.DetectionResult(
                    self.name, self.version, state_update=b"state"
                )

        function, runtime = opened_function()
        policy = detection_policy(
            "tenant-a", "policy-a", 7, state_retention_ns=10_000_000
        )
        context = ReadContext(
            {detection.policy_key(policy): policy.SerializeToString()},
            watermark_ms=0,
        )
        record = signal_record(
            "scope-a", "policy-a", 7, 1_000_000, "first",
            signal_pb2.SIGNAL_STAGE_CANDIDATE,
        )
        with mock.patch.object(detection.DetectorRegistry, "build", return_value=[Stateful()]):
            list(function.process_element(input_bytes(record), context))
            function.on_timer(2, context)

        self.assertNotEqual([], runtime.state.values)
        self.assertEqual({}, runtime._map_state("detector-states").values)
        self.assertEqual({}, runtime._map_state("detector-state-expiries").values)

    def test_state_upgrade_removes_old_managed_state_version(self):
        contracts = __import__(
            "streaming.detectors.contracts", fromlist=["DetectorInputs"]
        )

        class StatefulV2:
            name = "stateful"
            version = "2"
            required_inputs = (contracts.RequiredInput.SIGNAL,)
            state_requirements = contracts.StateRequirements(keyed=True, version=2)

            def analyze(self, inputs):
                return contracts.DetectionResult(
                    self.name, self.version, state_update=b"version-2"
                )

        function, runtime = opened_function()
        runtime._map_state("detector-states").values["stateful@1/state-1"] = b"version-1"
        runtime._map_state("detector-state-expiries").values["stateful@1/state-1"] = 10_000
        policy = detection_policy("tenant-a", "policy-a", 7)
        context = ReadContext(
            {detection.policy_key(policy): policy.SerializeToString()}, watermark_ms=0
        )
        record = signal_record(
            "scope-a", "policy-a", 7, 100, "first",
            signal_pb2.SIGNAL_STAGE_CANDIDATE,
        )
        with mock.patch.object(
            detection.DetectorRegistry, "build", return_value=[StatefulV2()]
        ):
            list(function.process_element(input_bytes(record), context))

        self.assertEqual(
            {"stateful@2/state-2": b"version-2"},
            runtime._map_state("detector-states").values,
        )
        self.assertEqual(
            {"stateful@2/state-2": 1_100},
            runtime._map_state("detector-state-expiries").values,
        )

    def test_detector_state_survives_function_restore(self):
        contracts = __import__("streaming.detectors.contracts", fromlist=["DetectorInputs"])

        class Stateful:
            name = "stateful"
            version = "1"
            required_inputs = (contracts.RequiredInput.SIGNAL,)
            state_requirements = contracts.StateRequirements(keyed=True, version=1)

            def analyze(self, inputs):
                value = int(inputs.detector_state or b"0") + 1
                return contracts.DetectionResult(self.name, self.version, state_update=str(value).encode())

        runtime = RuntimeContext()
        policy = detection_policy("tenant-a", "policy-a", 7)
        context = ReadContext({detection.policy_key(policy): policy.SerializeToString()}, watermark_ms=0)
        first = detection.DetectionFunction()
        first.open(runtime)
        with mock.patch.object(detection.DetectorRegistry, "build", return_value=[Stateful()]):
            list(first.process_element(input_bytes(signal_record("scope-a", "policy-a", 7, 100, "first", signal_pb2.SIGNAL_STAGE_CANDIDATE)), context))
            restored = detection.DetectionFunction()
            restored.open(runtime)
            list(restored.process_element(input_bytes(signal_record("scope-a", "policy-a", 7, 110, "second", signal_pb2.SIGNAL_STAGE_CANDIDATE)), context))

        self.assertEqual(b"2", runtime._map_state("detector-states").values["stateful@1/state-1"])
    def test_detection_state_is_restored_once_per_scope_after_signal(self):
        function, runtime = opened_function()
        policy = detection_policy("tenant-a", "policy-a", 7)
        policies = {detection.policy_key(policy): policy.SerializeToString()}
        context = ReadContext(policies, watermark_ms=0)

        original_restore = detection.DetectionState.restore
        with mock.patch.object(
            detection.DetectionState,
            "restore",
            autospec=True,
            side_effect=original_restore,
        ) as restore:
            list(function.process_element(input_bytes(event_record("scope-a", "policy-a", 7, 100, "event-a")), context))
            candidate = signal_record("scope-a", "policy-a", 7, 110, "model_anomaly", signal_pb2.SIGNAL_STAGE_CANDIDATE)
            candidate.signal.detector_kind = signal_pb2.DETECTOR_KIND_MODEL
            candidate.signal.where = signal_pb2.SIGNAL_WHERE_ENDPOINT
            list(function.process_element(input_bytes(candidate), context))
            list(function.process_element(input_bytes(event_record("scope-a", "policy-a", 7, 120, "event-b")), context))

        self.assertEqual(1, restore.call_count)
        self.assertEqual(0, runtime.state.update_calls)

    def test_out_of_order_record_rewrites_state_to_preserve_record_order(self):
        function, runtime = opened_function()
        policy = detection_policy("tenant-a", "policy-a", 7)
        context = ReadContext({detection.policy_key(policy): policy.SerializeToString()}, watermark_ms=0)
        candidate = signal_record("scope-a", "policy-a", 7, 120, "model_anomaly", signal_pb2.SIGNAL_STAGE_CANDIDATE)
        candidate.signal.detector_kind = signal_pb2.DETECTOR_KIND_MODEL
        candidate.signal.where = signal_pb2.SIGNAL_WHERE_ENDPOINT

        list(function.process_element(input_bytes(event_record("scope-a", "policy-a", 7, 100, "event-a")), context))
        list(function.process_element(input_bytes(candidate), context))
        list(function.process_element(input_bytes(event_record("scope-a", "policy-a", 7, 110, "event-b")), context))

        self.assertEqual(1, runtime.state.update_calls)

    def test_cache_is_isolated_by_tenant_and_scope(self):
        function, _ = opened_function()
        first_policy = detection_policy("tenant-a", "policy-a", 7)
        second_policy = detection_policy("tenant-b", "policy-b", 8)
        policies = {
            detection.policy_key(first_policy): first_policy.SerializeToString(),
            detection.policy_key(second_policy): second_policy.SerializeToString(),
        }
        context = ReadContext(policies, watermark_ms=0)
        first = signal_record("scope-a", "policy-a", 7, 100, "first", signal_pb2.SIGNAL_STAGE_CANDIDATE)
        second = signal_record("scope-a", "policy-b", 8, 110, "second", signal_pb2.SIGNAL_STAGE_CANDIDATE)
        second.context.tenant_id = "tenant-b"
        second.signal.detector_kind = signal_pb2.DETECTOR_KIND_MODEL

        list(function.process_element(input_bytes(first), context))
        list(function.process_element(input_bytes(second), context))

        self.assertEqual(2, len(function._detectors))

    def test_timer_does_not_cache_event_only_state(self):
        function, runtime = opened_function()
        policy = detection_policy("tenant-a", "policy-a", 7, state_retention_ns=10_000_000)
        context = ReadContext({detection.policy_key(policy): policy.SerializeToString()}, watermark_ms=0)
        list(function.process_element(input_bytes(event_record("scope-a", "policy-a", 7, 100_000_000, "event-a")), context))
        list(function.process_element(input_bytes(event_record("scope-a", "policy-a", 7, 105_000_000, "event-b")), context))

        function.on_timer(111, context)
        list(function.process_element(input_bytes(event_record("scope-a", "policy-a", 7, 120_000_000, "event-c")), context))
        function.on_timer(116, context)

        retained = [
            streaming_pb2.NormalizedTelemetry.FromString(value).event.id
            for value in runtime.state.values
        ]
        self.assertEqual(["event-c"], retained)

    def test_job_fast_path_is_disabled_for_graph_detector(self):
        function, _ = opened_function()
        policy = detection_policy("tenant-a", "policy-a", 7)
        context = ReadContext({detection.policy_key(policy): policy.SerializeToString()}, watermark_ms=0)
        record = event_record("agent-a", "policy-a", 7, 100, "event-a")

        with mock.patch.object(detection.DetectorRegistry, "affected_by", return_value=True), mock.patch.object(
            function, "_restore_detector", wraps=function._restore_detector
        ) as restore:
            list(function.process_element(input_bytes(record), context))

        self.assertEqual(1, restore.call_count)

    def test_job_fast_path_is_available_for_signal_only_detectors(self):
        function, _ = opened_function()
        record = event_record("scope-a", "policy-a", 7, 100, "event-a")

        with mock.patch.object(
            detection.DetectorRegistry, "affected_by", return_value=False
        ) as affected_by:
            available = function._can_append_event(record)

        self.assertTrue(available)
        affected_by.assert_called_once_with(
            frozenset(
                {
                    detection.RequiredInput.NORMALIZED_EVENT,
                    detection.RequiredInput.PROVENANCE_EDGE,
                }
            ),
            frozenset(
                {
                    detection.RequiredInput.NORMALIZED_EVENT,
                    detection.RequiredInput.PROVENANCE_EDGE,
                }
            ),
            frozenset(),
        )

    def test_job_fast_path_is_disabled_when_scope_cache_exists(self):
        function, _ = opened_function()
        policy = detection_policy("tenant-a", "policy-a", 7)
        context = ReadContext({detection.policy_key(policy): policy.SerializeToString()}, watermark_ms=0)
        record = event_record("scope-a", "policy-a", 7, 100, "event-a")
        function._detectors[detection._cache_key(record)] = object()

        self.assertFalse(function._can_append_event(record))

    def test_validation_routes_permanent_bad_input_to_failure_output(self):
        output = list(detection.ValidateTelemetryFunction().process_element(b"bad", None))

        tag, value = output[0]
        failure = streaming_pb2.DetectionFailure.FromString(value)
        self.assertEqual(detection.FAILURE_TAG.tag_id, tag.tag_id)
        self.assertFalse(failure.retryable)
        self.assertEqual("invalid_normalized_telemetry", failure.reason_code)

    def test_validation_keeps_valid_normalized_batch_on_main_output(self):
        record = event_record("agent-a", "policy-a", 7, 100, "event-a")
        batch = normalized_batch([record])

        output = list(
            detection.ValidateTelemetryFunction().process_element(
                batch.SerializeToString(), None
            )
        )

        normalized = streaming_pb2.NormalizedTelemetryBatch.FromString(output[0])
        self.assertEqual([record.SerializeToString()], [item.SerializeToString() for item in normalized.records])

    def test_validation_rejects_scope_that_does_not_match_agent(self):
        record = event_record("forged-scope", "policy-a", 7, 100, "event-a")
        batch = normalized_batch([record])

        output = list(
            detection.ValidateTelemetryFunction().process_element(
                batch.SerializeToString(), None
            )
        )

        failure = streaming_pb2.DetectionFailure.FromString(output[0][1])
        self.assertEqual("normalized_scope_mismatch", failure.reason_code)

    def test_broadcast_policy_and_keyed_records_produce_artifact(self):
        function, runtime = opened_function()
        policy = detection_policy("tenant-a", "policy-a", 7)
        broadcast = BroadcastContext()
        function.process_broadcast_element(policy.SerializeToString(), broadcast)
        context = ReadContext(broadcast.state, watermark_ms=0)

        first = list(function.process_element(
            input_bytes(event_record("scope-a", "policy-a", 7, 100, "event-a")),
            context,
        ))
        second = list(function.process_element(
            input_bytes(signal_record(
                "scope-a",
                "policy-a",
                7,
                110,
                "reverse_shell_pattern",
                signal_pb2.SIGNAL_STAGE_CONCLUSION,
            )),
            context,
        ))

        self.assertEqual([], first)
        self.assertEqual(2, len(runtime.state.values))
        artifacts = [streaming_pb2.AnalysisArtifact.FromString(value) for value in second]
        self.assertTrue(any(item.WhichOneof("payload") == "incident" for item in artifacts))

    def test_missing_policy_fails_job_without_advancing_state(self):
        function, runtime = opened_function()
        record = event_record("scope-a", "policy-a", 7, 100, "event-a")

        with self.assertRaisesRegex(
            detection.PolicyVersionUnavailable, "tenant-a/policy-a/7"
        ):
            list(function.process_element(
                input_bytes(record), ReadContext({}, watermark_ms=0)
            ))

        self.assertEqual([], runtime.state.values)

    def test_late_record_uses_late_side_output_without_state(self):
        function, runtime = opened_function()
        policy = detection_policy("tenant-a", "policy-a", 7)
        state = {detection.policy_key(policy): policy.SerializeToString()}
        record = event_record("scope-a", "policy-a", 7, 100, "event-a")

        output = list(function.process_element(
            input_bytes(record), ReadContext(state, watermark_ms=1, timestamp_ms=0)
        ))

        tag, value = output[0]
        late = streaming_pb2.LateTelemetry.FromString(value)
        self.assertEqual(detection.LATE_TAG.tag_id, tag.tag_id)
        self.assertEqual(1_000_000, late.watermark_unix_nano)
        self.assertEqual([], runtime.state.values)

    def test_stream_key_includes_tenant_and_scope(self):
        record = event_record("scope-a", "policy-a", 7, 100, "event-a")

        self.assertEqual(
            "tenant-a\x00scope-a",
            detection.telemetry_key(input_bytes(record)),
        )

    def test_stream_key_keeps_scope_across_policy_versions(self):
        first = event_record("scope-a", "policy-a", 7, 100, "event-a")
        second = event_record("scope-a", "policy-a", 8, 100, "event-a")

        self.assertEqual(
            detection.telemetry_key(input_bytes(first)),
            detection.telemetry_key(input_bytes(second)),
        )

    def test_timestamp_assigner_uses_event_time_in_milliseconds(self):
        record = event_record(
            "scope-a", "policy-a", 7, 1_700_000_000_123_456_789, "event-a"
        )

        timestamp = detection.TelemetryTimestampAssigner().extract_timestamp(
            input_bytes(record), -1
        )

        self.assertEqual(1_700_000_000_123, timestamp)

    def test_invalid_policy_snapshot_fails_job_instead_of_entering_state(self):
        function, _ = opened_function()
        invalid = streaming_pb2.DetectionPolicySnapshot(
            schema_version="wrong", tenant_id="tenant-a", policy_id="policy-a", policy_version=7
        )

        with self.assertRaisesRegex(ValueError, "unsupported detection policy schema"):
            function.process_broadcast_element(
                invalid.SerializeToString(), BroadcastContext()
            )

    def test_checkpoint_restored_emission_state_prevents_duplicate_incident(self):
        function, runtime = opened_function()
        policy = detection_policy("tenant-a", "policy-a", 7)
        policies = {detection.policy_key(policy): policy.SerializeToString()}
        context = ReadContext(policies, watermark_ms=0)
        conclusion = signal_record(
            "scope-a",
            "policy-a",
            7,
            100,
            "reverse_shell_pattern",
            signal_pb2.SIGNAL_STAGE_CONCLUSION,
        )
        list(function.process_element(input_bytes(conclusion), context))
        self.assertNotEqual([], runtime._list_state("emitted-artifacts").values)

        restored = detection.DetectionFunction()
        restored.open(runtime)
        output = list(
            restored.process_element(
                input_bytes(signal_record(
                    "scope-a",
                    "policy-a",
                    7,
                    110,
                    "disabled_noise",
                    signal_pb2.SIGNAL_STAGE_CANDIDATE,
                )),
                context,
            )
        )

        artifacts = [streaming_pb2.AnalysisArtifact.FromString(bytes(item)) for item in output]
        self.assertEqual(["signal"], [item.WhichOneof("payload") for item in artifacts])

    def test_event_completing_provenance_path_triggers_analysis(self):
        function, _ = opened_function()
        policy = detection_policy("tenant-a", "policy-a", 7)
        policy.detection.endpoint_rules.extend(
            ["payload_dropped", "suspicious_exec_connect"]
        )
        policy.detection.converge.cross_lineage = True
        policies = {detection.policy_key(policy): policy.SerializeToString()}
        context = ReadContext(policies, watermark_ms=0)
        dropped = signal_record(
            "scope-a", "policy-a", 7, 100, "payload_dropped",
            signal_pb2.SIGNAL_STAGE_CANDIDATE,
        )
        dropped.signal.lineage_id = "lin-a"
        dropped.signal.ClearField("entities")
        dropped.signal.entities.extend([
            signal_pb2.EntityRef(kind="file", key="/dev/shm/x.sh", role="object")
        ])
        connected = signal_record(
            "scope-a", "policy-a", 7, 110, "suspicious_exec_connect",
            signal_pb2.SIGNAL_STAGE_CANDIDATE,
        )
        connected.signal.lineage_id = "lin-b"
        connected.signal.ClearField("entities")
        connected.signal.entities.extend([
            signal_pb2.EntityRef(
                kind="socket", key="10.66.0.99:443", role="object"
            )
        ])
        list(function.process_element(input_bytes(dropped), context))
        list(function.process_element(input_bytes(connected), context))

        output = []
        for record in causal_event_records():
            output = list(function.process_element(input_bytes(record), context))

        # Signal arrival is the detector trigger; preceding events only update the graph.
        output = list(function.process_element(input_bytes(connected), context))

        artifacts = [streaming_pb2.AnalysisArtifact.FromString(value) for value in output]
        self.assertTrue(any(item.WhichOneof("payload") == "incident" for item in artifacts))

    def test_event_fast_path_enforces_scope_capacity(self):
        runtime = RuntimeContext()
        function = detection.DetectionFunction(max_scope_records=2)
        function.open(runtime)
        policy = detection_policy("tenant-a", "policy-a", 7)
        context = ReadContext(
            {detection.policy_key(policy): policy.SerializeToString()}, watermark_ms=0
        )

        for observed, event_id in ((100, "first"), (110, "second"), (120, "third")):
            list(function.process_element(
                input_bytes(event_record(
                    "scope-a", "policy-a", 7, observed, event_id
                )),
                context,
            ))

        retained = [
            streaming_pb2.NormalizedTelemetry.FromString(value).event.id
            for value in runtime._list_state("bounded-telemetry").values
        ]
        self.assertEqual(["second", "third"], retained)

    def test_rarity_function_restores_tenant_baseline_from_managed_state(self):
        runtime = RuntimeContext()
        function = detection.RarityFunction()
        function.open(runtime)
        policy = detection_policy("tenant-a", "policy-a", 7)
        policies = {detection.policy_key(policy): policy.SerializeToString()}
        context = ReadContext(policies, watermark_ms=0)
        first = signal_record(
            "scope-a",
            "policy-a",
            7,
            100,
            "download",
            signal_pb2.SIGNAL_STAGE_CANDIDATE,
        )
        first.signal.global_rarity = 1
        first_output = list(function.process_element(input_bytes(first), context))

        restored = detection.RarityFunction()
        restored.open(runtime)
        second = signal_record(
            "scope-b",
            "policy-a",
            7,
            110,
            "download",
            signal_pb2.SIGNAL_STAGE_CANDIDATE,
        )
        second.signal.global_rarity = 1
        second_output = list(restored.process_element(input_bytes(second), context))

        first_record = streaming_pb2.NormalizedTelemetryBatch.FromString(first_output[0]).records[0]
        second_record = streaming_pb2.NormalizedTelemetryBatch.FromString(second_output[0]).records[0]
        self.assertEqual(1, first_record.signal.global_rarity)
        self.assertEqual(0.5, second_record.signal.global_rarity)

    def test_rarity_late_signal_does_not_enter_baseline(self):
        runtime = RuntimeContext()
        function = detection.RarityFunction()
        function.open(runtime)
        policy = detection_policy("tenant-a", "policy-a", 7)
        policies = {detection.policy_key(policy): policy.SerializeToString()}
        record = signal_record(
            "scope-a",
            "policy-a",
            7,
            100,
            "download",
            signal_pb2.SIGNAL_STAGE_CANDIDATE,
        )

        output = list(
            function.process_element(
                input_bytes(record), ReadContext(
                    policies, watermark_ms=1, timestamp_ms=0
                )
            )
        )

        tag, value = output[0]
        self.assertEqual(detection.LATE_TAG.tag_id, tag.tag_id)
        self.assertEqual([], runtime._list_state("rarity-observations").values)
        self.assertEqual(1_000_000, streaming_pb2.LateTelemetry.FromString(value).watermark_unix_nano)

    def test_rarity_event_does_not_read_or_rewrite_observation_state(self):
        runtime = RuntimeContext()
        function = detection.RarityFunction()
        function.open(runtime)
        policy = detection_policy("tenant-a", "policy-a", 7)
        policies = {detection.policy_key(policy): policy.SerializeToString()}
        record = event_record("scope-a", "policy-a", 7, 100, "event-a")

        output = list(function.process_element(
            input_bytes(record), ReadContext(policies, watermark_ms=0)
        ))

        self.assertEqual([input_bytes(record)], output)
        self.assertEqual(
            0, runtime._list_state("rarity-observations").update_calls
        )

    def test_late_boundary_uses_flink_millisecond_timestamp(self):
        runtime = RuntimeContext()
        function = detection.RarityFunction()
        function.open(runtime)
        policy = detection_policy("tenant-a", "policy-a", 7)
        policies = {detection.policy_key(policy): policy.SerializeToString()}
        record = event_record(
            "scope-a", "policy-a", 7, 1_000_000, "same-millisecond"
        )

        output = list(
            function.process_element(
                input_bytes(record),
                ReadContext(policies, watermark_ms=1, timestamp_ms=1),
            )
        )

        self.assertEqual(detection.LATE_TAG.tag_id, output[0][0].tag_id)

    def test_detection_timer_cleans_silent_scope_state(self):
        function, runtime = opened_function()
        policy = detection_policy(
            "tenant-a", "policy-a", 7, state_retention_ns=1_000_000
        )
        policies = {detection.policy_key(policy): policy.SerializeToString()}
        context = ReadContext(policies, watermark_ms=0, timestamp_ms=1)
        record = event_record(
            "scope-a", "policy-a", 7, 1_000_000, "event-a"
        )
        list(function.process_element(input_bytes(record), context))

        function.on_timer(2, context)

        self.assertEqual([], runtime.state.values)

    def test_rarity_timer_cleans_silent_tenant_state(self):
        runtime = RuntimeContext()
        function = detection.RarityFunction()
        function.open(runtime)
        policy = detection_policy("tenant-a", "policy-a", 7)
        policy.detection.rarity.baseline_window_ns = 1_000_000
        policies = {detection.policy_key(policy): policy.SerializeToString()}
        context = ReadContext(policies, watermark_ms=0, timestamp_ms=1)
        record = signal_record(
            "scope-a",
            "policy-a",
            7,
            1_000_000,
            "download",
            signal_pb2.SIGNAL_STAGE_CANDIDATE,
        )
        list(function.process_element(input_bytes(record), context))

        function.on_timer(2, context)

        self.assertEqual([], runtime._list_state("rarity-observations").values)


def opened_function():
    runtime = RuntimeContext()
    function = detection.DetectionFunction()
    function.open(runtime)
    return function, runtime


def opened_windowed_function():
    runtime = RuntimeContext()
    function = detection.WindowedDetectionFunction()
    function.open(runtime)
    return function, runtime


def normalized_batch(records):
    first = records[0]
    return streaming_pb2.NormalizedTelemetryBatch(
        schema_version="sysarmor.telemetry.normalized.batch/v1",
        tenant_id=first.context.tenant_id,
        agent_id=first.context.agent_id,
        host_id=first.context.host_id,
        batch_id=first.context.batch_id,
        policy_id=first.context.policy_id,
        policy_version=first.context.policy_version,
        policy_mode=first.context.policy_mode,
        records=records,
    )


def input_bytes(record):
    return normalized_batch([record]).SerializeToString()


def causal_event_records():
    definitions = (
        (120, "exec-curl", "process.exec", "p-curl", "p-shell", "", ""),
        (130, "write-payload", "file.write", "p-curl", "", "/dev/shm/x.sh", ""),
        (140, "exec-bash", "process.exec", "p-bash", "p-curl", "", ""),
        (150, "connect-c2", "network.connect", "p-bash", "", "", "10.66.0.99:443"),
    )
    records = []
    for observed, event_id, behavior, subject, parent, path, address in definitions:
        record = event_record("scope-a", "policy-a", 7, observed, event_id)
        record.event.CopyFrom(
            event_pb2.CanonicalEvent(
                id=event_id,
                tenant_id="tenant-a",
                occurred_at_ns=observed,
                behavior=behavior,
                subject_proc=event_pb2.ProcessRef(stable_id=subject),
                parent_stable_id=parent,
                object=event_pb2.ObjectRef(file_path=path, socket_addr=address),
            )
        )
        records.append(record)
    return records


class ListState:
    def __init__(self):
        self.values = []
        self.update_calls = 0
        self.get_calls = 0

    def get(self):
        self.get_calls += 1
        return iter(self.values)

    def update(self, values):
        self.update_calls += 1
        self.values = list(values)

    def add(self, value):
        self.values.append(value)


class RuntimeContext:
    def __init__(self):
        self.list_states = {}
        self.value_states = {}
        self.map_states = {}
        self.state = self._list_state("bounded-telemetry")

    def get_list_state(self, descriptor):
        return self._list_state(descriptor.name)

    def get_state(self, descriptor):
        return self.value_states.setdefault(descriptor.name, ValueState())

    def get_map_state(self, descriptor):
        return self._map_state(descriptor.name)

    def _list_state(self, name):
        return self.list_states.setdefault(name, ListState())

    def _map_state(self, name):
        return self.map_states.setdefault(name, MapState())


class MapState:
    def __init__(self):
        self.values = {}

    def items(self):
        return self.values.items()

    def put(self, key, value):
        self.values[key] = value

    def remove(self, key):
        self.values.pop(key, None)

    def clear(self):
        self.values.clear()


class ValueState:
    def __init__(self):
        self.current = None

    def value(self):
        return self.current

    def update(self, value):
        self.current = value

    def clear(self):
        self.current = None


class BroadcastState:
    def __init__(self, values):
        self.values = values

    def get(self, key):
        return self.values.get(key)

    def put(self, key, value):
        self.values[key] = value


class BroadcastContext:
    def __init__(self):
        self.state = {}

    def get_broadcast_state(self, descriptor):
        return BroadcastState(self.state)


class TimerService:
    def __init__(self, watermark_ms):
        self.watermark_ms = watermark_ms
        self.timers = []

    def current_watermark(self):
        return self.watermark_ms

    def register_event_time_timer(self, timestamp):
        self.timers.append(timestamp)

    def delete_event_time_timer(self, timestamp):
        self.timers = [value for value in self.timers if value != timestamp]


class ReadContext:
    def __init__(self, policies, watermark_ms, timestamp_ms=None):
        self.policies = policies
        self.watermark_ms = watermark_ms
        self.timestamp_ms = watermark_ms + 1 if timestamp_ms is None else timestamp_ms
        self._timer_service = TimerService(watermark_ms)

    def get_broadcast_state(self, descriptor):
        return BroadcastState(self.policies)

    def timer_service(self):
        return self._timer_service

    def timestamp(self):
        return self.timestamp_ms

    def get_current_key(self):
        return "tenant-a\x00scope-a"


if __name__ == "__main__":
    unittest.main()
