import unittest

from packages.contracts.proto.event.v1 import event_pb2
from packages.contracts.proto.streaming.v1 import streaming_pb2

from sysarmor_streaming.jobs import detection
from tests.test_detection_state import (
    detection_policy,
    event_record,
    signal_record,
)
from packages.contracts.proto.signal.v1 import signal_pb2


class DetectionFunctionTest(unittest.TestCase):
    def test_validation_routes_permanent_bad_input_to_failure_output(self):
        output = list(detection.ValidateTelemetryFunction().process_element(b"bad", None))

        tag, value = output[0]
        failure = streaming_pb2.DetectionFailure.FromString(value)
        self.assertEqual(detection.FAILURE_TAG.tag_id, tag.tag_id)
        self.assertFalse(failure.retryable)
        self.assertEqual("invalid_normalized_telemetry", failure.reason_code)

    def test_validation_keeps_valid_normalized_telemetry_on_main_output(self):
        record = event_record("scope-a", "policy-a", 7, 100, "event-a")

        output = list(
            detection.ValidateTelemetryFunction().process_element(
                record.SerializeToString(), None
            )
        )

        self.assertEqual([record.SerializeToString()], output)

    def test_broadcast_policy_and_keyed_records_produce_artifact(self):
        function, runtime = opened_function()
        policy = detection_policy("tenant-a", "policy-a", 7)
        broadcast = BroadcastContext()
        function.process_broadcast_element(policy.SerializeToString(), broadcast)
        context = ReadContext(broadcast.state, watermark_ms=0)

        first = list(function.process_element(
            event_record("scope-a", "policy-a", 7, 100, "event-a").SerializeToString(),
            context,
        ))
        second = list(function.process_element(
            signal_record(
                "scope-a",
                "policy-a",
                7,
                110,
                "reverse_shell_pattern",
                signal_pb2.SIGNAL_STAGE_CONCLUSION,
            ).SerializeToString(),
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
                record.SerializeToString(), ReadContext({}, watermark_ms=0)
            ))

        self.assertEqual([], runtime.state.values)

    def test_late_record_uses_late_side_output_without_state(self):
        function, runtime = opened_function()
        policy = detection_policy("tenant-a", "policy-a", 7)
        state = {detection.policy_key(policy): policy.SerializeToString()}
        record = event_record("scope-a", "policy-a", 7, 100, "event-a")

        output = list(function.process_element(
            record.SerializeToString(), ReadContext(state, watermark_ms=1, timestamp_ms=0)
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
            detection.telemetry_key(record.SerializeToString()),
        )

    def test_stream_key_keeps_scope_across_policy_versions(self):
        first = event_record("scope-a", "policy-a", 7, 100, "event-a")
        second = event_record("scope-a", "policy-a", 8, 100, "event-a")

        self.assertEqual(
            detection.telemetry_key(first.SerializeToString()),
            detection.telemetry_key(second.SerializeToString()),
        )

    def test_timestamp_assigner_uses_event_time_in_milliseconds(self):
        record = event_record(
            "scope-a", "policy-a", 7, 1_700_000_000_123_456_789, "event-a"
        )

        timestamp = detection.TelemetryTimestampAssigner().extract_timestamp(
            record.SerializeToString(), -1
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
        list(function.process_element(conclusion.SerializeToString(), context))
        self.assertNotEqual([], runtime._list_state("emitted-artifacts").values)

        restored = detection.DetectionFunction()
        restored.open(runtime)
        output = list(
            restored.process_element(
                signal_record(
                    "scope-a",
                    "policy-a",
                    7,
                    110,
                    "disabled_noise",
                    signal_pb2.SIGNAL_STAGE_CANDIDATE,
                ).SerializeToString(),
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
        list(function.process_element(dropped.SerializeToString(), context))
        list(function.process_element(connected.SerializeToString(), context))

        output = []
        for record in causal_event_records():
            output = list(function.process_element(record.SerializeToString(), context))

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
                event_record(
                    "scope-a", "policy-a", 7, observed, event_id
                ).SerializeToString(),
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
        first_output = list(function.process_element(first.SerializeToString(), context))

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
        second_output = list(restored.process_element(second.SerializeToString(), context))

        first_record = streaming_pb2.NormalizedTelemetry.FromString(first_output[0])
        second_record = streaming_pb2.NormalizedTelemetry.FromString(second_output[0])
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
                record.SerializeToString(), ReadContext(
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
            record.SerializeToString(), ReadContext(policies, watermark_ms=0)
        ))

        self.assertEqual([record.SerializeToString()], output)
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
            "scope-a", "policy-a", 7, 1_000_001, "same-millisecond"
        )

        output = list(
            function.process_element(
                record.SerializeToString(),
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
        list(function.process_element(record.SerializeToString(), context))

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
        list(function.process_element(record.SerializeToString(), context))

        function.on_timer(2, context)

        self.assertEqual([], runtime._list_state("rarity-observations").values)


def opened_function():
    runtime = RuntimeContext()
    function = detection.DetectionFunction()
    function.open(runtime)
    return function, runtime


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

    def get(self):
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
        self.state = self._list_state("bounded-telemetry")

    def get_list_state(self, descriptor):
        return self._list_state(descriptor.name)

    def get_state(self, descriptor):
        return self.value_states.setdefault(descriptor.name, ValueState())

    def _list_state(self, name):
        return self.list_states.setdefault(name, ListState())


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


class ReadContext:
    def __init__(self, policies, watermark_ms, timestamp_ms=None):
        self.policies = policies
        self.watermark_ms = watermark_ms
        self.timestamp_ms = watermark_ms + 1 if timestamp_ms is None else timestamp_ms

    def get_broadcast_state(self, descriptor):
        return BroadcastState(self.policies)

    def timer_service(self):
        return TimerService(self.watermark_ms)

    def timestamp(self):
        return self.timestamp_ms


if __name__ == "__main__":
    unittest.main()
