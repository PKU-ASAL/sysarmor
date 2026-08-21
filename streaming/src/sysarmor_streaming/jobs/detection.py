"""Build bounded detection state and emit analysis artifacts."""

import json
from dataclasses import dataclass

from pyflink.common import Duration, Types, WatermarkStrategy
from pyflink.datastream import KeyedBroadcastProcessFunction, OutputTag, ProcessFunction
from pyflink.common.watermark_strategy import TimestampAssigner
from pyflink.datastream.state import (
    ListStateDescriptor,
    MapStateDescriptor,
    ValueStateDescriptor,
)

from packages.contracts.proto.streaming.v1 import streaming_pb2
from sysarmor_streaming.operators.detection_state import (
    MAX_SCOPE_RECORDS,
    DetectionState,
)
from sysarmor_streaming.operators.rarity_window import RarityObservation, RarityWindow
from sysarmor_streaming.operators.telemetry_validation import validate_telemetry


JOB_NAME = "sysarmor-detection-v1"
BYTE_ARRAY = Types.PRIMITIVE_ARRAY(Types.BYTE())
POLICY_STATE = MapStateDescriptor("detection-policies", Types.STRING(), BYTE_ARRAY)
RARITY_POLICY_STATE = MapStateDescriptor("rarity-policies", Types.STRING(), BYTE_ARRAY)
TELEMETRY_STATE = ListStateDescriptor("bounded-telemetry", BYTE_ARRAY)
EMITTED_STATE = ListStateDescriptor("emitted-artifacts", Types.STRING())
TELEMETRY_COUNT_STATE = ValueStateDescriptor("telemetry-count", Types.LONG())
SIGNAL_COUNT_STATE = ValueStateDescriptor("signal-count", Types.LONG())
RARITY_STATE = ListStateDescriptor("rarity-observations", Types.STRING())
LATE_TAG = OutputTag("late-telemetry", BYTE_ARRAY)
FAILURE_TAG = OutputTag("detection-failures", BYTE_ARRAY)
MIN_WATERMARK_MS = -(1 << 63)
DEFAULT_OUT_OF_ORDERNESS_MS = 5_000


@dataclass(frozen=True)
class DetectionStreams:
    artifacts: object
    late: object
    failures: object


class TelemetryTimestampAssigner(TimestampAssigner):
    def extract_timestamp(self, value, record_timestamp):
        record = streaming_pb2.NormalizedTelemetry.FromString(bytes(value))
        observed_ns = record.context.observed_at_unix_nano
        if record.WhichOneof("payload") == "event" and record.event.occurred_at_ns:
            observed_ns = record.event.occurred_at_ns
        return observed_ns // 1_000_000


class PolicyVersionUnavailable(RuntimeError):
    pass


class ValidateTelemetryFunction(ProcessFunction):
    def process_element(self, value, ctx):
        result = validate_telemetry(bytes(value))
        if result.failure is not None:
            yield FAILURE_TAG, result.failure.SerializeToString()
            return
        yield result.record.SerializeToString()


class RarityFunction(KeyedBroadcastProcessFunction):
    def open(self, runtime_context):
        self._observations = runtime_context.get_list_state(RARITY_STATE)

    def process_broadcast_element(self, value, ctx):
        policy = streaming_pb2.DetectionPolicySnapshot.FromString(bytes(value))
        _validate_policy(policy)
        ctx.get_broadcast_state(RARITY_POLICY_STATE).put(
            policy_key(policy), policy.SerializeToString()
        )

    def process_element(self, value, ctx):
        record = streaming_pb2.NormalizedTelemetry.FromString(bytes(value))
        policy = _require_policy(ctx, record, RARITY_POLICY_STATE)
        if _is_late(ctx):
            late = streaming_pb2.LateTelemetry(
                telemetry=record, watermark_unix_nano=_watermark_ns(ctx)
            )
            yield LATE_TAG, late.SerializeToString()
            return
        if record.WhichOneof("payload") == "event":
            yield bytes(value)
            return
        window = RarityWindow()
        window.restore(map(_decode_observation, self._observations.get()))
        result = window.process(record, policy)
        self._observations.update(map(_encode_observation, window.observations()))
        _register_timer(ctx, window.next_expiry_ns())
        yield result.SerializeToString()

    def on_timer(self, timestamp, ctx):
        window = RarityWindow()
        window.restore(map(_decode_observation, self._observations.get()))
        window.cleanup(timestamp * 1_000_000)
        self._observations.update(map(_encode_observation, window.observations()))
        _register_timer(ctx, window.next_expiry_ns())


class DetectionFunction(KeyedBroadcastProcessFunction):
    def __init__(self, max_scope_records=MAX_SCOPE_RECORDS):
        self._max_scope_records = max_scope_records

    def open(self, runtime_context):
        self._telemetry = runtime_context.get_list_state(TELEMETRY_STATE)
        self._emitted = runtime_context.get_list_state(EMITTED_STATE)
        self._telemetry_count = runtime_context.get_state(TELEMETRY_COUNT_STATE)
        self._signal_count = runtime_context.get_state(SIGNAL_COUNT_STATE)

    def process_broadcast_element(self, value, ctx):
        policy = streaming_pb2.DetectionPolicySnapshot.FromString(bytes(value))
        _validate_policy(policy)
        state = ctx.get_broadcast_state(POLICY_STATE)
        state.put(policy_key(policy), policy.SerializeToString())

    def process_element(self, value, ctx):
        record = streaming_pb2.NormalizedTelemetry.FromString(bytes(value))
        policy = _require_policy(ctx, record, POLICY_STATE)
        if _is_late(ctx):
            late = streaming_pb2.LateTelemetry(
                telemetry=record, watermark_unix_nano=_watermark_ns(ctx)
            )
            yield LATE_TAG, late.SerializeToString()
            return
        if self._can_append_event(record):
            self._telemetry.add(record.SerializeToString())
            self._telemetry_count.update(_state_count(self._telemetry_count) + 1)
            _register_cleanup_timer(ctx, record, policy)
            return
        detector = self._restore_detector(record, ctx)
        identity = (policy.tenant_id, policy.policy_id, policy.policy_version)
        policies = {identity: policy}
        scope_key = record.context.analysis_scope_key
        result = detector.process(record, 0, policies)
        if result.failure is not None:
            if result.failure.retryable:
                identity = record.context
                raise PolicyVersionUnavailable(
                    f"{identity.tenant_id}/{identity.policy_id}/{identity.policy_version}"
                )
            yield FAILURE_TAG, result.failure.SerializeToString()
            return
        if result.late is not None:
            yield LATE_TAG, result.late.SerializeToString()
            return
        self._persist_detector(detector, scope_key)
        _register_cleanup_timer(ctx, record, policy)
        for artifact in result.artifacts:
            yield artifact.SerializeToString()

    def on_timer(self, timestamp, ctx):
        stored = [
            streaming_pb2.NormalizedTelemetry.FromString(bytes(item))
            for item in self._telemetry.get()
        ]
        if not stored:
            self._emitted.update([])
            self._telemetry_count.update(0)
            self._signal_count.update(0)
            return
        sample = stored[0]
        policy = _require_policy(ctx, sample, POLICY_STATE)
        scope_key = sample.context.analysis_scope_key
        detector = DetectionState(max_scope_records=self._max_scope_records)
        detector.restore(scope_key, stored, self._policies_for(ctx, stored, policy))
        detector.restore_emissions(scope_key, map(_decode_emission, self._emitted.get()))
        detector.cleanup(scope_key, timestamp * 1_000_000, policy)
        self._persist_detector(detector, scope_key)

    def _can_append_event(self, record) -> bool:
        return (
            record.WhichOneof("payload") == "event"
            and _state_count(self._signal_count) == 0
            and _state_count(self._telemetry_count) < self._max_scope_records
        )

    def _restore_detector(self, record, ctx):
        detector = DetectionState(max_scope_records=self._max_scope_records)
        scope_key = record.context.analysis_scope_key
        stored = [
            streaming_pb2.NormalizedTelemetry.FromString(bytes(item))
            for item in self._telemetry.get()
        ]
        current_policy = _require_policy(ctx, record, POLICY_STATE)
        detector.restore(
            scope_key,
            stored,
            self._policies_for(ctx, stored, current_policy),
        )
        detector.restore_emissions(
            scope_key, map(_decode_emission, self._emitted.get())
        )
        return detector

    def _policies_for(self, ctx, records, current_policy):
        policies = {
            (current_policy.tenant_id, current_policy.policy_id, current_policy.policy_version): current_policy
        }
        for record in records:
            policy = _read_policy_state(ctx, record, POLICY_STATE)
            if policy is not None:
                policies[(policy.tenant_id, policy.policy_id, policy.policy_version)] = policy
        return policies

    def _persist_detector(self, detector, scope_key) -> None:
        records = detector.records(scope_key)
        self._telemetry.update([item.SerializeToString() for item in records])
        self._emitted.update(map(_encode_emission, detector.emissions(scope_key)))
        self._telemetry_count.update(len(records))
        self._signal_count.update(detector.signal_count(scope_key))


def telemetry_key(value) -> str:
    record = streaming_pb2.NormalizedTelemetry.FromString(bytes(value))
    context = record.context
    return context.tenant_id + "\x00" + context.analysis_scope_key


def tenant_key(value) -> str:
    record = streaming_pb2.NormalizedTelemetry.FromString(bytes(value))
    return record.context.tenant_id


def build_graph(telemetry_stream, policy_stream, out_of_orderness_ms=DEFAULT_OUT_OF_ORDERNESS_MS):
    watermark = WatermarkStrategy.for_bounded_out_of_orderness(
        Duration.of_millis(out_of_orderness_ms)
    ).with_timestamp_assigner(TelemetryTimestampAssigner())
    validated = telemetry_stream.process(
        ValidateTelemetryFunction(), output_type=BYTE_ARRAY
    )
    telemetry = validated.assign_timestamps_and_watermarks(watermark)
    rarity = telemetry.key_by(tenant_key, key_type=Types.STRING()).connect(
        policy_stream.broadcast(RARITY_POLICY_STATE)
    ).process(RarityFunction(), output_type=BYTE_ARRAY)
    keyed = rarity.key_by(telemetry_key, key_type=Types.STRING())
    policies = policy_stream.broadcast(POLICY_STATE)
    artifacts = keyed.connect(policies).process(
        DetectionFunction(), output_type=BYTE_ARRAY
    )
    return DetectionStreams(
        artifacts=artifacts,
        late=rarity.get_side_output(LATE_TAG).union(
            artifacts.get_side_output(LATE_TAG)
        ),
        failures=validated.get_side_output(FAILURE_TAG).union(
            artifacts.get_side_output(FAILURE_TAG)
        ),
    )


def policy_key(policy) -> str:
    return json.dumps(
        [policy.tenant_id, policy.policy_id, policy.policy_version],
        separators=(",", ":"),
    )


def _read_policy(ctx, record):
    return _read_policy_state(ctx, record, POLICY_STATE)


def _read_policy_state(ctx, record, descriptor):
    context = record.context
    identity = json.dumps(
        [context.tenant_id, context.policy_id, context.policy_version],
        separators=(",", ":"),
    )
    value = ctx.get_broadcast_state(descriptor).get(identity)
    if value is None:
        return None
    return streaming_pb2.DetectionPolicySnapshot.FromString(bytes(value))


def _require_policy(ctx, record, descriptor):
    policy = _read_policy_state(ctx, record, descriptor)
    if policy is None:
        identity = record.context
        raise PolicyVersionUnavailable(
            f"{identity.tenant_id}/{identity.policy_id}/{identity.policy_version}"
        )
    return policy


def _watermark_ns(ctx) -> int:
    watermark_ms = ctx.timer_service().current_watermark()
    return 0 if watermark_ms == MIN_WATERMARK_MS else watermark_ms * 1_000_000


def _is_late(ctx) -> bool:
    watermark_ms = ctx.timer_service().current_watermark()
    timestamp_ms = ctx.timestamp()
    return (
        watermark_ms != MIN_WATERMARK_MS
        and timestamp_ms is not None
        and timestamp_ms <= watermark_ms
    )


def _validate_policy(policy) -> None:
    if policy.schema_version != "sysarmor.detection.policy/v1":
        raise ValueError("unsupported detection policy schema")
    if not policy.tenant_id or not policy.policy_id or policy.policy_version == 0:
        raise ValueError("incomplete detection policy identity")


def _encode_emission(value) -> str:
    observed_ns, identity = value
    return f"{observed_ns}\x00{identity}"


def _decode_emission(value) -> tuple[int, str]:
    observed_ns, identity = value.split("\x00", 1)
    return int(observed_ns), identity


def _encode_observation(value) -> str:
    return json.dumps(
        [value.observed_ns, value.expires_ns, value.workload, value.signal],
        separators=(",", ":"),
    )


def _decode_observation(value):
    observed_ns, expires_ns, workload, signal = json.loads(value)
    return RarityObservation(observed_ns, expires_ns, workload, signal)


def _register_cleanup_timer(ctx, record, policy) -> None:
    retention_ns = (
        policy.detection.converge.state_retention_ns or 300_000_000_000
    )
    observed_ns = record.context.observed_at_unix_nano
    if record.WhichOneof("payload") == "event" and record.event.occurred_at_ns:
        observed_ns = record.event.occurred_at_ns
    _register_timer(ctx, observed_ns + retention_ns)


def _register_timer(ctx, timestamp_ns: int) -> None:
    if timestamp_ns > 0:
        timestamp_ms = (timestamp_ns + 999_999) // 1_000_000
        ctx.timer_service().register_event_time_timer(timestamp_ms)


def _state_count(state) -> int:
    return int(state.value() or 0)
