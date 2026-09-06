"""Build bounded detection state and emit analysis artifacts."""

import json
from collections import OrderedDict
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
from streaming.engine.detection_state import (
    MAX_SCOPE_RECORDS,
    DetectionState,
)
from streaming.detectors.contracts import RequiredInput
from streaming.detectors.registry import DetectorRegistry
from streaming.preprocessing.rarity_window import RarityObservation, RarityWindow
from streaming.preprocessing.telemetry_validation import validate_telemetry


JOB_NAME = "sysarmor-detection-v1"
BYTE_ARRAY = Types.PRIMITIVE_ARRAY(Types.BYTE())
POLICY_STATE = MapStateDescriptor("detection-policies", Types.STRING(), BYTE_ARRAY)
RARITY_POLICY_STATE = MapStateDescriptor("rarity-policies", Types.STRING(), BYTE_ARRAY)
TELEMETRY_STATE = ListStateDescriptor("bounded-telemetry", BYTE_ARRAY)
EMITTED_STATE = ListStateDescriptor("emitted-artifacts", Types.STRING())
DETECTOR_STATE = MapStateDescriptor("detector-states", Types.STRING(), BYTE_ARRAY)
DETECTOR_STATE_EXPIRY = MapStateDescriptor(
    "detector-state-expiries", Types.STRING(), Types.LONG()
)
CLEANUP_TIMER_STATE = ValueStateDescriptor("cleanup-timer", Types.LONG())
TELEMETRY_COUNT_STATE = ValueStateDescriptor("telemetry-count", Types.LONG())
SIGNAL_COUNT_STATE = ValueStateDescriptor("signal-count", Types.LONG())
RARITY_STATE = ListStateDescriptor("rarity-observations", Types.STRING())
LATE_TAG = OutputTag("late-telemetry", BYTE_ARRAY)
FAILURE_TAG = OutputTag("detection-failures", BYTE_ARRAY)
MIN_WATERMARK_MS = -(1 << 63)
DEFAULT_OUT_OF_ORDERNESS_MS = 5_000
CLEANUP_TIMER_BUCKET_MS = 1_000
MAX_CACHED_AGENT_SCOPES = 64
MAX_CACHED_RECORDS = MAX_SCOPE_RECORDS
EVENT_CHANGED_INPUTS = frozenset(
    {RequiredInput.NORMALIZED_EVENT, RequiredInput.PROVENANCE_EDGE}
)


@dataclass(frozen=True)
class DetectionStreams:
    artifacts: object
    late: object
    failures: object


class TelemetryTimestampAssigner(TimestampAssigner):
    def extract_timestamp(self, value, record_timestamp):
        records, _ = _decode_batch(value)
        return max(_record_observed_ns(record) for record in records) // 1_000_000


class PolicyVersionUnavailable(RuntimeError):
    pass


class ValidateTelemetryFunction(ProcessFunction):
    def process_element(self, value, ctx):
        try:
            batch, is_batch = _decode_batch(value)
        except ValueError as error:
            yield FAILURE_TAG, _batch_failure(bytes(value), str(error))
            return
        records = []
        for record in batch:
            result = validate_telemetry(record.SerializeToString())
            if result.failure is not None:
                yield FAILURE_TAG, result.failure.SerializeToString()
                continue
            records.append(result.record)
        if records:
            yield _encode_batch(records)


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
        try:
            records, is_batch = _decode_batch(value)
        except ValueError as error:
            yield FAILURE_TAG, _batch_failure(bytes(value), str(error))
            return
        policy = _require_policy(ctx, records[0], RARITY_POLICY_STATE)
        watermark_ns = _watermark_ns(ctx)
        current_records = []
        for record in records:
            if _record_is_late(record, watermark_ns):
                late = streaming_pb2.LateTelemetry(
                    telemetry=record, watermark_unix_nano=watermark_ns
                )
                yield LATE_TAG, late.SerializeToString()
            else:
                current_records.append(record)
        if not current_records:
            return
        records = tuple(current_records)
        window = RarityWindow()
        window.restore(map(_decode_observation, self._observations.get()))
        if all(record.WhichOneof("payload") == "event" for record in records):
            yield bytes(value)
            return
        output = []
        for record in records:
            if record.WhichOneof("payload") == "event":
                output.append(record)
            else:
                output.append(window.process(record, policy))
        self._observations.update(map(_encode_observation, window.observations()))
        _register_timer(ctx, window.next_expiry_ns())
        yield _encode_batch(output) if is_batch else output[0].SerializeToString()

    def on_timer(self, timestamp, ctx):
        window = RarityWindow()
        window.restore(map(_decode_observation, self._observations.get()))
        window.cleanup(timestamp * 1_000_000)
        self._observations.update(map(_encode_observation, window.observations()))
        _register_timer(ctx, window.next_expiry_ns())


class DetectionFunction(KeyedBroadcastProcessFunction):
    def __init__(
        self,
        max_scope_records=MAX_SCOPE_RECORDS,
        max_cached_scopes=MAX_CACHED_AGENT_SCOPES,
        max_cached_records=MAX_CACHED_RECORDS,
    ):
        self._max_scope_records = max_scope_records
        if max_cached_scopes <= 0 or max_cached_records <= 0:
            raise ValueError("detector cache limits must be positive")
        self._max_cached_scopes = max_cached_scopes
        self._max_cached_records = max_cached_records
        self._detectors = OrderedDict()
        self._detector_policies = {}
        self._cached_record_counts = {}

    def open(self, runtime_context):
        self._telemetry = runtime_context.get_list_state(TELEMETRY_STATE)
        self._emitted = runtime_context.get_list_state(EMITTED_STATE)
        self._telemetry_count = runtime_context.get_state(TELEMETRY_COUNT_STATE)
        self._signal_count = runtime_context.get_state(SIGNAL_COUNT_STATE)
        self._cleanup_timer = runtime_context.get_state(CLEANUP_TIMER_STATE)
        self._detector_state = runtime_context.get_map_state(DETECTOR_STATE)
        self._detector_state_expiry = runtime_context.get_map_state(
            DETECTOR_STATE_EXPIRY
        )
        self._detectors = OrderedDict()
        self._detector_policies = {}
        self._cached_record_counts = {}

    def process_broadcast_element(self, value, ctx):
        policy = streaming_pb2.DetectionPolicySnapshot.FromString(bytes(value))
        _validate_policy(policy)
        state = ctx.get_broadcast_state(POLICY_STATE)
        state.put(policy_key(policy), policy.SerializeToString())

    def process_element(self, value, ctx):
        try:
            records, is_batch = _decode_batch(value)
        except ValueError as error:
            yield FAILURE_TAG, _batch_failure(bytes(value), str(error))
            return
        record = records[0]
        policy = _require_policy(ctx, record, POLICY_STATE)
        watermark_ns = _watermark_ns(ctx)
        current_records = []
        for item in records:
            if _record_is_late(item, watermark_ns):
                late = streaming_pb2.LateTelemetry(
                    telemetry=item, watermark_unix_nano=watermark_ns
                )
                yield LATE_TAG, late.SerializeToString()
            else:
                current_records.append(item)
        if not current_records:
            return
        records = tuple(current_records)
        if all(item.WhichOneof("payload") == "event" for item in records) and (
            self._can_append_event(record) or self._can_append_cached_event(record)
        ):
            self._remove_cached_detector(_cache_key(record))
            _state_add_all(self._telemetry, [item.SerializeToString() for item in records])
            self._telemetry_count.update(_state_count(self._telemetry_count) + len(records))
            self._schedule_cleanup(ctx, max(_record_expiry_ns(item, policy) for item in records))
            return
        detector = self._restore_detector(record, ctx)
        cache_key = _cache_key(record)
        policies = self._detector_policies[cache_key]
        policies.update(self._policies_for(ctx, records, policy))
        scope_key = record.context.analysis_scope_key
        results = detector.process_batch(records, 0, policies)
        for result in results:
            if result.failure is not None:
                if result.failure.retryable:
                    identity = record.context
                    raise PolicyVersionUnavailable(
                        f"{identity.tenant_id}/{identity.policy_id}/{identity.policy_version}"
                    )
                yield FAILURE_TAG, result.failure.SerializeToString()
            elif result.late is not None:
                yield LATE_TAG, result.late.SerializeToString()
        self._persist_detector(
            detector,
            scope_key,
            records,
            any(item.state_rewrite_required for item in results),
        )
        self._refresh_cached_detector(cache_key, detector)
        self._schedule_cleanup(ctx, detector.next_cleanup_ns(scope_key))
        for result in results:
            for artifact in result.artifacts:
                yield artifact.SerializeToString()

    def on_timer(self, timestamp, ctx):
        self._cleanup_timer.clear()
        cache_key = str(ctx.get_current_key())
        detector = self._cached_detector(cache_key)
        if detector is not None:
            scope_key = cache_key.split("\x00", 1)[1]
            policy = next(iter(self._detector_policies[cache_key].values()))
            self._cleanup_detector(
                detector, cache_key, scope_key, timestamp, policy, ctx
            )
            return
        stored = [
            record
            for item in self._telemetry.get()
            for record in (_decode_stored_record(item),)
        ]
        if not stored:
            self._emitted.update([])
            self._telemetry_count.update(0)
            self._signal_count.update(0)
            self._detector_state.clear()
            self._detector_state_expiry.clear()
            return
        sample = stored[0]
        policy = _require_policy(ctx, sample, POLICY_STATE)
        scope_key = sample.context.analysis_scope_key
        cache_key = _cache_key(sample)
        detector = DetectionState(max_scope_records=self._max_scope_records)
        detector.restore(scope_key, stored, self._policies_for(ctx, stored, policy))
        detector.restore_detector_states(
            scope_key,
            self._detector_state.items(),
            self._detector_state_expiry.items(),
        )
        detector.restore_emissions(scope_key, map(_decode_emission, self._emitted.get()))
        self._cleanup_detector(
            detector, cache_key, scope_key, timestamp, policy, ctx
        )

    def _cleanup_detector(
        self, detector, cache_key, scope_key, timestamp, policy, ctx
    ) -> None:
        detector.cleanup(scope_key, timestamp * 1_000_000, policy)
        self._persist_detector(detector, scope_key)
        self._refresh_cached_detector(cache_key, detector)
        self._schedule_cleanup(ctx, detector.next_cleanup_ns(scope_key))
        if detector.event_count(scope_key) == 0 and detector.signal_count(scope_key) == 0:
            self._remove_cached_detector(cache_key)

    def _can_append_event(self, record) -> bool:
        return (
            record.WhichOneof("payload") == "event"
            and not DetectorRegistry.affected_by(
                EVENT_CHANGED_INPUTS, EVENT_CHANGED_INPUTS, frozenset()
            )
            and _cache_key(record) not in self._detectors
            and _state_count(self._signal_count) == 0
            and _state_count(self._telemetry_count) < self._max_scope_records
        )

    def _can_append_cached_event(self, record) -> bool:
        if record.WhichOneof("payload") != "event":
            return False
        detector = self._detectors.get(_cache_key(record))
        if detector is None:
            return False
        return (
            not detector.accepts_event_changes(record)
            and detector.is_event_in_order(record)
        )

    def _restore_detector(self, record, ctx):
        scope_key = record.context.analysis_scope_key
        cache_key = _cache_key(record)
        cached = self._cached_detector(cache_key)
        if cached is not None:
            return cached
        detector = DetectionState(max_scope_records=self._max_scope_records)
        stored = [
            record
            for item in self._telemetry.get()
            for record in (_decode_stored_record(item),)
        ]
        current_policy = _require_policy(ctx, record, POLICY_STATE)
        policies = self._policies_for(ctx, stored, current_policy)
        detector.restore(scope_key, stored, policies)
        detector.restore_emissions(
            scope_key, map(_decode_emission, self._emitted.get())
        )
        detector.restore_detector_states(
            scope_key,
            self._detector_state.items(),
            self._detector_state_expiry.items(),
        )
        self._cache_detector(
            cache_key, detector, policies, record_count=len(stored)
        )
        return detector

    def _cached_detector(self, cache_key):
        detector = self._detectors.get(cache_key)
        if detector is not None:
            self._detectors.move_to_end(cache_key)
        return detector

    def _cache_detector(
        self, cache_key, detector, policies, record_count=0
    ) -> None:
        self._detectors[cache_key] = detector
        self._detectors.move_to_end(cache_key)
        self._detector_policies[cache_key] = policies
        self._cached_record_counts[cache_key] = record_count
        self._trim_detector_cache()

    def _refresh_cached_detector(self, cache_key, detector) -> None:
        if cache_key not in self._detectors:
            return
        scope_key = cache_key.split("\x00", 1)[1]
        self._cached_record_counts[cache_key] = (
            detector.event_count(scope_key) + detector.signal_count(scope_key)
        )
        self._trim_detector_cache()

    def _trim_detector_cache(self) -> None:
        while len(self._detectors) > self._max_cached_scopes or (
            len(self._detectors) > 1
            and sum(self._cached_record_counts.values()) > self._max_cached_records
        ):
            evicted_key, _ = self._detectors.popitem(last=False)
            self._detector_policies.pop(evicted_key, None)
            self._cached_record_counts.pop(evicted_key, None)

    def _remove_cached_detector(self, cache_key) -> None:
        self._detectors.pop(cache_key, None)
        self._detector_policies.pop(cache_key, None)
        self._cached_record_counts.pop(cache_key, None)

    def _schedule_cleanup(self, ctx, timestamp_ns: int) -> None:
        if timestamp_ns <= 0:
            return
        timestamp_ms = _cleanup_timer_ms(timestamp_ns)
        current_ms = _state_count(self._cleanup_timer)
        if current_ms and current_ms <= timestamp_ms:
            return
        if current_ms:
            ctx.timer_service().delete_event_time_timer(current_ms)
        ctx.timer_service().register_event_time_timer(timestamp_ms)
        self._cleanup_timer.update(timestamp_ms)

    def _policies_for(self, ctx, records, current_policy):
        policies = {
            (current_policy.tenant_id, current_policy.policy_id, current_policy.policy_version): current_policy
        }
        for record in records:
            policy = _read_policy_state(ctx, record, POLICY_STATE)
            if policy is not None:
                policies[(policy.tenant_id, policy.policy_id, policy.policy_version)] = policy
        return policies

    def _persist_detector(
        self, detector, scope_key, appended_record=None, rewrite_required=False
    ) -> None:
        previous_count = _state_count(self._telemetry_count)
        if not rewrite_required and appended_record is not None:
            values = [record.SerializeToString() for record in appended_record]
            _state_add_all(self._telemetry, values)
            record_count = previous_count + len(values)
        else:
            records = detector.records(scope_key)
            self._telemetry.update([item.SerializeToString() for item in records])
            record_count = len(records)
        detector.mark_persisted(scope_key)
        self._emitted.update(map(_encode_emission, detector.emissions(scope_key)))
        self._telemetry_count.update(record_count)
        self._signal_count.update(detector.signal_count(scope_key))
        _sync_map_state(self._detector_state, detector.detector_states(scope_key))
        _sync_map_state(
            self._detector_state_expiry,
            detector.detector_state_expiries(scope_key),
        )


def telemetry_key(value) -> str:
    records, _ = _decode_batch(value)
    return _cache_key(records[0])


def _cache_key(record) -> str:
    context = record.context
    return context.tenant_id + "\x00" + context.analysis_scope_key


def tenant_key(value) -> str:
    return _decode_batch(value)[0][0].context.tenant_id


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


def _record_expiry_ns(record, policy) -> int:
    retention_ns = (
        policy.detection.converge.state_retention_ns or 300_000_000_000
    )
    observed_ns = record.context.observed_at_unix_nano
    if record.WhichOneof("payload") == "event" and record.event.occurred_at_ns:
        observed_ns = record.event.occurred_at_ns
    return observed_ns + retention_ns


def _cleanup_timer_ms(timestamp_ns: int) -> int:
    timestamp_ms = (timestamp_ns + 999_999) // 1_000_000
    return (
        (timestamp_ms + CLEANUP_TIMER_BUCKET_MS - 1)
        // CLEANUP_TIMER_BUCKET_MS
        * CLEANUP_TIMER_BUCKET_MS
    )


def _register_timer(ctx, timestamp_ns: int) -> None:
    if timestamp_ns > 0:
        timestamp_ms = (timestamp_ns + 999_999) // 1_000_000
        ctx.timer_service().register_event_time_timer(timestamp_ms)


def _state_count(state) -> int:
    return int(state.value() or 0)


def _state_add_all(state, values) -> None:
    if hasattr(state, "add_all"):
        state.add_all(values)
        return
    for value in values:
        state.add(value)


def _decode_batch(value):
    raw = bytes(value)
    batch = streaming_pb2.NormalizedTelemetryBatch()
    try:
        batch.ParseFromString(raw)
    except Exception as error:
        raise ValueError("invalid_normalized_telemetry") from error
    if not batch.records:
        raise ValueError("normalized_batch_required")
    if batch.schema_version != "sysarmor.telemetry.normalized.batch/v1":
        raise ValueError("unsupported normalized telemetry batch schema")
    first = batch.records[0].context
    envelope = (
        batch.tenant_id,
        batch.agent_id,
        batch.batch_id,
        batch.policy_id,
        batch.policy_version,
    )
    expected = (
        first.tenant_id,
        first.agent_id,
        first.batch_id,
        first.policy_id,
        first.policy_version,
    )
    if envelope != expected:
        raise ValueError("normalized telemetry batch identity mismatch")
    for record in batch.records:
        context = record.context
        if (
            context.tenant_id,
            context.agent_id,
            context.batch_id,
            context.policy_id,
            context.policy_version,
            context.analysis_scope_key,
        ) != (
            first.tenant_id,
            first.agent_id,
            first.batch_id,
            first.policy_id,
            first.policy_version,
            first.analysis_scope_key,
        ):
            raise ValueError("normalized telemetry batch context mismatch")
    return tuple(batch.records), True


def _decode_stored_record(value):
    record = streaming_pb2.NormalizedTelemetry()
    record.ParseFromString(bytes(value))
    return record


def _batch_failure(raw: bytes, reason: str) -> bytes:
    return streaming_pb2.DetectionFailure(
        reason_code=reason,
        message=reason,
        retryable=False,
    ).SerializeToString()


def _encode_batch(records) -> bytes:
    first = records[0]
    batch = streaming_pb2.NormalizedTelemetryBatch(
        schema_version="sysarmor.telemetry.normalized.batch/v1",
        tenant_id=first.context.tenant_id,
        agent_id=first.context.agent_id,
        host_id=first.context.host_id,
        batch_id=first.context.batch_id,
        policy_id=first.context.policy_id,
        policy_version=first.context.policy_version,
        policy_mode=first.context.policy_mode,
        created_at_unix_nano=max(_record_observed_ns(record) for record in records),
        records=records,
    )
    return batch.SerializeToString()


def _record_observed_ns(record) -> int:
    if record.WhichOneof("payload") == "event" and record.event.occurred_at_ns:
        return record.event.occurred_at_ns
    return record.context.observed_at_unix_nano


def _record_is_late(record, watermark_ns) -> bool:
    return watermark_ns > 0 and _record_observed_ns(record) <= watermark_ns


def _sync_map_state(state, expected: dict) -> None:
    current_keys = {str(key) for key, _ in state.items()}
    for key in current_keys - set(expected):
        state.remove(key)
    for key, value in expected.items():
        state.put(key, value)
