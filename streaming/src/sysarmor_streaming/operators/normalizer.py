from dataclasses import dataclass
from datetime import datetime

from google.protobuf import json_format
from packages.contracts.proto.dataplane.v1 import dataplane_pb2
from packages.contracts.proto.signal.v1 import signal_pb2
from packages.contracts.proto.streaming.v1 import streaming_pb2


DATA_PLANE_SCHEMA = "sysarmor.dataplane/v1"
NORMALIZED_SCHEMA = "sysarmor.telemetry.normalized/v1"
REJECTED_SCHEMA = "sysarmor.telemetry.rejected/v1"
SCOPE_LABELS = ("case_type", "scenario", "workload", "policy_id", "policy_version")


@dataclass(frozen=True)
class NormalizationResult:
    records: tuple[streaming_pb2.NormalizedTelemetry, ...]
    rejection: streaming_pb2.RejectedTelemetry | None = None


class NormalizationError(ValueError):
    def __init__(self, reason_code: str, message: str):
        super().__init__(message)
        self.reason_code = reason_code


def normalize_batch(raw: bytes) -> NormalizationResult:
    batch = dataplane_pb2.DataBatch()
    try:
        json_format.Parse(raw.decode(), batch, ignore_unknown_fields=False)
        _validate_batch(batch)
        records = _normalized_records(batch)
    except (UnicodeDecodeError, json_format.ParseError) as error:
        return _rejected(batch, "invalid_data_batch", str(error))
    except NormalizationError as error:
        return _rejected(batch, error.reason_code, str(error))
    return NormalizationResult(tuple(records))


def _validate_batch(batch: dataplane_pb2.DataBatch) -> None:
    if batch.schema_version != DATA_PLANE_SCHEMA:
        raise NormalizationError("unsupported_schema_version", batch.schema_version)
    header = batch.header
    if not header.batch_id.strip() or not header.tenant_id.strip() or not header.agent_id.strip():
        raise NormalizationError("invalid_data_batch", "batch identity is required")
    if header.event_count != len(batch.events) or header.signal_count != len(batch.signals):
        raise NormalizationError("invalid_data_batch", "declared frame count does not match payload")
    _validate_candidate_references(batch)


def _validate_candidate_references(batch: dataplane_pb2.DataBatch) -> None:
    events = _event_subjects(batch)
    for frame in batch.signals:
        signal = frame.signal
        if not _is_model_candidate(signal):
            continue
        subjects = [
            entity.key.strip()
            for entity in signal.entities
            if entity.kind == "process" and entity.role == "subject"
        ]
        if len(subjects) > 1:
            _candidate_error("ambiguous_candidate_subject", signal.id)
        if len(subjects) != 1 or not subjects[0]:
            _candidate_error("missing_candidate_subject", signal.id)
        matched, mismatched = _match_current_events(signal.event_refs, subjects[0], events)
        if mismatched:
            _candidate_error("candidate_event_subject_mismatch", signal.id)
        if not matched:
            _candidate_error("missing_current_candidate_event", signal.id)


def _event_subjects(batch: dataplane_pb2.DataBatch) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for frame in batch.events:
        event_id = frame.event.id.strip()
        if event_id:
            result.setdefault(event_id, []).append(frame.event.subject_proc.stable_id.strip())
    return result


def _match_current_events(refs, subject: str, events: dict[str, list[str]]) -> tuple[bool, bool]:
    matched = mismatched = False
    for event_ref in refs:
        for event_subject in events.get(event_ref.strip(), ()):
            matched = matched or event_subject == subject
            mismatched = mismatched or event_subject != subject
    return matched, mismatched


def _candidate_error(code: str, signal_id: str) -> None:
    raise NormalizationError(code, f'model candidate "{signal_id}" violates {code}')


def _is_model_candidate(signal: signal_pb2.Signal) -> bool:
    return (
        signal.detector_kind == signal_pb2.DETECTOR_KIND_MODEL
        and signal.stage == signal_pb2.SIGNAL_STAGE_CANDIDATE
    )


def _normalized_records(batch: dataplane_pb2.DataBatch):
    result = []
    fallback = _batch_time_ns(batch)
    for frame in batch.events:
        event = frame.event
        if event.tenant_id and event.tenant_id != batch.header.tenant_id:
            raise NormalizationError("invalid_data_batch", "event tenant does not match batch")
        event.tenant_id = batch.header.tenant_id
        record = _record(batch, event.labels, _observed_ns(frame.observed_at, fallback), frame.sequence)
        record.event.CopyFrom(event)
        result.append(record)
    for frame in batch.signals:
        record = _record(batch, frame.signal.labels, _observed_ns(frame.observed_at, fallback), frame.sequence)
        record.signal.CopyFrom(frame.signal)
        result.append(record)
    return result


def _record(batch, labels, observed_ns: int, sequence: int) -> streaming_pb2.NormalizedTelemetry:
    policy_id, policy_version = _policy_reference(labels)
    context = streaming_pb2.RecordContext(
        tenant_id=batch.header.tenant_id,
        agent_id=batch.header.agent_id,
        host_id=batch.header.host_id,
        batch_id=batch.header.batch_id,
        policy_id=policy_id,
        policy_version=policy_version,
        policy_mode=batch.header.policy_mode,
        observed_at_unix_nano=observed_ns,
        analysis_scope_key=_scope_key(labels),
        labels=labels,
        record_sequence=sequence,
    )
    return streaming_pb2.NormalizedTelemetry(
        schema_version=NORMALIZED_SCHEMA,
        context=context,
    )


def _policy_reference(labels) -> tuple[str, int]:
    policy_id = labels.get("policy_id", "").strip()
    raw_version = labels.get("policy_version", "").strip()
    try:
        policy_version = int(raw_version)
    except ValueError as error:
        raise NormalizationError("invalid_data_batch", "invalid policy_version") from error
    if not policy_id or policy_version <= 0:
        raise NormalizationError("invalid_data_batch", "policy_id and policy_version are required")
    return policy_id, policy_version


def _scope_key(labels) -> str:
    selected = {key: labels[key].strip() for key in SCOPE_LABELS if labels.get(key, "").strip()}
    return ",".join(f"{key}={selected[key]}" for key in sorted(selected))


def _batch_time_ns(batch: dataplane_pb2.DataBatch) -> int:
    latest = batch.header.created_at_unix_nano
    for frame in batch.events:
        latest = max(latest, frame.event.occurred_at_ns, _observed_ns(frame.observed_at, 0))
    for frame in batch.signals:
        latest = max(latest, _observed_ns(frame.observed_at, 0))
    return latest


def _observed_ns(value: str, fallback: int) -> int:
    try:
        return int(datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp() * 1e9)
    except ValueError:
        return fallback


def _rejected(batch, reason_code: str, message: str) -> NormalizationResult:
    rejection = streaming_pb2.RejectedTelemetry(
        schema_version=REJECTED_SCHEMA,
        tenant_id=batch.header.tenant_id,
        agent_id=batch.header.agent_id,
        batch_id=batch.header.batch_id,
        reason_code=reason_code,
        message=message,
    )
    return NormalizationResult((), rejection)
