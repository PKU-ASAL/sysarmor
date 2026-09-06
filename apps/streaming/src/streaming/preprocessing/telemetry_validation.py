from dataclasses import dataclass

from google.protobuf.message import DecodeError
from packages.contracts.proto.streaming.v1 import streaming_pb2


NORMALIZED_SCHEMA = "sysarmor.telemetry.normalized/v1"


@dataclass(frozen=True)
class ValidationResult:
    record: object | None = None
    failure: object | None = None


def validate_telemetry(value: bytes) -> ValidationResult:
    record = streaming_pb2.NormalizedTelemetry()
    try:
        record.ParseFromString(value)
    except DecodeError:
        return _failure(record, "invalid_normalized_telemetry")
    context = record.context
    payload = record.WhichOneof("payload")
    if record.schema_version != NORMALIZED_SCHEMA:
        return _failure(record, "unsupported_normalized_schema")
    if not all(
        (context.tenant_id, context.agent_id, context.analysis_scope_key, context.policy_id)
    ) or context.policy_version == 0:
        return _failure(record, "incomplete_normalized_context")
    if context.analysis_scope_key != context.agent_id:
        return _failure(record, "normalized_scope_mismatch")
    if payload not in {"event", "signal"}:
        return _failure(record, "missing_normalized_payload")
    if payload == "event" and record.event.tenant_id != context.tenant_id:
        return _failure(record, "normalized_tenant_mismatch")
    identity = record.event.id if payload == "event" else record.signal.id
    if not identity:
        return _failure(record, "missing_normalized_identity")
    return ValidationResult(record=record)


def _failure(record, reason: str) -> ValidationResult:
    return ValidationResult(
        failure=streaming_pb2.DetectionFailure(
            telemetry=record,
            reason_code=reason,
            message=reason,
            retryable=False,
        )
    )
