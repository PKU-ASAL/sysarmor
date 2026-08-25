from dataclasses import dataclass, field

from packages.contracts.proto.streaming.v1 import streaming_pb2

from sysarmor_streaming.operators.analysis import analyze


DEFAULT_STATE_RETENTION_NS = 300_000_000_000
MAX_SCOPE_RECORDS = 100_000


@dataclass(frozen=True)
class DetectionResult:
    artifacts: tuple = ()
    late: object | None = None
    failure: object | None = None


@dataclass
class _ScopeState:
    events: list = field(default_factory=list)
    signals: list = field(default_factory=list)
    emitted: dict[str, int] = field(default_factory=dict)
    expiries: dict[str, int] = field(default_factory=dict)
    latest_ns: int = 0


class DetectionState:
    def __init__(self, max_scope_records=MAX_SCOPE_RECORDS):
        self._scopes: dict[str, _ScopeState] = {}
        self._max_scope_records = max_scope_records

    def process(self, record, watermark_ns: int, policies: dict) -> DetectionResult:
        context = record.context
        policy = policies.get((context.tenant_id, context.policy_id, context.policy_version))
        if policy is None:
            return DetectionResult(failure=_failure(record, "policy_version_unavailable", True))
        if policy.tenant_id != context.tenant_id:
            return DetectionResult(failure=_failure(record, "policy_tenant_mismatch", False))
        observed_ns = _observed_at(record)
        if watermark_ns > 0 and observed_ns <= watermark_ns:
            return DetectionResult(
                late=streaming_pb2.LateTelemetry(
                    telemetry=record, watermark_unix_nano=watermark_ns
                )
            )
        scope = self._scopes.setdefault(context.analysis_scope_key, _ScopeState())
        scope.latest_ns = max(scope.latest_ns, observed_ns)
        if record.WhichOneof("payload") == "event":
            scope.events.append((observed_ns, record))
        else:
            scope.signals.append((observed_ns, record))
        scope.expiries[_record_id(record)] = observed_ns + _retention_ns(policy)
        self._evict(scope, policy)
        result = analyze(
            [item.event for _, item in scope.events],
            [item.signal for _, item in scope.signals],
            policy.detection,
        )
        artifacts = []
        direct = record.signal if record.WhichOneof("payload") == "signal" else None
        for artifact in _artifacts(context, observed_ns, result, direct):
            identity = _artifact_id(artifact)
            if identity and identity not in scope.emitted:
                scope.emitted[identity] = observed_ns
                artifacts.append(artifact)
        return DetectionResult(artifacts=tuple(artifacts))

    def event_count(self, scope_key: str) -> int:
        return len(self._scopes.get(scope_key, _ScopeState()).events)

    def signal_count(self, scope_key: str) -> int:
        return len(self._scopes.get(scope_key, _ScopeState()).signals)

    def event_ids(self, scope_key: str) -> set[str]:
        return {
            record.event.id
            for _, record in self._scopes.get(scope_key, _ScopeState()).events
        }

    def restore(self, scope_key: str, records, policies=None) -> None:
        scope = _ScopeState()
        policies = policies or {}
        for record in records:
            observed_ns = _observed_at(record)
            scope.latest_ns = max(scope.latest_ns, observed_ns)
            target = scope.events if record.WhichOneof("payload") == "event" else scope.signals
            target.append((observed_ns, record))
            policy = policies.get(_policy_identity(record))
            scope.expiries[_record_id(record)] = observed_ns + (
                _retention_ns(policy) if policy is not None else DEFAULT_STATE_RETENTION_NS
            )
        self._scopes[scope_key] = scope

    def restore_emissions(self, scope_key: str, emissions) -> None:
        scope = self._scopes.setdefault(scope_key, _ScopeState())
        scope.emitted = {identity: observed_ns for observed_ns, identity in emissions}

    def emissions(self, scope_key: str):
        scope = self._scopes.get(scope_key, _ScopeState())
        return sorted((observed_ns, identity) for identity, observed_ns in scope.emitted.items())

    def cleanup(self, scope_key: str, timestamp_ns: int, policy) -> None:
        scope = self._scopes.setdefault(scope_key, _ScopeState())
        scope.latest_ns = max(scope.latest_ns, timestamp_ns)
        self._evict(scope, policy)

    def records(self, scope_key: str):
        scope = self._scopes.get(scope_key, _ScopeState())
        return [record for _, record in sorted([*scope.events, *scope.signals], key=_record_order)]

    def _evict(self, scope: _ScopeState, policy) -> None:
        window = policy.detection.converge.state_retention_ns or DEFAULT_STATE_RETENTION_NS
        cutoff = scope.latest_ns - window
        scope.events = [
            item for item in scope.events
            if scope.expiries.get(_record_id(item[1]), DEFAULT_STATE_RETENTION_NS + item[0]) > scope.latest_ns
        ]
        scope.signals = [
            item for item in scope.signals
            if scope.expiries.get(_record_id(item[1]), DEFAULT_STATE_RETENTION_NS + item[0]) > scope.latest_ns
        ]
        active_ids = {_record_id(item[1]) for item in [*scope.events, *scope.signals]}
        scope.expiries = {
            identity: expiry for identity, expiry in scope.expiries.items()
            if identity in active_ids
        }
        retained = sorted([*scope.events, *scope.signals], key=_record_order)[
            -self._max_scope_records :
        ]
        scope.events = [item for item in retained if item[1].WhichOneof("payload") == "event"]
        scope.signals = [item for item in retained if item[1].WhichOneof("payload") == "signal"]
        emissions = sorted(
            (observed_ns, identity)
            for identity, observed_ns in scope.emitted.items()
        )[-self._max_scope_records :]
        scope.emitted = {identity: observed_ns for observed_ns, identity in emissions}


def _observed_at(record) -> int:
    if record.WhichOneof("payload") == "event" and record.event.occurred_at_ns:
        return record.event.occurred_at_ns
    return record.context.observed_at_unix_nano


def _record_order(value):
    observed_ns, record = value
    payload = record.WhichOneof("payload")
    identity = record.event.id if payload == "event" else record.signal.id
    return observed_ns, payload, identity


def _failure(record, reason: str, retryable: bool):
    return streaming_pb2.DetectionFailure(
        telemetry=record,
        reason_code=reason,
        message=reason,
        retryable=retryable,
    )


def _record_id(record) -> str:
    payload = record.WhichOneof("payload")
    identity = record.event.id if payload == "event" else record.signal.id
    return payload + ":" + identity


def _policy_identity(record):
    context = record.context
    return context.tenant_id, context.policy_id, context.policy_version


def _retention_ns(policy) -> int:
    if policy is None:
        return DEFAULT_STATE_RETENTION_NS
    return policy.detection.converge.state_retention_ns or DEFAULT_STATE_RETENTION_NS


def _artifacts(context, observed_ns, result, direct_signal=None) -> list:
    artifacts = []
    if direct_signal is not None:
        artifacts.append(
            streaming_pb2.AnalysisArtifact(
                schema_version="sysarmor.analysis.artifact/v1",
                tenant_id=context.tenant_id,
                analysis_scope_key=context.analysis_scope_key,
                observed_at_unix_nano=observed_ns,
                signal=direct_signal,
            )
        )
    for signal in result.cloud_signals:
        artifacts.append(
            streaming_pb2.AnalysisArtifact(
                schema_version="sysarmor.analysis.artifact/v1",
                tenant_id=context.tenant_id,
                analysis_scope_key=context.analysis_scope_key,
                observed_at_unix_nano=observed_ns,
                signal=signal,
            )
        )
    for incident in result.incidents:
        artifacts.append(
            streaming_pb2.AnalysisArtifact(
                schema_version="sysarmor.analysis.artifact/v1",
                tenant_id=context.tenant_id,
                analysis_scope_key=context.analysis_scope_key,
                observed_at_unix_nano=observed_ns,
                incident=incident,
            )
        )
    return artifacts


def _artifact_id(artifact) -> str:
    payload = artifact.WhichOneof("payload")
    return artifact.signal.id if payload == "signal" else artifact.incident.id
