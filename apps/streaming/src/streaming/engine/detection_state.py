from dataclasses import dataclass, field

from packages.contracts.proto.streaming.v1 import streaming_pb2

from streaming.detectors.contracts import (
    AnalysisContext,
    DetectorDelta,
    RequiredInput,
)
from streaming.detectors.registry import DetectorRegistry
from streaming.engine.analysis import analyze
from streaming.engine.provenance import ProvenanceGraph


DEFAULT_STATE_RETENTION_NS = 300_000_000_000
MAX_SCOPE_RECORDS = 100_000


@dataclass(frozen=True)
class DetectionResult:
    artifacts: tuple = ()
    late: object | None = None
    failure: object | None = None
    state_rewrite_required: bool = False


@dataclass(frozen=True)
class _Eviction:
    changed: bool = False
    event_refs: tuple[str, ...] = ()
    signal_refs: tuple[str, ...] = ()


@dataclass(frozen=True)
class _AppliedChange:
    observed_ns: int
    eviction: _Eviction
    graph_rebuilt: bool
    changed_node_ids: tuple[str, ...]
    changed_edge_ids: tuple[str, ...]
    rewrite_required: bool


@dataclass
class AgentAnalysisContext:
    events: list = field(default_factory=list)
    signals: list = field(default_factory=list)
    emitted: dict[str, int] = field(default_factory=dict)
    expiries: dict[str, int] = field(default_factory=dict)
    latest_ns: int = 0
    next_expiry_ns: int = 0
    graph: ProvenanceGraph | None = None
    rewrite_required: bool = False
    pending_delta: DetectorDelta = field(default_factory=DetectorDelta)
    detector_states: dict[str, bytes] = field(default_factory=dict)
    detector_state_expiries: dict[str, int] = field(default_factory=dict)


class DetectionState:
    def __init__(self, max_scope_records=MAX_SCOPE_RECORDS):
        self._scopes: dict[str, AgentAnalysisContext] = {}
        self._max_scope_records = max_scope_records

    def process(self, record, watermark_ns: int, policies: dict) -> DetectionResult:
        return self.process_batch([record], watermark_ns, policies)[0]

    def process_batch(self, records, watermark_ns: int, policies: dict):
        if not records:
            return []
        validation = [self._validate_record(record, watermark_ns, policies) for record in records]
        failures = [result for result in validation if result is not None and result.failure]
        if failures:
            return failures
        accepted_records = [record for record, result in zip(records, validation) if result is None]
        deferred = [result for result in validation if result is not None]
        if not accepted_records:
            return deferred
        accepted, changes, results = self._apply_batch(
            accepted_records, watermark_ns, policies
        )
        if not accepted:
            return results
        last = accepted[-1]
        scope = self._scopes[last.context.analysis_scope_key]
        delta = scope.pending_delta.merged(self._batch_delta(accepted, changes))
        if not self._should_analyze(scope, delta):
            if DetectorRegistry.affected_by(delta.changed_inputs):
                scope.pending_delta = DetectorDelta(graph_rebuilt=True)
            return [*deferred, *self._direct_results(accepted, changes)]
        policy = policies[_policy_identity(last)]
        result = self._analyze(scope, last, policy, watermark_ns, delta)
        return [*deferred, *self._direct_results(accepted, changes, result)]

    def _apply_batch(self, records, watermark_ns, policies):
        accepted, changes = [], []
        for record in records:
            context = record.context
            policy = policies[_policy_identity(record)]
            scope = self._scopes.setdefault(
                context.analysis_scope_key, AgentAnalysisContext()
            )
            observed_ns = _observed_at(record)
            change = self._apply(scope, record, policy, observed_ns)
            self._expire_detector_states(scope, scope.latest_ns)
            accepted.append(record)
            changes.append(change)
        return accepted, changes, []

    @staticmethod
    def _validate_record(record, watermark_ns, policies):
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
        return None

    @staticmethod
    def _batch_delta(records, changes):
        return DetectorDelta(
            new_events=tuple(record.event for record in records if record.WhichOneof("payload") == "event"),
            new_signals=tuple(record.signal for record in records if record.WhichOneof("payload") == "signal"),
            expired_event_refs=tuple(sorted({ref for change in changes for ref in change.eviction.event_refs})),
            expired_signal_refs=tuple(sorted({ref for change in changes for ref in change.eviction.signal_refs})),
            changed_node_ids=tuple(sorted({node for change in changes for node in change.changed_node_ids})),
            changed_edge_ids=tuple(sorted({edge for change in changes for edge in change.changed_edge_ids})),
            graph_rebuilt=any(change.graph_rebuilt for change in changes),
        )

    def _direct_results(self, records, changes, result=None):
        outputs = []
        last_scope = self._scopes[records[-1].context.analysis_scope_key]
        for index, record in enumerate(records):
            scope = self._scopes[record.context.analysis_scope_key]
            artifacts = self._new_artifacts(
                scope,
                record,
                changes[index].observed_ns,
                result if index == len(records) - 1 else None,
            )
            outputs.append(
                DetectionResult(
                    artifacts=artifacts,
                    state_rewrite_required=changes[index].rewrite_required,
                )
            )
        return outputs

    def _apply(self, scope, record, policy, observed_ns) -> _AppliedChange:
        previous_order = self._last_record_order(scope)
        current_order = _record_order((observed_ns, record))
        out_of_order = previous_order is not None and current_order < previous_order
        scope.latest_ns = max(scope.latest_ns, observed_ns)
        if record.WhichOneof("payload") == "event":
            scope.events.append((observed_ns, record))
        else:
            scope.signals.append((observed_ns, record))
        if out_of_order:
            scope.events.sort(key=_record_order)
            scope.signals.sort(key=_record_order)
        expiry = observed_ns + _retention_ns(policy)
        scope.expiries[_record_id(record)] = expiry
        scope.next_expiry_ns = min(scope.next_expiry_ns or expiry, expiry)
        eviction = self._evict(scope, policy)
        graph_rebuilt = scope.graph is None or eviction.changed or (
            out_of_order and record.WhichOneof("payload") == "event"
        )
        changed_nodes, changed_edges = (), ()
        if graph_rebuilt:
            scope.graph = ProvenanceGraph.from_events(self._events(scope))
            changed_nodes = scope.graph.node_ids()
            changed_edges = tuple(edge_id for edge_id, _ in scope.graph.edges())
        elif record.WhichOneof("payload") == "event":
            graph_change = scope.graph.add_event(record.event)
            changed_nodes = graph_change.node_ids
            changed_edges = graph_change.edge_ids
        rewrite_required = scope.rewrite_required or eviction.changed or out_of_order
        return _AppliedChange(
            observed_ns, eviction, graph_rebuilt, changed_nodes,
            changed_edges, rewrite_required,
        )

    def _should_analyze(self, scope, delta) -> bool:
        available = {RequiredInput.PROVENANCE_EDGE}
        if scope.events:
            available.add(RequiredInput.NORMALIZED_EVENT)
        if scope.signals:
            available.add(RequiredInput.SIGNAL)
        signal_kinds = frozenset(
            record.signal.detector_kind for _, record in scope.signals
        )
        return DetectorRegistry.affected_by(
            delta.changed_inputs, frozenset(available), signal_kinds
        )

    @staticmethod
    def _delta(scope, record, change) -> DetectorDelta:
        return scope.pending_delta.merged(DetectorDelta(
            new_events=(record.event,) if record.WhichOneof("payload") == "event" else (),
            new_signals=(record.signal,) if record.WhichOneof("payload") == "signal" else (),
            expired_event_refs=change.eviction.event_refs,
            expired_signal_refs=change.eviction.signal_refs,
            changed_node_ids=change.changed_node_ids,
            changed_edge_ids=change.changed_edge_ids,
            graph_rebuilt=change.graph_rebuilt,
        ))

    @staticmethod
    def _analyze(scope, record, policy, watermark_ns, delta):
        context = record.context
        result = analyze(
            [item.event for _, item in scope.events],
            [item.signal for _, item in scope.signals],
            policy.detection,
            context=AnalysisContext(
                tenant_id=context.tenant_id,
                analysis_scope_key=context.analysis_scope_key,
                policy_id=context.policy_id,
                policy_version=context.policy_version,
                agent_id=context.agent_id,
                watermark_ns=watermark_ns,
                window_start_ns=min(
                    (_observed_at(item) for _, item in [*scope.events, *scope.signals]),
                    default=scope.latest_ns,
                ),
                window_end_ns=scope.latest_ns,
            ),
            graph=scope.graph,
            delta=delta,
            detector_states=scope.detector_states,
        )
        scope.pending_delta = DetectorDelta()
        DetectionState._update_detector_states(
            scope, result, scope.latest_ns, policy
        )
        return result

    @staticmethod
    def _update_detector_states(scope, result, observed_ns, policy) -> None:
        active_keys = set(result.detector_states)
        scope.detector_states = result.detector_states
        scope.detector_state_expiries = {
            key: expiry
            for key, expiry in scope.detector_state_expiries.items()
            if key in active_keys
        }
        for key, ttl_ns in result.detector_state_updates.items():
            scope.detector_state_expiries[key] = observed_ns + (
                ttl_ns or _retention_ns(policy)
            )

    @staticmethod
    def _new_artifacts(scope, record, observed_ns, result) -> tuple:
        context = record.context
        artifacts = []
        direct = record.signal if record.WhichOneof("payload") == "signal" else None
        for artifact in _artifacts(context, observed_ns, result, direct):
            identity = _artifact_id(artifact)
            if identity and identity not in scope.emitted:
                scope.emitted[identity] = observed_ns
                artifacts.append(artifact)
        return tuple(artifacts)

    def event_count(self, scope_key: str) -> int:
        return len(self._scopes.get(scope_key, AgentAnalysisContext()).events)

    def signal_count(self, scope_key: str) -> int:
        return len(self._scopes.get(scope_key, AgentAnalysisContext()).signals)

    def event_ids(self, scope_key: str) -> set[str]:
        return {
            record.event.id
            for _, record in self._scopes.get(scope_key, AgentAnalysisContext()).events
        }

    def accepts_event_changes(self, record) -> bool:
        scope = self._scopes.get(record.context.analysis_scope_key)
        if scope is None:
            return True
        return DetectorRegistry.affected_by(
            frozenset(
                {RequiredInput.NORMALIZED_EVENT, RequiredInput.PROVENANCE_EDGE}
            ),
            frozenset(
                {
                    RequiredInput.NORMALIZED_EVENT,
                    RequiredInput.PROVENANCE_EDGE,
                    *(
                        [RequiredInput.SIGNAL]
                        if scope.signals
                        else []
                    ),
                }
            ),
            frozenset(
                record.signal.detector_kind for _, record in scope.signals
            ),
        )

    def is_event_in_order(self, record) -> bool:
        scope = self._scopes.get(record.context.analysis_scope_key)
        if scope is None:
            return True
        return _record_order((_observed_at(record), record)) >= self._last_record_order(scope)

    def restore(self, scope_key: str, records, policies=None) -> None:
        scope = AgentAnalysisContext()
        policies = policies or {}
        restored = [(_observed_at(record), record) for record in records]
        ordered = sorted(restored, key=_record_order)
        scope.rewrite_required = ordered != restored
        for observed_ns, record in ordered:
            scope.latest_ns = max(scope.latest_ns, observed_ns)
            target = scope.events if record.WhichOneof("payload") == "event" else scope.signals
            target.append((observed_ns, record))
            policy = policies.get(_policy_identity(record))
            scope.expiries[_record_id(record)] = observed_ns + (
                _retention_ns(policy) if policy is not None else DEFAULT_STATE_RETENTION_NS
            )
        scope.next_expiry_ns = min(scope.expiries.values(), default=0)
        self._scopes[scope_key] = scope
        scope.graph = ProvenanceGraph.from_events(self._events(scope))
        scope.pending_delta = DetectorDelta(graph_rebuilt=True)

    def restore_emissions(self, scope_key: str, emissions) -> None:
        scope = self._scopes.setdefault(scope_key, AgentAnalysisContext())
        scope.emitted = {identity: observed_ns for observed_ns, identity in emissions}

    def restore_detector_states(self, scope_key: str, states, expiries=()) -> None:
        scope = self._scopes.setdefault(scope_key, AgentAnalysisContext())
        scope.detector_states = {str(key): bytes(value) for key, value in states}
        scope.detector_state_expiries = {
            str(key): int(value)
            for key, value in expiries
            if str(key) in scope.detector_states
        }

    def detector_states(self, scope_key: str) -> dict[str, bytes]:
        scope = self._scopes.get(scope_key, AgentAnalysisContext())
        return dict(scope.detector_states)

    def scope_keys(self) -> tuple[str, ...]:
        return tuple(sorted(self._scopes))

    def detector_state_expiries(self, scope_key: str) -> dict[str, int]:
        scope = self._scopes.get(scope_key, AgentAnalysisContext())
        return dict(scope.detector_state_expiries)

    def next_cleanup_ns(self, scope_key: str) -> int:
        scope = self._scopes.get(scope_key, AgentAnalysisContext())
        return min(
            filter(
                None,
                [scope.next_expiry_ns, *scope.detector_state_expiries.values()],
            ),
            default=0,
        )

    def emissions(self, scope_key: str):
        scope = self._scopes.get(scope_key, AgentAnalysisContext())
        return sorted((observed_ns, identity) for identity, observed_ns in scope.emitted.items())

    def cleanup(self, scope_key: str, timestamp_ns: int, policy) -> None:
        scope = self._scopes.setdefault(scope_key, AgentAnalysisContext())
        scope.latest_ns = max(scope.latest_ns, timestamp_ns)
        eviction = self._evict(scope, policy)
        self._expire_detector_states(scope, scope.latest_ns)
        if eviction.changed:
            scope.graph = ProvenanceGraph.from_events(self._events(scope))
            scope.pending_delta = scope.pending_delta.merged(DetectorDelta(
                expired_event_refs=eviction.event_refs,
                expired_signal_refs=eviction.signal_refs,
                changed_node_ids=scope.graph.node_ids(),
                changed_edge_ids=tuple(edge_id for edge_id, _ in scope.graph.edges()),
                graph_rebuilt=True,
            ))

    def records(self, scope_key: str):
        scope = self._scopes.get(scope_key, AgentAnalysisContext())
        return [record for _, record in sorted([*scope.events, *scope.signals], key=_record_order)]

    def mark_persisted(self, scope_key: str) -> None:
        scope = self._scopes.get(scope_key)
        if scope is not None:
            scope.rewrite_required = False

    def _evict(self, scope: AgentAnalysisContext, policy) -> _Eviction:
        before_count = len(scope.events) + len(scope.signals)
        if (
            before_count <= self._max_scope_records
            and len(scope.emitted) <= self._max_scope_records
            and (scope.next_expiry_ns == 0 or scope.next_expiry_ns > scope.latest_ns)
        ):
            return _Eviction()
        before_events = {_record_id(record): record.event.id for _, record in scope.events}
        before_signals = {_record_id(record): record.signal.id for _, record in scope.signals}
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
        scope.next_expiry_ns = min(scope.expiries.values(), default=0)
        retained = sorted([*scope.events, *scope.signals], key=_record_order)[
            -self._max_scope_records :
        ]
        scope.events = [item for item in retained if item[1].WhichOneof("payload") == "event"]
        scope.signals = [item for item in retained if item[1].WhichOneof("payload") == "signal"]
        active_ids = self._active_ids(scope)
        scope.expiries = {
            identity: expiry
            for identity, expiry in scope.expiries.items()
            if identity in active_ids
        }
        scope.next_expiry_ns = min(scope.expiries.values(), default=0)
        emissions = sorted(
            (observed_ns, identity)
            for identity, observed_ns in scope.emitted.items()
        )[-self._max_scope_records :]
        scope.emitted = {identity: observed_ns for observed_ns, identity in emissions}
        after = self._active_ids(scope)
        return _Eviction(
            changed=before_count != len(scope.events) + len(scope.signals),
            event_refs=tuple(sorted(value for key, value in before_events.items() if key not in after)),
            signal_refs=tuple(sorted(value for key, value in before_signals.items() if key not in after)),
        )

    @staticmethod
    def _expire_detector_states(scope: AgentAnalysisContext, timestamp_ns: int) -> None:
        expired = {
            key
            for key in scope.detector_states
            if scope.detector_state_expiries.get(key, 0) <= timestamp_ns
        }
        for key in expired:
            scope.detector_states.pop(key, None)
            scope.detector_state_expiries.pop(key, None)

    @staticmethod
    def _active_ids(scope: AgentAnalysisContext) -> set[str]:
        return {_record_id(item[1]) for item in [*scope.events, *scope.signals]}

    @staticmethod
    def _events(scope: AgentAnalysisContext) -> list:
        return [record.event for _, record in scope.events]

    @staticmethod
    def _last_record_order(scope: AgentAnalysisContext):
        tails = [values[-1] for values in (scope.events, scope.signals) if values]
        return max(map(_record_order, tails), default=None)


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
                context=context,
                signal=direct_signal,
            )
        )
    if result is None:
        return artifacts
    for signal in result.cloud_signals:
        artifacts.append(
            streaming_pb2.AnalysisArtifact(
                schema_version="sysarmor.analysis.artifact/v1",
                tenant_id=context.tenant_id,
                analysis_scope_key=context.analysis_scope_key,
                observed_at_unix_nano=observed_ns,
                context=context,
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
                context=context,
                incident=incident,
            )
        )
    return artifacts


def _artifact_id(artifact) -> str:
    payload = artifact.WhichOneof("payload")
    return artifact.signal.id if payload == "signal" else artifact.incident.id
