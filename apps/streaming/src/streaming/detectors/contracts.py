"""Pluggable cloud-side Detector contract.

This module defines the pure-logic contract Detectors implement and the
structured inputs/outputs they consume and produce. It does not import Kafka,
OpenSearch, or Flink types -- a Detector is a pure function of facts.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Protocol

from packages.contracts.proto.event.v1 import event_pb2
from packages.contracts.proto.incident.v1 import incident_pb2
from packages.contracts.proto.signal.v1 import signal_pb2


class RequiredInput(str, Enum):
    """Open set of standardized inputs a Detector may declare.

    `SIGNAL` covers every Signal regardless of detector_kind/stage; Detectors
    refine via the derived views on ``DetectorInputs`` rather than a
    hard-coded binary split (e.g. RULE vs MODEL), since DetectorKind is an
    open enum (RULE/MODEL/GRAPH/SYSTEM).
    """

    NORMALIZED_EVENT = "normalized_event"
    SIGNAL = "signal"
    PROVENANCE_EDGE = "provenance_edge"


@dataclass(frozen=True)
class StateRequirements:
    """State a Detector asks the framework to maintain on its behalf."""

    keyed: bool = False
    ttl_ns: int = 0
    version: int = 1


@dataclass(frozen=True)
class AnalysisContext:
    """Runtime context: static identity plus window/watermark boundaries."""

    tenant_id: str
    analysis_scope_key: str
    policy_id: str
    policy_version: int
    agent_id: str = ""
    watermark_ns: int = 0
    window_start_ns: int = 0
    window_end_ns: int = 0


@dataclass(frozen=True)
class DetectorDelta:
    """Changes since the previous analysis for this Agent context."""

    new_events: tuple[event_pb2.CanonicalEvent, ...] = ()
    new_signals: tuple[signal_pb2.Signal, ...] = ()
    expired_event_refs: tuple[str, ...] = ()
    expired_signal_refs: tuple[str, ...] = ()
    changed_node_ids: tuple[str, ...] = ()
    changed_edge_ids: tuple[str, ...] = ()
    graph_rebuilt: bool = False

    @property
    def changed_inputs(self) -> frozenset[RequiredInput]:
        changed = set()
        if self.new_events or self.expired_event_refs:
            changed.update((RequiredInput.NORMALIZED_EVENT, RequiredInput.PROVENANCE_EDGE))
        if self.new_signals or self.expired_signal_refs:
            changed.add(RequiredInput.SIGNAL)
        if self.changed_node_ids or self.changed_edge_ids or self.graph_rebuilt:
            changed.add(RequiredInput.PROVENANCE_EDGE)
        return frozenset(changed)

    @property
    def new_candidates(self) -> tuple[signal_pb2.Signal, ...]:
        """Model Candidate Signals introduced by this analysis window."""
        return tuple(
            signal for signal in self.new_signals
            if signal.detector_kind == signal_pb2.DETECTOR_KIND_MODEL
            and signal.stage == signal_pb2.SIGNAL_STAGE_CANDIDATE
        )

    def merged(self, other: DetectorDelta) -> DetectorDelta:
        return DetectorDelta(
            new_events=(*self.new_events, *other.new_events),
            new_signals=(*self.new_signals, *other.new_signals),
            expired_event_refs=tuple(sorted(set(self.expired_event_refs + other.expired_event_refs))),
            expired_signal_refs=tuple(sorted(set(self.expired_signal_refs + other.expired_signal_refs))),
            changed_node_ids=tuple(sorted(set(self.changed_node_ids + other.changed_node_ids))),
            changed_edge_ids=tuple(sorted(set(self.changed_edge_ids + other.changed_edge_ids))),
            graph_rebuilt=self.graph_rebuilt or other.graph_rebuilt,
        )


@dataclass(frozen=True)
class DetectorBatch:
    """Bounded incremental input delivered to one detector invocation."""

    window_id: int = 0
    watermark_ns: int = 0
    delta: DetectorDelta = field(default_factory=DetectorDelta)
    graph_delta: object | None = None
    detector_state: bytes = b""

    @property
    def new_events(self):
        return self.delta.new_events

    @property
    def new_signals(self):
        return self.delta.new_signals

    @property
    def new_candidates(self):
        return self.delta.new_candidates


@dataclass(frozen=True)
class DetectionFinding:
    """Self-contained detector finding: conclusion, evidence, and contributors."""

    correlation_key: str
    conclusion: signal_pb2.Signal
    evidence: incident_pb2.EvidenceSubgraph
    contributors: tuple[signal_pb2.Signal, ...] = ()
    event_refs: tuple[str, ...] = ()
    edge_refs: tuple[str, ...] = ()
    signal_refs: tuple[str, ...] = ()
    node_scores: dict[str, float] = field(default_factory=dict)


@dataclass(frozen=True)
class DetectionResult:
    """Unified output every Detector produces.

    ``findings`` is the only detector-owned semantic output. Each finding is
    self-contained so multiple campaigns cannot be accidentally flattened.
    """

    algorithm_name: str
    algorithm_version: str
    derived_signals: tuple[signal_pb2.Signal, ...] = ()
    findings: tuple[DetectionFinding, ...] = ()
    diagnostics: dict = field(default_factory=dict)
    state_update: bytes | None = None


@dataclass(frozen=True)
class DetectorInputs:
    """Read-only view the framework assembles per Detector's required_inputs.

    ``events`` is the universal bottom layer (normalized raw facts); ``graph``
    is an optional convenience view the framework pre-builds. A heavy Detector
    that builds its own graph simply declares only ``NORMALIZED_EVENT`` and
    ignores ``graph``.
    """

    events: tuple[event_pb2.CanonicalEvent, ...] = ()
    signals: tuple[signal_pb2.Signal, ...] = ()
    graph: object | None = None
    context: AnalysisContext | None = None
    policy: object | None = None
    delta: DetectorDelta = field(default_factory=DetectorDelta)
    detector_state: bytes = b""
    batch: DetectorBatch | None = None

    @property
    def candidates(self) -> tuple[signal_pb2.Signal, ...]:
        """Derived view: model candidates (MODEL + CANDIDATE)."""
        return tuple(
            signal
            for signal in self.signals
            if signal.detector_kind == signal_pb2.DETECTOR_KIND_MODEL
            and signal.stage == signal_pb2.SIGNAL_STAGE_CANDIDATE
        )

    @property
    def conclusions(self) -> tuple[signal_pb2.Signal, ...]:
        """Derived view: signals at conclusion stage."""
        return tuple(
            signal
            for signal in self.signals
            if signal.stage == signal_pb2.SIGNAL_STAGE_CONCLUSION
        )


class Detector(Protocol):
    """Logical interface every Detector implements.

    ``analyze`` is a pure function: standard facts in, DetectionResult out.
    Detectors must not read Kafka, OpenSearch, databases, or Agent-private
    state -- the framework satisfies ``required_inputs`` and
    ``state_requirements`` on their behalf.
    """

    name: str
    version: str
    required_inputs: tuple[RequiredInput, ...]
    signal_kinds: frozenset[int] | None
    trigger_inputs: tuple[RequiredInput, ...]
    state_requirements: StateRequirements

    def analyze(self, inputs: DetectorInputs) -> DetectionResult: ...

    def diagnostics(self) -> dict: ...


def cross_lineage_enabled(policy) -> bool:
    """Return whether a policy permits cross-lineage correlation."""
    return bool(policy is not None and policy.HasField("converge") and policy.converge.cross_lineage)


def detector_state_key(detector: Detector) -> str:
    return (
        f"{detector.name}@{detector.version}/"
        f"state-{detector.state_requirements.version}"
    )
