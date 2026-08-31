"""Pluggable cloud-side Detector contract.

This module defines the pure-logic contract Detectors implement and the
structured inputs/outputs they consume and produce. It does not import Kafka,
OpenSearch, or Flink types -- a Detector is a pure function of facts.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol

from packages.contracts.proto.event.v1 import event_pb2
from packages.contracts.proto.incident.v1 import incident_pb2
from packages.contracts.proto.signal.v1 import signal_pb2


class RequiredInput(StrEnum):
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
class DetectionResult:
    """Unified output every Detector produces.

    ``node_scores`` carries per-node anomaly scores for ML detectors
    (e.g. nodlink); rule detectors leave it empty. All results must carry
    algorithm identity plus the input window and references so they are
    auditable, reproducible, and comparable.
    """

    algorithm_name: str
    algorithm_version: str
    derived_signals: tuple[signal_pb2.Signal, ...] = ()
    evidence: incident_pb2.EvidenceSubgraph | None = None
    conclusions: tuple[signal_pb2.Signal, ...] = ()
    incidents: tuple[incident_pb2.Incident, ...] = ()
    event_refs: tuple[str, ...] = ()
    edge_refs: tuple[str, ...] = ()
    signal_refs: tuple[str, ...] = ()
    contributors: tuple[signal_pb2.Signal, ...] = ()
    node_scores: dict[str, float] = field(default_factory=dict)
    diagnostics: dict = field(default_factory=dict)


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
    Detectors must not read Kafka, OpenSearch, PostgreSQL, or Agent-private
    state -- the framework satisfies ``required_inputs`` and
    ``state_requirements`` on their behalf.
    """

    name: str
    version: str
    required_inputs: tuple[RequiredInput, ...]
    state_requirements: StateRequirements

    def analyze(self, inputs: DetectorInputs) -> DetectionResult: ...

    def diagnostics(self) -> dict: ...
