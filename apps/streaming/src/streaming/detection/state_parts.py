"""Small state containers separating facts from detector-owned state."""

from dataclasses import dataclass, field


@dataclass
class GraphState:
    """Mutable graph facts and their incremental snapshots."""

    events: list = field(default_factory=list)
    graph: object | None = None


@dataclass
class SignalState:
    """Signals retained for correlation and their expiry index."""

    signals: list = field(default_factory=list)
    expiries: dict[str, int] = field(default_factory=dict)


@dataclass
class CampaignState:
    """Opaque state owned by configured detectors."""

    detector_states: dict[str, bytes] = field(default_factory=dict)
    detector_state_expiries: dict[str, int] = field(default_factory=dict)
