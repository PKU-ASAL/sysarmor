from dataclasses import dataclass

from packages.contracts.proto.signal.v1 import signal_pb2
from streaming.detectors.contracts import cross_lineage_enabled


@dataclass(frozen=True)
class Decision:
    incident: bool
    method: str
    controls: tuple[str, ...]


def decide(view, cloud_signals, policy) -> Decision:
    converge = policy.converge if policy.HasField("converge") else None
    if converge is not None and converge.mode == "additive_threshold":
        threshold = converge.additive_risk_threshold or 100
        risk = sum(signal.base_risk for values in view.by_name.values() for signal in values)
        incident = _has_any_conclusion(view) and risk >= threshold
        return Decision(incident, "additive_threshold", ("additive_threshold",))
    if view.has_conclusion("reverse_shell_pattern"):
        eligible = any(
            signal.stage == signal_pb2.SIGNAL_STAGE_CONCLUSION
            and signal.detector_kind == signal_pb2.DETECTOR_KIND_RULE
            for signal in view.by_name.get("reverse_shell_pattern", ())
        )
        if eligible:
            return Decision(True, "rarity+causal-topk", ("conclusion_reverse_shell",))
    if cross_lineage_enabled(policy) and any(
        signal.name == "dropped_payload_executed_and_connects"
        and signal.cross_lineage
        for signal in cloud_signals
    ):
        return Decision(True, "rarity+causal-topk", ("cross_lineage_payload_connect",))
    conclusions = tuple(
        signal for signal in cloud_signals
        if signal.stage == signal_pb2.SIGNAL_STAGE_CONCLUSION
    )
    if conclusions:
        controls = tuple(sorted({f"detector:{signal.name}" for signal in conclusions}))
        return Decision(True, "detector-conclusion", controls)
    return Decision(False, "rarity+causal-topk", ())


def _has_any_conclusion(view) -> bool:
    return any(
        signal.stage == signal_pb2.SIGNAL_STAGE_CONCLUSION
        for values in view.by_name.values()
        for signal in values
    )
