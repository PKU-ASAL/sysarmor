from packages.contracts.proto.incident.v1 import incident_pb2
from packages.contracts.proto.signal.v1 import signal_pb2

from streaming.engine.identity import signal_digest
from streaming.preprocessing.rarity import count_score


def build_incident(signals, decision, evidence=None, scorer=None):
    contributing = tuple(signals)
    context = [f"method:{decision.method}", *(f"control:{item}" for item in decision.controls)]
    return incident_pb2.Incident(
        id="inc-" + signal_digest(contributing, context),
        summary="SysArmor detected a causal attack chain",
        severity=80,
        lineage_ids=sorted({signal.lineage_id for signal in contributing if signal.lineage_id}),
        evidence=evidence or incident_pb2.EvidenceSubgraph(),
        converge=incident_pb2.ConvergeTrace(
            method=decision.method,
            score=(scorer or count_score)(contributing),
            controls=decision.controls,
        ),
        contributing_signals=contributing,
        labels=_common_labels(contributing),
        conclusion_entities=_conclusion_entities(contributing),
    )


def _common_labels(signals) -> dict[str, str]:
    if not signals:
        return {}
    common = dict(signals[0].labels)
    for signal in signals[1:]:
        common = {
            key: value
            for key, value in common.items()
            if signal.labels.get(key) == value
        }
    return common


def _conclusion_entities(signals) -> list[str]:
    return sorted(
        {
            entity.key
            for signal in signals
            if signal.stage == signal_pb2.SIGNAL_STAGE_CONCLUSION
            for entity in signal.entities
            if entity.kind == "process"
        }
    )
