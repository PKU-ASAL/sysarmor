from dataclasses import dataclass

from packages.contracts.proto.signal.v1 import signal_pb2

from sysarmor_streaming.operators.provenance import entity_id


@dataclass(frozen=True)
class CorrelationView:
    by_name: dict

    def has(self, name: str) -> bool:
        return bool(self.by_name.get(name))

    def has_conclusion(self, name: str) -> bool:
        return any(
            signal.stage == signal_pb2.SIGNAL_STAGE_CONCLUSION
            for signal in self.by_name.get(name, ())
        )

    def entities(self, *names: str):
        signals = [signal for name in names for signal in self.by_name.get(name, ())]
        return entities_for(signals)

    def signal_refs(self, *names: str) -> list[str]:
        return sorted(
            {
                signal.id
                for name in names
                for signal in self.by_name.get(name, ())
                if signal.id
            }
        )


def build(events, signals, policy) -> CorrelationView:
    enabled = set(policy.endpoint_rules)
    by_name = {}
    for signal in signals:
        if not enabled or signal.name in enabled:
            by_name.setdefault(signal.name, []).append(signal)
    return CorrelationView(by_name=by_name)


def entities_for(signals):
    values = {}
    for signal in signals:
        for entity in signal.entities:
            normalized = normalize_entity(entity)
            if normalized.kind and normalized.key:
                values[(normalized.kind, normalized.key, normalized.role)] = normalized
    return [values[key] for key in sorted(values)]


def normalize_entity(entity):
    kind = entity.kind.strip().lower()
    return signal_pb2.EntityRef(
        kind=kind,
        key=entity_id(kind, entity.key),
        role=entity.role.strip().lower(),
    )


def related(left, right, graph, allow_cross_lineage: bool) -> tuple[bool, bool]:
    if left.lineage_id and left.lineage_id == right.lineage_id:
        return True, False
    if not allow_cross_lineage:
        return False, False
    left_entities = {(item.kind, item.key) for item in entities_for([left])}
    right_entities = {(item.kind, item.key) for item in entities_for([right])}
    connected = bool(left_entities & right_entities) or graph.connects(left, right)
    return connected, connected


def common_labels(records) -> dict[str, str]:
    labeled = [dict(record.labels) for record in records if record.labels]
    if not labeled:
        return {}
    common = labeled[0]
    for labels in labeled[1:]:
        common = {key: value for key, value in common.items() if labels.get(key) == value}
    return common
