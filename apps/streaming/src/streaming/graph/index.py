from dataclasses import dataclass

from packages.contracts.proto.signal.v1 import signal_pb2

from streaming.graph.state import entity_id


@dataclass(frozen=True)
class CorrelationView:
    by_name: dict

    @classmethod
    def empty(cls):
        return cls(by_name={})

    def add(self, signals, policy=None):
        enabled = set(policy.endpoint_rules) if policy is not None else set()
        index = {name: list(values) for name, values in self.by_name.items()}
        for signal in signals:
            if enabled and signal.name not in enabled:
                continue
            values = index.setdefault(signal.name, [])
            if signal.id and any(item.id == signal.id for item in values):
                continue
            values.append(signal)
        return CorrelationView(index)

    def remove(self, signal_ids):
        expired = set(signal_ids)
        return CorrelationView({
            name: [signal for signal in values if signal.id not in expired]
            for name, values in self.by_name.items()
        })

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
    return CorrelationView.empty().add(signals, policy)


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
