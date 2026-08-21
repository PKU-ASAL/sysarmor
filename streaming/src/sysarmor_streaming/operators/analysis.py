from dataclasses import dataclass

from packages.contracts.proto.signal.v1 import signal_pb2

from sysarmor_streaming.operators.convergence import cross_lineage_enabled, decide
from sysarmor_streaming.operators.correlation import (
    build,
    common_labels,
    entities_for,
    related,
)
from sysarmor_streaming.operators.identity import signal_digest
from sysarmor_streaming.operators.incident import build_incident
from sysarmor_streaming.operators.provenance import ProvenanceGraph


@dataclass(frozen=True)
class AnalysisResult:
    cloud_signals: tuple
    incidents: tuple


@dataclass(frozen=True)
class RuleMatch:
    signal: object
    contributors: tuple


def analyze(events, signals, policy, scorer=None) -> AnalysisResult:
    view = build(events, signals, policy)
    graph = ProvenanceGraph.from_events(events)
    matches = _cloud_matches(view, policy, graph)
    cloud_signals = [match.signal for match in matches]
    decision = decide(view, cloud_signals, policy)
    incidents = ()
    if decision.incident:
        contributors = _incident_contributors(view, matches, decision)
        incidents = (build_incident(events, contributors, decision, scorer),)
    return AnalysisResult(tuple(cloud_signals), incidents)


def _cloud_matches(view, policy, graph) -> list:
    result = []
    if _cloud_rule_enabled(policy, "dropped_payload_executed_and_connects"):
        match = _match_payload_chain(view, policy, graph)
        if match:
            result.append(_rule_match("dropped_payload_executed_and_connects", 80, view, match))
    if (
        _cloud_rule_enabled(policy, "web_shell_chain")
        and view.has("web_runtime_spawns_shell")
        and view.has_conclusion("reverse_shell_pattern")
    ):
        match = _match_pair(view, "web_runtime_spawns_shell", "reverse_shell_pattern", policy, graph, True)
        if match:
            result.append(_rule_match("web_shell_chain", 85, view, match))
    return result


def _match_payload_chain(view, policy, graph):
    match = _match_pair(view, "payload_dropped", "reverse_shell_pattern", policy, graph, True)
    if match:
        return match
    return _match_pair(view, "payload_dropped", "suspicious_exec_connect", policy, graph, False)


def _match_pair(view, left_name, right_name, policy, graph, require_conclusion):
    matches, crossed = [], False
    for left in view.by_name.get(left_name, ()):
        for right in view.by_name.get(right_name, ()):
            if require_conclusion and right.stage != signal_pb2.SIGNAL_STAGE_CONCLUSION:
                continue
            if not _has_rule_source(left, right):
                continue
            is_related, is_crossed = related(left, right, graph, cross_lineage_enabled(policy))
            if is_related:
                matches.extend((left, right))
                crossed = crossed or is_crossed
    return (_unique_signals(matches), crossed) if matches else None


def _rule_match(name, risk, view, match):
    contributors, cross_lineage = match
    signal = signal_pb2.Signal(
        name=name,
        where=signal_pb2.SIGNAL_WHERE_CLOUD,
        base_risk=risk,
        local_rarity=1,
        global_rarity=1,
        entities=entities_for(contributors),
        signal_refs=sorted({item.id for item in contributors if item.id}),
        cross_lineage=cross_lineage,
        labels=common_labels(contributors),
        stage=signal_pb2.SIGNAL_STAGE_CONCLUSION,
        detector_kind=signal_pb2.DETECTOR_KIND_RULE,
    )
    signal.id = "cloud-sig-" + signal_digest([signal])
    return RuleMatch(signal, contributors)


def _incident_contributors(view, matches, decision):
    if decision.method == "additive_threshold":
        endpoint = [signal for values in view.by_name.values() for signal in values]
        return [*_sorted_signals(endpoint), *(match.signal for match in matches)]
    endpoint = [signal for match in matches for signal in match.contributors]
    endpoint.extend(
        signal
        for signal in view.by_name.get("reverse_shell_pattern", ())
        if signal.stage == signal_pb2.SIGNAL_STAGE_CONCLUSION
        and signal.detector_kind == signal_pb2.DETECTOR_KIND_RULE
    )
    return [*_unique_signals(endpoint), *(match.signal for match in matches)]


def _unique_signals(signals):
    values = {}
    for signal in signals:
        values.setdefault(id(signal), signal)
    return _sorted_signals(values.values())


def _sorted_signals(signals):
    return tuple(
        sorted(signals, key=lambda signal: signal.SerializeToString(deterministic=True))
    )


def _has_rule_source(*signals) -> bool:
    return any(signal.detector_kind == signal_pb2.DETECTOR_KIND_RULE for signal in signals)


def _cloud_rule_enabled(policy, name: str) -> bool:
    return not policy.cloud_rules or name in policy.cloud_rules
