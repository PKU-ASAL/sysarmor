"""rule-correlation-v1: the current rule-correlation baseline as a Detector.

Extracted from ``operators.analysis._cloud_matches`` unchanged in behavior.
Correlates endpoint rule signals over the provenance graph and emits cloud
conclusion signals.
"""

from __future__ import annotations

from dataclasses import dataclass

from packages.contracts.proto.signal.v1 import signal_pb2

from sysarmor_streaming.detectors.contracts import (
    DetectorInputs,
    DetectionResult,
    RequiredInput,
    StateRequirements,
)
from sysarmor_streaming.operators.convergence import cross_lineage_enabled
from sysarmor_streaming.operators.correlation import (
    build,
    common_labels,
    entities_for,
    related,
)
from sysarmor_streaming.operators.identity import signal_digest


@dataclass(frozen=True)
class RuleMatch:
    signal: object
    contributors: tuple


class RuleCorrelationDetector:
    name = "rule-correlation-v1"
    version = "1"
    required_inputs = (RequiredInput.SIGNAL, RequiredInput.PROVENANCE_EDGE)
    state_requirements = StateRequirements()

    def analyze(self, inputs: DetectorInputs) -> DetectionResult:
        view = build(inputs.events, inputs.signals, inputs.policy)
        matches = _cloud_matches(view, inputs.policy, inputs.graph)
        signals = tuple(match.signal for match in matches)
        contributors = _unique_signals(
            signal for match in matches for signal in match.contributors
        )
        return DetectionResult(
            algorithm_name=self.name,
            algorithm_version=self.version,
            derived_signals=signals,
            signal_refs=tuple(
                sorted({item.id for match in matches for item in match.contributors if item.id})
            ),
            contributors=contributors,
        )

    def diagnostics(self) -> dict:
        return {}


def _cloud_matches(view, policy, graph) -> list:
    result = []
    if _cloud_rule_enabled(policy, "dropped_payload_executed_and_connects"):
        match = _match_payload_chain(view, policy, graph)
        if match:
            result.append(
                _rule_match("dropped_payload_executed_and_connects", 80, view, match)
            )
    if (
        _cloud_rule_enabled(policy, "web_shell_chain")
        and view.has("web_runtime_spawns_shell")
        and view.has_conclusion("reverse_shell_pattern")
    ):
        match = _match_pair(
            view, "web_runtime_spawns_shell", "reverse_shell_pattern", policy, graph, True
        )
        if match:
            result.append(_rule_match("web_shell_chain", 85, view, match))
    return result


def _match_payload_chain(view, policy, graph):
    match = _match_pair(view, "payload_dropped", "reverse_shell_pattern", policy, graph, True)
    if not match:
        match = _match_pair(view, "payload_dropped", "suspicious_exec_connect", policy, graph, False)
    return _with_related_downloads(view, match, policy, graph) if match else None


def _with_related_downloads(view, match, policy, graph):
    contributors, crossed = match
    downloads = (
        candidate
        for candidate in view.by_name.get("download_by_lolbin", ())
        if any(
            related(candidate, contributor, graph, cross_lineage_enabled(policy))[0]
            for contributor in contributors
        )
    )
    return (_unique_signals((*contributors, *downloads)), crossed)


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
