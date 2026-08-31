from dataclasses import dataclass

from packages.contracts.proto.signal.v1 import signal_pb2

from sysarmor_streaming.detectors.rule_correlation import (
    _cloud_matches,
    _sorted_signals,
    _unique_signals,
)
from sysarmor_streaming.operators.convergence import decide
from sysarmor_streaming.operators.correlation import build
from sysarmor_streaming.operators.incident import build_incident
from sysarmor_streaming.operators.provenance import ProvenanceGraph


@dataclass(frozen=True)
class AnalysisResult:
    cloud_signals: tuple
    incidents: tuple


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
