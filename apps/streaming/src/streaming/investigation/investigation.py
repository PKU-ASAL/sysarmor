"""Investigation: assemble Evidence/Conclusion/Incident from DetectionResults.

Investigation composes Detector outputs into incidents; Detectors decide what
is anomalous, Investigation organizes the evidence and the case.
"""

from __future__ import annotations

from packages.contracts.proto.signal.v1 import signal_pb2
from packages.contracts.proto.incident.v1 import incident_pb2

from streaming.investigation.incident import build_incident


def investigate(view, results, decision, scorer=None):
    findings = tuple(finding for result in results for finding in result.findings)
    if findings:
        contributors = _finding_contributors(findings)
        evidence = _merge_finding_evidence(findings)
    else:
        contributors = _incident_contributors(view, results, decision)
        evidence = _select_evidence(results)
    return (build_incident(contributors, decision, evidence, scorer),)


def _finding_contributors(findings):
    signals = [signal for finding in findings for signal in finding.contributors]
    signals.extend(finding.conclusion for finding in findings)
    return _unique_sorted(signals)


def _merge_finding_evidence(findings):
    return _merge_evidence(tuple(finding.evidence for finding in findings))


def _incident_contributors(view, results, decision):
    derived = tuple(signal for result in results for signal in result.derived_signals)
    if decision.method == "additive_threshold":
        endpoint = [signal for values in view.by_name.values() for signal in values]
        return tuple(
            sorted(
                (*endpoint, *derived),
                key=lambda signal: signal.SerializeToString(deterministic=True),
            )
        )
    endpoint = [signal for result in results for signal in result.contributors]
    endpoint.extend(
        signal
        for values in view.by_name.values()
        for signal in values
        if signal.stage == signal_pb2.SIGNAL_STAGE_CONCLUSION
    )
    return _unique_sorted((*endpoint, *derived))


def _unique_sorted(signals):
    values = {signal.SerializeToString(deterministic=True): signal for signal in signals}
    return tuple(values[key] for key in sorted(values))


def _select_evidence(results):
    relevant = [
        result.evidence for result in results
        if result.evidence is not None and _has_derived_conclusion(result)
    ]
    candidates = relevant or [
        result.evidence for result in results if result.evidence is not None
    ]
    return _merge_evidence(candidates) if candidates else None


def _has_derived_conclusion(result):
    return any(
        signal.stage == signal_pb2.SIGNAL_STAGE_CONCLUSION
        for signal in result.derived_signals
    )


def _merge_evidence(values):
    nodes = {item.id: item for value in values for item in value.nodes}
    edges = {item.id: item for value in values for item in value.edges}
    result = incident_pb2.EvidenceSubgraph()
    result.nodes.extend(nodes[key] for key in sorted(nodes))
    result.edges.extend(edges[key] for key in sorted(edges))
    return result
