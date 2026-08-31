"""Investigation: assemble Evidence/Conclusion/Incident from DetectionResults.

Investigation composes Detector outputs into incidents; Detectors decide what
is anomalous, Investigation organizes the evidence and the case.
"""

from __future__ import annotations

from packages.contracts.proto.signal.v1 import signal_pb2

from sysarmor_streaming.detectors.rule_correlation import _sorted_signals, _unique_signals
from sysarmor_streaming.operators.incident import build_incident


def investigate(view, results, decision, events, scorer=None):
    contributors = _incident_contributors(view, results, decision)
    return (build_incident(events, contributors, decision, scorer),)


def _incident_contributors(view, results, decision):
    derived = tuple(signal for result in results for signal in result.derived_signals)
    if decision.method == "additive_threshold":
        endpoint = [signal for values in view.by_name.values() for signal in values]
        return [*_sorted_signals(endpoint), *derived]
    endpoint = [signal for result in results for signal in result.contributors]
    endpoint.extend(
        signal
        for signal in view.by_name.get("reverse_shell_pattern", ())
        if signal.stage == signal_pb2.SIGNAL_STAGE_CONCLUSION
        and signal.detector_kind == signal_pb2.DETECTOR_KIND_RULE
    )
    return [*_unique_signals(endpoint), *derived]
