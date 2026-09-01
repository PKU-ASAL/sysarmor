from dataclasses import dataclass

from sysarmor_streaming.detectors.contracts import DetectorInputs
from sysarmor_streaming.detectors.factory import DetectorFactory
from sysarmor_streaming.operators.convergence import decide
from sysarmor_streaming.operators.correlation import build
from sysarmor_streaming.operators.investigation import investigate
from sysarmor_streaming.operators.provenance import ProvenanceGraph


@dataclass(frozen=True)
class AnalysisResult:
    cloud_signals: tuple
    incidents: tuple


def analyze(events, signals, policy, scorer=None, context=None) -> AnalysisResult:
    view = build(events, signals, policy)
    graph = ProvenanceGraph.from_events(events)
    inputs = DetectorInputs(
        events=tuple(events),
        signals=tuple(signals),
        graph=graph,
        policy=policy,
        context=context,
    )
    results = [detector.analyze(inputs) for detector in DetectorFactory.build_all()]
    cloud_signals = tuple(signal for result in results for signal in result.derived_signals)
    decision = decide(view, cloud_signals, policy)
    incidents = ()
    if decision.incident:
        incidents = investigate(view, results, decision, events, scorer)
    return AnalysisResult(cloud_signals, incidents)
