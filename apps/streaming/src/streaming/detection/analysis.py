from dataclasses import dataclass, field, replace
import logging
import time

from streaming.detectors.contracts import (
    DetectorDelta,
    DetectorInputs,
    RequiredInput,
    detector_state_key,
)
from streaming.detectors.registry import DetectorRegistry
from streaming.investigation.convergence import decide
from streaming.graph.index import build
from streaming.investigation.investigation import investigate
from streaming.graph.state import ProvenanceGraph


LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class AnalysisResult:
    cloud_signals: tuple
    incidents: tuple
    detector_states: dict[str, bytes] = field(default_factory=dict)
    detector_state_updates: dict[str, int] = field(default_factory=dict)
    detector_diagnostics: tuple[dict, ...] = ()
    metrics: dict = field(default_factory=dict)


def analyze(
    events, signals, policy, scorer=None, context=None, graph=None, delta=None,
    detector_states=None,
) -> AnalysisResult:
    incremental = delta is not None
    delta = delta or DetectorDelta()
    view = build(events, signals, policy)
    graph = graph or ProvenanceGraph.from_events(events)
    inputs = DetectorInputs(
        events=tuple(events),
        signals=tuple(signals),
        graph=graph,
        policy=policy,
        context=context,
        delta=delta,
    )
    states = dict(detector_states or {})
    available_inputs = _available_inputs(inputs, delta)
    available_signal_kinds = frozenset(
        signal.detector_kind for signal in inputs.signals
    )
    started = time.perf_counter()
    results, state_updates, diagnostics = _run_detectors(
        inputs,
        delta,
        incremental,
        available_inputs,
        available_signal_kinds,
        states,
    )
    cloud_signals = tuple(signal for result in results for signal in result.derived_signals)
    decision = decide(view, cloud_signals, policy)
    incidents = ()
    if decision.incident:
        incidents = investigate(view, results, decision, scorer)
    return AnalysisResult(
        cloud_signals, incidents, states, state_updates, diagnostics,
        {
            "analysis_ms": (time.perf_counter() - started) * 1000,
            "detector_count": len(results),
            "cloud_signal_count": len(cloud_signals),
            "incident_count": len(incidents),
            "input_event_count": len(events),
            "input_signal_count": len(signals),
        },
    )


def _run_detectors(
    inputs, delta, incremental, available_inputs, available_signal_kinds, states
):
    detectors = DetectorRegistry.build(_detector_names(inputs.policy))
    active_state_keys = {
        detector_state_key(detector)
        for detector in detectors
        if detector.state_requirements.keyed
    }
    for state_key in tuple(states):
        if state_key not in active_state_keys:
            states.pop(state_key)
    results, state_updates, diagnostics = [], {}, []
    for detector in detectors:
        state_key = detector_state_key(detector)
        missing_state = _prepare_detector_state(detector, state_key, states)
        affected = DetectorRegistry.detector_affected_by(
            detector,
            delta.changed_inputs,
            available_inputs,
            available_signal_kinds,
        )
        can_initialize = missing_state and DetectorRegistry.detector_inputs_available(
            detector, available_inputs, available_signal_kinds
        )
        if incremental and not affected and not can_initialize:
            continue
        detector_delta = replace(delta, graph_rebuilt=True) if missing_state else delta
        detector_inputs = _inputs_for(
            detector, inputs, detector_delta, states.get(state_key, b"")
        )
        started = time.perf_counter()
        try:
            result = detector.analyze(detector_inputs)
        except Exception as error:
            failure = _failure_diagnostic(detector, error)
            LOGGER.warning("detector analysis failed: %s", failure, exc_info=True)
            diagnostics.append(failure)
            continue
        elapsed_ms = (time.perf_counter() - started) * 1000
        diagnostics.append({
            "detector": detector.name,
            "version": detector.version,
            "status": "ok",
            "processing_ms": elapsed_ms,
            "state_bytes": len(result.state_update or states.get(state_key, b"")),
            "new_event_count": len(detector_delta.new_events),
            "new_signal_count": len(detector_delta.new_signals),
        })
        if result.state_update is not None:
            if not detector.state_requirements.keyed:
                raise ValueError(f"detector {detector.name} returned undeclared keyed state")
            if not isinstance(result.state_update, bytes):
                raise TypeError(f"detector {detector.name} state update must be bytes")
            states[state_key] = result.state_update
            state_updates[state_key] = detector.state_requirements.ttl_ns
        results.append(result)
    return results, state_updates, tuple(diagnostics)


def _inputs_for(detector, inputs, delta, detector_state):
    required = frozenset(detector.required_inputs)
    return replace(
        inputs,
        events=(inputs.events if RequiredInput.NORMALIZED_EVENT in required else ()),
        signals=(inputs.signals if RequiredInput.SIGNAL in required else ()),
        graph=(inputs.graph if RequiredInput.PROVENANCE_EDGE in required else None),
        delta=_delta_for(required, delta),
        detector_state=detector_state,
    )


def _delta_for(required, delta):
    return DetectorDelta(
        new_events=delta.new_events if RequiredInput.NORMALIZED_EVENT in required else (),
        new_signals=delta.new_signals if RequiredInput.SIGNAL in required else (),
        expired_event_refs=(
            delta.expired_event_refs if RequiredInput.NORMALIZED_EVENT in required else ()
        ),
        expired_signal_refs=(
            delta.expired_signal_refs if RequiredInput.SIGNAL in required else ()
        ),
        changed_node_ids=(
            delta.changed_node_ids if RequiredInput.PROVENANCE_EDGE in required else ()
        ),
        changed_edge_ids=(
            delta.changed_edge_ids if RequiredInput.PROVENANCE_EDGE in required else ()
        ),
        graph_rebuilt=delta.graph_rebuilt,
    )


def _failure_diagnostic(detector, error):
    return {
        "detector": detector.name,
        "version": detector.version,
        "status": "failed",
        "error_type": type(error).__name__,
        "message": str(error),
    }


def _detector_names(policy):
    names = tuple(getattr(policy, "detectors", ())) if policy is not None else ()
    return names or tuple(sorted(DetectorRegistry.known()))


def _available_inputs(inputs, delta):
    available = {RequiredInput.PROVENANCE_EDGE}
    if inputs.events or delta.new_events or delta.expired_event_refs:
        available.add(RequiredInput.NORMALIZED_EVENT)
    if inputs.signals or delta.new_signals or delta.expired_signal_refs:
        available.add(RequiredInput.SIGNAL)
    return frozenset(available)


def _prepare_detector_state(detector, state_key: str, states: dict) -> bool:
    if not detector.state_requirements.keyed:
        return False
    family_prefix = f"{detector.name}@"
    for existing_key in tuple(states):
        if existing_key.startswith(family_prefix) and existing_key != state_key:
            states.pop(existing_key)
    return state_key not in states
