"""Offline comparison through the production state machine, without private state."""

from dataclasses import dataclass
from itertools import groupby
from time import perf_counter

from streaming.detection.state import DetectionState
from streaming.detectors.registry import DetectorRegistry
from streaming.preprocessing.policy_validation import validate_policy


@dataclass(frozen=True)
class ReplayResult:
    input_records: int
    artifacts: tuple[bytes, ...]
    batches: tuple[dict, ...]


def replay(records, policies, detectors, batch_size=256):
    """Preserve arrival order per scope; never mutate supplied policy snapshots.

    This measures offline computation, not Flink backpressure or checkpoints.
    Every invocation owns fresh state. Only consecutive records with the same
    tenant/scope/policy are batched, preserving policy transition boundaries.
    """
    if batch_size <= 0:
        raise ValueError("batch_size must be positive")
    if not detectors:
        raise ValueError("explicit detectors are required")
    DetectorRegistry.build(detectors)
    selected = _policies(policies, detectors)
    states, artifacts, timings, count = {}, [], [], 0
    for identity, group in groupby(records, _identity):
        state = states.setdefault(identity[:2], DetectionState())
        chunk = []
        for record in group:
            chunk.append(record)
            count += 1
            if len(chunk) == batch_size:
                _process(state, chunk, selected, identity, artifacts, timings)
                chunk = []
        if chunk:
            _process(state, chunk, selected, identity, artifacts, timings)
    return ReplayResult(count, tuple(artifacts), tuple(timings))


def _identity(record):
    context = record.context
    if not context.tenant_id or not context.analysis_scope_key:
        raise ValueError("replay requires tenant and analysis scope")
    return (context.tenant_id, context.analysis_scope_key,
            context.policy_id, context.policy_version)


def _policies(policies, detectors):
    selected = {}
    for key, original in policies.items():
        validate_policy(original)
        if key != (original.tenant_id, original.policy_id, original.policy_version):
            raise ValueError("replay policy key does not match snapshot identity")
        policy = type(original)()
        policy.CopyFrom(original)
        del policy.detection.detectors[:]
        policy.detection.detectors.extend(detectors)
        selected[key] = policy
    return selected


def _process(state, records, policies, identity, artifacts, timings):
    started = perf_counter()
    results = state.process_batch(records, 0, policies)
    elapsed = (perf_counter() - started) * 1000
    diagnostics, metrics = [], []
    for result in results:
        if result.failure is not None:
            raise ValueError(f"replay failure: {result.failure}")
        artifacts.extend(item.SerializeToString(deterministic=True)
                         for item in result.artifacts)
        diagnostics.extend(result.detector_diagnostics)
        if result.metrics:
            metrics.append(result.metrics)
    timings.append({
        "tenant_id": identity[0], "scope": identity[1],
        "policy_id": identity[2], "policy_version": identity[3],
        "input_records": len(records), "processing_ms": elapsed,
        "detectors": diagnostics, "analysis": metrics,
    })
