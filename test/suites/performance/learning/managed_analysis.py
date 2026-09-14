#!/usr/bin/env python3
"""Managed Stream analysis artifact parsing for Learning experiments."""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any


def candidate_subject(signal: dict[str, Any]) -> str | None:
    subjects = {
        entity.get("key")
        for entity in signal.get("entities", [])
        if isinstance(entity, dict)
        and entity.get("kind") == "process"
        and entity.get("role") == "subject"
        and isinstance(entity.get("key"), str)
        and entity["key"]
    }
    return next(iter(subjects)) if len(subjects) == 1 else None


def candidate_refs(signal: dict[str, Any]) -> set[str]:
    refs = signal.get("eventRefs", signal.get("event_refs", []))
    return {str(ref) for ref in refs} if isinstance(refs, list) else set()


def attack_profile_diagnostics(
    events: list[dict[str, Any]],
    truth_event_ids: set[str],
    endpoint_candidates: list[dict[str, Any]],
    projected_candidates: list[dict[str, Any]],
    expected_endpoint_candidates: int | None = None,
    profile_campaign_ids: dict[str, str] | None = None,
    truth_campaign_ids: set[str] | None = None,
) -> dict[str, Any]:
    truth_by_profile: dict[str, set[str]] = {}
    mapped_events: set[str] = set()
    for event in events:
        event_id = str(event.get("id") or "")
        profile_id = event.get("subjectProc", {}).get("stableId")
        if event_id in truth_event_ids and isinstance(profile_id, str) and profile_id:
            truth_by_profile.setdefault(profile_id, set()).add(event_id)
            mapped_events.add(event_id)
    campaign_profiles = {
        profile_id
        for profile_id, campaign_id in (profile_campaign_ids or {}).items()
        if campaign_id in (truth_campaign_ids or set())
    }
    for profile_id in campaign_profiles:
        truth_by_profile.setdefault(profile_id, set())
    endpoint_by_profile = group_candidates(endpoint_candidates)
    projected_by_profile = group_candidates(projected_candidates)
    observed_ids = {str(signal.get("id") or "") for signal in endpoint_candidates}
    observed_ids.discard("")
    observation_complete = (
        None
        if expected_endpoint_candidates is None
        else len(observed_ids) >= expected_endpoint_candidates
    )
    profiles = [
        diagnose_profile(
            profile_id,
            refs,
            endpoint_by_profile.get(profile_id, []),
            projected_by_profile.get(profile_id, []),
            observation_complete,
            profile_id in campaign_profiles,
        )
        for profile_id, refs in sorted(truth_by_profile.items())
    ]
    unmapped = sorted(truth_event_ids - mapped_events)
    counts: dict[str, int] = {"truth_event_unmapped": len(unmapped)} if unmapped else {}
    for profile in profiles:
        counts[profile["status"]] = counts.get(profile["status"], 0) + 1
    return {
        "status_counts": counts,
        "endpoint_candidate_observation_complete": observation_complete,
        "unmapped_truth_event_ids": unmapped,
        "profiles": profiles,
    }


def group_candidates(candidates: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for signal in candidates:
        if profile_id := candidate_subject(signal):
            grouped.setdefault(profile_id, []).append(signal)
    return grouped


def diagnose_profile(
    profile_id: str,
    truth_refs: set[str],
    endpoint: list[dict[str, Any]],
    projected: list[dict[str, Any]],
    observation_complete: bool | None,
    campaign_member: bool,
) -> dict[str, Any]:
    projected_ids = {str(signal.get("id") or "") for signal in projected}
    projected_truth = [
        signal for signal in projected if candidate_refs(signal).intersection(truth_refs)
    ]
    pending_truth = [
        signal
        for signal in endpoint
        if (
        str(signal.get("id") or "") not in projected_ids
        and candidate_refs(signal).intersection(truth_refs)
        )
    ]
    if projected and (campaign_member or projected_truth):
        status = "detected"
    elif pending_truth:
        status = "candidate_not_projected"
    elif projected:
        status = "candidate_missing_truth_ref"
    elif endpoint:
        status = "candidate_not_projected"
    elif observation_complete is None:
        status = "candidate_observation_unavailable"
    elif observation_complete:
        status = "profile_not_candidate"
    else:
        status = "candidate_observation_incomplete"
    observed = endpoint or projected
    return {
        "profile_id": profile_id,
        "status": status,
        "truth_event_ids": sorted(truth_refs),
        "candidate_ids": sorted(str(signal.get("id") or "") for signal in observed),
        "candidate_scores": candidate_scores(observed),
        "projected_candidate_ids": sorted(str(signal.get("id") or "") for signal in projected),
        "projected_truth_candidate_ids": sorted(str(signal.get("id") or "") for signal in projected_truth),
        "pending_truth_candidate_ids": sorted(str(signal.get("id") or "") for signal in pending_truth),
    }


def candidate_scores(signals: list[dict[str, Any]]) -> list[float]:
    values = []
    for signal in signals:
        value = signal.get("localRarity", signal.get("local_rarity"))
        if isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value):
            values.append(float(value))
    return sorted(values)


def managed_candidate_artifacts(
    path: Path, agent_mode: Any, agent_id: Any, event_sequence_cutoff: Any
) -> dict[str, Any]:
    if agent_mode != "managed":
        return {"candidate_reference_integrity": {"source": "observation_stream"}}
    signals = [
        *incident_documents(load_json_value(path / "managed-signals.json")),
        *incident_documents(load_json_value(path / "managed-conclusions.json")),
    ]
    rows = load_json_value(path / "stream-processing.json")
    if not isinstance(agent_id, str) or not agent_id or not isinstance(event_sequence_cutoff, int) or event_sequence_cutoff < 0:
        return missing_stream_processing("invalid Stream cohort identity")
    if not isinstance(rows, list):
        return missing_stream_processing("stream Signal processing artifact is missing")
    try:
        cohort = stream_signal_cohort(rows, agent_id, event_sequence_cutoff)
    except (TypeError, ValueError) as error:
        return missing_stream_processing(str(error))
    projected_ids = {row["signal_id"] for row in cohort if row["status"] == "projected"}
    candidates = [
        projected_signal(signal) for signal in signals
        if signal.get("detector_kind") == "DETECTOR_KIND_MODEL" and signal.get("id") in projected_ids
    ]
    candidate_ids = [signal.get("id") for signal in candidates]
    if any(not isinstance(signal_id, str) or not signal_id for signal_id in candidate_ids):
        return missing_stream_processing("projected Model Candidate ID is missing")
    if len(candidate_ids) != len(set(candidate_ids)):
        return missing_stream_processing("projected Model Candidate ID is duplicated")
    if set(candidate_ids) != projected_ids:
        return missing_stream_processing("Stream projected Candidate IDs do not match OpenSearch artifacts")
    correlated = sum(row["status"] in ("correlated", "projected") for row in cohort)
    projected = sum(row["status"] == "projected" for row in cohort)
    reference_rejected = sum(row["status"] == "reference_rejected" for row in cohort)
    return {
        "model_candidates": candidates,
        "candidate_reference_integrity": {
            "source": "stream_projection",
            "projected": projected,
            "projection_artifacts": len(candidates),
            "correlated": correlated,
            "reference_rejected": reference_rejected,
        },
    }


def projected_signal(document: dict[str, Any]) -> dict[str, Any]:
    fields = {
        "detector_kind": "detectorKind",
        "model_ref": "modelRef",
        "model_version": "modelVersion",
        "model_digest": "modelDigest",
        "feature_schema": "featureSchema",
        "local_rarity": "localRarity",
        "event_refs": "eventRefs",
    }
    signal = dict(document)
    for source, target in fields.items():
        if source in document:
            signal[target] = document[source]
    return signal


def missing_stream_processing(detail: str) -> dict[str, Any]:
    return {
        "model_candidates": [],
        "candidate_reference_integrity": {
            "source": "missing_stream_processing",
            "detail": detail,
            "projected": None,
            "projection_artifacts": None,
            "correlated": None,
            "reference_rejected": None,
        },
    }


def stream_signal_cohort(rows: list[Any], agent_id: str, cutoff: int) -> list[dict[str, Any]]:
    required = (
        "signal_id", "agent_id", "batch_id", "subject_id", "trigger_event_id",
        "event_sequence", "status", "failure_class",
    )
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in rows:
        if not isinstance(row, dict) or any(field not in row for field in required):
            raise ValueError("stream Signal processing artifact has an incomplete row")
        if row["agent_id"] != agent_id or row["event_sequence"] > cutoff:
            continue
        if not isinstance(row["event_sequence"], int) or row["event_sequence"] < 0:
            raise ValueError("stream Signal processing event_sequence is invalid")
        signal_id = row["signal_id"]
        if not isinstance(signal_id, str) or not signal_id or signal_id in seen:
            raise ValueError("stream Signal processing Signal ID is invalid or duplicated")
        if row["status"] not in ("correlated", "projected", "reference_rejected"):
            raise ValueError("stream Signal processing status is invalid")
        seen.add(signal_id)
        result.append(row)
    return result


def managed_analysis_metrics(path: Path, agent_mode: Any, truth_event_ids: set[str]) -> dict[str, Any]:
    incident_path = path / "managed-incidents.json"
    measurement = {
        "required": agent_mode == "managed",
        "incident_artifact_present": incident_path.is_file(),
    }
    if agent_mode != "managed":
        return {"managed_analysis": measurement}
    incidents = incident_documents(load_json_value(incident_path))
    evidence_event_ids: set[str] = set()
    incident_campaign_ids: set[str] = set()
    for incident in incidents:
        collect_incident_metrics(incident, evidence_event_ids, incident_campaign_ids)
    return {
        "managed_analysis": measurement,
        "truth_graph_event_ids": set(truth_event_ids),
        "evidence_event_ids": evidence_event_ids,
        "incident_campaign_ids": incident_campaign_ids,
    }


def nodlink_quality_metrics(
    signals: list[dict[str, Any]],
    incidents: list[dict[str, Any]],
    truth_event_ids: set[str],
    campaign_ids: list[str],
    runtime_metrics: dict[str, Any] | None = None,
) -> dict[str, Any]:
    evidence_refs = _evidence_event_refs(incidents)
    return {
        "evidence_precision": (
            len(evidence_refs.intersection(truth_event_ids)) / len(evidence_refs)
            if evidence_refs else None
        ),
        "campaign_duplication_rate": _duplication_rate(campaign_ids),
        "candidate_to_conclusion_latency": _nodlink_latency(signals),
        "detector_processing_ms": _runtime_number(runtime_metrics, "processing_ms"),
        "detector_state_bytes": _runtime_number(runtime_metrics, "state_bytes"),
    }


def _evidence_event_refs(incidents: list[dict[str, Any]]) -> set[str]:
    refs: set[str] = set()
    for incident in incidents:
        evidence = incident.get("evidence", {})
        edges = evidence.get("edges", []) if isinstance(evidence, dict) else []
        for edge in edges if isinstance(edges, list) else []:
            if isinstance(edge, dict):
                values = edge.get("eventRefs", edge.get("event_refs", []))
                refs.update(str(value) for value in values if value) if isinstance(values, list) else None
    return refs


def _duplication_rate(campaign_ids: list[str]) -> float | None:
    values = [value for value in campaign_ids if value]
    if not values:
        return None
    return (len(values) - len(set(values))) / len(values)


def _nodlink_latency(signals: list[dict[str, Any]]) -> dict[str, Any] | None:
    candidates = {
        str(signal.get("id")): _timestamp_ns(signal)
        for signal in signals
        if signal.get("id") and signal.get("detectorKind", signal.get("detector_kind")) == "DETECTOR_KIND_MODEL"
    }
    latencies = []
    for signal in signals:
        if signal.get("name") != "nodlink_campaign" or signal.get("stage") != "SIGNAL_STAGE_CONCLUSION":
            continue
        conclusion_ns = _timestamp_ns(signal)
        refs = signal.get("signalRefs", signal.get("signal_refs", []))
        candidate_ns = [candidates.get(str(ref)) for ref in refs if str(ref) in candidates]
        if conclusion_ns is not None and candidate_ns and all(value is not None for value in candidate_ns):
            latencies.append((conclusion_ns - max(candidate_ns)) / 1_000_000)
    if not latencies:
        return None
    values = sorted(latencies)
    return {
        "count": len(values),
        "p50_ms": _percentile(values, 0.50),
        "p95_ms": _percentile(values, 0.95),
        "p99_ms": _percentile(values, 0.99),
    }


def _timestamp_ns(value: dict[str, Any]) -> int | None:
    raw = value.get("observedAtUnixNano", value.get("observed_at_unix_nano"))
    try:
        return int(raw) if raw is not None else None
    except (TypeError, ValueError):
        return None


def _percentile(values: list[float], quantile: float) -> float:
    index = min(len(values) - 1, max(0, math.ceil(len(values) * quantile) - 1))
    return values[index]


def _runtime_number(metrics: dict[str, Any] | None, key: str) -> float | int | None:
    if not isinstance(metrics, dict):
        return None
    value = metrics.get(key)
    return value if isinstance(value, (int, float)) and not isinstance(value, bool) else None


def collect_incident_metrics(
    incident: dict[str, Any], evidence_event_ids: set[str], incident_campaign_ids: set[str]
) -> None:
    lineages = incident.get("lineageIds", incident.get("lineage_ids", []))
    if isinstance(lineages, list):
        incident_campaign_ids.update(str(value) for value in lineages if value)
    evidence = incident.get("evidence", {})
    edges = evidence.get("edges", []) if isinstance(evidence, dict) else []
    for edge in edges if isinstance(edges, list) else []:
        if not isinstance(edge, dict):
            continue
        refs = edge.get("eventRefs", edge.get("event_refs", []))
        if isinstance(refs, list):
            evidence_event_ids.update(str(value) for value in refs if value)


def incident_documents(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    if not isinstance(value, dict):
        return []
    for key in ("incidents", "items", "data"):
        items = value.get(key)
        if isinstance(items, list):
            return [item for item in items if isinstance(item, dict)]
    return []


def load_json_value(path: Path) -> Any:
    if not path.exists():
        return None
    return json.loads(path.read_text())


def load_nodlink_quality(path: Path, truth_event_ids: set[str]) -> dict[str, Any]:
    signals = incident_documents(load_json_value(path / "managed-signals.json"))
    incidents = incident_documents(load_json_value(path / "managed-incidents.json"))
    conclusions = [
        signal.get("signal", signal) for signal in signals
        if signal.get("name") == "nodlink_campaign"
        or signal.get("signal", {}).get("name") == "nodlink_campaign"
    ]
    campaigns = [
        str(signal.get("labels", {}).get("campaign_id"))
        for signal in conclusions
        if signal.get("labels", {}).get("campaign_id")
    ]
    runtime = load_json_value(path / "nodlink-metrics.json")
    return nodlink_quality_metrics(
        signals, incidents, truth_event_ids, campaigns,
        runtime if isinstance(runtime, dict) else None,
    )
