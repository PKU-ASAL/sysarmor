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
    signals = incident_documents(load_json_value(path / "managed-signals.json"))
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
