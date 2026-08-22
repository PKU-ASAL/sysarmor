#!/usr/bin/env python3
"""Managed Stream analysis artifact parsing for Learning experiments."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


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
        signal for signal in signals
        if signal.get("detectorKind") == "DETECTOR_KIND_MODEL" and signal.get("id") in projected_ids
    ]
    candidate_ids = [signal.get("id") for signal in candidates]
    if any(not isinstance(signal_id, str) or not signal_id for signal_id in candidate_ids):
        return missing_stream_processing("projected Model Signal ID is missing")
    if len(candidate_ids) != len(set(candidate_ids)):
        return missing_stream_processing("projected Model Signal ID is duplicated")
    if set(candidate_ids) != projected_ids:
        return missing_stream_processing("Stream projected Signal IDs do not match OpenSearch artifacts")
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
