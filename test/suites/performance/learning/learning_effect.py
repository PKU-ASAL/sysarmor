#!/usr/bin/env python3
"""ProcessProfile-level Learning Detector effect contracts."""

from __future__ import annotations

import math
from typing import Any


def gate(status: str, value: Any = None, limit: Any = None, detail: str = "", blocking: bool = True) -> dict[str, Any]:
    return {"status": status, "value": value, "limit": limit, "detail": detail, "blocking": blocking}


def numeric(value: Any) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        result = float(value)
    except (TypeError, ValueError):
        return None
    return result if math.isfinite(result) else None


def subject_process_id(signal: dict[str, Any]) -> str | None:
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


def candidate_profile_ids(metrics: dict[str, Any]) -> set[str]:
    return {
        stable_id
        for signal in metrics.get("model_candidates", [])
        if (stable_id := subject_process_id(signal)) is not None
    }


def profile_health(value: dict[str, Any]) -> dict[str, int | None]:
    fields = {
        "active": ("Active", "active"), "exited": ("Exited", "exited"),
        "retained": ("Retained", "retained"), "compactions": ("Compactions", "compactions"),
        "expired": ("Expired", "expired"),
        "capacity_evictions": ("CapacityEvictions", "capacityEvictions", "capacity_evictions"),
        "file_evictions": ("FileEvictions", "fileEvictions", "file_evictions"),
        "network_evictions": ("NetworkEvictions", "networkEvictions", "network_evictions"),
        "event_ref_evictions": ("EventRefEvictions", "eventRefEvictions", "event_ref_evictions"),
        "identity_retained": ("IdentityRetained", "identityRetained", "identity_retained"),
        "identity_evictions": ("IdentityEvictions", "identityEvictions", "identity_evictions"),
        "active_evictions": ("ActiveEvictions", "activeEvictions", "active_evictions"),
        "identity_gaps": ("IdentityGaps", "identityGaps", "identity_gaps"),
    }
    return {name: health_count(value, aliases) for name, aliases in fields.items()}


def health_count(value: dict[str, Any], aliases: tuple[str, ...]) -> int | None:
    if not value:
        return None
    for alias in aliases:
        if alias in value:
            try:
                return int(value[alias])
            except (TypeError, ValueError):
                return None
    return 0


def set_recall(found: set[str], truth: set[str]) -> float | None:
    if not truth:
        return None
    return len(found.intersection(truth)) / len(truth)


def candidate_campaign_ids(metrics: dict[str, Any]) -> set[str]:
    campaigns = metrics.get("profile_campaign_ids") or {}
    return {campaigns[profile] for profile in candidate_profile_ids(metrics) if campaigns.get(profile)}


def attack_campaign_seed_recall(metrics: dict[str, Any]) -> float | None:
    return set_recall(candidate_campaign_ids(metrics), set(metrics.get("truth_campaign_ids") or set()))


def worker_graph_recall(metrics: dict[str, Any]) -> float | None:
    if "truth_graph_event_ids" not in metrics or "evidence_event_ids" not in metrics:
        return None
    return set_recall(set(metrics.get("evidence_event_ids") or set()), set(metrics.get("truth_graph_event_ids") or set()))


def conclusion_recall(metrics: dict[str, Any]) -> float | None:
    if "incident_campaign_ids" not in metrics:
        return None
    return set_recall(set(metrics.get("incident_campaign_ids") or set()), set(metrics.get("truth_campaign_ids") or set()))


def normal_profile_ids(metrics: dict[str, Any]) -> set[str]:
    profiles = set(metrics.get("profile_ids") or set())
    truth_profiles = set(metrics.get("truth_profile_ids") or set())
    truth_campaigns = set(metrics.get("truth_campaign_ids") or set())
    campaign_by_profile = metrics.get("profile_campaign_ids") or {}
    truth_profiles.update(profile for profile in profiles if campaign_by_profile.get(profile) in truth_campaigns)
    return profiles.difference(truth_profiles)


def normal_candidate_rate(metrics: dict[str, Any]) -> float | None:
    normal = normal_profile_ids(metrics)
    if not normal:
        return None
    return len(candidate_profile_ids(metrics).intersection(normal)) / len(normal)


def effect_gates(metrics: dict[str, Any], limits: dict[str, float]) -> dict[str, dict[str, Any]]:
    rate = normal_candidate_rate(metrics)
    seed_recall = attack_campaign_seed_recall(metrics)
    graph_recall = worker_graph_recall(metrics)
    incident_recall = conclusion_recall(metrics)
    return {
        "normal_candidate_rate": gate(
            "unavailable" if rate is None else "passed" if rate <= limits["normal_candidate_rate"] else "failed",
            rate,
            limits["normal_candidate_rate"],
            "normal ProcessProfile Candidate rate",
        ),
        "attack_campaign_seed_recall": gate(
            "unavailable" if seed_recall is None else "passed" if seed_recall >= limits["attack_campaign_seed_recall"] else "failed",
            seed_recall,
            limits["attack_campaign_seed_recall"],
            "Agent attack campaign seed recall",
        ),
        "worker_graph_recall": gate(
            "unavailable" if graph_recall is None else "passed" if graph_recall >= limits["worker_graph_recall"] else "failed",
            graph_recall,
            limits["worker_graph_recall"],
            "managed Worker Evidence Event recall",
            blocking=graph_recall is not None,
        ),
        "conclusion_recall": gate(
            "unavailable" if incident_recall is None else "passed" if incident_recall >= limits["conclusion_recall"] else "failed",
            incident_recall,
            limits["conclusion_recall"],
            "managed end-to-end Incident campaign recall",
            blocking=incident_recall is not None,
        ),
    }


def model_gate(disabled: dict[str, Any], enabled: dict[str, Any]) -> dict[str, Any]:
    if disabled.get("health", {}).get("learning") != "disabled":
        return gate("failed", disabled.get("health", {}).get("learning"), "disabled", "disabled variant loaded a model")
    if disabled.get("model_candidates"):
        return gate("failed", len(disabled["model_candidates"]), 0, "disabled emitted Model Candidate")
    if enabled.get("health", {}).get("learning") != "loaded":
        return gate("failed", enabled.get("health", {}).get("learning"), "loaded", "enabled model is not loaded")
    if not enabled.get("model_candidates"):
        return gate("failed", 0, ">=1", "enabled emitted no Model Candidate")

    event_ids = enabled.get("events", set())
    profile_ids = enabled.get("profile_ids", set())
    expected = enabled.get("expected_model", {})
    provenance = ("modelRef", "modelVersion", "modelDigest", "featureSchema")
    if any(not expected.get(field) for field in provenance):
        return gate("failed", expected, "experiment model", "missing expected model provenance")
    for signal in enabled.get("model_candidates", []):
        if (signal.get("stage"), signal.get("detectorKind"), signal.get("where")) != (
            "SIGNAL_STAGE_CANDIDATE", "DETECTOR_KIND_MODEL", "SIGNAL_WHERE_ENDPOINT"
        ):
            return gate("failed", signal, "candidate/model", "invalid Model Candidate contract")
        score = numeric(signal.get("localRarity"))
        subject = subject_process_id(signal)
        if any(signal.get(field) != expected[field] for field in provenance) or score is None:
            return gate("failed", signal, "complete provenance and score", "invalid Model Candidate provenance")
        if subject is None or subject not in profile_ids:
            return gate("failed", signal, "resolved subject process", "invalid Model Candidate subject process")
        refs = signal.get("eventRefs", [])
        if not refs or not set(refs).intersection(event_ids):
            return gate("failed", signal, "resolved refs", "unresolved Model Candidate event ref")
    return gate("passed", len(enabled.get("model_candidates", [])), None, "model provenance, subject, and refs")
