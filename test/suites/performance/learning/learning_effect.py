#!/usr/bin/env python3
"""ProcessProfile-level Learning Detector effect contracts."""

from __future__ import annotations

import math
from typing import Any


def gate(status: str, value: Any = None, limit: Any = None, detail: str = "") -> dict[str, Any]:
    return {"status": status, "value": value, "limit": limit, "detail": detail}


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


def attack_profile_recall(metrics: dict[str, Any]) -> float | None:
    truth = set(metrics.get("truth_profile_ids") or set())
    if not truth:
        return None
    return len(candidate_profile_ids(metrics).intersection(truth)) / len(truth)


def normal_candidate_rate(metrics: dict[str, Any]) -> float | None:
    profiles = set(metrics.get("profile_ids") or set())
    normal = profiles.difference(metrics.get("truth_profile_ids") or set())
    if not normal:
        return None
    return len(candidate_profile_ids(metrics).intersection(normal)) / len(normal)


def effect_gates(metrics: dict[str, Any], limits: dict[str, float]) -> dict[str, dict[str, Any]]:
    rate = normal_candidate_rate(metrics)
    recall = attack_profile_recall(metrics)
    return {
        "normal_candidate_rate": gate(
            "unavailable" if rate is None else "passed" if rate <= limits["normal_candidate_rate"] else "failed",
            rate,
            limits["normal_candidate_rate"],
            "normal ProcessProfile Candidate rate",
        ),
        "attack_profile_recall": gate(
            "unavailable" if recall is None else "passed" if recall >= limits["attack_profile_recall"] else "failed",
            recall,
            limits["attack_profile_recall"],
            "labeled attack ProcessProfile recall",
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
        if not refs or not set(refs).issubset(event_ids):
            return gate("failed", signal, "resolved refs", "unresolved Model Candidate event ref")
    return gate("passed", len(enabled.get("model_candidates", [])), None, "model provenance, subject, and refs")
