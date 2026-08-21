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
        "profile_observations": ("ProfileObservations", "profileObservations", "profile_observations"),
        "feature_updates": ("FeatureUpdates", "featureUpdates", "feature_updates"),
        "learning_score_calls": ("LearningScoreCalls", "learningScoreCalls", "learning_score_calls"),
        "lifecycle_only_observations": ("LifecycleOnlyObservations", "lifecycleOnlyObservations", "lifecycle_only_observations"),
        "suppressed_checkpoints": ("SuppressedCheckpoints", "suppressedCheckpoints", "suppressed_checkpoints"),
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


def managed_recall_gate(
    metrics: dict[str, Any], mode: str, value: float | None, limit: float, detail: str
) -> dict[str, Any]:
    measurement = metrics.get("managed_analysis", {})
    if mode != "hybrid":
        return gate("unavailable", value, limit, f"{detail}; not applicable outside hybrid", blocking=False)
    if not measurement.get("required"):
        return gate("unavailable", value, limit, f"{detail}; standalone run", blocking=False)
    if not measurement.get("incident_artifact_present"):
        return gate("failed", value, limit, f"{detail}; managed Incident artifact missing")
    if value is None:
        return gate("failed", value, limit, f"{detail}; managed truth or result missing")
    return gate("passed" if value >= limit else "failed", value, limit, detail)


def effect_gates(metrics: dict[str, Any], mode: str, limits: dict[str, float]) -> dict[str, dict[str, Any]]:
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
        "worker_graph_recall": managed_recall_gate(
            metrics, mode, graph_recall, limits["worker_graph_recall"],
            "managed Worker Evidence Event recall",
        ),
        "conclusion_recall": managed_recall_gate(
            metrics, mode, incident_recall, limits["conclusion_recall"],
            "managed end-to-end Incident campaign recall",
        ),
    }


def model_gate(baseline: dict[str, Any], candidate: dict[str, Any]) -> dict[str, Any]:
    if baseline.get("health", {}).get("learning") != "disabled":
        return gate("failed", baseline.get("health", {}).get("learning"), "disabled", "rule-only loaded a model")
    if baseline.get("model_candidates"):
        return gate("failed", len(baseline["model_candidates"]), 0, "rule-only emitted Model Candidate")
    if candidate.get("health", {}).get("learning") != "loaded":
        return gate("failed", candidate.get("health", {}).get("learning"), "loaded", "Learning model is not loaded")
    if not candidate.get("model_candidates"):
        return gate("failed", 0, ">=1", "Learning mode emitted no Model Candidate")

    event_ids = candidate.get("events", set())
    profile_ids = candidate.get("profile_ids", set())
    reference_integrity = candidate.get("candidate_reference_integrity", {})
    worker_projection = reference_integrity.get("source") == "worker_projection"
    expected = candidate.get("expected_model", {})
    provenance = ("modelRef", "modelVersion", "modelDigest", "featureSchema")
    if any(not expected.get(field) for field in provenance):
        return gate("failed", expected, "experiment model", "missing expected model provenance")
    for signal in candidate.get("model_candidates", []):
        if (signal.get("stage"), signal.get("detectorKind"), signal.get("where")) != (
            "SIGNAL_STAGE_CANDIDATE", "DETECTOR_KIND_MODEL", "SIGNAL_WHERE_ENDPOINT"
        ):
            return gate("failed", signal, "candidate/model", "invalid Model Candidate contract")
        score = numeric(signal.get("localRarity"))
        subject = subject_process_id(signal)
        if any(signal.get(field) != expected[field] for field in provenance) or score is None:
            return gate("failed", signal, "complete provenance and score", "invalid Model Candidate provenance")
        if subject is None or not worker_projection and subject not in profile_ids:
            return gate("failed", signal, "resolved subject process", "invalid Model Candidate subject process")
        refs = signal.get("eventRefs", [])
        if not refs or not worker_projection and not set(refs).intersection(event_ids):
            return gate("failed", signal, "resolved refs", "unresolved Model Candidate event ref")
    return gate("passed", len(candidate.get("model_candidates", [])), None, "model provenance, subject, and refs")


def candidate_lifecycle_gate(candidate: dict[str, Any]) -> dict[str, Any]:
    integrity = candidate.get("candidate_reference_integrity", {})
    if integrity.get("source") != "worker_projection":
        return gate("unavailable", None, "managed lifecycle", "Worker lifecycle artifacts are required")
    lifecycle = candidate.get("candidate_lifecycle", {})
    gaps = candidate.get("reference_gaps", {})
    counters = {
        "endpoint_storage_drop": gaps.get("endpoint_storage_drop"),
        "agent_contract_rejected": lifecycle.get("contract_rejected"),
        "agent_spool_backlog": gaps.get("agent_spool_backlog"),
        "gateway_rejected": lifecycle.get("gateway_rejected"),
        "agent_delivery_backlog": gaps.get("agent_delivery_backlog"),
        "worker_reference_rejected": integrity.get("reference_rejected"),
        "worker_pending_backlog": integrity.get("pending_backlog"),
    }
    failed = {name: value for name, value in counters.items() if value is not None and value != 0}
    if failed:
        return gate("failed", failed, 0, "Candidate delivery or reference lifecycle did not converge")
    if any(value is None for value in counters.values()):
        return gate("unavailable", counters, "complete lifecycle", "Candidate lifecycle metric is missing")
    stages = {
        "created": lifecycle.get("created"),
        "spooled": lifecycle.get("spooled"),
        "agent_contract_rejected": lifecycle.get("contract_rejected"),
        "gateway_accepted_unique": lifecycle.get("gateway_accepted"),
        "gateway_rejected": lifecycle.get("gateway_rejected"),
        "worker_correlated": integrity.get("correlated"),
        "worker_reference_rejected": integrity.get("reference_rejected"),
        "worker_projected": integrity.get("projected"),
        "worker_projection_artifacts": integrity.get("projection_artifacts"),
    }
    if any(value is None for value in stages.values()):
        return gate("unavailable", stages, "complete exact cohort", "Candidate lifecycle metric is missing")
    exact = (
        stages["created"] == stages["spooled"] + stages["agent_contract_rejected"]
        and stages["spooled"] == stages["gateway_accepted_unique"] + stages["gateway_rejected"]
        and stages["gateway_accepted_unique"]
        == stages["worker_correlated"] + stages["worker_reference_rejected"]
        and stages["worker_correlated"]
        == stages["worker_projected"]
        == stages["worker_projection_artifacts"]
    )
    if not exact:
        return gate("failed", stages, "exact Signal.id cohort", "Candidate lifecycle counts do not identify one cohort")
    return gate("passed", counters, 0, "Candidate lifecycle converged without rejection")
