#!/usr/bin/env python3
"""Learning experiment artifact contracts and model provenance."""

from __future__ import annotations

import math
from typing import Any


DEFAULT_GATES = {
    "learning_only_cpu_pct": 30.0,
    "hybrid_cpu_pct": 15.0,
    "rss_delta_mb": 16.0,
    "eps_relative": 0.90,
    "normal_candidate_rate": 0.01,
    "attack_campaign_seed_recall": 0.90,
    "worker_graph_recall": 0.90,
    "conclusion_recall": 0.90,
}


class ReportError(ValueError):
    """Raised when a strict report cannot be constructed."""


def numeric(value: Any) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        result = float(value)
    except (TypeError, ValueError):
        return None
    return result if math.isfinite(result) else None


def valid_gate_config(value: Any) -> bool:
    if not isinstance(value, dict) or set(value) != set(DEFAULT_GATES):
        return False
    return all(is_json_number(value.get(key)) and value[key] == expected for key, expected in DEFAULT_GATES.items())


def is_json_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def validate_calibration(manifest: dict[str, Any], calibration: dict[str, Any]) -> None:
    rate = numeric(calibration.get("calibration_candidate_rate"))
    candidates, allowed = calibration.get("calibration_candidates"), calibration.get("calibration_allowed")
    if rate is None or not 0 <= rate <= 0.005 or not valid_count(candidates) or not valid_count(allowed) or candidates > allowed:
        raise ReportError("calibration summary violates Candidate rate contract")
    datasets = calibration.get("datasets")
    if not isinstance(datasets, dict):
        raise ReportError("calibration summary is missing datasets")
    for name in ("training", "calibration"):
        validate_dataset_summary(manifest, datasets.get(name), name)
    bundle = calibration.get("bundle")
    fields = ("model_ref", "model_version", "model_digest", "feature_schema", "threshold")
    if not isinstance(bundle, dict) or any(bundle.get(key) != manifest.get(key) for key in fields):
        raise ReportError("calibration Bundle does not match experiment manifest")


def validate_dataset_summary(manifest: dict[str, Any], value: Any, name: str) -> None:
    if not isinstance(value, dict) or not valid_count(value.get("events")) or value["events"] == 0:
        raise ReportError(f"calibration summary has invalid {name} dataset")
    if value.get("sha256") != manifest.get(f"{name}_digest") or value.get("path") != manifest.get(f"{name}_data"):
        raise ReportError(f"calibration summary {name} provenance does not match manifest")


def valid_count(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def model_identity(manifest: dict[str, Any]) -> dict[str, Any]:
    return {
        "modelRef": manifest.get("model_ref"),
        "modelVersion": manifest.get("model_version"),
        "modelDigest": manifest.get("model_digest"),
        "featureSchema": manifest.get("feature_schema"),
    }


def model_summary(manifest: dict[str, Any], calibration: dict[str, Any]) -> dict[str, Any]:
    result = dict(calibration)
    for key in ("model_ref", "model_version", "model_digest", "feature_schema", "threshold"):
        result[key] = manifest.get(key, result.get("bundle", {}).get(key))
    return result
