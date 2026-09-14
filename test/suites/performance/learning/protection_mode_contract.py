"""Validation for effective EndpointPolicy protection-mode contracts."""

from __future__ import annotations

from typing import Any

from learning_artifacts import ReportError


PROTECTION_MODES = ("rule-only", "learning-only", "hybrid")


def validate_mode_matrix(modes: dict[str, dict[str, Any]], expected_model: dict[str, Any] | None = None) -> None:
    for mode in PROTECTION_MODES:
        run = modes.get(mode, {})
        actual = run.get("manifest", {}).get("protection_mode")
        if actual != mode:
            raise ReportError(f"protection mode directory {mode} contains {actual or 'unlabeled'} run")
        validate_effective_policy(mode, run.get("effective_policy"), expected_model)


def validate_effective_policy(mode: str, document: Any, expected_model: dict[str, Any] | None) -> None:
    if not isinstance(document, dict):
        raise ReportError(f"{mode} effective EndpointPolicy is not an object")
    for section in ("collection", "detection", "telemetry", "response"):
        if not isinstance(document.get(section), dict):
            raise ReportError(f"{mode} effective EndpointPolicy is missing {section}")
    detection = document["detection"]
    rules = detection.get("rulesets", [])
    if not isinstance(rules, list):
        raise ReportError(f"{mode} effective detection rulesets is not an array")
    has_rules = any(
        isinstance(rule, dict)
        and isinstance(rule.get("ref"), str)
        and rule["ref"].strip()
        and rule.get("enabled") is not False
        for rule in rules
    )
    model = detection.get("learning_model")
    has_model = isinstance(model, dict) and all(
        isinstance(model.get(key), str) and model[key].strip() for key in ("ref", "version", "digest")
    )
    if mode == "rule-only" and (not has_rules or model is not None):
        raise ReportError("rule-only effective policy must enable Rules without a Learning model")
    if mode == "learning-only" and (has_rules or not has_model):
        raise ReportError("learning-only effective policy must enable Learning without Rules")
    if mode == "hybrid" and (not has_rules or not has_model):
        raise ReportError("hybrid effective policy must enable both Rules and Learning")
    allowed_modes = document["response"].get("allowed_modes", [])
    if not isinstance(allowed_modes, list):
        raise ReportError(f"{mode} effective response allowed_modes is not an array")
    if mode == "learning-only" and any(str(value).strip().lower() == "enforce" for value in allowed_modes):
        raise ReportError("learning-only effective policy must be observe-only")
    if expected_model is not None and mode != "rule-only":
        actual_model = {
            "modelRef": model["ref"],
            "modelVersion": model["version"],
            "modelDigest": model["digest"],
        }
        if any(actual_model[key] != expected_model.get(key) for key in actual_model):
            raise ReportError(f"{mode} effective Learning model does not match the experiment bundle")
