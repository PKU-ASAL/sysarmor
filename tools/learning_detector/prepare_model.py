#!/usr/bin/env python3
"""Train and calibrate a deterministic FeatureSchemaV2 model bundle."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path
from typing import Any

from inference import score_profile
from model_bundle import canonical, validate_bundle
from profile_dataset import read_events, read_profiles
from training import TrainingConfig, train_bundle


def file_digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def validate_dataset(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise ValueError(f"dataset not found: {path}")
    events = read_events(path)
    event_ids = unique_values(events, lambda event: str(event.get("id") or "").strip(), "event ID")
    profiles = read_profiles(path)
    profile_ids = unique_values(profiles, profile_identity, "profile identity")
    return {
        "path": str(path), "events": len(event_ids), "profiles": len(profile_ids),
        "sha256": file_digest(path), "event_ids": event_ids, "profile_ids": profile_ids,
    }


def profile_identity(profile: dict[str, Any]) -> str:
    return f'{profile.get("agent_id", "")}:{profile["stable_id"]}'


def unique_values(values: list[dict[str, Any]], getter: Any, name: str) -> set[str]:
    result = set()
    for value in values:
        current = getter(value)
        if not current or current in result:
            raise ValueError(f"{name} must be non-empty and unique: {current!r}")
        result.add(current)
    return result


def validate_pair(training: Path, calibration: Path) -> dict[str, Any]:
    first, second = validate_dataset(training), validate_dataset(calibration)
    for field, label in (("event_ids", "event ID"), ("profile_ids", "profile stable ID")):
        overlap = first[field].intersection(second[field])
        if overlap:
            raise ValueError(f"training/calibration {label} overlap: {sorted(overlap)[:3]}")
    return {"training": first, "calibration": second}


def prepare(training: Path, calibration: Path, output: Path, target_rate: float = 0.005,
            config: TrainingConfig | None = None) -> dict[str, Any]:
    metadata = validate_pair(training, calibration)
    config = config or TrainingConfig(target_rate=target_rate)
    if config.target_rate != target_rate:
        config = TrainingConfig(**{**config.__dict__, "target_rate": target_rate})
    training_profiles, calibration_profiles = read_profiles(training), read_profiles(calibration)
    bundle = train_bundle(training_profiles, calibration_profiles, config)
    validate_bundle(bundle)
    scores = [score_profile(profile, bundle) for profile in calibration_profiles]
    allowed = math.floor(len(scores) * target_rate)
    candidates = sum(score >= bundle["threshold"] for score in scores)
    if candidates > allowed:
        raise ValueError("calibration candidate rate exceeds target")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(canonical(bundle) + b"\n")
    return {
        "bundle": bundle,
        "datasets": {key: public_metadata(value) for key, value in metadata.items()},
        "calibration_allowed": allowed, "calibration_candidates": candidates,
        "calibration_candidate_rate": candidates / len(scores),
        "calibration_score_quantiles": quantiles(scores),
    }


def public_metadata(value: dict[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in value.items() if key not in {"event_ids", "profile_ids"}}


def quantiles(scores: list[float]) -> dict[str, float]:
    values = sorted(float(score) for score in scores)
    indexes = (("min", 0), ("p50", len(values) // 2),
               ("p95", min(len(values) - 1, math.ceil(len(values) * 0.95) - 1)), ("max", -1))
    return {name: values[index] for name, index in indexes}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--training", type=Path, required=True)
    parser.add_argument("--calibration", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--target-rate", type=float, default=0.005)
    args = parser.parse_args()
    print(json.dumps(prepare(args.training, args.calibration, args.output, args.target_rate), sort_keys=True))


if __name__ == "__main__":
    main()
