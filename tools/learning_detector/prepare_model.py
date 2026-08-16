#!/usr/bin/env python3
"""Prepare and calibrate a deterministic Learning Detector bundle."""

from __future__ import annotations

import hashlib
import json
import math
import tempfile
from pathlib import Path
from typing import Any

from pipeline import canonical, calibrate_threshold, digest_material, float32, read_events, score, train, validate_bundle


def file_digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def event_ids(path: Path) -> set[str]:
    events = read_events(path)
    ids: set[str] = set()
    for event in events:
        event_id = str(event.get("id") or "").strip()
        if not event_id or event_id in ids:
            raise ValueError(f"event id must be non-empty and unique: {event_id!r}")
        ids.add(event_id)
    return ids


def validate_dataset(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise ValueError(f"dataset not found: {path}")
    ids = event_ids(path)
    return {"path": str(path), "events": len(ids), "sha256": file_digest(path), "ids": ids}


def validate_pair(training: Path, calibration: Path) -> dict[str, Any]:
    first = validate_dataset(training)
    second = validate_dataset(calibration)
    overlap = first["ids"].intersection(second["ids"])
    if overlap:
        raise ValueError(f"training/calibration event id overlap: {sorted(overlap)[:3]}")
    return {"training": first, "calibration": second}


def quantiles(scores: list[float]) -> dict[str, float]:
    values = sorted(float(score) for score in scores)
    return {name: values[index] for name, index in (
        ("min", 0), ("p50", len(values) // 2), ("p95", min(len(values) - 1, math.ceil(len(values) * 0.95) - 1)), ("max", -1)
    )}


def finalize_bundle(bundle: dict[str, Any], threshold: float) -> dict[str, Any]:
    bundle["threshold"] = float32(threshold)
    bundle["model_digest"] = "sha256:" + hashlib.sha256(digest_material(bundle, False)).hexdigest()
    bundle["payload_digest"] = "sha256:" + hashlib.sha256(digest_material(bundle, True)).hexdigest()
    validate_bundle(bundle)
    return bundle


def prepare(training: Path, calibration: Path, output: Path, target_rate: float = 0.005) -> dict[str, Any]:
    metadata = validate_pair(training, calibration)
    with tempfile.TemporaryDirectory() as directory:
        provisional_path = Path(directory) / "provisional.json"
        train(training, provisional_path, 1.0)
        bundle = json.loads(provisional_path.read_text())
    scores = [score(event, bundle) for event in read_events(calibration)]
    threshold, allowed = calibrate_threshold(scores, target_rate)
    finalized = finalize_bundle(bundle, threshold)
    candidates = sum(value >= finalized["threshold"] for value in scores)
    rate = candidates / len(scores)
    if candidates > allowed or rate > target_rate:
        raise ValueError("calibration candidate rate exceeds target")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(canonical(finalized) + b"\n")
    return {
        "bundle": finalized,
        "datasets": {key: {name: value for name, value in data.items() if name != "ids"} for key, data in metadata.items()},
        "calibration_allowed": allowed,
        "calibration_candidates": candidates,
        "calibration_candidate_rate": rate,
        "calibration_score_quantiles": quantiles(scores),
    }


if __name__ == "__main__":
    raise SystemExit("use prepare_model.prepare() from the experiment runner")
