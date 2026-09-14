#!/usr/bin/env python3
"""Collect canonical Events and replay FeatureSchemaV2 ProcessProfile detection."""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Any

from inference import score_profile
from model_bundle import validate_bundle
from profile_dataset import read_events, read_profiles


def collect(
    input_path: Path,
    output_path: Path,
    label: str | None,
    markers_path: Path | None = None,
    start_phase: str | None = None,
    end_phase: str | None = None,
) -> int:
    key, _, expected = (label or "").partition("=")
    window = marker_window(markers_path, start_phase, end_phase)
    selected = []
    for event in read_events(input_path):
        if label and str((event.get("labels") or {}).get(key)) != expected:
            continue
        if window and not window[0] <= event_time_ns(event) < window[1]:
            continue
        selected.append(event)
    if not selected:
        raise ValueError("normal-data filter selected no events")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("".join(json.dumps(event, sort_keys=True) + "\n" for event in selected))
    return len(selected)


def marker_window(
    path: Path | None, start_phase: str | None, end_phase: str | None
) -> tuple[int, int] | None:
    values = (path, start_phase, end_phase)
    if not any(values):
        return None
    if not all(values) or path is None or not path.is_file():
        raise ValueError("markers, start phase, and end phase are required together")
    markers = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    start = marker_timestamp_ns(markers, start_phase)
    end = marker_timestamp_ns(markers, end_phase)
    if end <= start:
        raise ValueError("benchmark marker window must be increasing")
    return start, end


def marker_timestamp_ns(markers: list[dict[str, Any]], phase: str) -> int:
    matches = [marker.get("ts") for marker in markers if marker.get("phase") == phase]
    if len(matches) != 1:
        raise ValueError(f"benchmark marker phase must occur exactly once: {phase}")
    return timestamp_ns(str(matches[0]))


def timestamp_ns(value: str) -> int:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("benchmark marker timestamp requires a timezone")
    return int(parsed.timestamp() * 1_000_000_000)


def event_time_ns(event: dict[str, Any]) -> int:
    value = event.get("occurredAtNs", event.get("occurred_at_ns"))
    try:
        return int(value)
    except (TypeError, ValueError) as error:
        raise ValueError("event occurred timestamp is required for marker filtering") from error


def replay(input_path: Path, bundle_path: Path, output_path: Path) -> int:
    bundle = json.loads(bundle_path.read_text())
    validate_bundle(bundle)
    candidates = []
    for profile in read_profiles(input_path):
        score = score_profile(profile, bundle)
        if score < bundle["threshold"]:
            continue
        candidates.append(candidate(profile, bundle, score))
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("".join(json.dumps(value, sort_keys=True) + "\n" for value in candidates))
    return len(candidates)


def candidate(profile: dict[str, Any], bundle: dict[str, Any], score: float) -> dict[str, Any]:
    material = f'{profile["stable_id"]}|{profile["revision"]}|{bundle["model_digest"]}|{score:.6f}'.encode()
    return {
        "id": "sig-model-" + hashlib.sha256(material).hexdigest()[:16], "name": "model_anomaly",
        "where": "SIGNAL_WHERE_ENDPOINT", "stage": "SIGNAL_STAGE_CANDIDATE",
        "detectorKind": "DETECTOR_KIND_MODEL", "localRarity": score,
        "eventRefs": list(profile["event_refs"]), "modelRef": bundle["model_ref"],
        "modelVersion": bundle["model_version"], "modelDigest": bundle["model_digest"],
        "featureSchema": bundle["feature_schema"],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    collect_parser = commands.add_parser("collect")
    collect_parser.add_argument("--input", type=Path, required=True)
    collect_parser.add_argument("--output", type=Path, required=True)
    collect_parser.add_argument("--label")
    collect_parser.add_argument("--markers", type=Path)
    collect_parser.add_argument("--start-phase")
    collect_parser.add_argument("--end-phase")
    replay_parser = commands.add_parser("replay")
    replay_parser.add_argument("--input", type=Path, required=True)
    replay_parser.add_argument("--bundle", type=Path, required=True)
    replay_parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "collect":
        print(collect(
            args.input, args.output, args.label,
            args.markers, args.start_phase, args.end_phase,
        ))
    else:
        print(replay(args.input, args.bundle, args.output))


if __name__ == "__main__":
    main()
