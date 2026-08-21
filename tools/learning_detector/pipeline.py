#!/usr/bin/env python3
"""Collect canonical Events and replay FeatureSchemaV2 ProcessProfile detection."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from inference import score_profile
from model_bundle import validate_bundle
from profile_dataset import read_events, read_profiles


def collect(input_path: Path, output_path: Path, label: str | None) -> int:
    key, _, expected = (label or "").partition("=")
    selected = []
    for event in read_events(input_path):
        if label and str((event.get("labels") or {}).get(key)) != expected:
            continue
        selected.append(event)
    if not selected:
        raise ValueError("normal-data filter selected no events")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("".join(json.dumps(event, sort_keys=True) + "\n" for event in selected))
    return len(selected)


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
    replay_parser = commands.add_parser("replay")
    replay_parser.add_argument("--input", type=Path, required=True)
    replay_parser.add_argument("--bundle", type=Path, required=True)
    replay_parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "collect":
        print(collect(args.input, args.output, args.label))
    else:
        print(replay(args.input, args.bundle, args.output))


if __name__ == "__main__":
    main()
