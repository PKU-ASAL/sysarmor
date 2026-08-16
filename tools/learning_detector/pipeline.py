#!/usr/bin/env python3
"""FeatureSchemaV1 collection, training, and replay for the model detector."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import struct
from pathlib import Path
from typing import Any

SCHEMA = "FeatureSchemaV1"
FEATURE_COUNT = 6


def fnv1a(value: str) -> int:
    result = 2166136261
    for byte in value.encode():
        result = ((result ^ byte) * 16777619) & 0xFFFFFFFF
    return result


def feature_vector(event: dict[str, Any]) -> list[float]:
    subject_value = event.get("subjectProc") if "subjectProc" in event else event.get("subject_proc")
    subject_present = subject_value is not None
    subject = subject_value or {}
    object_ref = event.get("object") or {}
    argv = subject.get("argv") or []
    behavior = str(event.get("behavior") or "").strip()
    return [
        (fnv1a(behavior) % 16) / 15 if behavior else -1.0,
        len(argv) / 8,
        float(subject_present),
        float(bool(event.get("parentStableId") or event.get("parent_stable_id"))),
        float(bool(object_ref.get("filePath") or object_ref.get("file_path"))),
        float(bool(object_ref.get("socketAddr") or object_ref.get("socket_addr"))),
    ]


def unwrap(line: dict[str, Any]) -> dict[str, Any]:
    return line.get("event") if isinstance(line.get("event"), dict) else line


def read_events(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for line_number, line in enumerate(path.read_text().splitlines(), 1):
        if not line.strip():
            continue
        try:
            event = unwrap(json.loads(line))
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid event JSON at line {line_number}") from exc
        if not isinstance(event, dict):
            raise ValueError(f"event at line {line_number} is not an object")
        events.append(event)
    if not events:
        raise ValueError(f"no events in {path}")
    return events


def collect(input_path: Path, output_path: Path, label: str | None) -> int:
    key, _, expected = (label or "").partition("=")
    events = read_events(input_path)
    selected = []
    for event in events:
        labels = event.get("labels") or {}
        if label and str(labels.get(key)) != expected:
            continue
        selected.append(event)
    if not selected:
        raise ValueError("normal-data filter selected no events")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("".join(json.dumps(event, sort_keys=True) + "\n" for event in selected))
    return len(selected)


def canonical(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def digest_material(bundle: dict[str, Any], include_model_digest: bool) -> bytes:
    purpose = "sysarmor.learning-model/payload-digest/v1" if include_model_digest else "sysarmor.learning-model/model-digest/v1"
    result = length_prefixed(purpose)
    for value in (bundle["model_ref"], bundle["model_version"], bundle["feature_schema"]):
        result += length_prefixed(value)
    if include_model_digest:
        result += length_prefixed(bundle["model_digest"])
    result += struct.pack("!f", float32(bundle["threshold"]))
    for values in (bundle["mean"], bundle["scale"]):
        result += struct.pack("!I", len(values))
        result += b"".join(struct.pack("!f", float32(value)) for value in values)
    return result


def length_prefixed(value: str) -> bytes:
    encoded = value.encode()
    return struct.pack("!I", len(encoded)) + encoded


def validate_bundle(bundle: dict[str, Any]) -> None:
    required = ("model_ref", "model_version", "model_digest", "feature_schema", "mean", "scale", "threshold", "payload_digest")
    if any(key not in bundle for key in required):
        raise ValueError("model bundle fields are required")
    if bundle["feature_schema"] != SCHEMA or len(bundle["mean"]) != FEATURE_COUNT or len(bundle["scale"]) != FEATURE_COUNT:
        raise ValueError("unsupported model bundle schema")
    numbers = [bundle["threshold"], *bundle["mean"], *bundle["scale"]]
    if not all(isinstance(value, (int, float)) and math.isfinite(value) for value in numbers):
        raise ValueError("model parameters must be finite")
    if bundle["threshold"] <= 0 or any(value <= 0 for value in bundle["scale"]):
        raise ValueError("model threshold and scale must be positive")
    model_digest = "sha256:" + hashlib.sha256(digest_material(bundle, False)).hexdigest()
    if bundle["model_digest"] != model_digest:
        raise ValueError("model digest mismatch")
    payload_digest = "sha256:" + hashlib.sha256(digest_material(bundle, True)).hexdigest()
    if bundle["payload_digest"] != payload_digest:
        raise ValueError("model payload digest mismatch")


def train(input_path: Path, output_path: Path, threshold: float) -> dict[str, Any]:
    events = read_events(input_path)
    vectors = [feature_vector(event) for event in events]
    mean = [round(sum(row[index] for row in vectors) / len(vectors), 6) for index in range(FEATURE_COUNT)]
    scale = []
    for index in range(FEATURE_COUNT):
        variance = sum((row[index] - mean[index]) ** 2 for row in vectors) / len(vectors)
        scale.append(round(max(math.sqrt(variance), 1e-6), 6))
    bundle = {
        "model_ref": "model:normal-centroid-v1",
        "model_version": "1",
        "model_digest": "",
        "feature_schema": SCHEMA,
        "mean": mean,
        "scale": scale,
        "threshold": round(threshold, 6),
    }
    digest = "sha256:" + hashlib.sha256(digest_material(bundle, False)).hexdigest()
    bundle["model_digest"] = digest
    bundle["payload_digest"] = "sha256:" + hashlib.sha256(digest_material(bundle, True)).hexdigest()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(canonical(bundle) + b"\n")
    return bundle


def score(event: dict[str, Any], bundle: dict[str, Any]) -> float:
    vector = [float32(value) for value in feature_vector(event)]
    distance = float32(0)
    for index, value in enumerate(vector):
        mean, scale = float32(bundle["mean"][index]), float32(bundle["scale"][index])
        normalized = float32(float32(value - mean) / scale)
        distance = float32(distance + float32(normalized * normalized))
    return float32(math.sqrt(distance))


def float32(value: float) -> float:
    return struct.unpack("!f", struct.pack("!f", value))[0]


def replay(input_path: Path, bundle_path: Path, output_path: Path) -> int:
    bundle = json.loads(bundle_path.read_text())
    validate_bundle(bundle)
    signals = []
    for event in read_events(input_path):
        value = score(event, bundle)
        if value < bundle["threshold"]:
            continue
        signals.append({
            "id": model_signal_id(str(event.get("id", "")), bundle["model_digest"], value),
            "name": "model_anomaly",
            "where": "SIGNAL_WHERE_ENDPOINT",
            "stage": "SIGNAL_STAGE_CANDIDATE",
            "detectorKind": "DETECTOR_KIND_MODEL",
            "localRarity": value,
            "eventRefs": [str(event.get("id", ""))],
            "modelRef": bundle["model_ref"],
            "modelVersion": bundle["model_version"],
            "modelDigest": bundle["model_digest"],
            "featureSchema": bundle["feature_schema"],
        })
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("".join(json.dumps(signal, sort_keys=True) + "\n" for signal in signals))
    return len(signals)


def model_signal_id(event_id: str, model_digest: str, value: float) -> str:
    material = f"{event_id}|{model_digest}|{value:.6f}".encode()
    return "sig-model-" + hashlib.sha256(material).hexdigest()[:16]


def main() -> None:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    collect_parser = subparsers.add_parser("collect")
    collect_parser.add_argument("--input", type=Path, required=True)
    collect_parser.add_argument("--output", type=Path, required=True)
    collect_parser.add_argument("--label")
    train_parser = subparsers.add_parser("train")
    train_parser.add_argument("--input", type=Path, required=True)
    train_parser.add_argument("--output", type=Path, required=True)
    train_parser.add_argument("--threshold", type=float, default=3.0)
    replay_parser = subparsers.add_parser("replay")
    replay_parser.add_argument("--input", type=Path, required=True)
    replay_parser.add_argument("--bundle", type=Path, required=True)
    replay_parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "collect":
        print(collect(args.input, args.output, args.label))
    elif args.command == "train":
        print(train(args.input, args.output, args.threshold)["model_digest"])
    else:
        print(replay(args.input, args.bundle, args.output))


if __name__ == "__main__":
    main()
