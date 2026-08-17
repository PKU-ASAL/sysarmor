#!/usr/bin/env python3
"""Strict aggregation and human report for Learning Detector A/B runs."""

from __future__ import annotations

import json
import math
import argparse
import csv
import importlib.util
from pathlib import Path
from typing import Any

from learning_report_renderer import render_report
from learning_effect import (
    attack_profile_recall,
    candidate_profile_ids,
    effect_gates,
    model_gate,
    normal_candidate_rate,
    profile_health,
)


DEFAULT_GATES = {
    "cpu_relative": 1.15,
    "rss_delta_mb": 16.0,
    "eps_relative": 0.90,
    "normal_candidate_rate": 0.01,
    "attack_profile_recall": 0.90,
}
TEST_ROOT = Path(__file__).resolve().parents[3]


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


def gate(status: str, value: Any = None, limit: Any = None, detail: str = "") -> dict[str, Any]:
    return {"status": status, "value": value, "limit": limit, "detail": detail}


def compare_upper(disabled: Any, enabled: Any, limit: float) -> dict[str, Any]:
    first, second = numeric(disabled), numeric(enabled)
    if first is None or second is None:
        return gate("unavailable", second, None, "missing A/B metric")
    return gate("passed" if second <= limit else "failed", second, limit, f"disabled={first}")


def evaluate_ab(disabled: dict[str, Any], enabled: dict[str, Any], gates: dict[str, float]) -> dict[str, Any]:
    disabled_performance = disabled.get("performance", {})
    enabled_performance = enabled.get("performance", {})
    disabled_cpu = numeric(disabled_performance.get("agent_cpu_avg_pct"))
    enabled_cpu = numeric(enabled_performance.get("agent_cpu_avg_pct"))
    disabled_rss = numeric(disabled_performance.get("agent_rss_max_mb"))
    enabled_rss = numeric(enabled_performance.get("agent_rss_max_mb"))
    disabled_eps = numeric(disabled_performance.get("eps"))
    enabled_eps = numeric(enabled_performance.get("eps"))
    cpu_limit = disabled_cpu * gates["cpu_relative"] if disabled_cpu is not None else None
    rss_limit = disabled_rss + gates["rss_delta_mb"] if disabled_rss is not None else None
    eps_limit = disabled_eps * gates["eps_relative"] if disabled_eps is not None else None
    gate_results = {
        "performance_cpu": compare_upper(disabled_cpu, enabled_cpu, cpu_limit) if cpu_limit is not None else gate("unavailable", enabled_cpu, None, "missing disabled CPU"),
        "performance_rss": compare_upper(disabled_rss, enabled_rss, rss_limit) if rss_limit is not None else gate("unavailable", enabled_rss, None, "missing disabled RSS"),
        "performance_eps": gate("unavailable", enabled_eps, None, "missing disabled EPS") if eps_limit is None else gate("passed" if enabled_eps is not None and enabled_eps >= eps_limit else "failed" if enabled_eps is not None else "unavailable", enabled_eps, eps_limit, f"disabled={disabled_eps}"),
        "reliability": reliability_gate(disabled, enabled),
        "model": model_gate(disabled, enabled),
        "rule_truth": rule_truth_gate(disabled, enabled),
        **effect_gates(enabled, gates),
    }
    statuses = [item["status"] for item in gate_results.values()]
    verdict = "passed" if all(status == "passed" for status in statuses) else "failed"
    return {
        "verdict": verdict,
        "gates": gate_results,
        "observations": {
            "stream_evictions": (disabled.get("stream_evictions") or 0) + (enabled.get("stream_evictions") or 0),
            "attack_profile_recall": attack_profile_recall(enabled),
            "normal_candidate_rate": normal_candidate_rate(enabled),
            "disabled_model_candidates": len(disabled.get("model_candidates", [])),
            "enabled_model_candidates": len(enabled.get("model_candidates", [])),
            "rule_truth_baseline_status": {
                "disabled": baseline_status(disabled),
                "enabled": baseline_status(enabled),
            },
        },
        "variants": {"disabled": variant_summary(disabled), "enabled": variant_summary(enabled)},
        "truth_steps": {"disabled": disabled.get("truth_steps", []), "enabled": enabled.get("truth_steps", [])},
        "samples": {"disabled": disabled.get("samples", {}), "enabled": enabled.get("samples", {})},
    }


def baseline_status(metrics: dict[str, Any]) -> str:
    return "passed" if metrics.get("truth_baseline_ok") else "failed"


def truth_signature(metrics: dict[str, Any]) -> dict[tuple[str, str], tuple[Any, Any]]:
    return {
        (step.get("label_type", ""), step.get("label_id", "")): (
            bool(step.get("matched")), step.get("match_quality", "")
        )
        for step in metrics.get("truth_steps", []) if step.get("required")
    }


def rule_truth_gate(disabled: dict[str, Any], enabled: dict[str, Any]) -> dict[str, Any]:
    first, second = truth_signature(disabled), truth_signature(enabled)
    if not first or not second:
        return gate("unavailable", None, None, "missing required Rule truth result")
    if not disabled.get("rule_refs_ok") or not enabled.get("rule_refs_ok"):
        return gate("failed", None, "resolved refs", "unresolved Rule Signal event ref")
    if first != second:
        return gate("failed", None, "equivalent", "Learning changed required Rule truth outcome")
    return gate("passed", "equivalent", "equivalent", "required Rule truth outcome and refs")


def variant_summary(metrics: dict[str, Any]) -> dict[str, Any]:
    profiles = set(metrics.get("profile_ids", []))
    truth = set(metrics.get("truth_profile_ids", []))
    candidates = candidate_profile_ids(metrics)
    normal = profiles.difference(truth)
    return {
        "health": metrics.get("health", {}),
        "reliability": metrics.get("reliability", {}),
        "performance": metrics.get("performance", {}),
        "stream_evictions": metrics.get("stream_evictions", 0),
        "event_count": len(metrics.get("events", [])),
        "rule_signal_count": metrics.get("rule_signal_count", 0),
        "model_candidate_count": len(metrics.get("model_candidates", [])),
        "profile_count": len(metrics.get("profile_ids", [])),
        "candidate_profile_count": len(candidate_profile_ids(metrics)),
        "normal_profile_count": len(normal),
        "normal_candidate_count": len(candidates.intersection(normal)),
        "truth_profile_count": len(truth),
        "detected_truth_profile_count": len(candidates.intersection(truth)),
        "normal_candidate_rate": normal_candidate_rate(metrics),
        "attack_profile_recall": attack_profile_recall(metrics),
        "profile_health": metrics.get("profile_health", {}),
        "candidate_scores": score_summary(metrics.get("model_candidates", [])),
    }


def score_summary(signals: list[dict[str, Any]]) -> dict[str, Any]:
    scores = sorted(value for signal in signals if (value := numeric(signal.get("localRarity"))) is not None)
    if not scores:
        return {"min": None, "p50": None, "max": None}
    return {"min": scores[0], "p50": scores[len(scores) // 2], "max": scores[-1]}


def reliability_gate(disabled: dict[str, Any], enabled: dict[str, Any]) -> dict[str, Any]:
    for side in (disabled, enabled):
        health = side.get("health", {})
        reliability = side.get("reliability", {})
        if any(reliability.get(key) is None for key in ("sensor_drop", "batcher_drop", "parse_errors")):
            return gate("unavailable", None, 0, "missing health drop/parse metric")
        if health.get("status") != "ok" or any(reliability.get(key) != 0 for key in ("sensor_drop", "batcher_drop", "parse_errors")):
            return gate("failed", None, 0, "health/drop/parse error")
    return gate("passed", 0, 0, "health/drop/parse error")


def load_endpoint_run(path: Path, phase: str = "normal_activity") -> dict[str, Any]:
    if (path / "collection-balanced").is_dir():
        path = path / "collection-balanced"
    manifest = require_json(path / "manifest.json")
    summary = require_json(path / "summary.json")
    signals = [unwrap(row, "signal") for row in require_records(path / "signals.scope.ndjson", "signal")]
    events = [unwrap(row, "event") for row in require_records(path / "events.scope.ndjson", "event")]
    model_candidates = [signal for signal in signals if signal.get("detectorKind") == "DETECTOR_KIND_MODEL"]
    rule_signals = [signal for signal in signals if signal.get("detectorKind") == "DETECTOR_KIND_RULE"]
    truth = evaluate_truth(path, events, rule_signals)
    event_ids = {str(event.get("id")) for event in events if event.get("id")}
    event_profiles = {
        str(event.get("id")): stable_id
        for event in events
        if event.get("id") and (stable_id := event_profile_id(event)) is not None
    }
    phase_data = load_matrix_phase(path, phase)
    health_document = latest_health(path)
    detection = health_document.get("detection", {})
    batcher = health_document.get("telemetryBatcher", health_document.get("telemetry_batcher", {}))
    sensor = health_document.get("sensor", {})
    learning = detection.get("learning", {})
    return {
        "manifest": manifest,
        "health": {"status": health_document.get("status"), "learning": learning.get("status")},
        "profile_health": profile_health(learning.get("profiles", {})),
        "reliability": {"sensor_drop": health_number(sensor, "eventsDropped", "events_dropped"), "batcher_drop": health_number(batcher, "droppedEvents", "dropped_events"), "parse_errors": health_number(sensor, "parseErrors", "parse_errors")},
        "performance": {"agent_cpu_avg_pct": phase_data.get("agent_cpu_avg_pct"), "agent_rss_max_mb": phase_data.get("agent_rss_max_mb"), "eps": phase_data.get("eps")},
        "stream_evictions": latest_stream_evictions(path),
        "model_candidates": model_candidates,
        "truth_baseline_ok": truth["ok"],
        "rule_refs_ok": all(signal.get("eventRefs") and set(signal["eventRefs"]).issubset(event_ids) for signal in rule_signals),
        "truth_events": truth["event_ids"],
        "profile_ids": set(event_profiles.values()),
        "truth_profile_ids": {event_profiles[event_id] for event_id in truth["event_ids"] if event_id in event_profiles},
        "truth_steps": truth["steps"],
        "events": event_ids,
        "rule_signal_count": len(rule_signals),
        "samples": bounded_samples(events, rule_signals, model_candidates),
    }


def bounded_samples(
    events: list[dict[str, Any]], rule_signals: list[dict[str, Any]], model_candidates: list[dict[str, Any]], limit: int = 3
) -> dict[str, Any]:
    return {
        "events": [event_sample(event) for event in events[:limit]],
        "rule_signals": [signal_sample(signal) for signal in rule_signals[:limit]],
        "model_candidates": [signal_sample(signal) for signal in model_candidates[:limit]],
    }


def event_sample(event: dict[str, Any]) -> dict[str, Any]:
    subject = event.get("subjectProc", {})
    return {
        "id": event.get("id"),
        "behavior": event.get("behavior"),
        "binary": subject.get("binary"),
        "argv": subject.get("argv", [])[:8],
        "object": event.get("object", {}),
    }


def event_profile_id(event: dict[str, Any]) -> str | None:
    stable_id = event.get("subjectProc", {}).get("stableId")
    return stable_id if isinstance(stable_id, str) and stable_id else None


def signal_sample(signal: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": signal.get("id"),
        "name": signal.get("name"),
        "stage": signal.get("stage"),
        "detectorKind": signal.get("detectorKind"),
        "where": signal.get("where"),
        "score": signal.get("localRarity"),
        "event_refs": signal.get("eventRefs", [])[:8],
        "entities": signal.get("entities", [])[:8],
    }


def detection_report_module():
    path = TEST_ROOT / "shared/reports/detection_report.py"
    spec = importlib.util.spec_from_file_location("sysarmor_detection_report", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def evaluate_truth(path: Path, events: list[dict[str, Any]], rule_signals: list[dict[str, Any]]) -> dict[str, Any]:
    evaluator = detection_report_module()
    labels = evaluator.load_yaml(TEST_ROOT / "data/scenarios/vm/apt-fileless-c2-local/labels.yaml")
    result = evaluator.evaluate_case(labels, events, rule_signals, load_json(path / "summary.json"))
    required = [step for step in result["truth_steps"] if step["required"]]
    signal_steps = [step for step in required if step["label_type"] == "signal"]
    ok = all(step["matched"] for step in required) and all(step["match_quality"] in ("", 1.0) for step in signal_steps)
    required_event_labels = {step["label_id"] for step in required if step["label_type"] == "event"}
    canonical = [evaluator.canonical_event(event) for event in events]
    event_ids = {
        event["id"] for label in labels["labels"]["events"] if label["id"] in required_event_labels
        for event in canonical if evaluator.event_label_matches(label, event) and event["id"]
    }
    return {"ok": ok, "event_ids": event_ids, "steps": required}


def load_matrix_phase(path: Path, phase: str) -> dict[str, Any]:
    matrix = path.parent / "matrix.csv"
    if matrix.exists():
        with matrix.open(newline="") as stream:
            for row in csv.DictReader(stream):
                if row.get("policy_dir") == path.name:
                    return {
                        "agent_cpu_avg_pct": numeric(row.get(f"{phase}_agent_cpu_avg_pct")),
                        "agent_rss_max_mb": numeric(row.get(f"{phase}_agent_rss_max_mb")),
                        "eps": numeric(row.get(f"{phase}_eps")),
                        "dropped_events_delta": int(float(row.get(f"{phase}_dropped_events_delta") or 0)),
                        "parse_errors_delta": int(float(row.get(f"{phase}_parse_errors_delta") or 0)),
                    }
    return {}


def read_lines(path: Path) -> list[str]:
    return path.read_text().splitlines() if path.exists() else []


def load_json_line(line: str) -> dict[str, Any]:
    value = json.loads(line)
    return value if isinstance(value, dict) else {}


def unwrap(value: dict[str, Any], key: str) -> dict[str, Any]:
    nested = value.get(key)
    return nested if isinstance(nested, dict) else value


def load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    value = json.loads(path.read_text())
    return value if isinstance(value, dict) else {}


def require_json(path: Path) -> dict[str, Any]:
    if not path.is_file() or path.stat().st_size == 0:
        raise ReportError(f"required JSON artifact is missing: {path}")
    try:
        value = json.loads(path.read_text())
    except json.JSONDecodeError as error:
        raise ReportError(f"invalid JSON artifact: {path}") from error
    if not isinstance(value, dict) or not value:
        raise ReportError(f"JSON artifact must be a non-empty object: {path}")
    return value


def require_ndjson(path: Path) -> list[dict[str, Any]]:
    if not path.is_file() or path.stat().st_size == 0:
        raise ReportError(f"required NDJSON artifact is missing: {path}")
    try:
        rows = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    except json.JSONDecodeError as error:
        raise ReportError(f"invalid NDJSON artifact: {path}") from error
    if not rows or any(not isinstance(row, dict) for row in rows):
        raise ReportError(f"NDJSON artifact must contain objects: {path}")
    return rows


def require_records(path: Path, record_type: str) -> list[dict[str, Any]]:
    required = {"event": ("id", "behavior"), "signal": ("id", "detectorKind", "stage")}
    if record_type not in required:
        raise ReportError(f"unsupported NDJSON record type: {record_type}")
    rows = require_ndjson(path)
    for row in rows:
        value = row.get(record_type, row)
        fields = [value.get(field) for field in required[record_type]] if isinstance(value, dict) else []
        if not fields or any(not isinstance(field, str) or not field.strip() for field in fields):
            raise ReportError(f"invalid {record_type} record in artifact: {path}")
        if record_type == "signal" and ("UNSPECIFIED" in fields[1] or "UNSPECIFIED" in fields[2]):
            raise ReportError(f"invalid {record_type} enum in artifact: {path}")
    return rows


def latest_health_status(path: Path) -> str | None:
    return latest_health(path).get("status")


def latest_health(path: Path) -> dict[str, Any]:
    files = sorted((path / "raw").glob("*.health.json"))
    return load_json(files[-1]) if files else {}


def health_number(value: dict[str, Any], *names: str) -> int | None:
    if not value:
        return None
    for name in names:
        if name in value:
            try:
                return int(value[name])
            except (TypeError, ValueError):
                return None
    return 0


def latest_stream_evictions(path: Path) -> int:
    files = sorted((path / "raw").glob("*.health.json"))
    streams = load_json(files[-1]).get("streams", {}) if files else {}
    return int(streams.get("eventEvicted", 0) or 0) + int(streams.get("signalEvicted", 0) or 0)


def generate_report(run_dir: Path, output: Path | None = None, strict: bool = True) -> dict[str, Any]:
    summary = load_json(run_dir / "summary.json")
    if not summary:
        raise ReportError("summary.json is required")
    if strict and summary.get("verdict") not in ("passed", "failed"):
        raise ReportError("summary verdict is required")
    destination = output or run_dir / "report.md"
    destination.write_text(render_report(summary))
    return {"output": str(destination), "verdict": summary.get("verdict")}


def aggregate_runs(run_dir: Path) -> dict[str, Any]:
    disabled_path, enabled_path = run_dir / "disabled", run_dir / "enabled"
    if not disabled_path.exists() or not enabled_path.exists():
        summary = {"verdict": "failed", "status": "partial", "gates": {}, "observations": {}, "missing": [str(path.name) for path in (disabled_path, enabled_path) if not path.exists()]}
    else:
        try:
            experiment = require_json(run_dir / "manifest.json")
            calibration = require_json(run_dir / "model/calibration.json")
            validate_experiment_artifacts(experiment, calibration)
            disabled, enabled = load_endpoint_run(disabled_path), load_endpoint_run(enabled_path)
            enabled["expected_model"] = model_identity(experiment)
            summary = evaluate_ab(disabled, enabled, DEFAULT_GATES)
            summary["experiment"] = experiment_summary(experiment, disabled_path)
            summary["model"] = model_summary(experiment, calibration)
        except Exception as error:
            summary = {"verdict": "failed", "status": "invalid", "gates": {}, "observations": {}, "error": f"{type(error).__name__}: {error}"}
    (run_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    (run_dir / "report.md").write_text(render_report(summary))
    return summary


def validate_experiment_artifacts(manifest: dict[str, Any], calibration: dict[str, Any]) -> None:
    required = (
        "suite", "run_id", "benchmark_profile", "policy", "activity_mode", "scenario", "git_commit",
        "git_provenance_source", "training_data", "training_digest", "calibration_data", "calibration_digest",
        "model_ref", "model_version", "model_digest", "feature_schema",
    )
    if any(not isinstance(manifest.get(key), str) or not manifest[key].strip() for key in required):
        raise ReportError("experiment manifest has missing or invalid required fields")
    if manifest.get("git_dirty") is not None and not isinstance(manifest.get("git_dirty"), bool):
        raise ReportError("experiment manifest git_dirty must be boolean or unavailable")
    threshold = manifest.get("threshold")
    if not is_json_number(threshold) or not valid_gate_config(manifest.get("gate_config")):
        raise ReportError("experiment manifest has invalid threshold or gate config")
    validate_calibration(manifest, calibration)


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
    if not isinstance(bundle, dict) or any(bundle.get(key) != manifest.get(key) for key in ("model_ref", "model_version", "model_digest", "feature_schema", "threshold")):
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


def experiment_summary(experiment: dict[str, Any], disabled_path: Path) -> dict[str, Any]:
    path = disabled_path / "collection-balanced" if (disabled_path / "collection-balanced").is_dir() else disabled_path
    endpoint = require_json(path / "manifest.json")
    result = dict(experiment)
    result["vm_env"] = endpoint.get("vm_env")
    return result


def model_summary(manifest: dict[str, Any], calibration: dict[str, Any]) -> dict[str, Any]:
    calibration = dict(calibration)
    for key in ("model_ref", "model_version", "model_digest", "feature_schema", "threshold"):
        calibration[key] = manifest.get(key, calibration.get("bundle", {}).get(key))
    return calibration


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("run_dir", type=Path)
    parser.add_argument("--aggregate", action="store_true")
    args = parser.parse_args()
    if args.aggregate:
        summary = aggregate_runs(args.run_dir)
        return 0 if summary.get("verdict") == "passed" else 1
    generate_report(args.run_dir, strict=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
