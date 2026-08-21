#!/usr/bin/env python3
"""Strict aggregation and human report for the protection mode matrix."""

from __future__ import annotations

import json
import argparse
import importlib.util
from pathlib import Path
from typing import Any

from learning_artifacts import (
    DEFAULT_GATES,
    ReportError,
    is_json_number,
    model_identity,
    model_summary,
    numeric,
    valid_gate_config,
    validate_calibration,
)
from learning_report_renderer import render_report
from learning_performance import load_matrix_phase
from managed_analysis import managed_analysis_metrics, managed_candidate_artifacts
from protection_mode_contract import PROTECTION_MODES, validate_mode_matrix
from learning_effect import (
    attack_campaign_seed_recall,
    candidate_profile_ids,
    candidate_lifecycle_gate,
    effect_gates,
    model_gate,
    normal_candidate_rate,
    normal_profile_ids,
    profile_health,
)


TEST_ROOT = Path(__file__).resolve().parents[3]
PROTECTION_MODE_POLICY_DIR = {
    "rule-only": "collection-balanced",
    "learning-only": "collection-learning",
    "hybrid": "collection-hybrid",
}


def gate(status: str, value: Any = None, limit: Any = None, detail: str = "") -> dict[str, Any]:
    return {"status": status, "value": value, "limit": limit, "detail": detail}


def compare_upper(baseline: Any, candidate: Any, limit: float) -> dict[str, Any]:
    first, second = numeric(baseline), numeric(candidate)
    if first is None or second is None:
        return gate("unavailable", second, None, "missing comparison metric")
    return gate("passed" if second <= limit else "failed", second, limit, f"rule-only={first}")


def evaluate_mode(
    baseline: dict[str, Any], candidate: dict[str, Any], mode: str, gates: dict[str, float]
) -> dict[str, Any]:
    baseline_performance = baseline.get("performance", {})
    candidate_performance = candidate.get("performance", {})
    baseline_cpu = numeric(baseline_performance.get("agent_cpu_avg_pct"))
    candidate_cpu = numeric(candidate_performance.get("agent_cpu_avg_pct"))
    baseline_rss = numeric(baseline_performance.get("agent_rss_steady_avg_mb"))
    candidate_rss = numeric(candidate_performance.get("agent_rss_steady_avg_mb"))
    baseline_eps = numeric(baseline_performance.get("eps"))
    candidate_eps = numeric(candidate_performance.get("eps"))
    cpu_limit = gates["learning_only_cpu_pct"] if mode == "learning-only" else gates["hybrid_cpu_pct"]
    rss_limit = baseline_rss + gates["rss_delta_mb"] if baseline_rss is not None else None
    eps_limit = baseline_eps * gates["eps_relative"] if baseline_eps is not None else None
    gate_results = {
        "performance_cpu": gate("passed" if candidate_cpu is not None and candidate_cpu <= cpu_limit else "failed" if candidate_cpu is not None else "unavailable", candidate_cpu, cpu_limit, f"absolute {mode} Agent CPU"),
        "performance_rss": compare_upper(baseline_rss, candidate_rss, rss_limit) if rss_limit is not None else gate("unavailable", candidate_rss, None, "missing rule-only RSS"),
        "performance_eps": gate("unavailable", candidate_eps, None, "missing rule-only EPS") if eps_limit is None else gate("passed" if candidate_eps is not None and candidate_eps >= eps_limit else "failed" if candidate_eps is not None else "unavailable", candidate_eps, eps_limit, f"rule-only={baseline_eps}"),
        "reliability": reliability_gate(baseline, candidate),
        "model": model_gate(baseline, candidate),
        "candidate_lifecycle": candidate_lifecycle_gate(candidate),
        **effect_gates(candidate, mode, gates),
    }
    if mode == "hybrid":
        gate_results["rule_truth"] = rule_truth_gate(baseline, candidate)
    statuses = [item["status"] for item in gate_results.values() if item.get("blocking", True)]
    verdict = "passed" if all(status == "passed" for status in statuses) else "failed"
    return {
        "verdict": verdict,
        "gates": gate_results,
        "observations": {
            "stream_evictions": (baseline.get("stream_evictions") or 0) + (candidate.get("stream_evictions") or 0),
            "attack_campaign_seed_recall": attack_campaign_seed_recall(candidate),
            "normal_candidate_rate": normal_candidate_rate(candidate),
            "rule_only_model_candidates": len(baseline.get("model_candidates", [])),
            "candidate_model_candidates": len(candidate.get("model_candidates", [])),
            "rule_truth_baseline_status": {
                "rule-only": baseline_status(baseline),
                mode: baseline_status(candidate),
            },
        },
        "variants": {"rule-only": variant_summary(baseline), mode: variant_summary(candidate)},
        "truth_steps": {"rule-only": baseline.get("truth_steps", []), mode: candidate.get("truth_steps", [])},
        "samples": {"rule-only": baseline.get("samples", {}), mode: candidate.get("samples", {})},
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


def rule_truth_gate(baseline: dict[str, Any], candidate: dict[str, Any]) -> dict[str, Any]:
    first, second = truth_signature(baseline), truth_signature(candidate)
    if not first or not second:
        return gate("unavailable", None, None, "missing required Rule truth result")
    if not baseline.get("rule_refs_ok") or not candidate.get("rule_refs_ok"):
        return gate("failed", None, "resolved refs", "unresolved Rule Signal event ref")
    if first != second:
        return gate("failed", None, "equivalent", "Learning changed required Rule truth outcome")
    return gate("passed", "equivalent", "equivalent", "required Rule truth outcome and refs")


def variant_summary(metrics: dict[str, Any]) -> dict[str, Any]:
    profiles = set(metrics.get("profile_ids", []))
    truth = set(metrics.get("truth_profile_ids", []))
    candidates = candidate_profile_ids(metrics)
    normal = normal_profile_ids(metrics)
    truth_campaigns = set(metrics.get("truth_campaign_ids") or set())
    campaign_by_profile = metrics.get("profile_campaign_ids") or {}
    candidate_campaigns = {campaign_by_profile[profile] for profile in candidates if campaign_by_profile.get(profile)}
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
        "truth_campaign_count": len(truth_campaigns),
        "seeded_campaign_count": len(candidate_campaigns.intersection(truth_campaigns)),
        "normal_candidate_rate": normal_candidate_rate(metrics),
        "attack_campaign_seed_recall": attack_campaign_seed_recall(metrics),
        "profile_health": metrics.get("profile_health", {}),
        "candidate_scores": score_summary(metrics.get("model_candidates", [])),
        "candidate_lifecycle": metrics.get("candidate_lifecycle", {}),
        "reference_gaps": metrics.get("reference_gaps", {}),
    }


def score_summary(signals: list[dict[str, Any]]) -> dict[str, Any]:
    scores = sorted(value for signal in signals if (value := numeric(signal.get("localRarity"))) is not None)
    if not scores:
        return {"min": None, "p50": None, "max": None}
    return {"min": scores[0], "p50": scores[len(scores) // 2], "max": scores[-1]}


def reliability_gate(baseline: dict[str, Any], candidate: dict[str, Any]) -> dict[str, Any]:
    for side in (baseline, candidate):
        health = side.get("health", {})
        reliability = side.get("reliability", {})
        if any(reliability.get(key) is None for key in ("sensor_drop", "batcher_drop", "parse_errors")):
            return gate("unavailable", None, 0, "missing health drop/parse metric")
        if health.get("status") != "ok" or any(reliability.get(key) != 0 for key in ("sensor_drop", "batcher_drop", "parse_errors")):
            return gate("failed", None, 0, "health/drop/parse error")
    return gate("passed", 0, 0, "health/drop/parse error")


def endpoint_policy_dir(path: Path) -> Path:
    if (path / "effective-policy.json").is_file():
        return path
    manifest = require_json(path / "manifest.json")
    mode = manifest.get("protection_mode")
    policy_dir = PROTECTION_MODE_POLICY_DIR.get(mode)
    if policy_dir is None:
        raise ReportError(f"endpoint run has unsupported protection mode: {mode!r}")
    resolved = path / policy_dir
    if not resolved.is_dir():
        raise ReportError(f"endpoint run is missing policy directory for {mode}: {resolved}")
    return resolved


def load_endpoint_run(path: Path) -> dict[str, Any]:
    path = endpoint_policy_dir(path)
    manifest = require_json(path / "manifest.json")
    effective_policy = require_json(path / "effective-policy.json")
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
    profile_campaigns = {
        stable_id: str(event.get("lineageId") or stable_id)
        for event in events
        if (stable_id := event_profile_id(event)) is not None
    }
    truth_profile_ids = {event_profiles[event_id] for event_id in truth["event_ids"] if event_id in event_profiles}
    health_document = latest_health(path)
    lifecycle_document = candidate_lifecycle_snapshot(path)
    detection = health_document.get("detection", {})
    batcher = health_document.get("telemetryBatcher", health_document.get("telemetry_batcher", {}))
    sensor = health_document.get("sensor", {})
    learning = detection.get("learning", {})
    lifecycle_learning = lifecycle_document.get("detection", {}).get("learning", {})
    candidate_lifecycle = candidate_lifecycle_health(lifecycle_learning.get("candidates", {}))
    local_store = lifecycle_document.get("localStore", lifecycle_document.get("local_store", {}))
    result = {
        "manifest": manifest,
        "effective_policy": effective_policy,
        "health": {"status": health_document.get("status"), "learning": learning.get("status")},
        "profile_health": profile_health(learning.get("profiles", {})),
        "reliability": {"sensor_drop": health_number(sensor, "eventsDropped", "events_dropped"), "batcher_drop": health_number(batcher, "droppedEvents", "dropped_events"), "parse_errors": health_number(sensor, "parseErrors", "parse_errors")},
        "performance": performance_metrics(path),
        "stream_evictions": latest_stream_evictions(path),
        "candidate_lifecycle": candidate_lifecycle,
        "reference_gaps": {
            "observation_gap": latest_stream_evictions(path),
            "endpoint_storage_drop": health_number(local_store, "droppedEventsStorage", "dropped_events_storage"),
            "gateway_reject": candidate_lifecycle.get("gateway_rejected"),
            "agent_contract_reject": candidate_lifecycle.get("contract_rejected"),
            "agent_spool_backlog": None,
            "agent_delivery_backlog": None,
            "worker_pending_backlog": None,
            "worker_reference_rejected": None,
        },
        "model_candidates": model_candidates,
        "truth_baseline_ok": truth["ok"],
        "rule_refs_ok": all(signal.get("eventRefs") and set(signal["eventRefs"]).issubset(event_ids) for signal in rule_signals),
        "truth_events": truth["event_ids"],
        "profile_ids": set(event_profiles.values()),
        "truth_profile_ids": truth_profile_ids,
        "profile_campaign_ids": profile_campaigns,
        "truth_campaign_ids": {profile_campaigns[profile] for profile in truth_profile_ids if profile in profile_campaigns},
        "truth_steps": truth["steps"],
        "events": event_ids,
        "rule_signal_count": len(rule_signals),
        "samples": bounded_samples(events, rule_signals, model_candidates),
    }
    cutoff = health_number(local_store, "eventSequenceCutoff", "event_sequence_cutoff")
    managed_candidates = managed_candidate_artifacts(
        path, manifest.get("agent_mode"), manifest.get("agent_id"), cutoff
    )
    if managed_candidates.get("model_candidates") is not None:
        result["model_candidates"] = managed_candidates["model_candidates"]
    result["candidate_reference_integrity"] = managed_candidates["candidate_reference_integrity"]
    accepted = candidate_lifecycle.get("gateway_accepted")
    correlated = managed_candidates["candidate_reference_integrity"].get("correlated")
    reference_rejected = managed_candidates["candidate_reference_integrity"].get("reference_rejected")
    pending_backlog = None
    pending_backlog = lifecycle_delta(accepted, correlated, reference_rejected)
    result["candidate_reference_integrity"]["pending_backlog"] = pending_backlog
    result["reference_gaps"]["worker_pending_backlog"] = pending_backlog
    result["reference_gaps"]["worker_reference_rejected"] = reference_rejected
    spooled = candidate_lifecycle.get("spooled")
    created = candidate_lifecycle.get("created")
    contract_rejected = candidate_lifecycle.get("contract_rejected")
    gateway_rejected = candidate_lifecycle.get("gateway_rejected")
    result["reference_gaps"]["agent_spool_backlog"] = lifecycle_delta(created, spooled, contract_rejected)
    result["reference_gaps"]["agent_delivery_backlog"] = lifecycle_delta(spooled, accepted, gateway_rejected)
    result["candidate_lifecycle"]["worker_correlated"] = correlated
    result["candidate_lifecycle"]["worker_projected"] = managed_candidates["candidate_reference_integrity"].get("projected")
    result["candidate_lifecycle"]["worker_projection_artifacts"] = managed_candidates["candidate_reference_integrity"].get("projection_artifacts")
    result["candidate_lifecycle"]["worker_pending_backlog"] = pending_backlog
    result.update(managed_analysis_metrics(path, manifest.get("agent_mode"), truth["event_ids"]))
    return result


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


def performance_metrics(path: Path) -> dict[str, Any]:
    activity = load_matrix_phase(path, "normal_activity")
    steady = load_matrix_phase(path, "steady")
    return {
        "agent_cpu_avg_pct": activity.get("agent_cpu_avg_pct"),
        "agent_rss_steady_avg_mb": steady.get("agent_rss_avg_mb"),
        "agent_rss_steady_max_mb": steady.get("agent_rss_max_mb"),
        "eps": activity.get("eps"),
    }


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
    if files:
        return load_json(files[-1])
    return candidate_lifecycle_snapshot(path)


def candidate_lifecycle_snapshot(path: Path) -> dict[str, Any]:
    final = path / "candidate-lifecycle-final.json"
    return load_json(final) if final.is_file() else latest_raw_health(path)


def latest_raw_health(path: Path) -> dict[str, Any]:
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


def candidate_lifecycle_health(value: dict[str, Any]) -> dict[str, int | None]:
    fields = {
        "created": ("experimentCreated", "experiment_created", "created", "Created"),
        "spooled": ("spooled", "Spooled"),
        "gateway_accepted": ("gatewayAccepted", "gateway_accepted", "GatewayAccepted"),
        "gateway_duplicate_ack": ("gatewayDuplicateAck", "gateway_duplicate_ack", "GatewayDuplicateAck"),
        "contract_rejected": ("contractRejected", "contract_rejected", "ContractRejected"),
        "gateway_rejected": ("gatewayRejected", "gateway_rejected", "GatewayRejected"),
    }
    return {name: explicit_health_number(value, *aliases) for name, aliases in fields.items()}


def explicit_health_number(value: dict[str, Any], *names: str) -> int | None:
    for name in names:
        if name in value:
            try:
                return int(value[name])
            except (TypeError, ValueError):
                return None
    return None


def lifecycle_delta(upstream: int | None, downstream: int | None, rejected: int | None) -> int | None:
    if upstream is None or downstream is None or rejected is None:
        return None
    return upstream - downstream - rejected


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
    paths = {mode: run_dir / mode for mode in PROTECTION_MODES}
    missing = [mode for mode, path in paths.items() if not path.exists()]
    if missing:
        summary = {"verdict": "failed", "status": "partial", "gates": {}, "observations": {}, "missing": missing}
    else:
        try:
            experiment = require_json(run_dir / "manifest.json")
            calibration = require_json(run_dir / "model/calibration.json")
            validate_experiment_artifacts(experiment, calibration)
            modes = {mode: load_endpoint_run(path) for mode, path in paths.items()}
            validate_mode_matrix(modes, model_identity(experiment))
            for mode in ("learning-only", "hybrid"):
                modes[mode]["expected_model"] = model_identity(experiment)
            comparisons = {
                mode: evaluate_mode(modes["rule-only"], modes[mode], mode, DEFAULT_GATES)
                for mode in ("learning-only", "hybrid")
            }
            summary = matrix_summary(modes, comparisons)
            summary["experiment"] = experiment_summary(experiment, paths["rule-only"])
            summary["model"] = model_summary(experiment, calibration)
        except Exception as error:
            summary = {"verdict": "failed", "status": "invalid", "gates": {}, "observations": {}, "error": f"{type(error).__name__}: {error}"}
    (run_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    (run_dir / "report.md").write_text(render_report(summary))
    return summary


def matrix_summary(modes: dict[str, dict[str, Any]], comparisons: dict[str, dict[str, Any]]) -> dict[str, Any]:
    gates = {
        f"{mode}.{name}": result
        for mode, comparison in comparisons.items()
        for name, result in comparison["gates"].items()
    }
    return {
        "verdict": "passed" if all(item["verdict"] == "passed" for item in comparisons.values()) else "failed",
        "gates": gates,
        "comparisons": comparisons,
        "observations": {
            "stream_evictions": sum(mode.get("stream_evictions") or 0 for mode in modes.values()),
            "rule_truth_baseline_status": {name: baseline_status(value) for name, value in modes.items()},
        },
        "variants": {name: variant_summary(value) for name, value in modes.items()},
        "truth_steps": {name: value.get("truth_steps", []) for name, value in modes.items()},
        "samples": {name: value.get("samples", {}) for name, value in modes.items()},
    }


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


def experiment_summary(experiment: dict[str, Any], baseline_path: Path) -> dict[str, Any]:
    path = endpoint_policy_dir(baseline_path)
    endpoint = require_json(path / "manifest.json")
    result = dict(experiment)
    result["vm_env"] = endpoint.get("vm_env")
    return result


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
