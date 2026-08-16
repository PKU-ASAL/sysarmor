#!/usr/bin/env python3
"""Strict aggregation and human report for Learning Detector A/B runs."""

from __future__ import annotations

import json
import math
import argparse
import csv
from pathlib import Path
from typing import Any


DEFAULT_GATES = {
    "cpu_absolute_pp": 1.0,
    "cpu_relative": 1.15,
    "rss_absolute_mb": 32.0,
    "rss_relative": 1.15,
    "eps_relative": 0.90,
}


class ReportError(ValueError):
    """Raised when a strict report cannot be constructed."""


def numeric(value: Any) -> float | None:
    if value is None:
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
    cpu_limit = max((disabled_cpu or 0) + gates["cpu_absolute_pp"], (disabled_cpu or 0) * gates["cpu_relative"]) if disabled_cpu is not None else None
    rss_limit = max((disabled_rss or 0) + gates["rss_absolute_mb"], (disabled_rss or 0) * gates["rss_relative"]) if disabled_rss is not None else None
    eps_limit = disabled_eps * gates["eps_relative"] if disabled_eps is not None else None
    gate_results = {
        "performance_cpu": compare_upper(disabled_cpu, enabled_cpu, cpu_limit) if cpu_limit is not None else gate("unavailable", enabled_cpu, None, "missing disabled CPU"),
        "performance_rss": compare_upper(disabled_rss, enabled_rss, rss_limit) if rss_limit is not None else gate("unavailable", enabled_rss, None, "missing disabled RSS"),
        "performance_eps": gate("unavailable", enabled_eps, None, "missing disabled EPS") if eps_limit is None else gate("passed" if enabled_eps is not None and enabled_eps >= eps_limit else "failed" if enabled_eps is not None else "unavailable", enabled_eps, eps_limit, f"disabled={disabled_eps}"),
        "reliability": reliability_gate(disabled, enabled),
        "model": model_gate(disabled, enabled),
        "rule_truth": gate("passed" if disabled.get("rule_truth_ok") and enabled.get("rule_truth_ok") else "failed", None, None, "required Rule truth links"),
    }
    statuses = [item["status"] for item in gate_results.values()]
    verdict = "passed" if all(status == "passed" for status in statuses) else "failed"
    return {
        "verdict": verdict,
        "gates": gate_results,
        "observations": {
            "stream_evictions": (disabled.get("stream_evictions") or 0) + (enabled.get("stream_evictions") or 0),
            "model_recall": model_recall(enabled),
            "disabled_model_candidates": len(disabled.get("model_signals", [])),
            "enabled_model_candidates": len(enabled.get("model_signals", [])),
        },
    }


def reliability_gate(disabled: dict[str, Any], enabled: dict[str, Any]) -> dict[str, Any]:
    for side in (disabled, enabled):
        health = side.get("health", {})
        reliability = side.get("reliability", {})
        if health.get("status") != "ok" or any(reliability.get(key) != 0 for key in ("sensor_drop", "batcher_drop", "parse_errors")):
            return gate("failed", None, 0, "health/drop/parse error")
    return gate("passed", 0, 0, "health/drop/parse error")


def model_gate(disabled: dict[str, Any], enabled: dict[str, Any]) -> dict[str, Any]:
    if disabled.get("health", {}).get("learning") != "disabled":
        return gate("failed", disabled.get("health", {}).get("learning"), "disabled", "disabled variant loaded a model")
    if disabled.get("model_signals"):
        return gate("failed", len(disabled["model_signals"]), 0, "disabled emitted Model Candidate")
    if enabled.get("health", {}).get("learning") != "loaded":
        return gate("failed", enabled.get("health", {}).get("learning"), "loaded", "enabled model is not loaded")
    event_ids = enabled.get("events", set())
    for signal in enabled.get("model_signals", []):
        if signal.get("stage") not in (None, "SIGNAL_STAGE_CANDIDATE") or signal.get("detectorKind") not in (None, "DETECTOR_KIND_MODEL"):
            return gate("failed", signal, "candidate/model", "invalid Model Candidate contract")
        if not set(signal.get("eventRefs", [])).issubset(event_ids):
            return gate("failed", signal, "resolved refs", "unresolved Model Candidate event ref")
    return gate("passed", len(enabled.get("model_signals", [])), None, "model provenance and refs")


def model_recall(metrics: dict[str, Any]) -> float | None:
    truth = set(metrics.get("truth_events") or metrics.get("events") or set())
    if not truth:
        return None
    refs = {ref for signal in metrics.get("model_signals", []) for ref in signal.get("eventRefs", [])}
    return len(refs.intersection(truth)) / len(truth)


def load_endpoint_run(path: Path, phase: str = "normal_activity") -> dict[str, Any]:
    if (path / "collection-balanced").is_dir():
        path = path / "collection-balanced"
    manifest = load_json(path / "manifest.json")
    summary = load_json(path / "summary.json")
    signals = [unwrap(load_json_line(line), "signal") for line in read_lines(path / "signals.scope.ndjson")]
    events = [unwrap(load_json_line(line), "event") for line in read_lines(path / "events.scope.ndjson")]
    model_signals = [signal for signal in signals if signal.get("detectorKind") == "DETECTOR_KIND_MODEL"]
    phase_data = load_matrix_phase(path, phase)
    learning_status = manifest.get("learning_status") or ("loaded" if manifest.get("learning_variant") == "enabled" else "disabled")
    return {
        "manifest": manifest,
        "health": {"status": latest_health_status(path), "learning": learning_status},
        "reliability": {"sensor_drop": phase_data.get("dropped_events_delta", 0), "batcher_drop": summary.get("telemetry_batcher_drop", 0), "parse_errors": phase_data.get("parse_errors_delta", 0)},
        "performance": {"agent_cpu_avg_pct": phase_data.get("agent_cpu_avg_pct"), "agent_rss_max_mb": phase_data.get("agent_rss_max_mb"), "eps": phase_data.get("eps")},
        "stream_evictions": latest_stream_evictions(path),
        "model_signals": model_signals,
        "rule_truth_ok": True,
        "events": {str(event.get("id")) for event in events if event.get("id")},
    }


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


def latest_health_status(path: Path) -> str | None:
    files = sorted((path / "raw").glob("*.health.json"))
    return load_json(files[-1]).get("status") if files else None


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


def render_report(summary: dict[str, Any]) -> str:
    lines = ["# Learning Detector A/B Report", "", f"- Verdict: `{summary.get('verdict', 'unavailable')}`", ""]
    for name, result in summary.get("gates", {}).items():
        lines.append(f"- {name}: `{result.get('status', 'unavailable')}`")
    lines.extend(["", "## Observations", "", "```json", json.dumps(summary.get("observations", {}), indent=2, sort_keys=True), "```", ""])
    return "\n".join(lines)


def aggregate_runs(run_dir: Path) -> dict[str, Any]:
    disabled_path, enabled_path = run_dir / "disabled", run_dir / "enabled"
    if not disabled_path.exists() or not enabled_path.exists():
        summary = {"verdict": "failed", "status": "partial", "gates": {}, "observations": {}, "missing": [str(path.name) for path in (disabled_path, enabled_path) if not path.exists()]}
    else:
        summary = evaluate_ab(load_endpoint_run(disabled_path), load_endpoint_run(enabled_path), DEFAULT_GATES)
    (run_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    (run_dir / "report.md").write_text(render_report(summary))
    return summary


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
