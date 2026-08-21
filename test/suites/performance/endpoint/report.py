#!/usr/bin/env python3
import csv
import json
import sys
from pathlib import Path


def load_json(path):
    p = Path(path)
    if not p.exists() or p.stat().st_size == 0:
        return {}
    try:
        return json.loads(p.read_text(errors="replace"))
    except json.JSONDecodeError:
        return {}


def number(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def metric(phase, name, field):
    value = phase.get(name, {})
    if not isinstance(value, dict):
        value = {}
    return number(value.get(field))


def phase(summary, name):
    phases = summary.get("phases", {})
    value = phases.get(name, {})
    return value if isinstance(value, dict) else {}


def raw_phase(summary, name):
    phases = summary.get("raw_phases", {})
    value = phases.get(name, {})
    return value if isinstance(value, dict) else {}


def marker_detail(summary, marker_name):
    for marker in summary.get("markers", []):
        if marker.get("phase") == marker_name:
            return marker.get("detail", "")
    return ""


def count_diagnostics(summary, key):
    diagnostics = summary.get("diagnostics", {})
    values = diagnostics.get(key, [])
    if isinstance(values, list):
        return len(values)
    return 0


def apply_report(path):
    data = load_json(path)
    policy_id = data.get("policyId") or data.get("policy_id") or ""
    policy_version = data.get("policyVersion") or data.get("policy_version") or ""
    report = data.get("reportJson") or data.get("report_json")
    resolved_refs = 0
    generated_policy_hash = ""
    if isinstance(report, str) and report:
        try:
            report = json.loads(report)
        except json.JSONDecodeError:
            report = {}
    if isinstance(report, dict):
        refs = report.get("resolved_refs") or report.get("resolvedRefs") or []
        if isinstance(refs, list):
            resolved_refs = len(refs)
        generated_policy_hash = report.get("generated_policy_hash") or report.get("generatedPolicyHash") or ""
    return policy_id, policy_version, generated_policy_hash, resolved_refs


def phase_fields(prefix, data):
    return {
        f"{prefix}_duration_s": number(data.get("duration_s")),
        f"{prefix}_samples": int(number(data.get("samples"))),
        f"{prefix}_events_delta": int(number(data.get("events_delta"))),
        f"{prefix}_eps": number(data.get("eps")),
        f"{prefix}_signals_delta": int(number(data.get("signals_delta"))),
        f"{prefix}_dropped_events_delta": int(number(data.get("dropped_events_delta"))),
        f"{prefix}_parse_errors_delta": int(number(data.get("parse_errors_delta"))),
        f"{prefix}_agent_cpu_avg_pct": metric(data, "agent_cpu_pct", "avg"),
        f"{prefix}_agent_cpu_max_pct": metric(data, "agent_cpu_pct", "max"),
        f"{prefix}_agent_rss_avg_mb": metric(data, "agent_rss_mb", "avg"),
        f"{prefix}_agent_rss_max_mb": metric(data, "agent_rss_mb", "max"),
        f"{prefix}_sensor_cpu_avg_pct": metric(data, "sensor_cpu_pct", "avg"),
        f"{prefix}_sensor_cpu_max_pct": metric(data, "sensor_cpu_pct", "max"),
        f"{prefix}_sensor_rss_avg_mb": metric(data, "sensor_rss_mb", "avg"),
        f"{prefix}_sensor_rss_max_mb": metric(data, "sensor_rss_mb", "max"),
        f"{prefix}_edr_cpu_avg_pct": metric(data, "edr_cpu_pct", "avg"),
        f"{prefix}_edr_cpu_max_pct": metric(data, "edr_cpu_pct", "max"),
        f"{prefix}_edr_rss_avg_mb": metric(data, "edr_rss_mb", "avg"),
        f"{prefix}_edr_rss_max_mb": metric(data, "edr_rss_mb", "max"),
    }


def build_row(policy_dir):
    summary = load_json(policy_dir / "summary.json")
    runtime_flags = load_json(policy_dir / "runtime-feature-flags.json")
    policy_id, policy_version, policy_hash, resolved_refs = apply_report(policy_dir / "collection-apply.json")
    row = {
        "policy_dir": policy_dir.name,
        "variant": runtime_flags.get("variant", ""),
        "matcher_strategy": runtime_flags.get("matcher_strategy", ""),
        "policy_id": policy_id,
        "policy_version": policy_version,
        "generated_policy_hash": policy_hash,
        "resolved_refs": resolved_refs,
        "workload": marker_detail(summary, "workload_start"),
        "scenario": marker_detail(summary, "scenario_start"),
        "scoped_events_total": int(number(summary.get("scoped_events_total"))),
        "events_seen_since_cursor_total": int(number(summary.get("events_seen_since_cursor_total"))),
        "scoped_signals_total": int(number(summary.get("scoped_signals_total"))),
        "signals_seen_total": int(number(summary.get("signals_seen_total"))),
        "event_watch_error_lines": count_diagnostics(summary, "event_watch_errors"),
        "signal_watch_error_lines": count_diagnostics(summary, "signal_watch_errors"),
    }
    row.update(phase_fields("normal_activity", raw_phase(summary, "normal_activity")))
    for name in ("startup", "steady", "workload", "activity", "persistence", "overall"):
        row.update(phase_fields(name, phase(summary, name)))
    return row


def policy_directories(out_dir):
    return [child for child in sorted(out_dir.iterdir()) if child.is_dir() and (child / "summary.json").exists()]


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: report.py <performance-endpoint-dir>")
    out_dir = Path(sys.argv[1])
    rows = []
    for child in policy_directories(out_dir):
        rows.append(build_row(child))
    deprecated_matrix_json = out_dir / "matrix.json"
    if deprecated_matrix_json.exists():
        deprecated_matrix_json.unlink()
    matrix_csv = out_dir / "matrix.csv"
    fields = [
        "policy_dir",
        "variant",
        "matcher_strategy",
        "policy_id",
        "policy_version",
        "generated_policy_hash",
        "resolved_refs",
        "workload",
        "scenario",
        "scoped_events_total",
        "events_seen_since_cursor_total",
        "scoped_signals_total",
        "signals_seen_total",
        "event_watch_error_lines",
        "signal_watch_error_lines",
    ]
    for name in ("normal_activity", "startup", "steady", "workload", "activity", "persistence", "overall"):
        fields.extend(phase_fields(name, {}).keys())
    with matrix_csv.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


if __name__ == "__main__":
    main()
