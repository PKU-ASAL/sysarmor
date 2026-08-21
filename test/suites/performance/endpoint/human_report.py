#!/usr/bin/env python3
"""Render a human-readable report from one endpoint performance run."""
import argparse
import json
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path


class ReportError(RuntimeError):
    """Raised when strict report generation finds invalid input."""


@dataclass
class ReportResult:
    output: Path
    warning_count: int = 0
    warnings: list[str] = field(default_factory=list)


class Loader:
    def __init__(self, strict=False):
        self.strict = strict
        self.warnings = []

    def warn(self, message):
        self.warnings.append(message)

    def json(self, path, required=False):
        if not path.exists():
            if required:
                self.warn(f"missing artifact: {path.name}")
            return {}
        try:
            return json.loads(path.read_text(errors="replace"))
        except (OSError, json.JSONDecodeError):
            self.warn(f"invalid JSON: {path.name}")
            return {}

    def jsonl(self, path, required=False):
        if not path.exists():
            if required:
                self.warn(f"missing artifact: {path.name}")
            return []
        rows = []
        for line_number, line in enumerate(path.read_text(errors="replace").splitlines(), 1):
            if not line.strip():
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                self.warn(f"invalid JSONL: {path.name}:{line_number}")
        return rows


def number(value, default=0.0):
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def integer(value, default=0):
    return int(number(value, default))


def text(value, default="N/A"):
    return str(value) if value not in (None, "") else default


def fmt(value, digits=2):
    if value in (None, "", "N/A"):
        return "N/A"
    return f"{number(value):.{digits}f}"


def clean_cell(value):
    return str(value).replace("|", "\\|").replace("\n", " ")


def metric(phase, name, field):
    value = phase.get(name, {})
    return number(value.get(field)) if isinstance(value, dict) else 0.0


def phase(summary, name):
    value = summary.get("phases", {}).get(name, {})
    return value if isinstance(value, dict) else {}


def load_apply(loader, policy_dir):
    data = loader.json(policy_dir / "collection-apply.json", required=True)
    report = {}
    for section in data.get("sections", []):
        if section.get("name") != "collection":
            continue
        raw = section.get("reportJson") or section.get("report_json")
        if isinstance(raw, dict):
            report = raw
        elif raw:
            try:
                report = json.loads(raw)
            except json.JSONDecodeError:
                loader.warn("invalid collection reportJson")
        break
    return data, report


def load_health(loader, policy_dir):
    snapshots = sorted((policy_dir / "raw").glob("*.health.json"))
    if not snapshots:
        loader.warn("missing artifact: raw/*.health.json")
        return {}
    for path in reversed(snapshots):
        value = loader.json(path)
        if value:
            return value
    return {}


def signal_value(envelope):
    return envelope.get("signal", envelope)


def event_value(envelope):
    return envelope.get("event", envelope)


def event_stats(events):
    behaviors = Counter(text(event_value(row).get("behavior"), "unknown") for row in events)
    return behaviors.most_common(10)


def policy_data(loader, policy_dir):
    manifest = loader.json(policy_dir / "manifest.json", required=True)
    apply, apply_report = load_apply(loader, policy_dir)
    summary = loader.json(policy_dir / "summary.json", required=True)
    events_path = policy_dir / "events.scope.ndjson"
    if not events_path.exists():
        events_path = policy_dir / "events.ndjson"
    signals_path = policy_dir / "signals.ndjson"
    if not signals_path.exists():
        signals_path = policy_dir / "signals.scope.ndjson"
    events = loader.jsonl(events_path, required=True)
    signals = loader.jsonl(signals_path, required=True)
    return {
        "name": policy_dir.name,
        "manifest": manifest,
        "apply": apply,
        "apply_report": apply_report,
        "summary": summary,
        "events": events,
        "signals": signals,
        "health": load_health(loader, policy_dir),
        "artifacts": loader.json(policy_dir / "artifacts.json"),
    }


def markdown_table(headers, rows):
    lines = ["| " + " | ".join(headers) + " |", "| " + " | ".join("---" for _ in headers) + " |"]
    lines.extend("| " + " | ".join(clean_cell(value) for value in row) + " |" for row in rows)
    return "\n".join(lines)


def render_summary(policies):
    rows = []
    for policy in policies:
        summary = policy["summary"].get("overall", {})
        health = policy["health"]
        rows.append([
            policy["name"], text(policy["manifest"].get("workload"), "none"),
            integer(summary.get("events_delta")), integer(summary.get("signals_delta")),
            fmt(summary.get("eps")), fmt(metric(summary, "agent_cpu_pct", "avg")),
            fmt(metric(summary, "agent_rss_mb", "avg")), fmt(metric(summary, "edr_cpu_pct", "avg")),
            fmt(metric(summary, "edr_rss_mb", "avg")), text(health.get("status")),
        ])
    return markdown_table(
        ["Policy", "Workload", "Events", "Signals", "EPS", "Agent CPU avg %", "Agent RSS avg MiB", "EDR CPU avg %", "EDR RSS avg MiB", "Health"],
        rows,
    )


def render_conditions(manifest):
    phase_seconds = manifest.get("phase_seconds", {})
    phases = ", ".join(f"{key}={value}s" for key, value in phase_seconds.items()) or "N/A"
    rows = [
        ["Profile", text(manifest.get("benchmark_profile"))],
        ["VM", text(manifest.get("vm_env"))],
        ["Run ID", text(manifest.get("run_id"))],
        ["Policy file", text(manifest.get("policy_file"))],
        ["Workload", text(manifest.get("workload"), "none")],
        ["Scenario", text(manifest.get("scenario"), "none")],
        ["Agent / Tenant", f"{text(manifest.get('agent_id'))} / {text(manifest.get('tenant_id'))}"],
        ["Variant / Matcher", f"{text(manifest.get('variant'), 'default')} / {text(manifest.get('matcher_strategy'), 'config-default')}"],
        ["Phase durations", phases],
    ]
    return markdown_table(["Condition", "Value"], rows)


def render_apply(policy):
    apply = policy["apply"]
    report = policy["apply_report"]
    coverage = report.get("detection_coverage", {})
    rules = coverage.get("rules", [])
    resolved = report.get("resolved_refs", [])
    pushed = report.get("pushed_down_selectors", [])
    agent_side = report.get("agent_side_selectors", [])
    unsupported = report.get("unsupported_selectors", [])
    lines = [f"- Status: `{text(apply.get('status'))}`", f"- Policy: `{text(apply.get('policyId') or apply.get('policy_id'))}` version `{text(apply.get('policyVersion') or apply.get('policy_version'))}`", f"- Generated policy hash: `{text(report.get('generated_policy_hash'))}`", f"- Detection coverage: `{text(coverage.get('status'))}` ({len([r for r in rules if r.get('status') == 'covered'])}/{len(rules)} rules covered)", f"- Resolved refs: {len(resolved)}; Tetragon selectors: {len(pushed)}; Agent-side selectors: {len(agent_side)}; Unsupported: {len(unsupported)}"]
    if rules:
        lines.append("\n" + markdown_table(["Rule", "Status"], [[r.get("rule_id"), r.get("status")] for r in rules]))
    return "\n".join(lines)


def render_events(policy):
    events = policy["events"]
    lines = [f"- Total samples loaded: {len(events)}", "- Behavior Top 10:"]
    stats = event_stats(events)
    lines.extend(f"  - `{behavior}`: {count}" for behavior, count in stats) if stats else lines.append("  - N/A")
    rows = []
    for row in events[:5]:
        event = event_value(row)
        subject = event.get("subjectProc", {}).get("binary", "") if isinstance(event.get("subjectProc"), dict) else ""
        rows.append([text(event.get("id")), text(event.get("behavior")), text(event.get("occurredAtNs")), text(subject, "N/A")])
    lines.append("\n" + markdown_table(["Event ID", "Behavior", "Occurred", "Subject"], rows or [["N/A"] * 4]))
    return "\n".join(lines)


def render_signals(policy):
    signals = policy["signals"]
    shown = signals[:20]
    lines = [f"- Signals loaded: {len(signals)}; displayed: {len(shown)}" + (" (truncated at 20)" if len(signals) > 20 else "")]
    for envelope in shown:
        signal = signal_value(envelope)
        evidence = signal.get("evidence") or {}
        evidence_text = evidence.get("summary") or evidence.get("id") or (json.dumps(evidence, ensure_ascii=False, sort_keys=True) if evidence else "N/A")
        refs = ", ".join(signal.get("eventRefs", [])) or "N/A"
        lines.extend([
            f"\n#### {text(signal.get('name'))}",
            f"- ID: `{text(signal.get('id'))}`; Stage: `{text(signal.get('stage'))}`; Detector: `{text(signal.get('detectorKind'))}`",
            f"- Severity / confidence: `{text(signal.get('severity'))}` / `{text(signal.get('confidence'))}`",
            f"- Rule: `{text(signal.get('ruleId'), 'N/A')}` version `{text(signal.get('ruleVersion'), 'N/A')}`",
            f"- Event refs: `{refs}`",
            f"- Evidence: {evidence_text}",
        ])
    return "\n".join(lines) if lines else "- N/A"


def render_performance(summary):
    rows = []
    for name in ("startup", "steady", "workload", "overall"):
        value = phase(summary, name)
        if not value:
            continue
        rows.append([
            name, fmt(value.get("duration_s"), 0), integer(value.get("events_delta")), fmt(value.get("eps")), integer(value.get("signals_delta")), integer(value.get("dropped_events_delta")), integer(value.get("parse_errors_delta")), fmt(metric(value, "agent_cpu_pct", "avg")), fmt(metric(value, "agent_rss_mb", "avg")), fmt(metric(value, "edr_cpu_pct", "avg")), fmt(metric(value, "edr_rss_mb", "avg")),
        ])
    return markdown_table(["Phase", "Duration s", "Events", "EPS", "Signals", "Sensor drops", "Parse errors", "Agent CPU %", "Agent RSS MiB", "EDR CPU %", "EDR RSS MiB"], rows or [["N/A"] * 11])


def render_health(health):
    sensor = health.get("sensor", {})
    batcher = health.get("telemetryBatcher", {})
    sender = health.get("telemetrySender", {})
    streams = health.get("streams", {})
    detection = health.get("detection", {})
    rows = [
        ["Status", text(health.get("status"))], ["Sensor", f"running={text(sensor.get('running'))}, policyLoaded={text(sensor.get('policyLoaded'))}, restarts={text(sensor.get('restartCount'))}"],
        ["Sensor drops / parse errors", f"{text(sensor.get('eventsDropped'), '0')} / {text(sensor.get('parseErrors'), '0')}"],
        ["Batcher drops (events / signals)", f"{text(batcher.get('droppedEvents'), '0')} / {text(batcher.get('droppedSignals'), '0')}"],
        ["Stream evictions (events / signals)", f"{text(streams.get('eventEvicted'), '0')} / {text(streams.get('signalEvicted'), '0')}"],
        ["Telemetry sender", f"events={text(sender.get('sentEvents'), '0')}, signals={text(sender.get('sentSignals'), '0')}"], ["Detection", f"policy={text(detection.get('policyId'))}, apply={text(detection.get('lastApplyStatus'))}"],
    ]
    if integer(streams.get("eventEvicted")) > 0 or integer(streams.get("signalEvicted")) > 0:
        rows.append(["Interpretation", "观察窗口已滚动；eviction 不表示 Sensor、Batcher 或 Storage 数据丢失"])
    return markdown_table(["Field", "Value"], rows)


def render_policy(policy):
    return "\n".join([
        f"## {policy['name']}", "", "### Policy and coverage", render_apply(policy), "", "### Events", render_events(policy), "", "### Signals and evidence", render_signals(policy), "", "### Performance", render_performance(policy['summary']), "", "### Final health", render_health(policy['health']), "",
    ])


def generate_report(run_dir, output=None, strict=False):
    run_dir = Path(run_dir)
    if not run_dir.is_dir():
        raise ReportError(f"run directory not found: {run_dir}")
    loader = Loader(strict)
    policy_dirs = sorted(path for path in run_dir.iterdir() if path.is_dir() and (path / "manifest.json").exists())
    if not policy_dirs:
        loader.warn("no policy directories found")
    policies = [policy_data(loader, path) for path in policy_dirs]
    output = Path(output or run_dir / "report.md")
    manifest = policies[0]["manifest"] if policies else {}
    lines = ["# Endpoint Performance Report", "", "## Executive Summary", "", f"- Run ID: `{text(manifest.get('run_id'))}`", f"- Policies: {len(policies)}", f"- Warnings: {len(loader.warnings)}", "", "## Policy Comparison", "", render_summary(policies), "", "## System and Experiment Conditions", "", render_conditions(manifest)]
    for policy in policies:
        lines.extend(["", render_policy(policy)])
    lines.extend(["", "## Warnings", ""])
    lines.extend(f"- {warning}" for warning in loader.warnings) if loader.warnings else lines.append("- None")
    lines.extend(["", "## Artifacts", "", f"- Run directory: `{run_dir}`", "- Raw artifacts remain under each policy directory."])
    output.write_text("\n".join(lines) + "\n")
    if strict and loader.warnings:
        raise ReportError(f"report generated with {len(loader.warnings)} warning(s)")
    return ReportResult(output=output, warning_count=len(loader.warnings), warnings=loader.warnings)


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("run_dir")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--strict", action="store_true")
    args = parser.parse_args(argv)
    try:
        result = generate_report(args.run_dir, args.output, args.strict)
    except ReportError as error:
        print(f"[human-report][ERROR] {error}", file=sys.stderr)
        return 1
    for warning in result.warnings:
        print(f"[human-report][WARN] {warning}", file=sys.stderr)
    print(f"[human-report] report written to {result.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
