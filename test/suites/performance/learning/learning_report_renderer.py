#!/usr/bin/env python3
"""Markdown rendering for a Learning Detector A/B summary."""

from __future__ import annotations

import json
import math
import shlex
from typing import Any


def render_report(summary: dict[str, Any]) -> str:
    lines = ["# Learning Detector A/B 实验报告", "", f"**结论：`{summary.get('verdict', 'unavailable')}`**", ""]
    lines.extend(failure_section(summary))
    lines.extend(gate_section(summary.get("gates", {})))
    lines.extend(experiment_section(summary.get("experiment", {})))
    lines.extend(model_section(summary.get("model", {})))
    lines.extend(performance_section(summary.get("variants", {})))
    lines.extend(reliability_section(summary.get("variants", {}), summary.get("observations", {})))
    lines.extend(profile_lifecycle_section(summary.get("variants", {})))
    lines.extend(candidate_section(summary.get("variants", {})))
    lines.extend(truth_section(summary.get("truth_steps", {}), summary.get("observations", {})))
    lines.extend(sample_section(summary.get("samples", {})))
    lines.extend(reproduction_section(summary.get("experiment", {})))
    return "\n".join(lines)


def failure_section(summary: dict[str, Any]) -> list[str]:
    if not any(summary.get(key) for key in ("status", "error", "missing")):
        return []
    return [
        "## 失败详情", "", f"- Status：`{display(summary.get('status'))}`",
        f"- Error：{display(summary.get('error'))}", f"- Missing：{display(summary.get('missing'))}", "",
    ]


def gate_section(gates: dict[str, Any]) -> list[str]:
    lines = ["## 质量门禁", "", "| 门禁 | 类型 | 状态 | 实测值 | 限制 | 说明 |", "|---|---|---:|---:|---:|---|"]
    for name, result in gates.items():
        lines.append(
            f"| {name} | {'blocking' if result.get('blocking', True) else 'observation'} | `{result.get('status', 'unavailable')}` | {display(result.get('value'))} | "
            f"{display(result.get('limit'))} | {result.get('detail', '')} |"
        )
    return lines + [""]


def experiment_section(experiment: dict[str, Any]) -> list[str]:
    fields = (
        ("Run ID", "run_id"), ("Profile", "benchmark_profile"), ("VM", "vm_env"),
        ("Policy", "policy"), ("Activity", "activity_mode"), ("Scenario", "scenario"),
        ("Git commit", "git_commit"), ("Git dirty", "git_dirty"),
        ("Git provenance", "git_provenance_source"),
        ("Training data", "training_data"), ("Training digest", "training_digest"),
        ("Calibration data", "calibration_data"), ("Calibration digest", "calibration_digest"),
    )
    lines = ["## 实验条件", "", "| 条件 | 值 |", "|---|---|"]
    lines.extend(f"| {label} | {display(experiment.get(key))} |" for label, key in fields)
    return lines + [""]


def model_section(model: dict[str, Any]) -> list[str]:
    dataset = model.get("datasets", {})
    fields = (
        ("Model", model.get("model_ref")), ("Version", model.get("model_version")),
        ("Digest", model.get("model_digest")), ("Feature schema", model.get("feature_schema")),
        ("Threshold", model.get("threshold")), ("Training events", dataset.get("training", {}).get("events")),
        ("Calibration events", dataset.get("calibration", {}).get("events")),
        ("Calibration candidates", model.get("calibration_candidates")),
        ("Calibration Candidate rate", percent(model.get("calibration_candidate_rate"))),
    )
    lines = ["## 模型与校准", "", "| 项目 | 值 |", "|---|---:|"]
    lines.extend(f"| {label} | {display(value)} |" for label, value in fields)
    return lines + [""]


def performance_section(variants: dict[str, Any]) -> list[str]:
    disabled = variants.get("disabled", {}).get("performance", {})
    enabled = variants.get("enabled", {}).get("performance", {})
    rows = (
        ("Agent CPU avg (normal activity)", "agent_cpu_avg_pct", "%"),
        ("Agent RSS avg (steady)", "agent_rss_steady_avg_mb", "MiB"),
        ("Agent RSS max (steady, observation)", "agent_rss_steady_max_mb", "MiB"),
        ("EPS (normal activity)", "eps", "events/s"),
    )
    lines = ["## A/B 性能", "", "| 指标 | Disabled | Enabled | Delta | 单位 |", "|---|---:|---:|---:|---|"]
    for label, key, unit in rows:
        first, second = numeric(disabled.get(key)), numeric(enabled.get(key))
        delta = second - first if first is not None and second is not None else None
        lines.append(f"| {label} | {display(first)} | {display(second)} | {display(delta)} | {unit} |")
    return lines + [""]


def reliability_section(variants: dict[str, Any], observations: dict[str, Any]) -> list[str]:
    lines = ["## 可靠性", "", "| Variant | Health | Learning | Sensor drop | Batcher drop | Parse error | Stream eviction |", "|---|---|---|---:|---:|---:|---:|"]
    for name in ("disabled", "enabled"):
        item = variants.get(name, {})
        health, reliability = item.get("health", {}), item.get("reliability", {})
        lines.append(f"| {name} | {display(health.get('status'))} | {display(health.get('learning'))} | {display(reliability.get('sensor_drop'))} | {display(reliability.get('batcher_drop'))} | {display(reliability.get('parse_errors'))} | {display(item.get('stream_evictions'))} |")
    lines.extend(["", f"> Stream eviction 合计 {display(observations.get('stream_evictions'))}，仅表示观察缓冲区覆盖，不计为主链路丢数。", ""])
    return lines


def profile_lifecycle_section(variants: dict[str, Any]) -> list[str]:
    fields = (
        ("Active", "active"), ("Exited", "exited"), ("Retained", "retained"),
        ("Compactions", "compactions"), ("Expired", "expired"),
        ("Capacity evictions", "capacity_evictions"), ("File evictions", "file_evictions"),
        ("Network evictions", "network_evictions"), ("EventRef evictions", "event_ref_evictions"),
        ("Identity retained", "identity_retained"), ("Identity evictions", "identity_evictions"),
        ("Active evictions", "active_evictions"), ("Identity gaps", "identity_gaps"),
    )
    lines = ["## ProcessProfile 生命周期", "", "| 指标 | Disabled | Enabled |", "|---|---:|---:|"]
    for label, key in fields:
        lines.append(
            f"| {label} | {display(variants.get('disabled', {}).get('profile_health', {}).get(key))} | "
            f"{display(variants.get('enabled', {}).get('profile_health', {}).get(key))} |"
        )
    return lines + [""]


def candidate_section(variants: dict[str, Any]) -> list[str]:
    lines = [
        "## Profile 检测效果", "",
        "| Variant | Events | Profiles | Model Candidates | Candidate profiles | Score min / p50 / max |",
        "|---|---:|---:|---:|---:|---|",
    ]
    for name in ("disabled", "enabled"):
        item, scores = variants.get(name, {}), variants.get(name, {}).get("candidate_scores", {})
        score_text = " / ".join(display(scores.get(key)) for key in ("min", "p50", "max"))
        lines.append(
            f"| {name} | {display(item.get('event_count'))} | {display(item.get('profile_count'))} | "
            f"{display(item.get('model_candidate_count'))} | {display(item.get('candidate_profile_count'))} | {score_text} |"
        )
    enabled = variants.get("enabled", {})
    lines.extend([
        "", "| 效果指标 | 总数 | 命中 | 比率 |", "|---|---:|---:|---:|",
        f"| Normal profiles | {display(enabled.get('normal_profile_count'))} | {display(enabled.get('normal_candidate_count'))} | {percent(enabled.get('normal_candidate_rate'))} |",
        f"| Attack campaigns seeded by Agent | {display(enabled.get('truth_campaign_count'))} | {display(enabled.get('seeded_campaign_count'))} | {percent(enabled.get('attack_campaign_seed_recall'))} |",
        "",
    ])
    return lines


def truth_section(truth: dict[str, Any], observations: dict[str, Any]) -> list[str]:
    indexed = {name: {(s.get("label_type"), s.get("label_id")): s for s in truth.get(name, [])} for name in ("disabled", "enabled")}
    keys = sorted(set(indexed["disabled"]) | set(indexed["enabled"]))
    lines = ["## Attack Truth 与 Rule 回归", "", "| Truth step | Disabled | Enabled | Quality A / B |", "|---|---|---|---|"]
    for kind, label_id in keys:
        first, second = indexed["disabled"].get((kind, label_id), {}), indexed["enabled"].get((kind, label_id), {})
        lines.append(f"| {kind}:{label_id} | {matched(first)} | {matched(second)} | {display(first.get('match_quality'))} / {display(second.get('match_quality'))} |")
    baseline = observations.get("rule_truth_baseline_status", {})
    lines.extend(["", f"> Rule baseline：disabled=`{baseline.get('disabled', 'unavailable')}`，enabled=`{baseline.get('enabled', 'unavailable')}`。硬门禁判断 A/B 是否发生回归，不掩盖既有 baseline 缺口。", ""])
    return lines


def sample_section(samples: dict[str, Any]) -> list[str]:
    lines = ["## 有界样本", ""]
    for variant in ("disabled", "enabled"):
        lines.extend([f"### {variant}", "", "```json", json.dumps(samples.get(variant, {}), indent=2, sort_keys=True), "```", ""])
    return lines


def reproduction_section(experiment: dict[str, Any]) -> list[str]:
    training = shlex.quote(str(experiment.get("training_data") or "unavailable"))
    calibration = shlex.quote(str(experiment.get("calibration_data") or "unavailable"))
    profile = shlex.quote(str(experiment.get("benchmark_profile") or "unavailable"))
    command = f"make -C test performance-learning TRAINING_DATA={training} CALIBRATION_DATA={calibration} PROFILE={profile}"
    git_commit = experiment.get("git_commit") or "unavailable"
    git_dirty = experiment.get("git_dirty") if experiment.get("git_dirty") is not None else "unavailable"
    provenance = experiment.get("git_provenance_source") or "unavailable"
    return ["## 复现信息", "", f"- Git commit：`{git_commit}`", f"- Git dirty：`{git_dirty}`", f"- Git provenance：`{provenance}`", "", "```bash", command, "```", ""]


def numeric(value: Any) -> float | None:
    try:
        result = float(value)
    except (TypeError, ValueError):
        return None
    return result if math.isfinite(result) else None


def display(value: Any) -> str:
    if value is None or value == "":
        return "unavailable"
    if isinstance(value, float):
        return f"{value:.4f}"
    return str(value).replace("|", "\\|").replace("\n", "<br>").replace("`", "\\`")


def percent(value: Any) -> str:
    number = numeric(value)
    return "unavailable" if number is None else f"{number * 100:.2f}%"


def matched(step: dict[str, Any]) -> str:
    return "matched" if step.get("matched") else "missing"
