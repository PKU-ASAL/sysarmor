#!/usr/bin/env python3
import argparse
import csv
import fnmatch
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("need pyyaml: pip install pyyaml")


def load_json(path):
    p = Path(path)
    if not p.exists() or p.stat().st_size == 0:
        return {}
    try:
        return json.loads(p.read_text(errors="replace"))
    except json.JSONDecodeError:
        return {}


def load_yaml(path):
    p = Path(path)
    if not p.exists() or p.stat().st_size == 0:
        return {}
    return yaml.safe_load(p.read_text()) or {}


def load_ndjson(path):
    p = Path(path)
    if not p.exists():
        return []
    rows = []
    for line in p.read_text(errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            rows.append({"_raw": line})
    return rows


def number(value, default=0.0):
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def parse_time(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return None


def frame_time(row):
    if not isinstance(row, dict):
        return None
    ts = parse_time(row.get("observedAt") or row.get("observed_at") or row.get("@timestamp"))
    if ts:
        return ts
    body = row.get("event") or row.get("signal") or {}
    if isinstance(body, dict):
        return parse_time(body.get("observedAt") or body.get("observed_at"))
    return None


def marker_time(markers, phase):
    for marker in markers or []:
        if marker.get("phase") == phase:
            ts = parse_time(marker.get("ts"))
            if ts:
                return ts
    return None


def detection_window(bench_summary):
    markers = (bench_summary or {}).get("markers") or []
    start = marker_time(markers, "workload_start")
    end = marker_time(markers, "workload_done") or marker_time(markers, "recorder_stop")
    if start and end and end > start:
        return start, end, "workload"
    return None, None, "all"


def filter_frames_by_window(frames, start, end):
    if not start or not end:
        return frames
    out = []
    for frame in frames:
        ts = frame_time(frame)
        if ts and start <= ts < end:
            out.append(frame)
    return out


def unwrap_event(row):
    if not isinstance(row, dict):
        return {}
    body = row.get("event")
    return body if isinstance(body, dict) else row


def unwrap_signal(row):
    if not isinstance(row, dict):
        return {}
    body = row.get("signal")
    return body if isinstance(body, dict) else row


def basename(value):
    value = str(value or "")
    return os.path.basename(value.rstrip("/")) if value else ""


def lower(value):
    return str(value or "").strip().lower()


def proc_ref(event):
    return event.get("subjectProc") or event.get("subject_proc") or event.get("process") or {}


def obj_ref(event):
    return event.get("object") or {}


def event_id(event):
    return str(event.get("id") or event.get("eventId") or event.get("event_id") or "")


def event_behavior(event):
    return lower(event.get("behavior") or event.get("kind"))


def event_binary(event):
    proc = proc_ref(event)
    return str(proc.get("binary") or "")


def event_argv(event):
    proc = proc_ref(event)
    argv = proc.get("argv") or proc.get("arguments") or []
    if isinstance(argv, list):
        return " ".join(str(x) for x in argv)
    return str(argv)


def event_path(event):
    obj = obj_ref(event)
    for key in ("filePath", "file_path", "path", "key"):
        if obj.get(key):
            return str(obj.get(key))
    return ""


def event_socket(event):
    obj = obj_ref(event)
    for key in ("socketAddr", "socket_addr", "dst", "addr"):
        if obj.get(key):
            return str(obj.get(key))
    return ""


def canonical_event(row):
    event = unwrap_event(row)
    binary = event_binary(event)
    path = event_path(event)
    socket = event_socket(event)
    entities = set()
    if binary:
        entities.add(f"process:{binary}")
        entities.add(f"process:{basename(binary)}")
    if path:
        entities.add(f"file:{path}")
    if socket:
        entities.add(f"socket:{socket}")
    return {
        "id": event_id(event),
        "behavior": event_behavior(event),
        "binary": binary,
        "binary_base": basename(binary),
        "argv": event_argv(event),
        "path": path,
        "socket": socket,
        "entities": entities,
        "raw": event,
    }


def signal_id(signal):
    return str(signal.get("id") or signal.get("signalId") or signal.get("signal_id") or "")


def signal_name(signal):
    return str(signal.get("name") or signal.get("ruleId") or signal.get("rule_id") or "")


def signal_stage(signal):
    value = str(signal.get("stage") or "").upper()
    return value.removeprefix("SIGNAL_STAGE_").lower()


def signal_where(signal):
    return str(signal.get("where") or "").upper()


def signal_event_refs(signal):
    refs = signal.get("eventRefs") or signal.get("event_refs") or []
    if isinstance(refs, list):
        return [str(x) for x in refs]
    return []


def signal_entities(signal):
    entities = set()
    for ent in signal.get("entities") or []:
        if not isinstance(ent, dict):
            continue
        kind = str(ent.get("kind") or "").strip()
        key = str(ent.get("key") or "").strip()
        if kind and key:
            entities.add(f"{kind}:{key}")
        if key:
            entities.add(key)
    return entities


def canonical_signal(row):
    signal = unwrap_signal(row)
    return {
        "id": signal_id(signal),
        "name": signal_name(signal),
        "stage": signal_stage(signal),
        "where": signal_where(signal),
        "entities": signal_entities(signal),
        "event_refs": signal_event_refs(signal),
        "raw": signal,
    }


def referenced_event_ids(signals):
    refs = set()
    for signal in signals:
        refs.update(canonical_signal(signal)["event_refs"])
    refs.discard("")
    return refs


def supplemental_referenced_events(events, auxiliary_events, signals):
    refs = referenced_event_ids(signals)
    if not refs:
        return []
    seen = {canonical_event(row)["id"] for row in events}
    seen.discard("")
    supplemental = []
    for row in auxiliary_events:
        eid = canonical_event(row)["id"]
        if eid and eid in refs and eid not in seen:
            supplemental.append(row)
            seen.add(eid)
    return supplemental


def inferred_missing_event_refs(event_labels, signal_labels, observed_signals, observed_event_ids):
    event_label_ids = {str(label.get("id") or "") for label in event_labels}
    event_label_ids.discard("")
    missing_by_label = {}
    for label in signal_labels:
        link_ids = [str(x) for x in label.get("link_events") or [] if str(x) in event_label_ids]
        if not link_ids:
            continue
        hits = [sig for sig in observed_signals if signal_label_matches(label, sig)]
        missing_refs = {
            ref
            for sig in hits
            for ref in sig["event_refs"]
            if ref and ref not in observed_event_ids
        }
        if not missing_refs:
            continue
        for link_id in link_ids:
            missing_by_label.setdefault(link_id, set()).update(missing_refs)
    return missing_by_label


def matches_pattern(value, pattern):
    if pattern in ("", None):
        return True
    value = str(value or "")
    pattern = str(pattern)
    return fnmatch.fnmatch(value, pattern) or fnmatch.fnmatch(basename(value), pattern) or pattern in value


def event_label_matches(label, event):
    behavior = lower(label.get("behavior"))
    if behavior and event["behavior"] != behavior:
        return False
    match = label.get("match") or {}
    if not isinstance(match, dict):
        return False
    if "path" in match and not matches_pattern(event["path"], match.get("path")):
        return False
    if "socket" in match and str(match.get("socket")) != event["socket"]:
        return False
    if "dst" in match and str(match.get("dst")) != event["socket"]:
        return False
    if "dst_ip" in match:
        host = event["socket"].split(":", 1)[0]
        if str(match.get("dst_ip")) != host:
            return False
    if "dst_port" in match:
        port = event["socket"].rsplit(":", 1)[-1] if ":" in event["socket"] else ""
        if str(match.get("dst_port")) != port:
            return False
    if "process" in match and not (
        matches_pattern(event["binary"], match.get("process"))
        or matches_pattern(event["binary_base"], match.get("process"))
        or matches_pattern(event["argv"], match.get("process"))
    ):
        return False
    if "entity" in match and str(match.get("entity")) not in event["entities"]:
        return False
    return True


def signal_label_matches(label, signal):
    name = str(label.get("name") or "")
    if name and signal["name"] != name:
        return False
    if "stage" in label and str(label.get("stage") or "").lower() != signal["stage"]:
        return False
    where = str(label.get("where") or "").upper()
    if where and where not in signal["where"]:
        return False
    for entity in label.get("entities") or []:
        if str(entity) not in signal["entities"]:
            return False
    return True


def ratio(hit, total):
    return round(hit / total, 4) if total else ""


def f1_score(precision, recall):
    if precision == "" or recall == "":
        return ""
    precision = number(precision)
    recall = number(recall)
    if precision + recall == 0:
        return 0.0
    return round((2 * precision * recall) / (precision + recall), 4)


def score_or_default(value, default=1.0):
    return default if value == "" else number(value)


def label_file(root, kind, topology, name):
    data_root = root / "data"
    if data_root.exists():
        root = data_root
    if kind == "workload":
        return root / "workloads" / topology / name / "labels.yaml"
    return root / "scenarios" / topology / name / "labels.yaml"


def case_kind(workload, scenario):
    if workload and scenario:
        return "cross"
    if workload:
        return "workload"
    return "scenario"


def case_paths(results, bench_case_dir=None, scope="local"):
    if not bench_case_dir:
        return None, None, None, None
    if scope in ("manager", "full", "control"):
        manager_events = bench_case_dir / "manager.events.ndjson"
        manager_signals = bench_case_dir / "manager.signals.ndjson"
        manager_incidents = bench_case_dir / "manager.incidents.ndjson"
        return (
            manager_events if manager_events.exists() else None,
            manager_events if manager_events.exists() else None,
            manager_signals if manager_signals.exists() else None,
            manager_incidents if manager_incidents.exists() else None,
        )
    events_scope_path = bench_case_dir / "events.scope.ndjson"
    events_path = events_scope_path if events_scope_path.exists() else bench_case_dir / "events.ndjson"
    raw_events_path = bench_case_dir / "events.ndjson"
    legacy_events_all_path = bench_case_dir / "events-all.ndjson"
    events_all_path = raw_events_path if events_scope_path.exists() and raw_events_path.exists() else legacy_events_all_path
    signals_scope_path = bench_case_dir / "signals.scope.ndjson"
    signals_path = signals_scope_path if signals_scope_path.exists() else bench_case_dir / "signals.ndjson"
    incidents_path = next(iter(sorted(bench_case_dir.glob("*incident*.json"))), None)
    return (
        events_path if events_path.exists() else None,
        events_all_path if events_all_path.exists() else None,
        signals_path if signals_path.exists() else None,
        incidents_path if incidents_path and incidents_path.exists() else None,
    )


def objective_ids(labels_doc, name, label_type):
    objective = (labels_doc.get("objectives") or {}).get(name) or {}
    key = "required_events" if label_type == "event" else "required_signals"
    return {str(x) for x in objective.get(key) or [] if str(x)}


def objective_metrics(name, event_rows, signal_rows, conclusion_signal_ids, signal_precision):
    event_ids = {row["label_id"] for row in event_rows if name in row["objectives"]}
    signal_ids = {row["label_id"] for row in signal_rows if name in row["objectives"]}
    conclusion_ids = {label_id for label_id in signal_ids if label_id in conclusion_signal_ids}
    event_hit = sum(1 for row in event_rows if name in row["objectives"] and row["matched"])
    signal_hit = sum(1 for row in signal_rows if name in row["objectives"] and row["matched"])
    conclusion_hit = sum(1 for row in signal_rows if name in row["objectives"] and row["matched"] and row["label_id"] in conclusion_signal_ids)
    event_recall = ratio(event_hit, len(event_ids))
    signal_recall = ratio(signal_hit, len(signal_ids))
    conclusion_recall = ratio(conclusion_hit, len(conclusion_ids))
    if not event_ids and not signal_ids:
        score = ""
    else:
        score = round(
            0.45 * score_or_default(event_recall, 1.0)
            + 0.45 * score_or_default(signal_recall, 1.0)
            + 0.05 * score_or_default(conclusion_recall, 1.0)
            + 0.05 * score_or_default(signal_precision, 1.0),
            4,
        )
    return {
        f"{name}_score": score,
        f"{name}_event_recall": event_recall,
        f"{name}_signal_recall": signal_recall,
        f"{name}_conclusion_recall": conclusion_recall,
        f"{name}_matched_event_labels": event_hit,
        f"{name}_required_event_labels": len(event_ids),
        f"{name}_matched_signal_labels": signal_hit,
        f"{name}_required_signal_labels": len(signal_ids),
    }


def evaluate_case(labels_doc, events, signals, bench_summary, auxiliary_events=None):
    event_labels = labels_doc.get("labels", {}).get("events") or []
    signal_labels = labels_doc.get("labels", {}).get("signals") or []
    objectives = labels_doc.get("objectives") or {}
    if "alert" not in objectives or "evidence" not in objectives:
        raise ValueError(f"labels {labels_doc.get('name') or '<unknown>'} must define objectives.alert and objectives.evidence")
    alert_event_ids = objective_ids(labels_doc, "alert", "event")
    alert_signal_ids = objective_ids(labels_doc, "alert", "signal")
    evidence_event_ids = objective_ids(labels_doc, "evidence", "event")
    evidence_signal_ids = objective_ids(labels_doc, "evidence", "signal")
    policy = labels_doc.get("policy") or {}
    kind = labels_doc.get("kind") or "unknown"
    supplemental_events = supplemental_referenced_events(events, auxiliary_events or [], signals)
    observed_events = [canonical_event(row) for row in (events + supplemental_events)]
    observed_signals = [canonical_signal(row) for row in signals]
    observed_event_ids = {ev["id"] for ev in observed_events if ev["id"]}
    missing_event_refs = inferred_missing_event_refs(event_labels, signal_labels, observed_signals, observed_event_ids)
    forbidden_signal_names = set(labels_doc.get("policy", {}).get("forbidden_signal_names") or [
        "download_by_lolbin",
        "payload_dropped",
        "payload_lifecycle",
        "suspicious_exec_connect",
        "reverse_shell_pattern",
        "sensitive_cred_read",
        "web_runtime_spawns_shell",
    ])

    event_matches = {}
    event_label_rows = []
    matched_event_ids = set()
    for label in event_labels:
        hits = [ev for ev in observed_events if event_label_matches(label, ev)]
        label_id = str(label.get("id") or "")
        row_objectives = []
        if label_id in alert_event_ids:
            row_objectives.append("alert")
        if label_id in evidence_event_ids:
            row_objectives.append("evidence")
        missing_refs = sorted(missing_event_refs.get(label_id) or [])
        event_matches[label_id] = hits
        for ev in hits:
            if ev["id"]:
                matched_event_ids.add(ev["id"])
        event_label_rows.append({
            "label_type": "event",
            "label_id": label_id,
            "objectives": " ".join(row_objectives),
            "required": bool(row_objectives),
            "matched": bool(hits or missing_refs),
            "matched_count": len(hits) + len(missing_refs),
            "matched_ids": " ".join([*(ev["id"] for ev in hits if ev["id"]), *(f"missing:{ref}" for ref in missing_refs)]),
            "match_quality": "event_missing_from_recorder" if missing_refs and not hits else ("partial_event_missing_from_recorder" if missing_refs else ""),
        })

    signal_label_rows = []
    matched_signal_ids = set()
    linked_signal_count = 0
    conclusion_signal_ids = {
        str(label.get("id") or "")
        for label in signal_labels
        if str(label.get("stage") or "").lower() == "conclusion"
    }
    for label in signal_labels:
        hits = [sig for sig in observed_signals if signal_label_matches(label, sig)]
        label_id = str(label.get("id") or "")
        row_objectives = []
        if label_id in alert_signal_ids:
            row_objectives.append("alert")
        if label_id in evidence_signal_ids:
            row_objectives.append("evidence")
        link_ids = [str(x) for x in label.get("link_events") or []]
        link_total = len(link_ids)
        link_hit = 0
        for link_id in link_ids:
            expected_event_ids = {ev["id"] for ev in event_matches.get(link_id, []) if ev["id"]}
            missing_expected_event_ids = set(missing_event_refs.get(link_id) or [])
            if (expected_event_ids or missing_expected_event_ids) and any(
                (expected_event_ids | missing_expected_event_ids).intersection(set(sig["event_refs"])) for sig in hits
            ):
                link_hit += 1
        if hits:
            linked_signal_count += 1 if link_total == 0 or link_hit > 0 else 0
        for sig in hits:
            if sig["id"]:
                matched_signal_ids.add(sig["id"])
        quality = ratio(link_hit, link_total) if link_total else ""
        signal_label_rows.append({
            "label_type": "signal",
            "label_id": label_id,
            "objectives": " ".join(row_objectives),
            "required": bool(row_objectives),
            "matched": bool(hits),
            "matched_count": len(hits),
            "matched_ids": " ".join(sig["id"] for sig in hits if sig["id"]),
            "match_quality": quality,
        })

    conclusion_observed = [sig for sig in observed_signals if sig["stage"] == "conclusion"]
    conclusion_allowed = int(policy.get("conclusion_signals_allowed", 999999))
    conclusion_fp = max(0, len(conclusion_observed) - conclusion_allowed)
    if kind == "benign":
        false_positive_signals = len([sig for sig in observed_signals if sig["name"] in forbidden_signal_names or sig["stage"] == "conclusion"])
    else:
        false_positive_signals = len([sig for sig in observed_signals if sig["id"] not in matched_signal_ids])
    event_noise = len([ev for ev in observed_events if ev["id"] not in matched_event_ids])

    signal_precision = ratio(len(observed_signals) - false_positive_signals, len(observed_signals))
    if signal_precision == "" and not observed_signals:
        signal_precision = 1.0
    event_noise_ratio = ratio(event_noise, len(observed_events))
    if not event_labels:
        event_noise_ratio = ""
    signal_event_link_rate = ratio(linked_signal_count, len([row for row in signal_label_rows if row["matched"]]))
    alert = objective_metrics("alert", event_label_rows, signal_label_rows, conclusion_signal_ids, signal_precision)
    evidence = objective_metrics("evidence", event_label_rows, signal_label_rows, conclusion_signal_ids, signal_precision)
    if kind == "benign":
        fp_policy_score = 1.0 if false_positive_signals == 0 else 0.0
        conclusion_policy_score = 1.0 if conclusion_fp == 0 else 0.0
        alert["alert_score"] = round(0.7 * fp_policy_score + 0.3 * conclusion_policy_score, 4)
        evidence["evidence_score"] = alert["alert_score"]

    workload_phase = (bench_summary or {}).get("raw_phases", {}).get("workload", {})
    if not workload_phase:
        workload_phase = (bench_summary or {}).get("phases", {}).get("workload", {})
    drops = int(workload_phase.get("dropped_events_delta") or 0)
    parse_errors = int(workload_phase.get("parse_errors_delta") or 0)
    events_delta = int(workload_phase.get("events_delta") or len(observed_events))
    edr_cpu = ((workload_phase.get("edr_cpu_pct") or {}).get("avg") or 0.0)
    cost_per_1k = round(float(edr_cpu) / events_delta * 1000, 4) if events_delta > 0 else 0.0

    return {
        "metrics": {
            "label_kind": kind,
            **alert,
            **evidence,
            "signal_precision": signal_precision,
            "event_noise_ratio": event_noise_ratio,
            "signal_event_link_rate": signal_event_link_rate,
            "false_positive_signals": false_positive_signals,
            "conclusion_false_positive_signals": conclusion_fp,
            "observed_events": len(observed_events),
            "observed_signals": len(observed_signals),
            "supplemental_referenced_events": len(supplemental_events),
            "drop_rate": round(drops / events_delta, 4) if events_delta > 0 else 0.0,
            "parse_error_rate": round(parse_errors / events_delta, 4) if events_delta > 0 else 0.0,
            "cost_per_1k_events_cpu": cost_per_1k,
        },
        "truth_steps": event_label_rows + signal_label_rows,
    }


def discover_bench_cases(root, results, matrix_dir):
    cases = []
    if not matrix_dir:
        return cases
    matrix_dir = Path(matrix_dir)
    cases_dir = matrix_dir / "cases"
    if cases_dir.exists():
        for case_dir in sorted(p for p in cases_dir.iterdir() if p.is_dir()):
            status = load_json(case_dir / "status.json")
            bench_run_id = status.get("bench_run_id", "")
            bench_root = results / "performance-endpoint" / bench_run_id
            if not bench_root.exists():
                continue
            workload = status.get("workload", "")
            scenario = status.get("scenario", "")
            kind = case_kind(workload, scenario)
            name = scenario or workload
            for policy_dir in sorted(p for p in bench_root.iterdir() if p.is_dir()):
                if not (policy_dir / "summary.json").exists():
                    continue
                cases.append({
                    "kind": kind,
                    "name": name,
                    "workload": workload,
                    "scenario": scenario,
                    "policy": policy_dir.name,
                    "bench_case_dir": policy_dir,
                })
    return cases


def build_rows(args):
    root = Path(args.root)
    results = root / ".results"
    bench_cases = discover_bench_cases(root, results, args.bench_matrix_dir)
    rows = []
    truth_rows = []
    scenario_filter = set(args.scenarios or [])
    workload_filter = set(args.workloads or [])

    for case in bench_cases:
        if case["kind"] in ("scenario", "cross") and scenario_filter and case.get("scenario") not in scenario_filter:
            continue
        if case["kind"] in ("workload", "cross") and workload_filter and case.get("workload") not in workload_filter:
            continue
        label_kind = "scenario" if case.get("scenario") else "workload"
        label_name = case.get("scenario") or case.get("workload") or case["name"]
        labels_path = label_file(root, label_kind, args.topology, label_name)
        if not labels_path.exists():
            continue
        labels_doc = load_yaml(labels_path)
        events_path, events_all_path, signals_path, incidents_path = case_paths(results, case["bench_case_dir"], args.scope)
        all_events = load_ndjson(events_path) if events_path else []
        auxiliary_events = load_ndjson(events_all_path) if events_all_path else []
        all_signals = load_ndjson(signals_path) if signals_path else []
        bench_summary = load_json(case["bench_case_dir"] / "summary.json")
        window_start, window_end, window_name = detection_window(bench_summary)
        events = filter_frames_by_window(all_events, window_start, window_end)
        auxiliary_events = filter_frames_by_window(auxiliary_events, window_start, window_end)
        signals = filter_frames_by_window(all_signals, window_start, window_end)
        if args.scope in ("manager", "full", "control"):
            window_name = "manager_query"
        evaluation = evaluate_case(labels_doc, events, signals, bench_summary, auxiliary_events)
        metrics = evaluation["metrics"]
        base = {
            "kind": case["kind"],
            "name": case["name"],
            "workload": case.get("workload", ""),
            "scenario": case.get("scenario", ""),
            "policy": case["policy"],
            "label_file": str(labels_path),
            "detection_window": window_name,
            "observed_events_total": len(all_events),
            "observed_signals_total": len(all_signals),
            "events_path": str(events_path) if events_path else "",
            "events_all_path": str(events_all_path) if events_all_path else "",
            "signals_path": str(signals_path) if signals_path else "",
            "incidents_path": str(incidents_path) if incidents_path else "",
        }
        row = {**base, **metrics}
        rows.append(row)
        for step in evaluation["truth_steps"]:
            truth_rows.append({
                "kind": case["kind"],
                "name": case["name"],
                "workload": case.get("workload", ""),
                "scenario": case.get("scenario", ""),
                "policy": case["policy"],
                **step,
            })
    return rows, truth_rows


def write_csv(path, rows, fields):
    with path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def remove_deprecated_outputs(out_dir):
    for name in (
        "summary.json",
        "matrix.json",
        "policy_comparison.csv",
        "policy_comparison.json",
        "attack_signal_matrix.csv",
        "attack_signal_matrix.md",
    ):
        path = out_dir / name
        if path.exists():
            path.unlink()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=str(Path(__file__).resolve().parents[2]))
    ap.add_argument("--topology", default="vm")
    ap.add_argument("--scenarios", nargs="*")
    ap.add_argument("--workloads", nargs="*")
    ap.add_argument("--bench-matrix-dir")
    ap.add_argument("--output-dir", required=True)
    ap.add_argument("--scope", choices=("local", "manager", "full", "control"), default="local")
    args = ap.parse_args()

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    remove_deprecated_outputs(out_dir)
    rows, truth_rows = build_rows(args)
    matrix_fields = [
        "kind",
        "label_kind",
        "name",
        "workload",
        "scenario",
        "policy",
        "alert_score",
        "alert_event_recall",
        "alert_signal_recall",
        "alert_conclusion_recall",
        "alert_matched_event_labels",
        "alert_required_event_labels",
        "alert_matched_signal_labels",
        "alert_required_signal_labels",
        "evidence_score",
        "evidence_event_recall",
        "evidence_signal_recall",
        "evidence_conclusion_recall",
        "evidence_matched_event_labels",
        "evidence_required_event_labels",
        "evidence_matched_signal_labels",
        "evidence_required_signal_labels",
        "signal_precision",
        "event_noise_ratio",
        "signal_event_link_rate",
        "false_positive_signals",
        "conclusion_false_positive_signals",
        "observed_events",
        "observed_events_total",
        "supplemental_referenced_events",
        "observed_signals",
        "observed_signals_total",
        "drop_rate",
        "parse_error_rate",
        "cost_per_1k_events_cpu",
        "detection_window",
        "label_file",
        "events_path",
        "events_all_path",
        "signals_path",
    ]
    truth_fields = [
        "kind",
        "workload",
        "scenario",
        "name",
        "policy",
        "label_type",
        "label_id",
        "objectives",
        "required",
        "matched",
        "matched_count",
        "matched_ids",
        "match_quality",
    ]
    write_csv(out_dir / "matrix.csv", rows, matrix_fields)
    write_csv(out_dir / "truth_steps.csv", truth_rows, truth_fields)


if __name__ == "__main__":
    main()
