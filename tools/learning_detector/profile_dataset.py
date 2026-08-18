"""Reconstruct bounded ProcessProfile snapshots from canonical Event NDJSON."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

MAX_FILES = 32
MAX_NETWORKS = 16
MAX_EVENT_REFS = 16


def read_events(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for line_number, line in enumerate(path.read_text().splitlines(), 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid event JSON at line {line_number}") from exc
        event = value.get("event") if isinstance(value.get("event"), dict) else value
        if not isinstance(event, dict):
            raise ValueError(f"event at line {line_number} is not an object")
        events.append(event)
    if not events:
        raise ValueError(f"no events in {path}")
    return events


def read_profiles(path: Path) -> list[dict[str, Any]]:
    profiles: dict[tuple[str, str], dict[str, Any]] = {}
    for event in read_events(path):
        subject = field(event, "subjectProc", "subject_proc") or {}
        stable_id = str(field(subject, "stableId", "stable_id") or "").strip()
        if not stable_id:
            raise ValueError("event subject process stable ID is required")
        agent_id = str(field(event, "agentId", "agent_id") or "").strip()
        profile_key = (agent_id, stable_id)
        profile = profiles.setdefault(profile_key, new_profile(stable_id, agent_id))
        update_identity(profile, subject, event)
        update_behavior(profile, event)
    return list(profiles.values())


def new_profile(stable_id: str, agent_id: str = "") -> dict[str, Any]:
    return {
        "agent_id": agent_id, "stable_id": stable_id, "parent_stable_id": "", "lineage_id": stable_id,
        "binary": "", "argv": [], "revision": 0, "state": "active",
        "behavior_counts": {}, "files": [], "networks": [], "event_refs": [], "labels": {},
    }


def update_identity(profile: dict[str, Any], subject: dict[str, Any], event: dict[str, Any]) -> None:
    binary = str(subject.get("binary") or "")
    argv = subject.get("argv") or []
    if binary:
        profile["binary"] = binary
    if argv:
        profile["argv"] = [str(value) for value in argv]
    profile["parent_stable_id"] = str(field(event, "parentStableId", "parent_stable_id") or profile["parent_stable_id"])
    profile["lineage_id"] = str(field(event, "lineageId", "lineage_id") or profile["lineage_id"])
    labels = event.get("labels") or {}
    if isinstance(labels, dict):
        profile["labels"] = {str(key): str(value) for key, value in labels.items()}


def update_behavior(profile: dict[str, Any], event: dict[str, Any]) -> None:
    behavior = str(event.get("behavior") or "").strip()
    event_id = str(event.get("id") or "").strip()
    if not event_id:
        raise ValueError("event ID is required")
    profile["revision"] += 1
    profile["behavior_counts"][behavior] = profile["behavior_counts"].get(behavior, 0) + 1
    object_ref = event.get("object") or {}
    append_bounded_unique(profile["files"], str(field(object_ref, "filePath", "file_path") or ""), MAX_FILES)
    append_bounded_unique(profile["networks"], str(field(object_ref, "socketAddr", "socket_addr") or ""), MAX_NETWORKS)
    append_bounded(profile["event_refs"], event_id, MAX_EVENT_REFS)
    if behavior == "process.exit":
        profile["state"] = "exited"


def append_bounded_unique(values: list[str], value: str, limit: int) -> None:
    if not value:
        return
    if value in values:
        values.remove(value)
    append_bounded(values, value, limit)


def append_bounded(values: list[str], value: str, limit: int) -> None:
    values.append(value)
    if len(values) > limit:
        del values[0]


def field(value: dict[str, Any], *names: str) -> Any:
    for name in names:
        if name in value:
            return value[name]
    return None
