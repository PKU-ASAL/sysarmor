#!/usr/bin/env python3
import argparse
import json
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "apps/streaming/src"))

from google.protobuf.json_format import MessageToDict, ParseDict  # noqa: E402
from packages.contracts.proto.event.v1 import event_pb2  # noqa: E402
from packages.contracts.proto.policy.v1 import policy_pb2  # noqa: E402
from packages.contracts.proto.signal.v1 import signal_pb2  # noqa: E402
from packages.contracts.proto.streaming.v1 import streaming_pb2  # noqa: E402
from streaming.detectors.nodlink.state import NodlinkState  # noqa: E402
from streaming.engine.detection_state import DetectionState  # noqa: E402


def replay_files(events_path, signals_path, output_dir, batch_size=256, allow_cross_lineage=False):
    records = [
        *(_record(item, "event") for item in _read_ndjson(events_path)),
        *(_record(item, "signal") for item in _read_ndjson(signals_path)),
    ]
    records.sort(key=_record_order)
    policies = _policies(records, allow_cross_lineage)
    artifacts, states = _process_by_agent(records, policies, batch_size)
    return _write_outputs(Path(output_dir), records, artifacts, states)


def _record(document, kind):
    payload = document.get(kind)
    if not isinstance(payload, dict):
        raise ValueError(f"missing {kind} payload")
    message = _parse_payload(kind, payload)
    observed_ns = _observed_ns(document, message)
    tenant_id = document.get("tenantId") or getattr(message, "tenant_id", "")
    agent_id = document.get("agentId") or getattr(message, "agent_id", "")
    if not all((tenant_id, agent_id, observed_ns)):
        raise ValueError(f"incomplete replay {kind} identity")
    context = streaming_pb2.RecordContext(
        tenant_id=tenant_id, agent_id=agent_id,
        host_id=getattr(message, "host_id", ""), batch_id=f"replay-{agent_id}",
        policy_id="nodlink-replay", policy_version=1, policy_mode="learning-only",
        observed_at_unix_nano=observed_ns, analysis_scope_key=agent_id,
        record_sequence=int(document.get("sequence") or 0),
        labels=getattr(message, "labels", {}),
    )
    record = streaming_pb2.NormalizedTelemetry(
        schema_version="sysarmor.telemetry.normalized/v1", context=context
    )
    getattr(record, kind).CopyFrom(message)
    return record


def _parse_payload(kind, payload):
    target = event_pb2.CanonicalEvent() if kind == "event" else signal_pb2.Signal()
    return ParseDict(payload, target, ignore_unknown_fields=False)


def _observed_ns(document, message):
    raw = document.get("observedAtUnixNano")
    if raw:
        return int(raw)
    if document.get("observedAt"):
        return _rfc3339_ns(document["observedAt"])
    return int(getattr(message, "occurred_at_ns", 0))


def _rfc3339_ns(value):
    timestamp = value.removesuffix("Z")
    whole, _, fraction = timestamp.partition(".")
    seconds = int(datetime.fromisoformat(whole).replace(tzinfo=timezone.utc).timestamp())
    nanos = int((fraction + "000000000")[:9])
    return seconds * 1_000_000_000 + nanos


def _policies(records, allow_cross_lineage):
    policies = {}
    for record in records:
        context = record.context
        key = context.tenant_id, context.policy_id, context.policy_version
        policies[key] = streaming_pb2.DetectionPolicySnapshot(
            schema_version="sysarmor.detection.policy/v1",
            tenant_id=context.tenant_id, policy_id=context.policy_id,
            policy_version=context.policy_version,
            detection=policy_pb2.DetectionPolicy(
                detectors=["nodlink"],
                converge=policy_pb2.ConvergeParams(cross_lineage=allow_cross_lineage),
            ),
        )
    return policies


def _process_by_agent(records, policies, batch_size):
    grouped = defaultdict(list)
    for record in records:
        grouped[(record.context.tenant_id, record.context.agent_id)].append(record)
    artifacts = []
    states = {}
    for key in sorted(grouped):
        state = DetectionState()
        states[key] = state
        scoped = sorted(grouped[key], key=_record_order)
        for offset in range(0, len(scoped), batch_size):
            results = state.process_batch(scoped[offset:offset + batch_size], 0, policies)
            artifacts.extend(item for result in results for item in result.artifacts)
    return tuple(artifacts), states


def _write_outputs(output, records, artifacts, states):
    output.mkdir(parents=True, exist_ok=True)
    campaigns = _campaign_documents(states)
    campaign_keys = {
        (item["tenant_id"], item["agent_id"], item["id"]) for item in campaigns
    }
    conclusions = _final_conclusions(artifacts, campaign_keys)
    incidents = _final_incidents(artifacts, conclusions)
    evidence = [
        {**_artifact_identity(item), "evidence": MessageToDict(item.incident.evidence)}
        for item in incidents
    ]
    summary = {
        "input_events": sum(item.WhichOneof("payload") == "event" for item in records),
        "input_model_signals": sum(_is_model_signal(item) for item in records),
        "campaigns": len(campaigns), "conclusions": len(conclusions),
        "incidents": len(incidents),
    }
    _write_json(output / "summary.json", summary)
    _write_ndjson(output / "campaigns.ndjson", campaigns)
    _write_ndjson(output / "conclusions.ndjson", map(_signal_document, conclusions))
    _write_ndjson(output / "incidents.ndjson", map(_incident_document, incidents))
    _write_ndjson(output / "evidence.ndjson", evidence)
    return summary


def _campaign_documents(states):
    documents = []
    for (tenant_id, agent_id), state in sorted(states.items()):
        for scope in state.scope_keys():
            raw = _nodlink_state(state, scope)
            for campaign in NodlinkState.decode(raw).campaigns:
                documents.append({
                    "id": campaign.id, "tenant_id": tenant_id,
                    "agent_id": agent_id, "scope": scope,
                    "model_digest": campaign.model_digest,
                    "terminal_ids": [item.signal_id for item in campaign.terminals],
                    "node_ids": list(campaign.node_ids),
                    "edge_ids": list(campaign.edge_ids),
                    "updated_ns": campaign.updated_ns,
                })
    return sorted(documents, key=lambda item: (item["scope"], item["id"]))


def _nodlink_state(state, scope):
    return next(
        (value for key, value in state.detector_states(scope).items() if key.startswith("nodlink@")),
        b"",
    )


def _final_conclusions(artifacts, campaign_keys):
    values = {}
    for artifact in artifacts:
        if artifact.WhichOneof("payload") != "signal" or not _is_cloud_conclusion(artifact.signal):
            continue
        campaign_id = artifact.signal.labels.get("campaign_id", "")
        key = artifact.tenant_id, artifact.context.agent_id, campaign_id
        if key in campaign_keys:
            values[key] = artifact
    return tuple(values[key] for key in sorted(values))


def _final_incidents(artifacts, conclusions):
    conclusion_ids = {item.signal.id for item in conclusions}
    values = {}
    for artifact in artifacts:
        if artifact.WhichOneof("payload") != "incident":
            continue
        referenced = {
            signal.id for signal in artifact.incident.contributing_signals
            if signal.id in conclusion_ids
        }
        for signal_id in referenced:
            key = artifact.tenant_id, artifact.context.agent_id, signal_id
            values[key] = artifact
    return tuple(values[key] for key in sorted(values))


def _artifact_identity(artifact):
    return {
        "tenant_id": artifact.tenant_id,
        "agent_id": artifact.context.agent_id,
        "scope": artifact.analysis_scope_key,
    }


def _signal_document(artifact):
    return {**_artifact_identity(artifact), "signal": MessageToDict(artifact.signal)}


def _incident_document(artifact):
    return {**_artifact_identity(artifact), "incident": MessageToDict(artifact.incident)}


def _is_cloud_conclusion(signal):
    return signal.where == signal_pb2.SIGNAL_WHERE_CLOUD and signal.stage == signal_pb2.SIGNAL_STAGE_CONCLUSION


def _is_model_signal(record):
    return record.WhichOneof("payload") == "signal" and record.signal.detector_kind == signal_pb2.DETECTOR_KIND_MODEL


def _record_order(record):
    return record.context.observed_at_unix_nano, record.context.record_sequence


def _read_ndjson(path):
    with Path(path).open() as source:
        return tuple(json.loads(line) for line in source if line.strip())


def _write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def _write_ndjson(path, values):
    path.write_text("".join(json.dumps(value, sort_keys=True) + "\n" for value in values))


def main():
    parser = argparse.ArgumentParser(description="Replay managed telemetry through Nodlink")
    parser.add_argument("--events", required=True, type=Path)
    parser.add_argument("--signals", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--batch-size", type=int, default=256)
    parser.add_argument("--allow-cross-lineage", action="store_true")
    args = parser.parse_args()
    if args.batch_size <= 0:
        parser.error("--batch-size must be positive")
    summary = replay_files(
        args.events, args.signals, args.output, args.batch_size,
        args.allow_cross_lineage,
    )
    print(json.dumps(summary, sort_keys=True))


if __name__ == "__main__":
    main()
