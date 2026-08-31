import json

from google.protobuf.json_format import MessageToDict
from packages.contracts.proto.streaming.v1 import streaming_pb2


def project_artifact(value: bytes) -> bytes:
    artifact = streaming_pb2.AnalysisArtifact.FromString(value)
    payload = artifact.WhichOneof("payload")
    if payload not in {"signal", "incident"}:
        raise ValueError("analysis artifact payload is required")
    document = MessageToDict(
        getattr(artifact, payload),
        preserving_proto_field_name=True,
    )
    document["id"] = document.get("id", "")
    document["tenant_id"] = artifact.tenant_id
    document["analysis_scope_key"] = artifact.analysis_scope_key
    document["observed_at_unix_nano"] = artifact.observed_at_unix_nano
    document["projection_kind"] = payload
    document["agent_id"] = artifact.context.agent_id
    document["batch_id"] = artifact.context.batch_id
    document["event_sequence"] = artifact.context.record_sequence
    if payload == "signal":
        subjects = [
            entity.key for entity in artifact.signal.entities
            if entity.kind == "process" and entity.role == "subject"
        ]
        document["subject_id"] = subjects[0] if len(subjects) == 1 else ""
        document["trigger_event_id"] = artifact.signal.event_refs[-1] if artifact.signal.event_refs else ""
    return json.dumps(document, separators=(",", ":"), sort_keys=True).encode()
