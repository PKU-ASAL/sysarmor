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
    return json.dumps(document, separators=(",", ":"), sort_keys=True).encode()
