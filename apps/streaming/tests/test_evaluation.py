import pytest

from streaming.evaluation import replay
from tests.test_detection_state import detection_policy, policy_key, signal_record
from packages.contracts.proto.signal.v1 import signal_pb2
from packages.contracts.proto.streaming.v1 import streaming_pb2


def test_replay_selects_detectors_and_keeps_inputs_immutable():
    policy = detection_policy("tenant-a", "policy-a", 7)
    record = signal_record("scope-a", "policy-a", 7, 100, "first",
                           signal_pb2.SIGNAL_STAGE_CANDIDATE)
    before = policy.SerializeToString()
    result = replay([record], {policy_key(policy): policy}, ["rule-correlation-v1"])
    assert result.input_records == 1
    assert result.batches[0]["detectors"][0]["detector"] == "rule-correlation-v1"
    assert policy.SerializeToString() == before
    repeated = replay([record], {policy_key(policy): policy}, ["rule-correlation-v1"])
    assert result.artifacts == repeated.artifacts


def test_replay_refuses_missing_policy_and_unknown_detector():
    record = signal_record("scope-a", "policy-a", 7, 100, "first",
                           signal_pb2.SIGNAL_STAGE_CANDIDATE)
    with pytest.raises(ValueError, match="policy"):
        replay([record], {}, ["nodlink"])
    with pytest.raises(ValueError, match="unknown detector"):
        replay([], {}, ["unknown"])
    with pytest.raises(ValueError, match="positive"):
        replay([], {}, ["nodlink"], batch_size=0)


def test_replay_refuses_mismatched_policy_identity():
    policy = detection_policy("tenant-a", "policy-a", 7)
    key = policy_key(policy)
    policy.policy_version = 8
    with pytest.raises(ValueError, match="policy"):
        replay([], {key: policy}, ["nodlink"])
    policy.policy_version = 7
    policy.schema_version = "invalid"
    with pytest.raises(ValueError, match="policy"):
        replay([], {key: policy}, ["nodlink"])


def test_replay_groups_tenants_and_policies_without_merging_scope_state():
    records, policies = [], {}
    for tenant in ("tenant-a", "tenant-b"):
        for version in (7, 8):
            policy = detection_policy(tenant, "policy-a", version)
            policies[policy_key(policy)] = policy
            record = signal_record("scope-a", "policy-a", version, 100, "same-id",
                                   signal_pb2.SIGNAL_STAGE_CANDIDATE)
            record.context.tenant_id = tenant
            records.append(record)
    result = replay(records, policies, ["rule-correlation-v1"])
    assert result.input_records == 4
    assert len(result.batches) == 4
    assert {row["tenant_id"] for row in result.batches} == {"tenant-a", "tenant-b"}
    artifacts = [streaming_pb2.AnalysisArtifact.FromString(raw) for raw in result.artifacts]
    assert {item.tenant_id for item in artifacts} == {"tenant-a", "tenant-b"}
