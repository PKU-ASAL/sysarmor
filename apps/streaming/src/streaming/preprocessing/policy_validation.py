"""Policy snapshot validation shared by Flink and offline evaluation."""


def validate_policy(policy):
    if policy.schema_version != "sysarmor.detection.policy/v1":
        raise ValueError("unsupported detection policy schema")
    if not policy.tenant_id or not policy.policy_id or policy.policy_version == 0:
        raise ValueError("incomplete detection policy identity")
