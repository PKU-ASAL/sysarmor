import os
from dataclasses import dataclass


@dataclass(frozen=True)
class StreamingConfig:
    brokers: str
    raw_topic: str
    normalized_topic: str
    policy_topic: str
    artifact_topic: str
    projected_topic: str
    opensearch_url: str
    late_topic: str
    failure_topic: str
    checkpoint_uri: str
    checkpoint_interval_ms: int
    parallelism: int
    kafka_connector_jar: str

    @classmethod
    def from_env(cls):
        return cls(
            brokers=_required("SYSARMOR_KAFKA_BROKERS"),
            raw_topic=_env(
                "SYSARMOR_KAFKA_RAW_TOPIC",
                "sysarmor.data.telemetry.endpoint.batch.ingress.v1",
            ),
            normalized_topic=_env(
                "SYSARMOR_KAFKA_NORMALIZED_TOPIC",
                "sysarmor.data.telemetry.record.normalized.v1",
            ),
            policy_topic=_env(
                "SYSARMOR_KAFKA_POLICY_TOPIC",
                "sysarmor.control.policy.endpoint.published.v1",
            ),
            artifact_topic=_env(
                "SYSARMOR_KAFKA_ARTIFACT_TOPIC",
                "sysarmor.data.detection.artifact.analyzed.v1",
            ),
            projected_topic=_env(
                "SYSARMOR_KAFKA_PROJECTED_TOPIC",
                "sysarmor.data.projection.document.projected.v1",
            ),
            opensearch_url=_env("SYSARMOR_OPENSEARCH_URL", ""),
            late_topic=_env(
                "SYSARMOR_KAFKA_LATE_TOPIC",
                "sysarmor.data.detection.record.late.v1",
            ),
            failure_topic=_env(
                "SYSARMOR_KAFKA_FAILURE_TOPIC",
                "sysarmor.data.pipeline.failure.rejected.v1",
            ),
            checkpoint_uri=_env(
                "SYSARMOR_FLINK_CHECKPOINT_URI",
                "s3://sysarmor-flink/checkpoints",
            ),
            checkpoint_interval_ms=_positive_int(
                "SYSARMOR_FLINK_CHECKPOINT_INTERVAL_MS", 30_000
            ),
            parallelism=_positive_int("SYSARMOR_FLINK_PARALLELISM", 1),
            kafka_connector_jar=os.getenv("SYSARMOR_FLINK_KAFKA_CONNECTOR_JAR", ""),
        )


def _required(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise ValueError(f"missing required environment variable: {name}")
    return value


def _env(name: str, default: str) -> str:
    return os.getenv(name, default).strip() or default


def _positive_int(name: str, default: int) -> int:
    value = os.getenv(name, str(default))
    try:
        parsed = int(value)
    except ValueError as error:
        raise ValueError(f"{name} must be an integer") from error
    if parsed <= 0:
        raise ValueError(f"{name} must be positive")
    return parsed
