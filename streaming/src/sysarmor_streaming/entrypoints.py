"""Flink submission entrypoints for streaming jobs."""

import os

from sysarmor_streaming.jobs.detection import build_graph
from sysarmor_streaming.jobs.normalize import BYTE_ARRAY, NormalizeFunction, REJECTION_TAG
from sysarmor_streaming.jobs.projection import FAILURE_TAG, ProjectionFunction
from sysarmor_streaming.runtime.config import StreamingConfig
from sysarmor_streaming.runtime.kafka import configure_environment, sink, source
from sysarmor_streaming.runtime.opensearch import OpenSearchProjector


def run_normalize():
    config = StreamingConfig.from_env()
    env = configure_environment(config)
    raw = source(env, config.raw_topic, "sysarmor-normalize-v1", config)
    normalized = (
        raw.process(NormalizeFunction(), output_type=BYTE_ARRAY)
        .uid("normalize")
        .name("normalize")
    )
    sink(normalized, config.normalized_topic, config, "sysarmor-normalize-v1")
    sink(
        normalized.get_side_output(REJECTION_TAG),
        config.failure_topic,
        config,
        "sysarmor-normalize-rejection-v1",
    )
    env.execute("sysarmor-normalize-v1")


def run_detection():
    config = StreamingConfig.from_env()
    env = configure_environment(config)
    telemetry = source(env, config.normalized_topic, "sysarmor-detection-v1", config)
    policies = source(env, config.policy_topic, "sysarmor-detection-policy-v1", config)
    streams = build_graph(telemetry, policies)
    sink(streams.artifacts, config.artifact_topic, config, "sysarmor-detection-artifact-v1")
    sink(streams.late, config.late_topic, config, "sysarmor-detection-late-v1")
    sink(streams.failures, config.failure_topic, config, "sysarmor-detection-failure-v1")
    env.execute("sysarmor-detection-v1")


def run_projection():
    config = StreamingConfig.from_env()
    env = configure_environment(config)
    artifacts = source(env, config.artifact_topic, "sysarmor-projection-v1", config)
    if not config.opensearch_url:
        raise ValueError("SYSARMOR_OPENSEARCH_URL is required for projection")
    projected = artifacts.process(
        ProjectionFunction(OpenSearchProjector(config.opensearch_url)),
        output_type=BYTE_ARRAY,
    ).uid("projection").name("projection")
    sink(projected, config.projected_topic, config, "sysarmor-projection-v1")
    sink(
        projected.get_side_output(FAILURE_TAG),
        config.failure_topic,
        config,
        "sysarmor-projection-failure-v1",
    )
    env.execute("sysarmor-projection-v1")


def main():
    job = os.getenv("SYSARMOR_FLINK_JOB", "detection").strip().lower()
    if job == "normalize":
        run_normalize()
    elif job == "detection":
        run_detection()
    elif job == "projection":
        run_projection()
    else:
        raise ValueError(f"unsupported SYSARMOR_FLINK_JOB: {job}")


if __name__ == "__main__":
    main()
