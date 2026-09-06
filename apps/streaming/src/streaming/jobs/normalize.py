"""Normalize raw DataBatch records into the versioned telemetry stream."""

from collections import defaultdict

from pyflink.common import Types
from pyflink.datastream import OutputTag, ProcessFunction

from packages.contracts.proto.streaming.v1 import streaming_pb2
from streaming.preprocessing.normalizer import normalize_batch

JOB_NAME = "sysarmor-normalize-v1"
BYTE_ARRAY = Types.PRIMITIVE_ARRAY(Types.BYTE())
REJECTION_TAG = OutputTag("normalization-rejections", BYTE_ARRAY)


class NormalizeFunction(ProcessFunction):
    def process_element(self, value, ctx):
        result = normalize_batch(bytes(value))
        if result.rejection is not None:
            yield REJECTION_TAG, result.rejection.SerializeToString()
            return
        if not result.records:
            return
        grouped = defaultdict(list)
        for record in result.records:
            grouped[
                (
                    record.context.tenant_id,
                    record.context.agent_id,
                    record.context.policy_id,
                    record.context.policy_version,
                )
            ].append(record)
        for records in grouped.values():
            first = records[0]
            batch = streaming_pb2.NormalizedTelemetryBatch(
                schema_version="sysarmor.telemetry.normalized.batch/v1",
                tenant_id=first.context.tenant_id,
                agent_id=first.context.agent_id,
                host_id=first.context.host_id,
                batch_id=first.context.batch_id,
                policy_id=first.context.policy_id,
                policy_version=first.context.policy_version,
                policy_mode=first.context.policy_mode,
                created_at_unix_nano=max(
                    record.context.observed_at_unix_nano for record in records
                ),
                records=records,
            )
            yield batch.SerializeToString()
