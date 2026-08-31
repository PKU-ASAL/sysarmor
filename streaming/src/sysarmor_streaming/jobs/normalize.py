"""Normalize raw DataBatch records into the versioned telemetry stream."""

from pyflink.common import Types
from pyflink.datastream import OutputTag, ProcessFunction

from sysarmor_streaming.operators.normalizer import normalize_batch

JOB_NAME = "sysarmor-normalize-v1"
BYTE_ARRAY = Types.PRIMITIVE_ARRAY(Types.BYTE())
REJECTION_TAG = OutputTag("normalization-rejections", BYTE_ARRAY)


class NormalizeFunction(ProcessFunction):
    def process_element(self, value, ctx):
        result = normalize_batch(bytes(value))
        if result.rejection is not None:
            yield REJECTION_TAG, result.rejection.SerializeToString()
            return
        for record in result.records:
            yield record.SerializeToString()
