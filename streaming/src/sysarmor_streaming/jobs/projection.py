"""Convert analysis artifacts into versioned documents for the index adapter."""

from pyflink.common import Types
from pyflink.datastream import OutputTag, ProcessFunction

from sysarmor_streaming.operators.projection import project_artifact
from packages.contracts.proto.streaming.v1 import streaming_pb2


JOB_NAME = "sysarmor-projection-v1"
BYTE_ARRAY = Types.PRIMITIVE_ARRAY(Types.BYTE())
FAILURE_TAG = OutputTag("projection-failures", BYTE_ARRAY)


class ProjectionFunction(ProcessFunction):
    def process_element(self, value, ctx):
        artifact = streaming_pb2.AnalysisArtifact.FromString(bytes(value))
        try:
            yield project_artifact(bytes(value))
        except ValueError as error:
            yield FAILURE_TAG, streaming_pb2.ProjectionFailure(
                artifact=artifact,
                reason_code="invalid_analysis_artifact",
                message=str(error),
                retryable=False,
            ).SerializeToString()
