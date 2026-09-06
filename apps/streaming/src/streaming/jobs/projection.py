"""Convert analysis artifacts into versioned documents for the index adapter."""

import logging
import time

from pyflink.common import Types
from pyflink.datastream import OutputTag, ProcessFunction

from streaming.projection import project_artifact
from packages.contracts.proto.streaming.v1 import streaming_pb2


JOB_NAME = "sysarmor-projection-v1"
BYTE_ARRAY = Types.PRIMITIVE_ARRAY(Types.BYTE())
FAILURE_TAG = OutputTag("projection-failures", BYTE_ARRAY)


class ProjectionFunction(ProcessFunction):
    def __init__(self, projector=None):
        self._projector = projector
        self._processed = 0
        self._started_at = 0.0

    def open(self, runtime_context):
        self._started_at = time.monotonic()

    def process_element(self, value, ctx):
        artifact = streaming_pb2.AnalysisArtifact.FromString(bytes(value))
        try:
            document = project_artifact(bytes(value))
            if self._projector is not None:
                self._projector.put(document)
            self._processed += 1
            if self._processed % 100 == 0:
                elapsed = max(time.monotonic() - self._started_at, 0.001)
                logging.info("projection throughput records=%d rate=%.1f/s", self._processed, self._processed / elapsed)
            yield document
        except ValueError as error:
            yield FAILURE_TAG, streaming_pb2.ProjectionFailure(
                artifact=artifact,
                reason_code="invalid_analysis_artifact",
                message=str(error),
                retryable=False,
            ).SerializeToString()

    def close(self):
        if self._projector is not None:
            self._projector.close()
        logging.info("projection completed records=%d", self._processed)
