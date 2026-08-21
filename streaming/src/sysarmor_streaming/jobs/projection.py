"""Convert analysis artifacts into versioned documents for the index adapter."""

from pyflink.common import Types
from pyflink.datastream import ProcessFunction

from sysarmor_streaming.operators.projection import project_artifact


JOB_NAME = "sysarmor-projection-v1"
BYTE_ARRAY = Types.PRIMITIVE_ARRAY(Types.BYTE())


class ProjectionFunction(ProcessFunction):
    def process_element(self, value, ctx):
        yield project_artifact(bytes(value))
