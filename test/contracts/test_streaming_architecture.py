import pathlib
import re
import unittest


REPO = pathlib.Path(__file__).resolve().parents[2]
STREAMING = REPO / "streaming"


class StreamingArchitectureContractTest(unittest.TestCase):
    def test_streaming_package_has_three_independent_job_entries(self):
        required = (
            "pyproject.toml",
            "src/sysarmor_streaming/jobs/normalize.py",
            "src/sysarmor_streaming/jobs/detection.py",
            "src/sysarmor_streaming/jobs/projection.py",
        )

        missing = [path for path in required if not (STREAMING / path).is_file()]

        self.assertEqual([], missing)

    def test_streaming_contract_is_versioned_protobuf(self):
        path = REPO / "packages/contracts/proto/streaming/v1/streaming.proto"
        self.assertTrue(path.is_file(), "missing versioned streaming contract")
        contract = path.read_text()

        self.assertIn("package sysarmor.streaming.v1;", contract)
        self.assertIn("message NormalizedTelemetry", contract)
        self.assertIn("message DetectionPolicySnapshot", contract)
        self.assertIn("message AnalysisArtifact", contract)

    def test_streaming_runtime_has_no_postgres_dependency(self):
        banned = re.compile(r"postgres|lib/pq|SYSARMOR_POSTGRES", re.IGNORECASE)
        violations = []
        sources = (STREAMING / "src/sysarmor_streaming").rglob("*.py")
        sources = [*sources, STREAMING / "pyproject.toml"]
        for source in sources:
            if source.is_file() and banned.search(source.read_text(errors="ignore")):
                violations.append(str(source.relative_to(REPO)))

        self.assertEqual([], violations)

    def test_api_target_generates_python_wire_types(self):
        makefile = (REPO / "Makefile").read_text()
        generated = (
            STREAMING
            / "src/packages/contracts/proto/streaming/v1/streaming_pb2.py"
        )

        self.assertIn("api: api-go api-python", makefile)
        self.assertIn("python -m grpc_tools.protoc", makefile)
        self.assertIn("--python_out=$(PYTHON_PROTO_OUT)", makefile)
        self.assertTrue(generated.is_file(), "missing generated Python wire types")


if __name__ == "__main__":
    unittest.main()
