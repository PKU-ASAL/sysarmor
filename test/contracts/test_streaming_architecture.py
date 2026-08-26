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
        self.assertTrue((STREAMING / "src/sysarmor_streaming/entrypoints.py").is_file())

    def test_streaming_deployment_has_flink_managers_and_checkpoint_store(self):
        compose = (REPO / "deployments/compose.platform.yaml").read_text()
        self.assertIn("flink-jobmanager:", compose)
        self.assertIn("flink-taskmanager:", compose)
        self.assertIn("rustfs:", compose)
        self.assertNotIn("minio/mc", compose)
        self.assertNotIn("minio:", compose)
        self.assertIn("flink-checkpoints:", compose)

    def test_kafka_topics_are_explicit_versioned_contracts(self):
        compose = (REPO / "deployments/compose.platform.yaml").read_text()
        manifest = (REPO / "deployments/kafka/topics.tsv").read_text()
        required = (
            "sysarmor.control.policy.endpoint.published.v1",
            "sysarmor.data.telemetry.endpoint.batch.ingress.v1",
            "sysarmor.data.telemetry.record.normalized.v1",
            "sysarmor.data.detection.artifact.analyzed.v1",
            "sysarmor.data.detection.record.late.v1",
            "sysarmor.data.projection.document.projected.v1",
            "sysarmor.data.pipeline.failure.rejected.v1",
        )

        self.assertIn('KAFKA_AUTO_CREATE_TOPICS_ENABLE: "false"', compose)
        self.assertIn("kafka-init:", compose)
        self.assertIn('KAFKA_TRANSACTION_MAX_TIMEOUT_MS: "3600000"', compose)
        self.assertIn('TASK_MANAGER_NUMBER_OF_TASK_SLOTS: "8"', compose)
        self.assertIn("condition: service_completed_successfully", compose)
        for topic in required:
            self.assertIn(topic, manifest)

    def test_vm_topology_uses_prebuilt_streaming_image(self):
        platform = (REPO / "deployments/compose.platform.yaml").read_text()
        harness = (REPO / "test/shared/harness/start-vm.sh").read_text()

        self.assertGreaterEqual(platform.count("image: sysarmor-flink:1.20.2"), 5)
        self.assertIn("sysarmor-flink:1.20.2", harness)
        self.assertIn(
            "docker build --network=host -t sysarmor-flink:1.20.2", harness
        )
        self.assertIn("up -d --no-build", harness)
        for image in (
            "sysarmor-postgres:latest",
            "sysarmor-kafka:latest",
            "sysarmor-redis:latest",
            "sysarmor-manager:latest",
            "sysarmor-gateway:latest",
            "sysarmor-manager-ui:latest",
        ):
            self.assertIn(f"image: {image}", platform)
            self.assertIn(image, harness)
        self.assertEqual(platform.count("- ../streaming/src:/opt/sysarmor/streaming/src:ro"), 1)
        topology = (REPO / "deployments/compose.vm-topology.yaml").read_text()
        self.assertIn("- ../streaming/src:/opt/sysarmor/streaming/src:ro", topology)
        dockerfile = (REPO / "deployments/streaming/Dockerfile").read_text()
        self.assertIn("ln -s /usr/bin/python3 /usr/local/bin/python", dockerfile)
        self.assertIn("flink-s3-fs-presto-1.20.2.jar", dockerfile)
        self.assertNotIn("flink-s3-fs-hadoop", dockerfile)
        kafka_runtime = (STREAMING / "src/sysarmor_streaming/runtime/kafka.py").read_text()
        self.assertIn("FileSystemCheckpointStorage(config.checkpoint_uri)", kafka_runtime)
        self.assertIn("io.sysarmor.streaming.ByteArraySchema", kafka_runtime)
        self.assertIn('f"kafka-{topic}"', kafka_runtime)
        schema = REPO / "deployments/streaming/java/io/sysarmor/streaming/ByteArraySchema.java"
        self.assertTrue(schema.is_file())

    def test_vm_harness_builds_project_images_without_registry_cache(self):
        harness = (REPO / "test/shared/harness/start-vm.sh").read_text()
        upstream = harness.split("required_images=(", 1)[1].split(")", 1)[0]

        self.assertNotIn("sysarmor-", upstream)
        self.assertIn("postgres kafka redis opensearch manager manager-ui gateway", harness)

    def test_streaming_contract_is_versioned_protobuf(self):
        path = REPO / "packages/contracts/proto/streaming/v1/streaming.proto"
        self.assertTrue(path.is_file(), "missing versioned streaming contract")
        contract = path.read_text()

        self.assertIn("package sysarmor.streaming.v1;", contract)
        self.assertIn("message NormalizedTelemetry", contract)
        self.assertIn("message DetectionPolicySnapshot", contract)
        self.assertIn("message AnalysisArtifact", contract)
        publisher = (REPO / "apps/manager/internal/adapters/outbound/kafka/policy_snapshot.go").read_text()
        detection = (STREAMING / "src/sysarmor_streaming/jobs/detection.py").read_text()
        self.assertIn('"sysarmor.detection.policy/v1"', publisher)
        self.assertIn('"sysarmor.detection.policy/v1"', detection)

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
