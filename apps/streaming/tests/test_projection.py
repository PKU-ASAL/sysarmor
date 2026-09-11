import json
import pickle
import time
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread

from packages.contracts.proto.incident.v1 import incident_pb2
from packages.contracts.proto.signal.v1 import signal_pb2
from packages.contracts.proto.streaming.v1 import streaming_pb2
from streaming.projection.transform import project_artifact
from streaming.projection.opensearch import OpenSearchProjector
from streaming.jobs.projection import ProjectionFunction


class ProjectionTest(unittest.TestCase):
    def test_opensearch_projector_can_be_serialized_for_flink_workers(self):
        projector = OpenSearchProjector("http://127.0.0.1:9200")
        restored = pickle.loads(pickle.dumps(projector))
        try:
            self.assertEqual("http://127.0.0.1:9200", restored._base_url)
        finally:
            projector.close()
            restored.close()

    def test_opensearch_projector_flushes_partial_batch_after_interval(self):
        requests = []

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                requests.append(self.rfile.read(int(self.headers["Content-Length"])))
                self.send_response(200)
                self.end_headers()

            def log_message(self, *_):
                return

        server = HTTPServer(("127.0.0.1", 0), Handler)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        projector = OpenSearchProjector(
            f"http://127.0.0.1:{server.server_port}",
            batch_size=100,
            flush_interval_seconds=0.01,
        )
        try:
            artifact = streaming_pb2.AnalysisArtifact(
                schema_version="sysarmor.analysis.artifact/v1",
                tenant_id="tenant-a",
                signal=signal_pb2.Signal(id="signal-partial"),
            )
            projector.put(project_artifact(artifact.SerializeToString()))
            deadline = time.monotonic() + 1
            while not requests and time.monotonic() < deadline:
                time.sleep(0.01)
        finally:
            projector.close()
            server.shutdown()
            server.server_close()

        self.assertEqual(1, len(requests))

    def test_opensearch_projector_batches_documents_until_flush(self):
        requests = []

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                requests.append(self.rfile.read(int(self.headers["Content-Length"])))
                self.send_response(200)
                self.end_headers()

            def log_message(self, *_):
                return

        server = HTTPServer(("127.0.0.1", 0), Handler)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            base = f"http://127.0.0.1:{server.server_port}"
            projector = OpenSearchProjector(base, batch_size=2)
            for identity in ("signal-a", "signal-b"):
                artifact = streaming_pb2.AnalysisArtifact(
                    schema_version="sysarmor.analysis.artifact/v1",
                    tenant_id="tenant-a",
                    signal=signal_pb2.Signal(id=identity),
                )
                projector.put(project_artifact(artifact.SerializeToString()))
            projector.flush()
        finally:
            server.shutdown()
            server.server_close()

        self.assertEqual(1, len(requests))
        lines = requests[0].decode().splitlines()
        self.assertEqual(4, len(lines))
        self.assertEqual({"signal-a", "signal-b"}, {json.loads(lines[index])["id"] for index in (1, 3)})

    def test_projection_function_flushes_projector_on_close(self):
        class Projector:
            def __init__(self):
                self.flushed = False

            def close(self):
                self.flushed = True

        projector = Projector()
        function = ProjectionFunction(projector)
        function.close()
        self.assertTrue(projector.flushed)

    def test_projection_function_reports_processed_records(self):
        function = ProjectionFunction()
        self.assertEqual({"processed_records": 0}, function.metrics())

    def test_opensearch_projector_puts_idempotent_document_to_kind_index(self):
        received = []

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                received.append((self.path, self.rfile.read(int(self.headers["Content-Length"]))))
                self.send_response(200)
                self.end_headers()

            def log_message(self, *_):
                return

        server = HTTPServer(("127.0.0.1", 0), Handler)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            artifact = streaming_pb2.AnalysisArtifact(
                schema_version="sysarmor.analysis.artifact/v1",
                tenant_id="tenant-a",
                analysis_scope_key="scope-a",
                incident=incident_pb2.Incident(id="incident-a"),
            )
            projector = OpenSearchProjector(
                server.url if hasattr(server, "url") else f"http://127.0.0.1:{server.server_port}"
            )
            projector.put(project_artifact(artifact.SerializeToString()))
            projector.flush()
            self.assertEqual(1, projector.metrics()["flushed_documents"])
        finally:
            server.shutdown()
            server.server_close()
        self.assertEqual("/_bulk", received[0][0])
        self.assertIn('"incident-a"', received[0][1].decode())

    def test_invalid_artifact_goes_to_projection_failure_side_output(self):
        output = list(ProjectionFunction().process_element(
            streaming_pb2.AnalysisArtifact(
                schema_version="sysarmor.analysis.artifact/v1",
                tenant_id="tenant-a",
            ).SerializeToString(),
            None,
        ))

        tag, value = output[0]
        failure = streaming_pb2.ProjectionFailure.FromString(value)
        self.assertEqual("invalid_analysis_artifact", failure.reason_code)
        self.assertFalse(failure.retryable)

    def test_incident_projection_is_json_document_with_scope_identity(self):
        artifact = streaming_pb2.AnalysisArtifact(
            schema_version="sysarmor.analysis.artifact/v1",
            tenant_id="tenant-a",
            analysis_scope_key="scope-a",
            observed_at_unix_nano=100,
            incident=incident_pb2.Incident(id="incident-a"),
        )

        document = project_artifact(artifact.SerializeToString()).decode()

        self.assertIn('"id":"incident-a"', document)
        self.assertIn('"tenant_id":"tenant-a"', document)
        self.assertIn('"projection_kind":"incident"', document)

    def test_signal_projection_keeps_stream_correlation_identity(self):
        artifact = streaming_pb2.AnalysisArtifact(
            schema_version="sysarmor.analysis.artifact/v1",
            tenant_id="tenant-a",
            context=streaming_pb2.RecordContext(
                agent_id="agent-a", batch_id="batch-a", record_sequence=17,
            ),
            signal=signal_pb2.Signal(
                id="candidate-a", event_refs=["event-a"],
                entities=[signal_pb2.EntityRef(kind="process", key="process-a", role="subject")],
            ),
        )

        document = project_artifact(artifact.SerializeToString()).decode()

        for expected in ('"agent_id":"agent-a"', '"batch_id":"batch-a"', '"subject_id":"process-a"', '"trigger_event_id":"event-a"', '"event_sequence":17'):
            self.assertIn(expected, document)


if __name__ == "__main__":
    unittest.main()
