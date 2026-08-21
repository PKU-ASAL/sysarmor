import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread

from packages.contracts.proto.incident.v1 import incident_pb2
from packages.contracts.proto.streaming.v1 import streaming_pb2
from sysarmor_streaming.operators.projection import project_artifact
from sysarmor_streaming.runtime.opensearch import OpenSearchProjector
from sysarmor_streaming.jobs.projection import ProjectionFunction


class ProjectionTest(unittest.TestCase):
    def test_opensearch_projector_puts_idempotent_document_to_kind_index(self):
        received = []

        class Handler(BaseHTTPRequestHandler):
            def do_PUT(self):
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
            OpenSearchProjector(server.url if hasattr(server, "url") else f"http://127.0.0.1:{server.server_port}").put(
                project_artifact(artifact.SerializeToString())
            )
        finally:
            server.shutdown()
            server.server_close()
        self.assertEqual("/sysarmor-incidents-write/_doc/incident-a", received[0][0])

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


if __name__ == "__main__":
    unittest.main()
