import importlib
import unittest

from packages.contracts.proto.event.v1 import event_pb2
from packages.contracts.proto.signal.v1 import signal_pb2


def load_graph():
    try:
        return importlib.import_module("streaming.engine.provenance")
    except ModuleNotFoundError as error:
        raise AssertionError("provenance operator is not implemented") from error


def load_shortest_path():
    try:
        return importlib.import_module("streaming.detectors.shortest_path")
    except ModuleNotFoundError as error:
        raise AssertionError("shortest-path detector is not implemented") from error


class ProvenanceGraphTest(unittest.TestCase):
    def test_add_event_reports_changed_nodes_and_edge(self):
        graph = load_graph().ProvenanceGraph()

        change = graph.add_event(
            event("write", "file.write", event_pb2.ProcessRef(stable_id="p1"), file_path="/tmp/a")
        )

        self.assertEqual({"process:p1", "file:/tmp/a"}, set(change.node_ids))
        self.assertEqual(("write:process:p1->file:/tmp/a",), change.edge_ids)

    def test_connecting_evidence_recovers_causal_path_and_event_refs(self):
        graph = load_graph().ProvenanceGraph.from_events(causal_events())
        signals = [
            signal("process", "p-shell"),
            signal("file", "/dev/shm/x.sh"),
            signal("socket", "10.66.0.99:443"),
        ]

        evidence = load_shortest_path().connecting_evidence(graph, signals)

        self.assertEqual(
            {
                "process:p-shell",
                "process:p-curl",
                "file:/dev/shm/x.sh",
                "process:p-bash",
                "socket:10.66.0.99:443",
            },
            {node.id for node in evidence.nodes},
        )
        self.assertEqual(4, len(evidence.edges))
        refs = {ref for edge in evidence.edges for ref in edge.event_refs}
        self.assertEqual(
            {"exec-curl", "write-payload", "exec-bash", "connect-c2"}, refs
        )

    def test_provenance_direction_and_repeated_edges_are_preserved(self):
        process = event_pb2.ProcessRef(stable_id="p-shell")
        events = [
            event("read", "file.read", process, file_path="/tmp/input"),
            event("write-a", "file.write", process, file_path="/tmp/output"),
            event("write-b", "file.write", process, file_path="/tmp/output"),
            event("receive", "network.receive", process, socket_addr="10.0.0.1:53"),
            event("exit", "process.exit", process),
        ]

        evidence = load_graph().ProvenanceGraph.from_events(events).evidence_subgraph()
        edges = {edge.id: edge for edge in evidence.edges}

        self.assertIn("read:file:/tmp/input->process:p-shell", edges)
        self.assertIn("write:process:p-shell->file:/tmp/output", edges)
        self.assertIn("receive:socket:10.0.0.1:53->process:p-shell", edges)
        self.assertEqual(
            ["write-a", "write-b"],
            list(edges["write:process:p-shell->file:/tmp/output"].event_refs),
        )
        self.assertFalse(any(edge.kind == "exit" for edge in evidence.edges))

    def test_unavailable_parent_is_an_explicit_incomplete_gap(self):
        orphan = event(
            "exec-orphan",
            "process.exec",
            event_pb2.ProcessRef(stable_id="p-orphan"),
            identity_status="unavailable",
        )

        evidence = load_shortest_path().connecting_evidence(
            load_graph().ProvenanceGraph.from_events([orphan]),
            [signal("process", "p-orphan")],
        )

        self.assertIn("gap:parent:exec-orphan", {node.id for node in evidence.nodes})
        edge = evidence.edges[0]
        self.assertTrue(edge.incomplete)
        self.assertEqual("gap:parent:exec-orphan", getattr(edge, "from"))
        self.assertEqual("process:p-orphan", edge.to)


def causal_events():
    return [
        event("exec-curl", "process.exec", event_pb2.ProcessRef(stable_id="p-curl"), parent="p-shell"),
        event("write-payload", "file.write", event_pb2.ProcessRef(stable_id="p-curl"), file_path="/dev/shm/x.sh"),
        event("exec-bash", "process.exec", event_pb2.ProcessRef(stable_id="p-bash"), parent="p-curl"),
        event("connect-c2", "network.connect", event_pb2.ProcessRef(stable_id="p-bash"), socket_addr="10.66.0.99:443"),
    ]


def event(event_id, behavior, process, parent="", file_path="", socket_addr="", identity_status=""):
    return event_pb2.CanonicalEvent(
        id=event_id,
        behavior=behavior,
        subject_proc=process,
        parent_stable_id=parent,
        object=event_pb2.ObjectRef(file_path=file_path, socket_addr=socket_addr),
        identity_status=identity_status,
    )


def signal(kind, key):
    return signal_pb2.Signal(
        entities=[signal_pb2.EntityRef(kind=kind, key=key, role="subject")]
    )


if __name__ == "__main__":
    unittest.main()
