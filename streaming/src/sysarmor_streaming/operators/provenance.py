from collections import deque
from dataclasses import dataclass

from packages.contracts.proto.incident.v1 import incident_pb2
from packages.contracts.proto.signal.v1 import signal_pb2


MAX_EVIDENCE_SEEDS = 128
MAX_GRAPH_EVENTS = 100_000
KNOWN_ENTITY_KINDS = {"file", "socket", "process", "container", "user", "token"}


@dataclass(frozen=True)
class ProvenanceEdge:
    edge_id: str
    from_id: str
    to_id: str
    operation: str
    event_id: str
    incomplete: bool = False


def edge_from_event(event) -> ProvenanceEdge | None:
    stable_id = event.subject_proc.stable_id.strip()
    if not stable_id:
        return None
    subject = entity_id("process", stable_id)
    behavior = event.behavior.strip().lower()
    if behavior in {"process.exec", "process.fork", "process.clone"}:
        operation = behavior.removeprefix("process.")
        if event.parent_stable_id:
            return _edge(entity_id("process", event.parent_stable_id), subject, operation, event.id)
        if event.identity_status == "unavailable":
            return _edge(f"gap:parent:{event.id}", subject, operation, event.id, True)
        return None
    mappings = {
        "file.open": (entity_id("file", event.object.file_path), subject, "open"),
        "file.read": (entity_id("file", event.object.file_path), subject, "read"),
        "file.write": (subject, entity_id("file", event.object.file_path), "write"),
        "file.create": (subject, entity_id("file", event.object.file_path), "create"),
        "file.chmod": (subject, entity_id("file", event.object.file_path), "chmod"),
        "file.rename": (subject, entity_id("file", event.object.file_path), "rename"),
        "network.connect": (subject, entity_id("socket", event.object.socket_addr), "connect"),
        "network.send": (subject, entity_id("socket", event.object.socket_addr), "send"),
        "network.receive": (entity_id("socket", event.object.socket_addr), subject, "receive"),
    }
    endpoints = mappings.get(behavior)
    return _edge(*endpoints, event.id) if endpoints else None


def _edge(from_id, to_id, operation, event_id, incomplete=False):
    if not from_id or not to_id or from_id == to_id:
        return None
    edge_id = f"{operation}:{from_id}->{to_id}"
    return ProvenanceEdge(edge_id, from_id, to_id, operation, event_id, incomplete)


def entity_id(kind: str, key: str) -> str:
    kind, key = kind.strip().lower(), key.strip()
    if not key:
        return ""
    prefix = f"{kind}:"
    return key if kind not in KNOWN_ENTITY_KINDS or key.startswith(prefix) else prefix + key


class ProvenanceGraph:
    def __init__(self):
        self._nodes = {}
        self._node_order = []
        self._edges = {}
        self._edge_order = []
        self._adjacency = {}

    @classmethod
    def from_events(cls, events):
        graph = cls()
        ordered = sorted(events, key=lambda item: (item.occurred_at_ns, item.id))
        for event in ordered[-MAX_GRAPH_EVENTS:]:
            graph.add_event(event)
        return graph

    def add_event(self, event) -> None:
        stable_id = event.subject_proc.stable_id.strip()
        if stable_id:
            self._add_node(entity_id("process", stable_id), "process", "subject")
        edge = edge_from_event(event)
        if edge is not None:
            self._add_provenance_edge(edge)

    def evidence_subgraph(self):
        return self._subgraph(set(self._node_order), set(self._edge_order))

    def connecting_evidence(self, signals):
        seeds = self._signal_seeds(signals)
        if not seeds:
            return incident_pb2.EvidenceSubgraph()
        nodes, edges = set(seeds), set()
        if len(seeds) == 1:
            adjacent_nodes, adjacent_edges = self._k_hop(seeds[0], 1)
            nodes.update(adjacent_nodes)
            edges.update(adjacent_edges)
        for left in range(len(seeds)):
            for right in range(left + 1, len(seeds)):
                path_nodes, path_edges = self._shortest_path(seeds[left], seeds[right])
                nodes.update(path_nodes)
                edges.update(path_edges)
        self._include_adjacent_gaps(nodes, edges)
        return self._subgraph(nodes, edges)

    def connects(self, left, right) -> bool:
        left_nodes = self._existing_signal_nodes(left)
        right_nodes = self._existing_signal_nodes(right)
        for start in left_nodes:
            for target in right_nodes:
                if start == target or self._shortest_path(start, target)[1]:
                    return True
        return False

    def _add_provenance_edge(self, edge: ProvenanceEdge) -> None:
        self._add_edge_node(edge.from_id, edge.operation, True)
        self._add_edge_node(edge.to_id, edge.operation, False)
        if edge.edge_id not in self._edges:
            value = incident_pb2.GraphEdge(
                id=edge.edge_id,
                to=edge.to_id,
                kind=edge.operation,
                incomplete=edge.incomplete,
                **{"from": edge.from_id},
            )
            self._edges[edge.edge_id] = value
            self._edge_order.append(edge.edge_id)
            self._adjacency.setdefault(edge.from_id, []).append(edge.edge_id)
            self._adjacency.setdefault(edge.to_id, []).append(edge.edge_id)
        value = self._edges[edge.edge_id]
        if edge.event_id and edge.event_id not in value.event_refs:
            value.event_refs.append(edge.event_id)
        value.incomplete = value.incomplete or edge.incomplete

    def _add_edge_node(self, node_id: str, operation: str, source: bool) -> None:
        if node_id.startswith("gap:"):
            self._add_node(node_id, "gap", "")
            return
        kind = node_id.split(":", 1)[0]
        role = "object"
        if kind == "process":
            role = "parent" if source and operation in {"exec", "fork", "clone"} else "subject"
        self._add_node(node_id, kind, role)

    def _add_node(self, node_id: str, kind: str, role: str) -> None:
        if not node_id or node_id in self._nodes:
            return
        node = incident_pb2.GraphNode(id=node_id, kind=kind, label=node_id)
        if role:
            node.entities.append(signal_pb2.EntityRef(kind=kind, key=node_id, role=role))
        self._nodes[node_id] = node
        self._node_order.append(node_id)

    def _signal_seeds(self, signals):
        entities = {}
        for signal in signals:
            for entity in signal.entities:
                key = entity_id(entity.kind, entity.key)
                if key:
                    entities[key] = entity
        seeds = []
        for key in sorted(entities)[:MAX_EVIDENCE_SEEDS]:
            if key in self._nodes:
                seeds.append(key)
            else:
                gap = f"gap:seed:{key}"
                self._add_node(gap, "gap", "")
                seeds.append(gap)
        return seeds

    def _existing_signal_nodes(self, signal):
        nodes = {
            entity_id(entity.kind, entity.key)
            for entity in signal.entities
            if entity_id(entity.kind, entity.key) in self._nodes
        }
        return sorted(nodes)[:MAX_EVIDENCE_SEEDS]

    def _k_hop(self, seed: str, hops: int):
        nodes, edges, frontier = {seed}, set(), [seed]
        for _ in range(hops):
            following = []
            for node in frontier:
                for edge_id in self._adjacency.get(node, ()):
                    other = self._adjacent(edge_id, node)
                    edges.add(edge_id)
                    if other not in nodes:
                        nodes.add(other)
                        following.append(other)
            frontier = following
        return nodes, edges

    def _shortest_path(self, start: str, target: str):
        if start not in self._nodes or target not in self._nodes:
            return set(), set()
        parents, seen, queue = {}, {start}, deque([start])
        while queue:
            node = queue.popleft()
            for edge_id in self._adjacency.get(node, ()):
                other = self._adjacent(edge_id, node)
                if other in seen:
                    continue
                parents[other] = (node, edge_id)
                if other == target:
                    return self._path(start, target, parents)
                seen.add(other)
                queue.append(other)
        return set(), set()

    def _path(self, start: str, target: str, parents):
        nodes, edges, current = {target}, set(), target
        while current != start:
            parent, edge_id = parents[current]
            nodes.add(parent)
            edges.add(edge_id)
            current = parent
        return nodes, edges

    def _adjacent(self, edge_id: str, node: str) -> str:
        edge = self._edges[edge_id]
        from_id = getattr(edge, "from")
        return edge.to if from_id == node else from_id

    def _include_adjacent_gaps(self, nodes, edges) -> None:
        for edge_id in self._edge_order:
            edge = self._edges[edge_id]
            from_id = getattr(edge, "from")
            if edge.incomplete and (from_id in nodes or edge.to in nodes):
                nodes.update((from_id, edge.to))
                edges.add(edge_id)

    def _subgraph(self, nodes, edges):
        result = incident_pb2.EvidenceSubgraph()
        result.nodes.extend(self._nodes[node_id] for node_id in self._node_order if node_id in nodes)
        result.edges.extend(self._edges[edge_id] for edge_id in self._edge_order if edge_id in edges)
        return result
