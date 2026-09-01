"""provenance-shortest-path-v1: shortest-path evidence as a Detector.

Extracted from ``operators.provenance.ProvenanceGraph.connecting_evidence``
unchanged in behavior. Given endpoint signals as seeds, unions the
shortest paths between seed pairs (plus single-seed k-hop and adjacent
incomplete gaps) into an EvidenceSubgraph.
"""

from __future__ import annotations

from packages.contracts.proto.incident.v1 import incident_pb2

from sysarmor_streaming.detectors.contracts import (
    DetectorInputs,
    DetectionResult,
    RequiredInput,
    StateRequirements,
)
from sysarmor_streaming.operators.provenance import entity_id

MAX_EVIDENCE_SEEDS = 128


class ShortestPathDetector:
    name = "provenance-shortest-path-v1"
    version = "1"
    required_inputs = (RequiredInput.SIGNAL, RequiredInput.PROVENANCE_EDGE)
    state_requirements = StateRequirements()

    def analyze(self, inputs: DetectorInputs) -> DetectionResult:
        evidence = connecting_evidence(inputs.graph, inputs.signals)
        edge_refs = tuple(edge.id for edge in evidence.edges)
        event_refs = tuple(ref for edge in evidence.edges for ref in edge.event_refs)
        return DetectionResult(
            algorithm_name=self.name,
            algorithm_version=self.version,
            evidence=evidence,
            edge_refs=edge_refs,
            event_refs=event_refs,
        )

    def diagnostics(self) -> dict:
        return {}


def connecting_evidence(graph, signals):
    seeds = _signal_seeds(graph, signals)
    if not seeds:
        return incident_pb2.EvidenceSubgraph()
    nodes, edges = set(seeds), set()
    if len(seeds) == 1:
        adjacent_nodes, adjacent_edges = _k_hop(graph, seeds[0], 1)
        nodes.update(adjacent_nodes)
        edges.update(adjacent_edges)
    for left in range(len(seeds)):
        for right in range(left + 1, len(seeds)):
            path_nodes, path_edges = graph.shortest_path(seeds[left], seeds[right])
            nodes.update(path_nodes)
            edges.update(path_edges)
    _include_adjacent_gaps(graph, nodes, edges)
    return graph.subgraph(nodes, edges)


def _signal_seeds(graph, signals):
    entities = {}
    for signal in signals:
        for entity in signal.entities:
            key = entity_id(entity.kind, entity.key)
            if key:
                entities[key] = entity
    seeds = []
    for key in sorted(entities)[:MAX_EVIDENCE_SEEDS]:
        if graph.has_node(key):
            seeds.append(key)
        else:
            gap = f"gap:seed:{key}"
            graph.add_node(gap, "gap", "")
            seeds.append(gap)
    return seeds


def _k_hop(graph, seed: str, hops: int):
    nodes, edges, frontier = {seed}, set(), [seed]
    for _ in range(hops):
        following = []
        for node in frontier:
            for edge_id in graph.neighbors(node):
                other = graph.adjacent(edge_id, node)
                edges.add(edge_id)
                if other not in nodes:
                    nodes.add(other)
                    following.append(other)
        frontier = following
    return nodes, edges


def _include_adjacent_gaps(graph, nodes, edges) -> None:
    for edge_id, edge in graph.edges():
        from_id = getattr(edge, "from")
        if edge.incomplete and (from_id in nodes or edge.to in nodes):
            nodes.update((from_id, edge.to))
            edges.add(edge_id)
