import random
from unittest.mock import patch

from streaming.graph.state import ProvenanceEdge, ProvenanceGraph
from streaming.detectors.nodlink.hopset import nearest_hop


def reference(graph, start, targets):
    paths = []
    for target in sorted(targets):
        nodes, edges = graph.shortest_path(start, target)
        if edges and len(nodes) <= 10:
            paths.append((len(edges), target, sorted(nodes), sorted(edges)))
    return min(paths, default=None)


def test_bounded_search_matches_existing_paths():
    rng = random.Random(17)
    graph = ProvenanceGraph()
    for index in range(40):
        graph.add_node(str(index), "process", "subject")
    for index in range(65):
        left, right = rng.sample(range(40), 2)
        graph._add_provenance_edge(ProvenanceEdge(str(index), str(left), str(right), "exec", str(index)))
    for start in map(str, range(40)):
        targets = set(map(str, rng.sample(range(40), 8)))
        expected = reference(graph, start, targets)
        result = nearest_hop(graph, start, targets)
        actual = None if result is None else (len(result.edge_ids), result.target_id, list(result.node_ids), list(result.edge_ids))
        assert actual == expected


def test_nearest_search_does_not_repeat_single_target_bfs():
    graph = ProvenanceGraph()
    for index in range(25):
        graph._add_provenance_edge(ProvenanceEdge(str(index), str(index), str(index + 1), "exec", str(index)))
    with patch.object(graph, "shortest_path", side_effect=AssertionError("repeated BFS")):
        assert nearest_hop(graph, "0", {"10", "25"}) is None
        assert nearest_hop(graph, "0", {"9", "25"}).target_id == "9"
        assert nearest_hop(graph, "0", {"0"}) is None


def test_nearest_path_reuses_same_query_until_graph_changes():
    graph = ProvenanceGraph()
    graph._add_provenance_edge(ProvenanceEdge("e", "0", "1", "exec", "e"))
    assert graph.nearest_path("0", {"1"}, 9) is not None
    assert graph.nearest_path("0", {"1"}, 9) is not None
    assert graph.nearest_path_metrics()["hits"] == 1
    graph._add_provenance_edge(ProvenanceEdge("e2", "1", "2", "exec", "e2"))
    assert graph.nearest_path_metrics()["size"] == 0
