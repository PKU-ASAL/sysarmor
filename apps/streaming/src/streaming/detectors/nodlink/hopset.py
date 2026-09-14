from dataclasses import dataclass

MAX_HOP_NODES = 10


@dataclass(frozen=True)
class Hop:
    terminal_id: str
    target_id: str
    node_ids: tuple[str, ...]
    edge_ids: tuple[str, ...]


def nearest_hop(graph, terminal_id: str, solution_nodes) -> Hop | None:
    path = graph.nearest_path(terminal_id, solution_nodes, MAX_HOP_NODES - 1)
    if path is None:
        return None
    target_id, nodes, edges = path
    return Hop(terminal_id, target_id, tuple(sorted(nodes)), tuple(sorted(edges)))
