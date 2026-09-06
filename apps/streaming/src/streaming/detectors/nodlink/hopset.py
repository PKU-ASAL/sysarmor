from dataclasses import dataclass

MAX_HOP_NODES = 10


@dataclass(frozen=True)
class Hop:
    terminal_id: str
    target_id: str
    node_ids: tuple[str, ...]
    edge_ids: tuple[str, ...]


def nearest_hop(graph, terminal_id: str, solution_nodes) -> Hop | None:
    paths = []
    for target_id in sorted(set(solution_nodes)):
        nodes, edges = graph.shortest_path(terminal_id, target_id)
        if edges and len(nodes) <= MAX_HOP_NODES:
            paths.append(Hop(terminal_id, target_id, tuple(sorted(nodes)), tuple(sorted(edges))))
    return min(paths, key=lambda item: (len(item.edge_ids), item.target_id), default=None)
