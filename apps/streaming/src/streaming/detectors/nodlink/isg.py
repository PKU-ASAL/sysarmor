from dataclasses import dataclass

from streaming.detectors.nodlink.hopset import nearest_hop


@dataclass(frozen=True)
class InformationSubgraph:
    node_ids: tuple[str, ...] = ()
    edge_ids: tuple[str, ...] = ()


def update_isg(graph, current: InformationSubgraph, terminals, max_nodes=128):
    nodes, edges = set(current.node_ids), set(current.edge_ids)
    for terminal in terminals:
        if not graph.has_node(terminal.node_id):
            continue
        if not nodes:
            nodes.add(terminal.node_id)
            continue
        if terminal.node_id in nodes:
            continue
        hop = nearest_hop(graph, terminal.node_id, nodes)
        if hop is not None and len(nodes.union(hop.node_ids)) <= max_nodes:
            nodes.update(hop.node_ids)
            edges.update(hop.edge_ids)
    return InformationSubgraph(tuple(sorted(nodes)), tuple(sorted(edges)))
