import hashlib

from streaming.detectors.nodlink.hopset import nearest_hop
from streaming.detectors.nodlink.isg import InformationSubgraph, update_isg
from streaming.detectors.nodlink.state import Campaign


MAX_CAMPAIGNS = 64
MAX_CAMPAIGN_NODES = 128
MAX_TERMINALS = 128


def update_campaigns(
    graph, campaigns, terminals, expired_refs=(), rebuilt=False,
    updated_ns=0, allow_cross_lineage=False, changed_node_ids=(), changed_edge_ids=(),
):
    active = () if rebuilt else _remove_expired(campaigns, expired_refs)
    active = tuple(
        _rebuild(graph, item) if _campaign_affected(item, changed_node_ids, changed_edge_ids)
        else item
        for item in active
    )
    for terminal in _ranked_terminals(terminals):
        active = _add_terminal(
            graph, active, terminal, updated_ns, allow_cross_lineage
        )
    active = _merge_connected(graph, active, updated_ns, allow_cross_lineage)
    return _bounded_campaigns(active)


def _campaign_affected(campaign, changed_nodes, changed_edges):
    return bool(
        set(campaign.node_ids).intersection(changed_nodes)
        or set(campaign.edge_ids).intersection(changed_edges)
    )


def _add_terminal(graph, campaigns, terminal, updated_ns, allow_cross):
    matches = [
        item for item in campaigns
        if _matches(graph, item, terminal, allow_cross)
    ]
    remaining = [item for item in campaigns if item not in matches]
    terminals = []
    for campaign in matches:
        terminals.extend(campaign.terminals)
    terminals.append(terminal)
    remaining.append(_build(graph, terminals, updated_ns))
    return tuple(remaining)


def _matches(graph, campaign, terminal, allow_cross):
    if campaign.model_digest != terminal.model_digest:
        return False
    if any(item.node_id == terminal.node_id for item in campaign.terminals):
        return True
    if not _lineages_allowed((*campaign.terminals, terminal), allow_cross):
        return False
    return nearest_hop(graph, terminal.node_id, campaign.node_ids) is not None


def _merge_connected(graph, campaigns, updated_ns, allow_cross):
    pending = list(sorted(campaigns, key=lambda item: item.id))
    merged = []
    while pending:
        current = pending.pop(0)
        matches = [
            item for item in pending
            if _campaigns_connect(graph, current, item, allow_cross)
        ]
        if matches:
            pending = [item for item in pending if item not in matches]
            terminals = [item for campaign in (current, *matches) for item in campaign.terminals]
            pending.append(_build(graph, terminals, updated_ns))
        else:
            merged.append(current)
    return tuple(merged)


def _campaigns_connect(graph, left, right, allow_cross):
    if left.model_digest != right.model_digest:
        return False
    if not _lineages_allowed((*left.terminals, *right.terminals), allow_cross):
        return False
    return any(nearest_hop(graph, node, left.node_ids) for node in right.node_ids)


def _build(graph, terminals, updated_ns):
    unique = {item.node_id: item for item in terminals}
    ranked = _ranked_terminals(unique.values())[:MAX_TERMINALS]
    isg = update_isg(
        graph, InformationSubgraph(), ranked, max_nodes=MAX_CAMPAIGN_NODES
    )
    digest = ranked[0].model_digest if ranked else ""
    identity = _campaign_id(digest, ranked)
    return Campaign(identity, digest, ranked, isg.node_ids, isg.edge_ids, updated_ns)


def _rebuild(graph, campaign):
    return _build(graph, campaign.terminals, campaign.updated_ns)


def _remove_expired(campaigns, expired_refs):
    expired = set(expired_refs)
    return tuple(
        Campaign(
            item.id, item.model_digest,
            tuple(terminal for terminal in item.terminals if terminal.signal_id not in expired),
            item.node_ids, item.edge_ids, item.updated_ns,
        )
        for item in campaigns
        if any(terminal.signal_id not in expired for terminal in item.terminals)
    )


def _ranked_terminals(terminals):
    return tuple(sorted(terminals, key=lambda item: (-item.score, item.node_id)))


def _lineages_allowed(terminals, allow_cross):
    lineages = {item.lineage_id for item in terminals if item.lineage_id}
    return allow_cross or len(lineages) <= 1


def _bounded_campaigns(campaigns):
    ranked = sorted(
        campaigns,
        key=lambda item: (-item.updated_ns, item.id),
    )
    return tuple(sorted(ranked[:MAX_CAMPAIGNS], key=lambda item: item.id))


def _campaign_id(model_digest, terminals):
    ordered = sorted(terminals, key=lambda item: item.signal_id)
    material = "|".join((model_digest, *(item.signal_id for item in ordered)))
    return "campaign-" + hashlib.sha256(material.encode()).hexdigest()[:16]
