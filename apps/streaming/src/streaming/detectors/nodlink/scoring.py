from dataclasses import dataclass


CAMPAIGN_THRESHOLD = 70


@dataclass(frozen=True)
class CampaignScore:
    total: int
    terminal_count: int
    behavior_count: int
    edge_count: int
    incomplete_edges: int
    max_terminal_score: float

    @property
    def eligible(self):
        return self.terminal_count >= 2 and self.edge_count > 0 and self.total >= CAMPAIGN_THRESHOLD


def score_campaign(campaign, evidence):
    connected = [
        item for item in campaign.terminals if item.node_id in campaign.node_ids
    ]
    behaviors = {edge.kind for edge in evidence.edges}
    incomplete = sum(1 for edge in evidence.edges if edge.incomplete)
    path_excess = max(0, len(evidence.edges) - max(0, len(connected) - 1))
    total = 30 * len(connected) + 10 * len(behaviors)
    if len({item.node_id for item in connected}) >= 2:
        total += 10
    total -= 2 * path_excess + 20 * incomplete
    return CampaignScore(
        max(0, min(100, total)), len(connected), len(behaviors),
        len(evidence.edges), incomplete,
        max((item.score for item in connected), default=0.0),
    )
