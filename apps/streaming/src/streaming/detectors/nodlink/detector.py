from __future__ import annotations

import hashlib

from packages.contracts.proto.incident.v1 import incident_pb2
from packages.contracts.proto.signal.v1 import signal_pb2

from streaming.detectors.contracts import (
    cross_lineage_enabled,
    DetectorInputs,
    DetectionFinding,
    DetectionResult,
    RequiredInput,
    StateRequirements,
)
from streaming.detectors.nodlink.campaign import update_campaigns
from streaming.detectors.nodlink.scoring import score_campaign
from streaming.detectors.nodlink.state import NodlinkState
from streaming.detectors.nodlink.terminal import terminals_from_signals


class NodlinkDetector:
    name = "nodlink"
    version = "1"
    required_inputs = (RequiredInput.SIGNAL, RequiredInput.PROVENANCE_EDGE)
    signal_kinds = frozenset({signal_pb2.DETECTOR_KIND_MODEL})
    state_requirements = StateRequirements(keyed=True, version=2)

    def analyze(self, inputs: DetectorInputs) -> DetectionResult:
        state = NodlinkState.decode(inputs.detector_state)
        terminals, rejected = terminals_from_signals(inputs.candidates)
        campaigns = update_campaigns(
            inputs.graph,
            state.campaigns,
            terminals,
            inputs.delta.expired_signal_refs,
            inputs.delta.graph_rebuilt,
            _updated_ns(inputs),
            cross_lineage_enabled(inputs.policy),
        )
        findings = tuple(_finding(inputs.graph, item) for item in campaigns)
        detected = tuple(item for item in findings if item[1].eligible)
        signals = tuple(
            _campaign_signal(campaign, score, inputs.candidates)
            for campaign, score, _ in detected
        )
        evidence = _merge_evidence(item[2] for item in detected)
        connected = _connected_terminals(campaigns)
        contributors = _connected_terminals(item[0] for item in detected)
        detection_findings = tuple(
            _detection_finding(campaign, score, evidence, signal, inputs.candidates)
            for (campaign, score, evidence), signal in zip(detected, signals)
        )
        return DetectionResult(
            algorithm_name=self.name, algorithm_version=self.version,
            derived_signals=signals, conclusions=signals, evidence=evidence,
            event_refs=_event_refs(evidence), edge_refs=tuple(edge.id for edge in evidence.edges),
            signal_refs=tuple(item.signal_id for item in contributors),
            contributors=_contributors(inputs.candidates, contributors),
            node_scores={item.node_id: item.score for item in connected},
            diagnostics=_diagnostics(findings, rejected),
            state_update=NodlinkState(campaigns).encode(),
            findings=detection_findings,
        )

    def diagnostics(self) -> dict:
        return {}


def _finding(graph, campaign):
    evidence = graph.subgraph(set(campaign.node_ids), set(campaign.edge_ids))
    return campaign, score_campaign(campaign, evidence), evidence


def _campaign_signal(campaign, score, candidates):
    terminals = tuple(
        item for item in campaign.terminals if item.node_id in campaign.node_ids
    )
    lineages = tuple(sorted({item.lineage_id for item in terminals if item.lineage_id}))
    labels = _common_labels(
        signal for signal in candidates
        if signal.id in {item.signal_id for item in terminals}
    )
    labels.update({"detector": "nodlink", "campaign_id": campaign.id})
    signal = signal_pb2.Signal(
        id="cloud-sig-nodlink-" + _finding_digest(campaign),
        name="nodlink_campaign", where=signal_pb2.SIGNAL_WHERE_CLOUD,
        stage=signal_pb2.SIGNAL_STAGE_CONCLUSION,
        detector_kind=signal_pb2.DETECTOR_KIND_GRAPH,
        base_risk=score.total, local_rarity=score.max_terminal_score,
        event_refs=sorted({ref for item in terminals for ref in item.event_refs}),
        signal_refs=sorted(item.signal_id for item in terminals if item.signal_id),
        lineage_id=lineages[0] if len(lineages) == 1 else "",
        cross_lineage=len(lineages) > 1,
        labels=labels,
    )
    signal.entities.extend(
        signal_pb2.EntityRef(kind="process", key=item.node_id, role="subject")
        for item in terminals
    )
    return signal


def _detection_finding(campaign, score, evidence, conclusion, candidates):
    terminals = tuple(
        item for item in campaign.terminals if item.node_id in campaign.node_ids
    )
    return DetectionFinding(
        correlation_key=f"nodlink:{campaign.id}",
        conclusion=conclusion,
        evidence=evidence,
        contributors=_contributors(candidates, terminals),
        event_refs=_event_refs(evidence),
        edge_refs=tuple(edge.id for edge in evidence.edges),
        signal_refs=tuple(item.signal_id for item in terminals),
        node_scores={item.node_id: item.score for item in terminals},
    )


def _finding_digest(campaign):
    material = "|".join((campaign.id, *campaign.edge_ids))
    return hashlib.sha256(material.encode()).hexdigest()[:16]


def _common_labels(signals):
    values = tuple(signals)
    if not values:
        return {}
    common = dict(values[0].labels)
    for signal in values[1:]:
        common = {
            key: value for key, value in common.items()
            if signal.labels.get(key) == value
        }
    return common


def _merge_evidence(values):
    nodes, edges = {}, {}
    for value in values:
        nodes.update({item.id: item for item in value.nodes})
        edges.update({item.id: item for item in value.edges})
    result = incident_pb2.EvidenceSubgraph()
    result.nodes.extend(nodes[key] for key in sorted(nodes))
    result.edges.extend(edges[key] for key in sorted(edges))
    return result


def _connected_terminals(campaigns):
    return tuple(
        terminal for campaign in campaigns for terminal in campaign.terminals
        if terminal.node_id in campaign.node_ids
    )


def _contributors(signals, terminals):
    selected = {item.signal_id for item in terminals}
    return tuple(signal for signal in signals if signal.id in selected)


def _event_refs(evidence):
    return tuple(sorted({ref for edge in evidence.edges for ref in edge.event_refs}))


def _updated_ns(inputs):
    if inputs.context is None:
        return 0
    return inputs.context.window_end_ns or inputs.context.watermark_ns


def _diagnostics(findings, rejected):
    return {
        "campaign_count": len(findings),
        "terminal_count": sum(item[1].terminal_count for item in findings),
        "campaigns": tuple(
            {
                "campaign_id": campaign.id,
                "score": score.total,
                "terminal_count": score.terminal_count,
                "edge_count": score.edge_count,
                "eligible": score.eligible,
            }
            for campaign, score, _ in findings
        ),
        "rejected_signals": tuple(
            {"signal_id": item.signal_id, "reason": item.reason} for item in rejected
        ),
    }
