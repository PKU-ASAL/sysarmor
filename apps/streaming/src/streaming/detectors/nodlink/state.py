import json
from dataclasses import dataclass

from streaming.detectors.nodlink.terminal import Terminal


STATE_VERSION = 2


@dataclass(frozen=True)
class Campaign:
    id: str
    model_digest: str
    terminals: tuple[Terminal, ...] = ()
    node_ids: tuple[str, ...] = ()
    edge_ids: tuple[str, ...] = ()
    updated_ns: int = 0


@dataclass(frozen=True)
class NodlinkState:
    campaigns: tuple[Campaign, ...] = ()

    @property
    def terminals(self):
        return tuple(item for campaign in self.campaigns for item in campaign.terminals)

    def encode(self) -> bytes:
        campaigns = sorted(self.campaigns, key=lambda item: item.id)
        document = {
            "version": STATE_VERSION,
            "campaigns": [_encode_campaign(item) for item in campaigns],
        }
        return json.dumps(document, sort_keys=True, separators=(",", ":")).encode()

    @classmethod
    def decode(cls, value: bytes):
        if not value:
            return cls()
        document = json.loads(value.decode())
        if document.get("version") != STATE_VERSION:
            raise ValueError("unsupported nodlink state version")
        campaigns = tuple(
            _decode_campaign(item) for item in document.get("campaigns", ())
        )
        return cls(campaigns)


def _encode_campaign(campaign):
    return {
        "id": campaign.id,
        "model_digest": campaign.model_digest,
        "terminals": [_encode_terminal(item) for item in campaign.terminals],
        "node_ids": sorted(set(campaign.node_ids)),
        "edge_ids": sorted(set(campaign.edge_ids)),
        "updated_ns": campaign.updated_ns,
    }


def _encode_terminal(terminal):
    return {
        "node_id": terminal.node_id,
        "signal_id": terminal.signal_id,
        "score": float(terminal.score),
        "event_refs": sorted(set(terminal.event_refs)),
        "lineage_id": terminal.lineage_id,
        "model_digest": terminal.model_digest,
    }


def _decode_campaign(value):
    terminals = tuple(_decode_terminal(item) for item in value.get("terminals", ()))
    return Campaign(
        value["id"],
        value["model_digest"],
        terminals,
        tuple(value.get("node_ids", ())),
        tuple(value.get("edge_ids", ())),
        int(value.get("updated_ns", 0)),
    )


def _decode_terminal(value):
    return Terminal(
        value["node_id"],
        value["signal_id"],
        float(value["score"]),
        tuple(value.get("event_refs", ())),
        value.get("lineage_id", ""),
        value.get("model_digest", ""),
    )
