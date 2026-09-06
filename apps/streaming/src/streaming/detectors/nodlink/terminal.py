from dataclasses import dataclass

from packages.contracts.proto.signal.v1 import signal_pb2

from streaming.engine.provenance import entity_id


@dataclass(frozen=True)
class Terminal:
    node_id: str
    signal_id: str
    score: float
    event_refs: tuple[str, ...]
    lineage_id: str = ""
    model_digest: str = ""


@dataclass(frozen=True)
class RejectedTerminal:
    signal_id: str
    reason: str


def terminals_from_signals(signals):
    terminals, rejected = {}, []
    for signal in signals:
        terminal, reason = _terminal_from_signal(signal)
        if reason:
            rejected.append(RejectedTerminal(signal.id, reason))
        elif terminal is not None:
            key = terminal.node_id, terminal.model_digest
            previous = terminals.get(key)
            if previous is None or _terminal_rank(terminal) < _terminal_rank(previous):
                terminals[key] = terminal
    ordered = tuple(terminals[key] for key in sorted(terminals))
    return ordered, tuple(rejected)


def _terminal_from_signal(signal):
    if signal.where != signal_pb2.SIGNAL_WHERE_ENDPOINT:
        return None, "not_endpoint_signal"
    if not _is_model_candidate(signal):
        return None, "not_model_candidate"
    model_identity = (
        signal.model_ref,
        signal.model_version,
        signal.model_digest,
        signal.feature_schema,
    )
    if not all(model_identity):
        return None, "incomplete_model_identity"
    if not signal.event_refs:
        return None, "missing_event_refs"
    subjects = [
        item for item in signal.entities
        if item.kind.strip().lower() == "process" and item.role.strip().lower() == "subject"
    ]
    if len(subjects) != 1:
        return None, "invalid_process_subject"
    node_id = entity_id("process", subjects[0].key)
    if not node_id:
        return None, "invalid_process_subject"
    return Terminal(
        node_id, signal.id, float(signal.local_rarity),
        tuple(signal.event_refs), signal.lineage_id, signal.model_digest,
    ), ""


def _is_model_candidate(signal):
    return (
        signal.detector_kind == signal_pb2.DETECTOR_KIND_MODEL
        and signal.stage == signal_pb2.SIGNAL_STAGE_CANDIDATE
    )


def _terminal_rank(terminal):
    return -terminal.score, terminal.signal_id
