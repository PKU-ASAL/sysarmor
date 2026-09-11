"""Window-level input contract for streaming detectors."""

from dataclasses import dataclass, field


@dataclass(frozen=True)
class WindowBatch:
    """One bounded event-time computation unit for a keyed analysis scope."""

    records: tuple
    window_start_ns: int
    window_end_ns: int
    watermark_ns: int = 0
    flush_reason: str = "count"
    expired_event_refs: tuple[str, ...] = ()
    expired_signal_refs: tuple[str, ...] = ()

    @property
    def events(self) -> tuple:
        return tuple(record for record in self.records if record.WhichOneof("payload") == "event")

    @property
    def signals(self) -> tuple:
        return tuple(record for record in self.records if record.WhichOneof("payload") == "signal")


@dataclass
class WindowAccumulator:
    window_size_ns: int = 10_000_000_000
    max_records: int = 256
    _windows: dict[tuple[str, str, str, int], list] = field(default_factory=dict)

    def __post_init__(self):
        if self.window_size_ns <= 0 or self.max_records <= 0:
            raise ValueError("window size and max records must be positive")

    def add(self, record) -> tuple[WindowBatch, ...]:
        scope = (
            record.context.tenant_id,
            record.context.agent_id,
            record.context.analysis_scope_key,
        )
        timestamp = _observed_ns(record)
        start = timestamp // self.window_size_ns * self.window_size_ns
        key = (*scope, start)
        values = self._windows.setdefault(key, [])
        values.append(record)
        if len(values) < self.max_records:
            return ()
        return self._flush(key, "count", timestamp)

    def flush_until(self, watermark_ns: int) -> tuple[WindowBatch, ...]:
        ready = [key for key in self._windows if key[3] + self.window_size_ns <= watermark_ns]
        return tuple(batch for key in sorted(ready) for batch in self._flush(key, "watermark", watermark_ns))

    def flush_all(self, reason: str = "shutdown") -> tuple[WindowBatch, ...]:
        return tuple(batch for key in sorted(self._windows) for batch in self._flush(key, reason, 0))

    def pending_records(self) -> int:
        return sum(len(values) for values in self._windows.values())

    def _flush(self, key, reason: str, watermark_ns: int) -> tuple[WindowBatch, ...]:
        records = tuple(self._windows.pop(key))
        start = key[3]
        return (WindowBatch(records, start, start + self.window_size_ns, watermark_ns, reason),)


def _observed_ns(record) -> int:
    if record.WhichOneof("payload") == "event" and record.event.occurred_at_ns:
        return record.event.occurred_at_ns
    return record.context.observed_at_unix_nano
