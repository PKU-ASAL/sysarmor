"""In-memory window coordinator used by local replay and tests."""

from dataclasses import dataclass, field
from streaming.detection.state import DetectionState
from streaming.windows.accumulator import WindowAccumulator, WindowBatch


@dataclass
class WindowedDetectionState:
    window_size_ns: int = 10_000_000_000
    max_records: int = 256
    detection: DetectionState = field(default_factory=DetectionState)

    def __post_init__(self):
        self._windows = WindowAccumulator(self.window_size_ns, self.max_records)
        self._metrics = {"input_records": 0, "flushed_windows": 0}

    def add(self, record, policies: dict, watermark_ns: int = 0):
        self._metrics["input_records"] += 1
        batches = self._windows.add(record)
        if watermark_ns:
            batches += self._windows.flush_until(watermark_ns)
        return self._process(batches, policies)

    def flush(self, policies: dict, reason: str = "shutdown"):
        return self._process(self._windows.flush_all(reason), policies)

    def metrics(self):
        return {**self._metrics, "pending_records": self._windows.pending_records()}

    def _process(self, batches: tuple[WindowBatch, ...], policies: dict):
        artifacts = []
        for batch in batches:
            artifacts.extend(result for result in self.detection.process_window(batch, policies) if result.artifacts)
            self._metrics["flushed_windows"] += 1
        return tuple(artifacts)
