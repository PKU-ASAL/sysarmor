"""Windowed facade that batches records before invoking DetectionState."""

from dataclasses import dataclass, field

from streaming.engine.detection_state import DetectionState
from streaming.engine.window import WindowAccumulator, WindowBatch


@dataclass
class WindowedDetectionState:
    """Collect records and run one DetectionState computation per window."""

    window_size_ns: int = 10_000_000_000
    max_records: int = 256
    detection: DetectionState = field(default_factory=DetectionState)

    def __post_init__(self):
        self._windows = WindowAccumulator(self.window_size_ns, self.max_records)
        self._metrics = {"input_records": 0, "flushed_windows": 0, "pending_records": 0}

    def add(self, record, policies: dict, watermark_ns: int = 0):
        self._metrics["input_records"] += 1
        batches = self._windows.add(record)
        if watermark_ns:
            batches += self._windows.flush_until(watermark_ns)
        return self._process(batches, policies)

    def flush(self, policies: dict, reason: str = "shutdown"):
        return self._process(self._windows.flush_all(reason), policies)

    def metrics(self) -> dict[str, int]:
        return {**self._metrics, "pending_records": self._windows.pending_records()}

    def _process(self, batches: tuple[WindowBatch, ...], policies: dict):
        artifacts = []
        for batch in batches:
            results = self.detection.process_window(batch, policies)
            artifacts.extend(result for result in results if result.artifacts)
            self._metrics["flushed_windows"] += 1
        return tuple(artifacts)
