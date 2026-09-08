import unittest
from unittest import mock

from packages.contracts.proto.streaming.v1 import streaming_pb2
from streaming.engine.windowed_detection import WindowedDetectionState


def record(sequence, observed_ns):
    return streaming_pb2.NormalizedTelemetry(
        context=streaming_pb2.RecordContext(
            tenant_id="tenant-a", agent_id="agent-a", analysis_scope_key="scope-a",
            policy_id="policy-a", policy_version=1,
            record_sequence=sequence, observed_at_unix_nano=observed_ns,
        ),
        event=__import__("packages.contracts.proto.event.v1", fromlist=["event_pb2"]).event_pb2.CanonicalEvent(
            id=f"event-{sequence}", occurred_at_ns=observed_ns,
        ),
    )


class WindowedDetectionStateTest(unittest.TestCase):
    def test_records_in_one_window_are_processed_once_at_watermark(self):
        state = WindowedDetectionState(window_size_ns=10, max_records=100)
        with mock.patch.object(state.detection, "process_window", return_value=[]) as process:
            self.assertEqual((), state.add(record(1, 3), {}))
            self.assertEqual((), state.add(record(2, 8), {}))
            self.assertEqual([], process.call_args_list)
            state.add(record(3, 12), {}, watermark_ns=10)
        self.assertEqual(1, process.call_count)
        batch = process.call_args.args[0]
        self.assertEqual(("event-1", "event-2"), tuple(item.event.id for item in batch.records))
        self.assertEqual("watermark", batch.flush_reason)

    def test_count_flush_is_bounded_and_metrics_expose_pending_records(self):
        state = WindowedDetectionState(window_size_ns=10, max_records=2)
        with mock.patch.object(state.detection, "process_window", return_value=[]):
            state.add(record(1, 1), {})
            self.assertEqual(1, state.metrics()["pending_records"])
            state.add(record(2, 2), {})
        self.assertEqual(0, state.metrics()["pending_records"])
        self.assertEqual(1, state.metrics()["flushed_windows"])


if __name__ == "__main__":
    unittest.main()
