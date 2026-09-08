import unittest

from packages.contracts.proto.streaming.v1 import streaming_pb2
from streaming.engine.window import WindowAccumulator


def record(scope, observed_ns, sequence):
    return streaming_pb2.NormalizedTelemetry(
        context=streaming_pb2.RecordContext(
            analysis_scope_key=scope,
            observed_at_unix_nano=observed_ns,
            record_sequence=sequence,
        ),
        event=__import__("packages.contracts.proto.event.v1", fromlist=["event_pb2"]).event_pb2.CanonicalEvent(
            id=f"event-{sequence}", occurred_at_ns=observed_ns,
        ),
    )


class WindowAccumulatorTest(unittest.TestCase):
    def test_groups_records_by_event_time_and_flushes_on_watermark(self):
        accumulator = WindowAccumulator(window_size_ns=10, max_records=10)
        self.assertEqual((), accumulator.add(record("scope-a", 3, 1)))
        self.assertEqual((), accumulator.add(record("scope-a", 8, 2)))
        batches = accumulator.flush_until(10)
        self.assertEqual(1, len(batches))
        self.assertEqual(("event-1", "event-2"), tuple(item.event.id for item in batches[0].records))
        self.assertEqual("watermark", batches[0].flush_reason)

    def test_count_flush_keeps_window_boundary(self):
        accumulator = WindowAccumulator(window_size_ns=10, max_records=2)
        batches = accumulator.add(record("scope-a", 11, 1))
        self.assertEqual((), batches)
        batches = accumulator.add(record("scope-a", 12, 2))
        self.assertEqual((10,), tuple(item.window_start_ns for item in batches))
        self.assertEqual("count", batches[0].flush_reason)
        self.assertEqual(0, accumulator.pending_records())


if __name__ == "__main__":
    unittest.main()
