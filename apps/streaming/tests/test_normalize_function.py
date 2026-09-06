import importlib
import unittest

from packages.contracts.proto.streaming.v1 import streaming_pb2

from tests.test_normalizer import candidate_batch, protojson


def load_job():
    return importlib.import_module("streaming.jobs.normalize")


def normalize_function(job):
    try:
        return job.NormalizeFunction()
    except AttributeError as error:
        raise AssertionError("NormalizeFunction is not implemented") from error


class NormalizeFunctionTest(unittest.TestCase):
    def test_valid_batch_uses_only_main_output(self):
        job = load_job()

        output = list(normalize_function(job).process_element(
            protojson(candidate_batch("process-a", ["event-current"])), None
        ))

        self.assertEqual(1, len(output))
        batch = streaming_pb2.NormalizedTelemetryBatch.FromString(output[0])
        self.assertEqual(
            ["event", "signal"],
            [item.WhichOneof("payload") for item in batch.records],
        )
        self.assertEqual("batch-a", batch.batch_id)

    def test_invalid_batch_uses_only_rejection_side_output(self):
        job = load_job()
        batch = candidate_batch("process-a", ["event-current"])
        batch.events[0].event.subject_proc.stable_id = "process-b"

        output = list(normalize_function(job).process_element(protojson(batch), None))

        self.assertEqual(1, len(output))
        tag, value = output[0]
        rejection = streaming_pb2.RejectedTelemetry.FromString(value)
        self.assertEqual(job.REJECTION_TAG.tag_id, tag.tag_id)
        self.assertEqual("candidate_event_subject_mismatch", rejection.reason_code)


if __name__ == "__main__":
    unittest.main()
