import importlib
import unittest

from google.protobuf import json_format
from packages.contracts.proto.dataplane.v1 import dataplane_pb2
from packages.contracts.proto.event.v1 import event_pb2
from packages.contracts.proto.signal.v1 import signal_pb2


def load_normalizer():
    try:
        return importlib.import_module("sysarmor_streaming.operators.normalizer")
    except ModuleNotFoundError as error:
        raise AssertionError("normalizer operator is not implemented") from error


class NormalizerTest(unittest.TestCase):
    def test_valid_batch_emits_versioned_event_and_candidate_records(self):
        normalizer = load_normalizer()
        batch = candidate_batch("process-a", ["event-current"])

        result = normalizer.normalize_batch(protojson(batch))

        self.assertIsNone(result.rejection)
        self.assertEqual(2, len(result.records))
        event_record, signal_record = result.records
        self.assertEqual("sysarmor.telemetry.normalized/v1", event_record.schema_version)
        self.assertEqual("event", event_record.WhichOneof("payload"))
        self.assertEqual("signal", signal_record.WhichOneof("payload"))
        self.assertEqual("tenant-a", event_record.event.tenant_id)
        self.assertEqual("tenant-a", event_record.context.tenant_id)
        self.assertEqual("agent-a", event_record.context.agent_id)
        self.assertEqual("policy-a", event_record.context.policy_id)
        self.assertEqual(7, event_record.context.policy_version)
        self.assertEqual(
            "policy_id=policy-a,policy_version=7,scenario=normalizer",
            event_record.context.analysis_scope_key,
        )

    def test_subject_mismatch_rejects_whole_batch(self):
        normalizer = load_normalizer()
        batch = candidate_batch("process-a", ["event-current"])
        batch.events[0].event.subject_proc.stable_id = "process-b"

        result = normalizer.normalize_batch(protojson(batch))

        self.assertEqual((), result.records)
        self.assertEqual(
            "candidate_event_subject_mismatch", result.rejection.reason_code
        )
        self.assertEqual("batch-a", result.rejection.batch_id)

    def test_invalid_json_is_explicitly_rejected(self):
        normalizer = load_normalizer()

        result = normalizer.normalize_batch(b"not-json")

        self.assertEqual((), result.records)
        self.assertEqual("invalid_data_batch", result.rejection.reason_code)

    def test_declared_frame_count_mismatch_rejects_whole_batch(self):
        normalizer = load_normalizer()
        batch = candidate_batch("process-a", ["event-current"])
        batch.header.event_count = 2

        result = normalizer.normalize_batch(protojson(batch))

        self.assertEqual((), result.records)
        self.assertEqual("invalid_data_batch", result.rejection.reason_code)


def candidate_batch(subject: str, event_refs: list[str]) -> dataplane_pb2.DataBatch:
    labels = {
        "policy_id": "policy-a",
        "policy_version": "7",
        "scenario": "normalizer",
    }
    batch = dataplane_pb2.DataBatch(
        schema_version="sysarmor.dataplane/v1",
        header=dataplane_pb2.BatchHeader(
            batch_id="batch-a",
            tenant_id="tenant-a",
            agent_id="agent-a",
            host_id="host-a",
            policy_id="policy-a",
            policy_version=7,
            policy_mode="hybrid",
            created_at_unix_nano=1_700_000_000_000_000_000,
            event_count=1,
            signal_count=1,
        ),
    )
    batch.events.append(
        dataplane_pb2.EventFrame(
            sequence=1,
            observed_at="2023-11-14T22:13:20Z",
            event=event_pb2.CanonicalEvent(
                id="event-current",
                tenant_id="tenant-a",
                behavior="process.exec",
                subject_proc=event_pb2.ProcessRef(stable_id=subject),
                labels=labels,
            ),
        )
    )
    batch.signals.append(
        dataplane_pb2.SignalFrame(
            sequence=1,
            observed_at="2023-11-14T22:13:20Z",
            signal=signal_pb2.Signal(
                id="candidate-a",
                detector_kind=signal_pb2.DETECTOR_KIND_MODEL,
                stage=signal_pb2.SIGNAL_STAGE_CANDIDATE,
                event_refs=event_refs,
                entities=[
                    signal_pb2.EntityRef(
                        kind="process", key=subject, role="subject"
                    )
                ],
                labels=labels,
            ),
        )
    )
    return batch


def protojson(message) -> bytes:
    return json_format.MessageToJson(message).encode()


if __name__ == "__main__":
    unittest.main()
