import importlib
import unittest

from packages.contracts.proto.event.v1 import event_pb2
from packages.contracts.proto.policy.v1 import policy_pb2
from packages.contracts.proto.signal.v1 import signal_pb2
from packages.contracts.proto.streaming.v1 import streaming_pb2


def load_state():
    try:
        return importlib.import_module("sysarmor_streaming.operators.detection_state")
    except ModuleNotFoundError as error:
        raise AssertionError("detection state is not implemented") from error


class DetectionStateTest(unittest.TestCase):
    def test_missing_exact_policy_fails_without_state_mutation(self):
        state = load_state().DetectionState()
        record = event_record("scope-a", "policy-a", 7, 100, "event-a")

        result = state.process(record, watermark_ns=0, policies={})

        self.assertEqual("policy_version_unavailable", result.failure.reason_code)
        self.assertTrue(result.failure.retryable)
        self.assertEqual(0, state.event_count("scope-a"))
        self.assertEqual((), result.artifacts)

    def test_event_and_signal_share_scope_and_emit_analysis_artifacts(self):
        state = load_state().DetectionState()
        policy = detection_policy("tenant-a", "policy-a", 7)
        event = event_record("scope-a", "policy-a", 7, 100, "event-a")
        signal = signal_record(
            "scope-a",
            "policy-a",
            7,
            110,
            "reverse_shell_pattern",
            stage=signal_pb2.SIGNAL_STAGE_CONCLUSION,
        )

        first = state.process(event, watermark_ns=0, policies={policy_key(policy): policy})
        second = state.process(signal, watermark_ns=0, policies={policy_key(policy): policy})

        self.assertIsNone(first.failure)
        self.assertEqual(1, state.event_count("scope-a"))
        self.assertEqual(1, state.signal_count("scope-a"))
        self.assertTrue(any(item.WhichOneof("payload") == "incident" for item in second.artifacts))

    def test_late_record_is_side_output_and_does_not_mutate_detection_state(self):
        state = load_state().DetectionState()
        policy = detection_policy("tenant-a", "policy-a", 7)
        record = event_record("scope-a", "policy-a", 7, 100, "event-late")

        result = state.process(record, watermark_ns=101, policies={policy_key(policy): policy})

        self.assertIsNone(result.failure)
        self.assertEqual(100, result.late.telemetry.event.occurred_at_ns)
        self.assertEqual(101, result.late.watermark_unix_nano)
        self.assertEqual(0, state.event_count("scope-a"))

    def test_window_eviction_removes_old_events_before_next_analysis(self):
        state = load_state().DetectionState()
        policy = detection_policy("tenant-a", "policy-a", 7, state_retention_ns=10)
        values = {policy_key(policy): policy}

        state.process(event_record("scope-a", "policy-a", 7, 100, "old"), 0, values)
        state.process(event_record("scope-a", "policy-a", 7, 120, "new"), 0, values)

        self.assertEqual(1, state.event_count("scope-a"))
        self.assertEqual({"new"}, state.event_ids("scope-a"))

    def test_scope_capacity_is_bounded_independently_of_retention_window(self):
        state = load_state().DetectionState(max_scope_records=2)
        policy = detection_policy("tenant-a", "policy-a", 7, state_retention_ns=1000)
        values = {policy_key(policy): policy}

        for observed, event_id in ((100, "first"), (110, "second"), (120, "third")):
            state.process(
                event_record("scope-a", "policy-a", 7, observed, event_id), 0, values
            )

        self.assertEqual({"second", "third"}, state.event_ids("scope-a"))

    def test_established_incident_is_not_reemitted_for_unrelated_event(self):
        state = load_state().DetectionState()
        policy = detection_policy("tenant-a", "policy-a", 7)
        values = {policy_key(policy): policy}
        conclusion = signal_record(
            "scope-a",
            "policy-a",
            7,
            100,
            "reverse_shell_pattern",
            signal_pb2.SIGNAL_STAGE_CONCLUSION,
        )

        first = state.process(conclusion, 0, values)
        second = state.process(
            event_record("scope-a", "policy-a", 7, 110, "unrelated"), 0, values
        )

        self.assertEqual(1, len(first.artifacts))
        self.assertEqual((), second.artifacts)
        self.assertEqual(1, len(state.emissions("scope-a")))


def detection_policy(tenant, policy_id, version, state_retention_ns=1000):
    return streaming_pb2.DetectionPolicySnapshot(
        schema_version="sysarmor.detection.policy/v1",
        tenant_id=tenant,
        policy_id=policy_id,
        policy_version=version,
        detection=policy_pb2.DetectionPolicy(
            endpoint_rules=["reverse_shell_pattern"],
            converge=policy_pb2.ConvergeParams(state_retention_ns=state_retention_ns),
            rarity=policy_pb2.RarityParams(baseline_window_ns=86_400_000_000_000),
        ),
    )


def policy_key(policy):
    return (policy.tenant_id, policy.policy_id, policy.policy_version)


def context(scope, policy_id, version, observed):
    return streaming_pb2.RecordContext(
        tenant_id="tenant-a",
        agent_id="agent-a",
        host_id="host-a",
        batch_id="batch-a",
        policy_id=policy_id,
        policy_version=version,
        policy_mode="rule-only",
        observed_at_unix_nano=observed,
        analysis_scope_key=scope,
    )


def event_record(scope, policy_id, version, observed, event_id):
    return streaming_pb2.NormalizedTelemetry(
        schema_version="sysarmor.telemetry.normalized/v1",
        context=context(scope, policy_id, version, observed),
        event=event_pb2.CanonicalEvent(
            id=event_id,
            tenant_id="tenant-a",
            occurred_at_ns=observed,
            behavior="process.exec",
            subject_proc=event_pb2.ProcessRef(stable_id="p-bash"),
        ),
    )


def signal_record(scope, policy_id, version, observed, name, stage):
    return streaming_pb2.NormalizedTelemetry(
        schema_version="sysarmor.telemetry.normalized/v1",
        context=context(scope, policy_id, version, observed),
        signal=signal_pb2.Signal(
            id="signal-" + name,
            name=name,
            where=signal_pb2.SIGNAL_WHERE_ENDPOINT,
            detector_kind=signal_pb2.DETECTOR_KIND_RULE,
            stage=stage,
            entities=[signal_pb2.EntityRef(kind="process", key="p-bash", role="subject")],
        ),
    )


if __name__ == "__main__":
    unittest.main()
