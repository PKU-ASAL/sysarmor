import importlib
import unittest

from packages.contracts.proto.event.v1 import event_pb2
from packages.contracts.proto.policy.v1 import policy_pb2
from packages.contracts.proto.signal.v1 import signal_pb2


def load_analysis():
    try:
        return importlib.import_module("sysarmor_streaming.operators.analysis")
    except ModuleNotFoundError as error:
        raise AssertionError("analysis operator is not implemented") from error


class AnalysisTest(unittest.TestCase):
    def test_rule_chains_emit_cloud_conclusions_and_incident(self):
        result = load_analysis().analyze(
            causal_events(),
            [
                endpoint_signal("web_runtime_spawns_shell", "lin-a", process("p-web")),
                endpoint_signal("payload_dropped", "lin-a", file("/dev/shm/x.sh")),
                endpoint_signal(
                    "reverse_shell_pattern",
                    "lin-a",
                    process("p-bash"),
                    socket("10.66.0.99:443"),
                    stage=signal_pb2.SIGNAL_STAGE_CONCLUSION,
                ),
            ],
            policy_pb2.DetectionPolicy(),
        )

        self.assertEqual(
            {"dropped_payload_executed_and_connects", "web_shell_chain"},
            {signal.name for signal in result.cloud_signals},
        )
        for signal in result.cloud_signals:
            self.assertEqual(signal_pb2.SIGNAL_WHERE_CLOUD, signal.where)
            self.assertEqual(signal_pb2.SIGNAL_STAGE_CONCLUSION, signal.stage)
            self.assertEqual(signal_pb2.DETECTOR_KIND_RULE, signal.detector_kind)
        self.assertEqual(1, len(result.incidents))
        self.assertEqual("rarity+causal-topk", result.incidents[0].converge.method)

    def test_model_candidate_alone_does_not_create_incident(self):
        candidate = endpoint_signal(
            "learning_anomaly",
            "lin-a",
            process("p-bash"),
            detector_kind=signal_pb2.DETECTOR_KIND_MODEL,
        )

        result = load_analysis().analyze([], [candidate], policy_pb2.DetectionPolicy())

        self.assertEqual((), result.cloud_signals)
        self.assertEqual((), result.incidents)

    def test_model_candidates_cannot_compose_rule_conclusion(self):
        signals = [
            endpoint_signal(
                "payload_dropped",
                "lin-a",
                file("/tmp/payload"),
                detector_kind=signal_pb2.DETECTOR_KIND_MODEL,
            ),
            endpoint_signal(
                "suspicious_exec_connect",
                "lin-b",
                file("/tmp/payload"),
                detector_kind=signal_pb2.DETECTOR_KIND_MODEL,
            ),
        ]
        policy = policy_pb2.DetectionPolicy(
            converge=policy_pb2.ConvergeParams(cross_lineage=True)
        )

        result = load_analysis().analyze([], signals, policy)

        self.assertEqual((), result.cloud_signals)
        self.assertEqual((), result.incidents)

    def test_cross_lineage_correlation_obeys_policy(self):
        signals = [
            endpoint_signal("payload_dropped", "lin-a", file("/tmp/payload"), signal_id="drop-a"),
            endpoint_signal(
                "suspicious_exec_connect",
                "lin-b",
                file("/tmp/payload"),
                socket("10.66.0.99:443"),
                signal_id="exec-a",
            ),
        ]
        enabled = policy_pb2.DetectionPolicy(
            converge=policy_pb2.ConvergeParams(cross_lineage=True)
        )
        disabled = policy_pb2.DetectionPolicy(
            converge=policy_pb2.ConvergeParams(cross_lineage=False)
        )

        linked = load_analysis().analyze([], signals, enabled)
        isolated = load_analysis().analyze([], signals, disabled)

        self.assertEqual(1, len(linked.cloud_signals))
        self.assertTrue(linked.cloud_signals[0].cross_lineage)
        self.assertEqual(["drop-a", "exec-a"], list(linked.cloud_signals[0].signal_refs))
        self.assertEqual(1, len(linked.incidents))
        self.assertEqual((), isolated.cloud_signals)
        self.assertEqual((), isolated.incidents)

    def test_cross_lineage_requires_shared_entity_or_provenance_path(self):
        signals = [
            endpoint_signal("payload_dropped", "lin-a", file("/tmp/a")),
            endpoint_signal(
                "suspicious_exec_connect", "lin-b", socket("10.0.0.1:443")
            ),
        ]
        policy = policy_pb2.DetectionPolicy(
            converge=policy_pb2.ConvergeParams(cross_lineage=True)
        )

        result = load_analysis().analyze([], signals, policy)

        self.assertEqual((), result.cloud_signals)
        self.assertEqual((), result.incidents)

    def test_disabled_cross_lineage_blocks_different_lineage_conclusion(self):
        signals = [
            endpoint_signal("payload_dropped", "lin-a", file("/tmp/payload")),
            endpoint_signal(
                "reverse_shell_pattern",
                "lin-b",
                process("p-bash"),
                stage=signal_pb2.SIGNAL_STAGE_CONCLUSION,
            ),
        ]
        policy = policy_pb2.DetectionPolicy(
            converge=policy_pb2.ConvergeParams(cross_lineage=False)
        )

        result = load_analysis().analyze([], signals, policy)

        self.assertEqual((), result.cloud_signals)

    def test_ids_are_stable_and_incident_recovers_intermediate_evidence(self):
        signals = [
            endpoint_signal(
                "payload_dropped",
                "lin-a",
                process("p-shell"),
                file("/dev/shm/x.sh"),
                signal_id="drop-a",
            ),
            endpoint_signal(
                "suspicious_exec_connect",
                "lin-b",
                socket("10.66.0.99:443"),
                signal_id="exec-a",
            ),
        ]
        policy = policy_pb2.DetectionPolicy(
            converge=policy_pb2.ConvergeParams(cross_lineage=True)
        )

        first = load_analysis().analyze(causal_events(), signals, policy)
        second = load_analysis().analyze(causal_events(), list(reversed(signals)), policy)

        self.assertEqual(first.cloud_signals[0].id, second.cloud_signals[0].id)
        self.assertEqual(first.incidents[0].id, second.incidents[0].id)
        evidence = first.incidents[0].evidence
        self.assertIn("process:p-bash", {node.id for node in evidence.nodes})
        self.assertIn(
            "exec-bash", {ref for edge in evidence.edges for ref in edge.event_refs}
        )

    def test_analyze_is_deterministic_across_repeated_calls(self):
        signals = [
            endpoint_signal("payload_dropped", "lin-a", file("/tmp/payload"), signal_id="drop-a"),
            endpoint_signal(
                "reverse_shell_pattern",
                "lin-a",
                process("p-bash"),
                stage=signal_pb2.SIGNAL_STAGE_CONCLUSION,
                signal_id="shell-a",
            ),
        ]
        policy = policy_pb2.DetectionPolicy()

        first = load_analysis().analyze(causal_events(), signals, policy)
        second = load_analysis().analyze(causal_events(), signals, policy)

        self.assertEqual(
            [signal.id for signal in first.cloud_signals],
            [signal.id for signal in second.cloud_signals],
        )
        self.assertEqual(first.incidents[0].id, second.incidents[0].id)

    def test_additive_threshold_requires_a_conclusion(self):
        policy = policy_pb2.DetectionPolicy(
            converge=policy_pb2.ConvergeParams(
                mode="additive_threshold", additive_risk_threshold=100
            )
        )
        candidates = [
            endpoint_signal("download", "lin-a", socket("10.0.0.1:80")),
            endpoint_signal("download", "lin-a", socket("10.0.0.1:80")),
        ]
        rejected = load_analysis().analyze([], candidates, policy)
        with_conclusion = list(candidates)
        with_conclusion[0].stage = signal_pb2.SIGNAL_STAGE_CONCLUSION

        accepted = load_analysis().analyze([], with_conclusion, policy)

        self.assertEqual((), rejected.incidents)
        self.assertEqual(1, len(accepted.incidents))
        self.assertEqual("additive_threshold", accepted.incidents[0].converge.method)

    def test_incident_contains_only_signals_that_contributed_to_match(self):
        policy = policy_pb2.DetectionPolicy(
            endpoint_rules=["payload_dropped", "reverse_shell_pattern"]
        )
        relevant = [
            endpoint_signal("payload_dropped", "lin-a", file("/tmp/payload")),
            endpoint_signal(
                "reverse_shell_pattern",
                "lin-a",
                process("p-bash"),
                stage=signal_pb2.SIGNAL_STAGE_CONCLUSION,
            ),
        ]
        baseline = load_analysis().analyze([], relevant, policy)
        noise = endpoint_signal("disabled_noise", "lin-z", process("p-noise"))
        noise.labels["scenario"] = "noise"
        polluted = load_analysis().analyze(
            [],
            [*relevant, noise],
            policy,
        )

        self.assertEqual(baseline.cloud_signals[0].id, polluted.cloud_signals[0].id)
        self.assertEqual(baseline.incidents[0].id, polluted.incidents[0].id)
        self.assertEqual({"scenario": "analysis"}, dict(polluted.cloud_signals[0].labels))
        self.assertEqual(
            3, len(polluted.incidents[0].contributing_signals)
        )

    def test_payload_chain_preserves_related_download_evidence(self):
        events = [
            event(
                "connect-download",
                "network.connect",
                "p-curl",
                socket_addr="10.66.0.99:8080",
            ),
            *causal_events(),
        ]
        signals = [
            endpoint_signal(
                "download_by_lolbin",
                "lin-a",
                process("p-curl"),
                socket("10.66.0.99:8080"),
                signal_id="download-a",
            ),
            endpoint_signal(
                "payload_dropped",
                "lin-a",
                process("p-curl"),
                file("/dev/shm/x.sh"),
                signal_id="drop-a",
            ),
            endpoint_signal(
                "reverse_shell_pattern",
                "lin-a",
                process("p-bash"),
                socket("10.66.0.99:443"),
                signal_id="shell-a",
                stage=signal_pb2.SIGNAL_STAGE_CONCLUSION,
            ),
        ]

        result = load_analysis().analyze(
            events, signals, policy_pb2.DetectionPolicy()
        )

        incident = result.incidents[0]
        self.assertIn(
            "download_by_lolbin",
            {signal.name for signal in incident.contributing_signals},
        )
        self.assertIn(
            "connect-download",
            {ref for edge in incident.evidence.edges for ref in edge.event_refs},
        )

    def test_additive_threshold_preserves_identical_observations(self):
        policy = policy_pb2.DetectionPolicy(
            converge=policy_pb2.ConvergeParams(
                mode="additive_threshold", additive_risk_threshold=100
            )
        )
        first = endpoint_signal(
            "download",
            "lin-a",
            socket("10.0.0.1:80"),
            stage=signal_pb2.SIGNAL_STAGE_CONCLUSION,
        )
        second = signal_pb2.Signal()
        second.CopyFrom(first)

        result = load_analysis().analyze([], [first, second], policy)

        self.assertEqual(2, len(result.incidents[0].contributing_signals))
        self.assertEqual(75, result.incidents[0].converge.score)

    def test_additive_threshold_preserves_repeated_object_observations(self):
        policy = policy_pb2.DetectionPolicy(
            converge=policy_pb2.ConvergeParams(
                mode="additive_threshold", additive_risk_threshold=100
            )
        )
        signal = endpoint_signal(
            "download",
            "lin-a",
            socket("10.0.0.1:80"),
            stage=signal_pb2.SIGNAL_STAGE_CONCLUSION,
        )

        result = load_analysis().analyze([], [signal, signal], policy)

        self.assertEqual(2, len(result.incidents[0].contributing_signals))
        self.assertEqual(75, result.incidents[0].converge.score)


def endpoint_signal(
    name,
    lineage,
    *entities,
    signal_id="",
    stage=signal_pb2.SIGNAL_STAGE_CANDIDATE,
    detector_kind=signal_pb2.DETECTOR_KIND_RULE,
):
    return signal_pb2.Signal(
        id=signal_id,
        name=name,
        where=signal_pb2.SIGNAL_WHERE_ENDPOINT,
        base_risk=50,
        global_rarity=1,
        lineage_id=lineage,
        entities=entities,
        labels={"scenario": "analysis"},
        stage=stage,
        detector_kind=detector_kind,
    )


def process(key):
    return signal_pb2.EntityRef(kind="process", key=key, role="subject")


def file(key):
    return signal_pb2.EntityRef(kind="file", key=key, role="object")


def socket(key):
    return signal_pb2.EntityRef(kind="socket", key=key, role="object")


def causal_events():
    return [
        event("exec-curl", "process.exec", "p-curl", parent="p-shell"),
        event("write-payload", "file.write", "p-curl", file_path="/dev/shm/x.sh"),
        event("exec-bash", "process.exec", "p-bash", parent="p-curl"),
        event(
            "connect-c2",
            "network.connect",
            "p-bash",
            socket_addr="10.66.0.99:443",
        ),
    ]


def event(event_id, behavior, stable_id, parent="", file_path="", socket_addr=""):
    return event_pb2.CanonicalEvent(
        id=event_id,
        behavior=behavior,
        subject_proc=event_pb2.ProcessRef(stable_id=stable_id),
        parent_stable_id=parent,
        object=event_pb2.ObjectRef(file_path=file_path, socket_addr=socket_addr),
    )


if __name__ == "__main__":
    unittest.main()
