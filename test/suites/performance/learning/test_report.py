import unittest

from report import DEFAULT_GATES, evaluate_ab


def metrics(cpu=2.0, rss=64.0, eps=20.0, evictions=0):
    return {
        "health": {"status": "ok", "learning": "loaded"},
        "reliability": {"sensor_drop": 0, "batcher_drop": 0, "parse_errors": 0},
        "performance": {"agent_cpu_avg_pct": cpu, "agent_rss_max_mb": rss, "eps": eps},
        "stream_evictions": evictions,
        "model_signals": [],
        "rule_truth_ok": True,
        "events": {"e1"},
    }


class LearningReportTest(unittest.TestCase):
    def test_marks_cpu_overhead_as_failed(self):
        disabled = metrics(cpu=2.0)
        enabled = metrics(cpu=4.0)
        result = evaluate_ab(disabled, enabled, DEFAULT_GATES)
        self.assertEqual(result["gates"]["performance_cpu"]["status"], "failed")

    def test_stream_eviction_is_not_a_drop_failure(self):
        disabled = metrics(evictions=10)
        enabled = metrics(evictions=20)
        result = evaluate_ab(disabled, enabled, DEFAULT_GATES)
        self.assertEqual(result["gates"]["reliability"]["status"], "passed")
        self.assertEqual(result["observations"]["stream_evictions"], 30)

    def test_unavailable_metric_does_not_become_zero(self):
        disabled = metrics()
        enabled = metrics()
        enabled["performance"]["eps"] = None
        result = evaluate_ab(disabled, enabled, DEFAULT_GATES)
        self.assertEqual(result["gates"]["performance_eps"]["status"], "unavailable")
        self.assertNotEqual(result["verdict"], "passed")

    def test_unresolved_model_event_reference_fails_model_gate(self):
        disabled = metrics()
        enabled = metrics()
        disabled["health"]["learning"] = "disabled"
        enabled["model_signals"] = [{"eventRefs": ["missing-event"]}]
        result = evaluate_ab(disabled, enabled, DEFAULT_GATES)
        self.assertEqual(result["gates"]["model"]["status"], "failed")

    def test_attack_recall_is_observation_only(self):
        disabled = metrics()
        enabled = metrics()
        disabled["health"]["learning"] = "disabled"
        enabled["model_signals"] = [{"eventRefs": ["e1"]}]
        enabled["rule_truth_ok"] = True
        result = evaluate_ab(disabled, enabled, DEFAULT_GATES)
        self.assertEqual(result["verdict"], "passed")
        self.assertEqual(result["observations"]["model_recall"], 1.0)


if __name__ == "__main__":
    unittest.main()
