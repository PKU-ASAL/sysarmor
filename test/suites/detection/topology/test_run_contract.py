import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parent / "run.sh"


class DetectionTopologyContractTest(unittest.TestCase):
    def setUp(self):
        self.script = SCRIPT.read_text()

    def test_detection_cases_request_managed_agent(self):
        self.assertIn('"agent_mode": "$AGENT_MODE"', self.script)
        self.assertIn('"$scenario" "$VM_ENV" "$AGENT_MODE"', self.script)

    def test_manager_capture_is_accounted_as_case_failure(self):
        self.assertIn("if capture_manager_case", self.script)
        self.assertIn("Manager telemetry capture failed", self.script)
        self.assertIn("failed_cases=$((failed_cases + 1))", self.script)

    def test_detection_score_threshold_defaults_to_ninety_percent(self):
        self.assertIn('SYSARMOR_DETECTION_MIN_SCORE:-0.9', self.script)


if __name__ == "__main__":
    unittest.main()
