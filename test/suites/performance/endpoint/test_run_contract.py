import unittest
from pathlib import Path


RUN_SCRIPT = Path(__file__).with_name("run.sh")


class PerformanceEndpointPolicyFlowTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.script = RUN_SCRIPT.read_text()

    def test_applies_detection_after_collection_and_before_activity(self):
        content = self.script.index('apply_content "$policy_out"')
        collection = self.script.index("policy apply collection", content)
        sensor_stable = self.script.index('sleep "$POLICY_SETTLE_SECONDS"', collection)
        detection = self.script.index('apply_detection "$policy_out"', collection)
        activity = self.script.index("run_case_activity", detection)

        self.assertLess(content, collection)
        self.assertLess(collection, sensor_stable)
        self.assertLess(sensor_stable, detection)
        self.assertLess(detection, activity)

    def test_requires_detection_policy_to_be_fully_applied(self):
        self.assertIn("jq -e '.status == \"applied\"'", self.script)

    def test_allows_only_known_minimal_file_read_coverage_gaps(self):
        compact_script = "".join(self.script.split())
        expected_gaps = (
            '[{"rule_id":"credential_file_read","missing_behaviors":["file.read"]},'
            '{"rule_id":"account_database_read","missing_behaviors":["file.read"]}]'
        )

        self.assertIn(expected_gaps, compact_script)

    def test_resets_each_case_before_recording_its_baseline(self):
        loop = self.script.index("for policy in $POLICIES_RAW; do")
        reset = self.script.index('reset_endpoint_policy "$policy_out"', loop)
        recorder = self.script.index('recorder "$rec_run_id" "$rec_labels" start', loop)

        self.assertLess(reset, recorder)
        self.assertIn('source "$ROOT/shared/agent/policy_runtime.sh"', self.script)

    def test_stops_active_recorder_when_the_script_exits_early(self):
        self.assertIn("trap cleanup_active_recorder EXIT", self.script)
        self.assertIn('ACTIVE_REC_RUN_ID="$rec_run_id"', self.script)
        self.assertIn('ACTIVE_REC_RUN_ID=""', self.script)


if __name__ == "__main__":
    unittest.main()
