import unittest
import json
from pathlib import Path


RUN_SCRIPT = Path(__file__).with_name("run.sh")
TEST_MAKEFILE = Path(__file__).resolve().parents[3] / "Makefile"
ATTACK_SCENARIO = TEST_MAKEFILE.parent / "data/scenarios/vm/apt-fileless-c2-local/attack.sh"


class LearningRunContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.script = RUN_SCRIPT.read_text()
        cls.makefile = TEST_MAKEFILE.resolve().read_text()

    def test_prepares_model_before_three_protection_modes(self):
        prepare = self.script.index("prepare_model.py")
        matrix = self.script.index("for protection_mode in rule-only learning-only hybrid")
        self.assertLess(prepare, matrix)
        self.assertIn('run_mode "$protection_mode"', self.script[matrix:])

    def test_does_not_use_learning_enabled_disabled_aliases(self):
        self.assertNotIn("run_variant", self.script)
        self.assertNotIn("learning-disabled", self.script)
        self.assertNotIn("learning-enabled", self.script)

    def test_uses_fixed_policy_fresh_vm_and_serial_activity(self):
        self.assertIn("collection-learning.json", self.script)
        self.assertIn("SYSARMOR_BENCH_PROTECTION_MODE", self.script)
        self.assertIn('SYSARMOR_BENCH_VM_FRESH="${SYSARMOR_LEARNING_VM_FRESH:-1}"', self.script)
        self.assertIn('endpoint-run.log', self.script)
        self.assertIn('failure.txt', self.script)
        self.assertIn('$ROOT/environments/$VM_ENV', self.script)
        self.assertLess(
            self.script.index('mkdir -p "$child_dir"'),
            self.script.index('>"$child_dir/endpoint-run.log"'),
        )
        self.assertIn("SYSARMOR_BENCH_ACTIVITY_MODE=serial", self.script)

    def test_defaults_to_managed_topology_for_stream_graph_recall(self):
        self.assertIn('AGENT_MODE="${SYSARMOR_LEARNING_AGENT_MODE:-managed}"', self.script)
        self.assertIn('VM_ENV="vm-topology"', self.script)
        self.assertIn('SYSARMOR_BENCH_AGENT_MODE="$AGENT_MODE"', self.script)
        self.assertIn('"agent_mode": "$AGENT_MODE"', self.script)

    def test_selects_collection_policy_by_protection_mode(self):
        self.assertIn('if [[ "$protection_mode" == "rule-only" ]]; then', self.script)
        self.assertIn('collection-balanced.json', self.script)
        self.assertIn('collection-learning.json', self.script)
        self.assertIn('collection-hybrid.json', self.script)

    def test_hybrid_collection_uses_one_behavior_shape(self):
        policy = json.loads((TEST_MAKEFILE.parent / "data/policies/collection-hybrid.json").read_text())
        self.assertTrue(all(isinstance(behavior, dict) for behavior in policy["behaviors"]))

    def test_attack_scenario_does_not_execute_payload_for_fixture_checksum(self):
        scenario = ATTACK_SCENARIO.read_text()
        self.assertNotIn('sha256sum "$PAYLOAD"', scenario)

    def test_requires_explicit_training_and_calibration_inputs(self):
        self.assertIn("SYSARMOR_LEARNING_TRAINING_DATA", self.script)
        self.assertIn("SYSARMOR_LEARNING_CALIBRATION_DATA", self.script)
        self.assertIn("training and calibration", self.script)

    def test_persists_public_trust_key_and_dataset_digests(self):
        self.assertIn("trust-key.txt", self.script)
        self.assertIn('"training_digest"', self.script)
        self.assertIn('"calibration_digest"', self.script)

    def test_persists_git_revision_and_dirty_state(self):
        self.assertIn('"git_commit"', self.script)
        self.assertIn('"git_dirty"', self.script)
        self.assertIn('"git_provenance_source"', self.script)
        self.assertIn("status --porcelain", self.script)

    def test_persists_exact_l3_hard_gate_contract(self):
        for contract in (
            '"learning_only_cpu_pct": 30.0',
            '"hybrid_cpu_pct": 15.0',
            '"rss_delta_mb": 16.0',
            '"eps_relative": 0.90',
            '"normal_candidate_rate": 0.01',
            '"attack_campaign_seed_recall": 0.90',
            '"stream_graph_recall": 0.90',
            '"conclusion_recall": 0.90',
        ):
            self.assertIn(contract, self.script)
        for legacy in ("cpu_relative", "cpu_absolute_pp", "rss_absolute_mb", "rss_relative"):
            self.assertNotIn(legacy, self.script)

    def test_exposes_learning_performance_make_target(self):
        self.assertIn("performance-learning", self.makefile)
        self.assertIn("PERFORMANCE_TARGET_learning", Path("Makefile").read_text())


if __name__ == "__main__":
    unittest.main()
