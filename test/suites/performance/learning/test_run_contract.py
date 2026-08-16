import unittest
from pathlib import Path


RUN_SCRIPT = Path(__file__).with_name("run.sh")
TEST_MAKEFILE = Path(__file__).resolve().parents[3] / "Makefile"


class LearningRunContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.script = RUN_SCRIPT.read_text()
        cls.makefile = TEST_MAKEFILE.resolve().read_text()

    def test_prepares_model_before_disabled_then_enabled(self):
        prepare = self.script.index("prepare_model.py")
        disabled = self.script.index('run_variant disabled')
        enabled = self.script.index('run_variant enabled')
        self.assertLess(prepare, disabled)
        self.assertLess(disabled, enabled)

    def test_uses_fixed_policy_fresh_vm_and_serial_activity(self):
        self.assertIn("collection-balanced.json", self.script)
        self.assertIn("SYSARMOR_BENCH_VM_FRESH=1", self.script)
        self.assertIn("SYSARMOR_BENCH_ACTIVITY_MODE=serial", self.script)

    def test_requires_explicit_training_and_calibration_inputs(self):
        self.assertIn("SYSARMOR_LEARNING_TRAINING_DATA", self.script)
        self.assertIn("SYSARMOR_LEARNING_CALIBRATION_DATA", self.script)
        self.assertIn("training and calibration", self.script)

    def test_exposes_learning_performance_make_target(self):
        self.assertIn("performance-learning", self.makefile)
        self.assertIn("PERFORMANCE_TARGET_learning", Path("Makefile").read_text())


if __name__ == "__main__":
    unittest.main()
