import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("monotonic_policy.py")
UINT64_MAX = 2**64 - 1


class MonotonicPolicyTest(unittest.TestCase):
    def generate(self, current_version):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            current = root / "current.json"
            template = root / "template.json"
            output = root / "baseline.json"
            current.write_text(json.dumps({"version": current_version}))
            template.write_text(json.dumps({"policy_id": "standalone-default", "version": 1}))
            result = subprocess.run(
                [sys.executable, SCRIPT, current, template, output],
                capture_output=True,
                text=True,
                check=False,
            )
            document = json.loads(output.read_text()) if output.exists() else None
            return result, document

    def test_increments_protojson_string_version(self):
        result, document = self.generate("1")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "2")
        self.assertEqual(document["version"], 2)

    def test_preserves_precision_above_javascript_safe_integer(self):
        result, document = self.generate("9007199254740993")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "9007199254740994")
        self.assertEqual(document["version"], 9007199254740994)

    def test_supports_largest_incrementable_uint64(self):
        result, document = self.generate(str(UINT64_MAX - 1))

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), str(UINT64_MAX))
        self.assertEqual(document["version"], UINT64_MAX)

    def test_rejects_uint64_max(self):
        result, document = self.generate(str(UINT64_MAX))

        self.assertNotEqual(result.returncode, 0)
        self.assertIsNone(document)
        self.assertIn("cannot increment", result.stderr)

    def test_rejects_invalid_versions(self):
        for version in (-1, "01", "1.5", True, None):
            with self.subTest(version=version):
                result, document = self.generate(version)
                self.assertNotEqual(result.returncode, 0)
                self.assertIsNone(document)


if __name__ == "__main__":
    unittest.main()
