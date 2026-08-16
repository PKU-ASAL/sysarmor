import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from pipeline import collect, digest_material, feature_vector, replay, train


class LearningPipelineTest(unittest.TestCase):
    def test_feature_schema_is_deterministic(self):
        event = {"id": "e1", "behavior": "process.exec", "subjectProc": {"argv": ["sh"]}}
        self.assertEqual(feature_vector(event), feature_vector(event))
        self.assertEqual(len(feature_vector(event)), 6)

    def test_feature_schema_treats_empty_subject_as_present(self):
        event = {"id": "e1", "behavior": "process.exec", "subjectProc": {}}
        self.assertEqual(feature_vector(event)[2], 1.0)

    def test_feature_schema_encodes_missing_behavior_explicitly(self):
        self.assertEqual(feature_vector({})[0], -1.0)
        self.assertEqual(feature_vector({"behavior": "  "})[0], -1.0)

    def test_digest_material_binds_float32_parameter_bits(self):
        bundle = {
            "model_ref": "model:normal-v1",
            "model_version": "1",
            "model_digest": "sha256:" + "a" * 64,
            "feature_schema": "FeatureSchemaV1",
            "mean": [0.0] * 6,
            "scale": [1.0] * 6,
            "threshold": 1.0,
        }
        original = digest_material(bundle, True)
        bundle["mean"][0] = 0.0000004
        self.assertNotEqual(digest_material(bundle, True), original)

    def test_digest_material_has_unambiguous_string_boundaries(self):
        bundle = {
            "model_ref": "model:a\n1",
            "model_version": "2",
            "model_digest": "sha256:" + "a" * 64,
            "feature_schema": "FeatureSchemaV1",
            "mean": [0.0] * 6,
            "scale": [1.0] * 6,
            "threshold": 1.0,
        }
        original = digest_material(bundle, True)
        bundle["model_ref"], bundle["model_version"] = "model:a", "1\n2"
        self.assertNotEqual(digest_material(bundle, True), original)

    def test_collect_train_replay_round_trip(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "events.ndjson"
            source.write_text("\n".join([
                json.dumps({"id": "normal-1", "behavior": "process.exec", "labels": {"class": "normal"}}),
                json.dumps({"id": "normal-2", "behavior": "process.exec", "labels": {"class": "normal"}}),
                json.dumps({"id": "odd", "behavior": "network.connect", "object": {"socketAddr": "10.0.0.1:443"}}),
            ]) + "\n")
            normal = root / "normal.ndjson"
            bundle = root / "bundle.json"
            signals = root / "signals.ndjson"
            self.assertEqual(collect(source, normal, "class=normal"), 2)
            trained = train(normal, bundle, 1.0)
            self.assertTrue(trained["model_digest"].startswith("sha256:"))
            self.assertEqual(replay(source, bundle, signals), 1)
            self.assertIn("SIGNAL_STAGE_CANDIDATE", signals.read_text())

    def test_train_quantizes_threshold_for_cross_language_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            events = root / "events.ndjson"
            bundle = root / "bundle.json"
            events.write_text(json.dumps({"id": "normal", "behavior": "process.exec"}) + "\n")

            trained = train(events, bundle, 134.36424497803696)

            self.assertEqual(trained["threshold"], 134.364245)

    def test_replay_rejects_forged_model_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            events = root / "events.ndjson"
            bundle_path = root / "bundle.json"
            output = root / "signals.ndjson"
            events.write_text(json.dumps({"id": "normal", "behavior": "process.exec"}) + "\n")
            bundle = train(events, bundle_path, 1.0)
            bundle["model_digest"] = "sha256:forged"
            bundle["payload_digest"] = "sha256:" + hashlib.sha256(digest_material(bundle, True)).hexdigest()
            bundle_path.write_text(json.dumps(bundle))

            with self.assertRaisesRegex(ValueError, "model digest mismatch"):
                replay(events, bundle_path, output)


if __name__ == "__main__":
    unittest.main()
