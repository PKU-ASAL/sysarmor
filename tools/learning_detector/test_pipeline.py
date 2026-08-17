import json
import math
import tempfile
import unittest
from pathlib import Path

from inference import natural_tokens, profile_vector, score_profile
from model_bundle import validate_bundle
from profile_dataset import read_profiles
from training import TrainingConfig, idf_weights, stability_scores, train_bundle


class LearningPipelineTest(unittest.TestCase):
    def test_reconstructs_process_profile_lifecycle(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "events.ndjson"
            source.write_text("\n".join([
                json.dumps({"id": "e1", "behavior": "process.exec", "subjectProc": {
                    "stableId": "p1", "binary": "/bin/bash", "argv": ["bash", "-c", "cat /etc/hosts"]}}),
                json.dumps({"id": "e2", "behavior": "file.read", "subjectProc": {"stableId": "p1"},
                            "object": {"filePath": "/etc/hosts"}}),
                json.dumps({"id": "e3", "behavior": "process.exit", "subjectProc": {"stableId": "p1"}}),
            ]) + "\n")
            profiles = read_profiles(source)
        self.assertEqual(len(profiles), 1)
        self.assertEqual(profiles[0]["stable_id"], "p1")
        self.assertEqual(profiles[0]["files"], ["/etc/hosts"])
        self.assertEqual(profiles[0]["event_refs"], ["e1", "e2", "e3"])
        self.assertEqual(profiles[0]["state"], "exited")

    def test_preprocessing_matches_nodlink_sentence_rules(self):
        self.assertEqual(natural_tokens("/etc/tmp/log.txt"), ["etc", "tmp", "log", "txt"])
        self.assertEqual(natural_tokens("10.0.0.1:443"), ["10", "0", "0", "1", "443"])

    def test_idf_degrades_resources_shared_by_all_processes(self):
        profiles = [
            {"files": ["/lib/libc.so", "/tmp/a"], "networks": []},
            {"files": ["/lib/libc.so"], "networks": ["10.0.0.1"]},
        ]
        rarity = idf_weights(profiles)
        self.assertEqual(rarity["files"]["/lib/libc.so"], 0.0)
        self.assertGreater(rarity["files"]["/tmp/a"], rarity["files"]["/lib/libc.so"])

    def test_dbscan_stability_is_cluster_count(self):
        names = ["browser", "browser", "browser", "browser", "bash"]
        vectors = [[0, 0], [0.01, 0], [10, 10], [10.01, 10], [1, 1]]
        scores = stability_scores(names, vectors, eps=0.1, min_samples=2)
        self.assertEqual(scores["browser"], 2.0)
        self.assertEqual(scores["bash"], 1.0)

    def test_training_is_reproducible_and_bundle_is_scoreable(self):
        profiles = normal_profiles()
        config = TrainingConfig(dimension=4, hidden_dimension=3, latent_dimension=2,
                                bucket_count=16, epochs=20, seed=7, target_rate=0.25)
        first = train_bundle(profiles, profiles, config)
        second = train_bundle(profiles, profiles, config)
        self.assertEqual(first, second)
        validate_bundle(first)
        vector = profile_vector(profiles[0], first)
        self.assertEqual(len(vector), 4)
        self.assertTrue(math.isfinite(score_profile(profiles[0], first)))


def normal_profiles():
    return [
        {"stable_id": "p1", "binary": "/bin/bash", "argv": ["bash", "-c", "cat /etc/hosts"],
         "files": ["/etc/hosts"], "networks": [], "event_refs": ["e1"], "revision": 1, "state": "exited"},
        {"stable_id": "p2", "binary": "/usr/bin/curl", "argv": ["curl", "example.test"],
         "files": [], "networks": ["10.0.0.1:443"], "event_refs": ["e2"], "revision": 1, "state": "exited"},
        {"stable_id": "p3", "binary": "/bin/cat", "argv": ["cat", "/etc/passwd"],
         "files": ["/etc/passwd"], "networks": [], "event_refs": ["e3"], "revision": 1, "state": "exited"},
        {"stable_id": "p4", "binary": "/bin/echo", "argv": ["echo", "ok"],
         "files": [], "networks": [], "event_refs": ["e4"], "revision": 1, "state": "exited"},
    ]


if __name__ == "__main__":
    unittest.main()
