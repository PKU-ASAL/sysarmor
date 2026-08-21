import os
import unittest
from unittest.mock import patch

from sysarmor_streaming.runtime.config import StreamingConfig


class StreamingConfigTest(unittest.TestCase):
    def test_defaults_define_separate_data_and_control_topics(self):
        with patch.dict(os.environ, {"SYSARMOR_KAFKA_BROKERS": "kafka:9092"}, clear=True):
            config = StreamingConfig.from_env()

        self.assertEqual("sysarmor.agent.databatch.raw", config.raw_topic)
        self.assertEqual("sysarmor.control.policy.published", config.policy_topic)
        self.assertEqual("s3://sysarmor-flink/checkpoints", config.checkpoint_uri)

    def test_invalid_runtime_values_fail_explicitly(self):
        with patch.dict(
            os.environ,
            {"SYSARMOR_KAFKA_BROKERS": "kafka:9092", "SYSARMOR_FLINK_PARALLELISM": "0"},
            clear=True,
        ):
            with self.assertRaisesRegex(ValueError, "must be positive"):
                StreamingConfig.from_env()


if __name__ == "__main__":
    unittest.main()
