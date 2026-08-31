import pathlib
import unittest


class KafkaRuntimeTest(unittest.TestCase):
    def test_kafka_module_imports_without_python_byte_schema(self):
        from sysarmor_streaming.runtime.kafka import ByteArraySchema

        self.assertTrue(ByteArraySchema)

    def test_exactly_once_sink_sets_bounded_transaction_timeout(self):
        source = pathlib.Path(__file__).resolve().parents[1] / "src/sysarmor_streaming/runtime/kafka.py"
        self.assertIn('.set_property("transaction.timeout.ms", "900000")', source.read_text())


if __name__ == "__main__":
    unittest.main()
