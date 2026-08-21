import unittest


class KafkaRuntimeTest(unittest.TestCase):
    def test_kafka_module_imports_without_python_byte_schema(self):
        from sysarmor_streaming.runtime.kafka import ByteArraySchema

        self.assertTrue(ByteArraySchema)


if __name__ == "__main__":
    unittest.main()
