import unittest
from pathlib import Path


class PostgresWorkerConcurrencyScriptTest(unittest.TestCase):
    def test_readiness_probe_waits_for_final_tcp_server(self):
        script = Path(__file__).with_name("postgres-worker-concurrency.sh").read_text()

        self.assertIn(
            'pg_isready -h 127.0.0.1 -p 5432 -U sysarmor -d sysarmor',
            script,
        )


if __name__ == "__main__":
    unittest.main()
