import unittest
from pathlib import Path


RECORDER = Path(__file__).with_name("recorder-vm.sh")


class RecorderContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.script = RECORDER.read_text()

    def test_bounds_each_continuous_watch_segment(self):
        self.assertEqual(self.script.count(r'--limit \"\$WATCH_LIMIT\"'), 2)

    def test_reads_only_a_bounded_tail_to_advance_stream_cursors(self):
        self.assertIn(r'tail -n 32 \"\$file\"', self.script)
        self.assertNotIn("open(path, errors='replace').read().splitlines()", self.script)

    def test_replaces_stale_watcher_pids_on_restart(self):
        start = self.script.index("start_watchers()")
        event_watch = self.script.index("event watch", start)
        reset = r': > \"\$WATCH_PIDS\"'
        self.assertIn(reset, self.script[start:event_watch])

    def test_transient_health_failure_keeps_sampler_alive(self):
        self.assertIn(r'>\"\$HEALTH_JSON\" 2>/dev/null || return 0', self.script)

    def test_advances_cursors_before_restarting_a_completed_segment(self):
        ensure = self.script.index("ensure_watchers()")
        restart = self.script.index("start_watchers", ensure)
        self.assertIn("advance_cursors", self.script[ensure:restart])


if __name__ == "__main__":
    unittest.main()
