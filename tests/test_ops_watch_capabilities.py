"""`ops_watch.py capabilities`: one capability per line, exit 0, including the exact line forward-foreign-critical, so the fabd
installer can refuse to install on a host whose ops-watch cannot forward a foreign critical (goodqa#15827). The probe is pure:
it reads no config, no state and no ring."""
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HOOKS = Path(__file__).resolve().parents[1] / "harness" / "hooks"
SCRIPT = HOOKS / "ops_watch.py"
sys.path.insert(0, str(HOOKS))
import ops_watch as ow  # noqa: E402


def probe(home):
    env = dict(os.environ, HOME=str(home))
    return subprocess.run([sys.executable, "-B", str(SCRIPT), "capabilities"], capture_output=True, text=True, env=env, timeout=60)


class Capabilities(unittest.TestCase):
    def test_the_probe_prints_the_forwarder_as_an_exact_line_and_exits_zero(self):
        with tempfile.TemporaryDirectory() as home:
            done = probe(home)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn("forward-foreign-critical", done.stdout.split("\n"))  # what `grep -qx` checks
        self.assertEqual(done.stderr, "")

    def test_it_is_one_capability_per_line_with_no_blank_or_decorated_lines(self):
        with tempfile.TemporaryDirectory() as home:
            lines = probe(home).stdout.splitlines()
        self.assertTrue(lines)
        for line in lines:
            self.assertRegex(line, r"^[a-z][a-z0-9-]*$")
        self.assertEqual(len(lines), len(set(lines)))

    def test_the_probe_touches_no_state_config_or_ring(self):
        with tempfile.TemporaryDirectory() as home:
            probe(home)
            self.assertEqual(list(Path(home).rglob("*")), [])

    def test_the_capability_is_listed_only_while_the_code_behind_it_exists(self):
        self.assertIn("forward-foreign-critical", ow.capabilities())
        saved = ow.forward_foreign
        try:
            del ow.forward_foreign
            self.assertNotIn("forward-foreign-critical", ow.capabilities())
        finally:
            ow.forward_foreign = saved

    def test_the_listed_capability_is_real_a_foreign_critical_reaches_the_queue(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            cfg = ow.load_config(home, host="testhost", overrides={})
            cfg["sinks"] = {"comment_min_interval_s": 3600, "comment": {"mode": "none"}, "deadman": []}
            ow.emit({"host": "testhost", "source": "fabd-health", "event": "raise", "severity": "critical",
                     "key": "fabric:live-down:fabd", "message": "down", "detail": {}}, home=home)
            state = {"fwd_seq": 0, "fwd_active": {}}
            rows = ow.forward_foreign(cfg, home, state, ow.ring_path(home), 0.0)
        self.assertEqual([r["key"] for r in rows], ["fabric:live-down:fabd"])


if __name__ == "__main__":
    unittest.main()
