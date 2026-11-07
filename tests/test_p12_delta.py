"""Delta review of PR #103 at 8f94dc4 (goodqa#14817): RCLONE_* settings given through env, sudo or export, uploads
run in parallel by a loop or xargs, and local walks outside the shared lookup budget. Subprocesses are stubbed.
"""
import os
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

HOOKS = Path(__file__).resolve().parents[1] / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
import heavy_job_guard as guard  # noqa: E402

MODES = dict(guard.DEFAULT_MODES)


def decide(command, cwd="/Users/eric"):
    return guard.decide(command, cwd, MODES)


class Lane(unittest.TestCase):
    def setUp(self):
        for patcher in (mock.patch.object(guard, "_DROPBOX_REMOTES", {"box"}),
                        mock.patch.object(guard, "lane_holders", lambda ps_text=None: [])):
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_rclone_settings_through_env_sudo_or_export_are_checked(self):
        for command in ("env RCLONE_TRANSFERS=64 rclone copy src box:x --tpslimit 4",
                        "sudo RCLONE_TRANSFERS=64 rclone copy src box:x --tpslimit 4",
                        "export RCLONE_TRANSFERS=64; rclone copy src box:x --tpslimit 4",
                        "export RCLONE_TPSLIMIT_BURST=500 && rclone copy src box:x --tpslimit 4"):
            with self.subTest(command=command):
                result = decide(command)
                self.assertEqual((result["action"], result.get("rule")), ("deny", "dropbox-lane"), result)

    def test_a_wrapper_setting_applies_to_its_own_command_only(self):
        result = decide("env RCLONE_TRANSFERS=64 true; rclone copy src box:x --tpslimit 4")
        self.assertEqual(result["action"], "allow", result)

    def test_parallel_uploads_from_a_loop_or_xargs_are_denied(self):
        for command in ("for d in a b c; do rclone copy $d box:x/$d --tpslimit 4 & done; wait",
                        "ls | xargs -P 2 -I{} rclone copy {} box:x --tpslimit 4",
                        "ls | xargs -P0 -I{} rclone copy {} box:x --tpslimit 4"):
            with self.subTest(command=command):
                result = decide(command)
                self.assertEqual((result["action"], result.get("rule")), ("deny", "dropbox-lane"), result)

    def test_sequential_loops_and_single_xargs_pass(self):
        for command in ("for d in a b c; do rclone copy $d box:x/$d --tpslimit 4; done",
                        "ls | xargs -I{} rclone copy {} box:x --tpslimit 4"):
            with self.subTest(command=command):
                self.assertEqual(decide(command)["action"], "allow", command)


class WalkBudget(unittest.TestCase):
    def test_many_slow_local_walks_stay_inside_the_hook_timeout(self):
        # The real walker over real trees on a slow disk (each directory listing takes 0.1 s): each walk stops at its
        # own 1 s bound, so twelve of them took 12 s before the walks shared the decision's budget.
        root = Path(tempfile.mkdtemp(prefix="p12-walk-"))
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        for i in range(12):
            for j in range(30):
                (root / f"src{i}" / f"d{j}").mkdir(parents=True)
        real_scandir = os.scandir

        def slow_scandir(path="."):
            time.sleep(0.1)
            return real_scandir(path)

        command = "; ".join(f"cp -R {root}/src{i} /Users/eric/d{i}" for i in range(12))
        with mock.patch("os.scandir", slow_scandir):
            start = time.monotonic()
            result = decide(command)
            elapsed = time.monotonic() - start
        self.assertLess(elapsed, 7.5, "local walks outran the shared budget")
        self.assertEqual(result["action"], "deny", result)  # the walks it could not afford count as heavy

    def test_the_budget_is_closed_after_a_decision(self):
        decide("ls")
        self.assertEqual(guard.net_left(30.0), 30.0, "a later caller in this process inherited the decision's budget")


if __name__ == "__main__":
    unittest.main()
