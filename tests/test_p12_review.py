"""Review findings on PR #103 at 60c0630 (goodqa#14817): remote shell injection in sizing, an unbounded network
budget, credentials in the hatch note, Dropbox-lane bypasses, unmeasured off-fleet sources, blobless clones and test
files named like replays. Every subprocess the guard would start is stubbed; nothing reaches the network.
"""
import os
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
GIB = 1024 ** 3
_STATE = tempfile.mkdtemp(prefix="p12-review-state-")


_STATE_PATCH = mock.patch.object(guard, "state_dir", lambda: _STATE)


def setUpModule():
    # The GitHub size cache lives in the state directory: keep the fake answers out of the real one.
    _STATE_PATCH.start()


def tearDownModule():
    _STATE_PATCH.stop()


def decide(command, cwd="/Users/eric"):
    return guard.decide(command, cwd, MODES)


class Calls:
    """A subprocess.run stand-in that records argv and answers per program."""

    def __init__(self, delay=0.0, du="10\t/x\n", gh="10"):
        self.argv, self.delay, self.du, self.gh = [], delay, du, gh

    def __call__(self, argv, **kwargs):
        self.argv.append(list(argv))
        if self.delay:
            time.sleep(min(self.delay, kwargs.get("timeout") or self.delay))
        out = {"ssh": self.du, "gh": self.gh}.get(os.path.basename(argv[0]), "")
        return mock.Mock(stdout=out, returncode=0)


class RemoteSizing(unittest.TestCase):
    def test_a_remote_path_never_reaches_the_remote_shell(self):
        calls = Calls()
        with mock.patch("subprocess.run", calls):
            for command in ("scp 'dev2:$(touch /tmp/pwned)' .", "rsync -a 'dev2:x;id>/tmp/p' ./d",
                            "scp 'dev2:`id`' .", "scp 'dev2:a b' ."):
                with self.subTest(command=command):
                    result = decide(command)
                    self.assertEqual((result["action"], result.get("rule")), ("deny", "copy"), result)
        self.assertEqual([a for a in calls.argv if a and a[0] == "ssh"], [], "an unsafe remote path was sent to ssh")

    def test_a_plain_remote_path_is_still_measured(self):
        calls = Calls(du="20\t/srv/x\n")
        with mock.patch("subprocess.run", calls):
            self.assertEqual(decide("rsync -a dev2:/srv/goodqa-1.2/ ./d")["action"], "allow")
        self.assertIn(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=2", "--", "dev2", "du", "-sk", "--",
                       "/srv/goodqa-1.2/"], calls.argv)

    def test_an_unmeasured_off_fleet_source_counts_as_heavy(self):
        calls = Calls()
        with mock.patch("subprocess.run", calls):
            for command in ("scp bigserver:/data/huge.tar .", "rsync -a prod:/var/lib/data/ ./data/"):
                with self.subTest(command=command):
                    result = decide(command)
                    self.assertEqual((result["action"], result.get("rule")), ("deny", "copy"), result)
        self.assertEqual([a for a in calls.argv if a and a[0] == "ssh"], [], "an off-fleet host was contacted")


class NetworkBudget(unittest.TestCase):
    def test_chained_lookups_share_one_bounded_budget(self):
        # Each lookup would take its full timeout; five clones and three copies must still be judged well inside the
        # hook's 10 s timeout, and anything left unmeasured is heavy.
        for command in ("; ".join(f"git clone https://github.com/o/r{i}" for i in range(5)),
                        "; ".join(f"scp dev2:/big{i} ." for i in range(3))):
            with self.subTest(command=command[:40]), mock.patch("subprocess.run", Calls(delay=5)), \
                    mock.patch.object(guard, "github_repo_bytes", guard.github_repo_bytes):
                start = time.monotonic()
                result = decide(command)
                self.assertLess(time.monotonic() - start, 7.5, "the decision outran the hook timeout")
                self.assertEqual(result["action"], "deny", result)


class Redaction(unittest.TestCase):
    def test_clone_urls_lose_their_credentials_in_the_detail(self):
        with mock.patch("subprocess.run", Calls(gh="")):
            result = decide("git clone https://oauth2:glpat-FAKEFAKEFAKE1234@gitlab.com/org/repo")
        self.assertEqual(result["action"], "deny", result)
        for text in (result["detail"], result["message"]):
            self.assertNotIn("glpat-FAKE", text)
            self.assertNotIn("oauth2:", text)

    def test_the_hatch_note_is_redacted(self):
        home = Path(tempfile.mkdtemp())
        decision = {"rule": "copy", "detail": "git clone of https://u:pw-FAKE-1234@gitlab.com/x/y: size unknown",
                    "hatch_reason": "restore drill"}
        with mock.patch.dict(os.environ, {"HOME": str(home)}):
            guard.log_hatch_to_wal({"session_id": "s1"}, decision)
        wal = home / ".claude" / "wals" / "s1" / "main.jsonl"
        self.assertTrue(wal.exists(), "the hatch record was not written")
        text = wal.read_text()
        self.assertIn("HARNESS_LOCAL_OK used", text)
        self.assertNotIn("pw-FAKE-1234", text)


class Lane(unittest.TestCase):
    def setUp(self):
        for patcher in (mock.patch.object(guard, "_DROPBOX_REMOTES", {"box", "secret"}),
                        mock.patch.object(guard, "lane_holders", lambda ps_text=None: [])):
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_lane_bypasses_are_denied(self):
        for command in ("rclone --progress copy src box:x --transfers 16",
                        "rclone copy src box:x --transfers 32 --exclude 'cache/**'",
                        "rclone copy src box:x --include '*/keep/*'",
                        "RCLONE_TRANSFERS=64 rclone copy src box:x --tpslimit 4",
                        "RCLONE_TPSLIMIT=50 rclone copy src box:x",  # the env sets the flag when it is absent
                        "rclone copy src secret:x --transfers 32",
                        "rclone copy src 'box,chunk_size=8M:x'",
                        "rclone copy src :dropbox:x",
                        "rclone rcat box:x",
                        "rclone copyurl https://e.com/f box:a",
                        "rclone copy a box:x --tpslimit 4 & rclone copy b box:y --tpslimit 4 & wait",
                        "rclone copy a box:x --tpslimit 4 --tpslimit-burst 500"):
            with self.subTest(command=command):
                result = decide(command)
                self.assertEqual((result["action"], result.get("rule")), ("deny", "dropbox-lane"), result)

    def test_reads_downloads_and_sequential_throttled_uploads_pass(self):
        for command in ("rclone copy box:x /Users/eric/restore --exclude 'cache/**'",
                        "rclone --progress copy box:x ./restore",
                        "rclone lsf box:x -R", "rclone check src box:x",
                        "rclone copy a box:x --tpslimit 4; rclone copy b box:y --tpslimit 4",
                        "rclone copy a box:x --tpslimit 2 --tpslimit-burst 2"):
            with self.subTest(command=command):
                self.assertEqual(decide(command)["action"], "allow", command)

    def test_wrapper_remotes_are_treated_as_dropbox(self):
        out = mock.Mock(stdout="box: dropbox\nsecret: crypt\nal: alias\nsf: sftp\n")
        with mock.patch.object(guard, "_DROPBOX_REMOTES", None), mock.patch("subprocess.run", return_value=out):
            self.assertEqual(guard.dropbox_remotes(), {"box", "secret", "al"})


class Small(unittest.TestCase):
    def test_a_blobless_clone_is_bounded_like_a_shallow_one(self):
        with mock.patch("subprocess.run", Calls(gh="")):
            self.assertEqual(decide("git clone --filter=blob:none https://gitlab.com/a/b")["action"], "allow")

    def test_test_files_named_like_replays_are_not_replays(self):
        for command in ("python3 tests/test_replay.py", "python3 tests/test_stress.py -k one"):
            with self.subTest(command=command):
                self.assertNotEqual(decide(command).get("rule"), "replay", command)
        self.assertEqual(decide("python3 scripts/replay.py").get("rule"), "replay")


if __name__ == "__main__":
    unittest.main()
