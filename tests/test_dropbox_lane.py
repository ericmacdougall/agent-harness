"""P12 (goodqa#14817): agent uploads to a Dropbox account go through one throttled lane.

On 2026-11-07 two agent uploads to the same Dropbox account (16 transfers, no tpslimit) ran for hours, Dropbox answered
too_many_write_operations, and the agent log backup went 6 h without a pass. The remote list and the process table
are injected, so these tests never run rclone or read its config.
"""
import sys
import unittest
from pathlib import Path
from unittest import mock

HOOKS = Path(__file__).resolve().parents[1] / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
import heavy_job_guard as guard  # noqa: E402

MODES = dict(guard.DEFAULT_MODES)
IDLE = ""
BUSY = ("  4242 rclone copy /Users/eric/archive lessons-dropbox:Backups/x --tpslimit 4 --transfers 4\n"
        "  4243 rclone copy /Users/eric/.claude/projects lessons-dropbox:Backups/agent-logs/mac/x --tpslimit 1 "
        "--log-file /Users/eric/.agent-harness/logs/log-backup.log\n")
BACKUP_ONLY = BUSY.splitlines()[1] + "\n"
LANE_ONLY = ("  4244 rclone copy --tpslimit 1 --log-file /Users/eric/.agent-harness/logs/log-backup.lane.log "
             "--files-from-raw /Users/eric/.agent-harness/logs/log-backup.bulk.d/x/chunk.paths -- "
             "/Users/eric/.agent-harness/work lessons-dropbox:Backups/agent-logs/mac/.agent-harness/work\n")
LOOKALIKE = ("  4245 rclone copy /Users/eric/a lessons-dropbox:Backups/a --tpslimit 4 --transfers 4 "
             "--log-file /Users/eric/.agent-harness/logs/log-backup.lanes.log\n")


class Lane(unittest.TestCase):
    def setUp(self):
        for patcher in (mock.patch.object(guard, "_DROPBOX_REMOTES", {"lessons-dropbox", "box2"}),
                        mock.patch.object(guard, "LANE_TPS", 4),   # the built-in ceiling; the budget share is tested apart
                        mock.patch.object(guard, "path_size", lambda p, cap=None, seconds=1.0: (10, True))):
            patcher.start()
            self.addCleanup(patcher.stop)
        self.ps = IDLE
        real = guard.lane_holders
        patcher = mock.patch.object(guard, "lane_holders", lambda ps_text=None: real(self.ps))
        patcher.start()
        self.addCleanup(patcher.stop)

    def decide(self, command):
        return guard.decide(command, "/Users/eric", MODES)

    def test_an_unthrottled_dropbox_upload_is_denied_with_the_lane_command(self):
        for command in ("rclone copy /Users/eric/a lessons-dropbox:Backups/a",
                        "rclone copy /Users/eric/a lessons-dropbox:Backups/a --transfers 16",
                        "rclone sync /Users/eric/a box2:x --tpslimit 12",
                        "rclone copy /Users/eric/a lessons-dropbox:Backups/a --tpslimit 4 --transfers 16",
                        "rclone move --tpslimit=0 /Users/eric/a lessons-dropbox:a",
                        "rclone --transfers 16 copy /Users/eric/a lessons-dropbox:a",  # global flags first
                        "rclone copy --progress src lessons-dropbox:a",  # relative source after a boolean flag
                        "rclone copy /Users/eric/a lessons-dropbox:a --tpslimit 4 --transfers 4 --tpslimit 50"):
            with self.subTest(command=command):
                result = self.decide(command)
                self.assertEqual((result["action"], result["rule"]), ("deny", "dropbox-lane"), result)
                self.assertIn("--tpslimit 4 --transfers 4", result["message"])
                self.assertNotIn("Exact equivalent on", result["message"])  # no pointless remote route

    def test_a_throttled_upload_on_an_idle_lane_is_allowed(self):
        for command in ("rclone copy /Users/eric/a lessons-dropbox:Backups/a --tpslimit 4 --transfers 4",
                        "rclone copy --tpslimit=2 --log-file /tmp/l.log /Users/eric/a lessons-dropbox:a",
                        "rclone copy lessons-dropbox:Backups/a /Users/eric/restore",  # a download writes nothing there
                        "rclone copy /Users/eric/a dev2-sftp:a",  # not a Dropbox remote
                        "rclone copy /Users/eric/a lessons-dropbox:a --dry-run",
                        "rclone lsjson lessons-dropbox:Backups --hash"):
            with self.subTest(command=command):
                self.assertEqual(self.decide(command)["action"], "allow", command)

    def test_a_second_agent_upload_waits_for_the_lane(self):
        self.ps = BUSY
        result = self.decide("rclone copy /Users/eric/b lessons-dropbox:Backups/b --tpslimit 4 --transfers 4")
        self.assertEqual((result["action"], result["rule"]), ("deny", "dropbox-lane"), result)
        self.assertIn("4242", result["detail"])
        self.assertNotIn("4243", result["detail"])

    def test_the_log_backup_never_holds_the_lane(self):
        self.ps = BACKUP_ONLY
        result = self.decide("rclone copy /Users/eric/b lessons-dropbox:Backups/b --tpslimit 4 --transfers 4")
        self.assertEqual(result["action"], "allow", result)

    def test_the_bulk_lane_of_the_log_backup_never_holds_the_lane(self):
        # PR #124 delta review N1: the lane logs to log-backup.lane.log and blocked every agent upload for hours.
        self.ps = LANE_ONLY
        result = self.decide("rclone copy /Users/eric/b lessons-dropbox:Backups/b --tpslimit 4 --transfers 4")
        self.assertEqual(result["action"], "allow", result)

    def test_a_look_alike_log_name_still_holds_the_lane(self):
        self.ps = LOOKALIKE
        result = self.decide("rclone copy /Users/eric/b lessons-dropbox:Backups/b --tpslimit 4 --transfers 4")
        self.assertNotEqual(result["action"], "allow", result)

    def test_the_hatch_allows_one_unanticipated_upload(self):
        result = self.decide("HARNESS_LOCAL_OK=restore-drill rclone copy /Users/eric/a lessons-dropbox:a")
        self.assertEqual((result["action"], result.get("hatch_reason")), ("allow", "restore-drill"), result)

    def test_remote_types_come_from_listremotes_not_the_config_file(self):
        out = mock.Mock(stdout="lessons-dropbox: dropbox\nsftp-box:  sftp\nArchive: Dropbox\n")
        with mock.patch.object(guard, "_DROPBOX_REMOTES", None), \
                mock.patch("subprocess.run", return_value=out) as run:
            self.assertEqual(guard.dropbox_remotes(), {"lessons-dropbox", "archive"})
        self.assertEqual(run.call_args[0][0], ["rclone", "listremotes", "--long"])


if __name__ == "__main__":
    unittest.main()
