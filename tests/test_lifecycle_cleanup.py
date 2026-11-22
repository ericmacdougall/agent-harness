"""Scoped lifecycle controls. All destructive controls use disposable fixtures."""
from pathlib import Path
import io
import json
import os
import tarfile
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "harness" / "hooks"))

import lifecycle_cleanup as cleanup
from test_copy_hygiene import Base as CopyFixture


class ArtifactLifecycle(unittest.TestCase):
    def setUp(self):
        self.task = Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        self.root = self.task / "artifacts"
        self.root.mkdir(mode=0o700)
        self.candidate = self.root / "reports"
        self.candidate.mkdir(mode=0o700)
        self.report = self.candidate / "dashboard.html"
        self.report.write_bytes(b"rendered fixture")

    def test_artifact_scope_refuses_logs_and_symlinks(self):
        self.assertTrue(cleanup.inventory(self.candidate))
        (self.candidate / "agent.log").write_bytes(b"protected fixture")
        with self.assertRaises(cleanup.Retention):
            cleanup.inventory(self.candidate)
        (self.candidate / "agent.log").unlink()
        (self.candidate / "linked.html").symlink_to(self.report)
        with self.assertRaises(cleanup.Retention):
            cleanup.inventory(self.candidate)

    def test_changed_source_during_backup_is_preserved(self):
        def backup(*args):
            self.report.write_bytes(b"later bytes")
            return "fixture-cold:bucket/artifact.tar", "1" * 64
        task = {"task_id": "fixture"}
        with patch.object(cleanup, "idle"), patch.object(cleanup, "store_archive", side_effect=backup):
            with self.assertRaisesRegex(cleanup.Retention, "changed"):
                cleanup.retire_artifact(self.task, task, "reports", "fixture-cold:bucket", True)
        self.assertEqual(self.report.read_bytes(), b"later bytes")

    def test_explicit_archive_limit_refuses_before_transfer(self):
        with patch.object(cleanup, "idle"), patch.object(cleanup, "store_archive") as archive:
            with self.assertRaisesRegex(cleanup.Retention, "limit exceeded"):
                cleanup.retire_artifact(self.task, {"task_id": "fixture"}, "reports", "fixture:bucket", True, 1)
            with self.assertRaisesRegex(cleanup.Retention, "4 GiB"):
                cleanup.retire_artifact(self.task, {"task_id": "fixture"}, "reports", "fixture:bucket", True,
                                        cleanup.MAX_BYTES + 1)
            archive.assert_not_called()
        self.assertTrue(self.report.is_file())

    def test_only_verified_download_allows_artifact_retirement(self):
        saved = {}
        trusted_tool = cleanup.trusted_tool

        def tool(name):
            return "/test/rclone" if name == "rclone" else trusted_tool(name)

        def transport(tool, action, *args, timeout):
            if action == "listremotes":
                return b"fixture-cold: b2\n"
            if action == "copyto":
                self.assertEqual(args[:2], ("--immutable", "--"))
                blob = Path(args[2]).read_bytes()
                saved[args[3]] = blob
                return b""
            self.assertEqual(action, "check")
            self.assertIn("--download", args)
            with tarfile.open(next(Path(args[-2]).iterdir())) as staged:
                self.assertEqual(staged.extractfile("reports/dashboard.html").read(), b"rendered fixture")
            filename = next(Path(args[-2]).iterdir()).name
            self.assertEqual(saved[f"{args[-1]}/{filename}"], (Path(args[-2]) / filename).read_bytes())
            return b""

        task = {"task_id": "fixture"}
        name = "fixture-cold:bucket"
        with patch.object(cleanup, "idle"), patch.object(cleanup, "trusted_tool", side_effect=tool), \
                patch.object(cleanup, "rclone", side_effect=transport):
            with self.assertRaisesRegex(cleanup.Retention, "download verification"):
                cleanup.retire_artifact(self.task, task, "reports", name, True)
        self.assertTrue(self.report.is_file())
        self.assertEqual(json.loads(cleanup.audit_path(self.task, self.candidate).read_text())["status"], "retained")

        def verified(tool, action, *args, timeout):
            result = transport(tool, action, *args, timeout=timeout)
            if action == "check":
                filename = next(Path(args[-2]).iterdir()).name
                return ("= " + filename + "\n").encode()
            return result

        with patch.object(cleanup, "idle"), patch.object(cleanup, "trusted_tool", side_effect=tool), \
                patch.object(cleanup, "rclone", side_effect=verified):
            result = cleanup.retire_artifact(self.task, task, "reports", name, True)
        self.assertEqual(result["status"], "removed")
        self.assertFalse(self.candidate.exists())
        self.assertEqual(result["sha256"] + ".tar", result["archive"].rsplit("/", 1)[1])

    def test_open_file_check_error_fails_closed(self):
        class Result:
            returncode, stdout, stderr = 1, b"", b"incomplete observation"

        with patch.object(cleanup.copy_hygiene, "protected_scan", return_value=({}, 0)), patch.object(
            cleanup, "trusted_tool", return_value="/test/lsof"
        ), patch.object(cleanup.subprocess, "run", return_value=Result()):
            with self.assertRaisesRegex(cleanup.Retention, "uncertain"):
                cleanup.idle(self.candidate)

    def test_quarantine_is_preserved_and_retry_refused_if_final_process_check_is_uncertain(self):
        task = {"task_id": "fixture"}
        with patch.object(
            cleanup, "idle", side_effect=[None, None, cleanup.Retention("open file after move")]
        ), patch.object(cleanup, "store_archive", return_value=("fixture:archive", "c" * 64)):
            with self.assertRaisesRegex(cleanup.Retention, "open file"):
                cleanup.retire_artifact(self.task, task, "reports", "fixture:archive", True)
        record = json.loads(cleanup.audit_path(self.task, self.candidate).read_text())
        self.assertEqual(record["status"], "uncertain")
        self.assertEqual((Path(record["quarantine"]) / "dashboard.html").read_bytes(), b"rendered fixture")

    def test_mount_table_rejects_same_filesystem_bind_mount(self):
        nested = self.candidate / "bind-mount"
        nested.mkdir()
        table = f"1 0 8:1 / / rw - ext4 /dev/a rw\n2 1 8:1 /elsewhere {nested} rw - ext4 /dev/a rw\n"
        with patch.object(cleanup.sys, "platform", "linux"), patch("builtins.open", return_value=io.StringIO(table)):
            with self.assertRaisesRegex(cleanup.Retention, "mounted"):
                cleanup.inventory(self.candidate)

    def test_checkout_path_cannot_supply_cleanup_tools(self):
        claimed = self.candidate / "rclone"
        claimed.write_text("fixture\n")
        claimed.chmod(0o700)
        with patch.object(cleanup, "TOOL_DIRS", (str(self.candidate),)):
            with self.assertRaisesRegex(cleanup.Retention, "trusted installed"):
                cleanup.trusted_tool("rclone")


class CopyLifecycle(CopyFixture):
    def fixture(self):
        self.enterContext(patch.dict(os.environ, {"HARNESS_COPY_HYGIENE_HOME": str(self.home.resolve())}))
        self.enterContext(patch.object(cleanup, "idle"))
        repo = str(self.repo.resolve())
        acquired = cleanup.copy_hygiene.acquire(repo, "pr-1", cfg=self.cfg(min_free_gb=0))
        self.assertTrue(acquired["ok"])
        path, head = acquired["path"], acquired["commit"]
        task = self.home.resolve() / "task-fixture"
        task.mkdir()
        manifest = {"task_id": "fixture", "cwd": path, "prompt_file": str(task / "prompt")}
        return task, manifest, repo, path, head

    def test_fresh_same_head_reuse_invalidates_earlier_completion(self):
        task, manifest, repo, path, head = self.fixture()
        os.utime(path + ".lock", (1, 1))
        generation = cleanup.task_recovery.enrolled_copy_generation(path)
        self.assertTrue(generation)
        with patch.object(cleanup, "guard", return_value={"removable": True, "head": head}) as guard:
            self.assertEqual(cleanup.retire_copy(task, manifest, generation, repo, "pr-1", head, False)["status"], "preview")
            guard.assert_called_once_with(Path(path), "verify-worktree")
        result = cleanup.copy_hygiene.acquire(repo, "pr-1", cfg=self.cfg(min_free_gb=0))
        self.assertTrue(result["ok"] and result["reused"])
        self.assertEqual(result["commit"], head)
        os.utime(path + ".lock", (1, 1))
        with patch.object(cleanup, "guard") as guard:
            with self.assertRaisesRegex(cleanup.Retention, "reacquired"):
                cleanup.retire_copy(task, manifest, generation, repo, "pr-1", head, True)
            guard.assert_not_called()

    def test_busy_acquire_fence_and_wrong_task_checkout_preserve_copy(self):
        task, manifest, repo, path, head = self.fixture()
        generation = cleanup.task_recovery.enrolled_copy_generation(path)
        with patch.object(cleanup, "guard") as guard:
            with cleanup.copy_hygiene.copy_lock(path, create=False, wait=True):
                with self.assertRaises(BlockingIOError):
                    cleanup.retire_copy(task, manifest, generation, repo, "pr-1", head, True)
            with self.assertRaisesRegex(cleanup.Retention, "does not own"):
                cleanup.retire_copy(task, dict(manifest, cwd=repo), generation, repo, "pr-1", head, True)
            with self.assertRaisesRegex(cleanup.Retention, "prompt is inside"):
                cleanup.retire_copy(task, dict(manifest, prompt_file=f"{path}/prompt"),
                                    generation, repo, "pr-1", head, True)
            guard.assert_not_called()
        self.assertTrue(Path(path).is_dir())

    def test_uncertain_or_incomplete_recovery_state_never_admits_cleanup(self):
        task, manifest, repo, path, head = self.fixture()
        task.chmod(0o700)
        (task / "lock").touch(mode=0o600)
        with patch.object(cleanup.workdir, "work_root", return_value=task.parent):
            for state in ("running", "recovery_uncertain", "paused", "attempts_exhausted"):
                with patch.object(cleanup.task_recovery, "load",
                                  return_value=(manifest, {"status": state, "verified_at": time.time()})):
                    with self.assertRaisesRegex(cleanup.Retention, "completion"):
                        with cleanup.completed_task(task):
                            self.fail("unexpected cleanup admission")
