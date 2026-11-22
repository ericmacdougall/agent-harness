"""Scoped lifecycle controls. All destructive controls use disposable fixtures."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
import io
import json
import multiprocessing
import os
import subprocess
import tarfile
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, call, patch

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
        self.manifest = {"task_id": "fixture", "prompt_file": str(self.task / "prompt")}

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
        with patch.object(cleanup, "idle"), patch.object(cleanup, "store_archive", side_effect=backup):
            with self.assertRaisesRegex(cleanup.Retention, "changed"):
                cleanup.retire_artifact(self.task, self.manifest, "reports", "fixture-cold:bucket", True)
        self.assertEqual(self.report.read_bytes(), b"later bytes")

    def test_enrolled_prompt_in_artifact_preserves_completed_task(self):
        prompt = self.candidate / "prompt"
        prompt.write_bytes(b"synthetic enrolled task")
        prompt.chmod(0o600)
        proposal = self.task / "manifest-input.json"
        proposal.write_text(json.dumps({
            "schema": "native-recovery-v1", "task_id": "fixture", "cwd": str(self.task),
            "agent_argv": ["/fixture/codex"], "verify_argv": ["/usr/bin/true"],
            "prompt_file": str(prompt), "prompt_sha256": cleanup.task_recovery.digest(prompt.read_bytes()),
            "max_attempts": 1, "attempt_timeout": 1, "task_timeout": 10,
        }))
        proposal.chmod(0o600)
        cleanup.task_recovery.enroll(self.task, proposal)
        self.assertEqual(cleanup.task_recovery.run(self.task), 0)
        manifest, state = cleanup.task_recovery.load(self.task)
        self.assertEqual(state["status"], "complete")
        with patch.object(cleanup, "idle"), patch.object(
            cleanup, "store_archive", return_value=("fixture-cold:bucket/archive.tar", "a" * 64)
        ) as backup:
            with self.assertRaisesRegex(cleanup.Retention, "task prompt"):
                cleanup.retire_artifact(self.task, manifest, "reports", "fixture-cold:bucket", True)
            backup.assert_not_called()
        self.assertEqual(prompt.read_bytes(), b"synthetic enrolled task")
        self.assertEqual(cleanup.task_recovery.load(self.task)[1]["status"], "complete")

    def test_uncached_service_scan_stops_retirement_after_in_place_unit_edit(self):
        units = self.task / "user-units"
        units.mkdir()
        unit = units / "fixture.service"
        unit.write_text("[Service]\nWorkingDirectory=/fixture/unrelated\n")
        before = units.stat().st_mtime_ns

        def backup(*args):
            unit.write_text(f"[Service]\nWorkingDirectory={self.candidate}\n")
            self.assertEqual(units.stat().st_mtime_ns, before)
            return "fixture-cold:bucket/archive.tar", "b" * 64

        with patch.object(cleanup.copy_hygiene, "_unit_dirs", return_value=[(str(units), "user")]), \
                patch.object(cleanup.copy_hygiene, "state_dir", return_value=str(self.task / "scanner-state")), \
                patch.object(cleanup, "store_archive", side_effect=backup):
            self.assertEqual(cleanup.copy_hygiene.protected_scan()[1], 0)
            with self.assertRaisesRegex(cleanup.Retention, "service uses"):
                cleanup.retire_artifact(self.task,
                                        {"task_id": "fixture", "prompt_file": str(self.task / "prompt")},
                                        "reports", "fixture-cold:bucket", True)
        self.assertTrue(self.report.is_file())

    def test_new_service_dependency_on_original_name_preserves_quarantined_bytes(self):
        units = self.task / "user-units"
        units.mkdir()
        unit = units / "fixture.service"
        unit.write_text("[Service]\nWorkingDirectory=/fixture/unrelated\n")
        original_inventory = cleanup.inventory

        def inventory(path, max_bytes):
            found = original_inventory(path, max_bytes)
            if path.parent.name.startswith("cleanup-quarantine-"):
                unit.write_text(f"[Service]\nWorkingDirectory={self.candidate}\n")
            return found

        with patch.object(cleanup.copy_hygiene, "_unit_dirs", return_value=[(str(units), "user")]), \
                patch.object(cleanup, "inventory", side_effect=inventory), \
                patch.object(cleanup, "store_archive", return_value=("fixture:archive", "e" * 64)):
            with self.assertRaisesRegex(cleanup.Retention, "service uses"):
                cleanup.retire_artifact(self.task, self.manifest, "reports", "fixture:archive", True)
        record = json.loads(cleanup.audit_path(self.task, self.candidate).read_text())
        self.assertEqual(record["status"], "uncertain")
        self.assertEqual((Path(record["quarantine"]) / self.report.name).read_bytes(), b"rendered fixture")

    def test_explicit_archive_limit_refuses_before_transfer(self):
        with patch.object(cleanup, "idle"), patch.object(cleanup, "store_archive") as archive:
            with self.assertRaisesRegex(cleanup.Retention, "limit exceeded"):
                cleanup.retire_artifact(self.task, self.manifest, "reports", "fixture:bucket", True, 1)
            with self.assertRaisesRegex(cleanup.Retention, "4 GiB"):
                cleanup.retire_artifact(self.task, self.manifest, "reports", "fixture:bucket", True,
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

        name = "fixture-cold:bucket"
        with patch.object(cleanup, "idle"), patch.object(cleanup, "trusted_tool", side_effect=tool), \
                patch.object(cleanup, "rclone", side_effect=transport):
            with self.assertRaisesRegex(cleanup.Retention, "download verification"):
                cleanup.retire_artifact(self.task, self.manifest, "reports", name, True)
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
            result = cleanup.retire_artifact(self.task, self.manifest, "reports", name, True)
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
        with patch.object(
            cleanup, "idle", side_effect=[None, None, cleanup.Retention("open file after move")]
        ), patch.object(cleanup, "store_archive", return_value=("fixture:archive", "c" * 64)):
            with self.assertRaisesRegex(cleanup.Retention, "open file"):
                cleanup.retire_artifact(self.task, self.manifest, "reports", "fixture:archive", True)
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

    def test_persisted_retirement_blocks_reacquire_without_a_worker(self):
        _, _, repo, path, _ = self.fixture()
        generation = cleanup.task_recovery.enrolled_copy_generation(path)
        record = f"retiring {generation}\n"
        Path(path + ".lock").write_text(record)
        result = cleanup.copy_hygiene.acquire(repo, "pr-1", cfg=self.cfg(min_free_gb=0))
        self.assertFalse(result["ok"])
        self.assertEqual(result["refused"], "retirement-unconfirmed")
        self.assertEqual(Path(path + ".lock").read_text(), record)
        self.assertTrue(Path(path).is_dir())

    def test_enabled_legacy_reaper_preserves_fenced_copy(self):
        _, _, _, path, _ = self.fixture()
        generation = cleanup.task_recovery.enrolled_copy_generation(path)
        cfg = self.cfg(reaper_delete_enabled=True, max_age_hours=0)
        with patch.object(cleanup.copy_hygiene, "deletable") as eligible:
            with cleanup.copy_hygiene.copy_lock(path, create=False, wait=True) as lock:
                cleanup.copy_hygiene.set_copy_retirement(lock, generation, pending=True)
                busy = cleanup.copy_hygiene.reap(apply=True, cfg=cfg)["copies"][0]
                self.assertIn("lock is busy", busy["action"])
            pending = cleanup.copy_hygiene.reap(apply=True, cfg=cfg)["copies"][0]
            self.assertIn("retirement is unconfirmed", pending["action"])
            eligible.assert_not_called()
        self.assertTrue(Path(path).is_dir())

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

    def completed_fixture(self):
        task, _, repo, path, head = self.fixture()
        task.rmdir()
        work = self.home.resolve() / ".agent-harness/work"
        work.mkdir()
        task = work / "enrolled"
        prompt = work / "prompt"
        prompt.write_bytes(b"synthetic task")
        prompt.chmod(0o600)
        proposal = work / "manifest-input.json"
        proposal.write_text(json.dumps({
            "schema": "native-recovery-v1", "task_id": "fixture", "cwd": path,
            "agent_argv": ["/fixture/codex"], "verify_argv": ["/usr/bin/true"],
            "prompt_file": str(prompt), "prompt_sha256": cleanup.task_recovery.digest(prompt.read_bytes()),
            "max_attempts": 1, "attempt_timeout": 1, "task_timeout": 10,
        }))
        proposal.chmod(0o600)
        cleanup.task_recovery.enroll(task, proposal)
        self.assertEqual(cleanup.task_recovery.run(task), 0)
        self.enterContext(patch.object(cleanup.workdir, "work_root", return_value=work))
        return task, repo, path, head

    def test_managed_copy_passes_real_guard_and_ordinary_entry_refuses(self):
        task, repo, path, head = self.completed_fixture()
        # Keep the real guard, Git worktree, index and removal. Replace only its remote transport with the
        # fixture's actually advertised Git ref so the test remains offline.
        live_git_output = subprocess.check_output(["/usr/bin/git", "ls-remote", str(self.origin)], text=True)
        live = {ref: sha for sha, ref in (line.split() for line in live_git_output.splitlines())}
        cleanup.safe_git(repo, "remote", "set-url", "origin", "https://github.com/fixture/project.git")
        with patch.dict(os.environ, {"HOME": str(self.home.resolve())}), patch.object(
            cleanup.command_guard, "authenticated_remote_refs", return_value=live
        ):
            self.assertIn("only a worktree inside work/",
                          cleanup.command_guard.verify_worktree(path, authenticated=True)["reason"])
            with cleanup.completed_task(task) as (manifest, state, task_lock):
                self.assertTrue(state["copy_generation"])
                preview = cleanup.retire_copy(task, manifest, state["copy_generation"], repo, "pr-1", head, False)
                self.assertEqual(preview["status"], "preview")
                result = cleanup.retire_copy(task, manifest, state["copy_generation"], repo, "pr-1", head, True,
                                             task_lock=task_lock)
                self.assertEqual(result["status"], "removed")
        self.assertFalse(Path(path).exists())
        self.assertEqual(cleanup.task_recovery.load(task)[1]["status"], "complete")
        self.assertTrue(cleanup.copy_hygiene.acquire(repo, "pr-1", cfg=self.cfg(min_free_gb=0))["ok"])

    def test_final_guard_refusal_releases_retirement_fence(self):
        task, repo, path, head = self.completed_fixture()
        with cleanup.completed_task(task) as (manifest, state, task_lock), patch.object(
            cleanup, "guard", return_value={"removable": False}
        ):
            result = cleanup.retire_copy(task, manifest, state["copy_generation"], repo, "pr-1", head, True,
                                         task_lock=task_lock)
        self.assertEqual(result["status"], "retained")
        self.assertTrue(cleanup.copy_hygiene.acquire(repo, "pr-1", cfg=self.cfg(min_free_gb=0))["ok"])

    def managed_backed_fixture(self):
        task, repo, path, head = self.completed_fixture()
        cg = cleanup.command_guard
        live_output = subprocess.check_output(["/usr/bin/git", "ls-remote", str(self.origin)], text=True)
        live = {ref: sha for sha, ref in (line.split() for line in live_output.splitlines())}
        cleanup.safe_git(repo, "remote", "set-url", "origin", "https://github.com/fixture/project.git")
        (Path(repo) / ".git/info/exclude").write_text(".cache/\n")
        folder = Path(path) / ".cache"
        folder.mkdir()
        leaves = [folder / name for name in ("first.tsbuildinfo", "second.tsbuildinfo")]
        policy = cg.load_policy()
        policy = dict(policy, marker=dict(policy['marker'], recent_change_seconds=0))

        class SyntheticMirror:
            def remote_types(self):
                return {'dropbox': 'dropbox'}

            def verify(self, local_root, manifest, remote):
                return cg.VerifyResult(True, checked=len(manifest))

        for leaf in leaves:
            leaf.write_text("synthetic backed managed output\n")
            cg.approve_delete(str(leaf), 'dropbox:fixture/managed', verifier=SyntheticMirror(),
                              home=str(self.home.resolve()), policy=policy)
        self.enterContext(patch.dict(os.environ, {"HOME": str(self.home.resolve())}))
        self.enterContext(patch.object(cg, "_pinned_home", return_value=str(self.home.resolve())))
        self.enterContext(patch.object(cg, "authenticated_remote_refs", return_value=live))
        self.enterContext(patch.object(cg, "load_policy", return_value=policy))
        return task, repo, path, head, leaves

    def test_managed_backed_copy_consumes_once_and_passes_both_locks_to_plain_git(self):
        task, repo, path, head, leaves = self.managed_backed_fixture()
        cg = cleanup.command_guard
        real_run, writers = subprocess.run, []

        def observe(argv, *args, **kwargs):
            if 'worktree' in argv and 'remove' in argv:
                writers.append((list(argv), tuple(kwargs.get('pass_fds', ()))))
            return real_run(argv, *args, **kwargs)

        with cleanup.completed_task(task) as (manifest, state, task_lock), patch.object(cg.subprocess, 'run', observe):
            result = cleanup.retire_copy(task, manifest, state['copy_generation'], repo, 'pr-1', head, True,
                                         task_lock=task_lock)
        self.assertEqual(result['status'], 'removed', result)
        self.assertEqual(len(writers), 1)
        self.assertEqual(len(set(writers[0][1])), 2)
        self.assertNotIn('--force', writers[0][0])
        self.assertEqual(cg.load_marker(self.home.resolve())[0], [])
        self.assertFalse(Path(path).exists())
        self.assertEqual(cleanup.task_recovery.load(task)[1]['status'], 'complete')

    def test_new_protection_after_backed_consume_retains_managed_copy_without_refunding_grants(self):
        task, repo, path, head, leaves = self.managed_backed_fixture()
        cg = cleanup.command_guard

        def new_dependency(candidate):
            if not cg.load_marker(self.home.resolve())[0]:
                raise ValueError('new protected service dependency')

        with cleanup.completed_task(task) as (manifest, state, task_lock), \
                patch.object(cleanup, 'idle', side_effect=new_dependency), \
                patch.object(cg, '_worktree_audit') as audit:
            result = cleanup.retire_copy(task, manifest, state['copy_generation'], repo, 'pr-1', head, True,
                                         task_lock=task_lock)
        self.assertEqual(result['status'], 'retained', result)
        self.assertFalse(audit.called, 'fresh service refusal must precede Git writer intent')
        self.assertTrue(all(leaf.exists() for leaf in leaves))
        self.assertEqual(cg.load_marker(self.home.resolve())[0], [], 'spent grants must not be refunded')
        with cleanup.copy_hygiene.copy_lock(path, create=False, wait=True) as lock:
            self.assertFalse(cleanup.copy_hygiene.copy_retirement_unconfirmed(lock))

    def test_managed_backed_copy_without_both_locks_refuses_before_any_grant_spend(self):
        _, _, path, head, leaves = self.managed_backed_fixture()
        cg = cleanup.command_guard
        original = cg.load_marker(self.home.resolve())[0]
        with patch.object(cg, '_worktree_audit') as audit:
            result = cg.remove_worktree(path, authenticated=True, expect_head=head,
                                        _managed_copy=path, _before_remove=lambda: None)
        self.assertFalse(result['removed'], result)
        self.assertIn('both held lock', result['reason'])
        self.assertFalse(audit.called)
        self.assertTrue(all(leaf.exists() for leaf in leaves))
        self.assertEqual(cg.load_marker(self.home.resolve())[0], original)

    def test_lost_worker_leaves_actual_removal_child_holding_both_locks(self):
        task, repo, path, head = self.completed_fixture()
        ready, release, exited = (task / name for name in ("writer-ready", "writer-release", "writer-exited"))
        real_spawn = subprocess.Popen

        def guarded_spawn(argv, *args, **kwargs):
            if ["worktree", "remove", "--", path] != argv[-4:]:
                return real_spawn(argv, *args, **kwargs)
            # Preserve the production Popen options. Replace only the destructive argv with a bounded writer.
            argv = [sys.executable, "-I", "-c", """
from pathlib import Path
import sys
import time
ready, release, exited = map(Path, sys.argv[1:])
ready.touch()
for unused in range(700):
    if release.exists():
        break
    time.sleep(0.01)
exited.touch()
""", str(ready), str(release), str(exited)]
            writer = real_spawn(argv, *args, **kwargs)
            deadline = time.monotonic() + 3
            while not ready.exists() and writer.poll() is None and time.monotonic() < deadline:
                time.sleep(0.01)
            # Exit this disposable worker at the process-creation boundary without running its cleanup handlers.
            os._exit(71 if ready.exists() and writer.poll() is None else 72)

        def worker_entry():
            with cleanup.completed_task(task) as (manifest, state, task_lock), patch.object(
                cleanup.command_guard, "verify_worktree", return_value={"removable": True, "head": head, "repo": repo}
            ), patch.object(cleanup.command_guard.subprocess, "Popen", side_effect=guarded_spawn):
                cleanup.retire_copy(task, manifest, state["copy_generation"], repo, "pr-1", head, True,
                                    task_lock=task_lock)

        worker = multiprocessing.get_context("fork").Process(target=worker_entry)
        worker.start()
        reaching_lock = threading.Event()
        copy_lock = cleanup.copy_hygiene.copy_lock

        def observe_lock(*args, **kwargs):
            reaching_lock.set()
            return copy_lock(*args, **kwargs)

        with ThreadPoolExecutor(max_workers=1) as contender:
            try:
                worker.join(timeout=5)
                self.assertEqual(worker.exitcode, 71, "the guarded removal worker did not exit at the intended boundary")
                self.assertTrue(ready.exists())
                self.assertFalse(exited.exists())
                with self.assertRaises(BlockingIOError), cleanup.completed_task(task):
                    self.fail("task lock released while the removal child is still running")
                with patch.object(cleanup.copy_hygiene, "copy_lock", side_effect=observe_lock):
                    acquisition = contender.submit(cleanup.copy_hygiene.acquire, repo, "pr-1",
                                                   cfg=self.cfg(min_free_gb=0))
                    self.assertTrue(reaching_lock.wait(timeout=3))
                    with self.assertRaises(TimeoutError):
                        acquisition.result(timeout=0.1)
                    release.touch()
                    refused = acquisition.result(timeout=3)
            finally:
                release.touch()
                worker.join(timeout=3)
        self.assertTrue(exited.exists())
        self.assertEqual(refused.get("refused"), "retirement-unconfirmed")
        self.assertEqual(json.loads(cleanup.audit_path(task, Path(path)).read_text())["status"], "removing")
        self.assertTrue(Path(path).is_dir())

    def test_controller_timeout_or_interrupt_does_not_stop_owned_worker(self):
        args = SimpleNamespace(cmd="finish", task_dir="/fixture/task", repo="/fixture/source", key="pr-1",
                               expect_head="1" * 40, apply=True)
        for error in (subprocess.TimeoutExpired("worker", 1), KeyboardInterrupt()):
            with self.subTest(error=type(error).__name__):
                worker = Mock()
                worker.wait.side_effect = error
                with patch.object(cleanup.subprocess, "Popen", return_value=worker) as spawn, redirect_stdout(io.StringIO()) as out:
                    self.assertEqual(cleanup.run(args), 2)
                self.assertTrue(spawn.call_args.kwargs["start_new_session"])
                self.assertIn("may still be running", json.loads(out.getvalue())["reason"])
                self.assertEqual(worker.mock_calls, [call.wait(timeout=cleanup.COPY_WORKER_WAIT_SECONDS)])

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
