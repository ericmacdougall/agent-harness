import json
import os
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "harness" / "hooks"))
import workdir  # noqa: E402

UUID = "0f8fad5b-d9cb-469f-a165-70867728950e"
OTHER_UUID = "7c9e6679-7425-40de-944b-e07fc1f90ae7"
DAY = 86400


class HomeCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name).resolve()
        env = patch.dict(os.environ, {"HOME": str(self.home), "TMPDIR": "/private/var/folders/zz/T/"})
        env.start()
        self.addCleanup(env.stop)
        self.work = self.home / ".agent-harness" / "work"
        self.scratch = self.home / ".agent-harness" / "scratch"


class AdvisoryTests(HomeCase):
    def paths(self, tool, tool_input, scratchpad=None):
        return workdir.tmp_advisory(tool, tool_input, scratchpad)

    def test_write_tools_flag_durable_state_in_tmp(self):
        for path in ("/tmp/fix.py", "/private/tmp/run.sh", "/tmp/classify.tsv", "/tmp/rclone-filter.txt",
                     "/tmp/run-kit.json", "/tmp/kit", "/private/var/folders/zz/T/pr-packet.md",
                     "/dev/shm/job.yaml"):
            with self.subTest(path=path):
                self.assertEqual(self.paths("Write", {"file_path": path}), [(path, "tmp")])
        self.assertEqual(self.paths("Edit", {"file_path": "/tmp/a.js"}), [("/tmp/a.js", "tmp")])
        self.assertEqual(self.paths("NotebookEdit", {"notebook_path": "/tmp/n.py"}), [("/tmp/n.py", "tmp")])

    def test_disposable_output_and_durable_locations_are_not_flagged(self):
        for path in ("/tmp/out.log", "/tmp/shot.png", "/tmp/toolkit.bin", "/tmp/build.o",
                     str(self.work / "s1" / "fix.py"), "/Users/someone/project/fix.py", "relative/fix.py"):
            with self.subTest(path=path):
                self.assertEqual(self.paths("Write", {"file_path": path}), [])
        self.assertEqual(self.paths("Read", {"file_path": "/tmp/fix.py"}), [])

    def test_scratchpad_locations_get_their_own_kind(self):
        tmp_pad = f"/private/tmp/claude-501/-Users-x/{UUID}/scratchpad"
        self.assertEqual(self.paths("Write", {"file_path": tmp_pad + "/kit.json"}, tmp_pad),
                         [(tmp_pad + "/kit.json", "tmp")])
        durable_pad = str(self.scratch / "claude-501" / "-Users-x" / UUID / "scratchpad")
        self.assertEqual(self.paths("Write", {"file_path": durable_pad + "/run.sh"}, durable_pad),
                         [(durable_pad + "/run.sh", "scratch")])
        elsewhere = f"/Volumes/x/claude-501/-Users-x/{UUID}/scratchpad/plan.sh"
        self.assertEqual(self.paths("Write", {"file_path": elsewhere}), [(elsewhere, "scratch")])
        # Notes and data in the reboot-surviving scratchpad are expected; kits and scripts are not.
        for name in ("notes.md", "rows.tsv", "result.json"):
            self.assertEqual(self.paths("Write", {"file_path": durable_pad + "/" + name}, durable_pad), [])
        self.assertEqual(self.paths("Write", {"file_path": durable_pad + "/run-kit.json"}, durable_pad),
                         [(durable_pad + "/run-kit.json", "scratch")])

    def test_bash_creation_forms(self):
        cases = {
            "cat > /tmp/a.sh <<'EOF'\necho hi\nEOF": ["/tmp/a.sh"],
            "echo x >/tmp/x.py": ["/tmp/x.py"],
            "make 2>>/tmp/err.txt": ["/tmp/err.txt"],
            "ls | tee -a /tmp/list.tsv": ["/tmp/list.tsv"],
            "cp scripts/a.py /tmp/": ["/tmp/a.py"],
            "mv kit.json /private/tmp/run-kit.json": ["/private/tmp/run-kit.json"],
            "curl -sS -o /tmp/f.json https://example.invalid/x": ["/tmp/f.json"],
            "touch /tmp/state.json && echo done": ["/tmp/state.json"],
            "FOO=1 sudo tee /tmp/a.conf < in": ["/tmp/a.conf"],
            "printf x > \"$TMPDIR/k.json\"": ["/private/var/folders/zz/T/k.json"],
            "echo 'unterminated > /tmp/q.sh": ["/tmp/q.sh"],
            "sudo -u svc tee /tmp/a.sh < in": ["/tmp/a.sh"],
            "curl -o/tmp/a.json https://example.invalid": ["/tmp/a.json"],
            "wget --output-document=/tmp/b.json https://example.invalid": ["/tmp/b.json"],
            "cp -t /tmp/d a.py b.sh": ["/tmp/d/a.py", "/tmp/d/b.sh"],
        }
        for command, expected in cases.items():
            with self.subTest(command=command):
                self.assertEqual([p for p, _ in self.paths("Bash", {"command": command})], expected)

    def test_bash_non_creation_is_not_flagged(self):
        for command in ("python3 /tmp/x.py", "cat /tmp/a.sh", "echo hi > /dev/null", "ls /tmp",
                        "grep x < /tmp/in.txt", "make > /tmp/build.log 2>&1",
                        f"echo x > {self.work}/s/a.py", "mkdir -p /tmp/dir"):
            with self.subTest(command=command):
                self.assertEqual(self.paths("Bash", {"command": command}), [])

    def test_malformed_and_oversized_inputs_are_ignored(self):
        self.assertEqual(self.paths("Bash", "not a dict"), [])
        self.assertEqual(self.paths("Bash", {"command": 42}), [])
        self.assertEqual(self.paths("Write", {"file_path": None}), [])
        huge = "cat > /tmp/a.sh <<'EOF'\n" + "x" * (workdir.MAX_ADVISORY_INPUT + 1) + "\nEOF"
        self.assertEqual(self.paths("Bash", {"command": huge}), [])

    def test_many_targets_stay_fast_and_bounded(self):
        command = "cp " + " ".join(f"s/abc{i}.sh" for i in range(9000)) + " /tmp/d"
        command = command[:workdir.MAX_ADVISORY_INPUT - 10] + " /tmp/d"
        started = time.monotonic()
        found = self.paths("Bash", {"command": command})
        self.assertLess(time.monotonic() - started, 1.5)
        self.assertLessEqual(len(found), workdir.MAX_ADVISORY_CANDIDATES)
        self.assertEqual(len(found), workdir.MAX_ADVISORY_CANDIDATES)
        self.assertEqual(found[0], ("/tmp/d/abc0.sh", "tmp"))

    def test_message_names_durable_dir_and_location(self):
        message = workdir.advisory_message([("/tmp/a.py", "tmp")], "Session-1")
        self.assertIn(str(self.work) + "/", message)
        self.assertIn("reboot wipes", message)
        self.assertIn("not blocked", message)
        scratch = workdir.advisory_message([("/x/a.py", "scratch")], "s")
        self.assertIn("pruned after", scratch)
        self.assertNotIn("reboot wipes", scratch)

    def test_drift_warning_only_for_reboot_wiped_scratchpad(self):
        self.assertIn("not in effect",
                      workdir.scratchpad_drift_warning(f"/private/tmp/claude-501/p/{UUID}/scratchpad"))
        self.assertEqual(workdir.scratchpad_drift_warning(
            str(self.scratch / "claude-501" / "p" / UUID / "scratchpad")), "")
        self.assertEqual(workdir.scratchpad_drift_warning(None), "")


class SessionDirTests(HomeCase):
    def test_creates_private_dir_and_marker_idempotently(self):
        path = workdir.ensure_session_dir(UUID)
        self.assertEqual(path, self.work / UUID)
        for folder in (self.work, path):
            self.assertEqual(stat.S_IMODE(folder.stat().st_mode), 0o700, folder)
        marker = path / workdir.MARKER
        self.assertEqual(stat.S_IMODE(marker.stat().st_mode), 0o600)
        self.assertEqual(json.loads(marker.read_text())["session_id"], UUID)
        first = marker.read_text()
        self.assertEqual(workdir.ensure_session_dir(UUID), path)
        self.assertEqual(marker.read_text(), first)

    def test_escapes_unsafe_session_ids(self):
        path = workdir.ensure_session_dir("../Evil/ID")
        self.assertEqual(path.parent, self.work)
        self.assertTrue(path.name.startswith("z-"))

    def test_refuses_symlinked_session_dir_and_root(self):
        outside = self.home / "outside"
        outside.mkdir()
        self.work.mkdir(parents=True)
        (self.work / UUID).symlink_to(outside)
        with self.assertRaises(OSError):
            workdir.ensure_session_dir(UUID)
        self.assertEqual(list(outside.iterdir()), [])
        (self.work / UUID).unlink()
        self.work.rmdir()
        self.work.symlink_to(outside)
        with self.assertRaises(OSError):
            workdir.ensure_session_dir(UUID)
        self.assertEqual(list(outside.iterdir()), [])


class PruneTests(HomeCase):
    def age(self, path: Path, days: float):
        moment = time.time() - days * DAY
        for root, dirs, files in os.walk(path):
            for name in dirs + files:
                os.utime(os.path.join(root, name), (moment, moment), follow_symlinks=False)
        os.utime(path, (moment, moment))

    def wal(self, session, events, days):
        wal = self.home / ".claude" / "wals" / session / "main.jsonl"
        wal.parent.mkdir(parents=True, exist_ok=True)
        wal.write_text("".join(json.dumps(e if isinstance(e, dict) else {"event": e}) + "\n" for e in events))
        self.age(wal.parent, days)
        return wal

    def work_dir(self, session, days, events=("intent",), wal_days=None):
        path = workdir.ensure_session_dir(session)
        (path / "kit.json").write_text("{}")
        (path / "nested").mkdir()
        (path / "nested" / "job.tsv").write_text("a\tb\n")
        self.age(path, days)
        self.wal(session, events, days if wal_days is None else wal_days)
        return path

    def run_prune(self, apply, **kwargs):
        return workdir.prune(apply, **kwargs)

    def test_dry_run_lists_and_apply_removes_only_eligible(self):
        old = self.work_dir("old-session", 50)
        fresh = self.work_dir("fresh-session", 2)
        dry = self.run_prune(False)
        self.assertEqual(dry["status"], "DRY_RUN")
        self.assertEqual([c["path"] for c in dry["candidates"]], [str(old)])
        self.assertTrue(old.exists())
        applied = self.run_prune(True)
        self.assertEqual(applied["removed"], [str(old)])
        self.assertFalse(old.exists())
        self.assertTrue(fresh.exists())
        # WALs are never deleted.
        self.assertTrue((self.home / ".claude/wals/old-session/main.jsonl").exists())

    def test_explicit_done_marker_shortens_retention(self):
        done_note = {"event": "status", "note": "WORKDIR_DONE: delivered"}
        done = self.work_dir("done-session", 20, events=("intent", done_note, "pretool"))
        reopened = self.work_dir("reopened-session", 20, events=(done_note, "intent"))
        result_only = self.work_dir("result-session", 20, events=("result",))
        handed = self.work_dir("handed-session", 20, events=("handoff",))
        dotdone = self.work_dir("dotdone-session", 20)
        (dotdone / workdir.DONE).write_text("")
        self.age(dotdone, 20)
        paths = [c["path"] for c in self.run_prune(False)["candidates"]]
        self.assertEqual(sorted(paths), sorted([str(done), str(dotdone)]))
        for kept in (reopened, result_only, handed):
            self.assertNotIn(str(kept), paths)

    def test_never_prunes_unmarked_kept_symlinked_current_or_recent(self):
        unmarked = self.work / "managed-game-install-20261103"
        unmarked.mkdir(parents=True)
        (unmarked / "push_owned.py").write_text("x")
        self.age(unmarked, 400)
        kept = self.work_dir("kept-session", 400)
        (kept / workdir.KEEP).write_text("")
        self.age(kept, 400)
        target = self.work_dir("target-session", 400)
        (self.work / "link-session").symlink_to(target)
        current = self.work_dir("current-session", 400)
        recent_wal = self.work_dir("active-session", 400, wal_days=0.1)
        mismatched = self.work_dir("mismatch-session", 400)
        (mismatched / workdir.MARKER).write_text(json.dumps({"session_id": "someone-else"}))
        self.age(mismatched, 400)
        result = self.run_prune(True, current_session="current-session")
        self.assertEqual(result["removed"], [str(target)])
        for survivor in (unmarked, kept, current, recent_wal, mismatched):
            self.assertTrue(survivor.exists(), survivor)
        self.assertTrue((self.work / "link-session").is_symlink())

    def test_scratch_tree_sessions_pruned_and_unmanaged_reported(self):
        base = self.scratch / f"claude-{os.getuid()}"
        old = base / "-Users-x" / UUID
        (old / "scratchpad").mkdir(parents=True)
        (old / "tasks").mkdir()
        (old / "tasks" / "b1.output").write_text("out")
        self.age(old, 10)
        recent = base / "-Users-x" / OTHER_UUID
        (recent / "scratchpad").mkdir(parents=True)
        odd = base / "-Users-x" / "not-a-session"
        odd.mkdir()
        self.age(odd, 100)
        stray = base / "stray.sock"
        stray.write_text("")
        result = self.run_prune(True)
        self.assertEqual((result["removed"], result["partially_removed"]), ([], [str(old)]))
        # Claude task output is kept unless explicitly included; the scratchpad is removed.
        self.assertFalse((old / "scratchpad").exists())
        self.assertTrue((old / "tasks" / "b1.output").exists())
        self.age(old, 10)
        again = self.run_prune(True, include_task_output=True)
        self.assertEqual(again["removed"], [str(old)])
        self.assertFalse(old.exists())
        unmanaged = {c["path"] for c in result["candidates"] if c["kind"] == "unmanaged"}
        self.assertEqual(unmanaged, {str(odd), str(stray)})
        for survivor in (recent, odd, stray):
            self.assertTrue(survivor.exists(), survivor)

    def test_keep_file_protects_scratch_sessions(self):
        old = self.scratch / f"claude-{os.getuid()}" / "-Users-x" / UUID
        (old / "scratchpad").mkdir(parents=True)
        (old / "scratchpad" / "kit.json").write_text("{}")
        (old / workdir.KEEP).write_text("")
        self.age(old, 30)
        self.assertEqual(self.run_prune(True)["removed"], [])
        self.assertTrue((old / "scratchpad" / "kit.json").exists())
        self.assertEqual(workdir._quick_count(time.time(), None), (0, True))

    def test_live_transcript_keeps_session(self):
        old = self.scratch / f"claude-{os.getuid()}" / "-Users-x" / UUID
        old.mkdir(parents=True)
        self.age(old, 30)
        transcript = self.home / ".claude" / "projects" / "-Users-x" / f"{UUID}.jsonl"
        transcript.parent.mkdir(parents=True)
        transcript.write_text("{}\n")
        self.assertEqual(self.run_prune(True)["removed"], [])
        work = self.work_dir(OTHER_UUID, 100)
        other = self.home / ".claude" / "projects" / "-Elsewhere" / f"{OTHER_UUID}.jsonl"
        other.parent.mkdir(parents=True)
        other.write_text("{}\n")
        self.assertNotIn(str(work), [c["path"] for c in self.run_prune(False)["candidates"]])

    def test_scratch_session_with_recent_wal_is_kept(self):
        old = self.scratch / f"claude-{os.getuid()}" / "-p" / UUID
        old.mkdir(parents=True)
        self.age(old, 30)
        self.wal(UUID, ("intent",), 0.1)
        self.assertEqual(self.run_prune(True)["removed"], [])
        self.assertTrue(old.exists())

    def test_over_budget_tree_needs_review_and_is_kept(self):
        old = self.work_dir("big-session", 100)
        with patch.object(workdir, "WALK_BUDGET", 2):
            result = self.run_prune(True)
        self.assertEqual(result["removed"], [])
        self.assertTrue(result["candidates"][0]["reason"].startswith("needs_review"))
        self.assertTrue(old.exists())

    def test_nested_recent_write_keeps_dir_alive(self):
        path = self.work_dir("nested-session", 100)
        os.utime(path / "nested" / "job.tsv")  # successor touched a nested file today
        self.assertEqual(self.run_prune(False)["candidates"], [])

    def test_refuses_when_rmtree_is_not_symlink_safe(self):
        old = self.work_dir("old-session", 100)
        with patch.object(workdir.shutil, "rmtree", lambda path: None):
            result = self.run_prune(True)
        self.assertEqual(result["status"], "REFUSED")
        self.assertTrue(old.exists())

    def test_cli_rejects_short_retention_and_defaults_to_dry_run(self):
        with self.assertRaises(SystemExit):
            workdir.main(["prune", "--idle-days", "0.5"])
        old = self.work_dir("old-session", 100)
        with patch("sys.stdout"):
            self.assertEqual(workdir.main(["prune"]), 0)
        self.assertTrue(old.exists())

    def test_retention_hint_is_daily_and_never_deletes(self):
        old = self.work_dir("old-session", 100)
        hint = workdir.retention_hint("current")
        self.assertIn("About 1 durable work or scratch directories", hint)
        self.assertEqual(workdir.retention_hint("current"), "")
        self.assertTrue(old.exists())


class TaskOutputPruneTests(HomeCase):
    def make(self, name, days, session=UUID):
        tasks = self.scratch / f"claude-{os.getuid()}" / "-Users-x" / session / "tasks"
        tasks.mkdir(parents=True, exist_ok=True)
        path = tasks / name
        path.write_text("secret-bearing output")
        moment = time.time() - days * DAY
        os.utime(path, (moment, moment))
        return path

    def test_removes_old_unopened_output_only(self):
        old = self.make("b1.output", 20)
        held = self.make("b2.output", 20)
        recent = self.make("b3.output", 3)
        other = self.make("notes.txt", 40)
        result = workdir.prune_task_output(True, open_check=lambda paths: {os.path.realpath(held)})
        self.assertEqual(result["removed"], [str(old)])
        for survivor in (held, recent, other):
            self.assertTrue(survivor.exists(), survivor)
        self.assertFalse(old.exists())

    def test_unknown_open_state_deletes_nothing(self):
        old = self.make("b1.output", 20)
        result = workdir.prune_task_output(True, open_check=lambda paths: None)
        self.assertEqual(result["status"], "SKIPPED")
        self.assertTrue(old.exists())

    def test_dry_run_and_symlinked_tasks_are_untouched(self):
        old = self.make("b1.output", 20)
        self.assertEqual(workdir.prune_task_output(False, open_check=lambda p: set())["removed"], [])
        self.assertTrue(old.exists())
        outside = self.home / "outside"
        outside.mkdir()
        target = outside / "x.output"
        target.write_text("keep")
        os.utime(target, (0, 0))
        link_session = self.scratch / f"claude-{os.getuid()}" / "-Users-x" / OTHER_UUID
        link_session.mkdir(parents=True)
        (link_session / "tasks").symlink_to(outside)
        workdir.prune_task_output(True, open_check=lambda p: set())
        self.assertTrue(target.exists())

    def test_real_open_check_sees_a_held_file(self):
        held = self.make("b1.output", 20)
        free = self.make("b2.output", 20)
        with open(held):
            found = workdir.open_files([held, free])
        if found is None:
            self.skipTest("no /proc or lsof on this host")
        self.assertEqual(found, {os.path.realpath(held)})

    def test_lsof_errors_mean_unknown(self):
        with patch.object(workdir.os.path, "isdir", lambda p: False if p == "/proc/self/fd" else os.path.isdir(p)):
            result = workdir.open_files([Path("/x/a.output")], run=lambda *a, **k: subprocess.CompletedProcess(a[0], 2, "", "err"))
        self.assertIsNone(result)

    def test_session_start_spawn_is_daily_and_detached(self):
        self.make("b1.output", 20)
        calls = []
        popen = lambda args, **kwargs: calls.append((args, kwargs))
        self.assertTrue(workdir.spawn_task_output_prune(popen=popen))
        self.assertFalse(workdir.spawn_task_output_prune(popen=popen))
        self.assertEqual(len(calls), 1)
        args, kwargs = calls[0]
        self.assertEqual(args[2:4], ["prune-task-output", "--apply"])
        self.assertTrue(kwargs["start_new_session"])
        self.assertEqual(kwargs["stdout"], subprocess.DEVNULL)


if __name__ == "__main__":
    unittest.main()
