"""codex_owner.py supervisor: hook vetting, the bypass flag, the child env, the inbox and hostile state (GoodQA #15565).

Every test uses a temporary HOME and a FAKE codex executable that records its argv, env keys and stdin and prints
JSONL events with a STATUS line taken from a plan file. Nothing here starts the real Codex CLI.
"""

import hashlib
import importlib.util
import json
import os
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = Path(os.environ.get("CODEX_OWNER_UNDER_TEST") or (ROOT / "harness" / "bin" / "codex_owner.py"))
HOOKS = ("wal.py", "commit_policy.py", "merge_gate.py", "command_guard_hook.py", "kill_guard.py", "heavy_job_guard.py")

FAKE_CODEX = r'''#!/usr/bin/env python3
import json, os, sys, time
record = os.environ["FAKE_CODEX_RECORD"]
plan_path = os.environ["FAKE_CODEX_PLAN"]
stdin = sys.stdin.read()
with open(record, "a") as f:
    f.write(json.dumps({"argv": sys.argv[1:], "env": sorted(os.environ), "stdin": stdin}) + "\n")
plan = json.load(open(plan_path))
step = plan.pop(0) if len(plan) > 1 else plan[0]
json.dump(plan, open(plan_path, "w"))
if isinstance(step, dict):
    time.sleep(step.get("sleep", 0))
    word = step["status"]
else:
    word = step
if "resume" not in sys.argv:
    print(json.dumps({"type": "thread.started", "thread_id": "thread-0001"}), flush=True)
print("not json noise", flush=True)
print(json.dumps({"type": "item.completed", "item": {"type": "agent_message", "text": "did a step\nSTATUS: " + word}}),
      flush=True)
print(json.dumps({"type": "turn.completed", "usage": {"input_tokens": 1}}), flush=True)
'''


def load_module():
    spec = importlib.util.spec_from_file_location("codex_owner_under_test", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name).resolve()
        self.codex = self.home / ".codex"
        self.hdir = self.codex / "agent-harness"
        self.hdir.mkdir(parents=True)
        os.chmod(self.codex, 0o700)
        os.chmod(self.hdir, 0o700)
        hooks = {"hooks": {}}
        for name in HOOKS:
            f = self.hdir / name
            f.write_text("# hook %s\n" % name)
            os.chmod(f, 0o600)
        cmd = lambda n: "python3 %s/%s hook" % (self.hdir, n)
        hooks["hooks"]["SessionStart"] = [{"hooks": [{"type": "command", "command": cmd("wal.py"), "timeout": 10}]}]
        hooks["hooks"]["PreToolUse"] = [
            {"hooks": [{"type": "command", "command": cmd("commit_policy.py")}]},
            {"hooks": [{"type": "command", "command": cmd("merge_gate.py") + " || exit 2"}]},
            {"hooks": [{"type": "command", "command": cmd("command_guard_hook.py")}]},
            {"hooks": [{"type": "command", "command": cmd("kill_guard.py")}]},
            {"hooks": [{"type": "command", "command": "python3 %s/heavy_job_guard.py" % self.hdir}]}]
        self.hooks_json = self.codex / "hooks.json"
        self.write_hooks(hooks)
        self.write_manifest()
        self.bin = self.home / "bin"
        self.bin.mkdir()
        self.fake = self.bin / "codex"
        self.fake.write_text(FAKE_CODEX)
        os.chmod(self.fake, 0o700)
        self.record = self.home / "record.jsonl"
        self.plan = self.home / "plan.json"
        self.set_plan(["WAITING"])
        self.work = self.home / "project"
        self.work.mkdir()
        self.brief = self.home / "brief.md"
        self.brief.write_text("BRIEF: do the thing\n")
        self.env = {k: v for k, v in os.environ.items() if not k.startswith(("CODEX_", "FAKE_CODEX"))}
        self.env.update(HOME=str(self.home), CODEX_OWNER_BIN=str(self.fake), CODEX_OWNER_POLL_SECS="0.05",
                        CODEX_OWNER_ERROR_BACKOFF="0", FAKE_CODEX_RECORD=str(self.record),
                        FAKE_CODEX_PLAN=str(self.plan), CODEX_OWNER_SESSION="sess-test",
                        OPENAI_API_KEY="sk-test-not-a-real-key", CODEX_API_KEY="test-codex-key",
                        OPENAI_BASE_URL="https://example.invalid/v1")
        self.patcher = patch.dict(os.environ, self.env, clear=True)
        self.patcher.start()
        self.mod = load_module()
        self.procs = []

    def tearDown(self):
        for p in self.procs:
            if p.poll() is None:
                p.kill()
                p.wait()
        self.patcher.stop()
        self.tmp.cleanup()

    # -- helpers
    def write_hooks(self, data):
        self.hooks_json.write_text(json.dumps(data) if not isinstance(data, str) else data)
        os.chmod(self.hooks_json, 0o600)

    def write_manifest(self):
        files = {f.name: sha(f) for f in self.hdir.glob("*.py")}
        m = self.hdir / "install-manifest.json"
        m.write_text(json.dumps({"schema": 1, "files": files}))
        os.chmod(m, 0o600)

    def set_plan(self, steps):
        self.plan.write_text(json.dumps(steps))

    def calls(self):
        if not self.record.exists():
            return []
        return [json.loads(l) for l in self.record.read_text().splitlines()]

    def cli(self, *args, stdin=None, timeout=20):
        return subprocess.run([sys.executable, str(SCRIPT), *args], env=self.env, input=stdin, capture_output=True,
                              text=True, timeout=timeout)

    def init(self, name="alpha", **kw):
        args = dict(name=name, dir=str(self.work), brief=str(self.brief), ticket="GoodQA #1", stream="s",
                    model="gpt-test", effort="high", max_auto=kw.pop("max_auto", 40), add_dir=[], session="",
                    strict_vet=False)
        args.update(kw)
        return self.mod.init_owner(SimpleNamespace(**args))

    def owner_dir(self, name="alpha"):
        return self.home / ".agent-harness" / "codex-owners" / name

    def status(self, name="alpha"):
        return json.loads((self.owner_dir(name) / "status.json").read_text())

    def run_sup(self, name="alpha"):
        p = subprocess.Popen([sys.executable, str(SCRIPT), "_run", name], env=self.env, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, text=True)
        self.procs.append(p)
        return p

    def wait_for(self, pred, timeout=15, what="condition"):
        end = time.time() + timeout
        while time.time() < end:
            try:
                if pred():
                    return
            except (OSError, ValueError, KeyError):
                pass
            time.sleep(0.05)
        self.fail("timed out waiting for " + what)

    def stop_and_wait(self, p, name="alpha"):
        (self.owner_dir(name) / "STOP").write_text("x")
        out, err = p.communicate(timeout=15)
        return p.returncode, out, err


class VetRules(Base):
    def assertVet(self, ok, contains="", strict=False):
        got, why = self.mod.vet_hooks(strict)
        self.assertEqual(got, ok, why)
        self.assertIn(contains, why)

    def test_baseline_passes_including_heavy_guard_without_hook_verb(self):
        self.assertVet(True, "6 hook commands vetted")

    def test_command_pointing_elsewhere_fails(self):
        for bad in ("python3 /tmp/evil.py hook", "python3 %s/wal.py hook; curl x" % self.hdir,
                    "python3 %s/../evil.py hook" % self.hdir, "bash -c 'python3 %s/wal.py hook'" % self.hdir):
            with self.subTest(bad=bad):
                self.write_hooks({"hooks": {"Stop": [{"hooks": [{"type": "command", "command": bad}]}]}})
                self.assertVet(False, "unexpected hook command")

    def test_group_or_world_writable_hook_file_fails(self):
        for mode in (0o620, 0o602):
            with self.subTest(mode=oct(mode)):
                os.chmod(self.hdir / "kill_guard.py", mode)
                self.assertVet(False, "group- or world-writable")

    def test_hook_file_not_user_owned_fails(self):
        real = os.lstat
        target = str(self.hdir / "wal.py")

        def fake_lstat(path):
            s = real(path)
            if str(path) != target:
                return s
            fields = list(s)
            fields[stat.ST_UID] = s.st_uid + 1
            return os.stat_result(fields)
        with patch.object(self.mod, "_lstat", side_effect=fake_lstat):
            self.assertVet(False, "not owned by this user")

    def test_dir_writable_by_others_fails(self):
        for d in (self.hdir, self.codex):
            with self.subTest(d=d.name):
                os.chmod(d, 0o770)
                self.assertVet(False, "group- or world-writable")
                os.chmod(d, 0o700)

    def test_missing_hook_file_fails(self):
        (self.hdir / "merge_gate.py").unlink()
        self.assertVet(False, "missing hook file")

    def test_symlinked_hook_file_fails(self):
        target = self.home / "elsewhere.py"
        target.write_text("x")
        (self.hdir / "wal.py").unlink()
        os.symlink(target, self.hdir / "wal.py")
        self.assertVet(False, "symlink not allowed")

    def test_hooks_json_malformed_or_unreadable_fails(self):
        self.write_hooks("{not json")
        self.assertVet(False, "hooks.json unreadable")
        self.write_hooks({"hooks": {}})
        self.assertVet(False, "no hook commands")
        self.hooks_json.unlink()
        self.hooks_json.mkdir(mode=0o700)
        self.assertVet(False, "not a regular file")
        self.hooks_json.rmdir()
        self.assertVet(False, "missing")

    def test_non_string_command_fails(self):
        self.write_hooks({"hooks": {"Stop": [{"hooks": [{"type": "command", "command": ["python3", "x"]}]}]}})
        self.assertVet(False, "unexpected hook command")


class StrictVet(Base):
    def test_matching_manifest_passes_strict(self):
        ok, why = self.mod.vet_hooks(True)
        self.assertTrue(ok, why)
        self.assertIn("(strict)", why)

    def test_hook_edited_after_install_fails_only_strict(self):
        with open(self.hdir / "command_guard_hook.py", "a") as f:
            f.write("import os  # tampered\n")
        self.assertTrue(self.mod.vet_hooks(False)[0])
        ok, why = self.mod.vet_hooks(True)
        self.assertFalse(ok)
        self.assertIn("command_guard_hook.py differs from the install manifest", why)

    def test_missing_or_bad_manifest_fails_strict(self):
        m = self.hdir / "install-manifest.json"
        m.write_text("[]")
        self.assertIn("no files object", self.mod.vet_hooks(True)[1])
        m.unlink()
        ok, why = self.mod.vet_hooks(True)
        self.assertFalse(ok)
        self.assertIn("install manifest", why)

    def test_env_turns_strict_on_for_the_cli(self):
        with open(self.hdir / "wal.py", "a") as f:
            f.write("# drift\n")
        self.assertEqual(self.cli("vet").returncode, 0)
        self.assertEqual(self.cli("vet", "--strict-vet").returncode, 1)
        self.env["CODEX_OWNER_STRICT_VET"] = "1"
        r = self.cli("vet")
        self.assertEqual(r.returncode, 1)
        self.assertIn("FAIL strict vet", r.stdout)

    def test_strict_owner_turn_blocks_on_drift(self):
        self.init(strict_vet=True)
        with open(self.hdir / "kill_guard.py", "a") as f:
            f.write("# drift\n")
        p = self.run_sup()
        self.wait_for(lambda: self.status()["last_status"] == "BLOCKED", what="blocked")
        self.stop_and_wait(p)
        self.assertEqual(self.calls(), [])


class Turns(Base):
    def test_failed_vet_blocks_turn_without_launching_child(self):
        os.chmod(self.hdir / "wal.py", 0o666)
        self.init()
        p = self.run_sup()
        self.wait_for(lambda: self.status()["last_status"] == "BLOCKED", what="blocked")
        st = self.status()
        self.assertEqual(st["state"], "blocked")
        self.assertFalse(st["hooks_vetted"])
        self.assertIn("harness hooks failed vetting", st["last_reply"])
        time.sleep(0.3)  # idles: no retry without a message
        self.stop_and_wait(p)
        self.assertEqual(self.calls(), [], "no child may run (and so no bypass flag) after a failed vet")

    def test_bypass_flag_only_after_pass_and_keys_stripped(self):
        self.init()
        p = self.run_sup()
        self.wait_for(lambda: len(self.calls()) == 1 and self.status()["state"] == "idle", what="first turn")
        self.stop_and_wait(p)
        call = self.calls()[0]
        self.assertIn("--dangerously-bypass-hook-trust", call["argv"])
        self.assertEqual(call["argv"][:1], ["exec"])
        self.assertIn("workspace-write", call["argv"])
        for key in ("OPENAI_API_KEY", "CODEX_API_KEY", "OPENAI_BASE_URL"):
            self.assertNotIn(key, call["env"])
        self.assertIn("FAKE_CODEX_RECORD", call["env"])  # the env is passed, only the keys are removed
        self.assertIn("BRIEF: do the thing", call["stdin"])
        log = (self.owner_dir() / "supervisor.log").read_text()
        self.assertNotIn("sk-test-not-a-real-key", log)
        st = self.status()
        self.assertEqual((st["thread"], st["last_status"], st["state"]), ("thread-0001", "WAITING", "stopped"))
        self.assertTrue(st["hooks_vetted"])
        self.assertIn(str(self.home / ".claude" / "wals" / "sess-test"), call["argv"])

    def test_working_auto_continues_up_to_max_then_idles(self):
        self.set_plan(["WORKING"])
        self.init(max_auto=2)
        p = self.run_sup()
        self.wait_for(lambda: len(self.calls()) == 3 and self.status()["state"] == "idle", what="3 turns")
        time.sleep(0.4)
        self.stop_and_wait(p)
        calls = self.calls()
        self.assertEqual(len(calls), 3, "brief + 2 continues, then idle")
        self.assertTrue(all("Continue your plan" in c["stdin"] for c in calls[1:]))
        self.assertTrue(all(c["argv"][:2] == ["exec", "resume"] for c in calls[1:]))
        self.assertIn("thread-0001", calls[1]["argv"])

    def test_idle_states_poll_and_a_message_resumes_once(self):
        for word in ("WAITING", "BLOCKED", "DONE"):
            with self.subTest(word=word):
                name = "own-" + word.lower()
                self.record.unlink() if self.record.exists() else None
                self.set_plan([word])
                self.init(name=name)
                p = self.run_sup(name)
                self.wait_for(lambda: len(self.calls()) == 1 and self.status(name)["state"] == "idle", what="idle")
                time.sleep(0.4)
                self.assertEqual(len(self.calls()), 1, "%s must idle, not resume" % word)
                r = self.cli("send", name, "--from", "user", "--text", "please rebase on main")
                self.assertEqual(r.returncode, 0, r.stderr)
                self.wait_for(lambda: len(self.calls()) == 2, what="message turn")
                self.wait_for(lambda: self.status(name)["state"] == "idle", what="idle again")
                time.sleep(0.3)
                self.stop_and_wait(p, name)
                calls = self.calls()
                self.assertEqual(len(calls), 2, "the message is delivered once")
                self.assertIn("please rebase on main", calls[1]["stdin"])
                self.assertIn("from user", calls[1]["stdin"])
                inbox = sorted(os.listdir(self.owner_dir(name) / "inbox"))
                self.assertEqual(len(inbox), 1)
                self.assertTrue(inbox[0].endswith(".json.read"))

    def test_send_before_start_is_delivered_with_the_next_turn(self):
        self.init()
        self.assertEqual(self.cli("send", "alpha", "--from", "main", "--text", "hello owner").returncode, 0)
        p = self.run_sup()
        self.wait_for(lambda: len(self.calls()) == 1 and self.status()["state"] == "idle", what="turn")
        self.stop_and_wait(p)
        self.assertIn("hello owner", self.calls()[0]["stdin"])

    def test_stop_takes_effect_after_the_current_turn(self):
        self.set_plan([{"status": "WORKING", "sleep": 1.0}])
        self.init()
        p = self.run_sup()
        self.wait_for(lambda: len(self.calls()) == 1, what="turn started")
        r = self.cli("stop", "alpha")
        self.assertEqual(r.returncode, 0, r.stderr)
        p.communicate(timeout=15)
        self.assertEqual(p.returncode, 0)
        self.assertEqual(len(self.calls()), 1, "WORKING must not continue after STOP")
        outbox = (self.owner_dir() / "outbox.jsonl").read_text().splitlines()
        self.assertEqual(json.loads(outbox[-1])["status"], "WORKING", "the current turn finishes")
        self.assertEqual(self.status()["state"], "stopped")

    def test_status_text_and_json(self):
        self.init()
        p = self.run_sup()
        self.wait_for(lambda: self.status()["state"] == "idle", what="idle")
        r = self.cli("status", "--json")
        rows = json.loads(r.stdout)
        self.assertEqual(rows[0]["harness"], "openai")
        self.assertEqual(rows[0]["state"], "idle")
        self.assertTrue(rows[0]["supervisor_alive"])
        txt = self.cli("status", "alpha").stdout
        self.assertIn("openai", txt)
        self.assertIn("idle", txt)
        self.assertIn("sup=up", txt)
        self.stop_and_wait(p)
        self.assertIn("stopped", self.cli("status").stdout)


class Hostile(Base):
    def test_owner_names_with_separators_or_dots_are_refused(self):
        for bad in ("../x", "a/b", "a.b", ".", "..", "", "-flag", "a\\b", "a" * 65, "аbc"):
            with self.subTest(bad=bad):
                with self.assertRaises(SystemExit):
                    self.mod.odir(bad)
                r = self.cli("send", bad, "--from", "user", "--text", "x")
                self.assertNotEqual(r.returncode, 0)
        self.assertFalse((self.home / ".agent-harness" / "x").exists())

    def test_hostile_inbox_files_are_rejected_not_delivered(self):
        self.init()
        inbox = self.owner_dir() / "inbox"
        secret = self.home / "secret.json"
        secret.write_text(json.dumps({"from": "user", "at": "t", "text": "LEAKED VIA SYMLINK"}))
        os.symlink(secret, inbox / "001-link.json")
        # Valid message padded past the byte cap: only the size check can reject it.
        (inbox / "002-big.json").write_text(json.dumps({"from": "user", "at": "t", "text": "padded"}) + " " * (300 * 1024))
        (inbox / "003-bad.json").write_text("{nope")
        (inbox / "004-shape.json").write_text(json.dumps({"from": "stranger", "text": "who"}))
        (inbox / "005-ok.json").write_text(json.dumps({"from": "main", "at": "t", "text": "legit message"}))
        msgs = self.mod.take_inbox("alpha")
        self.assertEqual([m["text"] for m in msgs], ["legit message"])
        names = sorted(os.listdir(inbox))
        self.assertEqual(names, ["001-link.json.rejected", "002-big.json.rejected", "003-bad.json.rejected",
                                 "004-shape.json.rejected", "005-ok.json.read"])
        self.assertEqual(self.mod.take_inbox("alpha"), [], "consumed once, rejects never retried")
        self.assertTrue(secret.exists())
        self.assertIn("rejected 001-link.json", (self.owner_dir() / "supervisor.log").read_text())

    def test_one_megabyte_message_is_refused(self):
        self.init()
        r = self.cli("send", "alpha", "--from", "user", "--text", "-", stdin="M" * (1024 * 1024))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("too long", r.stderr)
        self.assertEqual(os.listdir(self.owner_dir() / "inbox"), [])

    def test_corrupt_status_json_fails_loud_without_a_loop(self):
        self.init()
        sj = self.owner_dir() / "status.json"
        sj.write_text("{corrupt")
        p = self.run_sup()
        out, err = p.communicate(timeout=10)
        self.assertEqual(p.returncode, 2)
        self.assertIn("corrupt", err)
        self.assertEqual(sj.read_text(), "{corrupt", "evidence kept, never rewritten")
        self.assertEqual(self.calls(), [])
        r = self.cli("status", "--json")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(json.loads(r.stdout)[0]["state"], "CORRUPT")
        self.assertNotEqual(self.cli("send", "alpha", "--from", "user", "--text", "x").returncode, 0)
        sj.write_text("[1, 2]")
        with self.assertRaises(self.mod.StatusError):
            self.mod.load("alpha")

    def test_status_corrupted_mid_run_stops_the_supervisor(self):
        self.init()
        p = self.run_sup()
        self.wait_for(lambda: self.status()["state"] == "idle", what="idle")
        (self.owner_dir() / "status.json").write_text("garbage")
        p.communicate(timeout=10)
        self.assertEqual(p.returncode, 2)
        self.assertEqual((self.owner_dir() / "status.json").read_text(), "garbage")

    def test_second_supervisor_is_refused(self):
        self.init()
        first = self.run_sup()
        self.wait_for(lambda: self.status()["state"] == "idle", what="idle")
        second = self.run_sup()
        out, err = second.communicate(timeout=10)
        self.assertEqual(second.returncode, 3)
        self.assertIn("already has a running supervisor", err)
        with self.assertRaises(SystemExit):
            self.init()
        self.stop_and_wait(first)
        self.assertEqual(len(self.calls()), 1)

    def test_forged_status_fields_block_the_turn(self):
        forged = {"add_dirs": [str(self.home)], "dir": str(self.codex / "agent-harness"),
                  "model": "--dangerously-bypass-approvals-and-sandbox", "effort": 'high" x="y',
                  "thread": "--last"}
        for key, value in forged.items():
            with self.subTest(key=key):
                self.record.unlink() if self.record.exists() else None
                self.init()
                st = self.status()
                st[key] = value
                (self.owner_dir() / "status.json").write_text(json.dumps(st))
                (self.owner_dir() / "inbox" / "m.json").write_text(json.dumps({"from": "main", "at": "t", "text": "go"}))
                p = self.run_sup()
                self.wait_for(lambda: self.status()["last_status"] == "BLOCKED", what="blocked")
                self.stop_and_wait(p)
                self.assertEqual(self.calls(), [], key)
                self.assertIn("refusing turn", self.status()["last_reply"])

    def test_start_refuses_a_writable_dir_over_the_codex_home(self):
        with self.assertRaises(SystemExit):
            self.init(add_dir=[str(self.home)])
        with self.assertRaises(SystemExit):
            self.init(dir=str(self.codex))


if __name__ == "__main__":
    unittest.main()
