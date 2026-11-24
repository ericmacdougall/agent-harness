"""Checkout registry (goodqa#16947, spec v3): hook-written ownership rows for the checkouts agents create.

Every test runs with HOME set to a fresh temporary folder, real git repositories and real transcripts in it. Each
negative case first runs its positive control (the same fixture without the negative condition gives exactly one
row), then asserts no row AND the reason code from decisions.jsonl, so a dead hook cannot pass. Nothing reaches
another host: PR 1 starts no ssh.
"""
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import time
import types
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
HOOKS = ROOT / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
sys.path.insert(0, str(ROOT))
import checkout_registry as R  # noqa: E402

ENV = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@t", GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@t",
           GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_NOSYSTEM="1")


def sh(*a, cwd=None):
    return subprocess.run(a, cwd=cwd, check=True, capture_output=True, env=ENV, text=True).stdout


class Base(unittest.TestCase):
    def setUp(self):
        self.home = os.path.realpath(tempfile.mkdtemp(prefix="registry-home-"))
        self.addCleanup(shutil.rmtree, self.home, True)
        patcher = mock.patch.dict(os.environ, {"HOME": self.home})
        patcher.start()
        self.addCleanup(patcher.stop)
        os.environ.pop("CLAUDE_CONFIG_DIR", None)
        self.origin = os.path.join(self.home, "origin.git")
        sh("git", "init", "-q", "--bare", "-b", "main", self.origin)
        self.src = os.path.join(self.home, "src")
        sh("git", "init", "-q", "-b", "main", self.src)
        Path(self.src, "f.txt").write_text("x\n")
        Path(self.src, ".gitignore").write_text("build/\n")
        sh("git", "add", "f.txt", ".gitignore", cwd=self.src)
        sh("git", "commit", "-q", "-m", "one", cwd=self.src)
        sh("git", "remote", "add", "origin", self.origin, cwd=self.src)
        sh("git", "push", "-q", "origin", "main", cwd=self.src)
        self.proj = os.path.join(self.home, ".claude", "projects", "-tmp-proj")
        self.n = 0

    # transcripts ---------------------------------------------------------------------------------------------
    def main_transcript(self, session="s1"):
        p = os.path.join(self.proj, session + ".jsonl")
        os.makedirs(self.proj, exist_ok=True)
        if not os.path.exists(p):
            Path(p).write_text("")
        return p

    def sub_transcript(self, session="s1", agent="a1"):
        self.main_transcript(session)
        d = os.path.join(self.proj, session, "subagents")
        os.makedirs(d, exist_ok=True)
        p = os.path.join(d, "agent-%s.jsonl" % agent)
        if not os.path.exists(p):
            Path(p).write_text("")
        return p

    def record(self, tid, cmd, session="s1", agent="a1"):
        p = self.sub_transcript(session, agent) if agent else self.main_transcript(session)
        line = {"type": "assistant", "message": {"content": [{"type": "tool_use", "id": tid, "name": "Bash",
                                                              "input": {"command": cmd}}]}}
        with open(p, "a") as fh:
            fh.write(json.dumps(line) + "\n")

    # hook calls ----------------------------------------------------------------------------------------------
    def tid(self):
        self.n += 1
        return "toolu_%04d" % self.n

    def payload(self, cmd, tid, session="s1", agent="a1", cwd=None, tool="Bash", transcript=None):
        return {"session_id": session, "agent_id": agent, "tool_name": tool, "tool_use_id": tid,
                "cwd": cwd or self.home, "tool_input": {"command": cmd},
                "transcript_path": transcript or self.main_transcript(session)}

    def bash(self, cmd, action, session="s1", agent="a1", cwd=None, record=True, post_payload=None):
        """Transcript, PreToolUse, the command's real effect, PostToolUse: what Claude Code does for one call."""
        tid = self.tid()
        if record:
            self.record(tid, cmd, session, agent)
        R.pretool(self.payload(cmd, tid, session, agent, cwd))
        if action:
            action()
        rows = R.posttool(post_payload(tid) if post_payload else self.payload(cmd, tid, session, agent, cwd))
        self.last_tid = tid
        return rows

    def clone(self, dest, src=None):
        return lambda: sh("git", "clone", "-q", src or self.src, dest)

    def held(self):
        return list(R.current().values())

    def codes(self, tid=None):
        p = Path(self.home) / ".agent-harness/state/checkouts/decisions.jsonl"
        if not p.exists():
            return []
        out = [json.loads(l) for l in p.read_text().splitlines() if l.strip()]
        return [d["code"] for d in out if tid is None or d.get("tool_use_id") == tid]

    def assert_refused(self, code, rows):
        self.assertEqual(rows, [])
        self.assertIn(code, self.codes(self.last_tid), "the refusal must say why (AC-5)")

    def assert_one(self, rows):
        self.assertEqual(len(rows), 1, "positive control: %s" % self.codes(self.last_tid))
        return rows[0]


class Writer(Base):
    def test_clone_gets_one_row_with_payload_identity(self):
        dest = os.path.join(self.home, "c1")
        row = self.assert_one(self.bash("git clone %s %s 2>&1 | tail -3" % (self.src, dest), self.clone(dest)))
        st = os.lstat(dest)
        self.assertEqual((row["event"], row["kind"], row["host"], row["path"]), ("created", "clone", "local", dest))
        self.assertEqual((row["dev"], row["ino"], row["btime_ns"]), (st.st_dev, st.st_ino, R.birth_ns(dest)))
        self.assertEqual((row["session"], row["agent"], row["task"]), ("s1", "a1", None))
        self.assertEqual(row["common_dir"], os.path.join(dest, ".git"))
        self.assertTrue(R.verify(row))
        self.assertEqual(R.held(row)["session"], "s1")
        self.assertIn("written", self.codes(self.last_tid))

    def test_clone_into_cwd_uses_the_url_basename(self):
        work = os.path.join(self.home, "work")
        os.makedirs(work)
        row = self.assert_one(self.bash("git clone %s" % self.src, self.clone(os.path.join(work, "src")), cwd=work))
        self.assertEqual(row["path"], os.path.join(work, "src"))

    def test_worktree_add_gets_one_row(self):
        wt = os.path.join(self.home, "wt", "one")
        row = self.assert_one(self.bash("git -C %s worktree add %s -b feat >/dev/null 2>&1" % (self.src, wt),
                                        lambda: sh("git", "-C", self.src, "worktree", "add", "-q", wt, "-b", "feat")))
        self.assertEqual((row["kind"], row["path"]), ("worktree", wt))
        self.assertEqual(row["common_dir"], os.path.join(self.src, ".git"))

    def test_main_session_row_has_no_agent(self):
        dest = os.path.join(self.home, "c2")
        row = self.assert_one(self.bash("git clone %s %s" % (self.src, dest), self.clone(dest), agent=None))
        self.assertIsNone(row["agent"])

    def test_failed_bash_call_still_registers_what_it_made(self):
        dest = os.path.join(self.home, "c3")
        cmd = "git clone %s %s && false" % (self.src, dest)
        tid = self.tid()
        self.record(tid, cmd)
        R.pretool(self.payload(cmd, tid))
        self.clone(dest)()
        R.hook("posttool-failure", io.StringIO(json.dumps(self.payload(cmd, tid))))
        self.assertEqual([r["path"] for r in self.held()], [dest])

    # NEG-1
    def test_existing_path_gets_no_row(self):
        self.assert_one(self.bash("git clone %s %s/fresh" % (self.src, self.home), self.clone(self.home + "/fresh")))
        dest = os.path.join(self.home, "exists")
        self.clone(dest)()
        self.assert_refused("existed-at-pre", self.bash("git clone %s %s" % (self.src, dest), None))
        os.makedirs(os.path.join(self.home, "plain"))
        self.assert_refused("existed-at-pre", self.bash("git clone %s %s/plain" % (self.src, self.home),
                                                        lambda: None))
        self.assertEqual(len(self.held()), 1)

    # NEG-2
    def test_moved_in_or_wrong_kind_gets_no_row(self):
        p = os.path.join(self.home, "p")
        self.assert_one(self.bash("git clone %s %s || true" % (self.src, p), self.clone(p)))
        old = os.path.join(self.home, "shared-cache")
        self.clone(old)()
        time.sleep(0.05)
        q = os.path.join(self.home, "q")
        self.assert_refused("born-before-pre", self.bash("git clone %s %s || mv %s %s" % (self.src, q, old, q),
                                                         lambda: os.rename(old, q)))
        x = os.path.join(self.home, "x")
        self.assert_refused("not-a-checkout", self.bash("git -C %s worktree add %s || true" % (self.src, x),
                                                        lambda: os.makedirs(x)))
        y = os.path.join(self.home, "y")
        self.assert_refused("not-linked", self.bash("git -C %s worktree add %s || true" % (self.src, y),
                                                    self.clone(y)))
        self.assertEqual(len(self.held()), 1)

    # NEG-3
    def test_text_that_only_mentions_git_proposes_nothing(self):
        h = self.home
        self.assertEqual(len(R.candidates("git clone u %s/d" % h, h)), 1, "positive control")
        for cmd in ('echo "git clone u %s/d"' % h, "grep 'worktree add' notes.md",
                    "printf '%%s' 'git clone u /x'", "# git clone u %s/d" % h,
                    "cat <<E\ngit clone u %s/d\nE" % h):
            self.assertEqual(R.candidates(cmd, h), [], cmd)

    # NEG-4
    def test_symlink_and_outside_home_get_no_row(self):
        self.assert_one(self.bash("git clone %s %s/ok" % (self.src, self.home), self.clone(self.home + "/ok")))
        other, link = os.path.join(self.home, "other"), os.path.join(self.home, "link")

        def make_link():
            self.clone(other)()
            os.symlink(other, link)
        self.assert_refused("link", self.bash("git clone %s %s" % (self.src, link), make_link))
        outside = os.path.realpath(tempfile.mkdtemp(prefix="registry-outside-"))
        self.addCleanup(shutil.rmtree, outside, True)
        dest = os.path.join(outside, "c")
        self.assert_refused("outside-home", self.bash("git clone %s %s" % (self.src, dest), self.clone(dest)))

    def test_folder_replaced_during_the_call_gets_no_row(self):
        parent = os.path.join(self.home, "p")
        os.makedirs(parent)
        self.assert_one(self.bash("git clone %s %s/q/ok" % (self.src, parent), self.clone(parent + "/q/ok")))
        dest = os.path.join(parent, "q", "c")

        def swap_then_clone():
            os.rename(parent, parent + "-old")
            os.makedirs(parent)
            self.clone(dest)()
        self.assert_refused("anchor-changed", self.bash("git clone %s %s" % (self.src, dest), swap_then_clone))

    def test_link_repointed_during_the_call_gets_no_row(self):
        a, b = os.path.join(self.home, "A"), os.path.join(self.home, "B")
        os.makedirs(a)
        os.makedirs(b)
        lnk = os.path.join(self.home, "lnk")
        os.symlink(a, lnk)
        self.assert_one(self.bash("git clone %s %s/ok" % (self.src, lnk), self.clone(lnk + "/ok")))

        def repoint_then_clone():
            os.unlink(lnk)
            os.symlink(b, lnk)
            self.clone(os.path.join(lnk, "c"))()
        self.assert_refused("realpath-moved", self.bash("git clone %s %s/c" % (self.src, lnk), repoint_then_clone))

    # NEG-5
    def test_unsure_commands_propose_nothing(self):
        h = self.home
        for cmd in ("git clone --frobnicate u %s/d" % h, "cd %s; git clone u rel" % h, "git clone u $D",
                    "(cd %s && git clone u rel)" % h, "cd %s || true && git clone u rel" % h,
                    "git clone u %s/hd <<E\nunterminated" % h, "git clone u %s/hs <<< x" % h,
                    "git clone u %s/d%s" % (h, "`x`"), "git --git-dir=/x worktree add %s/w" % h,
                    "git clone u %s/a %s/b" % (h, h), "sudo -u other git clone u %s/d" % h,
                    "pushd %s; git worktree add w; popd" % h, "git clone u '%s/d\"e'" % h,
                    "git clone u ~other/d", "git clone --bare u %s/b" % h, "git clone -o up u %s/o" % h,
                    "ssh t2-dev 'git clone u repos/x'", "ssh -o BatchMode=yes t2-dev git clone u /abs",
                    "docker exec c git clone u /x", "git worktree add %s/w" % h,
                    "git clone a %s/1; git clone b %s/2; git clone c %s/3; git clone d %s/4; git clone e %s/5"
                    % (h, h, h, h, h)):
            self.assertEqual(R.propose(cmd, "")[0] if cmd.startswith("git worktree add") else R.candidates(cmd, h),
                             [], cmd)
        self.assertTrue(R.propose("ssh t2-dev 'git clone u x'", h)[1].startswith("unsure"))

    def test_common_real_shapes_are_proposed(self):
        h = self.home
        cases = {
            "git clone -q --depth 1 https://x/o/r.git %s/r 2>&1 | tail -2" % h: ("clone", h + "/r"),
            "GIT_TERMINAL_PROMPT=0 git clone u %s/e" % h: ("clone", h + "/e"),
            "git -C %s worktree add ../wt -b n && echo ok >&2" % self.src: ("worktree", h + "/wt"),
            "cd %s && git clone https://x/u %s/abs" % (h, h): ("clone", h + "/abs"),
            "git worktree add .claude/worktrees/x": ("worktree", h + "/.claude/worktrees/x"),
            "ssh t2-dev uptime && git clone u %s/after" % h: ("clone", h + "/after"),
            "cd %s && git clone u rel" % h: ("clone", h + "/rel"),
            "cd %s && git worktree add ../wt2 -b q 2>&1 | tail -1" % self.src: ("worktree", h + "/wt2"),
            "git clone u %s/hd && git commit -F - <<'EOF'\nbody: git clone u %s/body\nEOF" % (h, h):
                ("clone", h + "/hd"),
        }
        for cmd, want in cases.items():
            got = R.candidates(cmd, h)
            self.assertEqual([(c["kind"], c["path"]) for c in got], [want], cmd)

    # NEG-15
    def test_checkout_from_another_source_gets_no_row(self):
        other_src = os.path.join(self.home, "other-src")
        sh("git", "clone", "-q", self.src, other_src)
        d = os.path.join(self.home, "d")
        self.assert_refused("origin-mismatch", self.bash("git clone %s %s" % (self.src, d), self.clone(d, other_src)))
        wt = os.path.join(self.home, "wt-other")
        self.assert_refused("repo-mismatch", self.bash(
            "git -C %s worktree add %s -b z" % (self.src, wt),
            lambda: sh("git", "-C", other_src, "worktree", "add", "-q", wt, "-b", "z")))
        url = "https://example.invalid/o/r.git"
        e = os.path.join(self.home, "e")

        def fake_remote_clone():
            self.clone(e)()
            sh("git", "-C", e, "remote", "set-url", "origin", url)
        self.assert_one(self.bash("git clone %s %s" % (url, e), fake_remote_clone))

    # NEG-16
    def test_no_birth_time_gets_no_row(self):
        d = os.path.join(self.home, "nb")
        with mock.patch.object(R, "birth_ns", side_effect=lambda p: None if p == d else REAL_BIRTH(p)):
            self.assert_refused("no-btime", self.bash("git clone %s %s" % (self.src, d), self.clone(d)))

    # NEG-17
    def test_repo_config_runs_nothing_when_the_registry_reads_it(self):
        marker = os.path.join(self.home, "fsmonitor-ran")
        script = os.path.join(self.home, "fsmon.sh")
        Path(script).write_text("#!/bin/sh\ntouch %s\nexit 1\n" % marker)
        os.chmod(script, 0o755)
        sh("git", "config", "core.fsmonitor", script, cwd=self.src)
        subprocess.run(["git", "-C", self.src, "status", "--porcelain"], capture_output=True, env=ENV)
        self.assertTrue(os.path.exists(marker), "positive control: plain git status runs the fsmonitor hook")
        os.unlink(marker)
        R.stat_path(self.src)
        R.verdict({"path": self.src, "kind": "clone", "host": "local", "dev": 0, "ino": 0, "btime_ns": 0},
                  time.monotonic() + 10)
        R._git(self.src, "status", "--porcelain")
        self.assertFalse(os.path.exists(marker))


REAL_BIRTH = R.birth_ns


class Ownership(Base):
    # NEG-7
    def test_inode_reuse_never_matches_the_old_row(self):
        dest = os.path.join(self.home, "c")

        def mkdir_then_clone():                             # probe on t2-dev: this pattern reuses the inode 10 of 10
            os.mkdir(dest)
            self.clone(dest)()
        old = self.assert_one(self.bash("mkdir %s && git clone %s %s" % (dest, self.src, dest), mkdir_then_clone))
        reused, tries = False, 0
        while not reused and tries < 20:                    # recreated with no hook (user, Codex, a script)
            tries += 1
            shutil.rmtree(dest)
            os.mkdir(dest)                                  # ext4 hands the freed inode to the next new folder
            self.clone(dest)()                              # git clone into an existing empty folder is allowed
            live = dict(R.stat_path(dest), host="local")
            reused = (live["dev"], live["ino"]) == (old["dev"], old["ino"])
        sys.stderr.write("[inode reused at the same path: %s after %d tries on %s; %s]\n" % (
            reused, tries, sys.platform, "real reuse" if reused else "reuse presented with the old dev and inode"))
        if not reused:
            # ext4 reuse depends on allocator state (10 of 10 in one probe, 0 of 20 in a later run), so the test does
            # not rely on it: the new checkout is presented with the old dev and inode, as a reuse would show it.
            live = dict(live, dev=old["dev"], ino=old["ino"])
        self.assertNotEqual(live["btime_ns"], old["btime_ns"])
        self.assertIsNone(R.held(live), "the old row must not own the new checkout")
        shutil.rmtree(dest)
        new = self.assert_one(self.bash("git clone %s %s" % (self.src, dest), self.clone(dest), session="s2",
                                        agent="b2"))
        self.assertEqual([(r["session"], r["agent"]) for r in self.held()], [("s2", "b2")])
        removed = [r for r in R.rows()[0] if r["event"] == "removed"]
        self.assertEqual([(r["session"], r["route"]) for r in removed], [("s1", "observed-absent")])
        self.assertEqual(R.held(new)["session"], "s2")

    def test_second_owner_for_the_same_identity_is_refused(self):
        dest = os.path.join(self.home, "c")
        self.assert_one(self.bash("git clone %s %s" % (self.src, dest), self.clone(dest)))
        f = R.stat_path(dest)
        self.assertEqual(R.write_created(f, "clone", "s2", "b2", "toolu_x"), (None, "second-owner"))
        self.assertEqual(R.write_created(f, "clone", "s1", "a1", "toolu_y"), (None, "already-held"))
        self.assertEqual([(r["session"], r["agent"]) for r in self.held()], [("s1", "a1")])

    # NEG-9
    def test_two_calls_racing_for_one_path_write_no_row(self):
        dest = os.path.join(self.home, "race")
        cmd = "git clone %s %s" % (self.src, dest)
        for tid, s, a in (("toolu_A", "s1", "a1"), ("toolu_B", "s2", "b2")):
            self.record(tid, cmd, s, a)
            R.pretool(self.payload(cmd, tid, s, a))
        self.clone(dest)()
        self.assertEqual(R.posttool(self.payload(cmd, "toolu_A", "s1", "a1")), [])
        self.assertEqual(R.posttool(self.payload(cmd, "toolu_B", "s2", "b2")), [])
        self.assertIn("contested", self.codes("toolu_A"))
        self.assertIn("contested", self.codes("toolu_B"))
        self.assertEqual(self.held(), [])

    def test_two_writer_processes_produce_one_owner(self):
        dest = os.path.join(self.home, "c")
        self.clone(dest)()
        info = json.dumps(R.stat_path(dest))
        child = textwrap.dedent("""
            import json, sys, time
            sys.path.insert(0, %r)
            import checkout_registry as R
            slow = R.current
            def current(*a, **k):
                out = slow(*a, **k)
                time.sleep(0.4)            # widen the check-then-append window
                return out
            R.current = current
            print(R.write_created(json.loads(sys.argv[1]), "clone", sys.argv[2], sys.argv[3], "t")[1])
        """) % str(HOOKS)
        R.ensure_key()
        procs = [subprocess.Popen([sys.executable, "-c", child, info, s, a], stdout=subprocess.PIPE, text=True,
                                  env=dict(os.environ)) for s, a in (("s1", "a1"), ("s2", "b2"))]
        outs = sorted(p.communicate(timeout=60)[0].strip() for p in procs)
        self.assertEqual(outs, ["second-owner", "written"])
        self.assertEqual(len([r for r in R.rows()[0] if r["event"] == "created"]), 1)

    def test_two_created_rows_mean_no_owner(self):
        dest = os.path.join(self.home, "c")
        self.clone(dest)()
        f = R.stat_path(dest)
        key = R.ensure_key()
        base = {"v": 1, "event": "created", "kind": "clone", "host": "local", "path": dest, "dev": f["dev"],
                "ino": f["ino"], "btime_ns": f["btime_ns"], "common_dir": f["common_dir"], "agent": None,
                "task": None, "created_at": "x", "tool_use_id": None}
        with R._locked():
            R._append(dict(base, session="s1"), key)
        self.assertEqual(R.held(dict(f, host="local"))["session"], "s1", "positive control")
        with R._locked():
            R._append(dict(base, session="s2"), key)
        self.assertIsNone(R.held(dict(f, host="local")))

    # NEG-8
    def test_missing_forged_foreign_and_expired_pending_records_write_nothing(self):
        dest = os.path.join(self.home, "c")
        cmd = "git clone %s %s" % (self.src, dest)
        self.assert_one(self.bash(cmd, self.clone(dest)))
        shutil.rmtree(dest)
        R.retire_absent(dest, R.read_key())

        def run(post_session="s1", tamper=None, later=0.0, tid=None):
            tid = tid or self.tid()
            self.last_tid = tid
            self.record(tid, cmd)
            R.pretool(self.payload(cmd, tid))
            if tamper:
                p = R._pending_path(tid)
                rec = json.loads(p.read_text())
                tamper(rec)
                p.write_text(json.dumps(rec))
            self.clone(dest)()
            try:
                with mock.patch.object(R.time, "time", return_value=time.time() + later):
                    return R.posttool(self.payload(cmd, tid, session=post_session))
            finally:
                shutil.rmtree(dest, ignore_errors=True)

        self.last_tid = "toolu_none"
        self.clone(dest)()
        self.assertEqual(R.posttool(self.payload(cmd, "toolu_none")), [])
        self.assertIn("pending-missing", self.codes("toolu_none"))
        shutil.rmtree(dest)
        self.assert_refused("pending-bad-mac", run(tamper=lambda r: r.update(session="s9")))
        self.assert_refused("pending-foreign", run(post_session="s2"))
        self.assert_refused("pending-expired", run(later=R.PENDING_TTL + 60))
        self.assertEqual(self.held(), [])

    def test_replayed_posttool_adds_nothing_and_denied_forgets(self):
        dest = os.path.join(self.home, "c")
        cmd = "git clone %s %s" % (self.src, dest)
        self.record("toolu_r", cmd)
        R.pretool(self.payload(cmd, "toolu_r"))
        self.clone(dest)()
        self.assertEqual(len(R.posttool(self.payload(cmd, "toolu_r"))), 1)
        self.assertEqual(R.posttool(self.payload(cmd, "toolu_r")), [])
        self.assertEqual(len(R.rows()[0]), 1)
        d2 = os.path.join(self.home, "d2")
        cmd2 = "git clone %s %s" % (self.src, d2)
        self.record("toolu_d", cmd2)
        R.pretool(self.payload(cmd2, "toolu_d"))
        self.assertTrue(R._pending_path("toolu_d").exists())
        R.hook("denied", io.StringIO(json.dumps(self.payload(cmd2, "toolu_d"))))
        self.assertFalse(R._pending_path("toolu_d").exists())
        self.assertIn("permission-denied", self.codes("toolu_d"))

    def test_background_launch_gets_no_row(self):
        dest = os.path.join(self.home, "bg")
        cmd = "git clone %s %s" % (self.src, dest)

        def bg(tid):
            p = self.payload(cmd, tid)
            p["tool_input"]["run_in_background"] = True
            return p
        self.assert_refused("background", self.bash(cmd, self.clone(dest), post_payload=bg))

    # NEG-11
    def test_forged_hook_payloads_write_nothing(self):
        d = os.path.join(self.home, "f0")
        self.assert_one(self.bash("git clone %s %s" % (self.src, d), self.clone(d)))
        elsewhere = os.path.join(self.home, "fake.jsonl")
        Path(elsewhere).write_text("")
        for n, (record, post) in enumerate((
                (False, None),                                                     # tool_use not in the transcript
                (True, lambda tid: self.payload("git clone %s %s/f1" % (self.src, self.home), tid,
                                                transcript=elsewhere)),            # not the session's transcript
                ("other", None),                                                   # another command under that id
        )):
            dest = os.path.join(self.home, "f%d" % (n + 1))
            cmd = "git clone %s %s" % (self.src, dest)
            tid = self.tid()
            self.last_tid = tid
            if record == "other":
                self.record(tid, "echo something else")
            elif record:
                self.record(tid, cmd)
            R.pretool(self.payload(cmd, tid))
            self.clone(dest)()
            payload = post(tid) if post else self.payload(cmd, tid)
            payload["tool_input"]["command"] = cmd
            self.assert_refused("transcript-unbound", R.posttool(payload))
        dest = os.path.join(self.home, "f9")
        cmd = "git clone %s %s" % (self.src, dest)
        tid = self.tid()
        self.last_tid = tid
        self.record(tid, cmd, agent=None)                       # in main's transcript, but the agent has none
        R.pretool(self.payload(cmd, tid, agent="zz"))
        self.clone(dest)()
        self.assert_refused("transcript-unbound", R.posttool(self.payload(cmd, tid, agent="zz")))
        self.assertEqual(len(self.held()), 1)

    def test_subagent_transcript_path_form_is_accepted(self):
        dest = os.path.join(self.home, "sub")
        cmd = "git clone %s %s" % (self.src, dest)
        tid = self.tid()
        self.record(tid, cmd)
        p = self.payload(cmd, tid, transcript=self.sub_transcript())
        R.pretool(p)
        self.clone(dest)()
        self.assertEqual(len(R.posttool(p)), 1)


class Integrity(Base):
    def _row(self):
        dest = os.path.join(self.home, "c")
        return self.assert_one(self.bash("git clone %s %s" % (self.src, dest), self.clone(dest)))

    def test_append_removed_ends_ownership_and_unmatched_changes_nothing(self):
        row = self._row()
        self.assertIsNone(R.append_removed(dict(row, btime_ns=row["btime_ns"] + 1), "test", "unit"))
        self.assertEqual(R.held(row)["session"], "s1")
        gone = R.append_removed(row, "test", "unit")
        self.assertTrue(R.verify(gone))
        self.assertIsNone(R.held(row))
        self.assertIsNone(R.append_removed(row, "test", "unit"))

    def test_forged_removed_row_is_ignored(self):
        row = self._row()
        forged = dict(row, event="removed", mac="0" * 64)
        with open(R.ledger_path(), "a") as fh:
            fh.write(json.dumps(forged) + "\n")
        self.assertEqual(R.held(row)["session"], "s1")

    # NEG-6
    def test_edited_moved_and_foreign_key_rows_fail(self):
        row = self._row()
        self.assertTrue(R.verify(row), "positive control")
        self.assertFalse(R.verify(dict(row, session="s9")))
        self.assertFalse(R.verify(dict(row, v=2)))
        self.assertFalse(R.verify(row, key=b"k" * 32))
        pasted = dict(row, host="t2-dev")
        pasted["mac"] = R.mac(pasted)                         # same key, signed for another host
        with mock.patch.object(R, "HOSTS", ("local", "t2-dev")):
            t2 = R.ledger_path("t2-dev")
            with open(t2, "a") as fh:
                fh.write(json.dumps(row) + "\n")              # a local row pasted into the t2-dev file
            os.chmod(t2, 0o600)
            self.assertEqual(R.rows("t2-dev"), ([], 1))
            self.assertIsNone(R.held(dict(row, host="t2-dev")))
        with open(R.ledger_path(), "a") as fh:
            fh.write(json.dumps(pasted) + "\n")               # a t2-dev row pasted into the local file
        good, bad = R.rows()
        self.assertEqual((len(good), bad), (1, 1))

    def test_partial_line_is_repaired_before_the_next_row(self):
        row = self._row()
        with open(R.ledger_path(), "a") as fh:
            fh.write('{"v":1,"event":"crea')                  # a crash mid-append
        d = os.path.join(self.home, "d")
        self.assert_one(self.bash("git clone %s %s" % (self.src, d), self.clone(d)))
        good, bad = R.rows()
        self.assertEqual((len(good), bad), (2, 1))
        self.assertEqual(R.held(row)["session"], "s1")

    def test_rotating_the_key_voids_every_row(self):
        row = self._row()
        key = Path(self.home) / ".agent-harness/state/checkouts/registry.key"
        key.unlink()
        R.ensure_key()
        self.assertIsNone(R.held(row))
        self.assertEqual(R.rows(), ([], 1))

    # NEG-12
    def test_unsafe_state_dir_or_key_writes_nothing(self):
        state = Path(self.home) / ".agent-harness/state/checkouts"
        state.mkdir(parents=True)
        os.chmod(state, 0o770)
        d0 = os.path.join(self.home, "d0")
        self.assertEqual(self.bash("git clone %s %s" % (self.src, d0), self.clone(d0)), [])
        self.assertIsNone(R.ensure_key())
        os.chmod(state, 0o700)
        d1 = os.path.join(self.home, "d1")
        self.assert_one(self.bash("git clone %s %s" % (self.src, d1), self.clone(d1)))
        (state / "registry.key").unlink()
        target = Path(self.home) / "elsewhere.key"
        target.write_bytes(b"k" * 32)
        os.chmod(target, 0o600)
        os.symlink(target, state / "registry.key")
        self.assertIsNone(R.ensure_key())
        d2 = os.path.join(self.home, "d2")
        self.assertEqual(self.bash("git clone %s %s" % (self.src, d2), self.clone(d2)), [])

    def test_key_is_private_and_made_once(self):
        k1, k2 = R.ensure_key(), R.ensure_key()
        self.assertEqual(k1, k2)
        st = os.stat(Path(self.home) / ".agent-harness/state/checkouts/registry.key")
        self.assertEqual(st.st_mode & 0o777, 0o600)


class Contract(unittest.TestCase):
    def test_no_other_module_reads_the_registry_key(self):
        users = [p.name for p in HOOKS.glob("*.py") if p.name != "checkout_registry.py"
                 and "registry.key" in p.read_text(errors="replace")]
        self.assertEqual(users, [])

    def test_cli_has_no_write_command(self):
        for argv in (["add", "--path", "/x"], ["write"], ["created"]):
            with self.assertRaises(SystemExit):
                with redirect_stdout(io.StringIO()), mock.patch("sys.stderr", io.StringIO()):
                    R.main(argv)


class Isolation(Base):
    def make_iso(self, agent, repo=None):
        repo = repo or self.src
        path = os.path.join(repo, ".claude", "worktrees", "agent-" + agent)
        sh("git", "-C", repo, "worktree", "add", "-q", path, "-b", "w-" + agent)
        self.sub_transcript("s1", agent)
        return path

    def test_first_tool_call_inside_registers_once(self):
        path = self.make_iso("a1")
        R.pretool(self.payload("ls", "toolu_1", agent="a1", cwd=path + "/sub", tool="Read"))
        R.pretool(self.payload("ls", "toolu_2", agent="a1", cwd=path, tool="Read"))
        self.assertEqual([(r["kind"], r["path"], r["agent"], r["tool_use_id"]) for r in self.held()],
                         [("isolation", path, "a1", None)])
        self.assertEqual(len(R.rows()[0]), 1, "a resumed agent adds no second row")

    def test_subagent_start_registers_from_the_parent_cwd(self):
        path = self.make_iso("a1")
        self.assertEqual(R.subagent_start({"session_id": "s1", "agent_id": "a1", "cwd": self.src})["path"], path)
        R.subagent_start({"session_id": "s1", "agent_id": "a1", "cwd": path})
        self.assertEqual(len(R.rows()[0]), 1)

    # NEG-10
    @mock.patch.object(R, "ISO_RETRY_S", 0)
    def test_other_agents_folder_and_unregistered_folders_get_no_row(self):
        other = self.make_iso("a2")
        R.pretool(self.payload("ls", "t1", agent="a1", cwd=other, tool="Read"))
        R.pretool(self.payload("ls", "t2", agent="a2", cwd=other + "X", tool="Read"))
        self.assertEqual(self.held(), [])
        plain = os.path.join(self.src, ".claude", "worktrees", "agent-a3")
        os.makedirs(plain)
        self.sub_transcript("s1", "a3")
        R.pretool(self.payload("ls", "t3", agent="a3", cwd=plain, tool="Read"))
        full = os.path.join(self.src, ".claude", "worktrees", "agent-a4")
        self.clone(full)()
        self.sub_transcript("s1", "a4")
        R.pretool(self.payload("ls", "t4", agent="a4", cwd=full, tool="Read"))
        foreign_repo = os.path.join(self.home, "foreign")
        self.clone(foreign_repo)()
        planted = os.path.join(self.src, ".claude", "worktrees", "agent-a5")
        sh("git", "-C", foreign_repo, "worktree", "add", "-q", planted, "-b", "planted")
        self.sub_transcript("s1", "a5")
        R.pretool(self.payload("ls", "t5", agent="a5", cwd=planted, tool="Read"))
        self.assertEqual(self.held(), [])
        self.assertEqual(self.codes().count("iso-not-checkout"), 2)
        self.assertIn("iso-not-listed", self.codes())

    def test_a_failed_check_is_not_repeated_on_every_call(self):
        plain = os.path.join(self.src, ".claude", "worktrees", "agent-a7")
        os.makedirs(plain)
        for n in range(3):
            R.pretool(self.payload("ls", "t%d" % n, agent="a7", cwd=plain, tool="Read"))
        self.assertEqual(self.codes().count("iso-not-checkout"), 1)

    @mock.patch.object(R, "ISO_RETRY_S", 0)
    def test_no_transcript_or_outside_the_birth_window_gets_no_row(self):
        path = os.path.join(self.src, ".claude", "worktrees", "agent-a6")
        sh("git", "-C", self.src, "worktree", "add", "-q", path, "-b", "w-a6")
        R.pretool(self.payload("ls", "t1", agent="a6", cwd=path, tool="Read"))
        self.assertIn("iso-no-transcript", self.codes())
        self.sub_transcript("s1", "a6")
        real = R.birth_ns
        with mock.patch.object(R, "birth_ns", side_effect=lambda p: real(p) + (
                R.ISO_WINDOW_NS + 10 ** 9 if p.endswith("agent-a6.jsonl") else 0)):
            R.pretool(self.payload("ls", "t2", agent="a6", cwd=path, tool="Read"))
        self.assertIn("iso-window", self.codes())
        self.assertEqual(self.held(), [])
        R.pretool(self.payload("ls", "t3", agent="a6", cwd=path, tool="Read"))
        self.assertEqual(len(self.held()), 1, "positive control: same worktree, real birth times")


class Stop(Base):
    def note(self, agent="a1"):
        return Path(self.home) / (".agent-harness/work/s1/inbox/data-checkout-%s.md" % agent)

    def iso(self, agent="a1", repo=None, branch=None):
        repo = repo or self.src
        path = os.path.join(repo, ".claude", "worktrees", "agent-" + agent)
        sh("git", "-C", repo, "worktree", "add", "-q", "--detach", path, "origin/main")
        if branch:
            sh("git", "-C", path, "checkout", "-q", "-b", branch)
        self.sub_transcript("s1", agent)
        R.subagent_start({"session_id": "s1", "agent_id": agent, "cwd": path})
        return path

    # NEG-13 and NEG-14
    def test_verdicts_and_nothing_is_removed(self):
        calls = []
        fake = types.ModuleType("ah_worktree")
        fake.remove_owned = lambda *a, **k: calls.append(a) or shutil.rmtree(a[1]["path"])
        with mock.patch.dict(sys.modules, {"ah_worktree": fake}):
            iso = self.iso(branch="x`rm`OWNER-DECISION")
            os.makedirs(os.path.join(iso, "build"))
            Path(iso, "build", "out.o").write_text("o")
            text = R.subagent_stop({"session_id": "s1", "agent_id": "a1"}).read_text()
            self.assertIn("isolation `%s`: owner may remove" % iso, text, "positive control")
            self.assertIn("ignored 1", text)
            self.assertIn("Informational data", text)
            self.assertNotIn("`rm`", text)
            self.assertIn("x?rm?OWNER-DECISION", text)
            self.assertEqual(calls, [])
            self.assertTrue(os.path.isdir(iso))
            before = sh("git", "-C", iso, "status", "--porcelain", "--ignored")

            Path(iso, "f.txt").write_text("edited\n")
            text = R.subagent_stop({"session_id": "s1", "agent_id": "a1"}).read_text()
            self.assertIn("keep: changes", text)
            self.assertIn("changed 1, untracked 0", text)
            sh("git", "-C", iso, "checkout", "-q", "--", "f.txt")
            # The original path of a rename follows as its own NUL field; "ab c.txt" is shaped like an entry, so
            # it would be counted as a second change if the parser did not skip it.
            Path(iso, "ab c.txt").write_text("r\n")
            sh("git", "-C", iso, "add", "ab c.txt")
            sh("git", "-C", iso, "commit", "-q", "-m", "tracked")
            sh("git", "-C", iso, "mv", "ab c.txt", "g.txt")
            text = R.subagent_stop({"session_id": "s1", "agent_id": "a1"}).read_text()
            self.assertIn("changed 1, untracked 0", text, "a rename is one change, not two")
            sh("git", "-C", iso, "reset", "-q", "--hard", "origin/main")

            Path(iso, "new.txt").write_text("y\n")
            text = R.subagent_stop({"session_id": "s1", "agent_id": "a1"}).read_text()
            self.assertIn("keep: untracked files", text)
            os.unlink(os.path.join(iso, "new.txt"))

            sh("git", "-C", iso, "commit", "-q", "--allow-empty", "-m", "local only")
            text = R.subagent_stop({"session_id": "s1", "agent_id": "a1"}).read_text()
            self.assertIn("keep: unpushed", text)
            sh("git", "-C", iso, "reset", "-q", "--hard", "origin/main")

            child = os.path.join(iso, ".claude", "worktrees", "agent-c1")
            sh("git", "-C", iso, "worktree", "add", "-q", "--detach", child, "origin/main")
            text = R.subagent_stop({"session_id": "s1", "agent_id": "a1"}).read_text()
            self.assertIn("contains another checkout", text)
            self.assertIn("nested checkout `%s`" % child, text)
            sh("git", "-C", iso, "worktree", "remove", child)

            Path(self.src, "f.txt").write_text("changed\n")
            sh("git", "-C", self.src, "stash", "push", "-q", "-m", "t")
            text = R.subagent_stop({"session_id": "s1", "agent_id": "a1"}).read_text()
            self.assertIn("keep: stash", text)
            self.assertEqual(calls, [])
            self.assertEqual(sh("git", "-C", iso, "status", "--porcelain", "--ignored"), before)
        self.assertEqual(os.stat(self.note()).st_mode & 0o777, 0o600)

    def test_clone_is_listed_but_never_a_removal_candidate(self):
        dest = os.path.join(self.home, "c")
        self.bash("git clone %s %s" % (self.origin, dest), self.clone(dest, self.origin))
        text = R.subagent_stop({"session_id": "s1", "agent_id": "a1"}).read_text()
        self.assertIn("only an isolation worktree of this agent is a removal candidate", text)

    def test_gone_checkout_is_retired(self):
        dest = os.path.join(self.home, "c")
        self.assert_one(self.bash("git clone %s %s" % (self.src, dest), self.clone(dest)))
        shutil.rmtree(dest)
        text = R.subagent_stop({"session_id": "s1", "agent_id": "a1"}).read_text()
        self.assertIn("gone; its row is retired", text)
        self.assertEqual(self.held(), [])

    def test_nothing_held_writes_no_note(self):
        self.assertIsNone(R.subagent_stop({"session_id": "s1", "agent_id": "a9"}))
        self.assertFalse(self.note("a9").exists())


class FailOpen(Base):
    def run_hook(self, event, text):
        out = io.StringIO()
        with redirect_stdout(out):
            code = R.hook(event, io.StringIO(text))
        return code, out.getvalue()

    def test_every_hook_exits_zero_silently_on_broken_state(self):
        state = Path(self.home) / ".agent-harness/state"
        state.mkdir(parents=True)
        (state / "checkouts").write_text("not a folder")
        dest = os.path.join(self.home, "c")
        p = json.dumps(self.payload("git clone %s %s" % (self.src, dest), "toolu_1"))
        for event in ("pretool", "posttool", "posttool-failure", "denied", "subagent-start", "subagent-stop"):
            self.assertEqual(self.run_hook(event, p), (0, ""), event)
            self.assertEqual(self.run_hook(event, "{not json"), (0, ""), event)
            self.assertEqual(self.run_hook(event, "[1]"), (0, ""), event)

    def test_internal_error_is_swallowed_and_recorded(self):
        with mock.patch.object(R, "propose", side_effect=RuntimeError("bug")):
            self.assertEqual(self.run_hook("pretool", json.dumps(self.payload("git clone u /x", "t"))), (0, ""))
        self.assertIn("hook-error", self.codes())


class EntryPoint(Base):
    """The installed command line, as Claude Code runs it: one row through pretool then posttool, silence always."""

    def run_verb(self, verb, payload):
        r = subprocess.run([sys.executable, str(HOOKS / "checkout_registry.py"), "hook", verb], input=json.dumps(payload),
                           capture_output=True, text=True, timeout=60, env=dict(os.environ, HOME=self.home))
        self.assertEqual((r.returncode, r.stdout, r.stderr), (0, "", ""), verb)

    def test_every_wired_verb_runs_silently_and_a_row_is_written(self):
        dest = os.path.join(self.home, "ep")
        cmd = "git clone %s %s" % (self.src, dest)
        self.record("toolu_ep", cmd)
        p = self.payload(cmd, "toolu_ep")
        self.run_verb("pretool", p)
        self.clone(dest)()
        self.run_verb("posttool", p)
        self.assertEqual([r["path"] for r in self.held()], [dest])
        for verb in ("posttool-failure", "denied", "subagent-start", "subagent-stop"):
            self.run_verb(verb, p)


class Wiring(unittest.TestCase):
    def test_installer_ships_and_wires_every_event_within_budget(self):
        import install  # noqa: PLC0415
        self.assertIn("checkout_registry.py", install.HOOKS)
        claude = Path("/h/.claude")
        script = str(claude / "hooks" / "checkout_registry.py")
        self.assertIn(script, install.managed_scripts(claude))
        hooks = install.managed_hooks(claude, True)
        found = {}
        for event, groups in hooks.items():
            for g in groups:
                for h in g["hooks"]:
                    if h.get("args", [None])[0] == script:
                        found[(event, h["args"][2])] = (g.get("matcher"), h["timeout"])
        self.assertEqual(found, {
            ("PreToolUse", "pretool"): (".*", 10),
            ("PostToolUse", "posttool"): ("Bash", 10),
            ("PostToolUseFailure", "posttool-failure"): ("Bash", 10),
            ("PermissionDenied", "denied"): ("Bash", 10),
            ("SubagentStart", "subagent-start"): (".*", 20),
            ("SubagentStop", "subagent-stop"): (".*", 20),
        })
        self.assertLess(R.GIT_TIMEOUT, 10)
        self.assertLess(R.STOP_BUDGET + R.GIT_TIMEOUT, 20 + 1)


if __name__ == "__main__":
    unittest.main()
