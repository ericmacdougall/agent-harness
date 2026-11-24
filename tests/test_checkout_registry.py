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


def git_out(*a, cwd=None):
    """Run git as a Bash call would, and return everything it printed (stderr then stdout)."""
    r = subprocess.run(a, cwd=cwd, check=True, capture_output=True, env=ENV, text=True)
    return r.stderr + r.stdout


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
        self.out = ""                       # what the last real git call printed (see clone)
        self.opt_in(True)

    def opt_in(self, on: bool):
        """The user's opt-in file (default off; every test except the Default class runs with it on)."""
        d = os.path.join(self.home, ".agent-harness", "state", "checkouts")
        os.makedirs(d, mode=0o700, exist_ok=True)
        os.chmod(d, 0o700)
        p = os.path.join(d, "enabled.json")
        if on:
            fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            os.write(fd, b'{"enabled": true}\n')
            os.close(fd)
        elif os.path.exists(p):
            os.remove(p)

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
                "transcript_path": transcript or self.main_transcript(session),
                "tool_response": {"stdout": "", "stderr": self.out, "interrupted": False}}

    def bash(self, cmd, action, session="s1", agent="a1", cwd=None, record=True, post_payload=None, shown=True,
             output=None):
        """Transcript, PreToolUse, the command's real effect, PostToolUse: what Claude Code does for one call. The
        Post payload's tool_response carries what the action's real git printed (shown=False: the command hid it;
        output=TEXT: what git printed when the action stands in for something git did not do itself)."""
        tid = self.tid()
        if record:
            self.record(tid, cmd, session, agent)
        R.pretool(self.payload(cmd, tid, session, agent, cwd))
        out = action() if action else ""
        if isinstance(out, (tuple, list)):          # lambda: (side_effect(), self.clone(d)())
            out = next((x for x in reversed(out) if isinstance(x, str)), "")
        if output is not None:
            out = output
        if post_payload:
            post = post_payload(tid)
        else:
            post = self.payload(cmd, tid, session, agent, cwd)
            post["tool_response"] = {"stdout": "", "stderr": out if shown and isinstance(out, str) else "",
                                     "interrupted": False}
        rows = R.posttool(post)
        self.last_tid = tid
        return rows

    def clone(self, dest, src=None):
        """A real `git clone` (not quiet), returning what git printed; payload() then carries it as the call's
        output, as Claude Code's Post payload does."""
        def run():
            self.out = git_out("git", "clone", src or self.src, dest)
            return self.out
        return run

    def wt_add(self, repo, path, *extra):
        return lambda: git_out("git", "-C", repo, "worktree", "add", path, *extra)

    def held(self):
        try:
            return list(R.current().values())
        except R.NotHeld:
            return []

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
        row = self.assert_one(self.bash("git -C %s worktree add %s -b feat >/dev/null" % (self.src, wt),
                                        self.wt_add(self.src, wt, "-b", "feat")))
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
        out = self.clone(dest)()
        R.hook("posttool-failure", io.StringIO(json.dumps(dict(self.payload(cmd, tid), error=out + "Exit code 1"))))
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
        # The output has no fatal line, so the own-output rule passes and the birth check alone must refuse.
        self.assert_refused("born-outside-call", self.bash("git clone %s %s || mv %s %s" % (self.src, q, old, q),
                                                           lambda: os.rename(old, q),
                                                           output="Cloning into '%s'...\n" % q))
        old2 = os.path.join(self.home, "older")                 # a new folder, but the .git inside it is moved in
        self.clone(old2)()
        time.sleep(0.05)
        r = os.path.join(self.home, "r")

        def new_folder_old_git():
            os.makedirs(r)
            os.rename(os.path.join(old2, ".git"), os.path.join(r, ".git"))
        self.assert_refused("born-outside-call", self.bash("git clone %s %s || true" % (self.src, r),
                                                           new_folder_old_git,
                                                           output="Cloning into '%s'...\n" % r))
        x = os.path.join(self.home, "x")
        prep = "Preparing worktree (new branch 'x')\n"          # no fatal: the later checks alone must refuse
        self.assert_refused("not-a-checkout", self.bash("git -C %s worktree add %s || true" % (self.src, x),
                                                        lambda: os.makedirs(x), output=prep))
        y = os.path.join(self.home, "y")
        self.assert_refused("not-linked", self.bash("git -C %s worktree add %s || true" % (self.src, y),
                                                    self.clone(y), output=prep))
        self.assertEqual(len(self.held()), 1)

    # NEG-16
    def test_born_after_the_post_mark_or_on_another_filesystem_gets_no_row(self):
        real = R.clock_mark
        self.assert_one(self.bash("git clone %s %s/ok" % (self.src, self.home), self.clone(self.home + "/ok")))
        marks = []

        def early_post():                    # the Post mark reads earlier than the checkout's birth
            m = real()
            marks.append(m)
            return m if len(marks) == 1 else (marks[0][0], m[1])
        with mock.patch.object(R, "clock_mark", early_post):
            self.assert_refused("born-outside-call", self.bash("git clone %s %s/late" % (self.src, self.home),
                                                               lambda: (time.sleep(0.05),
                                                                        self.clone(self.home + "/late")())))

        def other_dev():
            m = real()
            return (m[0], m[1] + 1)
        with mock.patch.object(R, "clock_mark", other_dev):
            self.assert_refused("other-fs", self.bash("git clone %s %s/odev" % (self.src, self.home),
                                                      self.clone(self.home + "/odev")))
        self.assertEqual(len(self.held()), 1)

    @unittest.skipUnless(sys.platform.startswith("linux"), "the inode generation is read on Linux only")
    def test_no_inode_generation_gets_no_row(self):
        self.assert_one(self.bash("git clone %s %s/g1" % (self.src, self.home), self.clone(self.home + "/g1")))
        self.assertIsInstance(self.held()[0]["gen"], int)
        with mock.patch.object(R, "inode_generation", lambda p: None):
            self.assert_refused("no-generation", self.bash("git clone %s %s/g2" % (self.src, self.home),
                                                           self.clone(self.home + "/g2")))

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
        self.assert_refused("link", self.bash("git clone %s %s" % (self.src, link), make_link,
                                              output="Cloning into '%s'...\ndone.\n" % link))
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
            return self.clone(dest)()
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
            return self.clone(os.path.join(lnk, "c"))()
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
            self.wt_add(other_src, wt, "-b", "z")))
        url = "https://example.invalid/o/r.git"
        e = os.path.join(self.home, "e")

        def fake_remote_clone():
            out = self.clone(e)()
            sh("git", "-C", e, "remote", "set-url", "origin", url)
            return out
        self.assert_one(self.bash("git clone %s %s" % (url, e), fake_remote_clone))

    # NEG-16
    def test_no_birth_time_gets_no_row(self):
        d = os.path.join(self.home, "nb")
        with mock.patch.object(R, "birth_ns", side_effect=lambda p: None if p == d else REAL_BIRTH(p)):
            self.assert_refused("no-btime", self.bash("git clone %s %s" % (self.src, d), self.clone(d)))

    # NEG-17
    # NEG-17
    def test_repo_config_runs_nothing_when_the_registry_reads_it(self):
        marker = os.path.join(self.home, "program-ran")
        prog = os.path.join(self.home, "prog.sh")
        Path(prog).write_text(textwrap.dedent("""\
            #!/bin/sh
            echo "$*" >> %s
            case "$*" in
              *--verify*) exit 1;;
              *-bsau*) printf '%%s\\n' '-----BEGIN PGP SIGNATURE-----' x '-----END PGP SIGNATURE-----'
                       printf '\\n[GNUPG:] SIG_CREATED D 1 8 00 0 0\\n' >&2; exit 0;;
            esac
            cat
            """ % marker))
        os.chmod(prog, 0o755)
        inc = os.path.join(self.home, "included.cfg")            # include.path: a file outside the repo
        Path(inc).write_text("[filter \"p\"]\n\tclean = %s\n\tsmudge = %s\n" % (prog, prog))
        for k, v in (("include.path", inc), ("diff.p.textconv", prog), ("gpg.program", prog),
                     ("log.showSignature", "true"), ("core.fsmonitor", prog)):
            sh("git", "config", k, v, cwd=self.src)
        Path(self.src, ".gitattributes").write_text("*.txt filter=p diff=p\n")
        Path(self.src, "f.txt").write_text("signed\n")
        sh("git", "add", ".gitattributes", "f.txt", cwd=self.src)
        sh("git", "-c", "core.fsmonitor=false", "commit", "-q", "-S", "-m", "signed", cwd=self.src)
        sh("git", "-c", "core.fsmonitor=false", "push", "-q", "origin", "main", cwd=self.src)
        for control in (["status", "--porcelain"], ["log", "-1"], ["diff", "HEAD~1"]):
            if os.path.exists(marker):
                os.unlink(marker)
            subprocess.run(["git", "-C", self.src, *control], capture_output=True, env=ENV)
            self.assertTrue(os.path.exists(marker), "positive control: plain git %s runs a program" % control[0])
        os.unlink(marker)
        iso = os.path.join(self.src, ".claude", "worktrees", "agent-a9")
        sh("git", "-c", "core.fsmonitor=false", "-C", self.src, "worktree", "add", "-q", "--detach", iso, "main")
        os.unlink(marker) if os.path.exists(marker) else None     # the smudge filter ran in that checkout
        self.sub_transcript("s1", "a9")
        R.subagent_start({"session_id": "s1", "agent_id": "a9", "cwd": iso})
        wt = os.path.join(self.home, "wt-p")
        cmd = "git -C %s worktree add %s -b px" % (self.src, wt)
        tid = self.tid()
        self.record(tid, cmd)
        R.pretool(self.payload(cmd, tid))
        sh("git", "-c", "core.fsmonitor=false", "-c", "filter.p.smudge=cat", "-C", self.src, "worktree", "add", "-q",
           wt, "-b", "px")
        os.unlink(marker) if os.path.exists(marker) else None
        R.posttool(self.payload(cmd, tid))
        note = R.subagent_stop({"session_id": "s1", "agent_id": "a9"}).read_text()
        self.assertFalse(os.path.exists(marker), "no hook surface may start a repo-configured program")
        self.assertIn("keep: repo config runs programs", note)
        with self.assertRaises(ValueError):
            R._git(self.src, "status", "--porcelain")            # porcelain is refused inside the module


REAL_BIRTH = R.birth_ns


class Ownership(Base):
    # NEG-7
    def test_inode_reuse_never_matches_the_old_row(self):
        dest = os.path.join(self.home, "c")

        def mkdir_then_clone():                             # probe on t2-dev: this pattern reuses the inode 10 of 10
            os.mkdir(dest)
            return self.clone(dest)()
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
        if sys.platform.startswith("linux"):
            # H1: removed and recreated in-process inside one clock tick, so dev, ino and btime_ns are all equal
            # (probe P8: 249 of 300). Only the inode generation tells them apart.
            same_tick = dict(live, btime_ns=old["btime_ns"])
            self.assertIsInstance(old["gen"], int)
            self.assertNotEqual(same_tick["gen"], old["gen"])
            self.assertIsNone(R.held(same_tick), "equal dev, ino and btime with a new generation is a new checkout")
            self.assertIsNotNone(R.held(dict(same_tick, gen=old["gen"])), "positive control: the old identity")
        self.assertIsNone(R.held(dict(live, gen=old["gen"])), "same dev, ino and generation, but another btime")
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

    def race(self, cmd_a, cmd_b, make, before_b=None):
        """Pre of A, then Pre of B, then the real effect, then Post of B first and A second: the order in which a fast
        failing call would win."""
        for tid, cmd, s, a in (("toolu_A", cmd_a, "s1", "a1"), ("toolu_B", cmd_b, "s2", "b2")):
            if tid == "toolu_B" and before_b:
                before_b()
            self.record(tid, cmd, s, a)
            R.pretool(self.payload(cmd, tid, s, a))
        make()
        got = R.posttool(self.payload(cmd_b, "toolu_B", "s2", "b2")) + R.posttool(self.payload(cmd_a, "toolu_A",
                                                                                                  "s1", "a1"))
        return got

    # NEG-9: one claim key for case, normalization and pinned-ancestor variants of one path
    def test_variant_spellings_of_one_path_are_one_claim(self):
        h = self.home
        work = os.path.join(h, "Work")
        os.makedirs(work)
        self.assertEqual(R.claim_key(work + "/p"), R.claim_key(h + "/work/p"))
        got = self.race("git clone %s %s/Work/p" % (self.src, h), "git clone %s %s/work/p || true" % (self.src, h),
                        self.clone(os.path.join(work, "p")))
        self.assertEqual(got, [])
        self.assertIn("contested", self.codes("toolu_B"))

    def test_two_calls_that_pinned_different_folders_share_one_claim(self):
        h = self.home
        deep = os.path.join(h, "P", "x", "y")
        got = self.race("mkdir -p %s/P/x && git clone %s %s" % (h, self.src, deep),
                        "git clone %s %s || true" % (self.src, deep), self.clone(deep),
                        before_b=lambda: os.makedirs(os.path.join(h, "P", "x")))
        self.assertEqual(got, [])
        self.assertIn("contested", self.codes("toolu_B"))

    def test_nfc_and_nfd_spellings_share_one_claim(self):
        nfc, nfd = "café", "café"
        self.assertEqual(R.claim_key(self.home + "/" + nfc), R.claim_key(self.home + "/" + nfd))
        self.assertNotEqual(R.claim_key(self.home + "/a"), R.claim_key(self.home + "/b"), "positive control")
        bad = self.home + "/\udcff-not-utf8"              # surrogateescape: a non-UTF-8 byte hashes, never raises
        self.assertTrue(R._claim_file("claims", bad).name)

    def test_busy_lock_and_unreadable_claim_write_no_row(self):
        import fcntl
        self.assert_one(self.bash("git clone %s %s/free" % (self.src, self.home), self.clone(self.home + "/free")))
        fd = os.open(str(R.state_dir() / "registry.lock"), os.O_RDWR)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)                  # another holder (a separate open file description)
            with mock.patch.object(R, "LOCK_WAIT", 0.2):
                self.assert_refused("lock-timeout", self.bash("git clone %s %s/busy" % (self.src, self.home),
                                                              self.clone(self.home + "/busy")))
        finally:
            os.close(fd)
        target = self.home + "/locked-out"
        claim = R._claim_file("claims", target)
        claim.write_text("someone")
        os.chmod(str(claim), 0o644)                         # exists but is not a private file: unreadable to us
        self.assert_refused("contested", self.bash("git clone %s %s" % (self.src, target), self.clone(target)))
        self.assertEqual(len(self.held()), 1)

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
                "ino": f["ino"], "btime_ns": f["btime_ns"], "gen": f["gen"], "common_dir": f["common_dir"],
                "agent": None,
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
        dest = os.path.join(self.home, "f10")                  # G1: an agent's call binds to its own file only
        cmd = "git clone %s %s" % (self.src, dest)
        tid = self.tid()
        self.last_tid = tid
        self.sub_transcript("s1", "a1")                         # the agent's transcript exists ...
        self.record(tid, cmd, agent=None)                       # ... but this tool_use is only in main's
        R.pretool(self.payload(cmd, tid))
        self.clone(dest)()
        self.assert_refused("transcript-unbound", R.posttool(self.payload(cmd, tid)))
        self.assertEqual(len(self.held()), 1)

    def test_subagent_transcript_path_form_is_accepted(self):
        dest = os.path.join(self.home, "sub")
        cmd = "git clone %s %s" % (self.src, dest)
        tid = self.tid()
        self.record(tid, cmd)
        p = self.payload(cmd, tid, transcript=self.sub_transcript())
        R.pretool(p)
        self.clone(dest)()
        self.assertEqual(len(R.posttool(self.payload(cmd, tid, transcript=self.sub_transcript()))), 1)


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
        state.mkdir(parents=True, exist_ok=True)
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
        with mock.patch.object(R, "birth_ns", side_effect=lambda p: real(p) - (
                10 ** 9 if p.endswith("agent-a6.jsonl") else 0)):     # transcript older: worktree planted later
            R.pretool(self.payload("ls", "t2b", agent="a6", cwd=path, tool="Read"))
        self.assertEqual(self.codes().count("iso-window"), 2)
        self.assertEqual(self.held(), [])
        R.pretool(self.payload("ls", "t3", agent="a6", cwd=path, tool="Read"))
        self.assertEqual(len(self.held()), 1, "positive control: same worktree, real birth times")

    def test_a_missing_transcript_is_rechecked_at_once(self):
        """SubagentStart can fire before the subagent transcript exists; that must not block the row for a minute."""
        path = os.path.join(self.src, ".claude", "worktrees", "agent-a8")
        sh("git", "-C", self.src, "worktree", "add", "-q", path, "-b", "w-a8")
        R.subagent_start({"session_id": "s1", "agent_id": "a8", "cwd": path})
        self.assertIn("iso-no-transcript", self.codes())
        self.sub_transcript("s1", "a8")
        R.pretool(self.payload("ls", "t1", agent="a8", cwd=path, tool="Read"))
        self.assertEqual([r["agent"] for r in self.held()], ["a8"])


LIVE_FIXTURE = ROOT / "tests" / "fixtures" / "checkout_registry_live_payloads.json"


class LivePayloads(Base):
    """AC-7 replay: payloads exactly as Claude Code sent them in the live run (tests/live/checkout_registry_live.py,
    redacted and trimmed), with only paths, ids and the command localized to this test's HOME. Every other key the
    real hook received (effort, prompt_id, scratchpad_dir, agent_type, permission_mode, description) is kept."""

    def setUp(self):
        super().setUp()
        self.fix = json.loads(LIVE_FIXTURE.read_text())
        self.proj = os.path.join(self.home, ".claude", "projects", "-HOME-live-src")
        os.makedirs(os.path.join(self.home, "live"), exist_ok=True)

    def localize(self, p: dict, **override) -> dict:
        text = json.dumps(p).replace("/HOME/live/src", self.src).replace("/HOME", self.home)
        return dict(json.loads(text), **override)

    def replay_clone(self, key, record_in=None):
        p = self.localize(self.fix[key])
        session, agent = p["session_id"], p.get("agent_id")
        tid = self.last_tid = self.tid()
        p["tool_use_id"] = tid
        cmd, dest = p["tool_input"]["command"], p["tool_input"]["command"].split()[-1]
        self.main_transcript(session)
        self.record(tid, cmd, session, agent if record_in is None else record_in)
        R.pretool(p)
        out = self.clone(dest)()
        return R.posttool(dict(p, hook_event_name="PostToolUse",
                               tool_response={"interrupted": False, "isImage": False, "noOutputExpected": False,
                                              "stderr": out, "stdout": ""}))

    def test_the_live_subagent_payload_points_at_the_main_transcript(self):
        """The live fact the binding depends on: a subagent's Bash payload names the SESSION transcript, and the
        agent's calls are found in projects/P/SESSION/subagents/agent-ID.jsonl."""
        p = self.fix["subagent_pretool_clone"]
        self.assertTrue(p["agent_id"])
        self.assertTrue(p["transcript_path"].endswith("/%s.jsonl" % p["session_id"]))
        self.assertNotIn("/subagents/", p["transcript_path"])
        stop = self.fix["subagent_stop"]
        self.assertTrue(stop["agent_transcript_path"].endswith(
            "/%s/subagents/agent-%s.jsonl" % (stop["session_id"], stop["agent_id"])))

    def test_live_subagent_clone_payload_gives_one_row_with_its_agent(self):
        row = self.assert_one(self.replay_clone("subagent_pretool_clone"))
        self.assertEqual((row["session"], row["agent"], row["kind"]), ("session-8", "a10", "clone"))

    def test_live_subagent_payload_without_the_call_in_its_own_transcript_gets_no_row(self):
        """The same real payload, but the tool call is only in the session's main transcript: unbound."""
        self.assert_refused("transcript-unbound", self.replay_clone("subagent_pretool_clone", record_in=""))

    def test_live_main_clone_payload_gives_one_row_without_an_agent(self):
        row = self.assert_one(self.replay_clone("main_pretool_clone"))
        self.assertEqual((row["session"], row["agent"]), ("session-1", None))

    def test_live_isolation_payloads_give_one_row_and_a_stop_note(self):
        start = self.localize(self.fix["subagent_start"])
        path = start["cwd"]                                   # live: SubagentStart's cwd is the worktree itself
        sh("git", "-C", self.src, "worktree", "add", "-q", path, "-b", "w-a15")
        self.sub_transcript(start["session_id"], start["agent_id"])
        self.assertEqual(R.subagent_start(start)["path"], os.path.realpath(path))
        call = self.localize(self.fix["subagent_posttool"], hook_event_name="PreToolUse")
        call.pop("tool_response")
        R.pretool(call)
        self.assertEqual([(r["kind"], r["agent"]) for r in self.held()], [("isolation", "a15")])
        note = R.subagent_stop(self.localize(self.fix["subagent_stop"]))
        self.assertIn("owner may remove", note.read_text())


class ContractFour(Base):
    """PR 344 review F1, F4, F5b: every clause of contract 4 makes held() None, through the one read path current().
    The table must name exactly R.CONTRACT_4, so a clause added to the module without a test here fails."""

    def row(self, name="c4"):
        d = os.path.join(self.home, name)
        return self.assert_one(self.bash("git clone %s %s" % (self.src, d), self.clone(d)))

    def clauses(self, row):
        key = R.read_key()

        def second_created_same_owner():
            with R._locked():
                R._append({k: v for k, v in row.items() if k != "mac"}, key)

        def retired():
            shutil.rmtree(row["path"])
            self.assertEqual(R.retire_absent(row["path"], key), 1)
        return {
            "removed-row": (lambda: self.assertIsNotNone(R.append_removed(row, "test", "route")), None, None),
            "retired": (retired, None, None),
            "opt-in-off": (lambda: self.opt_in(False), lambda: self.opt_in(True), None),
            "unknown-host": (None, None, dict(row, host="t2-dev")),
            "state-not-local": (lambda: setattr(self, "_p", mock.patch.object(R, "state_is_local", return_value=False))
                                or self._p.start(), lambda: self._p.stop(), None),
            "no-key": (lambda: os.rename(self.keyp, self.keyp + ".off"), lambda: os.rename(self.keyp + ".off", self.keyp),
                       None),
            "ledger-too-large": (lambda: setattr(self, "_m", mock.patch.object(R, "MAX_FILE", 10)) or self._m.start(),
                                 lambda: self._m.stop(), None),
            "two-created-rows": (second_created_same_owner, None, None),
        }

    def test_every_clause_makes_held_none(self):
        self.keyp = str(Path(self.home) / ".agent-harness/state/checkouts/registry.key")
        self.assertEqual(set(self.clauses({})), set(R.CONTRACT_4), "a contract-4 clause has no test, or a test no clause")
        for name in R.CONTRACT_4:
            row = self.row(name)                          # a fresh checkout per clause, so no clause hides another
            setup, undo, ident = self.clauses(row)[name]
            with self.subTest(clause=name):
                self.assertEqual(R.held(row), row, "positive control before %s" % name)
                if setup:
                    setup()
                try:
                    self.assertIsNone(R.held(ident or row))
                    if name in ("unknown-host", "state-not-local", "no-key", "ledger-too-large"):
                        with self.assertRaises(R.NotHeld) as cm:     # the whole ledger is unusable
                            R.current((ident or row)["host"])
                        self.assertEqual(cm.exception.clause, name)
                    elif name != "opt-in-off":                        # this identity has no single owner
                        self.assertNotIn(R.identity(row), R.current())
                finally:
                    if undo:
                        undo()

    def test_a_ledger_that_grows_during_the_read_is_refused_not_read_in_part(self):
        p = Path(self.home) / ".agent-harness/state/checkouts/big"
        fd = os.open(str(p), os.O_WRONLY | os.O_CREAT, 0o600)
        os.write(fd, b"x" * 100)
        os.close(fd)
        self.assertEqual(R._read_secure(p, 100), b"x" * 100, "positive control: at the bound it is read whole")
        with self.assertRaises(R.TooLarge):
            R._read_secure(p, 99)
        real_fstat = os.fstat

        def small_fstat(fd):                             # the size check sees the old size; the read sees growth
            st = real_fstat(fd)
            return os.stat_result((st.st_mode, st.st_ino, st.st_dev, st.st_nlink, st.st_uid, st.st_gid, 50,
                                   st.st_atime, st.st_mtime, st.st_ctime))
        with mock.patch.object(R.os, "fstat", small_fstat), self.assertRaises(R.TooLarge):
            R._read_secure(p, 99)


class OptInDefault(Base):
    """PR 344 review F2: off by default. Rows may be recorded, but nothing treats them as ownership, and no verdict
    says "owner may remove"."""

    def test_off_means_no_owner_and_no_remove_verdict(self):
        self.opt_in(False)
        self.assertFalse(R.enabled())
        iso = os.path.join(self.src, ".claude", "worktrees", "agent-a1")
        sh("git", "-C", self.src, "worktree", "add", "-q", "--detach", iso, "origin/main")
        self.sub_transcript("s1", "a1")
        row = R.subagent_start({"session_id": "s1", "agent_id": "a1", "cwd": iso})
        self.assertIsNotNone(row, "recording needs no opt-in")
        self.assertIsNone(R.held(row))
        text = R.subagent_stop({"session_id": "s1", "agent_id": "a1"}).read_text()
        self.assertNotIn("owner may remove", text)
        self.assertIn("checkout registry opt-in is off", text)
        self.opt_in(True)                                 # positive control: the same clean worktree
        self.assertEqual(R.held(row), row)
        self.assertIn("owner may remove", R.subagent_stop({"session_id": "s1", "agent_id": "a1"}).read_text())

    def test_only_a_private_literal_true_turns_it_on(self):
        p = Path(self.home) / ".agent-harness/state/checkouts/enabled.json"
        for body, mode, want in ((b'{"enabled": true}', 0o600, True), (b'{"enabled": "true"}', 0o600, False),
                                 (b'{"enabled": 1}', 0o600, False), (b"true", 0o600, False),
                                 (b'{"enabled": true}', 0o644, False), (b"{" + b" " * 5000 + b"}", 0o600, False)):
            p.write_bytes(body)
            os.chmod(p, mode)
            with self.subTest(body=body[:30], mode=oct(mode)):
                self.assertIs(R.enabled(), want)
                import install  # noqa: PLC0415
                self.assertIs(install.checkout_registry_enabled(Path(self.home) / ".claude"), want,
                              "install.py and the registry read the opt-in the same way")


class RemoveVerdict(Base):
    """PR 344 review F2 and F5a: one choke point, may_remove(), produces the remove wording, and only when every
    REMOVE_EVIDENCE item is literally True."""

    def test_every_evidence_item_alone_keeps(self):
        names = [n for n, _ in R.REMOVE_EVIDENCE]
        self.assertEqual(R.may_remove({n: True for n in names}), "owner may remove", "positive control")
        for name, why in R.REMOVE_EVIDENCE:
            for bad in (False, None, "yes", 1):
                with self.subTest(item=name, value=bad):
                    ev = {n: True for n in names}
                    ev[name] = bad
                    self.assertEqual(R.may_remove(ev), "keep: " + why)
            ev = {n: True for n in names if n != name}
            self.assertEqual(R.may_remove(ev), "keep: " + why, "a missing item keeps")

    def test_the_verdict_gathers_exactly_the_listed_evidence(self):
        iso = os.path.join(self.src, ".claude", "worktrees", "agent-a1")
        sh("git", "-C", self.src, "worktree", "add", "-q", "--detach", iso, "origin/main")
        self.sub_transcript("s1", "a1")
        row = R.subagent_start({"session_id": "s1", "agent_id": "a1", "cwd": iso})
        seen = []
        real = R.may_remove
        with mock.patch.object(R, "may_remove", side_effect=lambda ev: seen.append(dict(ev)) or real(ev)):
            self.assertEqual(R.verdict(row, time.monotonic() + 15)["verdict"], "owner may remove")
        self.assertEqual(set(seen[0]), {n for n, _ in R.REMOVE_EVIDENCE})

    def test_skip_worktree_or_assume_unchanged_edits_keep(self):
        iso = os.path.join(self.src, ".claude", "worktrees", "agent-a1")
        sh("git", "-C", self.src, "worktree", "add", "-q", "--detach", iso, "origin/main")
        self.sub_transcript("s1", "a1")
        row = R.subagent_start({"session_id": "s1", "agent_id": "a1", "cwd": iso})
        self.assertEqual(R.verdict(row, time.monotonic() + 15)["verdict"], "owner may remove", "positive control")
        for flag in ("--skip-worktree", "--assume-unchanged"):
            with self.subTest(flag=flag):
                sh("git", "-C", iso, "update-index", flag, "f.txt")
                Path(iso, "f.txt").write_text("hidden edit\n")
                v = R.verdict(row, time.monotonic() + 15)
                self.assertEqual(v.get("changed"), 0, "diff-files really does not see it")
                self.assertIn("skip-worktree or assume-unchanged", v["verdict"])
                sh("git", "-C", iso, "update-index", flag.replace("--", "--no-"), "f.txt")
                sh("git", "-C", iso, "checkout", "-q", "--", "f.txt")


class OwnOutput(Base):
    """PR 344 review F3: the row needs this call's own git output creating the path."""

    def test_a_checkout_another_process_made_meanwhile_gets_no_row(self):
        ok = os.path.join(self.home, "own-ok")
        self.assert_one(self.bash("git clone %s %s 2>&1 | tail -3" % (self.src, ok), self.clone(ok)))
        dest = os.path.join(self.home, "raced")
        other = self.clone(dest)                          # an unhooked process clones the same URL to the same path

        def ours_fails():
            other()
            r = subprocess.run(["git", "clone", self.src, dest], capture_output=True, text=True, env=ENV)
            self.assertNotEqual(r.returncode, 0)
            return r.stderr                               # git's own "already exists" for that path
        self.assert_refused("git-failed-here", self.bash("git clone %s %s" % (self.src, dest), ours_fails))
        wt = os.path.join(self.home, "wt-raced")

        def ours_fails_wt():
            sh("git", "-C", self.src, "worktree", "add", "-q", wt, "-b", "theirs")
            r = subprocess.run(["git", "-C", self.src, "worktree", "add", wt, "-b", "ours"], capture_output=True,
                               text=True, env=ENV)
            self.assertNotEqual(r.returncode, 0)
            return r.stderr
        self.assert_refused("git-failed-here", self.bash("git -C %s worktree add %s -b ours" % (self.src, wt),
                                                         ours_fails_wt))
        self.assertEqual([r["path"] for r in self.held()], [ok])

    def test_a_git_that_started_then_failed_gets_no_row_for_a_checkout_made_meanwhile(self):
        dest = os.path.join(self.home, "started-then-failed")
        bad = "file://" + os.path.join(self.src, ".git", "objects")    # git starts the clone, then gives up

        def ours_starts_then_fails():
            r = subprocess.run(["git", "clone", bad, dest], capture_output=True, text=True, env=ENV)
            self.assertNotEqual(r.returncode, 0)
            self.assertRegex(r.stderr, r"(?m)^Cloning into '[^']*%s'\.\.\.$" % os.path.basename(dest),
                             "positive control: git started")
            self.assertFalse(os.path.exists(dest), "git removed what it made")
            self.clone(dest)()                            # then an unhooked process clones to the same path
            return r.stderr
        self.assert_refused("git-failed-here", self.bash("git clone %s %s" % (bad, dest), ours_starts_then_fails))
        wt = os.path.join(self.home, "wt-started-then-failed")

        def theirs_wt():
            sh("git", "-C", self.src, "worktree", "add", "-q", wt, "-b", "theirs2")
        self.assert_refused("git-failed-here", self.bash(
            "git -C %s worktree add %s -b ours2" % (self.src, wt), theirs_wt,
            output="Preparing worktree (new branch 'ours2')\nfatal: unable to checkout working tree\n"))
        self.assertEqual(self.held(), [])

    def test_hidden_or_quiet_output_gets_no_row(self):
        d = os.path.join(self.home, "hidden")
        self.assert_refused("no-own-output", self.bash("git clone %s %s >/dev/null 2>&1" % (self.src, d),
                                                       self.clone(d), shown=False))
        q = os.path.join(self.home, "quiet")
        self.assert_refused("no-own-output", self.bash("git clone -q %s %s" % (self.src, q),
                                                       lambda: git_out("git", "clone", "-q", self.src, q)))
        other = os.path.join(self.home, "named-elsewhere")
        self.assert_refused("no-own-output", self.bash("git clone %s %s" % (self.src, other), self.clone(other),
                                                       output="Cloning into 'something-else'...\ndone.\n"))
        self.assertEqual(self.held(), [])


class Retire(Base):
    # Rule 14
    def test_retire_needs_absence_on_the_rows_own_filesystem(self):
        d = os.path.join(self.home, "rt")
        row = self.assert_one(self.bash("git clone %s %s" % (self.src, d), self.clone(d)))
        key = R.read_key()
        self.assertEqual(R.retire_absent(d, key), 0, "present: nothing is retired")
        shutil.rmtree(d)
        elsewhere = {"realpath": self.home, "dev": row["dev"] + 1, "ino": 1, "rest": "rt"}
        with mock.patch.object(R, "_anchor", lambda p: elsewhere):
            self.assertEqual(R.retire_absent(d, key), 0, "a parent on another st_dev (an unmounted volume) never "
                                                         "retires a row")
        self.assertIsNotNone(R.held(row))
        out = io.StringIO()
        with redirect_stdout(out):
            R.main(["retire", "--path", d])
        self.assertEqual(json.loads(out.getvalue())["retired"], 1)
        self.assertIsNone(R.held(row))
        self.assertEqual([r["route"] for r in R.rows()[0] if r["event"] == "removed"], ["observed-absent"])

    # AC-3, Rule 13
    def test_oversized_ledger_or_remote_state_folder_writes_nothing(self):
        row = self.assert_one(self.bash("git clone %s %s/l1" % (self.src, self.home), self.clone(self.home + "/l1")))
        self.assertTrue(R.state_is_local(), "positive control: the test state folder is on a local filesystem")
        with mock.patch.object(R, "MAX_FILE", 10):
            self.assertIsNone(R.held(row), "never judge ownership from part of the file")
            self.assert_refused("ledger-too-large", self.bash("git clone %s %s/l2" % (self.src, self.home),
                                                              self.clone(self.home + "/l2")))
        locks = []
        real_flock = R.fcntl.flock
        with mock.patch.object(R, "state_is_local", lambda: False), \
                mock.patch.object(R.fcntl, "flock", lambda fd, op: locks.append(op) or real_flock(fd, op)):
            self.assert_refused("state-not-local", self.bash("git clone %s %s/l3" % (self.src, self.home),
                                                             self.clone(self.home + "/l3")))
            self.assertEqual(R.retire_absent(self.home + "/l3", R.ensure_key()), 0)
        self.assertEqual(locks, [], "a state folder that is not local is never locked: its flock cannot be trusted")
        self.assertEqual(len(self.held()), 1)


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
        Path(self.src, "package.json").write_text("{}\n")
        sh("git", "add", "package.json", cwd=self.src)
        sh("git", "commit", "-q", "-m", "pkg", cwd=self.src)
        sh("git", "push", "-q", "origin", "main", cwd=self.src)
        with open(os.path.join(self.src, ".git", "info", "exclude"), "a") as fh:
            fh.write("node_modules/\n.venv/\n__pycache__/\n*.pyc\n.env.local\n")
        with mock.patch.dict(sys.modules, {"ah_worktree": fake}):
            iso = self.iso(branch="x`rm`OWNER-DECISION")
            os.makedirs(os.path.join(iso, "node_modules", "left-pad"))           # regenerable ignored content only
            Path(iso, "node_modules", "left-pad", "index.js").write_text("x")
            os.makedirs(os.path.join(iso, ".venv", "bin"))
            Path(iso, ".venv", "pyvenv.cfg").write_text("home = /usr\n")
            os.makedirs(os.path.join(iso, "pkg", "__pycache__"))
            Path(iso, "pkg", "__pycache__", "m.cpython-312.pyc").write_bytes(b"x")
            Path(iso, "pkg", "m.pyc").write_bytes(b"x")
            text = R.subagent_stop({"session_id": "s1", "agent_id": "a1"}).read_text()
            self.assertIn("isolation `%s`: owner may remove" % iso, text, "positive control")
            self.assertRegex(text, r"ignored [1-9]")        # the entry count varies by git version (--directory)
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
            sh("git", "-C", iso, "mv", "f.txt", "g.txt")                       # staged: counted by path, so two
            text = R.subagent_stop({"session_id": "s1", "agent_id": "a1"}).read_text()
            self.assertIn("keep: changes", text)
            self.assertIn("changed 2, untracked 0", text)
            sh("git", "-C", iso, "reset", "-q", "--hard", "origin/main")

            for name in (".env.local", os.path.join("build", "out.o")):         # ignored, and maybe the only copy
                os.makedirs(os.path.dirname(os.path.join(iso, name)), exist_ok=True)
                Path(iso, name).write_text("data\n")
                text = R.subagent_stop({"session_id": "s1", "agent_id": "a1"}).read_text()
                self.assertIn("keep: ignored files", text, name)
                os.unlink(os.path.join(iso, name))
            shutil.rmtree(os.path.join(iso, "build"))

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

    # NEG-17: a global fsmonitor is trusted config, so the verdict's plumbing runs, and the hardening must stop it
    def test_global_fsmonitor_never_starts_from_the_verdict(self):
        marker = os.path.join(self.home, "fsmonitor-ran")
        prog = os.path.join(self.home, "fsmon.sh")
        Path(prog).write_text("#!/bin/sh\ntouch %s\nexit 1\n" % marker)
        os.chmod(prog, 0o755)
        iso = self.iso("a3")
        Path(self.home, ".gitconfig").write_text("[core]\n\tfsmonitor = %s\n" % prog)
        subprocess.run(["git", "-C", iso, "diff-files", "--name-only"], capture_output=True,
                       env={k: v for k, v in os.environ.items() if not k.startswith("GIT_")})
        self.assertTrue(os.path.exists(marker), "positive control: unhardened plumbing starts the fsmonitor")
        os.unlink(marker)
        text = R.subagent_stop({"session_id": "s1", "agent_id": "a3"}).read_text()
        self.assertIn("owner may remove", text, "the plumbing ran (global config is trusted)")
        self.assertFalse(os.path.exists(marker))

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
        shutil.rmtree(state / "checkouts")                  # setUp made it for the opt-in; this test breaks it
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
        p = self.payload(cmd, "toolu_ep")
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
        off = install.managed_hooks(claude, True)               # no opt-in file under /h: nothing is wired
        self.assertFalse(any(h.get("args", [None])[0] == script for groups in off.values() for g in groups
                             for h in g["hooks"]))
        hooks = install.managed_hooks(claude, True, checkout_registry=True)
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
