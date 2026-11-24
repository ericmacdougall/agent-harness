"""goodqa#17112, #17099 and #17106: below the disk floor, the copy check charges only real copies onto this disk.

- #17112 (CRITICAL): a WAL, transcript or log write is never read as a copy, alone or inside a compound command.
- #17099: a quoted-delimiter heredoc written to a file through cat or tee is data.
- #17106: an rsync to host:path is not charged here, even when a redirect or an option value follows it.

The base reading splits at every separator, even inside quotes and heredoc bodies, so a copy verb right after a
separator in data text was charged. Each allowed shape below holds such a verb, and a guard in every test checks
that the base reading does charge it; a shape the base never charged would test nothing.

A compound of a record write and a real copy is refused whole (main's ruling, WAL w5a6bf9907ea): a PreToolUse hook
cannot run half a command, so the refusal names the copy and says the record write passes on its own.

The commands are genericized; no host, project, path or session from a real run appears here.
"""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "harness" / "hooks"))
import copy_hygiene as tc  # noqa: E402

GB = 1024 ** 3
W = "~/.claude/wals/s-0000/agent-a0000.jsonl"
NOTE = "python3 ~/.claude/hooks/wal_note.py --wal %s --event check --note " % W

# Record writes as agents make them. Every one holds a copy verb right after a separator inside its data.
RECORD_WRITES = [
    NOTE + "'REALLY_TESTED x: ran `git clone a b` then; cp -r src dst; ok'",
    NOTE + "'next: $(git worktree add ../x) and && rsync -a a/ b/'",
    NOTE + "\"$(cat <<'EOF'\nREALLY_TESTED y (focused): it's green\ngit clone https://example.invalid/y.git z && cp -r a b\nEOF\n)\"",
    NOTE + "\"$(cat <<'EOF'\nresult; ditto a b\nEOF\n)\" --ticket goodqa#1",
    "python3 $HOME/.claude/hooks/wal_note.py --wal " + W + " --event result --note 'ok; git clone a b'",
    "echo '{\"event\":\"check\",\"note\":\"did git clone a b; then cp -a x y\"}' >> " + W,
    "printf '%s\\n' '{\"note\":\"`git clone a b`\"}' >> " + W,
    "echo \"step 2; git clone a b\" >> " + W,
    "cat >> " + W + " <<'EOF'\n{\"note\": \"x\"}\ncp -r a b\nEOF",
    "tee -a " + W + " <<'EOF'\ngit clone a b\nEOF",
    "echo 'step; git clone a b' | tee -a " + W,
    "echo 'step; git clone a b' | tee -a " + W + " | tail -1",
    "cat <<'EOF' >> ~/.claude/projects/p/s.log\nrsync -a a/ b/\nEOF",
]

# #17099: a file written through cat or tee from a quoted-delimiter heredoc.
HEREDOC_FILES = [
    "cat > notes.md <<'EOF'\n## Steps\ngit clone https://example.invalid/y.git z\ncp -r a b\nEOF",
    "cat > tests/case.txt <<\"EOF\"\nrsync -a src/ dst/\nEOF",
    "cat <<'EOF' > docs/run.md\nuse `git clone a b` here\nEOF",
    "mkdir -p d && cat > d/a.md <<-'EOF'\n\tgit clone a b\n\tEOF",
    "cat > a.md <<'A'\ngit clone a b\nA\ncat > b.md <<'B'\ncp -r x y\nB",
    "cat <<\\EOF > n.md\ngit worktree add ../w HEAD\nEOF",
    "cat <<EOF > n.md\nplain $HOME text\ngit clone a b\nEOF",
    # A quote that spans lines while the heredoc waits: every shell starts the body after the line it closes on.
    "cat > n.md <<'EOF' && echo 'spans\nlines'\ngit clone a b\nEOF",
]

# A real copy runs here: refused below the floor, alone or next to a record write.
NEAR_MISSES = [
    "git clone https://example.invalid/r.git /w/r",
    "git worktree add ../wt-x HEAD",
    "cp -r src /w/dst",
    "rsync -a ./ /w/dst/",
    "bash <<'EOF'\ngit clone a b\nEOF",
    "sh <<EOF\ncp -r big dst\nEOF",
    "python3 - <<'EOF'\nimport os\nos.system('true; git clone a b')\nEOF",
    "echo \"$(git clone a b)\"",
    NOTE + "\"$(git clone a b)\"",
    NOTE + "\"ran `git clone a b`\"",
    "echo $(git clone a b)",
    "echo \"${X:-$(git clone a b)}\"",
    "echo 'x; git clone a b' | bash",
    "echo 'x; git clone a b' | sh",
    "printf 'x; git clone a b\\n' | xargs -I{} sh -c '{}'",
    "echo 'step; git clone a b' | tee run.sh | sh",
    "cat <<'EOF' | sh\ngit clone a b\nEOF",
    "cat > x.sh <<'EOF'\ngit clone a b\nEOF\nbash x.sh",
    "echo 'x; git clone a b' > run.sh && sh run.sh",
    "F=run.sh; cat > \"$F\" <<'EOF'\ngit clone a b\nEOF\nbash \"$F\"",
    "cat <<EOF > n.md\n$(git clone a b)\nEOF",
    "cat <<EOF > n.md\n`git clone a b`\nEOF",
    "echo() { git clone \"$@\"; }; echo 'a; git clone b c'",
    "{ echo 'a; git clone b c'; } | bash",
    "(echo 'a; git clone b c') | bash",
    "if true; then echo 'a; git clone b c' | bash; fi",
    # A group, a loop or an exec redirect sends the output of a plain data command on to a shell.
    "{ true; echo 'a; git clone b c'; } | bash",
    "for i in 1; do true; echo 'a; git clone b c'; done | sh",
    "exec 3>&1 > run.sh; echo 'x; git clone a b'; exec 1>&3; bash run.sh",
    # A precommand runs eval in this shell, which redefines echo.
    "builtin eval 'echo() { git clone \"$@\"; }'; echo 'a; git clone b c'",
    "command eval 'echo() { git clone \"$@\"; }'; echo 'a; git clone b c'",
    # Two heredocs on one line: the first body is bash's, not cat's.
    "bash <<'A'; cat <<'B'\ngit clone a b\nA\nx\nB\necho\nA",
    NOTE + "'clone next' && git clone https://example.invalid/r.git /w/r",
    "git clone https://example.invalid/r.git /w/r; " + NOTE + "'cloned; cp -r a b'",
    "echo 'a; ok' >> " + W + " && cp -r src /w/dst",
]

# Strict by design: shapes the mask does not model keep the base reading, whether or not a shell would run a copy.
UNMODELLED = [
    "PATH=./bin:$PATH; echo 'a; git clone b c'",
    "export PATH=./bin; echo 'a; git clone b c'",
    "printf -v c '%s' 'a; git clone b c'",
    "python3 ./wal_note.py --note 'a; git clone b c'",
    "command echo 'a; git clone b c'",
    "exec > >(bash); echo 'a; git clone b c'",
    "tee >(bash) <<'EOF'\ngit clone a b\nEOF",
    "echo 'a; git clone b c' >&3",
    "echo $'a\\'; git clone b c'",
    "cat > n.md <<'EOF'\ngit clone a b",
    "cat <<'A' <<'B'\ngit clone a b\nA\ncp -r x y\nB",
    "cat <<'EOF' > n.md \"$(echo a\necho b)\"\ngit clone a b\nEOF",
    "cat <<EOF > n.md\nline \\\ngit clone a b\nEOF",
    "echo \"$(case x in x) git clone a b;; esac)\"",
    "eval 'echo ok'; echo 'a; git clone b c'",
    # A precommand runs eval in this shell; the code it evals comes from outside the line.
    "builtin eval \"$DEF\"; echo 'a; git clone b c'",
    "command -p eval \"$DEF\"; echo 'a; git clone b c'",
    "noglob eval \"$DEF\"; echo 'a; git clone b c'",
    # zsh -c and bash -c do not expand an alias defined in the same text; a runner that evals line by line may.
    "alias echo='git clone'\necho 'a; git clone b c'",
]

# #17106: an rsync to host:path. The base charged each one: a redirect word or an option value was read as the
# destination.
D = "devbox:/srv/w/x/"
REMOTE_DESTINATIONS = [
    "rsync -a ./ %s 2>&1 | tail -2" % D,
    "rsync -a ./ %s 2>/dev/null" % D,
    "rsync -a ./ %s > /tmp/rs.log" % D,
    "rsync -a ./ %s >> /tmp/rs.log 2>&1" % D,
    "rsync -a ./ %s --timeout 30" % D,
    "rsync -a ./ %s --exclude x" % D,
    "rsync -a ./ %s -e 'ssh -p 22'" % D,
    "cd /w && rm -f a.pyc && rsync -rc --delete --exclude .git ./ %s 2>&1 | tail -2" % D,
    "rsync -avz -e ssh ./ eric@%s 2>&1" % D,
]

# Still a copy onto this disk: a remote source, a local destination, or a host:path word that is not the destination.
LOCAL_DESTINATIONS = [
    "rsync -a %s ./local-x/" % D,
    "rsync -a %s ./local-x/ 2>&1 | tail -2" % D,
    "rsync -a %s 2>/dev/null ./local-x/" % D,
    "rsync -a %s 2>/dev/null ./local-x/  # pull back" % D,
    "rsync -a %s ./local-x/ --timeout 30" % D,
    "rsync -a ./ /w/dst/ --timeout 30",
    "rsync -a ./ /w/dst/ 2>/dev/null",
    "rsync -a --partial-dir devbox:p ./ /w/dst/",
    "rsync -a %s ./local-x/ --no-such-option devbox:y" % D,
    "rsync -a -e 'ssh -p 22' %s ./local-x/" % D,
]


def base_charges(line, rule=None):
    return any((rule or tc.is_copy_command)(words) for words in tc._legacy_copy_commands(line, 0))


def rsync_rule_at_8539e978(words):
    """The base's rsync rule, for the #17106 guard: the last word that is not an option was the destination."""
    if os.path.basename(words[0]) != "rsync":
        return tc.is_copy_command(words)
    flags, pos = tc._opts(words)
    return bool(flags & {"r", "a", "--recursive", "--archive"}) and not any(":" in p.split("/")[0] for p in pos[-1:])


class BelowTheFloor(unittest.TestCase):
    """A state directory and a disk 24 GB under the floor."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        patcher = mock.patch.dict(os.environ, {"HARNESS_COPY_HYGIENE_HOME": self.tmp.name})
        patcher.start()
        self.addCleanup(patcher.stop)
        low = mock.patch.object(tc, "free_bytes", return_value=1 * GB)
        low.start()
        self.addCleanup(low.stop)
        self.cfg = tc.normalize({"min_free_gb": 25, "min_free_pct": 0})

    def pretool(self, command):
        return tc.pretool({"tool_name": "Bash", "tool_input": {"command": command}, "cwd": self.tmp.name}, self.cfg)

    def assert_allowed(self, line, rule=None):
        with self.subTest(line=line):
            self.assertTrue(base_charges(line, rule), "the base reading never charged this shape; it tests nothing")
            self.assertEqual(self.pretool(line), (0, ""))

    def assert_refused(self, line):
        with self.subTest(line=line):
            code, err = self.pretool(line)
            self.assertEqual(code, 2)
            self.assertIn("DISK LOW", err)


def in_compounds(line):
    """The line alone, after `cd DIR &&`, and before another command (on its own line after a heredoc)."""
    after = "\necho done" if "<<" in line else "; echo done"
    return [line, "cd . && " + line, line + after]


class RecordWrites(BelowTheFloor):
    def test_a_record_write_is_never_read_as_a_copy(self):
        for line in RECORD_WRITES:
            for shape in in_compounds(line):
                self.assert_allowed(shape)

    def test_a_quoted_heredoc_written_to_a_file_is_data(self):
        for line in HEREDOC_FILES:
            for shape in in_compounds(line):
                self.assert_allowed(shape)

    def test_a_record_write_next_to_a_real_copy_is_refused_and_the_message_names_the_copy(self):
        code, err = self.pretool(NOTE + "'clone next' && git clone https://example.invalid/r.git /w/r")
        self.assertEqual(code, 2)
        self.assertIn("git clone", err)
        self.assertIn("on its own", err)
        code, err = self.pretool("echo 'a; ok' >> " + W + " && cp -r src /w/dst")
        self.assertEqual(code, 2)
        self.assertIn("cp -r", err)


class NearMisses(BelowTheFloor):
    def test_real_copies_are_still_refused(self):
        for line in NEAR_MISSES:
            self.assert_refused(line)

    def test_unmodelled_shapes_keep_the_base_reading(self):
        for line in UNMODELLED:
            with self.subTest(line=line):
                self.assertTrue(base_charges(line), "the base reading never charged this shape; it tests nothing")
            self.assert_refused(line)

    def test_the_mask_fails_strict(self):
        with mock.patch.object(tc, "data_mask", side_effect=RuntimeError("boom")):
            for line in RECORD_WRITES[:3] + NEAR_MISSES[:3]:
                self.assert_refused(line)

    def test_the_mask_only_removes_copies(self):
        """Guard: over every shape here, what the masked reading charges is a subset of what the base charges."""
        checked = 0
        for line in RECORD_WRITES + HEREDOC_FILES + NEAR_MISSES + UNMODELLED + REMOTE_DESTINATIONS + LOCAL_DESTINATIONS:
            for shape in in_compounds(line):
                masked = tc.data_mask(shape)
                if masked is None:
                    continue
                checked += 1
                strict = [w for w in tc.copy_commands(shape) if tc.is_copy_command(w)]
                left = tc._masked_reading(shape, masked)
                with self.subTest(line=shape):
                    self.assertTrue(all(w in strict for w in left))
                    self.assertEqual(len(masked), len(shape))
        self.assertGreaterEqual(checked, 60)

    def test_record_shapes_are_masked_and_unmodelled_shapes_are_not(self):
        for line in RECORD_WRITES + HEREDOC_FILES:
            with self.subTest(line=line):
                self.assertIsNotNone(tc.data_mask(line))
        for line in UNMODELLED:
            with self.subTest(line=line):
                masked = tc.data_mask(line)
                self.assertTrue(masked is None or base_charges(masked))


class RemoteDestinations(BelowTheFloor):
    def test_an_rsync_to_host_path_is_not_charged_here(self):
        for line in REMOTE_DESTINATIONS:
            self.assert_allowed(line, rsync_rule_at_8539e978)

    def test_a_copy_onto_this_disk_is_still_charged(self):
        for line in LOCAL_DESTINATIONS:
            self.assert_refused(line)

    def test_a_redirect_to_the_null_device_does_not_pick_the_volume_measured(self):
        def free(path):
            return 0 if str(path).startswith("/dev") else 100 * GB
        with mock.patch.object(tc, "free_bytes", side_effect=free):
            for line in ("cp -r src /w/dst 2>/dev/null", "git clone https://example.invalid/r.git /w/r > /dev/null",
                         "rsync -a ./ /w/dst/ >/dev/null 2>&1"):
                with self.subTest(line=line):
                    self.assertEqual(self.pretool(line), (0, ""))


SHELLS = [s for s in ("zsh", "bash") if shutil.which(s)]


class ShellGroundTruth(unittest.TestCase):
    """The real shells agree: no allowed shape runs a copy verb, and every near-miss runs one in some shell.

    Each line runs in a temporary HOME and working directory. git, cp, rsync, scp and ditto are stand-ins on PATH
    that only append to a marker file, and wal_note.py is a stand-in that exits 0. Nothing outside the temporary
    directory is read or written."""

    def setUp(self):
        if not SHELLS:
            self.skipTest("no zsh or bash on this host")
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.bin = root / "bin"
        self.bin.mkdir()
        self.mark = root / "marker"
        for verb in ("git", "cp", "rsync", "scp", "ditto"):
            path = self.bin / verb
            path.write_text("#!/bin/sh\necho %s >> %s\n" % (verb, self.mark))
            path.chmod(0o755)
        hooks = root / "home" / ".claude" / "hooks"
        hooks.mkdir(parents=True)
        (hooks / "wal_note.py").write_text("import sys\nsys.exit(0)\n")
        (root / "home" / ".claude" / "wals" / "s-0000").mkdir(parents=True)
        (root / "home" / ".claude" / "projects" / "p").mkdir(parents=True)
        self.home = root / "home"

    def ran(self, shell, line):
        work = Path(tempfile.mkdtemp(dir=self.tmp.name))
        for d in ("tests", "docs"):
            (work / d).mkdir()
        if self.mark.exists():
            self.mark.unlink()
        env = {"PATH": "%s:/usr/bin:/bin" % self.bin, "HOME": str(self.home), "LC_ALL": "C"}
        subprocess.run([shell, "-c", line], cwd=work, env=env, capture_output=True, timeout=20)
        return self.mark.exists()

    def test_allowed_shapes_never_run_a_copy(self):
        for line in RECORD_WRITES + HEREDOC_FILES:
            for shape in in_compounds(line):
                for shell in SHELLS:
                    with self.subTest(shell=shell, line=shape):
                        self.assertFalse(self.ran(shell, shape))

    def test_near_misses_run_a_copy_in_some_shell(self):
        for line in NEAR_MISSES:
            with self.subTest(line=line):
                self.assertTrue(any(self.ran(shell, line) for shell in SHELLS))


if __name__ == "__main__":
    unittest.main()
