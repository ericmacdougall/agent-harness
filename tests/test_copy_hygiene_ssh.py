"""goodqa#16811: the disk-floor copy check does not charge a copy inside an ssh's quoted remote command to this machine,
and still refuses every local copy below the floor.

The allowed commands are genericized from real refused runs (a clone or `cp -a` sent to a build host over ssh while
the workstation sat at its floor): no host, project, path or session from those runs appears here.

Round 2 (review of f54937a): only a plain remote ssh is dropped. The generated table, the guard test against the
base reading, and the real-ssh oracle check that a new word shape cannot slip through one at a time.
"""
import os
import shlex
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

# Real shapes: a remote clone or copy inside single or double quotes, with local `T=...;`, `&& scp`, `set -e;`.
REMOTE = [
    "ssh -o BatchMode=yes devbox 'cd /srv/w/fx && cp -a r6 r7 && cd r7 && echo done'",
    'T=/srv/w/s; ssh -o BatchMode=yes devbox "mkdir -p $T && ls $T" && scp -q a.bundle devbox:$T/a.bundle && '
    'ssh devbox "cd $T && git clone -q -b br a.bundle a && cd a && git log --oneline -2"',
    "ssh devbox 'set -e; git clone -q --branch fix/x https://example.invalid/r.git /srv/r 2>&1 | tail -2; "
    "cd /srv/r && git log --oneline -1'",
    "W=/x; ssh devbox 'cd ~/w/f1 && git clone -q -b fix/y base.bundle repo && cd repo && git log --oneline -1' "
    "&& scp -q a.go devbox:w/f1/repo/ && echo copied",
    "ssh -o BatchMode=yes devbox 'set -e; umask 077; S=~/w/s; D=~/w/d; mkdir -p $D; cd $S; cp -a binroot pkgs $D/; ls $D'",
    'ssh devbox "cd ~/w && git clone u d && timeout 120 git clone u2 d2"',
    "ssh devbox 'cd /srv && git worktree add -q --detach /srv/wt HEAD && rsync -a /srv/a/ /srv/b/'",
    "(ssh devbox 'cd x && git clone a b')",
    "sudo -u ops ssh devbox 'cd x; git clone a b'",
    "ssh devbox 'echo $(date) && git clone a b'",
    # F4 (round 1): the clone in an ssh payload inside `bash -c` runs on the far host too; base refused it.
    "bash -c 'ssh devbox \"cd x && git clone a b\"'",
    "sh -c \"ssh devbox 'cd x; cp -a r s'\"",
]

# Every local form the base test file refuses, which must stay refused after an ssh on the same line.
BASE_REFUSED = ["git worktree add ../tester-1408-r5 HEAD", "git clone https://x/y.git tester-2", "cp -R repo tester-3",
                "rsync -a repo/ tester-4/", "git -C /r worktree add /w HEAD", "cp -r repo t5", "cp -rf repo t6",
                "cp -pr repo t7", "cp --recursive repo t8", "cp --archive repo t9", "rsync -r src/ dst/",
                "rsync --archive src/ dst/", "rsync -e ssh -a src/ dst/", "cd x && sudo cp -a repo t10", "ditto a b"]

LOCAL = [
    "ssh devbox 'cd x' && git clone a b",
    "ssh devbox cd x && git clone a b",
    "ssh devbox 'true'; cp -a repo copy",
    'ssh devbox "echo $(git clone a b)"',
    'ssh devbox "echo `git clone a b`"',
    "ssh devbox echo $(git clone a b)",
    "ssh -o 'ProxyCommand=x; git clone a b' devbox true",
    "ssh devbox bash -s <<'EOF'\ncd x && git clone a b\nEOF",
    "ssh devbox 'cd x && git clone a b",
    "bash -c 'cd x && git clone a b'",
    # F1 (round 1): a comment holding an apostrophe on the ssh line, or an ANSI-C word with an escaped quote, must
    # not join the next lines into the quoted ssh payload; bash runs those lines here. 1330c1a allowed the first
    # five below the floor.
    "ssh devbox 'cd ~/w && git clone u d'   # remote, doesn't touch this disk\n"
    "git clone u ~/local-copy               # here's the local one",
    "ssh devbox 'x' # it's\ngit clone u d\n# that's",
    "ssh devbox 'cd x && git status' # it's remote\ncp -a repo copy\n# done, that's all",
    "ssh devbox echo $'don\\'t'\ngit clone u d\n# that's all",
    "ssh devbox echo $'don\\'t'\ncp -a repo copy\necho 'that'\\''s all'",
    "ssh devbox 'cd ~/w && git clone u d'   # remote; doesn't touch this disk\n"
    "git clone u ~/local-copy               # here's the local one",
    "ssh devbox $'a\\'b' true\ngit clone u d\necho $'c\\'d'",
    # An ssh shell_words cannot clear (a config file or a local-command option) gets the base reading.
    "ssh -F cfg devbox 'cd x && git clone a b'",
    "ssh -o LocalCommand=x devbox 'cd x; git clone a b'",
    "bash -c 'ssh devbox \"x\" && git clone a b'",
    # An option word built at run time can carry -oProxyCommand=..., which runs here.
    "ssh $OPTS devbox 'cd x && git clone a b'",
    "ssh \"$OPTS\" devbox 'cd x; git clone a b'",
    "ssh ${SSH_ARGS} devbox 'cd x && cp -a r s'",
    "ssh -o* devbox 'cd x && git clone a b'",
]

# Wrapper options used to hide the copy entirely (the wrapper word was dropped, its value read as the command).
WRAPPED = ["timeout 120 git clone u d", "timeout -s KILL 5m git clone u d", "nice -n 5 cp -r repo t", "sudo -u ops git clone u d",
           "bash -c 'git clone u d'", "sh -c \"timeout 60 git clone u d\""]

PAYLOAD = "'cd x && git clone a b'"

# Round 2 (review of f54937a). f54937a allowed each line below under the floor.
ROUND2_LOCAL = [
    # F1: an expansion in an ssh word that ssh may read as an option: after `-` or `-o`, after empty quotes, or
    # after the host (OpenSSH parses options there too, up to the first word that is not one). The reviewer's three
    # lines come first.
    "ssh -o\"$X\" devbox " + PAYLOAD,
    "ssh \"-$X\" devbox " + PAYLOAD,
    "ssh devbox \"-$X\" " + PAYLOAD,
    "ssh ''\"$X\" devbox " + PAYLOAD,
    "ssh \"\"$X devbox " + PAYLOAD,
    "ssh -v devbox ''\"$X\" " + PAYLOAD,
    "ssh devbox -o\"$X\" " + PAYLOAD,
    # Words the shell builds from a tilde or a glob, and options that load local code or config.
    "ssh -i ~/.ssh/k devbox " + PAYLOAD,
    "ssh devbox ~/x " + PAYLOAD,
    "ssh -o 'Include cfg' devbox " + PAYLOAD,
    "ssh -oMatch=all devbox " + PAYLOAD,
    "ssh -I lib.so devbox " + PAYLOAD,
    # F3: env -S hides a local command in front of the ssh, in every spelling GNU env accepts.
    "env -S 'cp -a repo copy #' ssh devbox x",
    "env -iS'cp -a repo copy #' ssh devbox x",
    "env --split-string='git clone u d' ssh devbox x",
    "env --s 'git clone u d' ssh devbox x",
    "sudo env -S 'git clone u d' ssh devbox x",
    # F4: something on the line defines or redirects `ssh`, or runs text as code.
    "eval 'ssh(){ cp -a r c; }'; ssh h x",
    "alias ssh='cp -a r c'\nssh h x",
    "eval 'git clone a b'",
    "trap 'git clone a b' EXIT; ssh h x",
    "functions[ssh]='cp -a r c'; ssh h x",
    "aliases[ssh]='git clone a b'\nssh h x",
    ". ./defs.sh; ssh devbox " + PAYLOAD,
    "source defs.sh; ssh devbox " + PAYLOAD,
    "hash -p ./x ssh; ssh devbox " + PAYLOAD,
    "export PATH=./bin:$PATH; ssh devbox " + PAYLOAD,
    "PATH=./bin; ssh devbox " + PAYLOAD,
    "LD_PRELOAD=./x.so ssh devbox " + PAYLOAD,
    "env A=1 ssh devbox " + PAYLOAD,
    "./ssh devbox " + PAYLOAD,
    "bin/ssh devbox " + PAYLOAD,
    "$SSH devbox " + PAYLOAD,
    "set -o vi; ssh devbox " + PAYLOAD,
    # Quoted text a command other than ssh runs here. The base reading refused these; f54937a read the quoted word
    # whole for every verified command.
    "watch " + PAYLOAD,
    "su -c " + PAYLOAD,
    "flock /tmp/l -c 'cd x; cp -a r s'",
    "xargs -I{} sh -c " + PAYLOAD,
    "bash -c '$1' _ " + PAYLOAD,
]

# Lines that stay refused, as on the base, when they run below the floor.
ROUND2_STILL_LOCAL = [
    "PATH=./bin:$PATH ssh devbox " + PAYLOAD,
    "ssh devbox * " + PAYLOAD,
    "bash -c \"ssh devbox " + PAYLOAD + " $X\"",
]

# Positive controls: real remote shapes that the round-2 rule still drops.
ROUND2_REMOTE = [
    "ssh -o BatchMode=yes -o ConnectTimeout=5 devbox " + PAYLOAD,
    "ssh -p 2222 -l ops -tt devbox " + PAYLOAD,
    "ssh devbox -o BatchMode=yes " + PAYLOAD,
    "/usr/bin/ssh devbox " + PAYLOAD,
    "timeout 120 ssh -q devbox " + PAYLOAD,
    "set -euo pipefail; ssh devbox " + PAYLOAD,
    "ssh devbox " + PAYLOAD + " \"$X\"",
    "ssh devbox \"cd $T && git clone a b\"",
    "ssh devbox x\"$X\" " + PAYLOAD,
    "cd /w && ssh devbox " + PAYLOAD,
    "echo start; ssh devbox 'cd x && cp -a r s'; echo done",
    "bash -c 'ssh devbox \"cd x && git clone a b\"' _ ok",
    # PR 334 review F1 control: a double-quoted harmless keyword stays remote.
    "ssh -o '\"BatchMode\" yes' devbox " + PAYLOAD,
]

# PR 334 review F1: OpenSSH strips double quotes from a -o keyword (OpenSSH 9.6 `ssh -F /dev/null -G` on t2-dev
# printed `pkcs11provider /nonexistent/x.so` for the first line), so these load a local library. 39f0735e allowed
# each of them below the floor.
QUOTED_KEYWORD_LOCAL = [
    "ssh -o '\"PKCS11Provider\" ./x.so' devbox " + PAYLOAD,
    "ssh -o '\"SecurityKeyProvider\"=./x.so' devbox " + PAYLOAD,
    "ssh -o ' \"pkcs11provider\"   ./x.so' devbox " + PAYLOAD,
    "ssh devbox -o '\"PKCS11Provider\" ./x.so' " + PAYLOAD,
]


def option_word_shapes():
    """[(line, position, remote)] for an ssh word built at run time in every shape. The word holds an expansion
    ($X, ${X}) or a glob (*) at its start, middle or end. It is unquoted, wholly double-quoted, or has only the
    expansion double-quoted. It sits before the host, as an -o value, as the first word after the host, or after
    the remote command has started.

    `remote` is the expected reading, written independently of the code. Only a word after the command start, or a
    first word after the host whose first character is literal text other than `-`, leaves the ssh remote-only."""
    out = []
    for prefix in ("", "-", "-o", "''", '""', "x"):
        # `.x`, not `x`: shell_words reads a letter right after `${X}` as unverified (the strict reading), and this
        # table is meant to test the ssh rule on verified lines.
        for suffix in ("", ".x", "=yes"):
            for expansion in ("$X", "${X}", "*"):
                for mode in ("bare", "whole", "inner"):
                    if expansion == "*" and mode != "bare":
                        continue  # a quoted * is literal text
                    if mode == "bare":
                        word = prefix + expansion + suffix
                    elif mode == "whole":
                        word = '"' + prefix + expansion + suffix + '"'
                    else:
                        word = prefix + '"' + expansion + '"' + suffix
                    # In "whole" mode the '' is literal text inside the double quotes.
                    first_is_literal = prefix == "x" or (mode == "whole" and prefix == "''")
                    for position, line in (("before-host", "ssh %s devbox %s" % (word, PAYLOAD)),
                                           ("o-value", "ssh -o %s devbox %s" % (word, PAYLOAD)),
                                           ("after-host", "ssh devbox %s %s" % (word, PAYLOAD)),
                                           ("in-command", "ssh devbox %s %s" % (PAYLOAD, word))):
                        remote = position == "in-command" or (position == "after-host" and first_is_literal)
                        out.append((line, position, remote))
    return out


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


class SshCopyFloor(BelowTheFloor):
    def test_a_copy_inside_an_ssh_remote_command_is_not_charged_here(self):
        for command in REMOTE:
            with self.subTest(command=command):
                self.assertEqual(self.pretool(command), (0, ""))

    def test_local_commands_and_local_substitutions_around_an_ssh_are_still_refused(self):
        for command in LOCAL:
            with self.subTest(command=command):
                code, err = self.pretool(command)
                self.assertEqual(code, 2)
                self.assertIn("DISK LOW", err)

    def test_every_base_refused_form_is_still_refused_alone_and_after_an_ssh(self):
        for local in BASE_REFUSED:
            for command in (local, "ssh devbox 'cd x && git status' && " + local,
                            "ssh devbox \"ls\"; " + local, local + " && ssh devbox 'git clone a b'"):
                with self.subTest(command=command):
                    self.assertEqual(self.pretool(command)[0], 2)

    def test_wrapper_options_no_longer_hide_a_copy(self):
        for command in WRAPPED:
            with self.subTest(command=command):
                self.assertEqual(self.pretool(command)[0], 2)

    def test_the_other_guards_still_read_the_ssh_payload(self):
        # Only the copy check changed: simple_commands still splits inside quotes for the delete and /dev/shm checks.
        words = tc.simple_commands("ssh devbox 'cd x && git clone a b'")
        self.assertIn(["git", "clone", "a", "b'"], words)
        self.assertTrue(tc.writes_into_shm("ssh devbox 'cd x && cp f /dev/shm/f'"))

    def assert_refused(self, command):
        code, err = self.pretool(command)
        self.assertEqual(code, 2, command)
        self.assertIn("DISK LOW", err)

    def test_round2_option_words_hidden_commands_and_redefinitions_are_refused(self):
        # Must fail on f54937a: it allowed every line below.
        for command in ROUND2_LOCAL:
            with self.subTest(command=command):
                self.assert_refused(command)

    def test_a_double_quoted_local_library_keyword_is_refused(self):
        # Must fail on 39f0735e (PR 334 review F1).
        for command in QUOTED_KEYWORD_LOCAL:
            with self.subTest(command=command):
                self.assert_refused(command)

    def test_round2_neighbours_the_base_refused_stay_refused(self):
        for command in ROUND2_STILL_LOCAL:
            with self.subTest(command=command):
                self.assert_refused(command)

    def test_round2_plain_remote_shapes_are_still_not_charged_here(self):
        # Positive control for the two tests above.
        for command in ROUND2_REMOTE:
            with self.subTest(command=command):
                self.assertEqual(self.pretool(command), (0, ""))


class GeneratedOptionWords(BelowTheFloor):
    """Round 2: every shape of an ssh word built at run time gets its expected reading. Adding a new shape to the
    generator cannot be missed one at a time: the reading comes from the word's position and first character."""

    def test_every_generated_shape_gets_the_expected_reading(self):
        shapes = option_word_shapes()
        self.assertGreaterEqual(len(shapes), 400)
        self.assertGreaterEqual(sum(1 for _, _, remote in shapes if remote), 100)  # both outcomes are exercised
        for line, position, remote in shapes:
            with self.subTest(line=line, position=position):
                code, err = self.pretool(line)
                if remote:
                    self.assertEqual((code, err), (0, ""))
                else:
                    self.assertEqual(code, 2)
                    self.assertIn("DISK LOW", err)


class NeverLooserThanTheBaseReading(BelowTheFloor):
    """Guard test: a line whose base reading (_legacy_copy_commands) finds a copy is refused, unless it is one of
    the listed remote shapes whose copies sit inside a plain ssh payload."""

    def test_only_listed_remote_shapes_escape_the_base_reading(self):
        shapes = option_word_shapes()
        remote_ok = set(REMOTE + ROUND2_REMOTE + [line for line, _, remote in shapes if remote])
        corpus = (LOCAL + ROUND2_LOCAL + ROUND2_STILL_LOCAL + WRAPPED + BASE_REFUSED + REMOTE + ROUND2_REMOTE
                  + QUOTED_KEYWORD_LOCAL + [line for line, _, _ in shapes]
                  + ["ssh devbox 'cd x && git status' && " + local for local in BASE_REFUSED])
        checked = 0
        for line in corpus:
            if not any(tc.is_copy_command(words) for words in tc._legacy_copy_commands(line, 0)):
                continue
            checked += 1
            if self.pretool(line)[0] == 0:
                with self.subTest(line=line):
                    self.assertIn(line, remote_ok, "allowed below the floor, but the base reading finds a copy")
        self.assertGreaterEqual(checked, 400)


class RealSshOracle(BelowTheFloor):
    """The guard's own verdicts checked against real shells and the real ssh.

    Each generated line is run with `ssh -F /dev/null -G`, which parses the options and prints the configuration
    without connecting or running anything. X is set to an injected option, in a directory holding a file named like
    one, under bash and zsh (whichever are installed). A line the guard allows below the floor (it dropped the ssh as
    remote-only) must never show the injected ProxyCommand. The lines it refuses must show it often enough to prove
    the oracle can see one."""

    INJECTIONS = ("-oProxyCommand=PCX", " -oProxyCommand=PCX", "oProxyCommand=PCX", "ProxyCommand=PCX")

    def run_lines(self, shell, cwd, injection, lines):
        script = ["X=" + shlex.quote(injection)]
        for index, line in enumerate(lines):
            assert line.startswith("ssh ")
            script.append("%s 2>/dev/null | grep -qi '^proxycommand pcx' && echo HIT %d" % (
                "ssh -F /dev/null -G " + line[len("ssh "):], index))
        argv = [shell, "--norc", "--noprofile", "-s"] if os.path.basename(shell) == "bash" else [shell, "-f", "-s"]
        result = subprocess.run(argv, input="\n".join(script) + "\n", capture_output=True, text=True, cwd=cwd,
                                env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": cwd}, timeout=300)
        return {int(line.split()[1]) for line in result.stdout.splitlines() if line.startswith("HIT ")}

    def unavailable(self, why):
        """Skip on a developer host. Under CI the independent oracle is the real proof for the remote lines, so its
        absence fails instead of passing quietly (PR 334 review F2)."""
        if os.environ.get("CI", "").strip().lower() not in ("", "0", "false", "no"):
            self.fail("the real-ssh oracle cannot run under CI: " + why)
        self.skipTest(why)

    def test_no_line_the_guard_drops_can_carry_a_local_proxycommand(self):
        shells = [path for path in (shutil.which("bash"), shutil.which("zsh")) if path]
        if not shutil.which("ssh") or not shells:
            self.unavailable("needs ssh and bash or zsh")
        lines = [line for line, _, _ in option_word_shapes()]
        remote = [line for line in lines if self.pretool(line)[0] == 0]  # the guard's verdict, not the table's
        strict = [line for line in lines if line not in remote][::3]
        self.assertGreaterEqual(len(remote), 100)
        caught = set()
        with tempfile.TemporaryDirectory() as cwd:
            Path(cwd, "-oProxyCommand=PCX").touch()
            for shell in shells:
                for injection in self.INJECTIONS:
                    hits = self.run_lines(shell, cwd, injection, remote + strict)
                    leaked = sorted(remote[index] for index in hits if index < len(remote))
                    self.assertEqual(leaked, [], (shell, repr(injection)))
                    caught.update(index - len(remote) for index in hits if index >= len(remote))
        self.assertGreaterEqual(len(caught), 20, "the oracle must see the injected ProxyCommand on strict lines")



class OracleCannotSkipUnderCI(unittest.TestCase):
    """PR 334 review F2: without ssh the oracle skips on a developer host and fails under CI."""

    def run_oracle(self, ci):
        case = RealSshOracle("test_no_line_the_guard_drops_can_carry_a_local_proxycommand")
        result = unittest.TestResult()
        with mock.patch.object(shutil, "which", return_value=None), mock.patch.dict(os.environ):
            os.environ.pop("CI", None)
            if ci is not None:
                os.environ["CI"] = ci
            case.run(result)
        return len(result.failures), len(result.skipped)

    def test_ci_without_ssh_fails(self):
        # Must fail on 39f0735e: the oracle skipped.
        self.assertEqual(self.run_oracle("true"), (1, 0))

    def test_a_developer_host_without_ssh_still_skips(self):
        # Positive control.
        self.assertEqual(self.run_oracle(None), (0, 1))
        self.assertEqual(self.run_oracle("false"), (0, 1))


if __name__ == "__main__":
    unittest.main()
