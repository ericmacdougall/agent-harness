"""goodqa#16811: the disk-floor copy check does not charge a copy inside an ssh's quoted remote command to this machine,
and still refuses every local copy below the floor.

The allowed commands are genericized from real refused runs (a clone or `cp -a` sent to a build host over ssh while
the workstation sat at its floor): no host, project, path or session from those runs appears here.
"""
import os
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


class SshCopyFloor(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
