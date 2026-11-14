"""Behaviour tests for the pinned Fabric DO auth script (GoodQA goodqa#15976; PR 248 receipt v1 F1-F3).

The fixture is byte-identical to the pinned file (test_guard_pinned_routes checks its digest against the table).

Nothing here contacts t2-dev or reads a real secret. The remote part of the script is extracted and run locally under a
temporary HOME, with a fake secret tool in place of the real one. The PATH test runs the whole local script against an
unresolvable host, so the real ssh can only fail. SCRIPT=<path> selects the script under test (default: the pinned one);
pointing it at the v1 copy shows these tests failing first.
"""

import os
import re
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPT = Path(os.environ.get('SCRIPT') or HERE / 'fixtures' / 'pinned_routes' / 'doctl-auth-fabric.sh')
TOKEN = 'dop_v1_' + 'ab' * 32
OLD = 'access-token: dop_v1_' + 'cd' * 32 + '\n'


def remote_body(text):
    """The commands the script runs on t2-dev, for either the v2 heredoc form or the v1 quoted-string form."""
    m = re.search(r"<<'REMOTE'\n(.*?)\nREMOTE\n", text, re.S)
    if m:
        return m.group(1)
    m = re.search(r"t2-dev '(.*?)' </dev/null", text, re.S)
    if m:
        return m.group(1)
    raise AssertionError('no remote body found')


class Base(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name).resolve()
        self.home = self.root / 'home'
        self.home.mkdir()
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        self.text = SCRIPT.read_text()
        self.dir = self.home / '.config' / 'doctl'
        self.conf = self.dir / 'fabric.yaml'

    def fake(self, body):
        tool = self.bin / 'gcloud'
        tool.write_text('#!/bin/sh\n' + body + '\n')
        tool.chmod(0o755)
        return tool

    def run_remote(self, fake_body):
        tool = self.fake(fake_body)
        body = remote_body(self.text).replace('/usr/bin/gcloud', str(tool))
        env = {'HOME': str(self.home), 'PATH': '%s:/usr/bin:/bin' % self.bin}
        return subprocess.run(['/bin/bash', '-c', body], env=env, stdin=subprocess.DEVNULL,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30).returncode

    def old_config(self, mode=0o600):
        self.dir.mkdir(parents=True, exist_ok=True)
        self.conf.write_text(OLD)
        self.conf.chmod(mode)

    def leftovers(self):
        return sorted(p.name for p in self.dir.iterdir() if p.name != 'fabric.yaml') if self.dir.exists() else []


class RemoteTests(Base):
    def test_success_publishes_a_private_config(self):
        self.assertEqual(self.run_remote('printf %s ' + TOKEN), 0)
        self.assertEqual(self.conf.read_text(), 'access-token: ' + TOKEN + '\n')
        self.assertEqual(stat.S_IMODE(self.conf.stat().st_mode), 0o600)
        self.assertEqual(self.leftovers(), [])

    def test_success_replaces_an_existing_world_readable_file_with_a_0600_one(self):
        self.old_config(0o644)
        self.assertEqual(self.run_remote('printf %s ' + TOKEN), 0)
        self.assertEqual(self.conf.read_text(), 'access-token: ' + TOKEN + '\n')
        self.assertEqual(stat.S_IMODE(self.conf.stat().st_mode), 0o600)

    def test_symlink_destination_is_refused_and_its_target_kept(self):
        self.dir.mkdir(parents=True)
        victim = self.root / 'victim'
        victim.write_text('keep\n')
        self.conf.symlink_to(victim)
        self.assertEqual(self.run_remote('printf %s ' + TOKEN), 4)
        self.assertTrue(self.conf.is_symlink())
        self.assertEqual(victim.read_text(), 'keep\n')
        self.assertEqual(self.leftovers(), [])

    def test_failure_without_output_keeps_the_previous_config(self):
        self.old_config()
        self.assertEqual(self.run_remote('exit 1'), 6)
        self.assertEqual(self.conf.read_text(), OLD)
        self.assertEqual(self.leftovers(), [])

    def test_failure_after_partial_output_keeps_the_previous_config(self):
        self.old_config()
        self.assertEqual(self.run_remote('printf %s ' + TOKEN + '; exit 1'), 6)
        self.assertEqual(self.conf.read_text(), OLD)
        self.assertEqual(self.leftovers(), [])

    def test_malformed_values_are_refused_with_their_class(self):
        rows = (('printf %s short', 7), ("printf '%s' " + 'a' * 513, 7),
                ("printf '%s\\n%s' " + TOKEN + ' ' + TOKEN, 9),
                ("printf '%s' 'dop_v1_ab cd" + 'e' * 40 + "'", 8), ("printf '%s' 'dop_v1_" + 'e' * 40 + "$x'", 8),
                ('true', 5), ("printf '\\n \\r\\n'", 5))
        for out, code in rows:
            with self.subTest(out=out):
                self.old_config()
                self.assertEqual(self.run_remote(out), code)
                self.assertEqual(self.conf.read_text(), OLD)
                self.assertEqual(self.leftovers(), [])

    def test_trailing_whitespace_and_blank_lines_are_ignored(self):
        for out in ("printf '%s\\r\\n' " + TOKEN, "printf '%s  \\n\\n\\n' " + TOKEN, "printf '%s\\t' " + TOKEN):
            with self.subTest(out=out):
                self.old_config()
                self.assertEqual(self.run_remote(out), 0)
                self.assertEqual(self.conf.read_text(), 'access-token: ' + TOKEN + '\n')
                self.assertEqual(stat.S_IMODE(self.conf.stat().st_mode), 0o600)

    def test_the_exit_status_never_carries_the_value(self):
        # Only the documented class codes can come back; a value byte cannot become the status.
        for out in ('printf %s ' + TOKEN, 'printf %s short', 'exit 1', 'true'):
            with self.subTest(out=out):
                self.assertIn(self.run_remote(out), (0, 5, 6, 7, 8, 9))


class LocalTests(Base):
    def copy_against_no_host(self):
        copy = self.root / 'copy.sh'
        copy.write_text(self.text.replace('t2-dev', 'fabric-route-test.invalid'))
        copy.chmod(0o700)
        return copy

    def test_an_inherited_hostile_path_cannot_intercept_ssh(self):
        marker = self.root / 'intercepted'
        for name in ('ssh', 'bash', 'sh', 'env'):
            shim = self.bin / name
            shim.write_text('#!/bin/sh\ntouch %s\nexit 0\n' % marker)
            shim.chmod(0o755)
        env = {'HOME': str(self.home), 'PATH': str(self.bin)}
        rc = subprocess.run(['/bin/bash', '-p', str(self.copy_against_no_host())], env=env, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60).returncode
        self.assertFalse(marker.exists(), 'a PATH shim ran')
        self.assertNotEqual(rc, 0)

    def test_arguments_are_refused(self):
        rc = subprocess.run(['/bin/bash', '-p', str(self.copy_against_no_host()), 'x'], env={'PATH': '/usr/bin:/bin'},
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30).returncode
        self.assertEqual(rc, 2)


if __name__ == '__main__':
    unittest.main()
