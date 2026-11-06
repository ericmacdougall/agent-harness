"""The gate's audit hook records writes into protected dirs under every child launch style (GoodQA #14560).

A throwaway virtualenv loads hermetic_audit_hook through a .pth file with its configuration in a JSON file, which is
how hermetic_check.sh runs the suite; a temp dir stands in for the real protected state dir.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HOOK = Path(__file__).resolve().parent / 'hermetic_audit' / 'hermetic_audit_hook.py'


def build_venv(root, protected, log):
    venv = Path(root, 'venv')
    subprocess.run([sys.executable, '-m', 'venv', '--without-pip', str(venv)], check=True, timeout=120,
                   capture_output=True)
    site = next(Path(venv, 'lib').glob('python*/site-packages'))
    shutil.copy(HOOK, site / 'hermetic_audit_hook.py')
    (site / 'hermetic_audit_config.json').write_text(json.dumps({'log': str(log), 'protect': [str(protected)], 'allow': []}))
    (site / 'hermetic_audit.pth').write_text('import hermetic_audit_hook\n')
    return venv / 'bin' / 'python'


class AuditHookLaunchStyles(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.mkdtemp(prefix='audit-hook-')
        cls.protected = os.path.realpath(os.path.join(cls.temp, 'protected'))
        os.mkdir(cls.protected)
        cls.log = os.path.join(cls.temp, 'audit.log')
        cls.python = str(build_venv(cls.temp, cls.protected, cls.log))

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.temp, ignore_errors=True)

    def setUp(self):
        if os.path.exists(self.log):
            os.unlink(self.log)
        for name in os.listdir(self.protected):
            path = os.path.join(self.protected, name)
            shutil.rmtree(path) if os.path.isdir(path) else os.unlink(path)

    def recorded(self):
        return Path(self.log).read_text() if os.path.exists(self.log) else ''

    def run_code(self, code, *, flags=(), env=None):
        subprocess.run([self.python, *flags, '-c', code.replace('PROT', repr(self.protected))],
                       env=os.environ.copy() if env is None else env, check=True, timeout=60)

    def test_loaded_marker_reports_the_protected_count(self):
        self.run_code('pass')
        self.assertIn('protected=1', Path(self.log + '.loaded').read_text())

    def test_swallowed_open_is_recorded(self):
        self.run_code("import os\ntry:\n    open(os.path.join(PROT,'x'),'w').write('1')\nexcept OSError:\n    pass\n")
        self.assertIn('open', self.recorded())

    def test_isolated_mode_is_recorded(self):
        self.run_code("import os\nopen(os.path.join(PROT,'x'),'w')\n", flags=('-I',))
        self.assertIn('open', self.recorded())

    def test_empty_environment_child_is_recorded(self):
        self.run_code("import os\nopen(os.path.join(PROT,'x'),'w')\n", env={})
        self.assertIn('open', self.recorded())

    def test_replaced_pythonpath_child_is_recorded(self):
        self.run_code("import os\nopen(os.path.join(PROT,'x'),'w')\n", env={'PYTHONPATH': '/nonexistent-elsewhere'})
        self.assertIn('open', self.recorded())

    def test_grandchild_with_an_empty_environment_is_recorded(self):
        code = ("import os,subprocess,sys\nsubprocess.run([sys.executable,'-c',"
                "\"import os\\nopen(os.path.join(%r,'x'),'w')\"],env={})\n" % self.protected)
        self.run_code(code)
        self.assertIn('open', self.recorded())

    def test_mkdir_and_rename_are_recorded(self):
        self.run_code("import os\nos.mkdir(os.path.join(PROT,'d'))\nos.rename(os.path.join(PROT,'d'), os.path.join(PROT,'e'))\n")
        found = self.recorded()
        self.assertIn('os.mkdir', found)
        self.assertIn('os.rename', found)

    def test_dir_fd_relative_writes_are_recorded(self):
        self.run_code("import os\nfd=os.open(PROT, os.O_RDONLY|os.O_DIRECTORY)\n"
                      "os.mkdir('sub', 0o700, dir_fd=fd)\nos.rename('sub','sub2', src_dir_fd=fd, dst_dir_fd=fd)\n"
                      "g=os.open('f', os.O_WRONLY|os.O_CREAT, 0o600, dir_fd=fd)\nos.close(g)\nos.close(fd)\n")
        found = self.recorded()
        self.assertIn('opendir', found)
        self.assertIn('os.mkdir', found)
        self.assertIn('(dir_fd)', found)

    def _fake_reviewer(self, directory):
        os.makedirs(directory, exist_ok=True)
        path = os.path.join(directory, 'codex')
        with open(path, 'w') as handle:
            handle.write('#!/bin/sh\nexit 0\n')
        os.chmod(path, 0o755)
        return path

    def test_reviewer_cli_outside_the_temp_root_is_recorded(self):
        outside = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.audit-fake-bin-%d' % os.getpid())
        self.addCleanup(shutil.rmtree, outside, True)
        fake = self._fake_reviewer(outside)
        self.run_code("import subprocess\nsubprocess.run([%r])\n" % fake)
        self.assertIn('reviewer-launch', self.recorded())

    def test_bare_reviewer_name_resolved_through_path_is_recorded(self):
        outside = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.audit-fake-bin2-%d' % os.getpid())
        self.addCleanup(shutil.rmtree, outside, True)
        self._fake_reviewer(outside)
        env = dict(os.environ, PATH=outside + os.pathsep + os.environ.get('PATH', ''))
        self.run_code("import subprocess\nsubprocess.run(['codex'])\n", env=env)
        self.assertIn('reviewer-launch', self.recorded())

    def test_bare_reviewer_name_no_path_entry_resolves_is_not_recorded(self):
        # install.py asks `claude --version`; with no claude on PATH nothing starts, so nothing may be recorded
        # (GoodQA #14553: the gate reported 12 phantom launches against <tree>/claude).
        self.run_code("import subprocess\ntry:\n    subprocess.run(['claude', '--version'])\nexcept OSError:\n    pass\n",
                      env={'PATH': '/nonexistent-bin'})
        self.assertEqual(self.recorded(), '')

    def test_fixture_reviewer_under_the_temp_root_is_not_recorded(self):
        with tempfile.TemporaryDirectory() as temp:
            fake = self._fake_reviewer(temp)
            self.run_code("import subprocess\nsubprocess.run([%r])\n" % fake)
        self.assertEqual(self.recorded(), '')

    def test_reads_and_unprotected_writes_are_not_recorded(self):
        self.run_code("import os,tempfile\nos.listdir(PROT)\nt=tempfile.mkdtemp()\nopen(os.path.join(t,'a'),'w').write('1')\n"
                      "import shutil\nshutil.rmtree(t)\n")
        self.assertEqual(self.recorded(), '')


if __name__ == '__main__':
    unittest.main()
