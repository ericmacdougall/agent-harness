"""Disposable CLI checks for scratch merge delivery and its recovery artifacts."""

import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path


INTEGRATE = Path(__file__).resolve().parents[1] / 'harness/hooks/integrate_local.py'
CHECK = 'python3 -m unittest discover -s tests'


def command(*argv, cwd=None, env=None, check=True):
    result = subprocess.run(argv, cwd=cwd, env=env, text=True, capture_output=True, timeout=90)
    if check and result.returncode:
        raise AssertionError((argv, result.stdout, result.stderr))
    return result


class ScratchRecovery(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='harness-scratch-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        tempdir_override = patch.object(tempfile, 'tempdir', str(self.root))
        tempdir_override.start()
        self.addCleanup(tempdir_override.stop)
        home = self.root / 'home'
        home.mkdir()
        self.env = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
        self.env.update(HOME=str(home), TMPDIR=str(self.root), GIT_CONFIG_GLOBAL=os.devnull,
                        GIT_CONFIG_NOSYSTEM='1', PYTHONDONTWRITEBYTECODE='1')
        self.original = self.root / 'original'
        command('git', 'init', '-q', '-b', 'main', str(self.original), env=self.env)
        command('git', 'config', 'user.name', 'Harness Test', cwd=self.original, env=self.env)
        command('git', 'config', 'user.email', 'test@example.invalid', cwd=self.original, env=self.env)
        (self.original / 'app.txt').write_text('base\n')
        tests = self.original / 'tests'
        tests.mkdir()
        (tests / 'test_ok.py').write_text(
            'import unittest\nfrom pathlib import Path\n'
            'class Check(unittest.TestCase):\n'
            '    def test_app_exists(self):\n'
            '        self.assertTrue(Path("app.txt").is_file())\n')
        command('git', 'add', 'app.txt', 'tests', cwd=self.original, env=self.env)
        command('git', 'commit', '-qm', 'base', cwd=self.original, env=self.env)
        self.base = self.head(self.original)
        self.feature = self.root / 'feature'
        command('git', 'worktree', 'add', '-qb', 'feat/recovery', str(self.feature),
                cwd=self.original, env=self.env)
        (self.feature / 'app.txt').write_text('feature\n')
        command('git', 'commit', '-qam', 'feature', cwd=self.feature, env=self.env)
        self.feature_head = self.head(self.feature)

    def head(self, repo):
        return command('git', 'rev-parse', 'HEAD', cwd=repo, env=self.env).stdout.strip()

    def invoke(self, *, env=None):
        result = command(sys.executable, str(INTEGRATE), '--repo', str(self.original),
                         '--original-branch', 'main', '--expected-head', self.base,
                         '--source', 'feat/recovery', '--expected-source-head', self.feature_head,
                         '--check', CHECK, env=self.env if env is None else env, check=False)
        self.assertTrue(result.stdout, result.stderr)
        return result, json.loads(result.stdout)

    def test_custom_driver_checks_actual_scratch_merge_tree(self):
        # Without the custom driver, these two changes conflict. Its output is
        # neither parent's blob, so a predicted default merge tree is wrong.
        baseline = self.root / 'base.txt'
        baseline.write_text('base\n')
        (self.original / 'app.txt').write_text('main\n')
        prediction = command('git', 'merge-file', '-p', str(self.original / 'app.txt'),
                             str(baseline), str(self.feature / 'app.txt'), env=self.env,
                             check=False)
        self.assertEqual(prediction.returncode, 1, prediction.stdout + prediction.stderr)
        self.assertIn('<<<<<<<', prediction.stdout)
        (self.original / '.gitattributes').write_text('app.txt merge=fixture\n')
        command('git', 'add', 'app.txt', '.gitattributes', cwd=self.original, env=self.env)
        command('git', 'commit', '-qm', 'main change and merge policy',
                cwd=self.original, env=self.env)
        self.base = self.head(self.original)
        marker = self.root / 'driver-observation.json'
        driver = self.root / 'driver.py'
        driver.write_text(
            'import json, os, subprocess, sys\nfrom pathlib import Path\n'
            f'original=Path({str(self.original)!r})\n'
            f'marker=Path({str(marker)!r})\n'
            f'real_git={shutil.which("git")!r}\n'
            'clean_env={k:v for k,v in os.environ.items() if not k.startswith("GIT_")}\n'
            'head=subprocess.check_output([real_git,"-C",str(original),"rev-parse","HEAD"], '
            'env=clean_env, text=True).strip()\n'
            'marker.write_text(json.dumps({"cwd":str(Path.cwd()),'
            '"original_head":head,"original_content":(original/"app.txt").read_text()}))\n'
            'if Path.cwd().resolve()==original.resolve(): sys.exit(77)\n'
            'Path(sys.argv[2]).write_text("merged by driver\\n")\n')
        command('git', 'config', 'merge.fixture.driver',
                f'{shlex.quote(sys.executable)} {shlex.quote(str(driver))} %O %A %B',
                cwd=self.original, env=self.env)

        result, data = self.invoke()
        self.assertEqual((result.returncode, data['status']), (0, 'INTEGRATED'),
                         result.stdout + result.stderr)
        observed = json.loads(marker.read_text())
        self.assertNotEqual(Path(observed['cwd']), self.original)
        self.assertEqual(observed['original_head'], self.base)
        self.assertEqual(observed['original_content'], 'main\n')
        self.assertEqual((self.original / 'app.txt').read_text(), 'merged by driver\n')
        self.assertEqual(self.head(self.original), data['head'])
        self.assertEqual(command('git', 'status', '--porcelain', cwd=self.original,
                                 env=self.env).stdout, '')

    def test_success_keeps_ignored_scratch_artifact_and_journal(self):
        (self.feature / '.gitignore').write_text('scratch-result.tmp\n')
        (self.feature / 'tests' / 'test_ok.py').write_text(
            'import unittest\nfrom pathlib import Path\n'
            f'original=Path({str(self.original)!r})\n'
            'class Check(unittest.TestCase):\n'
            '    def test_artifact(self):\n'
            '        self.assertTrue(Path("app.txt").is_file())\n'
            '        if Path.cwd().resolve()!=original.resolve():\n'
            '            Path("scratch-result.tmp").write_text("retain this ignored result\\n")\n')
        command('git', 'add', '.gitignore', 'tests/test_ok.py', cwd=self.feature, env=self.env)
        command('git', 'commit', '-qm', 'test scratch artifact', cwd=self.feature, env=self.env)
        self.feature_head = self.head(self.feature)

        result, data = self.invoke()
        self.assertEqual((result.returncode, data['status']), (0, 'INTEGRATED'),
                         result.stdout + result.stderr)
        self.assertTrue(data['cleanup_pending'])
        journal = Path(data['journal'])
        record = json.loads(journal.read_text())
        artifact = Path(record['scratch']) / 'scratch-result.tmp'
        self.assertEqual(artifact.read_text(), 'retain this ignored result\n')
        self.assertEqual(record['phase'], 'delivered')
        self.assertEqual(command('git', 'rev-parse', record['ref'], cwd=self.original,
                                 env=self.env).stdout.strip(), data['head'])
        self.assertFalse((self.original / 'scratch-result.tmp').exists())
        self.assertEqual(self.head(self.original), data['head'])

    def test_failed_candidate_ref_cleanup_reports_pending_after_delivery(self):
        bin_dir = self.root / 'bin'
        bin_dir.mkdir()
        marker = self.root / 'ref-delete-attempt'
        real_git = shutil.which('git')
        wrapper = bin_dir / 'git'
        wrapper.write_text(
            f'#!{sys.executable}\n'
            'import os, sys\nfrom pathlib import Path\n'
            f'original=Path({str(self.original)!r})\n'
            f'marker=Path({str(marker)!r})\n'
            f'real_git={real_git!r}\n'
            'args=sys.argv[1:]\n'
            'if len(args)==4 and args[:2]==["update-ref","-d"] '
            'and args[2].startswith("refs/agent-harness/delivery/") '
            'and Path.cwd().resolve()==original.resolve():\n'
            '    marker.write_text(args[2])\n'
            '    sys.exit(71)\n'
            'os.execv(real_git,[real_git,*args])\n')
        wrapper.chmod(0o700)
        env = {**self.env, 'PATH': str(bin_dir) + os.pathsep + self.env['PATH']}

        result, data = self.invoke(env=env)
        self.assertEqual((result.returncode, data['status']), (0, 'INTEGRATED'),
                         result.stdout + result.stderr)
        self.assertTrue(marker.is_file(), 'the candidate ref deletion was not faulted')
        self.assertTrue(data['cleanup_pending'], 'failed ref deletion was called complete')
        journal = Path(data['journal'])
        record = json.loads(journal.read_text())
        self.assertEqual(record['phase'], 'delivered')
        self.assertEqual(marker.read_text(), record['ref'])
        self.assertFalse(Path(record['scratch']).exists(), 'scratch removal did not precede ref deletion')
        self.assertEqual(command('git', 'rev-parse', record['ref'], cwd=self.original,
                                 env=self.env).stdout.strip(), data['head'])
        self.assertEqual(self.head(self.original), data['head'])
        self.assertEqual(command('git', 'status', '--porcelain', cwd=self.original,
                                 env=self.env).stdout, '')

    def test_helper_metadata_ref_cleanup_cannot_run_repo_hook_after_final_check(self):
        marker = self.root / 'ref-cleanup-hook-ran'
        hook = self.original / '.git' / 'hooks' / 'reference-transaction'
        hook.write_text(
            '#!/bin/sh\n'
            '[ "$1" = committed ] || exit 0\n'
            'while read old new ref; do\n'
            '  case "$ref" in\n'
            '    refs/agent-harness/delivery/*)\n'
            '      case "$new" in\n'
            '        *[!0]*) ;;\n'
            f'        *) printf "hook mutation\\n" > {shlex.quote(str(self.original / "app.txt"))}; '
            f'touch {shlex.quote(str(marker))} ;;\n'
            '      esac ;;\n'
            '  esac\n'
            'done\n')
        hook.chmod(0o700)

        result, data = self.invoke()
        self.assertEqual((result.returncode, data['status']), (0, 'INTEGRATED'),
                         result.stdout + result.stderr)
        self.assertFalse(marker.exists(), 'helper-owned ref deletion ran a repository hook')
        self.assertEqual((self.original / 'app.txt').read_text(), 'feature\n')
        self.assertEqual(command('git', 'status', '--porcelain', cwd=self.original,
                                 env=self.env).stdout, '')
        self.assertEqual(self.head(self.original), data['head'])

    def test_original_fast_forward_does_not_run_hook_that_deletes_ignored_user_data(self):
        (self.original / '.gitignore').write_text('cache.txt\n')
        command('git', 'add', '.gitignore', cwd=self.original, env=self.env)
        command('git', 'commit', '-qm', 'ignore local cache', cwd=self.original, env=self.env)
        self.base = self.head(self.original)
        cache = self.original / 'cache.txt'
        cache.write_text('user ignored data\n')
        marker = self.root / 'original-post-merge-ran'
        hook = self.original / '.git' / 'hooks' / 'post-merge'
        hook.write_text(
            '#!/bin/sh\n'
            f'if [ "$(pwd -P)" = {shlex.quote(str(self.original.resolve()))} ]; then\n'
            f'  rm -f -- {shlex.quote(str(cache))}\n'
            f'  touch {shlex.quote(str(marker))}\n'
            'fi\n')
        hook.chmod(0o700)

        result, data = self.invoke()
        self.assertEqual((result.returncode, data['status']), (0, 'INTEGRATED'),
                         result.stdout + result.stderr)
        self.assertFalse(marker.exists(), 'original fast-forward ran a destructive repository hook')
        self.assertEqual(cache.read_text(), 'user ignored data\n')
        self.assertEqual(self.head(self.original), data['head'])
        self.assertEqual(command('git', 'status', '--porcelain', cwd=self.original,
                                 env=self.env).stdout, '')

    def test_concurrent_dirty_original_never_autostashes_or_overwrites(self):
        command('git', 'config', 'merge.autostash', 'true', cwd=self.original, env=self.env)
        before_stash = command('git', 'stash', 'list', cwd=self.original, env=self.env).stdout
        bin_dir = self.root / 'bin'
        bin_dir.mkdir()
        marker = self.root / 'injected-before-fast-forward'
        real_git = shutil.which('git')
        wrapper = bin_dir / 'git'
        wrapper.write_text(
            f'#!{sys.executable}\n'
            'import os, sys\nfrom pathlib import Path\n'
            f'original=Path({str(self.original)!r})\n'
            f'marker=Path({str(marker)!r})\n'
            f'real_git={real_git!r}\n'
            'if sys.argv[1:2]==["merge"] and "--ff-only" in sys.argv[1:] '
            'and Path.cwd().resolve()==original.resolve() and not marker.exists():\n'
            '    (original/"app.txt").write_text("concurrent user edit\\n")\n'
            '    marker.write_text("injected")\n'
            'os.execv(real_git,[real_git,*sys.argv[1:]])\n')
        wrapper.chmod(0o700)
        env = {**self.env, 'PATH': str(bin_dir) + os.pathsep + self.env['PATH']}

        result, data = self.invoke(env=env)
        self.assertTrue(marker.exists(), 'the concurrent edit was not injected')
        self.assertEqual((result.returncode, data['status']), (3, 'BLOCKED_LOCAL'),
                         result.stdout + result.stderr)
        self.assertTrue(data['recovery_required'])
        self.assertEqual(data['phase'], 'apply')
        self.assertEqual(self.head(self.original), self.base)
        self.assertEqual((self.original / 'app.txt').read_text(), 'concurrent user edit\n')
        self.assertEqual(command('git', 'stash', 'list', cwd=self.original,
                                 env=self.env).stdout, before_stash)
        self.assertEqual(command('git', 'rev-parse', data['recovery_ref'], cwd=self.original,
                                 env=self.env).stdout.strip(), data['candidate'])
        self.assertTrue(Path(data['journal']).is_file())


if __name__ == '__main__':
    unittest.main()
