"""Bind publication to an expected GitHub repo using disposable real Git."""

import argparse
import contextlib
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


HOOKS = Path(__file__).resolve().parents[1] / 'harness/hooks'
PUBLISH = HOOKS / 'publish_feature.py'


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    with patch.object(sys, 'path', [str(HOOKS), *sys.path]):
        spec.loader.exec_module(module)
    return module


class PublicationDestination(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='publication-identity-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.real_git = shutil.which('git')
        self.env = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
        self.env.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM='1',
                        GIT_TERMINAL_PROMPT='0', PYTHONDONTWRITEBYTECODE='1')
        self.source = self.root / 'source'
        self.command('init', '-q', '-b', 'main', str(self.source))
        self.command('config', 'user.name', 'Harness Test', cwd=self.source)
        self.command('config', 'user.email', 'test@example.invalid', cwd=self.source)
        (self.source / 'app.txt').write_text('base\n')
        self.command('add', 'app.txt', cwd=self.source)
        self.command('commit', '-qm', 'base', cwd=self.source)
        self.destinations = {}
        for name in ('expected', 'changed'):
            bare = self.root / (name + '.git')
            self.command('init', '-q', '--bare', str(bare))
            self.command('push', '-q', str(bare), 'main:main', cwd=self.source)
            self.command('symbolic-ref', 'HEAD', 'refs/heads/main', cwd=bare)
            self.destinations['https://github.com/owner/' + name + '.git'] = str(bare)
        self.command('checkout', '-qb', 'feat/identity', cwd=self.source)
        (self.source / 'app.txt').write_text('feature\n')
        self.command('commit', '-qam', 'feature', cwd=self.source)
        self.head = self.command('rev-parse', 'HEAD', cwd=self.source).stdout.strip()
        self.command('remote', 'add', 'origin', 'https://github.com/owner/expected.git', cwd=self.source)
        self.marker = self.root / 'network.jsonl'
        bin_dir = self.root / 'bin'
        bin_dir.mkdir()
        wrapper = bin_dir / 'git'
        wrapper.write_text(
            f'#!{sys.executable}\n'
            'import json, os, sys\nfrom pathlib import Path\n'
            f'real_git={self.real_git!r}\n'
            f'mapping={self.destinations!r}\n'
            f'marker=Path({str(self.marker)!r})\n'
            'args=sys.argv[1:]\n'
            'offset=2 if args[:1]==["-C"] else 0\n'
            'verb=args[offset] if len(args)>offset else ""\n'
            'if verb in {"push","fetch","ls-remote"} and "--get-url" not in args:\n'
            '    remote_index=offset+3 if verb=="ls-remote" else offset+2\n'
            '    remote=args[remote_index]\n'
            '    configured={os.environ.get(f"GIT_CONFIG_KEY_{i}"):os.environ.get(f"GIT_CONFIG_VALUE_{i}")\n'
            '                for i in range(int(os.environ.get("GIT_CONFIG_COUNT","0")))}\n'
            '    url=configured.get(f"remote.{remote}.url",remote)\n'
            '    if url not in mapping: sys.exit(97)\n'
            '    with marker.open("a") as handle: handle.write(json.dumps({"verb":verb,"url":url})+"\\n")\n'
            '    args[remote_index]=mapping[url]\n'
            'os.execv(real_git,[real_git,*args])\n')
        wrapper.chmod(0o700)
        self.env['PATH'] = str(bin_dir) + os.pathsep + self.env.get('PATH', '')

    def command(self, *args, cwd=None, check=True):
        result = subprocess.run([self.real_git, *args], cwd=cwd, env=self.env,
                                text=True, capture_output=True, timeout=30)
        if check and result.returncode:
            self.fail(str((args, result.stdout, result.stderr)))
        return result

    def direct_publish(self, expected='owner/expected'):
        module = load_module('publication_expected_repo', PUBLISH)
        args = argparse.Namespace(repo=self.source, branch='feat/identity', original_branch='main',
                                  expected_head=self.head, expected_repository=expected, timeout=10)
        output = io.StringIO()
        with patch.dict(os.environ, self.env, clear=True), contextlib.redirect_stdout(output):
            code = module.publish(args)
        return code, json.loads(output.getvalue())

    def assert_unpublished(self):
        for bare in self.destinations.values():
            result = self.command('show-ref', '--verify', 'refs/heads/feat/identity', cwd=bare, check=False)
            self.assertNotEqual(result.returncode, 0, 'a refused destination received the feature branch')

    def test_changed_origin_is_rejected_before_network(self):
        # The orchestrator previously observed owner/expected, then origin moved
        # before this publisher's independent inspection.
        self.command('remote', 'set-url', 'origin', 'https://github.com/owner/changed.git', cwd=self.source)
        code, data = self.direct_publish()
        self.assertEqual((code, data['status']), (2, 'BLOCKED_POLICY'), data)
        self.assertFalse(self.marker.exists(), 'mismatched origin was contacted')
        self.assert_unpublished()

    def test_matching_repository_publishes_exact_commit(self):
        code, data = self.direct_publish()
        self.assertEqual((code, data['status']), (0, 'PUSHED'), data)
        self.assertEqual(self.command('rev-parse', 'refs/heads/feat/identity',
                                      cwd=self.destinations['https://github.com/owner/expected.git']).stdout.strip(), self.head)
        self.assertTrue(self.marker.is_file(), 'the positive fixture never exercised transport')


if __name__ == '__main__':
    unittest.main()
