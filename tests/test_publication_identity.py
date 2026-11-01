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
import traceback
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
        self.root = Path(temporary.name).resolve()
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
            '    if url in mapping: target=mapping[url]\n'
            '    elif url in mapping.values(): target=url\n'
            '    else: sys.exit(97)\n'
            '    with marker.open("a") as handle: handle.write(json.dumps({"verb":verb,"url":url})+"\\n")\n'
            '    args[remote_index]=target\n'
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
        self.assertEqual(data['repository'], 'owner/expected')
        self.assertEqual(self.command('rev-parse', 'refs/heads/feat/identity',
                                      cwd=self.destinations['https://github.com/owner/expected.git']).stdout.strip(), self.head)
        self.assertTrue(self.marker.is_file(), 'the positive fixture never exercised transport')

    def test_expected_option_is_enforced_by_cli(self):
        result = subprocess.run([sys.executable, str(PUBLISH), '--repo', str(self.source),
                                 '--branch', 'feat/identity', '--original-branch', 'main',
                                 '--expected-head', self.head, '--expected-repository', 'OwNeR/EXPECTED'],
                                env=self.env, text=True, capture_output=True, timeout=30)
        self.assertEqual((result.returncode, json.loads(result.stdout)['status']), (0, 'PUSHED'),
                         result.stdout + result.stderr)
        self.assertEqual(json.loads(result.stdout)['repository'], 'owner/expected')
        self.assertEqual(self.command('rev-parse', 'refs/heads/feat/identity',
                                      cwd=self.destinations['https://github.com/owner/expected.git']).stdout.strip(), self.head)

    def test_local_origin_with_expected_identity_has_no_network_effect(self):
        self.command('remote', 'set-url', 'origin', self.destinations['https://github.com/owner/expected.git'],
                     cwd=self.source)
        code, data = self.direct_publish()
        self.assertEqual((code, data['status']), (2, 'BLOCKED_POLICY'), data)
        self.assertFalse(self.marker.exists())
        self.assert_unpublished()

    def test_legacy_local_origin_still_publishes_without_expected_option(self):
        self.command('remote', 'set-url', 'origin', self.destinations['https://github.com/owner/expected.git'],
                     cwd=self.source)
        code, data = self.direct_publish(expected=None)
        self.assertEqual((code, data['status']), (0, 'PUSHED'), data)
        self.assertNotIn('repository', data)
        self.assertEqual(self.command('rev-parse', 'refs/heads/feat/identity',
                                      cwd=self.destinations['https://github.com/owner/expected.git']).stdout.strip(), self.head)

    def test_credentials_are_refused_without_contact_or_echo(self):
        credential = 'fixture-do-not-echo'
        self.command('remote', 'set-url', 'origin', f'https://{credential}@github.com/owner/expected.git',
                     cwd=self.source)
        code, data = self.direct_publish()
        self.assertEqual((code, data['status']), (2, 'BLOCKED_POLICY'), data)
        self.assertNotIn(credential, json.dumps(data))
        self.assertFalse(self.marker.exists())
        self.assert_unpublished()

    def test_invalid_expected_argument_does_not_contact_remote(self):
        code, data = self.direct_publish(expected='owner/../changed')
        self.assertEqual((code, data['status']), (2, 'BLOCKED_POLICY'), data)
        self.assertFalse(self.marker.exists())
        self.assert_unpublished()


class GitHubIdentity(unittest.TestCase):
    def setUp(self):
        self.identity = load_module('github_identity_control', HOOKS / 'github_identity.py')

    def test_standard_transports_canonicalize_the_same_repository(self):
        urls = ['https://GitHub.com/Owner/Repo.git', 'https://github.com:443/Owner/Repo.git/',
                'git@GitHub.com:Owner/Repo.git', 'ssh://git@github.com/Owner/Repo.git',
                'ssh://git@github.com:22/Owner/Repo.git']
        for value in urls:
            with self.subTest(url=value):
                self.assertEqual(self.identity.github_repository(value), 'owner/repo')
        self.assertEqual(self.identity.github_repository('https://github.com/org-code/repo.git.git'),
                         'org-code/repo.git')
        self.assertEqual(self.identity.repository_name('OWNER/REPO.git'), 'owner/repo.git')
        self.assertEqual(self.identity.repository_name('managed_code/repo_name'), 'managed_code/repo_name')

    def test_ambiguous_or_unsupported_url_text_is_rejected(self):
        values = [None, True, 3, '', '/tmp/owner/repo.git', 'file:///tmp/repo.git',
                  'http://github.com/owner/repo.git', 'git://github.com/owner/repo.git',
                  'https://github.com.evil.invalid/owner/repo.git', 'https://github.com./owner/repo.git',
                  'https://user:password@github.com/owner/repo.git', 'https://@github.com/owner/repo.git',
                  'ssh://root@github.com/owner/repo.git', 'ssh://git:password@github.com/owner/repo.git',
                  'ssh://git@github.com:443/owner/repo.git', 'https://github.com:22/owner/repo.git',
                  'https://github.com:bad/owner/repo.git', 'git@evil.invalid:owner/repo.git',
                  'https://github.com/owner/../repo', 'https://github.com/../repo.git',
                  'https://github.com/owner/repo.git?token=x', 'https://github.com/owner/repo.git?',
                  'git@github.com:owner/repo.git#fragment', 'https://github.com/owner%2fother/repo.git',
                  'https://github.com/owner/repo%2fgit', 'https://github.com//owner/repo.git',
                  'https://github.com/owner/repo.git//', 'https://github.com/owner/.git',
                  'https://github.com/owner/repo\n.git', 'https://github.com/owner/repo\0.git',
                  'https://github.com/owner/repo\ud800.git', ' https://github.com/owner/repo.git']
        for value in values:
            with self.subTest(value=repr(value)):
                with self.assertRaisesRegex(ValueError, '^Unsupported GitHub repository identity$'):
                    self.identity.github_repository(value)

    def test_repository_argument_is_bounded_without_url_interpretation(self):
        values = ['owner', 'owner/repo/extra', '../repo', 'owner/..', 'owner/.',
                  'https://github.com/owner/repo', 'owner/repo?token=x',
                  'o' * 40 + '/repo', 'owner/' + 'r' * 101, 'owner/repo\0', 'owner/repo\ud800']
        for value in values:
            with self.subTest(value=repr(value)):
                with self.assertRaises(ValueError):
                    self.identity.repository_name(value)

    def test_parser_tracebacks_do_not_echo_untrusted_port_text(self):
        sensitive = 'fixture-secret-port'
        try:
            self.identity.github_repository('https://github.com:' + sensitive + '/owner/repo.git')
        except ValueError as error:
            rendered = ''.join(traceback.format_exception(type(error), error, error.__traceback__))
        else:
            self.fail('invalid port was accepted')
        self.assertNotIn(sensitive, rendered)


if __name__ == '__main__':
    unittest.main()
