"""End-to-end delivery phase controls in disposable repositories."""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


DELIVER = Path(__file__).resolve().parents[1] / 'harness/hooks/deliver.py'
CHECK = 'python3 -m unittest discover -s tests'


def command(*argv, cwd=None, env=None, check=True):
    result = subprocess.run(argv, cwd=cwd, env=env, text=True, capture_output=True, timeout=90)
    if check and result.returncode:
        raise AssertionError((argv, result.stdout, result.stderr))
    return result


class DeliveryWorkflow(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='harness-delivery-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.addCleanup(self.cleanup_owned_scratch)
        self.home = self.root / 'home'
        self.home.mkdir()
        self.env = {**os.environ, 'HOME': str(self.home), 'GIT_CONFIG_GLOBAL': os.devnull,
                    'GIT_CONFIG_NOSYSTEM': '1'}
        for name in tuple(self.env):
            if name.startswith('GIT_') and name not in {'GIT_CONFIG_GLOBAL', 'GIT_CONFIG_NOSYSTEM'}:
                self.env.pop(name)
        self.env['PYTHONDONTWRITEBYTECODE'] = '1'
        self.original = self.root / 'original'
        command('git', 'init', '-q', '-b', 'main', str(self.original), env=self.env)
        command('git', 'config', 'user.name', 'Harness Test', cwd=self.original, env=self.env)
        command('git', 'config', 'user.email', 'test@example.invalid', cwd=self.original, env=self.env)
        (self.original / 'app.txt').write_text('base\n')
        command('git', 'add', 'app.txt', cwd=self.original, env=self.env)
        command('git', 'commit', '-qm', 'base', cwd=self.original, env=self.env)
        self.base = command('git', 'rev-parse', 'HEAD', cwd=self.original, env=self.env).stdout.strip()
        self.source = self.root / 'source'
        command('git', 'worktree', 'add', '-qb', 'codex/feature', str(self.source), cwd=self.original, env=self.env)
        tests = self.source / 'tests'
        tests.mkdir()
        (tests / 'test_change.py').write_text('import unittest\n'
                                               'class Change(unittest.TestCase):\n'
                                               '    def test_value(self):\n'
                                               '        self.assertEqual(2 + 2, 4)\n')
        (self.source / 'app.txt').write_text('feature\n')
        command('git', 'add', 'app.txt', 'tests', cwd=self.source, env=self.env)
        command('git', 'commit', '-qm', 'feature', cwd=self.source, env=self.env)
        self.head = command('git', 'rev-parse', 'HEAD', cwd=self.source, env=self.env).stdout.strip()
        self.remote = self.root / 'remote.git'
        command('git', 'init', '-q', '--bare', str(self.remote), env=self.env)
        command('git', 'remote', 'add', 'origin', str(self.remote), cwd=self.original, env=self.env)
        command('git', 'push', '-q', 'origin', 'main:main', cwd=self.original, env=self.env)
        command('git', 'symbolic-ref', 'HEAD', 'refs/heads/main', cwd=self.remote, env=self.env)
        wal_dir = self.home / '.claude' / 'wals' / 'fixture-session'
        wal_dir.mkdir(parents=True, mode=0o700)
        self.wal = wal_dir / 'main.jsonl'
        self.wal.write_text('{}\n')
        self.wal.chmod(0o600)
        self.kit = self.root / 'kit.json'
        self.kit.write_text(json.dumps({'run': 'python3 app.py', 'test': CHECK,
                                        'watch': 'watch-tests -- python3 -m unittest discover -s tests'}))
        self.kit.chmod(0o600)
        self.body = self.root / 'pr-body.md'
        self.body.write_text('Reviewed feature scope and test result.\n')
        self.body.chmod(0o600)

    def cleanup_owned_scratch(self):
        root = self.original / '.git' / 'agent-harness' / 'delivery-scratch'
        for journal in root.glob('scopes/*/*/*/journal.json'):
            record = json.loads(journal.read_text())
            if record.get('schema') != 2 or 'container' not in record:
                continue
            container = Path(record['container'])
            if not container.exists():
                continue
            info = container.stat()
            self.assertTrue(container.name.startswith('agent-harness-delivery-scratch-'))
            self.assertEqual((info.st_dev, info.st_ino), (record['container_dev'], record['container_ino']))
            shutil.rmtree(container)

    def finish_args(self, mode='remote', generation=None):
        args = ['finish', '--task', 'fixture', '--original', str(self.original),
                '--original-branch', 'main', '--mode', mode, '--check', CHECK]
        if generation:
            args.extend(('--generation', generation))
        return args

    def configure_github(self):
        """Only the fixture transport may reach the local bare remote."""
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        self.github_state = self.root / 'github.json'
        self.events = self.root / 'events.jsonl'
        self.write_github({'created': False, 'creates': 0, 'target': self.base, 'pr': {
            'number': 1, 'state': 'OPEN', 'headRefOid': self.head, 'headRefName': 'codex/feature',
            'baseRefName': 'main', 'url': 'https://github.com/fixture/project/pull/1', 'isDraft': True,
            'mergeCommit': None, 'isCrossRepository': False, 'headRepository': {'name': 'project'},
            'headRepositoryOwner': {'login': 'fixture'}}})
        real_git = shutil.which('git')
        shim = '''import json,os,subprocess,sys
from pathlib import Path
a=sys.argv[1:]
state_path=Path(os.environ['FIXTURE_GITHUB_STATE'])
s=json.loads(state_path.read_text())
with open(os.environ['FIXTURE_EVENTS'],'a') as f:f.write(json.dumps(a)+'\\n')
network=next((x for x in ('push','fetch','ls-remote') if x in a),None)
if network and '--get-url' not in a:
    os.environ['GIT_ALLOW_PROTOCOL']='file'
    remotes={}
    for i in range(int(os.environ.get('GIT_CONFIG_COUNT','0'))):
        key=os.environ.get('GIT_CONFIG_KEY_'+str(i),'');value=os.environ.get('GIT_CONFIG_VALUE_'+str(i),'')
        if key.startswith('remote.') and key.endswith('.url'):remotes[key[7:-4]]=value
    for x in a:
        if x.startswith('remote.') and '.url=' in x:
            key,value=x.split('.url=',1);remotes[key[7:]]=value
    start=a.index(network)+1
    replaced=False
    for i in range(start,len(a)):
        if a[i] in remotes:
            if remotes[a[i]]!='https://github.com/fixture/project.git':sys.exit(78)
            a[i]=os.environ['FIXTURE_REMOTE'];replaced=True;break
    if not replaced and not any(x==os.environ['FIXTURE_REMOTE'] for x in a[start:]):sys.exit(78)
if 'merge' in a and '--ff-only' in a:
    if s.get('inject_dirty'):
        Path(s['original'],'app.txt').write_text('user edit during preflight\\n')
        s['inject_dirty']=False;state_path.write_text(json.dumps(s))
    result=subprocess.run([os.environ['FIXTURE_REAL_GIT'],*a])
    if result.returncode==0 and s.get('ff_nonzero'):
        s['ff_nonzero']=False;state_path.write_text(json.dumps(s));sys.exit(75)
    sys.exit(result.returncode)
os.execv(os.environ['FIXTURE_REAL_GIT'],[os.environ['FIXTURE_REAL_GIT'],*a])
'''
        gh = '''import json,os,sys
from pathlib import Path
p=Path(os.environ['FIXTURE_GITHUB_STATE']);s=json.loads(p.read_text());a=sys.argv[1:]
if a[:2]==['pr','list']:
    if s.get('list_fail'):sys.exit(1)
    print(json.dumps(s.get('listing',([s['pr']] if s['created'] else []))))
elif a[:2]==['pr','create']:
    s['creates']+=1;s['created']=not s.get('create_absent',False);p.write_text(json.dumps(s))
    print('https://github.com/fixture/project/pull/1');sys.exit(s.get('create_exit',0))
elif a[:2]==['pr','view']:print(json.dumps(s['pr']))
elif a[0]=='api':print(json.dumps({'object':{'type':'commit','sha':s['target']}}))
else:sys.exit(79)
'''
        for name, source in (('git', shim), ('gh', gh)):
            path = self.bin / name
            path.write_text('#!' + sys.executable + '\n' + source)
            path.chmod(0o755)
        command('git', 'remote', 'set-url', 'origin', 'https://github.com/fixture/project.git',
                cwd=self.original, env=self.env)
        self.env.update({'PATH': str(self.bin) + os.pathsep + self.env['PATH'],
                         'FIXTURE_REAL_GIT': real_git, 'FIXTURE_REMOTE': str(self.remote),
                         'FIXTURE_GITHUB_STATE': str(self.github_state), 'FIXTURE_EVENTS': str(self.events)})

    def write_github(self, data):
        self.github_state.write_text(json.dumps(data))

    def change_github(self, **changes):
        state = json.loads(self.github_state.read_text())
        state.update(changes)
        self.write_github(state)
        return state

    def merge_remote(self, *, squash=False):
        self.merged = self.root / 'merged'
        command('git', 'worktree', 'add', '-q', '--detach', str(self.merged), self.base,
                cwd=self.original, env=self.env)
        if squash:
            command('git', 'merge', '--squash', 'codex/feature', cwd=self.merged, env=self.env)
            command('git', 'commit', '-qm', 'Squash feature', cwd=self.merged, env=self.env)
        else:
            command('git', 'merge', '--no-ff', '--no-edit', 'codex/feature', cwd=self.merged, env=self.env)
        target = command('git', 'rev-parse', 'HEAD', cwd=self.merged, env=self.env).stdout.strip()
        command('git', 'push', '-q', str(self.remote), target + ':refs/heads/main', cwd=self.merged, env=self.env)
        state = self.change_github(target=target)
        state['pr'].update(state='MERGED', mergeCommit={'oid': target}, isDraft=False)
        self.write_github(state)
        return target

    def invoke(self, *args):
        result = command(sys.executable, str(DELIVER), *args, env=self.env, check=False)
        self.assertTrue(result.stdout, result.stderr)
        return result, json.loads(result.stdout)

    def prepare_args(self):
        return ('prepare', '--wal', str(self.wal), '--task', 'fixture',
                '--source', str(self.source), '--original', str(self.original),
                '--original-branch', 'main', '--expected-source-head', self.head,
                '--expected-original-head', self.base, '--pr-title', 'Feature fixture',
                '--pr-body-file', str(self.body), '--kit-file', str(self.kit))

    def test_unsupported_origin_is_rejected_before_any_publication(self):
        prepared, prep = self.invoke(*self.prepare_args())
        pushed = command('git', 'show-ref', '--verify', 'refs/heads/codex/feature',
                         cwd=self.remote, env=self.env, check=False).returncode == 0
        self.assertEqual((prepared.returncode, prep['status'], pushed),
                         (2, 'BLOCKED_POLICY', False), prepared.stdout + prepared.stderr)
        self.assertEqual(command('git', 'rev-parse', 'HEAD', cwd=self.original,
                                 env=self.env).stdout.strip(), self.base)

    def test_explicit_local_only_delivers_and_repeats_without_home_state(self):
        result, prepared = self.invoke(*self.prepare_args(), '--local-only')
        self.assertEqual((result.returncode, prepared['status']), (0, 'LOCAL_READY'), result.stdout)
        self.assertTrue(Path(prepared['state']).resolve().is_relative_to((self.original / '.git').resolve()))
        second_home = self.root / 'other-home'
        second_home.mkdir()
        self.env['HOME'] = str(second_home)
        result, completed = self.invoke(*self.finish_args('local', prepared['generation']))
        self.assertEqual((result.returncode, completed['status']), (0, 'LOCAL_DELIVERED'), result.stdout)
        result, repeat = self.invoke(*self.finish_args('local', prepared['generation']))
        self.assertEqual((result.returncode, repeat['status']), (0, 'ALREADY_DELIVERED'), result.stdout)
        self.assertEqual(repeat['head'], completed['head'])
        self.assertEqual(command('git', 'rev-parse', 'HEAD', cwd=self.original, env=self.env).stdout.strip(), completed['head'])

    def test_pr_readiness_does_not_mutate_original_and_create_is_idempotent(self):
        self.configure_github()
        first, prepared = self.invoke(*self.prepare_args())
        self.assertEqual((first.returncode, prepared['status']), (0, 'PR_READY'), first.stdout)
        second, repeated = self.invoke(*self.prepare_args())
        self.assertEqual((second.returncode, repeated['status']), (0, 'PR_READY'), second.stdout)
        self.assertEqual(prepared['generation'], repeated['generation'])
        self.assertEqual(json.loads(self.github_state.read_text())['creates'], 1)
        self.assertEqual(command('git', 'rev-parse', 'HEAD', cwd=self.original, env=self.env).stdout.strip(), self.base)
        pending, outcome = self.invoke(*self.finish_args())
        self.assertEqual((pending.returncode, outcome['status']), (4, 'PR_READY'), pending.stdout)

    def test_remote_finish_checks_actual_checkout_and_ignores_repo_hooks(self):
        self.configure_github()
        prepared, data = self.invoke(*self.prepare_args())
        self.assertEqual(prepared.returncode, 0, prepared.stdout)
        target = self.merge_remote()
        marker = self.root / 'hook-fired'
        hook = self.original / '.git' / 'hooks' / 'post-merge'
        hook.write_text('#!/bin/sh\ntouch "' + str(marker) + '"\n')
        hook.chmod(0o755)
        finished, outcome = self.invoke(*self.finish_args(generation=data['generation']))
        self.assertEqual((finished.returncode, outcome['status'], outcome.get('head')), (0, 'DELIVERED', target), finished.stdout)
        self.assertFalse(marker.exists())
        self.assertEqual(command('git', 'status', '--porcelain', cwd=self.original, env=self.env).stdout.strip(), '')
        receipt = json.loads(Path(outcome['receipt']).read_text())
        self.assertEqual(receipt['head'], target)
        guard = json.loads(next((self.original / '.git' / 'agent-harness' / 'delivery-scratch').glob('scopes/*/archive/*/journal.json')).read_text())
        self.assertEqual((guard['kind'], guard['phase'], guard['resolved_by']), ('external_apply', 'resolved', 'workflow'))

    def test_squash_merge_is_deliverable_and_terminal_repeat_is_historical(self):
        self.configure_github()
        prepared, _ = self.invoke(*self.prepare_args())
        self.assertEqual(prepared.returncode, 0, prepared.stdout)
        target = self.merge_remote(squash=True)
        finished, outcome = self.invoke(*self.finish_args())
        self.assertEqual((finished.returncode, outcome['head']), (0, target), finished.stdout)
        before = Path(outcome['receipt']).read_bytes()
        (self.original / 'later.txt').write_text('later reviewed work\n')
        command('git', 'add', 'later.txt', cwd=self.original, env=self.env)
        command('git', 'commit', '-qm', 'Later work', cwd=self.original, env=self.env)
        later = command('git', 'rev-parse', 'HEAD', cwd=self.original, env=self.env).stdout.strip()
        self.change_github(target=later)
        repeated, data = self.invoke(*self.finish_args())
        self.assertEqual((repeated.returncode, data['status'], data['head'], data['current_head']),
                         (0, 'ALREADY_DELIVERED', target, later), repeated.stdout)
        self.assertEqual(Path(outcome['receipt']).read_bytes(), before)


if __name__ == '__main__':
    unittest.main()
