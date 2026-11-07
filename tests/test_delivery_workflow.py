"""End-to-end delivery phase controls in disposable repositories."""

import json
import importlib.util
import contextlib
import io
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from commit_messages import message


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
        baseline_tests = self.original / 'tests'
        baseline_tests.mkdir()
        (baseline_tests / 'test_format.py').write_text('import os,unittest\nfrom pathlib import Path\n'
            'class Format(unittest.TestCase):\n'
            '    def test_record_is_one_line(self):\n'
            '        self.assertEqual(Path("app.txt").read_text().count("\\n"), 1)\n'
            '    def test_dependency_ready(self):\n'
            '        self.assertNotEqual(os.environ.get("FIXTURE_DEPENDENCY"), "unavailable")\n')
        command('git', 'add', 'app.txt', 'tests', cwd=self.original, env=self.env)
        command('git', 'commit', '-qm', message('record the fixture base'), cwd=self.original, env=self.env)
        self.base = command('git', 'rev-parse', 'HEAD', cwd=self.original, env=self.env).stdout.strip()
        self.source = self.root / 'source'
        command('git', 'worktree', 'add', '-qb', 'codex/feature', str(self.source), cwd=self.original, env=self.env)
        tests = self.source / 'tests'
        tests.mkdir(exist_ok=True)
        (tests / 'test_change.py').write_text('import unittest\n'
                                               'class Change(unittest.TestCase):\n'
                                               '    def test_value(self):\n'
                                               '        self.assertEqual(2 + 2, 4)\n')
        (self.source / 'app.txt').write_text('feature\n')
        command('git', 'add', 'app.txt', 'tests', cwd=self.source, env=self.env)
        command('git', 'commit', '-qm', message('record the fixture feature'), cwd=self.source, env=self.env)
        self.head = command('git', 'rev-parse', 'HEAD', cwd=self.source, env=self.env).stdout.strip()
        self.remote = self.root / 'remote.git'
        command('git', 'init', '-q', '--bare', str(self.remote), env=self.env)
        command('git', 'remote', 'add', 'origin', str(self.remote), cwd=self.original, env=self.env)
        command('git', 'push', '-q', 'origin', 'main:main', cwd=self.original, env=self.env)
        command('git', 'symbolic-ref', 'HEAD', 'refs/heads/main', cwd=self.remote, env=self.env)
        self.kit = self.root / 'kit.json'
        self.kit.write_text(json.dumps({'run': 'python3 app.py', 'test': CHECK,
                                        'watch': 'watch-tests -- python3 -m unittest discover -s tests'}))
        self.kit.chmod(0o600)
        self.body = self.root / 'pr-body.md'
        self.body.write_text(message('record the fixture feature').split('\n', 2)[2])
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
            if remotes[a[i]].lower()!='https://github.com/fixture/project.git':sys.exit(78)
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
    if s.get('fail_list_after_create'):s['list_fail']=True;p.write_text(json.dumps(s))
    sys.stderr.write(s.get('create_stderr',''));sys.stderr.flush()
    if s.get('create_stderr_flood'):
        for _ in range(int(s['create_stderr_flood'])):sys.stderr.write('x'*65536)
    print('https://github.com/fixture/project/pull/1');sys.exit(s.get('create_exit',0))
elif a[:2]==['pr','view']:
    if s.get('view_fail'):sys.exit(1)
    print(json.dumps(s['pr']))
elif a[0]=='api':print(json.dumps({'object':{'type':'commit','sha':s['target']}}))
else:sys.exit(79)
'''
        driver = self.bin / 'git-driver.py'
        driver.write_text(shim)
        driver.chmod(0o600)
        launcher = '''#!/bin/sh
for argument do
    case "$argument" in
        push|fetch|ls-remote|merge) exec "$FIXTURE_PYTHON" "$FIXTURE_GIT_DRIVER" "$@" ;;
    esac
done
exec "$FIXTURE_REAL_GIT" "$@"
'''
        for name, source in (('git', launcher), ('gh', '#!' + sys.executable + '\n' + gh)):
            path = self.bin / name
            path.write_text(source)
            path.chmod(0o755)
        command('git', 'remote', 'set-url', 'origin', 'https://github.com/fixture/project.git',
                cwd=self.original, env=self.env)
        self.env.update({'PATH': str(self.bin) + os.pathsep + self.env['PATH'],
                         'FIXTURE_REAL_GIT': real_git, 'FIXTURE_REMOTE': str(self.remote),
                         'FIXTURE_GITHUB_STATE': str(self.github_state), 'FIXTURE_EVENTS': str(self.events),
                         'FIXTURE_PYTHON': sys.executable, 'FIXTURE_GIT_DRIVER': str(driver)})

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

    def direct_finish(self, patch_factory, arguments=None):
        """Inject a precise process/write boundary without shipping fault flags."""
        hooks = DELIVER.parent
        spec = importlib.util.spec_from_file_location('workflow_fixture_target', DELIVER)
        module = importlib.util.module_from_spec(spec)
        captured = io.StringIO()
        # The path patch must cover main() too: deliver imports commit_policy (and friends)
        # dynamically while running, so it fails when this file is the only one on the path
        # (it passes in a full discover run only because an earlier test module imported
        # commit_policy first).
        with mock.patch.object(sys, 'path', [str(hooks), *sys.path]):
            spec.loader.exec_module(module)
            with mock.patch.dict(os.environ, self.env, clear=True), contextlib.redirect_stdout(captured):
                with mock.patch.object(sys, 'argv', [str(DELIVER), *(arguments or self.finish_args())]):
                    with patch_factory(module):
                        code = module.main()
        return code, json.loads(captured.getvalue())

    def baseline_args(self, head):
        return ['finish', '--task', 'fixture', '--original', str(self.original),
                '--original-branch', 'main', '--resolve-baseline', head, '--check', CHECK]

    def replace_feature_tests(self, body):
        for path in (self.source / 'tests').glob('*.py'):
            path.unlink()
        (self.source / 'tests' / 'test_change.py').write_text(body)
        command('git', 'add', '-A', 'tests', cwd=self.source, env=self.env)
        command('git', 'commit', '-qm', message('record the failing scenario'), cwd=self.source, env=self.env)
        self.head = command('git', 'rev-parse', 'HEAD', cwd=self.source, env=self.env).stdout.strip()

    def invoke(self, *args):
        result = command(sys.executable, str(DELIVER), *args, env=self.env, check=False)
        self.assertTrue(result.stdout, result.stderr)
        return result, json.loads(result.stdout)

    def prepare_args(self):
        return ('prepare', '--task', 'fixture',
                '--source', str(self.source), '--original', str(self.original),
                '--original-branch', 'main', '--expected-source-head', self.head,
                '--expected-original-head', self.base, '--pr-title', 'chore(fixture): record the fixture feature',
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
        command('git', 'commit', '-qm', message('record later original work'), cwd=self.original, env=self.env)
        later = command('git', 'rev-parse', 'HEAD', cwd=self.original, env=self.env).stdout.strip()
        self.change_github(target=later)
        repeated, data = self.invoke(*self.finish_args())
        self.assertEqual((repeated.returncode, data['status'], data['head'], data['current_head']),
                         (0, 'ALREADY_DELIVERED', target, later), repeated.stdout)
        self.assertEqual(Path(outcome['receipt']).read_bytes(), before)

    def test_post_fast_forward_failure_reports_actual_head_and_blocks_other_tools(self):
        self.configure_github()
        prepared, _ = self.invoke(*self.prepare_args())
        self.assertEqual(prepared.returncode, 0, prepared.stdout)
        target = self.merge_remote()
        self.change_github(ff_nonzero=True)
        result, outcome = self.invoke(*self.finish_args())
        self.assertEqual((result.returncode, outcome['status'], outcome.get('head'), outcome.get('original_advanced')),
                         (3, 'RECOVERY_REQUIRED', target, True), result.stdout)
        helper = command(sys.executable, str(DELIVER.with_name('integrate_local.py')),
                         '--repo', str(self.original), '--original-branch', 'main', '--expected-head', target,
                         '--source', 'codex/feature', '--expected-source-head', self.head, '--check', CHECK,
                         env=self.env, check=False)
        self.assertEqual((helper.returncode, json.loads(helper.stdout)['status']), (3, 'RECOVERY_REQUIRED'), helper.stdout)
        self.assertFalse(list((self.original / '.git' / 'agent-harness' / 'delivery-workflows').glob('*/**/receipt/journal.json')))

    def test_dirty_edit_race_cannot_autostash_or_advance_original(self):
        self.configure_github()
        prepared, _ = self.invoke(*self.prepare_args())
        self.assertEqual(prepared.returncode, 0, prepared.stdout)
        self.merge_remote()
        command('git', 'config', 'merge.autoStash', 'true', cwd=self.original, env=self.env)
        self.change_github(inject_dirty=True, original=str(self.original))
        result, outcome = self.invoke(*self.finish_args())
        self.assertEqual((result.returncode, outcome['status'], outcome.get('head'), outcome.get('original_advanced')),
                         (3, 'RECOVERY_REQUIRED', self.base, False), result.stdout)
        self.assertEqual((self.original / 'app.txt').read_text(), 'user edit during preflight\n')
        self.assertEqual(command('git', 'stash', 'list', cwd=self.original, env=self.env).stdout, '')

    def assert_bad_checks_refuse_delivery(self, body):
        self.replace_feature_tests(body)
        self.configure_github()
        prepared, _ = self.invoke(*self.prepare_args())
        self.assertEqual(prepared.returncode, 0, prepared.stdout)
        target = self.merge_remote()
        result, outcome = self.invoke(*self.finish_args())
        self.assertEqual((result.returncode, outcome['status'], outcome.get('head')),
                         (3, 'RECOVERY_REQUIRED', target), result.stdout)
        self.assertEqual(outcome.get('cause'), 'DELIVERED_CHECK_FAILED')
        active = list((self.original / '.git' / 'agent-harness' / 'delivery-scratch').glob('scopes/*/active/*/journal.json'))
        self.assertEqual(len(active), 1)
        self.assertEqual(json.loads(active[0].read_text())['phase'], 'applying')

    def test_failed_real_check_cannot_claim_delivery(self):
        self.assert_bad_checks_refuse_delivery('import unittest\nclass Failure(unittest.TestCase):\n'
                                               '    def test_dependency(self): self.fail("fixture failure")\n')

    def test_all_skipped_check_cannot_claim_delivery(self):
        self.assert_bad_checks_refuse_delivery('import unittest\n@unittest.skip("fixture")\n'
            'class Skipped(unittest.TestCase):\n    def test_dependency(self): pass\n')

    def test_zero_case_check_cannot_claim_delivery(self):
        self.assert_bad_checks_refuse_delivery('# Deliberate empty discovery control.\n')

    def test_guard_resolved_before_receipt_is_rechecked_without_second_fast_forward(self):
        self.configure_github()
        prepared, _ = self.invoke(*self.prepare_args())
        self.assertEqual(prepared.returncode, 0, prepared.stdout)
        target = self.merge_remote()
        code, failed = self.direct_finish(lambda module: mock.patch.object(module.Workflow, 'complete',
                                                                           side_effect=OSError('fixture receipt fault')))
        self.assertEqual((code, failed['status'], failed.get('head')), (3, 'RECOVERY_REQUIRED', target))
        before = [json.loads(line) for line in self.events.read_text().splitlines()]
        ff_before = sum('merge' in event and '--ff-only' in event for event in before)
        command('git', 'worktree', 'remove', str(self.source), cwd=self.original, env=self.env)
        result, completed = self.invoke(*self.finish_args())
        self.assertEqual((result.returncode, completed['status'], completed.get('head')), (0, 'DELIVERED', target), result.stdout)
        after = [json.loads(line) for line in self.events.read_text().splitlines()]
        self.assertEqual(sum('merge' in event and '--ff-only' in event for event in after), ff_before)

    def test_unbound_apply_needs_tested_baseline_and_new_generation(self):
        self.configure_github()
        prepared, data = self.invoke(*self.prepare_args())
        self.assertEqual(prepared.returncode, 0, prepared.stdout)
        self.merge_remote()
        code, failed = self.direct_finish(lambda module: mock.patch.object(module.OriginalScope, 'reserve_external',
                                                                           side_effect=OSError('fixture reserve fault')))
        self.assertEqual((code, failed['status'], failed.get('head')), (3, 'RECOVERY_REQUIRED', self.base))
        blocked, _ = self.invoke(*self.prepare_args(), '--new-generation')
        self.assertEqual(blocked.returncode, 3)
        resolved, outcome = self.invoke(*self.baseline_args(self.base))
        self.assertEqual((resolved.returncode, outcome['status']), (0, 'RESOLVED_BASELINE'), resolved.stdout)
        self.assertFalse(list(Path(data['state']).parent.glob('receipt/journal.json')))
        pending, _ = self.invoke(*self.finish_args())
        self.assertEqual(pending.returncode, 3)
        fresh, new = self.invoke(*self.prepare_args(), '--new-generation')
        self.assertEqual((fresh.returncode, new['status']), (0, 'PR_READY'), fresh.stdout)
        self.assertNotEqual(new['generation'], data['generation'])
        stale, old = self.invoke(*self.finish_args(generation=data['generation']))
        self.assertEqual((stale.returncode, old['status']), (3, 'STALE_GENERATION'))
        finished, current = self.invoke(*self.finish_args(generation=new['generation']))
        self.assertEqual((finished.returncode, current['status']), (0, 'DELIVERED'), finished.stdout)

    def test_publication_uncertainty_cannot_become_a_baseline_resolution(self):
        self.configure_github()
        self.change_github(fail_list_after_create=True)
        result, data = self.invoke(*self.prepare_args())
        self.assertEqual((result.returncode, data['status']), (4, 'REMOTE_UNCERTAIN'), result.stdout)
        state = Path(data['state'])
        before = state.read_bytes()
        rejected, outcome = self.invoke(*self.baseline_args(self.base))
        self.assertEqual((rejected.returncode, outcome['status']), (2, 'BLOCKED_POLICY'), rejected.stdout)
        self.assertEqual(state.read_bytes(), before)
        self.change_github(list_fail=False)
        (self.source / 'later.txt').write_text('next reviewed scope\n')
        command('git', 'add', 'later.txt', cwd=self.source, env=self.env)
        command('git', 'commit', '-qm', message('record the next scope'), cwd=self.source, env=self.env)
        reconciled, old = self.invoke('prepare', '--task', 'fixture', '--original', str(self.original),
                                     '--original-branch', 'main', '--reconcile-only')
        self.assertEqual((reconciled.returncode, old['status']), (0, 'PR_READY'), reconciled.stdout)
        self.assertEqual(json.loads(self.github_state.read_text())['creates'], 1)
        self.assertEqual(json.loads(state.read_text())['source_head'], self.head)

    def test_known_pr_access_failure_is_not_absence_or_local_fallback(self):
        self.configure_github()
        result, data = self.invoke(*self.prepare_args())
        self.assertEqual(result.returncode, 0, result.stdout)
        state = Path(data['state'])
        before = state.read_bytes()
        self.change_github(view_fail=True, listing=[])
        result, failed = self.invoke('prepare', '--task', 'fixture', '--original', str(self.original),
                                     '--original-branch', 'main', '--reconcile-only')
        self.assertEqual((result.returncode, failed['status']), (4, 'REMOTE_UNCERTAIN'), result.stdout)
        self.assertEqual(state.read_bytes(), before)
        local, response = self.invoke(*self.finish_args('local'))
        self.assertEqual((local.returncode, response['status']), (2, 'BLOCKED_POLICY'), local.stdout)

    def test_ambiguous_bounded_pr_lookup_cannot_unlock_local_fallback(self):
        self.configure_github()
        record = json.loads(self.github_state.read_text())['pr']
        second = {**record, 'number': 2, 'url': 'https://github.com/fixture/project/pull/2'}
        for listing in ([record, second], [record] * 101, [record] * 4000):
            with self.subTest(records=len(listing)):
                self.change_github(listing=listing)
                result, data = self.invoke(*self.prepare_args(), '--new-generation')
                self.assertEqual(data['status'], 'BLOCKED_POLICY', result.stdout)
                self.assertNotEqual(result.returncode, 0)
                local, failed = self.invoke(*self.finish_args('local'))
                self.assertEqual((local.returncode, failed['status']), (2, 'BLOCKED_POLICY'), local.stdout)
        self.assertEqual(json.loads(self.github_state.read_text())['creates'], 0)

    def test_case_aliases_of_github_identity_are_supported(self):
        self.configure_github()
        command('git', 'remote', 'set-url', 'origin', 'https://github.com/Fixture/Project.git',
                cwd=self.original, env=self.env)
        state = json.loads(self.github_state.read_text())
        state['pr'].update(url='https://github.com/Fixture/Project/pull/1',
                            headRepository={'name': 'Project'}, headRepositoryOwner={'login': 'Fixture'})
        self.write_github(state)
        result, data = self.invoke(*self.prepare_args())
        self.assertEqual((result.returncode, data['status']), (0, 'PR_READY'), result.stdout)

    def test_malformed_private_workflow_fields_fail_closed_without_echo(self):
        result, data = self.invoke(*self.prepare_args(), '--local-only')
        self.assertEqual(result.returncode, 0, result.stdout)
        state = Path(data['state'])
        before = state.read_bytes()
        mutations = [('phase', []), ('schema', True), ('source_head', 'secret_fixture'),
                     ('source', 'bad\ud800'), ('kit_digest', None), ('target', False),
                     ('pr_number', True), ('guard_key', {'untrusted': 'secret_fixture'})]
        for name, value in mutations:
            with self.subTest(field=name):
                record = json.loads(before)
                record[name] = value
                state.write_text(json.dumps(record))
                response, error = self.invoke(*self.finish_args('local'))
                self.assertEqual((response.returncode, error['status']), (3, 'RECOVERY_REQUIRED'), response.stdout)
                self.assertNotIn('Traceback', response.stderr)
                self.assertNotIn('secret_fixture', response.stdout)
                self.assertEqual(json.loads(state.read_text()), record)
        state.write_bytes(before)
        self.assertEqual(command('git', 'rev-parse', 'HEAD', cwd=self.original, env=self.env).stdout.strip(), self.base)

    def test_focused_baseline_check_must_run_a_test(self):
        # GoodQA #14729: the focused form reaches finish --resolve-baseline; a pattern that runs no test must not resolve.
        self.configure_github()
        result, data = self.invoke(*self.prepare_args())
        self.assertEqual(result.returncode, 0, result.stdout)
        self.merge_remote()
        code, _ = self.direct_finish(lambda module: mock.patch.object(module.OriginalScope, 'reserve_external',
                                                                      side_effect=OSError('fixture reserve fault')))
        self.assertEqual(code, 3)
        state = Path(data['state'])
        before = state.read_bytes()

        def focused(pattern):
            args = self.baseline_args(self.base)
            args[args.index('--check') + 1] = 'python3 -m unittest discover -s tests -p ' + pattern
            return args
        empty, error = self.invoke(*focused('test_missing.py'))
        self.assertEqual((empty.returncode, error['status']), (3, 'RECOVERY_REQUIRED'), empty.stdout)
        self.assertEqual(state.read_bytes(), before)
        globbed, error = self.invoke(*focused("'test_*.py'"))
        self.assertEqual((globbed.returncode, error['status']), (2, 'BLOCKED_POLICY'), globbed.stdout)
        self.assertEqual(state.read_bytes(), before)
        passed, outcome = self.invoke(*focused('test_format.py'))
        self.assertEqual((passed.returncode, outcome['status']), (0, 'RESOLVED_BASELINE'), passed.stdout)

    def test_baseline_negative_checks_and_transition_crashes_preserve_no_delivery(self):
        self.configure_github()
        result, data = self.invoke(*self.prepare_args())
        self.assertEqual(result.returncode, 0, result.stdout)
        self.merge_remote()
        code, _ = self.direct_finish(lambda module: mock.patch.object(module.OriginalScope, 'reserve_external',
                                                                      side_effect=OSError('fixture reserve fault')))
        self.assertEqual(code, 3)
        state = Path(data['state'])
        before = state.read_bytes()
        for value in ('HEAD', self.base[:8], 'a' * 64):
            with self.subTest(oid=value):
                rejected, error = self.invoke(*self.baseline_args(value))
                self.assertEqual((rejected.returncode, error['status']), (2, 'BLOCKED_POLICY'), rejected.stdout)
                self.assertEqual(state.read_bytes(), before)
        self.env['FIXTURE_DEPENDENCY'] = 'unavailable'
        failed, error = self.invoke(*self.baseline_args(self.base))
        self.env.pop('FIXTURE_DEPENDENCY')
        self.assertEqual((failed.returncode, error['status']), (3, 'RECOVERY_REQUIRED'), failed.stdout)
        self.assertEqual(state.read_bytes(), before)
        code, _ = self.direct_finish(lambda module: mock.patch.object(module.Workflow, 'save',
                            side_effect=OSError('fixture write fault')), self.baseline_args(self.base))
        self.assertEqual(code, 3)
        self.assertEqual(state.read_bytes(), before)
        def changed_generation(module):
            def mutate(*unused):
                value = json.loads(state.read_text())
                value['checks_digest'] = '0' * 64
                state.write_text(json.dumps(value))
            return mock.patch.object(module, 'run_checks', side_effect=mutate)
        code, _ = self.direct_finish(changed_generation, self.baseline_args(self.base))
        self.assertEqual(code, 3)
        self.assertEqual(json.loads(state.read_text())['phase'], 'REMOTE_APPLYING')
        state.write_bytes(before)
        def moved_head(module):
            def advance(*unused):
                (self.original / 'user.txt').write_text('user-owned advance\n')
                command('git', 'add', 'user.txt', cwd=self.original, env=self.env)
                command('git', 'commit', '-qm', message('record a user advance'), cwd=self.original, env=self.env)
            return mock.patch.object(module, 'run_checks', side_effect=advance)
        code, _ = self.direct_finish(moved_head, self.baseline_args(self.base))
        self.assertEqual(code, 3)
        self.assertEqual(state.read_bytes(), before)
        current = command('git', 'rev-parse', 'HEAD', cwd=self.original, env=self.env).stdout.strip()
        self.assertNotEqual(current, self.base)
        def crash_after_write(module):
            save = module.Workflow.save
            def crash(workflow, **changes):
                save(workflow, **changes)
                raise OSError('fixture interruption after durable write')
            return mock.patch.object(module.Workflow, 'save', crash)
        code, error = self.direct_finish(crash_after_write, self.baseline_args(current))
        self.assertEqual((code, error['status']), (3, 'RECOVERY_REQUIRED'))
        self.assertEqual(json.loads(state.read_text())['phase'], 'RESOLVED_BASELINE')
        self.assertFalse(list(state.parent.glob('receipt/journal.json')))
        pending, error = self.invoke(*self.finish_args())
        self.assertEqual((pending.returncode, error['status']), (3, 'RESOLVED_BASELINE'))


if __name__ == '__main__':
    unittest.main()
