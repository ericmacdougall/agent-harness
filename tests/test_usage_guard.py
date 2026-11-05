"""Owned-state controls for declared identities and finite execution evidence."""

import hashlib
import importlib.util
import json
import os
import fcntl
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import shutil
import signal
import unittest
from unittest import mock
from datetime import datetime, timedelta, timezone


HOOKS = Path(__file__).resolve().parents[1] / 'harness/hooks'
sys.path.insert(0, str(HOOKS))
import usage_guard as guard


class StoreFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='usage-guard-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / 'repo'; self.repo.mkdir()
        self.store = guard.UsageStore(self.root / 'private')
        self.subject = guard.Subject(schema=1, fingerprint='a' * 64, reusable=True,
                                     head='b' * 40, tree='c' * 40)
        self.subject.repo, self.subject.manifest = self.repo, {}
        self.subject.probe = lambda: self.subject
        self.tool = self.root / 'tool'; self.tool.write_bytes(b'public fixture tool')
        self.tool.chmod(0o700)
        self.toolchain = {'fixture': {'path': str(self.tool), 'public': True,
                                     'sha256': hashlib.sha256(self.tool.read_bytes()).hexdigest()}}
        self.identity = guard.invocation_identity(self.subject, purpose='focused', argv=['public-command'],
                                                  cwd=self.repo, toolchain=self.toolchain)

    def begin(self, **options):
        return self.store.begin(self.subject, self.identity, owner='fixture', label='focused',
                                timeout=10, kind='focused', minimum_bytes=0, **options)

    def finish(self, run):
        return run.finish(execution='COMPLETED', result='CHECK_OK', reason='NONE', exit_code=0, count=1)


class EvidenceStore(StoreFixture):
    def test_private_start_final_and_reuse_preserve_original_reference(self):
        run = self.begin(); reference = self.finish(run)
        start = self.store.load_ref(run.start_ref); final = self.store.load_ref(reference)
        self.assertEqual((start['execution'], final['result'], final['observed_count']), ('RUNNING', 'CHECK_OK', 1))
        self.assertEqual((self.store.root.stat().st_mode & 0o777), 0o700)
        self.assertEqual((self.store.root / 'runs' / run.run_id / 'final.json').stat().st_mode & 0o777, 0o600)
        reused = self.store.reuse(self.subject, self.identity, reference)
        self.assertEqual((reused['evidence'], reused['reference']), ('REUSED', reference))
        self.assertTrue(reused['eligible'])
        self.assertNotIn('result', reused)
        self.assertNotIn('VERDICT: PASS', json.dumps(reused))

    def test_duplicate_and_missing_final_require_explicit_reconciliation(self):
        run = self.begin(aggregate_timeout=30)
        with self.assertRaises(guard.GuardError) as refused: self.begin(repeat_reason='investigate environment')
        self.assertEqual(refused.exception.reason, 'UNKNOWN')
        self.store.reconcile(run.run_id, actor='fixture', reason='owned process ended', evidence='owned log checked')
        repeated = self.begin(repeat_reason='observed environment change', aggregate_timeout=30)
        self.finish(repeated)
        with self.assertRaises(guard.GuardError): self.begin(repeat_reason='third attempt', aggregate_timeout=30)
        self.assertFalse((self.store.root / 'runs' / run.run_id / 'final.json').exists())

    def test_repeat_cannot_enlarge_first_aggregate_declaration(self):
        run = self.begin(aggregate_timeout=10); self.finish(run)
        with self.assertRaises(guard.GuardError) as refused:
            self.begin(repeat_reason='fresh evidence required', aggregate_timeout=20)
        self.assertEqual(refused.exception.reason, 'BUDGET_EXHAUSTED')

    def test_metadata_lock_wait_is_finite(self):
        fd = os.open(self.store.root / '.lock', os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            started = time.monotonic()
            with mock.patch.object(guard, 'LOCK_SECONDS', .05), self.assertRaises(guard.GuardError) as refused:
                self.begin()
            self.assertEqual(refused.exception.reason, 'TRANSIENT_INFRA')
            self.assertLess(time.monotonic() - started, 1)
        finally:
            os.close(fd)

    def test_missing_final_inspection_is_unknown_and_read_does_not_restore_namespace(self):
        run = self.begin()
        self.assertEqual(self.store.inspect(run.start_ref)['execution'], 'UNKNOWN')
        runs = self.store.root / 'runs'
        moved = self.store.root / 'held-runs'; runs.rename(moved)
        with self.assertRaises(guard.GuardError): self.store.load_ref(run.start_ref)
        self.assertFalse(runs.exists())
        moved.rename(runs)

    def test_runtime_drift_invalidates_finished_invocation(self):
        run = self.begin()
        self.tool.write_bytes(b'changed tool')
        reference = self.finish(run)
        value = self.store.load_ref(reference)
        self.assertEqual((value['result'], value['reason']), ('NO_RESULT', 'INPUT_CHANGED'))

    def test_completed_duplicate_is_refused_before_any_new_run(self):
        run = self.begin(); self.finish(run)
        with self.assertRaises(guard.GuardError) as refused: self.begin()
        self.assertEqual(refused.exception.reason, 'BUDGET_EXHAUSTED')
        self.assertEqual(len(list((self.store.root / 'runs').iterdir())), 1)

    def test_tampered_prior_final_cannot_purchase_extra_budget(self):
        run = self.begin(); reference = self.finish(run)
        path = self.store.root / 'runs' / run.run_id / 'final.json'
        value = json.loads(path.read_text()); value['elapsed_seconds'] = -100
        path.write_text(json.dumps(value))
        with self.assertRaises(guard.GuardError): self.store.load_ref(reference)
        with self.assertRaises(guard.GuardError):
            self.begin(repeat_reason='environment changed', aggregate_timeout=1)

    def test_ar_ug_01_missing_start_cannot_authorize_repeat(self):
        run = self.begin(); self.finish(run)
        path = self.store.root / 'runs' / run.run_id / 'start.json'
        path.rename(path.with_name('preserved-start.json'))
        with self.assertRaises(guard.GuardError): self.begin(repeat_reason='owned diagnostic repeat')
        self.assertEqual(len(list((self.store.root / 'runs').iterdir())), 1)

    def test_ar_ug_01_attempt_budget_must_match_immutable_start(self):
        run = self.begin(aggregate_timeout=10)
        with mock.patch.object(guard.time, 'monotonic', return_value=run.began + 11):
            run.finish(execution='INTERRUPTED', result='NO_RESULT', reason='TIMEOUT')
        self.store.reconcile(run.run_id, actor='fixture', reason='owned child is gone', evidence='owned receipt checked')
        path = next((self.store.root / 'purposes').glob('*/attempt-1.json'))
        value = json.loads(path.read_text()); value['aggregate_timeout'] = 20
        path.write_text(json.dumps(value))
        with self.assertRaises(guard.GuardError): self.begin(repeat_reason='owned repeat', aggregate_timeout=20)
        self.assertEqual(len(list((self.store.root / 'runs').iterdir())), 1)

    def test_ar_ug_01_malformed_reconciliation_cannot_authorize_repeat(self):
        run = self.begin()
        path = self.store.root / 'runs' / run.run_id / 'reconciled.json'
        path.write_text('{}'); path.chmod(0o600)
        with self.assertRaises(guard.GuardError): self.begin(repeat_reason='owned repeat')

    def test_ar_ug_02_corrupt_pool_history_cannot_be_blessed_by_reconcile(self):
        run = self.begin()
        self.store.acquire_pool('codex', 'fixture-pool', run.run_id)
        pool = next((self.store.root / 'pools').iterdir())
        index_before = (pool / 'head.json').read_bytes()
        index = json.loads(index_before)
        event = pool / 'events' / (index['event'] + '.json')
        value = json.loads(event.read_text()); value['at'] = 'changed timestamp'
        event.write_text(json.dumps(value))
        with self.assertRaises(guard.GuardError):
            self.store.reconcile(run.run_id, actor='fixture', reason='owned process ended', evidence='owned inspection')
        self.assertEqual((pool / 'head.json').read_bytes(), index_before)
        self.assertFalse((self.store.root / 'runs' / run.run_id / 'reconciled.json').exists())

    def test_missing_referenced_run_is_not_recreated(self):
        reference = {'run_id': 'd' * 32, 'record': 'final', 'sha256': 'e' * 64}
        with self.assertRaises(guard.GuardError): self.store.load_ref(reference)
        self.assertFalse((self.store.root / 'runs' / reference['run_id']).exists())

    def test_receipt_permissions_hardlinks_and_unsupported_schema_refuse(self):
        run = self.begin(); reference = self.finish(run)
        path = self.store.root / 'runs' / run.run_id / 'final.json'
        before = path.read_bytes()
        path.chmod(0o644)
        with self.assertRaises(guard.GuardError): self.store.load_ref(reference)
        path.chmod(0o600)
        alias = self.root / 'alias'; os.link(path, alias)
        with self.assertRaises(guard.GuardError): self.store.load_ref(reference)
        alias.unlink()
        value = json.loads(before); value['schema'] = 2; path.write_text(json.dumps(value))
        changed = {**reference, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
        with self.assertRaises(guard.GuardError): self.store.load_ref(changed)

    def test_zero_tests_cannot_be_success_and_failure_reuse_is_not_a_gate(self):
        run = self.begin()
        reference = run.finish(execution='COMPLETED', result='CHECK_OK', reason='NONE', exit_code=0, count=0)
        final = self.store.load_ref(reference)
        self.assertEqual((final['result'], final['reason']), ('NO_RESULT', 'INVALID_OUTPUT'))
        self.assertFalse(self.store.reuse(self.subject, self.identity, reference)['eligible'])
        with self.assertRaises(guard.GuardError): self.store.check_gate(self.subject, reference)

    def test_review_gate_uses_subject_not_argv_and_refuses_wrong_stage(self):
        review_id = guard.invocation_identity(self.subject, purpose='inspect', argv=['review-command'], cwd=self.repo)
        run = self.store.begin(self.subject, review_id, owner='fixture', label='review', timeout=10,
                               kind='review', minimum_bytes=0)
        reference = run.finish(execution='COMPLETED', result='CHECK_OK', reason='NONE', exit_code=0,
                               review={'stage': 'CODE_INSPECTION', 'verdict': 'ACCEPT', 'findings': []})
        with self.assertRaises(guard.GuardError): self.store.check_gate(self.subject, reference)
        self.store.settle_review(reference)
        full = self.store.begin(self.subject, self.identity, owner='fixture', label='full', timeout=10,
                                kind='full', gate=reference, minimum_bytes=0)
        self.assertEqual(full.start['gate'], reference)
        changed = guard.Subject(self.subject); changed['fingerprint'] = 'f' * 64
        with self.assertRaises(guard.GuardError): self.store.check_gate(changed, reference)

    def test_low_disk_and_probe_failure_make_not_started_receipts(self):
        with mock.patch.object(guard.shutil, 'disk_usage', return_value=type('Space', (), {'free': 0})()):
            with self.assertRaises(guard.GuardError) as refused:
                self.store.begin(self.subject, self.identity, owner='fixture', label='low-disk',
                                  timeout=10, kind='focused', minimum_bytes=1)
        final = self.store.load_ref(refused.exception.reference)
        self.assertEqual((final['execution'], final['reason']), ('NOT_STARTED', 'LOW_DISK'))
        other = guard.invocation_identity(self.subject, purpose='probe', argv=['public-command'], cwd=self.repo)
        with mock.patch.object(guard.shutil, 'disk_usage', side_effect=OSError('owned probe failure')):
            with self.assertRaises(guard.GuardError) as refused:
                self.store.begin(self.subject, other, owner='fixture', label='probe', timeout=10,
                                  kind='focused', minimum_bytes=1)
        self.assertEqual(self.store.load_ref(refused.exception.reference)['execution'], 'NOT_STARTED')

    def test_pool_quota_shared_across_models_and_ack_preserves_history(self):
        run = self.begin()
        self.store.acquire_pool('codex', 'fixture-pool', run.run_id)
        self.store.release_pool('codex', 'fixture-pool', run.run_id, reason='QUOTA', account_cooldown=True)
        other = guard.invocation_identity(self.subject, purpose='other-model', argv=['other-model'], cwd=self.repo)
        next_run = self.store.begin(self.subject, other, owner='fixture', label='other', timeout=10, minimum_bytes=0)
        with self.assertRaises(guard.GuardError) as refused:
            self.store.acquire_pool('codex', 'fixture-pool', next_run.run_id)
        self.assertEqual(refused.exception.reason, 'QUOTA')
        before = list((self.store.root / 'pools').glob('*/events/*.json'))
        self.store.ack_pool('codex', 'fixture-pool', actor='fixture', reason='availability changed', evidence='owned check')
        after = list((self.store.root / 'pools').glob('*/events/*.json'))
        self.assertTrue(set(before) < set(after))
        self.store.acquire_pool('codex', 'fixture-pool', next_run.run_id)

    def test_parallel_processes_cannot_duplicate_one_reservation(self):
        script = ('import sys\nfrom pathlib import Path\n'
                  f'sys.path.insert(0,{str(HOOKS)!r})\nimport usage_guard as g\n'
                  f's=g.Subject(schema=1,fingerprint={"a"*64!r},reusable=True)\n'
                  f's.repo=Path({str(self.repo)!r});s.manifest={{}};s.probe=lambda:s\n'
                  'i=g.invocation_identity(s,purpose="simultaneous",argv=["same"],cwd=s.repo)\n'
                  f'store=g.UsageStore({str(self.store.root)!r})\n'
                  'try:\n    run=store.begin(s,i,owner="fixture",label="parallel",timeout=10,minimum_bytes=0)\n'
                  'except g.GuardError: raise SystemExit(2)\n'
                  'raise SystemExit(0)\n')
        children = [subprocess.Popen([sys.executable, '-c', script], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    for _ in range(2)]
        outcomes = []
        try:
            for child in children:
                child.communicate(timeout=10); outcomes.append(child.returncode)
        finally:
            for child in children:
                if child.poll() is None: child.kill(); child.communicate(timeout=5)
        self.assertEqual(sorted(outcomes), [0, 2])
        self.assertEqual(len(list((self.store.root / 'runs').iterdir())), 1)


class SubjectIdentity(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='usage-subject-'); self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        self.env = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
        self.env.update(HOME=str(self.repo), GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM='1')
        self.git('init', '-q', '-b', 'main'); self.git('config', 'user.name', 'Fixture')
        self.git('config', 'user.email', 'fixture@example.invalid')
        (self.repo / 'app.txt').write_text('tracked fixture\n')
        self.git('add', 'app.txt'); self.git('commit', '-qm', 'baseline')
        self.tool = self.repo.parent / (self.repo.name + '-tool')
        self.tool.write_bytes(b'owned tool v1'); self.addCleanup(self.tool.unlink)
        self.tool.chmod(0o700)
        self.manifest = {'schema': 1, 'files': [], 'revisions': {'config': 'fixture-v1'},
                         'complete': True, 'deterministic': True, 'public_arguments': True,
                         'toolchain': {'fixture': {'path': str(self.tool), 'public': True,
                                      'sha256': hashlib.sha256(self.tool.read_bytes()).hexdigest()}}}

    def git(self, *args):
        return subprocess.run(['git', *args], cwd=self.repo, env=self.env, check=True,
                              text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def subject(self):
        with mock.patch.dict(os.environ, self.env, clear=True):
            return guard.capture_subject(self.repo, self.manifest)

    def test_hidden_index_flags_never_produce_reusable_subject(self):
        for flag in ('assume-unchanged', 'skip-worktree'):
            with self.subTest(flag=flag):
                self.git('update-index', '--' + flag, 'app.txt')
                (self.repo / 'app.txt').write_text('hidden edit\n')
                self.assertEqual(self.git('status', '--porcelain').stdout, '')
                with self.assertRaises(guard.GuardError): self.subject()
                (self.repo / 'app.txt').write_text('tracked fixture\n')
                self.git('update-index', '--no-' + flag, 'app.txt')

    def test_declared_toolchain_mutation_invalidates_identity(self):
        before = self.subject()
        self.assertTrue(before['reusable'])
        self.tool.write_bytes(b'owned tool v2')
        after = self.subject()
        self.assertNotEqual(before['fingerprint'], after['fingerprint'])
        self.assertFalse(after['reusable'])

    def test_declared_instruction_fixture_config_and_head_changes_invalidate(self):
        declared = self.repo.parent / (self.repo.name + '-instructions')
        declared.write_text('public fixture input1'); self.addCleanup(declared.unlink)
        self.manifest['files'] = [{'label': 'instructions-config-fixture', 'path': str(declared), 'public': True}]
        before = self.subject(); declared.write_text('public fixture input2')
        after = self.subject(); self.assertNotEqual(before['fingerprint'], after['fingerprint'])
        self.git('commit', '--allow-empty', '-qm', 'new reviewed head')
        self.assertNotEqual(after['fingerprint'], self.subject()['fingerprint'])

    def test_nonpublic_input_is_not_read_or_hashed(self):
        private = self.repo.parent / (self.repo.name + '-private')
        self.manifest['files'] = [{'label': 'secret-dependent', 'path': str(private), 'public': False}]
        self.assertFalse(self.subject()['reusable'])
        self.assertFalse(private.exists())

    def test_declared_environment_and_manifest_file_are_reprobed(self):
        self.manifest['environment'] = {'LANG': 'C'}
        path = self.repo.parent / (self.repo.name + '-manifest')
        path.write_text(json.dumps(self.manifest)); path.chmod(0o600); self.addCleanup(path.unlink)
        with mock.patch.dict(os.environ, {**self.env, 'LANG': 'C'}, clear=True):
            subject = guard.capture_subject(self.repo, path)
            self.assertTrue(subject['reusable'])
            with mock.patch.dict(os.environ, {'LANG': 'fr'}):
                self.assertNotEqual(subject['fingerprint'], subject.probe()['fingerprint'])
            value = json.loads(path.read_text()); value['revisions']['config'] = 'v2'
            path.write_text(json.dumps(value))
            self.assertNotEqual(subject['fingerprint'], subject.probe()['fingerprint'])


class ResultContracts(unittest.TestCase):
    def test_c1_prior_or_nonterminal_summaries_cannot_satisfy_current_run(self):
        cases = [
            ('unittest', 'Ran 2 tests in 0.01s\n\nOK\nRan 0 tests in 0.01s\n\nOK'),
            ('pytest', 'Previous run: 3 passed in 0.01s\n\nno tests ran in 0.01s'),
            ('go-json', '\n'.join(json.dumps(event) for event in (
                {'Action': 'start', 'Package': 'done'},
                {'Action': 'run', 'Package': 'done', 'Test': 'TestReady'},
                {'Action': 'pass', 'Package': 'done', 'Test': 'TestReady'},
                {'Action': 'pass', 'Package': 'done'},
                {'Action': 'start', 'Package': 'unfinished'}))),
        ]
        for adapter, output in cases:
            with self.subTest(adapter=adapter):
                self.assertEqual(guard.command_result(adapter, 0, output)[0], 'NO_RESULT')

    def test_c2_pytest_errors_and_interruption_are_not_code_findings(self):
        for code, output in (
                (1, '================ 1 passed, 1 error in 0.01s ================'),
                (2, '1 passed in 0.01s\n!!!!!!!! KeyboardInterrupt !!!!!!!!')):
            with self.subTest(code=code):
                self.assertEqual(guard.command_result('pytest', code, output)[0:2], ('NO_RESULT', 'UNKNOWN'))

    def test_vacuous_and_false_success_controls(self):
        self.assertEqual(guard.command_result('unittest', 0, '', 'Ran 0 tests in 0.01s\n\nOK')[0], 'NO_RESULT')
        self.assertEqual(guard.command_result('unittest', 0, '', 'Ran 1 test in 0.01s\n\nFAILED (failures=1)')[0], 'NO_RESULT')
        self.assertEqual(guard.command_result('unittest', 0, '', 'Ran 2 tests in 0.01s\n\nOK (skipped=2)')[0], 'NO_RESULT')
        self.assertEqual(guard.command_result('unittest', 0, '', 'Ran 2 tests in 0.01s\n\nOK'), ('CHECK_OK', 'NONE', 2))

    def test_compile_error_is_not_automatically_a_code_repair_failure(self):
        self.assertEqual(guard.command_result('go-json', 1, '{"Action":"fail","Package":"fixture"}')[0], 'NO_RESULT')
        mixed = '\n'.join(json.dumps(event) for event in (
            {'Action': 'start', 'Package': 'good'},
            {'Action': 'run', 'Package': 'good', 'Test': 'TestGood'},
            {'Action': 'pass', 'Package': 'good', 'Test': 'TestGood'},
            {'Action': 'pass', 'Package': 'good'},
            {'Action': 'start', 'Package': 'build-error'},
            {'Action': 'fail', 'Package': 'build-error'}))
        self.assertEqual(guard.command_result('go-json', 1, mixed)[0:2], ('NO_RESULT', 'UNKNOWN'))
        self.assertEqual(guard.command_result('unittest', 1, '', 'Ran 1 test in 0.01s\n\nFAILED (errors=1)')[0:2],
                         ('NO_RESULT', 'UNKNOWN'))

    def test_terminal_positive_and_actual_failure_contracts_remain_supported(self):
        self.assertEqual(guard.command_result('pytest', 0, '=== 2 passed in 0.01s ==='), ('CHECK_OK', 'NONE', 2))
        self.assertEqual(guard.command_result('pytest', 1, '=== 1 passed, 1 failed in 0.01s ==='),
                         ('CHECK_FAILED', 'CODE_FINDINGS', 2))
        for failed in (False, True):
            events = [{'Action': 'start', 'Package': 'fixture'},
                      {'Action': 'run', 'Package': 'fixture', 'Test': 'TestReady'},
                      {'Action': 'fail' if failed else 'pass', 'Package': 'fixture', 'Test': 'TestReady'},
                      {'Action': 'fail' if failed else 'pass', 'Package': 'fixture'}]
            text = '\n'.join(json.dumps(event) for event in events)
            expected = ('CHECK_FAILED', 'CODE_FINDINGS', 1) if failed else ('CHECK_OK', 'NONE', 1)
            self.assertEqual(guard.command_result('go-json', int(failed), text), expected)


class LiveReceipts(unittest.TestCase):
    def setUp(self):
        self.fixture = SubjectIdentity('test_declared_toolchain_mutation_invalidates_identity')
        self.fixture.setUp(); self.addCleanup(self.fixture.doCleanups)
        self.repo = self.fixture.repo
        self.runtime = self.repo.parent / (self.repo.name + '-runtime')
        self.runtime.mkdir(mode=0o700); self.addCleanup(shutil.rmtree, self.runtime)
        for name in ('usage_guard.py', 'git_safety.py', 'process.py', 'peer_review.py', 'report_file.py'):
            shutil.copyfile(HOOKS / name, self.runtime / name)
        self.store_path = self.repo.parent / (self.repo.name + '-state')
        self.addCleanup(lambda: shutil.rmtree(self.store_path) if self.store_path.exists() else None)
        self.manifest = self.repo.parent / (self.repo.name + '-manifest.json')
        data = {**self.fixture.manifest, 'public_arguments': False, 'command_revision': 'fixture-v1'}
        self.manifest.write_text(json.dumps(data)); self.manifest.chmod(0o600)
        self.addCleanup(self.manifest.unlink)
        self.env = {**self.fixture.env, 'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONNOUSERSITE': '1',
                    'AGENT_HARNESS_USAGE_DIR': str(self.store_path)}

    def command(self, *arguments):
        return [sys.executable, str(self.runtime / 'usage_guard.py'), *arguments]

    def arguments(self, purpose, command, *, adapter='command', kind='command', timeout=5):
        return ['check', '--repo', str(self.repo), '--manifest', str(self.manifest),
                '--purpose', purpose, '--owner', 'fixture', '--label', purpose,
                '--timeout', str(timeout), '--minimum-free-bytes', '0', '--kind', kind,
                '--adapter', adapter, '--success-exit', '0', '--', *command]

    def invoke(self, *arguments):
        result = subprocess.run(self.command(*arguments), env=self.env, capture_output=True, text=True, timeout=20)
        return result, json.loads(result.stdout)

    def test_actual_success_and_fresh_process_inspection_do_not_store_output_or_argv(self):
        sensitive = 'fixture_sensitive_output_58'
        result, value = self.invoke(*self.arguments('privacy', [sys.executable, '-c', f'print({sensitive!r})']))
        self.assertEqual((result.returncode, value['execution'], value['result']), (0, 'COMPLETED', 'CHECK_OK'))
        reference = value['reference']
        token = ':'.join(reference[key] for key in ('run_id', 'record', 'sha256'))
        inspected, current = self.invoke('inspect', '--reference', token)
        self.assertEqual((inspected.returncode, current['run_id']), (0, reference['run_id']))
        for path in self.store_path.rglob('*.json'):
            self.assertNotIn(sensitive, path.read_text())
            self.assertNotIn(f'print({sensitive!r})', path.read_text())

    def test_actual_test_failure_and_timeout_have_typed_final_receipts(self):
        tests = self.repo / 'tests'; tests.mkdir()
        (tests / 'test_fixture.py').write_text('import unittest\nclass Failure(unittest.TestCase):\n'
                                              '    def test_failure(self): self.assertTrue(False)\n')
        self.fixture.git('add', 'tests'); self.fixture.git('commit', '-qm', 'owned failing test')
        result, value = self.invoke(*self.arguments('failed-test', [sys.executable, '-m', 'unittest', 'discover', '-s', 'tests'],
                                                    adapter='unittest', kind='focused'))
        self.assertEqual((result.returncode, value['execution'], value['result'], value['reason'], value['observed_count']),
                         (3, 'COMPLETED', 'CHECK_FAILED', 'CODE_FINDINGS', 1))
        result, timed = self.invoke(*self.arguments('timeout', [sys.executable, '-c', 'import time;time.sleep(30)'], timeout=.1))
        self.assertEqual((result.returncode, timed['execution'], timed['result'], timed['reason']),
                         (3, 'INTERRUPTED', 'NO_RESULT', 'TIMEOUT'))

    def test_killed_supervisor_past_deadline_is_swept_from_the_cli(self):
        marker = self.repo.parent / (self.repo.name + '-swept-child.json')
        self.addCleanup(lambda: marker.unlink() if marker.exists() else None)
        program = ('import json,os,time\nfrom pathlib import Path\n'
                   f'Path({str(marker)!r}).write_text(json.dumps({{"group":os.getpgrp()}}))\n'
                   'time.sleep(30)\n')
        arguments = self.arguments('swept-owner', [sys.executable, '-c', program], timeout=2)
        env = {**self.env, 'AGENT_HARNESS_DEADLINE_GRACE': '0'}
        process = subprocess.Popen(self.command(*arguments), env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic() + 10
            while not marker.exists() and process.poll() is None and time.monotonic() < deadline: time.sleep(.02)
            self.assertTrue(marker.exists())
            process.kill(); process.communicate(timeout=5)
            group = json.loads(marker.read_text())['group']
            run_id = next((self.store_path / 'runs').iterdir()).name
            children = json.loads((self.store_path / 'runs' / run_id / 'children.json').read_text())['children']
            self.assertEqual(len(children), 1)
            # The recorded child is still alive: the sweep must not reconcile, even past the deadline.
            time.sleep(2.2)
            swept = subprocess.run(self.command('sweep'), env=env, capture_output=True, text=True, timeout=20)
            report = json.loads(swept.stdout)['reports'][0]
            self.assertEqual((swept.returncode, report['reconciled']), (0, False)); self.assertIn('child pid', report['why'])
            os.killpg(group, signal.SIGKILL)
            for _ in range(100):
                if guard.pid_exists(children[0]['pid']) is False: break
                time.sleep(.05)
            swept = subprocess.run(self.command('sweep'), env=env, capture_output=True, text=True, timeout=20)
            value = json.loads(swept.stdout)
            self.assertEqual((swept.returncode, value['reconciled']), (0, [run_id]))
            self.assertEqual(json.loads((self.store_path / 'runs' / run_id / 'reconciled.json').read_text())['kind'],
                             'automatic_reconciliation')
            again = subprocess.run(self.command('reconcile', '--run', run_id, '--auto'), env=env,
                                   capture_output=True, text=True, timeout=20)
            self.assertEqual(json.loads(again.stdout)['automatic_reconciliation']['why'], 'already reconciled')
            self.assertFalse((self.store_path / 'runs' / run_id / 'final.json').exists())
            repeated, refused = self.invoke(*arguments)
            self.assertEqual((repeated.returncode, refused['reason']), (2, 'BUDGET_EXHAUSTED'))
        finally:
            if process.poll() is None: process.kill(); process.communicate(timeout=5)
            if marker.exists():
                try: os.killpg(json.loads(marker.read_text())['group'], signal.SIGKILL)
                except ProcessLookupError: pass

    def test_killed_supervisor_missing_final_is_unknown_and_blocks_duplicate(self):
        marker = self.repo.parent / (self.repo.name + '-child.json')
        self.addCleanup(lambda: marker.unlink() if marker.exists() else None)
        program = ('import json,os,time\nfrom pathlib import Path\n'
                   f'Path({str(marker)!r}).write_text(json.dumps({{"group":os.getpgrp()}}))\n'
                   'time.sleep(30)\n')
        arguments = self.arguments('interrupted-owner', [sys.executable, '-c', program], timeout=40)
        process = subprocess.Popen(self.command(*arguments), env=self.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic() + 10
            while not marker.exists() and process.poll() is None and time.monotonic() < deadline: time.sleep(.02)
            self.assertTrue(marker.exists())
            process.kill(); process.communicate(timeout=5)
            entry = json.loads(next((self.store_path / 'purposes').glob('*/attempt-1.json')).read_text())
            reference = entry['start']; token = ':'.join(reference[key] for key in ('run_id', 'record', 'sha256'))
            inspected, value = self.invoke('inspect', '--reference', token)
            self.assertEqual((inspected.returncode, value['execution'], value['result']), (0, 'UNKNOWN', 'NO_RESULT'))
            repeated, refused = self.invoke(*arguments)
            self.assertEqual((repeated.returncode, refused['reason']), (2, 'UNKNOWN'))
            self.assertFalse((self.store_path / 'runs' / reference['run_id'] / 'final.json').exists())
        finally:
            if process.poll() is None: process.kill(); process.communicate(timeout=5)
            if marker.exists():
                try: os.killpg(json.loads(marker.read_text())['group'], signal.SIGKILL)
                except ProcessLookupError: pass


class OwnerLiveness(StoreFixture):
    """GoodQA goodqa#14525: dead owners are reconciled automatically, auditable, never minted as success."""

    def child(self, seconds=30):
        process = subprocess.Popen([sys.executable, '-c', f'import time; time.sleep({seconds})'])
        self.addCleanup(lambda: (process.kill(), process.wait(timeout=5)) if process.poll() is None else None)
        return process

    def facts_for(self, process, **overrides):
        facts = guard.owner_process_facts(pid=process.pid)
        facts.update(overrides)
        return facts

    def begin_owned(self, facts, label='focused', **options):
        identity = (self.identity if label == 'focused'
                    else guard.invocation_identity(self.subject, purpose=label, argv=[label], cwd=self.repo))
        with mock.patch.object(guard, 'owner_process_facts', return_value=facts):
            return self.store.begin(self.subject, identity, owner='fixture', label=label, timeout=10,
                                    kind='focused', minimum_bytes=0, aggregate_timeout=30, **options)

    def future(self):
        return mock.patch.object(guard, 'now_utc', return_value=datetime.now(timezone.utc) + timedelta(days=1))

    def reconciled_path(self, run):
        return self.store.root / 'runs' / run.run_id / 'reconciled.json'

    def test_start_records_owner_process_facts_and_deadline(self):
        run = self.begin()
        start = self.store.load_ref(run.start_ref)
        owner = start['owner_process']
        self.assertEqual(set(owner), {'pid', 'host', 'boot_id', 'process_started', 'deadline'})
        self.assertEqual((owner['pid'], owner['host']), (os.getpid(), guard.host_identity()))
        self.assertTrue(owner['process_started'].startswith(('ps:', 'proc:')))
        self.assertIsInstance(owner['boot_id'], (str, type(None)))
        started = datetime.fromisoformat(start['started_at']); deadline = datetime.fromisoformat(owner['deadline'])
        self.assertAlmostEqual((deadline - started).total_seconds(), start['timeout'] + guard.DEADLINE_GRACE, delta=1)

    def test_boot_identity_is_a_tagged_boot_session_id(self):
        value = guard.boot_identity()
        if value is None: self.skipTest('no boot identity source on this platform')
        self.assertTrue(value.startswith(('bootsession:', 'procboot:')))
        self.assertNotIn('sec =', value)  # never kern.boottime, which moves with clock steps
        with mock.patch.dict(os.environ, {'TZ': 'America/New_York'}): self.assertEqual(guard.boot_identity(), value)

    def test_process_start_token_is_stable_across_time_zones(self):
        alive = self.child()
        with mock.patch.dict(os.environ, {'TZ': 'UTC'}): utc = guard.process_start_token(alive.pid)
        with mock.patch.dict(os.environ, {'TZ': 'America/New_York'}): east = guard.process_start_token(alive.pid)
        self.assertIsNotNone(utc); self.assertEqual(utc, east)

    def test_auto_reconcile_dead_owner_past_deadline_is_audited_and_never_success(self):
        child = self.child(); facts = self.facts_for(child)
        run = self.begin_owned(facts)
        self.store.acquire_pool('codex', 'fixture-pool', run.run_id)
        child.kill(); child.wait(timeout=5)
        # NEG-1: dead but not yet past the deadline stays uncertain, nothing is written.
        with self.assertRaises(guard.GuardError) as refused: self.begin(repeat_reason='retry', aggregate_timeout=30)
        self.assertEqual(refused.exception.reason, 'UNKNOWN')
        self.assertFalse(self.reconciled_path(run).exists())
        with self.future():
            report = self.store.auto_reconcile(run.run_id)
        self.assertTrue(report['reconciled']); self.assertEqual(report['liveness']['state'], 'DEAD')
        record = json.loads(self.reconciled_path(run).read_text())
        self.assertEqual((record['kind'], record['actor'], record['execution'], record['result']),
                         ('automatic_reconciliation', 'usage_guard.auto', 'UNKNOWN', 'NO_RESULT'))
        self.assertIn(str(child.pid), record['evidence'])
        self.assertFalse((self.store.root / 'runs' / run.run_id / 'final.json').exists())
        self.assertFalse((self.store.root / 'runs' / run.run_id / 'completion.json').exists())
        self.assertFalse(self.store.reuse(self.subject, self.identity, run.start_ref).get('eligible'))
        # NEG-7: the reconciled run counts as an attempt (its launches are unknown), so the retry
        # needs a repeat reason, but no manual reconcile. The pool was released.
        with self.assertRaises(guard.GuardError) as refused: self.begin(aggregate_timeout=30)
        self.assertEqual(refused.exception.reason, 'BUDGET_EXHAUSTED')
        other = self.begin(repeat_reason='owner died', aggregate_timeout=30)
        self.store.acquire_pool('codex', 'fixture-pool', other.run_id)
        events = [json.loads(path.read_text())['action'] for path in (self.store.root / 'pools').glob('*/events/*.json')]
        self.assertIn('RECONCILED', events)
        with self.future():
            self.assertEqual(self.store.auto_reconcile(run.run_id)['why'], 'already reconciled')

    def test_begin_and_acquire_pool_auto_reconcile_inline(self):
        child = self.child(); facts = self.facts_for(child)
        run = self.begin_owned(facts)
        self.store.acquire_pool('codex', 'fixture-pool', run.run_id)
        child.kill(); child.wait(timeout=5)
        with self.future():
            retry = self.begin(repeat_reason='owner died', aggregate_timeout=30)
            self.store.acquire_pool('codex', 'fixture-pool', retry.run_id)
        self.assertTrue(self.reconciled_path(run).exists())

    def test_live_other_host_malformed_and_legacy_owners_are_never_reconciled(self):
        alive = self.child()
        cases = {
            'alive': (self.facts_for(alive), 'ALIVE', 'process alive'),
            'other-host': (self.facts_for(alive, host='another-host.example'), 'UNCERTAIN', 'other host'),
            'legacy-none': (None, 'UNCERTAIN', 'owner facts missing'),
            'pid-overflow': (self.facts_for(alive, pid=2 ** 40), 'UNCERTAIN', 'owner facts missing'),
            'pid-text': (self.facts_for(alive, pid='7'), 'UNCERTAIN', 'owner facts missing'),
            'host-oversize': (self.facts_for(alive, host='h' * 10000), 'UNCERTAIN', 'owner facts missing'),
            'deadline-text': (self.facts_for(alive, deadline='soon'), 'UNCERTAIN', 'deadline malformed'),
            'token-scheme': (self.facts_for(alive, process_started='other:1'), 'UNCERTAIN', 'scheme differs'),
        }
        for label, (facts, expected, why) in cases.items():
            with self.subTest(label):
                run = self.begin_owned(facts, label=label)
                if label == 'deadline-text':
                    # begin() overwrites the deadline; craft the malformed one through the liveness probe.
                    start = {**self.store.load_ref(run.start_ref)}
                    start['owner_process'] = {**start['owner_process'], 'deadline': 'soon'}
                    report = {'reconciled': False, 'liveness': guard.owner_liveness(start)}
                else:
                    with self.future(): report = self.store.auto_reconcile(run.run_id)
                self.assertFalse(report['reconciled'])
                self.assertEqual(report['liveness']['state'], expected)
                self.assertIn(why, report['liveness']['why'])
                self.assertFalse(self.reconciled_path(run).exists())

    def test_reused_pid_and_rebooted_host_are_dead(self):
        alive = self.child()
        real = guard.process_start_token(alive.pid)
        reused = self.begin_owned(self.facts_for(alive, process_started=real + 'x'), label='reused')
        with self.future(): report = self.store.auto_reconcile(reused.run_id)
        self.assertTrue(report['reconciled']); self.assertIn('pid reused', report['liveness']['why'])
        rebooted = self.begin_owned(self.facts_for(alive, boot_id='bootsession:before'), label='rebooted')
        with self.future(), mock.patch.object(guard, 'boot_identity', return_value='bootsession:after'):
            report = self.store.auto_reconcile(rebooted.run_id)
        self.assertTrue(report['reconciled']); self.assertIn('rebooted', report['liveness']['why'])
        # F24: an id from another build or scheme (for example the old kern.boottime text) never proves a reboot.
        old_build = self.begin_owned(self.facts_for(alive, boot_id='{ sec = 1, usec = 2 } Wed Nov 4 2026'), label='old-build')
        with self.future(), mock.patch.object(guard, 'boot_identity', return_value='bootsession:after'):
            report = self.store.auto_reconcile(old_build.run_id)
        self.assertFalse(report['reconciled']); self.assertIn('scheme differs', report['liveness']['why'])
        unknown_boot = self.begin_owned(self.facts_for(alive, boot_id='bootsession:before'), label='unknown-boot')
        alive.kill(); alive.wait(timeout=5)
        with self.future(), mock.patch.object(guard, 'boot_identity', return_value=None):
            report = self.store.auto_reconcile(unknown_boot.run_id)
        self.assertFalse(report['reconciled']); self.assertEqual(report['liveness']['state'], 'UNCERTAIN')

    def test_recorded_child_must_be_dead_too(self):
        supervisor = self.child(); reviewer = self.child()
        run = self.begin_owned(self.facts_for(supervisor))
        run.note_child(reviewer)
        children = json.loads((self.store.root / 'runs' / run.run_id / 'children.json').read_text())['children']
        self.assertEqual(children[0]['pid'], reviewer.pid)
        supervisor.kill(); supervisor.wait(timeout=5)
        with self.future(): report = self.store.auto_reconcile(run.run_id)
        self.assertFalse(report['reconciled']); self.assertIn('child pid %d alive' % reviewer.pid, report['liveness']['why'])
        reviewer.kill(); reviewer.wait(timeout=5)
        with self.future(): self.assertTrue(self.store.auto_reconcile(run.run_id)['reconciled'])
        with self.assertRaises(guard.GuardError): run.note_child(2 ** 40)

    def test_child_with_live_group_members_is_not_dead(self):
        supervisor = self.child()
        # A child that forks a grandchild: the leader dies, the grandchild stays in the leader's group.
        program = ('import subprocess, sys, time\n'
                   'subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])\n'
                   'time.sleep(30)\n')
        leader = subprocess.Popen([sys.executable, '-c', program], start_new_session=True)
        def cleanup():
            try: os.killpg(leader.pid, signal.SIGKILL)
            except ProcessLookupError: pass
        self.addCleanup(cleanup)
        run = self.begin_owned(self.facts_for(supervisor))
        run.note_child(leader)
        supervisor.kill(); supervisor.wait(timeout=5)
        time.sleep(.5)
        leader.kill(); leader.wait(timeout=5)
        self.assertIs(guard.pid_exists(leader.pid), False); self.assertIs(guard.group_empty(leader.pid), False)
        with self.future(): report = self.store.auto_reconcile(run.run_id)
        self.assertFalse(report['reconciled']); self.assertIn('process group still has members', report['liveness']['why'])
        os.killpg(leader.pid, signal.SIGKILL)
        for _ in range(100):
            if guard.group_empty(leader.pid): break
            time.sleep(.05)
        with self.future(): self.assertTrue(self.store.auto_reconcile(run.run_id)['reconciled'])

    def test_failed_child_record_kills_the_child(self):
        import process as process_module
        run = self.begin()
        seen = {}
        def failing(child):
            seen['pid'] = child.pid
            raise guard.GuardError('TRANSIENT_INFRA', 'Metadata lock is busy; no command was launched')
        with self.assertRaises(guard.GuardError):
            process_module.run([sys.executable, '-c', 'import time; time.sleep(30)'], timeout=5, on_spawn=failing)
        for _ in range(100):
            if guard.pid_exists(seen['pid']) is False: break
            time.sleep(.05)
        self.assertIs(guard.pid_exists(seen['pid']), False)
        self.assertFalse((self.store.root / 'runs' / run.run_id / 'children.json').exists())

    def test_malformed_owner_facts_never_crash_a_sweep(self):
        alive = self.child()
        for label, facts in {'pid-overflow': self.facts_for(alive, pid=2 ** 40), 'host-oversize': self.facts_for(alive, host='h' * 10000),
                             'boot-odd': self.facts_for(alive, boot_id=['x'])}.items():
            self.begin_owned(facts, label=label)
        with self.future(): reports = self.store.sweep()
        self.assertEqual(len(reports), 3); self.assertFalse(any(r['reconciled'] for r in reports))

    def test_finish_after_reconciliation_discards_the_late_result(self):
        child = self.child()
        run = self.begin_owned(self.facts_for(child))
        child.kill(); child.wait(timeout=5)
        with self.future(): self.assertTrue(self.store.auto_reconcile(run.run_id)['reconciled'])
        with self.assertRaises(guard.GuardError) as refused: self.finish(run)
        self.assertEqual(refused.exception.reason, 'UNKNOWN')
        self.assertFalse((self.store.root / 'runs' / run.run_id / 'final.json').exists())
        self.assertFalse((self.store.root / 'runs' / run.run_id / 'completion.json').exists())
        # R11: a reconciled run can neither take a pool nor record a new child.
        with self.assertRaises(guard.GuardError): self.store.acquire_pool('codex', 'fixture-pool', run.run_id)
        with self.assertRaises(guard.GuardError): run.note_child(self.child())
        done = self.begin_owned(self.facts_for(self.child()), label='done'); self.finish(done)
        with self.assertRaises(guard.GuardError): self.store.acquire_pool('codex', 'fixture-pool', done.run_id)
        with self.assertRaises(guard.GuardError): done.note_child(self.child())

    def test_completed_run_is_not_auto_reconciled_and_sweep_reports_every_run(self):
        done = self.begin(); self.finish(done)
        child = self.child()
        dead = self.begin_owned(self.facts_for(child), label='dead')
        child.kill(); child.wait(timeout=5)
        with self.future():
            self.assertEqual(self.store.auto_reconcile(done.run_id)['why'], 'completed')
            report = {item['run_id']: item for item in self.store.sweep()}
        self.assertEqual(report[done.run_id]['why'], 'completed')
        self.assertTrue(report[dead.run_id]['reconciled'])
        self.assertEqual(json.loads((self.store.root / 'runs' / done.run_id / 'final.json').read_text())['result'], 'CHECK_OK')

    def test_legacy_start_without_owner_process_key_stays_uncertain(self):
        run = self.begin(aggregate_timeout=30)
        directory = self.store.root / 'runs' / run.run_id
        legacy = json.loads((directory / 'start.json').read_bytes()); del legacy['owner_process']
        body = guard.encoded(legacy)
        (directory / 'start.json').write_bytes(body)
        purpose = next((self.store.root / 'purposes').glob('*/attempt-1.json'))
        entry = json.loads(purpose.read_text()); entry['start']['sha256'] = hashlib.sha256(body).hexdigest()
        purpose.write_bytes(guard.encoded(entry))
        self.assertNotIn('owner_process', self.store.load_ref(entry['start']))
        with self.future(): report = self.store.auto_reconcile(run.run_id)
        self.assertEqual((report['reconciled'], report['liveness']['state']), (False, 'UNCERTAIN'))
        with self.assertRaises(guard.GuardError) as refused: self.begin(repeat_reason='retry', aggregate_timeout=30)
        self.assertEqual(refused.exception.reason, 'UNKNOWN')

    def test_tampered_reconciliations_are_rejected(self):
        child = self.child()
        run = self.begin_owned(self.facts_for(child))
        child.kill(); child.wait(timeout=5)
        with self.future(): self.store.auto_reconcile(run.run_id)
        path = self.reconciled_path(run); original = json.loads(path.read_text())
        tampers = {'other-run': {**original, 'run_id': 'f' * 32}, 'wrong-kind': {**original, 'kind': 'blessing'},
                   'wrong-actor': {**original, 'actor': 'someone'},
                   'missing-field': {key: value for key, value in original.items() if key != 'evidence'},
                   'manual-success': {**original, 'kind': 'manual_reconciliation', 'actor': 'fixture', 'result': 'CHECK_OK'}}
        for label, record in tampers.items():
            with self.subTest(label):
                path.write_text(json.dumps(record))
                with self.assertRaises(guard.GuardError) as refused: self.begin(repeat_reason='retry', aggregate_timeout=30)
                self.assertEqual(refused.exception.reason, 'UNKNOWN')


class ZeroLaunchAttempts(StoreFixture):
    """GoodQA goodqa#14526: infrastructure refusals before any provider ran do not spend the repeat budget."""

    def refuse(self, run, *, launches=0, execution='NOT_STARTED', reason='TRANSIENT_INFRA', reported=()):
        return run.finish(execution=execution, result='NO_RESULT', reason=reason,
                          usage={'provider_launches': launches, 'reported': list(reported)})

    def test_zero_launch_attempts_do_not_need_a_repeat_reason_or_spend_the_cap(self):
        for reason in ('TRANSIENT_INFRA', 'LOW_DISK', 'QUOTA', 'AUTH'):
            self.refuse(self.begin(aggregate_timeout=60), reason=reason)
        first = self.begin(aggregate_timeout=60); self.finish(first)
        with self.assertRaises(guard.GuardError) as refused: self.begin(aggregate_timeout=60)
        self.assertEqual(refused.exception.reason, 'BUDGET_EXHAUSTED')
        second = self.begin(repeat_reason='new evidence', aggregate_timeout=60); self.finish(second)
        with self.assertRaises(guard.GuardError) as refused: self.begin(repeat_reason='third', aggregate_timeout=60)
        self.assertEqual(refused.exception.reason, 'BUDGET_EXHAUSTED')
        self.assertEqual(len(list((self.store.root / 'purposes').glob('*/attempt-*.json'))), 6)
        # Every run stays bound to exactly one of the slots beyond the historical two.
        self.assertEqual(self.store._owned_start(second.run_id)['run_id'], second.run_id)

    def test_launched_content_uncertain_and_odd_counters_still_count(self):
        cases = {'launched': dict(launches=1, execution='COMPLETED'),
                 'code-findings': dict(reason='CODE_FINDINGS'), 'input-changed': dict(reason='INPUT_CHANGED'),
                 'invalid-output': dict(reason='INVALID_OUTPUT'),
                 'completed-infra': dict(execution='COMPLETED', reason='TRANSIENT_INFRA'),
                 'reported-usage': dict(reported=[{'provider': 'codex', 'reported': {}}]),
                 'float-zero': dict(launches=0.0), 'text-zero': dict(launches='0'), 'bool-zero': dict(launches=False)}
        for label, options in cases.items():
            with self.subTest(label):
                identity = guard.invocation_identity(self.subject, purpose=label, argv=[label], cwd=self.repo)
                run = self.store.begin(self.subject, identity, owner='fixture', label=label, timeout=10,
                                       kind='focused', minimum_bytes=0, aggregate_timeout=60)
                self.refuse(run, **options)
                with self.assertRaises(guard.GuardError) as refused:
                    self.store.begin(self.subject, identity, owner='fixture', label=label, timeout=10,
                                     kind='focused', minimum_bytes=0, aggregate_timeout=60)
                self.assertEqual(refused.exception.reason, 'BUDGET_EXHAUSTED')
        second = self.begin(aggregate_timeout=60)
        self.store.reconcile(second.run_id, actor='fixture', reason='owner ended', evidence='owned log')
        with self.assertRaises(guard.GuardError) as refused: self.begin(aggregate_timeout=60)
        self.assertEqual(refused.exception.reason, 'BUDGET_EXHAUSTED')

    def test_zero_launch_cap_bounds_the_retry_loop_per_window(self):
        for _ in range(guard.ZERO_LAUNCH_CAP):
            self.refuse(self.begin(aggregate_timeout=600))
        with self.assertRaises(guard.GuardError) as refused: self.begin(aggregate_timeout=600)
        self.assertEqual(refused.exception.reason, 'BUDGET_EXHAUSTED')
        self.assertIn('infrastructure', refused.exception.message); self.assertIn('do not change the packet', refused.exception.message)
        later = datetime.now(timezone.utc) + timedelta(seconds=guard.ZERO_LAUNCH_WINDOW + 5)
        with mock.patch.object(guard, 'now_utc', return_value=later):
            run = self.begin(aggregate_timeout=600)
        self.assertEqual(self.store._owned_start(run.run_id)['run_id'], run.run_id)

    def test_attempt_slots_are_finite(self):
        with mock.patch.object(guard, 'ZERO_LAUNCH_CAP', 10 ** 6):
            for _ in range(guard.MAX_ATTEMPTS):
                self.refuse(self.begin(aggregate_timeout=86400))
            with self.assertRaises(guard.GuardError) as refused: self.begin(aggregate_timeout=86400)
        self.assertEqual(refused.exception.reason, 'BUDGET_EXHAUSTED'); self.assertIn('slots', refused.exception.message)

    def test_zero_launch_budget_still_spends_elapsed_and_cannot_enlarge(self):
        run = self.begin(aggregate_timeout=20)
        run.began -= 15
        self.refuse(run)
        with self.assertRaises(guard.GuardError) as refused: self.begin(aggregate_timeout=40)
        self.assertEqual(refused.exception.reason, 'BUDGET_EXHAUSTED')
        retry = self.begin(aggregate_timeout=20)
        self.assertLessEqual(retry.timeout, 5)
