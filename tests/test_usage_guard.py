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


HOOKS = Path(__file__).resolve().parents[1] / 'harness/hooks'
sys.path.insert(0, str(HOOKS))
import usage_guard as guard


class EvidenceStore(unittest.TestCase):
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
