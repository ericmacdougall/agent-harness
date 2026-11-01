"""Owned-state controls for declared identities and finite execution evidence."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
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
        self.identity = guard.invocation_identity(self.subject, purpose='focused', argv=['public-command'],
                                                  cwd=self.repo, toolchain={'fixture': 'v1'})

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
        self.assertNotIn('result', reused)
        self.assertNotIn('VERDICT: PASS', json.dumps(reused))

    def test_duplicate_and_missing_final_require_explicit_reconciliation(self):
        run = self.begin()
        with self.assertRaises(guard.GuardError) as refused: self.begin(repeat_reason='investigate environment')
        self.assertEqual(refused.exception.reason, 'UNKNOWN')
        self.store.reconcile(run.run_id, actor='fixture', reason='owned process ended', evidence='owned log checked')
        repeated = self.begin(repeat_reason='observed environment change', aggregate_timeout=30)
        self.finish(repeated)
        with self.assertRaises(guard.GuardError): self.begin(repeat_reason='third attempt', aggregate_timeout=30)
        self.assertFalse((self.store.root / 'runs' / run.run_id / 'final.json').exists())

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

    def test_pool_quota_shared_across_models_and_ack_preserves_history(self):
        run = self.begin()
        self.store.acquire_pool('codex', 'fixture-pool', run.run_id)
        self.store.release_pool('codex', 'fixture-pool', run.run_id, reason='QUOTA', account_cooldown=True)
        with self.assertRaises(guard.GuardError) as refused:
            self.store.acquire_pool('codex', 'fixture-pool', 'f' * 32)
        self.assertEqual(refused.exception.reason, 'QUOTA')
        before = list((self.store.root / 'pools').glob('*/events/*.json'))
        self.store.ack_pool('codex', 'fixture-pool', actor='fixture', reason='availability changed', evidence='owned check')
        after = list((self.store.root / 'pools').glob('*/events/*.json'))
        self.assertTrue(set(before) < set(after))
        self.store.acquire_pool('codex', 'fixture-pool', 'f' * 32)


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
                self.assertFalse(self.subject()['reusable'])
                (self.repo / 'app.txt').write_text('tracked fixture\n')
                self.git('update-index', '--no-' + flag, 'app.txt')

    def test_declared_toolchain_mutation_invalidates_identity(self):
        before = self.subject()
        self.assertTrue(before['reusable'])
        self.tool.write_bytes(b'owned tool v2')
        after = self.subject()
        self.assertNotEqual(before['fingerprint'], after['fingerprint'])
        self.assertFalse(after['reusable'])


class ResultContracts(unittest.TestCase):
    def test_vacuous_and_false_success_controls(self):
        self.assertEqual(guard.command_result('unittest', 0, '', 'Ran 0 tests in 0.01s\n\nOK')[0], 'NO_RESULT')
        self.assertEqual(guard.command_result('unittest', 0, '', 'Ran 1 test in 0.01s\n\nFAILED (failures=1)')[0], 'NO_RESULT')
        self.assertEqual(guard.command_result('unittest', 0, '', 'Ran 2 tests in 0.01s\n\nOK (skipped=2)')[0], 'NO_RESULT')
        self.assertEqual(guard.command_result('unittest', 0, '', 'Ran 2 tests in 0.01s\n\nOK'), ('CHECK_OK', 'NONE', 2))

    def test_compile_error_is_not_automatically_a_code_repair_failure(self):
        self.assertEqual(guard.command_result('go-json', 1, '{"Action":"fail","Package":"fixture"}')[0], 'NO_RESULT')

