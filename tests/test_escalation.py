"""Deterministic ladder state: classifier rows, replay, concurrency, resets, TOP permission (goodqa#14527)."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HOOKS = Path(__file__).resolve().parents[1] / 'harness/hooks'
sys.path.insert(0, str(HOOKS))
import escalation as esc
import model_tiers as tiers


def final(*, verdict=None, findings=(), launches=1, reason='NONE', execution='COMPLETED', result='NO_RESULT', head='a' * 40, salt=''):
    """A usage_guard FINAL receipt shaped like the real one; salt makes distinct bytes for distinct events."""
    review = None if verdict is None else {'stage': 'CODE_INSPECTION', 'verdict': verdict, 'findings': list(findings)}
    return json.dumps({'schema': 1, 'kind': 'final', 'run_id': 'b' * 32, 'evidence': 'EXECUTED', 'subject': {'head': head},
                       'invocation': {}, 'execution': execution, 'result': result, 'reason': reason,
                       'usage': {'provider_launches': launches, 'reported': []}, 'review': review, 'salt': salt},
                      sort_keys=True).encode()


class LedgerFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ladder-'); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'state'; self.root.mkdir(mode=0o700)
        self.policy = tiers.load_policy()
        self.ledger = esc.Ledger(self.root, self.policy)

    def block(self, task, *findings, salt=''):
        return self.ledger.record(task, final(verdict='BLOCK', findings=findings, salt=salt), kind='review', source='test')


class ClassifierTable(LedgerFixture):
    def test_every_row_of_the_fixed_table(self):
        rows = [
            ('material review finding', final(verdict='BLOCK', findings=['F1:a.py:logic']), 'review', 'FAIL'),
            ('review accepted', final(verdict='ACCEPT'), 'review', 'PASS'),
            ('block without findings', final(verdict='BLOCK'), 'review', 'NOT_COUNTED'),
            ('zero launch', final(verdict='BLOCK', findings=['F1'], launches=0, execution='NOT_STARTED', reason='TRANSIENT_INFRA'), 'review', 'NOT_COUNTED'),
            ('launched but infra', final(verdict='BLOCK', findings=['F1'], reason='TRANSIENT_INFRA'), 'review', 'NOT_COUNTED'),
            ('zero launch with a verdict', final(verdict='BLOCK', findings=['F1'], launches=0), 'review', 'NOT_COUNTED'),
            ('timeout unreconciled', final(reason='TIMEOUT', execution='INTERRUPTED'), 'review', 'NOT_COUNTED'),
            ('unknown', final(reason='UNKNOWN', execution='UNKNOWN'), 'review', 'NOT_COUNTED'),
            ('quota', final(reason='QUOTA', execution='NOT_STARTED', launches=0), 'review', 'NOT_COUNTED'),
            ('tests green', final(result='CHECK_OK', reason='NONE'), 'test', 'PASS'),
            ('tests red no claim', final(result='CHECK_FAILED', reason='CODE_FINDINGS', head='c' * 40), 'test', 'NOT_COUNTED'),
            ('tests red after claim', final(result='CHECK_FAILED', reason='CODE_FINDINGS', head='d' * 40), 'test', 'FAIL'),
            ('tests timeout', final(result='NO_RESULT', reason='TIMEOUT', execution='INTERRUPTED'), 'test', 'NOT_COUNTED'),
            ('not a final', json.dumps({'kind': 'start'}).encode(), 'review', 'NOT_COUNTED'),
            ('spec blocked', json.dumps({'verdict': 'BLOCK', 'findings': ['A1']}).encode(), 'spec_review', 'FAIL'),
            ('spec accepted', json.dumps({'verdict': 'ACCEPT'}).encode(), 'spec_review', 'PASS'),
            ('unknown kind', final(verdict='BLOCK', findings=['F1']), 'other', 'NOT_COUNTED'),
        ]
        for label, receipt, kind, expected in rows:
            with self.subTest(label):
                klass, why, _ = esc.classify(json.loads(receipt), kind=kind, claimed_heads=['d' * 40])
                self.assertEqual(klass, expected, why)

    def test_fingerprint_is_order_independent_and_normalized(self):
        a = esc.fingerprint(['F1:a.py:Logic', 'F2:b.py:security'])
        b = esc.fingerprint([{'id': 'f2', 'file': 'b.py', 'category': 'Security'}, 'F1:a.py:logic'])
        self.assertEqual(a, b)
        self.assertNotEqual(a, esc.fingerprint(['F1:a.py:logic']))
        self.assertIsNone(esc.fingerprint([]))

    def test_bounded_mutation_check_of_the_classifier(self):
        """Each hand-written mutant must be caught by the row table (failing-first control for the table)."""
        source = (HOOKS / 'escalation.py').read_text()
        mutants = {
            'infra counts': ("if reason in NOT_COUNTED_REASONS or", "if False and reason in NOT_COUNTED_REASONS or"),
            'zero launch counts': ("launches == 0):", "launches == -1):"),
            'block without findings counts': ("verdict') == 'BLOCK' and review.get('findings'):", "verdict') == 'BLOCK':"),
            'red tests without claim count': ("if reason == 'CODE_FINDINGS' and head and head in set(claimed_heads):", "if reason == 'CODE_FINDINGS':"),
            'accept is a fail': ("return 'PASS', 'review accepted', None", "return 'FAIL', 'review accepted', None"),
        }
        rows = [(final(verdict='BLOCK', findings=['F1'], reason='TRANSIENT_INFRA'), 'review', 'NOT_COUNTED'),
                (final(verdict='BLOCK', findings=['F1'], launches=0), 'review', 'NOT_COUNTED'),
                (final(verdict='BLOCK', findings=['F1'], launches=0, execution='NOT_STARTED', reason='TRANSIENT_INFRA'), 'review', 'NOT_COUNTED'),
                (final(verdict='BLOCK'), 'review', 'NOT_COUNTED'),
                (final(result='CHECK_FAILED', reason='CODE_FINDINGS', head='c' * 40), 'test', 'NOT_COUNTED'),
                (final(verdict='ACCEPT'), 'review', 'PASS')]
        for label, (old, new) in mutants.items():
            with self.subTest(label):
                self.assertEqual(source.count(old), 1, label)
                namespace = {'__file__': str(HOOKS / 'escalation.py'), '__name__': 'mutant'}
                exec(compile(source.replace(old, new), 'mutant', 'exec'), namespace)
                caught = any(namespace['classify'](json.loads(r), kind=k, claimed_heads=['d' * 40])[0] != expected
                             for r, k, expected in rows)
                self.assertTrue(caught, 'mutant survived: ' + label)


class Transitions(LedgerFixture):
    def test_two_genuine_failures_on_one_finding_advance_one_rung(self):
        self.assertEqual(self.ledger.status('t1')['rung'], 'R0')
        first = self.block('t1', 'F1:a.py:logic', salt='1')
        self.assertEqual((first['rung'], first['failures_at_rung']), ('R0', 1))
        second = self.block('t1', 'F1:a.py:logic', salt='2')
        self.assertEqual((second['rung'], second['failures_at_rung'], second['climbs']), ('R1', 0, 1))
        self.assertEqual(second['escalation']['from'], 'R0'); self.assertEqual(second['escalation']['to'], 'R1')
        notes = (self.root / 'notifications.jsonl').read_text().splitlines()
        self.assertEqual(json.loads(notes[-1])['event'], 'escalation')

    def test_new_finding_resets_the_count_at_the_same_rung(self):
        self.block('t2', 'F1:a.py:logic', salt='1')
        status = self.block('t2', 'F2:b.py:security', salt='2')
        self.assertEqual((status['rung'], status['failures_at_rung']), ('R0', 1))
        status = self.block('t2', 'F2:b.py:security', salt='3')
        self.assertEqual(status['rung'], 'R1')

    def test_infra_and_zero_launch_never_count(self):
        for salt, receipt in enumerate([
                final(verdict='BLOCK', findings=['F1'], launches=0, execution='NOT_STARTED', reason='TRANSIENT_INFRA', salt='a'),
                final(verdict='BLOCK', findings=['F1'], reason='QUOTA', salt='b'),
                final(reason='TIMEOUT', execution='INTERRUPTED', salt='c'),
                final(reason='UNKNOWN', execution='UNKNOWN', salt='d')]):
            status = self.ledger.record('t3', receipt, kind='review', source='test')
            self.assertEqual((status['rung'], status['failures_at_rung']), ('R0', 0))
        self.assertEqual(self.ledger.status('t3')['rung'], 'R0')
        self.assertEqual(self.ledger.load('t3')['launches'], 0)

    def test_replay_is_idempotent(self):
        receipt = final(verdict='BLOCK', findings=['F1'], salt='same')
        self.ledger.record('t4', receipt, kind='review', source='test')
        again = self.ledger.record('t4', receipt, kind='review', source='test')
        self.assertTrue(again.get('replayed')); self.assertEqual(again['failures_at_rung'], 1)
        self.assertEqual(len(self.ledger.load('t4')['events']), 1)

    def test_ladder_skips_review_only_rungs_and_stops_at_the_top(self):
        rungs = []
        for n in range(12):
            rungs.append(self.block('t5', 'F1', salt=str(n))['rung'])
        self.assertEqual(rungs, ['R0', 'R1', 'R1', 'R2', 'R2', 'R3', 'R3', 'R5', 'R5', 'R5', 'R5', 'R5'])
        status = self.ledger.status('t5')
        self.assertTrue(status['needs_user_permission']); self.assertIn('max_rung_climbs', status['blocked_by'])

    def test_tests_red_after_claimed_fix_counts_only_at_that_head(self):
        self.ledger.claim_fix('t6', 'd' * 40)
        red = final(result='CHECK_FAILED', reason='CODE_FINDINGS', head='d' * 40, salt='1')
        self.assertEqual(self.ledger.record('t6', red, kind='test', source='test')['failures_at_rung'], 1)
        other = final(result='CHECK_FAILED', reason='CODE_FINDINGS', head='e' * 40, salt='2')
        self.assertEqual(self.ledger.record('t6', other, kind='test', source='test')['failures_at_rung'], 1)

    def test_cost_and_launch_ceilings_block(self):
        self.ledger.add_spend('t7', 61)
        self.assertIn('max_total_review_usd', self.ledger.status('t7')['blocked_by'])
        for n in range(8):
            self.ledger.record('t8', final(verdict='ACCEPT', salt=str(n)), kind='review', source='test')
        self.assertIn('max_review_launches', self.ledger.status('t8')['blocked_by'])


class Resets(LedgerFixture):
    def test_corrupt_state_resets_to_lowest_with_a_preserved_copy_and_cannot_jump_rungs(self):
        self.block('t9', 'F1', salt='1'); self.block('t9', 'F1', salt='2')
        path = self.root / 't9.json'
        forged = json.loads(path.read_text()); forged['events'] = 'not a list'
        path.write_text(json.dumps(forged))
        status = self.ledger.status('t9')
        self.assertEqual(status['rung'], 'R0')
        state = self.ledger.load('t9')
        self.assertEqual(state['resets'][-1]['code'], 'state_corrupt')
        self.assertTrue(Path(state['resets'][-1]['preserved_copy']).exists())
        self.assertIsNotNone(state['resets'][-1]['prior_state_sha256'])
        # A forged state that claims R5 without events is still computed from events: R0.
        path.write_text(json.dumps({**self.ledger.fresh('t9'), 'rung': 'R5'}))
        self.assertEqual(self.ledger.status('t9')['rung'], 'R0')

    def test_each_reset_code_is_recorded_and_notified(self):
        for code in sorted(esc.RESET_CODES):
            with self.subTest(code):
                status = self.ledger.reset('t10', code, 'test detail')
                self.assertEqual(status['rung'], 'R0')
                self.assertEqual(self.ledger.load('t10')['resets'][-1]['code'], code)
        with self.assertRaises(esc.LedgerError): self.ledger.reset('t10', 'made_up', 'x')
        lines = [json.loads(l) for l in (self.root / 'notifications.jsonl').read_text().splitlines()]
        self.assertEqual(sorted({l['code'] for l in lines if l['event'] == 'reset'}), sorted(esc.RESET_CODES))

    def test_unreadable_and_non_json_receipts_do_not_count_and_are_recorded(self):
        status = self.ledger.record('t11', b'\xff\xfe not json', kind='review', source='test')
        self.assertEqual(status['event']['class'], 'NOT_COUNTED')
        self.assertEqual(self.ledger.load('t11')['resets'][-1]['code'], 'unclassifiable_evidence')
        with self.assertRaises(esc.LedgerError): self.ledger.record('t11', 'text', kind='review', source='test')

    def test_task_key_parsing_and_generated_keys(self):
        self.assertEqual(esc.task_key_from('fix the bug [task:pp-416] now', None), 'pp-416')
        self.assertIsNone(esc.task_key_from('no key here', 'nor here'))
        self.assertEqual(esc.generated_key('a', 'b'), esc.generated_key('a', 'b'))
        self.assertNotEqual(esc.generated_key('a'), esc.generated_key('b'))
        with self.assertRaises(esc.LedgerError): self.ledger.status('../escape')


class Concurrency(LedgerFixture):
    def test_concurrent_writers_keep_every_distinct_event_once(self):
        receipts = [final(verdict='BLOCK', findings=['F1'], salt=str(n)) for n in range(2)] * 3
        script = ('import sys\nfrom pathlib import Path\n'
                  f'sys.path.insert(0, {str(HOOKS)!r})\nimport escalation as esc, model_tiers as tiers\n'
                  f'ledger = esc.Ledger({str(self.root)!r}, tiers.load_policy())\n'
                  'ledger.record("t12", sys.stdin.buffer.read(), kind="review", source="child")\n')
        children = [subprocess.Popen([sys.executable, '-c', script], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    for _ in receipts]
        for child, receipt in zip(children, receipts):
            child.stdin.write(receipt); child.stdin.close()
        for child in children:
            child.wait(timeout=30)
            self.assertEqual(child.returncode, 0, child.stderr.read().decode()[-300:])
        state = self.ledger.load('t12')
        self.assertEqual(len(state['events']), 2)
        self.assertEqual(self.ledger.status('t12')['rung'], 'R1')


class TopPermission(LedgerFixture):
    def wal(self, *, source='user:s/u "please use fable on t13"', note='permission for [task:t13] top rung', resolved=True,
            resolution='approved: user said yes'):
        path = Path(self.temp.name) / 'main.jsonl'
        lines = [json.dumps({'id': 'wask1', 'event': 'ask', 'note': note, 'source': source})]
        if resolved:
            lines.append(json.dumps({'id': 'wres1', 'event': 'ask_resolved', 'ref': 'wask1', 'note': resolution}))
        path.write_text('\n'.join(lines) + '\n')
        return path

    def test_top_needs_a_user_sourced_ask_pair_naming_the_task(self):
        for label, wal in {'unresolved': self.wal(resolved=False), 'agent-sourced': self.wal(source='wal:x#y'),
                           'other-task': self.wal(note='permission for [task:other]'),
                           'substring-task': self.wal(note='permission for [task:t13x]'),
                           'declined': self.wal(resolution='user said NO, do not use fable'),
                           'no-decision': self.wal(resolution='discussed')}.items():
            with self.subTest(label), self.assertRaises(esc.LedgerError):
                self.ledger.approve_top('t13', 'wask1', wal)
        self.assertIsNone(self.ledger.status('t13')['permission'])
        status = self.ledger.approve_top('t13', 'wask1', self.wal())
        self.assertEqual(status['permission']['ask_id'], 'wask1'); self.assertTrue(status['permission']['source'].startswith('user:'))


if __name__ == '__main__':
    unittest.main()
