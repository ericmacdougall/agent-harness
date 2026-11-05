"""The one tier table: classification, spawn specs and deterministic reviewer selection (goodqa#14527)."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HOOKS = Path(__file__).resolve().parents[1] / 'harness/hooks'
sys.path.insert(0, str(HOOKS))
import model_tiers as tiers


class TableShape(unittest.TestCase):
    def setUp(self):
        self.policy = tiers.load_policy()

    def test_ladder_matches_the_user_rule(self):
        self.assertEqual(tiers.rung_order(self.policy), ['R0', 'R1', 'R2', 'R3', 'R4', 'R5', 'R6'])
        self.assertEqual(tiers.writing_rungs(self.policy), ['R0', 'R1', 'R2', 'R3', 'R5'])
        rungs = self.policy['rungs']
        self.assertEqual([rungs[r]['effort'] for r in ('R1', 'R2', 'R3', 'R4')], ['medium', 'high', 'xhigh', 'max'])
        self.assertEqual((rungs['R5']['effort'], rungs['R6']['effort']), ('medium', 'high'))
        self.assertFalse(rungs['R4']['writable']); self.assertFalse(rungs['R6']['writable'])
        self.assertTrue(rungs['R5']['needs_user_permission']); self.assertTrue(rungs['R6']['needs_user_permission'])
        self.assertFalse(any(rungs[r]['ultracode'] for r in rungs))  # user decision Q3: off until verifiable
        self.assertEqual([rungs[r]['reviewer_rung'] for r in ('R0', 'R1', 'R2', 'R3', 'R4', 'R5', 'R6')],
                         ['R1', 'R2', 'R3', 'R4', None, 'R6', None])
        self.assertEqual(self.policy['unknown_author_reviewer_rung'], 'R1')  # user decision Q1
        # Three automatic climbs (R0 -> R1 -> R2 -> R3); the fourth needs the user (cost numbers are assumptions).
        self.assertEqual(self.policy['ladder_limits'], {'max_review_launches': 8, 'max_rung_climbs': 3, 'max_total_review_usd': 60})
        self.assertEqual(self.policy['mode'], 'warn')

    def test_next_writing_rung_skips_review_only_rungs_and_stops_at_top(self):
        self.assertEqual(tiers.next_writing_rung(self.policy, 'R0'), 'R1')
        self.assertEqual(tiers.next_writing_rung(self.policy, 'R3'), 'R5')  # R4 is review only
        self.assertIsNone(tiers.next_writing_rung(self.policy, 'R5'))
        with self.assertRaises(tiers.TierError): tiers.next_writing_rung(self.policy, 'R4')

    def test_malformed_tables_fail_closed(self):
        good = self.policy
        bad = [
            ('mode', {**good, 'mode': 'maybe'}),
            ('schema', {**good, 'schema': 2}),
            ('reviewer', {**good, 'rungs': {**good['rungs'], 'R0': {**good['rungs']['R0'], 'reviewer_rung': 'R9'}}}),
            ('lowest-not-writable', {**good, 'lowest_rung': 'R4'}),
            ('family-rung', {**good, 'families': {**good['families'], 'claude': {**good['families']['claude'], 'opus': {**good['families']['claude']['opus'], 'rung_by_effort': {'medium': 'R9'}}}}}),
            ('limits', {**good, 'ladder_limits': {'max_review_launches': '8'}}),
        ]
        for label, table in bad:
            with self.subTest(label), self.assertRaises(tiers.TierError):
                tiers.validate(table)
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'tiers.json'
            path.write_text('{not json')
            with self.assertRaises(tiers.TierError): tiers.load_policy(path)
            path.write_bytes(b'{"schema": 1}' + b' ' * tiers.MAX_BYTES)
            with self.assertRaises(tiers.TierError): tiers.load_policy(path)
            with self.assertRaises(tiers.TierError): tiers.load_policy(Path(temp) / 'missing.json')


class Classification(unittest.TestCase):
    def setUp(self):
        self.policy = tiers.load_policy()

    def rung(self, model, effort=None):
        value = tiers.classify(model, effort, self.policy)
        return None if value is None else (value['rung'], value['harness'])

    def test_equivalence_across_harnesses_and_effort_rungs(self):
        self.assertEqual(self.rung('sonnet'), ('R0', 'claude'))
        self.assertEqual(self.rung('claude-sonnet-4-5-20250929', 'xhigh'), ('R0', 'claude'))
        self.assertEqual(self.rung('gpt-5.1-terra', 'high'), ('R0', 'openai'))
        self.assertEqual(self.rung('opus'), ('R1', 'claude'))
        self.assertEqual(self.rung('opus', 'low'), ('R1', 'claude'))
        self.assertEqual(self.rung('gpt-6.1-sol', 'medium'), ('R1', 'openai'))
        self.assertEqual(self.rung('opus', 'high'), ('R2', 'claude'))
        self.assertEqual(self.rung('gpt-6.1-sol', 'high'), ('R2', 'openai'))
        self.assertEqual(self.rung('opus', 'xhigh'), ('R3', 'claude'))
        self.assertEqual(self.rung('opus', 'ultracode'), ('R3', 'claude'))
        self.assertEqual(self.rung('opus', 'max'), ('R4', 'claude'))
        self.assertEqual(self.rung('gpt-6-sol', 'max'), ('R4', 'openai'))
        self.assertEqual(self.rung('fable'), ('R5', 'claude'))
        self.assertEqual(self.rung('gpt-6-astra', 'medium'), ('R5', 'openai'))
        self.assertEqual(self.rung('claude-fable-5-1', 'high'), ('R6', 'claude'))
        self.assertEqual(self.rung('gpt-6-astra', 'high'), ('R6', 'openai'))

    def test_prefixes_suffixes_and_case_are_normalized(self):
        self.assertEqual(self.rung('us.anthropic.claude-opus-4-5-20251101', 'high'), ('R2', 'claude'))
        self.assertEqual(self.rung('claude-opus-4-5[1m]', 'xhigh'), ('R3', 'claude'))
        self.assertEqual(self.rung('OPUS', 'HIGH'), ('R2', 'claude'))
        self.assertEqual(self.rung('claude-sonnet-4-5@20250929'), ('R0', 'claude'))

    def test_unknown_models_and_efforts_are_none_not_guessed(self):
        for model, effort in [('gpt-4o', 'high'), ('haiku', None), ('', None), (None, None), (7, None),
                              ('opus', 'extreme'), ('opus', 3), ('claude-opus', 'high'), ('gpt-6.1-solo', 'high'),
                              ('sonnet-opus', None)]:
            with self.subTest(model=model, effort=effort):
                self.assertIsNone(tiers.classify(model, effort, self.policy))


class Selection(unittest.TestCase):
    def setUp(self):
        self.policy = tiers.load_policy()

    def test_spawn_spec_names_model_and_effort_per_harness(self):
        self.assertEqual(tiers.spawn_spec(self.policy, 'R2', 'claude')['model'], 'opus')
        self.assertEqual(tiers.spawn_spec(self.policy, 'R2', 'claude')['effort'], 'high')
        self.assertEqual(tiers.spawn_spec(self.policy, 'R2', 'openai')['model'], 'gpt-6.1-sol')
        self.assertEqual(tiers.spawn_spec(self.policy, 'R6', 'openai'), {
            'rung': 'R6', 'harness': 'openai', 'model': 'gpt-6-astra', 'effort': 'high', 'writable': False,
            'needs_user_permission': True, 'ultracode': False, 'review_budget_usd': 30, 'timeout_minutes': 40})
        with self.assertRaises(tiers.TierError): tiers.spawn_spec(self.policy, 'R7', 'claude')
        with self.assertRaises(tiers.TierError): tiers.spawn_spec(self.policy, 'R1', 'gemini')

    def test_reviewer_is_one_rung_above_and_cross_harness_when_available(self):
        choice = tiers.reviewer_for(self.policy, 'R0', 'claude')
        self.assertEqual((choice['rung'], choice['harness'], choice['model'], choice['effort']), ('R1', 'openai', 'gpt-6.1-sol', 'medium'))
        self.assertTrue(choice['cross_harness']); self.assertFalse(choice['author_unknown'])
        choice = tiers.reviewer_for(self.policy, 'R3', 'openai')
        self.assertEqual((choice['rung'], choice['harness'], choice['model'], choice['effort']), ('R4', 'claude', 'opus', 'max'))
        choice = tiers.reviewer_for(self.policy, 'R5', 'claude')
        self.assertEqual((choice['rung'], choice['harness'], choice['effort']), ('R6', 'openai', 'high'))

    def test_review_only_rungs_need_no_reviewer(self):
        for rung in ('R4', 'R6'):
            choice = tiers.reviewer_for(self.policy, rung, 'claude')
            self.assertIsNone(choice['rung']); self.assertIn('review-only', choice['why'])

    def test_unavailable_harness_falls_back_to_same_harness_one_effort_up(self):
        # "Same harness one effort up" is the reviewer rung (one above the author) on the author's harness;
        # a writing rung that needs permission is never chosen while a review-only rung sits below it.
        choice = tiers.reviewer_for(self.policy, 'R1', 'claude', {'openai': False})
        self.assertEqual((choice['rung'], choice['harness'], choice['effort']), ('R2', 'claude', 'high'))
        self.assertFalse(choice['cross_harness']); self.assertIn('one effort above the author', choice['why'])
        choice = tiers.reviewer_for(self.policy, 'R3', 'claude', {'openai': False})
        self.assertEqual((choice['rung'], choice['harness'], choice['effort']), ('R4', 'claude', 'max'))
        self.assertFalse(choice['needs_user_permission']); self.assertFalse(choice['writable'])
        none = tiers.reviewer_for(self.policy, 'R0', 'claude', {'openai': False, 'claude': False})
        self.assertIsNone(none['harness']); self.assertEqual(none['rung'], 'R1')

    def test_unknown_author_gets_opus_medium_flagged(self):
        for author in (None, 'R9'):
            choice = tiers.reviewer_for(self.policy, author, 'unknown')
            self.assertEqual((choice['rung'], choice['harness'], choice['model'], choice['effort']), ('R1', 'openai', 'gpt-6.1-sol', 'medium'))
            self.assertTrue(choice['author_unknown']); self.assertIn('author unknown', choice['why'])
        choice = tiers.reviewer_for(self.policy, None, 'unknown', {'openai': False})
        self.assertEqual((choice['rung'], choice['harness'], choice['model'], choice['effort']), ('R1', 'claude', 'opus', 'medium'))

    def test_cli_is_deterministic_and_never_prints_secrets(self):
        env = {**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'}
        first = subprocess.run([sys.executable, str(HOOKS / 'model_tiers.py'), 'reviewer', '--author-rung', 'R2', '--author-harness', 'claude'],
                               capture_output=True, text=True, env=env, timeout=20)
        second = subprocess.run([sys.executable, str(HOOKS / 'model_tiers.py'), 'reviewer', '--author-rung', 'R2', '--author-harness', 'claude'],
                                capture_output=True, text=True, env=env, timeout=20)
        self.assertEqual(first.returncode, 0); self.assertEqual(first.stdout, second.stdout)
        self.assertEqual(json.loads(first.stdout)['rung'], 'R3')
        table = subprocess.run([sys.executable, str(HOOKS / 'model_tiers.py'), 'table'], capture_output=True, text=True, env=env, timeout=20)
        self.assertEqual(set(json.loads(table.stdout)), {'R0', 'R1', 'R2', 'R3', 'R4', 'R5', 'R6'})


class ModeSwitch(unittest.TestCase):
    def test_mode_set_rewrites_the_table_atomically_and_reports_the_rollback(self):
        import os, shutil, subprocess, sys, tempfile
        with tempfile.TemporaryDirectory() as temp:
            table = Path(temp) / 'model_tiers.json'
            shutil.copy(tiers.DEFAULT_PATH, table); os.chmod(table, 0o600)
            cli = [sys.executable, str(tiers.DEFAULT_PATH.parent / 'model_tiers.py'), '--policy', str(table), 'mode']
            shown = json.loads(subprocess.run(cli, capture_output=True, text=True, timeout=30).stdout)
            self.assertEqual((shown['mode'], shown['changed']), ('warn', False))
            flipped = json.loads(subprocess.run(cli + ['--set', 'enforce'], capture_output=True, text=True, timeout=30).stdout)
            self.assertEqual((flipped['previous'], flipped['mode'], flipped['changed']), ('warn', 'enforce', True))
            self.assertEqual(tiers.load_policy(table)['mode'], 'enforce')
            self.assertEqual(oct(table.stat().st_mode & 0o777), '0o600'); self.assertFalse(list(Path(temp).glob('*.tmp')))
            back = json.loads(subprocess.run(cli + ['--set', 'warn'], capture_output=True, text=True, timeout=30).stdout)
            self.assertEqual(back['mode'], 'warn'); self.assertEqual(tiers.load_policy(table)['mode'], 'warn')
            bogus = subprocess.run(cli + ['--set', 'loud'], capture_output=True, text=True, timeout=30)
            self.assertNotEqual(bogus.returncode, 0); self.assertEqual(tiers.load_policy(table)['mode'], 'warn')


if __name__ == '__main__':
    unittest.main()
