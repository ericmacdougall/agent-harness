"""Explicit review routing is independent of author and merge authority."""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'harness' / 'hooks'))
import peer_review as review
from tests import test_peer_review as fixtures


class RoutingBoundary(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.snapshot = Path(self.tmp.name)
        self.calls, self.leases = [], []
        policy = review.tiers.load_policy()
        self.policy = policy
        selection = review.tiers.reviewer_for(policy, 'R0', 'claude')
        class Store:
            def acquire_pool(inner, provider, pool, run): self.leases.append(provider)
            def release_pool(inner, *args, **kwargs): pass
        self.options = {'reviewer': 'codex-only', 'secondary': 'default', 'selection': selection,
                        'codex_model': policy['rungs'][selection['rung']]['models']['openai'],
                        'claude_model': policy['rungs'][selection['rung']]['models']['claude'],
                        'resolutions': {'codex': {'path': '/fixture/codex'}, 'claude': {'path': '/fixture/claude'}},
                        'store': Store(), 'run_record': SimpleNamespace(timeout=60, run_id='fixture', note_child=lambda p: None)}
        self.failure = None
        def run(command, prompt, cwd, timeout, **kwargs):
            provider = Path(command[0]).name; self.calls.append(provider)
            if provider == 'codex' and self.failure: return self.failure
            text = 'CODE_INSPECTION_RESULT: ACCEPT\nFixture reviewed.'
            if provider == 'codex':
                records = [{'type': 'item.completed', 'item': {'type': 'agent_message', 'text': text}},
                           {'type': 'turn.completed'}]
                return 0, '\n'.join(json.dumps(r) for r in records), ''
            return 0, json.dumps({'type': 'result', 'is_error': False, 'subtype': 'success', 'result': text}), ''
        patch = mock.patch.object(review, 'run', side_effect=run)
        patch.start(); self.addCleanup(patch.stop)

    def invoke(self):
        return review.review_snapshot(self.snapshot, 'a' * 40, 'code-inspection', 'Fixture rules', 'Fixture packet', self.options)

    def test_codex_failure_never_spends_excluded_fallback(self):
        for failure in ((127, '', 'HARNESS_PROVIDER_UNAVAILABLE'), (1, '', '401 Unauthorized'),
                        (124, '', 'HARNESS_PROVIDER_TIMEOUT'), (0, 'invalid result', '')):
            with self.subTest(exit=failure[0]):
                self.failure = failure; self.calls.clear(); self.leases.clear()
                with self.assertRaises(review.ReviewFailure): self.invoke()
                self.assertEqual(self.calls, ['codex']); self.assertEqual(self.leases, ['codex'])

    def test_contradictory_direct_selection_refuses_before_lease(self):
        self.options['selection'] = review.tiers.reviewer_for(self.policy, 'R0', 'openai')
        with self.assertRaises(OSError): self.invoke()
        self.assertEqual(self.calls, []); self.assertEqual(self.leases, [])

    def test_conflicting_or_unknown_direct_route_refuses(self):
        for mode, secondary in (('unknown', 'default'), (None, 'default'), ([], 'default'), ('codex-only', 'kimi')):
            self.options.update(reviewer=mode, secondary=secondary)
            with self.assertRaises(OSError): self.invoke()
        self.assertEqual(self.calls, []); self.assertEqual(self.leases, [])

    def test_auto_route_and_real_authority_rules_are_preserved(self):
        self.options.update(reviewer='auto', selection=review.tiers.reviewer_for(self.policy, 'R0', 'openai'))
        self.invoke(); self.assertEqual(self.calls, ['claude'])
        for author, stamp in (('unknown', {'purpose': 'fixture'}), ('openai', {'purpose': 'fixture'}), ('claude', None)):
            args = SimpleNamespace(stage='pr', author_harness=author, main_stamp=stamp)
            self.assertFalse(review.review_merge_eligible(args, {'repo': 'o/r', 'pr': 1}, 'VERDICT: PASS', {'harness': 'openai'}))

    def test_codex_block_is_one_validated_attempt(self):
        self.failure = (0, '\n'.join(json.dumps(r) for r in (
            {'type': 'item.completed', 'item': {'type': 'agent_message', 'text': 'CODE_INSPECTION_RESULT: BLOCK\nF1: fixture defect'}},
            {'type': 'turn.completed'})), '')
        source, report, failure = self.invoke()
        self.assertTrue(source.startswith('Codex ')); self.assertTrue(report.startswith('CODE_INSPECTION_RESULT: BLOCK'))
        self.assertEqual(self.calls, ['codex']); self.assertEqual(self.leases, ['codex'])
        self.assertEqual(self.options['actual_reviewer'], 'codex')

    def test_failed_internal_retry_does_not_reuse_prior_actual_reviewer(self):
        self.invoke(); self.assertEqual(self.options['actual_reviewer'], 'codex')
        self.failure = (127, '', 'HARNESS_PROVIDER_UNAVAILABLE')
        with self.assertRaises(review.ReviewFailure): self.invoke()
        self.assertIsNone(review.routing_evidence(self.options)['actual_reviewer'])


class CodexOnlyCLI(unittest.TestCase):
    fake = fixtures.PeerReviewTests.fake
    invoke = fixtures.PeerReviewTests.invoke
    evidence = staticmethod(fixtures.PeerReviewTests.evidence)

    def setUp(self):
        fixtures.PeerReviewTests.setUp(self)
        self.launches = self.root / 'launches.txt'
        self.ladder = self.root / 'ladder'
        patch = mock.patch.dict('os.environ', {'HARNESS_PROVENANCE_OFFLINE': '1',
                                             'AGENT_HARNESS_ESCALATION_DIR': str(self.ladder)})
        patch.start(); self.addCleanup(patch.stop)

    def execute(self, *extra, output=None):
        return self.invoke(stage='code-inspection', output=output, extra=list(extra),
                           env={'PROVIDER_LAUNCH_LOG': str(self.launches)})

    def test_requested_codex_only_overrides_opposite_harness_preference(self):
        result = self.execute('--reviewer', 'codex-only', '--author-rung', 'R0', '--author-harness', 'openai')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.launches.read_text().splitlines(), ['codex'])
        self.assertIn('Reviewer-Route: codex-only; attempts codex; fallback none', self.output.read_text())
        final = json.loads(next((self.root / 'usage-state' / 'runs').glob('*/final.json')).read_text())
        self.assertEqual(final['usage']['review_routing']['actual_reviewer'], 'codex')
        self.assertEqual(final['usage']['review_routing']['requested_mode'], 'codex-only')
        self.assertIn('Reviewer-Rung: R1\n', self.output.read_text())
        selection = json.loads(next((self.ladder / 'selections').glob('*.json')).read_text())
        self.assertEqual(selection['author_harness'], 'openai')
        self.assertEqual(selection['review_routing']['attempt_order'], ['codex'])

    def test_missing_codex_never_uses_available_claude(self):
        (self.bin / 'codex').unlink()
        result = self.execute('--reviewer', 'codex-only', '--author-rung', 'R0', '--author-harness', 'openai')
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn('requested Codex-only route has no trusted Codex CLI', result.stderr)
        self.assertFalse(self.launches.exists())
        self.assertFalse((self.root / 'usage-state' / 'runs').exists())

    def test_mode_changes_invocation_identity_with_same_primary(self):
        for mode in ('auto', 'codex-only'):
            result = self.execute('--reviewer', mode, '--author-rung', 'R0', '--author-harness', 'claude',
                                  output=self.root / (mode + '.md'))
            self.assertEqual(result.returncode, 0, result.stderr)
        finals = [json.loads(p.read_text()) for p in (self.root / 'usage-state' / 'runs').glob('*/final.json')]
        self.assertEqual(len(finals), 2)
        self.assertEqual(len({f['invocation']['fingerprint'] for f in finals}), 2)
        self.assertEqual({f['usage']['review_routing']['requested_mode'] for f in finals}, {'auto', 'codex-only'})

    def test_kimi_conflict_and_permission_gate_do_not_launch(self):
        for extra in (('--secondary', 'kimi'), ('--author-rung', 'R5')):
            result = self.execute('--reviewer', 'codex-only', *extra)
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertFalse(self.launches.exists())


class SelectionIsolation(unittest.TestCase):
    def test_legacy_fixture_never_writes_the_ambient_selection_store(self):
        with tempfile.TemporaryDirectory() as folder:
            ambient = Path(folder) / 'ambient'; selections = ambient / 'selections'
            selections.mkdir(parents=True)
            sentinel = selections / 'sentinel.json'; sentinel.write_text('owned sentinel')
            with mock.patch.dict('os.environ', {'AGENT_HARNESS_ESCALATION_DIR': str(ambient)}):
                fixture = fixtures.PeerReviewTests(methodName='runTest')
                fixture.setUp()
                try:
                    result = fixture.invoke(stage='code-inspection')
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(sorted(p.name for p in selections.iterdir()), ['sentinel.json'])
                    self.assertEqual(sentinel.read_text(), 'owned sentinel')
                    self.assertTrue(list((fixture.root / 'escalation-state' / 'selections').glob('*.json')))
                finally:
                    fixture.doCleanups()


if __name__ == '__main__': unittest.main()
