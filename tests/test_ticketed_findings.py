"""goodqa#15253 item 6: review findings the author has filed as tickets do not count toward the escalation cap.

The review still BLOCKs (no pass marker, merge still gated); only the ladder's failure count skips ticketed findings.
"""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'harness' / 'hooks'))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import escalation as esc  # noqa: E402
import peer_review  # noqa: E402
import usage_guard as guard  # noqa: E402
from test_usage_guard import StoreFixture  # noqa: E402


def receipt(findings, ticketed=None):
    review = {'stage': 'CODE_INSPECTION', 'verdict': 'BLOCK', 'findings': list(findings)}
    if ticketed is not None:
        review['ticketed'] = list(ticketed)
    return {'schema': 1, 'kind': 'final', 'run_id': 'b' * 32, 'evidence': 'EXECUTED', 'subject': {'head': 'a' * 40},
            'invocation': {}, 'execution': 'COMPLETED', 'result': 'CHECK_FAILED', 'reason': 'CODE_FINDINGS',
            'usage': {'provider_launches': 1, 'reported': []}, 'review': review}


class Classify(unittest.TestCase):
    def test_all_ticketed_findings_are_not_counted(self):
        verdict = esc.classify(receipt(['F1', 'F2'], ['F1:goodqa:15001', 'F2:goodqa:15002']), kind='review')
        self.assertEqual(verdict[0], 'NOT_COUNTED', verdict)

    def test_untouched_findings_still_count_with_their_own_fingerprint(self):
        verdict = esc.classify(receipt(['F1', 'F2'], ['F1:goodqa:15001']), kind='review')
        self.assertEqual((verdict[0], verdict[2]), ('FAIL', esc.fingerprint(['F2'])))
        self.assertEqual(esc.classify(receipt(['F1', 'F2']), kind='review')[0], 'FAIL')  # control: no tickets

    def test_a_ticket_for_an_unknown_finding_changes_nothing(self):
        verdict = esc.classify(receipt(['F1'], ['F9:goodqa:1']), kind='review')
        self.assertEqual((verdict[0], verdict[2]), ('FAIL', esc.fingerprint(['F1'])))


class Parse(unittest.TestCase):
    def test_ticket_arguments_become_safe_labels(self):
        self.assertEqual(peer_review.ticketed_labels(['F1=GoodQA goodqa#15001', 'R2=goodqa#7'], ['F1', 'R2', 'F3']),
                         ['F1:goodqa:15001', 'R2:goodqa:7'])

    def test_bad_arguments_are_refused(self):
        for value in ('F1', 'F1=15001', 'F4=goodqa#1', 'F1=goodqa#1; rm', 'x=goodqa#1'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                peer_review.ticketed_labels([value], ['F1'])


class Receipt(StoreFixture):
    def run_review(self, review):
        identity = guard.invocation_identity(self.subject, purpose='inspect', argv=['review'], cwd=self.repo)
        run = self.store.begin(self.subject, identity, owner='fixture', label='review', timeout=10,
                               kind='review', minimum_bytes=0)
        return run.finish(execution='COMPLETED', result='CHECK_FAILED', reason='CODE_FINDINGS', exit_code=0,
                          review=review)

    def test_ticketed_list_is_kept_in_the_final_receipt(self):
        reference = self.run_review({'stage': 'CODE_INSPECTION', 'verdict': 'BLOCK', 'findings': ['F1', 'F2'],
                                     'ticketed': ['F1:goodqa:15001']})
        self.assertEqual(self.store.load_ref(reference)['review']['ticketed'], ['F1:goodqa:15001'])

    def test_ticketed_on_an_accept_or_for_a_missing_finding_is_malformed(self):
        for review in ({'stage': 'CODE_INSPECTION', 'verdict': 'BLOCK', 'findings': ['F1'], 'ticketed': ['F2:goodqa:1']},
                       {'stage': 'CODE_INSPECTION', 'verdict': 'BLOCK', 'findings': ['F1'], 'ticketed': ['F1 goodqa 1']}):
            with self.subTest(review=review), self.assertRaises(guard.GuardError):
                self.run_review(review)


if __name__ == '__main__':
    unittest.main()
