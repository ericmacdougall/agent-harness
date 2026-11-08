"""Scenario B2.5: status lists come from evidence, never from memory. `ah status --since` classifies WAL entries as
VERIFIED (REALLY_TESTED), LIVE (DONE_LIVE only when a REALLY_TESTED shares a ticket/sha token, else LIVE_UNTESTED),
PENDING, CLAIMED (narrative only), BLOCKED, open ASKS, and ASSUMPTION / TARGET_MISMATCH (B2.4: an unsourced decision
that moved a target). Also B3.16: a live `waiting` disposition acknowledges a handoff."""

import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest import mock

HOOKS = Path(__file__).resolve().parents[1] / 'harness/hooks'
sys.path.insert(0, str(HOOKS))
import ah  # noqa: E402

NOW = 1_800_000_000.0
SESSION = 'sess-status-0001'


def iso(ts):
    return time.strftime('%Y-%m-%dT%H:%M:%S+00:00', time.gmtime(ts))


def jl(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, 'a') as fh:
        for r in rows:
            fh.write(json.dumps(r) + '\n')


class StatusReport(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)
        p = mock.patch.dict(os.environ, {'AH_HOME': str(self.home), 'HOME': str(self.home)}); p.start(); self.addCleanup(p.stop)
        self.w = self.home / '.claude' / 'wals' / SESSION
        jl(self.w / 'main.jsonl', [
            {'at': iso(NOW - 9000), 'event': 'subagent', 'agent_id': 'owner1', 'agent_type': 'task-owner'},
            {'at': iso(NOW - 8000), 'event': 'decision', 'id': 'wdec1', 'note': 'lead target 1000 -> at least 50 verified leads', 'source': 'inferred: from file:x -- assistant judgement'},
            {'at': iso(NOW - 7900), 'event': 'decision', 'id': 'wdec2', 'note': 'use Apache-2.0', 'source': 'user:11111111-2222-4333-8444-555555555555/00000000-0000-4000-8000-000000000001 "apache please"'},
            {'at': iso(NOW - 7800), 'event': 'decision', 'id': 'wdec3', 'note': 'click-tests run headless for now', 'unsourced': True},
            {'at': iso(NOW - 7000), 'event': 'status', 'id': 'wst1', 'note': 'Kimi reviewer done, runs on the subscription'},
            {'at': iso(NOW - 6000), 'event': 'ask', 'id': 'wask1', 'note': '[ask] approve the harness PR', 'reason': 'changes your rules', 'source': 'user:x/y "z"'},
            {'at': iso(NOW - 5000), 'event': 'ask', 'id': 'wask2', 'note': 'confirm license', 'reason': 'product choice', 'source': 'user:x/y "z"'},
            {'at': iso(NOW - 4900), 'event': 'ask_resolved', 'id': 'wres2', 'ref': 'wask2', 'note': 'Apache', 'source': 'user:x/y "z"'},
            {'at': iso(NOW - 30 * 3600), 'event': 'status', 'id': 'wold', 'note': 'old entry: shipped yesterday LIVE'},
        ])
        jl(self.w / 'agent-owner1.jsonl', [
            {'at': iso(NOW - 8500), 'event': 'intent', 'note': 'PENDING_REAL_TEST PP-615: email approve link signs in on the device'},
            {'at': iso(NOW - 8400), 'event': 'intent', 'note': 'PENDING_REAL_TEST LESSONS-LIVE: 24 lessons visible in the portal'},
            {'at': iso(NOW - 4000), 'event': 'check', 'note': 'REALLY_TESTED PP-615: curl + device flow on prod a67ab74f, 200, session issued'},
            {'at': iso(NOW - 3500), 'event': 'commit', 'note': 'a67ab74f fix(auth): email approve link'},
            {'at': iso(NOW - 3000), 'event': 'status', 'note': 'ParentProof platform a67ab74f DEPLOYED to prod'},
            {'at': iso(NOW - 2500), 'event': 'status', 'note': 'blog worker ae83610c is live on transition2.ai'},
            {'at': iso(NOW - 2400), 'event': 'status', 'note': 'course PR #43 merged, not live'},
            {'at': iso(NOW - 2000), 'event': 'blocker', 'note': 'GoodQA MCP returns 403 for the smoke key'},
        ])

    def report(self, since='12h'):
        return ah.status_report(self.home, SESSION, ah.parse_since(since), now=NOW)

    def test_classes_come_from_evidence_not_narrative(self):
        r = self.report()
        self.assertEqual([v['check'] for v in r['verified']], ['PP-615'])
        self.assertEqual([p['check'] for p in r['pending']], ['LESSONS-LIVE'])  # PP-615 was verified, so it left pending
        live = {e['note'].split()[0]: e['label'] for e in r['live']}
        self.assertEqual(live['ParentProof'], 'DONE_LIVE')  # shares sha a67ab74f with the REALLY_TESTED
        self.assertEqual(live['blog'], 'LIVE_UNTESTED')
        self.assertNotIn('course PR #43 merged, not live', [e['note'] for e in r['live']])
        claimed = [c['note'] for c in r['claimed']]
        self.assertTrue(any('Kimi reviewer done' in c for c in claimed))  # narrative "done" never becomes VERIFIED or LIVE
        self.assertTrue(any('merged, not live' in c for c in claimed))
        self.assertEqual([b['note'][:12] for b in r['blockers']], ['GoodQA MCP r'])
        self.assertEqual([a['id'] for a in r['asks_open']], ['wask1'])
        labels = {a['id']: a['label'] for a in r['assumptions']}
        self.assertEqual(labels, {'wdec1': 'TARGET_MISMATCH', 'wdec3': 'ASSUMPTION'})
        self.assertEqual([d['id'] for d in r['decisions']], ['wdec2'])
        self.assertNotIn('wold', [e['id'] for e in r['live']])  # outside the window
        self.assertEqual(len(r['commits']), 1)

    def test_text_rendering_and_window_parsing(self):
        text = ah.status_text(self.report())
        for heading in ('VERIFIED (REALLY_TESTED) (1)', 'LIVE (2)', 'PENDING checks', 'CLAIMED only', 'ASKS open (1)', 'TARGET_MISMATCH'):
            self.assertIn(heading, text)
        self.assertIn('never write a status list from memory', text)
        self.assertEqual(ah.parse_since('90m'), 5400); self.assertEqual(ah.parse_since('2d'), 172800)
        with self.assertRaises(ah.AhError):
            ah.parse_since('soon')
        self.assertEqual(len(self.report('2d')['live']), 3)  # the 30 h old LIVE note is inside a 2-day window

    def test_an_all_digit_token_never_links_live_to_a_test(self):
        # Review F7: a version code or date shared by a unit test and a LIVE note is not evidence that the live thing
        # was tested; only a #ticket or a hex sha with a letter a-f links them.
        jl(self.w / 'agent-owner2.jsonl', [
            {'at': iso(NOW - 1000), 'event': 'check', 'note': 'REALLY_TESTED UNIT-1: unit suite for build 2026110801 and 1234567 OK'},
            {'at': iso(NOW - 900), 'event': 'status', 'note': 'widget build 2026110801 and 1234567 DEPLOYED to prod'},
            {'at': iso(NOW - 800), 'event': 'check', 'note': 'REALLY_TESTED LIVE-2: ticket #4242 verified on prod'},
            {'at': iso(NOW - 700), 'event': 'status', 'note': 'gadget for #4242 is live'},
        ])
        live = {e['note'].split()[0]: e for e in self.report()['live']}
        self.assertEqual(live['widget']['label'], 'LIVE_UNTESTED')
        self.assertEqual(live['widget']['shared_evidence'], [])
        self.assertEqual(live['gadget']['label'], 'DONE_LIVE')
        self.assertEqual(live['ParentProof']['label'], 'DONE_LIVE')  # a67ab74f still links

    def test_a_wal_that_could_not_be_read_is_listed(self):
        # Review F9: an evidence report must say which WALs it did not read instead of skipping them silently.
        jl(self.w / 'agent-big.jsonl', [{'at': iso(NOW - 100), 'event': 'status', 'note': 'big DEPLOYED'}])
        real = ah._bounded

        def bounded(path, *a, **k):
            if Path(path).name == 'agent-big.jsonl':
                raise OSError('too_large')
            return real(path, *a, **k)
        with mock.patch.object(ah, '_bounded', side_effect=bounded):
            r = self.report()
        self.assertEqual([u['wal'] for u in r['unread']], ['agent-big.jsonl'])
        self.assertIn('too_large', r['unread'][0]['reason'])
        self.assertIn('UNREAD WALs (1)', ah.status_text(r))
        self.assertEqual(self.report()['unread'], [])

    def test_cli_dispatch_needs_a_session(self):
        args = ah.build_parser().parse_args(['status', '--session', SESSION, '--since', '12h'])
        self.assertEqual(ah.run(args, self.home)['session'], SESSION)
        with mock.patch.dict(os.environ, {'CLAUDE_CODE_SESSION_ID': '', 'CLAUDE_SESSION_ID': ''}):
            with self.assertRaises(ah.AhError):
                ah.run(ah.build_parser().parse_args(['status']), self.home)


class WaitingAcknowledgesHandoff(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)
        p = mock.patch.dict(os.environ, {'AH_HOME': str(self.home), 'HOME': str(self.home)}); p.start(); self.addCleanup(p.stop)
        clock = mock.patch.object(ah, 'server_now', side_effect=lambda: iso(NOW)); clock.start(); self.addCleanup(clock.stop)
        for k in ('CLAUDE_CODE_CHILD_SESSION', 'AH_AGENT_ID', 'AGENT_ID'):
            os.environ.pop(k, None)
        self.w = self.home / '.claude' / 'wals' / SESSION
        jl(self.w / 'main.jsonl', [{'at': iso(NOW - 9000), 'event': 'subagent', 'agent_id': 'handoffowner', 'agent_type': 'task-owner'},
                                   {'at': iso(NOW - 3000), 'event': 'subagent_stop', 'agent_id': 'handoffowner', 'agent_type': 'task-owner'}])
        jl(self.w / 'agent-handoffowner.jsonl', [{'at': iso(NOW - 4000), 'event': 'intent', 'note': 'work'},
                                                 {'at': iso(NOW - 3100), 'event': 'handoff', 'note': 'handed to main: PR #1'}])

    def test_a_plain_wait_does_not_ack_a_handoff(self):
        # B3.16 is covered on main by #134 P4: only a main wait marked --ack-handoff acks (test_dropped_gate).
        # A plain wait, which an owner can write, must leave the handoff unacked.
        by = {r['agent_id']: r for r in ah.owners(self.home, SESSION, now=NOW + 1000)['owners']}
        self.assertIn('handoff-unacked', by['handoffowner']['flags'])
        with mock.patch.object(ah, '_ticket_exists', return_value=True):
            ah.write(self.home, 'task.dispose', {'agent': 'handoffowner', 'session': SESSION, 'kind': 'waiting', 'at': iso(NOW),
                                                 'until': iso(NOW + 6 * 3600), 'ref': 'GoodQA goodqa#14791',
                                                 'reason': 'waiting on the user to approve the PR'}, SESSION, 'disp-wait-0001')
        by = {r['agent_id']: r for r in ah.owners(self.home, SESSION, now=NOW + 1000)['owners']}
        self.assertTrue(by['handoffowner']['decision_required'])
        self.assertIn('handoff-unacked', by['handoffowner'].get('flags') or [])


if __name__ == '__main__':
    unittest.main()
