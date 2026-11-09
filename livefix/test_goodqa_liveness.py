"""goodqa fleet liveness (bin/goodqa_liveness.py, bin/rule_overrides.py): offline tests; nothing reaches dev2, GoodQA or systemd.

Run: python3 -m pytest -q bin/test_goodqa_liveness.py. Every finding has a negative control (the case that must NOT fire), and the
actor is tested for: remedies rate-limited, one ticket per class, a flapping condition keeping its ticket, recovery noted once,
a dry run writing nothing."""
import collections
import json
import os
import shutil
import sys
import tempfile
import time
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
_TMP = tempfile.mkdtemp(prefix='liveness-test-')
os.environ['GOODQA_LANE_ROOT'] = _TMP
os.environ['GOODQA_RULE_OVERRIDES'] = os.path.join(_TMP, 'overrides.json')
# Isolate state/land-lag writes (tickets write a body file beside state_path) into the temp dir, never ~/.local.
os.environ['GOODQA_LIVENESS_STATE'] = os.path.join(_TMP, 'state.json')
import goodqa_liveness as L  # noqa: E402
import rule_overrides as RO  # noqa: E402

CFG = L.load_config(os.path.join(os.path.dirname(HERE), 'config', 'fleet-liveness.json'))
CFG['floor'] = 40
T0 = L.ts('2026-10-23T21:00:00Z')


def sample(at=T0, running=30, queued=0, **kw):
    s = dict(at=at, floor=40, running=running, queued=queued, merging={}, last_merge={}, drain=None, holders=[], fleet_state='running | x',
             lane_floor=None, gq_refusals=collections.Counter(), gq_refused={}, broker=None, grade_failed=[], limit_pauses=0, services={})
    s.update(kw)
    return s


def lf(shortfall=10, available=0, skips=None, refused=None, at=T0 - 120, gate=None):
    return dict(at=at, end=at + 30, shortfall=shortfall, available=available, gate=gate,
                skips=collections.Counter(skips or {}), refused=refused or {}, queued=0)


def st():
    return dict(since={}, alerts={}, remedied={})


def classes(fs):
    return [f['cls'] for f in fs]


class Detector(unittest.TestCase):
    def test_running_starved_needs_four_minutes(self):
        s0 = st()
        self.assertEqual(L.evaluate(sample(running=10), s0, CFG), [])                      # first sight: not yet
        self.assertEqual(L.evaluate(sample(at=T0 + 120, running=10), s0, CFG), [])
        self.assertEqual(classes(L.evaluate(sample(at=T0 + 240, running=10), s0, CFG)), ['running-starved'])
        # negative controls: at half the floor it is fine; a recovery resets the clock
        s1 = st()
        for i in range(5):
            self.assertEqual(L.evaluate(sample(at=T0 + i * 120, running=20), s1, CFG), [])
        s2 = st()
        L.evaluate(sample(running=10), s2, CFG)
        L.evaluate(sample(at=T0 + 120, running=30), s2, CFG)
        self.assertEqual(L.evaluate(sample(at=T0 + 240, running=10), s2, CFG), [])

    def test_queue_idle_names_the_drain_and_its_holders(self):
        s0 = st()
        d = dict(since=T0 - 900, reason='deploy drain: install.sh 12bccf532663', install='12bccf532663')
        L.evaluate(sample(running=0, queued=18, drain=d, holders=['a', 'b']), s0, CFG)
        fs = L.evaluate(sample(at=T0 + 120, running=0, queued=18, drain=d, holders=['a', 'b']), s0, CFG)
        self.assertEqual(classes(fs), ['queue-idle'])
        self.assertIn('install drain 12bccf532663 for 17 min', fs[0]['lines'][0])
        self.assertIn('a, b', fs[0]['lines'][0])
        self.assertEqual(fs[0]['remedies'][0]['unit'], 'goodqa-autopilot.service')     # drain-holders pauses the 2 holders
        # negative control: no session holds it -> the installer is named, and no holder-pause remedy is claimed
        s1 = st()
        L.evaluate(sample(running=0, queued=18, drain=d), s1, CFG)
        fs = L.evaluate(sample(at=T0 + 120, running=0, queued=18, drain=d), s1, CFG)
        self.assertIn('ship qualification', fs[0]['lines'][0])
        self.assertFalse(any('drain-holders' in r['why'] for r in fs[0]['remedies']))

    def test_floor_starved_counts_blocking_skips_not_held_briefs(self):
        s0 = st()
        busy = lf(skips={'owned paths overlap active x': 30})
        L.evaluate(sample(lane_floor=busy), s0, CFG)
        fs = L.evaluate(sample(at=T0 + 240, lane_floor=busy), s0, CFG)
        self.assertEqual(classes(fs), ['floor-starved'])
        self.assertIn('owned paths overlap active x x30', ' '.join(fs[0]['lines']))
        self.assertTrue(any(r['unit'] == 'lane-floor.service' for r in fs[0]['remedies']))
        s1 = st()                                                                         # negative control: only held briefs
        held = lf(skips={'held on a dependency': 200})
        L.evaluate(sample(lane_floor=held), s1, CFG)
        self.assertEqual(L.evaluate(sample(at=T0 + 240, lane_floor=held), s1, CFG), [])
        s2 = st()                                                                         # negative control: briefs available
        ok = lf(available=8, skips={'owned paths overlap active x': 30})
        L.evaluate(sample(lane_floor=ok), s2, CFG)
        self.assertEqual(L.evaluate(sample(at=T0 + 240, lane_floor=ok), s2, CFG), [])

    def test_merge_stall_with_the_top_stop_class(self):
        gf = [dict(ts='2026-10-23T20:00:00Z', task='g%d' % i, product='goodqa',
                   reason='STOP: merge train workspace (not attributed to this task): git clone ... early EOF') for i in range(3)]
        fs = L.evaluate(sample(merging={'goodqa': 9}, last_merge={'goodqa': T0 - 91 * 60}, grade_failed=gf), st(), CFG)
        self.assertEqual(classes(fs), ['merge-stall:goodqa'])
        self.assertIn('train workspace / clone failure (infrastructure) x3', fs[0]['lines'][1])
        # negative controls: nothing merging; a recent merge
        self.assertEqual(L.evaluate(sample(merging={}, last_merge={'goodqa': T0 - 300 * 60}), st(), CFG), [])
        self.assertEqual(L.evaluate(sample(merging={'goodqa': 9}, last_merge={'goodqa': T0 - 60 * 60}), st(), CFG), [])

    def test_mass_stop_needs_five_of_one_class_in_fifteen_minutes(self):
        mk = lambda n, reason: [dict(ts=L.iso(T0 - 60), task='t%d' % i, product='goodqa', reason=reason) for i in range(n)]
        fs = L.evaluate(sample(grade_failed=mk(5, 'STOP: merge train workspace: git clone failed')), st(), CFG)
        self.assertEqual(classes(fs), ['mass-stop'])
        self.assertEqual(L.evaluate(sample(grade_failed=mk(4, 'STOP: merge train workspace: git clone failed')), st(), CFG), [])
        old = [dict(g, ts=L.iso(T0 - 3600)) for g in mk(8, 'STOP: git clone failed')]
        self.assertEqual(L.evaluate(sample(grade_failed=old), st(), CFG), [])

    def test_a_rule_refusing_more_than_five_ready_briefs_is_flipped(self):
        six = {'postship-flow': {'b%d.md' % i for i in range(6)}}
        fs = L.evaluate(sample(lane_floor=lf(shortfall=0, available=0, refused=six)), st(), CFG)
        self.assertEqual(classes(fs), ['rule-refusing:postship-flow'])
        rw = [r for r in fs[0]['remedies'] if r['kind'] == 'rule-warn'][0]
        self.assertEqual((rw['config'], rw['key'], rw['value']), ('ticket-lifecycle', 'bug_brief_postship', 'warn'))
        five = {'postship-flow': {'b%d.md' % i for i in range(5)}}                        # negative control: 5 is allowed
        self.assertEqual(L.evaluate(sample(lane_floor=lf(shortfall=0, available=0, refused=five)), st(), CFG), [])
        # lane-floor and gq-queue refusals add up, counted by distinct brief
        fs = L.evaluate(sample(lane_floor=lf(shortfall=0, refused={'tests-lint': {'a', 'b', 'c'}}),
                               gq_refused={'tests-lint': {'c', 'd', 'e', 'f'}}), st(), CFG)
        self.assertEqual(classes(fs), ['rule-refusing:tests-lint'])

    def test_classifiers(self):
        self.assertEqual(L.rule_of('back-fill refused: ... a bug brief names the postship ... `Postship-flow: <group>`'), 'postship-flow')
        self.assertEqual(L.rule_of('refused: x: TESTS lint: line 43: ... (relative-testrun)'), 'tests-lint')
        self.assertIsNone(L.rule_of('owned paths overlap active x'))
        self.assertEqual(L.skip_class('owned paths overlap active goodqa-x-sol: more'), 'owned paths overlap active goodqa-x-sol:')
        self.assertEqual(L.stop_class('STOP: merge train workspace (not attributed): git clone --no-hardlinks'),
                         'train workspace / clone failure (infrastructure)')


class LaneFloorJournal(unittest.TestCase):
    def test_parse_runs(self):
        lines = [
            '2026-10-23T19:48:54+00:00 dev systemd[1]: Starting lane-floor.service - lane-floor: keep at least 15',
            '2026-10-23T19:48:55+00:00 dev lane-floor[9]: lane-floor: skip gorunner/tasks/ready/bugtracker/a.md: owned paths overlap active x-sol',
            '2026-10-23T19:48:55+00:00 dev lane-floor[9]: lane-floor: skip gorunner/tasks/ready/bugtracker/b.md: back-fill refused (ruling 55): '
            'refused: b: a bug brief names the postship click-test flow: add `Postship-flow: <group>/<flow id>`',
            '2026-10-23T19:48:55+00:00 dev lane-floor[9]: > a quoted brief line that is not a log line',
            '2026-10-23T19:48:56+00:00 dev lane-floor[9]: lane-floor: shortfall 14, this run takes at most 12; 0 brief(s) available',
            '2026-10-23T19:48:57+00:00 dev lane-floor[9]: lane-floor: QUEUED bugtracker c (ready, goodqa#1)',
            '2026-10-23T19:49:10+00:00 dev systemd[1]: Finished lane-floor.service - lane-floor',
        ]
        runs = L.parse_lane_floor(lines)
        self.assertEqual(len(runs), 1)
        r = runs[0]
        self.assertEqual((r['shortfall'], r['available'], r['queued']), (14, 0, 1))
        self.assertEqual(r['refused'], {'postship-flow': {'gorunner/tasks/ready/bugtracker/b.md'}})
        self.assertEqual(r['skips']['owned paths overlap active x-sol'], 1)
        self.assertEqual(r['end'], L.ts('2026-10-23T19:49:10Z'))


class Fx:
    def __init__(self):
        self.calls = []

    def ticket_status(self, ref):
        return 'triage'

    def start_unit(self, unit):
        self.calls.append(('start', unit))
        return 0, ''

    def rule_warn(self, config, key, value, why):
        self.calls.append(('warn', config, key, value))
        return 0, ''

    def ticket_new(self, title, body, idem):
        self.calls.append(('ticket', title))
        return 'goodqa#%d' % (9000 + len([c for c in self.calls if c[0] == 'ticket'])), 'ok'

    def ticket_patch(self, ref, status):
        self.calls.append(('patch', ref, status))

    def duplicate_survivor(self, ref):
        return None                      # no `duplicates` link: a duplicate-closed alert falls back to reopening

    def comment(self, ref, body):
        self.calls.append(('comment', ref, body[:40]))
        return 0, ''


class StatusFx(Fx):
    """Records ticket_status calls (so a test can prove the status was or was NOT read) and returns a scripted value."""
    def __init__(self, status='triage'):
        super().__init__()
        self._status = status

    def ticket_status(self, ref):
        self.calls.append(('status', ref))
        return self._status


class RaisingPatchFx(Fx):
    """ticket_patch always raises, like a refused/timed-out API close; ticket_status is the base 'triage'."""
    def ticket_patch(self, ref, status):
        self.calls.append(('patch-attempt', ref))
        raise RuntimeError('simulated PATCH failure')


class StatefulFx(Fx):
    """ticket_status reflects the last status ticket_patch set (default 'triage'), so a filer-closed ticket
    really reads `done` on a later pass -- the realistic fixture the reopen guard depends on."""
    def __init__(self):
        super().__init__()
        self._status = {}

    def ticket_status(self, ref):
        self.calls.append(('status', ref))
        return self._status.get(ref, 'triage')

    def ticket_patch(self, ref, status):
        self.calls.append(('patch', ref, status))
        self._status[ref] = status


class Actor(unittest.TestCase):
    def finding(self):
        return dict(cls='queue-idle', title='18 queued, 0 running', lines=['x'],
                    remedies=[dict(kind='start-unit', unit='lane-floor.service', why='w')])

    def test_one_ticket_cooldown_hysteresis_and_recovery(self):
        fx, s0 = Fx(), st()
        L.act([self.finding()], s0, CFG, fx, True, T0)
        self.assertEqual([c[0] for c in fx.calls], ['start', 'ticket'])
        L.act([self.finding()], s0, CFG, fx, True, T0 + 120)                              # cooldown, same ticket, no comment yet
        self.assertEqual([c[0] for c in fx.calls], ['start', 'ticket'])
        L.act([], s0, CFG, fx, True, T0 + 240)                                            # gone for 2 min: not yet recovered
        L.act([self.finding()], s0, CFG, fx, True, T0 + 360)                              # flaps back: still the same ticket
        self.assertEqual(len([c for c in fx.calls if c[0] == 'ticket']), 1)
        self.assertEqual(len([c for c in fx.calls if c[0] == 'start']), 1)
        L.act([], s0, CFG, fx, True, T0 + 480)
        L.act([], s0, CFG, fx, True, T0 + 480 + 601)                                      # absent for clear_seconds: recovered once
        L.act([], s0, CFG, fx, True, T0 + 480 + 900)
        self.assertEqual(len([c for c in fx.calls if c[0] == 'comment' and 'recovered' in c[2]]), 1)
        L.act([self.finding()], s0, CFG, fx, True, T0 + 2400)                             # a new incident inside alert_reopen_days:
        self.assertEqual(len([c for c in fx.calls if c[0] == 'ticket']), 1)                # the SAME ticket is reopened (gq-clutter S1)
        self.assertEqual(len([c for c in fx.calls if c[0] == 'comment' and 'reopened' in c[2]]), 1)

    def _open(self, fx, s0, t=T0):
        L.act([self.finding()], s0, CFG, fx, True, t)
        return s0['alerts']['queue-idle']['ref']

    def test_recovery_closes_its_own_ticket_and_a_firing_alert_is_never_closed(self):
        """goodqa#13953: on a confirmed recovery the filer CLOSES its alert (status done) so recovered
        `^Fleet liveness:` tickets do not pile up open; the negative controls are that a still-firing finding
        is never closed and that a recovered alert is closed (and commented) exactly once."""
        cs = float(CFG.get('clear_seconds', 600))
        fx, s0 = Fx(), st()
        ref = self._open(fx, s0)
        self.assertEqual([c for c in fx.calls if c[0] == 'patch'], [])
        # NEGATIVE CONTROL: the finding keeps firing across MORE than clear_seconds; a live condition is never
        # closed (dropping the `cls in live` skip or its absent_since reset would let its clock run and close it).
        L.act([self.finding()], s0, CFG, fx, True, T0 + 3600)                              # a periodic comment is due
        L.act([self.finding()], s0, CFG, fx, True, T0 + 3600 + 2 * cs)                     # still firing, well past cs
        self.assertEqual([c for c in fx.calls if c[0] == 'patch'], [])
        self.assertFalse(s0['alerts']['queue-idle'].get('cleared'))
        base = T0 + 3600 + 2 * cs
        L.act([], s0, CFG, fx, True, base + 60)                                            # first absent pass: inside window
        self.assertEqual([c for c in fx.calls if c[0] == 'patch'], [])
        L.act([], s0, CFG, fx, True, base + 60 + cs + 1)                                   # absent past cs: closed, once
        self.assertEqual([c for c in fx.calls if c[0] == 'patch'], [('patch', ref, 'done')])
        self.assertEqual(len([c for c in fx.calls if c[0] == 'comment' and 'recovered' in c[2]]), 1)
        self.assertTrue(s0['alerts']['queue-idle'].get('cleared'))
        L.act([], s0, CFG, fx, True, base + 60 + cs + 1 + 900)                             # later pass: no re-close/re-comment
        self.assertEqual(len([c for c in fx.calls if c[0] == 'patch']), 1)
        self.assertEqual(len([c for c in fx.calls if c[0] == 'comment' and 'recovered' in c[2]]), 1)

    def test_recovery_hysteresis_interior_does_not_close(self):
        """M04: a pass strictly inside the clear_seconds window must not close (the window is not ~1 s)."""
        cfg = {k: v for k, v in CFG.items() if k != 'clear_seconds'}                        # exercise the 600 s default
        cs = 600.0
        fx, s0 = Fx(), st()
        self._open(fx, s0)
        L.act([], s0, cfg, fx, True, T0 + 3600)                                            # first absent: absent_since set
        L.act([], s0, cfg, fx, True, T0 + 3600 + cs / 2)                                   # strictly inside the window
        self.assertEqual([c for c in fx.calls if c[0] == 'patch'], [])                     # not closed yet
        L.act([], s0, cfg, fx, True, T0 + 3600 + cs + 1)                                   # past the window
        self.assertEqual(len([c for c in fx.calls if c[0] == 'patch']), 1)

    def test_a_flap_resets_the_absence_clock(self):
        """M02: a finding that fires again resets absent_since, so recovery waits the FULL window from the last absence."""
        cfg = {k: v for k, v in CFG.items() if k != 'clear_seconds'}
        cs = 600.0
        fx, s0 = Fx(), st()
        self._open(fx, s0)
        L.act([], s0, cfg, fx, True, T0 + 100)                                             # absent (absent_since = T0+100)
        L.act([self.finding()], s0, cfg, fx, True, T0 + 200)                               # flaps back live -> clock reset
        L.act([], s0, cfg, fx, True, T0 + 300)                                             # absent again (absent_since = T0+300)
        L.act([], s0, cfg, fx, True, T0 + 300 + cs - 50)                                   # inside the window off the 2nd absence
        self.assertEqual([c for c in fx.calls if c[0] == 'patch'], [])                     # NOT closed early off the 1st absence
        L.act([], s0, cfg, fx, True, T0 + 300 + cs + 1)                                    # full window from the 2nd absence
        self.assertEqual(len([c for c in fx.calls if c[0] == 'patch']), 1)

    def test_recovery_dry_run_would_close_but_writes_nothing(self):
        fx, s0 = Fx(), st()
        self._open(fx, s0)
        before = len(fx.calls)
        L.act([], s0, CFG, fx, False, T0 + 3600)                                           # dry run: first absent pass
        rep = L.act([], s0, CFG, fx, False, T0 + 3600 + 601)                               # dry run: past the hysteresis
        self.assertEqual(len(fx.calls), before)                                            # nothing written
        rec = [r for r in rep if r.get('title') == 'recovered']
        self.assertTrue(rec and rec[0]['alert'].startswith('would close '))

    def test_recovery_does_not_repatch_a_status_already_closed(self):
        """M08: a ticket a human already closed (ANY closed status) is commented once and never re-patched."""
        for status in sorted(L.CLOSED_ALERT_STATUSES):
            fx, s0 = StatusFx(status), st()
            self._open(fx, s0)
            L.act([], s0, CFG, fx, True, T0 + 3600)
            L.act([], s0, CFG, fx, True, T0 + 3600 + 601)
            self.assertEqual([c for c in fx.calls if c[0] == 'patch'], [], status)         # never re-patched
            self.assertEqual(len([c for c in fx.calls if c[0] == 'comment' and 'recovered' in c[2]]), 1, status)
            self.assertTrue(s0['alerts']['queue-idle'].get('cleared'), status)

    def test_recovery_unreadable_status_is_not_closed_and_retries(self):
        """M06: an unreadable ticket status (None) is never patched; the comment posts once and the close retries."""
        fx, s0 = StatusFx(None), st()
        ref = self._open(fx, s0)
        L.act([], s0, CFG, fx, True, T0 + 3600)
        L.act([], s0, CFG, fx, True, T0 + 3600 + 601)                                      # recovered, status unreadable
        self.assertEqual([c for c in fx.calls if c[0] == 'patch'], [])                     # not patched
        self.assertIn(('status', ref), fx.calls)                                           # it did read the status
        self.assertFalse(s0['alerts']['queue-idle'].get('cleared'))                        # cleared unset: retry next pass
        L.act([], s0, CFG, fx, True, T0 + 3600 + 601 + 300)                                # a later pass
        self.assertEqual(len([c for c in fx.calls if c[0] == 'comment' and 'recovered' in c[2]]), 1)   # commented ONCE

    def test_recovery_patch_failure_comments_once_and_does_not_wedge(self):
        """Blind review R1: a raising ticket_patch must not end the pass, must leave `cleared` unset, and must not
        re-post the recovery comment every pass; the close retries next pass."""
        fx, s0 = RaisingPatchFx(), st()
        self._open(fx, s0)
        L.act([], s0, CFG, fx, True, T0 + 3600)                                            # first absent pass
        for extra in (601, 900, 1200):                                                     # several recovered passes
            rep = L.act([], s0, CFG, fx, True, T0 + 3600 + extra)                          # must NOT raise
            self.assertTrue(any(r.get('title') == 'recovered' for r in rep))
        self.assertFalse(s0['alerts']['queue-idle'].get('cleared'))                        # never falsely cleared
        self.assertEqual(len([c for c in fx.calls if c[0] == 'comment' and 'recovered' in c[2]]), 1)   # commented ONCE
        self.assertGreaterEqual(len([c for c in fx.calls if c[0] == 'patch-attempt']), 2)  # it kept retrying the close

    def test_refire_after_a_filer_close_reopens_inside_the_window_and_opens_new_after(self):
        """M20, revised by gq-clutter S1: a re-fire within alert_reopen_days of the filer's close REOPENS that same
        ticket (patch to triage, one comment) instead of filing another; after the window it opens a NEW ticket and
        leaves the old `done` ticket alone. Uses a stateful fake so the closed ticket really reads `done` later."""
        window = float(CFG.get('alert_reopen_days', 7)) * 86400
        fx, s0 = StatefulFx(), st()
        ref1 = self._open(fx, s0)
        L.act([], s0, CFG, fx, True, T0 + 3600)                                            # absent
        L.act([], s0, CFG, fx, True, T0 + 3600 + 601)                                      # recovered -> closed to done
        self.assertEqual(fx._status.get(ref1), 'done')
        self.assertTrue(s0['alerts']['queue-idle'].get('cleared'))
        tickets_before = len([c for c in fx.calls if c[0] == 'ticket'])
        L.act([self.finding()], s0, CFG, fx, True, T0 + 7200)                              # the class fires again
        self.assertEqual(len([c for c in fx.calls if c[0] == 'ticket']), tickets_before)   # no new ticket ...
        self.assertIn(('patch', ref1, 'triage'), fx.calls)                                 # ... the closed one is reopened
        self.assertEqual(s0['alerts']['queue-idle']['ref'], ref1)
        L.act([], s0, CFG, fx, True, T0 + 9000)                                            # clears again
        L.act([], s0, CFG, fx, True, T0 + 9000 + 601)
        self.assertEqual(fx._status.get(ref1), 'done')
        patches = len([c for c in fx.calls if c == ('patch', ref1, 'triage')])
        L.act([self.finding()], s0, CFG, fx, True, T0 + 9000 + 601 + window + 1)          # past the window
        self.assertEqual(len([c for c in fx.calls if c[0] == 'ticket']), tickets_before + 1)   # a NEW ticket opened
        self.assertEqual(len([c for c in fx.calls if c == ('patch', ref1, 'triage')]), patches)  # old one left closed
        self.assertNotEqual(s0['alerts']['queue-idle']['ref'], ref1)

    def test_git_credentials_recovery_is_comment_only_and_never_touches_the_ticket(self):
        """M16/M17: the landed-dark git-credentials class recovers with a comment only -- it must NOT read the
        ticket status or patch it, and it is never closed by this filer."""
        cfg = dict(CFG, git_credentials_mode='off')
        cls = 'git-credentials:dev:operator'
        fx, s0 = StatusFx('triage'), st()
        s0['alerts'][cls] = dict(ref='goodqa#gc-1', opened=T0 - 100, recovery_evidence='secret-evidence')
        # reconcile=False is how git-credentials-off reaches recovery even when nothing else is observed.
        L.act([], s0, cfg, fx, True, T0, reconcile=False)                                  # first absent pass
        L.act([], s0, cfg, fx, True, T0 + 601, reconcile=False)                            # recovered
        self.assertEqual([c for c in fx.calls if c[0] == 'patch'], [])                     # never patched (and no patch-attempt)
        self.assertEqual([c for c in fx.calls if c[0] == 'status'], [])                    # never read the ticket status
        self.assertEqual(len([c for c in fx.calls if c[0] == 'comment']), 1)               # a single recovery comment
        self.assertTrue(s0['alerts'][cls].get('cleared'))

    def test_dry_run_writes_nothing_and_the_rule_flip_goes_through_overrides(self):
        fx = Fx()
        f = dict(cls='rule-refusing:postship-flow', title='t', lines=[],
                 remedies=[dict(kind='rule-warn', config='ticket-lifecycle', key='bug_brief_postship', value='warn', rule='postship-flow')])
        rep = L.act([f], st(), CFG, fx, False, T0)
        self.assertEqual(fx.calls, [])
        self.assertEqual(rep[0]['remedies'][0]['result'], 'would')
        L.act([f], st(), CFG, fx, True, T0)
        self.assertIn(('warn', 'ticket-lifecycle', 'bug_brief_postship', 'warn'), fx.calls)


class _Clock:
    """A fake monotonic clock: returns each value in turn, sticky on the last, so a test can make act()'s
    per-pass alert budget run out deterministically."""
    def __init__(self, values):
        self.values = list(values)
        self.i = 0

    def __call__(self):
        v = self.values[min(self.i, len(self.values) - 1)]
        self.i += 1
        return v


class AlertBudget(unittest.TestCase):
    """goodqa#14007: act() files/comments at most until a per-pass wall budget for GoodQA ticket I/O is spent,
    then DEFERS the rest instead of serially blocking on one `goodqa ticket` call per finding past the unit's
    300s TimeoutStartSec. The incident: 222 findings (128 land-lag + 85 unit-failing), ~5s per ticket call, the
    pass killed before save_state, so every pass re-filed ~200 alerts (state frozen since 03:42Z)."""
    def findings(self, n):
        return [dict(cls='unit-failing:dev:u%d.service' % i, title='u%d failed' % i, lines=['x'], remedies=[])
                for i in range(n)]

    def test_budget_spent_defers_the_rest_and_a_generous_budget_files_them_all(self):
        # alert_start=0; finding 0's room check reads 1 (119s left -> files); findings 1..3 read 200 (budget spent -> defer).
        fx, s0 = Fx(), st()
        rep = L.act(self.findings(4), s0, CFG, fx, True, T0, alert_budget=120, clock=_Clock([0, 1, 200, 200, 200]))
        self.assertEqual(len([c for c in fx.calls if c[0] == 'ticket']), 1)                 # only what fit in the budget
        deferred = [r for r in rep if 'deferred' in str(r.get('alert'))]
        self.assertEqual(len(deferred), 3)
        self.assertEqual(len(s0['alerts']), 1)                                              # the filed alert persists for save_state
        # NEGATIVE CONTROL: a budget that never runs out files every alert and defers none.
        fx2, s2 = Fx(), st()
        rep2 = L.act(self.findings(4), s2, CFG, fx2, True, T0, alert_budget=120, clock=_Clock([0, 1, 2, 3, 4, 5]))
        self.assertEqual(len([c for c in fx2.calls if c[0] == 'ticket']), 4)
        self.assertEqual([r for r in rep2 if 'deferred' in str(r.get('alert'))], [])

    def test_dry_run_never_defers_even_with_no_budget(self):
        # apply=False makes no ticket calls, so an exhausted budget must not turn a dry run into deferrals.
        fx, s0 = Fx(), st()
        rep = L.act(self.findings(3), s0, CFG, fx, False, T0, alert_budget=0, clock=_Clock([0, 999]))
        self.assertEqual(fx.calls, [])
        self.assertEqual([r for r in rep if 'deferred' in str(r.get('alert'))], [])
        self.assertTrue(all(r.get('alert') == 'would open' for r in rep))

    def test_recovery_close_defers_when_the_budget_is_spent_then_closes_next_pass(self):
        fx, s0 = StatefulFx(), st()
        f = dict(cls='unit-failing:dev:u.service', title='u failed', lines=['x'], remedies=[])
        L.act([f], s0, CFG, fx, True, T0)                                                   # open the alert
        ref = s0['alerts'][f['cls']]['ref']
        L.act([], s0, CFG, fx, True, T0 + 3600)                                             # first absent pass: within hysteresis
        before = list(fx.calls)
        # Absent past clear_seconds, but the budget is spent at the recovery gate -> the close is deferred.
        rep = L.act([], s0, CFG, fx, True, T0 + 3600 + 601, alert_budget=120, clock=_Clock([0, 200]))
        self.assertEqual(fx.calls, before)                                                  # no comment/patch this pass
        self.assertIsNone(s0['alerts'][f['cls']].get('cleared'))
        self.assertTrue(any('recovery close deferred' in str(r.get('alert')) for r in rep))
        # NEGATIVE CONTROL: a later pass with budget left really closes the recovered alert to done.
        L.act([], s0, CFG, fx, True, T0 + 3600 + 601 + 10)
        self.assertIn(('patch', ref, 'done'), fx.calls)
        self.assertTrue(s0['alerts'][f['cls']].get('cleared'))

    def test_ticket_timeout_clamps_to_ceiling_and_to_the_remaining_budget(self):
        fx = L.Effects(dict(ticket_timeout_seconds=60))
        self.assertEqual(fx._ticket_timeout(180), 60.0)                                     # no deadline: the configured ceiling
        fx._alert_deadline = time.monotonic() + 8                                           # a near deadline clamps below the ceiling
        self.assertLessEqual(fx._ticket_timeout(180), 9.0)
        fx._alert_deadline = time.monotonic() - 100                                         # a spent budget still leaves a working floor
        self.assertEqual(fx._ticket_timeout(180), 5.0)


class _Spent:                      # a clock already past any budget after the first read (alert_start)
    def __init__(self):
        self.i = 0

    def __call__(self):
        self.i += 1
        return 0.0 if self.i == 1 else 10_000.0


class _Frozen:                     # a clock that never advances (budget never spent)
    def __call__(self):
        return 0.0


def _finds(n, prefix='unit-failing:dev:u'):
    return [dict(cls='%s%d.service' % (prefix, i), title='u%d' % i, lines=['x'], remedies=[]) for i in range(n)]


class AlertBudgetReviewer(unittest.TestCase):
    """Independent blind-review behaviour tests for the goodqa#14007 alert budget (reviewer a9c07fc, adapted inline).
    These kill the 12 mutants the first author suite missed: the `due`/ref=None gate (R7), deferred-stays-live (R2),
    dry-run makes no WRITES (R3), the _alert_deadline reset (R4), every real call site honours the clamp (R5), run_pass
    pass-budget plumbing (R6), the boundary (R9), and the known-good negative control (N)."""
    # R1: a non-due finding (recent alert) must NOT be deferred or touched when the budget is spent
    def test_R1_non_due_finding_not_deferred_and_no_calls(self):
        fx, s0 = Fx(), st()
        s0['alerts']['unit-failing:dev:a.service'] = dict(ref='goodqa#1', opened=T0, commented=T0, last='', note='ok')
        rep = L.act([dict(cls='unit-failing:dev:a.service', title='a', lines=['x'], remedies=[])], s0, CFG, fx, True, T0 + 60,
                    alert_budget=0, clock=_Spent())
        self.assertEqual(fx.calls, [])
        self.assertEqual(rep[0]['alert'], 'open goodqa#1')

    # R2: a deferred, still-firing finding stays LIVE: never marked absent / never closed as recovered
    def test_R2_deferred_finding_is_not_recovered_or_closed(self):
        fx, s0 = StatefulFx(), st()
        f = dict(cls='unit-failing:dev:b.service', title='b', lines=['x'], remedies=[])
        s0['alerts'][f['cls']] = dict(ref='goodqa#2', opened=T0, commented=T0, last='', note='ok')
        for k in range(4):
            now = T0 + 4000 + k * 700
            rep = L.act([f], s0, CFG, fx, True, now, alert_budget=0, clock=_Spent())
            self.assertNotIn('absent_since', s0['alerts'][f['cls']])
            self.assertFalse(any(r.get('title') == 'recovered' for r in rep))
        self.assertFalse([c for c in fx.calls if c[0] in ('patch', 'comment', 'ticket')])
        L.act([f], s0, CFG, fx, True, T0 + 9000, alert_budget=120, clock=_Frozen())
        self.assertTrue([c for c in fx.calls if c[0] in ('status', 'comment')])           # the overdue ticket I/O resumes

    # R3: dry run makes no WRITE calls and never defers, even with an overdue alert and zero budget
    def test_R3_dry_run_no_writes_never_defers(self):
        fx, s0 = StatusFx(), st()
        f = dict(cls='unit-failing:dev:c.service', title='c', lines=['x'], remedies=[])
        s0['alerts'][f['cls']] = dict(ref='goodqa#3', opened=T0, commented=T0, last='', note='ok')
        rep = L.act([f], s0, CFG, fx, False, T0 + 4000, alert_budget=0, clock=_Spent())
        self.assertFalse([c for c in fx.calls if c[0] in ('ticket', 'patch', 'comment')])
        self.assertNotIn('deferred', str(rep[0]['alert']))

    def _recording_effects(self):
        fx = L.Effects(dict(CFG))
        seen = []

        def fake_run(cmd, timeout=10, input=None, env=None):
            seen.append((cmd[1:3] if len(cmd) > 2 else cmd, timeout))
            return 0, 'goodqa#4242', ''
        return fx, seen, fake_run

    # R4: stale _alert_deadline must not leak out of act() into later direct calls (reopen_closed)
    def test_R4_deadline_cleared_after_act(self):
        fx, seen, fake_run = self._recording_effects()
        with mock.patch.object(L.C, 'run', fake_run), mock.patch.object(L.C, 'journal'):
            L.act(_finds(1), st(), CFG, fx, True, T0, alert_budget=0.01, clock=_Frozen())
            self.assertIsNone(getattr(fx, '_alert_deadline', None))
            seen.clear()
            fx.ticket_status('goodqa#9')
            self.assertEqual(seen[-1][1], 60.0)              # ceiling, not the 5s floor from a stale spent deadline

    # R5: every real Effects ticket call site honours the clamp (not just the helper)
    def test_R5_call_sites_use_the_clamp(self):
        fx, seen, fake_run = self._recording_effects()
        fx._alert_deadline = time.monotonic() + 8
        with mock.patch.object(L.C, 'run', fake_run):
            fx.ticket_new('t', 'b', 'k')
            fx.ticket_status('goodqa#1')
            fx.comment('goodqa#1', 'b')
        self.assertEqual(len(seen), 3)
        for cmd, timeout in seen:
            self.assertLessEqual(timeout, 9.0, cmd)

    # R6: run_pass hands act() what is left of pass_budget_seconds (collection cost eats into it), both branches
    def _run_pass_budget(self, collection_cost, fail_collection=False):
        offset = [0.0]
        real = time.monotonic
        got = []

        class PFx(Fx):
            def snapshot(self_inner):
                offset[0] += collection_cost
                if fail_collection:
                    raise RuntimeError('collect failed')
                return dict(counts=dict(running=30, queued=0), services={})

            def lane_floor_floor(self_inner):
                return 40

            def lane_floor_lines(self_inner, since):
                return []

            def refusals(self_inner):
                return []

            def land_lag_rows(self_inner, known=None):
                return dict(rows=[], errors=[])

            def hawk(self_inner, m):
                return 0, '', ''
        real_act = L.act

        def spy(*a, **k):
            got.append(k.get('alert_budget'))
            return real_act(*a, **k)
        with mock.patch.object(L.time, 'monotonic', lambda: real() + offset[0]), mock.patch.object(L, 'act', spy), \
                mock.patch.object(L.C, 'journal'):
            L.run_pass(dict(CFG, deploy_lag_mode='off'), PFx(), True, now=T0, state=st())
        return got

    def test_R6_run_pass_budget_tracks_pass_budget(self):
        self.assertAlmostEqual(self._run_pass_budget(0)[0], 120, delta=2)
        self.assertAlmostEqual(self._run_pass_budget(200)[0], 40, delta=2)
        self.assertAlmostEqual(self._run_pass_budget(500)[0], 10, delta=0.5)
        self.assertAlmostEqual(self._run_pass_budget(200, fail_collection=True)[0], 40, delta=2)

    # R7 (the blocker this review caught): a persisted ref=None alert (a failed filing) is retried WITHOUT the budget
    def test_R7_ref_none_retry_is_budget_gated(self):
        fx, s0 = Fx(), st()
        for f in _finds(30):
            s0['alerts'][f['cls']] = dict(ref=None, opened=T0, commented=T0, last='', note='api down')
        L.act(_finds(30), s0, CFG, fx, True, T0 + 120, alert_budget=0, clock=_Spent())
        self.assertEqual(len([c for c in fx.calls if c[0] == 'ticket']), 0)

    # R8: total fake time for many due NEW findings stays within the budget (+ at most one floor call)
    def test_R8_new_findings_total_time_bounded(self):
        t = [0.0]

        class SlowFx(Fx):
            def ticket_new(self_inner, title, body, idem):
                t[0] += 5.0
                return super().ticket_new(title, body, idem)
        L.act(_finds(300), st(), CFG, SlowFx(), True, T0, alert_budget=120, clock=lambda: t[0])
        self.assertLessEqual(t[0], 120 + 5.0)

    # R9: boundary -- room == 0 exactly counts as spent, at both the finding gate and the recovery gate
    def test_R9a_boundary_finding_gate(self):
        seq = iter([0.0, 120.0, 120.0, 120.0])
        fx = Fx()
        rep = L.act(_finds(1), st(), CFG, fx, True, T0, alert_budget=120, clock=lambda: next(seq))
        self.assertEqual([c for c in fx.calls if c[0] == 'ticket'], [])
        self.assertIn('deferred', str(rep[0]['alert']))

    def test_R9b_boundary_recovery_gate(self):
        fx, s0 = StatefulFx(), st()
        L.act(_finds(1), s0, CFG, fx, True, T0, alert_budget=120, clock=_Frozen())
        L.act([], s0, CFG, fx, True, T0 + 3600, alert_budget=120, clock=_Frozen())
        before = list(fx.calls)
        seq = iter([0.0, 120.0, 120.0, 120.0])
        rep = L.act([], s0, CFG, fx, True, T0 + 3600 + 601, alert_budget=120, clock=lambda: next(seq))
        self.assertEqual(fx.calls, before)
        self.assertTrue(any('recovery close deferred' in str(r.get('alert')) for r in rep))

    # N: NEGATIVE CONTROL: generous budget files everything, defers nothing, then recovers and closes
    def test_N_known_good_path(self):
        fx, s0 = StatefulFx(), st()
        rep = L.act(_finds(10), s0, CFG, fx, True, T0, alert_budget=120, clock=_Frozen())
        self.assertEqual(len([c for c in fx.calls if c[0] == 'ticket']), 10)
        self.assertFalse([r for r in rep if 'deferred' in str(r.get('alert'))])
        self.assertEqual(len(s0['alerts']), 10)
        L.act([], s0, CFG, fx, True, T0 + 3600, alert_budget=120, clock=_Frozen())
        L.act([], s0, CFG, fx, True, T0 + 3600 + 601, alert_budget=120, clock=_Frozen())
        self.assertEqual(len([c for c in fx.calls if c[0] == 'patch']), 10)

    # the pass-budget helper in isolation (floor / ceiling / pass_budget subtraction)
    def test_act_budget_helper(self):
        c = dict(act_budget_seconds=120, act_budget_floor_seconds=10, pass_budget_seconds=240)
        self.assertEqual(L._act_budget(c, 0), 120)            # cheap collection -> the ceiling
        self.assertEqual(L._act_budget(c, 210), 30)           # 210s of collection -> 240-210 left
        self.assertEqual(L._act_budget(c, 500), 10)           # past the pass budget -> the floor


class AlertBudgetReviewerR2(unittest.TestCase):
    """Round-2 blind-review tests (reviewer a9c07fc), adapted inline: sibling behaviours of the ref=None blocker that
    the R1-R10 set did not cover -- remedies fire under a spent budget, the git-credentials comment-only recovery and
    the cleared-alert deferral/refire are budget-gated, a ref=None record heals when budget allows and is only
    postponed (never lost) when spent, the `due` gate is not over-widened, and _act_budget edge/boundary cases."""
    def test_X1_remedies_still_fire_when_budget_is_spent(self):
        fx, s0 = Fx(), st()
        f = dict(cls='queue-idle', title='q', lines=['x'], remedies=[dict(kind='start-unit', unit='lane-floor.service', why='w')])
        rep = L.act([f], s0, CFG, fx, True, T0, alert_budget=0, clock=_Spent())
        self.assertIn(('start', 'lane-floor.service'), fx.calls)
        self.assertFalse([c for c in fx.calls if c[0] == 'ticket'])
        self.assertIn('deferred', str(rep[0]['alert']))
        self.assertEqual(rep[0]['remedies'][0]['result'][:4], 'rc=0')

    def test_X2_git_credentials_recovery_comment_is_budget_gated(self):
        fx, s0 = StatefulFx(), st()
        cls = 'git-credentials:dev'
        s0['alerts'][cls] = dict(ref='goodqa#55', opened=T0 - 9000, commented=T0 - 9000, last='', note='ok', absent_since=T0 - 5000)
        cfg = dict(CFG, git_credentials_mode='off')
        before = list(fx.calls)
        L.act([], s0, cfg, fx, True, T0, alert_budget=0, clock=_Spent())
        self.assertEqual(fx.calls, before)
        self.assertIsNone(s0['alerts'][cls].get('cleared'))
        L.act([], s0, cfg, fx, True, T0 + 5, alert_budget=120, clock=_Frozen())
        self.assertTrue([c for c in fx.calls if c[0] == 'comment'])
        self.assertFalse([c for c in fx.calls if c[0] == 'patch'])

    def test_X3_cleared_alert_deferral_message(self):
        fx, s0 = Fx(), st()
        f = dict(cls='unit-failing:dev:z.service', title='z', lines=['x'], remedies=[])
        s0['alerts'][f['cls']] = dict(ref='goodqa#9', opened=T0 - 9000, commented=T0 - 9000, last='', note='ok', cleared=T0 - 100)
        rep = L.act([f], s0, CFG, fx, True, T0, alert_budget=0, clock=_Spent())
        self.assertEqual(rep[0]['alert'], 'deferred: alert budget spent')
        self.assertEqual(fx.calls, [])

    def test_X4_ref_none_alert_is_retried_and_heals_when_budget_allows(self):
        fx, s0 = Fx(), st()
        f = dict(cls='unit-failing:dev:y.service', title='y', lines=['x'], remedies=[])
        s0['alerts'][f['cls']] = dict(ref=None, opened=T0 - 60, commented=T0 - 60, last='', note='api down')
        rep = L.act([f], s0, CFG, fx, True, T0, alert_budget=120, clock=_Frozen())
        self.assertEqual(len([c for c in fx.calls if c[0] == 'ticket']), 1)
        self.assertTrue(s0['alerts'][f['cls']].get('ref'))
        self.assertTrue(str(rep[0]['alert']).startswith('opened'))

    def test_X5_deferred_ref_none_retries_next_pass(self):
        fx, s0 = Fx(), st()
        f = dict(cls='unit-failing:dev:w.service', title='w', lines=['x'], remedies=[])
        s0['alerts'][f['cls']] = dict(ref=None, opened=T0 - 60, commented=T0 - 60, last='', note='api down')
        L.act([f], s0, CFG, fx, True, T0, alert_budget=0, clock=_Spent())
        self.assertFalse(s0['alerts'][f['cls']].get('ref'))
        L.act([f], s0, CFG, fx, True, T0 + 120, alert_budget=120, clock=_Frozen())
        self.assertTrue(s0['alerts'][f['cls']].get('ref'))

    def test_X6_recent_alert_with_ref_is_still_not_due(self):
        fx, s0 = Fx(), st()
        f = dict(cls='unit-failing:dev:v.service', title='v', lines=['x'], remedies=[])
        s0['alerts'][f['cls']] = dict(ref='goodqa#5', opened=T0, commented=T0, last='', note='ok')
        rep = L.act([f], s0, CFG, fx, True, T0 + 60, alert_budget=0, clock=_Spent())
        self.assertEqual(fx.calls, [])
        self.assertEqual(rep[0]['alert'], 'open goodqa#5')

    def test_X7_act_budget_edges(self):
        c = dict(act_budget_seconds=120, act_budget_floor_seconds=10, pass_budget_seconds=240)
        self.assertEqual(L._act_budget(c, 120), 120)
        self.assertEqual(L._act_budget(c, 121), 119)
        self.assertEqual(L._act_budget(c, 230), 10)
        self.assertEqual(L._act_budget(c, 239), 10)
        self.assertEqual(L._act_budget({}, 0), 120)

    def test_X8_run_pass_uses_elapsed_not_zero(self):
        seen = []
        real = L._act_budget

        def spy(cfg, elapsed):
            seen.append(elapsed)
            return real(cfg, elapsed)
        off = [0.0]
        rm = time.monotonic

        class PFx(Fx):
            def snapshot(self_i):
                off[0] += 77
                return dict(counts=dict(running=30, queued=0), services={})

            def lane_floor_floor(self_i):
                return 40

            def lane_floor_lines(self_i, s):
                return []

            def refusals(self_i):
                return []

            def land_lag_rows(self_i, known=None):
                return dict(rows=[], errors=[])

            def hawk(self_i, m):
                return 0, '', ''
        with mock.patch.object(L.time, 'monotonic', lambda: rm() + off[0]), mock.patch.object(L, '_act_budget', spy), \
                mock.patch.object(L.C, 'journal'):
            L.run_pass(dict(CFG, deploy_lag_mode='off'), PFx(), True, now=T0, state=st())
        self.assertTrue(seen and seen[0] >= 77, seen)

    def test_X9_cleared_refire_with_recent_comment_is_budget_gated(self):
        fx, s0 = Fx(), st()
        f = dict(cls='unit-failing:dev:flap.service', title='flap', lines=['x'], remedies=[])
        s0['alerts'][f['cls']] = dict(ref='goodqa#9', opened=T0 - 600, commented=T0 - 300, last='', note='ok', cleared=T0 - 100)
        rep = L.act([f], s0, CFG, fx, True, T0, alert_budget=0, clock=_Spent())
        self.assertEqual([c for c in fx.calls if c[0] == 'ticket'], [])
        self.assertEqual(rep[0]['alert'], 'deferred: alert budget spent')
        L.act([f], s0, CFG, fx, True, T0 + 120, alert_budget=120, clock=_Frozen())
        self.assertEqual([c for c in fx.calls if c[0] == 'ticket'], [])                   # inside alert_reopen_days:
        self.assertIn(('patch', 'goodqa#9', 'triage'), fx.calls)                          # the same ticket is reopened


class Overrides(unittest.TestCase):
    def tearDown(self):
        if os.path.exists(os.environ['GOODQA_RULE_OVERRIDES']):
            os.remove(os.environ['GOODQA_RULE_OVERRIDES'])

    def test_set_apply_clear_and_never_raise(self):
        self.assertEqual(RO.apply('tests-lint', {'from_file': 'enforce'}), {'from_file': 'enforce'})
        RO.set_value('tests-lint', 'from_file', 'warn', 'test')
        self.assertEqual(RO.apply('tests-lint', {'from_file': 'enforce', 'x': 1}), {'from_file': 'warn', 'x': 1})
        self.assertEqual(RO.apply('lane-floor', {'brief_tickets': 'enforce'}), {'brief_tickets': 'enforce'})   # other configs untouched
        self.assertTrue(RO.clear('tests-lint', 'from_file'))
        self.assertEqual(RO.apply('tests-lint', {'from_file': 'enforce'}), {'from_file': 'enforce'})
        open(os.environ['GOODQA_RULE_OVERRIDES'], 'w').write('not json')
        self.assertEqual(RO.apply('tests-lint', {'a': 1}), {'a': 1})

    def test_the_rule_loaders_honour_an_override(self):
        import goodqa_lifecycle as LC
        import lane_floor as LF
        import tests_lint as TL
        RO.set_value('ticket-lifecycle', 'bug_brief_postship', 'warn', 't')
        RO.set_value('tests-lint', 'from_file', 'warn', 't')
        RO.set_value('lane-floor', 'brief_tickets', 'warn', 't')
        root = os.path.dirname(HERE)
        self.assertEqual(LC.load_config(os.path.join(root, 'config', 'ticket-lifecycle.json'))['bug_brief_postship'], 'warn')
        self.assertEqual(TL._load_config()['from_file'], 'warn')
        self.assertEqual(LF.load_config(os.path.join(root, 'config', 'lane-floor.json'))['brief_tickets'], 'warn')
        os.remove(os.environ['GOODQA_RULE_OVERRIDES'])                                    # negative control: the committed values
        self.assertEqual(LF.load_config(os.path.join(root, 'config', 'lane-floor.json'))['brief_tickets'],
                         json.load(open(os.path.join(root, 'config', 'lane-floor.json')))['brief_tickets'])


class Replay(unittest.TestCase):
    def test_replay_reconstructs_counts_drain_and_merges(self):
        lines = ['2026-10-23T20:00:00Z state      goodqa-a -> running | started',
                 '2026-10-23T20:00:00Z state      goodqa-b -> queued | x',
                 '2026-10-23T20:01:00Z state      goodqa-c -> merged | GRADE PASS tree T commit C',
                 '2026-10-23T20:02:00Z fleet       fleet=drain | deploy drain: install.sh 12bccf532663',
                 '2026-10-23T20:03:00Z state      goodqa-a -> paused | drain',
                 '2026-10-23T20:10:00Z fleet       fleet=undrain | supervisor started']
        ss = L.replay_samples(lines, {}, dict(CFG), [], [], L.ts('2026-10-23T20:00:00Z'), L.ts('2026-10-23T20:12:00Z'))
        at = {L.iso(s['at'])[11:16]: s for s in ss}
        self.assertEqual((at['20:00']['running'], at['20:00']['queued']), (1, 1))
        self.assertEqual(at['20:04']['drain']['install'], '12bccf532663')
        self.assertEqual((at['20:04']['running'], at['20:04']['holders']), (0, []))
        self.assertIsNone(at['20:10']['drain'])
        self.assertEqual(at['20:02']['last_merge']['goodqa'], L.ts('2026-10-23T20:01:00Z'))


def tearDownModule():
    shutil.rmtree(_TMP, ignore_errors=True)



class TrainStalled(unittest.TestCase):
    """goodqa#7956: trains kept running while 39 of 40 GoodQA train grades STOPped; merge-stall only watches merges."""

    def tv(self, verdict, hours_ago, head='STOP: x: control testrun suite targeted did not run tests (status empty) (control rc=0 merged rc=1)'):
        return dict(ts=L.iso(T0 - hours_ago * 3600), lead='goodqa-car', product='goodqa', verdict=verdict, head=head)

    def base(self, **kw):
        k = dict(merging={'goodqa': 15}, merge_trains={'goodqa': 8},
                 train_verdicts=[self.tv('PASS', 5), self.tv('STOP', 2), self.tv('STOP', 1),
                                 self.tv('STOP', 0.5, 'STOP: y: nonzero exit without identifiable test failures (control rc=2 merged rc=2)')],
                 train_running=[dict(lead='goodqa-lead', product='goodqa', dir='merge-grade-train6-1', started='s', last='l')])
        k.update(kw)
        return sample(**k)

    def test_fires_with_the_top_stop_class_and_the_train_in_grade(self):
        f = [x for x in L.evaluate(self.base(), st(), CFG) if x['cls'].startswith('train-stalled')]
        self.assertEqual([x['cls'] for x in f], ['train-stalled:goodqa'])
        text = '\n'.join(f[0]['lines'])
        self.assertIn('bare targeted testrun', text)
        self.assertIn('fails on main too', text)
        self.assertIn('goodqa-lead', text)
        self.assertIn('STOP x3', text)

    def test_negative_controls(self):
        def none(s):
            return [x for x in L.evaluate(s, st(), CFG) if x['cls'].startswith('train-stalled')] == []
        self.assertTrue(none(self.base(train_verdicts=[self.tv('PASS', 1), self.tv('STOP', 0.5)])))      # a PASS inside 3 h
        self.assertTrue(none(self.base(merging={'goodqa': 10})))                                       # not more than 10 merging
        self.assertTrue(none(self.base(merge_trains={})))                                              # no train configured
        self.assertTrue(none(self.base(merge_trains={'goodqa': 1})))
        self.assertTrue(none(self.base(last_grade_pass={'goodqa': T0 - 600})))                          # a GRADE PASS landing
        self.assertFalse(none(self.base(last_grade_pass={'goodqa': T0 - 4 * 3600})))                    # an old one does not count
        self.assertTrue(none(self.base(train_verdicts=[self.tv('PASS', 1)] + [dict(self.tv('STOP', 0.2), ts=L.iso(T0 + 600))])))

    def test_stop_class_names(self):
        self.assertIn('rc 124', L.train_stop_class('STOP: rc=0; x: control or merged run could not complete (control rc=124 merged rc=124)'))
        self.assertIn('rc 127', L.train_stop_class('STOP: x: could not complete (control rc=127 merged rc=127)'))
        self.assertIn('nothing countable', L.train_stop_class('STOP: x --wait-max 1800: no evidence that tests executed (silent success)'))


# ------------------------------------------------------------------------------------------------ deploy-lag (ruling 82)
LIVE = 'a' * 40
IGN = CFG['deploy_lag_ignore']


def sha(n):
    return '%040x' % (n + 1)


def cmp_main(n_main=3, branch=2, files=('apps/api/src/x.ts',), behind=0, landed_min=90):
    """live <- m1 <- m2 <- m3 (main, first parents); each merge also brings `branch` old branch commits."""
    commits, prev = [], LIVE
    for i in range(n_main):
        side = []
        for b in range(branch):
            c = dict(sha=sha(100 * i + b + 50), parents=[prev], date=L.iso(T0 - 3 * 86400))      # a branch commit days old
            commits.append(c)
            side.append(c['sha'])
        m = dict(sha=sha(100 * i), parents=[prev] + side[-1:], date=L.iso(T0 - (landed_min - i) * 60))
        commits.append(m)
        prev = m['sha']
    return dict(status='ahead' if not behind else 'diverged', ahead_by=len(commits), behind_by=behind, commits=commits, files=list(files))


class DeployLag(unittest.TestCase):
    def test_main_line_time_ignores_old_branch_commits(self):
        r = L.reduce_compare(cmp_main(), T0, IGN)
        self.assertEqual((r['ahead'], r['mainline'], r['main']), (9, 3, sha(200)))
        self.assertEqual(r['minutes'], 90.0)                                   # the first merge, not the 3-day-old branch commits
        self.assertEqual(r['since_source'], 'main-line commit time')

    def test_push_time_wins_over_commit_time(self):
        c = cmp_main()
        pushes = [dict(ts=L.iso(T0 - 600), after=sha(200)), dict(ts=L.iso(T0 - 3000), after=sha(0)),
                  dict(ts=L.iso(T0 - 9000), after=LIVE)]                       # the push that made main = live: shipped
        r = L.reduce_compare(c, T0, IGN, pushes)
        self.assertEqual((r['minutes'], r['since_source']), (50.0, 'first push of an unshipped product change to main'))
        r = L.reduce_compare(c, T0, IGN, pushes[:2])                           # every listed push unshipped: flagged a lower bound
        self.assertIn('lower bound', r['since_source'])
        r = L.reduce_compare(c, T0, IGN, [dict(ts=L.iso(T0 - 60), after='f' * 40)])   # no push names an unshipped commit: commit time
        self.assertEqual(r['since_source'], 'main-line commit time')

    def test_docs_and_lanes_only_do_not_count_but_a_capped_file_list_does(self):
        self.assertEqual(L.reduce_compare(cmp_main(files=('.lanes/x/RESULT.md', 'docs/a.md')), T0, IGN)['product_files'], 0)
        self.assertEqual(L.reduce_compare(cmp_main(files=['docs/%d.md' % i for i in range(300)]), T0, IGN)['product_files'], 1)
        self.assertEqual(L.reduce_compare(cmp_main(files=('apps/web/a.tsx', 'docs/a.md')), T0, IGN)['product_files'], 1)

    def test_pages_merge(self):
        text = json.dumps(dict(ahead_by=3, commits=[{'sha': 'x'}], files=['a'])) + '\n' + json.dumps(dict(ahead_by=3, commits=[{'sha': 'y'}], files=[]))
        m = L.merge_pages(text)
        self.assertEqual(([c['sha'] for c in m['commits']], m['files'], m['ahead_by']), (['x', 'y'], ['a'], 3))
        with self.assertRaises(ValueError):
            L.merge_pages('  ')

    def test_live_from_status(self):
        self.assertEqual(L.live_from_status(dict(outcome='current', sha=LIVE)), LIVE)
        self.assertEqual(L.live_from_status(dict(outcome='shipped', main=sha(1), live_after={'sourceSha': sha(2)})), sha(2))
        self.assertEqual(L.live_from_status(dict(outcome='current', main=sha(3), live_before=sha(4))), sha(3))
        for rec in (dict(outcome='unknown', sha=LIVE), dict(outcome='held', main=LIVE), dict(outcome='current', sha='abc'), None, 'x'):
            self.assertIsNone(L.live_from_status(rec))                        # a failed pass proves nothing about what is live

    def lagged(self, minutes=90.0, **kw):
        d = dict(live=LIVE, live_source='https://goodqa.app/v1/version', main=sha(200), ahead=9, behind=0, mainline=3, truncated=False,
                 landed=T0 - (minutes or 0) * 60, minutes=minutes, product_files=4, since_source='first push of an unshipped commit to main')
        d.update(kw)
        return d

    def test_fires_after_sixty_minutes_with_the_blockers(self):
        s = sample(deploy_lag={'goodqa': self.lagged()}, ship_waves={'goodqa': dict(id='wave-1', stage='deploying', started='t0',
                                                                                    updated='t1', retries=0, sha='abc', reason='r')})
        f = [x for x in L.evaluate(s, st(), CFG) if x['cls'] == 'deploy-lag:goodqa']
        self.assertEqual(len(f), 1)
        self.assertIn('by 3 main-line commit(s) (9 total) for 90 min', f[0]['title'])
        self.assertTrue(any(line.startswith('deploy running: runner ship wave wave-1 deploying') for line in f[0]['lines']))
        self.assertIsNone(f[0]['post'])                                        # warn: nothing for the release ticket

    def test_negative_controls(self):
        def fired(d, **kw):
            return [x['cls'] for x in L.evaluate(sample(deploy_lag={'goodqa': d}, **kw), st(), CFG) if x['cls'].startswith('deploy-lag')]
        self.assertEqual(fired(self.lagged(60.0)), [])                         # exactly 60 min: not more than 60
        self.assertEqual(fired(self.lagged(60.1)), ['deploy-lag:goodqa'])
        self.assertEqual(fired(self.lagged(ahead=0)), [])                      # live is main
        self.assertEqual(fired(self.lagged(product_files=0)), [])              # only docs / .lanes changed
        self.assertEqual(fired(dict(error='live sha unreadable')), [])         # unreadable: a report line, not a finding
        self.assertEqual(fired(self.lagged(minutes=None)), [])
        cfg = dict(CFG, deploy_lag_mode='off')
        self.assertEqual([x for x in L.evaluate(sample(deploy_lag={'goodqa': self.lagged()}), st(), cfg) if x['cls'].startswith('deploy')], [])

    def test_blocker_names(self):
        spec = dict(status_name='timbar-preview-ship')
        s = sample(drain=dict(since=T0 - 600, reason='deploy drain', install='abc123'), fleet_state='PAUSED: halted: memory available 9 GB',
                   ship_waves={'timbar': dict(id='w2', stage='rolled-back', started='t', updated='u', retries=2, sha='465c', reason='deploy exit 75')},
                   ship_watch={'dev:timbar-preview-ship': dict(product='timbar', source='DEV timer timbar-preview-ship', kind='unknown',
                                                               since='2026-10-24T00:03:35+00:00', reason='HOLD: x'),
                               'runner:timbar': dict(product='timbar', source='runner ship stage', kind='failing', reason='dup'),
                               'dev:optin-ship': dict(product='optinrouter', source='DEV timer optin-ship', kind='held', reason='y')},
                   deploy_lag={'timbar': dict(status_record=dict(outcome='unknown', reason='admission execute HOLD', finished_at='f'))})
        lines = L.deploy_blockers(s, 'timbar', spec)
        self.assertEqual([x.split(':')[0] for x in lines], ['install drain since 2026-10-23T20', 'fleet', 'ship refused or failed',
                                                            'ship-watch DEV timer timbar-preview-ship', 'ship refused'])
        self.assertFalse(any('dup' in x for x in lines))                       # the runner incident is the wave line already
        self.assertEqual(len(L.deploy_blockers(s, 'optin', {})), 3)            # optinrouter incidents map to optin (+ drain, fleet)
        self.assertEqual(L.deploy_blockers(sample(deploy_lag={'optin': dict(status_record=dict(outcome='current'))},
                                                  ship_waves={'optin': dict(stage='shipped')}), 'optin', {}), [])
        f = L.deploy_lag_findings(sample(deploy_lag={'optin': self.lagged()}), CFG)
        self.assertIn('blocker: none known', f[0]['lines'][-1])

    def test_enforce_posts_to_the_release_ticket_at_the_alert_cadence(self):
        cfg = dict(CFG, deploy_lag_mode='enforce')
        fs = L.deploy_lag_findings(sample(deploy_lag={'goodqa': self.lagged()}), cfg)
        self.assertEqual(fs[0]['post'], cfg['deploy_lag_products']['goodqa']['release_ticket'])
        fx, s0 = Fx(), st()
        rep = L.act(fs, s0, cfg, fx, False, T0)                                # dry run: nothing
        self.assertEqual((fx.calls, rep[0]['posted']), ([], 'would post to goodqa#5938'))
        rep = L.act(fs, s0, cfg, fx, True, T0)
        self.assertEqual([c[:2] for c in fx.calls], [('ticket', 'Fleet liveness: ' + fs[0]['title']), ('comment', 'goodqa#5938')])
        L.act(fs, s0, cfg, fx, True, T0 + 120)                                 # inside alert_comment_minutes: no second post
        self.assertEqual(len([c for c in fx.calls if c[:2] == ('comment', 'goodqa#5938')]), 1)
        every = float(cfg['alert_comment_minutes']) * 60
        L.act(fs, s0, cfg, fx, True, T0 + every + 60)                          # past the cadence, nothing material: no post
        self.assertEqual(len([c for c in fx.calls if c[:2] == ('comment', 'goodqa#5938')]), 1)
        changed = [dict(fs[0], title=fs[0]['title'] + ' (ship refused)')]
        L.act(changed, s0, cfg, fx, True, T0 + every + 180)                    # a material change: alert + release ticket again
        self.assertEqual(len([c for c in fx.calls if c[:2] == ('comment', 'goodqa#5938')]), 2)
        fx2 = Fx()                                                             # warn: the alert ticket, never the release ticket
        rep = L.act(L.deploy_lag_findings(sample(deploy_lag={'goodqa': self.lagged()}), CFG), st(), CFG, fx2, True, T0)
        self.assertEqual([c[0] for c in fx2.calls], ['ticket'])
        self.assertIn('warn mode', rep[0]['posted'])


class LagFx(Fx):
    def __init__(self, live_url=LIVE, status=None, fail=False):
        super().__init__()
        self.live_url, self.status, self.fail = live_url, status, fail

    def http_json(self, url, timeout=20):
        self.calls.append(('http', url))
        if self.fail:
            raise OSError('connection refused')
        return {'sourceSha': self.live_url, 'version': 'selfhost-x'}

    def json_cmd(self, argv, timeout=150):
        self.calls.append(('cmd', argv[-1]))
        return (self.status, 0, '') if argv[-1] == 'status' else ({'sourceSha': sha(7), 'healthy': True}, 0, '')

    def gh_compare(self, repo, base, head='main', timeout=30):
        self.calls.append(('compare', repo, base))
        return cmp_main()

    def gh_pushes(self, repo, ref='refs/heads/main', timeout=20):
        self.calls.append(('pushes', repo))
        return []


class DeployLagCollect(unittest.TestCase):
    def test_sources_cache_and_errors(self):
        cfg = dict(CFG, deploy_lag_products={k: CFG['deploy_lag_products'][k] for k in ('goodqa', 'timbar')})
        fx, s0 = LagFx(status=dict(outcome='current', main=sha(9), checked=L.iso(T0 - 120))), st()
        out = L.deploy_lag(cfg, fx, s0, T0)
        self.assertEqual(out['goodqa']['live'], LIVE)                          # GoodQA: /v1/version sourceSha
        self.assertEqual((out['timbar']['live'], out['timbar']['live_source']), (sha(9), 'status line'))   # timbar: its status line
        self.assertNotIn(('cmd', 'readback'), fx.calls)
        n = len(fx.calls)
        out = L.deploy_lag(cfg, fx, s0, T0 + 120)                              # cached: no reads, minutes move on
        self.assertEqual(len(fx.calls), n)
        self.assertEqual(out['goodqa']['minutes'], 92.0)
        fx2 = LagFx(status=dict(outcome='unknown', reason='HOLD'))
        out = L.deploy_lag(cfg, fx2, st(), T0)
        self.assertEqual((out['timbar']['live'], out['timbar']['live_source']), (sha(7), 'bin/timbar-preview-ship.py readback'))
        out = L.deploy_lag(cfg, LagFx(fail=True), st(), T0)                    # an unreachable version: an error line, never a raise
        self.assertIn('OSError', out['goodqa']['error'])
        out = L.deploy_lag(cfg, LagFx(live_url='not-a-sha'), st(), T0)
        self.assertIn('live sha unreadable', out['goodqa']['error'])
        s1 = st()
        L.deploy_lag(cfg, LagFx(), s1, T0)
        L.deploy_lag(dict(cfg, deploy_lag_products={'goodqa': cfg['deploy_lag_products']['goodqa']}), LagFx(), s1, T0 + 700)
        self.assertEqual(sorted(s1['deploy_lag']), ['goodqa'])                # a product taken out of config is dropped
        self.assertEqual(L.deploy_lag(dict(cfg, deploy_lag_mode='off'), LagFx(), st(), T0), {})

    def test_a_stale_status_line_is_not_trusted_and_a_disabled_ship_is_a_blocker(self):
        cfg = dict(CFG, deploy_lag_products={'timbar': CFG['deploy_lag_products']['timbar']})
        out = L.deploy_lag(cfg, LagFx(status=dict(outcome='current', main=sha(9), checked=L.iso(T0 - 3600))), st(), T0)
        self.assertEqual(out['timbar']['live'], sha(7))                       # an hour-old `current` pass: read back instead
        out = L.deploy_lag(cfg, LagFx(status=dict(outcome='current', main=sha(9))), st(), T0)
        self.assertEqual(out['timbar']['live'], sha(7))                       # no time on the record: not trusted either
        s = sample(deploy_lag={'timbar': dict(status_record=dict(outcome='disabled'))})
        self.assertTrue(L.deploy_blockers(s, 'timbar', {})[0].startswith('ship disabled'))

    def test_a_scoped_wave_is_qualifying_with_its_quiet_time(self):
        s = sample(ship_waves={'goodqa': dict(id='w', stage='scoped', started='a', updated=L.iso(T0 - 45 * 60), retries=9, sha='x', reason='r')})
        line = L.deploy_blockers(s, 'goodqa', {})[0]
        self.assertTrue(line.startswith('ship qualifying: runner ship wave w scoped'), line)
        self.assertIn('no update for 45 min', line)

    def test_failures_keep_the_last_good_reading_then_report_unreadable(self):
        cfg = dict(CFG, deploy_lag_products={'goodqa': CFG['deploy_lag_products']['goodqa']})
        s0 = st()
        L.deploy_lag(cfg, LagFx(), s0, T0)
        good = dict(s0['deploy_lag']['goodqa'])
        for n in range(1, 4):
            out = L.deploy_lag(cfg, LagFx(fail=True), s0, T0 + 600 * n)
            self.assertEqual((out['goodqa']['live'], out['goodqa']['failures']), (good['live'], n))
            fs = L.deploy_lag_findings(sample(at=T0 + 600 * n, deploy_lag=out), cfg)
            self.assertIn('deploy-lag:goodqa', [f['cls'] for f in fs])           # the open alert stays: no false recovery
            self.assertEqual('deploy-lag-unreadable:goodqa' in [f['cls'] for f in fs], n >= 3)
        self.assertIn('source unreadable since', fs[[f['cls'] for f in fs].index('deploy-lag:goodqa')]['lines'][2])
        out = L.deploy_lag(cfg, LagFx(), s0, T0 + 2400)                        # the source is back: clean reading
        self.assertNotIn('error', out['goodqa'])
        self.assertNotIn('failures', out['goodqa'])
        s1 = st()                                                               # never readable: unreadable after 3, no lag finding
        for n in range(3):
            out = L.deploy_lag(cfg, LagFx(fail=True), s1, T0 + 600 * n)
        self.assertEqual([f['cls'] for f in L.deploy_lag_findings(sample(deploy_lag=out), cfg)], ['deploy-lag-unreadable:goodqa'])

    def test_the_budget_defers_reads_and_keeps_the_cache(self):
        cfg = dict(CFG, deploy_lag_budget_seconds=4)
        fx, s0 = LagFx(status=dict(outcome='current', main=sha(9), checked=L.iso(T0))), st()
        out = L.deploy_lag(cfg, fx, s0, T0, clock=lambda: 0.0)
        self.assertEqual(sorted(out), [])                                     # 4 s < the 5 s floor: nothing read, nothing faked
        clock = iter([0.0, 0.0, 0.0] + [10.0] * 50)
        out = L.deploy_lag(dict(CFG, deploy_lag_budget_seconds=8), LagFx(), st(), T0, clock=lambda: next(clock))
        self.assertTrue(all('budget spent' in (d.get('error') or 'budget spent') for d in out.values()), out)

    def test_committed_config_names_all_products(self):
        self.assertEqual(sorted(CFG['deploy_lag_products']), ['goodqa', 'optin', 'tellready', 'timbar'])
        self.assertEqual(CFG['deploy_lag_mode'], 'warn')
        self.assertEqual(CFG['deploy_lag_minutes'], 60)
        for p, spec in CFG['deploy_lag_products'].items():
            self.assertTrue(spec.get('github') and (spec.get('live_url') or spec.get('live_cmd')) and spec.get('release_ticket'), p)


class LandLag(unittest.TestCase):
    def ready(self, **kw):
        row = dict(key='opmodel-run1/guard', source='codex-owner', receipt='READY (2 tests: 2 passed)',
                   spec='Ticket: goodqa#10498', candidate_sha='a' * 40, ready_at=L.iso(T0 - 660),
                   author='owner-account', landed=False)
        row.update(kw)
        return row

    def proof(self, row):
        sha = 'b' * 40
        return dict(row, proof_landed=True, proof_contains_candidate=True,
                    proof=dict(landed_sha=sha, activation=dict(sha=sha, observed_at=L.iso(T0),
                                                             observer='finisher', evidence='activation receipt'),
                               negative_control=dict(sha=sha, observed_at=L.iso(T0), observer='independent-reviewer',
                                                     evidence='refusal log', command='guard --mutant', refused=True, exit_code=2)))

    def find(self, row, state=None, at=T0):
        return L.land_lag_findings(dict(rows=[row], errors=[]), state if state is not None else st(), CFG, at)

    def test_ready_unlanded_safety_alarms_after_ten_minutes_other_after_sixty(self):
        self.assertEqual(classes(self.find(self.ready())), ['land-lag:opmodel-run1/guard'])
        self.assertEqual(self.find(self.ready(ready_at=L.iso(T0 - 599))), [])
        self.assertEqual(self.find(self.ready(spec='ordinary product change')), [])
        self.assertEqual(classes(self.find(self.ready(spec='ordinary product change', ready_at=L.iso(T0 - 3600)))),
                         ['land-lag:opmodel-run1/guard'])
        self.assertEqual(classes(self.find(self.ready(landed=True))), ['land-lag:opmodel-run1/guard'])
        self.assertEqual(CFG['land_lag_minutes'], 60)
        self.assertEqual(CFG['land_lag_safety_take'], 0)

    def test_safety_classification_all_declared_paths_and_tickets(self):
        for spec in ['Ticket: goodqa#' + str(x) for x in range(10495, 10502)] + ['Security-review: required']:
            self.assertEqual(L.land_lag_class(dict(spec=spec)), 'safety', spec)
        for path in ('bin/a-guard.py', 'boxops/register-claude-hooks.py', 'bin/rq', 'bin/rq-pin.py',
                     'config/finish-gate.json', 'bin/lane-registry-hook.py', 'bin/cause-receipt-guard.py', 'bin/land_lag_cap.py', 'bin/goodqa_liveness.py'):
            self.assertEqual(L.land_lag_class(dict(paths=[path])), 'safety', path)
        self.assertEqual(L.land_lag_class(dict(spec='goodqa#104950', paths=['bin/plain.py'])), 'other')

    def test_prose_mentions_do_not_convey_guard_ownership(self):
        prose = 'Run bin/rq status; see goodqa#10495 and Security-review: required for context.'
        self.assertEqual(L.land_lag_class(dict(spec=prose, paths=['apps/product.py'])), 'other')
        self.assertEqual(L.land_lag_class(dict(spec=prose, paths=['bin/finish_gate.py'])), 'safety')
        self.assertEqual(L.land_lag_class(dict(spec='Parent: goodqa#10495')), 'safety')
        self.assertEqual(L.land_lag_class(dict(spec='Ticket: goodqa#104950')), 'other')

    def test_other_landing_before_threshold_drops_cache_and_sticky_class_heals(self):
        state = st()
        other = self.ready(spec='run bin/rq status', paths=['docs/plain.md'], paths_unreadable=False,
                           ready_at=L.iso(T0 - 60))
        self.assertEqual(self.find(other, state), [])
        self.assertTrue(state['land_lag'])
        state['land_lag'][other['key']]['class'] = 'safety'  # persisted r1 misclassification
        self.assertEqual(self.find(dict(other, landed=True), state, T0 + 120), [])
        self.assertEqual(state['land_lag'], {})
        self.assertEqual(L.land_lag_findings(dict(rows=[], errors=[]), state, CFG, T0 + 5400), [])
        self.find(self.ready(), state)
        self.find(dict(other, landed=False), state)
        self.assertEqual(state['land_lag'][other['key']]['class'], 'safety')  # confirmed own safety stays proof-bound
        self.find(self.ready(), state)
        self.find(dict(other, paths_unreadable=True, landed=False), state)
        self.assertEqual(state['land_lag'][other['key']]['class'], 'safety')
        self.assertEqual(classes(self.find(self.ready(landed=True), st())), ['land-lag:opmodel-run1/guard'])

    def test_age_survives_reassignment_merge_and_missing_receipt(self):
        state = st()
        self.find(self.ready(), state)
        first = state['land_lag']['opmodel-run1/guard']['first_ready_at']
        self.find(self.ready(ready_at=L.iso(T0), author='new-owner', landed=True), state, T0 + 120)
        self.assertEqual(state['land_lag']['opmodel-run1/guard']['first_ready_at'], first)
        fs = L.land_lag_findings(dict(rows=[], errors=['dev2 unreachable']), state, CFG, T0 + 240)
        self.assertEqual(classes(fs), ['land-lag-unreadable', 'land-lag:opmodel-run1/guard'])
        self.assertEqual(state['land_lag']['opmodel-run1/guard']['age_minutes'], 15)
        self.assertIn('dev2 unreachable', ' '.join(fs[0]['lines']))
        self.assertEqual(fs[-1]['remedies'], [])  # safety cannot auto-downgrade, auto-land or disappear on read failure

    def test_clear_requires_landed_activation_and_independent_observed_refusal(self):
        from copy import deepcopy
        good = self.proof(self.ready(landed=True))
        self.assertTrue(L.land_lag_proven(good))
        self.assertFalse(L.land_lag_proven(dict(good, author='')))
        mutations = [lambda r: r.update(proof_landed=False), lambda r: r.update(proof_contains_candidate=False),
                     lambda r: r.update(proof={}), lambda r: r.update(proof=['merge']),
                     lambda r: r['proof'].pop('activation'), lambda r: r['proof'].pop('negative_control'),
                     lambda r: r['proof']['activation'].pop('evidence'),
                     lambda r: r['proof']['activation'].update(sha='c' * 40),
                     lambda r: r['proof']['negative_control'].update(sha='c' * 40),
                     lambda r: r['proof']['negative_control'].update(observer='owner-account'),
                     lambda r: r['proof']['negative_control'].update(observer=' Owner-Account '),
                     lambda r: r['proof']['negative_control'].update(observer='  '),
                     lambda r: r['proof']['negative_control'].update(exit_code=0),
                     lambda r: r['proof']['negative_control'].update(exit_code=True),
                     lambda r: r['proof']['negative_control'].update(refused=False),
                     lambda r: r['proof']['negative_control'].update(evidence=''),
                     lambda r: r['proof']['negative_control'].update(observer={}),
                     lambda r: r['proof']['negative_control'].update(evidence={'prose': 'READY'}),
                     lambda r: r['proof']['negative_control'].update(command=[]),
                     lambda r: r['proof']['negative_control'].update(observed_at='READY'),
                     lambda r: r['proof']['negative_control'].update(observed_at='2026-99-99T99:99:99Z')]
        for mutate in mutations:
            state, bad = st(), deepcopy(good)
            self.find(self.ready(), state)
            mutate(bad)
            self.assertFalse(L.land_lag_proven(bad), bad)
            self.assertEqual(classes(self.find(bad, state)), ['land-lag:opmodel-run1/guard'])
        state = st()
        self.find(self.ready(), state)
        self.assertEqual(self.find(good, state), [])
        self.assertEqual(state['land_lag'], {})

    def test_atomic_state_has_explicit_gate_and_clear_criteria(self):
        with tempfile.TemporaryDirectory(dir=_TMP) as directory:
            path = os.path.join(directory, 'land-lag.json')
            state = st()
            self.find(self.ready(ready_at=L.iso(T0 - 60)), state)  # gate opens before alert threshold
            L.save_land_lag(state, T0, path)
            with open(path) as f:
                data = json.load(f)
            self.assertEqual(data['schema'], 1)
            self.assertEqual(data['findings'][0]['key'], 'opmodel-run1/guard')
            self.assertEqual(data['findings'][0]['class'], 'safety')
            self.assertIn('independently observed', data['clear_criteria'])
            L.save_land_lag(st(), T0, path)
            with open(path) as f:
                self.assertEqual(json.load(f)['findings'], [])

    def test_writer_marks_collector_errors_incomplete(self):
        with tempfile.TemporaryDirectory(dir=_TMP) as directory:
            path = os.path.join(directory, 'land-lag.json')
            state = st()
            self.find(self.ready(), state)
            for errors in (['collector timed out'], []):
                with self.subTest(errors=errors):
                    L.save_land_lag(state, T0, path, errors=errors)
                    with open(path) as stream:
                        saved = json.load(stream)
                    self.assertEqual(saved['complete'], not bool(errors))
                    self.assertEqual(saved['findings'], list(state['land_lag'].values()))

    def test_run_pass_incomplete_bytes_preserve_safety_at_both_publications(self):
        import itertools
        import pathlib
        import land_lag_cap
        from unittest.mock import patch

        row = self.ready()
        config = dict(CFG, land_lag_mode='enforce', land_lag_safety_take=3)
        real_save = L.save_land_lag
        # Different discovery/final errors also catch forwarding the wrong pass's errors.
        errors_matrix = ((['discovery timeout'], ['classification timeout']),
                         ([], []), (['discovery timeout'], []),
                         ([], ['classification timeout']))
        for rows, errors_by_site in itertools.product(([row], []), errors_matrix):
            with self.subTest(rows=rows, errors_by_site=errors_by_site), \
                    tempfile.TemporaryDirectory(dir=_TMP) as directory:
                statefile = os.path.join(directory, 'state.json')
                gatefile = pathlib.Path(directory) / 'land-lag.json'
                captured = []

                class CollectorFx(L.Effects):
                    def host_health(self, host):
                        return dict(error='offline fixture')
                    def __init__(self):
                        super().__init__(config)
                        self.collects = 0

                    def land_lag_rows(self, known=None, limits=None):
                        index = self.collects
                        self.collects += 1
                        assert bool((limits or {}).get('land_lag_discovery_only')) is (index == 0)
                        return dict(rows=rows, errors=errors_by_site[index])

                    def snapshot(self):
                        # Both actual publication sites have finished; no remote work follows.
                        raise OSError('offline snapshot boundary')

                def capture(*args, **kwargs):
                    real_save(*args, **kwargs)
                    captured.append(gatefile.read_bytes())

                fx = CollectorFx()
                with patch.dict(os.environ, GOODQA_LIVENESS_STATE=statefile), \
                        patch.object(L, 'save_land_lag', side_effect=capture):
                    report = L.run_pass(config, fx, True, now=T0, state=st())
                self.assertEqual(report['collection_error'], 'offline snapshot boundary')
                self.assertEqual(fx.collects, 2)
                self.assertEqual(len(captured), 2)
                self.assertTrue((gatefile.parent / 'land-lag.bootstrapped').is_file())
                for index, raw in enumerate(captured):
                    # Feed the exact writer bytes to the real consumer, without rebuilding JSON.
                    gatefile.write_bytes(raw)
                    saved = json.loads(raw)
                    errors = errors_by_site[index]
                    self.assertEqual(saved['complete'], not bool(errors))
                    decision = land_lag_cap.evaluate('ordinary', gatefile, config)
                    self.assertEqual(decision['safety_keys'], [item['key'] for item in rows])
                    self.assertEqual(decision['state_status'], 'incomplete' if errors else 'present')
                    self.assertEqual(decision['admit'], not bool(errors))
                    if errors:
                        self.assertEqual(decision['alert'], 'land-lag-state-unreadable')
                    if rows:
                        self.assertTrue(land_lag_cap.evaluate('guard-land', gatefile, config)['admit'])

    def test_dedicated_gate_survives_general_state_reset_and_corruption(self):
        with tempfile.TemporaryDirectory(dir=_TMP) as directory:
            path = os.path.join(directory, 'land-lag.json')
            prior, fresh = st(), st()
            self.find(self.ready(), prior)
            L.save_land_lag(prior, T0, path)
            self.assertIsNone(L.load_land_lag(fresh, path))
            self.assertEqual(fresh['land_lag'], prior['land_lag'])
            L.save_land_lag(st(), T0, path)
            self.assertIsNone(L.load_land_lag(fresh, path))
            self.assertEqual(fresh['land_lag'], {})
            self.find(self.ready(), fresh)
            with open(path, 'w') as f:
                f.write('corrupt')
            self.assertIn('unreadable', L.load_land_lag(fresh, path))
            self.assertEqual(fresh['land_lag'], prior['land_lag'])
            self.assertIn('missing after bootstrap', L.load_land_lag(st(), path + '.missing'))

    def test_original_no_ticket_specs_bind_to_obligation_ledger(self):
        import pathlib
        from unittest.mock import patch
        with tempfile.TemporaryDirectory(dir=_TMP) as directory:
            root = pathlib.Path(directory)
            expected = {'opmodel-run2/finish-before-start': 'goodqa#10496', 'opmodel-run1/ingest-dedupe': 'goodqa#10497',
                        'opmodel-run1/rq-canary-guard': 'goodqa#10498', 'opmodel-run1/live-tree-code-guard': 'goodqa#10500'}
            ledger = (pathlib.Path(HERE).parent / 'docs/ops/ERIC-OBLIGATIONS.md').read_text()
            for key in expected:
                d = root / '.local/state/codex-owners' / key
                d.mkdir(parents=True)
                (d / 'receipt').write_text('READY (2 tests)')
                (d / 'spec.md').write_text('No ticket metadata in this historical specification')
                (d / 'worktree').write_text('/fixture/repo')
            with patch('subprocess.run') as run:
                run.return_value.returncode, run.return_value.stdout = 0, 'a' * 40
                rows = L.collect_land_lag_remote(root, ledger_text=ledger)['rows']
                self.assertEqual({row['key']: row['ticket'] for row in rows}, expected)
                # An explicit scenario ticket wins over an earlier contextual epic or the historic binding.
                (root / '.local/state/codex-owners/opmodel-run2/finish-before-start/spec.md').write_text(
                    'Parent: goodqa#10495\nTicket: goodqa#10999\n')
                rows = L.collect_land_lag_remote(root, ledger_text=ledger)['rows']
                self.assertEqual(next(row['ticket'] for row in rows if row['key'].endswith('finish-before-start')), 'goodqa#10999')

    def test_collector_budget_fairness_unknown_ancestry_and_landed_memoization(self):
        import pathlib
        from unittest.mock import patch
        with tempfile.TemporaryDirectory(dir=_TMP) as directory:
            root = pathlib.Path(directory)
            for name in ('a', 'b', 'c'):
                d = root / '.local/state/codex-owners/run' / name
                d.mkdir(parents=True)
                (d / 'receipt').write_text('READY')
                (d / 'worktree').write_text('/fixture/repo')
                (d / 'base').write_text('b' * 40)
            q = root / '.local/share/gorunner/tasks/held'
            q.mkdir(parents=True)
            (q / 'pin-queue.json').write_text(json.dumps(dict(repo='harness', candidate_sha='a' * 40,
                                                              reviewed_sha='b' * 40, paths=['bin/guard.py'])))
            grade = q / 'merge-grade-1'
            grade.mkdir()
            (grade / 'grade.json').write_text(json.dumps(dict(Verdict='PASS', Commit='a' * 40, Tip='b' * 40)))
            def git_reply(argv, **kw):
                import subprocess
                # rc 128 is unknown, never evidence that HEAD landed.
                rc = 128 if 'merge-base' in argv else 0
                output = 'a' * 40 if 'rev-parse' in argv else 'bin/finish_gate.py\0'
                if '--format=%ae' in argv:
                    output = 'fixture@example.test'
                elif '--format=%an' in argv:
                    output = 'Fixture'
                return subprocess.CompletedProcess(argv, rc, output, '')
            known, seen = {}, []
            with patch('subprocess.run', side_effect=git_reply) as run:
                for _ in range(4):
                    reading = L.collect_land_lag_remote(root, known=known, limits={'land_lag_ready_checks': 1})
                    classified = [row for row in reading['rows'] if row.get('checked_at', 0) > 0]
                    self.assertEqual(len(classified), 1)
                    row = classified[0]
                    self.assertIsNone(row['landed'])
                    self.assertIn('land-lag-unreadable', classes(L.land_lag_findings(reading, st(), CFG, T0)))
                    known[row['key']] = row
                    seen.append(row['key'])
                self.assertEqual(len(set(seen)), 4)
                self.assertIn('runner/held', seen)
                self.assertLessEqual(run.call_count, 12)
                # Exact runner candidates can be memoized; owner HEAD must recheck for replacement.
                for row in known.values():
                    row['landed'] = True
                run.reset_mock()
                reading = L.collect_land_lag_remote(root, known=known)
                self.assertEqual(len(reading['rows']), 4)
                self.assertEqual(sum('rev-parse' in call.args[0] for call in run.call_args_list), 3)
                self.assertFalse(any(any('harness-scratch.git' in str(arg) for arg in call.args[0])
                                     for call in run.call_args_list))
                self.assertLessEqual(run.call_count, 24)
            with patch('subprocess.run', side_effect=git_reply) as run:
                L.collect_land_lag_remote(root, limits={'land_lag_git_calls': 2})
                self.assertLessEqual(run.call_count, 2)

    def test_remote_transport_uses_dev2_and_failed_read_is_visible(self):
        from unittest.mock import patch
        with patch.object(L.C, 'run', return_value=(0, '{"rows":[],"errors":[]}', '')) as run:
            self.assertEqual(L.Effects({}).land_lag_rows(), dict(rows=[], errors=[]))
            args, kwargs = run.call_args
            self.assertEqual(args[0], [L.DEV2, '-t', '30', '-p', '-'])
            self.assertIn('collect_land_lag_remote', kwargs['input'])
            self.assertEqual(kwargs['timeout'], 65)
        for reply in ((124, '', 'offline'), (0, 'invalid json', ''), (0, '[]', '')):
            with patch.object(L.C, 'run', return_value=reply):
                result = L.Effects({}).land_lag_rows()
                self.assertEqual(result['rows'], [])
                self.assertTrue(result['errors'])

    def test_timer_pass_collects_with_deploy_off_and_alerts_once_without_remedies(self):
        from unittest.mock import patch
        row, test = self.ready(), self
        class TimerFx(Fx):
            def snapshot(self):
                return dict(counts=dict(running=30, queued=0), services={})
            def lane_floor_floor(self):
                return 40
            def lane_floor_lines(self, since):
                return []
            def refusals(self):
                return []
            def land_lag_rows(self, known=None):
                return dict(rows=[row], errors=[])
            def hawk(self, message):
                self.calls.append(('hawk', message))
        with tempfile.TemporaryDirectory(dir=_TMP) as directory:
            statefile = os.path.join(directory, 'state.json')
            gatefile = os.path.join(directory, 'land-lag.json')
            fx, config = TimerFx(), dict(CFG, deploy_lag_mode='off')
            with patch.dict(os.environ, GOODQA_LIVENESS_STATE=statefile), patch.object(L.C, 'journal'):
                dry = L.run_pass(config, fx, False, now=T0)
                self.assertEqual(classes(dry['findings']), [L.alert_key('land-lag:opmodel-run1/guard')])   # report: the lane family key
                self.assertFalse(os.path.exists(gatefile))
                self.assertEqual(fx.calls, [])
                L.run_pass(config, fx, True, now=T0)
                self.assertTrue(os.path.exists(gatefile))
                # Losing unrelated timer state must retain first-ready and the admission gate after merge.
                os.unlink(statefile)
                row['landed'], row['ready_at'] = True, L.iso(T0)
                result = L.run_pass(config, fx, False, now=T0 + 120)
                self.assertEqual(classes(result['findings']), [L.alert_key('land-lag:opmodel-run1/guard')])
                L.run_pass(config, fx, True, now=T0 + 120)
                L.run_pass(config, fx, True, now=T0 + 240)
                self.assertFalse(any(c[0] in ('warn', 'start') for c in fx.calls))
                # The external reset loses alert identity, but normal subsequent passes never duplicate tickets.
                self.assertEqual(len([c for c in fx.calls if c[0] == 'ticket']), 2)
                with open(gatefile, 'w') as f:
                    f.write('corrupt gate: preserve forensic evidence')
                result = L.run_pass(config, fx, True, now=T0 + 360)
                self.assertIn('land-lag-state-unreadable', classes(result['findings']))
                with open(gatefile) as f:
                    self.assertEqual(f.read(), 'corrupt gate: preserve forensic evidence')
                self.assertTrue(os.path.exists(os.path.join(directory, 'land-lag.bootstrapped')))
                os.unlink(gatefile)
                result = L.run_pass(config, fx, True, now=T0 + 480)
                self.assertIn('land-lag-state-unreadable', classes(result['findings']))
                self.assertFalse(os.path.exists(gatefile))


    def test_real_git_ready_receipts_and_exact_pass_pin_candidate(self):
        import pathlib
        import subprocess
        with tempfile.TemporaryDirectory(dir=_TMP) as directory:
            root = pathlib.Path(directory)
            wt = root / 'repo'
            def git(*args):
                return subprocess.check_output(['git', '-C', str(wt), *args], text=True).strip()
            wt.mkdir()
            git('init', '-q')
            git('config', 'user.email', 'fixture@example.test')
            git('config', 'user.name', 'Fixture')
            (wt / 'bin').mkdir()
            (wt / 'bin/finish_gate.py').write_text('main')
            git('add', '.')
            git('commit', '-qm', 'baseline')
            base = git('rev-parse', 'HEAD')
            git('update-ref', 'refs/remotes/origin/main', base)
            (wt / 'bin/finish_gate.py').write_text('safety')
            git('commit', '-qam', 'candidate')
            candidate = git('rev-parse', 'HEAD')
            d = root / '.local/state/codex-owners/opmodel-run1/guard'
            d.mkdir(parents=True)
            (d / 'worktree').write_text(str(wt))
            (d / 'base').write_text(base)
            (d / 'spec.md').write_text('Ticket: goodqa#10498')
            (d / 'account').write_text('owner-account')
            (d / 'receipt').write_text('READY (2 tests: 1 passed, 1 failed)')  # visibility, never landing authority
            os.utime(d / 'receipt', (T0 - 660, T0 - 660))
            (d.parent / 'not-ready').mkdir()
            (d.parent / 'not-ready/receipt').write_text('REFUSED-READY (0 counted tests)')
            reading = L.collect_land_lag_remote(root)
            self.assertEqual(len(reading['rows']), 1)
            row = reading['rows'][0]
            self.assertEqual(row['candidate_sha'], candidate)
            self.assertEqual(row['paths'], ['bin/finish_gate.py'])
            self.assertEqual(row['ticket'], 'goodqa#10498')
            self.assertFalse(row['landed'])
            self.assertEqual(classes(L.land_lag_findings(reading, st(), CFG, T0)), ['land-lag:opmodel-run1/guard'])
            proof = self.proof(row)['proof']
            proof['landed_sha'] = candidate
            for part in ('activation', 'negative_control'):
                proof[part]['sha'] = candidate
            (d / 'land-proof.json').write_text(json.dumps(proof))
            self.assertFalse(L.land_lag_proven(L.collect_land_lag_remote(root)['rows'][0]))
            git('update-ref', 'refs/remotes/origin/main', candidate)
            landed = L.collect_land_lag_remote(root)['rows'][0]
            self.assertTrue(landed['landed'])
            self.assertTrue(L.land_lag_proven(landed))
            self.assertEqual(classes(self.find(dict(landed, proof={}))), ['land-lag:opmodel-run1/guard'])
            q = root / '.local/share/gorunner/tasks/safety-task'
            q.mkdir(parents=True)
            (q / 'pin-queue.json').write_text(json.dumps(dict(repo='harness', candidate_sha=candidate,
                                                            reviewed_sha=candidate, queued_at=L.iso(T0 - 660), paths=['bin/guard.py'])))
            cfg = root / 'repos/gorunner/config.json'
            cfg.parent.mkdir(parents=True)
            cfg.write_text(json.dumps(dict(repos=dict(harness=str(wt)))))
            self.assertEqual(len(L.collect_land_lag_remote(root)['rows']), 1)  # pin prose without exact PASS ignored
            grade = q / 'merge-grade-1'
            grade.mkdir()
            (grade / 'grade.json').write_text(json.dumps(dict(Verdict='PASS', Commit=candidate, Tip=candidate)))
            rows = L.collect_land_lag_remote(root)['rows']
            self.assertEqual(len(rows), 2)
            runner = next(r for r in rows if r['source'] == 'runner')
            self.assertEqual(runner['key'], 'runner/safety-task')
            self.assertEqual(runner['author'], 'fixture@example.test')
            self.assertEqual(runner['author_aliases'], ['fixture@example.test', 'Fixture'])
            proof = self.proof(runner)['proof']
            proof['landed_sha'] = candidate
            for part in ('activation', 'negative_control'):
                proof[part]['sha'] = candidate
            (q / 'land-proof.json').write_text(json.dumps(proof))
            runner = next(r for r in L.collect_land_lag_remote(root)['rows'] if r['source'] == 'runner')
            self.assertTrue(L.land_lag_proven(runner))
            runner['proof']['negative_control']['observer'] = ' Fixture '
            self.assertFalse(L.land_lag_proven(runner))
            self.assertEqual(L.land_lag_class(runner), 'safety')
            (grade / 'grade.json').write_text(json.dumps(dict(Verdict='PASS', Commit=base, Tip=candidate)))
            self.assertEqual(len(L.collect_land_lag_remote(root)['rows']), 1)




class LandLagStateAlarmR3(unittest.TestCase):
    class BrokenSnapshot(Fx):
        def land_lag_rows(self, known=None):
            return dict(rows=[], errors=[])

        def snapshot(self):
            self.calls.append(('snapshot',))
            raise OSError('dev2 snapshot unavailable')

        def hawk(self, message):
            self.calls.append(('hawk', message))
            return 0, '', ''

    def test_missing_or_corrupt_gate_alarms_before_broken_snapshot(self):
        from unittest.mock import patch
        for contents in (None, '{broken json'):
            with self.subTest(contents=contents), tempfile.TemporaryDirectory(dir=_TMP) as directory:
                statefile = os.path.join(directory, 'state.json')
                with open(os.path.join(directory, 'land-lag.bootstrapped'), 'w'):
                    pass
                if contents is not None:
                    with open(os.path.join(directory, 'land-lag.json'), 'w') as f:
                        f.write(contents)
                fx = self.BrokenSnapshot()
                with patch.dict(os.environ, GOODQA_LIVENESS_STATE=statefile):
                    result = L.run_pass(CFG, fx, True, now=T0)
                self.assertIn('land-lag-state-unreadable', classes(result['findings']))
                self.assertIn('snapshot unavailable', result['collection_error'])
                self.assertIn('collection unavailable', L.human(result))
                # A detector-only test would miss suppression of the coordinator notification.
                alarms = [call for call in fx.calls if call[0] == 'hawk']
                self.assertEqual(len(alarms), 1)
                self.assertIn('land-lag-state-unreadable', alarms[0][1])
                self.assertIn('@coordinator', alarms[0][1])
                self.assertLess(fx.calls.index(alarms[0]), fx.calls.index(('snapshot',)))
                self.assertTrue(any(call[0] == 'ticket' and 'state unreadable' in call[1] for call in fx.calls))
                with open(statefile) as f:
                    saved = json.load(f)
                self.assertTrue(saved['alerts']['land-lag-state-unreadable']['ref'])

    def test_failed_alarm_delivery_is_durable_and_retries_after_gate_recovers(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory(dir=_TMP) as directory:
            statefile = os.path.join(directory, 'state.json')
            with open(os.path.join(directory, 'land-lag.bootstrapped'), 'w'):
                pass
            fx = self.BrokenSnapshot()
            with patch.dict(os.environ, GOODQA_LIVENESS_STATE=statefile):
                with patch.object(fx, 'hawk', return_value=(1, '', 'offline')):
                    L.run_pass(CFG, fx, True, now=T0)
                with open(statefile) as f:
                    self.assertTrue(json.load(f)['land_lag_state_alarm']['pending'])
                with open(os.path.join(directory, 'land-lag.json'), 'w') as f:
                    json.dump(dict(findings=[]), f)
                L.run_pass(CFG, fx, True, now=T0 + 120)
                with open(statefile) as f:
                    self.assertNotIn('land_lag_state_alarm', json.load(f))
            self.assertEqual(len([c for c in fx.calls if c[0] == 'hawk']), 1)

    def test_healthy_gate_has_no_state_alarm_with_broken_snapshot(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory(dir=_TMP) as directory:
            statefile = os.path.join(directory, 'state.json')
            fx = self.BrokenSnapshot()
            with patch.dict(os.environ, GOODQA_LIVENESS_STATE=statefile):
                result = L.run_pass(CFG, fx, True, now=T0)
            self.assertEqual(result['findings'], [])
            self.assertFalse(any(call[0] in ('ticket', 'hawk') for call in fx.calls))

    def test_coordinator_ticket_failure_retries_after_gate_recovers(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory(dir=_TMP) as directory:
            statefile = os.path.join(directory, 'state.json')
            with open(os.path.join(directory, 'land-lag.bootstrapped'), 'w'):
                pass
            fx = self.BrokenSnapshot()
            with patch.dict(os.environ, GOODQA_LIVENESS_STATE=statefile):
                with patch.object(fx, 'ticket_new', return_value=(None, 'coordinator unavailable')):
                    L.run_pass(CFG, fx, True, now=T0)
                with open(statefile) as f:
                    saved = json.load(f)
                self.assertTrue(saved['land_lag_state_alarm']['ticket_pending'])
                self.assertFalse(saved['land_lag_state_alarm']['pending'])
                with open(os.path.join(directory, 'land-lag.json'), 'w') as f:
                    json.dump(dict(findings=[]), f)
                L.run_pass(CFG, fx, True, now=T0 + 120)
                with open(statefile) as f:
                    saved = json.load(f)
                self.assertNotIn('land_lag_state_alarm', saved)
                self.assertTrue(saved['alerts']['land-lag-state-unreadable']['ref'])
            self.assertEqual(len([c for c in fx.calls if c[0] == 'ticket']), 1)

    def test_coordinator_delivery_uses_assigned_ticket(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory(dir=_TMP) as directory:
            statefile = os.path.join(directory, 'state.json')
            with patch.dict(os.environ, GOODQA_LIVENESS_STATE=statefile), patch.object(
                    L.C, 'run', return_value=(0, 'goodqa#10999', '')) as run:
                ref, _ = L.Effects(CFG).ticket_new('Fleet liveness: admission gate state unreadable', 'gate missing', 'alarm-test')
            self.assertEqual(ref, 'goodqa#10999')
            args = run.call_args.args[0]
            self.assertEqual(args[args.index('--assign') + 1], 'coordinator')
            self.assertEqual(args[args.index('--parent') + 1], 'goodqa#6099')


    def test_same_state_error_rearms_after_a_readable_pass(self):
        from unittest.mock import patch
        fx, state = self.BrokenSnapshot(), st()
        L.land_lag_state_alarm('missing after bootstrap', state, CFG, fx, True, T0)
        L.land_lag_state_alarm(None, state, CFG, fx, True, T0 + 120)
        L.land_lag_state_alarm('missing after bootstrap', state, CFG, fx, True, T0 + 240)
        self.assertEqual(len([c for c in fx.calls if c[0] == 'hawk']), 2)


    def test_real_snapshot_cli_error_keeps_alarm_and_human_output(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory(dir=_TMP) as directory:
            statefile = os.path.join(directory, 'state.json')
            with open(os.path.join(directory, 'land-lag.bootstrapped'), 'w'):
                pass
            fx = self.BrokenSnapshot()
            with patch.dict(os.environ, GOODQA_LIVENESS_STATE=statefile), patch.object(
                    L.C, 'run', return_value=(124, '', 'timed out')), patch.object(
                    fx, 'snapshot', side_effect=lambda: L.Effects.snapshot(fx)):
                result = L.run_pass(CFG, fx, True, now=T0)
            self.assertIn('land-lag-state-unreadable', classes(result['findings']))
            self.assertIn('dev2 snapshot failed', L.human(result))
            self.assertTrue(any(c[0] == 'ticket' for c in fx.calls))
            self.assertTrue(any(c[0] == 'hawk' for c in fx.calls))


class LandLagClassificationR3(unittest.TestCase):
    ready = LandLag.ready
    proof = LandLag.proof
    find = LandLag.find

    def test_metadata_fenced_examples_and_body_are_not_headers(self):
        for fence in ('```', '~~~'):
            for metadata in ('Security-review: required', 'Ticket: goodqa#10498', 'Parent: goodqa#10495'):
                for prefix in ('', '# Documentation only\nTicket: goodqa#10999\n\n## TASK\n'):
                    text = prefix + fence + 'text\n' + metadata + '\n' + fence + '\n'
                    self.assertEqual(L.land_lag_class(dict(spec=text, paths=['docs/example.md'])), 'other', text)
        self.assertEqual(L.land_lag_class(dict(spec='Ticket: goodqa#10999\n\n## TASK\nSecurity-review: required')), 'other')
        # Negative controls: real metadata is honored, including a multiline header.
        for text in ('Security-review: required\n\n## TASK\n```\nexample\n```',
                     '# Scenario\nTicket: goodqa#10999\nSecurity-review: required\n\n## TASK\nbody',
                     'Ticket: goodqa#10498\n\n## TASK\nbody'):
            self.assertEqual(L.land_lag_class(dict(spec=text, paths=['docs/example.md'])), 'safety')

    def test_unknown_paths_retry_and_heal_without_permanent_lag(self):
        state = st()
        row = self.ready(spec='Ticket: goodqa#10999', paths=[], paths_unreadable=True)
        for attempt in range(6):
            findings = self.find(row, state, T0 + attempt * 3600)
            saved = state['land_lag'][row['key']]
            self.assertEqual(saved['class'], 'unknown')
            self.assertTrue(saved['needs_reclassification'])
            self.assertEqual(saved['reclassification_attempts'], min(3, attempt + 1))
            self.assertEqual(classes(findings), ['land-lag-unreadable'])
        # A readable retry establishes actual ownership and the normal safety alarm.
        findings = self.find(dict(row, paths=['bin/finish_gate.py'], paths_unreadable=False), state)
        self.assertEqual(state['land_lag'][row['key']]['class'], 'safety')
        self.assertEqual(classes(findings), ['land-lag:' + row['key']])
        self.assertNotIn('needs_reclassification', state['land_lag'][row['key']])
        self.assertEqual(L.land_lag_class(dict(row, paths=['docs/example.md'], paths_unreadable=False)), 'other')

    def test_first_read_git_error_is_unknown_then_readable_retry_classifies(self):
        import pathlib
        import subprocess
        from unittest.mock import patch
        with tempfile.TemporaryDirectory(dir=_TMP) as directory:
            root = pathlib.Path(directory)
            owner = root / '.local/state/codex-owners/run/first'
            owner.mkdir(parents=True)
            for name, value in {'receipt': 'READY', 'worktree': '/fixture/repo', 'base': 'b' * 40,
                                'spec.md': 'Ticket: goodqa#10999'}.items():
                (owner / name).write_text(value)
            def response(argv, **kwargs):
                if 'diff' in argv:
                    raise OSError('diff unreadable')
                return subprocess.CompletedProcess(argv, 1 if 'merge-base' in argv else 0, 'a' * 40, '')
            with patch('subprocess.run', side_effect=response):
                reading = L.collect_land_lag_remote(root)
            state = st()
            L.land_lag_findings(reading, state, CFG, T0)
            self.assertEqual(state['land_lag']['run/first']['class'], 'unknown')
            def readable(argv, **kwargs):
                return subprocess.CompletedProcess(argv, 1 if 'merge-base' in argv else 0,
                                                   'bin/finish_gate.py\0' if 'diff' in argv else 'a' * 40, '')
            with patch('subprocess.run', side_effect=readable):
                reading = L.collect_land_lag_remote(root, known=state['land_lag'])
            L.land_lag_findings(reading, state, CFG, T0)
            self.assertEqual(state['land_lag']['run/first']['class'], 'safety')
            # Landing does not make a failed path read immutable: unchanged receipts retry too.
            cached = state['land_lag']['run/first']
            cached.update(landed=True, paths=[], paths_unreadable=True,
                          needs_reclassification=True, **{'class': 'unknown'})
            with patch('subprocess.run', side_effect=readable) as run:
                reading = L.collect_land_lag_remote(root, known=state['land_lag'])
            self.assertTrue(any('diff' in call.args[0] for call in run.call_args_list))
            L.land_lag_findings(reading, state, CFG, T0)
            self.assertEqual(state['land_lag']['run/first']['class'], 'safety')

    def test_replacement_ordinary_landing_preserves_original_safety_debt(self):
        state = st()
        original = self.ready(paths=['bin/finish_gate.py'])
        self.find(original, state)
        replacement = self.ready(candidate_sha='c' * 40, spec='Ticket: goodqa#10999',
                                 paths=['docs/example.md'], landed=True, author='new-owner')
        self.find(replacement, state)
        saved = state['land_lag'][original['key']]
        self.assertEqual(saved['candidate_sha'], original['candidate_sha'])
        self.assertEqual(saved['class'], 'safety')
        self.assertEqual(saved['author'], original['author'])
        self.assertFalse(saved['landed'])
        # B landing with proof for B still cannot erase A.
        self.find(self.proof(replacement), state)
        self.assertEqual(state['land_lag'][original['key']]['class'], 'safety')
        # Negative control: A's own bound independent activation/refusal proof clears.
        self.assertEqual(self.find(self.proof(dict(original, landed=True)), state), [])
        self.assertEqual(state['land_lag'], {})

    def test_unknown_state_survives_persistence(self):
        with tempfile.TemporaryDirectory(dir=_TMP) as directory:
            path = os.path.join(directory, 'land-lag.json')
            state = st()
            self.find(self.ready(spec='', paths_unreadable=True), state)
            L.save_land_lag(state, T0, path)
            fresh = st()
            self.assertIsNone(L.load_land_lag(fresh, path))
            self.assertEqual(fresh['land_lag'], state['land_lag'])

    def test_missing_pin_queue_paths_are_unknown_then_readable(self):
        import pathlib
        import subprocess
        from unittest.mock import patch
        with tempfile.TemporaryDirectory(dir=_TMP) as directory:
            root = pathlib.Path(directory)
            task = root / '.local/share/gorunner/tasks/guard'
            grade = task / 'merge-grade-1'
            grade.mkdir(parents=True)
            (grade / 'grade.json').write_text(json.dumps(dict(Verdict='PASS', Commit='a' * 40, Tip='b' * 40)))
            queue = dict(repo='harness', candidate_sha='a' * 40, reviewed_sha='b' * 40)
            def response(argv, **kwargs):
                return subprocess.CompletedProcess(argv, 1 if 'merge-base' in argv else 0, 'Owner <owner@example.org>', '')
            for paths, expected in ((None, 'unknown'), (42, 'unknown'), ([], 'other'),
                                    (['bin/finish_gate.py'], 'safety')):
                (task / 'pin-queue.json').write_text(json.dumps(dict(queue, paths=paths)))
                with patch('subprocess.run', side_effect=response):
                    row = L.collect_land_lag_remote(root)['rows'][0]
                self.assertEqual(L.land_lag_class(row), expected)


class ConservativeDebtR4(unittest.TestCase):
    ready = LandLag.ready
    proof = LandLag.proof
    find = LandLag.find

    def assert_caps(self, state, directory):
        import land_lag_cap
        path = os.path.join(directory, 'land-lag.json')
        L.save_land_lag(state, T0, path)
        result = land_lag_cap.evaluate('unrelated-product-work', state_path=path, config=CFG)
        self.assertTrue(result['gate_open'], result)
        self.assertFalse(result['admit'], result)

    def test_first_seen_landed_safety_requires_its_completion_proof(self):
        with tempfile.TemporaryDirectory(dir=_TMP) as directory:
            row, state = self.ready(landed=True), st()
            self.find(row, state)
            self.assertIn(row['key'], state['land_lag'])
            self.assertEqual(state['land_lag'][row['key']]['class'], 'safety')
            self.assert_caps(state, directory)
            # Negative control: landing with all three bound proofs resolves this exact debt.
            self.assertEqual(self.find(self.proof(row), state), [])
            self.assertEqual(state['land_lag'], {})
            ordinary = self.ready(landed=True, spec='Ticket: goodqa#10999', paths=['docs/plain.md'])
            self.find(ordinary, state)
            self.assertEqual(state['land_lag'], {})
            unknown = self.ready(landed=True, spec='Ticket: goodqa#10999', paths=[], paths_unreadable=True)
            self.find(unknown, state)
            self.assertEqual(state['land_lag'][unknown['key']]['class'], 'unknown')
            self.assert_caps(state, directory)
            self.find(self.proof(unknown), state)
            self.assertEqual(state['land_lag'], {})

    def test_unknown_reassignment_cannot_use_replacement_classification_or_proof(self):
        with tempfile.TemporaryDirectory(dir=_TMP) as directory:
            state = st()
            original = self.ready(spec='Ticket: goodqa#10999', paths=[], paths_unreadable=True)
            self.find(original, state)
            first = state['land_lag'][original['key']]['first_ready_at']
            replacement = self.ready(candidate_sha='c' * 40, spec='Ticket: goodqa#10999',
                                     paths=['docs/plain.md'], paths_unreadable=False, landed=True, author='replacement')
            for row in (replacement, self.proof(replacement)):
                self.find(row, state)
                self.assertIn(original['key'], state['land_lag'])
                saved = state['land_lag'][original['key']]
                self.assertEqual(saved['candidate_sha'], original['candidate_sha'])
                self.assertEqual(saved['class'], 'unknown')
                self.assertEqual(saved['first_ready_at'], first)
                self.assertEqual(saved['author'], original['author'])
                self.assert_caps(state, directory)
            # A's own readable ordinary ownership and landing can clear A; B cannot.
            self.find(dict(original, paths=['docs/plain.md'], paths_unreadable=False, landed=True), state)
            self.assertEqual(state['land_lag'], {})
            # Unknown ownership may alternatively clear through A's own complete proof.
            self.find(original, state)
            self.find(self.proof(dict(original, landed=True)), state)
            self.assertEqual(state['land_lag'], {})

    def repository(self, root, paths):
        import subprocess
        wt = root / 'repository'
        wt.mkdir()
        def git(*args):
            return subprocess.check_output(['git', '-C', str(wt), *args], text=True).strip()
        git('init', '-q')
        git('config', 'user.email', 'fixture@example.test')
        git('config', 'user.name', 'Fixture')
        for path in paths:
            file = wt / path
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_text('baseline')
        git('add', '.')
        git('commit', '-qm', 'baseline')
        base = git('rev-parse', 'HEAD')
        git('update-ref', 'refs/remotes/origin/main', base)
        for path in paths:
            (wt / path).write_text('candidate')
        git('commit', '-qam', 'candidate')
        return wt, base

    def owner(self, root, wt, base, name, spec='Ticket: goodqa#10999'):
        owner = root / '.local/state/codex-owners/run' / name
        owner.mkdir(parents=True)
        for filename, value in {'receipt': 'READY', 'worktree': str(wt), 'base': base,
                                'spec.md': spec, 'account': 'owner-account'}.items():
            (owner / filename).write_text(value)
        os.utime(owner / 'receipt', (T0 - 660, T0 - 660))

    def test_real_git_preserves_non_ascii_and_special_guard_filenames(self):
        import pathlib
        with tempfile.TemporaryDirectory(dir=_TMP) as directory:
            root = pathlib.Path(directory)
            paths = ['bin/é-guard.py', 'bin/tab\tguard.py', 'bin/line\nguard.py']
            wt, base = self.repository(root, paths)
            self.owner(root, wt, base, 'unusual')
            reading = L.collect_land_lag_remote(root)
            self.assertEqual(len(reading['rows']), 1)
            row = reading['rows'][0]
            self.assertEqual(set(row['paths']), set(paths))
            for path in paths:
                self.assertEqual(L.land_lag_class(dict(spec='', paths=[path])), 'safety')
            self.assertEqual(L.land_lag_class(row), 'safety')
            state = st()
            L.land_lag_findings(reading, state, CFG, T0)
            self.assert_caps(state, directory)
            self.assertEqual(L.land_lag_class(dict(paths=['docs/é-notes.md'])), 'other')

    def test_default_budget_registers_ninth_ready_row_and_retries_it(self):
        import pathlib
        import subprocess
        from unittest.mock import patch
        with tempfile.TemporaryDirectory(dir=_TMP) as directory:
            root = pathlib.Path(directory)
            wt = root / 'fixture-repo'
            (wt / '.git').mkdir(parents=True)
            (wt / '.git/HEAD').write_text('ref: refs/heads/fixture-task\n')
            for index in range(9):
                self.owner(root, wt, 'b' * 40, 'row-%02d' % index,
                           'Security-review: required' if index == 8 else 'Ticket: goodqa#10999')
            def response(argv, **kwargs):
                output = 'docs/plain.md\0' if 'diff' in argv else 'a' * 40
                return subprocess.CompletedProcess(argv, 1 if 'merge-base' in argv else 0, output, '')
            state = st()
            with patch('subprocess.run', side_effect=response) as run:
                reading = L.collect_land_lag_remote(root)
                self.assertLessEqual(run.call_count, 24)
                self.assertEqual({r['key'] for r in reading['rows']}, {'run/row-%02d' % i for i in range(9)})
                L.land_lag_findings(reading, state, CFG, T0)
                deferred = state['land_lag']['run/row-08']
                self.assertIn(deferred['class'], ('unknown', 'safety'))
                self.assert_caps(state, directory)
                # Each retry remains bounded, while eventually classifying every candidate.
                for attempt in range(5):
                    run.reset_mock()
                    reading = L.collect_land_lag_remote(root, known=state['land_lag'])
                    self.assertLessEqual(run.call_count, 24)
                    L.land_lag_findings(reading, state, CFG, T0 + 120 * (attempt + 1))
                original_keys = {'run/row-%02d' % i for i in range(9)}
                self.assertTrue(original_keys <= state['land_lag'].keys())
                self.assertTrue(all(not state['land_lag'][key].get('paths_unreadable') for key in original_keys))
                self.assertEqual(state['land_lag']['run/row-08']['class'], 'safety')
                self.assert_caps(state, directory)

    def test_timer_persists_every_discovered_debt_before_expensive_classification(self):
        import land_lag_cap
        from unittest.mock import patch
        row = self.ready(spec='Ticket: goodqa#10999', paths=[], paths_unreadable=True,
                         candidate_sha=None, deferred=True, checked_at=0)
        test = self
        with tempfile.TemporaryDirectory(dir=_TMP) as directory:
            statefile = os.path.join(directory, 'state.json')
            gatefile = os.path.join(directory, 'land-lag.json')
            class InterruptedFx(L.Effects):
                def host_health(self, host):
                    return dict(error='offline fixture')
                def __init__(self):
                    super().__init__(CFG)
                    self.collects = 0
                def land_lag_rows(self, known=None, limits=None):
                    self.collects += 1
                    if (limits or {}).get('land_lag_discovery_only'):
                        return dict(rows=[row], errors=[])
                    # This assertion happens inside collection, before classification returns.
                    with open(gatefile) as stream:
                        persisted = json.load(stream)
                    test.assertEqual(len(persisted['findings']), 1)
                    test.assertEqual(persisted['findings'][0]['class'], 'unknown')
                    test.assertFalse(land_lag_cap.evaluate('ordinary-work', state_path=gatefile, config=CFG)['admit'])
                    raise OSError('classification interrupted')
            fx = InterruptedFx()
            with patch.dict(os.environ, GOODQA_LIVENESS_STATE=statefile), patch.object(L.C, 'journal'):
                report = L.run_pass(CFG, fx, True, now=T0)
            self.assertEqual(fx.collects, 2)
            self.assertEqual(report['collection_error'], 'classification interrupted')
            with open(gatefile) as stream:
                persisted = json.load(stream)
            self.assert_caps({'land_lag': {row['key']: persisted['findings'][0]}}, directory)

    def test_deferred_known_ordinary_head_cannot_hide_a_possible_replacement(self):
        import pathlib
        import subprocess
        from unittest.mock import patch
        with tempfile.TemporaryDirectory(dir=_TMP) as directory:
            root = pathlib.Path(directory)
            wt = root / 'repo'
            refs = wt / '.git/refs/heads'
            refs.mkdir(parents=True)
            (wt / '.git/HEAD').write_text('ref: refs/heads/ordinary\n')
            (refs / 'ordinary').write_text('a' * 40 + '\n')
            self.owner(root, wt, 'b' * 40, 'ordinary')
            def response(argv, **kwargs):
                return subprocess.CompletedProcess(argv, 1 if 'merge-base' in argv else 0,
                                                   'docs/plain.md\0' if 'diff' in argv else 'a' * 40, '')
            state = st()
            with patch('subprocess.run', side_effect=response):
                L.land_lag_findings(L.collect_land_lag_remote(root), state, CFG, T0)
            self.assertEqual(state['land_lag']['run/ordinary']['class'], 'other')
            with patch('subprocess.run') as run:
                deferred = L.collect_land_lag_remote(root, known=state['land_lag'],
                                                     limits={'land_lag_git_calls': 0})
                run.assert_not_called()
            L.land_lag_findings(deferred, state, CFG, T0 + 120)
            self.assertEqual(state['land_lag']['run/ordinary']['class'], 'other')
            self.assertTrue(any(row['class'] == 'unknown' for row in state['land_lag'].values()))
            self.assert_caps(state, directory)

    def test_confirmed_header_safety_survives_same_sha_header_removal(self):
        with tempfile.TemporaryDirectory(dir=_TMP) as directory:
            state = st()
            original = self.ready(spec='Security-review: required', paths=['docs/plain.md'],
                                  paths_unreadable=False)
            self.find(original, state)
            stripped = dict(original, spec='Ticket: goodqa#10999', landed=True)
            for attempt in range(3):
                self.find(stripped, state, T0 + attempt * 120)
                self.assertIn(original['key'], state['land_lag'])
                saved = state['land_lag'][original['key']]
                self.assertEqual(saved['candidate_sha'], original['candidate_sha'])
                self.assertEqual(saved['class'], 'safety')
                self.assert_caps(state, directory)
            # Full proof bound to this candidate resolves even after metadata changes.
            self.find(self.proof(stripped), state)
            self.assertEqual(state['land_lag'], {})

    def test_failed_first_head_read_cannot_be_resolved_by_later_ordinary_identity(self):
        import pathlib
        import subprocess
        from unittest.mock import patch
        with tempfile.TemporaryDirectory(dir=_TMP) as directory:
            root = pathlib.Path(directory)
            self.owner(root, pathlib.Path('/fixture/original-tree'), 'b' * 40, 'unknown-identity')
            def failed_head(argv, **kwargs):
                return subprocess.CompletedProcess(argv, 128, '', 'unavailable')
            state = st()
            with patch('subprocess.run', side_effect=failed_head):
                reading = L.collect_land_lag_remote(root)
            L.land_lag_findings(reading, state, CFG, T0)
            original = state['land_lag']['run/unknown-identity']
            self.assertTrue(original['identity_unreadable'])
            self.assertFalse(original.get('candidate_sha'))
            self.assertEqual(original['class'], 'unknown')
            first = original['first_ready_at']
            owner = root / '.local/state/codex-owners/run/unknown-identity'
            (owner / 'worktree').write_text('/fixture/replacement-tree')
            def landed_ordinary(argv, **kwargs):
                return subprocess.CompletedProcess(argv, 0, 'docs/plain.md\0' if 'diff' in argv else 'c' * 40, '')
            with patch('subprocess.run', side_effect=landed_ordinary):
                reading = L.collect_land_lag_remote(root, known=state['land_lag'])
            L.land_lag_findings(reading, state, CFG, T0 + 120)
            self.assertIn('run/unknown-identity', state['land_lag'])
            retained = state['land_lag']['run/unknown-identity']
            self.assertTrue(retained['identity_unreadable'])
            self.assertFalse(retained.get('candidate_sha'))
            self.assertEqual(retained['worktree'], '/fixture/original-tree')
            self.assertEqual(retained['first_ready_at'], first)
            self.assertEqual(retained['class'], 'unknown')
            self.assert_caps(state, directory)


class RetainedProvisionalDebtR4(unittest.TestCase):
    ready = LandLag.ready
    find = LandLag.find
    assert_caps = ConservativeDebtR4.assert_caps
    def test_failed_pending_identity_survives_later_landed_replacement(self):
        with tempfile.TemporaryDirectory(dir=_TMP) as directory:
            state = st()
            ordinary = self.ready(spec='Ticket: goodqa#10999', paths=['docs/plain.md'],
                                  worktree='/tree/A')
            self.find(ordinary, state)
            unknown = dict(ordinary, candidate_sha=None, paths=[], paths_unreadable=True,
                           identity_unreadable=True, worktree='/tree/X')
            self.find(unknown, state)
            self.assert_caps(state, directory)
            replacement = dict(ordinary, candidate_sha='c' * 40, landed=True, worktree='/tree/X')
            self.find(replacement, state)
            self.assert_caps(state, directory)
            retained = [row for row in state['land_lag'].values() if row['class'] == 'unknown']
            self.assertEqual(len(retained), 1)
            self.assertEqual(retained[0]['worktree'], '/tree/X')

    def test_deferred_unidentified_tree_cannot_be_replaced_by_ordinary_tree(self):
        with tempfile.TemporaryDirectory(dir=_TMP) as directory:
            state = st()
            original = self.ready(candidate_sha=None, spec='Ticket: goodqa#10999', paths=[],
                                  paths_unreadable=True, deferred=True, worktree='/tree/A', base='b' * 40)
            self.find(original, state)
            replacement = dict(original, candidate_sha='c' * 40, paths=['docs/plain.md'],
                               paths_unreadable=False, deferred=False, landed=True, worktree='/tree/B')
            self.find(dict(replacement, deferred=True, candidate_sha=None, paths_unreadable=True), state)
            self.find(replacement, state)
            self.assert_caps(state, directory)
            self.assertEqual(state['land_lag'][original['key']]['worktree'], '/tree/A')

    def test_failed_identity_survives_new_sha_in_the_same_worktree(self):
        with tempfile.TemporaryDirectory(dir=_TMP) as directory:
            state = st()
            unknown = self.ready(candidate_sha=None, identity_unreadable=True,
                                 paths_unreadable=True, paths=[], spec='Ticket: goodqa#10999',
                                 worktree='/tree/A', base='b' * 40)
            self.find(unknown, state)
            replacement = dict(unknown, candidate_sha='c' * 40, identity_unreadable=False,
                               paths_unreadable=False, paths=['docs/plain.md'], landed=True)
            self.find(replacement, state)
            self.assert_caps(state, directory)
            self.assertTrue(state['land_lag'][unknown['key']]['identity_unreadable'])


class CandidateIdentityR5(unittest.TestCase):
    ready = LandLag.ready
    proof = LandLag.proof
    find = LandLag.find
    repository = ConservativeDebtR4.repository
    assert_caps = ConservativeDebtR4.assert_caps

    def test_discovery_enrichment_rejects_refusal_by_newly_learned_author_name(self):
        import pathlib
        import subprocess
        with tempfile.TemporaryDirectory(dir=_TMP) as directory:
            root = pathlib.Path(directory)
            wt, base = self.repository(root, ['bin/finish_gate.py'])
            candidate = subprocess.check_output(['git', '-C', str(wt), 'rev-parse', 'HEAD'], text=True).strip()
            subprocess.check_call(['git', '-C', str(wt), 'update-ref', 'refs/remotes/origin/main', candidate])
            task = root / '.local/share/gorunner/tasks/author-alias'
            grade = task / 'merge-grade-1'
            grade.mkdir(parents=True)
            (grade / 'grade.json').write_text(json.dumps(dict(Verdict='PASS', Commit=candidate, Tip=candidate)))
            (task / 'pin-queue.json').write_text(json.dumps(dict(repo='harness', candidate_sha=candidate,
                reviewed_sha=candidate, queued_at=L.iso(T0 - 660), paths=['bin/finish_gate.py'])))
            config = root / 'repos/gorunner/config.json'
            config.parent.mkdir(parents=True)
            config.write_text(json.dumps(dict(repos=dict(harness=str(wt)))))
            proof = self.proof({})['proof']
            proof['landed_sha'] = candidate
            for part in ('activation', 'negative_control'):
                proof[part]['sha'] = candidate
            proof['negative_control']['observer'] = ' Fixture '
            (task / 'land-proof.json').write_text(json.dumps(proof))

            state = st()
            discovery = L.collect_land_lag_remote(root, limits={'land_lag_discovery_only': True})
            self.assertEqual(len(discovery['rows']), 1)
            self.assertFalse(discovery['rows'][0].get('author_aliases'))
            L.land_lag_findings(discovery, state, CFG, T0)
            key = 'runner/author-alias'
            self.assertIn(key, state['land_lag'])
            discovered_state = json.loads(json.dumps(state))
            for cached_aliases in ([], ['fixture@example.test']):
                with self.subTest(cached_aliases=cached_aliases):
                    state = json.loads(json.dumps(discovered_state))
                    state['land_lag'][key]['author_aliases'] = cached_aliases
                    proof['negative_control']['observer'] = ' FIXTURE '
                    (task / 'land-proof.json').write_text(json.dumps(proof))
                    enriched = L.collect_land_lag_remote(root, known=state['land_lag'])
                    self.assertEqual(enriched['rows'][0]['author_aliases'], ['fixture@example.test', 'Fixture'])
                    self.assertTrue(enriched['rows'][0]['landed'])
                    L.land_lag_findings(enriched, state, CFG, T0 + 120)
                    self.assertIn(key, state['land_lag'], 'candidate author cannot independently observe its own refusal')
                    self.assert_caps(state, directory)
                    self.assertIn('fixture', [alias.strip().casefold() for alias in state['land_lag'][key]['author_aliases']])
                    # Persisting and reusing the enriched record must retain the same exclusion.
                    L.land_lag_findings(L.collect_land_lag_remote(root, known=state['land_lag']), state, CFG, T0 + 180)
                    self.assertIn(key, state['land_lag'])
                    self.assert_caps(state, directory)

                    # A genuine independent observer resolves the same candidate with the same bound proof.
                    proof['negative_control']['observer'] = 'independent-reviewer'
                    (task / 'land-proof.json').write_text(json.dumps(proof))
                    independent = L.collect_land_lag_remote(root, known=state['land_lag'])
                    L.land_lag_findings(independent, state, CFG, T0 + 240)
                    self.assertEqual(state['land_lag'], {})

    def test_deferred_unknown_survives_landed_reuse_of_same_worktree_and_base(self):
        import pathlib
        import subprocess
        with tempfile.TemporaryDirectory(dir=_TMP) as directory:
            root = pathlib.Path(directory)
            wt, base = self.repository(root, ['bin/finish_gate.py'])
            def git(*args):
                return subprocess.check_output(['git', '-C', str(wt), *args], text=True).strip()
            git('branch', '-m', 'safety-a')
            candidate_a = git('rev-parse', 'HEAD')
            ConservativeDebtR4.owner(self, root, wt, base, 'reused')
            owner = root / '.local/state/codex-owners/run/reused'
            state = st()
            discovery = L.collect_land_lag_remote(root, limits={'land_lag_discovery_only': True})
            self.assertFalse(discovery['rows'][0].get('candidate_sha'))
            self.assertEqual(discovery['rows'][0]['worktree'], str(wt))
            self.assertEqual(discovery['rows'][0]['base'], base)
            L.land_lag_findings(discovery, state, CFG, T0)
            original_first_ready = state['land_lag']['run/reused']['first_ready_at']
            self.assert_caps(state, directory)

            # B replaces A in exactly the same directory and against exactly the same base.
            git('checkout', '-qb', 'ordinary-b', base)
            (wt / 'docs').mkdir()
            (wt / 'docs/plain.md').write_text('ordinary candidate B')
            git('add', 'docs/plain.md')
            git('commit', '-qm', 'ordinary B')
            candidate_b = git('rev-parse', 'HEAD')
            git('update-ref', 'refs/remotes/origin/main', candidate_b)
            replacement = L.collect_land_lag_remote(root, known=state['land_lag'])
            row_b = next(row for row in replacement['rows'] if row['candidate_sha'] == candidate_b)
            self.assertEqual(row_b['worktree'], str(wt))
            self.assertEqual(row_b['base'], base)
            self.assertEqual(row_b['paths'], ['docs/plain.md'])
            self.assertTrue(row_b['landed'])
            L.land_lag_findings(replacement, state, CFG, T0 + 120)
            retained = [row for row in state['land_lag'].values() if not row.get('candidate_sha')]
            self.assertEqual(len(retained), 1, 'ordinary B landing cannot erase unidentified A debt')
            self.assertEqual(retained[0]['first_ready_at'], original_first_ready)
            self.assert_caps(state, directory)

            # Even a complete proof for B conveys no completion authority over A.
            proof_b = self.proof({})['proof']
            proof_b['landed_sha'] = candidate_b
            for part in ('activation', 'negative_control'):
                proof_b[part]['sha'] = candidate_b
            (owner / 'land-proof.json').write_text(json.dumps(proof_b))
            L.land_lag_findings(L.collect_land_lag_remote(root, known=state['land_lag']), state, CFG, T0 + 240)
            self.assert_caps(state, directory)

            # A's stable branch identity returns; only A's own bound completion clears its debt.
            git('checkout', '-q', 'safety-a')
            git('update-ref', 'refs/remotes/origin/main', candidate_a)
            proof_a = self.proof({})['proof']
            proof_a['landed_sha'] = candidate_a
            for part in ('activation', 'negative_control'):
                proof_a[part]['sha'] = candidate_a
            (owner / 'land-proof.json').write_text(json.dumps(proof_a))
            completed_a = L.collect_land_lag_remote(root, known=state['land_lag'])
            self.assertTrue(any(row.get('candidate_sha') == candidate_a and row.get('proof_contains_candidate')
                                for row in completed_a['rows']))
            L.land_lag_findings(completed_a, state, CFG, T0 + 360)
            self.assertEqual(state['land_lag'], {})


class CandidateIdentityR6(unittest.TestCase):
    repository = ConservativeDebtR4.repository
    ready = LandLag.ready
    proof = LandLag.proof
    find = LandLag.find
    assert_caps = ConservativeDebtR4.assert_caps

    def runner_fixture(self, root):
        import subprocess
        wt, _ = self.repository(root, ['bin/finish_gate.py'])
        candidate = subprocess.check_output(['git', '-C', str(wt), 'rev-parse', 'HEAD'], text=True).strip()
        subprocess.check_call(['git', '-C', str(wt), 'update-ref', 'refs/remotes/origin/main', candidate])
        task = root / '.local/share/gorunner/tasks/atomic-author'
        grade = task / 'merge-grade-1'
        grade.mkdir(parents=True)
        (grade / 'grade.json').write_text(json.dumps(dict(Verdict='PASS', Commit=candidate, Tip=candidate)))
        (task / 'pin-queue.json').write_text(json.dumps(dict(repo='harness', candidate_sha=candidate,
            reviewed_sha=candidate, queued_at=L.iso(T0 - 660), paths=['bin/finish_gate.py'])))
        config = root / 'repos/gorunner/config.json'
        config.parent.mkdir(parents=True)
        config.write_text(json.dumps(dict(repos=dict(harness=str(wt)))))
        proof = self.proof({})['proof']
        proof['landed_sha'] = candidate
        for part in ('activation', 'negative_control'):
            proof[part]['sha'] = candidate
        return wt, task, proof

    def test_r6_email_success_name_timeout_never_admits_author_refusal(self):
        import pathlib
        import subprocess
        from unittest import mock
        with tempfile.TemporaryDirectory(dir=_TMP) as directory:
            root = pathlib.Path(directory)
            _, task, proof = self.runner_fixture(root)
            proof['negative_control']['observer'] = 'Fixture'
            (task / 'land-proof.json').write_text(json.dumps(proof))
            state = st()
            L.land_lag_findings(L.collect_land_lag_remote(root, limits={'land_lag_discovery_only': True}),
                                state, CFG, T0)
            real_run = subprocess.run
            reads = []
            def partial_author(cmd, **kwargs):
                if 'show' in cmd:
                    reads.append(cmd)
                    if any('%an' in arg for arg in cmd):
                        raise subprocess.TimeoutExpired(cmd, kwargs.get('timeout', 1))
                return real_run(cmd, **kwargs)
            with mock.patch.object(subprocess, 'run', side_effect=partial_author):
                reading = L.collect_land_lag_remote(root, known=state['land_lag'])
            self.assertTrue(any('--format=%ae' in cmd for cmd in reads))
            self.assertEqual(reading['rows'][0]['author'], 'fixture@example.test')
            L.land_lag_findings(reading, state, CFG, T0 + 120)
            self.assertIn('runner/atomic-author', state['land_lag'])
            self.assert_caps(state, directory)
            # Merely changing the observer cannot make incomplete identity trustworthy.
            reading['rows'][0]['proof']['negative_control']['observer'] = 'independent-reviewer'
            L.land_lag_findings(reading, state, CFG, T0 + 180)
            self.assertIn('runner/atomic-author', state['land_lag'])
            # Complete identity plus genuinely independent proof clears the same debt.
            proof['negative_control']['observer'] = 'independent-reviewer'
            (task / 'land-proof.json').write_text(json.dumps(proof))
            L.land_lag_findings(L.collect_land_lag_remote(root, known=state['land_lag']), state, CFG, T0 + 240)
            self.assertEqual(state['land_lag'], {})

    def test_r6_later_narrower_enrichment_keeps_cached_author_alias(self):
        import pathlib
        with tempfile.TemporaryDirectory(dir=_TMP) as directory:
            root = pathlib.Path(directory)
            _, task, proof = self.runner_fixture(root)
            state = st()
            # First full enrichment learns both aliases without a completion proof.
            reading = L.collect_land_lag_remote(root)
            L.land_lag_findings(reading, state, CFG, T0)
            key = 'runner/atomic-author'
            self.assertIn('fixture', state['land_lag'][key]['author_aliases'])
            unrelated = self.ready(key='other/fresh', ready_at=L.iso(T0), candidate_sha='c' * 40)
            self.find(unrelated, state)
            original_unrelated = json.loads(json.dumps(state['land_lag']['other/fresh']))
            proof['negative_control']['observer'] = ' Fixture '
            (task / 'land-proof.json').write_text(json.dumps(proof))
            later = L.collect_land_lag_remote(root, known=state['land_lag'])
            # Simulate an otherwise successful later enrichment omitting a known alias.
            later['rows'][0]['author_aliases'] = ['fixture@example.test']
            L.land_lag_findings(later, state, CFG, T0)
            self.assertIn(key, state['land_lag'], 'narrower enrichment cannot reopen author self-observation')
            self.assertIn('fixture', state['land_lag'][key]['author_aliases'])
            self.assertEqual(state['land_lag']['other/fresh'], original_unrelated)
            self.assert_caps(state, directory)
            later['rows'][0]['proof']['negative_control']['observer'] = 'independent-reviewer'
            L.land_lag_findings(later, state, CFG, T0)
            self.assertNotIn(key, state['land_lag'])
            self.assertEqual(state['land_lag']['other/fresh'], original_unrelated)

    def test_r6_mid_enrichment_checkout_cannot_lend_a_identity_to_landed_b(self):
        import pathlib
        import subprocess
        from unittest import mock
        with tempfile.TemporaryDirectory(dir=_TMP) as directory:
            root = pathlib.Path(directory)
            wt, base = self.repository(root, ['bin/finish_gate.py'])
            def git(*args):
                return subprocess.check_output(['git', '-C', str(wt), *args], text=True).strip()
            git('branch', '-m', 'safety-a')
            candidate_a = git('rev-parse', 'HEAD')
            git('checkout', '-qb', 'ordinary-b', base)
            (wt / 'ordinary.md').write_text('ordinary B')
            git('add', 'ordinary.md')
            git('commit', '-qm', 'ordinary B')
            candidate_b = git('rev-parse', 'HEAD')
            git('update-ref', 'refs/remotes/origin/main', candidate_b)
            git('checkout', '-q', 'safety-a')
            ConservativeDebtR4.owner(self, root, wt, base, 'race')
            state = st()
            L.land_lag_findings(L.collect_land_lag_remote(root, limits={'land_lag_discovery_only': True}),
                                state, CFG, T0)
            key = 'run/race'
            self.assertTrue(state['land_lag'][key]['branch'].endswith('safety-a'))
            first_ready = state['land_lag'][key]['first_ready_at']
            real_run = subprocess.run
            switched = []
            def switch_before_resolution(cmd, **kwargs):
                if 'rev-parse' in cmd and not switched:
                    switched.append(True)
                    real_run(['git', '-C', str(wt), 'checkout', '-q', 'ordinary-b'], check=True)
                return real_run(cmd, **kwargs)
            with mock.patch.object(subprocess, 'run', side_effect=switch_before_resolution):
                reading = L.collect_land_lag_remote(root, known=state['land_lag'])
            self.assertTrue(switched, 'probe must switch the checkout during enrichment')
            self.assertEqual(git('rev-parse', 'HEAD'), candidate_b)
            L.land_lag_findings(reading, state, CFG, T0 + 120)
            self.assertTrue(state['land_lag'], 'landed B cannot erase deferred A debt')
            self.assertTrue(any(row['first_ready_at'] == first_ready for row in state['land_lag'].values()))
            self.assert_caps(state, directory)
            # Returning A with its own landing and bound independent proof clears A.
            git('checkout', '-q', 'safety-a')
            git('update-ref', 'refs/remotes/origin/main', candidate_a)
            proof = self.proof({})['proof']
            proof['landed_sha'] = candidate_a
            for part in ('activation', 'negative_control'):
                proof[part]['sha'] = candidate_a
            (root / '.local/state/codex-owners/run/race/land-proof.json').write_text(json.dumps(proof))
            L.land_lag_findings(L.collect_land_lag_remote(root, known=state['land_lag']), state, CFG, T0 + 240)
            self.assertEqual(state['land_lag'], {})

    def test_r6_consecutive_deferred_shas_do_not_overwrite_original_debt(self):
        for branch in ('refs/heads/safety-a', None):
            with self.subTest(branch=branch), tempfile.TemporaryDirectory(dir=_TMP) as directory:
                state = st()
                candidate_a, candidate_b = 'a' * 40, 'b' * 40
                deferred_a = self.ready(key='run/reused', candidate_sha=None, captured_sha=candidate_a,
                    branch=branch, worktree='/same/tree', base='c' * 40, spec='Ticket: goodqa#10999',
                    deferred=True, paths=[], paths_unreadable=True)
                self.find(deferred_a, state)
                first_ready = state['land_lag']['run/reused']['first_ready_at']
                deferred_b = dict(deferred_a, captured_sha=candidate_b, ready_at=L.iso(T0))
                self.find(deferred_b, state, at=T0 + 60)
                landed_b = dict(deferred_b, candidate_sha=candidate_b, gate_candidate_sha=candidate_b,
                                deferred=False, paths=['docs/plain.md'], paths_unreadable=False, landed=True)
                self.find(landed_b, state, at=T0 + 120)
                self.assertTrue(state['land_lag'], 'later deferred B and ordinary landing cannot erase A')
                retained = list(state['land_lag'].values())
                self.assertEqual(len(retained), 1)
                self.assertEqual(retained[0]['captured_sha'], candidate_a)
                self.assertEqual(retained[0]['first_ready_at'], first_ready)
                self.assert_caps(state, directory)
                # A completes under its captured SHA, including detached HEAD identity.
                own_completion = self.proof(dict(deferred_a, candidate_sha=candidate_a,
                    gate_candidate_sha=candidate_a, deferred=False, landed=True,
                    paths=['bin/finish_gate.py'], paths_unreadable=False))
                own_completion['proof']['landed_sha'] = candidate_a
                for part in ('activation', 'negative_control'):
                    own_completion['proof'][part]['sha'] = candidate_a
                self.find(own_completion, state, at=T0 + 180)
                self.assertEqual(state['land_lag'], {})


class TellReadyDeployLag(unittest.TestCase):
    def test_product_ignore_is_scoped_and_code_lag_alerts(self):
        spec = CFG['deploy_lag_products']['tellready']
        self.assertEqual(spec['github'], 'ericmacdougall/interview-prep')
        self.assertEqual(spec['live_url'], 'https://tellready.com/api/health')
        class Fx(LagFx):
            files = ['experiments/probe.py']
            def http_json(self, url, timeout=20):
                return {'sha': LIVE, 'sourceSha': LIVE}
            def gh_compare(self, repo, base, head='main', timeout=30):
                return cmp_main(files=self.files)
        fx = Fx()
        for files, expected in [(['experiments/probe.py'], False), (['docs/x.md', '.lanes/x'], False),
                                (['ip/app.py'], True), (['experiments/x', 'ip/app.py'], True)]:
            fx.files = files
            reading = L.collect_deploy_lag('tellready', spec, CFG, fx, T0)
            self.assertNotIn('error', reading)
            findings = L.deploy_lag_findings(sample(deploy_lag={'tellready': reading}), CFG)
            self.assertEqual(bool(findings), expected, files)
        fx.files = ['experiments/probe.py']
        other = L.collect_deploy_lag('goodqa', CFG['deploy_lag_products']['goodqa'], CFG, fx, T0)
        self.assertTrue(L.deploy_lag_findings(sample(deploy_lag={'goodqa': other}), CFG))


class AutocommitStalled(unittest.TestCase):
    """goodqa#11505 (C-35): the live tree's autocommit stalling is detected whatever the cause, from EVIDENCE OF FAILED ATTEMPTS; the cause is named from the log
    after the last success; a quiet fleet is not a stall; a bypassed guard (hook crash) is reported on its own."""
    NEED = 600.0

    def ac(self, fail_since=None, last_fail=None, last_ok=None, crash=None, after_ok='', **kw):
        d = dict(dirty=5, ahead=0, ahead_oldest='', behind=True, last_commit_age_s=900, lock=dict(exists=False), log_tail=after_ok, remote_sha='a' * 40,
                 log=dict(fail_since_age_s=fail_since, last_fail_age_s=last_fail, last_ok_age_s=last_ok, crash_age_s=crash, after_ok=after_ok))
        d.update(kw)
        return d

    def find(self, ac, at=T0):
        return L.autocommit_findings(sample(at=at, autocommit=ac), {'since': {}}, CFG)

    def refusal_log(self, count, different=False, repo=None, success=True, path=None):
        repo = repo or L.LIVE_GIT_DIR
        path = path or 'bin/rw-ship.sh.pre-mainadvance-20261029'
        start = L.ts('2026-10-30T22:03:09Z')
        lines = []
        for i in range(count):
            stamp = L.iso(start + i * 60).rstrip('Z')
            name = path + str(i) if different else path
            lines.extend([
                '%s %s pre-commit guards left uncommitted: 1 path(s): %s' % (stamp, repo, name),
                '%s %s rc=1 autocommit: 1 file(s) %s' % (stamp, repo, name)])
            if success:
                lines.append('%s %s rc=0 autocommit: 1 file(s) docs/other.md' % (stamp, repo))
        return '\n'.join(lines), start + count * 60

    def refusal_findings(self, text, now, cfg=None):
        ac = self.ac(dirty=1)
        ac['log'] = L.parse_autocommit_log(text, now, repo=L.LIVE_GIT_DIR)
        return L.autocommit_findings(sample(at=now, autocommit=ac), {'since': {}}, cfg or CFG)

    def test_ClassifiesTheRealLogShape(self):
        text, now = self.refusal_log(2, success=False)
        text = text.replace('2026-10-30T22:04:09', '2026-10-30T22:03:09 /home/eric/repos/harness-scratch.git rc=0 autocommit: 1 file(s) docs/other.md\n2026-10-30T22:04:09', 1)
        other, _ = self.refusal_log(1, repo='/home/eric/repos/fleet-guards/.git')
        text += '\n' + other
        parsed = L.parse_autocommit_log(text, now, repo=L.LIVE_GIT_DIR)
        self.assertEqual(L.classify_autocommit_log(parsed['after_ok']), 'guard-refusal')
        self.assertEqual(parsed['refusals']['bin/rw-ship.sh.pre-mainadvance-20261029']['count'], 2)

    def test_RefusalCountSurvivesInterleavedSuccess(self):
        text, now = self.refusal_log(30)
        parsed = L.parse_autocommit_log(text, now, repo=L.LIVE_GIT_DIR)
        evidence = parsed['refusals']['bin/rw-ship.sh.pre-mainadvance-20261029']
        self.assertEqual(evidence['count'], 30)
        self.assertEqual(evidence['last_ts'] - evidence['first_ts'], 29 * 60)
        findings = self.refusal_findings(text, now)
        self.assertEqual(len(findings), 1)
        self.assertIn('(guard-refusal)', findings[0]['title'])
        self.assertEqual(findings[0]['remedies'], [])
        lines = '\n'.join(findings[0]['lines'])
        for value in ('bin/rw-ship.sh.pre-mainadvance-20261029', '30',
                      L.iso(evidence['first_ts']), L.iso(evidence['last_ts'])):
            self.assertIn(value, lines)

    def test_DifferentPathsDoNotAccumulate(self):
        text, now = self.refusal_log(30, different=True)
        self.assertEqual(self.refusal_findings(text, now), [])

    def test_OtherReposAreIgnored(self):
        text, now = self.refusal_log(30, repo='/home/eric/repos/fleet-guards/.git')
        prefix, _ = self.refusal_log(30, repo=L.LIVE_GIT_DIR + '.other')
        self.assertEqual(self.refusal_findings(text + '\n' + prefix, now), [])

    def test_BelowTheMinimumIsQuiet(self):
        for count in (19, 20):
            text, now = self.refusal_log(count)
            self.assertEqual(bool(self.refusal_findings(text, now)), count == 20)
        text, now = self.refusal_log(20)
        self.assertEqual(self.refusal_findings(text, now, dict(CFG, autocommit_refusal_min=21)), [])

    def test_refusal_duration_recency_and_space_paths(self):
        text, now = self.refusal_log(20, path='bin/backup copy.pre-old')
        self.assertIn('bin/backup copy.pre-old', L.parse_autocommit_log(text, now, repo=L.LIVE_GIT_DIR)['refusals'])
        self.assertEqual(self.refusal_findings(text, now + 3600), [])
        self.assertEqual(self.refusal_findings(text, now, dict(CFG, autocommit_stall_minutes=30)), [])
        # A commit subject can quote the producer marker without being a refusal.
        fake = text.replace('pre-commit guards left uncommitted:', 'rc=0 subject pre-commit guards left uncommitted:')
        self.assertEqual(self.refusal_findings(fake, now), [])

    def test_refusal_paths_crosscheck_and_clean_tree(self):
        text, now = self.refusal_log(20, path='bin/backup copy.pre-old, bin/other.pre-old')
        parsed = L.parse_autocommit_log(text.replace('1 path(s):', '2 path(s):').replace(
            '1 file(s) bin/backup copy.pre-old, bin/other.pre-old',
            '2 file(s) bin/backup copy.pre-old bin/other.pre-old'), now, repo=L.LIVE_GIT_DIR)
        self.assertEqual(set(parsed['refusals']), {'bin/backup copy.pre-old', 'bin/other.pre-old'})
        self.assertEqual(parsed['refusals']['bin/backup copy.pre-old']['count'], 20)
        mismatched, _ = self.refusal_log(20, path='bin/backup copy.pre-old')
        mismatched = mismatched.replace('file(s) bin/backup copy.pre-old', 'file(s) other')
        self.assertEqual(L.parse_autocommit_log(mismatched, now, repo=L.LIVE_GIT_DIR)['refusals'], {})
        ac = self.ac(dirty=0, behind=False)
        ac['log'] = parsed
        self.assertEqual(self.find(ac, at=now), [])

    def test_refusal_alert_contract_and_recovery(self):
        text, now = self.refusal_log(30)
        findings = self.refusal_findings(text, now)
        self.assertEqual(findings[0]['title'], 'live tree autocommit stalled (guard-refusal)')

        class Capture(Fx):
            def ticket_new(self, title, body, idem):
                self.body = body
                return super().ticket_new(title, body, idem)

        fx, state = Capture(), st()
        L.act(findings, state, CFG, fx, True, now)
        self.assertIn('bin/rw-ship.sh.pre-mainadvance-20261029; count: 30', fx.body)
        self.assertEqual([c[0] for c in fx.calls], ['ticket'])
        L.act(findings, state, CFG, fx, True, now + 120)
        self.assertEqual([c[0] for c in fx.calls], ['ticket'])
        cleared = self.refusal_findings(text, now + 3600)
        L.act(cleared, state, CFG, fx, True, now + 3600)
        L.act(cleared, state, CFG, fx, True, now + 3600 + CFG.get('clear_seconds', 600))
        self.assertTrue(state['alerts']['autocommit-stalled']['cleared'])
        self.assertEqual([c[0] for c in fx.calls], ['ticket', 'comment', 'patch'])        # the filer closes its own recovered alert (goodqa#13953)
        self.assertEqual(fx.calls[-1], ('patch', 'goodqa#9001', 'done'))

    def test_classify_each_known_cause_and_misleading_inputs(self):
        cases = {"fatal: Unable to create '/x.git/index.lock': File exists.": 'stale-index-lock', 'PRE-COMMIT HOOK CRASH (ValueError in quality_gate): x': 'pre-commit-crash',
                 'UnicodeDecodeError: x': 'pre-commit-crash', 'HARNESS-CHECK refused: biz/x': 'guard-refusal', 'WARN integrate upstream: dirty': 'integrate-dirty',
                 ' ! [rejected]          master -> main (non-fast-forward)': 'push-rejected', 'all fine': 'unknown', '': 'unknown',
                 "fatal: Unable to create '/x.git/refs/heads/foo.lock': File exists.": 'unknown',      # a ref lock is not the index lock
                 'X CLEARED stale index.lock (0 bytes)\nOLD-PATH GUARD refused: a': 'guard-refusal',     # a self-heal line is not a cause
                 ' ! [rejected] protected-branch -> x': 'unknown', 'Traceback (most recent call last): other tool': 'unknown'}
        for tail, want in cases.items():
            self.assertEqual(L.classify_autocommit_log(tail), want, tail)

    def test_parse_log_success_resets_failures_and_cleared_lines_do_not_count(self):
        now = L.ts('2026-10-27T23:00:00Z')
        txt = '\n'.join(['2026-10-27T22:30:00.1 /g rc=0 autocommit: 1 file(s) a', '2026-10-27T22:40:00.1 /g rc=1 x', 'fatal: git said no', '2026-10-27T22:45:00.1 /g WARN integrate upstream: dirty',
                         '2026-10-27T22:46:00.1 /g CLEARED stale index.lock (0 bytes, 300 s old, no holder)', '2026-10-27T22:50:00 PRE-COMMIT HOOK CRASH (X in y): z'])
        r = L.parse_autocommit_log(txt, now)
        self.assertEqual((r['last_ok_age_s'], r['fail_since_age_s'], r['last_fail_age_s'], r['crash_age_s']), (1800.0, 1200.0, 600.0, 600.0))
        self.assertIn('fatal: git said no', r['after_ok'])
        ok_again = L.parse_autocommit_log(txt + '\n2026-10-27T22:55:00.1 /g rc=0 autocommit: 2 file(s) b', now)
        self.assertIsNone(ok_again['fail_since_age_s']); self.assertEqual(ok_again['last_ok_age_s'], 300.0)                # a success clears the failing streak

    def test_fires_on_the_first_sample_once_failing_for_the_hold_and_names_the_cause(self):
        f = self.find(self.ac(fail_since=self.NEED + 30, last_fail=60, last_ok=3000, after_ok='2026-10-27T23:00 rc=1\nWARN integrate upstream: dirty'))
        self.assertEqual(len(f), 1); f = f[0]
        self.assertEqual((f['cls'], f['remedies']), ('autocommit-stalled', [])); self.assertIn('integrate-dirty', f['title']); self.assertIn('5 uncommitted', f['title'])

    def test_negative_controls_nothing_fires_without_evidence_of_a_persisting_failure(self):
        for ac in (self.ac(),                                                                         # QUIET FLEET: dirty + behind, the log has no failure at all
                   self.ac(fail_since=120, last_fail=30, last_ok=5000),                               # failing for 2 min only
                   self.ac(fail_since=2000, last_fail=1500, last_ok=5000),                            # the last failure is old: the failing streak is over
                   self.ac(fail_since=2000, last_fail=100, last_ok=50),                               # a success since the last failure
                   self.ac(fail_since=2000, last_fail=100, last_ok=5000, dirty=0, ahead=0, behind=False)):    # nothing pending, nothing behind
            self.assertEqual(self.find(ac), [], ac['log'])

    def test_a_stale_zero_byte_lock_beside_pending_work_is_named_a_held_or_idle_one_is_not(self):
        stale = self.ac(lock=dict(exists=True, size=0, age_s=1700, holder=''))
        f = self.find(stale)
        self.assertEqual(len(f), 1); self.assertIn('stale-index-lock', f[0]['title']); self.assertIn('0 bytes', ' '.join(f[0]['lines']))
        for lock, extra in ((dict(exists=True, size=0, age_s=1700, holder='4242'), {}), (dict(exists=True, size=0, age_s=1700, holder='unknown'), {}),
                            (dict(exists=True, size=0, age_s=100, holder=''), {}), (dict(exists=True, size=9, age_s=1700, holder=''), {}),
                            (dict(exists=True, size=0, age_s=1700, holder=''), dict(dirty=0, ahead=0, behind=False))):
            self.assertEqual(self.find(self.ac(lock=lock, **extra)), [], (lock, extra))

    def test_unknown_ahead_counts_as_pending_and_a_fresh_hook_crash_is_reported_on_its_own(self):
        f = self.find(self.ac(fail_since=900, last_fail=60, dirty=0, ahead=None, last_ok=4000))
        self.assertEqual(len(f), 1); self.assertIn('? local-only', f[0]['title'])
        h = self.find(self.ac(crash=900, dirty=0, ahead=0, behind=False))
        self.assertEqual([x['cls'] for x in h], ['precommit-hook-crashed']); self.assertEqual(self.find(self.ac(crash=7200, dirty=0, ahead=0, behind=False)), [])

    def test_unreadable_state_is_a_finding_after_the_hold_never_all_clear(self):
        st = {'since': {}}
        err = {'error': 'git status failed: x'}
        self.assertEqual(L.autocommit_findings(sample(at=T0, autocommit=err), st, CFG), [])
        f = L.autocommit_findings(sample(at=T0 + 700, autocommit=err), st, CFG)
        self.assertEqual(len(f), 1); self.assertIn('unreadable', f[0]['title'])
        self.assertEqual(L.autocommit_findings(sample(at=T0 + 800, autocommit=self.ac()), st, CFG), [])      # readable again: cleared

    def test_state_reader_errors_budget_and_real_repos(self):
        import subprocess
        R = lambda rc, out='', err='': type('R', (), dict(returncode=rc, stdout=out, stderr=err))()
        fx = L.Effects(CFG)

        def runner(ls_rc=0, known=True):
            def run(cmd, **k):
                a = cmd[cmd.index('--work-tree') + 2:]
                if a[0] == 'log': return R(0, '1790000000\n')
                if a[0] == 'status': return R(0, ' M a\n')
                if a[0] == 'ls-remote': return R(ls_rc, 'b' * 40 + '\trefs/heads/main\n' if ls_rc == 0 else '', 'fatal: no remote' if ls_rc else '')
                if a[0] == 'cat-file': return R(0 if known else 1)
                if a[0] == 'merge-base': return R(1)
                if a[0] == 'rev-list': return R(0, '2\n')
            return run
        self.assertIn('ls-remote', fx.autocommit_state(run=runner(ls_rc=128), log='/nonexistent')['error'])                  # a missing remote is an ERROR, never behind=False
        s = fx.autocommit_state(run=runner(known=False), log='/nonexistent')
        self.assertTrue(s['behind']); self.assertIsNone(s['ahead']); self.assertNotIn('error', s)                              # unknown object: behind, ahead unknown
        self.assertIn('TimeoutExpired', fx.autocommit_state(run=runner(), log='/nonexistent', budget_s=0)['error'])             # one shared deadline
        E = dict(os.environ, GIT_AUTHOR_NAME='t', GIT_AUTHOR_EMAIL='t@t', GIT_COMMITTER_NAME='t', GIT_COMMITTER_EMAIL='t@t')
        with tempfile.TemporaryDirectory() as t:
            g = lambda cwd, *a: subprocess.run(['git', *a], cwd=cwd, check=True, capture_output=True, text=True, env=E)
            origin, live, other = os.path.join(t, 'origin.git'), os.path.join(t, 'live'), os.path.join(t, 'other')
            g(t, 'init', '-q', '--bare', '-b', 'main', origin)
            os.makedirs(live); g(live, 'init', '-q', '-b', 'master'); open(os.path.join(live, 'a.txt'), 'w').write('1\n'); g(live, 'add', 'a.txt'); g(live, 'commit', '-qm', 'one')
            g(live, 'remote', 'add', 'origin', origin); g(live, 'push', '-q', 'origin', 'master:main')
            logf = os.path.join(t, 'ac.log'); open(logf, 'w').write('2026-10-27T22:00:00.1 %s rc=0 autocommit: 1 file(s) a\n' % os.path.join(live, '.git'))
            s0 = fx.autocommit_state(git_dir=os.path.join(live, '.git'), work_tree=live, log=logf)
            self.assertEqual((s0['dirty'], s0['behind'], s0['ahead'], s0['lock']['exists']), (0, False, 0, False))
            g(t, 'clone', '-q', origin, other); open(os.path.join(other, 'b.txt'), 'w').write('2\n'); g(other, 'add', 'b.txt'); g(other, 'commit', '-qm', 'two'); g(other, 'push', '-q', 'origin', 'HEAD:main')
            open(os.path.join(live, 'c.txt'), 'w').write('3\n')
            lockp = os.path.join(live, '.git', 'index.lock'); open(lockp, 'w').close(); os.utime(lockp, (1, 1))
            open(logf, 'a').write("2026-10-27T23:00:00.1 %s rc=128 x\nfatal: Unable to create '%s': File exists.\n" % (os.path.join(live, '.git'), lockp))
            s1 = fx.autocommit_state(git_dir=os.path.join(live, '.git'), work_tree=live, log=logf)
            self.assertTrue(s1['behind']); self.assertEqual(s1['dirty'], 1); self.assertEqual(s1['lock']['size'], 0); self.assertGreater(s1['lock']['age_s'], 1000)
            self.assertEqual(s1['lock']['holder'], ''); self.assertEqual(L.classify_autocommit_log(s1['log']['after_ok']), 'stale-index-lock')
            self.assertIsNotNone(s1['log']['fail_since_age_s'])
            self.assertIn('error', fx.autocommit_state(git_dir=os.path.join(t, 'nope.git'), work_tree=live, log=logf))

    # ---- Astra review round 2 (REVIEW-C35-ASTRA2.md) ----
    def test_other_repos_entries_do_not_clear_or_create_this_trees_streak_and_any_rc0_line_is_a_success(self):
        now = L.ts('2026-10-27T22:30:00Z')
        H, F = '/home/eric/repos/harness-scratch.git', '/home/eric/repos/fleet-guards/.git'
        txt = '\n'.join(['2026-10-27T22:16:00.1 %s rc=1 x' % H, '2026-10-27T22:29:00.1 %s rc=1 x' % H, '2026-10-27T22:29:30.1 %s rc=0 autocommit: 1 file(s) y' % F])
        r = L.parse_autocommit_log(txt, now, repo=H)
        self.assertEqual((r['fail_since_age_s'], r['last_ok_age_s']), (840.0, None))                      # fleet-guards' success does not clear harness' streak
        only_other = L.parse_autocommit_log('2026-10-27T22:20:00.1 %s rc=1 x' % F, now, repo=H)
        self.assertIsNone(only_other['fail_since_age_s'])                                                  # fleet-guards' failures never flag this tree
        custom = L.parse_autocommit_log(txt + '\n2026-10-27T22:29:40.1 %s rc=0 fix: useful subject' % H, now, repo=H)
        self.assertIsNone(custom['fail_since_age_s']); self.assertEqual(custom['last_ok_age_s'], 20.0)    # a custom commit subject still counts as a success

    def test_a_wedge_older_than_the_log_tail_is_still_found_by_the_observation_clock(self):
        st = {'since': {}}
        ac = self.ac(fail_since=100, last_fail=30, last_ok=90000)                                          # the tail only shows 100 s of a wedge that began hours ago
        self.assertEqual(L.autocommit_findings(sample(at=T0, autocommit=ac), st, CFG), [])                  # first sight: the clock starts
        f = L.autocommit_findings(sample(at=T0 + 700, autocommit=ac), st, CFG)
        self.assertEqual(len(f), 1); self.assertEqual(f[0]['cls'], 'autocommit-stalled')                    # still failing 700 s later: found

    def test_a_fresh_hook_crash_is_reported_even_when_the_git_state_cannot_be_read(self):
        ac = {'error': 'git ls-remote origin main failed or empty (rc=128): no origin', 'log': {'crash_age_s': 120.0}, 'log_tail': 'PRE-COMMIT HOOK CRASH (X in y)'}
        f = L.autocommit_findings(sample(at=T0, autocommit=ac), {'since': {}}, CFG)
        self.assertEqual([x['cls'] for x in f], ['precommit-hook-crashed'])

    def test_lock_and_push_causes_are_not_over_claimed(self):
        self.assertEqual(L.classify_autocommit_log("fatal: Unable to create '/x.git/index.lock': Permission denied"), 'index-lock-permission')
        self.assertEqual(L.classify_autocommit_log("fatal: Unable to create '/x.git/index.lock': File exists.\nAnother git process seems to be running in this repository"), 'git-writer-busy')
        self.assertEqual(L.classify_autocommit_log(' ! [rejected]  feature -> feature (non-fast-forward)'), 'unknown')
        self.assertEqual(L.classify_autocommit_log(' ! [rejected]  master -> main (non-fast-forward)'), 'push-rejected')

    def test_a_bad_budget_is_contained_not_raised(self):
        r = L.Effects({'autocommit_budget_seconds': 'bad'}).autocommit_state(log='/nonexistent')
        self.assertIn('error', r)

    # ---- Astra review round 3 (REVIEW-C35-ASTRA3.md) ----
    def test_a_commit_subject_with_a_failure_word_is_still_a_success(self):
        now = L.ts('2026-10-27T22:30:00Z'); H = '/home/eric/repos/harness-scratch.git'
        r = L.parse_autocommit_log('2026-10-27T22:20:00.1 %s rc=1 x\n2026-10-27T22:29:00.1 %s rc=0 Fix ERROR handling and rc=1 retries' % (H, H), now, repo=H)
        self.assertIsNone(r['fail_since_age_s']); self.assertEqual(r['last_ok_age_s'], 60.0)

    def test_unpushed_local_commits_that_persist_are_a_stall_whatever_the_untimestamped_push_errors_say(self):
        st = {'since': {}}
        ac = self.ac(dirty=0, ahead=2, ahead_oldest='a' * 40, behind=False, last_ok=30, log_tail=' ! [rejected] master -> main (non-fast-forward)')     # rc=0 recently, raw rejections without timestamps
        self.assertEqual(L.autocommit_findings(sample(at=T0, autocommit=ac), st, CFG), [])                                          # first sight
        f = L.autocommit_findings(sample(at=T0 + 700, autocommit=ac), st, CFG)
        self.assertEqual(len(f), 1); self.assertIn('2 local-only', f[0]['title'])
        quiet = self.ac(dirty=0, ahead=0, behind=False)
        self.assertEqual([L.autocommit_findings(sample(at=T0 + i * 700, autocommit=quiet), {'since': {}}, CFG) for i in range(3)], [[], [], []])   # a pushed tree never fires

    def test_after_ok_keeps_only_this_repos_entries_and_the_newest_cause_wins(self):
        now = L.ts('2026-10-27T22:30:00Z'); H, F = '/home/eric/repos/harness-scratch.git', '/home/eric/repos/fleet-guards/.git'
        txt = '\n'.join(['2026-10-27T22:10:00.1 %s rc=1 x' % H, "fatal: Unable to create '/x.git/index.lock': File exists.", '2026-10-27T22:11:00.1 %s rc=1 y' % F,
                         "fatal: index.lock Permission denied (other repo)", '2026-10-27T22:20:00.1 %s rc=1 z' % H, 'HARNESS-CHECK refused: biz/x'])
        r = L.parse_autocommit_log(txt, now, repo=H)
        self.assertNotIn('Permission denied', r['after_ok'])                                           # the other repo's raw lines are not attributed to this tree
        self.assertEqual(L.classify_autocommit_log(r['after_ok']), 'guard-refusal')                    # the newest cause (HARNESS-CHECK) beats the older index.lock one

    def test_an_odd_timestamp_line_never_loses_the_crash_evidence(self):
        now = L.ts('2026-10-27T22:30:00Z')
        r = L.parse_autocommit_log('2026-10-27T22:20:00.1 PRE-COMMIT HOOK CRASH (X in y): z\n2026-99-27T22:05:00 strange', now)
        self.assertEqual(r['crash_age_s'], 600.0)

    # ---- Astra review round 4 (REVIEW-C35-ASTRA4.md) ----
    def test_a_success_subject_naming_the_crash_marker_is_a_success_only_the_hook_line_is_a_crash(self):
        now = L.ts('2026-10-27T23:30:00Z'); H = '/home/eric/repos/harness-scratch.git'
        r = L.parse_autocommit_log('2026-10-27T23:00:00.1 %s rc=0 fix PRE-COMMIT HOOK CRASH logging' % H, now, repo=H)
        self.assertIsNone(r['crash_age_s']); self.assertIsNone(r['fail_since_age_s']); self.assertEqual(r['last_ok_age_s'], 1800.0)
        self.assertEqual(L.parse_autocommit_log('2026-10-27T23:00:00.1 PRE-COMMIT HOOK CRASH (X in y): z', now)['crash_age_s'], 1800.0)

    def test_a_healthy_publish_cycle_never_alerts_but_the_same_commit_stuck_does(self):
        st = {'since': {}}
        out = []
        for i in range(8):                                                             # every 120 s a NEW local commit is the oldest unpushed one: it was published before
            ac = self.ac(dirty=0, ahead=1, ahead_oldest=('%040x' % i), behind=False, last_ok=30)
            out.append(L.autocommit_findings(sample(at=T0 + i * 120, autocommit=ac), st, CFG))
        self.assertEqual([o for o in out if o], [])
        stuck = []
        for i in range(8):
            ac = self.ac(dirty=0, ahead=1, ahead_oldest='b' * 40, behind=False, last_ok=30)
            stuck.append(L.autocommit_findings(sample(at=T0 + 5000 + i * 120, autocommit=ac), st, CFG))
        self.assertTrue(any(stuck)); self.assertIn('unpushed-commits', [o for o in stuck if o][0][0]['title'])

    def test_an_unknown_ahead_alone_is_not_a_stall_but_the_same_stuck_commit_found_through_the_fallback_is(self):
        st = {'since': {}}
        quiet = self.ac(dirty=0, ahead=None, ahead_oldest='', behind=True, last_ok=30, after_ok='', log_tail='x rc=0 fix UnicodeDecodeError handling')
        outs = [L.autocommit_findings(sample(at=T0 + i * 700, autocommit=quiet), st, CFG) for i in range(3)]
        self.assertEqual([o for o in outs if o], [])                                  # behind a moved origin in a quiet period: normal
        stuck = self.ac(dirty=0, ahead=1, ahead_oldest='c' * 40, behind=True, last_ok=30, after_ok='', log_tail='x rc=0 fix UnicodeDecodeError handling')
        f = [L.autocommit_findings(sample(at=T0 + 9000 + i * 700, autocommit=stuck), st, CFG) for i in range(3)]
        self.assertTrue(any(f)); title = [o for o in f if o][0][0]['title']
        self.assertIn('unpushed-commits', title); self.assertNotIn('pre-commit-crash', title)

    def test_healthy_publication_with_an_advancing_unknown_tip_does_not_alert_and_an_empty_fallback_means_published(self):
        R = lambda rc, out='', err='': type('R', (), dict(returncode=rc, stdout=out, stderr=err))()
        st = {'since': {}}
        outs = []
        for i in range(8):                                                              # origin advances each pass (unknown tip); our newest commit is published via the push (the tracking ref follows it)
            def run(cmd, i=i, **k):
                a = cmd[cmd.index('--work-tree') + 2:]
                if a[0] == 'log': return R(0, '1790000000\n')
                if a[0] == 'status': return R(0, '')
                if a[0] == 'ls-remote': return R(0, ('%040x' % (i + 1)) + '\trefs/heads/main\n')
                if a[0] == 'cat-file': return R(1)
                if a[0] == 'rev-list': return R(0, '')                                  # nothing our origin/main ref lacks: everything published
            s = L.Effects(CFG).autocommit_state(run=run, log='/nonexistent', now=T0 + i * 120)
            self.assertEqual((s['ahead'], s['ahead_oldest']), (0, ''))
            outs.append(L.autocommit_findings(sample(at=T0 + i * 120, autocommit=s), st, CFG))
        self.assertEqual([o for o in outs if o], [])

    def test_reader_uses_the_remote_ref_fallback_for_an_unknown_tip_and_reports_the_oldest_unpushed_commit(self):
        R = lambda rc, out='', err='': type('R', (), dict(returncode=rc, stdout=out, stderr=err))()
        calls = []

        def run(cmd, **k):
            a = cmd[cmd.index('--work-tree') + 2:]; calls.append(a)
            if a[0] == 'log': return R(0, '1790000000\n')
            if a[0] == 'status': return R(0, '')
            if a[0] == 'ls-remote': return R(0, 'b' * 40 + '\trefs/heads/main\n')
            if a[0] == 'cat-file': return R(1)
            if a[0] == 'rev-list': return R(0, ('c' * 40) + '\n' + ('d' * 40) + '\n')
        s = L.Effects(CFG).autocommit_state(run=run, log='/nonexistent')
        self.assertEqual((s['behind'], s['ahead'], s['ahead_oldest']), (True, 2, 'd' * 40))
        self.assertIn(['rev-list', 'master', '--not', 'refs/remotes/origin/main'], [list(c) for c in calls])



class HostHealth(unittest.TestCase):
    """Scripted facts only: no test reaches systemd, ssh, or ticket services."""
    def setUp(self):
        self.cfg = dict(CFG, unit_autostop_mode='enforce', clear_seconds=0)
        self.state = st()
        self.fx = Fx()
        self.fx.stop_timer = lambda host, service, unit, user: (self.fx.calls.append(('stop', host, unit, user)) or (0, 'stopped'))
        self.fx.hawk = lambda body: (self.fx.calls.append(('journal', body)) or (0, '', ''))
        self.path = '~/archive/state-backups'
        self.unit = dict(unit='box-state-backup.service', active='failed', sub='failed', user=True,
                         Result='exit-code', ExecMainStatus='2', InactiveEnterTimestamp='failure timestamp', journal='FATAL: tar exit 2')

    def reading(self, units=None, files=None, disks=None):
        return dict(units=[self.unit] if units is None else units, dirs={self.path: files or []}, disks=disks or {})

    def detect(self, reading=None, at=T0, host='dev2', apply=False):
        findings = L.host_health_findings({host: reading or self.reading()}, self.state, self.cfg, at)
        if apply:
            L.act(findings, self.state, self.cfg, self.fx, True, at)
        return findings

    def file(self, name='x.tar', gb=74, age=7200, at=T0):
        return dict(name=name, size=int(gb * 1024**3), mtime=at-age, type='file')

    def test_UnitFailedForTwoSamplesAlerts(self):
        self.assertEqual(self.detect(), [])
        self.assertEqual(self.detect(at=T0+59), [])
        found = self.detect(at=T0+60)
        self.assertIn('unit-failing:dev2:box-state-backup.service', classes(found))
        self.assertIn('FATAL: tar exit 2', ' '.join(found[0]['lines']))
        self.detect(self.reading(units=[]), at=T0+120)
        self.detect(at=T0+180)
        self.assertEqual(self.state['host_health']['dev2']['units']['box-state-backup.service']['count'],1)

    def test_AllowListedTimerIsStoppedOnceInEnforce(self):
        self.detect(apply=True)
        self.detect(at=T0+60, apply=True)
        self.detect(at=T0+900, apply=True)
        self.assertEqual([c for c in self.fx.calls if c[0]=='stop'], [('stop', 'dev2', 'box-state-backup.timer', True)])
        self.assertTrue(any(c[0]=='journal' for c in self.fx.calls))
        self.cfg['unit_autostop_mode']='warn'
        self.state=st(); self.fx.calls=[]
        self.detect(apply=True); self.detect(at=T0+60, apply=True)
        self.assertFalse(any(c[0]=='stop' for c in self.fx.calls))

    def test_AFailedUnitNotOnTheAllowListIsNeverStopped(self):
        self.unit['unit']='other.service'
        self.detect(apply=True); self.detect(at=T0+60, apply=True)
        self.assertTrue(self.state['alerts'])
        self.assertFalse(any(c[0]=='stop' for c in self.fx.calls))

    def test_ARunningServiceIsNeverStopped(self):
        for active in ('active', 'activating', 'inactive'):
            with self.subTest(active=active):
                self.unit['active']=active
                self.detect(apply=True); self.detect(at=T0+60, apply=True)
                self.assertFalse(any(c[0]=='stop' for c in self.fx.calls))

    def test_OnlyTheMappedTimerIsStopped(self):
        for name in ('x.service; touch bad', '-bad.service', 'x.service\n', '../../x.service'):
            self.unit['unit']=name
            self.state=st()
            self.assertEqual(self.detect(at=T0, apply=True), [])
            self.assertEqual(self.detect(at=T0+60, apply=True), [])
        self.assertFalse(any(c[0]=='stop' for c in self.fx.calls))

    def test_ALeakedRawTarFiresOnBothHosts(self):
        for host in ('dev', 'dev2'):
            fs=self.detect(self.reading(units=[], files=[self.file()]), host=host)
            self.assertIn('output-leak:%s:%s' % (host,self.path), classes(fs))
            self.assertIn('x.tar', ' '.join(fs[0]['lines']))

    def test_ACleanBackupDirDoesNotFire(self):
        self.assertEqual(self.detect(self.reading(units=[],files=[self.file('backup.tar.gz',gb=1)])), [])
        self.assertEqual(self.detect(self.reading(units=[],files=[self.file(gb=1,age=0)])), [])

    def test_AnOversizedUnlistedFileFires(self):
        self.assertTrue(self.detect(self.reading(units=[],files=[self.file('unexpected', gb=6)])))

    def test_AnOverBudgetDirFires(self):
        files=[self.file('backup%d.tar.gz'%i,gb=100) for i in range(6)]
        self.assertTrue(self.detect(self.reading(units=[],files=files)))

    def test_GraceAndSizeBoundaries(self):
        for age in (3540,3600,3660):
            self.state=st()
            found=self.detect(self.reading(units=[],files=[self.file(gb=1,age=age)]))
            self.assertEqual(bool(found),age>3600)
        for delta in (-1,0,1):
            f=self.file('unknown',gb=5); f['size']+=delta
            self.assertEqual(bool(self.detect(self.reading(units=[],files=[f]))),delta>0)

    def disks(self, at, growth=27, free=136):
        used=(5800-free)*1024**2 + growth*1024**2*(at-T0)/3600
        return {'/':dict(used_kb=used,free_kb=5800*1024**2-used,total_kb=5800*1024**2)}

    def test_ProjectedFillUnderTheWindowFires(self):
        for growth in (27,0.5,-27,0):
            self.state=st()
            for i in range(11):
                at=T0+i*360
                found=self.detect(self.reading(units=[],disks=self.disks(at,growth,free=136 if growth==27 else 1500)),at=at)
                self.assertEqual(any(f['cls'].startswith('disk-fill-eta:') for f in found),i>=9 and growth>5)
            if growth==27:
                self.assertIn('halt', ' '.join(found[0]['lines']))
                self.assertIn('growth 27.00 GB/h', ' '.join(found[0]['lines']))

    def test_AnUnreachableHostIsUnknownNotAFindingNorAClear(self):
        self.detect(apply=True); self.detect(at=T0+60,apply=True)
        for at in (T0+120,T0+10000):
            self.detect({'error':'ssh timeout'},at=at,apply=True)
        self.assertEqual(len(self.state['alerts']),1)
        self.assertFalse(any(a.get('cleared') for a in self.state['alerts'].values()))
        fresh=st()
        self.assertEqual(L.host_health_findings({'dev':{'error':'timeout'}},fresh,self.cfg,T0),[])

    def test_RecoveryClearsTheFindingsAndCommentsOnce(self):
        self.detect(apply=True); self.detect(at=T0+60,apply=True)
        for i in range(2,6):
            self.detect(self.reading(units=[]),at=T0+i*60,apply=True)
        recovered=[c for c in self.fx.calls if c[0]=='comment' and 'recovered' in c[2]]
        self.assertEqual(len(recovered),1)
        self.detect(at=T0+900,apply=True); self.detect(at=T0+960,apply=True)
        self.assertEqual(len([c for c in self.fx.calls if c[0]=='stop']),2)

    def test_ConfigRoundTrips(self):
        cfg=L.load_config()
        self.assertEqual(json.loads(json.dumps(cfg)),cfg)
        for key in ('host_health','host_health_budget_seconds','unit_failed_samples','unit_failed_sample_gap_seconds',
                    'unit_clean_samples','unit_autostop_mode','disk_fill_window_minutes','disk_fill_eta_hours',
                    'disk_fill_min_gb_per_h','disk_fill_warn_free_pct','disk_halt_free_pct'):
            self.assertIn(key,cfg)

    def test_IncidentReplay(self):
        # Two detector observations establish the failure before the first output
        # is left behind; then six job runs fail at their six-hour cadence.
        self.assertEqual(self.detect(self.reading(files=[]),at=T0,apply=True),[])
        second=self.detect(self.reading(files=[]),at=T0+60,apply=True)
        self.assertIn('unit-failing:dev2:box-state-backup.service',classes(second))
        sizes=(74,76,77,79,87,90)
        for i,gb in enumerate(sizes):
            at=T0+(i+1)*21600
            files=[self.file('run%d.tar'%j,g,at=at) for j,g in enumerate(sizes[:i+1])]
            findings=self.detect(self.reading(files=files),at=at,apply=True)
            self.assertIn('unit-failing:dev2:box-state-backup.service',classes(findings))
            self.assertIn('output-leak:dev2:'+self.path,classes(findings))
        self.assertEqual(sum(f['size'] for f in files),483*1024**3)
        self.assertEqual(len([c for c in self.fx.calls if c[0]=='stop']),1)


class HostHealthCollection(unittest.TestCase):
    def result(self, output='', rc=0):
        import types
        return types.SimpleNamespace(stdout=output, stderr='', returncode=rc)

    def runner(self, calls, state='failed', fail=None):
        def run(argv, **kwargs):
            calls.append((argv, kwargs))
            if fail and fail in argv:
                return self.result(rc=1)
            if '--failed' in argv:
                return self.result('box-state-backup.service loaded failed failed backup\n' if '--user' in argv else '')
            if 'show' in argv:
                return self.result(state+'\n' if '--value' in argv else 'ActiveState='+state+'\nSubState=failed\nResult=exit-code\nExecMainStatus=2\nInactiveEnterTimestamp=yesterday\n')
            if argv[0]=='journalctl':
                return self.result('FATAL token=secret-value password=secret-value\n')
            if argv[0]=='df':
                return self.result('Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/root 10000 9000 1000 90% /\n')
            if 'stop' in argv:
                return self.result()
            raise AssertionError(argv)
        return run

    def test_CollectorIsBoundedNonRecursiveAndScrubbed(self):
        calls=[]
        with tempfile.TemporaryDirectory(dir=_TMP) as root:
            with open(os.path.join(root,'x.tar'),'w') as f:
                f.write('data')
            os.mkdir(os.path.join(root,'deep'))
            with open(os.path.join(root,'deep','hidden'),'w') as f:
                f.write('hidden data')
            result=L.collect_host_health(dict(output_dirs=[dict(path=root)],filesystems=['/']),25,run=self.runner(calls))
            self.assertNotIn('error',result)
            self.assertEqual({e['name'] for e in result['dirs'][root]}, {'x.tar','deep'})
            self.assertEqual(next(e for e in result['dirs'][root] if e['name']=='x.tar')['size'],4)
            self.assertEqual(result['disks']['/']['free_kb'],1000)
            unit=result['units'][0]
            self.assertEqual((unit['Result'],unit['ExecMainStatus'],unit['user']),('exit-code','2',True))
            self.assertNotIn('secret-value',unit['journal'])
            self.assertTrue(all(0<kwargs['timeout']<=25 for _,kwargs in calls))
            self.assertEqual(len([a for a,k in calls if '--failed' in a]),2)
        for secret in ('Bearer secret-value','api_key=secret-value', 'https://user:secret-value@host/'):
            self.assertNotIn('secret-value',L.health_scrub(secret))
        self.assertLessEqual(len(L.health_scrub('a'*500)),300)

    def test_CollectorTimeoutFailureAndOverflowAreUnknown(self):
        import subprocess
        def timeout(*a,**k):
            raise subprocess.TimeoutExpired('fake',25)
        self.assertIn('error',L.collect_host_health({},25,run=timeout))
        for command in ('systemctl','journalctl','df'):
            self.assertIn('error',L.collect_host_health(dict(filesystems=['/']),25,run=self.runner([],fail=command)))
        with tempfile.TemporaryDirectory(dir=_TMP) as root:
            for i in range(501):
                with open(os.path.join(root,str(i)),'w'):
                    pass
            self.assertIn('error',L.collect_host_health(dict(output_dirs=[dict(path=root)]),25,run=self.runner([])))
        ticks=iter((0,26))
        self.assertIn('error',L.collect_host_health({},25,run=self.runner([]),clock=lambda:next(ticks)))

    def test_FreshActiveGuardAndExactTimerEffect(self):
        for user in (True,False):
            for active in ('active','activating','inactive','failed','unknown'):
                calls=[]
                rc,note=L.stop_health_timer('box-state-backup.service','box-state-backup.timer',user,25,run=self.runner(calls,active))
                stops=[a for a,k in calls if 'stop' in a]
                self.assertEqual(bool(stops),active=='failed')
                if stops:
                    self.assertEqual(stops,[['systemctl',*(['--user'] if user else []),'stop','box-state-backup.timer']])
                    self.assertEqual(rc,0)
        for unit in ('bad.service;echo X','x.timer\n','../x.timer','-x.timer'):
            calls=[]
            self.assertNotEqual(L.stop_health_timer('box-state-backup.service',unit,True,25,run=self.runner(calls))[0],0)
            self.assertEqual(calls,[])

    def test_TransportUsesExistingHelperAndRejectsInvalidJSONShape(self):
        from unittest.mock import patch
        fx=L.Effects(CFG)
        for host in ('dev','dev2'):
            with patch.object(L.C,'run',return_value=(0,'{"units":[],"dirs":{},"disks":{}}','')) as run:
                self.assertNotIn('error',fx.host_health(host))
                argv=run.call_args.args[0]
                self.assertEqual(argv[0],sys.executable if host=='dev' else L.DEV2)
                self.assertEqual(run.call_args.kwargs['timeout'],25)
                self.assertIn('collect_host_health',run.call_args.kwargs['input'])
        for body in ('[]','null','{}','{"units":{}}','invalid'):
            with patch.object(L.C,'run',return_value=(0,body,'')):
                self.assertIn('error',fx.host_health('dev2'))
        with patch.object(L.C,'run',return_value=(124,'','timeout')):
            self.assertIn('error',fx.host_health('dev2'))

    def test_TransportProgramRunsWithOnlyItsOwnDependencies(self):
        from unittest.mock import patch
        for host in ('dev','dev2'):
            def transport(argv,**kw):
                import contextlib
                import io
                out=io.StringIO()
                with contextlib.redirect_stdout(out), patch('subprocess.run',self.runner([])):
                    exec(kw['input'],{})
                return 0,out.getvalue(),''
            config=dict(CFG,host_health=dict(filesystems={'dev':['/'],'dev2':['/']},output_dirs=[]))
            with patch.object(L.C,'run',side_effect=transport):
                self.assertEqual(L.Effects(config).host_health(host)['units'][0]['Result'],'exit-code')

    def test_EffectPolicyRefusesWarnAndUnmappedTimer(self):
        from unittest.mock import patch
        for cfg,timer in ((CFG,'box-state-backup.timer'),(dict(CFG,unit_autostop_mode='enforce'),'other.timer')):
            with patch.object(L.C,'run') as run:
                self.assertNotEqual(L.Effects(cfg).stop_timer('dev2','box-state-backup.service',timer,True)[0],0)
                run.assert_not_called()
        cfg=dict(CFG,unit_autostop_mode='enforce')
        def transport(argv,**kw):
            import contextlib
            import io
            out=io.StringIO()
            with contextlib.redirect_stdout(out), patch('subprocess.run',self.runner(calls)):
                exec(kw['input'],{})
            return 0,out.getvalue(),''
        calls=[]
        with patch.object(L.C,'run',side_effect=transport):
            self.assertEqual(L.Effects(cfg).stop_timer('dev2','box-state-backup.service','box-state-backup.timer',True)[0],0)
        self.assertEqual([a[-1] for a,k in calls if 'stop' in a],['box-state-backup.timer'])

    def test_SharedTimerChecksTheServiceThatProducedTheRemedy(self):
        from unittest.mock import patch
        import contextlib
        import io
        for host in ('dev', 'dev2'):
            for user in (False, True):
                for sibling_state in ('active', 'activating', 'failed'):
                    with self.subTest(host=host, user=user, sibling_state=sibling_state):
                        fixture = HostHealth()
                        fixture.setUp()
                        fixture.unit['user'] = user
                        policy = dict(fixture.cfg['host_health'])
                        policy['failed_units'] = dict(policy['failed_units'], autostop={
                            'first.service': 'box-state-backup.timer',
                            'box-state-backup.service': 'box-state-backup.timer'})
                        fixture.cfg = dict(fixture.cfg, host_health=policy)
                        fixture.fx.stop_timer = L.Effects(fixture.cfg).stop_timer
                        calls = []

                        def systemctl(argv, **kwargs):
                            calls.append(argv)
                            state = sibling_state if 'first.service' in argv else 'failed'
                            return __import__('subprocess').CompletedProcess(argv, 0, state, '')

                        def transport(argv, **kwargs):
                            out = io.StringIO()
                            with contextlib.redirect_stdout(out), patch('subprocess.run', systemctl):
                                exec(kwargs['input'], {})
                            return 0, out.getvalue(), ''

                        with patch.object(L.C, 'run', side_effect=transport):
                            fixture.detect(host=host, apply=True)
                            fixture.detect(host=host, at=T0+60, apply=True)
                            fixture.detect(host=host, at=T0+120, apply=True)
                        scope = ['--user'] if user else []
                        self.assertEqual(calls, [
                            ['systemctl', *scope, 'show', 'box-state-backup.service', '--property=ActiveState', '--value'],
                            ['systemctl', *scope, 'stop', 'box-state-backup.timer']])
                        self.assertTrue(any(c[0] == 'journal' and 'rc=0' in c[1] for c in fixture.fx.calls))

    def test_StopRequiresTheExactServiceTimerPair(self):
        from unittest.mock import patch
        cfg = dict(CFG, unit_autostop_mode='enforce')
        for service, timer in (
                ('other.service', 'box-state-backup.timer'),
                ('box-state-backup.service', 'other.timer'),
                ('box-state-backup.service;echo', 'box-state-backup.timer'),
                ('box-state-backup.timer', 'box-state-backup.timer')):
            with self.subTest(service=service, timer=timer), patch.object(
                    L.C, 'run', return_value=(0, '{"result":[0,"stub stop"]}', '')) as run:
                self.assertNotEqual(L.Effects(cfg).stop_timer('dev2', service, timer, True)[0], 0)
                run.assert_not_called()

    def test_NameAndPathEdges(self):
        for name in ('x.service','a@b:1-2_.timer'):
            self.assertTrue(L.health_unit(name))
        for name in ('x.unknown','x.service\n','x.service;echo','../x.service','-x.service',''):
            self.assertFalse(L.health_unit(name))
        for path in ('/','~/archive/backups','/space dir/a'):
            self.assertTrue(L.health_path(path))
        for path in ('relative','/x/../y','~/../x','/x\x00','/x\n'):
            self.assertFalse(L.health_path(path))

    def test_ReplayIgnoresTheLiveOnlyFindings(self):
        from unittest.mock import patch
        fx=Fx()
        fx.snapshot=lambda **k: dict(lines=[],repo_of={})
        fx.lane_floor_floor=lambda:40
        fx.lane_floor_lines=lambda *a:[]
        fx.refusals=lambda:[]
        fx.host_health=lambda *a: self.fail('replay must not collect live health')
        with patch.object(L,'host_health_findings',side_effect=AssertionError('live detector called')):
            result=L.replay(CFG,fx,L.iso(T0),L.iso(T0+120))
        self.assertEqual(result['events'],[])


class HostHealthEdges(HostHealth):
    # Inherit fixture helpers without rerunning the named controls in this class.
    def test_FlappingFailedUnitKeepsEpisodeUntilConfirmedRecovery(self):
        self.detect(apply=True); self.detect(at=T0+60,apply=True)
        self.detect(self.reading(units=[]),at=T0+120,apply=True)
        found=self.detect(at=T0+180,apply=True)
        self.assertIn('unit-failing:dev2:box-state-backup.service',classes(found))
        self.assertFalse(any(a.get('cleared') for a in self.state['alerts'].values()))
        self.assertEqual(len([c for c in self.fx.calls if c[0]=='stop']),1)

    def test_TenSamplesWindowAndRingBound(self):
        for count in (9,10,11):
            self.state=st()
            for i in range(count):
                now=T0+i*360
                found=self.detect(self.reading(units=[],disks=self.disks(now)),at=now)
            self.assertEqual(bool(found),count>=10)
        self.state=st()
        for i in range(130):
            now=T0+i*20
            self.detect(self.reading(units=[],disks=self.disks(now)),at=now)
        self.assertEqual(len(self.state['host_health']['dev2']['disks']['/']),120)

    def test_LeastSquaresAndThresholdBoundaries(self):
        # Construct the historical ring directly to isolate slope from free-space thresholds.
        for rate,free,total,expected in ((5,200,1000,False),(5.01,200,1000,True),(4.99,200,1000,False),
                (10,480,1000,False),(10,479,1000,True),(1,150,1000,False),(1,149,1000,True),
                (0,100,1000,False),(-1,100,1000,False)):
            with self.subTest(rate=rate,free=free):
                self.state=st()
                # Integer-hour positions within a configurable 12-hour window avoid float boundary noise.
                cfg=dict(self.cfg,disk_fill_window_minutes=720)
                ring=[[T0-i*3600,(total-free-rate*i)*1024**2] for i in range(9,0,-1)]
                self.state['host_health']={'dev2':dict(units={},findings={},disks={'/':ring})}
                found=L.host_health_findings({'dev2':self.reading(units=[],disks={'/':dict(used_kb=(total-free)*1024**2,
                     free_kb=free*1024**2,total_kb=total*1024**2)})},self.state,cfg,T0)
                self.assertEqual(bool(found),expected)

    def test_MultipleHostsCooldownDryRunAndStopFailure(self):
        readings={h:self.reading() for h in ('dev','dev2')}
        L.host_health_findings(readings,self.state,self.cfg,T0)
        found=L.host_health_findings(readings,self.state,self.cfg,T0+60)
        L.act(found,self.state,self.cfg,self.fx,False,T0+60)
        self.assertEqual(self.fx.calls,[])
        L.act(found,self.state,self.cfg,self.fx,True,T0+60)
        self.assertEqual({c[1] for c in self.fx.calls if c[0]=='stop'},{'dev','dev2'})
        self.state=st(); self.fx.calls=[]
        def fail(*args):
            self.fx.calls.append(('stop-failed',args)); return 2,'stub failure'
        self.fx.stop_timer=fail
        self.detect(apply=True); self.detect(at=T0+60,apply=True); self.detect(at=T0+900,apply=True)
        self.assertEqual(len([c for c in self.fx.calls if c[0]=='stop-failed']),1)

    def test_IgnoreAndConfigurablePersistence(self):
        policy=dict(self.cfg['host_health'])
        policy['failed_units']=dict(policy['failed_units'],ignore=[{'glob':'box-*.service', 'reason':'test fixture'}])
        self.cfg=dict(self.cfg,host_health=policy)
        self.detect(at=T0); self.assertEqual(self.detect(at=T0+60),[])
        self.cfg=dict(CFG,unit_failed_samples=3)
        self.state=st()
        self.assertEqual(self.detect(at=T0),[])
        self.assertEqual(self.detect(at=T0+60),[])
        self.assertTrue(self.detect(at=T0+120))


    def test_AllowedOversizedFileAndDirBudgetBoundaries(self):
        self.assertEqual(self.detect(self.reading(units=[],files=[self.file('allowed.tar.gz',gb=6)])),[])
        for delta in (-1,0,1):
            file=self.file('allowed.tar.gz',gb=500)
            file['size']+=delta
            self.assertEqual(bool(self.detect(self.reading(units=[],files=[file]))),delta>0)

    def test_WatchedDirectoryIsHostSpecific(self):
        policy=dict(self.cfg['host_health'])
        policy['output_dirs']=[dict(d,path='/only-on-dev') for d in policy['output_dirs'] if d['host']=='dev']
        self.cfg=dict(self.cfg,host_health=policy)
        self.assertEqual(self.detect(dict(units=[],dirs={'/only-on-dev':[self.file()]},disks={})),[])


    def test_ProjectionReportsHaltThresholdAndLeastSquares(self):
        # Uneven growth in the middle distinguishes least squares from an endpoint slope.
        self.state['host_health']={'dev2':dict(units={},findings={},disks={'/':[
            [T0-3600,4700*1024**2],[T0-3000,4720*1024**2],[T0-2400,4740*1024**2],
            [T0-1800,4750*1024**2],[T0-1200,4760*1024**2],[T0-900,4770*1024**2],
            [T0-600,4780*1024**2],[T0-300,4790*1024**2],[T0-120,4795*1024**2]]})}
        found=self.detect(self.reading(units=[],disks={'/':dict(used_kb=4800*1024**2,free_kb=1000*1024**2,total_kb=5800*1024**2)}))
        self.assertEqual(len(found),1)
        self.assertIn('growth 94.36 GB/h',found[0]['lines'][0])
        self.assertIn('5.68 h to fleet halt (8% free)',found[0]['lines'][0])


class FailedUnitCensus(unittest.TestCase):
    result = HostHealthCollection.result
    runner = HostHealthCollection.runner

    def collect(self, lines, tail='first diagnostic\nlast diagnostic', calls=None):
        calls = [] if calls is None else calls
        fallback = self.runner(calls)
        def run(argv, **kw):
            if '--failed' in argv:
                calls.append((argv, kw))
                return self.result(lines if '--user' in argv else '')
            if argv[0] == 'journalctl':
                calls.append((argv, kw))
                return self.result(tail)
            return fallback(argv, **kw)
        return L.collect_host_health({}, 25, run=run, clock=lambda: 0)

    def test_ScopeUnitDoesNotBlindTheCensus(self):
        names = ['app-com.google.Chrome-1.scope', 'coordinator-watch@stuck-lanes.service', 'rule-reliability.service']
        r = self.collect('\n'.join(n+' loaded failed failed description' for n in names))
        self.assertNotIn('error', r)
        self.assertEqual([u['unit'] for u in r['units']], names)
        self.assertEqual(r['failed_lines'], 3)
        self.assertEqual(r['failed_lines_by_scope'], {'user': 3, 'system': 0})
        for suffix in ('service', 'timer', 'scope', 'socket', 'mount', 'path', 'slice', 'target', 'device', 'swap', 'automount'):
            self.assertTrue(L.health_unit('example.'+suffix))

    def test_UnparsedLineIsAFindingNotAnOutage(self):
        r = self.collect('bad-token\nvalid.service loaded failed failed\ninvalid token=private-value loaded failed failed')
        self.assertNotIn('error', r)
        self.assertEqual(len(r['units']), 1)
        self.assertEqual(len(r['unparsed']), 2)
        self.assertNotIn('private-value', str(r['unparsed']))
        fs = L.host_health_findings({'dev': r}, st(), CFG, T0)
        self.assertIn('host-health-unparsed:dev', classes(fs))
        self.assertNotIn('host-health-census:dev', classes(fs))

    def test_UnknownCensusIsRedAfterN(self):
        state = st()
        def detect(reading, tick):
            return L.host_health_findings({'dev': reading}, state, CFG, T0+60*tick)
        error = {'error': 'TimeoutError: token=private-value'}
        self.assertEqual(detect(error, 0), [])
        self.assertEqual(detect(error, 1), [])
        found = detect(error, 2)
        self.assertIn('host-health-unknown:dev', classes(found))
        self.assertNotIn('private-value', str(found))
        clean = dict(units=[], dirs={}, disks={}, failed_lines=0, unparsed=[])
        self.assertIn('host-health-unknown:dev', classes(detect(clean, 3)))
        self.assertNotIn('host-health-unknown:dev', classes(detect(clean, 4)))
        self.assertEqual(detect(error, 5), [])
        detect(clean, 6)
        self.assertEqual(detect(error, 7), [])

    def test_CensusCountMismatchIsAFinding(self):
        for host in ('dev', 'dev2'):
            r = dict(units=[], unparsed=[], failed_lines=1, dirs={}, disks={})
            self.assertIn('host-health-census:'+host, classes(L.host_health_findings({host:r}, st(), CFG, T0)))
            r['failed_lines'] = 0
            self.assertEqual(L.host_health_findings({host:r}, st(), CFG, T0), [])

    def test_FirstSightJournalTailIsAttached(self):
        from unittest.mock import patch
        for tail in ('first diagnostic\npassword=private-value\nlast diagnostic', ''):
            calls = []
            r = self.collect('a.service loaded failed failed', tail, calls)
            state, fx = st(), Fx()
            L.host_health_findings({'dev':r}, state, CFG, T0)
            fs = L.host_health_findings({'dev':r}, state, CFG, T0+60)
            with patch.object(fx, 'ticket_new', return_value=('goodqa#1', 'ok')) as new:
                L.act(fs, state, CFG, fx, True, T0+60)
            body = new.call_args.args[1]
            self.assertIn('journal tail at first sight', body)
            self.assertIn('first diagnostic' if tail else 'no journal entries (rotated)', body)
            self.assertIn('last diagnostic' if tail else 'no journal entries (rotated)', body)
            self.assertNotIn('private-value', body)
            stored = state['host_health']['dev']['units']['a.service']['first_tail']
            self.assertLessEqual(len(stored.encode()), 4096)
            r['units'][0]['journal_tail'] = 'replacement'
            L.host_health_findings({'dev':r}, state, CFG, T0+120)
            self.assertEqual(state['host_health']['dev']['units']['a.service']['first_tail'], stored)
            journal = next(a for a,k in calls if a[0]=='journalctl')
            self.assertEqual(journal[journal.index('-n')+1], '40')
            self.assertTrue(all(0 < k['timeout'] <= 25 for a,k in calls))
        r = self.collect('a.service loaded failed failed', 'é'*6000+' token=private-value')
        self.assertLessEqual(len(r['units'][0]['journal_tail'].encode()), 4096)
        self.assertNotIn('private-value', str(r))

    def test_AutostopStaysServiceOnly(self):
        calls = []
        rc, _ = L.stop_health_timer('a.scope', 'a.timer', True, 25, run=self.runner(calls))
        self.assertNotEqual(rc, 0)
        self.assertEqual(calls, [])
        cfg = dict(CFG, unit_failed_samples=1, unit_autostop_mode='enforce',
                   host_health={'failed_units': {'autostop': {'a.scope':'a.timer'}}})
        fs = L.host_health_findings({'dev':self.collect('a.scope loaded failed failed')}, st(), cfg, T0)
        self.assertIn('unit-failing:dev:a.scope', classes(fs))
        self.assertEqual(fs[0]['remedies'], [])

    def test_BothScopesRetainTheirCountsAndJournalScope(self):
        calls = []
        fallback = self.runner(calls)
        def run(argv, **kw):
            if '--failed' in argv:
                calls.append((argv, kw))
                name = 'user.scope' if '--user' in argv else 'system.socket'
                return self.result(name+' loaded failed failed\n\n')
            return fallback(argv, **kw)
        r = L.collect_host_health({}, 25, run=run, clock=lambda: 0)
        self.assertNotIn('error', r)
        self.assertEqual(r['failed_lines_by_scope'], {'user':1, 'system':1})
        self.assertEqual(r['failed_lines'], 2)
        self.assertEqual([(u['unit'], u['user']) for u in r['units']], [('user.scope', True), ('system.socket', False)])
        for argv, kw in calls:
            if argv[0] == 'journalctl':
                self.assertEqual('--user' in argv, argv[argv.index('-u')+1] == 'user.scope')
        state = st()
        cfg = dict(CFG, unit_failed_samples=1)
        for host in ('dev', 'dev2'):
            fs = L.host_health_findings({host:r}, state, cfg, T0)
            self.assertEqual(set(classes(fs)), {'unit-failing:'+host+':user.scope', 'unit-failing:'+host+':system.socket'})

    def test_RecoveryStartsANewTailEpisode(self):
        state = st()
        def detect(r, tick):
            return L.host_health_findings({'dev':r}, state, CFG, T0+tick*60)
        r = self.collect('a.service loaded failed failed', 'original tail')
        detect(r, 0); detect(r, 1)
        clean = dict(units=[], dirs={}, disks={}, failed_lines=0)
        detect(clean, 2)
        r['units'][0]['journal_tail'] = 'transient replacement'
        detect(r, 3); detect(r, 4)
        self.assertEqual(state['host_health']['dev']['units']['a.service']['first_tail'], 'original tail')
        detect(clean, 5); detect(clean, 6)
        r['units'][0]['journal_tail'] = 'new episode tail'
        detect(r, 7)
        found = detect(r, 8)
        self.assertIn('new episode tail', '\n'.join(found[0]['lines']))
        self.assertEqual(state['host_health']['dev']['units']['a.service']['first_tail'], 'new episode tail')

    def test_UnknownThresholdIsConfigurable(self):
        state = st()
        cfg = dict(CFG, unit_census_unknown_samples=4)
        for tick in range(4):
            fs = L.host_health_findings({'dev2':{'error':'OSError: private-output'}}, state, cfg, T0+tick*60)
            self.assertEqual('host-health-unknown:dev2' in classes(fs), tick == 3)
            self.assertNotIn('private-output', str(fs))

    def test_HelpExplainsCensusAndJournalEvidence(self):
        import argparse
        import contextlib
        import io
        parser = argparse.ArgumentParser()
        L.register_fleet(parser.add_subparsers())
        output = io.StringIO()
        with contextlib.redirect_stdout(output), self.assertRaises(SystemExit) as exit:
            parser.parse_args(['liveness', '--help'])
        self.assertEqual(exit.exception.code, 0)
        for phrase in ('every failed unit type', 'unit_census_unknown_samples', 'journal tail', '4096'):
            self.assertIn(phrase, output.getvalue())

    def test_IgnoreRequiresReasonAtLoad(self):
        import contextlib
        import io
        for entry in ('ignored.*', {'glob':'ignored.*'}, {'glob':'ignored.*', 'reason':'  '}):
            cfg = dict(CFG, host_health={'failed_units':{'ignore':[entry]}})
            with tempfile.NamedTemporaryFile(mode='w', dir=_TMP) as f:
                json.dump(cfg, f); f.flush()
                stderr = io.StringIO()
                with contextlib.redirect_stderr(stderr), self.assertRaises(L.C.CliError):
                    L.load_config(f.name)
                self.assertIn('ignored', stderr.getvalue())
                self.assertIn('reason', stderr.getvalue())
        cfg['host_health']['failed_units']['ignore'] = [{'glob':'ignored.*', 'reason':'known fixture'}]
        with tempfile.NamedTemporaryFile(mode='w', dir=_TMP) as f:
            json.dump(cfg, f); f.flush()
            loaded = L.load_config(f.name)
        r = self.collect('ignored.scope loaded failed failed')
        self.assertEqual(L.host_health_findings({'dev':r}, st(), loaded, T0), [])


# Each mutant is applied alone to a disposable single-module source fixture. The test
# executes its named behavioral control, requires an assertion failure (not an import
# or runtime error), then runs the same control on the restored real module.
HOST_HEALTH_MUTANTS = [
    ('N=1', "int(cfg.get('unit_failed_samples', 2))", '1', HostHealth, 'UnitFailedForTwoSamplesAlerts'),
    ('gap ignored', "now-record['last'] < float(cfg.get('unit_failed_sample_gap_seconds', 60))", 'False', HostHealth, 'UnitFailedForTwoSamplesAlerts'),
    ('clean does not reset', "record['count'] = 0", "record['count'] += 0", HostHealth, 'UnitFailedForTwoSamplesAlerts'),
    ('stop in warn', "cfg.get('unit_autostop_mode', 'warn') == 'enforce'", 'True', HostHealth, 'AllowListedTimerIsStoppedOnceInEnforce'),
    ('stop twice', "record['stopped'] = True", "record['stopped'] = False", HostHealth, 'AllowListedTimerIsStoppedOnceInEnforce'),
    ('unmapped unit stopped', "failed_policy.get('autostop', {}).get(unit)", "'box-state-backup.timer'", HostHealth, 'AFailedUnitNotOnTheAllowListIsNeverStopped'),
    ('active accepted', "row.get('active') == 'failed'", "row.get('active') in ('active', 'activating', 'failed')", HostHealth, 'ARunningServiceIsNeverStopped'),
    ('name validation omitted', "health_unit(unit) and row.get('active')", "True and row.get('active')", HostHealth, 'OnlyTheMappedTimerIsStopped'),
    ('raw tar glob omitted', "for g in directory['leak_globs'])", "for g in directory['leak_globs'] if g != '*.tar')", HostHealth, 'GraceAndSizeBoundaries'),
    ('grace ignored', "now-e['mtime'] > directory['leak_grace_min']*60", 'True', HostHealth, 'ACleanBackupDirDoesNotFire'),
    ('grace inclusive', "now-e['mtime'] > directory['leak_grace_min']*60", "now-e['mtime'] >= directory['leak_grace_min']*60", HostHealth, 'GraceAndSizeBoundaries'),
    ('oversize cap inclusive', "e['size'] > directory['max_file_gb']*1024**3", "e['size'] >= directory['max_file_gb']*1024**3", HostHealth, 'GraceAndSizeBoundaries'),
    ('oversize disabled', "e['size'] > directory['max_file_gb']*1024**3", 'False', HostHealth, 'AnOversizedUnlistedFileFires'),
    ('directory budget disabled', "total > directory['max_dir_gb']*1024**3", 'False', HostHealth, 'AnOverBudgetDirFires'),
    ('always leak', 'if leaks or total >', 'if True or total >', HostHealth, 'ACleanBackupDirDoesNotFire'),
    ('window five minutes', "float(cfg.get('disk_fill_window_minutes', 60))*60", '5*60', HostHealth, 'ProjectedFillUnderTheWindowFires'),
    ('KB versus GB', "float(cfg.get('disk_fill_min_gb_per_h', 5))*1024**2", "float(cfg.get('disk_fill_min_gb_per_h', 5))", HostHealthEdges, 'LeastSquaresAndThresholdBoundaries'),
    ('slope units seconds', '(p[0]-now)/3600', '(p[0]-now)', HostHealth, 'ProjectedFillUnderTheWindowFires'),
    ('nine samples enough', 'if len(ring) < 10:', 'if len(ring) < 9:', HostHealth, 'ProjectedFillUnderTheWindowFires'),
    ('slope inclusive', "slope > float(cfg.get('disk_fill_min_gb_per_h', 5))", "slope >= float(cfg.get('disk_fill_min_gb_per_h', 5))", HostHealthEdges, 'LeastSquaresAndThresholdBoundaries'),
    ('eta inclusive', "eta < float(cfg.get('disk_fill_eta_hours', 48))", "eta <= float(cfg.get('disk_fill_eta_hours', 48))", HostHealthEdges, 'LeastSquaresAndThresholdBoundaries'),
    ('free pct inclusive', "free/total*100 < float(cfg.get('disk_fill_warn_free_pct', 15))", "free/total*100 <= float(cfg.get('disk_fill_warn_free_pct', 15))", HostHealthEdges, 'LeastSquaresAndThresholdBoundaries'),
    ('unbounded ring', 'ring[:] = ring[-ring_limit:]', 'ring[:] = ring[:]', HostHealthEdges, 'TenSamplesWindowAndRingBound'),
    ('unknown raises fresh failure', "out.extend(dict(f, remedies=[]) for f in state['findings'].values())", "out.append(dict(cls='unit-failing:dev:bad.service', title='bad', lines=[], remedies=[]))", HostHealth, 'AnUnreachableHostIsUnknownNotAFindingNorAClear'),
    ('recovery never clears', "int(cfg.get('unit_clean_samples', 2))", '999', HostHealth, 'RecoveryClearsTheFindingsAndCommentsOnce'),
    ('fresh active guard omitted', "r.returncode or r.stdout.strip() != 'failed'", 'r.returncode', HostHealthCollection, 'FreshActiveGuardAndExactTimerEffect'),
    ('stops service', "['systemctl', *scope, 'stop', timer]", "['systemctl', *scope, 'stop', service]", HostHealthCollection, 'FreshActiveGuardAndExactTimerEffect'),
    ('stop scope lost', "['systemctl', *scope, 'stop', timer]", "['systemctl', 'stop', timer]", HostHealthCollection, 'FreshActiveGuardAndExactTimerEffect'),
    ('failed transport considered healthy', "return dict(error='host health transport unknown')", "return dict(units=[], dirs={}, disks={})", HostHealthCollection, 'TransportUsesExistingHelperAndRejectsInvalidJSONShape'),
    ('collector cap removed', 'if len(entries) >= 500:', 'if False:', HostHealthCollection, 'CollectorTimeoutFailureAndOverflowAreUnknown'),
    ('scrubbing omitted', 'def health_scrub(text, limit=300):', 'def health_scrub(text, limit=300):\n    return str(text)[:300]', HostHealthCollection, 'CollectorIsBoundedNonRecursiveAndScrubbed'),
    ('config key dropped', 'return json.load(f)', "return {k:v for k,v in json.load(f).items() if k != 'unit_failed_samples'}", HostHealth, 'ConfigRoundTrips'),
    ('replay collects live', 'def replay(cfg, fx, since, until):', "def replay(cfg, fx, since, until):\n    fx.host_health('dev2')", HostHealthCollection, 'ReplayIgnoresTheLiveOnlyFindings'),
    ('allow globs ignored', "not any(fnmatch.fnmatchcase(e['name'], g) for g in directory['allow'])", 'True', HostHealthEdges, 'AllowedOversizedFileAndDirBudgetBoundaries'),
    ('host ignored', "directory['host'] != host", 'False', HostHealthEdges, 'WatchedDirectoryIsHostSpecific'),
    ('ignore globs dropped', "for entry in failed_policy.get('ignore', [])", 'for entry in []', HostHealthEdges, 'IgnoreAndConfigurablePersistence'),
]


HOST_HEALTH_MUTANTS.extend([
    ('ScopeUnitDoesNotBlindTheCensus', '(service|timer|scope|socket|mount|path|slice|target|device|swap|automount)',
     '(service|timer)', FailedUnitCensus, 'ScopeUnitDoesNotBlindTheCensus'),
    ('UnparsedLineIsAFindingNotAnOutage', "result['unparsed'].append(health_scrub(line))",
     "raise ValueError('invalid failed unit reading')", FailedUnitCensus, 'UnparsedLineIsAFindingNotAnOutage'),
    ('UnknownCensusIsRedAfterN', "state['unknown_count'] = state.get('unknown_count', 0) + 1",
     "state['unknown_count'] = 0", FailedUnitCensus, 'UnknownCensusIsRedAfterN'),
    ('CensusCountMismatchIsAFinding', "if accounted != reading.get('failed_lines', accounted):",
     'if False:', FailedUnitCensus, 'CensusCountMismatchIsAFinding'),
    ('FirstSightJournalTailIsAttached', "lines.append('journal tail at first sight:\\n' + record['first_tail'])",
     'pass', FailedUnitCensus, 'FirstSightJournalTailIsAttached'),
    ('AutostopStaysServiceOnly', "or not service.endswith('.service') or not health_unit(timer)",
     'or not health_unit(timer)', FailedUnitCensus, 'AutostopStaysServiceOnly'),
])


HOST_HEALTH_MUTANTS.extend([
    ('shared timer reverse lookup', "        if (self.cfg.get('unit_autostop_mode', 'warn') != 'enforce' or", "        service = next((s for s, t in mapping.items() if t == unit), None)\n        if (self.cfg.get('unit_autostop_mode', 'warn') != 'enforce' or", HostHealthCollection, 'SharedTimerChecksTheServiceThatProducedTheRemedy'),
    ('service timer pair unchecked', 'mapping.get(service) != unit', 'False', HostHealthCollection, 'StopRequiresTheExactServiceTimerPair'),
    ('one host leak ignored', "directory['host'] != host", "host == 'dev' or directory['host'] != host", HostHealth, 'ALeakedRawTarFiresOnBothHosts'),
    ('incident alerted too late', "int(cfg.get('unit_failed_samples', 2))", '3', HostHealth, 'IncidentReplay'),
    ('wrong mapped timer', "timer = failed_policy.get('autostop', {}).get(unit)", "timer = 'wrong.timer'", HostHealth, 'AllowListedTimerIsStoppedOnceInEnforce'),
    ('host cooldown collision', "r.get('host', '')", "''", HostHealthEdges, 'MultipleHostsCooldownDryRunAndStopFailure'),
    ('halt free threshold omitted', "float(cfg.get('disk_halt_free_pct', 8))", '0', HostHealthEdges, 'ProjectionReportsHaltThresholdAndLeastSquares'),
    ('endpoint slope', 'sum((x-mx)*(y-my) for x,y in zip(xs,ys))/denominator', '(ys[-1]-ys[0])/(xs[-1]-xs[0])', HostHealthEdges, 'ProjectionReportsHaltThresholdAndLeastSquares'),
    ('ring too short', 'ring_limit = 120', 'ring_limit = 119', HostHealthEdges, 'TenSamplesWindowAndRingBound'),
])


class HostHealthMutations(unittest.TestCase):
    def test_EveryNamedMutantIsKilledAndRestored(self):
        from pathlib import Path
        from unittest.mock import patch
        import types
        source=Path(L.__file__).read_text()
        for name,old,new,case,method in HOST_HEALTH_MUTANTS:
            with self.subTest(mutant=name):
                self.assertIn(old,source)
                with tempfile.TemporaryDirectory(dir=_TMP,prefix='host-health-mutant-') as root:
                    path=Path(root)/'goodqa_liveness.py'
                    path.write_text(source.replace(old,new,1))
                    module=types.ModuleType('_host_health_mutant')
                    module.__file__=str(path)
                    with patch.dict(sys.modules,{'_host_health_mutant':module}):
                        exec(compile(path.read_text(),str(path),'exec'),module.__dict__)
                        result=unittest.TestResult()
                        with patch.object(sys.modules[__name__],'L',module):
                            case('test_'+method).run(result)
                    self.assertEqual(result.errors,[], 'mutant must fail an assertion, not crash: '+name)
                    self.assertTrue(result.failures,'SURVIVOR: '+name)
                restored=unittest.TestResult()
                case('test_'+method).run(restored)
                self.assertTrue(restored.wasSuccessful(),repr(restored.failures+restored.errors))


class HostHealthIntegration(unittest.TestCase):
    def test_EachHostCollectedOnceEvenWhenFleetSnapshotIsUnavailable(self):
        from unittest.mock import patch
        class TimerFx(Fx):
            def host_health(self, host):
                self.calls.append(('health',host))
                return dict(units=[],dirs={'~/archive/state-backups':[
                    dict(name='x.tar',type='file',size=74*1024**3,mtime=T0-7200)]},disks={})
            def snapshot(self):
                raise OSError('snapshot unreachable')
            def hawk(self,body):
                self.calls.append(('journal',body))
        fx=TimerFx()
        with patch.object(L.C,'journal'), patch.object(L,'save_land_lag'):
            result=L.run_pass(dict(CFG,deploy_lag_mode='off'),fx,True,now=T0,state=st())
        self.assertEqual([c for c in fx.calls if c[0]=='health'],[('health','dev'),('health','dev2')])
        self.assertEqual({f['cls'] for f in result['findings']},{'output-leak:dev:~/archive/state-backups','output-leak:dev2:~/archive/state-backups'})
        self.assertIn('unreachable',result['collection_error'])

    def test_NormalPassRoutesHealthFindingsThroughActorAndJournals(self):
        from unittest.mock import patch
        class TimerFx(Fx):
            def host_health(self,host):
                self.calls.append(('health',host))
                return dict(units=[dict(unit='box-state-backup.service',active='failed',sub='failed',user=True)],dirs={},disks={})
            def snapshot(self):
                return dict(counts=dict(running=30,queued=0), services={})
            def lane_floor_floor(self): return 40
            def lane_floor_lines(self,*a): return []
            def refusals(self): return []
            def stop_timer(self,*args):
                self.calls.append(('stop',*args)); return 0,'stopped'
            def hawk(self,body): self.calls.append(('journal',body))
        fx=TimerFx(); state=st(); cfg=dict(CFG,deploy_lag_mode='off',unit_autostop_mode='enforce')
        with patch.object(L.C,'journal') as journal, patch.object(L,'save_land_lag'):
            for offset in (0,60,900):
                L.run_pass(cfg,fx,True,now=T0+offset,state=state)
        self.assertEqual(len([c for c in fx.calls if c[0]=='stop']),2)
        self.assertEqual(len([c for c in fx.calls if c[0]=='health']),6)
        self.assertEqual(len([c for c in fx.calls if c[0]=='ticket']),2)
        self.assertEqual(journal.call_count,3)
        self.assertTrue(any('rc=0' in c[1] for c in fx.calls if c[0]=='journal'))




class HostHealthExistingStateContract(unittest.TestCase):
    def test_ExistingRemedyCooldownKeysRemainEffective(self):
        state=st(); state['remedied']['start-unit|lane-floor.service']=T0
        fx=Fx()
        findings=[dict(cls='queue-idle',title='queued',lines=[],remedies=[dict(kind='start-unit',unit='lane-floor.service')])]
        report=L.act(findings,state,CFG,fx,True,T0+120)
        self.assertFalse(any(c[0]=='start' for c in fx.calls))
        self.assertEqual(report[0]['remedies'][0]['result'],'cooldown')


HOST_HEALTH_MUTANTS.append(('legacy cooldown key changed', "rk = '%s|%s'", "rk = '%s||%s'",
    HostHealthExistingStateContract, 'ExistingRemedyCooldownKeysRemainEffective'))


if __name__ == '__main__':
    unittest.main()


class CredentialSwitch(unittest.TestCase):
    """All effects are fakes; each producer emits multiple independently tracked rules."""
    def run_switch(self, mode='off', state=None, apply=False, broken_snapshot=False):
        from unittest.mock import patch
        from contextlib import ExitStack
        from types import SimpleNamespace
        self.collected = []
        self.comments = []
        def collect():
            self.collected.append(True)
            if mode == 'off':
                raise AssertionError('off mode collected credentials')
            return {'fixture': {'status': 'RED', 'findings': [
                {'key': 'git-credentials:fixture:operator', 'what': 'fixture failure'}]}}
        def snapshot():
            if broken_snapshot:
                raise OSError('fixture unavailable')
            return {'rows': {}}
        fx = SimpleNamespace(git_credentials=collect, snapshot=snapshot, lane_floor_floor=lambda: 40,
                             lane_floor_lines=lambda *a: [], refusals=lambda: [],
                             comment=lambda ref, body: self.comments.append((ref, body)), hawk=lambda *a: None,
                             ticket_status=lambda ref: None, ticket_patch=lambda ref, status: None)
        groups = (
            ('land_lag_findings', ['land-lag:run/a', 'land-lag:run/b', 'land-lag-unreadable']),
            ('evaluate', ['running-starved', 'queue-idle', 'floor-starved', 'merge-stall:goodqa',
                          'merge-stall:timbar', 'mass-stop', 'train-stalled:goodqa', 'deploy-lag:goodqa',
                          'deploy-lag-unreadable:timbar', 'rule-refusing:tests-lint', 'limbo']),
            ('autocommit_findings', ['autocommit-stalled', 'precommit-hook-crashed']),
            ('host_health_findings', ['failed-unit:dev:a', 'failed-unit:dev2:b',
                                      'output-leak:dev:x', 'disk-fill:dev2:y']))
        cfg = dict(CFG, clear_seconds=10)
        if mode is not None:
            cfg['git_credentials_mode'] = mode
        else:
            cfg.pop('git_credentials_mode', None)
        with ExitStack() as stack:
            for name, keys in groups:
                stack.enter_context(patch.object(L, name, return_value=[
                    dict(cls=k, title=k, lines=['fixture'], remedies=[]) for k in (keys if not apply else [])]))
            stack.enter_context(patch.object(L, 'live_sample', return_value=sample()))
            stack.enter_context(patch.object(L, 'deploy_lag', return_value={}))
            stack.enter_context(patch.object(L, 'save_land_lag'))
            stack.enter_context(patch.object(L.C, 'journal'))
            result = L.run_pass(cfg, fx, apply, now=T0, state=state if state is not None else st())
        return result

    def test_OffNeverCollects(self):
        for broken in (False, True):
            with self.subTest(broken_snapshot=broken):
                state = st()
                state['git_credentials'] = {'fixture': {'git-credentials:fixture:operator': {
                    'finding': dict(cls='git-credentials:fixture:operator', title='old', lines=['old'], remedies=[])}}}
                from unittest.mock import patch
                with patch.object(L, 'git_credentials_findings', side_effect=AssertionError('off computed findings')):
                    self.run_switch(state=state, broken_snapshot=broken)
                self.assertEqual(self.collected, [])

    def test_DefaultOnUnchanged(self):
        for mode in ('on', None):
            result = self.run_switch(mode)
            self.assertEqual(self.collected, [True])
            self.assertIn('git-credentials:fixture:operator', classes(result['findings']))

    def test_OffOnlyCredentialFindings(self):
        on = self.run_switch('on')['findings']
        off = self.run_switch('off')['findings']
        self.assertEqual(len(off), 20)
        self.assertEqual(off, [r for r in on if not r['cls'].startswith('git-credentials:')])

    def recovery(self):
        state = st()
        for host in ('dev', 'dev2'):
            key = 'git-credentials:%s:operator' % host
            state['alerts'][key] = dict(ref='goodqa#fixture-' + host, opened=T0-100,
                                        recovery_evidence='private retained evidence', last='private old body')
        state['git_credentials'] = {'dev': {'git-credentials:dev:operator': {'finding': {'lines': ['private']}}}}
        # Hysteresis is the normal recovery path: first absent tick, then elapsed grace.
        self.run_switch(state=state, apply=True)
        self.assertEqual(self.comments, [])
        for alert in state['alerts'].values():
            alert['absent_since'] = T0 - 11
        self.run_switch(state=state, apply=True)
        return state

    def test_OpenAlertCloses(self):
        state = self.recovery()
        self.assertEqual(len(self.comments), 2)
        self.assertTrue(all(a.get('cleared') == T0 for a in state['alerts'].values()))
        for ref, body in self.comments:
            self.assertIn('detector switched off (landed dark pending hardening)', body)
        self.run_switch(state=state, apply=True)
        self.assertEqual(self.comments, [])

    def test_NoEvidenceInCloseComment(self):
        self.recovery()
        self.assertEqual(len(self.comments), 2)
        for ref, body in self.comments:
            self.assertNotIn('evidence', body)
            self.assertNotIn('private', body)


class CredentialSwitchMutations(unittest.TestCase):
    def test_NamedControlsKillMutantsAndRestore(self):
        from pathlib import Path
        from unittest.mock import patch
        import types
        source = Path(L.__file__).read_text()
        mutants = [
            ('OffNeverCollects', "if cfg.get('git_credentials_mode', 'on') == 'on' and hasattr(fx, 'git_credentials'):",
             "if hasattr(fx, 'git_credentials'):", 'OffNeverCollects'),
            ('OffNeverCollects-error', "if cfg.get('git_credentials_mode', 'on') == 'on' else []", 'if True else []', 'OffNeverCollects'),
            ('OffOnlyCredentialFindings', '                    health_findings)', '                    [])', 'OffOnlyCredentialFindings'),
            ('OffOnlyCredentialFindings-all', '    report = act(findings, st, cfg, fx, apply, now, sample=sample, left=left, alert_budget=act_budget())',
             '    report = act([], st, cfg, fx, apply, now, sample=sample, left=left, alert_budget=act_budget())', 'OffOnlyCredentialFindings'),
            ('DefaultOnUnchanged', "if cfg.get('git_credentials_mode', 'on') == 'on' and hasattr(fx, 'git_credentials'):",
             "if cfg.get('git_credentials_mode', 'off') == 'on' and hasattr(fx, 'git_credentials'):", 'DefaultOnUnchanged'),
            ('OpenAlertCloses', '        if cls in live:',
             "        if cls in live or cls.startswith('git-credentials:'):", 'OpenAlertCloses'),
            ('NoEvidenceInCloseComment', "suffix = '; detector switched off (landed dark pending hardening)'",
             "suffix = '; detector switched off (landed dark pending hardening); evidence: ' + a.get('recovery_evidence', '')",
             'NoEvidenceInCloseComment'),
            ('OpenAlertCloses-prefix', "if cls.startswith('git-credentials:'):",
             "if cls == 'git-credentials:':", 'OpenAlertCloses'),
            ('OpenAlertCloses-mode', "if cfg.get('git_credentials_mode', 'on') == 'off':",
             "if cfg.get('git_credentials_mode', 'on') == 'on':", 'OpenAlertCloses'),
        ]
        for name, old, new, method in mutants:
            with self.subTest(mutant=name):
                self.assertEqual(source.count(old), 1)
                mutant = types.ModuleType('_credential_switch_mutant')
                mutant.__file__ = L.__file__
                exec(compile(source.replace(old, new, 1), L.__file__, 'exec'), mutant.__dict__)
                result = unittest.TestResult()
                with patch.object(sys.modules[__name__], 'L', mutant):
                    CredentialSwitch('test_' + method).run(result)
                self.assertEqual(result.errors, [], name + ': must fail assertions, not crash')
                self.assertTrue(result.failures, 'SURVIVOR: ' + name)
                restored = unittest.TestResult()
                CredentialSwitch('test_' + method).run(restored)
                self.assertTrue(restored.wasSuccessful(), repr(restored.failures + restored.errors))


class CredentialSwitchRealRules(unittest.TestCase):
    def test_MultiRuleSamplesPreserveEveryFinding(self):
        import copy
        from unittest.mock import patch
        from types import SimpleNamespace
        for running, queued, expected in ((0, 12, 'queue-idle'), (10, 0, 'running-starved'), (30, 0, 'floor-starved')):
            with self.subTest(running=running):
                s = sample(running=running, queued=queued,
                    merging={p: 12 for p in L.PRODUCTS},
                    last_merge={p: T0 - 10000 for p in L.PRODUCTS},
                    merge_trains={p: 2 for p in L.PRODUCTS},
                    grade_failed=[dict(ts=L.iso(T0-60), task='t%d' % n, product='goodqa',
                                       reason='STOP: merge train workspace: git clone failed') for n in range(6)],
                    lane_floor=lf(skips={'owned paths overlap active fixture': 30},
                                  refused={'tests-lint': {'b%d' % n for n in range(7)}}))
                seed = st()
                L.evaluate(dict(s, at=T0-1000), seed, CFG)
                results = []
                for mode in ('on', 'off'):
                    calls = []
                    def collect():
                        calls.append(True)
                        return {'fixture': dict(status='RED', findings=[dict(
                            key='git-credentials:fixture:operator', what='fixture')])}
                    fx = SimpleNamespace(snapshot=lambda: {}, lane_floor_floor=lambda: 40,
                        lane_floor_lines=lambda *a: [], refusals=lambda: [], git_credentials=collect)
                    with patch.object(L, 'live_sample', return_value=copy.deepcopy(s)), patch.object(L, 'deploy_lag', return_value={}):
                        result = L.run_pass(dict(CFG, git_credentials_mode=mode), fx, False,
                                            now=T0, state=copy.deepcopy(seed))
                    self.assertEqual(calls, [True] if mode == 'on' else [])
                    results.append(result['findings'])
                on, off = results
                self.assertEqual(off, [r for r in on if not r['cls'].startswith('git-credentials:')])
                keys = classes(off)
                self.assertIn(expected, keys)
                for p in L.PRODUCTS:
                    self.assertIn('merge-stall:' + p, keys)
                    self.assertIn('train-stalled:' + p, keys)
                self.assertIn('mass-stop', keys)
                self.assertIn('rule-refusing:tests-lint', keys)


class CredentialSwitchErrorCompatibility(unittest.TestCase):
    def test_OnAndMissingRetainBothHostsWhenSnapshotFails(self):
        import copy
        for mode in ('on', None):
            state = st()
            state['git_credentials'] = {}
            for host in ('dev', 'dev2'):
                key = 'git-credentials:%s:operator' % host
                state['git_credentials'][host] = {key: dict(ok_ticks=0, finding=dict(
                    cls=key, title='retained', lines=['fixture'], remedies=[]))}
            retained = copy.deepcopy(state['git_credentials'])
            case = CredentialSwitch()
            report = case.run_switch(mode, state=state, broken_snapshot=True)
            self.assertEqual(case.collected, [])
            self.assertEqual(state['git_credentials'], retained)
            self.assertEqual([r['cls'] for r in report['findings'] if r['cls'].startswith('git-credentials:')],
                             ['git-credentials:dev:operator', 'git-credentials:dev2:operator'])


class CredentialSwitchFailedCollectionRecovery(unittest.TestCase):
    def test_OpenAlertClosesOnFailureWithoutReconcilingUnknownRules(self):
        import copy
        from unittest.mock import patch
        for mode in ('off', 'on', None):
            for apply in (False, True):
                with self.subTest(mode=mode, apply=apply):
                    state = st()
                    credential_keys = ['git-credentials:dev:operator', 'git-credentials:dev2:ship']
                    other_keys = ['queue-idle', 'deploy-lag:goodqa', 'git-credentials-other:dev']
                    for index, key in enumerate(credential_keys + other_keys):
                        state['alerts'][key] = dict(ref='fixture#%d' % index, opened=T0 - 100,
                            last='private old body', recovery_evidence='private retained evidence')
                    retained = {'dev': {}, 'dev2': {}}
                    state['git_credentials'] = copy.deepcopy(retained)
                    case = CredentialSwitch()
                    def run():
                        with patch.object(L, 'git_credentials_findings', return_value=[]):
                            return case.run_switch(mode, state=state, apply=apply, broken_snapshot=True)
                    first = run()
                    self.assertEqual(first['collection_error'], 'fixture unavailable')
                    self.assertEqual(case.collected, [])
                    self.assertEqual(case.comments, [])
                    expected = credential_keys if mode == 'off' else []
                    self.assertEqual([k for k, a in state['alerts'].items() if 'absent_since' in a], expected)
                    # A stale absence timestamp must not clear an unobserved unrelated rule.
                    for alert in state['alerts'].values():
                        alert['absent_since'] = T0 - 11
                    before = copy.deepcopy(state['alerts'])
                    result = run()
                    self.assertEqual(result['collection_error'], 'fixture unavailable')
                    self.assertEqual([r['cls'] for r in result['findings'] if r['title'] == 'recovered'], expected)
                    self.assertEqual(state['git_credentials'], retained)
                    self.assertEqual(case.collected, [])
                    self.assertEqual([ref for ref, _ in case.comments],
                                     ['fixture#0', 'fixture#1'] if mode == 'off' and apply else [])
                    for _, body in case.comments:
                        self.assertIn('detector switched off (landed dark pending hardening)', body)
                        self.assertNotIn('evidence', body)
                        self.assertNotIn('private', body)
                    for key in other_keys:
                        self.assertEqual(state['alerts'][key], before[key])
                    for key in credential_keys:
                        self.assertEqual(bool(state['alerts'][key].get('cleared')), mode == 'off' and apply)
                    run()
                    self.assertEqual(case.comments, [])


class CredentialSwitchFailedCollectionMutations(unittest.TestCase):
    def test_ErrorRecoveryControlsKillMutantsAndRestore(self):
        from pathlib import Path
        from unittest.mock import patch
        import types
        source = Path(L.__file__).read_text()
        guard = """        if not reconcile and not (cls.startswith('git-credentials:') and
                                  cfg.get('git_credentials_mode', 'on') == 'off'):
            continue
"""
        mutants = [
            ('OpenAlertCloses-error-original', guard, '        if not reconcile:\n            continue\n'),
            ('OffOnlyCredentialFindings-error-unguarded', guard, ''),
            ('OffOnlyCredentialFindings-error-any', guard, guard.replace("credentials:') and", "credentials:') or")),
            ('OpenAlertCloses-error-prefix', guard, guard.replace("cls.startswith('git-credentials:')", "cls == 'git-credentials:'")),
            ('DefaultOnUnchanged-error', guard, guard.replace("mode', 'on'", "mode', 'off'")),
            ('OpenAlertCloses-error-mode', guard, guard.replace("== 'off'", "== 'on'")),
        ]
        for name, old, new in mutants:
            with self.subTest(mutant=name):
                self.assertEqual(source.count(old), 1)
                mutant = types.ModuleType('_credential_failed_collection_mutant')
                mutant.__file__ = L.__file__
                exec(compile(source.replace(old, new, 1), L.__file__, 'exec'), mutant.__dict__)
                method = 'test_OpenAlertClosesOnFailureWithoutReconcilingUnknownRules'
                result = unittest.TestResult()
                with patch.object(sys.modules[__name__], 'L', mutant):
                    CredentialSwitchFailedCollectionRecovery(method).run(result)
                self.assertEqual(result.errors, [], name + ': must fail assertions, not crash')
                self.assertTrue(result.failures, 'SURVIVOR: ' + name)
                restored = unittest.TestResult()
                CredentialSwitchFailedCollectionRecovery(method).run(restored)
                self.assertTrue(restored.wasSuccessful(), repr(restored.failures + restored.errors))


class LiveAlertReopen(unittest.TestCase):
    def setup_case(self, status='duplicate'):
        from unittest.mock import Mock
        fx = Fx()
        fx.ticket_status = Mock(return_value=status)
        fx.ticket_patch = Mock(side_effect=lambda ref, status: fx.calls.append(('patch', ref, status)))
        fx.moved_copy = Mock(return_value=None)
        fx.undo_copy = Mock()
        state = st()
        state['alerts']['test'] = dict(ref='goodqa#11932', opened=T0-4000, commented=T0-4000)
        finding = dict(cls='test', title='still failing', lines=['failure'], remedies=[])
        return fx, state, finding

    def test_ClosedTrackedAlertIsReopenedWhileFindingLive(self):
        """ClosedTrackedAlertIsReopenedWhileFindingLive"""
        fx, state, f = self.setup_case()
        out = L.act([f], state, CFG, fx, True, T0)
        self.assertEqual([x[0] for x in fx.calls], ['patch', 'comment'])          # gq-clutter S1: the reopen comment only
        self.assertEqual(fx.calls[0], ('patch', 'goodqa#11932', 'triage'))
        self.assertEqual(out[0]['alert'], 'reopened goodqa#11932')
        self.assertEqual(state['alerts']['test']['reopened'], T0)
        L.act([f], state, CFG, fx, True, T0+120)
        self.assertEqual(fx.ticket_patch.call_count, 1)
        dry = L.act([f], state, CFG, fx, False, T0+3601)
        self.assertEqual(dry[0]['alert'], 'would reopen goodqa#11932')

    # --- duplicate close follows the canonical ticket instead of reopening the alert (goodqa#14977 fleet liveness regrowth)
    def dup_case(self, status='duplicate', survivor='goodqa#15558'):
        from unittest.mock import Mock
        fx, state, finding = self.setup_case(status)
        fx.duplicate_survivor = Mock(return_value=survivor)
        return fx, state, finding

    def notes(self, fx, survivor='goodqa#15558'):
        return [c for c in fx.calls if c[0] == 'comment' and c[1] == survivor]

    def test_DuplicateOfOpenTicketNeverReopensAndNotesOnceThenStaysQuietWhileUnchanged(self):
        fx, state, f = self.dup_case()
        out = L.act([f], state, CFG, fx, True, T0)
        self.assertEqual(fx.ticket_patch.call_count, 0, 'a duplicate-closed alert must not be reopened')
        self.assertEqual(len(self.notes(fx)), 1)
        self.assertEqual(out[0]['alert'], 'followed duplicate goodqa#11932 of goodqa#15558')
        for dt in (120, 1800, 3601, 7300, 20000):
            L.act([f], state, CFG, fx, True, T0 + dt)
        self.assertEqual(len(self.notes(fx)), 1, 'unchanged member set: no further note')
        self.assertEqual(fx.ticket_patch.call_count, 0)
        self.assertFalse([c for c in fx.calls if c[0] == 'comment' and c[1] == 'goodqa#11932'], 'nothing posted on the closed alert')

    def many_case(self, n, survivor='goodqa#15558'):
        from unittest.mock import Mock
        fx = Fx()
        fx.ticket_status = Mock(return_value='duplicate')
        fx.ticket_patch = Mock(side_effect=lambda ref, status: fx.calls.append(('patch', ref, status)))
        fx.moved_copy = Mock(return_value=None)
        fx.undo_copy = Mock()
        fx.duplicate_survivor = Mock(return_value=survivor)
        state = st()
        fs = []
        for i in range(n):
            cls = 'unit-failing:dev:u%d.service' % i
            state['alerts'][cls] = dict(ref='goodqa#%d' % (12000 + i), opened=T0 - 90000, commented=T0 - 4000)
            fs.append(dict(cls=cls, title='u%d.service failed on dev' % i, lines=['failure'], remedies=[]))
        return fx, state, fs

    def test_F5_ManyAlertsInOneHourProduceExactlyOneAggregateNote(self):
        fx, state, fs = self.many_case(30)
        L.act(fs, state, CFG, fx, True, T0)
        notes = [c for c in fx.calls if c[0] == 'comment']
        self.assertEqual(len(notes), 1, 'one aggregate note per canonical ticket, not one per alert')
        self.assertEqual(notes[0][1], 'goodqa#15558')
        full = L.dup_note_body('goodqa#15558', sorted(state['dup_members']['goodqa#15558'].items(), key=lambda kv: kv[1]['since']), T0)
        for i in range(30):
            self.assertIn('goodqa#%d' % (12000 + i), full)
            self.assertIn('u%d.service' % i, full)
        self.assertIn('since', full)
        for dt in (120, 600, 3000):
            L.act(fs, state, CFG, fx, True, T0 + dt)
        self.assertEqual(len([c for c in fx.calls if c[0] == 'comment']), 1)
        self.assertEqual(fx.ticket_patch.call_count, 0)

    def test_F5_ChangedMembershipNotesAtMostOncePerHour(self):
        fx, state, fs = self.many_case(3)
        L.act(fs[:2], state, CFG, fx, True, T0)
        self.assertEqual(len(self.notes(fx)), 1)
        state['alerts'][fs[2]['cls']]['status_synced'] = 0
        L.act(fs, state, CFG, fx, True, T0 + 600)            # a third alert joins inside the hour: held back
        self.assertEqual(len(self.notes(fx)), 1)
        L.act(fs, state, CFG, fx, True, T0 + 3601)           # the hour passed and the set changed: one more note
        self.assertEqual(len(self.notes(fx)), 2)
        L.act(fs, state, CFG, fx, True, T0 + 7300)
        self.assertEqual(len(self.notes(fx)), 2, 'unchanged again: quiet')

    def test_F5_AllMembersClearedPostsOneClosingNote(self):
        fx, state, fs = self.many_case(2)
        L.act(fs, state, CFG, fx, True, T0)
        self.assertEqual(len(self.notes(fx)), 1)
        L.act([], state, CFG, fx, True, T0 + 9000 + 3601)    # nothing observed for 2.5 h+: members aged out
        self.assertEqual(len(self.notes(fx)), 2)
        L.act([], state, CFG, fx, True, T0 + 30000)
        self.assertEqual(len(self.notes(fx)), 2, 'the closing note is posted once')

    def test_R1_FailedClosingNoteIsRetried(self):
        fx, state, fs = self.many_case(1)
        L.act(fs, state, CFG, fx, True, T0)
        ok_comment = fx.comment
        fx.comment = lambda ref, body: (1, 'boom')
        L.act([], state, CFG, fx, True, T0 + 13000)                      # aged out: the closing note fails
        self.assertIn('goodqa#15558', state['dup_members'], 'a failed closing note must stay queued')
        fx.comment = ok_comment
        L.act([], state, CFG, fx, True, T0 + 13200)
        closing = [c for c in fx.calls if c[0] == 'comment' and c[1] == 'goodqa#15558']
        self.assertEqual(len(closing), 2)
        self.assertNotIn('goodqa#15558', state['dup_members'])

    def test_R2_AlertReopenedByAPersonLeavesTheMemberListNotAFalseClear(self):
        from unittest.mock import Mock
        fx, state, fs = self.many_case(2)
        L.act(fs, state, CFG, fx, True, T0)
        self.assertEqual(len(state['dup_members']['goodqa#15558']), 2)
        fx.ticket_status = Mock(side_effect=lambda ref: 'triage' if ref == 'goodqa#12000' else 'duplicate')
        state['alerts'][fs[0]['cls']]['status_synced'] = 0               # due again
        L.act(fs, state, CFG, fx, True, T0 + 3700)
        self.assertEqual(list(state['dup_members']['goodqa#15558']), [fs[1]['cls']], 'the reopened alert is no longer counted as followed')

    def test_R2_ReLinkedAlertMovesToTheNewCanonicalTicket(self):
        fx, state, fs = self.many_case(1)
        L.act(fs, state, CFG, fx, True, T0)
        fx.duplicate_survivor.return_value = 'goodqa#15600'
        state['alerts'][fs[0]['cls']]['status_synced'] = 0
        L.act(fs, state, CFG, fx, True, T0 + 3700)
        self.assertNotIn(fs[0]['cls'], state['dup_members'].get('goodqa#15558', {}))
        self.assertIn(fs[0]['cls'], state['dup_members']['goodqa#15600'])

    def test_R2_NoOpenCanonicalTicketUnregistersAndReopens(self):
        fx, state, fs = self.many_case(1)
        L.act(fs, state, CFG, fx, True, T0)
        fx.duplicate_survivor.return_value = None                         # the canonical ticket was closed
        state['alerts'][fs[0]['cls']]['status_synced'] = 0
        L.act(fs, state, CFG, fx, True, T0 + 3700)
        self.assertNotIn(fs[0]['cls'], state['dup_members'].get('goodqa#15558', {}))
        self.assertIn(('patch', 'goodqa#12000', 'triage'), fx.calls)

    def test_R3_FreshnessWindowIsAParameterSoALongSyncIntervalDoesNotFlap(self):
        fx, state, fs = self.many_case(1)
        L.act(fs, state, CFG, fx, True, T0)
        n = len(self.notes(fx))
        L.flush_dup_notes(state, fx, T0 + 20000, lambda: True, fresh=40000)
        self.assertEqual(len(self.notes(fx)), n, 'still a member inside a longer window: no false closing note')

    def test_R4_QuietCanonicalStateIsForgotten(self):
        fx, state, fs = self.many_case(1)
        L.act(fs, state, CFG, fx, True, T0)
        L.act([], state, CFG, fx, True, T0 + 13000)                       # closing note posted, members gone
        L.flush_dup_notes(state, fx, T0 + 13000 + 8 * 86400, lambda: True)
        self.assertNotIn('goodqa#15558', state['dup_agg'])

    def test_DuplicateNoteBodyIsCappedAndDefanged(self):
        rows = [('c%d`@x' % i, dict(ref='goodqa#%d' % i, title='t\n`@bob`' + 'z' * 300, since=T0, seen=T0)) for i in range(150)]
        body = L.dup_note_body('goodqa#1', rows, T0)
        self.assertNotIn('@bob', body)
        self.assertIn('and 50 more', body)
        self.assertLess(len(body), 30000)

    def test_DuplicateDryRunWritesNothing(self):
        fx, state, f = self.dup_case()
        out = L.act([f], state, CFG, fx, False, T0)
        self.assertEqual(out[0]['alert'], 'would follow duplicate goodqa#11932 of goodqa#15558')
        self.assertEqual([c for c in fx.calls if c[0] in ('comment', 'patch')], [])
        self.assertNotIn('dup_members', state)

    def test_DuplicateOfClosedOrUnlinkedTicketFallsBackToReopen(self):
        fx, state, f = self.dup_case(survivor=None)          # canonical closed, unreadable or no `duplicates` link
        out = L.act([f], state, CFG, fx, True, T0)
        self.assertEqual(fx.calls[0], ('patch', 'goodqa#11932', 'triage'))
        self.assertEqual(out[0]['alert'], 'reopened goodqa#11932')
        self.assertEqual(self.notes(fx), [])

    def test_DoneOrWontFixCloseIsStillReopenedWithoutLookingForACanonical(self):
        for status in ('done', 'wont_fix', 'cancelled'):
            fx, state, f = self.dup_case(status)
            L.act([f], state, CFG, fx, True, T0)
            self.assertEqual(fx.calls[0], ('patch', 'goodqa#11932', 'triage'), status)
            self.assertEqual(fx.duplicate_survivor.call_count, 0, status)
            self.assertEqual(self.notes(fx), [], status)

    def test_ClearedFindingNeitherReopensNorNotes(self):
        fx, state, f = self.dup_case()
        L.act([], state, CFG, fx, True, T0)                   # the detector no longer reports the finding
        self.assertNotIn(('patch', 'goodqa#11932', 'triage'), fx.calls)
        self.assertEqual(self.notes(fx), [])
        self.assertEqual(fx.duplicate_survivor.call_count, 0)

    def test_F1_FollowedDuplicateIsLookedUpOncePerSyncWindowNotEveryPass(self):
        fx, state, f = self.dup_case()
        for dt in (0, 120, 240, 3599):
            L.act([f], state, CFG, fx, True, T0 + dt)
        self.assertEqual(fx.duplicate_survivor.call_count, 1, 'the lookup costs ~6 calls: once per alert_status_minutes')
        self.assertEqual(fx.ticket_patch.call_count, 0)
        L.act([f], state, CFG, fx, True, T0 + 3601)
        self.assertEqual(fx.duplicate_survivor.call_count, 2)
        self.assertEqual(len(self.notes(fx)), 1, 'unchanged member set: still one aggregate note')

    def test_N1_RisenSeverityDoesNotDefeatTheLookupGate(self):
        fx, state, f = self.dup_case()
        state['alerts']['test']['severity'] = 'low'          # finding severity is higher: `escalate` would stay true
        for dt in (0, 120, 240, 360):
            L.act([f], state, CFG, fx, True, T0 + dt)
        self.assertEqual(fx.duplicate_survivor.call_count, 1)
        self.assertEqual(fx.ticket_patch.call_count, 0)

    def test_F2_RecurrenceAfterClearNotesCanonicalInsteadOfReopeningTheDuplicate(self):
        fx, state, f = self.dup_case()
        state['alerts']['test'].update(cleared=T0 - 100)
        out = L.act([f], state, CFG, fx, True, T0)
        self.assertEqual(fx.ticket_patch.call_count, 0, 'a recurring finding must not reopen a duplicate-closed alert')
        self.assertEqual(len(self.notes(fx)), 1)
        self.assertIsNone(state['alerts']['test']['cleared'], 'the alert is tracked again')
        self.assertIn('followed duplicate goodqa#11932 of goodqa#15558', out[0]['alert'])

    def test_F2_RecurrenceWithoutACanonicalTicketStillReopens(self):
        fx, state, f = self.dup_case(survivor=None)
        state['alerts']['test'].update(cleared=T0 - 100)
        L.act([f], state, CFG, fx, True, T0)
        self.assertEqual(fx.calls[0], ('patch', 'goodqa#11932', 'triage'))

    def test_F3_FailedLookupDefersAndNeverReopens(self):
        fx, state, f = self.dup_case()
        fx.duplicate_survivor.side_effect = RuntimeError('503')
        out = L.act([f], state, CFG, fx, True, T0)
        self.assertEqual(fx.ticket_patch.call_count, 0)
        self.assertEqual(self.notes(fx), [])
        self.assertIn('lookup failed', out[0]['alert'])
        L.act([f], state, CFG, fx, True, T0 + 120)
        self.assertEqual(fx.duplicate_survivor.call_count, 1, 'retry is deferred ~10 min, not every pass')
        fx.duplicate_survivor.side_effect = None
        fx.duplicate_survivor.return_value = 'goodqa#15558'
        L.act([f], state, CFG, fx, True, T0 + 700)
        self.assertEqual(len(self.notes(fx)), 1)
        # a recurrence on a failed lookup defers as well
        fx2, state2, f2 = self.dup_case()
        state2['alerts']['test'].update(cleared=T0 - 100)
        fx2.duplicate_survivor.side_effect = RuntimeError('503')
        L.act([f2], state2, CFG, fx2, True, T0)
        self.assertEqual(fx2.ticket_patch.call_count, 0)

    def test_F6_FailedNoteCommentIsRetriedNextPass(self):
        fx, state, f = self.dup_case()
        fx.comment = lambda ref, body: (1, 'boom')
        L.act([f], state, CFG, fx, True, T0)
        self.assertFalse(state['dup_agg']['goodqa#15558'].get('digest'), 'a failed note is not latched')
        fx.comment = lambda ref, body: (fx.calls.append(('comment', ref, body[:40])), (0, ''))[1]
        L.act([f], state, CFG, fx, True, T0 + 120)
        self.assertEqual(len(self.notes(fx)), 1)

    def _api_fx(self, links, issues, projects=None):
        """The REAL Effects.duplicate_survivor against a fake API: links[id] -> duplicates endpoints; issues[id] -> issue."""
        class Api:
            def get(self_, path):
                if path.startswith('/issues/') and path.endswith('/links'):
                    iid = path.split('/')[2]
                    if links.get(iid) is RuntimeError:
                        raise RuntimeError('503')
                    return {'duplicates': [{'issue': {'id': t}} for t in links.get(iid, [])]}
                if path.startswith('/projects/'):
                    return {'project': {'slug': 'goodqa'}}
                raise AssertionError(path)

        class W:
            api = Api()

            def issue(self_, iid):
                return issues[iid]

        eff = L.Effects.__new__(L.Effects)
        eff.ticket_writer = lambda ref: (W(), {'id': 'A'})
        return eff

    def test_F4_RealSurvivorLookupParsesLinksFollowsChainsAndBreaksCycles(self):
        iss = lambda n, status, **k: dict(id=n, number=1, status=status, projectId='p', **k)
        eff = self._api_fx({'A': ['B']}, {'B': iss('B', 'triage')})
        self.assertEqual(eff.duplicate_survivor('goodqa#1'), 'goodqa#1')
        # chain: A -> B (duplicate) -> C (open)
        eff = self._api_fx({'A': ['B'], 'B': ['C']}, {'B': iss('B', 'duplicate'), 'C': iss('C', 'in_progress')})
        self.assertEqual(eff.duplicate_survivor('goodqa#1'), 'goodqa#1')
        # canonical closed done / archived -> None (reopen fallback)
        eff = self._api_fx({'A': ['B']}, {'B': iss('B', 'done')})
        self.assertIsNone(eff.duplicate_survivor('goodqa#1'))
        eff = self._api_fx({'A': ['B']}, {'B': iss('B', 'triage', archivedAt='2026-11-09')})
        self.assertIsNone(eff.duplicate_survivor('goodqa#1'))
        # cycle A -> B -> A, nothing open
        eff = self._api_fx({'A': ['B'], 'B': ['A']}, {'B': iss('B', 'duplicate'), 'A': iss('A', 'duplicate')})
        self.assertIsNone(eff.duplicate_survivor('goodqa#1'))
        # no link at all
        self.assertIsNone(self._api_fx({}, {}).duplicate_survivor('goodqa#1'))
        # a read failure RAISES (the caller defers)
        with self.assertRaises(RuntimeError):
            self._api_fx({'A': RuntimeError}, {}).duplicate_survivor('goodqa#1')

    def test_RepairCommandSkipsDuplicatesWithAnOpenCanonicalTicket(self):
        from unittest.mock import Mock
        for survivor, expect in (('goodqa#15558', []), (None, ['goodqa#11932'])):
            fx = Fx()
            fx.ticket_status = Mock(return_value='duplicate')
            fx.moved_copy = Mock(return_value=None)
            fx.undo_copy = Mock()
            fx.duplicate_survivor = Mock(return_value=survivor)
            fx.ticket_patch = Mock()
            state = st()
            state['alerts']['test'] = dict(ref='goodqa#11932', opened=T0 - 4000, commented=T0 - 4000)
            f = dict(cls='test', title='still failing', lines=['failure'], remedies=[])
            from unittest.mock import patch
            with patch.object(L, 'run_pass', return_value=dict(findings=[f])):
                rep = L.reopen_closed(CFG, fx, False, 25, state=state, now=T0)
            self.assertEqual([r['ref'] for r in rep['alerts']], expect, survivor)

    def test_TrackedAlertStatusReadOnlyWhenCommentDue(self):
        """TrackedAlertStatusReadOnlyWhenCommentDue"""
        import copy
        # gq-clutter S1: the ticket is touched (status read + status block) only when its status sync is due
        # (alert_status_minutes), never on every pass; the rolling counters are local state, not ticket I/O.
        every = float(CFG.get('alert_status_minutes', 60)) * 60
        rolling = ('occurrences', 'first_seen', 'last_seen', 'last_value', 'last_minutes', 'members', 'severity', 'comment_digest')
        for apply in (False, True):
            for status in ('triage', 'duplicate', None):
                with self.subTest(apply=apply, status=status):
                    fx, state, f = self.setup_case(status)
                    state['alerts']['test']['commented'] = T0
                    before = copy.deepcopy(state['alerts']['test'])
                    for elapsed in (0, 120, every - 1):
                        out = L.act([f], state, CFG, fx, apply, T0 + elapsed)
                        self.assertEqual(out[0]['alert'], 'open goodqa#11932')
                    fx.ticket_status.assert_not_called()
                    self.assertEqual(fx.calls, [])
                    self.assertEqual({k: v for k, v in state['alerts']['test'].items() if k not in rolling}, before)
                    out = L.act([f], state, CFG, fx, apply, T0 + every)
                    fx.ticket_status.assert_called_once_with('goodqa#11932')
                    if status is None:
                        self.assertIn('status unreadable', ' '.join(out[0]['lines']))
                        self.assertEqual(fx.calls, [])
                    elif status == 'duplicate':
                        if apply:
                            self.assertEqual([x[0] for x in fx.calls], ['patch', 'comment'])
                            self.assertEqual(out[0]['alert'], 'reopened goodqa#11932')
                        else:
                            self.assertEqual(out[0]['alert'], 'would reopen goodqa#11932')
                            self.assertEqual(fx.calls, [])
                    else:
                        self.assertEqual(fx.calls, [])                             # nothing material: no comment
                        self.assertEqual(out[0]['alert'], 'open goodqa#11932')

    def test_UnreadableStatusDoesNotRefile(self):
        """UnreadableStatusDoesNotRefile"""
        fx, state, f = self.setup_case(None)
        out = L.act([f], state, CFG, fx, True, T0)
        self.assertEqual(fx.calls, [])
        self.assertEqual(len(out), 1)
        self.assertIn('status unreadable', ' '.join(out[0]['lines']))

    def repair(self, fx, state, findings, apply=False, limit=25):
        from unittest.mock import patch
        with patch.object(L, 'run_pass', return_value=dict(findings=findings)) as run:
            out = L.reopen_closed(CFG, fx, apply, limit, state=state, now=T0)
            self.assertFalse(run.call_args.args[2])
            return out

    def test_ClearedAlertStaysClosed(self):
        """ClearedAlertStaysClosed"""
        fx, state, f = self.setup_case()
        state['alerts']['test']['cleared'] = T0-100
        self.assertEqual(self.repair(fx, state, [])['alerts'], [])
        self.assertEqual(self.repair(fx, state, [f], True)['alerts'], [])
        self.assertEqual(fx.calls, [])
        fx.ticket_status.assert_not_called()

    def test_ReopenClosedIsDryRunByDefault(self):
        """ReopenClosedIsDryRunByDefault"""
        import argparse
        from unittest.mock import patch
        fx, state, f = self.setup_case()
        fx.moved_copy.return_value = 'work-tracker-automatic#35159'
        out = self.repair(fx, state, [f])
        self.assertEqual(out['alerts'], [dict(ref='goodqa#11932', cls='test', status='duplicate',
                                             copy='work-tracker-automatic#35159')])
        self.assertEqual(fx.calls, [])
        fx.undo_copy.assert_not_called()
        print('FAKE DRY RUN: ' + json.dumps(out, sort_keys=True))
        parser = argparse.ArgumentParser()
        L.register_fleet(parser.add_subparsers())
        with patch.object(L, 'load_config', return_value=CFG), patch.object(L, 'Effects', return_value=fx), \
             patch.object(L.C, '_verify_ticket', return_value={}) as verify:
            for flags in (['--apply'], ['--apply', '--ticket', 'goodqa#12903'],
                          ['--apply', '--reason', 'repair active alerts']):
                with self.assertRaises(L.C.CliError):
                    L.cmd_liveness(parser.parse_args(['liveness', 'reopen-closed'] + flags))
            verify.assert_not_called()
        self.repair(fx, state, [f], True)
        fx.ticket_patch.assert_called_once_with('goodqa#11932', 'triage')
        fx.undo_copy.assert_called_once_with('goodqa#11932', 'work-tracker-automatic#35159')
        fx.ticket_status.return_value = 'triage'
        self.assertEqual(self.repair(fx, state, [f])['alerts'], [])


class LiveAlertEffectsContracts(unittest.TestCase):
    def test_ticket_status_command_and_unreadable_results(self):
        from unittest.mock import patch
        fx = L.Effects(CFG)
        with patch.object(L.C, 'run', return_value=(0, '{"status":"duplicate"}', '')) as call:
            self.assertEqual(fx.ticket_status('goodqa#11932'), 'duplicate')
            self.assertEqual(call.call_args.args[0][1:],
                             ['ticket', 'show', 'goodqa#11932', '--json', '--wait', '0'])
        for result in ((3, '', 'unavailable'), (0, 'bad json', ''), (0, '{}', ''), (0, '[]', '')):
            with patch.object(L.C, 'run', return_value=result):
                self.assertIsNone(fx.ticket_status('goodqa#11932'))

    def test_copy_link_shape_and_quiet_status_patch_contract(self):
        from unittest.mock import Mock
        fx = L.Effects(CFG)
        fx._tickets = Mock()
        fx._tickets._owner_ids = ['eric']
        original = dict(id='orig', updatedAt='v1', reporterId='eric')
        copy = dict(id='copy', number=35159, projectId='automatic', status='triage',
                    labels=['moved-from-goodqa'])
        fx._tickets.resolve.side_effect = lambda ref: dict(original) if ref == 'goodqa#11932' else dict(copy)
        fx._tickets.issue.return_value = copy
        fx._tickets.api.get.side_effect = lambda path: ({'duplicates': [{'issue': {'id': 'copy'}}]}
            if path.endswith('/links') else {'project': {'slug': 'work-tracker-automatic'}})
        self.assertEqual(fx.moved_copy('goodqa#11932'), 'work-tracker-automatic#35159')
        fx.ticket_patch('goodqa#11932', 'triage')
        fx._tickets.quiet.assert_called_with('orig')
        self.assertEqual(fx._tickets.patch.call_args.args[:2], ('orig', {'status': 'triage'}))
        fx.undo_copy('goodqa#11932', 'work-tracker-automatic#35159')
        self.assertEqual(fx._tickets.link_duplicate.call_args.args[:2], ('copy', 'orig'))
        self.assertEqual(fx._tickets.patch.call_args.args[:2], ('copy', {'status': 'duplicate'}))
        self.assertIn('goodqa#11932', fx._tickets.comment.call_args.args[1])
        for changes in ({'status': 'done'}, {'labels': []}):
            fx._tickets.issue.return_value = dict(copy, **changes)
            self.assertIsNone(fx.moved_copy('goodqa#11932'))

    def test_repair_limit_live_filter_collection_failure_and_state_persistence(self):
        from unittest.mock import patch
        case = LiveAlertReopen()
        fx, state, f = case.setup_case()
        state['alerts']['other'] = dict(ref='goodqa#11933')
        fs = [f, dict(f, cls='other')]
        out = case.repair(fx, state, fs, True, limit=1)
        self.assertEqual(out['reopened'], ['goodqa#11932'])
        self.assertEqual(len(out['alerts']), 2)
        fx.ticket_patch.reset_mock()
        with patch.object(L, 'run_pass', return_value=dict(findings=[], collection_error='snapshot unavailable')):
            with self.assertRaises(L.C.CliError):
                L.reopen_closed(CFG, fx, True, state=state)
        fx.ticket_patch.assert_not_called()
        with patch.object(L, 'run_pass', return_value=dict(findings=[f])), \
             patch.object(L, 'load_state', return_value=state), patch.object(L, 'save_state') as save:
            L.reopen_closed(CFG, fx, True, now=T0)
            save.assert_called_once_with(state)


class LiveAlertReopenMutations(unittest.TestCase):
    def test_named_mutants_are_red_then_restored(self):
        import inspect
        from unittest.mock import patch
        mutants = [
            ('TrackedAlertStatusReadOnlyWhenCommentDue', 'act',
             "if due and a and a.get('ref') and not a.get('cleared'):",
             "if a and a.get('ref') and not a.get('cleared'):"),
            ('ClosedTrackedAlertIsReopenedWhileFindingLive', 'act', "status = fx.ticket_status(a['ref'])", "status = 'triage'"),
            ('ClearedAlertStaysClosed', 'reopen_closed', "if a.get('cleared') or cls not in live or not a.get('ref'):",
             "if not a.get('ref'):"),
            ('ReopenClosedIsDryRunByDefault', 'reopen_closed', '    if apply:', '    if True:'),
            ('UnreadableStatusDoesNotRefile', 'act', "status = fx.ticket_status(a['ref'])", "status = fx.ticket_status(a['ref']) or 'duplicate'"),
        ]
        for name, func, old, new in mutants:
            with self.subTest(mutant=name):
                source = inspect.getsource(getattr(L, func))
                self.assertEqual(source.count(old), 1)
                scope = dict(L.__dict__)
                exec(compile(source.replace(old, new), L.__file__, 'exec'), scope)
                result = unittest.TestResult()
                from types import FunctionType
                mutant = FunctionType(scope[func].__code__, L.__dict__, func, scope[func].__defaults__)
                with patch.object(L, func, mutant):
                    LiveAlertReopen('test_' + name).run(result)
                self.assertEqual(result.errors, [], repr(result.errors))
                self.assertTrue(result.failures, 'SURVIVOR: ' + name)
                print('MUTANT ' + name + ' -> test_' + name + ': RED')
                restored = unittest.TestResult()
                LiveAlertReopen('test_' + name).run(restored)
                self.assertTrue(restored.wasSuccessful(), repr(restored.failures + restored.errors))
                print(name + ': restored GREEN')


class ManagedServices(unittest.TestCase):
    FAIL = '2026-10-30T03:30:11Z service bug-briefer end | service worker: exit status 1:  {"name":"bug-briefer","op":"end","run":"18e3310b03b23000","scheduled":"0001-01-01T00:00:00Z","result":"fail"}\n'
    START = '2026-10-30T03:45:07Z service bug-briefer start | digest {"name":"bug-briefer","op":"start","run":"r","config":{"schedule":"*/15 * * * *","handler":"bug-briefer-v1","mode":"warn","enabled":true}}\n'
    ACTION = '2026-10-28T04:32:41Z service bug-briefer action |  {"name":"bug-briefer","op":"action","receipt":{"type":"escalate","outcome":"would","detail":"impactmap/brief-consumers footprint unavailable"}}\n'

    def collect(self, lines, days=7, missing=False):
        import contextlib
        import io
        from pathlib import Path
        from unittest.mock import patch
        import goodqa_liveness_remote as R
        with tempfile.TemporaryDirectory(dir=os.environ.get('SCRATCH')) as root:
            if not missing:
                Path(root, 'events.log').write_text(lines)
            output = io.StringIO()
            with patch.object(R, 'DATA', root), patch.object(R.time, 'time', return_value=L.ts('2026-10-30T04:00:00Z')), \
                 patch.object(R, 'sh', return_value=(0, '{}')), patch.object(R, 'train_verdicts', return_value=([], [])), \
                 patch.object(R, 'merge_train_products', return_value={}), contextlib.redirect_stdout(output):
                self.assertEqual(R.main(['--service-inert-days', str(days)]), 0)
            return json.loads(output.getvalue())

    def svc(self, results, **kw):
        record = dict(enabled=True, mode='warn', ends=[dict(ts='2026-10-30T03:%02d:00Z' % i,
                      result=r, reason='') for i, r in reversed(list(enumerate(results)))], last_ok=None,
                      actions={'would': 100}, actions_total=100)
        record.update(kw)
        return record

    def findings(self, record):
        return L.service_findings(sample(services={'bug-briefer': record}), st(), CFG)

    def test_ServiceFailingNeedsNConsecutive(self):
        self.assertIn('service-failing:bug-briefer', classes(self.findings(self.svc(['fail'] * 4))))
        for results in (['fail'] * 3, ['fail'] * 3 + ['ok'], ['fail', 'ok', 'fail', 'fail', 'fail']):
            self.assertNotIn('service-failing:bug-briefer', classes(self.findings(self.svc(results))))
        self.assertNotIn('service-failing:bug-briefer', classes(self.findings(self.svc(['fail'] * 4 + ['stopped']))))

    def test_DisabledServiceNeverAlerts(self):
        self.assertEqual(self.findings(self.svc(['fail'] * 10, enabled=False)), [])
        self.assertEqual(self.findings(self.svc(['fail'] * 10, enabled=None)), [])

    def test_BlankReasonIsNamed(self):
        for record in (self.svc(['fail'] * 4), self.collect(self.START + self.FAIL * 4)['services']['bug-briefer']):
            finding = next(f for f in self.findings(record) if f['cls'].startswith('service-failing:'))
            self.assertIn('(blank reason: the worker gave no message; check the dev2 journal for oom-kill)', '\n'.join(finding['lines']))
            self.assertIn('never', '\n'.join(finding['lines']))

    def test_InertNeedsZeroEffects(self):
        self.assertIn('service-inert:bug-briefer', classes(self.findings(self.svc([]))))
        self.assertIn('service-inert:bug-briefer', classes(self.findings(self.svc([], actions={'would': 50}))))
        for outcome in ('applied', 'spawned', 'escalated'):
            self.assertEqual(self.findings(self.svc([], actions={'would': 100, outcome: 1})), [])
        self.assertEqual(self.findings(self.svc([], actions={'would': 49})), [])
        self.assertEqual(self.findings(self.svc([], mode='enforce')), [])
        self.assertIn('goodqa#10939-#10947', '\n'.join(self.findings(self.svc([]))[0]['lines']))

    def test_UnreadableServicesIsUnknownNotGreen(self):
        for snapshot in ({'services_error': 'read failed'}, {}, {'services': None}):
            self.assertEqual(classes(L.service_findings(snapshot, st(), CFG)), ['service-unknown'])
        self.assertEqual(classes(L.service_findings({'services': {}}, st(), CFG)), [])

    def test_OneTicketKeyPerClass(self):
        from unittest.mock import patch
        fx = Fx()
        record = self.svc(['fail'] * 4, actions={})
        snapshot = sample(services={'bug-briefer': record, 'other': record})
        findings = L.service_findings(snapshot, st(), CFG)
        self.assertEqual(len(findings), 2)
        keys = []
        with patch.object(fx, 'ticket_new', side_effect=lambda title, body, idem: (keys.append(idem) or 'goodqa#1', 'ok')):
            L.act(findings, st(), CFG, fx, True, T0)
            record['ends'][0]['reason'] = 'different reason'
            L.act(L.service_findings(snapshot, st(), CFG), st(), CFG, fx, True, T0 + 7200)
        self.assertEqual(keys, ['liveness-service-failing-bug-briefer', 'liveness-service-failing-other'] * 2)
        state = st()
        L.act(findings, state, CFG, fx, True, T0)
        before = len(fx.calls)
        L.act(findings, state, CFG, fx, True, T0 + 120)
        self.assertEqual(len(fx.calls), before)

    def test_collector_and_live_sample_contract(self):
        snap = self.collect(self.START + self.FAIL * 15 + self.ACTION * 50)
        record = snap['services']['bug-briefer']
        self.assertEqual(len(record['ends']), 12)
        self.assertEqual(record['ends'][0]['reason'], 'service worker: exit status 1:')
        self.assertEqual(record['actions'], {'would': 50})
        self.assertEqual(record['actions_total'], 50)
        self.assertIsNone(record['last_ok'])
        result = L.live_sample(snap, CFG, [], [], T0)
        self.assertEqual(set(classes(L.service_findings(result, st(), CFG))),
                         {'service-failing:bug-briefer', 'service-inert:bug-briefer'})
        old = self.collect(self.START + self.ACTION, days=1)['services']['bug-briefer']
        self.assertEqual(old['actions'], {})
        self.assertEqual(old['actions_total'], 1)
        ok = self.FAIL.replace('"fail"', '"ok"')
        self.assertEqual(self.collect(ok)['services']['bug-briefer']['last_ok'], '2026-10-30T03:30:11Z')

    def test_collector_errors_and_latest_config(self):
        for snap in (self.collect('', missing=True), self.collect(self.START + self.FAIL.rstrip()),
                     self.collect(self.START + '2026-10-30T03:50:00Z service bug-briefer start | broken\n')):
            self.assertIn('services_error', snap)
            self.assertNotIn('services', snap)
        disabled = self.START.replace('true', 'false').replace('03:45', '03:55')
        record = self.collect(disabled + self.START)['services']['bug-briefer']
        self.assertIs(record['enabled'], False)

    def test_live_pass_and_transport_contract(self):
        from unittest.mock import patch
        snap = self.collect(self.START + self.FAIL * 4 + self.ACTION * 50)
        class TimerFx(Fx):
            def snapshot(self): return snap
            def lane_floor_floor(self): return 40
            def lane_floor_lines(self, *a): return []
            def refusals(self): return []
        with patch.object(L, 'save_land_lag'), patch.object(L.C, 'journal'):
            result = L.run_pass(dict(CFG, deploy_lag_mode='off'), TimerFx(), False, now=T0, state=st())
        self.assertIn('service-failing:bug-briefer', classes(result['findings']))
        self.assertIn('service-inert:bug-briefer', classes(result['findings']))
        with patch.object(L.C, 'run', return_value=(0, '{"services":{}}', '')) as call:
            L.Effects(dict(CFG, service_inert_days=3)).snapshot()
            self.assertEqual(call.call_args.args[0], [L.DEV2, '-t', '90', '-p', L.REMOTE, '--service-inert-days', '3'])
            L.Effects(CFG).snapshot(replay_since='2026-10-30T00:00:00Z')
            self.assertEqual(call.call_args.args[0], [L.DEV2, '-t', '90', '-p', L.REMOTE,
                                                    '--replay-since', '2026-10-30T00:00:00Z'])

    def test_unknown_collection_cannot_claim_recovery(self):
        fx, state = Fx(), st()
        active = self.findings(self.svc(['fail'] * 4))
        L.act(active, state, CFG, fx, True, T0)
        unknown = L.service_findings({'services_error': 'read failed'}, state, CFG)
        L.act(unknown, state, CFG, fx, True, T0 + 120)
        L.act(unknown, state, CFG, fx, True, T0 + 1200)
        self.assertFalse(any(a.get('cleared') for k, a in state['alerts'].items() if k != 'service-unknown'))
        L.act([], state, CFG, fx, True, T0 + 1800)
        L.act([], state, CFG, fx, True, T0 + 2500)
        self.assertTrue(all(a.get('cleared') for a in state['alerts'].values()))


class ManagedServicesMutations(unittest.TestCase):
    def test_NamedControlsKillMutantsAndRestore(self):
        from pathlib import Path
        from unittest.mock import patch
        import types
        source = Path(L.__file__).read_text()
        mutants = [
            ('any-failure', 'if len(consecutive) >= need:', 'if consecutive:',
             'ServiceFailingNeedsNConsecutive'),
            ('nonconsecutive-count', "            if end.get('result') != 'fail':\n                break",
             "            if end.get('result') != 'fail':\n                continue", 'ServiceFailingNeedsNConsecutive'),
            ('strict-boundary', 'if len(consecutive) >= need:', 'if len(consecutive) > need:',
             'ServiceFailingNeedsNConsecutive'),
            ('ignore-enabled', "if service.get('enabled') is not True:", 'if False:', 'DisabledServiceNeverAlerts'),
            ('drop-blank-marker', "message += ' (blank reason: the worker gave no message; check the dev2 journal for oom-kill)'",
             "message += ''", 'BlankReasonIsNamed'),
            ('any-would', "and not any(actions.get(outcome, 0) for outcome in ('applied', 'spawned', 'escalated'))",
             "and actions.get('would', 0)", 'InertNeedsZeroEffects'),
            ('unknown-is-green', "return [dict(cls='service-unknown', title='managed service collection UNKNOWN',\n                     lines=[str(sample.get('services_error') or 'services missing from remote snapshot')], remedies=[])]",
             'return []', 'UnreadableServicesIsUnknownNotGreen'),
            ('reason-in-key', "cls='service-failing:' + name,", "cls='service-failing:' + name + reason,", 'OneTicketKeyPerClass'),
        ]
        for name, old, new, method in mutants:
            with self.subTest(mutant=name):
                self.assertEqual(source.count(old), 1)
                mutant = types.ModuleType('_service_mutant')
                mutant.__file__ = L.__file__
                exec(compile(source.replace(old, new, 1), L.__file__, 'exec'), mutant.__dict__)
                red = unittest.TestResult()
                with patch.object(sys.modules[__name__], 'L', mutant):
                    ManagedServices('test_' + method).run(red)
                self.assertEqual(red.errors, [], 'mutant must fail an assertion: ' + repr(red.errors))
                self.assertTrue(red.failures, 'SURVIVOR: ' + name)
                restored = unittest.TestResult()
                ManagedServices('test_' + method).run(restored)
                self.assertTrue(restored.wasSuccessful(), repr(restored.failures + restored.errors))
                print('MUTANT %s -> %s: RED; restored GREEN' % (name, method))


# ------------------------------------------------------------------------------------------------ gq-clutter S1: rolling alerts
class BlockFx(StatefulFx):
    """StatefulFx that also records the description status-block writes (Effects.ticket_status_block)."""
    def __init__(self):
        super().__init__()
        self.blocks = []

    def ticket_status_block(self, ref, block):
        self.calls.append(('block', ref))
        self.blocks.append((ref, block))
        return True


def _land(key, minutes=120.0, klass='other'):
    """A land-lag finding shaped like land_lag_findings() emits it."""
    return dict(cls='land-lag:' + key, title='%s %s ready but not activated for %.0f min' % (klass, key, minutes),
                lines=['first READY x; candidate y; landed False'], remedies=[],
                severity='high' if klass == 'safety' else 'normal', minutes=minutes)


def _ready_row(key, sha='c' * 40, landed=False):
    """A readable ordinary (class other) runner row as the dev2 collector returns it."""
    return dict(key=key, source='runner', task_id=key.split('/', 1)[1], candidate_sha=sha, gate_candidate_sha=sha,
                ready_at=L.iso(T0 - 7200), paths=['docs/x.md'], paths_unreadable=False, landed=landed,
                author='a@example.invalid', author_identity_complete=True, author_aliases=['a@example.invalid'],
                proof={}, proof_landed=None, proof_contains_candidate=False)


class RollingAlerts(unittest.TestCase):
    """gq-clutter S1 (goodqa#14007 follow-up, goodqa#7925): one rolling ticket per alert key, a status block instead of
    a comment per repeat observation, lane families, supersede close and recurrence reopen. Each test FAILED on the
    pre-fix main (dc7409614): 6 comments in 100 passes and no occurrence counter; one ticket per successor lane; a
    re-fire opened a new ticket; a superseded or landed lane only cleared after clear_seconds, or never."""

    @staticmethod
    def comments(fx, word=None):
        return [c for c in fx.calls if c[0] == 'comment' and (word is None or word in c[2])]

    @staticmethod
    def tickets(fx):
        return [c for c in fx.calls if c[0] == 'ticket']

    def test_100_passes_of_one_finding_make_one_ticket_at_most_one_comment_and_occurrences_100(self):
        fx, s0 = BlockFx(), st()
        f = dict(cls='unit-failing:dev:x.service', title='dev x.service failed', lines=['failed since T0'], remedies=[])
        for i in range(100):                                                       # a pass every 2 min for 198 min
            L.act([dict(f)], s0, CFG, fx, True, T0 + 120 * i)
        self.assertEqual(len(self.tickets(fx)), 1)
        self.assertLessEqual(len(self.comments(fx)), 1)
        a = s0['alerts'][f['cls']]
        self.assertEqual(a.get('occurrences'), 100)
        self.assertEqual((a.get('first_seen'), a.get('last_seen')), (T0, T0 + 120 * 99))
        # the repeat observations went to the ONE status block, rewritten in place at most every alert_status_minutes
        status_every = float(CFG.get('alert_status_minutes', 60)) * 60
        self.assertTrue(fx.blocks)
        self.assertLessEqual(len(fx.blocks), int(120 * 99 // status_every) + 1)
        self.assertIn('occurrences: %d' % a['status_synced_occurrences'], fx.blocks[-1][1])
        self.assertIn('first_seen: %s' % L.iso(T0), fx.blocks[-1][1])

    def test_a_reminder_is_at_most_daily_and_only_on_a_material_change(self):
        fx, s0 = BlockFx(), st()
        f = dict(cls='merge-stall', title='no merge for 95 min; top STOP class flaky', lines=['x'], remedies=[])
        L.act([f], s0, CFG, fx, True, T0)
        every = float(CFG['alert_comment_minutes']) * 60
        L.act([dict(f, title='no merge for 2000 min; top STOP class flaky')], s0, CFG, fx, True, T0 + every + 60)
        self.assertEqual(self.comments(fx), [])                                    # a number ticking up is not material
        changed = dict(f, title='no merge for 2100 min; top STOP class oom')
        L.act([changed], s0, CFG, fx, True, T0 + every + 180)
        self.assertEqual(len(self.comments(fx)), 1)                                # material, past the cadence: ONE reminder
        L.act([dict(f, title='no merge for 2200 min; top STOP class disk')], s0, CFG, fx, True, T0 + every + 300)
        self.assertEqual(len(self.comments(fx)), 1)                                # inside the cadence: none

    def test_severity_escalation_is_a_transition_comment(self):
        fx, s0 = BlockFx(), st()
        L.act([_land('runner/harness-foo-guard-sol-20261101')], s0, CFG, fx, True, T0)
        L.act([_land('runner/harness-foo-guard-r2-sol-20261102', klass='safety')], s0, CFG, fx, True, T0 + 120)
        self.assertEqual(len(self.comments(fx, 'escalated')), 1)
        L.act([_land('runner/harness-foo-guard-r2-sol-20261102', klass='safety')], s0, CFG, fx, True, T0 + 240)
        self.assertEqual(len(self.comments(fx)), 1)

    def test_r2_and_r3_successor_lanes_map_to_the_same_ticket(self):
        fx, s0 = BlockFx(), st()
        r2 = _land('runner/harness-foo-guard-r2-sol-20261101@' + 'a' * 40)
        r3 = _land('runner/harness-foo-guard-r3-sol-20261102@' + 'b' * 40)
        L.act([r2], s0, CFG, fx, True, T0)
        L.act([r2, r3], s0, CFG, fx, True, T0 + 120)
        L.act([r3], s0, CFG, fx, True, T0 + 240)
        L.act([_land('runner/harness-foo-guard-successor-sol-20261103@pending')], s0, CFG, fx, True, T0 + 360)
        self.assertEqual(len(self.tickets(fx)), 1)
        self.assertEqual(self.comments(fx), [])
        # codex-owner lanes: successor runs rename the run directory too
        fx2, s2 = BlockFx(), st()
        L.act([_land('o8-run2/land-lag-gate-r2')], s2, CFG, fx2, True, T0)
        L.act([_land('o8-astra/land-lag-gate-r6'), _land('o8-run3/land-lag-gate-r3@pending-0123456789abcdef')], s2, CFG, fx2, True, T0 + 120)
        self.assertEqual(len(self.tickets(fx2)), 1)
        # NEGATIVE CONTROL: a different lane, and non-lane classes, keep their own tickets
        fx3, s3 = BlockFx(), st()
        L.act([_land('runner/harness-foo-guard-r2'), _land('runner/harness-bar-guard-r2'),
               dict(cls='unit-failing:dev:a-r2.service', title='a', lines=['x'], remedies=[]),
               dict(cls='unit-failing:dev:a-r3.service', title='a', lines=['x'], remedies=[])], s3, CFG, fx3, True, T0)
        self.assertEqual(len(self.tickets(fx3)), 4)

    def test_alert_key_strips_successor_suffixes_and_the_candidate_sha(self):
        k = L.alert_key
        self.assertEqual(k('land-lag:runner/go-rebuild-p0-failure-contract-r6-sol-20261027-fix-sol'),
                         'land-lag:runner:go-rebuild-p0-failure-contract')
        self.assertEqual(k('land-lag:runner/gorunner-ship-reconcile-cap-sol-20261027@' + 'e' * 40),
                         k('land-lag:runner/gorunner-ship-reconcile-cap-sol-20261027@pending'))
        self.assertEqual(k('land-lag:o8-run1/land-lag-gate'), 'land-lag:owner:land-lag-gate')
        self.assertEqual(k('land-lag:owner:land-lag-gate'), 'land-lag:owner:land-lag-gate')        # idempotent
        for cls in ('unit-failing:dev2:goodqa-hive-direct-dev-canary@r314-canary.service', 'deploy-lag:goodqa',
                    'land-lag-unreadable', 'service-failing:bug-briefer'):
            self.assertEqual(k(cls), cls)
        self.assertEqual(L.lane_family('r2'), 'r2')                                                # never empty

    def test_clear_posts_one_recovery_comment_and_done_and_recurrence_reopens_the_same_ticket(self):
        cs = float(CFG.get('clear_seconds', 600))
        fx, s0 = BlockFx(), st()
        f = dict(cls='queue-idle', title='18 queued, 0 running', lines=['x'], remedies=[])
        L.act([f], s0, CFG, fx, True, T0)
        ref = s0['alerts']['queue-idle']['ref']
        L.act([], s0, CFG, fx, True, T0 + 120)
        L.act([], s0, CFG, fx, True, T0 + 120 + cs + 1)
        L.act([], s0, CFG, fx, True, T0 + 120 + cs + 300)
        self.assertEqual(len(self.comments(fx, 'recovered')), 1)
        self.assertEqual([c for c in fx.calls if c[0] == 'patch'], [('patch', ref, 'done')])
        self.assertEqual(fx._status[ref], 'done')
        # recurrence two days later (inside alert_reopen_days): the SAME ticket is reopened, one comment, no new ticket
        L.act([f], s0, CFG, fx, True, T0 + 2 * 86400)
        self.assertEqual(len(self.tickets(fx)), 1)
        self.assertEqual(fx._status[ref], 'triage')
        self.assertEqual(len(self.comments(fx, 'reopened')), 1)
        self.assertEqual(s0['alerts']['queue-idle']['ref'], ref)
        self.assertFalse(s0['alerts']['queue-idle'].get('cleared'))
        L.act([f], s0, CFG, fx, True, T0 + 2 * 86400 + 120)
        self.assertEqual(len(self.comments(fx)), 2)                                # nothing more while it holds
        # NEGATIVE CONTROL: a recurrence after alert_reopen_days opens a new ticket
        L.act([], s0, CFG, fx, True, T0 + 3 * 86400)
        L.act([], s0, CFG, fx, True, T0 + 3 * 86400 + cs + 1)
        L.act([f], s0, CFG, fx, True, T0 + 3 * 86400 + cs + 1 + 8 * 86400)
        self.assertEqual(len(self.tickets(fx)), 2)

    def test_a_superseded_lane_closes_within_one_pass(self):
        key = 'runner/harness-foo-guard-sol-20261101'
        fx, s0 = BlockFx(), st()
        reading = dict(rows=[_ready_row(key)], errors=[], discovered=[key])
        L.act(L.land_lag_findings(reading, s0, CFG, T0), s0, CFG, fx, True, T0)
        self.assertEqual(len(self.tickets(fx)), 1)
        ref = [a for a in s0['alerts'].values()][0]['ref']
        self.assertEqual(fx._status.get(ref, 'triage'), 'triage')
        # NEGATIVE CONTROL: no discovery evidence (a transport failure, an empty or older collector) never closes it
        for t, bad in ((T0 + 120, dict(rows=[], errors=['dev2 land-lag read failed: x'])),
                       (T0 + 240, dict(rows=[], errors=[], discovered=[]))):
            L.act(L.land_lag_findings(bad, s0, CFG, t), s0, CFG, fx, True, t)
        self.assertEqual([c for c in fx.calls if c[0] == 'patch'], [])
        # superseded: its pin queue is gone, so the next read no longer discovers it (another lane still is)
        gone = dict(rows=[], errors=[], discovered=['runner/some-other-lane'])
        L.act(L.land_lag_findings(gone, s0, CFG, T0 + 360), s0, CFG, fx, True, T0 + 360)
        self.assertEqual([c for c in fx.calls if c[0] == 'patch'], [('patch', ref, 'done')])   # closed within the pass
        self.assertEqual(len(self.comments(fx, 'recovered')), 1)
        L.act(L.land_lag_findings(gone, s0, CFG, T0 + 480), s0, CFG, fx, True, T0 + 480)
        self.assertEqual((len([t for t in self.tickets(fx) if key in t[1]]),           # stays closed while absent
                          len([c for c in self.comments(fx) if c[1] == ref])), (1, 1))
        self.assertIn(key, s0['land_lag'])                                         # the gate debt is untouched

    def test_a_landed_lane_closes_within_one_pass(self):
        key = 'runner/harness-foo-guard-sol-20261101'
        fx, s0 = BlockFx(), st()
        L.act(L.land_lag_findings(dict(rows=[_ready_row(key)], errors=[], discovered=[key]), s0, CFG, T0), s0, CFG, fx, True, T0)
        ref = [a for a in s0['alerts'].values()][0]['ref']
        landed = dict(rows=[_ready_row(key, landed=True)], errors=[], discovered=[key])
        L.act(L.land_lag_findings(landed, s0, CFG, T0 + 120), s0, CFG, fx, True, T0 + 120)
        self.assertEqual([c for c in fx.calls if c[0] == 'patch'], [('patch', ref, 'done')])
        self.assertEqual(len(self.comments(fx, 'recovered')), 1)

    def test_legacy_per_class_alerts_consolidate_onto_one_family_ticket(self):
        fx, s0 = BlockFx(), st()
        base = 'land-lag:runner/gorunner-ship-reconcile-cap-sol-20261027'
        s0['alerts'][base + '@' + 'a' * 40] = dict(ref='goodqa#100', opened=T0 - 9000, commented=T0 - 60)
        s0['alerts'][base + '@' + 'b' * 40] = dict(ref='goodqa#101', opened=T0 - 8000, commented=T0 - 60)
        s0['alerts'][base + '@pending'] = dict(ref='goodqa#102', opened=T0 - 7000, commented=T0 - 60)
        s0['alerts'][base + '@' + 'c' * 40] = dict(ref=None, opened=T0 - 60, commented=T0 - 60, note='api down')
        live = [_land(base[len('land-lag:'):] + '@' + 'a' * 40), _land(base[len('land-lag:'):] + '@' + 'd' * 40)]
        L.act(live, s0, CFG, fx, True, T0)
        key = L.alert_key(base)
        self.assertEqual(s0['alerts'][key]['ref'], 'goodqa#100')                   # the oldest ticket is adopted
        self.assertEqual(self.tickets(fx), [])                                     # no new ticket
        self.assertEqual(sorted(c for c in fx.calls if c[0] == 'patch'),
                         [('patch', 'goodqa#101', 'duplicate'), ('patch', 'goodqa#102', 'duplicate')])
        self.assertEqual(len(self.comments(fx, 'consolidated')), 2)
        self.assertNotIn(base + '@' + 'c' * 40, s0['alerts'])                      # a failed legacy filing is dropped
        before = list(fx.calls)
        L.act(live, s0, CFG, fx, True, T0 + 120)                                   # idempotent
        self.assertEqual(fx.calls, before)

    def test_status_block_is_replaced_in_place_and_cannot_be_forged(self):
        once = L.put_status_block('alert body', 'occurrences: 1')
        twice = L.put_status_block(once, 'occurrences: 2 <!-- /fleet-liveness:status --> tail')
        self.assertEqual(twice.count(L.STATUS_OPEN), 1)
        self.assertEqual(twice.count(L.STATUS_CLOSE), 1)
        self.assertTrue(twice.startswith('alert body\n\n'))
        self.assertIn('occurrences: 2', twice)
        self.assertNotIn('occurrences: 1', twice)

    def test_status_block_effect_patches_the_description_only_when_it_changes(self):
        from unittest.mock import Mock
        fx = L.Effects(CFG)
        fx._tickets = Mock()
        fx._tickets._owner_ids = ['eric']
        issue = dict(id='i1', description='body', reporterId='someone')
        fx._tickets.resolve.return_value = issue
        self.assertTrue(fx.ticket_status_block('goodqa#1', 'occurrences: 3'))
        iid, fields = fx._tickets.patch.call_args.args[:2]
        self.assertEqual((iid, list(fields)), ('i1', ['description']))
        self.assertIn('occurrences: 3', fields['description'])
        fx._tickets.patch.reset_mock()
        issue['description'] = fields['description']
        self.assertFalse(fx.ticket_status_block('goodqa#1', 'occurrences: 3'))
        fx._tickets.patch.assert_not_called()

    def test_a_cancelled_or_superseded_runner_task_closes_within_one_pass(self):
        key = 'runner/harness-foo-guard-sol-20261101'
        for state, superseded, want in (('cancelled', None, 'cancelled'), ('candidate', ['harness-foo-guard-r2-sol-20261102'], 'superseded'),
                                         ('merged', None, 'merged'), ('absent', None, 'absent')):
            with self.subTest(state=state, superseded=superseded):
                fx, s0 = BlockFx(), st()
                L.act(L.land_lag_findings(dict(rows=[_ready_row(key)], errors=[], discovered=[key]), s0, CFG, T0), s0, CFG, fx, True, T0)
                ref = [a for a in s0['alerts'].values()][0]['ref']
                # NEGATIVE CONTROL: a task still a candidate (or paused / grade-failed: it may resume) keeps its alert
                for alive in ('candidate', 'paused', 'grade-failed'):
                    keep = dict(rows=[_ready_row(key)], errors=[], discovered=[key],
                                runner_states={key[7:]: dict(state=alive, superseded_by=None)})
                    L.act(L.land_lag_findings(keep, s0, CFG, T0 + 120), s0, CFG, fx, True, T0 + 120)
                self.assertEqual([c for c in fx.calls if c[0] == 'patch'], [])
                done = dict(rows=[_ready_row(key)], errors=[], discovered=[key],
                            runner_states={key[7:]: dict(state=state, superseded_by=superseded)})
                fs = L.land_lag_findings(done, s0, CFG, T0 + 240)
                self.assertIn(want, fs[0]['stale'])
                L.act(fs, s0, CFG, fx, True, T0 + 240)
                self.assertEqual([c for c in fx.calls if c[0] == 'patch'], [('patch', ref, 'done')])
                self.assertEqual(len(self.comments(fx, 'recovered')), 1)
                self.assertIn(key, s0['land_lag'])                                 # the gate debt is untouched

    # ---- red-team (fa1ca583e review) regressions: each FAILED on fa1ca583e and passes on the fix
    def test_rt1_a_safety_lane_closes_only_when_its_candidate_can_no_longer_land(self):
        key = 'runner/harness-foo-guard-sol-20261101'
        row = lambda **kw: dict(_ready_row(key), paths=['bin/finish_gate.py'], **kw)
        fx, s0 = BlockFx(), st()
        L.act(L.land_lag_findings(dict(rows=[row()], errors=[], discovered=[key]), s0, CFG, T0), s0, CFG, fx, True, T0)
        self.assertEqual(s0['land_lag'][key]['class'], 'safety')
        ref = [a for a in s0['alerts'].values()][0]['ref']
        # merged / shipped, landed, or no longer discovered: the safety debt is still live, so is its alert
        for i, reading in enumerate((
                dict(rows=[row()], errors=[], discovered=[key], runner_states={key[7:]: dict(state='merged', superseded_by=None)}),
                dict(rows=[row()], errors=[], discovered=[key], runner_states={key[7:]: dict(state='shipped', superseded_by=None)}),
                dict(rows=[row(landed=True)], errors=[], discovered=[key]),
                dict(rows=[], errors=[], discovered=['runner/some-other-lane']))):
            t = T0 + 120 * (i + 1)
            fs = L.land_lag_findings(reading, s0, CFG, t)
            self.assertFalse([f for f in fs if f.get('stale')], i)
            L.act(fs, s0, CFG, fx, True, t)
        self.assertEqual([c for c in fx.calls if c[0] == 'patch'], [])
        # cancelled: it can never land, so the alert closes within the pass (the gate debt stays)
        gone = dict(rows=[row()], errors=[], discovered=[key], runner_states={key[7:]: dict(state='cancelled', superseded_by=None)})
        L.act(L.land_lag_findings(gone, s0, CFG, T0 + 900), s0, CFG, fx, True, T0 + 900)
        self.assertEqual([c for c in fx.calls if c[0] == 'patch'], [('patch', ref, 'done')])
        self.assertIn(key, s0['land_lag'])

    def test_rt2_partial_or_mass_missing_discovery_closes_nothing(self):
        keys = ['runner/lane-%s-sol-20261101' % c for c in 'abcdefghijkl']            # 12 distinct lane families
        fx, s0 = BlockFx(), st()
        L.act(L.land_lag_findings(dict(rows=[_ready_row(k) for k in keys], errors=[], discovered=list(keys)), s0, CFG, T0),
              s0, CFG, fx, True, T0)
        self.assertEqual(len(self.tickets(fx)), 12)
        for i, discovered in enumerate((['o8-run1/owner-lane'],                       # the runner glob read nothing
                                        keys[:1])):                                   # 11 of 12 vanish at once: breaker
            t = T0 + 120 * (i + 1)
            fs = L.land_lag_findings(dict(rows=[], errors=[], discovered=discovered), s0, CFG, t)
            self.assertFalse([f for f in fs if f.get('stale')], discovered)
            L.act(fs, s0, CFG, fx, True, t)
        self.assertEqual([c for c in fx.calls if c[0] == 'patch'], [])
        # CONTROL (fresh state; lanes held by the breaker above stay held for the confirm window, rt3a/rt3d): a minority
        # vanishing (2 of 12) is real evidence and closes exactly those two within the pass
        fx, s0 = BlockFx(), st()
        L.act(L.land_lag_findings(dict(rows=[_ready_row(k) for k in keys], errors=[], discovered=list(keys)), s0, CFG, T0),
              s0, CFG, fx, True, T0)
        fs = L.land_lag_findings(dict(rows=[], errors=[], discovered=keys[2:]), s0, CFG, T0 + 600)
        self.assertEqual(sorted(f['cls'] for f in fs if f.get('stale')), ['land-lag:' + k for k in keys[:2]])
        L.act(fs, s0, CFG, fx, True, T0 + 600)
        self.assertEqual(len([c for c in fx.calls if c[0] == 'patch']), 2)

    def test_rt2b_a_no_evidence_read_never_reopens_a_correct_supersede_close(self):
        # red-team delta R1 reproducer (rt_flap.py): c1d84edeb reopened lane a's closed ticket to triage here
        keys = ['runner/lane-%s-sol-20261101' % c for c in 'abcd']
        fx, s0, t = BlockFx(), st(), T0
        L.act(L.land_lag_findings(dict(rows=[_ready_row(k) for k in keys], errors=[], discovered=list(keys)), s0, CFG, t),
              s0, CFG, fx, True, t)
        t += 1200
        d = keys[1:]
        L.act(L.land_lag_findings(dict(rows=[_ready_row(k) for k in d], errors=[], discovered=d), s0, CFG, t), s0, CFG, fx, True, t)
        closed = [c for c in fx.calls if c[0] == 'patch']
        self.assertEqual(len(closed), 1)
        for t, reading in ((t + 1200, dict(rows=[], errors=[], discovered=['o8-run1/owner-lane'])),   # runner glob empty
                           (t + 2400, dict(rows=[], errors=['dev2 land-lag read failed: x'])),        # transport failure
                           (t + 3600, dict(rows=[_ready_row(k) for k in d], errors=[], discovered=d))):
            L.act(L.land_lag_findings(reading, s0, CFG, t), s0, CFG, fx, True, t)
        self.assertEqual([c for c in fx.calls if c[0] == 'patch'], closed)        # no reopen, no new close
        self.assertEqual(self.comments(fx, 'reopened'), [])
        # CONTROL: the lane genuinely discovered again (resumed) is positive evidence: the same ticket reopens
        t += 4800
        L.act(L.land_lag_findings(dict(rows=[_ready_row(k) for k in keys], errors=[], discovered=list(keys)), s0, CFG, t),
              s0, CFG, fx, True, t)
        self.assertEqual(len(self.comments(fx, 'reopened')), 1)

    def test_rt2c_one_supersede_per_pass_always_closes_within_the_pass(self):
        # red-team delta R1 reproducer (rt_breaker.py): c1d84edeb's breaker tripped for good at the 6th supersede
        keys = ['runner/lane-%s-sol-20261101' % c for c in 'abcdefgh']
        allk = keys + ['runner/lane-z-sol-20261101']
        fx, s0, t = BlockFx(), st(), T0
        L.act(L.land_lag_findings(dict(rows=[_ready_row(k) for k in allk], errors=[], discovered=list(allk)), s0, CFG, t),
              s0, CFG, fx, True, t)
        gone = []
        for k in keys:
            gone.append(k)
            t += 1200
            disc = [x for x in allk if x not in gone]
            fs = L.land_lag_findings(dict(rows=[_ready_row(x) for x in disc], errors=[], discovered=disc), s0, CFG, t)
            self.assertIn('land-lag:' + k, [f['cls'] for f in fs if f.get('stale')], k)
            L.act(fs, s0, CFG, fx, True, t)
            self.assertEqual(len([c for c in fx.calls if c[0] == 'patch' and c[2] == 'done']), len(gone), k)
        self.assertEqual([c for c in fx.calls if c[0] == 'patch' and c[2] != 'done'], [])     # nothing reopened

    @staticmethod
    def _read(keys, rows=None):
        return dict(rows=list(rows) if rows is not None else [_ready_row(k) for k in keys], errors=[], discovered=list(keys))

    @staticmethod
    def _done(fx):
        return [c for c in fx.calls if c[0] == 'patch' and c[2] == 'done']

    def test_rt3a_the_breaker_holds_a_mass_vanish_then_recovers_after_the_confirm_window(self):
        # red-team delta2 F1-A: 6 of 11 lanes cancelled in one read; 57fce50f3 never closed them (0 of 6 in 6.7 h)
        keys = ['runner/fam%s-sol-20261101' % i for i in range(11)]
        fx, s0, t = BlockFx(), st(), T0
        L.act(L.land_lag_findings(self._read(keys), s0, CFG, t), s0, CFG, fx, True, t)
        confirm = float(CFG.get('land_lag_stale_confirm_seconds', 1800))
        t += 120
        L.act(L.land_lag_findings(self._read(keys[6:]), s0, CFG, t), s0, CFG, fx, True, t)
        self.assertEqual(self._done(fx), [])                                       # the breaker holds the mass vanish
        L.act(L.land_lag_findings(self._read(keys[6:]), s0, CFG, t + confirm - 60), s0, CFG, fx, True, t + confirm - 60)
        self.assertEqual(self._done(fx), [])
        L.act(L.land_lag_findings(self._read(keys[6:]), s0, CFG, t + confirm), s0, CFG, fx, True, t + confirm)
        self.assertEqual(len(self._done(fx)), 6)                                   # ...then accepts it as evidence
        # CONTROL: a mass vanish that comes back inside the window closes nothing and leaves no mark
        fx2, s2, t2 = BlockFx(), st(), T0
        L.act(L.land_lag_findings(self._read(keys), s2, CFG, t2), s2, CFG, fx2, True, t2)
        L.act(L.land_lag_findings(self._read(keys[6:]), s2, CFG, t2 + 120), s2, CFG, fx2, True, t2 + 120)
        L.act(L.land_lag_findings(self._read(keys), s2, CFG, t2 + 240), s2, CFG, fx2, True, t2 + 240)
        L.act(L.land_lag_findings(self._read(keys[6:]), s2, CFG, t2 + confirm + 120), s2, CFG, fx2, True, t2 + confirm + 120)
        self.assertEqual(self._done(fx2), [])
        self.assertFalse([k for k in keys if s2['land_lag'][k].get('undiscovered')])

    def test_rt3d_a_held_vanish_stays_held_when_new_lanes_appear_and_tolerates_a_bad_timestamp(self):
        # red-team delta3 nits 1 and 3: new lanes shrank the ratio and released the hold at once; a non-numeric
        # persisted missing_since raised ValueError on every pass
        keys = ['runner/fam%s-sol-20261101' % i for i in range(11)]
        fresh = ['runner/new%s-sol-20261101' % i for i in range(3)]
        fx, s0, t = BlockFx(), st(), T0
        L.act(L.land_lag_findings(self._read(keys), s0, CFG, t), s0, CFG, fx, True, t)
        L.act(L.land_lag_findings(self._read(keys[6:]), s0, CFG, t + 120), s0, CFG, fx, True, t + 120)
        s0['land_lag'][keys[0]]['missing_since'] = '2026-10-23T21:00:00Z'
        L.act(L.land_lag_findings(self._read(keys[6:] + fresh), s0, CFG, t + 240), s0, CFG, fx, True, t + 240)
        self.assertEqual(self._done(fx), [])
        confirm = float(CFG.get('land_lag_stale_confirm_seconds', 1800))
        L.act(L.land_lag_findings(self._read(keys[6:] + fresh), s0, CFG, t + 240 + confirm), s0, CFG, fx, True, t + 240 + confirm)
        self.assertEqual(len(self._done(fx)), 6)

    def test_rt3b_superseded_safety_lanes_leave_the_breaker_count_but_keep_their_alerts(self):
        # red-team delta2 F1-B: 6 superseded safety lanes latched the breaker against every later ordinary supersede
        sk = ['runner/safe%s-sol-20261101' % i for i in range(6)]
        ok = ['runner/ord%s-sol-20261101' % i for i in range(5)]
        rows = [dict(_ready_row(k), paths=['bin/finish_gate.py']) for k in sk] + [_ready_row(k) for k in ok]
        fx, s0, t = BlockFx(), st(), T0
        pick = lambda disc: dict(rows=[r for r in rows if r['key'] in disc], errors=[], discovered=disc)
        L.act(L.land_lag_findings(pick(sk + ok), s0, CFG, t), s0, CFG, fx, True, t)
        gone = []
        for k in sk:
            gone.append(k)
            t += 1200
            L.act(L.land_lag_findings(pick([x for x in sk + ok if x not in gone]), s0, CFG, t), s0, CFG, fx, True, t)
        self.assertEqual(self._done(fx), [])                                       # safety alerts stay open
        t += 1200
        fs = L.land_lag_findings(pick(ok[1:]), s0, CFG, t)
        self.assertIn('land-lag:' + ok[0], [f['cls'] for f in fs if f.get('stale')])
        self.assertFalse([f for f in fs if f.get('stale') and f['cls'].startswith('land-lag:runner/safe')])
        L.act(fs, s0, CFG, fx, True, t)
        self.assertEqual(len(self._done(fx)), 1)                                   # the ordinary lane closes in the pass

    def test_rt3c_a_lane_superseded_before_it_ages_is_marked_and_never_files_a_ticket(self):
        # red-team delta2 F1-C: young lanes gone before land_lag_minutes latched the breaker and later opened 6 tickets
        old = ['runner/old%s-sol-20261101' % i for i in range(4)]
        young = ['runner/yng%s-sol-20261101' % i for i in range(6)]
        fx, s0, t = BlockFx(), st(), T0
        L.act(L.land_lag_findings(self._read(old), s0, CFG, t), s0, CFG, fx, True, t)
        opened = len(self.tickets(fx))
        t += 600
        young_rows = [dict(_ready_row(k), ready_at=L.iso(t)) for k in young]
        L.land_lag_findings(self._read(old + young, [_ready_row(k) for k in old] + young_rows), s0, CFG, t)
        for _ in range(30):                                                        # 5 h: young lanes and old0 gone
            t += 600
            L.act(L.land_lag_findings(self._read(old[1:]), s0, CFG, t), s0, CFG, fx, True, t)
        self.assertEqual(len(self.tickets(fx)), opened)                            # no ticket for a lane already gone
        self.assertEqual(len(self._done(fx)), 1)                                   # old0 closed
        self.assertTrue(all(s0['land_lag'][k].get('undiscovered') for k in young))

    def test_rt2d_a_runner_done_close_holds_after_the_cached_states_expire(self):
        key = 'runner/harness-foo-guard-sol-20261101'
        fx, s0 = BlockFx(), st()
        L.act(L.land_lag_findings(dict(rows=[_ready_row(key)], errors=[], discovered=[key]), s0, CFG, T0), s0, CFG, fx, True, T0)
        done = dict(rows=[_ready_row(key)], errors=[], discovered=[key],
                    runner_states={key[7:]: dict(state='cancelled', superseded_by=None)})
        L.act(L.land_lag_findings(done, s0, CFG, T0 + 120), s0, CFG, fx, True, T0 + 120)
        self.assertEqual(len([c for c in fx.calls if c[0] == 'patch']), 1)
        # later reads carry no runner states (expired cache / failed gorunner read): the close holds
        later = dict(rows=[_ready_row(key)], errors=[], discovered=[key])
        L.act(L.land_lag_findings(later, s0, CFG, T0 + 3 * 3600), s0, CFG, fx, True, T0 + 3 * 3600)
        self.assertEqual(len([c for c in fx.calls if c[0] == 'patch']), 1)
        self.assertEqual(self.comments(fx, 'reopened'), [])

    def test_rt2e_every_http_ticket_patch_respects_the_write_reserve(self):
        # red-team delta R2: the recovery `done` PATCH and the human-closed reopen PATCH were gated only on budget <= 0
        fx, s0 = BlockFx(), st()
        f = dict(cls='queue-idle', title='18 queued, 0 running', lines=['x'], remedies=[])
        L.act([f], s0, CFG, fx, True, T0)
        ref = s0['alerts']['queue-idle']['ref']
        cs = float(CFG.get('clear_seconds', 600))
        L.act([], s0, CFG, fx, True, T0 + 120)
        L.act([], s0, CFG, fx, True, T0 + 120 + cs + 1, alert_budget=30)
        self.assertEqual([c for c in fx.calls if c[0] == 'patch'], [])
        L.act([], s0, CFG, fx, True, T0 + 120 + cs + 121)                      # CONTROL: full budget closes it
        self.assertEqual([c for c in fx.calls if c[0] == 'patch'], [('patch', ref, 'done')])
        # human-closed while the finding is live: the reopen PATCH waits for budget too
        fx2, s2 = BlockFx(), st()
        L.act([f], s2, CFG, fx2, True, T0)
        ref2 = s2['alerts']['queue-idle']['ref']
        fx2._status[ref2] = 'done'
        later = T0 + float(CFG.get('alert_status_minutes', 60)) * 60 + 60
        L.act([f], s2, CFG, fx2, True, later, alert_budget=30)
        self.assertEqual([c for c in fx2.calls if c[0] == 'patch'], [])
        L.act([f], s2, CFG, fx2, True, later + 120)
        self.assertEqual([c for c in fx2.calls if c[0] == 'patch'], [('patch', ref2, 'triage')])

    def test_rt4_a_sync_only_pass_skips_the_status_write_when_the_alert_budget_reserve_is_short(self):
        fx, s0 = BlockFx(), st()
        f = dict(cls='queue-idle', title='18 queued, 0 running', lines=['x'], remedies=[])
        L.act([f], s0, CFG, fx, True, T0)
        later = T0 + float(CFG.get('alert_status_minutes', 60)) * 60 + 60
        before = list(fx.calls)
        L.act([f], s0, CFG, fx, True, later, alert_budget=30)                     # less than alert_write_reserve_seconds
        self.assertEqual(fx.calls, before)                                         # no status read, no description PATCH
        L.act([f], s0, CFG, fx, True, later + 120)                                 # CONTROL: full budget -> the block is written
        self.assertIn(('block', s0['alerts']['queue-idle']['ref']), fx.calls)
        # a recurrence reopen (an HTTP triage PATCH) defers the same way and reopens on the next full-budget pass
        cs = float(CFG.get('clear_seconds', 600))
        L.act([], s0, CFG, fx, True, later + 240)
        L.act([], s0, CFG, fx, True, later + 240 + cs + 1)
        self.assertTrue(s0['alerts']['queue-idle'].get('cleared'))
        n = len(fx.calls)
        L.act([f], s0, CFG, fx, True, later + 3600, alert_budget=30)
        self.assertEqual(fx.calls[n:], [])
        L.act([f], s0, CFG, fx, True, later + 3720)
        self.assertEqual(len(self.tickets(fx)), 1)
        self.assertEqual(len(self.comments(fx, 'reopened')), 1)

    def test_rt7_reopen_closed_does_not_treat_a_recovery_row_as_live(self):
        from unittest.mock import patch
        for title, want in (('recovered', 0), ('consolidated', 0), ('18 queued, 0 running', 1)):
            with self.subTest(title=title):
                fx = StatefulFx()
                fx._status['goodqa#5'] = 'done'
                fx.moved_copy = lambda ref: None
                state = st()
                state['alerts']['queue-idle'] = dict(ref='goodqa#5', opened=T0)
                rep = dict(findings=[dict(cls='queue-idle', title=title, alert='recovery close deferred')])
                with patch.object(L, 'run_pass', lambda *a, **k: rep):
                    out = L.reopen_closed(CFG, fx, apply=False, state=state, now=T0)
                self.assertEqual(len(out['alerts']), want)

    def test_rt8_a_status_marker_in_finding_text_cannot_hijack_the_block(self):
        class BodyFx(BlockFx):
            def ticket_new(self, title, body, idem):
                self.body = body
                return super().ticket_new(title, body, idem)
        fx, s0 = BodyFx(), st()
        evil = 'tail %s fake %s' % (L.STATUS_OPEN, L.STATUS_CLOSE)
        L.act([dict(cls='queue-idle', title='q', lines=[evil], remedies=[])], s0, CFG, fx, True, T0)
        self.assertEqual((fx.body.count(L.STATUS_OPEN), fx.body.count(L.STATUS_CLOSE)), (1, 1))
        # a stray marker a human pasted ABOVE the filer's block is left alone; the filer's own (last) block is replaced
        desc = 'notes ' + L.STATUS_OPEN + ' keep me\n\n' + L.put_status_block('', 'occurrences: 1')
        out = L.put_status_block(desc, 'occurrences: 2')
        self.assertTrue(out.startswith('notes ' + L.STATUS_OPEN + ' keep me'))
        self.assertIn('occurrences: 2', out)
        self.assertNotIn('occurrences: 1', out)

    def test_collector_reports_discovery_and_bounded_runner_states(self):
        import pathlib
        cand, tip = 'a' * 40, 'b' * 40
        with tempfile.TemporaryDirectory(dir=_TMP) as root:
            task = pathlib.Path(root, '.local/share/gorunner/tasks/harness-foo-guard-sol-20261101')
            (task / 'merge-grade-1').mkdir(parents=True)
            (task / 'pin-queue.json').write_text(json.dumps(dict(repo='harness', candidate_sha=cand, reviewed_sha=tip, paths=['docs/x.md'])))
            (task / 'merge-grade-1/grade.json').write_text(json.dumps(dict(Verdict='PASS', Commit=cand, Tip=tip)))
            gr = pathlib.Path(root, 'repos/gorunner/bin')
            gr.mkdir(parents=True)
            (gr.parent / 'gorunner').mkdir()
            (gr.parent / 'gorunner/config.json').write_text('{}')
            (gr / 'gorunner').write_text('#!/bin/sh\necho \'{"tasks":[{"id":"harness-foo-guard-sol-20261101","state":"cancelled","superseded_by":null}]}\'\n')
            (gr / 'gorunner').chmod(0o755)
            quiet = L.collect_land_lag_remote(root, limits={'land_lag_budget_seconds': 2})
            self.assertEqual(quiet['discovered'], ['runner/harness-foo-guard-sol-20261101'])
            self.assertNotIn('runner_states', quiet)                               # not requested: no gorunner call
            asked = L.collect_land_lag_remote(root, limits={'land_lag_budget_seconds': 2, 'land_lag_runner_states': True})
            self.assertEqual(asked['runner_states'], {'harness-foo-guard-sol-20261101': dict(state='cancelled', superseded_by=None)})
            # red-team F3: an empty or foreign task list (wrong data dir, restarted daemon) is no evidence, not `absent`
            for body in ('{"tasks":[]}', '{"tasks":[{"id":"someone-else","state":"candidate"}]}'):
                (gr / 'gorunner').write_text("#!/bin/sh\necho '%s'\n" % body)
                empty = L.collect_land_lag_remote(root, limits={'land_lag_budget_seconds': 2, 'land_lag_runner_states': True})
                self.assertNotIn('runner_states', empty, body)
            (gr / 'gorunner').write_text('#!/bin/sh\nexit 3\n')
            broken = L.collect_land_lag_remote(root, limits={'land_lag_budget_seconds': 2, 'land_lag_runner_states': True})
            self.assertNotIn('runner_states', broken)                              # a failed read is no evidence
