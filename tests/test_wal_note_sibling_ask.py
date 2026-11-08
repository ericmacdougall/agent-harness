"""goodqa#15319 (defect 5): an ask registered in an owner WAL (agent-*.jsonl) was refused from main with "no open ask in this
WAL". Main may resolve it by citing the user's answer; the resolution names the WAL that holds the ask. An unknown ask,
an already resolved one and an ask in a WAL of another session still refuse."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import uuid

HOOKS = Path(__file__).resolve().parents[1] / 'harness/hooks'
sys.path.insert(0, str(Path(__file__).resolve().parent))
SID = '33333333-4444-5555-6666-777777777777'
OTHER = '44444444-5555-6666-7777-888888888888'
ANSWER_UUID = str(uuid.UUID(int=77))


class SiblingAsk(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        self.home = Path(tmp.name)
        self.wals = self.home / '.claude/wals' / SID
        self.wals.mkdir(parents=True)
        (self.home / '.claude/wals' / OTHER).mkdir(parents=True)
        proj = self.home / '.claude/projects/-p'; proj.mkdir(parents=True)
        rec = {'type': 'user', 'uuid': ANSWER_UUID, 'timestamp': '2026-11-04T10:00:00Z', 'sessionId': SID,
               'origin': {'kind': 'human'}, 'message': {'role': 'user', 'content': 'yes go ahead with the change'}}
        (proj / (SID + '.jsonl')).write_text(json.dumps(rec, separators=(',', ':')) + '\n')
        (self.wals / 'main.jsonl').write_text('{"event":"status","note":"x"}\n')
        self.ask = lambda ident, wal: wal.write_text(json.dumps({'at': '2026-11-08T10:00:00+00:00', 'event': 'ask', 'id': ident,
                                                                'note': 'n', 'reason': 'needs the user to decide'}) + '\n')
        self.ask('wabc123456789', self.wals / 'agent-aaa.jsonl')
        self.ask('wdef123456789', self.home / '.claude/wals' / OTHER / 'agent-bbb.jsonl')

    def resolve(self, ref):
        return subprocess.run([sys.executable, str(HOOKS / 'wal_note.py'), '--wal', str(self.wals / 'main.jsonl'),
                               '--event', 'ask_resolved', '--ref', ref, '--note', 'answered', '--decision', 'approved',
                               '--source', 'user:%s/%s "yes go ahead with the change"' % (SID, ANSWER_UUID)],
                              capture_output=True, text=True, env=dict(os.environ, HOME=str(self.home), HARNESS_PROVENANCE_OFFLINE='1'))

    def test_main_resolves_an_ask_held_by_an_owner_wal(self):
        done = self.resolve('wabc123456789')
        self.assertEqual(done.returncode, 0, done.stderr)
        rows = [json.loads(line) for line in (self.wals / 'main.jsonl').read_text().splitlines()]
        self.assertEqual(rows[-1]['ref'], 'wabc123456789')
        self.assertEqual(rows[-1]['ask_wal'], 'agent-aaa')
        again = self.resolve('wabc123456789')
        self.assertEqual(again.returncode, 2, 'resolved twice')

    def test_control_unknown_and_other_session_asks_still_refuse(self):
        self.assertEqual(self.resolve('wfff123456789').returncode, 2)
        self.assertEqual(self.resolve('wdef123456789').returncode, 2)

    def test_red_team_owner_cannot_close_main_or_other_owner_asks(self):
        self.ask('wmain1234567', self.wals / 'main.jsonl')
        self.ask('wother123456', self.wals / 'agent-bbb.jsonl')
        for wal, ref in (('agent-aaa.jsonl', 'wmain1234567'), ('agent-aaa.jsonl', 'wother123456')):
            done = subprocess.run([sys.executable, str(HOOKS / 'wal_note.py'), '--wal', str(self.wals / wal), '--event', 'ask_resolved',
                                   '--ref', ref, '--note', 'x', '--source', 'user:%s/%s "yes go ahead with the change"' % (SID, ANSWER_UUID)],
                                  capture_output=True, text=True, env=dict(os.environ, HOME=str(self.home), HARNESS_PROVENANCE_OFFLINE='1'))
            self.assertEqual(done.returncode, 2, (wal, ref, done.stdout))

    def test_red_team_second_resolution_is_refused_after_the_wal_grows_past_4_mib(self):
        self.assertEqual(self.resolve('wabc123456789').returncode, 0)
        with open(self.wals / 'main.jsonl', 'a') as handle:
            handle.write(('{"event":"status","note":"%s"}\n' % ('x' * 1000)) * 4500)
        self.assertGreater((self.wals / 'main.jsonl').stat().st_size, 4 << 20)
        self.assertEqual(self.resolve('wabc123456789').returncode, 2)

    def test_red_team_symlinked_sibling_wal_does_not_reach_another_session(self):
        other_main = self.home / '.claude/wals' / OTHER / 'main.jsonl'
        self.ask('wsym12345678', other_main)
        (self.wals / 'agent-link.jsonl').symlink_to(other_main)
        self.assertEqual(self.resolve('wsym12345678').returncode, 2)

    def test_m2_fifo_and_unbounded_files_refuse_instead_of_hanging(self):
        import time
        os.mkfifo(str(self.wals / 'agent-zfifo.jsonl'))
        started = time.monotonic()
        done = subprocess.run([sys.executable, str(HOOKS / 'wal_note.py'), '--wal', str(self.wals / 'main.jsonl'), '--event', 'ask_resolved',
                               '--ref', 'wabc123456789', '--note', 'x', '--source', 'user:%s/%s "yes go ahead with the change"' % (SID, ANSWER_UUID)],
                              capture_output=True, text=True, timeout=20,
                              env=dict(os.environ, HOME=str(self.home), HARNESS_PROVENANCE_OFFLINE='1'))
        self.assertLess(time.monotonic() - started, 15)
        self.assertEqual(done.returncode, 2, done.stdout + done.stderr)
        os.unlink(self.wals / 'agent-zfifo.jsonl')
        # an oversized sibling with no newline is refused rather than read whole
        big = self.wals / 'agent-zbig.jsonl'
        with open(big, 'wb') as handle:
            handle.truncate(1200 << 20)  # sparse: no disk used, larger than the scan cap
        started = time.monotonic()
        done = subprocess.run([sys.executable, str(HOOKS / 'wal_note.py'), '--wal', str(self.wals / 'main.jsonl'), '--event', 'ask_resolved',
                               '--ref', 'wabc123456789', '--note', 'x', '--source', 'user:%s/%s "yes go ahead with the change"' % (SID, ANSWER_UUID)],
                              capture_output=True, text=True, timeout=30,
                              env=dict(os.environ, HOME=str(self.home), HARNESS_PROVENANCE_OFFLINE='1'))
        self.assertLess(time.monotonic() - started, 20)
        self.assertEqual(done.returncode, 2, done.stdout + done.stderr)
        os.unlink(big)
        # a single line longer than the line cap that mentions the ask could hold its resolution: refuse, never skip it
        with open(self.wals / 'agent-zline.jsonl', 'wb') as handle:
            handle.write(b'{"event":"ask_resolved","ref":"wabc123456789","pad":"' + b'x' * (9 << 20) + b'"}\n')
        done = subprocess.run([sys.executable, str(HOOKS / 'wal_note.py'), '--wal', str(self.wals / 'main.jsonl'), '--event', 'ask_resolved',
                               '--ref', 'wabc123456789', '--note', 'x', '--source', 'user:%s/%s "yes go ahead with the change"' % (SID, ANSWER_UUID)],
                              capture_output=True, text=True, timeout=30,
                              env=dict(os.environ, HOME=str(self.home), HARNESS_PROVENANCE_OFFLINE='1'))
        self.assertEqual(done.returncode, 2, done.stdout + done.stderr)


if __name__ == '__main__':
    unittest.main()
