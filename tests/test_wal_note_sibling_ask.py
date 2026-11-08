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


if __name__ == '__main__':
    unittest.main()
