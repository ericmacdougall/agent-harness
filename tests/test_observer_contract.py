"""Observer contract (docs/observer.md, goodqa#14547): the golden sample and the rules both sides enforce."""

import hashlib
import json
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / 'docs' / 'observer-sample.json'
# Pinned in both repositories; bump the schema when the sample changes.
PINNED_SHA256 = 'aefcb5a6983e8bfd75fa75b6297d8c0416228dd4fa3a642f1680b039e559de83'
ATTRIBUTION_KEYS = {'task', 'agent', 'ticket', 'session', 'run_id'}
STATES = {'attributed', 'unattributed', 'conflict', 'hook-ssh'}
TOKEN = re.compile(r'^(proc|ps):.+$')


def load():
    raw = SAMPLE.read_bytes()
    return json.loads(raw), hashlib.sha256(raw).hexdigest()


class GoldenSample(unittest.TestCase):
    def test_pinned_sha_matches_the_sample(self):
        _, sha = load()
        pinned = (ROOT / 'docs' / 'observer-sample.sha256').read_text().strip()
        self.assertEqual(sha, pinned); self.assertEqual(sha, PINNED_SHA256)

    def test_shape_and_rules(self):
        doc, _ = load()
        self.assertEqual(doc['schema'], 1)
        for volume in doc['volumes']:
            self.assertTrue(volume['fsid'].startswith('0x'))
            self.assertIsInstance(volume['mounts'], list)
            for key in ('total_bytes', 'free_bytes', 'growth_bytes_per_hour'):
                self.assertIsInstance(volume[key], (int, float))
            self.assertLessEqual(len(volume['top_growing_dirs']), 5)
        self.assertLessEqual(len(doc['top_writers']), 5)
        for sample in doc['samples']:
            self.assertEqual(sample['schema'], 1)
            for key in ('pid', 'ppid', 'uid'):
                self.assertIsInstance(sample[key], int)
            self.assertTrue(sample['pgid'] is None or isinstance(sample['pgid'], int))
            self.assertRegex(sample['start_token'], TOKEN)
            self.assertLessEqual(len(sample['argv_masked']), 512)
            attribution = sample['attribution']
            self.assertIn(attribution['state'], STATES)
            if attribution['state'] in ('attributed', 'hook-ssh'):
                self.assertTrue(ATTRIBUTION_KEYS <= set(attribution)); self.assertIn(attribution['via'], ('env', 'ancestry', 'both'))
                self.assertRegex(attribution['run_id'], r'^[0-9a-f]{32}$')
            elif attribution['state'] == 'conflict':
                self.assertEqual(set(attribution['env']), ATTRIBUTION_KEYS); self.assertEqual(set(attribution['ancestry']), ATTRIBUTION_KEYS)
                self.assertNotEqual(attribution['env'], attribution['ancestry'])
            else:
                self.assertEqual(set(attribution), {'state'})

    def test_no_secret_or_raw_environment_ever_appears(self):
        raw = SAMPLE.read_text()
        for forbidden in ('SECRET_X', 'Authorization: Bearer', 'AGENT_HARNESS_TASK=', 'PATH=', 'HOME='):
            self.assertNotIn(forbidden, raw)
        # Masked tokens are the only trace of a secret-shaped argument.
        self.assertIn('--token ****', raw)

    def test_every_state_is_represented_so_both_sides_test_it(self):
        doc, _ = load()
        self.assertEqual({s['attribution']['state'] for s in doc['samples']}, STATES)


if __name__ == '__main__':
    unittest.main()
