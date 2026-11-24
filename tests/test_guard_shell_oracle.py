"""The differential shell oracle (tests/guard_shell_oracle.py) as a rerunnable test (goodqa#17059, goodqa#17073).

`Vocabulary` runs anywhere and is cheap: it checks that the oracle can only ever hand a shell a marker.
`Property` is a dev-host job, not part of the Mac's focused suite. It runs every generated text under bash, dash and
zsh in a bubblewrap sandbox, then asks both guards of this checkout, and fails when any shell ran the marker and a
guard allowed the twin, outside the seeds the oracle names as open elsewhere (SEED_OPEN, CONTEXT_OPEN). Run it with:
  HARNESS_SHELL_ORACLE=1 python3 -B -m unittest tests.test_guard_shell_oracle
HARNESS_SHELL_ORACLE_FAMILIES narrows the families (default: every family; the full run is about 400,000 texts).
It prints counts and skeletons only, never a text.
"""
import importlib.util
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location('guard_shell_oracle', ROOT / 'tests' / 'guard_shell_oracle.py')
oracle = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(oracle)


class Vocabulary(unittest.TestCase):
    def test_marker_has_the_twins_shape(self):
        for twin in oracle.TWINS.values():
            self.assertEqual(len(twin.split()), len((oracle.MARK + 'I0000001').split()))

    def test_a_template_holding_a_twin_is_refused(self):
        for twin in oracle.TWINS.values():
            for t in (twin + '; {X}', 'echo $(' + twin + ') {X}', twin.split()[0] + ' x; {X}'):
                with self.assertRaises(ValueError):
                    oracle.check_template(t)
        with self.assertRaises(ValueError):
            oracle.check_template('echo no marker')

    def test_every_seed_and_context_is_marker_only(self):
        for _, t, _ in oracle.SEEDS:
            oracle.check_template(t)
        for ctx in oracle.CONTEXTS.values():
            for b in oracle.CONTEXT_BLANKS.values():
                oracle.check_template(ctx.replace('{B}', b))

    def test_open_seeds_name_their_owner(self):
        names = {name for name, _, _ in oracle.SEEDS}
        for name, owner in oracle.SEED_OPEN.items():
            self.assertIn(name, names)
            self.assertIn('goodqa#', owner)
        for seed in oracle.CONTEXT_OPEN.values():
            self.assertIn(seed, oracle.SEED_OPEN)


@unittest.skipUnless(os.environ.get('HARNESS_SHELL_ORACLE') == '1' and shutil.which('bwrap'),
                     'dev-host job: needs bubblewrap and HARNESS_SHELL_ORACLE=1')
class Property(unittest.TestCase):
    def test_no_shell_runs_what_a_guard_allows(self):
        families = os.environ.get('HARNESS_SHELL_ORACLE_FAMILIES', 'ERCNSM')
        jobs = int(os.environ.get('HARNESS_SHELL_ORACLE_JOBS', str(max(1, (os.cpu_count() or 2) - 2))))
        with tempfile.TemporaryDirectory(prefix='oracle-test-') as tmp:
            results = Path(tmp) / 'results.jsonl'
            oracle.shells_phase(SimpleNamespace(seed=1, sampled=20000, limit=0, families=families, jobs=jobs,
                                                chunk=400, out=str(results)))
            rows = [json.loads(line) for line in open(results)]
            verdicts = oracle.judge_rows([r['template'] for r in rows], ROOT / 'harness' / 'hooks', jobs)
        found = {}
        for r, v in zip(rows, verdicts):
            if oracle.ran_any(r) and not oracle.open_seed(r):
                for g, at in (('command_guard', 0), ('kill_guard', 2)):
                    if v[at] != 'block':
                        key = '%s %s %s' % (g, r['family'], oracle.skel_class(r['skel']))
                        found[key] = found.get(key, 0) + 1
        print('texts %d, ran in some shell %d' % (len(rows), sum(1 for r in rows if oracle.ran_any(r))),
              file=sys.stderr)
        self.assertEqual({}, found, 'a shell ran the marker and a guard allowed the twin (counts by skeleton)')


if __name__ == '__main__':
    unittest.main()
