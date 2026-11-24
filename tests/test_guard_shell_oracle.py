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


class Runner(unittest.TestCase):
    """The shells phase records a row only from a sandbox that finished and whose canary ran everywhere (goodqa#17073:
    run2 at 14:16Z on the dev host died with an empty `sandbox failed`; a died or blind sandbox must never read as
    "no shell ran it")."""

    # each shell's own message for a rejected text, as bash 5.2, dash and zsh 5.9 print it on the dev host
    MESSAGES = {'bash': b"/usr/bin/bash: -c: line 2: syntax error: unexpected end of file",
                'bash_file': b"probe.sh: line 2: syntax error near unexpected token `)'",
                'dash': b'/usr/bin/dash: 1: Syntax error: end of file unexpected (expecting ")")',
                'dash_eval': b'/usr/bin/dash: 1: eval: Syntax error: end of file unexpected (expecting ")")',
                'zsh': b"zsh:1: parse error near `('", 'zsh_eval': b"(eval):1: parse error near `('"}

    def inner_syntax(self):
        """The pattern the sandboxed script really compiles, read from its own text."""
        import ast
        import re
        line = next(x for x in oracle.INNER.splitlines() if x.startswith('SYNTAX = re.compile('))
        return re.compile(ast.literal_eval(line[len('SYNTAX = re.compile('):-1]))

    def test_every_shells_rejection_is_read_as_one(self):
        rx = self.inner_syntax()
        self.assertEqual([k for k, m in self.MESSAGES.items() if not rx.search(m)], [])
        for harmless in (b'', b'mk: not found', b'/usr/bin/bash: line 1: x: command not found'):
            self.assertIsNone(rx.search(harmless))

    @staticmethod
    def sent(n=3):
        rows = [{'id': 'I%07d' % i, 'text': 'x', 'shells': list(oracle.SHELLS), 'modes': ['c', 'eval']}
                for i in range(n)]
        return [oracle.canary_row(rows)] + rows

    @staticmethod
    def result(sent, canary_ran=True, drop=()):
        rows = []
        for i, r in enumerate(sent):
            if r['id'] in drop:
                continue
            on = canary_ran if i == 0 else False
            rows.append({'id': r['id'], 'ran': {'%s.%s' % (s, m): on for s in r['shells'] for m in r['modes']},
                         'late': [], 'syntax': []})
        return {'rows': rows, 'tail': []}

    def test_a_chunk_comes_back_without_its_canary(self):
        sent = self.sent()
        got = oracle.accept_chunk(sent, self.result(sent))
        self.assertEqual([g['id'] for g in got], [r['id'] for r in sent[1:]])
        self.assertTrue(all(g['late_ran'] is False and 'late' not in g for g in got))

    def test_a_chunk_whose_canary_did_not_run_everywhere_is_not_recorded(self):
        sent = self.sent()
        res = self.result(sent)
        res['rows'][0]['ran']['dash.eval'] = False  # a full disk, a broken record log, a shell that never started
        with self.assertRaises(oracle.ChunkFailed):
            oracle.accept_chunk(sent, res)
        with self.assertRaises(oracle.ChunkFailed):
            oracle.accept_chunk(sent, self.result(sent, canary_ran=False))

    def test_a_chunk_missing_a_row_is_not_recorded(self):
        sent = self.sent()
        with self.assertRaises(oracle.ChunkFailed):
            oracle.accept_chunk(sent, self.result(sent, drop={sent[2]['id']}))
        with self.assertRaises(oracle.ChunkFailed):
            oracle.accept_chunk(sent, {'rows': [], 'tail': []})

    def test_a_signal_is_named(self):
        self.assertIn('signal=SIGXCPU', oracle.sandbox_failure(128 + 24, ''))
        self.assertIn('signal=SIGKILL', oracle.sandbox_failure(-9, ''))
        self.assertNotIn('signal', oracle.sandbox_failure(1, 'bwrap: setting up uid map'))
        self.assertIn('rc=1', oracle.sandbox_failure(1, 'bwrap: setting up uid map'))

    def test_a_failed_chunk_is_retried_in_halves_and_a_twice_failed_text_stops_the_run(self):
        chunks = [[{'id': 'I%07d' % (10 * k + i)} for i in range(4)] for k in range(3)]
        calls = []

        def flaky(chunk, name):  # chunk 1 dies once, as a sandbox killed by the host would
            calls.append(name)
            if name == 'c00001':
                raise oracle.ChunkFailed('rc=137 signal=SIGKILL')
            return [{'id': r['id']} for r in chunk]
        recorded = []
        retried = oracle.run_all(chunks, flaky, 2, recorded.extend, log=lambda s: None)
        self.assertEqual(retried, [1])
        self.assertEqual(sorted(r['id'] for r in recorded), sorted(r['id'] for c in chunks for r in c))
        self.assertIn('c00001-r0', calls)
        self.assertIn('c00001-r1', calls)

        def poisoned(chunk, name):  # one text kills every sandbox it is in
            if any(r['id'] == 'I0000012' for r in chunk):
                raise oracle.ChunkFailed('rc=-9 signal=SIGKILL')
            return [{'id': r['id']} for r in chunk]
        recorded = []
        with self.assertRaises(oracle.ChunkFailed) as cm:
            oracle.run_all(chunks, poisoned, 2, recorded.extend, log=lambda s: None)
        self.assertIn('failed twice', str(cm.exception))
        self.assertNotIn('I0000012', [r['id'] for r in recorded])  # never recorded as "not run"


class Compare(unittest.TestCase):
    """The reverse split: a newly refused text no shell ran is `rejected_everywhere` only when every shell and mode
    rejected it; one shell accepting it makes it `accepted` (a possible cost to a real command)."""

    def compare(self, rows, base, head):
        import contextlib
        import io
        with tempfile.TemporaryDirectory(prefix='oracle-compare-test-') as tmp:
            paths = {}
            for name, data in (('results', rows), ('base', base), ('head', head)):
                paths[name] = os.path.join(tmp, name)
                with open(paths[name], 'w') as f:
                    if name == 'results':
                        f.write(''.join(json.dumps(r) + '\n' for r in data))
                    else:
                        json.dump(data, f)
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                oracle.compare_phase(SimpleNamespace(results=paths['results'], base=paths['base'],
                                                     head=paths['head'], top=5))
        text = buf.getvalue()
        return json.loads(text[:text.index('\nhead_findings')])

    @staticmethod
    def row(i, ran=(), syntax=()):
        keys = ['%s.%s' % (s, m) for s in oracle.SHELLS for m in ('c', 'eval')]
        return {'id': 'I%07d' % i, 'family': 'E', 'skel': 'echo sp - sp X', 'template': '{X}',
                'ran': {k: k in ran for k in keys}, 'late_ran': False, 'syntax': [k for k in keys if k in syntax]}

    def test_the_reverse_split_and_the_forward_counts(self):
        keys = ['%s.%s' % (s, m) for s in oracle.SHELLS for m in ('c', 'eval')]
        rows = [self.row(0, syntax=keys),  # every shell rejects it
                self.row(1, syntax=[k for k in keys if not k.startswith('zsh')]),  # zsh accepts it
                self.row(2),  # every shell accepts it, none reaches the marker
                self.row(3, ran=['bash.c']),  # a base finding the head closes
                self.row(4)]  # a base over-refusal the head drops
        allow, block = ['allow', '', 'allow', ''], ['block', '[r]', 'block', 'r']
        out = self.compare(rows, [allow, allow, allow, allow, block], [block, block, block, block, allow])
        self.assertEqual(out['not_run_allowed_to_refused']['E'],
                         {'command_guard rejected_everywhere': 1, 'command_guard accepted': 2,
                          'kill_guard rejected_everywhere': 1, 'kill_guard accepted': 2})
        self.assertEqual(out['reverse_accepted_by']['E'],
                         {'command_guard zsh': 1, 'command_guard bash+dash+zsh': 1,
                          'kill_guard zsh': 1, 'kill_guard bash+dash+zsh': 1})
        self.assertEqual(out['ran_allowed_to_refused']['E'], {'command_guard': 1, 'kill_guard': 1})
        self.assertEqual(out['not_run_refused_to_allowed']['E'], {'command_guard': 1, 'kill_guard': 1})
        self.assertEqual(out['ran_refused_to_allowed'], {})

    def test_results_without_a_syntax_field_are_refused(self):
        r = self.row(0)
        del r['syntax']
        with self.assertRaises(SystemExit):
            self.compare([r], [['allow', '', 'allow', '']], [['block', '[r]', 'block', 'r']])


@unittest.skipUnless(shutil.which('bwrap') and all(shutil.which(s) for s in oracle.SHELLS),
                     'dev-host check: needs bubblewrap, bash, dash and zsh')
class Sandbox(unittest.TestCase):
    def test_one_chunk_records_runs_and_each_shells_rejection(self):
        rows = [{'id': 'I0000001', 'text': oracle.MARK + 'I0000001', 'shells': list(oracle.SHELLS),
                 'modes': ['c', 'eval']},
                {'id': 'I0000002', 'text': '( ' + oracle.MARK + 'I0000002', 'shells': list(oracle.SHELLS),
                 'modes': ['c', 'eval']},
                {'id': 'I0000003', 'text': 'false && ' + oracle.MARK + 'I0000003', 'shells': list(oracle.SHELLS),
                 'modes': ['c', 'eval']}]
        with tempfile.TemporaryDirectory(prefix='oracle-sandbox-test-') as tmp:
            got = {g['id']: g for g in oracle.run_chunk(rows, Path(tmp))}
        keys = {'%s.%s' % (s, m) for s in oracle.SHELLS for m in ('c', 'eval')}
        self.assertEqual({k for k, v in got['I0000001']['ran'].items() if v}, keys)
        self.assertEqual(set(got['I0000002']['syntax']), keys)  # dash's `Syntax error` included
        self.assertFalse(any(got['I0000002']['ran'].values()))
        self.assertEqual(got['I0000003']['syntax'], [])
        self.assertFalse(any(got['I0000003']['ran'].values()))


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
