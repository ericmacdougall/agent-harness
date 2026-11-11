"""Tests for harness/hooks/kill_guard.py (GoodQA #14506, matrix X05).

Every command string here is DATA handed to kill_guard.decide() or piped as text to the hook launcher, which only
analyses it; nothing in this file executes a corpus row (safety rules S1/S3). Real signals are sent only by
tests/live_kill_canary.py, on dev2, in a scratch HOME (rule S2).

KG_HOOKS_DIR points the suite at another directory (for example one without kill_guard.py) to show it failing first.
"""

import ast
import contextlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from io import StringIO
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
HOOKS = Path(os.environ.get('KG_HOOKS_DIR') or ROOT / 'harness/hooks')
sys.path.insert(0, str(HOOKS))

import kill_guard as kg  # noqa: E402

CORPUS = json.loads((Path(__file__).resolve().parent / 'kill_guard_corpus.json').read_text(encoding='utf-8'))
ROWS, WORLD = CORPUS['rows'], CORPUS['world']
POSITIVE_FLOOR, NEGATIVE_FLOOR = 120, 80
TAG_FLOORS = {'verb': 40, 'wrapper': 20, 'pidfeed': 10, 'ssh': 10, 'netwatch': 6, 'interpreter': 6, 'obfuscation': 6,
              'listing': 8, 'ownership': 20, 'text': 20, 'signal0': 4, 'job': 4, 'windows': 3, 'delayed': 3, 'spawn': 2}
LITERAL = 'netwatch orphans --kill --pid'
CWD = WORLD['worktree'] + '/sub'
POLICY = kg.load_policy()


class FakeProbe:
    """Process facts from the corpus world. Never touches a real process."""

    def __init__(self, world):
        self.pids = {int(k): v for k, v in world['pids'].items()}
        self.chain = {os.getpid(): world['ancestors'][1], world['ancestors'][1]: world['ancestors'][0],
                      world['ancestors'][0]: 1}

    def _get(self, pid, key):
        entry = self.pids.get(pid)
        return None if entry is None else entry[key]

    def uid(self, pid):
        value = self._get(pid, 'uid')
        return os.getuid() if value == 1000 else value  # 1000 in the corpus means "the caller"

    def comm(self, pid):
        return self._get(pid, 'comm')

    def cwd(self, pid):
        return self._get(pid, 'cwd')

    def argv(self, pid):
        return self._get(pid, 'argv')

    def start(self, pid):
        return self._get(pid, 'start')

    def ppid(self, pid):
        return self.chain.get(pid)


def fake_runner(world):
    def run(argv, timeout=2.0, cwd=None, env=None):
        if 'rev-parse' in argv:
            return world['worktree'] + '\n'
        if 'worktree' in argv:
            return 'worktree %s\n\nworktree %s\n\nworktree %s\n' % (world['worktree'], world['nested'], world['sibling'])
        return None
    return run


class WorldCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = self.tmp.name
        env = mock.patch.dict(os.environ, {'HOME': self.home})
        env.start()
        self.addCleanup(env.stop)
        patch = mock.patch.object(kg, 'read_ledger', lambda root, home=None, max_lines=2000: [tuple(x) for x in WORLD['ledger']])
        patch.start()
        self.addCleanup(patch.stop)

    def ownership(self, world=WORLD):
        return kg.Ownership(world['worktree'] + '/sub', home=world['home'], probe=FakeProbe(world),
                            runner=fake_runner(world), policy=POLICY)

    def decide(self, cmd, ps=False, world=WORLD, cwd=CWD):
        return kg.decide(cmd, cwd=cwd, ps=ps, ownership=self.ownership(world), policy=POLICY, home=self.home)


def judge_rows(rows, decide_fn):
    """Names of rows whose verdict differs from the expectation. Shared by the corpus tests and the mutant tests."""
    bad = []
    for row in rows:
        verdict = decide_fn(row)[0]
        if (row['expect'] == 'block') != (verdict == 'block'):
            bad.append('%s expected %s got %s' % (row['id'], row['expect'], verdict))
    return bad


class GrammarCorpus(WorldCase):
    """The closed kill grammar: every shape that ever got past the guard, plus what must keep working."""
    SHAPES = {'WS', 'WV', 'VH', 'WSOK', 'EH', 'EHOK', 'XH', 'cc473a3', 'ce11b1e', '1949bbc', 'a9432ef', '4a6982f', 'a03f8ac', 'F6', 'F7', 'F8', 'F9', 'R2', 'R3', 'R3OK', 'R4', 'R5', 'R4OK', 'RR', 'TC', 'AH', 'RROK', 'PKILL', 'OK', 'ECH', 'ECHOK', 'ENE', 'EHV', 'EHVOK', 'EIF'}

    @classmethod
    def setUpClass(cls):
        path = Path(__file__).resolve().parent / 'kill_guard_grammar_corpus.json'
        cls.rows = json.loads(path.read_text(encoding='utf-8'))['rows']

    def test_every_shape_has_rows(self):
        counts = {}
        for row in self.rows:
            counts[row['shape']] = counts.get(row['shape'], 0) + 1
        self.assertEqual(set(counts), self.SHAPES)
        for shape, count in counts.items():
            self.assertGreaterEqual(count, 6, shape)
        ids = [r['id'] for r in self.rows]
        self.assertEqual(len(ids), len(set(ids)))

    def test_verdicts(self):
        bad = judge_rows(self.rows, lambda r: self.decide(r['cmd']))
        self.assertEqual(bad, [], '\n'.join(bad[:40]))

    def test_generic_pkill_blocks_through_the_hook_as_a_deny(self):
        # Through the launcher, so a warn-only path cannot satisfy it (goodqa#14617).
        for cmd in ('ssh dev2 \'pkill -f "unittest discover"; sleep 1\'', 'killall node'):
            payload = json.dumps({'tool_name': 'Bash', 'tool_input': {'command': cmd}, 'cwd': self.home})
            done = subprocess.run([sys.executable, str(HOOKS / 'kill_guard.py'), 'hook'], input=payload, text=True,
                                  capture_output=True, timeout=30, env=dict(os.environ, HOME=self.home))
            self.assertEqual(done.returncode, 2, cmd)
            self.assertIn('BLOCKED', done.stderr, cmd)
            self.assertIn(LITERAL, done.stderr, cmd)


class Corpus(WorldCase):
    def rows(self, expect):
        return [r for r in ROWS if r['expect'] == expect]

    def test_corpus_is_not_vacuous(self):
        pos, neg = self.rows('block'), self.rows('allow')
        self.assertGreaterEqual(len(pos), POSITIVE_FLOOR)
        self.assertGreaterEqual(len(neg), NEGATIVE_FLOOR)
        ids = [r['id'] for r in ROWS]
        self.assertEqual(len(ids), len(set(ids)))
        for row in ROWS:
            self.assertIn(row['expect'], ('block', 'allow'), row['id'])
            self.assertTrue(row['cmd'].strip(), row['id'])
        for tag, floor in TAG_FLOORS.items():
            self.assertGreaterEqual(sum(1 for r in ROWS if tag in r['tags']), floor, 'tag %s' % tag)

    def test_positive_rows_blocked(self):
        bad = judge_rows(self.rows('block'), lambda r: self.decide(r['cmd'], ps=r.get('ps', False)))
        self.assertEqual(bad, [], '\n'.join(bad[:40]))

    def test_negative_rows_allowed(self):
        bad = judge_rows(self.rows('allow'), lambda r: self.decide(r['cmd'], ps=r.get('ps', False)))
        self.assertEqual(bad, [], '\n'.join(bad[:40]))

    def test_every_verb_in_the_table_has_a_row(self):
        text = ' '.join(r['cmd'] for r in self.rows('block'))
        for verb in POLICY['broad_verbs'] + ['fuser', 'taskkill', 'Stop-Process', 'systemctl kill', 'launchctl kill',
                                              'os.kill', 'process.kill', 'psutil', 'xargs', 'netwatch']:
            self.assertIn(verb.lower(), text.lower(), verb)

    def test_twins_differ_only_in_the_risky_token(self):
        """Every positive verb row has a negative twin quoting the same text, so block-everything fails one of them."""
        verbs = {r['cmd'] for r in ROWS if r['id'].startswith('P-verb') and r['id'].endswith('-plain')}
        text_rows = ' '.join(r['cmd'] for r in ROWS if r['id'].startswith('N-text'))
        for verb in verbs:
            self.assertIn(verb, text_rows)


class ClobberReadings(WorldCase):
    """zsh takes `>! w` as one operator and bash as `>` onto a file named `!`, and the shared analyzer judges a script under
    both (GoodQA #14657). bash runs `kill` in `>! kill 4004` and zsh writes a file with that name, so losing a reading loses
    the kill. These rows are strings handed to decide(); nothing is run or signalled."""
    # Three scripts holding `>!` use up the forks, so a fourth gets only zsh's reading.
    TOO_DEEP = "bash -c 'echo a >! b; bash -c \"echo c >! d; bash -c \\\"echo e >! f; bash -c \\\\\\\"echo g >! h; %s\\\\\\\"\\\"\"'"

    def test_each_reading_has_its_own_words_tagged(self):
        # (N) cuts the command at 4001. Only bash's reading has kill as a word, so tagging only the first reading misses 4004.
        for text in ('>! kill 4001(N) 4004', '>! K=(kill); $K 4004', "bash -c '>! kill 4001(N) 4004'",
                     'for p in 4004; do echo "kill $p"; done | >! sh'):
            with self.subTest(text=text):
                self.assertEqual(self.decide(text)[0], 'block')

    def test_a_reading_with_no_kill_refuses_nothing(self):
        for text in ('echo x >! y(N)', 'ls >! kill', 'echo x >! kill 4004', '>! y echo 4001(N) 4004', '>! kill',
                     'echo kill >! y', 'echo ok >! y | cat'):
            with self.subTest(text=text):
                self.assertEqual(self.decide(text)[0], 'allow')

    def test_a_kill_under_only_one_reading_is_refused(self):
        for text in ('>! y kill 4004', '>! echo kill 4004', 'echo kill 4004 | sh >! y'):
            with self.subTest(text=text):
                self.assertEqual(self.decide(text)[0], 'block')

    def test_a_reading_dropped_for_depth_blocks(self):
        # A kill can be spelled without the word (K=ki; K+=ll), so a dropped reading blocks whatever the text says. The
        # harmless rows are the cost, pinned so it is seen.
        for inner in ('>! kill 4004', '>! kill 4001(N) 4004', 'K=ki; K+=ll; >! $K 4004', 'echo ok', '>! ls', '>! y'):
            with self.subTest(inner=inner):
                verdict = self.decide(self.TOO_DEEP % inner)
                self.assertEqual(verdict[:2], ('block', 'readings-capped'))
        self.assertEqual(self.decide('echo x >! y; bash -c "echo x >! y; bash -c \'echo x >! y; bash -c \\">! kill 4004\\"\'"')[0],
                         'block')

    def test_a_remote_shell_string_is_read_both_ways(self):
        # bash on the far side writes `!` and runs `bash -s` on the piped text; zsh writes a file named bash.
        for text in ('echo "kill 4004" | ssh h \'>! bash -s\'', 'echo "kill 4004" | ssh h \'cd /srv; >! sh\'',
                     'echo "kill 4004" | ssh h \'>! y bash -s\''):
            with self.subTest(text=text):
                self.assertEqual(self.decide(text)[0], 'block')
        self.assertEqual(self.decide('echo ok | ssh h \'>! y\'')[0], 'allow')

    def test_readings_that_disagree_block_as_unknown(self):
        # No kill here, but the nested readings end in different state, so the guard cannot say what a later command
        # uses: a cost, pinned so it is seen. Readings that agree are judged.
        for text in ("A=1; eval '>! y A=2'; echo $A", "A=1; bash -c '>! y A=2'; echo $A"):
            with self.subTest(text=text):
                self.assertEqual(self.decide(text)[:2], ('block', 'readings-capped'))
        self.assertEqual(self.decide("A=1; bash -c 'echo ok >! y'; echo $A")[0], 'allow')

    def test_a_reading_dropped_for_budget_blocks(self):
        # The real trigger is time and size, so it moves with load; the patch fixes the decision that follows from it.
        with mock.patch.object(kg._import_base().Budget, 'has_room', return_value=False):
            for text in ('>! kill 4004', 'K=ki; K+=ll; >! $K 4004', 'echo ok >! y'):
                with self.subTest(text=text):
                    self.assertEqual(self.decide(text)[:2], ('block', 'readings-capped'))

    def test_a_stop_with_clobber_text_blocks_a_kill_spelled_without_the_word(self):
        # The script is judged on disk first; 256 KB of clean lines stop the analysis before the recorded text, which
        # holds the kill, is read. Main reads the recorded text and blocks. Blocked is raised directly too, as a control
        # that does not depend on time.
        big = os.path.join(self.home, 'big.sh')
        with open(big, 'w') as handle:
            handle.write(':\n' * 131000)
        text = "x=$(printf 'K=ki; K+=ll; $K 4004' >! %s); bash %s" % (big, big)
        self.assertEqual(self.decide(text)[0], 'block')
        with mock.patch.object(kg._import_base().Budget, 'tick', side_effect=kg._import_base().Blocked('budget')):
            for text in ('K=ki; K+=ll; >! y; $K 4004', 'K=ki; K+=ll; >&! y; $K 4004',
                         # the guard's lexer joins a backslash-newline, so these are judged as `>!` (real shells split
                         # them; refusing errs safe and matches what was analysed)
                         'K=ki; K+=ll; >\\\n! y; $K 4004', 'K=ki; K+=ll; &>\\\n! y; $K 4004',
                         'K=ki; K+=ll; >\\\r\n! y; $K 4004'):
                with self.subTest(text=text):
                    self.assertEqual(self.decide(text)[0], 'block')
            # no clobber text and no kill word: still allows on a stop (Known limits, goodqa#14764)
            self.assertEqual(self.decide('K=ki; K+=ll; $K 4004')[0], 'allow')
        # Too large to analyse at all: Blocked comes before the analyzer exists.
        self.assertEqual(self.decide('K=ki; K+=ll; >! y; $K 4004; : ' + 'x' * 270000)[0], 'block')

    def test_a_kill_found_before_the_analysis_stops_stays_found(self):
        # The kill is judged first; clean lines after it then run the budget out. Main dropped the finding and allowed.
        # Blocked is raised at the next budget check after the kill is recorded, so this does not depend on time.
        cg = kg._import_base()
        real_make, real_tick = kg.make_analyzer_class, cg.Budget.tick
        found = []

        def make(base):
            class StopsAfterAKill(real_make(base)):
                def block(self, rule, reason, pids=()):
                    found.append(rule)
                    return super().block(rule, reason, pids)
            return StopsAfterAKill

        def tick(budget, weight=1):
            if found:
                raise cg.Blocked('budget')
            return real_tick(budget, weight)
        with mock.patch.object(kg, 'make_analyzer_class', make), mock.patch.object(cg.Budget, 'tick', tick):
            verdict = self.decide('K=ki; K+=ll; $K 4004; echo after')
        self.assertEqual(found, ['not-yours'])
        self.assertEqual(verdict[:2], ('block', 'not-yours'))


class Mutants(WorldCase):
    def test_allow_everything_mutant_fails_positives(self):
        bad = judge_rows([r for r in ROWS if r['expect'] == 'block'], lambda r: ('allow', '', '', ()))
        self.assertGreaterEqual(len(bad), POSITIVE_FLOOR)

    def test_block_everything_mutant_fails_negatives(self):
        bad = judge_rows([r for r in ROWS if r['expect'] == 'allow'], lambda r: ('block', 'x', 'x', ()))
        self.assertGreaterEqual(len(bad), NEGATIVE_FLOOR)

    def test_empty_corpus_would_be_caught(self):
        with self.assertRaises(AssertionError):
            self.assertGreaterEqual(len([]), POSITIVE_FLOOR)


class Ownership(WorldCase):
    def check(self, pid):
        return self.ownership().check(pid)

    def test_cwd_proof(self):
        self.assertEqual(self.check(4001)[:2], (True, 'cwd'))

    def test_argv_proof(self):
        self.assertEqual(self.check(4002)[:2], (True, 'argv'))
        self.assertEqual(self.check(4003)[:2], (True, 'argv'))

    def test_argv_arbitrary_arg_not_proof(self):
        self.assertFalse(self.check(4005)[0])
        self.assertFalse(self.check(4014)[0])

    def test_sibling_worktree(self):
        self.assertFalse(self.check(4004)[0])

    def test_prefix_sharing_path(self):
        self.assertFalse(self.check(4006)[0])

    def test_nested_worktree(self):
        self.assertFalse(self.check(4007)[0])

    def test_uid_mismatch(self):
        self.assertEqual(self.check(4008)[1], 'other-user')

    def test_deny_list_ancestors_and_protected(self):
        self.assertEqual(self.check(1)[1], 'protected')
        self.assertEqual(self.check(WORLD['ancestors'][1])[1], 'ancestor')
        self.assertEqual(self.check(os.getpid())[1], 'ancestor')
        self.assertEqual(self.check(4009)[1], 'protected')

    def test_ledger_proof(self):
        self.assertEqual(self.check(4010)[:2], (True, 'ledger'))

    def test_ledger_start_time_mismatch(self):
        self.assertFalse(self.check(4011)[0])

    def test_probe_failure_blocks(self):
        self.assertEqual(self.check(4015)[1], 'uninspectable')
        self.assertEqual(self.check(9999)[1], 'uninspectable')

    def test_cwd_outside_everything(self):
        self.assertFalse(self.check(4012)[0])

    def test_no_worktree_means_unprovable(self):
        own = kg.Ownership('/tmp/not-a-repo', home=WORLD['home'], probe=FakeProbe(WORLD),
                           runner=lambda *a, **k: None, policy=POLICY)
        self.assertEqual(own.check(4001)[1], 'no-worktree')

    def test_main_can_stop_own_git_grep_and_server_but_not_foreign_or_dynamic_pids(self):
        world = json.loads(json.dumps(WORLD))
        world['pids'].update({
            '4101': {'uid': 1000, 'comm': 'git', 'cwd': '/w/own/sub', 'argv': ['git', 'grep', 'needle'], 'start': 'g1'},
            '4102': {'uid': 1000, 'comm': 'server', 'cwd': '/tmp',
                     'argv': ['/w/own/bin/server', '--port', '8080'], 'start': 'g2'},
            '4103': {'uid': 1000, 'comm': 'netwatch', 'cwd': '/w/own', 'argv': ['netwatch', 'daemon'], 'start': 'g3'},
        })
        for pid in (4101, 4102):
            for command in ('kill %d' % pid, 'netwatch orphans --kill --pid %d' % pid):
                with self.subTest(command=command):
                    self.assertEqual(self.decide(command, world=world)[0], 'allow')
        for command in ('kill 4004', 'kill 3901', 'kill 4009', 'kill 4008', 'kill $PID',
                        'kill 4101 4004', 'netwatch orphans --kill --pid 4004',
                        'netwatch orphans --kill --pid 4101,4004', 'netwatch orphans --kill --pid 4103',
                        'netwatch orphans --kill --pid $PID'):
            with self.subTest(command=command):
                self.assertEqual(self.decide(command, world=world)[0], 'block')
        self.assertEqual(self.decide('netwatch orphans --kill --pid 4103', world=world)[1], 'not-yours')

    def test_main_in_home_can_use_netwatch_after_basic_checks(self):
        # #134 made every netwatch kill need a worktree; main runs from HOME, which is never a worktree
        world = json.loads(json.dumps(WORLD))
        world['pids'].update({
            '4201': {'uid': 1000, 'comm': 'node', 'cwd': '/tmp/elsewhere', 'argv': ['node', 'dev.js'], 'start': 'n1'},
            '4202': {'uid': 1000, 'comm': 'zsh', 'cwd': '/tmp', 'argv': ['-zsh'], 'start': 'n2'},
        })

        def decide(cmd, main):
            own = kg.Ownership(world['home'], home=world['home'], probe=FakeProbe(world),
                               runner=lambda *a, **k: None, policy=POLICY)
            return kg.decide(cmd, cwd=world['home'], ownership=own, policy=POLICY, home=self.home, main=main)

        self.assertEqual(decide('netwatch orphans --kill --pid 4201', True)[0], 'allow')
        self.assertEqual(decide('netwatch orphans --kill --pid 4201', False)[:2], ('block', 'not-yours'))  # sub-agent
        self.assertEqual(decide('kill 4201', True)[0], 'block')  # only the netwatch route
        for command in ('netwatch orphans --kill --pid 4008', 'netwatch orphans --kill --pid 4009',
                        'netwatch orphans --kill --pid 4202', 'netwatch orphans --kill --pid %d' % os.getpid(),
                        'netwatch orphans --kill --pid 4201,4008', 'netwatch orphans --kill --all',
                        'netwatch orphans --kill --pid 9999'):
            with self.subTest(command=command):
                self.assertEqual(decide(command, True)[0], 'block')

    def test_hook_payload_without_agent_id_is_main(self):
        seen = []
        real = kg.decide

        def spy(command, **kw):
            seen.append(kw.get('main'))
            return 'allow', '', '', ()
        sid = '11111111-2222-3333-4444-555555555555'
        transcript = Path(self.home) / '.claude' / 'projects' / '-x' / (sid + '.jsonl')
        transcript.parent.mkdir(parents=True)
        transcript.write_text('{}\n')
        base = {'tool_name': 'Bash', 'tool_input': {'command': 'netwatch orphans'}, 'cwd': '/'}
        with mock.patch.object(kg, 'decide', spy):
            for payload in (dict(base, session_id=sid, transcript_path=str(transcript)),
                            dict(base, session_id=sid, transcript_path=str(transcript), agent_id='sub'),
                            base):  # #134 red-team B7: no agent_id is not main (every Codex payload)
                kg.analyze_main(json.dumps(payload).encode())
        self.assertEqual(seen, [True, False, False])
        self.assertIs(kg.decide, real)

    def test_malformed_pids(self):
        for cmd in ('kill 001', 'kill １２３', 'kill 4194305', 'kill +4001', 'kill 0x4001', 'kill 4001abc', 'kill -- -4001'):
            self.assertEqual(self.decide(cmd)[0], 'block', cmd)

    def test_mixed_list(self):
        self.assertEqual(self.decide('kill 4001 4004')[0], 'block')
        self.assertEqual(self.decide('kill 4001 4016')[0], 'allow')

    def test_cd_into_other_worktree(self):
        verdict = self.decide('cd /w/other && kill 4004')
        self.assertEqual(verdict[0], 'block')
        # the proof comes from the tool call's cwd: a cd cannot make another owner's processes yours
        self.assertEqual(self.decide('cd /w/other && kill 4001')[0], 'allow')

    def test_root_rejected(self):
        for top in ('/', WORLD['home'], '/home', '/x'):
            runner = lambda argv, *a, _t=top, **k: _t + '\n' if 'rev-parse' in argv else ''  # noqa: E731
            own = kg.Ownership('/w/own', home=WORLD['home'], probe=FakeProbe(WORLD), runner=runner, policy=POLICY)
            self.assertEqual(own.check(4001)[1], 'no-worktree', top)

    def test_spawn_command_is_analysed_as_typed(self):
        self.assertEqual(self.decide('kill_guard.py spawn -- sleep 60')[0], 'allow')
        self.assertEqual(self.decide('kill_guard.py spawn -- pkill x')[0], 'block')
        self.assertEqual(self.decide('python3 harness/hooks/kill_guard.py spawn --log o.txt -- killall node')[0], 'block')


class RealLedger(unittest.TestCase):
    """The ledger with real files in a scratch HOME and a real temporary git worktree. No process is signalled."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = os.path.realpath(self.tmp.name)
        self.root = os.path.join(self.home, 'wt')
        os.makedirs(self.root)

    def probe(self, start='st1'):
        world = json.loads(json.dumps(WORLD))
        world['pids']['5001'] = {'uid': os.getuid(), 'comm': 'sleep', 'cwd': '/tmp/q', 'argv': ['sleep'], 'start': start}
        world['pids']['5002'] = {'uid': os.getuid(), 'comm': 'sleep', 'cwd': '/tmp/q', 'argv': ['sleep'], 'start': 'x'}
        return FakeProbe(world)

    def own(self, root=None, start='st1', home=None):
        root = root or self.root
        runner = lambda argv, *a, **k: root + '\n' if 'rev-parse' in argv else ''  # noqa: E731
        return kg.Ownership(root, home=home or self.home, probe=self.probe(start), runner=runner, policy=POLICY)

    def test_ledger_roundtrip_and_proof(self):
        kg.append_ledger(self.root, 5001, 'st1', home=self.home)
        self.assertEqual(self.own().check(5001)[:2], (True, 'ledger'))
        self.assertFalse(self.own().check(5002)[0])

    def test_ledger_start_time_mismatch(self):
        kg.append_ledger(self.root, 5001, 'st1', home=self.home)
        self.assertFalse(self.own(start='REUSED').check(5001)[0])

    def test_ledger_other_worktree(self):
        other = os.path.join(self.home, 'wt2')
        os.makedirs(other)
        kg.append_ledger(other, 5001, 'st1', home=self.home)
        self.assertFalse(self.own().check(5001)[0])

    def test_ledger_bad_mac(self):
        kg.append_ledger(self.root, 5001, 'st1', home=self.home)
        path = kg.ledger_path(self.root, self.home)
        text = Path(path).read_text()
        Path(path).write_text(text.replace('"pid": 5001', '"pid": 5002'))
        self.assertFalse(self.own().check(5002)[0])
        Path(path).write_text('{"pid": 5002, "start": "x", "ts": 1, "root": "%s", "mac": "00"}\n' % self.root)
        self.assertFalse(self.own().check(5002)[0])

    def test_ledger_without_key_is_empty(self):
        kg.append_ledger(self.root, 5001, 'st1', home=self.home)
        os.unlink(str(kg.state_dir(self.home) / 'ledger.key'))
        self.assertFalse(self.own().check(5001)[0])

    def test_ledger_symlink_and_world_writable(self):
        kg.append_ledger(self.root, 5001, 'st1', home=self.home)
        path = Path(kg.ledger_path(self.root, self.home))
        os.chmod(str(path), 0o666)
        self.assertFalse(self.own().check(5001)[0], 'world-writable ledger must be ignored')
        os.chmod(str(path), 0o600)
        self.assertTrue(self.own().check(5001)[0])
        real = path.with_name('real.jsonl')
        path.rename(real)
        os.symlink(str(real), str(path))
        self.assertFalse(self.own().check(5001)[0], 'symlinked ledger must be ignored')
        path.unlink()
        sdir = kg.state_dir(self.home)
        os.chmod(str(sdir), 0o777)
        self.assertIsNone(kg.read_key(self.home), 'world-writable state directory must be ignored')
        os.chmod(str(sdir), 0o700)

    def test_ledger_is_read_from_its_tail(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = os.path.realpath(tmp)
            root = os.path.join(home, 'wt')
            os.makedirs(root)
            kg.append_ledger(root, 1, 'old', home=home)
            path = kg.ledger_path(root, home)
            with open(path, 'a') as handle:
                handle.write('{"junk": 1}\n' * 120000)  # more than 1 MiB of unrelated lines
            kg.append_ledger(root, 77, 'new', home=home)
            self.assertIn((77, 'new'), kg.read_ledger(root, home))

    def test_state_dir_symlink_refused_for_new_key(self):
        sdir = kg.state_dir(self.home)
        os.makedirs(str(sdir.parent))
        os.symlink(self.home, str(sdir))
        with self.assertRaises(OSError):
            kg.ensure_key(self.home)

    def test_real_git_worktree_discovery(self):
        subprocess.run(['git', 'init', '-q', self.root], check=True)
        sub = os.path.join(self.root, 'a', 'b')
        os.makedirs(sub)
        root, nested = kg.find_worktree(sub, home='/home/someone')
        self.assertEqual(root, os.path.realpath(self.root))
        self.assertEqual(nested, [])
        # a HOME that is inside the repo makes the repo unusable as a proof boundary
        self.assertEqual(kg.find_worktree(sub, home=os.path.join(self.root, 'a'))[0], None)

    def test_real_probe_reads_this_process(self):
        probe = kg.Probe()
        me = os.getpid()
        self.assertEqual(probe.uid(me), os.getuid())
        self.assertTrue(probe.start(me))
        self.assertEqual(os.path.realpath(probe.cwd(me)), os.path.realpath(os.getcwd()))
        self.assertTrue(probe.argv(me))
        self.assertTrue(probe.comm(me))
        self.assertIsNotNone(probe.ppid(me))
        self.assertIsNone(probe.uid(4194303))


class Messages(WorldCase):
    def test_every_positive_row_one_line(self):
        for row in (r for r in ROWS if r['expect'] == 'block'):
            verdict, rule, message, _pids = self.decide(row['cmd'], ps=row.get('ps', False))
            self.assertEqual(verdict, 'block', row['id'])
            self.assertNotIn('\n', message, row['id'])
            self.assertIn(LITERAL, message, row['id'])
            self.assertTrue(rule, row['id'])
            self.assertLess(len(message), 600, row['id'])

    def test_no_command_echo(self):
        secret = 'ghp_' + 'A1b2C3d4' * 5
        for cmd in ('pkill -f "%s"' % secret, 'kill $(echo %s)' % secret, 'ssh host.example "pkill -f %s"' % secret,
                    'pkill -f x\n# %s' % secret):
            verdict, _rule, message, _pids = self.decide(cmd)
            self.assertEqual(verdict, 'block')
            self.assertNotIn(secret[:8], message)
            self.assertNotIn('host.example', message)
            self.assertNotIn('\n', message)

    def test_message_names_pid_not_other_processes_command_line(self):
        message = self.decide('kill 4004')[2]
        self.assertIn('4004', message)
        self.assertNotIn('t.py', message)
        self.assertNotIn('/w/other', message)

    def test_unprovable_message_mentions_spawn(self):
        self.assertIn('spawn', self.decide('kill 4004')[2])


class Audit(WorldCase):
    def test_block_logged_without_command_text(self):
        self.decide('pkill -f very-secret-pattern')
        log = Path(kg.state_dir(self.home)) / 'audit.jsonl'
        text = log.read_text()
        entry = json.loads(text.splitlines()[-1])
        self.assertEqual(entry['rule'], 'broad-kill')
        self.assertEqual(len(entry['sha256']), 16)
        self.assertNotIn('very-secret', text)
        self.assertNotIn('pkill', text)

    def test_allow_writes_nothing(self):
        self.decide('ls -la')
        self.assertFalse((Path(kg.state_dir(self.home)) / 'audit.jsonl').exists())


class Perf(WorldCase):
    def test_no_probe_for_non_kill_commands(self):
        def boom(*a, **k):
            raise AssertionError('probe or ledger touched for a command without a kill verb')
        with mock.patch.object(kg.Probe, 'uid', boom), mock.patch.object(kg.Probe, 'cwd', boom), \
                mock.patch.object(kg.Probe, 'argv', boom), mock.patch.object(kg.Probe, 'start', boom), \
                mock.patch.object(kg, 'read_ledger', boom), mock.patch.object(kg, 'append_ledger', boom), \
                mock.patch.object(kg, 'audit', boom), mock.patch.object(kg, 'find_worktree', boom):
            for cmd in ('ls', 'git status', 'grep -n pkill f', 'pgrep -f x | wc -l', 'kill -0 5', 'kill -l', 'echo kill'):
                own = kg.Ownership(CWD, home=self.home, policy=POLICY)
                self.assertEqual(kg.decide(cmd, cwd=CWD, ownership=own, policy=POLICY, home=self.home)[0], 'allow', cmd)

    def test_decision_time_is_bounded(self):
        start = time.monotonic()
        for _ in range(5):
            self.decide('pkill -f x')
        self.assertLess((time.monotonic() - start) / 5, 0.5)


class Policy(unittest.TestCase):
    def test_shipped_mode_is_enforce(self):
        data = json.loads((HOOKS / 'kill_guard_policy.json').read_text())
        self.assertEqual(data['mode'], 'enforce')
        self.assertEqual(kg.load_policy()['mode'], 'enforce')

    def test_bad_policy_falls_back_to_enforce(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'p.json'
            path.write_text('{"mode": "banana", "broad_verbs": "x"}')
            policy = kg.load_policy(path)
            self.assertEqual(policy['mode'], 'enforce')
            self.assertIsInstance(policy['broad_verbs'], list)
            path.write_text('not json')
            self.assertEqual(kg.load_policy(path)['mode'], 'enforce')

    def test_mode_off_allows_everything_and_warn_does_not_block(self):
        off = dict(POLICY, mode='off')
        self.assertEqual(kg.decide('pkill -f x', cwd=CWD, policy=off)[0], 'allow')
        warn = dict(POLICY, mode='warn')
        with tempfile.TemporaryDirectory() as tmp:
            verdict, _rule, message, _p = kg.decide('pkill -f x', cwd=CWD, policy=warn, home=tmp)
        self.assertEqual(verdict, 'warn')
        self.assertIn('WARNING', message)

    def test_interpreter_switch_disables_only_the_interpreter_check(self):
        cmd_py = "python3 -c 'import os; os.kill(5, 9)'"
        off = dict(POLICY, script_kill_pattern='(?!x)x')
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(kg.decide(cmd_py, cwd=CWD, policy=off, home=tmp)[0], 'allow')
            self.assertEqual(kg.decide('pkill x', cwd=CWD, policy=off, home=tmp)[0], 'block')

    def test_interpreter_code_without_signals_is_allowed(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(kg.decide("python3 -c 'print(sum(range(9)))'", cwd=CWD, policy=POLICY, home=tmp)[0], 'allow')

    def test_overridden_base_methods_exist_with_expected_signatures(self):
        import inspect
        import command_guard as cg
        expected = {'apply': ['self', 'name', 'words', 'cmd', 'pl', 'idx', 'depth'],
                    'command': ['self', 'cmd', 'pl', 'idx', 'depth'],
                    'inner_words': ['self', 'words', 'depth', 'pl', 'idx', 'via_xargs'],
                    'script': ['self', 'text', 'depth', 'tail_visible', 'ps'],
                    'heredoc': ['self', 'rd', 'name', 'words', 'pl', 'idx', 'depth'],
                    'ssh': ['self', 'args', 'depth'],
                    'container': ['self', 'name', 'args', 'words', 'depth', 'pl', 'idx'],
                    'check_tokens': ['self', 'tokens'],
                    'resolve': ['self', 'word'],
                    'dispatch': ['self', 'words', 'cmd', 'pl', 'idx', 'depth'],
                    'bind_loop_var': ['self', 'words'],
                    'names_for': ['self', 'head']}
        self.assertEqual(sorted(expected), sorted(kg.OVERRIDDEN))
        for name, params in expected.items():
            self.assertEqual(list(inspect.signature(getattr(cg.Analyzer, name)).parameters), params, name)


def run_hook(payload_text, hooks_dir=None, mode='hook', timeout=60, env_extra=None):
    """Pipe text to the launcher. The text is only ever analysed, never executed."""
    hooks_dir = hooks_dir or HOOKS
    with tempfile.TemporaryDirectory() as home:
        env = {'HOME': home, 'PATH': '/usr/bin:/bin'}
        env.update(env_extra or {})
        done = subprocess.run([sys.executable, '-I', str(Path(hooks_dir) / 'kill_guard.py'), mode],
                              input=payload_text.encode('utf-8', 'replace'), stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=timeout, env=env, check=False)
    return done.returncode, done.stdout.decode('utf-8', 'replace'), done.stderr.decode('utf-8', 'replace')


def payload(command, tool='Bash', cwd=None):
    return json.dumps({'tool_name': tool, 'tool_input': {'command': command}, 'cwd': cwd or str(ROOT)})


class Hook(unittest.TestCase):
    def test_blocks_with_exit_2_and_message(self):
        code, _out, err = run_hook(payload('pkill -f pytest'))
        self.assertEqual(code, 2, err)
        self.assertIn(LITERAL, err)
        self.assertEqual(len(err.strip().splitlines()), 1)

    def test_allows_plain_commands(self):
        for cmd in ('ls -la', 'git status', 'kill -0 1', 'pgrep -f x'):
            code, _out, err = run_hook(payload(cmd))
            self.assertEqual(code, 0, (cmd, err))

    def test_non_shell_tools_pass_untouched(self):
        payload_text = json.dumps({'tool_name': 'Write', 'tool_input': {'file_path': 'x', 'content': 'pkill -f x'}})
        self.assertEqual(run_hook(payload_text)[0], 0)

    def test_codex_shell_shapes(self):
        for body in ({'tool_name': 'Bash', 'tool_input': {'command': ['bash', '-lc', 'pkill -f x']}},
                     {'tool_name': 'exec_command', 'tool_input': {'cmd': 'killall node', 'workdir': str(ROOT)}},
                     {'tool_name': 'write_stdin', 'tool_input': {'chars': 'pkill x\n'}}):
            self.assertEqual(run_hook(json.dumps(body))[0], 2, body)

    def test_powershell_kill_alias_blocked(self):
        self.assertEqual(run_hook(payload('kill 5', tool='PowerShell'))[0], 2)
        self.assertEqual(run_hook(payload('Get-Process', tool='PowerShell'))[0], 0)

    def test_unowned_numeric_kill_blocked_end_to_end(self):
        code, _out, err = run_hook(payload('kill 1'))
        self.assertEqual(code, 2, err)
        self.assertIn(LITERAL, err)


class Failure(unittest.TestCase):
    """The launcher must turn analyser trouble into a block for kill-looking input and an allow for the rest."""

    def staged(self, command_guard_source=None, policy=None):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        for name in ('kill_guard.py', 'kill_guard_policy.json', 'command_guard_policy.json', 'redact.py', 'safe_input.py'):
            src = HOOKS / name
            if src.exists():
                Path(tmp, name).write_bytes(src.read_bytes())
        if command_guard_source is not None:
            Path(tmp, 'command_guard.py').write_text(command_guard_source)
        else:
            Path(tmp, 'command_guard.py').write_bytes((HOOKS / 'command_guard.py').read_bytes())
        if policy is not None:
            Path(tmp, 'kill_guard_policy.json').write_text(json.dumps(policy))
        return tmp

    def assert_fail_closed(self, tmp):
        code, _out, err = run_hook(payload('pkill -f x'), hooks_dir=tmp)
        self.assertEqual(code, 2, err)
        self.assertIn(LITERAL, err)
        for obf in ('"pk""ill" -f x', "$'\\x70kill' -f x", 'eval "$X"'):
            self.assertEqual(run_hook(payload(obf), hooks_dir=tmp)[0], 2, obf)
        code, _out, err = run_hook(payload('ls -la'), hooks_dir=tmp)
        self.assertEqual(code, 0, err)

    def test_module_missing(self):
        tmp = self.staged()
        os.unlink(os.path.join(tmp, 'command_guard.py'))
        self.assert_fail_closed(tmp)

    def test_import_raises(self):
        self.assert_fail_closed(self.staged('raise RuntimeError("boom")\n'))

    def test_child_exits_nonzero(self):
        self.assert_fail_closed(self.staged('import os\nos._exit(3)\n'))

    def test_child_prints_invalid_output(self):
        self.assert_fail_closed(self.staged('import sys\nsys.stdout.write("garbage")\nsys.exit(0)\n'))

    def test_child_hangs(self):
        policy = json.loads((HOOKS / 'kill_guard_policy.json').read_text())
        policy['child_timeout_seconds'] = 3
        self.assert_fail_closed(self.staged('import time\ntime.sleep(60)\n', policy=policy))

    def test_oversized_input_blocked(self):
        code, _out, err = run_hook(payload('pkill x ' + 'a' * (9 * 1024 * 1024)))
        self.assertEqual(code, 2, err[:300])
        self.assertIn(LITERAL, err)

    def test_nul_bytes_and_unterminated_quote(self):
        self.assertEqual(run_hook(payload('pkill\x00 -f x'))[0], 2)
        self.assertEqual(run_hook(payload('echo "pkill -f x'))[0], 2)
        self.assertEqual(run_hook(payload('echo "unterminated'))[0], 0)

    def test_deep_nesting(self):
        deep = 'echo ' + '$(' * 200 + 'pkill x' + ')' * 200
        self.assertEqual(run_hook(payload(deep))[0], 2)
        self.assertEqual(run_hook(payload('echo ' + '$(' * 200 + 'date' + ')' * 200))[0], 0)

    def test_garbage_payload(self):
        self.assertEqual(run_hook('{not json pkill')[0], 2)
        self.assertEqual(run_hook('{not json at all')[0], 0)

    def test_policy_off_allows(self):
        policy = json.loads((HOOKS / 'kill_guard_policy.json').read_text())
        policy['mode'] = 'off'
        tmp = self.staged(policy=policy)
        self.assertEqual(run_hook(payload('pkill -f x'), hooks_dir=tmp)[0], 0)


class Spawn(unittest.TestCase):
    """Refusal paths of spawn only: nothing is started and nothing is signalled here (the real spawn plus signal run is
    tests/live_kill_canary.py, dev2 only)."""

    def test_refuses_outside_a_worktree_and_without_a_command(self):
        home = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, home, True)
        env = {'HOME': home, 'PATH': '/usr/bin:/bin'}
        done = subprocess.run([sys.executable, '-I', str(HOOKS / 'kill_guard.py'), 'spawn'], env=env,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, cwd=home)
        self.assertEqual(done.returncode, 2)
        done = subprocess.run([sys.executable, '-I', str(HOOKS / 'kill_guard.py'), 'spawn', '--', 'sleep', '1'], env=env,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, cwd=home)
        self.assertEqual(done.returncode, 2)
        self.assertIn(b'git worktree', done.stderr)
        self.assertFalse((Path(home) / '.agent-harness').exists())

    def test_numeric_command_is_not_a_pid_argument(self):
        self.assertEqual(kg.spawn_main([]), 2)


class RemoteSpawn(unittest.TestCase):
    """goodqa#14927: `spawn --host H -- CMD` records (host, pid, start) and only that PID becomes killable through
    `ssh H kill PID`; every other remote kill stays refused. No ssh runs here (SSH_RUNNER is faked)."""

    START = 'Thu Nov 6 10:00:00 2026'

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = os.path.realpath(self.tmp.name)
        kg.ensure_key(self.home)

    def decide(self, cmd, probe=None):
        with mock.patch.object(kg, '_remote_start', probe or (lambda host, pid: None)):
            return kg.decide(cmd, cwd=self.home, home=self.home, policy=POLICY)

    def test_remote_kill_is_refused_without_a_spawn_record(self):
        verdict, rule, message, pids = self.decide('ssh dev2 kill 4242')
        self.assertEqual((verdict, rule), ('block', 'remote-kill'))
        self.assertIn('spawn --host dev2', message)

    def test_netwatch_remote_unledgered_pids_need_foreign_route_or_remote_ledger(self):
        verdict, rule, message, _pids = self.decide('ssh dev2 netwatch orphans --kill --pid 4242')
        self.assertEqual((verdict, rule), ('block', 'remote-kill'))
        self.assertIn('--foreign', message)
        kg.append_ledger(kg.remote_root('dev2'), 4242, self.START, home=self.home)
        same = lambda host, pid: self.START if (host, pid) == ('dev2', 4242) else None  # noqa: E731
        self.assertEqual(self.decide('ssh dev2 netwatch orphans --kill --pid 4242', same)[0], 'allow')
        for command in ('ssh dev2 netwatch orphans --kill --pid 4243',
                        'ssh dev2 netwatch orphans --kill --pid 4242,4243',
                        'ssh t2-dev netwatch orphans --kill --pid 4242'):
            with self.subTest(command=command):
                self.assertEqual(self.decide(command, same)[0], 'block')

    def test_spawned_pid_is_killable_only_on_its_host_while_its_start_time_matches(self):
        kg.append_ledger(kg.remote_root('dev2'), 4242, self.START, home=self.home)
        same = lambda host, pid: self.START if (host, pid) == ('dev2', 4242) else None  # noqa: E731
        for cmd in ('ssh dev2 kill 4242', 'ssh dev2 kill -TERM 4242', "ssh dev2 'kill 4242'", 'ssh -p 22 dev2 -- kill 4242',
                    'ssh -o BatchMode=yes -o ConnectTimeout=3 dev2 kill 4242', 'ssh -q -l eric -p2222 dev2 kill 4242',
                    'ssh dev2 -- kill 4242'):
            with self.subTest(cmd):
                self.assertEqual(self.decide(cmd, same)[0], 'allow', cmd)
        refused = {'other host': 'ssh t2-dev kill 4242', 'other pid': 'ssh dev2 kill 4243', 'mixed pids': 'ssh dev2 kill 4242 4243',
                   'container': 'docker exec c kill 4242', 'nested hop': 'ssh gw ssh dev2 kill 4242',
                   'broad verb': 'ssh dev2 pkill -f tsc', 'variable host': 'ssh $H kill 4242',
                   'finder': 'ssh dev2 "kill $(pgrep -f tsc)"', 'local kill': 'kill 4242',
                   # routing options send the kill elsewhere while the ledger and probe name dev2 (review HIGH)
                   'hostname option': 'ssh -o HostName=prod dev2 kill 4242', 'glued hostname': 'ssh -oHostName=prod dev2 kill 4242',
                   'config file': 'ssh -F evil.cfg dev2 kill 4242', 'jump': 'ssh -J gw dev2 kill 4242',
                   'proxyjump': 'ssh -o ProxyJump=gw dev2 kill 4242', 'proxycommand': "ssh -o 'ProxyCommand=nc prod 22' dev2 kill 4242",
                   'stdio forward': 'ssh -W prod:22 dev2 kill 4242', 'control socket': 'ssh -S ctl dev2 kill 4242',
                   'variable option': 'ssh -o $OPT dev2 kill 4242', 'unknown flag': 'ssh -A dev2 kill 4242',
                   # OpenSSH parses options after the destination too (review round 2)
                   'option after host': 'ssh dev2 -o HostName=prod kill 4242', 'config after host': 'ssh dev2 -F evil.cfg kill 4242',
                   'jump after host': 'ssh dev2 -J gw kill 4242', 'socket after host': 'ssh dev2 -S ctl kill 4242',
                   'variable after host': 'ssh dev2 $OPT HostName=prod kill 4242'}
        # Known pre-existing gap, not this route's: an unquoted `$(...)` word inside an ssh command makes the base
        # analyzer drop the remote kill entirely (`ssh dev2 $(echo x) kill 4242` is 'allow' on main too); tracked on
        # GoodQA goodqa#14927 as a base-analyzer finding.
        for label, cmd in refused.items():
            with self.subTest(label):
                self.assertEqual(self.decide(cmd, same)[0], 'block', cmd)
        # pid reuse or a dead process: the host must still report the recorded start time
        self.assertEqual(self.decide('ssh dev2 kill 4242', lambda h, p: 'Fri Nov 7 09:00:00 2026')[0], 'block')
        self.assertEqual(self.decide('ssh dev2 kill 4242', lambda h, p: None)[0], 'block')
        self.assertEqual(self.decide('ssh dev2 kill 4242', lambda h, p: self.START)[0], 'allow')  # same, whitespace-normalized

    def test_routing_options_held_in_an_array_stay_refused(self):
        """Delta review F1 (pr96-merge-51a8d87.md): on main 51a8d87 an array kept `"${O[@]}"` as plain text, so the
        routing options inside it were invisible to the spawn route and these were allowed, killing on another host."""
        kg.append_ledger(kg.remote_root('dev2'), 4242, self.START, home=self.home)
        same = lambda host, pid: self.START if (host, pid) == ('dev2', 4242) else None  # noqa: E731
        self.assertEqual(self.decide('ssh dev2 kill 4242', same)[0], 'allow')  # the ledgered plain form still works
        for cmd in ('O=(-o HostName=prod); ssh "${O[@]}" dev2 kill 4242',
                    'O=(-o BatchMode=yes -o HostName=prod); ssh "${O[@]}" dev2 kill 4242',
                    'O=(-oBatchMode=yes -oHostName=prod); ssh "${O[@]}" dev2 kill 4242',
                    'X=(-J); ssh "${X[@]}" prod dev2 kill 4242'):
            with self.subTest(cmd):
                self.assertEqual(self.decide(cmd, same)[0], 'block', cmd)

    def test_spawn_host_records_the_remote_pid_and_start_time(self):
        calls = []

        def runner(argv, **kw):
            calls.append(argv)
            return subprocess.CompletedProcess(argv, 0, stdout='4242\nThu Nov  6 10:00:00 2026\n', stderr='')

        with mock.patch.object(kg, 'SSH_RUNNER', runner), mock.patch.object(kg.Path, 'home', return_value=Path(self.home)), \
                mock.patch.dict(os.environ, {'HOME': self.home}):
            out = StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(kg.spawn_main(['--host', 'dev2', '--log', '/tmp/tsc.log', '--', 'sh', '-c', 'tsc --noEmit; echo $? > done']), 0)
        record = json.loads(out.getvalue())
        self.assertEqual((record['host'], record['pid'], record['start']), ('dev2', 4242, self.START))
        self.assertEqual(calls[0][:3], ['ssh', '-o', 'BatchMode=yes'])
        self.assertIn("nohup sh -c 'tsc --noEmit; echo $? > done' >/tmp/tsc.log", calls[0][-1])
        self.assertEqual(kg.read_ledger(kg.remote_root('dev2'), self.home), [(4242, self.START)])
        self.assertEqual(kg.read_ledger(kg.remote_root('t2-dev'), self.home), [])

    def test_spawn_host_records_nothing_when_the_host_reports_no_pid(self):
        def failing(argv, **kw):
            return subprocess.CompletedProcess(argv, 255, stdout='', stderr='Permission denied')

        with mock.patch.object(kg, 'SSH_RUNNER', failing), mock.patch.object(kg.Path, 'home', return_value=Path(self.home)), \
                mock.patch.dict(os.environ, {'HOME': self.home}), contextlib.redirect_stderr(StringIO()):
            self.assertEqual(kg.spawn_main(['--host', 'dev2', '--', 'sleep', '5']), 1)
            self.assertEqual(kg.spawn_main(['--host', 'dev2;id', '--', 'sleep', '5']), 2)
            self.assertEqual(kg.spawn_main(['--host', '-oProxyCommand=x', '--', 'sleep', '5']), 2)
            self.assertEqual(kg.spawn_main(['--host', 'dev2']), 2)
        self.assertEqual(kg.read_ledger(kg.remote_root('dev2'), self.home), [])


class RedTeamRound(WorldCase):
    """Regression tests for the red-team findings that the corpus cannot express (work/redteam-report.md)."""

    def world_with(self, extra):
        world = json.loads(json.dumps(WORLD))
        world['pids'].update({str(k): v for k, v in extra.items()})
        return world

    def test_rt1_verb_after_four_mib_is_blocked(self):
        code, _out, err = run_hook(payload('echo ' + 'a' * 6_000_000 + '; pkill foo'))
        self.assertEqual(code, 2, err[:200])
        self.assertIn(LITERAL, err)

    def test_rt1_fallback_scans_the_whole_text(self):
        self.assertTrue(kg.fallback_blocks('a' * 5_000_000 + ' pkill x'))
        self.assertFalse(kg.fallback_blocks('a' * 5_000_000))

    def test_rt13_unknown_shell_like_tool_with_command_key_is_judged(self):
        body = {'tool_name': 'mcp__x__run', 'tool_input': {'command': 'pkill foo'}}
        self.assertEqual(run_hook(json.dumps(body))[0], 2)
        body = {'tool_name': 'mcp__x__run', 'tool_input': {'command': 'ls'}}
        self.assertEqual(run_hook(json.dumps(body))[0], 0)

    def test_rt17_empty_pattern_disables_the_interpreter_check_only(self):
        off = dict(POLICY, script_kill_pattern='')
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(kg.decide("python3 -c 'print(1)'", cwd=CWD, policy=off, home=tmp)[0], 'allow')
            self.assertEqual(kg.decide("python3 -c 'import os; os.kill(5, 9)'", cwd=CWD, policy=off, home=tmp)[0], 'allow')
            self.assertEqual(kg.decide('pkill x', cwd=CWD, policy=off, home=tmp)[0], 'block')

    def test_rt19_values_are_never_echoed(self):
        for cmd in ('kill sk-live-ABCDEF123456SECRETVALUE', 'netwatch orphans --kill --pid 4242 --token=sk-live-ABCDEF123456SE',
                    'netwatch orphans --kill --pid sk-live-ABCDEF123456'):
            verdict, _rule, message, _pids = self.decide(cmd)
            self.assertEqual(verdict, 'block', cmd)
            self.assertNotIn('sk-live', message)

    def test_rt20_interactive_shell_is_protected_but_a_script_shell_is_not(self):
        world = self.world_with({
            4020: {'uid': 1000, 'comm': 'zsh', 'cwd': '/w/own', 'argv': ['-zsh'], 'start': 'a'},
            4021: {'uid': 1000, 'comm': 'bash', 'cwd': '/w/own', 'argv': ['bash'], 'start': 'b'},
            4022: {'uid': 1000, 'comm': 'bash', 'cwd': '/w/own', 'argv': ['bash', '/w/own/run.sh'], 'start': 'c'},
            4023: {'uid': 1000, 'comm': 'node', 'cwd': '/elsewhere', 'argv': ['node', '--inspect', '/w/own/s.js'], 'start': 'd'},
            4024: {'uid': 1000, 'comm': 'terminal', 'cwd': '/w/own', 'argv': ['x'], 'start': 'e'}})
        own = self.ownership(world)
        self.assertEqual(own.check(4020)[1], 'protected')
        self.assertEqual(own.check(4021)[1], 'protected')
        self.assertTrue(own.check(4022)[0])
        self.assertTrue(own.check(4023)[0], 'a flag before the script must not hide it')
        self.assertEqual(own.check(4024)[1], 'protected')

    def test_rt20_system_roots_are_rejected(self):
        for top in ('/private/tmp', '/tmp', '/var', '/opt', '/usr', '/private'):
            runner = lambda argv, *a, _t=top, **k: _t + '\n' if 'rev-parse' in argv else ''  # noqa: E731
            own = kg.Ownership('/tmp/x', home=WORLD['home'], probe=FakeProbe(WORLD), runner=runner, policy=POLICY)
            self.assertEqual(own.check(4001)[1], 'no-worktree', top)

    def test_rt20_probe_results_are_memoised(self):
        calls = []
        probe = FakeProbe(WORLD)
        real_uid = probe.uid
        probe.uid = lambda pid: calls.append(pid) or real_uid(pid)
        own = kg.Ownership(CWD, home=WORLD['home'], probe=probe, runner=fake_runner(WORLD), policy=POLICY)
        for _ in range(20):
            own.check(4001)
        self.assertEqual(calls.count(4001), 1)

    def test_rt8_large_brace_expansions_are_blocked(self):
        self.assertEqual(self.decide('kill 1{0,1,2,3,4,5,6,7,8,9}{0,1,2,3,4,5,6,7,8,9}')[0], 'block')
        self.assertEqual(self.decide('kill {-9,4001}')[0], 'block')

    def test_rt14_only_the_first_signal_option_counts(self):
        # Reviewer F1: after the first signal option bash and zsh read -0 as process group 0, so the PID is a real target.
        self.assertEqual(self.decide('kill -0 -s KILL 4004')[0], 'block')
        self.assertEqual(self.decide('kill -s KILL -0 4004')[0], 'block')
        self.assertEqual(self.decide('kill -9 -s 4004')[0], 'block')
        self.assertEqual(self.decide('kill -0 4004')[0], 'allow')

    def test_rt18_spawn_log_outside_the_worktree_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = os.path.realpath(tmp)
            repo = os.path.join(home, 'wt')
            os.makedirs(repo)
            subprocess.run(['git', 'init', '-q', repo], check=True)
            env = {'HOME': home, 'PATH': '/usr/bin:/bin'}
            done = subprocess.run([sys.executable, '-I', str(HOOKS / 'kill_guard.py'), 'spawn', '--log',
                                   os.path.join(home, 'outside.log'), '--', 'true'], cwd=repo, env=env,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
            self.assertEqual(done.returncode, 2)
            self.assertIn(b'inside the worktree', done.stderr)
            self.assertFalse(os.path.exists(os.path.join(home, 'outside.log')))


class Hygiene(unittest.TestCase):
    FILES = ('test_kill_guard.py', 'live_kill_canary.py')

    def trees(self):
        base = Path(__file__).resolve().parent
        for name in self.FILES:
            path = base / name
            if path.exists():
                yield name, ast.parse(path.read_text(encoding='utf-8'))

    def test_no_shell_or_eval_anywhere_in_kill_guard_tests(self):
        seen = 0
        for name, tree in self.trees():
            seen += 1
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    func = node.func
                    dotted = (func.value.id + '.' + func.attr) if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name) else getattr(func, 'id', '')
                    self.assertNotIn(dotted, ('os.system', 'os.popen', 'eval', 'exec', 'subprocess.getoutput'), name)
                    for kw in node.keywords:
                        self.assertFalse(kw.arg == 'shell' and not (isinstance(kw.value, ast.Constant) and kw.value.value is False),
                                         '%s uses shell=' % name)
        self.assertGreaterEqual(seen, 1)

    def test_signals_only_through_safe_signal(self):
        for name, tree in self.trees():
            for fn in ast.walk(tree):
                if isinstance(fn, ast.FunctionDef) and fn.name != 'safe_signal':
                    for node in ast.walk(fn):
                        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and \
                                node.func.attr in ('kill', 'killpg') and isinstance(node.func.value, ast.Name) and node.func.value.id == 'os':
                            self.fail('%s: os.%s outside safe_signal in %s' % (name, node.func.attr, fn.name))

    def test_subprocess_in_unit_tests_only_pipes_text_on_stdin(self):
        """The only subprocess call that takes corpus-shaped text is run_hook, which passes it via stdin=input."""
        tree = ast.parse(Path(__file__).read_text(encoding='utf-8'))
        for fn in ast.walk(tree):
            if isinstance(fn, ast.FunctionDef):
                for node in ast.walk(fn):
                    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == 'run' \
                            and isinstance(node.func.value, ast.Name) and node.func.value.id == 'subprocess' and node.args:
                        argv = node.args[0]
                        self.assertIsInstance(argv, ast.List, fn.name)
                        for item in argv.elts:
                            self.assertNotIn(type(item).__name__, ('BinOp', 'JoinedStr'), fn.name)

    def test_corpus_loaded_only_as_json_data(self):
        text = Path(__file__).read_text(encoding='utf-8')
        self.assertIn('json.loads', text)
        self.assertNotRegex(text, r'(?m)^\s*(?:import|from)\s+kill_guard_corpus')


class Install(unittest.TestCase):
    def setUp(self):
        sys.path.insert(0, str(ROOT))
        import install
        import install_codex
        self.install, self.install_codex = install, install_codex
        tmp = tempfile.TemporaryDirectory(prefix='kg-install-')
        self.addCleanup(tmp.cleanup)
        self.home = Path(tmp.name)

    @staticmethod
    def kill_groups(groups, needle='kill_guard.py'):
        return [g for g in groups if any(needle in ' '.join(h.get('args') or [h.get('command', '')])
                                         for h in g.get('hooks', []))]

    def test_claude_entry_is_separate_fail_closed_and_idempotent(self):
        claude = self.home / '.claude'
        user = {'matcher': 'Bash', 'hooks': [{'type': 'command', 'command': 'echo mine'}]}
        settings = self.install.merged_settings({'hooks': {'PreToolUse': [user]}}, claude)
        groups = self.kill_groups(settings['hooks']['PreToolUse'])
        self.assertEqual(len(groups), 1)
        hook = groups[0]['hooks'][0]
        self.assertEqual((hook['onFailure'], hook['timeout']), ('block', 30))
        self.assertEqual(hook['args'][-1], 'hook')
        self.assertIn('Bash', groups[0]['matcher'])
        self.assertIn('PowerShell', groups[0]['matcher'])
        self.assertIn(user, settings['hooks']['PreToolUse'])
        again = self.install.merged_settings(settings, claude)
        self.assertEqual(json.dumps(again, sort_keys=True), json.dumps(settings, sort_keys=True))
        rolled = self.install.merged_settings(settings, claude, command_guard=False)
        self.assertEqual(self.kill_groups(rolled['hooks']['PreToolUse']), [])
        self.assertIn(user, rolled['hooks']['PreToolUse'])
        for name in ('kill_guard.py', 'kill_guard_policy.json', 'command_guard.py', 'redact.py', 'safe_input.py'):
            self.assertIn(name, self.install.HOOKS)

    def test_codex_entry_has_no_matcher_and_is_idempotent(self):
        codex = self.home / '.codex'
        hooks = self.install_codex.merge_hooks({}, codex)
        command = self.install_codex.kill_guard_command(codex)
        groups = [g for g in hooks['hooks']['PreToolUse'] if g['hooks'][0]['command'] == command]
        self.assertEqual(len(groups), 1)
        self.assertNotIn('matcher', groups[0])
        self.assertTrue(command.endswith(' hook'))
        again = self.install_codex.merge_hooks(hooks, codex)
        self.assertEqual(json.dumps(again, sort_keys=True), json.dumps(hooks, sort_keys=True))
        for name in ('kill_guard.py', 'kill_guard_policy.json'):
            self.assertIn(name, self.install_codex.DELIVERY_HELPERS)


class Wiring(unittest.TestCase):
    def test_rules_registry_entry(self):
        path = ROOT / 'docs' / 'rules' / 'kill-guard.json'
        data = json.loads(path.read_text(encoding='utf-8'))
        entries = [e for e in data['rules'] if e.get('id') == 'kill-guard']
        self.assertEqual(len(entries), 1)
        entry = entries[0]
        for key in ('rule', 'mechanism', 'enforcement', 'test', 'test_file', 'source'):
            self.assertTrue(entry.get(key), key)
        self.assertEqual(entry['enforcement'], 'ENFORCED')
        self.assertIn('14506', entry['source'])
        test_file = ROOT / entry['test_file']
        self.assertTrue(test_file.exists())
        klass, _, method = entry['test'].partition('.')
        tree = ast.parse(test_file.read_text(encoding='utf-8'))
        found = any(isinstance(c, ast.ClassDef) and c.name == klass and any(
            isinstance(m, ast.FunctionDef) and m.name == method for m in c.body) for c in ast.walk(tree))
        self.assertTrue(found, 'registry names a test that does not exist: %s' % entry['test'])

    def test_registry_with_a_missing_test_would_fail(self):
        tree = ast.parse(Path(__file__).read_text(encoding='utf-8'))
        names = {m.name for c in ast.walk(tree) if isinstance(c, ast.ClassDef) and c.name == 'Corpus'
                 for m in c.body if isinstance(m, ast.FunctionDef)}
        self.assertNotIn('test_no_such_test', names)


class GuardCompositionTests(unittest.TestCase):
    """The kill guard and the command guard (#66) are separate hook groups and decide independently."""
    REAL = ROOT / 'harness/hooks'
    PROTECTED = 'rm -rf /home/x/' + '.cla' + 'ude/proj' + 'ects'  # a command the command guard blocks; never executed

    def run_both(self, command):
        home = tempfile.TemporaryDirectory(prefix='kg-compose-')
        self.addCleanup(home.cleanup)
        data = json.dumps({'tool_name': 'Bash', 'tool_input': {'command': command}, 'session_id': 's',
                           'cwd': str(ROOT)}).encode()
        env = {'PATH': '/usr/bin:/bin', 'HOME': home.name}
        codes = {}
        for name, script in (('command', 'command_guard_hook.py'), ('kill', 'kill_guard.py')):
            done = subprocess.run([sys.executable, '-I', str(self.REAL / script), 'hook'], input=data, env=env,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60, check=False)
            codes[name] = done.returncode
        return codes

    def test_each_guard_blocks_its_own_class_and_allows_the_other(self):
        self.assertEqual(self.run_both('ls -la'), {'command': 0, 'kill': 0})
        self.assertEqual(self.run_both('pkill -f pytest'), {'command': 0, 'kill': 2})
        self.assertEqual(self.run_both(self.PROTECTED), {'command': 2, 'kill': 0})
        self.assertEqual(self.run_both('pkill -f pytest; ' + self.PROTECTED), {'command': 2, 'kill': 2})

    def test_claude_install_keeps_both_guards_in_separate_blocking_groups(self):
        sys.path.insert(0, str(ROOT))
        import install
        groups = install.managed_hooks(Path('/home/u/.claude'))['PreToolUse']
        names = [[Path((h.get('args') or [''])[0]).name for h in g['hooks']] for g in groups]
        self.assertEqual(names[0], ['command_guard_hook.py'])
        kill = [g for g, n in zip(groups, names) if 'kill_guard.py' in n]
        self.assertEqual(len(kill), 1)
        self.assertEqual([Path(h['args'][0]).name for h in kill[0]['hooks']], ['kill_guard.py'])
        self.assertEqual(kill[0]['hooks'][0]['args'][1], 'hook')
        self.assertEqual(kill[0]['hooks'][0]['onFailure'], 'block')

    def test_codex_install_appends_the_kill_guard_so_existing_indexes_do_not_shift(self):
        sys.path.insert(0, str(ROOT))
        try:
            import install_codex
        except (ImportError, SyntaxError, TypeError) as error:  # needs Python 3.11 (tomllib)
            self.skipTest('install_codex not importable here: %s' % error)
        groups = install_codex.merge_hooks({}, Path('/home/u/.codex'))['hooks']['PreToolUse']
        commands = [h['command'] for g in groups for h in g['hooks']]
        order = ('wal.py', 'commit_policy.py', 'merge_gate.py', 'command_guard_hook.py', 'kill_guard.py', 'heavy_job_guard.py')
        self.assertEqual(len(commands), len(order))
        self.assertEqual([len(g['hooks']) for g in groups], [1] * len(order))  # trust is keyed on group:handler
        for command, name in zip(commands, order):
            self.assertIn(name, command)
        self.assertEqual(sum('kill_guard.py' in c for c in commands), 1)



class ScriptArgumentTextIsData(WorldCase):
    """goodqa#14817: words in a script's ARGUMENTS (a note, a JSON body) are data, not interpreter code."""
    DATA = [
        "python3 ~/.claude/hooks/wal_note.py --wal ~/w.jsonl --event status --note 'owner will kill nothing; delete later'",
        "python3 ~/.claude/hooks/spec_flow.py --note 'os.kill is not called here'",
        "python3 ./gq.py comment 14817 --json '{\"body\": \"a kill-guard false positive\"}'",
    ]
    CODE = [  # inline code and heredoc bodies are still scanned
        "python3 -c 'import os; os.kill(5, 9)'",
        "python3 - <<'EOF'\nimport os\nos.kill(5, 9)\nEOF",
        "python3 -m somemod --note x -c 'os.kill(5,9)'",
        # review F1: a flag value that looks like a script must not hide the inline code after it
        "python3 -W x/y -c 'import os; os.kill(4242, 9)'",
        "python3 -W ignore::a.py -c 'import os; os.kill(4242, 9)'",
        "perl -I /opt/lib -e 'kill 9, 4242'",
        "ruby -I /opt/lib -e 'Process.kill(9, 4242)'",
        "php -d include_path=/x -r 'posix_kill(4242, 9);'",
        # a script that runs its own arguments as a command
        "python3 ~/.claude/hooks/run_capped.py --max-rss-gb 1 -- kill -9 4242",
        "python3 ./runner.py pkill -f node",
        "python3 ./unlisted_tool.py --note 'will kill the job'",  # not on the named list: scanned in full
        # goodqa#15276: a cwd-relative copy of a named helper is any file; only the caller's installed copies are data
        "python3 spec_flow.py --note 'os.kill is not called here'",
        # delta review: runners that take a command without `--`, absolute-path verbs, shell and -c strings
        "python3 ~/.claude/hooks/run_capped.py --max-rss-gb 1 /bin/kill -9 4242",
        "python3 ~/.claude/hooks/run_capped.py --max-rss-gb 1 /usr/bin/pkill -f node",
        "python3 ~/.claude/hooks/run_capped.py --max-rss-gb 1 sh -c 'kill -9 4242'",
        "python3 ~/.claude/hooks/run_capped.py --max-rss-gb 1 python3 -c 'import os; os.kill(4242, 9)'",
        "python3 ~/.claude/tools/watch-tests.py --root . -- killall node",
    ]

    def test_script_arguments_are_not_code(self):
        for cmd in self.DATA:
            with self.subTest(cmd=cmd):
                self.assertNotEqual(self.decide(cmd)[0], 'block', cmd)

    def test_inline_code_still_blocks(self):
        for cmd in self.CODE:
            with self.subTest(cmd=cmd):
                self.assertEqual(self.decide(cmd)[0], 'block', cmd)

if __name__ == '__main__':
    unittest.main()
