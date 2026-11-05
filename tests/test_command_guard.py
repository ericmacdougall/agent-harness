"""Tests for harness/hooks/command_guard.py (GoodQA #14471).

Every command string here is DATA handed to command_guard.decide(); nothing in this file executes a corpus row
(safety rule S1/S3). The live, executing harness is tests/live_guard_canary.py and runs only on dev2 (rule S2).

CG_HOOKS_DIR overrides the module directory so the same tests can be pointed at an older implementation to show
them failing first.
"""

import ast
import inspect
import json
import os
import random
import re
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HOOKS = Path(os.environ.get('CG_HOOKS_DIR') or ROOT / 'harness/hooks')
sys.path.insert(0, str(HOOKS))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import command_guard as cg  # noqa: E402
import command_guard_corpus as corpus  # noqa: E402

POSITIVE_FLOOR = 400
NEGATIVE_FLOOR = 200


def make_fixture(home):
    """The tree the corpus rows refer to: harness roots, a real worktree, a fake one, a plain task folder."""
    h = Path(home)
    files = [
        '.claude/projects/p/a.jsonl', '.claude/history.jsonl', '.claude/settings.json', '.claude/wals/s/main.jsonl',
        '.claude/hooks/command_guard.py', '.codex/sessions/2026/x.jsonl', '.codex/history.jsonl',
        '.codex/config.toml', '.agent-harness/state/log-delete-ok.json',
        '.agent-harness/work/S/notes.md', '.agent-harness/work/S/T/kit.json', '.agent-harness/work/S/T/notes.md',
        '.agent-harness/work/S/T/main.jsonl', '.agent-harness/work/S/T/tmp/packet.md',
        '.agent-harness/work/S/T/tmp/scripts/a.py', '.agent-harness/work/S/T/tmp/main.jsonl',
        '.agent-harness/work/S/T/tmp/kit.json', '.agent-harness/work/S/T/wt/.git/HEAD',
        '.agent-harness/work/S/T/wt/build/a.o', '.agent-harness/work/S/T/wt/out/x.o',
        '.agent-harness/work/S/T/wt/out/results.jsonl', '.agent-harness/work/S/T/fake/.git/config',
        '.agent-harness/work/S/T/fake/x/y', '.agent-harness/work/S/T/plain/x/y',
        '.agent-harness/work/S/T2/notes.md', '.agent-harness/scratch/a/b/c/d/tmp.txt',
        '.agent-harness/scratch/a/b/c/tasks/x.output', '.agent-harness/scratch/a/b/c/run.log',
        '.agent-harness/scratch/a/b/c/tasks/d/session.txt',
        'repo/.git/HEAD', 'repo/tests/fixtures/wals/main.jsonl',
    ]
    for rel in files:
        p = h / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text('ref: refs/heads/main\n' if rel.endswith('/HEAD') else 'x\n')
    (h / '.agent-harness/work/S/T/state').mkdir(parents=True, exist_ok=True)
    return h


def fill(text, home):
    h = str(home)
    return (text.replace('@WT@', h + '/.agent-harness/work/S/T/wt')
            .replace('@TASK@', h + '/.agent-harness/work/S/T').replace('@HOME@', h))


class Fixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory(prefix='cg-home-')
        cls.home = Path(os.path.realpath(cls._tmp.name))
        make_fixture(cls.home)
        cls.policy = cg.load_policy(path=str(cls.home / 'no-such-policy.json'))
        cls._old_home = os.environ.get('HOME')
        os.environ['HOME'] = str(cls.home)

    @classmethod
    def tearDownClass(cls):
        if cls._old_home is not None:
            os.environ['HOME'] = cls._old_home
        cls._tmp.cleanup()

    def decide(self, command, cwd='@HOME@/repo', ps=False, proc=None):
        """`cwd` is the payload cwd (None: the host sent none); `proc` is the hook process's own directory."""
        cwd = fill(cwd, self.home) if cwd else None
        proc = fill(proc, self.home) if proc else None
        compiled = cg.Compiled(self.policy, home=str(self.home), cwd=proc or cwd or str(self.home / 'repo'))
        return cg.decide(fill(command, self.home), compiled, cwd=cwd, ps=ps)

    def expect(self, rows, want, ps=False, label=''):
        failures = []
        for row in rows:
            cmd, cwd = (row['cmd'], row['cwd']) if isinstance(row, dict) else (row, '@HOME@/repo')
            proc = row.get('proc') if isinstance(row, dict) else None
            verdict, message = self.decide(cmd, cwd=cwd, ps=ps, proc=proc)
            ok = verdict in want if isinstance(want, tuple) else verdict == want
            if not ok:
                failures.append('%r (cwd=%s) -> %s %s' % (cmd, cwd, verdict, message.splitlines()[:1]))
        self.assertGreater(len(rows), 0, 'empty corpus section ' + label)
        self.assertEqual(failures, [], '%s: %d of %d rows wrong:\n%s' % (label, len(failures), len(rows),
                                                                         '\n'.join(failures[:40])))


class CorpusTests(Fixture):
    def test_secret_positive_blocks(self):
        self.expect(corpus.SECRET_POSITIVE, 'block', label='SECRET_POSITIVE')

    def test_secret_positive_powershell_blocks(self):
        self.expect(corpus.SECRET_POSITIVE_PS, 'block', ps=True, label='SECRET_POSITIVE_PS')

    def test_gh_token_shapes_block(self):
        self.expect(corpus.NEG13_GH_TOKEN, 'block', label='NEG13_GH_TOKEN')

    def test_log_positive_blocks(self):
        self.expect(corpus.LOG_POSITIVE, 'block', label='LOG_POSITIVE')

    def test_log_positive_powershell_blocks(self):
        self.expect(corpus.LOG_POSITIVE_PS, 'block', ps=True, label='LOG_POSITIVE_PS')

    def test_work_tree_blocks(self):
        self.expect(corpus.NEG15_WORK_BLOCK, 'block', label='NEG15_WORK_BLOCK')

    def test_work_tree_allows(self):
        self.expect(corpus.NEG15_WORK_ALLOW, 'allow', label='NEG15_WORK_ALLOW')

    def test_kill_positive_warns_or_blocks(self):
        self.expect(corpus.KILL_POSITIVE, ('warn', 'block'), label='KILL_POSITIVE')

    def test_negative_allows(self):
        self.expect(corpus.NEGATIVE, 'allow', label='NEGATIVE')

    def test_negative_powershell_allows(self):
        self.expect(corpus.NEGATIVE_PS, 'allow', ps=True, label='NEGATIVE_PS')

    def test_block_messages_never_carry_secrets_or_suggest_file_tools(self):
        sentinel = 'sk-ant-api03-' + 'Q' * 40  # fake key shape, not a real credential
        rows = ['rm -rf ~/.claude/projects/' + sentinel, 'gh auth status --show-token ' + sentinel, 'echo $GITHUB_TOKEN ' + sentinel,
                'rm ~/.agent-harness/state/' + sentinel]
        for cmd in rows + corpus.SECRET_POSITIVE[:40] + corpus.LOG_POSITIVE[:40]:
            verdict, message = self.decide(cmd)
            self.assertEqual(verdict, 'block', cmd)
            self.assertNotIn(sentinel, message)
            for word in ('Write tool', 'Edit tool', 'apply_patch'):
                self.assertNotIn(word, message, cmd)


class CrossProductTests(Fixture):
    """Seeded wrapper x base products; the seed is printed in every failure."""

    def product(self, bases, wrappers, n):
        rng = random.Random(corpus.SEED)
        rows = []
        compound = (';', '&&', '||', '|', 'for ', 'if ', 'while ', '\n')
        for base in bases:
            simple = not any(x in base for x in compound) and not base.startswith(('{', '(', '>', ':', '`')) \
                and not re.match(r'[A-Za-z_][A-Za-z0-9_]*=', base) and not base.endswith('&')
            for w in wrappers:
                prefix = w.endswith('{}') or w.endswith('{} &') or w.startswith('eval')
                if "'" in base and "'{}'" in w:
                    continue
                if prefix and not w.startswith(('true &&', 'false ||', 'echo pre;')) and not simple:
                    continue  # a prefix command applies to the first simple command only: not a real wrapping
                if w.startswith('eval') and ('"' in base or '$' in base or '\\' in base):
                    continue
                if '\n' in base:
                    continue
                rows.append(w.format(base))
        rng.shuffle(rows)
        return rows[:n]

    def test_wrapped_positives_block(self):
        bases = [r for r in corpus.SECRET_POSITIVE + corpus.LOG_POSITIVE if r.count('$(') == 0 and '`' not in r]
        rows = self.product(bases, corpus.WRAPPERS_POSITIVE, 1200)
        self.assertGreaterEqual(len(rows), POSITIVE_FLOOR, 'seed %d' % corpus.SEED)
        self.expect(rows, 'block', label='wrapped positives seed=%d' % corpus.SEED)

    def test_wrapped_negatives_allow(self):
        bases = [r for r in corpus.NEGATIVE if '\n' not in r and '$(' not in r and 'cd ' not in r
                 and not r.startswith(('export', 'x=', 'set ', 'if ', 'for ', '[', 'source', '. '))]
        rows = self.product(bases, corpus.WRAPPERS_NEGATIVE, 800)
        self.assertGreaterEqual(len(rows), NEGATIVE_FLOOR, 'seed %d' % corpus.SEED)
        self.expect(rows, 'allow', label='wrapped negatives seed=%d' % corpus.SEED)


class CorpusManifestTests(unittest.TestCase):
    def test_floors_and_no_overlap(self):
        positives = corpus.SECRET_POSITIVE + corpus.LOG_POSITIVE + corpus.NEG13_GH_TOKEN
        self.assertGreaterEqual(len(positives), 250)
        self.assertGreaterEqual(len(corpus.NEGATIVE), 150)
        self.assertEqual(set(positives) & set(corpus.NEGATIVE), set())
        block = {r['cmd'] for r in corpus.NEG15_WORK_BLOCK}
        allow = {r['cmd'] for r in corpus.NEG15_WORK_ALLOW}
        for cmd in block & allow:  # the same text may differ only by cwd
            cwds_b = {r['cwd'] for r in corpus.NEG15_WORK_BLOCK if r['cmd'] == cmd}
            cwds_a = {r['cwd'] for r in corpus.NEG15_WORK_ALLOW if r['cmd'] == cmd}
            self.assertEqual(cwds_b & cwds_a, set(), cmd)

    def test_incident_rows_present(self):
        incident = "cat <<'EOF'\nhello\nEOF\nrm -rf ~/.claude/projects"
        self.assertIn(incident, corpus.LOG_POSITIVE)
        self.assertIn('rclone config file', corpus.SECRET_POSITIVE)
        self.assertIn('rm ~/.claude/settings.json', corpus.LOG_POSITIVE)


class PayloadTests(Fixture):
    def test_codex_and_claude_payload_shapes(self):
        cmd = 'rm -rf ' + str(self.home) + '/.claude/projects'
        shapes = [
            {'tool_name': 'Bash', 'tool_input': {'command': cmd}},
            {'tool_name': 'exec_command', 'tool_input': {'cmd': cmd}},
            {'tool_name': 'shell', 'tool_input': {'command': ['bash', '-lc', cmd]}},
            {'tool_name': 'write_stdin', 'tool_input': {'chars': cmd + '\n'}},
            {'tool_name': 'unified_exec', 'tool_input': {'input': cmd}},
            {'tool_name': 'local_shell', 'tool_input': {'command': ['rm', '-rf', str(self.home) + '/.claude/projects']}},
        ]
        for payload in shapes:
            command, _ = cg.extract_command(payload)
            self.assertTrue(command, payload['tool_name'])
            text = command if isinstance(command, str) else ' '.join(command)
            self.assertEqual(self.decide(text)[0], 'block', payload['tool_name'])

    def test_non_shell_tools_are_ignored(self):
        self.assertEqual(cg.extract_command({'tool_name': 'Read', 'tool_input': {'file_path': '/x'}}), (None, False))

    def test_codex_workdir_is_the_cwd(self):
        wt = str(self.home) + '/.agent-harness/work/S/T/wt'
        self.assertEqual(cg.payload_cwd({'cwd': '/elsewhere', 'tool_input': {'workdir': wt}}), wt)
        self.assertEqual(cg.payload_cwd({'cwd': '/elsewhere', 'tool_input': {}}), '/elsewhere')
        self.assertIsNone(cg.payload_cwd({'tool_input': {}}))


class FailureModeTests(Fixture):
    def test_unterminated_quote_with_protected_text_blocks(self):
        self.assertEqual(self.decide("rm -rf ~/.claude/projects '")[0], 'block')
        self.assertEqual(self.decide('echo "rclone config show')[0], 'block')

    def test_unterminated_quote_without_protected_text_warns(self):
        self.assertEqual(self.decide("echo 'hello")[0], 'warn')

    def test_over_budget_with_exec_step_blocks(self):
        padding = 'true; ' * 120000
        self.assertEqual(self.decide(padding + 'echo eA== | base64 -d | sh; rm x')[0], 'block')

    def test_over_budget_plain_text_does_not_block(self):
        padding = 'true; ' * 120000
        self.assertIn(self.decide(padding + 'echo ok')[0], ('warn', 'allow'))


class ApprovalTests(Fixture):
    class Verifier:
        def __init__(self, ok=True, kinds=None):
            self.ok, self.kinds, self.calls = ok, kinds or {'dropbox': 'dropbox'}, 0

        def remote_types(self):
            return dict(self.kinds)

        def verify(self, local_root, manifest, remote):
            self.calls += 1
            return cg.VerifyResult(self.ok, checked=len(manifest))

    def setUp(self):
        self.target = self.home / '.claude/projects' / ('old-%d' % time.monotonic_ns())
        (self.target / 'sub').mkdir(parents=True)
        (self.target / 'sub/a.jsonl').write_text('x\n')
        past = time.time() - 3600
        for p in (self.target / 'sub/a.jsonl', self.target / 'sub', self.target):
            os.utime(p, (past, past))

    def approve(self, path=None, remote='dropbox:backups/x', **kw):
        return cg.approve_delete(str(path or self.target), remote, verifier=kw.pop('verifier', self.Verifier()),
                                 home=str(self.home), policy=self.policy, **kw)

    def test_whole_roots_and_log_dirs_are_never_approvable(self):
        for rel in ('.claude', '.codex', '.agent-harness', '.claude/projects', '.claude/wals', '.codex/sessions', ''):
            with self.assertRaises(ValueError, msg=rel):
                self.approve(self.home / rel if rel else self.home)

    def test_failed_backup_check_refuses(self):
        with self.assertRaises(ValueError):
            self.approve(verifier=self.Verifier(ok=False))

    def test_non_dropbox_and_local_remotes_refused(self):
        with self.assertRaises(ValueError):
            self.approve(verifier=self.Verifier(kinds={'dropbox': 'local'}))
        for remote in ('/tmp/x', ':local:/tmp', 'nosuch:x', 'dropbox'):
            with self.assertRaises(ValueError, msg=remote):
                self.approve(remote=remote)

    def test_recent_change_refused(self):
        (self.target / 'sub/a.jsonl').write_text('y\n')
        with self.assertRaises(ValueError):
            self.approve()

    def test_single_use_and_bound_to_the_tree(self):
        self.approve()
        approvals = cg.Approvals(home=str(self.home), compiled=cg.Compiled(self.policy, home=str(self.home)))
        self.assertTrue(approvals.covers(str(self.target)))
        self.assertFalse(approvals.covers(str(self.target / 'sub')))  # exact path only
        self.assertTrue(approvals.consume())
        again = cg.Approvals(home=str(self.home), compiled=cg.Compiled(self.policy, home=str(self.home)))
        self.assertFalse(again.covers(str(self.target)))

    def test_changed_tree_voids_the_approval(self):
        self.approve()
        (self.target / 'sub/new.jsonl').write_text('z\n')
        approvals = cg.Approvals(home=str(self.home), compiled=cg.Compiled(self.policy, home=str(self.home)))
        self.assertFalse(approvals.covers(str(self.target)))

    def test_forged_mac_refused(self):
        self.approve()
        marker = self.home / '.agent-harness/state/log-delete-ok.json'
        data = json.loads(marker.read_text())
        data['entries'][-1]['expires_at'] += 10 ** 6
        marker.write_text(json.dumps(data))
        approvals = cg.Approvals(home=str(self.home), compiled=cg.Compiled(self.policy, home=str(self.home)))
        self.assertFalse(approvals.covers(str(self.target)))

    def test_concurrent_consumers_exactly_one_wins(self):
        self.approve()
        compiled = cg.Compiled(self.policy, home=str(self.home))
        racers = [cg.Approvals(home=str(self.home), compiled=compiled) for _ in range(6)]
        for r in racers:
            self.assertTrue(r.covers(str(self.target)))
        results = []
        threads = [threading.Thread(target=lambda r=r: results.append(r.consume())) for r in racers]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(results.count(True), 1, results)

    def test_every_decision_is_audited(self):
        self.approve()
        with self.assertRaises(ValueError):
            self.approve(self.home / '.claude')
        lines = (self.home / '.agent-harness/state/log-delete-audit.jsonl').read_text().splitlines()
        events = [json.loads(line)['event'] for line in lines]
        self.assertIn('approved', events)
        self.assertIn('refused', events)


class InterfaceTests(unittest.TestCase):
    def test_rclone_verifier_signature_is_stable(self):
        # the log-backup owner (feat/log-backup) imports this; changing it breaks their branch
        params = list(inspect.signature(cg.RcloneVerifier.verify).parameters)
        self.assertEqual(params, ['self', 'local_root', 'manifest', 'remote'])


class SafetyRuleTests(unittest.TestCase):
    """NEG-8 / S1: no test module passes corpus text to a shell."""

    BANNED = {('subprocess', 'run'), ('subprocess', 'Popen'), ('subprocess', 'call'), ('subprocess', 'check_call'),
              ('subprocess', 'check_output'), ('os', 'system'), ('os', 'popen')}

    def offenders(self, source):
        bad = []
        for node in ast.walk(ast.parse(source)):
            if not isinstance(node, ast.Call):
                continue
            f = node.func
            name = (getattr(f.value, 'id', None), f.attr) if isinstance(f, ast.Attribute) else (None, None)
            if name in {('os', 'system'), ('os', 'popen')}:
                bad.append(node.lineno)
            elif name in self.BANNED:
                if any(k.arg == 'shell' and getattr(k.value, 'value', False) for k in node.keywords):
                    bad.append(node.lineno)
                text = ast.dump(node)
                if 'corpus' in text or 'POSITIVE' in text or 'NEGATIVE' in text:
                    bad.append(node.lineno)
        return bad

    def test_this_suite_never_shells_out_corpus_text(self):
        for name in ('test_command_guard.py', 'command_guard_corpus.py'):
            source = (Path(__file__).resolve().parent / name).read_text()
            self.assertEqual(self.offenders(source), [], name)

    def test_scan_catches_a_seeded_violation(self):
        seeded = 'import subprocess, corpus\nsubprocess.run(corpus.LOG_POSITIVE[0], shell=True)\n'
        self.assertTrue(self.offenders(seeded))


if __name__ == '__main__':
    unittest.main()
