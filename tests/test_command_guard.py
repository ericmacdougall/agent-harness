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
        p.write_text('ref: refs/heads/main\n' if rel.endswith('/HEAD') else '{}\n' if rel.endswith('.json') else 'x\n')
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

    def test_heredoc_with_destructive_text_is_never_silent(self):
        # warn, never block: writing or printing the text is not a deletion, but it must not pass silently
        self.expect(corpus.HEREDOC_DESTRUCTIVE_WARN, 'warn', label='HEREDOC_DESTRUCTIVE_WARN')
        for cmd in corpus.HEREDOC_DESTRUCTIVE_WARN:
            self.assertIn('heredoc-destructive-text', self.decide(cmd)[1], cmd)
        self.expect(corpus.HEREDOC_DESTRUCTIVE_BLOCK, 'block', label='HEREDOC_DESTRUCTIVE_BLOCK')
        self.expect(corpus.HEREDOC_PLAIN_ALLOW, 'allow', label='HEREDOC_PLAIN_ALLOW')

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

    def test_write_stdin_has_no_trusted_cwd(self):
        """Red-team F5: typed shell input may run after a cd in an earlier call."""
        self.assertIsNone(cg.payload_cwd({'tool_name': 'write_stdin', 'cwd': '/elsewhere', 'tool_input': {'chars': 'x'}}))

    def test_blank_command_key_does_not_hide_another(self):
        """Red-team F8: every non-blank command field is judged; a JSON-string tool_input is decoded."""
        cmd = 'rm -rf ' + str(self.home) + '/.claude/projects'
        command, _ = cg.extract_command({'tool_name': 'exec_command', 'tool_input': {'command': '   ', 'cmd': cmd}})
        self.assertEqual(self.decide(command)[0], 'block')
        command, _ = cg.extract_command({'tool_name': 'exec_command', 'tool_input': {'command': 'ls', 'cmd': cmd}})
        self.assertEqual(self.decide(command)[0], 'block')
        command, _ = cg.extract_command({'tool_name': 'Bash', 'tool_input': json.dumps({'command': cmd})})
        self.assertEqual(command, cmd)
        # fresh red-team #11: a list command next to a string field
        command, _ = cg.extract_command({'tool_name': 'shell', 'tool_input': {
            'command': ['rm', '-rf', str(self.home) + '/.claude/projects'], 'cmd': 'ls'}})
        self.assertEqual(self.decide(command)[0], 'block')


class FailureModeTests(Fixture):
    def test_unterminated_quote_with_protected_text_blocks(self):
        self.assertEqual(self.decide("rm -rf ~/.claude/projects '")[0], 'block')
        self.assertEqual(self.decide('echo "rclone config show')[0], 'block')

    def test_unterminated_quote_without_protected_text_warns(self):
        self.assertEqual(self.decide("echo 'hello")[0], 'warn')

    def test_over_budget_with_exec_step_blocks(self):
        padding = 'true; ' * 120000
        self.assertEqual(self.decide(padding + 'echo eA== | base64 -d | sh; rm x')[0], 'block')

    def test_existing_script_counts_only_log_deletion(self):
        """Replay false positives: repo tooling that handles env is allowed; its log deletion still blocks."""
        tools = self.home / 'repo/tools'
        tools.mkdir(exist_ok=True)
        (tools / 'envcheck.sh').write_text('#!/bin/sh\nenv | sort\n')
        (tools / 'wipe.sh').write_text('#!/bin/sh\nrm -rf "$HOME/.claude/projects"\n')
        self.assertEqual(self.decide('bash @HOME@/repo/tools/envcheck.sh')[0], 'allow')
        self.assertEqual(self.decide('bash @HOME@/repo/tools/wipe.sh')[0], 'block')
        written = "printf 'env\\n' > @HOME@/repo/tools/new.sh && bash @HOME@/repo/tools/new.sh"
        self.assertEqual(self.decide(written)[0], 'block')

    def test_symlink_in_own_worktree_does_not_reach_protected(self):
        """Red-team F3: the own-worktree exception must hold for the path a symlink really leads to."""
        wt = self.home / '.agent-harness/work/S/T/wt'
        for name, target in (('lnk_claude', self.home / '.claude'), ('lnk_task', self.home / '.agent-harness/work/S/T'),
                             ('lnk_build', wt / 'build')):
            if not os.path.lexists(wt / name):
                os.symlink(str(target), str(wt / name))
        self.assertEqual(self.decide('rm -f lnk_claude/settings.json', cwd='@WT@')[0], 'block')
        self.assertEqual(self.decide('rm -f lnk_task/notes.md', cwd='@WT@')[0], 'block')
        self.assertEqual(self.decide('rm -f lnk_build/a.o', cwd='@WT@')[0], 'allow')

    def test_globs_and_dotdot_follow_links_like_the_shell(self):
        """Native code-inspection of b5daca9 (findings 3 and 4): `..` after a symlink and a hidden symlink under a
        wildcard are judged where the shell really goes."""
        wt = self.home / '.agent-harness/work/S/T/wt'
        (wt / 'linkfx/b').mkdir(parents=True, exist_ok=True)
        (wt / 'linkfx/d/e').mkdir(parents=True, exist_ok=True)
        (self.home / '.claude/projects/p').mkdir(parents=True, exist_ok=True)
        for link, target in ((wt / 'linkfx/b/c', self.home / '.claude/projects/p'),
                             (wt / 'linkfx/d/.hid', self.home / '.claude')):
            if not os.path.lexists(link):
                os.symlink(str(target), str(link))
        for cmd, want in corpus.LINK_GLOB_ROWS:
            self.assertEqual(self.decide(cmd, cwd='@WT@')[0], want, cmd)

    def test_brace_overflow_is_not_dropped(self):
        """Red-team F4: alternatives past the expansion cap are unknown, not absent."""
        alts = ','.join('d%d' % k for k in range(40)) + ',.claude'
        verdict, message = self.decide('rm -rf ~/{' + alts + '}/projects')
        self.assertEqual(verdict, 'block')
        self.assertIn('[log_delete/log-delete]', message)  # judged by the analyser, not its error fallback
        self.assertEqual(self.decide('rm -rf ~/{d1,.claude}/projects')[0], 'block')
        creds = ','.join('c%d' % k for k in range(40)) + ',.aws'
        self.assertEqual(self.decide('cat ~/{' + creds + '}/credentials')[0], 'block')
        self.assertEqual(self.decide('touch {' + ','.join('f%d' % k for k in range(40)) + '}')[0], 'allow')

    def test_internal_error_uses_raw_sensitive(self):
        """Red-team F6: an analyser bug must fail closed for commands that name protected locations."""
        original = cg.Analyzer.run
        def boom(self, *a, **k):
            raise ValueError('seeded analyser bug')
        cg.Analyzer.run = boom
        try:
            self.assertEqual(self.decide('rm -rf ~/.agent-harness/state')[0], 'block')
            self.assertEqual(self.decide('rm -rf ~/.claude')[0], 'block')
            self.assertEqual(self.decide('ls -la')[0], 'allow')
        finally:
            cg.Analyzer.run = original

    def test_remote_home_is_not_resolved_through_local_links(self):
        """Fresh red-team #1: on macOS /home is a symlink; ssh targets' Tier B paths must stay protected. The
        remote user is one that is not local on any test machine (on dev2 /home/someone is the local home, which
        is rightly resolved as local)."""
        original = cg._resolve_prefix
        cg._resolve_prefix = lambda p: ('/System/Volumes/Data' + p) if p and p.startswith('/home/') else original(p)
        try:
            for row in ('ssh dev2 "rm -rf /home/cgremote/.agent-harness/work"',
                        'ssh dev2 rm /home/cgremote/.claude/settings.json',
                        'ssh dev2 rm -rf /home/cgremote/.agent-harness/scratch'):
                self.assertEqual(self.decide(row)[0], 'block', row)
        finally:
            cg._resolve_prefix = original

    def test_over_budget_from_protected_cwd_blocks(self):
        """Fresh red-team #2: the unanalysable fallback must consider a protected working directory."""
        padding = "cat <<'EOF'\n" + ('x' * 280000) + "\nEOF\n"
        self.assertEqual(self.decide(padding + 'rm -rf projects', cwd='@HOME@/.claude')[0], 'block')
        nested = '$(' * 12 + 'true' + ')' * 12
        self.assertEqual(self.decide('echo ' + nested + '; rm -rf sessions', cwd='@HOME@/.codex')[0], 'block')
        self.assertIn(self.decide(padding + 'ls', cwd='@HOME@/repo')[0], ('warn', 'allow'))

    def test_powershell_overwrite_is_not_an_append(self):
        """Fresh red-team #3: -Value/-FilePath are not short-flag bundles containing a."""
        for row in ('Set-Content -Path ~/.claude/wals/s/main.jsonl -Value ""',
                    'Out-File -FilePath ~/.claude/history.jsonl'):
            self.assertEqual(self.decide(row, ps=True)[0], 'block', row)
        self.assertEqual(self.decide('Add-Content -Path ~/.claude/history.jsonl -Value x', ps=True)[0], 'allow')

    def test_dotnet_environment_dump_blocks(self):
        """Fresh red-team #9."""
        self.assertEqual(self.decide('[Environment]::GetEnvironmentVariables()', ps=True)[0], 'block')
        self.assertEqual(self.decide('[System.Environment]::GetEnvironmentVariable("GITHUB_TOKEN")', ps=True)[0], 'block')
        self.assertEqual(self.decide('[Environment]::GetEnvironmentVariable("PATH")', ps=True)[0], 'allow')

    def test_over_budget_plain_text_does_not_block(self):
        padding = 'true; ' * 120000
        self.assertIn(self.decide(padding + 'echo ok')[0], ('warn', 'allow'))


class PolicyFileTests(Fixture):
    """Red-team F2: a written or replaced policy file must not weaken the guard."""

    def test_hostile_policy_cannot_weaken(self):
        hostile = {
            'modes': {'secret_dump': 'warn', 'log_delete': 'warn', 'broad_kill': 'warn'},
            'protected_log_roots': [], 'protected_roots': [], 'protected_segment_names': [],
            'ancestor_roots': [], 'credential_path_regexes': [], 'guard_files': [],
            'allow_subtrees': ['{home}/.claude', '{home}/.claude/*'], 'temp_roots': ['{home}'],
            'credential_allow_regexes': ['.*'], 'secret_env_regex': 'NEVERMATCH',
            'limits': {'max_command_bytes': 1}, 'keep_suffixes': [],
        }
        path = self.home / 'hostile-policy.json'
        path.write_text(json.dumps(hostile))
        policy = cg.load_policy(path=str(path))
        compiled = cg.Compiled(policy, home=str(self.home), cwd=str(self.home / 'repo'))
        for row in ('rm -rf ~/.claude/projects', 'cat ~/.aws/credentials', 'env', 'rm -rf ~/.claude'):
            self.assertEqual(cg.decide(fill(row, self.home), compiled, cwd=str(self.home / 'repo'))[0], 'block', row)
        self.assertEqual(policy['allow_subtrees'], cg.DEFAULT_POLICY['allow_subtrees'])

    def test_policy_may_add_protection(self):
        path = self.home / 'extra-policy.json'
        path.write_text(json.dumps({'protected_log_roots': ['{home}/repo/precious'], 'modes': {'broad_kill': 'enforce'}}))
        policy = cg.load_policy(path=str(path))
        self.assertEqual(policy['modes']['broad_kill'], 'enforce')
        compiled = cg.Compiled(policy, home=str(self.home), cwd=str(self.home / 'repo'))
        self.assertEqual(cg.decide(fill('rm -rf @HOME@/repo/precious', self.home), compiled,
                                   cwd=str(self.home / 'repo'))[0], 'block')

    def test_creating_guard_files_blocks(self):
        for row in ("printf '{}' > ~/.claude/hooks/command_guard_policy.json",
                    'cp /dev/null ~/.codex/agent-harness/command_guard_policy.json',
                    "printf 'x' > ~/.claude/hooks/safe_input.py",
                    'tee ~/.claude/hooks/command_guard_extra.py < /dev/null'):
            self.assertEqual(self.decide(row)[0], 'block', row)

    def test_block_message_does_not_point_at_policy_file(self):
        self.assertNotIn('command_guard_policy', self.decide('rm -rf ~/.claude/projects')[1])


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


LAUNCHER_SRC = HOOKS / 'command_guard_hook.py'
PROTECTED_PAYLOAD = {'tool_name': 'Bash', 'tool_input': {'command': 'rm -rf /home/x/.claude/projects'}}
HARMLESS_PAYLOAD = {'tool_name': 'Bash', 'tool_input': {'command': 'ls -la'}}
READ_PAYLOAD = {'tool_name': 'Read', 'tool_input': {'file_path': '/home/x/.claude/projects/a.jsonl'}}
EXEC_PAYLOAD = {'tool_name': 'Bash', 'tool_input': {'command': 'echo eA== | base64 -d | sh; rm -f x'}}


class LauncherTests(unittest.TestCase):
    """command_guard_hook.py turns an analyser crash, hang or garbage into a raw-text decision (AC-6)."""

    def launcher_dir(self, guard_source=None, child_timeout=None):
        tmp = tempfile.TemporaryDirectory(prefix='cg-launcher-')
        self.addCleanup(tmp.cleanup)
        d = Path(tmp.name)
        text = LAUNCHER_SRC.read_text()
        if child_timeout is not None:
            text = text.replace('CHILD_TIMEOUT = 10.0', 'CHILD_TIMEOUT = %r' % child_timeout)
        (d / 'command_guard_hook.py').write_text(text)
        if guard_source is None:
            for name in ('command_guard.py', 'redact.py', 'safe_input.py'):
                (d / name).write_text((HOOKS / name).read_text())
        else:
            (d / 'command_guard.py').write_text(guard_source)
        return d

    def run_launcher(self, d, payload):
        import subprocess
        data = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        env = {'PATH': '/usr/bin:/bin', 'HOME': str(d)}
        done = subprocess.run([sys.executable, str(d / 'command_guard_hook.py')], input=data, env=env,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60, check=False)
        return done.returncode, done.stderr.decode()

    def test_real_analyser_blocks_and_allows(self):
        d = self.launcher_dir()
        self.assertEqual(self.run_launcher(d, PROTECTED_PAYLOAD)[0], 2)
        self.assertEqual(self.run_launcher(d, HARMLESS_PAYLOAD)[0], 0)
        self.assertEqual(self.run_launcher(d, READ_PAYLOAD)[0], 0)

    def test_crashing_analyser_fails_closed_for_sensitive_text(self):
        d = self.launcher_dir('import sys\nraise SystemExit(7)\n')
        code, err = self.run_launcher(d, PROTECTED_PAYLOAD)
        self.assertEqual(code, 2, err)
        self.assertEqual(self.run_launcher(d, EXEC_PAYLOAD)[0], 2)
        self.assertEqual(self.run_launcher(d, HARMLESS_PAYLOAD)[0], 0)
        self.assertEqual(self.run_launcher(d, READ_PAYLOAD)[0], 0)

    def test_missing_analyser_fails_closed(self):
        d = self.launcher_dir('')
        (d / 'command_guard.py').unlink()  # this test's own temp copy
        self.assertEqual(self.run_launcher(d, PROTECTED_PAYLOAD)[0], 2)

    def test_hanging_analyser_times_out_closed(self):
        d = self.launcher_dir('import time\ntime.sleep(30)\n', child_timeout=1.0)
        started = time.monotonic()
        self.assertEqual(self.run_launcher(d, PROTECTED_PAYLOAD)[0], 2)
        self.assertLess(time.monotonic() - started, 20)

    def test_garbage_output_fails_closed(self):
        d = self.launcher_dir('print("not json")\n')
        self.assertEqual(self.run_launcher(d, PROTECTED_PAYLOAD)[0], 2)

    def test_unparsable_payload_is_probed(self):
        d = self.launcher_dir('import sys\nraise SystemExit(7)\n')
        self.assertEqual(self.run_launcher(d, b'{not json rm -rf ~/.claude/wals')[0], 2)

    def test_large_non_shell_payload_is_fast(self):
        d = self.launcher_dir()
        big = {'tool_name': 'Write', 'tool_input': {'file_path': '/tmp/x', 'content': 'y' * (4 << 20)}}
        started = time.monotonic()
        self.assertEqual(self.run_launcher(d, big)[0], 0)
        self.assertLess(time.monotonic() - started, 10)

    def test_launcher_is_stdlib_only(self):
        tree = ast.parse(LAUNCHER_SRC.read_text())
        mods = {a.name.split('.')[0] for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
        mods |= {n.module.split('.')[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module}
        self.assertLessEqual(mods, {'json', 'os', 're', 'subprocess', 'sys'})


class GuardCompositionTests(unittest.TestCase):
    """The command guard and the heavy-job guard (#53) both classify Bash commands. They are separate hook groups
    and decide independently: neither one's allow, hatch or crash policy can override the other's block."""

    def run_both(self, command):
        import subprocess
        home = tempfile.TemporaryDirectory(prefix='cg-compose-')
        self.addCleanup(home.cleanup)
        data = json.dumps({'tool_name': 'Bash', 'tool_input': {'command': command}, 'session_id': 's'}).encode()
        env = {'PATH': '/usr/bin:/bin', 'HOME': home.name, 'HARNESS_HEAVY_GUARD_FORCE': '1'}
        codes = {}
        for name, argv in (('command', [str(HOOKS / 'command_guard_hook.py'), 'hook']),
                           ('heavy', [str(HOOKS / 'heavy_job_guard.py')])):
            done = subprocess.run([sys.executable] + argv, input=data, env=env, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, timeout=60, check=False)
            codes[name] = done.returncode
        return codes

    def test_each_guard_blocks_its_own_class_and_allows_the_other(self):
        protected = PROTECTED_PAYLOAD['tool_input']['command']
        self.assertEqual(self.run_both('ls -la'), {'command': 0, 'heavy': 0})
        self.assertEqual(self.run_both('pytest'), {'command': 0, 'heavy': 2})
        self.assertEqual(self.run_both(protected), {'command': 2, 'heavy': 0})
        self.assertEqual(self.run_both('pytest; ' + protected), {'command': 2, 'heavy': 2})

    def test_heavy_job_hatch_does_not_bypass_the_command_guard(self):
        protected = PROTECTED_PAYLOAD['tool_input']['command']
        hatch = 'HARNESS_LOCAL_OK=needs-the-local-mac-gpu '
        self.assertEqual(self.run_both(hatch + 'pytest')['heavy'], 0)
        self.assertEqual(self.run_both(hatch + protected)['command'], 2)

    def test_install_keeps_the_guards_in_separate_groups(self):
        sys.path.insert(0, str(ROOT))
        import install
        groups = install.managed_hooks(Path('/home/u/.claude'))['PreToolUse']
        scripts = [[Path((h.get('args') or [''])[0]).name for h in g['hooks']] for g in groups]
        self.assertEqual(scripts[0], ['command_guard_hook.py'])
        self.assertEqual(groups[0]['hooks'][0]['onFailure'], 'block')
        heavy = [g for g, s in zip(groups, scripts) if 'heavy_job_guard.py' in s]
        self.assertEqual(len(heavy), 1)
        self.assertEqual([Path(h['args'][0]).name for h in heavy[0]['hooks']], ['heavy_job_guard.py'])
        self.assertNotIn('onFailure', heavy[0]['hooks'][0])  # fail-open by design (#53); the guard stays fail-closed


class InstallTests(unittest.TestCase):
    def setUp(self):
        sys.path.insert(0, str(ROOT))
        import install
        import install_codex
        self.install, self.install_codex = install, install_codex
        tmp = tempfile.TemporaryDirectory(prefix='cg-install-')
        self.addCleanup(tmp.cleanup)
        self.home = Path(tmp.name)

    def guard_groups(self, settings):
        return [g for g in settings['hooks'].get('PreToolUse', [])
                if any('command_guard_hook.py' in ' '.join(h.get('args') or [h.get('command', '')])
                       for h in g.get('hooks', []))]

    def test_claude_registration_and_rollback(self):
        claude = self.home / '.claude'
        settings = self.install.merged_settings({}, claude)
        groups = self.guard_groups(settings)
        self.assertEqual(len(groups), 1)
        hook = groups[0]['hooks'][0]
        self.assertEqual(hook['onFailure'], 'block')
        self.assertEqual(hook['timeout'], 30)
        self.assertIn('Bash', groups[0]['matcher'])
        again = self.install.merged_settings(settings, claude)
        self.assertEqual(len(self.guard_groups(again)), 1)  # idempotent
        rolled_back = self.install.merged_settings(settings, claude, command_guard=False)
        self.assertEqual(self.guard_groups(rolled_back), [])
        for name in ('command_guard.py', 'command_guard_hook.py', 'redact.py', 'safe_input.py'):
            self.assertIn(name, self.install.HOOKS)

    def test_codex_registration_has_no_matcher_and_rolls_back(self):
        codex = self.home / '.codex'
        hooks = self.install_codex.merge_hooks({}, codex)
        guard = self.install_codex.guard_command(codex)
        groups = [g for g in hooks['hooks']['PreToolUse'] if g['hooks'][0]['command'] == guard]
        self.assertEqual(len(groups), 1)
        self.assertNotIn('matcher', groups[0])
        self.assertEqual(len([g for g in self.install_codex.merge_hooks(hooks, codex)['hooks']['PreToolUse']
                              if g['hooks'][0]['command'] == guard]), 1)
        off = self.install_codex.merge_hooks(hooks, codex, command_guard=False)
        self.assertFalse([g for g in off['hooks']['PreToolUse'] if g['hooks'][0]['command'] == guard])
        for name in ('command_guard.py', 'command_guard_hook.py', 'redact.py', 'safe_input.py'):
            self.assertIn(name, self.install_codex.DELIVERY_HELPERS)

    def test_guard_carries_the_gate_verb_and_replaces_a_verbless_entry(self):
        # cmd/harness/gates.json lists command-guard as a fail-closed gate only when the hook verb is present.
        claude, codex = self.home / '.claude', self.home / '.codex'
        hook = self.guard_groups(self.install.merged_settings({}, claude))[0]['hooks'][0]
        self.assertEqual(hook['args'][1:], ['hook'])
        guard = self.install_codex.guard_command(codex)
        self.assertTrue(guard.endswith(' hook'))
        legacy = {'hooks': {'PreToolUse': [{'hooks': [{'type': 'command', 'timeout': 30,
                                                       'command': self.install_codex.guard_command(codex, '')}]}]}}
        merged = self.install_codex.merge_hooks(legacy, codex)
        commands = [h['command'] for g in merged['hooks']['PreToolUse'] for h in g['hooks']]
        self.assertEqual([c for c in commands if 'command_guard_hook.py' in c], [guard])

    def test_old_claude_version_warns(self):
        self.assertIn('WARNING', self.install.command_guard_status(True, runner=lambda: '2.1.200 (Claude Code)'))
        self.assertNotIn('WARNING', self.install.command_guard_status(True, runner=lambda: '2.1.295 (Claude Code)'))
        self.assertIn('not registered', self.install.command_guard_status(False))


class DoctorTests(unittest.TestCase):
    def test_doctor_reports_unregistered_and_old_version(self):
        with tempfile.TemporaryDirectory(prefix='cg-doctor-') as d:
            home = Path(d)
            (home / '.claude' / 'hooks').mkdir(parents=True)
            checks = {name: ok for name, ok, _ in cg.doctor(home=home, version_runner=lambda: '2.1.100')}
            self.assertFalse(checks['claude files'])
            self.assertFalse(checks['claude registered'])
            self.assertTrue(checks['self-test probes'])

    def test_doctor_healthy_install(self):
        sys.path.insert(0, str(ROOT))
        import install
        with tempfile.TemporaryDirectory(prefix='cg-doctor-') as d:
            home = Path(d)
            hooks = home / '.claude' / 'hooks'
            hooks.mkdir(parents=True)
            for name in ('command_guard.py', 'command_guard_hook.py', 'redact.py', 'safe_input.py'):
                (hooks / name).write_text('#\n')
            (home / '.claude' / 'settings.json').write_text(json.dumps(install.merged_settings({}, home / '.claude')))
            checks = cg.doctor(home=home, version_runner=lambda: '2.1.300')
            self.assertTrue(all(ok for _n, ok, _d in checks), checks)


class DocsTests(unittest.TestCase):
    def test_operations_section_and_readme_line(self):
        ops = (ROOT / 'docs' / 'operations.md').read_text()
        self.assertIn('## Command guard', ops)
        for needle in ('approve-delete', 'doctor', '--no-command-guard', '#14500', 'not an ownership boundary',
                       'git clean'):
            self.assertIn(needle, ops)
        self.assertIn('command_guard', (ROOT / 'README.md').read_text())


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
