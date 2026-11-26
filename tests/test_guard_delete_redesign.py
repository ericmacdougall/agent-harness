"""The deletion side of the command guard after the owner's redesign of 2026-11-24.

Effect, not words: a command is refused only when it would itself delete, move away or overwrite a protected target.
Roles (ah_roles.may_delete): own roots and checkouts the caller made, supervised projects, Fable/Astra anywhere; the one
exception for everyone is transcripts, WALs and audit logs (a verified copy first: approve-delete or `ah log-push`).
Also: the rule-file write rule, the harness-maintainer lift, `ah worktree-remove` (free-worktree) and `ah log-push`.

Every command string is DATA handed to command_guard.decide(); nothing here executes one. CG_HOOKS_DIR points the tests at
another implementation (to show them failing on the old code).
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
HOOKS = Path(os.environ.get('CG_HOOKS_DIR') or ROOT / 'harness/hooks')
sys.path.insert(0, str(HOOKS))

import command_guard as cg  # noqa: E402

SID = '11111111-2222-3333-4444-555555555555'
OTHER = '99999999-8888-7777-6666-555555555555'


def git(cwd, *args):
    env = dict(os.environ, GIT_AUTHOR_NAME='t', GIT_AUTHOR_EMAIL='t@t', GIT_COMMITTER_NAME='t', GIT_COMMITTER_EMAIL='t@t',
               GIT_CONFIG_GLOBAL='/dev/null', GIT_CONFIG_NOSYSTEM='1')
    return subprocess.run(['git', '-C', str(cwd), *args], check=True, capture_output=True, text=True,
                          env=env).stdout.strip()


class Home(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix='cg-redesign-')
        self.addCleanup(tmp.cleanup)
        self.home = Path(os.path.realpath(tmp.name))
        patch = mock.patch.dict(os.environ, {'HOME': str(self.home)})
        patch.start()
        self.addCleanup(patch.stop)
        self.own = self.home / '.agent-harness/work' / SID
        self.wt = self.own / 'wt'
        for rel in ('.claude/wals/%s/main.jsonl' % SID, '.claude/projects/p/%s.jsonl' % SID, '.claude/settings.json',
                    '.claude/CLAUDE.md', '.claude/CLAUDE.md.bak.1', '.claude/hooks/command_guard.py',
                    '.claude/plugins/cache/x/a.js', '.codex/AGENTS.md', '.agent-harness/state/log-delete-ok.json',
                    '.agent-harness/work/%s/tmpdir/a' % OTHER, '.agent-harness/work/%s/tmpdir/a' % SID):
            p = self.home / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text('{}\n')
        self.wt.mkdir(parents=True)
        git(self.wt, 'init', '-q', '-b', 'main')
        for rel in ('node_modules/.cache/x', '__pycache__/a.pyc', '.pytest_cache/v', 'build/a.o', 'fix.sh', 'w.py'):
            p = self.wt / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text('x\n')
        (self.wt / 'w.sh').write_text('#!/bin/bash\ncp new.md ~/.claude/CLAUDE.md\nrm -rf ~/.claude/wals/old\n')
        self.policy = cg.load_policy(path=str(self.home / 'no-policy.json'))

    def payload(self, **extra):
        return dict({'session_id': SID, 'tool_name': 'Bash'}, **extra)

    def decide(self, command, cwd=None, payload=None):
        cwd = str(cwd or self.wt)
        compiled = cg.Compiled(self.policy, home=str(self.home), cwd=cwd)
        command = command.replace('~/', str(self.home) + '/')
        if 'payload' not in cg.decide.__code__.co_varnames:  # an older guard (CG_HOOKS_DIR): it knows no caller
            return cg.decide(command, compiled, cwd=cwd)
        return cg.decide(command, compiled, cwd=cwd, payload=self.payload() if payload is None else payload)

    def verdicts(self, rows, **kw):
        return {row: self.decide(row, **kw)[0] for row in rows}


class ReportedFalseRefusals(Home):
    """Each of these was refused (or flagged) before; each is a read, a parse check, prose or an own cleanup."""

    ROWS = [
        'cat ~/.claude/wals/%s/main.jsonl' % SID,
        'tail -5 ~/.claude/wals/%s/main.jsonl | jq .' % SID,
        'grep -c intent ~/.claude/wals/%s/main.jsonl' % SID,
        'python3 -c "import json; print(len(open(\'~/.claude/wals/%s/main.jsonl\').read()))"' % SID,
        'python3 -m pytest tests -q && rm -rf node_modules/.cache',
        'make && rm -rf __pycache__ .pytest_cache build',
        'git commit -m "drop the rm -rf ~/.claude/wals step"',
        "cat > notes.md <<'EOF'\nnever rm -rf ~/.claude/projects or ~/.codex/sessions\nEOF",
        "cat > gen.py <<'EOF'\nimport shutil\nshutil.rmtree('~/.claude/wals/old')\nEOF",
        'gh issue create --title t --body "cleanup: rm -rf ~/.claude/wals"',
        "jq 'keys' ~/.claude/settings.json",
        'grep -n hooks ~/.claude/settings.json',
        'cat ~/.claude/settings.json',
        'python3 ~/.claude/hooks/ah.py --help',
        'bash w.sh --help',
        'bash -n w.sh',
        'sh -n fix.sh',
        'python3 -m py_compile w.py',
        'shellcheck w.sh',
        'cat w.sh',
        'less w.sh',
        "python3 -c \"import re; print('remove wals'.replace('a', 'b')); [].remove\"",
    ]

    def test_reads_prose_parse_checks_and_own_cleanups_are_allowed(self):
        got = self.verdicts(self.ROWS)
        self.assertEqual({k: v for k, v in got.items() if v != 'allow'}, {})

    def test_running_the_script_is_judged_by_what_it_does(self):
        self.assertEqual(self.decide('bash w.sh')[0], 'block')


class RuleFiles(Home):
    WRITES = ['echo x >> ~/.claude/CLAUDE.md', 'cp new.md ~/.claude/CLAUDE.md', "sed -i '' s/a/b/ ~/.claude/CLAUDE.md",
              'tee -a ~/.codex/AGENTS.md < x', 'mv x ~/.codex/AGENTS.md',
              'python3 -c "open(\'~/.claude/CLAUDE.md\', \'w\').write(\'x\')"']
    NOT_WRITES = ["cat > write_rules.sh <<'EOF'\necho x >> ~/.claude/CLAUDE.md\nEOF", 'bash -n write_rules.sh',
                  'cat ~/.claude/CLAUDE.md', 'grep -n Hard ~/.codex/AGENTS.md', 'diff ~/.claude/CLAUDE.md x']

    def test_direct_writes_are_refused_for_an_ordinary_agent(self):
        for row in self.WRITES:
            verdict, message = self.decide(row)
            self.assertEqual(verdict, 'block', row)
            self.assertIn('rule-file-write', message, row)

    def test_creating_reading_and_parse_checking_a_script_that_would_write_is_allowed(self):
        (self.wt / 'write_rules.sh').write_text('echo x >> ~/.claude/CLAUDE.md\n')
        self.assertEqual({k: v for k, v in self.verdicts(self.NOT_WRITES).items() if v != 'allow'}, {})

    def test_top_rung_and_supervisors_may_write_them(self):
        top = self.payload(model='claude-fable-5')
        self.assertEqual(self.decide(self.WRITES[0], payload=top)[0], 'allow')
        import ah_roles
        ah_roles.set_supervisor(SID, [str(self.home / 'proj')], home=str(self.home))
        self.assertEqual(self.decide(self.WRITES[1])[0], 'allow')


class Roles(Home):
    def test_own_roots_are_deletable_and_another_sessions_are_not(self):
        self.assertEqual(self.decide('rm -rf ~/.agent-harness/work/%s/tmpdir' % SID)[0], 'allow')
        verdict, message = self.decide('rm -rf ~/.agent-harness/work/%s/tmpdir' % OTHER)
        self.assertEqual(verdict, 'block')
        self.assertIn('supervisor', message)
        self.assertIn('Fable/Astra', message)

    def test_harness_files_follow_the_roles_and_the_top_rung_deletes_anywhere(self):
        rows = ['rm -rf ~/.claude/plugins/cache/x', 'rm ~/.claude/CLAUDE.md.bak.1',
                'rm -rf ~/.agent-harness/work/%s/tmpdir' % OTHER]
        self.assertEqual(set(self.verdicts(rows).values()), {'block'})
        top = self.payload(model='claude-fable-5')
        self.assertEqual(set(self.verdicts(rows, payload=top).values()), {'allow'})

    def test_a_supervisor_may_delete_inside_its_projects_only(self):
        import ah_roles
        ah_roles.set_supervisor(SID, [str(self.home / '.agent-harness/work' / OTHER)], home=str(self.home))
        self.assertEqual(self.decide('rm -rf ~/.agent-harness/work/%s/tmpdir' % OTHER)[0], 'allow')
        self.assertEqual(self.decide('rm -rf ~/.claude/plugins/cache/x')[0], 'block')
        # its sub-agents act as ordinary agents
        sub = self.payload(agent_id='abcd1234')
        self.assertEqual(self.decide('rm -rf ~/.agent-harness/work/%s/tmpdir' % OTHER, payload=sub)[0], 'block')

    def test_records_need_a_verified_copy_for_everyone_and_the_refusal_names_log_push(self):
        top = self.payload(model='claude-fable-5')
        for row in ('rm -rf ~/.claude/wals/%s' % SID, 'rm ~/.claude/projects/p/%s.jsonl' % SID,
                    'mv ~/.claude/wals/%s /tmp/x' % SID, 'rm -rf ~/.agent-harness/state',
                    'python3 -c "import shutil; shutil.rmtree(\'~/.claude/wals\')"', 'rm -rf ~/.claude'):
            for who in (None, top):
                verdict, message = self.decide(row, payload=who)
                self.assertEqual(verdict, 'block', (row, who))
                self.assertIn('ah.py log-push', message, row)
                self.assertIn('approve-delete', message, row)

    def test_a_delete_approval_lifts_a_role_refusal_but_never_the_records_rule(self):
        # 2026-11-24 integration: `ah approve delete --path P` covers a path a role would refuse; transcripts, WALs and
        # audit logs keep needing a verified copy whatever the store says
        import ah_approvals
        other = 'rm -rf ~/.agent-harness/work/%s/tmpdir' % OTHER
        verdict, message = self.decide(other)
        self.assertEqual(verdict, 'block')
        self.assertIn('ah approve delete --path', message)
        with mock.patch.dict(os.environ, {'AH_HOME': str(self.home)}):
            ah_approvals.grant('delete', {'path': str(self.home / '.agent-harness/work' / OTHER)}, 'user', 't',
                               home=str(self.home))
            ah_approvals.grant('delete', {'path': str(self.home / '.claude')}, 'user', 't', home=str(self.home))
            self.assertEqual(self.decide(other)[0], 'allow')
            self.assertEqual(self.decide('rm -rf ~/.claude/wals/%s' % SID)[0], 'block')
            self.assertEqual(self.decide('rm ~/.claude/projects/p/%s.jsonl' % SID)[0], 'block')
            self.assertEqual(self.decide('rm -rf ~/.claude/plugins/cache/x')[0], 'allow')

    def test_a_worktree_the_caller_made_elsewhere_is_its_own(self):
        outside = self.home / '.agent-harness/work' / OTHER / 'made-by-me'
        outside.mkdir(parents=True)
        transcript = self.home / ('.claude/projects/p/%s.jsonl' % SID)
        call = {'type': 'assistant', 'cwd': str(self.wt), 'message': {'content': [{
            'type': 'tool_use', 'name': 'Bash', 'input': {'command': 'git worktree add %s -b x' % outside}}]}}
        transcript.write_text(json.dumps(call) + '\n')
        payload = self.payload(transcript_path=str(transcript))
        self.assertEqual(self.decide('rm -rf %s' % outside, payload=payload)[0], 'allow')
        self.assertEqual(self.decide('rm -rf %s' % outside)[0], 'block')  # without the transcript it is not known

    def test_git_worktree_remove_follows_the_roles(self):
        self.assertEqual(self.decide('git worktree remove ~/.agent-harness/work/%s/wt2' % SID)[0], 'allow')
        self.assertEqual(self.decide('git worktree remove ~/.agent-harness/work/%s/tmpdir' % OTHER)[0], 'block')
        self.assertEqual(self.decide('git worktree remove /srv/elsewhere/wt')[0], 'allow')  # git refuses a dirty one
        verdict, message = self.decide('git worktree remove --force /srv/elsewhere/wt')
        self.assertEqual(verdict, 'block')
        self.assertIn('--rescue', message)

    def test_an_unreadable_operand_is_allowed_with_a_note_unless_it_names_records(self):
        self.assertEqual(self.decide('rm -rf "$(mktemp -d)/x" "$BUILD_DIR/out"')[0], 'allow')
        self.assertEqual(self.decide('D=~/.claude/wals; rm -rf "$D"')[0], 'block')


class RecordsWhenTheReadingsDisagree(Home):
    """Integration 2026-11-24: a `>!` command the guard cannot judge under both shell readings is allowed with a note,
    except when its visible text deletes, moves or overwrites a transcript, session WAL or audit-log path."""

    def test_records_targets_still_block(self):
        for row in ("cd ~/proj; eval '>! x cd /tmp'; echo > ../.claude/projects/p/%s.jsonl" % SID,
                    "cd ~/proj; eval '>! x cd /tmp'; rm -rf ../.claude/projects",
                    "R='rm -rf'; eval '>! x R=ls'; $R ~/.claude/wals"):
            (self.home / 'proj').mkdir(exist_ok=True)
            verdict, message = self.decide(row.replace('~/', str(self.home) + '/'), cwd=self.home)
            self.assertEqual(verdict, 'block', (row, message))
            self.assertIn('log-push', message)

    def test_other_targets_only_warn(self):
        (self.home / 'proj').mkdir(exist_ok=True)
        for row in ("cd ~/proj; eval '>! x cd /tmp'; rm -rf build", "eval '>! x cd /tmp'; echo hi > notes.txt"):
            self.assertNotEqual(self.decide(row.replace('~/', str(self.home) + '/'), cwd=self.home)[0], 'block', row)


class Maintainer(Home):
    def test_a_supervising_top_rung_session_may_change_the_machinery_and_is_audited(self):
        rows = ['echo x > ~/.claude/hooks/command_guard.py', 'cp new.json ~/.claude/settings.json',
                "sed -i '' s/a/b/ ~/.claude/hooks/command_guard.py"]
        self.assertEqual(set(self.verdicts(rows).values()), {'block'})
        self.assertEqual(set(self.verdicts(rows, payload=self.payload(model='claude-fable-5')).values()), {'block'})
        import ah_roles
        ah_roles.set_supervisor(SID, [str(self.home / 'proj')], home=str(self.home))
        maintainer = self.payload(model='claude-fable-5')
        self.assertEqual(set(self.verdicts(rows, payload=maintainer).values()), {'allow'})
        log = self.home / '.agent-harness/logs/harness-maintainer.jsonl'
        self.assertTrue(log.is_file() and log.read_text().count('\n') >= 1)
        # the records exception still holds for a maintainer
        self.assertEqual(self.decide('rm -rf ~/.claude/wals/%s' % SID, payload=maintainer)[0], 'block')

    def test_other_harness_files_may_be_overwritten_by_anyone(self):
        (self.home / '.agent-harness/work' / OTHER / 'notes.md').write_text('x\n')
        self.assertEqual(self.decide('echo x > ~/.agent-harness/work/%s/notes.md' % OTHER)[0], 'allow')


class FreeWorktree(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix='cg-free-')
        self.addCleanup(tmp.cleanup)
        self.home = Path(os.path.realpath(tmp.name))
        patch = mock.patch.dict(os.environ, {'HOME': str(self.home)})
        patch.start()
        self.addCleanup(patch.stop)
        self.primary = self.home / 'code/proj'
        self.primary.mkdir(parents=True)
        git(self.primary, 'init', '-q', '-b', 'main')
        (self.primary / 'a.txt').write_text('one\n')
        git(self.primary, 'add', 'a.txt')
        git(self.primary, 'commit', '-q', '-m', 'one')
        self.linked = self.home / '.agent-harness/work' / SID / 'wt'
        self.linked.parent.mkdir(parents=True)
        git(self.primary, 'worktree', 'add', '-q', '-b', 'feature', str(self.linked))
        self.head = git(self.linked, 'rev-parse', 'HEAD')
        self.wal = self.home / '.claude/wals' / SID
        self.wal.mkdir(parents=True)  # the owning session is live (just written)

    def publish(self):
        git(self.primary, 'update-ref', 'refs/remotes/origin/feature', git(self.linked, 'rev-parse', 'HEAD'))

    def test_clean_and_published_is_removed_by_anyone(self):
        self.publish()
        report = cg.free_worktree(str(self.linked))
        self.assertTrue(report['removed'], report)
        self.assertFalse(self.linked.exists())

    def test_uncommitted_changes_need_rescue_and_rescue_saves_a_patch_and_the_commits(self):
        (self.linked / 'b.txt').write_text('new\n')
        git(self.linked, 'add', 'b.txt')
        git(self.linked, 'commit', '-q', '-m', 'local')
        (self.linked / 'dirty.txt').write_text('uncommitted\n')
        report = cg.free_worktree(str(self.linked))
        self.assertFalse(report['removable'])
        self.assertIn('--rescue', report['reason'])
        patches = self.home / '.agent-harness/work' / OTHER / 'rescue'
        report = cg.free_worktree(str(self.linked), rescue=True, patch_dir=str(patches))
        self.assertTrue(report['removed'], report)
        self.assertIn('dirty.txt', Path(report['patch']).read_text())
        self.assertEqual(git(self.primary, 'rev-parse', report['rescue_ref']), git(self.primary, 'rev-parse', 'feature'))

    def test_unpushed_commits_of_an_ended_session_are_kept_in_a_rescue_ref(self):
        git(self.linked, 'checkout', '-q', '--detach')
        (self.linked / 'c.txt').write_text('detached\n')
        git(self.linked, 'add', 'c.txt')
        git(self.linked, 'commit', '-q', '-m', 'detached only')
        detached = git(self.linked, 'rev-parse', 'HEAD')
        self.assertFalse(cg.free_worktree(str(self.linked))['removable'])  # session live, not published
        old = 1_000_000_000
        os.utime(self.wal, (old, old))
        report = cg.free_worktree(str(self.linked))
        self.assertTrue(report['removed'], report)
        self.assertEqual(git(self.primary, 'rev-parse', report['rescue_ref']), detached)

    def test_a_process_inside_still_stops_it_and_the_primary_is_never_removable(self):
        self.publish()
        self.assertFalse(cg.free_worktree(str(self.primary))['removable'])
        with mock.patch.object(cg, 'busy_scan', return_value={'busy': [(1, 'sh')], 'unreadable': [], 'skipped': [],
                                                               'failed': False}):
            self.assertIn('process', cg.free_worktree(str(self.linked))['reason'])

    def test_the_guard_admits_rescue_only_for_its_own_session_a_supervisor_or_the_top_rung(self):
        other = self.home / '.agent-harness/work' / OTHER / 'wt'
        git(self.primary, 'worktree', 'add', '-q', '-b', 'other', str(other))
        command = 'python3 ~/.claude/hooks/ah.py worktree-remove --host local --path %s --rescue' % other
        self.assertIsNotNone(cg.worktree_rescue_refusal(command, {'session_id': SID}))
        self.assertIsNone(cg.worktree_rescue_refusal(command, {'session_id': OTHER}))
        self.assertIsNone(cg.worktree_rescue_refusal(command, {'session_id': SID, 'model': 'claude-fable-5'}))
        import ah_roles
        ah_roles.set_supervisor(SID, [str(self.primary)], home=str(self.home))
        self.assertIsNone(cg.worktree_rescue_refusal(command, {'session_id': SID}))
        self.assertIsNone(cg.worktree_rescue_refusal(command.replace(' --rescue', ''), {'session_id': SID}))


class LogPush(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix='log-push-')
        self.addCleanup(tmp.cleanup)
        self.home = Path(os.path.realpath(tmp.name)) / 'home'
        self.remote = Path(os.path.realpath(tmp.name)) / 'logs.git'
        self.home.mkdir()
        git(self.home.parent, 'init', '-q', '--bare', str(self.remote))
        self.wals = self.home / '.claude/wals' / SID
        self.wals.mkdir(parents=True)
        (self.wals / 'main.jsonl').write_text('{"a":1}\n')
        (self.wals / 'sub').mkdir()
        (self.wals / 'sub/b.jsonl').write_bytes(b'\x00binary\xff\n')
        import ah_log_push
        self.lp = ah_log_push
        self.lp.setup(str(self.remote), home=self.home)

    def test_push_verifies_then_deletes_and_audits(self):
        report = self.lp.push([str(self.wals)], home=self.home)
        self.assertTrue(report['ok'], report)
        self.assertEqual(report['deleted'], 2)
        self.assertFalse(self.wals.exists())
        tree = git(self.remote, 'ls-tree', '-r', '--name-only', 'main')
        self.assertIn('.claude/wals/%s/sub/b.jsonl' % SID, tree)
        self.assertEqual(git(self.remote, 'cat-file', '-p', 'main:%s' % [t for t in tree.split('\n')
                                                                          if t.endswith('main.jsonl')][0]), '{"a":1}')
        row = json.loads((self.home / '.agent-harness/logs/log-push.jsonl').read_text().splitlines()[-1])
        self.assertEqual(row['deleted'], 2)
        # a second push lands on top of the first (no force)
        (self.home / '.claude/wals/x').mkdir(parents=True)
        (self.home / '.claude/wals/x/main.jsonl').write_text('2\n')
        self.assertTrue(self.lp.push([str(self.home / '.claude/wals/x/main.jsonl')], home=self.home)['ok'])
        self.assertEqual(git(self.remote, 'rev-list', '--count', 'main'), '2')

    def test_dry_run_changes_nothing(self):
        report = self.lp.push([str(self.wals)], dry_run=True, home=self.home)
        self.assertTrue(report['ok'])
        self.assertTrue((self.wals / 'main.jsonl').exists())
        self.assertNotIn('main', subprocess.run(['git', '--git-dir', str(self.remote), 'branch'], capture_output=True,
                                                text=True).stdout)

    def test_a_file_that_changes_during_the_push_is_kept(self):
        real = self.lp.build_commit

        def append_then_build(*args, **kw):
            commit = real(*args, **kw)
            with open(self.wals / 'main.jsonl', 'a') as handle:
                handle.write('{"late":true}\n')
            return commit
        with mock.patch.object(self.lp, 'build_commit', append_then_build):
            report = self.lp.push([str(self.wals)], home=self.home)
        self.assertFalse(report['ok'])
        self.assertTrue((self.wals / 'main.jsonl').exists())
        self.assertEqual(report['deleted'], 1)

    def test_size_limit_refuses_before_anything_is_pushed(self):
        (self.wals / 'big.jsonl').write_bytes(b'x' * 2_000_000)
        with self.assertRaises(self.lp.PushError) as caught:
            self.lp.push([str(self.wals)], max_mb=1, home=self.home)
        self.assertIn('limit', str(caught.exception))
        self.assertTrue((self.wals / 'main.jsonl').exists())

    def test_public_and_unknown_repositories_are_refused(self):
        def gh(answer, code=0):
            return lambda *a, **k: subprocess.CompletedProcess(a, code, stdout=answer, stderr='')
        url = 'https://github.com/someone/logs.git'
        self.assertIn('public', self.lp.visibility_refusal(url, gh('PUBLIC\n')))
        self.assertIn('unknown', self.lp.visibility_refusal(url, gh('', 1)))
        self.assertIsNone(self.lp.visibility_refusal(url, gh('PRIVATE\n')))
        self.assertIn('cannot be checked', self.lp.visibility_refusal('ssh://host.example/logs.git', gh('PRIVATE')))
        self.assertIn('public', self.lp.visibility_refusal('git@github.com:x/agent-harness.git', gh('PRIVATE')))
        with self.assertRaises(self.lp.PushError):
            self.lp.setup(url, home=self.home, gh_runner=gh('PUBLIC\n'))

    def test_paths_outside_the_harness_roots_are_refused(self):
        (self.home / 'code').mkdir()
        (self.home / 'code/a.txt').write_text('x')
        with self.assertRaises(self.lp.PushError):
            self.lp.push([str(self.home / 'code')], home=self.home)

    def test_the_guard_admits_the_tool(self):
        compiled = cg.Compiled(cg.load_policy(path='/nonexistent'), home=str(self.home), cwd=str(self.home))
        command = 'python3 ~/.claude/hooks/ah.py log-push %s' % self.wals
        self.assertEqual(cg.decide(command, compiled, cwd=str(self.home), payload={'session_id': SID})[0], 'allow')


if __name__ == '__main__':
    unittest.main()
