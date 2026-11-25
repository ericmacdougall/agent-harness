"""Tests for harness/hooks/kill_guard.py: the guard judges EFFECT, not words (redesign 2026-11-24; GoodQA #14506).

Every command string here is DATA handed to kill_guard.decide(); nothing in this file executes one. The process table
is a fixed fake (Context), so no real process is looked at or signalled, except in Hook, which pipes harmless payloads
through the real launcher.

Failing first: KG_HOOKS_DIR=<dir with the previous kill_guard.py> python3 -m unittest tests.test_kill_guard runs the
same rows against the old guard: ReportedFalseRefusals, Roles and the new broad rows fail there (old blocked them, or
let `docker system prune` through).
"""

import ast
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HOOKS = Path(os.environ.get('KG_HOOKS_DIR') or ROOT / 'harness/hooks')
sys.path.insert(0, str(HOOKS))

import kill_guard as kg  # noqa: E402

U = os.getuid()
OWN = '/w/own'
NEW = hasattr(kg, 'Context')


def table():
    P = getattr(kg, 'Proc', None)
    if P is None:
        return {}
    rows = [(1, 0, 1, 0, '/sbin/launchd'),
            (100, 1, 100, U, '/usr/local/bin/claude --model x'),       # the agent session
            (101, 100, 101, U, 'python3 kill_guard.py hook'),          # this hook
            (200, 100, 200, U, 'node /w/own/node_modules/.bin/vitest run'),  # a child of the agent
            (210, 1, 210, U, 'python3 /w/own/tools/server.py'),        # reparented, but runs from the worktree
            (220, 1, 220, U, 'sleep 1000'),                            # started with kill_guard.py spawn
            (300, 1, 300, U, 'node /other/repo/node_modules/.bin/vitest run'),  # another owner's test run
            (400, 1, 400, U, 'python3 /Users/x/.claude/hooks/ahd.py'),  # harness daemon
            (410, 1, 410, U, 'node /srv/shop/server.js --env staging'),  # staging (policy)
            (500, 1, 500, U, 'node /sup/proj/server.js'),               # in a supervised project
            (600, 1, 600, U + 1, 'postgres -D /var/db')]                # another user
    return {r[0]: P(*r) for r in rows}


def context(top=False, supervised=(), maintainer=False, lsof=(300,)):
    policy = kg.load_policy()
    policy['staging_live'] = [r'--env staging']
    return kg.Context(cwd=OWN, policy=policy, table=table(), ancestors=[101, 100],
                      roles={'top': top, 'maintainer': maintainer, 'supervised': list(supervised), 'own': []},
                      cwds={210: OWN + '/tools', 220: '/tmp', 300: '/other/repo', 400: '/', 410: '/srv/shop',
                            500: '/sup/proj', 600: '/'},
                      own_roots=([OWN], [OWN + '/nested']), ledger={(220, 'S')}, start=lambda pid: 'S',
                      lsof=lambda args: list(lsof))


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = self.tmp.name

    def decide(self, command, **roles):
        extra = {'context': context(**roles)} if NEW else {}
        return kg.decide(command, cwd=self.home, home=self.home, **extra)

    def verdict(self, command, **roles):
        return self.decide(command, **roles)[0]

    def assertAllowed(self, rows, **roles):
        for command in rows:
            with self.subTest(command=command):
                self.assertEqual(self.verdict(command, **roles), 'allow', self.decide(command, **roles)[2])

    def assertRefused(self, rows, rule=None, **roles):
        for command in rows:
            with self.subTest(command=command):
                verdict, got, message, _pids = self.decide(command, **roles)
                self.assertEqual(verdict, 'block')
                if rule:
                    self.assertEqual(got, rule, message)
                self.assertIn('To proceed:', message)


class ReportedFalseRefusals(Base):
    """Each row was refused by the old guard (checked at 2ad9bbb0); none of them signals a process it should not."""

    def test_help_of_the_stop_tools(self):
        self.assertAllowed(['pkill --help', 'killall --help', 'kill -l', 'kill -L', 'ah kill --help',
                            'python3 ~/.claude/hooks/ah.py kill --help', 'python3 ~/.claude/hooks/ah_kill.py --help'])

    def test_read_only_checks(self):
        # What triggered the old "broad-kill": a wrapper (timeout, nohup, env) followed by any program whose argument
        # word was a kill verb; scan_tail read that word as the command.
        self.assertAllowed(['timeout 30 ah owners killall', 'nohup ah task list pkill', 'env FOO=1 ah task list killall',
                            'ah task list', 'ps aux', 'pgrep -fl node', 'lsof -i :3000', 'docker ps',
                            'grep broad-kill ~/.agent-harness/kill-audit.jsonl',
                            'python3 -c \'import json; [print(l) for l in open("/x/kill-audit.jsonl")]\'',
                            'uv run python -c \'print("pkill")\''])

    def test_a_program_signalling_only_itself(self):
        self.assertAllowed(["python3 -c 'import os,signal; os.kill(os.getpid(), signal.SIGTERM)'",
                            "node -e 'process.kill(process.pid)'", 'kill $$', "bash -c 'kill $$'",
                            'python3 -m pytest tests/test_x.py -k kill', 'node --test test/kill.test.js',
                            'python3 -m pytest tests/test_kill_guard.py -q'])


class OwnProcesses(Base):
    def test_own_processes_need_no_approval(self):
        self.assertAllowed(['kill 200', 'kill -9 210', 'kill 220', 'kill -TERM 200 210', 'kill %1', 'kill 0',
                            'sleep 5 & pid=$!; kill $pid', 'kill -9 $!', 'pkill -f /w/own', 'pkill -P $$',
                            'kill 99999', 'netwatch orphans --kill --pid 200'])

    def test_a_tester_stops_its_own_disposable_stack(self):
        self.assertAllowed(['docker compose -p qa-run-1 down', 'docker compose -p qa-run-1 stop',
                            'docker compose down -v', 'docker stop qa-db-1', 'docker rm -f qa-db-1',
                            'systemctl --user stop run-u123.service', 'tmux kill-session -t qa-1'])

    def test_pkill_whose_every_match_is_own(self):
        self.assertAllowed(['pkill -f "node /w/own"', 'pgrep -f /w/own | xargs kill'])


class Refusals(Base):
    def test_not_yours(self):
        self.assertRefused(['kill 300', 'kill -9 600', 'kill 500', "node -e 'process.kill(300)'"], 'not-yours')

    def test_broad_patterns_resolve_against_the_table(self):
        self.assertRefused(['pkill -f vitest', 'pkill node', 'killall node', 'pgrep -f vitest | xargs kill',
                            'kill $(pgrep -f vitest)', 'for p in $(pgrep -f vitest); do kill $p; done',
                            'pgrep -f vitest | while read p; do kill $p; done', 'lsof -ti :3000 | xargs kill',
                            "ps aux | grep vitest | awk '{print $2}' | xargs kill", 'fuser -k 3000/tcp',
                            "bash <<'EOF'\npkill -f vitest\nEOF", "sh -c 'pkill -f vitest'"], 'broad-kill')

    def test_everything_at_once(self):
        self.assertRefused(['kill -1', 'kill -9 -1', 'kill -- -1', 'killall5', 'tmux kill-server', 'pm2 kill',
                            'docker system prune -af', 'docker container prune', 'docker kill $(docker ps -q)',
                            'docker stop $(docker ps -aq)', 'ssh dev2 pkill -f node'], 'broad-kill')

    def test_never(self):
        self.assertRefused(['kill 1', 'kill 100', 'kill -9 101'], 'never')

    def test_refusal_names_the_command_that_proceeds(self):
        message = self.decide('pkill -f vitest')[2]
        self.assertIn('kill 200', message)  # the one match that is the caller's
        self.assertIn('ah.py kill --pid 300', self.decide('kill 300')[2])


class Roles(Base):
    def test_supervisor_may_stop_its_projects(self):
        self.assertAllowed(['kill 500'], supervised=['/sup'])
        self.assertRefused(['kill 300'], 'not-yours', supervised=['/sup'])

    def test_top_rung_may_stop_anything_but_the_protected_list(self):
        self.assertAllowed(['kill 300', 'kill 500', 'pkill -f vitest', 'kill 600'], top=True)
        self.assertRefused(['kill 400', 'kill 410', 'launchctl bootout gui/501/com.ericmacdougall.ahd'],
                           'protected', top=True)
        self.assertRefused(['kill 100', 'kill 1'], 'never', top=True)

    def test_protected_needs_approval_for_everyone(self):
        self.assertRefused(['kill 400', 'kill 410', 'docker compose -p log-backup down'], 'protected')
        self.assertIn('--approved-by', self.decide('kill 400')[2])

    def test_harness_maintainer_may_stop_harness_daemons_and_it_is_logged(self):
        self.assertAllowed(['kill 400', 'launchctl kickstart -k gui/501/com.ericmacdougall.ahd',
                            'launchctl bootout gui/501/com.ericmacdougall.ahd'], top=True, maintainer=True)
        self.assertRefused(['kill 410'], 'protected', top=True, maintainer=True)  # staging/live still asks
        audit = Path(self.home) / '.agent-harness/state/kill-guard/audit.jsonl'
        rows = [json.loads(line) for line in audit.read_text().splitlines()]
        self.assertTrue(any(r['rule'].startswith('maintainer:') and r['verdict'] == 'allow' for r in rows))


class TextIsNotEffect(Base):
    def test_prose_heredocs_and_quotes(self):
        self.assertAllowed(["echo 'kill 300'", "cat <<'EOF'\npkill -f node\nkill -9 -1\nEOF",
                            'git commit -m "pkill -f node was the bug"', "printf 'killall node\\n' > notes.md",
                            'grep -c pkill audit.jsonl', 'bash scripts/kill-stack.sh', './kill-stack.sh'])

    def test_unsure_allows_and_logs_one_line(self):
        for command in ('kill $SERVER_PID', 'kill $(cat app.pid)', 'cat pids | xargs kill', 'ssh dev2 kill 1234'):
            with self.subTest(command=command):
                self.assertEqual(self.verdict(command), 'allow')
        audit = Path(self.home) / '.agent-harness/state/kill-guard/audit.jsonl'
        self.assertTrue(all(json.loads(x)['verdict'] == 'allow' for x in audit.read_text().splitlines()))

    def test_analysis_error_allows(self):
        ctx = context()
        ctx.judge = None  # any bug inside the analysis
        self.assertEqual(kg.decide('kill 300', context=ctx, home=self.home)[0], 'allow')


class Corpus(Base):
    """The registry (docs/rules/kill-guard.json) names test_positive_rows_blocked."""

    def test_positive_rows_blocked(self):
        self.assertRefused(['pkill -f node', 'pgrep -f vitest | xargs kill', 'kill 300', 'killall node', 'kill -9 -1'])

    def test_negative_rows_allowed(self):
        self.assertAllowed(['kill 200', 'pgrep -fl node', 'ps aux | grep pkill', 'kill -0 300'])


class Hook(unittest.TestCase):
    def run_hook(self, payload, home):
        env = dict(os.environ, HOME=home)
        return subprocess.run([sys.executable, str(HOOKS / 'kill_guard.py'), 'hook'], input=json.dumps(payload).encode(),
                              capture_output=True, env=env, timeout=30)

    def test_hook_allows_reads_help_and_edits_and_refuses_kill_minus_one(self):
        with tempfile.TemporaryDirectory() as home:
            for command in ('pkill --help', 'ps aux | grep kill', 'kill -l'):
                done = self.run_hook({'tool_name': 'Bash', 'tool_input': {'command': command}, 'cwd': home}, home)
                self.assertEqual(done.returncode, 0, (command, done.stderr))
            done = self.run_hook({'tool_name': 'Write', 'tool_input': {'content': 'kill -9 -1'}}, home)
            self.assertEqual(done.returncode, 0)
            done = self.run_hook({'tool_name': 'Bash', 'tool_input': {'command': 'kill -9 -1'}, 'cwd': home}, home)
            self.assertEqual(done.returncode, 2)
            self.assertIn('To proceed', done.stderr.decode())

    def test_garbage_input_allows(self):
        with tempfile.TemporaryDirectory() as home:
            done = subprocess.run([sys.executable, str(HOOKS / 'kill_guard.py'), 'hook'], input=b'{not json kill -9 -1',
                                  capture_output=True, env=dict(os.environ, HOME=home), timeout=30)
            self.assertEqual(done.returncode, 0)


class Wiring(unittest.TestCase):
    def test_rules_registry_entry(self):
        data = json.loads((ROOT / 'docs' / 'rules' / 'kill-guard.json').read_text(encoding='utf-8'))
        entry = [e for e in data['rules'] if e.get('id') == 'kill-guard'][0]
        klass, _, method = entry['test'].partition('.')
        tree = ast.parse((ROOT / entry['test_file']).read_text(encoding='utf-8'))
        self.assertTrue(any(isinstance(c, ast.ClassDef) and c.name == klass and any(
            isinstance(m, ast.FunctionDef) and m.name == method for m in c.body) for c in ast.walk(tree)))


if __name__ == '__main__':
    unittest.main()
