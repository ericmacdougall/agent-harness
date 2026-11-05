"""The ladder enforcement hook: spawn decisions, resets, TOP permission, Bash advisory, live cap (goodqa#14527)."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

HOOKS = Path(__file__).resolve().parents[1] / 'harness/hooks'
sys.path.insert(0, str(HOOKS))
import escalation as esc
import model_tiers as tiers
import tier_gate as gate


def final(*, verdict='BLOCK', findings=('F1',), salt=''):
    return json.dumps({'schema': 1, 'kind': 'final', 'run_id': 'b' * 32, 'evidence': 'EXECUTED', 'subject': {'head': 'a' * 40},
                       'invocation': {}, 'execution': 'COMPLETED', 'result': 'NO_RESULT', 'reason': 'CODE_FINDINGS',
                       'usage': {'provider_launches': 1, 'reported': []},
                       'review': {'stage': 'CODE_INSPECTION', 'verdict': verdict, 'findings': list(findings)}, 'salt': salt}).encode()


class GateFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='gate-'); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'state'; self.root.mkdir(mode=0o700)
        self.policy = tiers.load_policy()
        self.ledger = esc.Ledger(self.root, self.policy)
        os.environ['AGENT_HARNESS_ESCALATION_DIR'] = str(self.root)
        self.addCleanup(lambda: os.environ.pop('AGENT_HARNESS_ESCALATION_DIR', None))

    def spawn(self, prompt, *, model=None, effort=None, subagent_type='task-owner', description='owner'):
        tool_input = {'prompt': prompt, 'description': description, 'subagent_type': subagent_type}
        if model is not None: tool_input['model'] = model
        if effort is not None: tool_input['effort'] = effort
        return gate.decide_spawn({'tool_name': 'Agent', 'tool_input': tool_input, 'session_id': 's1'}, self.policy, self.ledger, session_id='s1')

    def escalate(self, task, times=2):
        self.salt = getattr(self, 'salt', 0)
        for n in range(times):
            self.salt += 1
            receipt = json.loads(final(salt='%s-%d' % (task, self.salt)))
            receipt['subject'] = {'head': hashlib.sha256(str(self.salt).encode()).hexdigest()[:40]}  # a new HEAD per failure
            self.ledger.record(task, json.dumps(receipt).encode(), kind='review', source='test')


class SpawnDecisions(GateFixture):
    def test_matching_rung_is_allowed_and_a_missing_model_is_filled_in(self):
        decision, reason, updated, facts = self.spawn('do it [task:k1]', model='sonnet')
        self.assertEqual((decision, updated), ('allow', None)); self.assertEqual(facts['required_rung'], 'R0')
        decision, reason, updated, facts = self.spawn('do it [task:k1]')
        self.assertEqual(decision, 'allow'); self.assertEqual((updated['model'], updated['effort']), ('sonnet', 'medium'))

    def test_above_the_rung_is_downgraded_and_below_needs_a_reason(self):
        decision, reason, updated, facts = self.spawn('do it [task:k2]', model='opus', effort='high')
        self.assertEqual(decision, 'allow'); self.assertEqual((updated['model'], updated['effort']), ('sonnet', 'medium'))
        self.assertIn('downgraded', reason)
        self.escalate('k2')
        decision, reason, updated, facts = self.spawn('do it [task:k2]', model='opus', effort='medium')
        self.assertEqual((decision, updated), ('allow', None)); self.assertEqual(facts['required_rung'], 'R1')
        decision, reason, updated, facts = self.spawn('do it [task:k2]', model='sonnet')
        self.assertEqual(decision, 'deny'); self.assertIn('[rung-below:', reason)
        decision, reason, updated, facts = self.spawn('do it [task:k2] [rung-below:cheap retry of a typo]', model='sonnet')
        self.assertEqual(decision, 'allow'); self.assertEqual(facts['downgrade_reason'], 'cheap retry of a typo')

    def test_review_only_rungs_never_write_and_reviewers_sit_one_rung_above(self):
        decision, reason, updated, facts = self.spawn('do it [task:k3]', model='opus', effort='max')
        self.assertEqual(decision, 'deny'); self.assertIn('review-only', reason)
        decision, reason, updated, facts = self.spawn('review it [task:k3]', model='opus', effort='medium', subagent_type='red-team')
        self.assertEqual(decision, 'allow'); self.assertEqual(facts['reviewer_rung'], 'R1')
        decision, reason, updated, facts = self.spawn('review it [task:k3]', model='sonnet', subagent_type='red-team')
        self.assertEqual(decision, 'deny')  # a reviewer below the reviewer rung without a reason
        self.escalate('k3'); self.escalate('k3'); self.escalate('k3')  # R3
        decision, reason, updated, facts = self.spawn('review it [task:k3]', model='opus', effort='max', subagent_type='red-team')
        self.assertEqual(decision, 'allow'); self.assertEqual(facts['reviewer_rung'], 'R4')

    def test_opus_xhigh_is_reachable_and_the_fourth_climb_asks_the_user(self):
        # Six FAILs on one finding: R0 -> R1 -> R2 -> R3, all automatic; an opus xhigh writer is allowed.
        for _ in range(3): self.escalate('k12')
        decision, reason, updated, facts = self.spawn('do it [task:k12]', model='opus', effort='xhigh')
        self.assertEqual((decision, updated, facts['required_rung']), ('allow', None, 'R3'))
        # Two more FAILs compute R5, which needs the user; the reason names approve-top, not a limit.
        self.escalate('k12')
        decision, reason, updated, facts = self.spawn('do it [task:k12]', model='fable')
        self.assertEqual(decision, 'deny'); self.assertIn('approve-top', reason)

    def test_top_rung_is_blocked_without_user_permission_and_allowed_with_it(self):
        # The launch and spend ceilings are raised so the permission gate itself is exercised.
        self.policy = {**self.policy, 'ladder_limits': {'max_review_launches': 100, 'max_rung_climbs': 10, 'max_total_review_usd': 1000}}
        self.ledger = esc.Ledger(self.root, self.policy)
        for _ in range(4): self.escalate('k4')
        self.assertEqual(self.ledger.status('k4')['rung'], 'R5')
        decision, reason, updated, facts = self.spawn('do it [task:k4]', model='fable')
        self.assertEqual(decision, 'deny'); self.assertIn('approve-top', reason)
        decision, reason, updated, facts = self.spawn('do it [task:k4]', model='opus', effort='xhigh')
        self.assertEqual(decision, 'deny')  # the computed rung needs permission; nothing is minted below it silently
        # The spend ceiling counts each counted launch at the rung's review budget (conservative).
        self.assertGreater(self.ledger.load('k4')['spend_usd'], 0)
        wals = Path(self.temp.name) / 'wals'; (wals / 's1').mkdir(parents=True)
        os.environ['AGENT_HARNESS_WALS_DIR'] = str(wals); self.addCleanup(lambda: os.environ.pop('AGENT_HARNESS_WALS_DIR', None))
        wal = wals / 's1' / 'main.jsonl'
        wal.write_text(json.dumps({'id': 'w1', 'event': 'ask', 'note': 'fable for [task:k4]', 'source': 'user:s/u "yes use fable for k4"'}) + '\n'
                       + json.dumps({'id': 'w2', 'event': 'ask_resolved', 'ref': 'w1', 'note': 'approved by the user'}) + '\n')
        self.ledger.approve_top('k4', 'w1', wal)
        decision, reason, updated, facts = self.spawn('do it [task:k4]', model='fable')
        self.assertEqual(decision, 'allow')
        decision, reason, updated, facts = self.spawn('do it [task:k4]', model='fable', effort='high')
        self.assertEqual(decision, 'deny'); self.assertIn('review-only', reason)

    def test_no_model_at_a_permission_rung_is_denied_not_filled_in(self):
        self.policy = {**self.policy, 'ladder_limits': {'max_review_launches': 100, 'max_rung_climbs': 10, 'max_total_review_usd': 1000}}
        self.ledger = esc.Ledger(self.root, self.policy)
        for _ in range(4): self.escalate('k13')
        decision, reason, updated, facts = self.spawn('do it [task:k13]')
        self.assertEqual((decision, updated), ('deny', None)); self.assertIn('approve-top', reason)
        decision, reason, updated, facts = self.spawn('review it [task:k13]', subagent_type='red-team')
        self.assertEqual((decision, updated), ('deny', None))  # a Fable/Astra reviewer needs the task's permission too
        decision, reason, updated, facts = self.spawn('fork me [task:k13]', subagent_type='fork')
        self.assertEqual(decision, 'deny')

    def test_fork_cannot_escape_the_rung_but_is_fine_at_the_lowest(self):
        decision, reason, updated, facts = self.spawn('fork [task:k14]', subagent_type='fork')
        self.assertEqual(decision, 'allow')
        self.escalate('k14')
        decision, reason, updated, facts = self.spawn('fork [task:k14]', subagent_type='fork')
        self.assertEqual(decision, 'deny'); self.assertIn('fork inherits', reason)

    def test_ladder_limits_deny_writers_but_not_reviewers(self):
        self.ledger.add_spend('k5', 100)
        decision, reason, updated, facts = self.spawn('do it [task:k5]', model='sonnet')
        self.assertEqual(decision, 'deny'); self.assertIn('max_total_review_usd', reason)
        decision, reason, updated, facts = self.spawn('review [task:k5]', model='opus', subagent_type='red-team')
        self.assertEqual(decision, 'allow')


class Resets(GateFixture):
    def test_missing_task_key_resets_to_lowest_with_a_generated_key(self):
        decision, reason, updated, facts = self.spawn('no key at all', model='opus', effort='high')
        self.assertEqual(decision, 'allow'); self.assertEqual((updated['model'], updated['effort']), ('sonnet', 'medium'))
        self.assertTrue(facts['task'].startswith('auto-')); self.assertEqual(facts['reset'], ['missing_task_key'])
        state = self.ledger.load(facts['task'])
        self.assertEqual(state['resets'][-1]['code'], 'missing_task_key')
        again = self.spawn('no key at all', model='sonnet')
        self.assertEqual(again[3]['task'], facts['task'])  # the generated key is stable, so later failures count
        self.assertNotIn('reset', again[3])  # a known generated key is loaded, never wiped again
        self.escalate(facts['task'])
        later = self.spawn('no key at all', model='opus', effort='medium')
        self.assertEqual((later[0], later[1] and 'matches' in later[1], later[3]['required_rung']), ('allow', True, 'R1'))
        self.assertEqual(len(self.ledger.load(facts['task'])['events']), 2)
        self.assertEqual(len(list(self.root.glob(facts['task'] + '.reset.*'))), 0)

    def test_corrupt_state_resets_and_never_reaches_top(self):
        for _ in range(4): self.escalate('k6')
        (self.root / 'k6.json').write_text('{"schema": 1, "task": "k6", "events": "x"}')
        decision, reason, updated, facts = self.spawn('do it [task:k6]', model='fable')
        self.assertEqual(decision, 'deny')  # fable needs permission regardless
        decision, reason, updated, facts = self.spawn('do it [task:k6]', model='opus', effort='xhigh')
        self.assertEqual(decision, 'allow'); self.assertEqual(updated['model'], 'sonnet')
        self.assertEqual(facts['required_rung'], 'R0')
        self.assertEqual(self.ledger.load('k6')['resets'][-1]['code'], 'state_corrupt')

    def test_lock_timeout_resets_to_lowest_with_a_durable_record(self):
        import fcntl
        self.escalate('k7')
        holder = os.open(self.root / 'k7.lock', os.O_RDWR | os.O_CREAT, 0o600)
        fcntl.flock(holder, fcntl.LOCK_EX)
        try:
            with mock.patch.object(esc, 'LOCK_SECONDS', 0.2):
                decision, reason, updated, facts = self.spawn('do it [task:k7]', model='opus', effort='high')
        finally:
            fcntl.flock(holder, fcntl.LOCK_UN); os.close(holder)
        self.assertEqual(decision, 'allow'); self.assertEqual(updated['model'], 'sonnet')
        self.assertEqual(facts['reset'], ['lock_timeout'])
        pending = (self.root / 'k7.pending-resets.jsonl').read_text().splitlines()
        self.assertEqual(json.loads(pending[-1])['code'], 'lock_timeout')
        notes = [json.loads(l) for l in (self.root / 'notifications.jsonl').read_text().splitlines()]
        self.assertEqual(notes[-1]['code'], 'lock_timeout')
        # The next successful load absorbs the pending record into the state and keeps the earned rung.
        state = self.ledger.load('k7')
        self.assertEqual(state['resets'][-1]['code'], 'lock_timeout'); self.assertFalse((self.root / 'k7.pending-resets.jsonl').exists())
        self.assertEqual(self.ledger.status('k7')['rung'], 'R1')

    def test_tier_table_error_fails_closed_at_the_hook_entry(self):
        with tempfile.TemporaryDirectory() as temp, mock.patch.dict(os.environ, {'AGENT_HARNESS_TIER_POLICY': str(Path(temp) / 'none.json')}):
            result = subprocess.run([sys.executable, str(HOOKS / 'tier_gate.py'), 'hook'], input=json.dumps(
                {'tool_name': 'Agent', 'tool_input': {'prompt': 'x [task:k8]', 'model': 'sonnet'}, 'session_id': 's'}),
                capture_output=True, text=True, timeout=20, env={**os.environ, 'AGENT_HARNESS_TIER_POLICY': str(Path(temp) / 'none.json')})
        self.assertEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout)['hookSpecificOutput']['permissionDecision'], 'deny')
        # Plain shell use is never blocked by a broken table.
        with tempfile.TemporaryDirectory() as temp:
            result = subprocess.run([sys.executable, str(HOOKS / 'tier_gate.py'), 'hook'], input=json.dumps(
                {'tool_name': 'Bash', 'tool_input': {'command': 'ls -la'}, 'session_id': 's'}),
                capture_output=True, text=True, timeout=20, env={**os.environ, 'AGENT_HARNESS_TIER_POLICY': str(Path(temp) / 'none.json')})
            self.assertEqual((result.returncode, result.stdout.strip()), (0, ''))


class BashAdvisory(GateFixture):
    def bash(self, command):
        return gate.decide_bash({'tool_name': 'Bash', 'tool_input': {'command': command}}, self.policy, self.ledger)

    def test_launch_lines_are_checked_against_the_task_rung(self):
        self.assertEqual(self.bash('ls -la')[0], 'allow')
        self.assertEqual(self.bash('claude -p --model opus --effort high --task k9 "x"')[0], 'deny')
        self.escalate('k9'); self.escalate('k9')
        self.assertEqual(self.bash('claude -p --model opus --effort high --task k9 "x"')[0], 'allow')
        self.assertEqual(self.bash('codex exec --model gpt-6.1-sol -c model_reasoning_effort=high --task k9 -')[0], 'allow')
        self.assertEqual(self.bash('codex exec --model gpt-6-astra --task k9 -')[0], 'deny')
        self.assertEqual(self.bash('claude -p --model gpt-4o --task k9 x')[0], 'deny')
        # No --task means no recorded permission: the top tier is denied, also through a path or rescue.py.
        self.assertEqual(self.bash('claude -p --model fable "x"')[0], 'deny')
        self.assertEqual(self.bash('codex exec --model gpt-6-astra -')[0], 'deny')
        self.assertEqual(self.bash('/opt/homebrew/bin/claude -p --model fable --task k9 x')[0], 'deny')
        self.assertEqual(self.bash('python3 ~/.claude/hooks/rescue.py --repo r --packet p --output o --model fable --rung R5')[0], 'deny')
        self.assertEqual(self.bash('python3 ~/.claude/hooks/rescue.py --repo r --packet p --output o --model opus --effort max')[0], 'deny')
        self.assertEqual(self.bash('claude -p --model=fable --task=k9 x')[0], 'deny')
        self.assertEqual(self.bash('codex exec -c model=gpt-6-astra --task k9 -')[0], 'deny')
        self.assertEqual(self.bash('ANTHROPIC_MODEL=claude-fable-5-1 claude -p --task k9 x')[0], 'deny')
        self.assertEqual(self.bash('python3 rescue.py --repo r --packet p --output o --model opus --effort xhigh --task k9')[0], 'allow')
        # Without a task a Bash line cannot be rewritten: only the lowest writing rung runs.
        self.assertEqual(self.bash('claude -p --model opus "no task"')[0], 'deny')
        self.assertEqual(self.bash('claude -p --model sonnet "no task"')[0], 'allow')
        # A peer_review launch at a permission rung is checked here, against the installed ledger, not in the helper's env.
        self.assertEqual(self.bash('python3 ~/.claude/hooks/peer_review.py code-inspection --repo r --packet p --output o --author-rung R5 --author-harness claude')[0], 'deny')
        self.assertEqual(self.bash('python3 ~/.claude/hooks/peer_review.py code-inspection --repo r --packet p --output o --task k9 --author-rung R2')[0], 'allow')
        self.assertEqual(self.bash('python3 ~/.claude/hooks/peer_review.py pr --repo r --packet p --output o --task k9 --author-rung R5')[0], 'deny')
        # A review token never exempts the rest of the line, in either order.
        self.assertEqual(self.bash('python3 ~/.claude/hooks/peer_review.py pr --repo r --packet p --output o --task k9 --author-rung R0; claude -p --model fable x')[0], 'deny')
        self.assertEqual(self.bash('claude -p --model fable x; python3 ~/.claude/hooks/peer_review.py pr --repo r --packet p --output o --task k9 --author-rung R0')[0], 'deny')
        # A --task-only review line takes the author rung from the installed ledger (k9 is at R2 here: an R3 reviewer, no permission).
        self.assertEqual(self.bash('python3 ~/.claude/hooks/peer_review.py pr --repo r --packet p --output o --task k9')[0], 'allow')

    def test_every_launch_segment_of_a_compound_line_is_checked(self):
        self.escalate('k9'); self.escalate('k9')  # k9 at R2
        # Failing-first control: a later harmless launch must not mask an earlier top-tier one.
        self.assertEqual(self.bash('claude -p --model fable x; claude -p --model sonnet y')[0], 'deny')
        self.assertEqual(self.bash('codex exec --model gpt-6-astra - && claude -p --model sonnet y')[0], 'deny')
        self.assertEqual(self.bash('claude -p --model sonnet y || claude -p --model fable x')[0], 'deny')
        self.assertEqual(self.bash('claude -p --model fable x | cat')[0], 'deny')
        self.assertEqual(self.bash('claude -p --model fable x\nclaude -p --model sonnet --task k9 y')[0], 'deny')
        self.assertEqual(self.bash('python3 ~/.claude/hooks/peer_review.py pr --repo r --packet p --output o --author-rung R5 --author-harness claude; '
                                   'python3 ~/.claude/hooks/peer_review.py pr --repo r --packet p --output o --task k9 --author-rung R0')[0], 'deny')
        self.assertEqual(self.bash('claude -p --model opus --effort xhigh --task k9 x; claude -p --model sonnet --task k9 y')[0], 'deny')
        # Allowed shapes: every segment within its rung; quoted text is not a launch; redirections stay in their segment.
        self.assertEqual(self.bash('claude -p --model opus --effort high --task k9 x; claude -p --model sonnet --task k9 y')[0], 'allow')
        self.assertEqual(self.bash("echo 'claude --model fable'; ls")[0], 'allow')
        self.assertEqual(self.bash('sleep 1 2>&1; claude -p --model sonnet --task k9 y &> /dev/null')[0], 'allow')
        self.assertEqual(gate.split_segments('a "b; c" d\\; e; f && g || h | i & j 2>&1 &> k'),
                         ['a "b; c" d\\; e', 'f', 'g', 'h', 'i', 'j 2>&1 &> k'])
        # A backtick substitution is a launch too (the $(...) form already was).
        self.assertEqual(self.bash('ls; `claude -p --model fable x`')[0], 'deny')
        self.assertEqual(self.bash('echo `claude -p --model sonnet --task k9 x`')[0], 'allow')

    def test_launches_hidden_in_shell_strings_and_substitutions_are_checked(self):
        self.escalate('k9'); self.escalate('k9')
        for line in ('out=`claude -p --model fable x`',
                     "bash -c 'claude -p --model fable x'",
                     'sh -c "claude -p --model fable x"',
                     "/bin/zsh -lc 'cd /tmp; claude -p --model fable x'",
                     "sudo -u eric -c 'claude -p --model fable x'",
                     "eval 'claude -p --model fable x'",
                     "ssh dev2 'claude -p --model fable x'",
                     "ssh -p 2222 -o StrictHostKeyChecking=no dev2 claude -p --model fable x",
                     'claude -p --model sonnet --task k9 "$(claude -p --model fable x)"',
                     "export ANTHROPIC_MODEL=claude-fable-5-1; claude -p x",
                     "export ANTHROPIC_MODEL=claude-fable-5-1\nclaude -p x",
                     "ANTHROPIC_MODEL=claude-fable-5-1; claude -p x",
                     'Claude -p --model fable x',
                     '/opt/homebrew/bin/CLAUDE -p --model fable x',
                     'claude -p --model fable "x',
                     'codex exec -m gpt-6-astra -'):
            self.assertEqual(self.bash(line)[0], 'deny', line)
        for line in ("echo 'claude --model fable'",
                     'git commit -m "claude --model fable notes"',
                     'git commit -m "see claude"',
                     "python3 -m unittest 'claude'",
                     "bash -c 'claude -p --model sonnet --task k9 x'",
                     "ssh dev2 'git log'",
                     "export ANTHROPIC_MODEL=claude-sonnet-4-5; claude -p --task k9 x",
                     'claude -p --model opus --effort high --task k9 "$(date)"'):
            self.assertEqual(self.bash(line)[0], 'allow', line)

    def test_a_task_at_a_permission_rung_launches_nothing_below_it_either(self):
        self.policy = {**self.policy, 'ladder_limits': {'max_review_launches': 100, 'max_rung_climbs': 10, 'max_total_review_usd': 1000}}
        self.ledger = esc.Ledger(self.root, self.policy)
        for _ in range(4): self.escalate('k5')
        self.assertEqual(self.ledger.status('k5')['rung'], 'R5')
        decision, reason, _, _ = self.bash('claude -p --model opus --task k5 x')
        self.assertEqual(decision, 'deny'); self.assertIn('approve-top', reason)
        self.assertEqual(self.bash('claude -p --model sonnet --task k5 x')[0], 'deny')
        self.assertEqual(self.bash('python3 rescue.py --repo r --packet p --output o --model opus --effort high --task k5')[0], 'allow')
        self.assertEqual(self.bash('python3 rescue.py --repo r --packet p --output o --model opus --effort high')[0], 'allow')


class ModesAndCap(GateFixture):
    def run_hook(self, data, mode):
        policy = dict(self.policy); policy['mode'] = mode
        path = Path(self.temp.name) / 'tiers.json'; path.write_text(json.dumps(policy))
        env = {**os.environ, 'AGENT_HARNESS_TIER_POLICY': str(path), 'AGENT_HARNESS_ESCALATION_DIR': str(self.root)}
        result = subprocess.run([sys.executable, str(HOOKS / 'tier_gate.py'), 'hook'], input=json.dumps(data), capture_output=True, text=True, timeout=20, env=env)
        self.assertEqual(result.returncode, 0, result.stderr[-300:])
        return json.loads(result.stdout)['hookSpecificOutput'] if result.stdout.strip() else None

    def test_warn_mode_only_adds_context_and_enforce_mode_decides(self):
        data = {'tool_name': 'Agent', 'tool_input': {'prompt': 'x [task:k10]', 'model': 'opus', 'effort': 'max'}, 'session_id': 's'}
        warn = self.run_hook(data, 'warn')
        self.assertNotIn('permissionDecision', warn); self.assertNotIn('updatedInput', warn)  # warn only speaks
        self.assertIn('would deny', warn['additionalContext'])
        enforce = self.run_hook(data, 'enforce')
        self.assertEqual(enforce['permissionDecision'], 'deny')
        log = [json.loads(l) for l in (self.root / 'gate.jsonl').read_text().splitlines()]
        self.assertEqual([entry['mode'] for entry in log], ['warn', 'enforce'])

    def test_unusable_state_dir_never_blocks_plain_shell_use(self):
        # onFailure: block means the hook must always answer: a symlinked or unwritable state dir is not a lockout.
        link = Path(self.temp.name) / 'linked'; link.symlink_to(self.root)
        env = {**os.environ, 'AGENT_HARNESS_ESCALATION_DIR': str(link)}
        plain = subprocess.run([sys.executable, str(HOOKS / 'tier_gate.py'), 'hook'], input=json.dumps(
            {'tool_name': 'Bash', 'tool_input': {'command': 'ls -la'}, 'session_id': 's'}), capture_output=True, text=True, timeout=20, env=env)
        self.assertEqual((plain.returncode, plain.stdout.strip()), (0, ''))
        spawn = subprocess.run([sys.executable, str(HOOKS / 'tier_gate.py'), 'hook'], input=json.dumps(
            {'tool_name': 'Agent', 'tool_input': {'prompt': 'x [task:k15]', 'model': 'sonnet'}, 'session_id': 's'}), capture_output=True, text=True, timeout=20, env=env)
        self.assertEqual(spawn.returncode, 0)
        out = json.loads(spawn.stdout)['hookSpecificOutput']
        self.assertIn('ladder state unusable', out.get('additionalContext', '') + out.get('permissionDecisionReason', ''))

    def test_live_agent_cap_counts_starts_and_stops(self):
        for n in range(gate.LIVE_CAP_DEFAULT):
            gate.live_update('s2', 'agent-%d' % n, start=True)
        self.assertEqual(gate.live_count('s2'), gate.LIVE_CAP_DEFAULT)
        data = {'tool_name': 'Agent', 'tool_input': {'prompt': 'x [task:k11]', 'model': 'sonnet'}, 'session_id': 's2'}
        self.assertEqual(self.run_hook(data, 'enforce')['permissionDecision'], 'deny')
        gate.live_update('s2', 'agent-0', start=False)
        self.assertIsNone(self.run_hook(data, 'enforce'))  # matching rung, nothing to say


if __name__ == '__main__':
    unittest.main()
