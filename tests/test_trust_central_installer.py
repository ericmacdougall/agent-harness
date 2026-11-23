"""GoodQA goodqa#16651: scripts/trust-central-decisions.sh merges only on an exact-HEAD PASS receipt, through
`gh pr merge --match-head-commit`, checks the merge commit, installs through repair-harness, and publishes only
after all of that. gh, ssh, repair-harness and ah.py are stubs in a temp HOME; nothing leaves the machine."""

import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import textwrap
import unittest

HERE = Path(__file__).resolve().parent
SCRIPT = HERE.parent / 'scripts' / 'trust-central-decisions.sh'
SESSION = '11111111-2222-4333-8444-555555555555'
UID = '00000000-0000-4000-8000-0000000000f1'
HEAD = 'a' * 40
MERGE = 'b' * 40
ITEM = 'executive-synthesis:prj_46fm8uPeK89KN1:run_sW0Xrg0xyQVbfC:wrk_Zb18EJJnaBqcly'
KEY = 't2scan-audit-5db5032d0c554f08e7e50c90f47ebc85'

GH = r'''#!/usr/bin/env python3
import json, os, sys
state_path = os.environ['STUB_STATE']
state = json.load(open(state_path))
log = open(os.environ['STUB_LOG'], 'a'); log.write('gh ' + ' '.join(sys.argv[1:]) + '\n'); log.close()
args = sys.argv[1:]
if args[:2] == ['pr', 'view']:
    pr = state['prs'][args[2]]
    expr = args[args.index('--jq') + 1]
    value = {'.state': pr['state'], '.headRefOid': pr['head'], '.baseRefName': 'main',
             '.mergeCommit.oid // empty': pr.get('merge') or ''}[expr]
    print(value)
elif args[:2] == ['pr', 'merge']:
    pr = state['prs'][args[2]]
    if args[args.index('--match-head-commit') + 1] != pr['head']:
        sys.exit(1)
    pr['state'], pr['merge'] = 'MERGED', state['merge_sha']
    json.dump(state, open(state_path, 'w'))
elif args[0] == 'api' and '/commits/' in args[1]:
    print(state['second_parent'])
elif args[0] == 'api' and '/contents/' in args[1]:
    print(state['blobs'].get(args[1].split('/contents/harness/hooks/')[1].split('?')[0], ''))
else:
    sys.exit(3)
'''

SSH = r'''#!/usr/bin/env python3
import os, subprocess, sys
log = open(os.environ['STUB_LOG'], 'a'); log.write('ssh ' + ' '.join(sys.argv[1:]) + '\n'); log.close()
args = sys.argv[1:]
while args and args[0].startswith('-'):
    args = args[2:] if args[0] == '-o' else args[1:]
args = args[1:]  # host
if len(args) == 1 and 'import cryptography' in args[0]:
    sys.exit(0)  # the stub worker has the package (the local /usr/bin/python3 -I may not)
if len(args) == 1:
    sys.exit(subprocess.run(['bash', '-c', args[0]]).returncode)
sys.exit(subprocess.run(args).returncode)
'''

REPAIR = r'''#!/usr/bin/env python3
import os, sys
log = open(os.environ['STUB_LOG'], 'a'); log.write('repair ' + ' '.join(sys.argv[1:]) + '\n'); log.close()
'''

AH = r'''#!/usr/bin/env python3
import json, os, sys
log = open(os.environ['STUB_LOG'], 'a'); log.write('ah ' + ' '.join(sys.argv[1:]) + '\n'); log.close()
if sys.argv[1:3] == ['decision', 'keygen']:
    print(json.dumps({'ok': True, 'public_key': 'A' * 43, 'key_id': '0123456789abcdef', 'created': True}))
elif sys.argv[1:3] == ['decision', 'publish'] and os.environ.get('STUB_PUBLISH_FAIL'):
    print(json.dumps({'ok': False, 'code': 'later_turn'})); sys.exit(2)
else:
    print(json.dumps({'ok': True}))
'''


def receipt(path, *, head=HEAD, repo='ericmacdougall/agent-harness', pr='311', stage='pr', verdict='PASS'):
    path.write_text('Reviewer: x\nStage: %s\nReviewed HEAD: %s\nReviewed repository: %s\nReviewed PR: %s\n'
                    'Reviewed packet SHA-256: %s\n\nVERDICT: %s\n\nbody\n' % (stage, head, repo, pr, 'c' * 64, verdict))


class Installer(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='trust-central-'); self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name)
        self.home = base / 'home'
        bin_dir = base / 'bin'; bin_dir.mkdir()
        hooks = self.home / '.claude' / 'hooks'; hooks.mkdir(parents=True)
        (self.home / '.agent-harness' / 'work').mkdir(parents=True)
        (self.home / '.agent-harness' / 'bin').mkdir(parents=True)
        self.wal = self.home / '.claude' / 'wals' / SESSION / 'main.jsonl'
        self.wal.parent.mkdir(parents=True); self.wal.write_text('')
        for path, body in ((bin_dir / 'gh', GH), (bin_dir / 'ssh', SSH),
                           (self.home / '.agent-harness' / 'bin' / 'repair-harness', REPAIR), (hooks / 'ah.py', AH)):
            path.write_text(body); path.chmod(0o755)
        blobs = {}
        for name in ('central_decisions.py', 'tier_gate.py', 'provenance_hooks.py', 'escalation.py', 'ticket_adapters.py', 'ah.py'):
            if name != 'ah.py':
                (hooks / name).write_text('# installed %s\n' % name)
            blobs[name] = subprocess.run(['git', 'hash-object', str(hooks / name)], capture_output=True, text=True,
                                         check=True).stdout.strip()
        self.state = base / 'state.json'
        self.log = base / 'calls.log'
        self.write_state({'prs': {'311': {'state': 'OPEN', 'head': HEAD}}, 'merge_sha': MERGE, 'second_parent': HEAD, 'blobs': blobs})
        self.receipt = base / 'receipt.md'
        receipt(self.receipt)
        import site
        self.env = {**os.environ, 'HOME': str(self.home), 'PATH': '%s:%s' % (bin_dir, os.environ['PATH']),
                    'PYTHONUSERBASE': site.getuserbase(),  # keep the real user site (cryptography) under the temp HOME
                    'STUB_STATE': str(self.state), 'STUB_LOG': str(self.log)}

    def write_state(self, state):
        self.state.write_text(json.dumps(state))

    def run_script(self, *extra, receipt_path=None, env=None):
        args = ['bash', str(SCRIPT), '--harness-pr', '311', '--harness-receipt', str(receipt_path or self.receipt),
                '--user-msg', 'uuid:%s/%s' % (SESSION, UID), '--wal', str(self.wal), '--item', ITEM, '--yes', *extra]
        return subprocess.run(args, capture_output=True, text=True, env=env or self.env, timeout=60)

    def calls(self):
        return self.log.read_text().splitlines() if self.log.exists() else []

    def test_full_flow_merges_with_match_head_then_installs_then_publishes(self):
        out = self.run_script()
        self.assertEqual(out.returncode, 0, out.stderr + out.stdout)
        calls = self.calls()
        merge = next(i for i, c in enumerate(calls) if c.startswith('gh pr merge'))
        self.assertIn('--match-head-commit ' + HEAD, calls[merge])
        apply_ = next(i for i, c in enumerate(calls) if c.startswith('repair') and '--apply' in c)
        self.assertIn('--ref ' + MERGE, calls[apply_])
        approve = next(i for i, c in enumerate(calls) if c.startswith('ah approve-top'))
        publish = next(i for i, c in enumerate(calls) if c.startswith('ah decision publish'))
        verify = next(i for i, c in enumerate(calls) if 'decision verify --task ' + KEY in c)
        self.assertLess(merge, apply_); self.assertLess(apply_, approve); self.assertLess(approve, publish)
        self.assertLess(publish, verify)
        self.assertIn('--task ' + KEY, calls[approve])  # the key is derived from the item, not typed

    def assert_stopped_before_merge(self, out, needle):
        self.assertNotEqual(out.returncode, 0)
        self.assertIn(needle, out.stderr)
        self.assertFalse(any(c.startswith(('gh pr merge', 'repair', 'ah ')) for c in self.calls()), self.calls())

    def test_receipt_problems_stop_before_any_merge(self):  # NEG-11
        base = Path(self.temp.name)
        cases = {
            'BLOCK verdict': dict(verdict='BLOCK'),
            'stale head': dict(head='d' * 40),
            'other PR': dict(pr='310'),
            'other repo': dict(repo='ericmacdougall/other'),
            'plan stage': dict(stage='plan'),
        }
        for name, change in cases.items():
            with self.subTest(name):
                self.log.unlink(missing_ok=True)
                path = base / ('r-%s.md' % name.replace(' ', '-'))
                receipt(path, **change)
                self.assert_stopped_before_merge(self.run_script(receipt_path=path), 'receipt refused')
        self.log.unlink(missing_ok=True)
        out = self.run_script(receipt_path=base / 'missing.md')
        self.assert_stopped_before_merge(out, 'harness-receipt')

    def test_pr_head_moved_after_review_stops(self):  # NEG-11
        self.write_state({**json.loads(self.state.read_text()), 'prs': {'311': {'state': 'OPEN', 'head': 'e' * 40}}})
        self.assert_stopped_before_merge(self.run_script(), 'is not the PR head')

    def test_no_items_or_bad_item_stops(self):  # NEG-11
        args = ['bash', str(SCRIPT), '--harness-pr', '311', '--harness-receipt', str(self.receipt),
                '--user-msg', 'uuid:%s/%s' % (SESSION, UID), '--wal', str(self.wal), '--yes']
        out = subprocess.run(args, capture_output=True, text=True, env=self.env, timeout=60)
        self.assert_stopped_before_merge(out, '1 to 3 T2Scan items')
        out = subprocess.run(args + ['--item', 'executive-synthesis:prj_x*:run_y:wrk_z'], capture_output=True, text=True,
                             env=self.env, timeout=60)
        self.assert_stopped_before_merge(out, 'item must be')
        out = subprocess.run(args + ['--item', ITEM] * 4, capture_output=True, text=True, env=self.env, timeout=60)
        self.assert_stopped_before_merge(out, '1 to 3 T2Scan items')

    def test_wal_of_another_session_stops(self):
        other = self.home / '.claude' / 'wals' / ('9' + SESSION[1:]) / 'main.jsonl'
        other.parent.mkdir(parents=True); other.write_text('')
        args = ['bash', str(SCRIPT), '--harness-pr', '311', '--harness-receipt', str(self.receipt),
                '--user-msg', 'uuid:%s/%s' % (SESSION, UID), '--wal', str(other), '--item', ITEM, '--yes']
        out = subprocess.run(args, capture_output=True, text=True, env=self.env, timeout=60)
        self.assert_stopped_before_merge(out, 'not the WAL of the session')

    def test_merge_commit_without_the_reviewed_parent_stops_before_install(self):
        self.write_state({**json.loads(self.state.read_text()), 'second_parent': 'f' * 40})
        out = self.run_script()
        self.assertNotEqual(out.returncode, 0)
        self.assertIn('second parent', out.stderr)
        self.assertFalse(any(c.startswith(('repair', 'ah ')) for c in self.calls()))

    def test_check_mode_merges_and_publishes_nothing(self):
        out = self.run_script('--check')
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertFalse(any(c.startswith(('gh pr merge', 'repair', 'ah ')) for c in self.calls()))

    def test_publish_refusal_stops_before_worker_verification(self):
        out = self.run_script(env={**self.env, 'STUB_PUBLISH_FAIL': '1'})
        self.assertNotEqual(out.returncode, 0)
        self.assertIn('publish refused', out.stderr)
        self.assertFalse(any('decision verify' in c for c in self.calls()))

    def test_any_installed_gate_hook_differing_from_the_merge_stops_before_publish(self):  # spec review 2 item 7
        state = json.loads(self.state.read_text())
        state['blobs']['tier_gate.py'] = '0' * 40
        self.write_state(state)
        out = self.run_script()
        self.assertNotEqual(out.returncode, 0)
        self.assertIn('installed tier_gate.py differs', out.stderr)
        self.assertFalse(any('decision publish' in c for c in self.calls()))


if __name__ == '__main__':
    unittest.main()
