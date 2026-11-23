"""goodqa#16699: command_guard approve-delete --host (fleet-host no-backup approval).

Hermetic: the ssh runner is injected, the validator program runs locally against a temp tree with a git stub standing
in for ls-remote, and a fake /proc, mountinfo and docker. Commands are only judged by decide(), never run.
CG_HOOKS_DIR points the suite at another implementation (a mutant) to show tests failing.
"""

import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HOOKS = Path(os.environ.get('CG_HOOKS_DIR') or ROOT / 'harness/hooks')
sys.path.insert(0, str(HOOKS))

import command_guard as cg  # noqa: E402

GIT_ENV = {'GIT_AUTHOR_NAME': 't', 'GIT_AUTHOR_EMAIL': 't@example.invalid', 'GIT_COMMITTER_NAME': 't',
           'GIT_COMMITTER_EMAIL': 't@example.invalid', 'GIT_CONFIG_NOSYSTEM': '1'}
SOURCE = 'answer:sess-1/a54d2164-40ad-4be7-bcb7-7c8125c0fc87'
P1 = '/home/eric/.agent-harness/work/S1/tester/wt'
P2 = '/home/eric/.agent-harness/work/S1/tester/other'
PARENT = '/home/eric/.agent-harness/work/S1/tester/repo'
TILDE_CFG = '~/.ssh/config_fleetops'  # refused: the executing shell expands ~ with its own HOME (T5)
HEX = 'a' * 40
TIPS = 'b' * 64


def sh(*args, cwd=None):
    done = subprocess.run(list(args), cwd=cwd, env=dict(os.environ, **GIT_ENV), stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, check=False)
    if done.returncode != 0:
        raise AssertionError('%s failed: %s' % (args[:3], done.stderr.decode()[-300:]))
    return done.stdout.decode()


def hook_wal(path, at):
    import datetime
    stamp = datetime.datetime.fromtimestamp(at, datetime.timezone.utc).isoformat()
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, 'a') as handle:
        handle.write(json.dumps({'at': stamp, 'event': 'pretool', 'agent_id': 'a1', 'tool': 'Bash',
                                 'tool_use_id': 'toolu_x', 'target_chars': 10}) + '\n')


def resolver_for(path, text='Delete, no backup (Recommended)', session='sess-1', predefined=True, question=None):
    def resolver(source, now=None, max_age=None, home=None):
        return {'kind': 'answer', 'session': session, 'uid': source.rsplit('/', 1)[-1].lower(), 'at': time.time(),
                'text': text, 'predefined': predefined,
                'question': question or 'Delete %s on t2-dev without a backup?' % path}
    return resolver


FOOT = 'c' * 64


def answer(kind='linked', parent=PARENT, head=HEX, tips=TIPS, linked=(), dev=1, ino=2, mode='validate', foot=FOOT):
    return {'ok': True, 'mode': mode, 'kind': kind, 'parent': parent if kind == 'linked' else None, 'head': head,
            'tips_sha256': tips, 'tips_count': 1, 'linked_existing': list(linked), 'dev': dev, 'ino': ino,
            'footprint_sha256': foot, 'skipped_processes': 3, 'live_refs': 5, 'status': 'clean'}


class FakeFleet:
    """An injected ssh runner: records every call, answers from `reply` (a dict, an Exception, or a callable)."""

    def __init__(self, reply=None):
        self.reply = reply if reply is not None else answer()
        self.calls = []

    def __call__(self, argv, data, timeout):
        self.calls.append((list(argv), data, timeout))
        reply = self.reply(argv, data) if callable(self.reply) else self.reply
        if isinstance(reply, Exception):
            raise reply
        if isinstance(reply, tuple):
            return reply
        body = dict(reply)
        body['mode'] = 'recheck' if b'"mode\\": \\"recheck' in data or b'"recheck"' in data else body.get('mode')
        return 0, json.dumps(body).encode()


class Base(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix='cg-fleet-')
        self.home = Path(os.path.realpath(self._tmp.name))
        self._old_home = os.environ.get('HOME')
        os.environ['HOME'] = str(self.home)
        for rel in ('.claude/projects/p/a.jsonl', '.claude/wals/s/main.jsonl', '.agent-harness/state/x.json'):
            (self.home / rel).parent.mkdir(parents=True, exist_ok=True)
            (self.home / rel).write_text('x\n')
        (self.home / '.ssh').mkdir()
        cfg = self.home / '.ssh/config_fleetops'
        cfg.write_text('Host t2-dev\n  HostName example.invalid\n')
        os.chmod(str(cfg), 0o600)
        self.cfg = str(cfg)  # the only accepted -F spelling: absolute
        self.policy = cg.load_policy(path=str(self.home / 'no-such-policy.json'))
        self.wal = str(self.home / '.claude/wals/sess-1/agent-f.jsonl')
        hook_wal(self.wal, time.time() - 600)

    def tearDown(self):
        if self._old_home is None:
            os.environ.pop('HOME', None)
        else:
            os.environ['HOME'] = self._old_home
        self._tmp.cleanup()

    def approve(self, path=P1, host='t2-dev', runner=None, **kw):
        kw.setdefault('resolver', resolver_for(path))
        return cg.approve_delete_fleet(host, path, kw.pop('source', SOURCE), kw.pop('wal', self.wal),
                                       home=str(self.home), policy=self.policy,
                                       runner=runner or FakeFleet(), **kw)

    def approvals(self, runner=None, now=None):
        return cg.Approvals(home=str(self.home), compiled=cg.Compiled(self.policy, home=str(self.home)), now=now,
                            fleet_runner=runner)

    def decide(self, command, approvals):
        c = cg.Compiled(self.policy, home=str(self.home))
        return cg.decide(command, c, marker=approvals)

    def rm(self, path=P1, host='t2-dev', cfg=None):
        return 'ssh -F %s %s rm -rf %s' % (cfg or self.cfg, host, path)


class HostAllowlist(Base):
    def test_t2_dev_accepted_and_others_refused(self):
        entry = self.approve()
        self.assertEqual(entry['kind'], cg.NO_BACKUP_REMOTE_KIND)
        for bad in ('dev2', 'evil', 'T2-DEV', 'user@t2-dev', 't2-dev;x', ''):
            with self.assertRaises(ValueError, msg=bad):
                self.approve(host=bad)

    def test_policy_can_only_narrow_hosts(self):
        self.policy['marker']['no_backup_fleet_hosts'] = ['t2-dev', 'dev2']
        with self.assertRaises(ValueError):
            self.approve(host='dev2')
        self.policy['marker']['no_backup_fleet_hosts'] = []
        with self.assertRaises(ValueError):
            self.approve()

    def test_config_must_be_private_regular_file(self):
        cfg = self.home / '.ssh/config_fleetops'
        os.chmod(str(cfg), 0o666)
        runner = FakeFleet()
        with self.assertRaises(ValueError):
            self.approve(runner=runner)
        self.assertEqual(runner.calls, [])
        os.chmod(str(cfg), 0o600)
        real = self.home / '.ssh/real'
        cfg.rename(real)
        cfg.symlink_to(real)
        with self.assertRaises(ValueError):
            self.approve(runner=runner)
        self.assertEqual(runner.calls, [])


class PathRules(Base):
    BAD = ['/home/eric/.agent-harness/work/S', '/home/eric/.agent-harness/work', '/home/eric/.agent-harness/work/S/..',
           '/home/eric/.agent-harness/work/S/a/../b', '/home/eric/.agent-harness/work/S//a', 'relative/p',
           '/home/eric/.agent-harness/work/S/a b', '/home/eric/.agent-harness/work/S/a\nb',
           "/home/eric/.agent-harness/work/S/a'b", '/home/eric/.agent-harness/work/S/a$b',
           '/home/eric/.agent-harness/work/S/a`b', '/home/eric/.agent-harness/work/S/a*', '/home/eric/.agent-harness/work/S/a?',
           '/home/eric/.agent-harness/work/S/[a]', '/home/eric/.agent-harness/work/S/~', '/home/eric/.agent-harness/work/S/wals/x',
           '/home/eric/.agent-harness/work/S/a/logs', '/home/eric/.agent-harness/work/S/sessions/x',
           '/home/eric/.agent-harness/work/S/projects/x', '/home/eric/.agent-harness/work/S/.claude/x',
           '/home/eric/.agent-harness/work/S/x/.git', '/home/eric/.agent-harness/work/S/x.jsonl',
           '/home/eric/other/S/x', '/Users/eric/.agent-harness/work/S/x']

    def test_refused_paths_never_reach_ssh(self):
        for bad in self.BAD:
            runner = FakeFleet()
            with self.assertRaises(ValueError, msg=repr(bad)):
                self.approve(path=bad, runner=runner, resolver=resolver_for(bad))
            self.assertEqual(runner.calls, [], bad)

    def test_good_path_is_accepted(self):
        self.assertEqual(cg.fleet_path_problem(P1), '')


class RemoteArgv(Base):
    def test_fixed_argv_and_stdin_literal(self):
        runner = FakeFleet()
        self.approve(runner=runner)
        argv, data, timeout = runner.calls[0]
        cfg = str(self.home / '.ssh/config_fleetops')
        self.assertEqual(argv, ['/usr/bin/ssh', '-F', cfg, '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', '-o',
                                'ClearAllForwardings=yes', 't2-dev', '/usr/bin/python3', '-I', '-'])
        self.assertFalse(any(P1 in a for a in argv))
        self.assertIn(P1.encode(), data)

    def test_program_differs_only_by_the_literal(self):
        a = cg.build_fleet_program('validate', P1, self.policy)
        b = cg.build_fleet_program('validate', P2, self.policy)
        self.assertEqual(a.replace(json.dumps(json.dumps(
            {'k': 1})), ''), a)
        self.assertEqual(a.split('\n', 2)[2], b.split('\n', 2)[2])
        self.assertNotEqual(a.split('\n', 2)[1], b.split('\n', 2)[1])


class NoTestHooksInProduction(Base):
    def test_production_config_has_only_the_fixed_keys(self):
        program = cg.build_fleet_program('validate', P1, self.policy)
        line = program.split('\n')[1]
        cfg = json.loads(json.loads(line[len('CONFIG = json.loads('):-1]))
        self.assertEqual(sorted(cfg), ['ignored_ok', 'ignored_top_ok', 'mode', 'path', 'remote_hosts',
                                       'status_seconds'])
        for key in ('proc_root', 'mountinfo', 'docker', 'home', 'git'):
            self.assertNotIn(key, cfg)

    def test_runner_never_receives_test_keys(self):
        runner = FakeFleet()
        self.approve(runner=runner)
        self.assertNotIn(b'proc_root', runner.calls[0][1].split(b'\n')[1])


class ApprovalRecord(Base):
    def test_entry_fields_and_cap(self):
        entry = self.approve()
        self.assertEqual(entry['path'], 'fleet:t2-dev:' + P1)
        self.assertEqual(entry['host'], 't2-dev')
        self.assertEqual(entry['remote_path'], P1)
        self.assertLessEqual(entry['expires_at'] - entry['verified_at'], 1800)
        self.assertRegex(entry['state_sha256'], r'^[0-9a-f]{64}$')
        self.assertEqual(entry['identity'], [1, 2])
        for n in range(3):
            p = '/home/eric/.agent-harness/work/S1/tester/n%d' % n
            self.approve(path=p)
        with self.assertRaises(ValueError):
            self.approve(path='/home/eric/.agent-harness/work/S1/tester/n9')

    def test_cap_counts_local_and_remote_kinds_together(self):
        for n in range(4):
            self.approve(path='/home/eric/.agent-harness/work/S1/tester/n%d' % n)
        audit = (self.home / '.agent-harness/state' / cg.AUDIT_NAME).read_text()
        self.assertEqual(cg._uses_of_source(cg._canonical_source(SOURCE), str(self.home)), 4)
        self.assertIn('no-backup-remote', audit)

    def test_ttl_over_limit_refused_even_if_policy_allows_more(self):
        self.policy['marker']['fleet_max_ttl_seconds'] = 99999
        with self.assertRaises(ValueError):
            self.approve(ttl=1801)
        self.assertEqual(self.approve(ttl=1800)['expires_at'] - time.time() < 1805, True)

    def test_second_approval_replaces_first(self):
        self.approve()
        self.approve()
        entries, _ = cg.load_marker(str(self.home))
        self.assertEqual(len([e for e in entries if e.get('remote_path') == P1]), 1)

    def test_audit_and_entry_carry_no_url_or_token(self):
        runner = FakeFleet(answer('main'))
        entry = self.approve(runner=runner)
        text = json.dumps(entry) + (self.home / '.agent-harness/state' / cg.AUDIT_NAME).read_text() + \
            Path(self.wal).read_text()
        self.assertNotIn('://', text)
        self.assertNotIn('@', text)

    def test_unwritable_audit_stores_nothing(self):
        state = self.home / '.agent-harness/state'
        state.mkdir(parents=True, exist_ok=True)
        (state / cg.AUDIT_NAME).mkdir()  # a directory: the open fails
        with self.assertRaises(ValueError):
            self.approve()
        entries, _ = cg.load_marker(str(self.home))
        self.assertEqual(entries, [])

    def test_refusal_reason_is_cleaned(self):
        runner = FakeFleet({'ok': False, 'reason': 'x https://tok@github.com/a/b y'})
        with self.assertRaises(ValueError) as caught:
            self.approve(runner=runner)
        self.assertNotIn('://', str(caught.exception))
        self.assertNotIn('@', str(caught.exception))


class UserSource(Base):
    def test_unchanged_rules_apply(self):
        cases = [dict(text='Reclaim if pushed (Recommended)'), dict(predefined=False),
                 dict(session='other'), dict(question='Delete /home/eric/.agent-harness/work/S1/tester/zzz on t2-dev?'),
                 dict(question='Delete %s and %s on t2-dev?' % (P1, P2)),
                 ]
        for kw in cases:
            with self.assertRaises(ValueError, msg=str(kw)):
                self.approve(resolver=resolver_for(P1, **kw))
        self.approve(resolver=resolver_for(P1))
        # the question names the path, not the host (the unchanged local rule)
        self.approve(resolver=resolver_for(P1, question='Delete %s without a backup?' % P1))

    def test_wal_without_hook_entry_before_answer(self):
        other = str(self.home / '.claude/wals/sess-1/agent-late.jsonl')
        hook_wal(other, time.time() + 600)
        with self.assertRaises(ValueError):
            self.approve(wal=other)


class HookAllows(Base):
    def test_exact_command_allowed_once_and_consumed(self):
        self.approve()
        runner = FakeFleet(lambda argv, data: answer(mode='recheck'))
        approvals = self.approvals(runner)
        self.assertEqual(self.decide(self.rm(), approvals), ('allow', ''))
        self.assertEqual(len(runner.calls), 1)
        self.assertIn(b'recheck', runner.calls[0][1])
        self.assertTrue(approvals.consume())
        again = self.approvals(runner)
        self.assertEqual(self.decide(self.rm(), again)[0], 'block')

    def test_variants_allowed(self):
        self.approve()
        runner = FakeFleet(lambda argv, data: answer(mode='recheck'))
        for cmd in ('ssh -F %s -o BatchMode=yes t2-dev rm -rf %s' % (self.cfg, P1),
                    '/usr/bin/ssh -F %s/.ssh/config_fleetops t2-dev rm -rf %s' % (self.home, P1),
                    'ssh -o BatchMode=yes -F %s t2-dev rm -rf %s' % (self.cfg, P1),
                    'ssh -F %s t2-dev git -C %s worktree remove %s' % (self.cfg, PARENT, P1)):
            self.assertEqual(self.decide(cmd, self.approvals(runner))[0], 'allow', cmd)

    def test_worktree_remove_needs_a_linked_entry_and_its_parent(self):
        self.approve(runner=FakeFleet(answer('main')))
        runner = FakeFleet(lambda a, d: answer('main', mode='recheck'))
        cmd = 'ssh -F %s t2-dev git -C %s worktree remove %s' % (self.cfg, PARENT, P1)
        self.assertEqual(self.decide(cmd, self.approvals(runner))[0], 'block')
        self.assertEqual(runner.calls, [])
        self.approve(path=P2)
        runner = FakeFleet(lambda a, d: answer(mode='recheck'))
        wrong = 'ssh -F %s t2-dev git -C /home/eric/.agent-harness/work/S1/tester/x worktree remove %s' % (self.cfg, P2)
        self.assertEqual(self.decide(wrong, self.approvals(runner))[0], 'block')
        self.assertEqual(runner.calls, [])


class HookRecheck(Base):
    def setUp(self):
        super().setUp()
        self.approve()

    def blocked(self, reply):
        runner = FakeFleet(reply)
        verdict, message = self.decide(self.rm(), self.approvals(runner))
        self.assertEqual(verdict, 'block')
        approvals = self.approvals(FakeFleet(lambda a, d: answer(mode='recheck')))
        self.assertEqual(self.decide(self.rm(), approvals)[0], 'allow')  # still unspent
        return message

    def test_failures_refuse_and_leave_entry_unspent(self):
        self.blocked(subprocess.TimeoutExpired('ssh', 5))
        self.blocked(OSError('no ssh'))
        self.blocked(lambda a, d: (255, b''))
        self.blocked(lambda a, d: (0, b'not json'))
        self.blocked(lambda a, d: answer(head='c' * 40, mode='recheck'))
        self.blocked(lambda a, d: answer(tips='d' * 64, mode='recheck'))
        self.blocked(lambda a, d: answer(dev=9, mode='recheck'))
        self.blocked(lambda a, d: answer(ino=9, mode='recheck'))
        self.blocked(lambda a, d: answer(foot='e' * 64, mode='recheck'))  # the physical store layout changed
        self.blocked(lambda a, d: dict(answer(mode='recheck'), footprint_sha256=None))
        self.blocked(lambda a, d: {'ok': False, 'reason': 'a process has its working directory inside the path'})
        self.blocked(lambda a, d: answer('main', mode='recheck', linked=['/x/y']))

    def test_expired_entry_refused(self):
        runner = FakeFleet(lambda a, d: answer(mode='recheck'))
        late = self.approvals(runner, now=time.time() + 4000)
        self.assertEqual(self.decide(self.rm(), late)[0], 'block')
        self.assertEqual(runner.calls, [])

    def test_decide_without_runner_never_opens_ssh(self):
        approvals = self.approvals(None)
        self.assertEqual(self.decide(self.rm(), approvals)[0], 'block')
        self.assertEqual(approvals.used, {})

    def test_check_command_does_not_allow(self):
        c = cg.Compiled(self.policy, home=str(self.home))
        verdict, _ = cg.decide(self.rm(), c, marker=cg.Approvals(home=str(self.home), compiled=c))
        self.assertEqual(verdict, 'block')


class HookRefuses(Base):
    """Every near miss is refused while the exact approved command is allowed in the same test."""

    def setUp(self):
        super().setUp()
        self.approve()
        self.runner = FakeFleet(lambda a, d: answer(mode='recheck'))

    def verdict(self, cmd):
        return self.decide(cmd, self.approvals(self.runner))[0]

    def test_near_misses(self):
        h = str(self.home)
        bad = [
            'ssh t2-dev rm -rf %s' % P1,                                    # no -F
            'ssh -F /other/config t2-dev rm -rf %s' % P1,
            'ssh -F %s -F %s t2-dev rm -rf %s' % (self.cfg, self.cfg, P1),
            'ssh -F%s t2-dev rm -rf %s' % (self.cfg, P1),
            'ssh -oBatchMode=yes -F %s t2-dev rm -rf %s' % (self.cfg, P1),
            'ssh -F %s -o BatchMode=no t2-dev rm -rf %s' % (self.cfg, P1),
            'ssh -F %s -o ProxyCommand=x t2-dev rm -rf %s' % (self.cfg, P1),
            'ssh -F %s -J h t2-dev rm -rf %s' % (self.cfg, P1),
            'ssh -F %s -o LocalCommand=x t2-dev rm -rf %s' % (self.cfg, P1),
            'ssh -F %s -t t2-dev rm -rf %s' % (self.cfg, P1),
            'ssh -F %s dev2 rm -rf %s' % (self.cfg, P1),
            'ssh -F %s T2-DEV rm -rf %s' % (self.cfg, P1),
            'ssh -F %s t2-dev rm -rf %s %s' % (self.cfg, P1, P2),
            'ssh -F %s t2-dev rm -rf %s/' % (self.cfg, P1),
            'ssh -F %s t2-dev rm -fr %s' % (self.cfg, P1),
            'ssh -F %s t2-dev rm -r -f %s' % (self.cfg, P1),
            'ssh -F %s t2-dev rm -rf %s' % (self.cfg, P2),                       # a different path, unapproved
            'ssh -F %s t2-dev "rm -rf %s"' % (self.cfg, P1),
            "ssh -F %s t2-dev rm -rf '%s'" % (self.cfg, P1),
            'ssh -F %s t2-dev rm -rf %s && ssh -F %s t2-dev rm -rf %s' % (self.cfg, P1, self.cfg, P2),
            'ssh -F %s t2-dev rm -rf %s; echo' % (self.cfg, P1),
            'ssh -F %s t2-dev rm -rf %s $(x)' % (self.cfg, P1),
            'ssh -F %s t2-dev rm -rf %s | cat' % (self.cfg, P1),
            'ssh -F %s t2-dev rm -rf %s > f' % (self.cfg, P1),
            'ssh -F %s t2-dev rm -rf %s\nls' % (self.cfg, P1),
            'env ssh -F %s t2-dev rm -rf %s' % (self.cfg, P1),
            "bash -c 'ssh -F %s t2-dev rm -rf %s'" % (self.cfg, P1),
            'ssh -F %s t2-dev git -C %s worktree remove --force %s' % (self.cfg, PARENT, P1),
            'ssh -F %s t2-dev git worktree remove %s' % (self.cfg, P1),
            'ssh -F %s t2-dev rm -rf %s' % (TILDE_CFG, P1),                 # T5: only the absolute spelling
            'ssh -F %s -o BatchMode=yes t2-dev rm -rf %s' % (TILDE_CFG, P1),
        ]
        for cmd in bad:
            self.assertEqual(self.verdict(cmd), 'block', cmd)
        self.assertEqual(self.verdict(self.rm()), 'allow')

    def test_powershell_payload_is_not_allowed(self):
        c = cg.Compiled(self.policy, home=str(self.home))
        self.assertEqual(cg.decide(self.rm(), c, ps=True, marker=self.approvals(self.runner))[0], 'block')
        self.assertEqual(self.runner.calls, [])
        self.assertEqual(self.verdict(self.rm()), 'allow')

    def test_non_matching_command_never_invokes_runner(self):
        self.verdict('ssh -F %s t2-dev rm -rf %s' % (self.cfg, P2))
        self.verdict('ssh t2-dev rm -rf %s' % P1)
        self.assertEqual(self.runner.calls, [])

    def test_wrong_host_entry_not_used(self):
        self.policy['marker']['no_backup_fleet_hosts'] = ['t2-dev']
        self.assertEqual(self.verdict(self.rm(host='t2-dev')), 'allow')
        self.assertEqual(self.verdict(self.rm(host='dev2')), 'block')


class LocalUnchanged(Base):
    def test_remote_entry_never_covers_a_local_path(self):
        local = self.home / '.agent-harness/work/S1/tester/wt'
        local.mkdir(parents=True)
        entry = self.approve(path=str(local) if False else P1)
        approvals = self.approvals(None)
        self.assertFalse(approvals.covers(P1))
        self.assertFalse(approvals.covers(str(local)))
        self.assertEqual(entry['kind'], cg.NO_BACKUP_REMOTE_KIND)
        # even an entry forged with the same path string and a valid MAC is skipped by the local lookup
        entries, key = cg.load_marker(str(self.home))
        forged = dict(entries[0], path=str(local), identity=list(cg._identity(str(local))),
                      stat_sha256=cg.stat_manifest(str(local), self.policy['marker']))
        forged['mac'] = cg._mac(key, forged)
        approvals.entries = [forged]
        self.assertFalse(approvals.covers(str(local)))

    def test_local_entry_does_not_authorize_ssh(self):
        approvals = self.approvals(FakeFleet(lambda a, d: answer(mode='recheck')))
        approvals.entries = [{'kind': cg.NO_BACKUP_KIND, 'path': P1, 'nonce': 'x' * 16}]
        self.assertEqual(self.decide(self.rm(), approvals)[0], 'block')


class Repo:
    """A pushed clone under <home>/.agent-harness/work/S/T, with a git stub that answers ls-remote from a bare repo."""

    def __init__(self, home, name='clone'):
        self.home = Path(home)
        self.task = self.home / '.agent-harness/work/S/T'
        self.task.mkdir(parents=True, exist_ok=True)
        self.bare = self.home / 'remote.git'
        sh('git', 'init', '-q', '--bare', str(self.bare))
        self.path = self.task / name
        sh('git', 'init', '-q', '-b', 'main', str(self.path))
        (self.path / 'README').write_text('hi\n')
        sh('git', 'add', '-A', cwd=self.path)
        sh('git', 'commit', '-q', '-m', 'one', cwd=self.path)
        sh('git', 'remote', 'add', 'origin', str(self.bare), cwd=self.path)
        sh('git', 'push', '-q', 'origin', 'main', cwd=self.path)
        sh('git', 'remote', 'set-url', 'origin', 'https://github.com/example/x.git', cwd=self.path)
        self.stub = self.home / 'git-stub'
        self.stub.write_text('#!/bin/sh\nfor a in "$@"; do if [ "$a" = ls-remote ]; then\n  exec /usr/bin/git --git-dir=%s '
                             "for-each-ref --format='%%(objectname)\t%%(refname)' refs/heads refs/tags\nfi; done\n"
                             'exec /usr/bin/git "$@"\n' % self.bare)
        os.chmod(str(self.stub), 0o755)
        self.proc = self.home / 'proc'
        self.proc.mkdir()
        self.mountinfo = self.home / 'mountinfo'
        self.mountinfo.write_text('1 0 8:1 / / rw - ext4 /dev/sda1 rw\n')

    def test(self, **extra):
        cfg = {'home': str(self.home), 'git': str(self.stub), 'proc_root': str(self.proc),
               'mountinfo': str(self.mountinfo), 'docker': ''}
        cfg.update(extra)
        return cfg


class ValidatorBase(Base):
    def setUp(self):
        super().setUp()
        self.repo = Repo(self.home)

    def run_program(self, path=None, mode='validate', **extra):
        program = cg.build_fleet_program(mode, path or str(self.repo.path), self.policy, _test=self.repo.test(**extra))
        done = subprocess.run([sys.executable, '-I', '-'], input=program.encode(), stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, check=False, timeout=120)
        self.assertEqual(done.returncode, 0, done.stderr.decode()[-500:])
        return json.loads(done.stdout.decode())

    def refused(self, fragment=None, **kw):
        out = self.run_program(**kw)
        self.assertFalse(out['ok'], out)
        if fragment:
            self.assertIn(fragment, out['reason'])
        self.assertNotIn('://', out['reason'])
        return out


class RemoteValidatorScript(ValidatorBase):
    def test_clean_pushed_checkout_passes_and_recheck_matches(self):
        out = self.run_program()
        self.assertTrue(out['ok'], out)
        self.assertEqual(out['kind'], 'main')
        again = self.run_program(mode='recheck')
        self.assertTrue(again['ok'])
        self.assertEqual((out['head'], out['tips_sha256'], out['dev'], out['ino']),
                         (again['head'], again['tips_sha256'], again['dev'], again['ino']))

    def test_dirty_and_untracked(self):
        (self.repo.path / 'README').write_text('changed\n')
        self.refused('changed or untracked')
        sh('git', 'checkout', '-q', '--', 'README', cwd=self.repo.path)
        (self.repo.path / 'new.txt').write_text('x\n')
        self.refused('changed or untracked')

    def test_unpushed_head_and_branch_tip(self):
        sh('git', 'branch', 'side', cwd=self.repo.path)
        sh('git', 'checkout', '-q', 'side', cwd=self.repo.path)
        (self.repo.path / 'f').write_text('1\n')
        sh('git', 'add', 'f', cwd=self.repo.path)
        sh('git', 'commit', '-q', '-m', 'two', cwd=self.repo.path)
        self.refused('unpushed')
        sh('git', 'checkout', '-q', 'main', cwd=self.repo.path)
        self.refused('unpushed')  # the branch tip alone is enough

    def test_commit_only_on_notes_or_tracking_or_custom_refs(self):
        sh('git', 'checkout', '-q', '--detach', cwd=self.repo.path)
        (self.repo.path / 'f').write_text('1\n')
        sh('git', 'add', 'f', cwd=self.repo.path)
        sh('git', 'commit', '-q', '-m', 'two', cwd=self.repo.path)
        sha = sh('git', 'rev-parse', 'HEAD', cwd=self.repo.path).strip()
        sh('git', 'checkout', '-q', 'main', cwd=self.repo.path)
        for ref in ('refs/notes/x', 'refs/remotes/origin/gone', 'refs/custom/y'):
            sh('git', 'update-ref', ref, sha, cwd=self.repo.path)
            self.refused('unpushed')
            sh('git', 'update-ref', '-d', ref, cwd=self.repo.path)
        self.assertTrue(self.run_program()['ok'])

    def test_stash_submodule_filter_skipworktree_replace(self):
        (self.repo.path / 'README').write_text('s\n')
        sh('git', 'stash', cwd=self.repo.path)
        self.refused('stash')
        sh('git', 'stash', 'drop', cwd=self.repo.path)
        sh('git', 'config', 'filter.x.clean', 'cat', cwd=self.repo.path)
        self.refused('filter')
        sh('git', 'config', '--unset', 'filter.x.clean', cwd=self.repo.path)
        sh('git', 'update-index', '--skip-worktree', 'README', cwd=self.repo.path)
        (self.repo.path / 'README').write_text('hidden edit\n')
        self.refused('hides changes')
        sh('git', 'update-index', '--no-skip-worktree', 'README', cwd=self.repo.path)
        sh('git', 'checkout', '-q', '--', 'README', cwd=self.repo.path)
        (self.repo.path / '.gitmodules').write_text('[submodule "a"]\n')
        self.refused('submodule')

    def test_ignored_policy(self):
        (self.repo.path / '.git/info/exclude').write_text('*\n')
        (self.repo.path / 'hidden.txt').write_text('x\n')
        self.refused('ignored')
        (self.repo.path / '.git/info/exclude').write_text('')
        (self.repo.path / 'hidden.txt').unlink()
        (self.repo.path / '.gitignore').write_text('node_modules/\ndata/\nnotes.txt\n')
        sh('git', 'add', '.gitignore', cwd=self.repo.path)
        sh('git', 'commit', '-q', '-m', 'ig', cwd=self.repo.path)
        sh('git', 'push', '-q', str(self.repo.bare), 'main', cwd=self.repo.path)
        (self.repo.path / 'node_modules/a').mkdir(parents=True)
        (self.repo.path / 'node_modules/a/f.js').write_text('x\n')
        self.assertTrue(self.run_program()['ok'])
        (self.repo.path / 'data').mkdir()
        (self.repo.path / 'data/f').write_text('x\n')
        self.refused('not a build or cache')
        sh('rm', '-rf', str(self.repo.path / 'data'))
        (self.repo.path / 'notes.txt').write_text('x\n')
        self.refused('ignored file')
        (self.repo.path / 'notes.txt').unlink()
        sh('git', 'init', '-q', str(self.repo.path / 'node_modules/a/nested'))
        self.refused('nested git')

    def test_origin_must_be_allowlisted_and_credential_free(self):
        for url, fragment in (('https://tok@github.com/e/x.git', 'credentials'), ('https://example.org/e/x.git',
                                                                                  'allowlisted'),
                              (str(self.repo.bare), 'allowlisted')):
            sh('git', 'remote', 'set-url', 'origin', url, cwd=self.repo.path)
            out = self.refused(fragment)
            self.assertNotIn('tok', out['reason'])

    def test_lsremote_failure_and_no_lazy_fetch_for_missing_tip(self):
        stub = self.repo.home / 'git-fail'
        stub.write_text('#!/bin/sh\nfor a in "$@"; do if [ "$a" = ls-remote ]; then exit 128; fi; done\n'
                        'exec /usr/bin/git "$@"\n')
        os.chmod(str(stub), 0o755)
        self.refused('did not answer', git=str(stub))
        # a live tip this clone lacks is not fetched: the live listing has only commits we do not have
        empty = self.home / 'other.git'
        sh('git', 'init', '-q', '--bare', str(empty))
        other = self.home / 'o'
        sh('git', 'init', '-q', '-b', 'main', str(other))
        (other / 'z').write_text('z\n')
        sh('git', 'add', 'z', cwd=other)
        sh('git', 'commit', '-q', '-m', 'z', cwd=other)
        sh('git', 'push', '-q', str(empty), 'main', cwd=other)
        stub2 = self.repo.home / 'git-other'
        stub2.write_text('#!/bin/sh\nfor a in "$@"; do if [ "$a" = ls-remote ]; then exec /usr/bin/git --git-dir=%s '
                         "for-each-ref --format='%%(objectname)\t%%(refname)'; fi; done\nexec /usr/bin/git \"$@\"\n" % empty)
        os.chmod(str(stub2), 0o755)
        self.refused('no live remote commit exists', git=str(stub2))

    def test_process_open_file_mount_docker(self):
        pid = self.repo.proc / '4242'
        (pid / 'fd').mkdir(parents=True)
        os.symlink('/', str(pid / 'cwd'))
        os.symlink('/', str(pid / 'root'))
        os.symlink('/bin/sh', str(pid / 'exe'))
        os.symlink(str(self.repo.path / 'README'), str(pid / 'fd/3'))
        self.refused('open file inside')
        os.unlink(str(pid / 'fd/3'))
        os.unlink(str(pid / 'cwd'))
        os.symlink(str(self.repo.path / 'sub'), str(pid / 'cwd'))
        self.refused('working directory')
        os.unlink(str(pid / 'cwd'))
        os.symlink('/', str(pid / 'cwd'))
        self.assertTrue(self.run_program()['ok'])
        self.repo.mountinfo.write_text('1 0 8:1 / / rw - ext4 /dev/sda1 rw\n2 1 8:2 / %s/node rw - ext4 /d rw\n'
                                       % self.repo.path)
        self.refused('mount')
        self.repo.mountinfo.write_text('1 0 8:1 / / rw - ext4 /dev/sda1 rw\n')
        bad = self.home / 'docker-bad'
        bad.write_text('#!/bin/sh\nexit 1\n')
        os.chmod(str(bad), 0o755)
        self.refused('docker', docker=str(bad))
        mounts = self.home / 'docker-mount'
        mounts.write_text('#!/bin/sh\nif [ "$1" = ps ]; then echo %s; else echo %s; fi\n' % ('a' * 12, self.repo.path))
        os.chmod(str(mounts), 0o755)
        self.refused('docker', docker=str(mounts))
        ok = self.home / 'docker-ok'
        ok.write_text('#!/bin/sh\nif [ "$1" = ps ]; then echo %s; else echo /elsewhere; fi\n' % ('a' * 12))
        os.chmod(str(ok), 0o755)
        self.assertTrue(self.run_program(docker=str(ok))['ok'])

    def test_unreadable_process_fails_closed(self):
        pid = self.repo.proc / '77'
        pid.mkdir()
        (pid / 'cwd').write_text('not a link')  # readlink fails with EINVAL: a process that cannot be inspected
        self.refused('could not be inspected')

    def test_symlinks_and_paths(self):
        link = self.repo.task / 'lnk'
        link.symlink_to(self.repo.path)
        self.refused('symlink', path=str(link))
        sub = self.repo.task / 'real'
        sub.mkdir()
        sh('git', 'init', '-q', str(sub / 'g'))
        (self.repo.task / 'viaLink').symlink_to(sub)
        self.refused('symlink', path=str(self.repo.task / 'viaLink' / 'g'))
        for bad in (str(self.home / '.agent-harness/work/S'), str(self.repo.task),
                    str(self.home / '.agent-harness/work/S/T/../T/clone'), '/tmp/elsewhere/x/y'):
            self.refused(path=bad)

    def test_not_a_checkout_and_top_of_tree(self):
        plain = self.repo.task / 'plain'
        plain.mkdir()
        self.refused('not a git checkout', path=str(plain))
        (self.repo.path / 'subdir').mkdir()
        self.refused('not a git checkout', path=str(self.repo.path / 'subdir'))


class LinkedWorktrees(ValidatorBase):
    def test_linked_records_parent_and_ignores_shared_state(self):
        wt = self.repo.task / 'wt'
        sh('git', 'worktree', 'add', '-q', '--detach', str(wt), cwd=self.repo.path)
        sh('git', 'branch', 'unpushed-in-parent', cwd=self.repo.path)
        (self.repo.path / 'x').write_text('1\n')
        sh('git', 'add', 'x', cwd=self.repo.path)
        sh('git', 'commit', '-q', '-m', 'local only', cwd=self.repo.path)
        (self.repo.path / 'README').write_text('s\n')
        sh('git', 'stash', cwd=self.repo.path)
        out = self.run_program(path=str(wt))
        self.assertTrue(out['ok'], out)
        self.assertEqual(out['kind'], 'linked')
        self.assertEqual(os.path.realpath(out['parent']), str(self.repo.path))

    def test_main_refused_while_linked_exists_then_accepted(self):
        wt = self.repo.task / 'wt'
        sh('git', 'worktree', 'add', '-q', '--detach', str(wt), cwd=self.repo.path)
        out = self.run_program()
        self.assertTrue(out['ok'])
        self.assertEqual(out['linked_existing'], [str(wt)])
        with self.assertRaises(ValueError) as caught:
            cg.run_fleet_validator('t2-dev', 'validate', P1, self.policy, str(self.home),
                                   runner=FakeFleet(answer('main', linked=[str(wt)])))
        self.assertIn('linked worktrees', str(caught.exception))
        sh('rm', '-rf', str(wt))
        self.assertEqual(self.run_program()['linked_existing'], [])  # prunable: gone on disk

    def test_malformed_answers_refuse(self):
        for bad in (dict(answer(), kind='bogus'), dict(answer(), head='zz'), dict(answer(), dev=True),
                    dict(answer(), parent='/a b'), dict(answer(), linked_existing=['/x y']),
                    dict(answer('main'), parent='/x'), dict(answer(), tips_sha256='1'),
                    dict(answer(), footprint_sha256='1'), {k: v for k, v in answer().items() if k != 'footprint_sha256'}):
            with self.assertRaises(ValueError, msg=str(bad)):
                cg.run_fleet_validator('t2-dev', 'validate', P1, self.policy, str(self.home), runner=FakeFleet(bad))

    def test_forged_linked_layout_with_common_dir_inside_target_refused(self):
        """red-team C1: a .git directory whose commondir sits inside the target must not pass as a linked worktree."""
        import shutil
        path = self.repo.path
        sha = sh('git', 'rev-parse', 'HEAD', cwd=path).strip()
        moved = self.home / 'moved-git'
        os.rename(str(path / '.git'), str(moved))
        (path / '.git').mkdir()
        os.rename(str(moved), str(path / '.git/common'))
        (path / '.git/commondir').write_text('common\n')
        (path / '.git/HEAD').write_text(sha + '\n')
        sh('git', 'read-tree', 'HEAD', cwd=path)
        out = self.refused()
        self.assertTrue('inside the path' in out['reason'] or 'registered' in out['reason'], out)
        shutil.rmtree(str(path / '.git'))

    def test_per_worktree_refs_refused(self):
        wt = self.repo.task / 'wt2'
        sh('git', 'worktree', 'add', '-q', '--detach', str(wt), cwd=self.repo.path)
        self.assertTrue(self.run_program(path=str(wt))['ok'])
        sh('git', 'update-ref', 'refs/worktree/keep', 'HEAD', cwd=wt)
        self.refused('per-worktree', path=str(wt))

    def test_parent_inside_the_path_is_refused_on_the_mac_side(self):
        with self.assertRaises(ValueError):
            cg.run_fleet_validator('t2-dev', 'validate', P1, self.policy, str(self.home),
                                   runner=FakeFleet(answer(parent=P1 + '/.git/common')))

    def test_runner_output_is_bounded_and_timed(self):
        # V1: the cap stops the read at once (a SubprocessError that is not the timeout), well inside the 5 s timeout
        started = time.monotonic()
        with self.assertRaises(subprocess.SubprocessError) as caught:
            cg._fleet_default_runner(['/bin/sh', '-c', 'yes'], b'', 5, cap=1000)
        self.assertNotIsInstance(caught.exception, subprocess.TimeoutExpired)
        self.assertLess(time.monotonic() - started, 2.0)
        with self.assertRaises(subprocess.TimeoutExpired):
            cg._fleet_default_runner(['/bin/sh', '-c', 'sleep 5'], b'', 1)

    def test_nested_json_answer_refuses_without_recursion_error(self):
        with self.assertRaises(ValueError):
            cg.run_fleet_validator('t2-dev', 'validate', P1, self.policy, str(self.home),
                                   runner=FakeFleet(reply=(0, b'[' * 200000)))


# --------------------------------------------------------------------------- physical footprint (goodqa#16699 rescue)
#
# Every escape found so far makes bytes another repository needs physically live inside TARGET, or hides a git store
# under a name the old scan did not look for. Each row builds one escape; the validator must refuse it. Rows marked
# REGRESSION were already refused at 91f289f (kept as guards); every other row is answered ok=true by 91f289f.

def _move(src, dst):
    import shutil
    shutil.move(str(src), str(dst))


def _loose_object(objdir):
    for fan in sorted(os.listdir(str(objdir))):
        if re.fullmatch(r'[0-9a-f]{2}', fan):
            return Path(objdir) / fan / sorted(os.listdir(str(Path(objdir) / fan)))[0]
    raise AssertionError('no loose object')


class FootprintBase(ValidatorBase):
    """A pushed parent P (node_modules/ ignored and pushed), a linked worktree T, and an unpushed branch `precious` in P."""

    def setUp(self):
        super().setUp()
        P = self.repo.path
        (P / '.gitignore').write_text('node_modules/\n')
        sh('git', 'add', '.gitignore', cwd=P)
        sh('git', 'commit', '-q', '-m', 'gi', cwd=P)
        sh('git', 'push', '-q', str(self.repo.bare), 'main', cwd=P)
        self.wt = self.repo.task / 'wt'
        sh('git', 'worktree', 'add', '-q', '--detach', str(self.wt), cwd=P)
        self.cd = P / '.git'
        self.gd = self.cd / 'worktrees' / 'wt'
        self.nm = self.wt / 'node_modules'

    def precious(self):
        P = self.repo.path
        sh('git', 'checkout', '-q', '-b', 'precious', cwd=P)
        (P / 'p').write_text('1\n')
        sh('git', 'add', 'p', cwd=P)
        sh('git', 'commit', '-q', '-m', 'p', cwd=P)
        sh('git', 'checkout', '-q', 'main', cwd=P)
        self.nm.mkdir(exist_ok=True)

    def foreign(self):
        """An unrelated repo R outside TARGET with one unpushed commit."""
        r = self.repo.task / 'r'
        sh('git', 'init', '-q', '-b', 'main', str(r))
        (r / 'f').write_text('r\n')
        sh('git', 'add', 'f', cwd=r)
        sh('git', 'commit', '-q', '-m', 'r', cwd=r)
        return r


def _row_d1a_symlinked_objects(t):
    t.precious()
    _move(t.cd / 'objects', t.nm / 'o')
    os.symlink(str(t.nm / 'o'), str(t.cd / 'objects'))


def _alternates_into_target(t, line_for):
    t.precious()
    objs = t.cd / 'objects'
    (t.nm / 'o').mkdir()
    for e in os.listdir(str(objs)):
        if e != 'info':
            _move(objs / e, t.nm / 'o' / e)
    (objs / 'pack').mkdir()
    (objs / 'info').mkdir(exist_ok=True)
    (objs / 'info/alternates').write_text(line_for(objs, t.nm / 'o') + '\n')


def _row_d1b_alternates(t):
    _alternates_into_target(t, lambda objs, o: str(o))


def _row_relative_alternates(t):
    _alternates_into_target(t, lambda objs, o: os.path.relpath(str(o), str(objs)))


def _row_nested_alternates_chain(t):
    _alternates_into_target(t, lambda objs, o: str(o))
    hop = t.repo.task / 'hop-objects'  # a real object dir outside TARGET that itself borrows from TARGET
    (hop / 'pack').mkdir(parents=True)
    (hop / 'info').mkdir()
    _move(t.cd / 'objects/info/alternates', hop / 'info/alternates')
    (t.cd / 'objects/info/alternates').write_text(str(hop) + '\n')


def _row_d1c_symlinked_refs(t):
    t.precious()
    _move(t.cd / 'refs', t.nm / 'r')
    os.symlink(str(t.nm / 'r'), str(t.cd / 'refs'))


def _row_symlinked_packed_refs(t):
    t.precious()
    sh('git', 'pack-refs', '--all', cwd=t.repo.path)
    _move(t.cd / 'packed-refs', t.nm / 'pr')
    os.symlink(str(t.nm / 'pr'), str(t.cd / 'packed-refs'))


def _row_symlinked_loose_object(t):
    t.precious()
    obj = _loose_object(t.cd / 'objects')
    _move(obj, t.nm / 'blob')
    os.symlink(str(t.nm / 'blob'), str(obj))


def _row_http_alternates(t):
    t.precious()
    (t.cd / 'objects/info').mkdir(exist_ok=True)
    (t.cd / 'objects/info/http-alternates').write_text('https://example.invalid/objects\n')


def _row_config_include(t):
    t.precious()
    (t.nm / 'inc.cfg').write_text('[user]\n\tname = x\n')
    sh('git', 'config', 'include.path', str(t.nm / 'inc.cfg'), cwd=t.repo.path)


def _row_config_include_if(t):
    t.precious()
    (t.nm / 'inc.cfg').write_text('[user]\n\tname = x\n')
    sh('git', 'config', 'includeIf.gitdir:/.path', str(t.nm / 'inc.cfg'), cwd=t.repo.path)


def _row_mount_on_parent_store(t):
    t.precious()
    t.repo.mountinfo.write_text('1 0 8:1 / / rw - ext4 /dev/sda1 rw\n2 1 8:2 / %s/objects rw - ext4 /d rw\n' % t.cd)


def _row_git_dir_parked_in_node_modules(t):
    t.precious()
    r = t.repo.task / 'r'
    sh('git', 'init', '-q', '--separate-git-dir', str(t.nm / 'm'), str(r))  # like a submodule store, under another name


def _row_worktree_rebase_in_progress(t):
    (t.gd / 'rebase-merge').mkdir()


def _row_worktree_merge_in_progress(t):
    (t.gd / 'MERGE_HEAD').write_text(sh('git', 'rev-parse', 'HEAD', cwd=t.wt))


def _row_worktree_rewritten_ref(t):
    sh('git', 'update-ref', 'refs/rewritten/label', 'HEAD', cwd=t.wt)


def _row_worktree_ref_write_in_flight(t):
    (t.gd / 'HEAD.lock').write_text('x\n')


def _row_unknown_common_entry(t):
    (t.cd / 'frobnicate').write_text('x\n')


def _row_unknown_worktree_entry(t):
    (t.gd / 'frobnicate').write_text('x\n')


def _row_regression_submodule_store_in_modules(t):
    sh('git', 'init', '-q', '--bare', str(t.cd / 'modules/sub'))


# main-repository rows: TARGET is P itself (clean and fully pushed), something foreign is parked inside it
def _row_bare_store_in_node_modules(t):
    t.nm = t.repo.path / 'node_modules'
    r = t.foreign()
    sh('git', 'clone', '-q', '--bare', str(r), str(t.nm / 'x/store'))


def _row_git_dir_parked_main(t):
    t.nm = t.repo.path / 'node_modules'
    t.nm.mkdir()
    sh('git', 'init', '-q', '--separate-git-dir', str(t.nm / 'm'), str(t.repo.task / 'r2'))


def _row_foreign_objects_parked(t):
    t.nm = t.repo.path / 'node_modules'
    t.nm.mkdir()
    r = t.foreign()
    _move(r / '.git/objects', t.nm / 'o')
    os.symlink(str(t.nm / 'o'), str(r / '.git/objects'))


def _row_foreign_refs_parked(t):
    t.nm = t.repo.path / 'node_modules'
    t.nm.mkdir()
    r = t.foreign()
    _move(r / '.git/refs', t.nm / 'r')
    os.symlink(str(t.nm / 'r'), str(r / '.git/refs'))


def _row_foreign_pack_parked(t):
    t.nm = t.repo.path / 'node_modules'
    t.nm.mkdir()
    r = t.foreign()
    sh('git', 'gc', '-q', cwd=r)
    _move(r / '.git/objects/pack', t.nm / 'p')
    os.symlink(str(t.nm / 'p'), str(r / '.git/objects/pack'))


def _row_foreign_fanout_parked_renamed(t):
    t.nm = t.repo.path / 'node_modules'
    t.nm.mkdir()
    r = t.foreign()
    objs = r / '.git/objects'
    fan = sorted(d for d in os.listdir(str(objs)) if re.fullmatch(r'[0-9a-f]{2}', d))[0]
    _move(objs / fan, t.nm / 'x')  # not a two-hex name inside TARGET
    os.symlink(str(t.nm / 'x'), str(objs / fan))


def _row_regression_core_worktree(t):
    sh('git', 'config', 'core.worktree', str(t.wt), cwd=t.repo.path)


def _row_regression_config_worktree(t):
    sh('git', 'config', 'extensions.worktreeConfig', 'true', cwd=t.repo.path)
    sh('git', 'config', '--worktree', 'core.worktree', str(t.repo.task / 'elsewhere'), cwd=t.wt)


def _row_regression_core_bare(t):
    sh('git', 'config', 'core.bare', 'true', cwd=t.repo.path)


def _row_main_rebase_in_progress(t):
    (t.cd / 'rebase-merge').mkdir()


def _row_regression_c1_commondir_inside_target(t):
    path = t.repo.path
    sha = sh('git', 'rev-parse', 'HEAD', cwd=path).strip()
    moved = t.home / 'moved-git'
    _move(path / '.git', moved)
    (path / '.git').mkdir()
    _move(moved, path / '.git/common')
    (path / '.git/commondir').write_text('common\n')
    (path / '.git/HEAD').write_text(sha + '\n')
    sh('git', 'read-tree', 'HEAD', cwd=path)


# (name, builder, target 'linked' or 'main', regression-only, the reason fragment the head refuses with)
ESCAPES = [
    ('d1a_symlinked_objects', _row_d1a_symlinked_objects, 'linked', False, 'object store is not a plain directory'),
    ('d1b_alternates', _row_d1b_alternates, 'linked', False, 'alternate object store is inside the path'),
    ('relative_alternates', _row_relative_alternates, 'linked', False, 'alternate object store is inside the path'),
    ('nested_alternates_chain', _row_nested_alternates_chain, 'linked', False, 'alternate object store is inside the path'),
    ('d1c_symlinked_refs', _row_d1c_symlinked_refs, 'linked', False, 'git store entry is a symlink (refs)'),
    ('symlinked_packed_refs', _row_symlinked_packed_refs, 'linked', False, 'git store entry is a symlink (packed-refs)'),
    ('symlinked_loose_object', _row_symlinked_loose_object, 'linked', False, 'git store entry is a symlink'),
    ('http_alternates', _row_http_alternates, 'linked', False, 'http-alternates'),
    ('config_include', _row_config_include, 'linked', False, 'config includes another file'),
    ('config_include_if', _row_config_include_if, 'linked', False, 'config includes another file'),
    ('mount_on_parent_store', _row_mount_on_parent_store, 'linked', False, 'mount is at or under a git store'),
    ('git_dir_parked_in_node_modules', _row_git_dir_parked_in_node_modules, 'linked', False, 'git store look-alike'),
    ('worktree_rebase_in_progress', _row_worktree_rebase_in_progress, 'linked', False, 'in progress in the worktree (rebase-merge)'),
    ('worktree_merge_in_progress', _row_worktree_merge_in_progress, 'linked', False, 'in progress in the worktree (MERGE_HEAD)'),
    ('worktree_rewritten_ref', _row_worktree_rewritten_ref, 'linked', False, 'per-worktree refs'),
    ('worktree_ref_write_in_flight', _row_worktree_ref_write_in_flight, 'linked', False, 'in progress in the worktree (HEAD.lock)'),
    ('unknown_common_entry', _row_unknown_common_entry, 'linked', False, 'git directory has an unknown entry (frobnicate)'),
    ('unknown_worktree_entry', _row_unknown_worktree_entry, 'linked', False, 'worktree git directory has an unknown entry'),
    ('regression_submodule_store_in_modules', _row_regression_submodule_store_in_modules, 'linked', True, 'submodules'),
    ('regression_core_worktree', _row_regression_core_worktree, 'linked', True, 'sets core.worktree'),
    ('regression_config_worktree', _row_regression_config_worktree, 'linked', True, 'not the top of its git working tree'),
    ('regression_core_bare', _row_regression_core_bare, 'linked', True, 'no main working tree'),
    ('bare_store_in_node_modules', _row_bare_store_in_node_modules, 'main', False, 'git store look-alike'),
    ('git_dir_parked_main', _row_git_dir_parked_main, 'main', False, 'git store look-alike'),
    ('foreign_objects_parked', _row_foreign_objects_parked, 'main', False, 'loose git object'),
    ('foreign_fanout_parked_renamed', _row_foreign_fanout_parked_renamed, 'main', False, 'loose git object'),
    ('foreign_refs_parked', _row_foreign_refs_parked, 'main', False, 'git ref file'),
    ('foreign_pack_parked', _row_foreign_pack_parked, 'main', False, 'git pack is inside the path'),
    ('main_rebase_in_progress', _row_main_rebase_in_progress, 'main', False, 'git operation is in progress (rebase-merge)'),
    ('regression_c1_commondir_inside_target', _row_regression_c1_commondir_inside_target, 'main', True,
     'inside the path'),
]


class FootprintEscapes(FootprintBase):
    def check_escape(self, build, kind, fragment):
        if kind == 'main':
            sh('git', 'worktree', 'remove', str(self.wt), cwd=self.repo.path)
        target = str(self.wt if kind == 'linked' else self.repo.path)
        base = self.run_program(path=target)
        self.assertTrue(base['ok'], base)  # the clean layout passes: the refusal below is the escape's, not the setup's
        build(self)
        out = self.run_program(path=target)
        self.assertFalse(out['ok'], 'escape approved: %s' % out)
        self.assertIn(fragment, out['reason'])  # refused by the rule meant for this escape, not a neighbour
        again = self.run_program(path=target, mode='recheck')
        self.assertFalse(again['ok'], 'escape approved at recheck: %s' % again)
        self.assertIn(fragment, again['reason'])


def _escape_test(build, kind, fragment):
    def test(self):
        self.check_escape(build, kind, fragment)
    return test


for _name, _build, _kind, _reg, _fragment in ESCAPES:
    setattr(FootprintEscapes, 'test_escape_%s' % _name, _escape_test(_build, _kind, _fragment))


class FootprintRecheck(FootprintBase):
    def test_layout_built_after_approval_fails_recheck(self):
        first = self.run_program(path=str(self.wt))
        self.assertTrue(first['ok'], first)
        _row_d1a_symlinked_objects(self)
        out = self.run_program(path=str(self.wt), mode='recheck')
        self.assertFalse(out['ok'], out)

    def test_nested_git_created_after_approval_fails_recheck(self):
        sh('git', 'worktree', 'remove', str(self.wt), cwd=self.repo.path)
        self.assertTrue(self.run_program()['ok'])
        sh('git', 'init', '-q', str(self.repo.path / 'node_modules/a/nested'))
        out = self.run_program(mode='recheck')
        self.assertFalse(out['ok'], out)
        self.assertIn('nested git', out['reason'])

    def test_replaced_object_dir_changes_the_footprint_digest(self):
        first = self.run_program(path=str(self.wt))
        objs = self.cd / 'objects'
        sh('cp', '-R', str(objs), str(self.cd / 'objects.new'))
        sh('rm', '-rf', str(objs))
        _move(self.cd / 'objects.new', objs)
        again = self.run_program(path=str(self.wt), mode='recheck')
        self.assertTrue(again['ok'], again)
        self.assertRegex(str(first.get('footprint_sha256')), r'^[0-9a-f]{64}$')
        self.assertNotEqual(first.get('footprint_sha256'), again.get('footprint_sha256'))
        d1 = cg._fleet_digest('t2-dev', P1, dict(first, parent=PARENT))
        d2 = cg._fleet_digest('t2-dev', P1, dict(again, parent=PARENT))
        self.assertNotEqual(d1, d2)  # the hook compares this digest, so the recheck refuses

    def test_pack_refs_in_the_parent_keeps_the_footprint(self):
        first = self.run_program(path=str(self.wt))
        sh('git', 'branch', 'side', cwd=self.repo.path)
        sh('git', 'pack-refs', '--all', cwd=self.repo.path)
        sh('git', 'branch', '-D', 'side', cwd=self.repo.path)  # rewrites packed-refs: a new inode
        again = self.run_program(path=str(self.wt), mode='recheck')
        self.assertTrue(again['ok'], again)
        self.assertEqual(first['footprint_sha256'], again['footprint_sha256'])


class FootprintGuards(FootprintBase):
    def test_hostile_git_environment_does_not_steer_the_validator(self):
        """The validator runs git with a fresh environment: GIT_DIR, GIT_OBJECT_DIRECTORY and friends in the caller's
        environment reach neither the clean answer nor the refusal of an escape."""
        decoy = self.home / 'decoy.git'
        sh('git', 'init', '-q', '--bare', str(decoy))
        hostile = {'GIT_DIR': str(decoy), 'GIT_COMMON_DIR': str(decoy), 'GIT_WORK_TREE': str(self.home),
                   'GIT_OBJECT_DIRECTORY': str(decoy / 'objects'), 'GIT_INDEX_FILE': str(self.home / 'idx'),
                   'GIT_ALTERNATE_OBJECT_DIRECTORIES': str(self.nm), 'GIT_CONFIG_PARAMETERS': "'core.worktree=/'",
                   'GIT_CONFIG_COUNT': '1', 'GIT_CONFIG_KEY_0': 'core.bare', 'GIT_CONFIG_VALUE_0': 'true'}
        def hostile_run():
            saved = {k: os.environ.get(k) for k in hostile}
            os.environ.update(hostile)  # only around the validator run: the fixture's own git calls stay clean
            try:
                return self.run_program(path=str(self.wt))
            finally:
                for k, v in saved.items():
                    if v is None:
                        os.environ.pop(k, None)
                    else:
                        os.environ[k] = v
        clean = hostile_run()
        self.assertTrue(clean['ok'], clean)
        _row_d1a_symlinked_objects(self)
        out = hostile_run()
        self.assertFalse(out['ok'], out)
        self.assertIn('object store is not a plain directory', out['reason'])

    def test_unknown_git_dir_entries_default_to_refused(self):
        """A name git might add tomorrow is refused until someone allow-lists it, in each store directory."""
        for where in (self.cd, self.gd, self.cd / 'objects', self.cd / 'objects/info'):
            where.mkdir(exist_ok=True)
            probe = where / 'zz-new-entry'
            probe.write_text('x\n')
            out = self.run_program(path=str(self.wt))
            self.assertFalse(out['ok'], (where, out))
            self.assertIn('unknown entry', out['reason'])
            probe.unlink()
        self.assertTrue(self.run_program(path=str(self.wt))['ok'])
        for name in ('frobnicate', 'annex', 'svn', 'filter-repo'):
            self.assertNotIn(name, cg.FLEET_VALIDATOR_BODY.split('KNOWN_STORE = ', 1)[1].split('}', 1)[0])

    def test_ordinary_layouts_still_pass(self):
        P = self.repo.path
        sh('git', 'commit', '-q', '--allow-empty', '-m', 'e', cwd=P)
        sh('git', 'push', '-q', str(self.repo.bare), 'main', cwd=P)
        sh('git', 'gc', '-q', cwd=P)
        sh('git', 'commit-graph', 'write', '--reachable', cwd=P)
        sh('git', 'multi-pack-index', 'write', cwd=P)
        for name in ('ORIG_HEAD', 'FETCH_HEAD', 'COMMIT_EDITMSG', 'gc.log'):
            (self.cd / name).write_text('x\n')
        (self.cd / 'MERGE_HEAD').write_text('x\n')  # the parent is mid-merge: it survives the worktree's removal
        (self.gd / 'ORIG_HEAD').write_text('x\n')
        (self.gd / 'gc.log.lock').write_text('')  # left by a killed `gc --auto` (seen live on t2-dev)
        (self.cd / 'gc.log.lock').write_text('')
        (self.cd / 'gc.pid').write_text('1 host\n')
        hooks = self.cd / 'hooks'
        hooks.mkdir(exist_ok=True)
        (hooks / 'pre-commit').symlink_to('/bin/true')
        nm = self.wt / 'node_modules/pkg'
        (nm / '.cache/webpack').mkdir(parents=True)
        (nm / '.cache/webpack/0.pack').write_bytes(b'\x00webpack cache')
        (nm / 'REVISION').write_text('a' * 40 + '\n')
        (nm / 'ab').mkdir()
        (nm / 'ab' / ('c' * 38)).write_text('{"not": "zlib"}')
        (self.wt / 'node_modules/.bin').mkdir()
        (self.wt / 'node_modules/.bin/tool').symlink_to('../pkg/REVISION')
        out = self.run_program(path=str(self.wt))
        self.assertTrue(out['ok'], out)
        self.assertGreater(out['store_entries'], 0)
        self.assertGreater(out['tree_entries'], 0)

    def test_hardlinked_pack_is_harmless_and_deleting_the_target_keeps_the_parent(self):
        """Hardlinks are not refused (local clones hardlink packs): unlinking TARGET's name leaves the parent's."""
        self.precious()
        P = self.repo.path
        sh('git', 'gc', '-q', cwd=P)
        pack = sorted((self.cd / 'objects/pack').glob('pack-*.pack'))[0]
        os.link(str(pack), str(self.nm / 'blob'))
        self.assertGreater(os.stat(str(pack)).st_nlink, 1)
        out = self.run_program(path=str(self.wt))
        self.assertTrue(out['ok'], out)
        sh('rm', '-rf', str(self.wt))
        sh('git', 'fsck', '--connectivity-only', cwd=P)
        self.assertTrue(sh('git', 'rev-parse', '--verify', 'precious', cwd=P).strip())


if __name__ == '__main__':
    unittest.main()
