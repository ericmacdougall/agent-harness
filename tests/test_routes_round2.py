"""goodqa#16943: guard refusals name the sanctioned route instead of the log-backup procedure.

H7: every refused `git worktree remove` (a compound line, --force, an ssh payload) names the exact
`ah worktree-remove --host ... --path ...` command, and a stale-tracking-ref refusal names the
`git -C <registry repo> fetch --prune <remote>` that clears it. H6: a refused move or delete of durable work state
under ~/.agent-harness/work says it is not a log and names the task tmp/ folder. Every refusal stays a refusal, and
logs, WALs, transcripts and kits keep the log wording (must-fail controls). Real temporary repositories under a
temporary HOME, fake network and ssh only; commands are data passed to decide()."""

import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
HOOKS = Path(os.environ.get('CG_HOOKS_DIR') or ROOT / 'harness/hooks')
sys.path.insert(0, str(HOOKS))
import ah_worktree  # noqa: E402
import command_guard as cg  # noqa: E402

URL = 'https://github.com/acme/widgets.git'
REMOTE = ah_worktree.REMOTE_HOSTS[0]  # the one remote host the route serves; never spelled out here
GIT_ENV = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
GIT_ENV.update(GIT_CONFIG_GLOBAL='/dev/null', GIT_CONFIG_NOSYSTEM='1', GIT_AUTHOR_NAME='t',
               GIT_AUTHOR_EMAIL='t@example.invalid', GIT_COMMITTER_NAME='t', GIT_COMMITTER_EMAIL='t@example.invalid')
LOG_WORDING = 'Claude/Codex/harness logs and state are never deleted'
ROUTE = 'ah.py worktree-remove --host '
ADVISED_ROUTE = re.compile(r'python3 -I ~/\.claude/hooks/ah\.py worktree-remove --host (\S+) --path (\S+) --reason "<why>"')
FOREIGN = 'inside a container, chroot or namespace'


def git(cwd, *args):
    done = subprocess.run(['git', *args], cwd=str(cwd), env=GIT_ENV, capture_output=True, text=True, check=False)
    if done.returncode:
        raise AssertionError('git %s: %s' % (' '.join(args), done.stderr))
    return done.stdout.strip()


class Home(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='cg-routes-')
        self.addCleanup(self.temp.cleanup)
        self.home = Path(os.path.realpath(self.temp.name))
        patch = mock.patch.dict(os.environ, {'HOME': str(self.home)})
        patch.start()
        self.addCleanup(patch.stop)
        self.work = self.home / '.agent-harness/work/S'
        self.work.mkdir(parents=True)
        self.policy = cg.load_policy(path=str(self.home / 'missing-policy.json'))

    def decide(self, command, cwd=None):
        cwd = str(cwd or self.work)
        compiled = cg.Compiled(self.policy, home=str(self.home), cwd=cwd)
        return cg.decide(command, compiled, cwd=cwd)

    def blocked(self, command, cwd=None):
        verdict, message = self.decide(command, cwd)
        self.assertEqual(verdict, 'block', command)
        return message


class WorktreeRoutes(Home):
    def setUp(self):
        super().setUp()
        self.primary, self.linked = self.work / 'T/primary', self.work / 'T/linked'
        self.primary.mkdir(parents=True)
        git(self.primary, 'init', '-q', '-b', 'main')
        (self.primary / 'a.txt').write_text('one\n')
        git(self.primary, 'add', 'a.txt')
        git(self.primary, 'commit', '-q', '-m', 'one')
        git(self.primary, 'remote', 'add', 'origin', URL)
        git(self.primary, 'worktree', 'add', '-q', '-b', 'linked', str(self.linked))
        self.head = git(self.linked, 'rev-parse', 'HEAD')
        git(self.primary, 'update-ref', 'refs/remotes/origin/main', self.head)
        git(self.primary, 'update-ref', 'refs/remotes/origin/linked', self.head)
        self.live = {'refs/heads/main': self.head, 'refs/heads/linked': self.head}
        patch = mock.patch.object(cg, 'REMOTE_LS', lambda url, repo, timeout: dict(self.live))
        patch.start()
        self.addCleanup(patch.stop)

    def stale_ref(self, remote='origin'):
        """A remote-tracking ref for a branch the remote no longer has, at a commit only that ref reaches."""
        git(self.primary, 'checkout', '-q', '-b', 'side-' + remote)
        (self.primary / ('b-%s.txt' % remote)).write_text('two\n')
        git(self.primary, 'add', 'b-%s.txt' % remote)
        git(self.primary, 'commit', '-q', '-m', 'side')
        git(self.primary, 'update-ref', 'refs/remotes/%s/gone' % remote, git(self.primary, 'rev-parse', 'HEAD'))
        git(self.primary, 'checkout', '-q', 'main')
        self.assertIn('stale', cg.linked_worktree_remove_refusal(str(self.linked), str(self.primary), self.policy))

    def test_the_exemption_is_unchanged_for_the_verified_standalone_form(self):
        self.assertEqual(self.decide('git worktree remove ' + str(self.linked), self.primary)[0], 'allow')

    def test_a_compound_or_forced_removal_names_the_route_with_the_literal_path(self):
        for command in ('cd %s && git worktree remove --force %s' % (self.primary, self.linked),
                        'git worktree remove %s && echo done' % self.linked,
                        'git worktree remove --force ../linked',
                        'cd %s && git worktree remove --force ../linked' % self.primary):
            message = self.blocked(command, self.primary)
            self.assertIn(ROUTE + 'local --path %s ' % self.linked, message, command)
            self.assertNotIn('back up to Dropbox', message, command)
            self.assertIn('no --force', message, command)

    def test_a_path_the_guard_cannot_prove_is_a_placeholder_never_a_resolved_guess(self):
        # #333 review F1: after cd "$X", cd -, popd or a git -C, a relative spelling resolves against a directory the
        # analysis no longer knows, so the advice could name a DIFFERENT worktree; variables and globs are not printed
        for command in ('cd "$OTHER" && git worktree remove --force ../linked',
                        'cd - && git worktree remove --force ../linked',
                        'pushd /var && popd; git worktree remove --force ../linked',
                        'git -C %s worktree remove --force ../linked' % self.linked,
                        'W=%s; git worktree remove --force $W/linked' % (self.work / 'T'),
                        'git worktree remove --force %s/lin*' % (self.work / 'T')):
            message = self.blocked(command, self.primary)
            self.assertIn(ROUTE + 'local --path <abs path> ', message, command)
            self.assertNotIn('--path %s ' % self.linked, message, command)

    def test_inside_a_container_chroot_or_namespace_no_local_route_is_printed(self):
        # #333 review F4: the path belongs to another filesystem view; --host local would point at this machine
        for command in ('docker exec box git worktree remove --force /srv/wt',
                        'podman exec -u u box git worktree remove --force /srv/wt',
                        'chroot /srv git worktree remove --force /wt',
                        'nsenter -t 1 -m git worktree remove --force /srv/wt',
                        'unshare -m git worktree remove --force /srv/wt'):
            message = self.blocked(command, self.primary)
            self.assertNotIn(ROUTE, message, command)
            self.assertIn(FOREIGN, message, command)
        # and the sentinel does not leak to a command after the wrapper
        message = self.blocked('docker exec box true; git worktree remove --force %s' % self.linked, self.primary)
        self.assertIn(ROUTE + 'local --path %s ' % self.linked, message)

    def test_every_advised_command_is_itself_allowed_by_the_guard(self):
        self.stale_ref()
        message = self.blocked('git worktree remove %s' % self.linked, self.primary)
        prune = re.search(r'`(git -C \S+ fetch --prune --all)`', message)
        route = ADVISED_ROUTE.search(message)
        self.assertTrue(prune and route, message)
        self.assertEqual(self.decide(prune.group(1), self.primary)[0], 'allow', prune.group(1))
        filled = route.group(0).replace('<why>', 'merged and published')
        self.assertEqual(self.decide(filled, self.primary)[0], 'allow', filled)
        step = ah_worktree.next_step(REMOTE, '/home/u/scratch/wt', StaleRefNextStep.stale(), True)
        fetch = re.search(r'`(ssh \S+ .+?)` first', step).group(1)
        self.assertEqual(self.decide(fetch, self.primary)[0], 'allow', fetch)
        again = ADVISED_ROUTE.search(step).group(0).replace('<why>', 'merged and published') + ' --remote-auth'
        self.assertEqual(self.decide(again, self.primary)[0], 'allow', again)

    def test_an_ssh_payload_names_the_route_on_that_host(self):
        message = self.blocked("ssh %s 'git -C /home/u/repo worktree remove /home/u/scratch/wt'" % REMOTE)
        self.assertIn(ROUTE + REMOTE + ' --path /home/u/scratch/wt ', message)
        self.assertNotIn('standalone literal non-forced form', message)

    def test_an_ssh_payload_never_prints_this_machines_home_or_a_shell_active_path(self):
        for command in ("ssh %s 'git worktree remove ~/scratch/wt'" % REMOTE,
                        'ssh %s "git worktree remove \\$HOME/scratch/wt"' % REMOTE,
                        "ssh %s 'W=/home/u/x; git worktree remove $W/wt'" % REMOTE,
                        "ssh %s 'git worktree remove \"/home/u/x;rm -rf ~\"'" % REMOTE,
                        "ssh %s 'git worktree remove \"/home/u/$(id)/wt\"'" % REMOTE):
            message = self.blocked(command)
            self.assertIn(ROUTE + REMOTE + ' --path <abs path> ', message, command)
            self.assertNotIn(str(self.home), message, command)

    def test_an_ssh_payload_to_a_host_the_route_does_not_serve_gets_no_command_for_it(self):
        message = self.blocked("ssh user@build-box-9 'git worktree remove /home/u/wt'")
        self.assertNotIn('--host build-box-9', message)
        self.assertIn('serves only this machine and ' + REMOTE, message)

    def test_a_stale_tracking_ref_refusal_names_the_fetch_prune_then_the_route(self):
        git(self.primary, 'checkout', '-q', '-b', 'side')
        (self.primary / 'b.txt').write_text('two\n')
        git(self.primary, 'add', 'b.txt')
        git(self.primary, 'commit', '-q', '-m', 'side')
        git(self.primary, 'update-ref', 'refs/remotes/origin/gone', git(self.primary, 'rev-parse', 'HEAD'))
        git(self.primary, 'checkout', '-q', 'main')
        self.assertIn('stale', cg.linked_worktree_remove_refusal(str(self.linked), str(self.primary), self.policy))
        message = self.blocked('git worktree remove ' + str(self.linked), self.primary)
        prune = 'git -C %s fetch --prune --all' % self.primary
        self.assertIn(prune, message)
        self.assertLess(message.index(prune), message.index(ROUTE + 'local --path %s ' % self.linked))

    def test_the_route_hosts_agree_with_ah_worktree(self):
        self.assertEqual(tuple(cg.WORKTREE_ROUTE_HOSTS), tuple(ah_worktree.REMOTE_HOSTS))

    def test_prune_hint_refuses_values_that_are_not_plain_literals(self):
        # #333 review F2, F3: --all clears a stale ref under any remote, and no remote name is ever printed
        self.assertEqual(cg.worktree_prune_hint('/home/u/repo'), 'git -C /home/u/repo fetch --prune --all')
        for repo in ('/home/u/a b', '/home/u/$(id)', 'relative/repo', '/home/u/../etc', '-C/x', None):
            self.assertIsNone(cg.worktree_prune_hint(repo), repo)

    def test_a_stale_ref_under_another_remote_gets_advice_that_clears_it(self):
        git(self.primary, 'remote', 'add', 'upstream', URL)
        self.stale_ref('upstream')
        message = self.blocked('git worktree remove ' + str(self.linked), self.primary)
        self.assertIn('git -C %s fetch --prune --all' % self.primary, message)
        self.assertNotIn('fetch --prune origin', message)


class StaleRefNextStep(unittest.TestCase):
    """The delegated route keeps its stale-ref rule; its answer names the two commands that clear it."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)

    def run_remove(self, answer, host=REMOTE, authenticated=False):
        def runner(argv, **kwargs):
            return subprocess.CompletedProcess(argv, 1, json.dumps(answer), '')
        return ah_worktree.remove(host, '/home/u/scratch/wt', 'merged and published', authenticated, 's1', 'a1',
                                  self.home, runner)

    @staticmethod
    def stale(**kw):
        base = {'removable': False, 'removed': False, 'verifier': ah_worktree.VERIFIER_VERSION, 'head': 'a' * 40,
                'reason': 'a remote-tracking ref is stale or names a moved/deleted remote branch; fetch --prune first',
                'repo': '/home/u/repos/base', 'urls': {'origin': [URL]}}
        base.update(kw)
        return base

    def test_a_stale_ref_refusal_names_the_fetch_prune_on_the_same_host_then_the_same_removal(self):
        result = self.run_remove(self.stale(), authenticated=True)
        self.assertFalse(result['removed'])
        self.assertIn("ssh %s 'git -C /home/u/repos/base fetch --prune --all'" % REMOTE, result['next'])
        self.assertIn('worktree-remove --host %s --path /home/u/scratch/wt ' % REMOTE, result['next'])
        self.assertTrue(result['next'].endswith('--remote-auth'))
        local = self.run_remove(self.stale(), host='local')
        self.assertIn('run `git -C /home/u/repos/base fetch --prune --all` first', local['next'])
        # the remote names come from the repository: none is printed, whichever remote holds the stale ref
        for urls in ({'upstream': [URL]}, {'--upload-pack=x': [URL]}, {'origin': [URL], 'up\u0441tream': [URL]}, {}):
            step = self.run_remove(self.stale(urls=urls))['next']
            self.assertIn('fetch --prune --all', step, urls)
            for name in urls:
                self.assertNotIn(name, step, urls)

    def test_no_next_step_for_other_refusals_or_for_values_that_are_not_plain(self):
        self.assertNotIn('next', self.run_remove(self.stale(reason='the working tree is not clean')))
        self.assertNotIn('next', self.run_remove(self.stale(repo='/home/u/$(id)')))
        self.assertNotIn('next', self.run_remove(self.stale(repo='/home/u/../etc')))


class WorkStateWording(Home):
    """H6: durable work state keeps its refusal but not the log wording; logs keep both (must-fail controls)."""

    def test_moving_or_deleting_a_work_file_is_refused_with_the_tmp_folder_advice(self):
        (self.work / 'spec.tmp').write_text('x\n')
        (self.work / 'T').mkdir()
        (self.work / 'T/packet.md').write_text('x\n')
        for command in ('mv %s %s' % (self.work / 'spec.tmp', self.home / 'elsewhere.md'),
                        'rm %s' % (self.work / 'spec.tmp'),
                        'mv %s %s' % (self.work / 'T/packet.md', self.work / 'T/p2.md')):
            message = self.blocked(command)
            self.assertIn('It is not a log', message, command)
            self.assertIn('/<task>/tmp/', message, command)
            self.assertNotIn('back up to Dropbox', message, command)
            self.assertNotIn(LOG_WORDING, message, command)

    def test_the_task_tmp_folder_stays_movable(self):
        (self.work / 'T/tmp').mkdir(parents=True)
        (self.work / 'T/tmp/spec.tmp').write_text('x\n')
        self.assertEqual(self.decide('mv %s %s' % (self.work / 'T/tmp/spec.tmp', self.work / 'T/spec.md'))[0], 'allow')

    def test_a_directory_or_missing_path_keeps_the_log_wording(self):
        # #333 review F5: only one proven plain work file gets the "not a log" wording; a directory may hold WALs,
        # kits or *.jsonl files, and a path that does not exist (or a link) proves nothing
        (self.work / 'T/wal').mkdir(parents=True)
        (self.work / 'T/wal/main.jsonl').write_text('x\n')
        (self.work / 'U').mkdir()
        (self.work / 'U/notes.md').write_text('x\n')
        (self.work / 'U/kit.json').write_text('{}\n')
        (self.work / 'V').mkdir()
        (self.work / 'V/a.md').write_text('x\n')
        os.symlink(str(self.work / 'U/kit.json'), str(self.work / 'V/link.md'))
        for command in ('rm -r %s' % (self.work / 'T'), 'rm -rf %s' % (self.work / 'U'),
                        'mv %s %s' % (self.work / 'U', self.home / 'moved'), 'rm -r %s' % (self.work / 'V'),
                        'rm %s' % (self.work / 'V/link.md'), 'rm %s' % (self.work / 'V/missing.md')):
            message = self.blocked(command)
            self.assertNotIn('It is not a log', message, command)
            self.assertIn(LOG_WORDING, message, command)

    def test_logs_wals_transcripts_and_kits_keep_the_log_refusal(self):
        paths = [self.home / '.claude/wals/S/main.jsonl', self.home / '.claude/projects/p/S.jsonl',
                 self.work / 'T/wal/note.txt', self.work / 'T/run.wal.jsonl', self.work / 'T/kit.json',
                 self.work / 'T/notes.jsonl', self.work / 'T/state/x.json', self.home / '.agent-harness/state/a.json',
                 self.home / '.claude/agents/owner.md']
        for path in paths:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('x\n')
            for command in ('rm %s' % path, 'mv %s %s' % (path, self.home / 'moved')):
                message = self.blocked(command)
                self.assertIn(LOG_WORDING, message, command)
                self.assertNotIn('It is not a log', message, command)
            # truncation may meet a stronger rule first (transcript forgery); it is refused either way
            self.assertNotIn('It is not a log', self.blocked(': > %s' % path))


if __name__ == '__main__':
    unittest.main()
