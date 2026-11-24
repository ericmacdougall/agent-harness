"""goodqa#16943: guard refusals name the sanctioned route instead of the log-backup procedure.

H7: every refused `git worktree remove` (a compound line, --force, an ssh payload, a container) names the
`ah worktree-remove` route as CONSTANT text with placeholders, and a stale-tracking-ref refusal names a constant
`git fetch --prune <the remote that holds the deleted branch>` step that states when pruning is safe. The route advice
fills in no path, host or remote of its own: review rounds of PR 333 showed that any value the guard resolves can differ
from what the kernel or git resolves. The verifier reason printed before the advice is the verifier's own text, unchanged
by this ticket, and may name a remote or ignored files of the worktree (asserted below). Every refusal stays a refusal.
Real temporary repositories under a temporary HOME, fake network and ssh only; commands are data passed to decide()."""

import json
import os
from pathlib import Path
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
# the fixed advice, spelled out here so a change to it is a visible test change (byte-stable)
ROUTE = ('python3 -I ~/.claude/hooks/ah.py worktree-remove --host <local|%s> --path <absolute path of the worktree> '
         '--reason "<why>" [--remote-auth] (one worktree per call, no --force, audited; add --remote-auth when the '
         'repository is private, so the host reads its remote with its own credentials)' % REMOTE)
SAFE_PRUNE = ('but only when every fetch refspec of that remote writes under refs/remotes/<that remote>/ and pruneTags is '
              'not set; prune deletes local branches or tags through any other destination (for example +refs/*:refs/* '
              'or +refs/heads/*:refs/heads/up/*)')
PRUNE = ('run `git fetch --prune <the remote that holds the deleted branch>` in the registry repository (the checkout '
         'the worktree was added from) first, ' + SAFE_PRUNE)
NEXT_STALE = ('run `git fetch --prune <the remote that holds the deleted branch>` in the registry repository (the '
              'checkout the worktree was added from) on the same host first, ' + SAFE_PRUNE +
              '. Then repeat the same ah worktree-remove call')


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


class FixedText(unittest.TestCase):
    """The advice is byte-stable: fixed text, placeholders only."""

    def test_the_route_and_prune_texts_are_fixed(self):
        self.assertEqual(getattr(cg, 'WORKTREE_ROUTE', None), ROUTE)
        self.assertEqual(getattr(cg, 'WORKTREE_PRUNE_STEP', None), PRUNE)
        self.assertEqual(getattr(ah_worktree, 'NEXT_STALE', None), NEXT_STALE)
        self.assertNotIn('--all', PRUNE + NEXT_STALE)

    def test_the_route_hosts_agree_with_ah_worktree(self):
        self.assertEqual(tuple(cg.WORKTREE_ROUTE_HOSTS), tuple(ah_worktree.REMOTE_HOSTS))


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
        # a symlinked parent: <work>/S/T/ln -> <work>/S/Q/sub, so ln/../linked is <work>/S/Q/linked to the kernel
        (self.work / 'Q/sub').mkdir(parents=True)
        os.symlink(str(self.work / 'Q/sub'), str(self.work / 'T/ln'))

    def assert_no_concrete_value(self, message, command):
        """No path segment, host or remote of the command or the fixture appears in the advice."""
        self.assertIn(ROUTE, message, command)
        # only the route text is removed: the prune step is searched too, so a value it gained would be caught
        advice = message.split('Safe alternative:', 1)[-1].replace(ROUTE, '')
        for value in (str(self.home), str(self.work), 'linked', 'primary', '/srv', '/home/u', 'build-box-9', 'upstream',
                      '--host local', '--host ' + REMOTE + ' ', 'fetch --prune origin', 'fetch --prune --all'):
            self.assertNotIn(value, advice, (command, value))

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

    def test_every_refused_shape_names_the_route_in_fixed_text_and_no_value_of_the_command(self):
        # round 1 and round 2 reviewer examples, and the shapes the route was first built for
        T = self.work / 'T'
        for command in ('cd %s && git worktree remove --force %s' % (self.primary, self.linked),
                        'git worktree remove %s && echo done' % self.linked,
                        'git worktree remove --force ../linked',
                        'cd "$OTHER" && git worktree remove --force ../linked',
                        'cd - && git worktree remove --force ../linked',
                        'pushd /var && popd; git worktree remove --force ../linked',
                        'git -C %s worktree remove --force ../linked' % self.linked,
                        'W=%s; git worktree remove --force $W/linked' % T,
                        'git worktree remove --force %s/lin*' % T,
                        'git worktree remove --force %s/ln/../linked' % T,
                        'cd %s/ln && git worktree remove --force ../linked' % T,
                        'cd -P %s/ln/.. && git worktree remove --force linked' % T,
                        "ssh %s 'git -C /home/u/repo worktree remove /home/u/scratch/wt'" % REMOTE,
                        "ssh %s 'git worktree remove ~/scratch/wt'" % REMOTE,
                        'ssh %s "git worktree remove \\$HOME/scratch/wt"' % REMOTE,
                        "ssh %s 'W=/home/u/x; git worktree remove $W/wt'" % REMOTE,
                        "ssh %s 'git worktree remove \"/home/u/x;rm -rf ~\"'" % REMOTE,
                        "ssh %s 'git worktree remove \"/home/u/$(id)/wt\"'" % REMOTE,
                        "ssh user@build-box-9 'git worktree remove /home/u/wt'",
                        'docker exec box git worktree remove --force /srv/wt',
                        'podman exec -u u box git worktree remove --force /srv/wt',
                        'chroot /srv git worktree remove --force /wt',
                        'nsenter -t 1 -m git worktree remove --force /srv/wt',
                        'unshare -m git worktree remove --force /srv/wt'):
            message = self.blocked(command, self.primary)
            self.assert_no_concrete_value(message, command)
            self.assertNotIn('back up to Dropbox', message, command)

    def test_a_stale_tracking_ref_refusal_names_the_fixed_prune_step_then_the_route(self):
        self.stale_ref()
        message = self.blocked('git worktree remove ' + str(self.linked), self.primary)
        self.assertIn(PRUNE, message)
        self.assertLess(message.index(PRUNE), message.index(ROUTE))
        self.assert_no_concrete_value(message, 'stale')

    def test_a_stale_ref_under_a_mirror_remote_gets_no_command_that_could_prune_local_work(self):
        # round 2 F2: --all (or a guessed remote) with a mirror-style refspec or pruneTags deletes local branches or tags
        git(self.primary, 'remote', 'add', '--mirror=fetch', 'upstream', URL)
        git(self.primary, 'branch', 'local-only')
        git(self.primary, 'update-ref', 'refs/remotes/upstream/gone', self.head)
        self.stale_ref()
        message = self.blocked('git worktree remove ' + str(self.linked), self.primary)
        self.assertIn('every fetch refspec of that remote writes under refs/remotes/<that remote>/', message)
        self.assert_no_concrete_value(message, 'mirror')

    def assert_values_only_in_the_verifier_reason(self, reason, message, values):
        """The narrowed rule (round 3 F2): the verifier's own reason is printed unchanged and may name repository
        values; the advice after it is constant text and names none of them."""
        for value in values:
            self.assertIn(value, reason, value)
        shown = 'verifier: %s. ' % cg._clean_reason(reason)
        self.assertIn(shown, message)
        self.assertEqual(cg._worktree_instead(reason),
                         shown + (cg._worktree_next_step(reason) + '; then ' if cg._worktree_next_step(reason) else '')
                         + ROUTE)
        rest = message.replace(shown, '')
        for value in values:
            self.assertNotIn(value, rest, value)

    def test_a_remote_off_the_known_hosts_is_named_only_by_the_verifier_reason(self):
        git(self.primary, 'remote', 'add', 'evil-remote', 'https://git.example.invalid/x.git')
        reason = cg.linked_worktree_remove_refusal(str(self.linked), str(self.primary), self.policy)
        self.assertIn('not on a known hosting service', reason)
        message = self.blocked('git worktree remove ' + str(self.linked), self.primary)
        self.assert_values_only_in_the_verifier_reason(reason, message, ['evil-remote'])

    def test_an_ignored_file_is_named_only_by_the_verifier_reason(self):
        (self.linked / '.gitignore').write_text('.env\n')
        git(self.linked, 'add', '.gitignore')
        git(self.linked, 'commit', '-q', '-m', 'ignore')
        head = git(self.linked, 'rev-parse', 'HEAD')
        git(self.primary, 'update-ref', 'refs/remotes/origin/linked', head)
        self.live['refs/heads/linked'] = head
        (self.linked / '.env').write_text('X=1\n')
        reason = cg.linked_worktree_remove_refusal(str(self.linked), str(self.primary), self.policy)
        self.assertIn('ignored file', reason)
        message = self.blocked('git worktree remove ' + str(self.linked), self.primary)
        self.assert_values_only_in_the_verifier_reason(reason, message, ['.env'])

    def test_the_route_shape_with_its_placeholders_filled_is_allowed_by_the_guard(self):
        filled = (ROUTE.split(' (one worktree')[0].replace('<local|%s>' % REMOTE, 'local')
                  .replace('<absolute path of the worktree>', str(self.linked)).replace('<why>', 'merged and published')
                  .replace(' [--remote-auth]', ''))
        self.assertEqual(self.decide(filled, self.primary)[0], 'allow', filled)
        self.assertEqual(self.decide(filled + ' --remote-auth', self.primary)[0], 'allow', filled)
        self.assertEqual(self.decide('git fetch --prune origin', self.primary)[0], 'allow')


class StaleRefNextStep(unittest.TestCase):
    """The delegated route keeps its stale-ref rule; its answer names the fixed next step."""

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
                'repo': '/home/u/repos/base', 'urls': {'origin': [URL], 'upstream': [URL]}}
        base.update(kw)
        return base

    def test_a_stale_ref_refusal_gives_the_fixed_next_step_on_both_hosts(self):
        for host in (REMOTE, 'local'):
            result = self.run_remove(self.stale(), host=host, authenticated=True)
            self.assertFalse(result['removed'])
            self.assertEqual(result['next'], NEXT_STALE)
            for value in ('/home/u', 'origin', 'upstream', '--all', 'ssh '):
                self.assertNotIn(value, result['next'], (host, value))

    def test_no_next_step_for_other_refusals(self):
        self.assertNotIn('next', self.run_remove(self.stale(reason='the working tree is not clean')))


if __name__ == '__main__':
    unittest.main()
