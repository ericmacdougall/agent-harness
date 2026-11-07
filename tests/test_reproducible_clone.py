"""P12 gap 5 (goodqa#14817): deleting a reproducible git clone needs no Dropbox backup; everything else still does.

Real git repositories in a temporary HOME; the only fake is the network (cg.REMOTE_LS), which answers from a local
bare repository standing in for the hosting service. Every refusal case must stay a block.
Needs git. Run with the other suites on dev2/T2.
"""
import os
import shutil
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

GIT_ENV = {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}
GIT_ENV.update(GIT_CONFIG_GLOBAL='/dev/null', GIT_CONFIG_NOSYSTEM='1', GIT_AUTHOR_NAME='t', GIT_AUTHOR_EMAIL='t@x',
               GIT_COMMITTER_NAME='t', GIT_COMMITTER_EMAIL='t@x')
URL = 'https://github.com/acme/widgets.git'


def git(cwd, *args, check=True):
    done = subprocess.run(['git', *args], cwd=str(cwd), env=GIT_ENV, capture_output=True, text=True)
    if check and done.returncode:
        raise AssertionError('git %s: %s' % (' '.join(args), done.stderr))
    return done.stdout.strip()


class CloneCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory(prefix='cg-clone-')
        cls.home = Path(os.path.realpath(cls._tmp.name))
        cls._old_home = os.environ.get('HOME')
        os.environ['HOME'] = str(cls.home)
        cls.policy = cg.load_policy(path=str(cls.home / 'no-such-policy.json'))

    @classmethod
    def tearDownClass(cls):
        if cls._old_home is not None:
            os.environ['HOME'] = cls._old_home
        cls._tmp.cleanup()

    def setUp(self):
        self.n = getattr(CloneCase, '_n', 0) + 1
        CloneCase._n = self.n
        self.base = self.home / '.agent-harness' / 'work' / 'S2' / ('T%d' % self.n)
        self.base.mkdir(parents=True)
        # the "hosting service": a bare repo with one pushed commit
        self.origin = self.home / ('origin%d.git' % self.n)
        seed = self.home / ('seed%d' % self.n)
        seed.mkdir()
        git(seed, 'init', '-q', '-b', 'main')
        (seed / 'a.txt').write_text('one\n')
        git(seed, 'add', '.')
        git(seed, 'commit', '-q', '-m', 'one')
        git(self.home, 'clone', '-q', '--bare', str(seed), str(self.origin))
        self.clone = self.base / 'clone'
        git(self.home, 'clone', '-q', str(self.origin), str(self.clone))
        git(self.clone, 'remote', 'set-url', 'origin', URL)  # what a GitHub clone looks like
        self.live = {}
        self.refresh_live()
        patch = mock.patch.object(cg, 'REMOTE_LS', lambda url, cwd, timeout: dict(self.live))
        patch.start()
        self.addCleanup(patch.stop)

    def refresh_live(self):
        out = git(self.origin, 'for-each-ref', '--format=%(refname) %(objectname)')
        self.live = dict(line.split(' ') for line in out.splitlines())

    def verdict(self, command, cwd=None):
        compiled = cg.Compiled(self.policy, home=str(self.home), cwd=cwd or str(self.home))
        return cg.decide(command, compiled, cwd=cwd or str(self.home))

    def rm(self, path=None, flags='-rf'):
        return self.verdict('rm %s %s' % (flags, path or self.clone))

    def assertAllowed(self, result):
        self.assertEqual(result[0], 'allow', result)

    def assertRefused(self, result, mention=None):
        self.assertEqual(result[0], 'block', result)
        if mention:
            self.assertIn(mention, result[1])


class Allowed(CloneCase):
    def test_clean_fully_pushed_clone_is_deletable(self):
        self.assertAllowed(self.rm())
        self.assertAllowed(self.rm(str(self.clone) + '/'))
        self.assertAllowed(self.verdict('rm -rf %s' % self.clone, cwd=str(self.base)))

    def test_regenerable_ignored_dirs_do_not_matter(self):
        (self.clone / '.gitignore').write_text('node_modules/\n__pycache__/\n')
        git(self.clone, 'add', '.gitignore')
        git(self.clone, 'commit', '-q', '-m', 'ignore')
        git(self.clone, 'push', '-q', 'origin', 'HEAD:main', check=False)  # local bare origin was replaced by the URL
        git(self.origin, 'fetch', '-q', str(self.clone), 'main:main', '--update-head-ok', check=False)
        git(self.clone, 'update-ref', 'refs/remotes/origin/main', 'HEAD')
        self.live['refs/heads/main'] = git(self.clone, 'rev-parse', 'HEAD')
        (self.clone / 'node_modules').mkdir()
        (self.clone / 'node_modules' / 'x.js').write_text('1')
        (self.clone / '__pycache__').mkdir()
        (self.clone / '__pycache__' / 'a.pyc').write_text('1')
        self.assertAllowed(self.rm())


class MustRefuse(CloneCase):
    """Every row keeps the existing refusal: back up to Dropbox and approve-delete first."""

    def test_unpushed_commit(self):
        (self.clone / 'b.txt').write_text('two\n')
        git(self.clone, 'add', '.')
        git(self.clone, 'commit', '-q', '-m', 'local only')
        self.assertRefused(self.rm())

    def test_untracked_file(self):
        (self.clone / 'notes.txt').write_text('mine\n')
        self.assertRefused(self.rm())

    def test_modified_and_staged_tracked_files(self):
        (self.clone / 'a.txt').write_text('changed\n')
        self.assertRefused(self.rm())
        git(self.clone, 'add', 'a.txt')
        self.assertRefused(self.rm())

    def test_ignored_file_outside_the_regenerable_list(self):
        (self.clone / '.git' / 'info' / 'exclude').write_text('.env\nsecrets.txt\n')
        (self.clone / 'secrets.txt').write_text('token\n')
        self.assertRefused(self.rm())

    def test_symlinked_path_components(self):
        link = self.base / 'link'
        os.symlink(self.clone, link)
        self.assertRefused(self.rm(link))
        self.assertRefused(self.rm(str(link) + '/'))
        outside = self.home / 'elsewhere'
        outside.mkdir()
        os.symlink(outside, self.base / 'hop')
        self.assertRefused(self.verdict('rm -rf %s/hop/../T%d/clone' % (self.base, self.n)))

    def test_a_symlinked_clone_is_not_judged_as_one(self):
        other = self.home / ('realclone%d' % self.n)
        git(self.home, 'clone', '-q', str(self.origin), str(other))
        git(other, 'remote', 'set-url', 'origin', URL)
        link = self.base / 'viaLink'
        os.symlink(other, link)
        self.assertIn('symlink', cg.reproducible_clone_refusal(str(link), self.policy))
        self.assertIn('symlink', cg.reproducible_clone_refusal(str(self.base / 'x' / '..' / 'clone'), self.policy))

    def test_dot_git_must_be_a_real_directory(self):
        wt = self.base / 'linked'
        git(self.clone, 'worktree', 'add', '-q', '-b', 'side', str(wt))
        self.assertRefused(self.rm(wt))  # .git is a file here
        self.assertRefused(self.rm())  # the main clone now owns a linked worktree

    def test_forged_tracking_ref(self):
        (self.clone / 'b.txt').write_text('two\n')
        git(self.clone, 'add', '.')
        git(self.clone, 'commit', '-q', '-m', 'local only')
        git(self.clone, 'update-ref', 'refs/remotes/origin/main', 'HEAD')  # looks pushed, was never pushed
        self.assertRefused(self.rm())

    def test_remote_that_is_a_local_path_or_file_url(self):
        for url in (str(self.origin), 'file://' + str(self.origin), '../' + self.origin.name, 'ext::sh -c x'):
            git(self.clone, 'remote', 'set-url', 'origin', url)
            self.assertRefused(self.rm(), 'remote')

    def test_no_remote_at_all(self):
        git(self.clone, 'remote', 'remove', 'origin')
        self.assertRefused(self.rm())

    def test_stash(self):
        (self.clone / 'a.txt').write_text('wip\n')
        git(self.clone, 'stash', '-q')
        self.assertRefused(self.rm())

    def test_detached_head_on_unpushed_commit(self):
        git(self.clone, 'checkout', '-q', '--detach')
        (self.clone / 'b.txt').write_text('x\n')
        git(self.clone, 'add', '.')
        git(self.clone, 'commit', '-q', '-m', 'detached')
        self.assertRefused(self.rm())

    def test_local_tag_on_unpushed_commit(self):
        (self.clone / 'b.txt').write_text('x\n')
        git(self.clone, 'add', '.')
        git(self.clone, 'commit', '-q', '-m', 'tagged')
        git(self.clone, 'tag', 'v-local')
        git(self.clone, 'reset', '-q', '--hard', 'HEAD~1')
        self.assertRefused(self.rm())

    def test_remote_unreachable_or_slow_fails_closed(self):
        def boom(url, cwd, timeout):
            raise TimeoutError('network')
        with mock.patch.object(cg, 'REMOTE_LS', boom):
            self.assertRefused(self.rm())
        with mock.patch.object(cg, 'REMOTE_LS', lambda url, cwd, timeout: None):
            self.assertRefused(self.rm())

    def test_remote_moved_on_since_the_last_fetch_needs_a_fetch_first(self):
        self.live['refs/heads/main'] = '0' * 40
        self.assertRefused(self.rm(), 'fetch')

    def test_hostile_repository_config_never_runs_and_refuses(self):
        marker = self.home / ('PWNED%d' % self.n)
        script = self.home / ('hook%d.sh' % self.n)
        script.write_text('#!/bin/sh\ntouch %s\ncat\n' % marker)
        script.chmod(0o755)
        with open(self.clone / '.git' / 'config', 'a') as handle:
            handle.write('[core]\n\tfsmonitor = %s\n[filter "x"]\n\tclean = %s\n[core]\n\tsshCommand = %s\n' % (script, script, script))
        (self.clone / '.gitattributes').write_text('* filter=x\n')
        self.assertRefused(self.rm())
        self.assertFalse(marker.exists(), 'repository config executed code during the check')

    def test_submodule_marker(self):
        (self.clone / '.gitmodules').write_text('[submodule "s"]\n\tpath = s\n\turl = https://github.com/acme/s.git\n')
        git(self.clone, 'add', '.gitmodules')
        git(self.clone, 'commit', '-q', '-m', 'sub')
        self.assertRefused(self.rm())

    def test_only_the_clone_top_level_not_a_parent_or_a_subpath(self):
        self.assertRefused(self.verdict('rm -rf %s' % self.base))
        self.assertRefused(self.rm(self.clone / 'a.txt', flags='-f'))
        self.assertRefused(self.verdict('rm -rf %s/*' % self.base))
        self.assertRefused(self.verdict('rm -rf %s/clone/.git' % self.base))

    def test_dynamic_paths_stay_refused(self):
        self.assertRefused(self.verdict('rm -rf $(echo %s)' % self.clone))
        self.assertRefused(self.verdict('rm -rf %s/cl*' % self.base))

    def test_moves_and_truncation_are_not_deletes(self):
        self.assertRefused(self.verdict('mv %s %s/gone' % (self.clone, self.home)))

    def test_protected_log_tiers_are_never_exempt(self):
        logs = self.home / '.claude' / 'projects' / 'p'
        logs.mkdir(parents=True)
        git(logs, 'init', '-q')
        self.assertRefused(self.verdict('rm -rf %s' % logs))

    def test_exemption_can_be_switched_off_by_policy(self):
        policy = cg.load_policy(path=str(self.home / 'no-such-policy.json'))
        policy['reproducible_clone'] = dict(policy['reproducible_clone'], enabled=False)
        compiled = cg.Compiled(policy, home=str(self.home), cwd=str(self.home))
        self.assertRefused(cg.decide('rm -rf %s' % self.clone, compiled, cwd=str(self.home)))


class RedTeamRound(CloneCase):
    """Each row reproduced against the first version of the exemption (red-team and review of #14817)."""

    def run_marker_script(self):
        marker = self.home / ('PWNED%d' % self.n)
        script = self.home / ('run%d.sh' % self.n)
        script.write_text('#!/bin/sh\ntouch %s\ncat\n' % marker)
        script.chmod(0o755)
        return marker, script

    def test_byte_order_mark_and_include_cannot_smuggle_a_program(self):
        marker, script = self.run_marker_script()
        extra = self.home / ('extra%d.cfg' % self.n)
        extra.write_text('[filter "x"]\n\tclean = %s\n[core]\n\tsshCommand = %s\n' % (script, script))
        config = self.clone / '.git' / 'config'
        config.write_bytes(b'\xef\xbb\xbf' + ('[include]\n\tpath = %s\n' % extra).encode() + config.read_bytes())
        (self.clone / '.git' / 'info').mkdir(exist_ok=True)
        (self.clone / '.git' / 'info' / 'attributes').write_text('* filter=x\n')
        self.assertRefused(self.rm(), 'include')
        self.assertFalse(marker.exists(), 'git ran a program named by an included config')

    def test_hidden_modifications_are_refused(self):
        for flag in ('--assume-unchanged', '--skip-worktree'):
            (self.clone / 'a.txt').write_text('secret edit %s\n' % flag)
            git(self.clone, 'update-index', flag, 'a.txt')
            self.assertRefused(self.rm(), 'hidden')
            git(self.clone, 'update-index', flag.replace('--', '--no-'), 'a.txt')
            git(self.clone, 'checkout', '--', 'a.txt')

    def test_remotes_that_loop_back_or_are_odd_are_not_a_backup(self):
        for url in ('ssh://eric@localhost%s' % self.clone, 'ssh://u@127.0.0.1/x', 'x@127.0.0.1.nip.io:y',
                    'u@localhost.localdomain:y', 'https://github.com.evil.example/a/b.git', 'host.example.com::x',
                    'https://example.com/a/b.git', 'git@github.com.attacker.net:a/b.git'):
            git(self.clone, 'remote', 'set-url', 'origin', url)
            self.assertRefused(self.rm(), 'known hosting')

    def test_the_real_remote_lookup_refuses_local_transports(self):
        for url in (str(self.origin), 'file://' + str(self.origin), 'ext::sh -c true'):
            with self.assertRaises(Exception):
                cg._live_remote_refs(url, str(self.clone), 3)

    def test_nothing_may_change_the_clone_between_the_check_and_the_delete(self):
        base = str(self.base)
        self.assertRefused(self.verdict('echo precious > %s/clone/new.txt && rm -rf %s/clone' % (base, base)))
        self.assertRefused(self.verdict('git -C %s/clone commit --allow-empty -m x && rm -rf %s/clone' % (base, base)))
        self.assertRefused(self.verdict('rm -rf %s/clone; echo done' % base))
        self.assertRefused(self.verdict('cd %s && rm -rf clone' % base))

    def test_cdpath_cannot_redirect_the_delete(self):
        other = self.home / ('other%d' % self.n)
        (other / 'x' / 'clone').mkdir(parents=True)
        (self.base / 'x').mkdir()
        shutil.copytree(self.clone, self.base / 'x' / 'clone', symlinks=True)
        self.assertRefused(self.verdict('CDPATH=%s cd x && rm -rf clone' % other, cwd=str(self.base)))
        self.assertRefused(self.verdict('export CDPATH=%s; cd x && rm -rf clone' % other, cwd=str(self.base)))

    def test_ignored_content_must_be_a_whole_build_directory(self):
        (self.clone / 'notes' / 'build').mkdir(parents=True)
        (self.clone / 'notes' / 'keep.md').write_text('tracked\n')
        git(self.clone, 'add', 'notes/keep.md')
        git(self.clone, 'commit', '-q', '-m', 'notes')
        git(self.clone, 'update-ref', 'refs/remotes/origin/main', 'HEAD')
        self.live['refs/heads/main'] = git(self.clone, 'rev-parse', 'HEAD')
        (self.clone / '.git' / 'info' / 'exclude').write_text('notes/build/thesis.md\nbuild\nnode_modules/\n')
        (self.clone / 'notes' / 'build' / 'thesis.md').write_text('unique\n')
        self.assertRefused(self.rm(), 'ignored')  # a file under a folder that happens to be named build
        (self.clone / 'notes' / 'build' / 'thesis.md').unlink()
        (self.clone / 'build').write_text('unique content in a file named build\n')
        self.assertRefused(self.rm(), 'ignored')
        (self.clone / 'build').unlink()
        nested = self.clone / 'node_modules' / 'dep'
        nested.mkdir(parents=True)
        git(nested, 'init', '-q')
        self.assertRefused(self.rm(), 'nested')

    def test_commits_only_in_the_reflog_and_hand_written_hooks_are_local_work(self):
        (self.clone / 'b.txt').write_text('x\n')
        git(self.clone, 'add', '.')
        git(self.clone, 'commit', '-q', '-m', 'orphaned')
        git(self.clone, 'reset', '-q', '--hard', 'HEAD~1')
        self.assertRefused(self.rm(), 'not on the remote')
        git(self.clone, 'reflog', 'expire', '--expire=now', '--all')
        hook = self.clone / '.git' / 'hooks' / 'pre-push'
        hook.write_text('#!/bin/sh\nexit 0\n')
        self.assertRefused(self.rm(), 'hooks')
        hook.unlink()
        self.assertRefused(self.rm(), 'not on the remote')  # ORIG_HEAD still names the orphaned commit
        (self.clone / '.git' / 'ORIG_HEAD').unlink()
        self.assertAllowed(self.rm())  # control: the same clone is deletable once both are gone


class NoContactWithOddHosts(CloneCase):
    def test_a_remote_outside_the_allowlist_is_refused_without_being_contacted(self):
        called = []
        with mock.patch.object(cg, 'REMOTE_LS', lambda url, cwd, timeout: called.append(url) or dict(self.live)):
            for url in ('https://evil.example/a/b.git', 'ssh://u@10.0.0.5/x', 'git@gitlab.com.evil.example:a/b.git'):
                git(self.clone, 'remote', 'set-url', 'origin', url)
                self.assertRefused(self.rm(), 'known hosting')
        self.assertEqual(called, [], 'the guard contacted a host that is not on the hosting allowlist')


class RoundThree(CloneCase):
    def test_bare_repository_inside_a_build_directory(self):
        (self.clone / '.git' / 'info' / 'exclude').write_text('build/\n')
        (self.clone / 'build').mkdir()
        git(self.clone / 'build', 'init', '-q', '--bare', 'mine.git')
        self.assertRefused(self.rm(), 'nested')

    def test_a_huge_build_directory_is_refused_with_an_honest_reason_and_a_big_one_passes(self):
        (self.clone / '.git' / 'info' / 'exclude').write_text('build/\n')
        deep = self.clone / 'build' / 'debug' / 'deps'
        deep.mkdir(parents=True)
        for i in range(30):
            (deep / ('f%d.o' % i)).write_text('x')
        self.assertAllowed(self.rm())  # plenty of files, no repository
        self.assertEqual(cg._nested_repo(str(self.clone / 'build'), limit=10, deep=True), 'large')
        self.assertFalse(cg._nested_repo(str(self.clone / 'build'), deep=True))


class RoundTwo(CloneCase):
    """Second red-team round (head 0c9592c): each row was allowed by that head."""

    def test_embedded_repository_added_without_gitmodules(self):
        sub = self.clone / 'sub'
        sub.mkdir()
        git(sub, 'init', '-q', '-b', 'main')
        (sub / 'f.txt').write_text('only here\n')
        git(sub, 'add', '.')
        git(sub, 'commit', '-q', '-m', 'inner')
        git(self.clone, 'add', 'sub')
        git(self.clone, 'commit', '-q', '-m', 'embed')
        git(self.clone, 'update-ref', 'refs/remotes/origin/main', 'HEAD')
        self.live['refs/heads/main'] = git(self.clone, 'rev-parse', 'HEAD')
        self.assertRefused(self.rm(), 'embedded')

    def test_control_characters_are_not_word_separators(self):
        for ch in ('\x0b', '\x0c', '\r'):
            self.assertRefused(self.verdict('rm -rf %s%s' % (self.clone, ch)))
            self.assertRefused(self.verdict('rm -rf %s %s' % (self.clone, ch)))
        self.assertAllowed(self.verdict('rm\t-rf  %s' % self.clone))  # ordinary blanks still work
        self.assertAllowed(self.verdict('rm -rf -- %s/' % self.clone))

    def test_stat_trust_settings_that_hide_same_size_edits(self):
        for key, value in (('core.trustctime', 'false'), ('core.checkStat', 'minimal'), ('core.ignoreStat', 'true')):
            git(self.clone, 'config', key, value)
            self.assertRefused(self.rm(), key.split('.')[1].lower())
            git(self.clone, 'config', '--unset', key)
        git(self.clone, 'config', 'core.logAllRefUpdates', 'false')
        self.assertRefused(self.rm(), 'reflog')

    def test_a_relative_path_entry_cannot_supply_the_program_git_runs(self):
        env = cg._clone_env()
        self.assertTrue(all(p.startswith('/') for p in env['PATH'].split(os.pathsep)))
        with mock.patch.dict(os.environ, {'PATH': 'node_modules/.bin:.::/usr/bin'}):
            self.assertEqual(cg._clone_env()['PATH'], '/usr/bin')

    def test_nested_repository_deep_inside_a_top_level_build_dir(self):
        (self.clone / '.git' / 'info' / 'exclude').write_text('build/\n')
        deep = self.clone / 'build' / 'a' / 'b'
        deep.mkdir(parents=True)
        git(deep, 'init', '-q')
        self.assertRefused(self.rm(), 'nested')





if __name__ == '__main__':
    unittest.main()
