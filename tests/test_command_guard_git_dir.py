"""goodqa#15565: command_guard refuses deleting a git directory or anything inside one.

Incident (dev2): a sweep agent's delete list held /home/eric/repos/bugtracker/.git and /home/eric/repos/harness/.git;
an `rm` run over ssh and fed from the list file through xargs deleted both, losing unpushed commits. The guard only
protected the harness trees (~/.claude, ~/.codex, ~/.agent-harness), so a `.git` anywhere else passed.

Every command here is DATA handed to command_guard.decide(); nothing is executed. Each test builds its own temporary
home with a real git repository and list files. CG_HOOKS_DIR points the suite at another implementation (for example
origin/main before this change) to show it failing first.
"""

import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
HOOKS = Path(os.environ.get('CG_HOOKS_DIR') or ROOT / 'harness/hooks')
sys.path.insert(0, str(HOOKS))

import command_guard as cg  # noqa: E402

GIT_ENV = {'GIT_AUTHOR_NAME': 't', 'GIT_AUTHOR_EMAIL': 't@example.invalid', 'GIT_COMMITTER_NAME': 't',
           'GIT_COMMITTER_EMAIL': 't@example.invalid', 'GIT_CONFIG_NOSYSTEM': '1'}


def run(*args, cwd=None):
    env = dict(os.environ, **GIT_ENV)
    done = subprocess.run(list(args), cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if done.returncode != 0:
        raise AssertionError('%s failed: %s' % (args[:3], done.stderr.decode()[-300:]))
    return done.stdout.decode()


class GitDirCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory(prefix='cg-gitdir-')
        cls.home = Path(os.path.realpath(cls._tmp.name))
        cls._old_home = os.environ.get('HOME')
        os.environ['HOME'] = str(cls.home)
        h = cls.home
        for rel in ('.claude/projects/p/a.jsonl', '.claude/wals/s/main.jsonl', '.agent-harness/state/x.json'):
            (h / rel).parent.mkdir(parents=True, exist_ok=True)
            (h / rel).write_text('x\n')
        cls.repo = h / 'repos/proj'
        cls.repo.mkdir(parents=True)
        run('git', 'init', '-q', str(cls.repo))
        (cls.repo / 'a.txt').write_text('a\n')
        run('git', 'add', 'a.txt', cwd=str(cls.repo))
        run('git', 'commit', '-q', '-m', 'one', cwd=str(cls.repo))
        (cls.repo / 'node_modules/x').mkdir(parents=True)
        (cls.repo / 'foo.txt').write_text('f\n')
        (cls.repo / '.github/workflows').mkdir(parents=True)
        (cls.repo / '.github/workflows/a.yml').write_text('on: push\n')
        cls.bare = h / 'srv/bare-repo'  # a bare repository whose name does not end in .git: judged by content
        run('git', 'init', '-q', '--bare', str(cls.bare))
        lists = h / 'lists'
        lists.mkdir()
        cls.sweep = lists / 'sweep.txt'
        cls.sweep.write_text('%s/junk/a.log\n%s/.git\n' % (h, cls.repo))
        cls.ok = lists / 'ok.txt'
        cls.ok.write_text('%s/junk/a.log\n%s/node_modules\n%s/foo.txt\n' % (h, cls.repo, cls.repo))
        cls.policy = cg.load_policy(path=str(h / 'no-such-policy.json'))

    @classmethod
    def tearDownClass(cls):
        if cls._old_home is None:
            os.environ.pop('HOME', None)
        else:
            os.environ['HOME'] = cls._old_home
        cls._tmp.cleanup()

    def fill(self, text):
        return (text.replace('@REPO@', str(self.repo)).replace('@SWEEP@', str(self.sweep))
                .replace('@OK@', str(self.ok)).replace('@BARE@', str(self.bare)).replace('@HOME@', str(self.home)))

    def decide(self, command, cwd='@REPO@', marker=None):
        cwd = self.fill(cwd)
        compiled = cg.Compiled(self.policy, home=str(self.home), cwd=cwd)
        return cg.decide(self.fill(command), compiled, cwd=cwd, marker=marker)

    def expect(self, rows, want, cwd='@REPO@', marker=None):
        wrong = []
        for row in rows:
            verdict, message = self.decide(row, cwd=cwd, marker=marker)
            # a block must come from this rule, not from an unrelated one (a parse failure, a harness-root rule)
            if verdict != want or (want == 'block' and 'git-dir-delete' not in message
                                   and 'git-clone-delete' not in message):
                wrong.append('%r -> %s %s' % (row, verdict, message.splitlines()[:1]))
        self.assertEqual(wrong, [], '%d of %d rows wrong:\n%s' % (len(wrong), len(rows), '\n'.join(wrong)))


class LocalDeleteTests(GitDirCase):
    def test_deleting_a_git_directory_blocks(self):
        self.expect([
            'rm -rf @REPO@/.git',
            'rm -rf .git',
            'rm -rf ./.git/',
            'rm -rf .GIT',
            'rm -r -f .git',
            'rmdir .git',
            '/bin/rm -rf @REPO@/.git',
            'sudo rm -rf @REPO@/.git',
            'rm -rf /home/eric/repos/bugtracker/.git /home/eric/repos/harness/.git',
            'rm -rf @REPO@/node_modules @REPO@/.git',
            'cd @REPO@ && rm -rf .git',
            'rm -rf .gi?',
            'rm -rf .g*',
            'mv .git /tmp/old-git',
            'bash -c "rm -rf @REPO@/.git"',
            'rm -rf {build,.git}',
            'D=@REPO@/.git; rm -rf "$D"',
            'rm -rf $(git rev-parse --git-dir)',
            'rm -rf "$(git rev-parse --absolute-git-dir)"',
            'rsync -a --delete empty/ @REPO@/.git/',
        ], 'block')

    def test_deleting_inside_a_git_directory_blocks(self):
        self.expect([
            'rm -rf @REPO@/.git/objects',
            'rm -rf .git/refs',
            'rm -f .git/refs/heads/main',
            'rm -rf repo/.git/refs/heads/x',
            'rm -f .git/HEAD',
            'rm -f .git/packed-refs',
            'rm -f .git/index',
            'rm -rf .git/worktrees',
            'unlink .git/config',
            'cd .git && rm -rf objects',
            'rm -rf .git/objects/*',
        ], 'block')

    def test_deleting_a_bare_or_separate_git_directory_blocks(self):
        self.expect(['rm -rf @BARE@', 'rm -rf @BARE@/objects'], 'block')

    def test_find_deleting_git_directories_blocks(self):
        self.expect([
            'find @HOME@/repos -name .git -exec rm -rf {} +',
            'find . -type d -name .git -prune -exec rm -rf {} \\;',
            "find . -path '*/.git/*' -delete",
            "find . -iname '.GIT' -exec rm -rf {} +",
            'find @HOME@/repos -name .git | xargs rm -rf',
        ], 'block')

    def test_transient_git_files_stay_deletable(self):
        # stale locks and per-operation scratch files: removing them is the documented recovery and loses no commit
        self.expect([
            'rm .git/index.lock',
            'rm -f .git/index.lock',
            'rm -f @REPO@/.git/index.lock',
            'rm -f .git/HEAD.lock',
            'rm -f .git/refs/heads/main.lock',
            'rm -f .git/COMMIT_EDITMSG',
            'rm -f .git/ORIG_HEAD .git/FETCH_HEAD',
            'rm -f .git/MERGE_HEAD .git/MERGE_MSG .git/MERGE_MODE',
        ], 'allow')

    def test_ordinary_deletes_stay_allowed(self):
        self.expect([
            'rm -rf node_modules',
            'rm foo.txt',
            'git gc',
            'git clean -n',
            'rm -rf @REPO@/.github/workflows/a.yml',
            'rm -rf .github',
            'rm -rf /x/not.git/y',
            'rm -f x.gitignore',
            'rm -f .gitignore .gitattributes .gitmodules',
            'rm -rf /x/.gitkeep',
            "find . -name '*.pyc' -delete",
            'find . -name node_modules -prune -exec rm -rf {} +',
            'cat .git/HEAD',
            'git status',
        ], 'allow')


class ApprovalTests(GitDirCase):
    class Verifier:
        def remote_types(self):
            return {'dropbox': 'dropbox'}

        def verify(self, local_root, manifest, remote):
            return cg.VerifyResult(True, checked=len(manifest))

    def setUp(self):
        self.target = self.home / ('repos/approved-%d' % time.monotonic_ns())
        self.target.mkdir(parents=True)
        run('git', 'init', '-q', str(self.target))
        (self.target / 'a').write_text('a\n')
        run('git', 'add', 'a', cwd=str(self.target))
        run('git', 'commit', '-q', '-m', 'a', cwd=str(self.target))
        past = time.time() - 3600
        for root, dirs, files in os.walk(str(self.target), topdown=False):
            for name in dirs + files:
                os.utime(os.path.join(root, name), (past, past), follow_symlinks=False)
        os.utime(str(self.target), (past, past))

    def approvals(self):
        return cg.Approvals(home=str(self.home), compiled=cg.Compiled(self.policy, home=str(self.home)))

    def test_verified_backup_approval_lets_the_exact_git_dir_go(self):
        gitdir = self.target / '.git'
        cg.approve_delete(str(gitdir), 'dropbox:backups/x', verifier=self.Verifier(), home=str(self.home),
                          policy=self.policy)
        cwd = str(self.target)
        self.assertEqual(self.decide('rm -rf %s' % gitdir, cwd=cwd, marker=self.approvals())[0], 'allow')
        self.assertEqual(self.decide('rm -rf .git', cwd=cwd, marker=self.approvals())[0], 'allow')
        # exact path only: a path inside it, a glob, or the same path on another host is not covered
        self.assertEqual(self.decide('rm -rf %s/objects' % gitdir, cwd=cwd, marker=self.approvals())[0], 'block')
        self.assertEqual(self.decide('rm -rf %s/.gi?' % self.target, cwd=cwd, marker=self.approvals())[0], 'block')
        self.assertEqual(self.decide("ssh dev2 'rm -rf %s'" % gitdir, cwd=cwd, marker=self.approvals())[0], 'block')

    def test_without_an_approval_the_same_command_blocks(self):
        self.assertEqual(self.decide('rm -rf %s/.git' % self.target, cwd=str(self.target),
                                     marker=self.approvals())[0], 'block')

    def test_injected_marker_is_consulted_for_the_real_path(self):
        seen = []

        def marker(path):
            seen.append(path)
            return path == str(self.target / '.git')
        self.assertEqual(self.decide('rm -rf .git', cwd=str(self.target), marker=marker)[0], 'allow')
        self.assertIn(str(self.target / '.git'), seen)


class RemoteDeleteTests(GitDirCase):
    def test_ssh_deletes_of_git_directories_block(self):
        self.expect([
            "ssh dev2 'rm -rf /home/eric/repos/x/.git'",
            'ssh dev2 rm -rf /home/eric/repos/x/.git',
            'ssh -p 22 eric@dev2 -- rm -rf /home/eric/repos/x/.git/objects',
            'ssh dev2 "cd /home/eric/repos/x && rm -rf .git"',
            "ssh dev2 'cd /home/eric/repos/x; rm -rf .git/refs'",
            "ssh dev2 \"bash -c 'rm -rf /home/eric/repos/x/.git'\"",
            "ssh dev2 python3 -c \"'import shutil; shutil.rmtree(\\\"/home/eric/repos/x/.git\\\")'\"",
        ], 'block')

    def test_ssh_delete_fed_from_a_local_list_reads_the_list(self):
        self.expect([
            'ssh dev2 xargs rm -rf < @SWEEP@',
            "ssh dev2 'xargs rm -rf' < @SWEEP@",
            'cat @SWEEP@ | ssh dev2 xargs rm -rf',
            "ssh dev2 'while read p; do rm -rf \"$p\"; done' < @SWEEP@",
            'ssh dev2 rm -rf $(cat @SWEEP@)',
        ], 'block')
        self.expect([
            'cat @OK@ | ssh dev2 xargs rm -f',
            'ssh dev2 rm -rf /home/eric/tmp/build',
            'ssh dev2 rm -rf /srv/app/node_modules',
        ], 'allow')
        # the whole-clone rule: a recursive delete of another host's directories cannot be walked from here, so a list
        # without .git entries still blocks when it names ordinary directories there
        self.expect(['ssh dev2 xargs rm -rf < @OK@'], 'block')

    def test_remote_list_files_cannot_be_read_so_they_block(self):
        self.expect([
            "ssh dev2 'xargs -a /home/eric/sweep.txt rm -rf'",
            "ssh dev2 'xargs rm -rf < /home/eric/sweep.txt'",
            "ssh dev2 'cat /home/eric/sweep.txt | xargs rm -rf'",
            "ssh dev2 'rm -rf $(cat /home/eric/sweep.txt)'",
            "ssh dev2 'while read p; do rm -rf \"$p\"; done < /home/eric/sweep.txt'",
        ], 'block')


class ListFedDeleteTests(GitDirCase):
    def test_list_files_naming_a_git_dir_block(self):
        self.expect([
            'xargs rm -rf < @SWEEP@',
            'xargs -a @SWEEP@ rm -rf',
            'xargs --arg-file=@SWEEP@ rm -rf',
            'xargs -I{} rm -rf {} < @SWEEP@',
            'cat @SWEEP@ | xargs rm -rf',
            'grep -v nothing @SWEEP@ | xargs rm -rf',
            'sort -u @SWEEP@ | xargs -n1 rm -rf',
            '< @SWEEP@ xargs rm -rf',
            'rm -rf $(cat @SWEEP@)',
            'rm -rf `cat @SWEEP@`',
            'rm -rf $(< @SWEEP@)',
            'while read p; do rm -rf "$p"; done < @SWEEP@',
            'while IFS= read -r p; do rm -rf -- "$p"; done < @SWEEP@',
            'cat @SWEEP@ | while read p; do rm -rf "$p"; done',
            'echo @REPO@/.git | xargs rm -rf',
            "printf '%s\\n' @REPO@/.git | xargs rm -rf",
            'xargs rm -rf <<< "@REPO@/.git"',
            'xargs rm -rf <<EOF\n@REPO@/.git\nEOF',
        ], 'block')

    def test_unverifiable_lists_fail_closed(self):
        self.expect([
            'xargs rm -rf < @HOME@/lists/missing.txt',
            'xargs -a @HOME@/lists/missing.txt rm -rf',
            'xargs -a "$LIST" rm -rf',
            'rm -rf $(cat "$LIST")',
            "sed 's/a.log/x/' @OK@ | xargs rm -rf",
            "awk '{print $1}' @OK@ | xargs rm -rf",
            'while read p; do rm -rf "$p"; done < "$LIST"',
            'xargs rm -rf < @HOME@/lists',
        ], 'block')

    def test_list_files_without_git_paths_stay_allowed(self):
        self.expect([
            'xargs rm -rf < @OK@',
            'xargs -a @OK@ rm -f',
            'cat @OK@ | xargs rm -f',
            'rm -rf $(cat @OK@)',
            'while read p; do rm -f "$p"; done < @OK@',
            'cat @SWEEP@ | wc -l',
            'xargs echo < @SWEEP@',
            'echo build | xargs rm -rf',
        ], 'allow')


class InterpreterTests(GitDirCase):
    def test_interpreter_deletes_naming_a_git_path_block(self):
        self.expect([
            "python3 -c \"import shutil; shutil.rmtree('/x/.git')\"",
            "python3 -c \"import shutil; shutil.rmtree('@REPO@/.git/objects')\"",
            "python3 -c \"import os; os.remove('/x/.git/HEAD')\"",
            "python3 -c \"import os; os.unlink('.git/config')\"",
            "python3 -c \"from pathlib import Path; Path('/x/.git/index').unlink()\"",
            "perl -e 'unlink \"/x/.git/config\"'",
            "node -e \"require('fs').rmSync('/x/.git', {recursive: true})\"",
            "node -e \"require('fs').unlinkSync('/x/.git/HEAD')\"",
            "ruby -e 'require \"fileutils\"; FileUtils.rm_rf(\"/x/.git\")'",
            "python3 - <<'PY'\nimport shutil\nshutil.rmtree('/home/eric/repos/x/.git')\nPY",
        ], 'block')

    def test_interpreter_reads_and_other_deletes_stay_allowed(self):
        self.expect([
            "python3 -c \"import shutil; shutil.rmtree('build')\"",
            "python3 -c \"print(open('.git/HEAD').read())\"",
            "python3 -c \"import os; os.remove('/x/.github/workflows/a.yml')\"",
            "python3 -c \"import os; os.remove('.git/index.lock')\"",
            "node -e \"require('fs').rmSync('dist', {recursive: true})\"",
        ], 'allow')


class CloneDeleteCase(unittest.TestCase):
    """goodqa#15565 follow-up (main's decision): deleting a directory that holds a git repository (a clone, a linked
    worktree, or an ancestor such as ~/repos) is refused unless every repository in it is provably pushed to a live
    allowlisted remote, or an approve-delete marker covers the exact path. A local bare repository stands in for the
    network remote through an injected ls-remote."""

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory(prefix='cg-clone-')
        cls.home = Path(os.path.realpath(cls._tmp.name))
        cls._old_home = os.environ.get('HOME')
        os.environ['HOME'] = str(cls.home)
        h = cls.home
        for rel in ('.claude/projects/p/a.jsonl', '.agent-harness/state/x.json'):
            (h / rel).parent.mkdir(parents=True, exist_ok=True)
            (h / rel).write_text('x\n')
        cls.clones = []
        cls.remote = h / 'remote/proj.git'
        run('git', 'init', '-q', '--bare', '-b', 'main', str(cls.remote))
        cls.url = 'https://github.com/acme/proj.git'
        repos = h / 'repos'
        cls.pushed = cls.clone(repos / 'pushed')
        cls.unpushed = cls.clone(repos / 'unpushed')
        cls.commit(cls.unpushed, 'local only')
        cls.stashed = cls.clone(repos / 'stashed')
        (cls.stashed / 'c-stashed.txt').write_text('changed\n')
        run('git', 'stash', '-q', cwd=str(cls.stashed))
        assert run('git', 'stash', 'list', cwd=str(cls.stashed)).strip()
        cls.detached = cls.clone(repos / 'detached')
        run('git', 'checkout', '-q', '--detach', cwd=str(cls.detached))
        cls.commit(cls.detached, 'detached work')
        cls.tagged = cls.clone(repos / 'tagged')
        cls.commit(cls.tagged, 'tagged only')
        run('git', 'tag', 'v-local', cwd=str(cls.tagged))
        run('git', 'reset', '-q', '--hard', 'HEAD~1', cwd=str(cls.tagged))
        cls.dirty = cls.clone(h / 'dirtyhold/dirty')
        (cls.dirty / 'notes.txt').write_text('uncommitted\n')
        cls.noremote = h / 'loose/noremote'
        run('git', 'init', '-q', '-b', 'main', str(cls.noremote))
        cls.commit(cls.noremote, 'no remote')
        cls.badhost = cls.clone(h / 'loose/badhost')
        run('git', 'remote', 'set-url', 'origin', 'https://evil.example/acme/proj.git', cwd=str(cls.badhost))
        cls.holder = h / 'holder'  # only pushed, clean repositories, one nested two levels down
        cls.clone(cls.holder / 'a')
        cls.clone(cls.holder / 'group/b')
        (cls.holder / 'notes').mkdir()
        cls.nested_parent = h / 'nestedparent'  # a plain directory with an unpushed repository two levels down
        inner = cls.clone(cls.nested_parent / 'x/inner')
        cls.commit(inner, 'inner local')
        cls.outer = cls.clone(h / 'outer')  # pushed outer, unpushed repository inside its working tree
        cls.commit(cls.clone(cls.outer / 'vendor/sub'), 'sub local')
        cls.wt_main = cls.clone(h / 'wtmain/main')
        cls.wt_clean = h / 'wtmain/clean'
        run('git', 'worktree', 'add', '-q', '--detach', str(cls.wt_clean), cwd=str(cls.wt_main))
        cls.wt_dirty = h / 'wtmain/detached'
        run('git', 'worktree', 'add', '-q', '--detach', str(cls.wt_dirty), cwd=str(cls.wt_main))
        cls.commit(cls.wt_dirty, 'worktree detached work')
        cls.plain = h / 'plain/a/b'
        cls.plain.mkdir(parents=True)
        (cls.plain / 'f.txt').write_text('x\n')
        (cls.pushed / 'node_modules/pkg').mkdir(parents=True)
        (cls.pushed / 'build').mkdir()
        cls.many = h / 'many'
        (cls.many / 'deep').mkdir(parents=True)
        for k in range(60):
            (cls.many / ('f%02d' % k)).write_text('x\n')
        lists = h / 'lists'
        lists.mkdir()
        cls.bad_list = lists / 'bad.txt'
        cls.bad_list.write_text('%s\n%s\n' % (cls.plain, cls.unpushed))
        cls.good_list = lists / 'good.txt'
        cls.good_list.write_text('%s\n%s\n' % (cls.plain, cls.pushed / 'build'))
        # every clone sees the remote's final tips (later clones pushed after earlier ones fetched), as after a fetch
        for path in cls.clones:
            run('git', 'fetch', '-q', str(cls.remote), '+refs/heads/*:refs/remotes/origin/*', cwd=str(path))
        cls.policy = cg.load_policy(path=str(h / 'no-such-policy.json'))

    @classmethod
    def tearDownClass(cls):
        if cls._old_home is None:
            os.environ.pop('HOME', None)
        else:
            os.environ['HOME'] = cls._old_home
        cls._tmp.cleanup()

    @classmethod
    def commit(cls, path, message):
        (Path(path) / ('%s.txt' % message.replace(' ', '-'))).write_text(message + '\n')
        run('git', 'add', '-A', cwd=str(path))
        run('git', 'commit', '-q', '-m', message, cwd=str(path))

    @classmethod
    def clone(cls, path):
        """A clone whose branch is pushed to the bare remote, its origin URL then pointed at github.com."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        run('git', 'clone', '-q', str(cls.remote), str(path))
        if not run('git', 'branch', '--list', cwd=str(path)).strip():  # the first clone of an empty remote
            run('git', 'checkout', '-q', '-b', 'main', cwd=str(path))
        cls.commit(path, 'c-%s' % path.name)
        run('git', 'push', '-q', 'origin', 'HEAD:main', cwd=str(path))
        run('git', 'fetch', '-q', 'origin', cwd=str(path))
        run('git', 'remote', 'set-url', 'origin', cls.url, cwd=str(path))
        cls.clones.append(path)
        return path

    def setUp(self):
        self.calls = []

        def ls_remote(url, timeout):
            self.calls.append(url)
            if url != self.url:
                return None
            done = subprocess.run(['git', '--git-dir', str(self.remote), 'for-each-ref', '--format=%(objectname)',
                                   'refs/heads', 'refs/tags'], stdout=subprocess.PIPE, check=False)
            return done.stdout.decode().split()
        self.patches = [mock.patch.object(cg, 'CLONE_LS_REMOTE', ls_remote, create=True)]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()

    def decide(self, command, cwd=None, marker=None):
        cwd = str(cwd or self.home)
        compiled = cg.Compiled(self.policy, home=str(self.home), cwd=cwd)
        return cg.decide(command, compiled, cwd=cwd, marker=marker)

    def expect(self, rows, want, rule=None, cwd=None, marker=None):
        wrong = []
        for row in rows:
            verdict, message = self.decide(row, cwd=cwd, marker=marker)
            if verdict != want or (rule and rule not in message):
                wrong.append('%r -> %s %s' % (row, verdict, message.splitlines()[:1]))
        self.assertEqual(wrong, [], '%d of %d rows wrong:\n%s' % (len(wrong), len(rows), '\n'.join(wrong)))


class CloneDeleteTests(CloneDeleteCase):
    def test_unpushed_work_in_a_repository_blocks(self):
        self.expect(['rm -rf %s' % self.unpushed, 'rm -rf %s' % self.stashed, 'rm -rf %s' % self.detached,
                     'rm -rf %s' % self.tagged, 'rm -rf %s' % self.noremote, 'rm -rf %s' % self.badhost,
                     'rm -r %s/' % self.unpushed, 'cd %s && rm -rf unpushed' % (self.home / 'repos')],
                    'block', rule='git-clone-delete')

    def test_ancestors_holding_unpushed_repositories_block(self):
        self.expect(['rm -rf %s' % (self.home / 'repos'), 'rm -rf %s/*' % (self.home / 'repos'),
                     'find %s -maxdepth 1 -exec rm -rf {} +' % (self.home / 'repos'),
                     'find %s -delete' % (self.home / 'repos'),
                     'rm -rf %s' % self.nested_parent, 'rm -rf %s' % self.outer,
                     'rsync -a --delete %s/ %s/' % (self.plain, self.unpushed)],
                    'block', rule='git-clone-delete')

    def test_linked_worktree_with_unpushed_detached_head_blocks(self):
        self.expect(['rm -rf %s' % self.wt_dirty], 'block', rule='git-clone-delete')

    def test_list_fed_and_remote_clone_deletes_block(self):
        self.expect(['xargs rm -rf < %s' % self.bad_list, 'cat %s | xargs rm -rf' % self.bad_list,
                     'rm -rf $(cat %s)' % self.bad_list,
                     'while read p; do rm -rf "$p"; done < %s' % self.bad_list],
                    'block', rule='git-clone-delete')
        # another host's directory cannot be walked or pushed-checked from here
        self.expect(['ssh dev2 rm -rf /home/eric/repos/harness', "ssh dev2 'rm -rf /home/eric/repos'",
                     "ssh dev2 'cd /home/eric/repos && rm -rf bugtracker'", 'ssh dev2 xargs rm -rf < %s' % self.good_list],
                    'block', rule='git-clone-delete-unverifiable')

    def test_network_failure_blocks_as_unverifiable(self):
        with mock.patch.object(cg, 'CLONE_LS_REMOTE', lambda url, timeout: None, create=True):
            self.expect(['rm -rf %s' % self.pushed, 'rm -rf %s' % self.holder], 'block',
                        rule='git-clone-delete-unverifiable')

        def boom(url, timeout):
            raise subprocess.TimeoutExpired('git', timeout)
        with mock.patch.object(cg, 'CLONE_LS_REMOTE', boom, create=True):
            self.expect(['rm -rf %s' % self.pushed], 'block', rule='git-clone-delete-unverifiable')

    def test_incomplete_walk_blocks_as_unverifiable(self):
        with mock.patch.object(cg, 'CLONE_WALK_MAX_ENTRIES', 50, create=True):
            self.expect(['rm -rf %s' % self.many], 'block', rule='git-clone-delete-unverifiable')

    def test_pushed_repositories_stay_deletable(self):
        self.expect(['rm -rf %s' % self.pushed, 'rm -rf %s' % self.holder, 'rm -rf %s' % self.wt_clean,
                     'xargs rm -rf < %s' % self.good_list], 'allow')

    def test_live_listing_is_cached_per_url_within_one_decision(self):
        self.assertEqual(self.decide('rm -rf %s' % self.holder)[0], 'allow')
        self.assertEqual(self.calls, [self.url])

    def test_dirty_working_tree_alone_does_not_block_but_is_named(self):
        verdict, message = self.decide('rm -rf %s' % self.dirty)
        self.assertEqual(verdict, 'warn', message)
        self.assertIn('git-clone-delete', message)
        self.assertIn('uncommitted', message)

    def test_ordinary_directory_deletes_stay_allowed(self):
        self.expect(['rm -rf node_modules', 'rm -rf build', 'rm -rf %s/node_modules' % self.pushed,
                     'rm -rf %s' % (self.home / 'plain'), 'rm -rf %s' % self.plain, 'rm -rf %s/src' % self.pushed,
                     'rm -f %s/c-pushed.txt' % self.pushed, 'rm -rf %s' % (self.home / 'nothing-here'),
                     'ssh dev2 rm -rf /srv/app/node_modules', 'ssh dev2 rm -f /home/eric/repos/harness/README.md',
                     'rm -rf %s' % self.many], 'allow', cwd=self.pushed)


class CloneVerifierStrictnessTests(CloneDeleteCase):
    def test_a_remote_off_the_allowlist_is_never_listed_and_refuses_as_unpushed(self):
        verdict, message = self.decide('rm -rf %s' % self.badhost)
        self.assertEqual(verdict, 'block')
        self.assertIn('[log_delete/git-clone-delete]', message)
        self.assertNotIn('https://evil.example/acme/proj.git', self.calls)

    def test_a_git_failure_refuses_as_unverifiable(self):
        broken = self.clone(self.home / ('broken/b-%d' % time.monotonic_ns()))
        run('git', 'fetch', '-q', str(self.remote), '+refs/heads/*:refs/remotes/origin/*', cwd=str(broken))
        (broken / '.git/refs/heads/dangling').write_text('0123456789abcdef0123456789abcdef01234567\n')
        verdict, message = self.decide('rm -rf %s' % broken)
        self.assertEqual(verdict, 'block', message)
        self.assertIn('git-clone-delete-unverifiable', message)


class RedTeamTests(GitDirCase):
    """PR 175 red-team (45ce84f) reproducers. LIST (@SWEEP@) holds a line naming REPO/.git."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        h = cls.home
        cls.wipe = h / 'lists/wipe.sh'
        cls.wipe.write_text('#!/bin/sh\nrm -rf /home/eric/repos/bugtracker/.git\n')
        cls.nul = h / 'lists/nul.txt'
        cls.nul.write_bytes(b'%s/junk/a\x00%s/.git\x00' % (str(h).encode(), str(cls.repo).encode()))
        cls.spaced = h / 'lists/spaced.txt'
        cls.spaced.write_text('%s/.git %s/junk/a\n' % (cls.repo, h))
        cls.long = h / 'lists/long.txt'
        cls.long.write_text(''.join('%s/junk/f%02d\n' % (h, k) for k in range(20)))
        cls.fifo = h / 'lists/fifo'
        os.mkfifo(str(cls.fifo))
        (cls.repo / '.git/dir.lock').mkdir()
        (cls.repo / 'src').mkdir()

    def blocks(self, rows, cwd='@REPO@'):
        self.expect(rows, 'block', cwd=cwd)

    def test_xargs_value_options_before_the_list_file(self):
        self.blocks(["xargs -d '\\n' -a @SWEEP@ rm -rf", 'xargs -n 1 -a @SWEEP@ rm -rf', 'xargs -P 4 -a @SWEEP@ rm -rf',
                     'xargs -I {} -a @SWEEP@ rm -rf {}', 'xargs --max-args 1 -a @SWEEP@ rm -rf',
                     "xargs --delimiter '\\n' -a @SWEEP@ rm -rf", 'xargs -E END -a @SWEEP@ rm -rf',
                     'xargs -L 1 -a @SWEEP@ rm -rf', 'xargs --max-procs 2 -a @SWEEP@ rm -rf'])

    def test_lists_carried_through_a_variable_or_for_loop(self):
        self.blocks(['for p in $(cat @SWEEP@); do rm -rf "$p"; done', 'for p in `cat @SWEEP@`; do rm -rf "$p"; done',
                     'L=$(cat @SWEEP@); rm -rf $L', 'L="$(< @SWEEP@)"; rm -rf $L',
                     'for p in @REPO@/.git; do rm -rf "$p"; done', 'D=$(echo @REPO@/.git); rm -rf "$D"'])

    def test_variable_hint_naming_git(self):  # M31
        self.blocks(['D="$(pwd)/.git"; rm -rf "$D"', 'D="${UNSET_BASE}/.git"; rm -rf $D'])

    def test_grouped_and_subshell_producers(self):
        self.blocks(['{ cat @SWEEP@; } | xargs rm -rf', '(cat @SWEEP@; cat @OK@) | xargs rm -rf',
                     'cat @SWEEP@ | (xargs rm -rf)', 'cat @SWEEP@ | { xargs rm -rf; }'])

    def test_transformed_lists_fail_closed(self):
        self.blocks(["cat @SWEEP@ | tr -d '\\r' | xargs rm -rf", "cat @OK@ | sed 's/x/y/' | xargs rm -rf",
                     "cat @OK@ | awk '{print}' | xargs rm -f", 'cat @OK@ | cut -c1- | xargs rm -f'])

    def test_ssh_options_after_the_host(self):
        self.blocks(['ssh dev2 -p 22 xargs rm -rf < @SWEEP@', "ssh dev2 -o BatchMode=yes 'rm -rf x/.git'",
                     "ssh dev2 -p 22 'xargs -a /home/eric/sweep.txt rm -rf'",
                     "ssh host -o ProxyCommand=none 'rm -rf x/.git'"])

    def test_local_script_fed_to_a_remote_shell(self):
        self.blocks(['ssh host bash -s < @HOME@/lists/wipe.sh', 'ssh host sh < @HOME@/lists/wipe.sh',
                     'ssh host < @HOME@/lists/wipe.sh', "ssh host 'bash -s' < @HOME@/lists/wipe.sh",
                     'cat @HOME@/lists/wipe.sh | ssh dev2 bash', 'ssh host "$(cat @HOME@/lists/wipe.sh)"',
                     'ssh host bash -s < "$SCRIPT"'])

    def test_whole_clone_shapes(self):
        self.blocks(['rm -rf @REPO@', 'cd .. && rm -rf proj', 'rm -rf .', 'rm -rf @REPO@/.git/..',
                     'find @REPO@ -delete', 'find . -mindepth 1 -delete', 'find . | xargs rm -rf',
                     'rm -rf @HOME@/repos/*', "ssh dev2 'rm -rf /home/eric/repos/bugtracker'",
                     'rsync -a --delete @HOME@/lists/ @REPO@/', 'rsync -a --delete src/ dev2:repos/x/',
                     'rsync -a --delete src/ dev2:repos/x/.git/', 'rsync -a --delete src/ dev2:/home/eric/repos/x'])
        self.expect(['rsync -a --delete --exclude=.git src/ dev2:repos/x/', 'rsync -a --delete src/ dev2:app/node_modules/',
                     'rsync -a --delete --exclude .git @HOME@/lists/ @REPO@/'], 'allow')

    def test_overwriting_git_internals_blocks(self):
        self.blocks([': > .git/packed-refs', 'truncate -s0 .git/packed-refs', 'dd if=/dev/zero of=.git/packed-refs',
                     'cp /dev/null .git/index', '> .git/HEAD', 'echo x > .git/refs/heads/master'])
        self.expect(['echo "*.log" >> .git/info/exclude', 'echo "*.log" > .git/info/exclude',
                     'cp hook.sh .git/hooks/pre-commit', 'echo msg > .git/COMMIT_EDITMSG'], 'allow')

    def test_git_clean_double_force_deletes_nested_repositories(self):
        self.blocks(['git clean -ffd', 'git clean -ffdx', 'git clean -f -f -d', 'git -C @REPO@ clean -ffdx',
                     "ssh dev2 'cd /home/eric/repos/x && git clean -ffdx'"])
        self.expect(['git clean -fd', 'git clean -n', 'git clean -ffdn'], 'allow')

    def test_rev_parse_git_dir_with_a_transient_suffix_is_allowed(self):
        self.expect(['rm -f "$(git rev-parse --git-dir)/index.lock"', 'rm -f "$(git rev-parse --git-dir)/COMMIT_EDITMSG"',
                     'rm -f "$(git rev-parse --absolute-git-dir)/refs/heads/main.lock"'], 'allow')
        self.blocks(['rm -rf "$(git rev-parse --git-dir)/objects"', 'rm -rf "$(git rev-parse --git-dir)"'])

    def test_find_producer_excluding_git_is_allowed(self):
        self.expect(["find . -path ./.git -prune -o -name '*.tmp' -print | xargs rm -f",
                     "find . -not -path '*/.git/*' -name '*.tmp' | xargs rm -f",
                     "find . -name .git -prune -o -name '*.tmp' -exec rm {} +",
                     "find . -not -path '*/.git/*' -name '*.tmp' -delete"], 'allow')
        self.blocks(["find . -name .git | xargs rm -rf", "find . -path '*/.git/*' | xargs rm -f"])

    def test_more_transient_files_and_rebase_message(self):
        self.expect(['rm -f .git/gc.log', 'rm -f .git/gc.pid', 'rm -f .git/objects/pack/tmp_pack_abc123',
                     'rm -f .git/objects/pack/.tmp-1234-pack-abc.pack', 'rm -f .git/CHERRY_PICK_HEAD',
                     'rm -f .git/REVERT_HEAD', 'rm -f .git/AUTO_MERGE', 'rm -f .git/BISECT_LOG'], 'allow')
        verdict, message = self.decide('rm -rf .git/rebase-merge')
        self.assertEqual(verdict, 'block')
        self.assertIn('git rebase --abort', message)

    def test_transient_names_only_directly_in_the_git_directory(self):  # M04, M05
        self.blocks(['rm -f .git/refs/heads/ORIG_HEAD', 'rm -f .git/refs/heads/COMMIT_EDITMSG', 'rm -rf .git/dir.lock'])

    def test_list_caps(self):  # M11, M12
        with mock.patch.object(cg, 'GIT_LIST_MAX_LINES', 5):
            self.blocks(['xargs rm -rf < @HOME@/lists/long.txt'])
        with mock.patch.object(cg, 'GIT_LIST_MAX_BYTES', 64):
            self.blocks(['xargs rm -rf < @HOME@/lists/long.txt'])
        self.expect(['xargs rm -f < @HOME@/lists/long.txt'], 'allow')

    def test_fifo_list_does_not_hang_and_blocks(self):  # M13
        import threading
        out = []
        worker = threading.Thread(target=lambda: out.append(self.decide('xargs rm -rf < @HOME@/lists/fifo')))
        worker.daemon = True
        worker.start()
        worker.join(20)
        self.assertFalse(worker.is_alive(), 'the guard hung on a FIFO list')
        self.assertEqual(out[0][0], 'block')
        self.assertIn('git-dir-delete-unverifiable', out[0][1])

    def test_list_written_by_the_same_command(self):  # M14
        self.blocks(['echo @REPO@/.git > @HOME@/lists/long.txt; xargs rm -rf < @HOME@/lists/long.txt'])

    def test_grep_only_matching_recursive_and_ls_all(self):  # M15, M16
        self.blocks(['grep -o x @OK@ | xargs rm -rf', 'grep -r junk @HOME@/lists | xargs rm -rf', 'ls -a | xargs rm -rf',
                     'ls -A @REPO@ | xargs rm -rf'])

    def test_whitespace_and_nul_separated_lists(self):  # M19, M20
        self.blocks(['xargs rm -rf < @HOME@/lists/spaced.txt', 'xargs -0 rm -rf < @HOME@/lists/nul.txt'])

    def test_container_hop_is_remote(self):  # M22
        verdict, message = self.decide('docker exec c xargs -a @OK@ rm -f')
        self.assertEqual(verdict, 'block', message)
        self.assertIn('another host', message)

    def test_casefold_is_part_of_the_match(self):  # M29
        self.assertEqual(cg.git_path_kind('/x/.GIT/HEAD'), 'git')
        self.assertEqual(cg.git_path_kind('/x/.Git'), 'git')
        self.assertIsNone(cg.git_path_kind('/x/.GITHUB/a'))

    def test_uniq_second_operand_is_an_output(self):  # M30
        self.expect(['uniq @OK@ @HOME@/lists/uniq-out.txt | xargs rm -f'], 'allow')
        self.blocks(['uniq @SWEEP@ | xargs rm -rf'])

    def test_remote_list_that_also_exists_locally_is_still_remote(self):  # M33
        verdict, message = self.decide("ssh dev2 'xargs -a @OK@ rm -f'")
        self.assertEqual(verdict, 'block', message)
        self.assertIn('another host', message)


class CloneApprovalTests(CloneDeleteCase):
    class Verifier:
        def remote_types(self):
            return {'dropbox': 'dropbox'}

        def verify(self, local_root, manifest, remote):
            return cg.VerifyResult(True, checked=len(manifest))

    def test_verified_backup_approval_covers_the_exact_clone(self):
        target = self.clone(self.home / ('approved/u-%d' % time.monotonic_ns()))
        self.commit(target, 'local work')
        past = time.time() - 3600
        for root, dirs, files in os.walk(str(target), topdown=False):
            for name in dirs + files:
                os.utime(os.path.join(root, name), (past, past), follow_symlinks=False)
        os.utime(str(target), (past, past))
        self.assertEqual(self.decide('rm -rf %s' % target)[0], 'block')
        cg.approve_delete(str(target), 'dropbox:backups/x', verifier=self.Verifier(), home=str(self.home),
                          policy=self.policy)
        approvals = cg.Approvals(home=str(self.home), compiled=cg.Compiled(self.policy, home=str(self.home)))
        self.assertEqual(self.decide('rm -rf %s' % target, marker=approvals)[0], 'allow')
        approvals = cg.Approvals(home=str(self.home), compiled=cg.Compiled(self.policy, home=str(self.home)))
        self.assertEqual(self.decide('rm -rf %s' % target.parent, marker=approvals)[0], 'block')


if __name__ == '__main__':
    unittest.main()
