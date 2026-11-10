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
            if verdict != want or (want == 'block' and 'git-dir-delete' not in message):
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
            'ssh dev2 xargs rm -rf < @OK@',
            'cat @OK@ | ssh dev2 xargs rm -f',
            'ssh dev2 rm -rf /home/eric/tmp/build',
        ], 'allow')

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


if __name__ == '__main__':
    unittest.main()
