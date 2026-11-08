"""goodqa#15251: remote_delete.py, a guarded delete of an archive-backed tree on another host.

The Mac side (approval checks) runs for real against a temporary home. The ssh hop is the only fake: the runner
runs the remote command with bash in a second temporary home ("the remote host"), so remote_delete_agent.py really
re-checks and removes there. rclone is a fake that maps dropbox:<path> to a local directory; the archives in it are
real tar.gz files, sha256 files, `tar -tvf` listings and git bundles.
"""
import hashlib
import json
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
sys.path.insert(0, str(Path(__file__).resolve().parent))

import command_guard as cg  # noqa: E402
import remote_delete as rd  # noqa: E402
from test_command_guard_no_backup import GIT_ENV, SOURCE, hook_wal, run  # noqa: E402

FAKE_RCLONE = r'''#!/usr/bin/env python3
import os, shutil, sys
args = sys.argv[1:]
if args[:1] == ["--tpslimit"]:
    args = args[2:]
op, rest = args[0], [a for a in args[1:] if a != "--"]
root = os.environ["FAKE_DROPBOX"]
def local(remote):
    return os.path.join(root, remote.split(":", 1)[1])
if op == "cat":
    during = os.environ.get("FAKE_WRITE_DURING_DOWNLOAD")
    if during and rest[0].endswith(".tar.gz"):  # a writer that runs while the archive downloads
        with open(during, "w") as f:
            f.write("late\n")
    try:
        with open(local(rest[0]), "rb") as f:
            shutil.copyfileobj(f, sys.stdout.buffer)
    except OSError:
        sys.exit(3)
elif op == "copyto":
    try:
        shutil.copyfile(local(rest[0]), rest[1])
    except OSError:
        sys.exit(3)
else:
    sys.exit(9)
'''
ARCHIVE_DIR = 'dropbox:Backups/t2-dev/worktree-archives'
QUESTION = ("[ask:w1] t2-dev's disk is critical. Each one is already backed up to Dropbox, both the files and its "
            "git history. Remove these 2 from t2-dev: ~/wt/alpha, ~/wt/beta?")
ANSWER = 'Yes, remove all 2 (Recommended)'


class RemoteCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix='rdel-')
        base = Path(os.path.realpath(self._tmp.name))
        self.home, self.rhome, self.box = base / 'mac', base / 'remote', base / 'box'
        for d in (self.home, self.rhome / 'wt', self.box / 'Backups/t2-dev/worktree-archives', base / 'bin'):
            d.mkdir(parents=True)
        self.rclone = base / 'bin/rclone'
        self.rclone.write_text(FAKE_RCLONE)
        self.rclone.chmod(0o755)
        self.policy = cg.load_policy(path=str(self.home / 'no-such-policy.json'))
        self.wal = str(self.home / '.claude/wals/sess-1/agent-rd.jsonl')
        hook_wal(self.wal, time.time() - 600)
        self.turn = {'text': ANSWER, 'question': QUESTION, 'predefined': True}
        self.calls = []
        self.between = None  # run between the remote check and the remote delete
        self._old_home = os.environ.get('HOME')
        os.environ['HOME'] = str(self.home)  # wal_note.py only appends to WALs under this home
        os.environ['COPYFILE_DISABLE'] = '1'  # macOS tar: no ._ AppleDouble members (GNU tar on the hosts has none)

    def tearDown(self):
        if self._old_home is None:
            os.environ.pop('HOME', None)
        else:
            os.environ['HOME'] = self._old_home
        self._tmp.cleanup()

    # the remote host ------------------------------------------------------------------------------------------
    def runner(self, argv, input=None, capture_output=True, text=True, timeout=None):
        self.assertEqual(argv[:6], ['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', '--'])
        self.calls.append(argv[7].split()[3] if len(argv[7].split()) > 3 else '')
        if self.calls[-1] == 'delete' and self.between:
            self.between()
        env = dict(os.environ, HOME=str(self.rhome), REMOTE_DELETE_RCLONE=str(self.rclone),
                   FAKE_DROPBOX=str(self.box), **GIT_ENV)
        return subprocess.run(['bash', '-c', argv[7]], input=input, capture_output=True, text=True, env=env,
                              cwd=str(self.rhome))

    def archive(self, name, corrupt=False, bundle_of=None):
        """Archive ~/wt/<name> the way t2_archive_one.sh does, into the fake Dropbox."""
        out = self.box / 'Backups/t2-dev/worktree-archives'
        tar = out / (name + '.tar.gz')
        run('tar', '-czf', str(tar), '-C', str(self.rhome / 'wt'), name)
        digest = hashlib.sha256(tar.read_bytes()).hexdigest()
        if corrupt:
            digest = '0' * 64
        (out / (name + '.tar.gz.sha256')).write_text('%s  %s.tar.gz\n' % (digest, name))
        (out / (name + '.tar.gz.listing')).write_text(run('tar', '-tvf', str(tar)))
        if bundle_of:
            run('git', '-C', str(bundle_of), 'bundle', 'create', str(out / (name + '.bundle')), 'HEAD',
                '--not', '--remotes')

    def plain_tree(self, name):
        tree = self.rhome / 'wt' / name
        tree.mkdir()
        (tree / 'notes.txt').write_text('hello\n')
        return tree

    def git_tree(self, name, unpushed=True):
        repo = self.rhome / 'repos/main'
        if not repo.exists():
            bare = self.rhome / 'repos/origin.git'
            run('git', 'init', '-q', '--bare', str(bare))
            run('git', 'init', '-q', str(repo))
            (repo / 'a').write_text('a\n')
            run('git', '-C', str(repo), 'add', 'a')
            run('git', '-C', str(repo), 'commit', '-q', '-m', 'a')
            run('git', '-C', str(repo), 'remote', 'add', 'origin', str(bare))
            run('git', '-C', str(repo), 'push', '-q', 'origin', 'HEAD:refs/heads/main')
        tree = self.rhome / 'wt' / name
        run('git', '-C', str(repo), 'worktree', 'add', '-q', '-b', name, str(tree))
        if unpushed:
            (tree / 'b').write_text('b\n')
            run('git', '-C', str(tree), 'add', 'b')
            run('git', '-C', str(tree), 'commit', '-q', '-m', 'b')
        return tree, repo

    # the Mac side ---------------------------------------------------------------------------------------------
    def resolver(self, source, now=None, max_age=None, home=None):
        return dict(self.turn, kind='answer', session='sess-1', uid=source.rsplit('/', 1)[-1].lower(),
                    at=time.time() - 60)

    def delete(self, tree, host='t2-dev', source=SOURCE, wal=None):
        return rd.remote_delete(host, str(tree), ARCHIVE_DIR, source, wal or self.wal, home=str(self.home),
                                resolver=self.resolver, runner=self.runner, policy=self.policy)

    def mac_audit(self):
        path = cg.state_dir(str(self.home)) / cg.AUDIT_NAME
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def refused(self, tree, contains, **kw):
        with self.assertRaises(rd.Refused) as caught:
            self.delete(tree, **kw)
        self.assertIn(contains, str(caught.exception))
        self.assertTrue(tree.exists(), 'a refused delete must leave the tree')
        return caught.exception


class Allowed(RemoteCase):
    def test_plain_tree_named_with_tilde_is_removed_and_audited_on_both_sides(self):
        tree = self.plain_tree('alpha')
        self.archive('alpha')
        result = self.delete(tree)
        self.assertTrue(result['ok'] and result['deleted'])
        self.assertFalse(tree.exists())
        self.assertEqual(self.calls, ['check', 'delete'])
        events = [(r['event'], r.get('kind')) for r in self.mac_audit()]
        self.assertEqual(events, [('approved', rd.ARCHIVE_KIND), ('deleted', rd.ARCHIVE_KIND)])
        remote = [json.loads(x)['event'] for x in
                  (self.rhome / '.agent-harness/state/remote-delete-audit.jsonl').read_text().splitlines()]
        self.assertEqual(remote, ['remote-check', 'remote-delete'])
        self.assertIn('command_guard approved', Path(self.wal).read_text())

    def test_one_question_naming_two_paths_approves_both(self):
        for name in ('alpha', 'beta'):
            tree = self.plain_tree(name)
            self.archive(name)
            self.delete(tree)
            self.assertFalse(tree.exists())

    def test_linked_worktree_with_unpushed_commit_needs_and_uses_the_bundle(self):
        tree, repo = self.git_tree('alpha')
        self.archive('alpha', bundle_of=tree)
        self.assertTrue(self.delete(tree)['archive']['bundle'])
        self.assertFalse(tree.exists())
        self.assertNotIn(str(tree), run('git', '-C', str(repo), 'worktree', 'list'))
        self.assertIn('refs/heads/alpha', run('git', '-C', str(repo), 'for-each-ref'))  # the branch stays


class Refused(RemoteCase):
    def test_declining_answer(self):
        tree = self.plain_tree('alpha')
        self.archive('alpha')
        self.turn['text'] = "No, keep them for now"
        self.refused(tree, 'not a plain approval')
        self.assertEqual(self.calls, [], 'nothing runs remotely before the wording checks pass')

    def test_free_text_answer(self):
        tree = self.plain_tree('alpha')
        self.turn['predefined'] = False
        self.refused(tree, 'free text')

    def test_question_without_the_host(self):
        tree = self.plain_tree('alpha')
        self.turn['question'] = QUESTION.replace('t2-dev', 'the server')
        self.refused(tree, 'does not name the host t2-dev')

    def test_question_without_backup_wording(self):
        tree = self.plain_tree('alpha')
        self.turn.update(question='Remove ~/wt/alpha from t2-dev?', text='Remove it')
        self.refused(tree, 'backed up')

    def test_question_naming_another_path(self):
        tree = self.plain_tree('gamma')
        self.archive('gamma')
        self.refused(tree, 'does not name')
        self.assertEqual(self.calls, ['check'])

    def test_host_off_the_allowlist(self):
        tree = self.plain_tree('alpha')
        self.refused(tree, '--host must be one of', host='ah-spectre')

    def test_wal_of_another_session(self):
        tree = self.plain_tree('alpha')
        other = str(self.home / '.claude/wals/sess-2/main.jsonl')
        hook_wal(other, time.time() - 600)
        self.refused(tree, 'not a WAL of that session', wal=other)

    def test_cap_per_answer(self):
        self.policy['marker']['archive_remote_max_paths_per_source'] = 1
        first, second = self.plain_tree('alpha'), self.plain_tree('beta')
        self.archive('alpha')
        self.archive('beta')
        self.delete(first)
        self.refused(second, 'already approved 1')

    def test_archive_that_does_not_match_its_sha256(self):
        tree = self.plain_tree('alpha')
        self.archive('alpha', corrupt=True)
        self.refused(tree, 'does not match its sha256')

    def test_missing_archive(self):
        tree = self.plain_tree('alpha')
        self.refused(tree, 'check refused')

    def test_unpushed_commit_without_a_bundle(self):
        tree, _ = self.git_tree('alpha')
        self.archive('alpha')
        self.refused(tree, 'bundle could not be downloaded')

    def test_dirty_git_tree(self):
        tree, _ = self.git_tree('alpha', unpushed=False)
        self.archive('alpha')
        (tree / 'new.txt').write_text('work\n')
        self.refused(tree, 'uncommitted or untracked')

    def test_path_replaced_between_check_and_delete(self):
        tree = self.plain_tree('alpha')
        self.archive('alpha')

        def swap():
            os.rename(str(tree), str(tree) + '.old')
            tree.mkdir()
            import shutil
            shutil.copy2(str(tree) + '.old/notes.txt', str(tree / 'notes.txt'))  # same content and mtime
        self.between = swap
        self.refused(tree, 'identity changed')
        self.assertEqual(self.mac_audit()[-1]['event'], 'remote-failed')

    def test_protected_location(self):
        tree = self.rhome / '.claude/projects'
        tree.mkdir(parents=True)
        self.turn.update(question=QUESTION + ' Also ~/.claude/projects', text='Yes, remove all 3')
        self.refused(tree, 'protected')

    def test_credential_location(self):
        tree = self.rhome / '.aws/sso'
        tree.mkdir(parents=True)
        self.turn.update(question=QUESTION + ' Also ~/.aws/sso', text='Yes, remove all 3')
        self.refused(tree, 'protected')

    # red-team F1: the archive must be the tree, not just any archive of that name
    def test_archive_of_a_different_tree(self):
        tree = self.plain_tree('alpha')
        self.archive('alpha')
        (tree / 'later.txt').write_text('written after the archive\n')
        self.refused(tree, 'the tree has alpha/later.txt, which the archive does not')

    def test_archive_with_a_changed_file(self):
        tree = self.plain_tree('alpha')
        self.archive('alpha')
        (tree / 'notes.txt').write_text('hello, and more\n')
        self.refused(tree, 'alpha/notes.txt differs from the archive')

    def test_archive_missing_a_deleted_file_is_fine_only_when_equal(self):
        tree = self.plain_tree('alpha')
        (tree / 'gone.txt').write_text('x\n')
        self.archive('alpha')
        (tree / 'gone.txt').unlink()
        self.refused(tree, 'the archive has alpha/gone.txt, which the tree does not')

    # red-team F3: a file written while the archive downloads is seen, because the tree is compared after it
    def test_write_during_the_download(self):
        tree = self.plain_tree('alpha')
        self.archive('alpha')
        os.environ['FAKE_WRITE_DURING_DOWNLOAD'] = str(tree / 'late.txt')
        self.addCleanup(os.environ.pop, 'FAKE_WRITE_DURING_DOWNLOAD', None)
        self.refused(tree, 'the tree has alpha/late.txt')

    # red-team F18: contents count, not only size and mtime
    def test_same_size_edit_with_mtime_restored(self):
        tree = self.plain_tree('alpha')
        self.archive('alpha')
        info = os.stat(tree / 'notes.txt')
        (tree / 'notes.txt').write_text('HELLO\n')
        os.utime(tree / 'notes.txt', ns=(info.st_atime_ns, info.st_mtime_ns))
        self.refused(tree, 'alpha/notes.txt differs from the archive')

    # red-team F16: a submodule's repository lives in the worktree's git dir and goes with worktree remove
    def test_worktree_with_a_submodule(self):
        sub = self.rhome / 'repos/sub'
        run('git', 'init', '-q', str(sub))
        (sub / 's').write_text('s\n')
        run('git', '-C', str(sub), 'add', 's')
        run('git', '-C', str(sub), 'commit', '-q', '-m', 's')
        tree, _ = self.git_tree('alpha', unpushed=False)
        run('git', '-c', 'protocol.file.allow=always', '-C', str(tree), 'submodule', 'add', '-q', str(sub), 'sub')
        run('git', '-C', str(tree), 'commit', '-q', '-m', 'add sub')
        self.archive('alpha', bundle_of=tree)
        self.refused(tree, 'submodules')

    # red-team F17: a question that also says keep, and a multi-path answer without its count
    def test_question_that_also_says_keep(self):
        keep, old = self.plain_tree('active'), self.plain_tree('old')
        self.archive('old')
        self.turn.update(question="Keep ~/wt/active (an owner is in it). t2-dev: ~/wt/old is backed up. Remove ~/wt/old?",
                         text='Yes, remove all 2')
        self.refused(old, 'keep or not remove')
        self.refused(keep, 'keep or not remove')

    def test_question_that_spares_a_path(self):
        tree = self.plain_tree('old')
        self.archive('old')
        for question in ("t2-dev: both are backed up. Spare ~/wt/active; remove ~/wt/old?",
                         "t2-dev: all backed up. Remove ~/wt/old and ~/wt/x, except ~/wt/active?"):
            self.turn.update(question=question, text='Yes, remove all %d' % rd.named_count(question))
            self.refused(tree, 'keep or not remove')

    def test_multi_path_answer_must_state_the_count(self):
        tree = self.plain_tree('alpha')
        self.archive('alpha')
        self.turn['text'] = 'Yes, remove them'
        self.refused(tree, 'must state that count')

    # red-team F2: a checkout with its own .git directory takes its branches with it
    def test_main_checkout_is_refused(self):
        tree = self.rhome / 'wt' / 'alpha'
        run('git', 'init', '-q', str(tree))
        (tree / 'a').write_text('a\n')
        run('git', '-C', str(tree), 'add', 'a')
        run('git', '-C', str(tree), 'commit', '-q', '-m', 'a')
        run('git', '-C', str(tree), 'branch', 'side')
        self.archive('alpha')
        self.refused(tree, 'own .git directory')

    # red-team F4: the answer must approve every named path, and approves no more than the question names
    def test_partial_answers(self):
        tree = self.plain_tree('alpha')
        self.archive('alpha')
        for text in ('Delete only alpha', 'Remove all except beta', 'Yes, remove alpha', 'Delete 1 of them'):
            self.turn['text'] = text
            self.refused(tree, 'question names' if text == 'Delete 1 of them' else 'not a plain approval')

    def test_cap_is_the_number_of_named_paths(self):
        self.turn.update(question=QUESTION.replace(', ~/wt/beta', ''), text='Yes, remove it')
        first = self.plain_tree('alpha')
        self.archive('alpha')
        self.delete(first)
        again = self.plain_tree('alpha')
        self.archive('alpha')
        self.refused(again, 'already approved 1')


if __name__ == '__main__':
    unittest.main()
