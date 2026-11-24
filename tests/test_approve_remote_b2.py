"""approve-delete accepts a verified copy on Eric's B2 remote, pinned by NAME (supervisor standing authority, rule 4:
"verified copy on b2-archive or Dropbox"). A b2-type remote is accepted only when it is called b2-archive; the type
alone never approves. The list is built in: no policy file can widen it. Remote lists come from `rclone listremotes
--long` (names and types), never from reading rclone.conf."""

import ast
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'harness/hooks'))
import command_guard as cg  # noqa: E402

LISTING = ('dropbox: dropbox\nb2-archive: b2\nb2-archive2: b2\nb2-other: b2\nB2-Archive: b2\nbackup-sftp: sftp\n'
           'local-crypt: crypt\n')


class Verifier:
    def __init__(self, types):
        self._types = types

    def remote_types(self):
        return self._types


def check(remote, types=None, policy=None):
    cg._check_remote(remote, policy or cg.load_policy('/nonexistent'), Verifier(types if types is not None else {
        'dropbox': 'dropbox', 'b2-archive': 'b2', 'b2-archive2': 'b2', 'b2-other': 'b2', 'B2-Archive': 'b2',
        'backup-sftp': 'sftp'}))


class B2Archive(unittest.TestCase):
    def test_b2_archive_is_accepted(self):
        check('b2-archive:bucket/claude-logs/2026')
        check('b2-archive:')

    def test_dropbox_is_still_accepted(self):
        check('dropbox:backups/claude')

    def test_other_b2_remotes_are_refused_by_name(self):
        for remote in ('b2-archive2:bucket/x', 'b2-other:bucket/x', 'B2-Archive:bucket/x', 'b2-archiv:bucket/x',
                       'xb2-archive:bucket/x'):
            with self.subTest(remote=remote), self.assertRaises(ValueError):
                check(remote)

    def test_the_name_without_a_b2_type_is_refused(self):
        with self.assertRaises(ValueError):
            check('b2-archive:bucket/x', {'b2-archive': 'sftp'})
        with self.assertRaises(ValueError):
            check('b2-archive:bucket/x', {'b2-archive': 'local'})
        with self.assertRaises(ValueError):
            check('b2-archive:bucket/x', {})  # not configured at all

    def test_other_types_stay_refused(self):
        for remote in ('backup-sftp:x', 'local-crypt:x'):
            with self.subTest(remote=remote), self.assertRaises(ValueError):
                check(remote, {'backup-sftp': 'sftp', 'local-crypt': 'crypt'})

    def test_local_paths_and_on_the_fly_backends_are_refused(self):
        for remote in ('/Users/eric/backup', '~/backup', './b2-archive:x', ':b2:bucket/x', ':b2,account=a:bucket',
                       'b2-archive,account=a:bucket', 'b2-archive', ':local:/tmp/x'):
            with self.subTest(remote=remote), self.assertRaises(ValueError):
                check(remote)

    def test_a_policy_file_cannot_add_a_type_or_a_name(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'command_guard_policy.json'
            path.write_text(json.dumps({'marker': {'approve_remote_types': ['dropbox', 'sftp', 'b2'],
                                                   'approve_remote_names': {'b2': ['b2-archive2'], 'sftp': ['backup-sftp']}},
                                        'approve_remote_types': ['sftp'],
                                        'approve_remote_names': {'b2': ['b2-archive2']}}))
            policy = cg.load_policy(path)
        for remote in ('backup-sftp:x', 'b2-archive2:bucket/x'):
            with self.subTest(remote=remote), self.assertRaises(ValueError):
                check(remote, policy=policy)
        check('b2-archive:bucket/x', policy=policy)

    def test_remote_types_come_from_listremotes_not_the_config_file(self):
        calls = []

        def runner(argv):
            calls.append(argv)
            return 0, LISTING.encode()

        found = cg.RcloneVerifier(runner=runner).remote_types()
        self.assertEqual(calls, [['rclone', 'listremotes', '--long']])
        self.assertEqual(found['b2-archive'], 'b2')
        self.assertEqual(found['b2-archive2'], 'b2')
        check('b2-archive:x', found)
        with self.assertRaises(ValueError):
            check('b2-archive2:x', found)


# ---------------------------------------------------------------------------------------------------------------
# One rule, many descriptions (PR 356 review F1/F2). The accepted remotes are described in guidance strings, a refusal
# message, a CLI help text, the README and docs/operations.md; these tests fail when one of them says "Dropbox" without
# the b2-archive route, so the descriptions cannot drift apart again.

TOPIC = ('approve', 'back up', 'backup', 'remote', 'verified copy')
EXEMPT = (  # strings about Dropbox for another reason: hashing, the access check, a log-backup feature, identifiers
    'content_hash', 'first of dropbox', 'rclone lsd dropbox', 'user-run-store', 'recreated by `git clone`',
    'needs no Dropbox backup',
)


class OperatorStrings(unittest.TestCase):
    def test_every_guard_string_that_names_the_accepted_remotes_names_b2_archive(self):
        tree = ast.parse((ROOT / 'harness/hooks/command_guard.py').read_text())
        drifted = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                text = node.value
                folded = text.casefold()
                if 'dropbox' in folded and folded != 'dropbox' and any(t in folded for t in TOPIC) \
                        and 'b2-archive' not in folded and not any(e.casefold() in folded for e in EXEMPT):
                    drifted.append((node.lineno, text[:90]))
        self.assertEqual(drifted, [], 'a guard string describes the accepted remotes as Dropbox only')

    def test_the_refusal_text_carries_the_route_and_an_example(self):
        self.assertIn('b2-archive', cg.APPROVE_REMOTES)
        with self.assertRaises(ValueError) as caught:
            cg._check_remote('/Users/eric/x', cg.load_policy('/nonexistent'), Verifier({}))
        self.assertIn('b2-archive:', str(caught.exception))
        self.assertIn('dropbox:backups/claude', str(caught.exception))

    def test_readme_and_operations_doc_describe_both_remotes(self):
        for rel in ('README.md', 'docs/operations.md'):
            drifted = []
            for number, line in enumerate((ROOT / rel).read_text().splitlines(), 1):
                folded = line.casefold()
                if line.startswith(('python3 ', '  --')):  # command examples; the b2-archive examples are required below
                    continue
                if 'ah-mac-mini' in folded:  # the separate remote_delete route, which keeps its own Dropbox archive check
                    continue
                if 'dropbox' in folded and 'b2-archive' not in folded and (
                        'approve-delete' in folded or 'named remote' in folded or 'named `dropbox`' in folded
                        or 'verified dropbox' in folded):
                    drifted.append((number, line[:100]))
            self.assertEqual(drifted, [], rel)
        text = (ROOT / 'docs/operations.md').read_text()
        self.assertIn('approve-delete --path <literal path> --remote b2-archive:', text)

    def test_the_archive_example_in_the_doc_names_the_b2_remote_too(self):
        text = (ROOT / 'docs/operations.md').read_text()
        self.assertIn('--archive b2-archive:', text)


class ArchivePath(unittest.TestCase):
    """F2: --archive, --archive-sha256 and --archive-listing are three remotes; one wrong-name b2 among them refuses."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        self.target = self.home / '.claude/projects/old-tree'
        (self.target / 'sub').mkdir(parents=True)
        (self.target / 'sub/a.jsonl').write_text('x\n')
        past = time.time() - 3600
        for p in (self.target / 'sub/a.jsonl', self.target / 'sub', self.target):
            os.utime(p, (past, past))
        self.types = {'b2-archive': 'b2', 'b2-archive2': 'b2', 'dropbox': 'dropbox'}

    def approve(self, archive, sha, listing):
        return cg.approve_delete(str(self.target), archive, verifier=Verifier(self.types), home=str(self.home),
                                 policy=cg.load_policy('/nonexistent'), archive=[sha, listing])

    def test_one_wrong_name_b2_remote_among_the_three_refuses(self):
        suffixes = ('.tar.zst', '.tar.zst.sha256', '.tar.listing.txt')
        for position in range(3):
            remotes = ['b2-archive:bucket/t' + s for s in suffixes]
            remotes[position] = 'b2-archive2:bucket/t' + suffixes[position]
            with self.subTest(position=position), self.assertRaises(ValueError) as caught:
                self.approve(*remotes)
            self.assertIn('b2-archive2', str(caught.exception))

    def test_all_three_remotes_pass_the_remote_check_when_each_is_b2_archive_or_dropbox(self):
        for remotes in (('b2-archive:b/t.tar.zst', 'b2-archive:b/t.sha256', 'b2-archive:b/t.txt'),
                        ('dropbox:b/t.tar.zst', 'b2-archive:b/t.sha256', 'dropbox:b/t.txt')):
            for remote in remotes:
                check(remote)


if __name__ == '__main__':
    unittest.main()
