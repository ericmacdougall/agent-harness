"""approve-delete accepts a verified copy on Eric's B2 remote, pinned by NAME (supervisor standing authority, rule 4:
"verified copy on b2-archive or Dropbox"). A b2-type remote is accepted only when it is called b2-archive; the type
alone never approves. The list is built in: no policy file can widen it. Remote lists come from `rclone listremotes
--long` (names and types), never from reading rclone.conf."""

import json
import sys
import tempfile
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


if __name__ == '__main__':
    unittest.main()
