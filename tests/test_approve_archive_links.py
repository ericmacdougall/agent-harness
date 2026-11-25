"""Archive approvals compare literal symlink metadata without following it."""
import hashlib
import os
import subprocess
import tarfile
import time
import unittest

import test_approve_archive as archive_tests
from test_approve_archive import FILES, build_members, listing_for
from test_command_guard import Fixture, cg


class ArchiveLinks(Fixture):
    setUp = archive_tests.ArchiveApproval.setUp
    put = archive_tests.ArchiveApproval.put
    approve = archive_tests.ArchiveApproval.approve
    refused = archive_tests.ArchiveApproval.refused

    def links(self, links):
        past = time.time() - 3600
        for name, target in links.items():
            path = self.target / name
            path.parent.mkdir(parents=True, exist_ok=True)
            os.symlink(target, path)
            os.utime(path, (past, past), follow_symlinks=False)
        for root, dirs, files in os.walk(self.target):
            os.utime(root, (past, past))

    def listing(self, links, style='gnu'):
        text = listing_for(self.name, FILES).decode()
        for name, target in links.items():
            if style == 'gnu':
                text += 'lrwxrwxrwx eric/staff 0 2026-11-01 12:00 %s/%s -> %s\n' % (self.name, name, target)
            else:
                text += 'lrwxrwxrwx 0 eric staff 0 Nov 1 12:00 %s/%s -> %s\n' % (self.name, name, target)
        return text.encode()

    def archive(self, links, extras=()):
        return build_members(self.name, FILES,
                             [(name, tarfile.SYMTYPE, target) for name, target in links.items()] + list(extras))

    def test_relative_dangling_absolute_parent_and_directory_links_roundtrip(self):
        links = {'alias': 'b.txt', 'dangling': 'missing', 'absolute': '/not-a-real-external-target',
                 'parent': '../../outside', 'directory': 'sub'}
        self.links(links)
        archive = self.archive(links)
        for style in ('gnu', 'bsd'):
            with self.subTest(style=style):
                self.put(archive, self.listing(links, style))
                entry = self.approve()
                self.assertEqual(entry['files'], len(FILES) + len(links))
                self.assertTrue(cg.marker_covers(str(self.target), home=str(self.home)))
        manifest = dict((name, (size, value)) for name, size, value in
                        cg.tree_manifest(str(self.target), self.policy['marker'], include_links=True))
        for name, target in links.items():
            self.assertEqual(manifest[name], (-1, hashlib.sha256(os.fsencode(target)).hexdigest()))
        archive_path = self.home / 'roundtrip.tar.gz'
        archive_path.write_bytes(archive)
        restored = self.home / 'restore'
        restored.mkdir()
        subprocess.run(['tar', '-xf', str(archive_path), '-C', str(restored)], check=True,
                       capture_output=True)
        for name, target in links.items():
            self.assertEqual(os.readlink(restored / self.name / name), target)

    def test_file_and_link_type_substitution_is_rejected(self):
        self.links({'alias': 'b.txt'})
        wrong = build_members(self.name, dict(FILES, alias=b'b.txt'), [])
        self.put(wrong, listing_for(self.name, dict(FILES, alias=b'b.txt')))
        self.refused('content differs')
        wrong_files = dict(FILES)
        del wrong_files['b.txt']
        wrong = build_members(self.name, wrong_files, [('b.txt', tarfile.SYMTYPE, 'sub/a.jsonl'),
                                                     ('alias', tarfile.SYMTYPE, 'b.txt')])
        self.put(wrong, listing_for(self.name, wrong_files) +
                 ('lrwxrwxrwx eric/staff 0 2026-11-01 12:00 %s/b.txt -> sub/a.jsonl\n'
                  'lrwxrwxrwx eric/staff 0 2026-11-01 12:00 %s/alias -> b.txt\n' % (self.name, self.name)).encode())
        self.refused('content differs')

    def test_target_mismatch_and_listing_target_mismatch_are_rejected(self):
        self.links({'alias': 'b.txt'})
        self.put(self.archive({'alias': 'c.txt'}), self.listing({'alias': 'c.txt'}))
        self.refused('content differs')
        self.put(self.archive({'alias': 'b.txt'}), self.listing({'alias': 'c.txt'}))
        self.refused('listing does not match')

    def test_same_size_and_mtime_link_retarget_invalidates_approval(self):
        self.links({'alias': 'b.txt'})
        self.put(self.archive({'alias': 'b.txt'}), self.listing({'alias': 'b.txt'}))
        self.approve()
        link = self.target / 'alias'
        before = link.lstat()
        link.unlink()
        os.symlink('c.txt', link)
        os.utime(link, ns=(before.st_atime_ns, before.st_mtime_ns), follow_symlinks=False)
        self.assertEqual(link.lstat().st_size, before.st_size)
        self.assertEqual(link.lstat().st_mtime_ns, before.st_mtime_ns)
        self.assertFalse(cg.marker_covers(str(self.target), home=str(self.home)))

    def test_members_cannot_descend_through_links_in_either_order_or_alias(self):
        self.links({'alias': '../../outside', 'caf\N{LATIN SMALL LETTER E WITH ACUTE}': 'sub'})
        base = [('alias', tarfile.SYMTYPE, '../../outside'),
                ('caf\N{LATIN SMALL LETTER E WITH ACUTE}', tarfile.SYMTYPE, 'sub')]
        for child in ('alias/child', 'ALIAS/./child', 'cafe\N{COMBINING ACUTE ACCENT}/child'):
            for first in (True, False):
                with self.subTest(child=child, first=first):
                    item = [(child, tarfile.REGTYPE, b'not written outside')]
                    members = item + base if first else base + item
                    self.put(build_members(self.name, FILES, members),
                             self.listing({'alias': '../../outside', 'caf\N{LATIN SMALL LETTER E WITH ACUTE}': 'sub'}))
                    self.refused('descend through a symlink')

    def test_ambiguous_link_listing_is_rejected(self):
        self.links({'alias': 'b.txt'})
        for target in ('b.txt -> c.txt', '"b.txt"', "'b.txt'", 'b\\txt'):
            with self.subTest(target=target):
                self.put(self.archive({'alias': 'b.txt'}), self.listing({'alias': target}))
                self.refused('ambiguous symlink')

    def test_mirror_manifest_still_omits_links_and_budget_is_unchanged(self):
        self.links({'alias': 'b.txt', 'directory': 'sub'})
        manifest = cg.tree_manifest(str(self.target), self.policy['marker'])
        self.assertEqual({name for name, _, _ in manifest}, set(FILES))
        self.assertEqual(cg.DEFAULT_POLICY['marker'].get('max_approve_files', 20000), 20000)
        previous = self.policy['marker'].get('max_approve_files', 20000)
        self.addCleanup(self.policy['marker'].__setitem__, 'max_approve_files', previous)
        self.policy['marker']['max_approve_files'] = 2
        self.put(self.archive({'alias': 'b.txt', 'directory': 'sub'}),
                 self.listing({'alias': 'b.txt', 'directory': 'sub'}))
        self.refused('too large')


if __name__ == '__main__':
    unittest.main()
