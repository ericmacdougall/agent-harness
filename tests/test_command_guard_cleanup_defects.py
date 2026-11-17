"""goodqa#16374 AC-3 (a-d): guard defects found during the Mac cleanup (goodqa#16355, goodqa#16362).

(a) approve-delete accepts a tree holding symlinks when every local link is an archive link member with the same
    target string, and nothing else; (b) a single-file path expects the member `<name>`; (c) a unit over 20 GiB is
    approvable under the default policy; (d) a lone literal move of a secret-named file into a real 0700
    ~/secret-quarantine passes the hook. Every relaxation keeps its negative cases.
"""
import hashlib
import io
import os
import sys
import tarfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_command_guard import Fixture, cg  # noqa: E402
from test_approve_archive import ARCHIVE, LISTING, SHA, Store, listing_for  # noqa: E402

PAST = time.time() - 3600


def age(root):
    """Set every entry (links too, without following them) an hour into the past."""
    root = Path(root)
    entries = [root] if not root.is_dir() or root.is_symlink() else sorted(root.rglob('*'), reverse=True) + [root]
    for p in entries:
        os.utime(str(p), (PAST, PAST), follow_symlinks=False)


def tar_of(members, mode='w:gz'):
    """members: [(name, 'f', bytes) | (name, 'l', target) | (name, 'd', None)]"""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode=mode) as tar:
        for name, kind, value in members:
            info = tarfile.TarInfo(name)
            info.mtime = 1700000000
            if kind == 'f':
                info.size = len(value)
                tar.addfile(info, io.BytesIO(value))
            elif kind == 'l':
                info.type, info.linkname = tarfile.SYMTYPE, value
                tar.addfile(info)
            else:
                info.type = tarfile.DIRTYPE
                tar.addfile(info)
    return buf.getvalue()


class _Archive(Fixture):
    def put(self, archive, listing):
        self.store.objects[ARCHIVE] = archive
        self.store.objects[SHA] = ('%s  T.tar.gz\n' % hashlib.sha256(archive).hexdigest()).encode()
        self.store.objects[LISTING] = listing

    def approve(self):
        verifier = cg.ArchiveVerifier(SHA, LISTING, opener=self.store.open, types=self.store.remote_types)
        return cg.approve_delete(str(self.target), ARCHIVE, verifier=verifier, home=str(self.home),
                                 policy=self.policy, archive=(SHA, LISTING))

    def refused(self, fragment):
        with self.assertRaises(ValueError) as caught:
            self.approve()
        self.assertIn(fragment, str(caught.exception))
        self.assertFalse(cg.marker_covers(str(self.target), home=str(self.home)))


class SymlinkTrees(_Archive):
    """AC-3a / NEG-8: links are compared as (path, target string), never followed."""

    def setUp(self):
        self.target = self.home / '.agent-harness/work/S' / ('links-%d' % time.monotonic_ns())
        (self.target / 'sub').mkdir(parents=True)
        (self.target / 'b.txt').write_bytes(b'bee\n')
        (self.target / 'sub/c.txt').write_bytes(b'sea\n')
        os.symlink('b.txt', str(self.target / 'alias'))           # file link
        os.symlink('sub', str(self.target / 'dirlink'))           # directory link (os.walk lists it as a dir)
        os.symlink('/nonexistent/outside', str(self.target / 'dangling'))
        age(self.target)
        self.name = self.target.name
        self.store = Store()
        self.files = {'b.txt': b'bee\n', 'sub/c.txt': b'sea\n'}
        self.links = {'alias': 'b.txt', 'dirlink': 'sub', 'dangling': '/nonexistent/outside'}

    def members(self, files=None, links=None):
        n = self.name
        out = [(n, 'd', None), (n + '/sub', 'd', None)]
        out += [('%s/%s' % (n, rel), 'f', data) for rel, data in (files or self.files).items()]
        out += [('%s/%s' % (n, rel), 'l', target) for rel, target in (self.links if links is None else links).items()]
        return out

    def test_a_tree_with_matching_symlink_members_is_approved(self):
        self.put(tar_of(self.members()), listing_for(self.name, self.files))
        entry = self.approve()
        self.assertEqual(entry['files'], len(self.files))
        self.assertTrue(cg.marker_covers(str(self.target), home=str(self.home)))

    def test_a_link_member_with_another_target_is_refused(self):
        self.put(tar_of(self.members(links=dict(self.links, alias='sub/c.txt'))), listing_for(self.name, self.files))
        self.refused('link')

    def test_a_local_link_missing_from_the_archive_is_refused(self):
        links = dict(self.links)
        links.pop('dirlink')
        self.put(tar_of(self.members(links=links)), listing_for(self.name, self.files))
        self.refused('link')

    def test_an_archive_link_with_no_local_link_is_refused(self):
        self.put(tar_of(self.members(links=dict(self.links, extra='b.txt'))), listing_for(self.name, self.files))
        self.refused('link')

    def test_a_link_retargeted_after_approval_voids_the_approval(self):
        self.put(tar_of(self.members()), listing_for(self.name, self.files))
        self.approve()
        os.unlink(str(self.target / 'alias'))
        os.symlink('sub/c.txt', str(self.target / 'alias'))
        age(self.target)  # same mtimes as before: only the link target differs
        self.assertFalse(cg.marker_covers(str(self.target), home=str(self.home)))


class SingleFileArchive(_Archive):
    """AC-3b / NEG-9: a single file is stored as the member `<name>`, as `tar -C parent -cf - name` writes it."""

    def setUp(self):
        folder = self.home / '.agent-harness/work/S' / ('single-%d' % time.monotonic_ns())
        folder.mkdir(parents=True)
        self.target = folder / 'bundle.tgz'
        self.data = b'one file\n' * 100
        self.target.write_bytes(self.data)
        age(self.target)
        self.store = Store()

    def listing(self, name):
        return ('-rw-r--r--  0 eric   staff %7d Nov  7 07:03 %s\n' % (len(self.data), name)).encode()

    def test_a_single_file_archive_with_the_basename_member_is_approved(self):
        self.put(tar_of([('bundle.tgz', 'f', self.data)]), self.listing('bundle.tgz'))
        entry = self.approve()
        self.assertEqual(entry['files'], 1)

    def test_a_nested_name_member_is_refused(self):
        self.put(tar_of([('bundle.tgz/bundle.tgz', 'f', self.data)]), self.listing('bundle.tgz/bundle.tgz'))
        self.refused('differ')

    def test_a_single_file_archive_with_other_content_is_refused(self):
        other = b'One file\n' * 100
        self.put(tar_of([('bundle.tgz', 'f', other)]), self.listing('bundle.tgz'))
        self.refused('differs')


class _OkVerifier(cg.Verifier):
    def __init__(self):
        self.called = 0

    def remote_types(self):
        return {'dropbox': 'dropbox'}

    def verify(self, local_root, manifest, remote):
        self.called += 1
        return cg.VerifyResult(True, len(manifest))


@unittest.skipUnless(os.environ.get('CG_BIG_TEST') == '1', 'reads a 21 GiB sparse file; set CG_BIG_TEST=1 (t2-dev)')
class LargeUnit(Fixture):
    """AC-3c: a unit over 20 GiB is approvable under the default policy (sparse file, about 0 bytes on disk)."""

    def test_a_21_gib_unit_is_approved(self):
        folder = self.home / '.agent-harness/work/S' / ('big-%d' % time.monotonic_ns())
        folder.mkdir(parents=True)
        big = folder / 'disk.img'
        with open(str(big), 'wb') as handle:
            handle.truncate(21 << 30)
        age(folder)
        verifier = _OkVerifier()
        entry = cg.approve_delete(str(folder), 'dropbox:x/big', verifier=verifier, home=str(self.home),
                                  policy=cg.load_policy(path=str(self.home / 'no-such-policy.json')))
        self.assertEqual(verifier.called, 1)
        self.assertEqual(entry['files'], 1)
        big.unlink()


class LargeUnitLimits(Fixture):
    """AC-3c without the 21 GiB read: the default cap and the archive download limit are above 20 GiB."""

    def test_default_cap_is_above_20_gib(self):
        policy = cg.load_policy(path=str(self.home / 'no-such-policy.json'))
        self.assertGreater(int(policy['marker']['max_hash_bytes']), 20 << 30)

    def test_archive_limit_follows_the_policy(self):
        policy = cg.load_policy(path=str(self.home / 'no-such-policy.json'))
        verifier = cg.ArchiveVerifier(SHA, LISTING, policy=policy, opener=Store().open, types=Store().remote_types)
        self.assertGreaterEqual(verifier.limit, int(policy['marker']['max_hash_bytes']))


class SecretQuarantine(Fixture):
    """AC-3d / NEG-10: a lone literal move of a secret-named file into a real 0700 ~/secret-quarantine."""

    def setUp(self):
        self.unit = self.home / '.agent-harness/work/S' / ('unit-%d' % time.monotonic_ns())
        self.unit.mkdir(parents=True)
        for name in ('.npmrc', 'server.key', '.env.local', 'notes.md', 'main.jsonl'):
            (self.unit / name).write_text('x\n')
        (self.unit / 'creds').mkdir()
        (self.unit / 'creds/credentials.json').write_text('{}\n')
        os.symlink('.npmrc', str(self.unit / 'id_rsa'))
        self.q = self.home / 'secret-quarantine'
        self.q.mkdir(mode=0o700, exist_ok=True)
        os.chmod(str(self.q), 0o700)
        self.dest = self.q / self.unit.name
        self.dest.mkdir(exist_ok=True)

    def mv(self, src, dest=None, flags='-n '):
        dest = dest or str(self.dest / os.path.basename(src))
        return self.decide('mv %s%s %s' % (flags, src, dest))[0]

    def test_secret_named_files_move_into_the_quarantine(self):
        for name in ('.npmrc', 'server.key', '.env.local'):
            with self.subTest(name=name):
                self.assertEqual(self.mv(str(self.unit / name)), 'allow')
        self.assertEqual(self.mv(str(self.unit / '.npmrc'), flags='-n -- '), 'allow')
        self.assertEqual(self.mv(str(self.unit / 'creds/credentials.json')), 'allow')

    def test_the_move_needs_no_clobber_and_keeps_the_name(self):
        # red-team r1 findings 12 and 13: without -n a file created at DEST between the check and the move is
        # overwritten; a new name (.env -> notes.txt) would launder the credential-read block
        src = str(self.unit / '.npmrc')
        self.assertEqual(self.mv(src, flags=''), 'block')
        self.assertEqual(self.mv(src, flags='-- '), 'block')
        for name in ('notes.txt', 'npmrc', '.npmrc.bak'):
            with self.subTest(name=name):
                self.assertEqual(self.mv(src, dest=str(self.dest / name)), 'block')

    def test_the_quarantine_is_a_credential_dir(self):
        # red-team r1 finding 12: ~/secret-quarantine joins credential_dirs, so recursive and find-exec readers of it
        # are credential reads too
        for command in ('cat %s' % (self.dest / '.npmrc'), 'grep -r token %s' % self.q,
                        'find %s -type f -exec cat {} +' % self.q):
            with self.subTest(command=command):
                self.assertEqual(self.decide(command)[0], 'block')

    def test_non_secret_and_log_names_stay_blocked(self):
        for name in ('notes.md', 'main.jsonl'):
            with self.subTest(name=name):
                self.assertEqual(self.mv(str(self.unit / name)), 'block')

    def test_directories_and_symlinks_stay_blocked(self):
        self.assertEqual(self.mv(str(self.unit / 'creds'), dest=str(self.dest / 'creds')), 'block')
        self.assertEqual(self.mv(str(self.unit / 'id_rsa')), 'block')

    def test_bad_destinations_stay_blocked(self):
        src = str(self.unit / '.npmrc')
        (self.dest / 'taken').write_text('x\n')
        for dest in (str(self.dest / 'taken'),                              # overwrite
                     str(self.dest) + '/../../.agent-harness/x.npmrc',      # climbs out
                     str(self.home / 'elsewhere/.npmrc'),                   # not the quarantine
                     str(self.dest)):                                       # an existing directory
            with self.subTest(dest=dest):
                self.assertEqual(self.mv(src, dest=dest), 'block')

    def test_compound_commands_stay_blocked(self):
        src = str(self.unit / '.npmrc')
        verdict, _ = self.decide('mv %s %s; true' % (src, self.dest / '.npmrc'))
        self.assertEqual(verdict, 'block')
        verdict, _ = self.decide('cd /tmp && mv %s %s' % (src, self.dest / '.npmrc'))
        self.assertEqual(verdict, 'block')

    def test_an_open_or_linked_quarantine_stays_blocked(self):
        src = str(self.unit / '.npmrc')
        os.chmod(str(self.q), 0o755)
        try:
            self.assertEqual(self.mv(src), 'block')
        finally:
            os.chmod(str(self.q), 0o700)
        real = self.home / 'q-real'
        real.mkdir(mode=0o700, exist_ok=True)
        os.rename(str(self.q), str(self.home / 'q-saved'))
        os.symlink(str(real), str(self.q))
        try:
            (real / self.unit.name).mkdir(exist_ok=True)
            self.assertEqual(self.mv(src), 'block')
        finally:
            os.unlink(str(self.q))
            os.rename(str(self.home / 'q-saved'), str(self.q))


if __name__ == '__main__':
    unittest.main()
