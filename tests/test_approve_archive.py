"""approve-delete --archive (goodqa#15068): a tree backed up as one remote tar archive plus its .sha256 and listing.

The guard reads the archive itself (streamed, never extracted), checks its sha256 against the .sha256 file, and
requires the regular-file set (path, size, content sha256) to equal both the listing and the local tree. Remotes are
an in-memory store; no rclone or network is used except the optional real-zstd case.
"""
import hashlib
import io
import os
import shutil
import sys
import tarfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_command_guard import Fixture, cg  # noqa: E402

ARCHIVE = 'dropbox:archives/T.tar.gz'
SHA = 'dropbox:archives/T.tar.gz.sha256'
LISTING = 'dropbox:archives/T.tar.listing.txt'
FILES = {'sub/a.jsonl': b'transcript A\n', 'b.txt': b'bee\n', '.git': b'gitdir: /elsewhere\n'}


def build_tar(root_name, files, mode='w:gz', extra=None):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode=mode) as tar:
        for rel, data in list(files.items()) + list((extra or {}).items()):
            info = tarfile.TarInfo('%s/%s' % (root_name, rel) if not rel.startswith(('/', '..')) else rel)
            info.size, info.mtime = len(data), 1700000000
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def listing_for(root_name, files):
    """bsdtar `tar -tvf` style lines, as the pp407 archive script writes them."""
    lines = ['drwxr-xr-x  0 eric   staff       0 Nov  7 07:03 %s/' % root_name]
    for rel, data in files.items():
        lines.append('-rw-r--r--  0 eric   staff %7d Nov  7 07:03 %s/%s' % (len(data), root_name, rel))
    return ('\n'.join(lines) + '\n').encode()


class Store:
    def __init__(self, kinds=None):
        self.objects, self.kinds, self.opened = {}, kinds or {'dropbox': 'dropbox'}, []

    def remote_types(self):
        return dict(self.kinds)

    def open(self, remote):
        self.opened.append(remote)
        if remote not in self.objects:
            return io.BytesIO(b''), (lambda: 3)  # rclone cat exits 3 for a missing object
        return io.BytesIO(self.objects[remote]), (lambda: 0)


class ArchiveApproval(Fixture):
    def setUp(self):
        self.target = self.home / '.claude/projects' / ('old-%d' % time.monotonic_ns())
        for rel, data in FILES.items():
            p = self.target / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(data)
        past = time.time() - 3600
        for p in sorted(self.target.rglob('*'), reverse=True) + [self.target]:
            os.utime(p, (past, past))
        self.name = self.target.name
        self.store = Store()
        self.put(build_tar(self.name, FILES), listing_for(self.name, FILES))

    def put(self, archive, listing, sha=None):
        self.store.objects[ARCHIVE] = archive
        self.store.objects[SHA] = ('%s  T.tar.gz\n' % (sha or hashlib.sha256(archive).hexdigest())).encode()
        self.store.objects[LISTING] = listing

    def approve(self, archive=ARCHIVE, **kw):
        verifier = cg.ArchiveVerifier(SHA, LISTING, opener=self.store.open, types=self.store.remote_types)
        return cg.approve_delete(str(self.target), archive, verifier=verifier, home=str(self.home),
                                 policy=self.policy, archive=(SHA, LISTING), **kw)

    def refused(self, fragment):
        with self.assertRaises(ValueError) as caught:
            self.approve()
        self.assertIn(fragment, str(caught.exception))
        self.assertFalse(cg.marker_covers(str(self.target), home=str(self.home)))

    def test_a_verified_archive_approves_and_the_receipt_names_it(self):
        entry = self.approve()
        self.assertEqual(entry['remote'], ARCHIVE)
        self.assertEqual(entry['archive'], ARCHIVE)
        self.assertEqual(entry['archive_sha256'], hashlib.sha256(self.store.objects[ARCHIVE]).hexdigest())
        self.assertEqual(entry['archive_listing'], LISTING)
        self.assertEqual(entry['files'], len(FILES))
        self.assertTrue(cg.marker_covers(str(self.target), home=str(self.home)))
        audit = (cg.state_dir(str(self.home)) / cg.AUDIT_NAME).read_text()
        self.assertIn(ARCHIVE, audit.splitlines()[-1])
        self.assertIn(entry['archive_sha256'], audit.splitlines()[-1])

    def test_a_truncated_archive_is_refused(self):
        whole = self.store.objects[ARCHIVE]
        cut = whole[: len(whole) // 2]
        self.put(cut, listing_for(self.name, FILES))  # its .sha256 matches the cut bytes: only the tar can tell
        self.refused('archive')

    def test_a_listing_missing_one_file_is_refused(self):
        short = dict(FILES)
        short.pop('b.txt')
        self.put(self.store.objects[ARCHIVE], listing_for(self.name, short))
        self.refused('listing')

    def test_a_sha256_mismatch_is_refused(self):
        self.put(self.store.objects[ARCHIVE], listing_for(self.name, FILES), sha='0' * 64)
        self.refused('sha256')

    def test_an_archive_with_different_content_is_refused(self):
        changed = dict(FILES, **{'b.txt': b'BEE\n'})  # same path and size, other bytes; the listing agrees with it
        self.put(build_tar(self.name, changed), listing_for(self.name, changed))
        self.refused('content')

    def test_an_archive_missing_a_local_file_is_refused(self):
        short = dict(FILES)
        short.pop('b.txt')
        self.put(build_tar(self.name, short), listing_for(self.name, short))
        self.refused('local')

    def test_unsafe_member_names_are_refused(self):
        self.put(build_tar(self.name, FILES, extra={'../escape': b'x'}), listing_for(self.name, FILES))
        self.refused('unsafe')

    def test_a_missing_sha_file_or_listing_is_refused(self):
        del self.store.objects[SHA]
        self.refused('sha256')

    def test_archive_remotes_must_be_allowed_backends(self):
        self.store.kinds = {'dropbox': 'local'}
        self.refused('backend type')

    def test_a_malformed_sha_file_is_refused(self):
        self.store.objects[SHA] = b'not a digest\n'
        self.refused('sha256')

    @unittest.skipUnless(shutil.which('zstd'), 'zstd not installed')
    def test_a_real_zstd_archive_is_read_through_zstd(self):
        import subprocess
        plain = build_tar(self.name, FILES, mode='w')
        packed = subprocess.run(['zstd', '-q', '-c'], input=plain, stdout=subprocess.PIPE, check=True).stdout
        zst = ARCHIVE.replace('.tar.gz', '.tar.zst')
        self.store.objects[zst] = packed
        self.store.objects[SHA] = ('%s  T.tar.zst\n' % hashlib.sha256(packed).hexdigest()).encode()
        self.store.objects[LISTING] = listing_for(self.name, FILES)
        entry = self.approve(archive=zst)
        self.assertEqual(entry['archive'], zst)
        self.store.objects[zst] = packed[: len(packed) - 40]  # truncated stream: zstd itself fails
        self.store.objects[SHA] = ('%s  T.tar.zst\n' % hashlib.sha256(self.store.objects[zst]).hexdigest()).encode()
        with self.assertRaises(ValueError):
            self.approve(archive=zst)


class ArchiveCli(Fixture):
    def test_archive_needs_its_sha_and_listing(self):
        import contextlib
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = cg.main(['approve-delete', '--path', str(self.home / 'x'), '--archive', ARCHIVE, '--wal',
                            str(self.home / 'w.jsonl')])
        self.assertEqual(code, 2)
        self.assertIn('--archive-sha256', err.getvalue())


if __name__ == '__main__':
    unittest.main()
