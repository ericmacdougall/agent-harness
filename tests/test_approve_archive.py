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


def build_members(root_name, files, specials, mode='w:gz'):
    """A tar of `files` followed by `specials`: (relative name, tarfile type, linkname or data)."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode=mode) as tar:
        for rel, data in files.items():
            info = tarfile.TarInfo('%s/%s' % (root_name, rel))
            info.size, info.mtime = len(data), 1700000000
            tar.addfile(info, io.BytesIO(data))
        for rel, kind, value in specials:
            info = tarfile.TarInfo('%s/%s' % (root_name, rel))
            info.type, info.mtime = kind, 1700000000
            if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE):
                info.linkname = value
                tar.addfile(info)
            elif kind == tarfile.REGTYPE:
                info.size = len(value)
                tar.addfile(info, io.BytesIO(value))
            else:
                tar.addfile(info)
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
        self.refused('truncated')

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

    def test_macos_appledouble_companions_are_metadata_not_files(self):
        # Live batchD-wt (2026-11-07): bsdtar wrote 16,150 `._name` xattr companions that its own -tvf does not list.
        apple = {'._b.txt': b'\x00\x05\x16\x07xattr', 'sub/._a.jsonl': b'\x00\x05\x16\x07xattr'}
        archive = build_tar(self.name, FILES, extra=apple)
        self.put(archive, listing_for(self.name, FILES))
        self.assertEqual(self.approve()['files'], len(FILES))

    def test_a_dot_underscore_file_without_a_sibling_is_still_an_extra_file(self):
        archive = build_tar(self.name, FILES, extra={'._orphan': b'data'})
        self.put(archive, listing_for(self.name, dict(FILES, **{'._orphan': b'data'})))
        self.refused('extra')

    def test_a_failed_upload_left_empty_files_is_refused(self):
        # pp407 review-full first try: no archive stored, .sha256 of empty input, 0-byte listing.
        del self.store.objects[ARCHIVE]
        self.store.objects[SHA] = ('%s  T.tar.gz\n' % hashlib.sha256(b'').hexdigest()).encode()
        self.store.objects[LISTING] = b''
        self.refused('empty input')
        self.store.objects[ARCHIVE] = b''
        self.refused('empty input')

    def test_an_empty_listing_is_refused(self):
        # a failed listing step leaves a 0-byte or directory-only listing behind
        self.put(build_tar(self.name, FILES), b'')
        self.refused('no regular files')
        self.put(build_tar(self.name, FILES), listing_for(self.name, {}))
        self.refused('no regular files')

    def test_an_archive_with_no_regular_members_is_refused(self):
        # approve_delete refuses an empty local tree first; the verifier must refuse on its own as well
        self.put(build_tar(self.name, {}), b'-rw-r--r--  0 eric   staff       0 Nov  7 07:03 x/ignored\n')
        verifier = cg.ArchiveVerifier(SHA, LISTING, opener=self.store.open, types=self.store.remote_types)
        result = verifier.verify(str(self.target), [], ARCHIVE)
        self.assertFalse(result.ok)
        self.assertIn('no regular files', result.error)
        self.assertIsNone(getattr(verifier, 'verified_sha256', None))

    # PR #120 red-team (2026-11-07). Each case below was approved on b0dba6e.
    def test_a_file_changed_while_the_archive_streams_is_refused(self):
        # F1: the delete-time stat check must cover the state the archive was compared with.
        target, plain_open = self.target, self.store.open

        def open_and_append(remote):
            if remote == ARCHIVE:
                with open(target / 'b.txt', 'ab') as handle:
                    handle.write(b'appended while verifying\n')
            return plain_open(remote)
        self.store.open = open_and_append
        self.refused('changed')

    def test_a_second_member_with_the_same_name_is_refused(self):
        # F2: a later link, directory or case-variant member replaces the verified file on restore.
        for specials in ([('b.txt', tarfile.SYMTYPE, 'sub/a.jsonl')],
                         [('b.txt', tarfile.LNKTYPE, '%s/sub/a.jsonl' % self.name)],
                         [('b.txt', tarfile.DIRTYPE, None)],
                         [('B.TXT', tarfile.SYMTYPE, 'sub/a.jsonl')],
                         [('b.txt', tarfile.REGTYPE, b'bee\n')]):
            with self.subTest(specials=specials):
                self.put(build_members(self.name, FILES, specials), listing_for(self.name, FILES))
                self.refused('twice')

    def test_link_and_special_members_are_refused(self):
        # F2/F6: the comparison covers regular files only, so a link member is never trusted.
        for specials in ([('extra-link', tarfile.SYMTYPE, 'b.txt')],
                         [('extra-hard', tarfile.LNKTYPE, '%s/b.txt' % self.name)],
                         [('fifo', tarfile.FIFOTYPE, None)]):
            with self.subTest(specials=specials):
                self.put(build_members(self.name, FILES, specials), listing_for(self.name, FILES))
                self.refused('link or special')

    def test_a_local_symlink_is_refused(self):
        # F6: a symlink in the tree would be deleted but is not part of the compared regular-file set.
        os.symlink('b.txt', str(self.target / 'alias'))
        past = time.time() - 3600
        os.utime(str(self.target / 'alias'), (past, past), follow_symlinks=False)
        os.utime(str(self.target), (past, past))
        self.refused('symlink')

    def test_a_second_gzip_member_is_read_like_bsdtar_reads_it(self):
        # F3: Python r|gz stops after the first gzip member; bsdtar restores the second one too.
        import gzip
        plain = build_tar(self.name, FILES, mode='w')
        body = plain.rstrip(b'\0')
        body += b'\0' * (-len(body) % 512)
        evil = build_members(self.name, {}, [('b.txt', tarfile.REGTYPE, b'EVIL')], mode='w')
        self.put(gzip.compress(body) + gzip.compress(evil), listing_for(self.name, FILES))
        self.refused('twice')

    def test_data_after_the_end_of_the_tar_is_refused(self):
        import gzip
        plain = build_tar(self.name, FILES, mode='w')
        self.put(gzip.compress(plain + b'trailing payload'.ljust(512, b'\0')), listing_for(self.name, FILES))
        self.refused('after the end')

    def test_an_archive_with_far_more_members_than_the_tree_is_refused(self):
        # F4: stream parsing keeps state per member; a header flood must stop early, not exhaust memory.
        specials = [('d%05d' % i, tarfile.DIRTYPE, None) for i in range(3000)]
        self.put(build_members(self.name, FILES, specials), listing_for(self.name, FILES))
        self.refused('more members')

    def test_an_archive_that_inflates_far_beyond_the_tree_is_refused(self):
        specials = [('big.pad', tarfile.REGTYPE, b'\0' * (2 << 20))]
        self.put(build_members(self.name, FILES, specials), listing_for(self.name, FILES))
        verifier = cg.ArchiveVerifier(SHA, LISTING, opener=self.store.open, types=self.store.remote_types)
        verifier.inflate_slack = 1 << 20
        result = verifier.verify(str(self.target), cg.tree_manifest(str(self.target), self.policy['marker']), ARCHIVE)
        self.assertFalse(result.ok)
        self.assertIn('inflates', result.error)

    def test_an_endless_sha_file_stops_at_its_limit(self):
        # F5: the small files are read up to their limit, never drained without end.
        class Endless(io.RawIOBase):
            reads = 0

            def readable(self):
                return True

            def readinto(self, buf):
                Endless.reads += 1
                if Endless.reads > 10000:
                    raise AssertionError('drained an endless stream')
                buf[:len(buf)] = b'a' * len(buf)
                return len(buf)
        plain_open = self.store.open
        self.store.open = lambda remote: ((io.BufferedReader(Endless()), lambda: 0) if remote == SHA
                                          else plain_open(remote))
        self.refused('larger than')

    def test_appledouble_companions_need_the_appledouble_magic(self):
        # F10: a `._name` member is dropped as metadata only when it really is an AppleDouble file.
        archive = build_tar(self.name, FILES, extra={'._b.txt': b'not appledouble'})
        self.put(archive, listing_for(self.name, FILES))
        self.refused('extra')

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

    def test_rclone_environment_overrides_are_refused(self):
        # F7: RCLONE_CONFIG or another RCLONE_* setting could point the verifier at a different store.
        verb = 'approve' + '-delete'
        for prefix in ('RCLONE_CONFIG=/x/rclone.conf', 'export RCLONE_CONFIG_DROPBOX_TYPE=local;'):
            self.assertTrue(cg.approval_env_override('%s python3 command_guard.py %s --path /p' % (prefix, verb)), prefix)

    def test_no_backup_and_archive_together_are_refused(self):
        # F9: the archive flags must not be silently ignored by the no-backup path.
        import contextlib
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = cg.main(['approve-delete', '--path', str(self.home / 'x'), '--no-backup', '--user-source',
                            'answer:s/u', '--archive', ARCHIVE, '--archive-sha256', SHA, '--archive-listing', LISTING,
                            '--wal', str(self.home / 'w.jsonl')])
        self.assertEqual(code, 2)
        self.assertIn('--no-backup', err.getvalue())
        self.assertIn('--archive', err.getvalue())


if __name__ == '__main__':
    unittest.main()
