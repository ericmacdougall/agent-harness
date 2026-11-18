"""goodqa#16374 AC-2: approve-delete --upload trusts Dropbox's server-side content hash instead of a download.

The guard builds the tar stream itself from the files it reads, compresses it with zstd, hashes the exact bytes it
sends with the Dropbox content hash, streams them with `rclone rcat` to a new unique name, then compares Dropbox's
stored hash and size. A fake `rclone` executable stands in for the remote: it stores objects in a folder tree, computes the
Dropbox content hash of what it stored with its own independent implementation (or a wrong one on request) and records
every subcommand, so the tests can prove that nothing is ever downloaded (`cat`, `copy`, `copyto`, `sync`, `check`
never run).
"""
import copy
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import re
import tarfile
import tempfile
import textwrap
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_command_guard import Fixture, cg  # noqa: E402

PAST = time.time() - 3600
FAKE_RCLONE = textwrap.dedent('''\
    #!%(python)s
    import hashlib, json, os, sys
    store = os.environ["FAKE_RCLONE_STORE"]
    argv = sys.argv[1:]
    with open(os.path.join(store, "calls.jsonl"), "a") as log:
        log.write(json.dumps(argv) + "\\n")
    words = [a for a in argv if not a.startswith("-")]
    def obj(remote):
        # Dropbox paths ignore letter case: resolve each part against what exists, on any host file system
        name, _, rest = remote.partition(":")
        path = os.path.join(store, "objects", name)
        for part in [p for p in rest.split("/") if p]:
            match = part
            if os.path.isdir(path):
                for existing in os.listdir(path):
                    if existing.casefold() == part.casefold():
                        match = existing
                        break
            path = os.path.join(path, match)
        return path
    def dbx(path):
        # independent of the guard's DropboxHash: whole 4 MiB blocks read straight from the stored file
        outer = hashlib.sha256()
        with open(path, "rb") as h:
            while True:
                block = h.read(4 << 20)
                if not block:
                    break
                outer.update(hashlib.sha256(block).digest())
        return outer.hexdigest()
    mode_file = os.path.join(store, "mode")
    mode = open(mode_file).read().strip() if os.path.exists(mode_file) else ""
    cmd = words[0] if words else ""
    if cmd == "listremotes":
        print("dropbox:  dropbox"); print("local:    local"); sys.exit(0)
    if cmd == "rcat":
        target = obj(words[-1])
        main_object = not words[-1].endswith(".sha256")
        if mode == "stall" and main_object:
            with open(os.path.join(store, "stall.pid"), "w") as h:
                h.write(str(os.getpid()))
            import time
            time.sleep(120)  # a stall long past the 2 s test deadline; an orphan from a hung run ends by itself
        chunks = []
        with open(os.path.join(store, "received.bin"), "ab") as seen:
            while True:
                chunk = sys.stdin.buffer.read1(65536)
                if not chunk:
                    break
                seen.write(chunk); seen.flush()
                chunks.append(chunk)
        data = b"".join(chunks)
        if mode == "rcat-fail" and main_object:
            sys.exit(5)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "wb") as h:
            h.write(data[:-7] if mode == "truncate" and main_object else data)
        sys.exit(0)
    if cmd == "lsjson":
        path = obj(words[-1])
        if os.path.isfile(path):
            size = os.path.getsize(path) + (1 if mode == "size" else 0)
            print(json.dumps([{"Path": os.path.basename(path), "Name": os.path.basename(path), "Size": size,
                               "IsDir": False}]))
            sys.exit(0)
        if os.path.isdir(path):
            print(json.dumps([{"Path": n, "Name": n, "Size": os.path.getsize(os.path.join(path, n)),
                               "IsDir": os.path.isdir(os.path.join(path, n))} for n in sorted(os.listdir(path))]))
            sys.exit(0)
        sys.stderr.write("directory not found"); sys.exit(3)
    if cmd == "hashsum":
        path = obj(words[-1])
        if mode == "hash-stall":
            import time
            time.sleep(120)
        if mode == "hash-empty":
            sys.exit(0)
        if mode == "hash-garbled":
            print("not a hash"); sys.exit(0)
        if not os.path.isfile(path):
            sys.exit(3)
        value = "0" * 64 if mode == "hash-wrong" else dbx(path)
        print("%%s  %%s" %% (value, os.path.basename(path))); sys.exit(0)
    sys.stderr.write("fake rclone: refused subcommand " + cmd); sys.exit(9)
''')
DOWNLOADS = ('cat', 'copy', 'copyto', 'sync', 'check', 'cryptcheck', 'mount', 'serve', 'move', 'moveto', 'bisync')


def age(root):
    root = Path(root)
    for p in sorted(root.rglob('*'), reverse=True) + [root]:
        os.utime(str(p), (PAST, PAST), follow_symlinks=False)


def expected_members(root):
    """{member name: ('d', None) | ('l', target) | ('f', bytes)} for `tar -C parent -cf - name` of root."""
    root = Path(root)
    base = root.name
    if root.is_file():
        return {base: ('f', root.read_bytes())}
    found = {base: ('d', None)}
    for path in root.rglob('*'):
        name = base + '/' + path.relative_to(root).as_posix()
        if path.is_symlink():
            found[name] = ('l', os.readlink(str(path)))
        elif path.is_dir():
            found[name] = ('d', None)
        else:
            found[name] = ('f', path.read_bytes())
    return found


def stored_members(data):
    """The same map, read independently from the stored .tar.zst bytes (zstd CLI plus tarfile)."""
    plain = subprocess.run(['zstd', '-dc'], input=data, stdout=subprocess.PIPE, check=True).stdout
    found = {}
    with tarfile.open(fileobj=io.BytesIO(plain), mode='r:') as tar:
        for m in tar.getmembers():
            if m.issym():
                found[m.name] = ('l', m.linkname)
            elif m.isdir():
                found[m.name] = ('d', None)
            elif m.isfile():
                found[m.name] = ('f', tar.extractfile(m).read())
            else:
                found[m.name] = ('?', m.type)
    return found


def git(cwd, *args):
    env = dict(os.environ, GIT_AUTHOR_NAME='t', GIT_AUTHOR_EMAIL='t@e', GIT_COMMITTER_NAME='t',
               GIT_COMMITTER_EMAIL='t@e', GIT_CONFIG_GLOBAL='/dev/null', GIT_CONFIG_NOSYSTEM='1')
    subprocess.run(['git', '-C', str(cwd)] + list(args), check=True, env=env, stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL)


class UploadBase(Fixture):
    def setUp(self):
        self.store = Path(tempfile.mkdtemp(prefix='fake-rclone-'))
        self.addCleanup(shutil.rmtree, str(self.store), True)
        self.rclone = self.store / 'rclone'
        self.rclone.write_text(FAKE_RCLONE % {'python': sys.executable})
        self.rclone.chmod(0o755)
        os.environ['FAKE_RCLONE_STORE'] = str(self.store)
        self.addCleanup(os.environ.pop, 'FAKE_RCLONE_STORE', None)
        self.target = self.home / '.agent-harness/work/S' / ('unit-%d' % time.monotonic_ns())
        (self.target / 'sub').mkdir(parents=True)
        (self.target / 'a.bin').write_bytes(os.urandom(5 << 20))  # more than one 4 MiB Dropbox block once packed
        (self.target / 'sub/b.txt').write_text('bee\n' * 1000)
        os.symlink('a.bin', str(self.target / 'alias'))
        (self.target / 'empty').mkdir()
        age(self.target)
        self.remote = 'dropbox:backups/mac/%s.tar.zst' % self.target.name

    def mode(self, value):
        (self.store / 'mode').write_text(value)

    def stored(self, remote):
        name, _, rest = remote.partition(':')
        return self.store.joinpath('objects', name, *rest.split('/'))

    def calls(self):
        path = self.store / 'calls.jsonl'
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def rcats(self):
        return [c for c in self.calls() if c and c[0] == 'rcat']

    def transport(self):
        # one transport per test, so its recorded subcommands show whether any upload ever started
        if getattr(self, '_shared_transport', None) is None:
            self._shared_transport = cg.RcloneUpload(rclone=str(self.rclone), policy=self.policy)
        return self._shared_transport

    def assert_never_uploaded(self):
        # the fake's call log can miss an rcat the guard killed at once; the transport's own record cannot
        self.assertEqual(self.rcats(), [])
        self.assertNotIn('rcat', self.transport().subcommands)

    def approve(self, remote=None, path=None, transport=None, **kw):
        return cg.approve_delete_upload(str(path or self.target), remote or self.remote,
                                        transport=transport or self.transport(), home=str(self.home),
                                        policy=self.policy, **kw)

    def refused(self, fragment, **kw):
        started = time.monotonic()
        with self.assertRaises(ValueError) as caught:
            self.approve(**kw)
        self.assertLess(time.monotonic() - started, 30, 'a refusal must come within its time budget')
        self.assertIn(fragment, str(caught.exception))
        self.assertFalse(cg.marker_covers(str(kw.get('path') or self.target), home=str(self.home)))
        return str(caught.exception)

    def assert_no_download(self):
        for argv in self.calls():
            self.assertNotIn(argv[0], DOWNLOADS, argv)


class UploadApproval(UploadBase):
    def test_matching_server_hash_approves_without_any_download(self):
        entry = self.approve()
        self.assertTrue(cg.marker_covers(str(self.target), home=str(self.home)))
        self.assertEqual(entry['kind'], 'dropbox-upload')
        archive = entry['archive']
        self.assertRegex(archive, '^' + re.escape(self.remote[:-len('.tar.zst')]) + r'\.[0-9a-f]{32}\.tar\.zst$')
        data = self.stored(archive).read_bytes()
        self.assertEqual(entry['dropbox_hash'], cg.DropboxHash.of_bytes(data))
        self.assertEqual(entry['archive_sha256'], hashlib.sha256(data).hexdigest())
        self.assertEqual(entry['archive_bytes'], len(data))
        self.assert_no_download()
        self.assertIn(['hashsum', 'dropbox', '--', archive], [c[:4] for c in self.calls()])
        # the approval records which rclone subcommands ran: the live audit row is the no-download evidence
        self.assertEqual(entry['rclone_subcommands'], ['hashsum dropbox', 'listremotes', 'lsjson', 'rcat'])
        # Codex r3b F4: the stored archive holds exactly the tree (every member, content and link target, the empty
        # directory too) with the `tar -C parent name` layout
        self.assertEqual(stored_members(data), expected_members(self.target))
        sidecar = self.stored(archive + '.sha256')
        self.assertTrue(sidecar.read_text().startswith(entry['archive_sha256']))

    def test_the_approval_records_the_ledger_and_the_index(self):
        entry = self.approve()
        ident = cg._identity(str(self.target))
        row = cg.ledger_lookup(str(self.target), entry['stat_sha256'], ident, home=str(self.home))
        self.assertIsNotNone(row)
        self.assertEqual(row['archive'], entry['archive'])
        self.assertEqual(row['dropbox_hash'], entry['dropbox_hash'])
        self.assertIsNone(cg.ledger_lookup(str(self.target), '0' * 64, ident, home=str(self.home)))
        index = [json.loads(line) for line in (self.home / 'DROPBOX_INDEX.jsonl').read_text().splitlines()]
        self.assertEqual(index[-1]['archive'], entry['archive'])
        self.assertEqual(index[-1]['dropbox_hash'], entry['dropbox_hash'])
        self.assertEqual(index[-1]['kind'], 'dropbox-upload')
        for key in ('path', 'bytes', 'date', 'sha256', 'archive_bytes', 'source', 'verified', 'stat_sha256', 'host'):
            self.assertIn(key, index[-1])
        self.assertFalse(index[-1]['path'].startswith('/'))
        self.assertIn(entry['archive'], (self.home / 'DROPBOX_INDEX.md').read_text())

    def test_the_index_md_keeps_hand_written_sections(self):
        (self.home / 'DROPBOX_INDEX.md').write_text('# What moved to Dropbox\n\n## Hand section\n\nkeep me\n')
        entry = self.approve()
        text = (self.home / 'DROPBOX_INDEX.md').read_text()
        self.assertIn('keep me', text)
        self.assertIn(entry['archive'], text)

    def test_a_forged_ledger_row_does_not_count(self):
        entry = self.approve()
        ledger = self.home / '.agent-harness/state' / cg.LEDGER_NAME
        row = json.loads(ledger.read_text().splitlines()[-1])
        row['stat_sha256'] = 'f' * 64
        with open(str(ledger), 'a') as handle:
            handle.write(json.dumps(row) + '\n')
        ident = cg._identity(str(self.target))
        self.assertIsNone(cg.ledger_lookup(str(self.target), 'f' * 64, ident, home=str(self.home)))
        self.assertIsNotNone(cg.ledger_lookup(str(self.target), entry['stat_sha256'], ident, home=str(self.home)))

    def test_a_backup_covers_only_the_same_unaltered_unit(self):
        # Codex r5 F3: a same-length edit with its mtime restored, a replaced child file and a whole unit replaced
        # at the same path each void the ledger row
        entry = self.approve()
        limits = self.policy['marker']
        target = str(self.target)
        ident = cg._identity(target)
        self.assertEqual(cg.stat_manifest(target, limits), entry['stat_sha256'])
        b = self.target / 'sub/b.txt'
        st = os.lstat(str(b))
        b.write_text('BEE\n' * 1000)  # same length
        os.utime(str(b), ns=(st.st_atime_ns, st.st_mtime_ns))
        self.assertNotEqual(cg.stat_manifest(target, limits), entry['stat_sha256'])
        self.assertIsNone(cg.ledger_lookup(target, cg.stat_manifest(target, limits), ident, home=str(self.home)))
        # a child replaced by a copy (new inode, same bytes, same mtime)
        fresh = self.target / 'sub/b.new'
        shutil.copy2(str(b), str(fresh))
        os.replace(str(fresh), str(b))
        os.utime(str(b), ns=(st.st_atime_ns, st.st_mtime_ns))
        self.assertNotEqual(cg.stat_manifest(target, limits), entry['stat_sha256'])
        # the whole unit replaced at the same path
        moved = self.target.with_name(self.target.name + '-old')
        os.rename(target, str(moved))
        shutil.copytree(str(moved), target, symlinks=True, copy_function=shutil.copy2)
        self.assertNotEqual(tuple(cg._identity(target)), tuple(ident))
        self.assertIsNone(cg.ledger_lookup(target, entry['stat_sha256'], cg._identity(target), home=str(self.home)))

    def test_a_single_file_is_stored_as_its_basename(self):
        entry = self.approve(remote='dropbox:backups/mac/a.bin.tar.zst', path=self.target / 'a.bin')
        self.assertEqual(stored_members(self.stored(entry['archive']).read_bytes()),
                         expected_members(self.target / 'a.bin'))

    def repo(self, files, pushed=True):
        repo = self.target / 'repo'
        for rel, text in files.items():
            (repo / rel).parent.mkdir(parents=True, exist_ok=True)
            (repo / rel).write_text(text)
        git(repo, 'init', '-q', '-b', 'main')
        git(repo, 'add', '-A')
        git(repo, 'commit', '-q', '-m', 'init')
        if pushed:
            hub = Path(tempfile.mkdtemp(prefix='hub-')) / 'hub.git'
            self.addCleanup(shutil.rmtree, str(hub.parent), True)
            git(hub.parent, 'init', '-q', '--bare', str(hub))
            git(repo, 'remote', 'add', 'origin', str(hub))
            git(repo, 'push', '-q', 'origin', 'main')
            git(repo, 'fetch', '-q', 'origin')
        return repo

    def test_tracked_unmodified_credential_like_names_are_ordinary_content(self):
        # red-team r2 N1 / r3b E1: a Go `credentials.go`, an `x-token.json` fixture and a `.env.example` tracked in
        # a pushed repo are not secrets
        repo = self.repo({'credentials.go': 'package x\n', 'fixtures/x-token.json': '{}\n', '.env.example': 'A=\n'})
        age(self.target)
        self.approve()
        self.assertTrue((repo / 'credentials.go').exists())

    def test_a_pinned_file_swapped_after_the_check_never_leaves_the_host(self):
        # Codex r5 F1: classification and upload use the same bytes. The fixture is swapped in place (same inode,
        # same length) after it was classified as ordinary content; the swapped bytes must never reach rcat.
        repo = self.repo({'fixtures/x-token.json': '{"fixture": "public placeholder"}\n'})
        age(self.target)
        fixture = repo / 'fixtures/x-token.json'
        swapped = b'{"fixture": "SWAPPED-AFTERCHECK"}\n'
        self.assertEqual(len(swapped), fixture.stat().st_size)
        real = cg._counted_credentials

        def classify_then_swap(*a, **kw):
            return real(*a, **kw)

        def swap():
            with open(str(fixture), 'r+b') as handle:
                handle.write(swapped)
        classify_then_swap.swap = swap
        plain = self.store / 'plain-zstd'
        plain.write_text('#!/bin/sh\nexec cat\n')  # no compression, so the received bytes show the tar content
        plain.chmod(0o755)
        with self.swap_in_stream('fixtures/x-token.json', lambda: classify_then_swap.swap()):
            message = self.refused('changed after it was checked', zstd=str(plain))
        self.assertIn('x-token.json', message)
        received = (self.store / 'received.bin').read_bytes() if (self.store / 'received.bin').exists() else b''
        self.assertNotIn(b'SWAPPED-AFTERCHECK', received)

    def swap_after_check(self, action):
        """Patch the credential check so `action` runs right after it returned (the race window)."""
        real = cg._counted_credentials

        def check_then_act(*a, **kw):
            result = real(*a, **kw)
            action()
            return result
        return mock.patch.object(cg, '_counted_credentials', check_then_act)

    def swap_in_stream(self, suffix, action):
        """Run `action` inside the send-side walk, right after it checked the entry ending in `suffix` and before
        the stream reads it: the window only the byte binding closes."""
        real_iter = cg._upload_iter_fd

        def wrapped(*a, **kw):
            for item in real_iter(*a, **kw):
                if item[0].endswith(suffix):
                    action()
                yield item
        return mock.patch.object(cg, '_upload_iter_fd', wrapped)

    def plain_zstd(self):
        plain = self.store / 'plain-zstd'
        plain.write_text('#!/bin/sh\nexec cat\n')  # no compression, so the received bytes show the tar content
        plain.chmod(0o755)
        return str(plain)

    def received(self):
        path = self.store / 'received.bin'
        return path.read_bytes() if path.exists() else b''

    def test_a_git_config_rewritten_after_the_check_is_never_sent(self):
        # Codex PR-A F2: the userinfo check and the upload use the same bytes of .git/config
        repo = self.repo({'main.go': 'package x\n'})
        age(self.target)
        config = repo / '.git/config'

        def inject():
            with open(str(config), 'ab') as handle:
                handle.write(b'[remote "m"]\n\turl = https://u:INJECTEDTOKEN@example.invalid/x.git\n')
        with self.swap_after_check(inject):  # before the send walk: the (inode, ctime) key refuses it
            self.refused('after the check', zstd=self.plain_zstd())
        self.assertNotIn(b'INJECTEDTOKEN', self.received())
        git(repo, 'config', '--remove-section', 'remote.m')
        age(self.target)
        with self.swap_in_stream('/.git/config', inject):  # inside the send walk: the byte binding refuses it
            self.refused('changed after', zstd=self.plain_zstd(), remote='dropbox:backups/mac/%s-in.tar.zst'
                         % self.target.name)
        self.assertNotIn(b'INJECTEDTOKEN', self.received())

    def test_a_credential_file_created_after_the_check_is_never_sent(self):
        # a checked file renamed in the tree to a credential name keeps its inode, so the name is checked again
        (self.target / 'sub/b.txt').write_text('PLANTEDVALUE=1\n')
        age(self.target)
        dotenv = '.' + 'env'

        def rename():
            os.rename(str(self.target / 'sub/b.txt'), str(self.target / 'sub' / dotenv))
        with self.swap_after_check(rename):
            self.refused('after the check', zstd=self.plain_zstd())
        self.assertNotIn(b'PLANTEDVALUE', self.received())

    def test_git_config_forms(self):
        # red-team PR-A E1: a user-only ssh URL is ordinary; an extraheader and a submodule's userinfo URL count
        repo = self.repo({'main.go': 'package x\n'})
        git(repo, 'remote', 'add', 'mirror', 'ssh://git@example.invalid/x.git')
        age(self.target)
        self.approve()
        git(repo, 'config', 'http.extraheader', 'AUTHORIZATION: placeholder')
        age(self.target)
        self.refused('credential in a git remote URL')
        git(repo, 'config', '--unset', 'http.extraheader')
        sub_config = repo / '.git/modules/lib/config'
        sub_config.parent.mkdir(parents=True)
        sub_config.write_text('[remote "origin"]\n\turl = https://u:p@example.invalid/lib.git\n')
        age(self.target)
        self.refused('credential in a git remote URL')

    def test_a_directory_swapped_for_a_link_after_the_check_leaks_nothing(self):
        # Codex PR-A r2 F1: the send-side walk goes through pinned directory descriptors
        outside = Path(tempfile.mkdtemp(prefix='outside-'))
        self.addCleanup(shutil.rmtree, str(outside), True)
        (outside / 'b.txt').write_text('OUTSIDESECRET\n')

        def swap():
            os.rename(str(self.target / 'sub'), str(self.target / 'sub-old'))
            os.symlink(str(outside), str(self.target / 'sub'))
        with self.swap_after_check(swap):
            self.refused('after the check', zstd=self.plain_zstd())
        self.assertNotIn(b'OUTSIDESECRET', self.received())

    def test_a_directory_swapped_mid_walk_leaks_nothing(self):
        # the swap happens right after the stream wrote the directory's own member and before it lists the directory
        outside = Path(tempfile.mkdtemp(prefix='outside-'))
        self.addCleanup(shutil.rmtree, str(outside), True)
        (outside / 'b.txt').write_text('MIDWALKSECRET\n')
        real_addfile = tarfile.TarFile.addfile
        target = self.target

        def addfile(tar, info, fileobj=None):
            result = real_addfile(tar, info, fileobj)
            if info.isdir() and info.name.endswith('/sub') and not (target / 'sub-old').exists():
                os.rename(str(target / 'sub'), str(target / 'sub-old'))
                os.symlink(str(outside), str(target / 'sub'))
            return result
        with mock.patch.object(tarfile.TarFile, 'addfile', addfile):
            self.refused('sub', zstd=self.plain_zstd())
        self.assertNotIn(b'MIDWALKSECRET', self.received())

    def test_a_file_moved_in_after_the_check_leaks_nothing(self):
        outside = Path(tempfile.mkdtemp(prefix='outside-', dir=str(self.target.parent)))
        self.addCleanup(shutil.rmtree, str(outside), True)
        (outside / 'notes.txt').write_text('MOVEDINSECRET\n')

        def move_in():
            os.rename(str(outside / 'notes.txt'), str(self.target / 'sub/aaa.txt'))
        with self.swap_after_check(move_in):
            self.refused('after the check', zstd=self.plain_zstd())
        self.assertNotIn(b'MOVEDINSECRET', self.received())

    def test_a_unit_that_is_a_credential_home_is_refused(self):
        # red-team M1: the unit's own name is the directory context the location rules need
        for name, rel in (('.codex', 'auth.json'), ('codex-home', 'auth.json'), ('.claude', '.credentials.json'),
                          ('claude-config', '.credentials.json'), ('gh', 'hosts.yml'), ('goodqa', 'user-token'),
                          ('vault', '.vault-token'), ('.kube', 'config')):
            with self.subTest(unit=name):
                unit = self.target / ('u-%d' % time.monotonic_ns()) / name
                (unit / rel).parent.mkdir(parents=True, exist_ok=True)
                (unit / rel).write_text('DUMMY\n')
                age(unit)
                message = self.refused('credential', path=unit, remote='dropbox:backups/mac/%s-%d.tar.zst'
                                       % (name.strip('.'), time.monotonic_ns()))
                self.assertIn(rel, message)
        self.assert_never_uploaded()

    def test_a_unit_inside_or_above_a_credential_dir_is_refused(self):
        for path in (self.home / '.ssh/old', self.home / '.config'):
            path.mkdir(parents=True, exist_ok=True)
            (path / 'x.txt').write_text('x\n')
            age(path)
            with self.subTest(path=str(path)):
                self.refused('credential directory', path=path)
        self.assert_never_uploaded()

    def test_a_hard_link_to_an_outside_file_is_refused(self):
        # red-team M2: the inode's other name is outside the unit
        outside = self.target.parent / ('outside-%d.txt' % time.monotonic_ns())
        outside.write_text('LINKEDSECRET\n')
        self.addCleanup(lambda: outside.exists() and outside.unlink())
        os.link(str(outside), str(self.target / 'notes.txt'))
        age(self.target)
        self.refused('hard link to a file outside the unit')
        self.assert_never_uploaded()
        # two names inside the unit are fine
        outside.unlink()
        os.link(str(self.target / 'notes.txt'), str(self.target / 'sub/notes-copy.txt'))
        age(self.target)
        self.approve()

    def test_only_a_real_gitdir_skips_the_loose_name_list(self):
        # red-team E1: a plain directory named .git carries no exemption; tier 1 counts inside a real gitdir
        fake = self.target / 'vendor/.git'
        fake.mkdir(parents=True)
        (fake / 'secrets.json').write_text('{}\n')
        age(self.target)
        self.refused('credential file')
        shutil.rmtree(str(self.target / 'vendor'))
        repo = self.repo({'main.go': 'package x\n'})
        (repo / '.git/info/.env').write_text('A=1\n')
        age(self.target)
        self.refused('credential file')

    def test_a_credential_store_inside_a_real_gitdir_counts(self):
        # red-team r2 N1: `credential.helper 'store --file=.git/credentials'` keeps plaintext tokens in the gitdir;
        # only git's own data (objects/, refs/, logs/) skips the loose name list
        repo = self.repo({'main.go': 'package x\n'})
        for inner in ('credentials', 'modules/sub/credentials', 'worktrees/w1/credentials'):
            path = repo / '.git' / inner
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('https://someone:not-a-real-token@example.invalid\n')
            age(self.target)
            self.refused('credential file')
            path.unlink()
        self.assert_never_uploaded()

    def test_a_link_target_is_read_through_the_pinned_directory(self):
        # substitute review r4 F3: a directory swapped for a symlink mid-stream cannot put an outside link target in
        # the archive; the target is read relative to the directory descriptor the walk holds
        os.symlink('inside-target', str(self.target / 'sub/L'))
        outside = self.home / ('outside-%d' % time.monotonic_ns())
        outside.mkdir()
        os.symlink('OUTSIDETARGET', str(outside / 'L'))
        age(self.target)
        held = self.target / 'sub.held'

        def swap():
            os.rename(str(self.target / 'sub'), str(held))
            os.symlink(str(outside), str(self.target / 'sub'))
        try:
            with self.swap_in_stream('/sub/L', swap):
                self.approve(zstd=self.plain_zstd())
        except ValueError:
            pass  # refused after the stream is fine; what matters is what reached rcat
        self.assertFalse(b'OUTSIDETARGET' in self.received(), 'an outside link target reached rcat')

    def test_no_approval_without_its_audit_row(self):
        # substitute review r4 F4: the audit row is written strictly, before the approval is stored
        real_audit = cg.audit

        def failing(event, fields, *a, **kw):
            if event == 'approved':
                raise ValueError('audit log is read-only')
            return real_audit(event, fields, *a, **kw)
        with mock.patch.object(cg, 'audit', failing):
            self.refused('records could not be written')
        self.assertFalse(cg.marker_covers(str(self.target), home=str(self.home)))

    def test_no_approval_without_its_records(self):
        # red-team E3: a failed index write leaves no usable approval
        with mock.patch.object(cg, 'index_record', side_effect=OSError('read-only file system')):
            self.refused('records could not be written')
        self.assertFalse(cg.marker_covers(str(self.target), home=str(self.home)))

    def test_a_git_remote_url_with_userinfo_counts(self):
        repo = self.repo({'main.go': 'package x\n'})
        git(repo, 'remote', 'add', 'mirror', 'https://someone:not-a-real-token@example.invalid/x.git')
        age(self.target)
        transport = self.transport()
        message = self.refused('credential in a git remote URL', transport=transport)
        # refused by the check, before any upload started (the stream's own byte check is a second layer)
        self.assertNotIn('changed after the check', message)
        self.assertNotIn('rcat', transport.subcommands)

    def test_dropbox_hash_matches_the_block_construction(self):
        self.assertEqual(cg.DropboxHash.of_bytes(b''), hashlib.sha256(b'').hexdigest())
        block = b'x' * (4 << 20)
        want = hashlib.sha256(hashlib.sha256(block).digest() + hashlib.sha256(b'y').digest()).hexdigest()
        h = cg.DropboxHash()
        for piece in (block[:1000], block[1000:], b'y'):
            h.update(piece)
        self.assertEqual(h.hexdigest(), want)
        path = self.target / 'a.bin'
        self.assertEqual(cg.dropbox_content_hash(str(path)), cg.DropboxHash.of_bytes(path.read_bytes()))


class UploadRefusals(UploadBase):
    def test_a_wrong_server_hash_is_refused(self):
        self.mode('hash-wrong')
        self.refused('hash')
        self.assert_no_download()

    def test_a_wrong_server_size_is_refused(self):
        self.mode('size')
        self.refused('size')

    def test_empty_or_garbled_hashsum_output_is_refused(self):
        for mode in ('hash-empty', 'hash-garbled'):
            with self.subTest(mode=mode):
                self.mode(mode)
                self.refused('hash', remote='dropbox:backups/mac/%s-%s.tar.zst' % (self.target.name, mode))

    def test_a_truncated_upload_is_refused(self):
        self.mode('truncate')
        self.refused('hash')

    def test_a_failed_rcat_is_refused(self):
        self.mode('rcat-fail')
        self.refused('upload')

    def test_an_existing_destination_is_refused_in_any_letter_case(self):
        with mock.patch.object(cg, '_upload_suffix', lambda: 'abcdef01'):
            self.approve()
            os.utime(str(self.target), (PAST, PAST))
            before = len(self.rcats())
            shouted = self.remote.replace('backups/mac/unit-', 'BACKUPS/MAC/UNIT-')
            for remote in (self.remote, shouted):
                with self.subTest(remote=remote):
                    with self.assertRaises(ValueError) as caught:
                        self.approve(remote=remote)
                    self.assertIn('exists', str(caught.exception))
                    self.assertIn('new name', str(caught.exception))
        self.assertEqual(len(self.rcats()), before)

    def test_two_uploads_of_one_name_never_replace_each_other(self):
        # live 2026-11-17: Dropbox rcat overwrites even with --immutable; the guard's unique name is the protection
        first = self.approve()['archive']
        kept = self.stored(first).read_bytes()
        (self.target / 'sub/b.txt').write_text('second\n')
        age(self.target)
        second = self.approve()['archive']
        self.assertNotEqual(first.casefold(), second.casefold())
        self.assertEqual(self.stored(first).read_bytes(), kept)

    def test_a_stalled_hash_check_ends_at_the_same_deadline(self):
        # Codex PR-A F4: remote verification shares the upload's absolute deadline
        self.mode('hash-stall')
        started = time.monotonic()
        self.refused('time budget', upload_timeout=3)
        self.assertLess(time.monotonic() - started, 20)

    def test_the_entry_cap_refuses_before_any_upload(self):
        self.policy = copy.deepcopy(self.policy)
        self.policy['marker']['max_upload_entries'] = 3
        self.refused('more than 3 entries')
        self.assert_never_uploaded()

    def test_a_slow_approval_stat_pass_is_refused(self):
        # D1, substitute review r4 F1: an approval is written only when its stat pass took at most 1/recheck_margin of
        # the time the hook will grant its re-check, so a written approval can always be used
        real = cg.stat_manifest

        def slow(path, limits, deadline=None, max_entries=None, counted=False):
            time.sleep(1.3)  # the 6-entry tree gets about 2 s at hook time; 1.3 s x margin 2 does not fit
            return real(path, limits, deadline=deadline, max_entries=max_entries, counted=counted)
        with mock.patch.object(cg, 'stat_manifest', slow):
            self.refused('re-checking it')

    def test_the_upload_walk_streams(self):
        import inspect
        self.assertTrue(inspect.isgeneratorfunction(cg._upload_iter))
        entry = self.approve()
        self.assertEqual(entry['files'], 2)
        self.assertEqual(entry['stat_entries'], 6)  # root, a.bin, alias, empty, sub, sub/b.txt

    def test_the_hook_recheck_shares_one_budget(self):
        entry = self.approve()
        self.assertTrue(cg.marker_covers(str(self.target), home=str(self.home)))
        self.assertAlmostEqual(cg.recheck_seconds(entry['stat_entries']), 2.0 + 6 * cg.RECHECK_SECONDS_PER_ENTRY)
        self.assertEqual(cg.recheck_seconds(10 ** 7), cg.DEFAULT_POLICY['marker']['hook_recheck_seconds'])
        tight = cg.Compiled(dict(self.policy, marker=dict(self.policy['marker'], hook_recheck_seconds=0.0)),
                            home=str(self.home))
        approvals = cg.Approvals(home=str(self.home), compiled=tight)
        self.assertFalse(approvals.covers(str(self.target)))
        self.assertTrue(approvals.recheck_exhausted)

    def test_the_deadline_rate_is_a_policy_key(self):
        # red-team PR-A E3: the stall test passes no upload_timeout; a rate this high gives the 900 s floor
        self.assertEqual(self.policy['marker'].get('upload_min_bytes_per_second', 2 << 20), 2 << 20)

    def test_a_stalled_upload_is_stopped_at_its_deadline(self):
        # Codex r5 F2: an rcat that stays alive but stops reading cannot hang the guard. 32 MiB of incompressible
        # data is far more than the pipes and zstd buffer, so the guard's own write blocks until the watchdog acts.
        (self.target / 'big.bin').write_bytes(os.urandom(32 << 20))
        age(self.target)
        self.mode('stall')
        started = time.monotonic()
        self.refused('time budget', upload_timeout=2)
        self.assertLess(time.monotonic() - started, 20)
        pid = int((self.store / 'stall.pid').read_text())
        with self.assertRaises(ProcessLookupError):  # ended and reaped, not left running
            os.kill(pid, 0)

    def test_remote_shapes_are_refused_before_any_upload(self):
        for remote in ('local:backups/x.tar.zst', 'dropbox:backups/x.zip', 'dropbox:backups/../x.tar.zst',
                       'dropbox:backups/*.tar.zst', '/tmp/x.tar.zst', 'dropbox:', ':dropbox:x.tar.zst'):
            with self.subTest(remote=remote):
                with self.assertRaises(ValueError):
                    self.approve(remote=remote)
        self.assert_never_uploaded()

    def test_globs_and_protected_roots_are_refused(self):
        for path in (str(self.target) + '/*', str(self.home / '.claude'), str(self.home / '.agent-harness/work')):
            with self.subTest(path=path):
                with self.assertRaises(ValueError):
                    self.approve(path=path)
        self.assert_never_uploaded()

    def test_a_tree_changed_during_the_upload_is_refused(self):
        transport = self.transport()
        target = self.target

        def touch():
            (target / 'sub/b.txt').write_text('changed\n')
            os.utime(str(target / 'sub/b.txt'), (PAST, PAST))
        transport.after_upload = touch
        self.refused('changed', transport=transport)

    def test_a_recent_change_is_refused_before_any_upload(self):
        (self.target / 'sub/b.txt').write_text('new\n')
        self.refused('changed in the last')
        self.assert_never_uploaded()

    def test_special_and_unreadable_files_are_refused_within_the_budget(self):
        # NEG-18: a FIFO is never opened (opening one for read would block forever)
        os.mkfifo(str(self.target / 'pipe'))
        age(self.target)
        self.refused('special')
        os.unlink(str(self.target / 'pipe'))
        locked = self.target / 'locked.bin'
        locked.write_bytes(b'x')
        locked.chmod(0)
        self.addCleanup(locked.chmod, 0o600)
        age(self.target)
        self.refused('read', remote='dropbox:backups/mac/%s-2.tar.zst' % self.target.name)
        self.assert_never_uploaded()

    def test_the_archive_route_does_not_hang_on_a_fifo(self):
        # E1: the shared tree_manifest gets the same protection
        os.mkfifo(str(self.target / 'pipe'))
        started = time.monotonic()
        with self.assertRaises(ValueError) as caught:
            cg.tree_manifest(str(self.target), self.policy['marker'])
        self.assertLess(time.monotonic() - started, 10)
        self.assertIn('special', str(caught.exception))

    def test_credential_files_are_refused_with_no_upload(self):
        # NEG-19 / NEG-27: tier 1 always counts, tier 2 counts when untracked
        for rel in ('rclone.conf', '.codex/auth.json', 'keys/AuthKey_X.p8', '.docker/config.json',
                    '.config/gh/hosts.yml', '.env', 'notes/credentials.txt', 'x-token.json'):
            with self.subTest(rel=rel):
                path = self.target / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('placeholder\n')
                age(self.target)
                message = self.refused('credential', remote='dropbox:backups/mac/%s-%d.tar.zst' % (
                    self.target.name, time.monotonic_ns()))
                self.assertIn(rel.rsplit('/', 1)[-1], message)
                self.assertIn('secret-quarantine', message)
                path.unlink()
        self.assert_never_uploaded()

    def repo(self, files, pushed=True):
        return UploadApproval.repo(self, files, pushed)

    def test_a_modified_tracked_credential_name_counts(self):
        repo = self.repo({'credentials.json': '{}\n'})
        (repo / 'credentials.json').write_text('{"changed": 1}\n')
        age(self.target)
        self.refused('credential')

    def test_a_tracked_secret_on_an_unpushed_head_counts(self):
        # NEG-32 / red-team r3b E2: committed locally, never pushed: not yet anywhere but here
        self.repo({'secrets.json': '{}\n'}, pushed=False)
        age(self.target)
        self.refused('credential')

    def test_a_tracked_real_credential_counts(self):
        # tier 1 is never cleared by being tracked
        self.repo({'deploy/rclone.conf': '[x]\n'})
        age(self.target)
        self.refused('tracked credential')

    def test_another_device_inside_the_unit_is_refused(self):
        real_lstat = os.lstat
        sub = str(self.target / 'sub')

        def lstat(path, *a, **kw):
            st = real_lstat(path, *a, **kw)
            if str(path) == sub:
                values = list(st)
                values[2] = st.st_dev + 1  # st_dev
                return os.stat_result(values)
            return st
        with mock.patch.object(cg, '_lstat', lstat):
            self.refused('device')
        self.assert_never_uploaded()


@unittest.skipUnless(os.environ.get('CG_BIG_TEST') == '1', 'builds 120,000 small files; set CG_BIG_TEST=1 (t2-dev)')
class UploadScale(UploadBase):
    """D1: the upload route's Python memory does not grow with the entry count, and a 100,000-entry approval is
    re-checked by the hook inside its budget."""

    def build(self, root, dirs, per_dir):
        for d in range(dirs):
            sub = root / ('d%04d' % d)
            sub.mkdir(parents=True)
            for f in range(per_dir):
                (sub / ('f%03d.txt' % f)).write_bytes(b'x')
        age(root)

    def peak(self, root):
        import tracemalloc
        tracemalloc.start()
        try:
            entry = self.approve(path=root, remote='dropbox:backups/mac/%s.tar.zst' % root.name)
            return entry, tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()

    def test_memory_does_not_grow_with_entries_and_the_hook_rechecks_in_time(self):
        small = self.target.parent / ('small-%d' % time.monotonic_ns())
        large = self.target.parent / ('large-%d' % time.monotonic_ns())
        self.build(small, 200, 100)    # 20,000 files
        self.build(large, 1000, 100)   # 100,000 files
        entry_small, peak_small = self.peak(small)
        entry_large, peak_large = self.peak(large)
        self.assertEqual(entry_large['files'], 100000)
        growth = peak_large - peak_small
        print('\nD1 peak traced memory: 20,000 files %.1f MiB, 100,000 files %.1f MiB, growth %.1f MiB'
              % (peak_small / 2 ** 20, peak_large / 2 ** 20, growth / 2 ** 20))
        # an entry list costs about 400 bytes per entry: 80,000 more entries would add about 30 MiB
        self.assertLess(growth, 8 << 20)
        started = time.monotonic()
        self.assertTrue(cg.marker_covers(str(large), home=str(self.home)))
        took = time.monotonic() - started
        print('D1 hook-time re-check of 100,000 files: %.2f s (budget %.2f s)'
              % (took, cg.recheck_seconds(entry_large['stat_entries'])))
        self.assertLess(took, cg.recheck_seconds(entry_large['stat_entries']))


class UploadCli(UploadBase):
    def test_cli_needs_wal_and_takes_no_other_backup_route(self):
        wal = self.home / 'wal.jsonl'
        wal.write_text('')
        for extra in (['--remote', 'dropbox:x'], ['--archive', 'dropbox:x.tar.zst'], ['--no-backup'],
                      ['--backup-verified-sha256', 'a' * 64]):
            with self.subTest(extra=extra):
                code = cg.main(['approve-delete', '--path', str(self.target), '--upload', self.remote,
                                '--wal', str(wal)] + extra)
                self.assertEqual(code, 2)
        self.assert_never_uploaded()



class HookRecheckBudget(UploadBase):
    """Substitute review r4 F1: the hook-time re-check fits inside the analyser's alarm, the alarm inside the launcher's
    child timeout and that inside the host's hook timeout; a re-check that runs out of time blocks, never allows."""

    def craft(self, target, entries):
        # re-MAC the stored approval with a larger recorded entry count (the fixture's own key): models a big tree
        sd = cg.state_dir(str(self.home))
        data = json.loads((sd / cg.MARKER_NAME).read_text())
        key = (sd / cg.KEY_NAME).read_bytes()
        for e in data['entries']:
            if e['path'] == os.path.realpath(str(target)):
                e['stat_entries'] = entries
                e.pop('mac', None)
                e['mac'] = cg._mac(key, e)
        (sd / cg.MARKER_NAME).write_text(json.dumps(data))

    def unit(self, name, entries=10 ** 6):
        unit = self.target.parent / ('%s-%d' % (name, time.monotonic_ns()))
        (unit / 'sub').mkdir(parents=True)
        (unit / 'sub/f.txt').write_text('x\n')
        age(unit)
        self.approve(path=unit, remote='dropbox:backups/mac/%s.tar.zst' % unit.name)
        self.craft(unit, entries)
        return unit

    def slow_walk(self, seconds):
        """Each hook re-check takes `seconds`, the way a real walk does: it honours its deadline and raises at it."""
        real = cg.stat_manifest

        def walk(path, limits, deadline=None, max_entries=None, counted=False):
            wait = seconds if deadline is None else min(seconds, max(0.0, deadline - time.monotonic()))
            time.sleep(wait)
            if wait < seconds:
                raise ValueError('walking the tree exceeded its time budget')
            return real(path, limits, deadline=deadline, max_entries=max_entries, counted=counted)
        return mock.patch.object(cg, 'stat_manifest', walk)

    def hook(self, command, policy):
        cwd = str(self.home)
        payload = json.dumps({'tool_name': 'Bash', 'tool_input': {'command': command}, 'cwd': cwd}).encode()
        compiled = cg.Compiled(policy, home=str(self.home), cwd=cwd)
        err, out = io.StringIO(), io.StringIO()
        import contextlib
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(out):
            code = cg.hook_main(fmt='exit2', stdin_bytes=payload, compiled=compiled)
        return code, err.getvalue() + out.getvalue()

    def small_budget(self, recheck):
        policy = copy.deepcopy(self.policy)
        policy['limits']['max_seconds'] = 0.5  # analyser alarm part: int(2 x 0.5) + 1 = 2 s
        policy['marker']['hook_recheck_seconds'] = recheck
        return policy

    def alias(self):
        # a path whose text names no protected location, so the launcher's raw-text probe sees nothing sensitive
        link = Path(tempfile.mkdtemp(prefix='w')) / 'w'
        os.symlink(str(self.target.parent), str(link))
        self.addCleanup(shutil.rmtree, str(link.parent), True)
        return link

    def test_a_recheck_longer_than_the_analysis_alarm_still_completes(self):
        unit = self.unit('one')
        with self.slow_walk(3.0):  # longer than the 2 s analysis part, inside the 4 s re-check budget
            code, message = self.hook('rm -rf %s/%s' % (self.alias(), unit.name), self.small_budget(4.0))
        self.assertEqual(code, 0, message)
        self.assertFalse(cg.marker_covers(str(unit), home=str(self.home)))  # used, so consumed

    def test_a_long_recheck_is_not_charged_to_the_analysis_budget(self):
        unit = self.unit('compound')
        with self.slow_walk(1.5):  # three times the 0.5 s analysis budget; more segments are analysed afterwards
            code, message = self.hook('rm -rf %s/%s; ' % (self.alias(), unit.name) + '; '.join(['true'] * 300),
                                      self.small_budget(4.0))
        self.assertEqual(code, 0, message)

    def test_approvals_that_do_not_fit_block_and_say_so(self):
        alias = self.alias()
        first, second = self.unit('b1'), self.unit('b2')
        with self.slow_walk(3.0):  # two 3 s re-checks against one 4 s budget
            code, message = self.hook('rm -rf %s/%s %s/%s' % (alias, first.name, alias, second.name),
                                      self.small_budget(4.0))
        self.assertEqual(code, 2, message)
        self.assertIn('delete one approved path per command', message)
        self.assertTrue(cg.marker_covers(str(first), home=str(self.home)))
        self.assertTrue(cg.marker_covers(str(second), home=str(self.home)))

    def test_an_alarm_during_a_recheck_blocks(self):
        # the alarm is only a backstop; if it fires while approvals are in use the verdict is a block, not a warning
        unit = self.unit('alarm')
        real = cg.stat_manifest

        def interrupted(*a, **kw):
            raise TimeoutError('command_guard wall-clock limit')
        with mock.patch.object(cg, 'stat_manifest', interrupted):
            code, message = self.hook('rm -rf %s/%s' % (self.alias(), unit.name), self.policy)
        self.assertEqual(code, 2, message)
        self.assertIn('delete one approved path per command', message)
        self.assertTrue(cg.marker_covers(str(unit), home=str(self.home)))
        self.assertIs(cg.stat_manifest, real)

    def test_the_budgets_nest_inside_the_host_timeout(self):
        import ast
        hooks = Path(cg.__file__).resolve().parent
        tree = ast.parse((hooks / 'command_guard_hook.py').read_text())
        child = [n.value.value for n in tree.body if isinstance(n, ast.Assign)
                 and getattr(n.targets[0], 'id', '') == 'CHILD_TIMEOUT'][0]
        install = (hooks.parent.parent / 'install.py').read_text()
        host = min(int(x) for x in re.findall(r'command_guard_hook[^\n]*\n?[^\n]*?"timeout": (\d+)', install)
                   or re.findall(r'"timeout": (\d+), "onFailure": "block"', install))
        for policy in (cg.DEFAULT_POLICY, self.policy):
            alarm = cg.hook_alarm_seconds(policy)
            analysis = int(float(policy['limits']['max_seconds']) * 2) + 1
            self.assertGreaterEqual(alarm, analysis + float(policy['marker']['hook_recheck_seconds']))
            self.assertLessEqual(alarm + 4, child, 'the analyser must finish before the launcher kills it')
            self.assertLessEqual(child + 4, host, 'the launcher must answer before the host times out')

    def test_the_launcher_blocks_a_delete_when_the_analyser_times_out(self):
        import subprocess as sp
        hooks = Path(cg.__file__).resolve().parent
        d = Path(tempfile.mkdtemp(prefix='cg-launcher-'))
        self.addCleanup(shutil.rmtree, str(d), True)
        text = (hooks / 'command_guard_hook.py').read_text()
        patched = re.sub(r'(?m)^CHILD_TIMEOUT = [0-9.]+$', 'CHILD_TIMEOUT = 1.0', text)
        self.assertNotEqual(patched, text)
        (d / 'command_guard_hook.py').write_text(patched)
        (d / 'command_guard.py').write_text('import time\ntime.sleep(30)\n')
        alias = self.alias()

        def run(command):
            payload = json.dumps({'tool_name': 'Bash', 'tool_input': {'command': command}}).encode()
            done = sp.run([sys.executable, str(d / 'command_guard_hook.py')], input=payload, stdout=sp.PIPE,
                          stderr=sp.PIPE, env={'PATH': '/usr/bin:/bin', 'HOME': str(d)}, timeout=60, check=False)
            return done.returncode, done.stderr.decode()
        code, err = run('rm -rf %s/e1 %s/e2' % (alias, alias))
        self.assertEqual(code, 2, err)
        self.assertEqual(run('ls -la')[0], 0)


if __name__ == '__main__':
    unittest.main()
