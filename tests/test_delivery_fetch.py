"""Exercise real Git fetch negotiation and maintenance in the borrowed store."""

import importlib.util
import os
from pathlib import Path
import random
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


HOOKS = Path(__file__).resolve().parents[1] / 'harness' / 'hooks'


class BorrowedObjectFetch(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='delivery-real-fetch-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.real_git = shutil.which('git')
        self.config = self.root / 'global.config'
        self.config.write_text('[gc]\n autoPackLimit = 1\n pruneExpire = now\n autoDetach = false\n'
                               '[fetch]\n unpackLimit = 1\n[protocol "file"]\n allow = always\n')
        self.environment = {name: value for name, value in os.environ.items() if not name.startswith('GIT_')}
        self.environment.update(GIT_CONFIG_GLOBAL=str(self.config), GIT_CONFIG_NOSYSTEM='1',
                                GIT_TERMINAL_PROMPT='0')
        self.producer, self.original = self.root / 'producer.git', self.root / 'original'
        self.git(self.root, 'init', '--bare', '--quiet', '--object-format=sha1', str(self.producer))
        rng, stream = random.Random(873150), bytearray()
        for index in range(32):
            data = rng.randbytes(8192)
            stream.extend(f'blob\nmark :{index * 2 + 1}\ndata {len(data)}\n'.encode() + data + b'\n')
            message = f'Fixture history {index}\n'.encode()
            stream.extend(f'commit refs/heads/main\nmark :{index * 2 + 2}\n'
                f'committer Fixture <fixture@example.invalid> {1700000000 + index} +0000\n'
                f'data {len(message)}\n'.encode() + message)
            if index:
                stream.extend(f'from :{index * 2}\n'.encode())
            stream.extend(f'M 100644 :{index * 2 + 1} payload.bin\n\n'.encode())
        self.git(self.producer, '-c', 'gc.auto=0', 'fast-import', '--quiet', data=bytes(stream))
        self.git(self.producer, 'symbolic-ref', 'HEAD', 'refs/heads/main')
        self.baseline = self.git(self.producer, 'rev-parse', 'HEAD').strip()
        self.git(self.root, '-c', 'gc.auto=0', 'clone', '--quiet', 'file://' + str(self.producer), str(self.original))
        self.old_objects = self.object_ids(self.original)
        self.assertEqual(len(self.old_objects), 96)
        content, message = b'new target payload\n', b'One new target\n'
        stream = (f'blob\nmark :1\ndata {len(content)}\n'.encode() + content + b'\n'
                  + b'commit refs/heads/main\ncommitter Fixture <fixture@example.invalid> 1700001000 +0000\n'
                  + f'data {len(message)}\n'.encode() + message + f'from {self.baseline}\nM 100644 :1 new.txt\n\n'.encode())
        self.git(self.producer, '-c', 'gc.auto=0', 'fast-import', '--quiet', data=stream)
        self.target = self.git(self.producer, 'rev-parse', 'HEAD').strip()
        self.new_objects = set(self.object_ids(self.producer)) - set(self.old_objects)
        self.assertEqual(len(self.new_objects), 3)
        self.assertNotEqual(self.git(self.original, 'cat-file', '-e', self.target, check=False).returncode, 0)
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        shim = self.bin / 'git'
        # Change only the endpoint. Keep the actual temporary bare cwd, flags,
        # object-directory environment, negotiation and maintenance behavior.
        shim.write_text('#!' + sys.executable + '\n' + '''import os,sys
a=sys.argv[1:]
if 'fetch' in a:
    for index,value in enumerate(a):
        if value.startswith('remote.') and '.url=https://github.com/fixture/fetch.git' in value:
            a[index]=value.split('=',1)[0]+'='+os.environ['FIXTURE_FETCH_URL']
    os.environ['GIT_ALLOW_PROTOCOL']='file'
os.execv(os.environ['FIXTURE_REAL_GIT'],[os.environ['FIXTURE_REAL_GIT'],*a])
''')
        shim.chmod(0o755)
        self.environment.update(PATH=str(self.bin) + os.pathsep + self.environment['PATH'],
                                FIXTURE_REAL_GIT=self.real_git, FIXTURE_FETCH_URL='file://' + str(self.producer))
        spec = importlib.util.spec_from_file_location('borrowed_fetch_target', HOOKS / 'deliver.py')
        self.delivery = importlib.util.module_from_spec(spec)
        with mock.patch.object(sys, 'path', [str(HOOKS), *sys.path]):
            spec.loader.exec_module(self.delivery)

    def git(self, repo, *args, data=None, check=True):
        result = subprocess.run([self.real_git, '-C', str(repo), *args], input=data,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                env=self.environment, timeout=30)
        if check:
            self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
            return result.stdout.decode()
        return result

    def object_ids(self, repo):
        return [line.split()[0] for line in self.git(repo, 'rev-list', '--objects', 'HEAD').splitlines()]

    def fetch(self, *, negotiation_tips=()):
        with mock.patch.dict(os.environ, self.environment, clear=True):
            code, _ = self.delivery.transport(self.original, 'https://github.com/fixture/fetch.git',
                'fixture/fetch', ['fetch', '--no-tags', '--no-write-fetch-head', self.target], 30,
                objects=(self.original / '.git' / 'objects').resolve(), negotiation_tips=negotiation_tips)
        self.assertEqual(code, 0)

    def assert_preserved(self):
        fsck = self.git(self.original, 'fsck', '--connectivity-only', check=False)
        batch = self.git(self.original, 'cat-file', '--batch-check',
                         data=('\n'.join(self.old_objects) + '\n').encode(), check=False)
        missing = [line.split()[0] for line in batch.stdout.decode().splitlines() if line.endswith(' missing')]
        self.assertEqual((fsck.returncode, missing), (0, []))
        self.assertEqual(self.git(self.original, 'rev-parse', 'HEAD').strip(), self.baseline)
        self.assertEqual(self.git(self.original, 'cat-file', '-t', self.target).strip(), 'commit')

    def test_fetch_cannot_maintain_or_delete_preexisting_original_objects(self):
        content, message = b'unrelated user branch\n', b'Preserve another original branch\n'
        stream = (f'blob\nmark :1\ndata {len(content)}\n'.encode() + content + b'\n'
                  + b'commit refs/heads/another-user-feature\ncommitter Fixture <fixture@example.invalid> 1700000500 +0000\n'
                  + f'data {len(message)}\n'.encode() + message
                  + f'from {self.baseline}\nM 100644 :1 other.txt\n\n'.encode())
        self.git(self.original, '-c', 'gc.auto=0', 'fast-import', '--quiet', data=stream)
        self.old_objects = [line.split()[0] for line in self.git(self.original, 'rev-list', '--objects', '--all').splitlines()]
        pack = self.original / '.git' / 'objects' / 'pack'
        before = set(pack.iterdir())
        # Preserve the old pack until every baseline object has a new home.
        for index in range(3):
            self.git(self.original, '-c', 'gc.auto=0', 'pack-objects', str(pack / 'pack'),
                     data=('\n'.join(self.old_objects[index::3]) + '\n').encode())
        for path in before:
            path.unlink()
        for path in pack.iterdir():
            os.utime(path, (1600000000, 1600000000))
        self.git(self.original, 'fsck', '--connectivity-only')
        self.fetch()
        self.assert_preserved()

    def test_fetch_transfers_only_new_objects_with_real_negotiation(self):
        # Isolate negotiation from the separate maintenance regression above.
        self.config.write_text('[gc]\n auto = 0\n[fetch]\n unpackLimit = 1\n'
                               '[protocol "file"]\n allow = always\n')
        pack = self.original / '.git' / 'objects' / 'pack'
        before = set(pack.glob('*.idx'))
        self.fetch()
        added = set(pack.glob('*.idx')) - before
        self.assertTrue(added)
        received = set()
        for path in added:
            for line in self.git(self.original, 'verify-pack', '-v', str(path)).splitlines():
                if re.match(r'^[a-f0-9]{40} ', line):
                    received.add(line.split()[0])
        self.assertEqual(received, self.new_objects)
        self.assert_preserved()

    def test_cached_feature_tip_is_not_downloaded_again(self):
        self.config.write_text('[gc]\n auto = 0\n[fetch]\n unpackLimit = 1\n'
                               '[protocol "file"]\n allow = always\n')
        feature = self.target
        self.git(self.original, 'fetch', '--no-auto-maintenance', 'file://' + str(self.producer),
                 feature + ':refs/heads/cached-feature')
        prior_fetch_head = (self.original / '.git' / 'FETCH_HEAD').read_bytes()
        message = b'One later remote commit\n'
        stream = (b'commit refs/heads/main\ncommitter Fixture <fixture@example.invalid> 1700002000 +0000\n'
                  + f'data {len(message)}\n'.encode() + message + f'from {feature}\n\n'.encode())
        self.git(self.producer, '-c', 'gc.auto=0', 'fast-import', '--quiet', data=stream)
        self.target = self.git(self.producer, 'rev-parse', 'HEAD').strip()
        pack = self.original / '.git' / 'objects' / 'pack'
        before = set(pack.glob('*.idx'))
        self.fetch(negotiation_tips=(feature,))
        received = set()
        for path in set(pack.glob('*.idx')) - before:
            for line in self.git(self.original, 'verify-pack', '-v', str(path)).splitlines():
                if re.match(r'^[a-f0-9]{40} ', line):
                    received.add(line.split()[0])
        self.assertEqual(received, {self.target})
        self.assertEqual((self.original / '.git' / 'FETCH_HEAD').read_bytes(), prior_fetch_head)
        self.assert_preserved()


if __name__ == '__main__':
    unittest.main()
