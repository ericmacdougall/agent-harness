"""Small packaging contract checks. No Go builds or provider calls."""

import hashlib
import importlib.util
import os
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('package_console', ROOT / 'tools/package_console.py')
packager = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(packager)


class PackagingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.output = self.root / 'release'
        self.calls = []
        self.go_license = b'Copyright The Go Authors. Synthetic license fixture.\nRedistribution permitted.\n'

    def build(self, argv, *, cwd, env, timeout):
        self.calls.append((argv, cwd, env, timeout))
        Path(argv[argv.index('-o') + 1]).write_bytes(b'synthetic executable\x00\n')

    def package(self, targets=None, build=None):
        with patch.object(packager.shutil, 'which', return_value='/trusted/go'), \
                patch.object(packager, 'read_go_license', return_value=self.go_license, create=True), \
                patch.object(packager, 'run_build', side_effect=build or self.build):
            return packager.package(self.output, '1.2.3', targets or packager.TARGETS)

    def test_fixed_six_archives_modes_checksums_and_safe_metadata(self):
        result = self.package()
        self.assertEqual(result, self.output)
        self.assertEqual(len(self.calls), 6)
        sums = {}
        for line in (result / 'SHA256SUMS').read_text().splitlines():
            digest, name = line.split('  ')
            sums[name] = digest
        self.assertEqual(len(sums), 6)
        for target in packager.TARGETS:
            extension = '.zip' if target.startswith('windows-') else '.tar.gz'
            name = f'harness-console-1.2.3-{target}{extension}'
            path = result / name
            self.assertEqual(sums[name], hashlib.sha256(path.read_bytes()).hexdigest())
            executable = 'harness-console.exe' if extension == '.zip' else 'harness-console'
            if extension == '.zip':
                with zipfile.ZipFile(path) as archive:
                    self.assertEqual(archive.namelist(), [executable, 'RUN.txt', 'LICENSE', 'GO-LICENSE'])
                    self.assertEqual(archive.getinfo(executable).external_attr >> 16, 0o100755)
                    doc = archive.read('RUN.txt').decode()
                    self.assertEqual(archive.read('LICENSE'), (ROOT / 'LICENSE').read_bytes())
                    self.assertEqual(archive.read('GO-LICENSE'), self.go_license)
                    for notice in ('RUN.txt', 'LICENSE', 'GO-LICENSE'):
                        self.assertEqual(archive.getinfo(notice).external_attr >> 16, 0o100644)
                    self.assertEqual(archive.getinfo(executable).date_time, (1980, 1, 1, 0, 0, 0))
            else:
                with tarfile.open(path) as archive:
                    self.assertEqual(archive.getnames(), [executable, 'RUN.txt', 'LICENSE', 'GO-LICENSE'])
                    member = archive.getmember(executable)
                    self.assertEqual(member.mode, 0o755)
                    for item in archive.getmembers():
                        self.assertEqual((item.uid, item.gid, item.uname, item.gname, item.mtime),
                                         (0, 0, '', '', 0))
                        self.assertTrue(item.isfile())
                    doc = archive.extractfile('RUN.txt').read().decode()
                    self.assertEqual(archive.extractfile('LICENSE').read(), (ROOT / 'LICENSE').read_bytes())
                    self.assertEqual(archive.extractfile('GO-LICENSE').read(), self.go_license)
                    for notice in ('RUN.txt', 'LICENSE', 'GO-LICENSE'):
                        self.assertEqual(archive.getmember(notice).mode, 0o644)
            self.assertIn('unsigned', doc)
            self.assertIn('compile', doc)
            self.assertNotIn(str(self.root), doc)
            self.assertNotIn(str(Path.home()), doc)
        self.assertEqual(set(p.name for p in result.iterdir()), set(sums) | {'SHA256SUMS'})

    def test_missing_repo_or_go_license_publishes_nothing(self):
        with patch.object(packager, 'ROOT', self.root):
            with self.assertRaisesRegex(packager.PackagingError, 'repository license'):
                self.package(['linux-amd64'])
        self.assertEqual(self.calls, [])
        self.assertFalse(self.output.exists())
        with patch.object(packager.shutil, 'which', return_value='/trusted/go'), \
                patch.object(packager, 'read_go_license', side_effect=packager.PackagingError('Go license missing'), create=True), \
                patch.object(packager, 'run_build') as build:
            with self.assertRaisesRegex(packager.PackagingError, 'Go license'):
                packager.package(self.output, '1.2.3', ['linux-amd64'])
            build.assert_not_called()
        self.assertFalse(self.output.exists())

    def test_go_license_discovery_uses_fixed_bounded_command_and_exact_file(self):
        toolchain = self.root / 'toolchain'
        toolchain.mkdir()
        (toolchain / 'LICENSE').write_bytes(self.go_license)
        staging = self.root / 'staging'
        staging.mkdir()
        with patch.object(packager, 'run_build', return_value=(str(toolchain) + '\n').encode()) as command:
            self.assertEqual(packager.read_go_license('/trusted/go', staging), self.go_license)
        args, kwargs = command.call_args
        self.assertEqual(args[0], ['/trusted/go', 'env', 'GOROOT'])
        self.assertEqual(kwargs['env']['GOCACHE'], str(staging / 'cache'))
        self.assertLessEqual(kwargs['timeout'], 10)
        for invalid in (b'relative\n', b'/one\n/two\n', b'\xff', b'', (str(toolchain) + '\n\n').encode()):
            with patch.object(packager, 'run_build', return_value=invalid), \
                    self.assertRaises(packager.PackagingError):
                packager.read_go_license('/trusted/go', staging)

    def test_license_reader_refuses_missing_symlink_oversize_and_nontext(self):
        license_path = self.root / 'LICENSE'
        for value in (b'', b'x' * 65537, b'\xff', b'license\x00text'):
            license_path.write_bytes(value)
            with self.subTest(value_length=len(value)), self.assertRaises(packager.PackagingError):
                packager.read_license(license_path, 'test license')
        license_path.unlink()
        target = self.root / 'other'
        target.write_bytes(self.go_license)
        license_path.symlink_to(target)
        with self.assertRaises(packager.PackagingError):
            packager.read_license(license_path, 'test license')
        license_path.unlink()
        if hasattr(os, 'mkfifo'):
            os.mkfifo(license_path)
            with self.assertRaises(packager.PackagingError):
                packager.read_license(license_path, 'test license')

    def test_fixed_argv_and_minimal_environment(self):
        with patch.dict(os.environ, {'GOFLAGS': '-toolexec=untrusted',
                                     'ANTHROPIC_API_KEY': 'synthetic-sentinel'}):
            self.package(['linux-amd64'])
        argv, cwd, env, timeout = self.calls[0]
        self.assertEqual(argv[:6], ['/trusted/go', 'build', '-trimpath', '-buildvcs=false',
                                   '-mod=readonly', '-ldflags=-buildid='])
        self.assertEqual(argv[-1], '.')
        self.assertEqual(cwd, ROOT / 'console')
        self.assertEqual((env['GOOS'], env['GOARCH'], env['CGO_ENABLED']), ('linux', 'amd64', '0'))
        self.assertEqual((env['GOENV'], env['GOWORK'], env['GOTOOLCHAIN']), ('off', 'off', 'local'))
        self.assertNotIn('GOFLAGS', env)
        self.assertNotIn('ANTHROPIC_API_KEY', env)
        self.assertGreater(timeout, 0)
        self.assertLessEqual(timeout, 300)

    def debian_layout(self):
        library, docs = self.root / 'usr/lib', self.root / 'usr/share/doc'
        toolchain = library / 'go-1.22'
        (toolchain / 'bin').mkdir(parents=True)
        go = toolchain / 'bin/go'
        go.write_bytes(b'synthetic toolchain executable')
        notice = docs / 'golang-1.22-go/copyright'
        notice.parent.mkdir(parents=True)
        notice.write_bytes(self.go_license + b'Full distro notices, including other components.\n')
        return library, docs, toolchain, go, notice

    def test_debian_missing_canonical_license_uses_full_owned_package_notice(self):
        library, docs, toolchain, go, notice = self.debian_layout()
        calls = []
        def query(argv, **kwargs):
            calls.append((argv, kwargs))
            if argv == [str(go), 'env', 'GOROOT']:
                return (str(toolchain) + '\n').encode()
            if '--search' in argv:
                return f'golang-1.22-go: {go}\ngolang-1.22-go: {notice}\n'.encode()
            return b'install ok installed\tgolang-1.22-go\t1.22.2-2ubuntu0.5\n'
        with patch.object(packager, 'DEBIAN_LIB_ROOT', library, create=True), \
                patch.object(packager, 'DEBIAN_DOC_ROOT', docs, create=True), \
                patch.object(packager, 'run_build', side_effect=query):
            self.assertEqual(packager.read_go_license(str(go), self.root), notice.read_bytes())
        self.assertEqual(len(calls), 3)
        self.assertEqual(calls[1][0], ['/usr/bin/dpkg-query', '--show',
                                     '--showformat=${Status}\t${Package}\t${Version}\n', 'golang-1.22-go'])
        self.assertEqual(calls[2][0], ['/usr/bin/dpkg-query', '--search', '--', str(go), str(notice)])
        for _, kwargs in calls:
            self.assertLessEqual(kwargs['timeout'], 10)
            self.assertNotIn('ANTHROPIC_API_KEY', kwargs['env'])

    def test_debian_fallback_rejects_wrong_owner_status_layout_and_missing_notice(self):
        library, docs, toolchain, go, notice = self.debian_layout()
        def check(status, owners, executable=None):
            def query(argv, **kwargs):
                if argv[0] == str(executable or go):
                    return (str(toolchain) + '\n').encode()
                return owners if '--search' in argv else status
            with patch.object(packager, 'DEBIAN_LIB_ROOT', library), \
                    patch.object(packager, 'DEBIAN_DOC_ROOT', docs), \
                    patch.object(packager, 'run_build', side_effect=query), \
                    self.assertRaises(packager.PackagingError):
                packager.read_go_license(str(executable or go), self.root)
        good_status = b'install ok installed\tgolang-1.22-go\t1.22.2-2ubuntu0.5\n'
        good_owners = f'golang-1.22-go: {go}\ngolang-1.22-go: {notice}\n'.encode()
        for status in (b'deinstall ok config-files\tgolang-1.22-go\t1.22.2\n',
                       b'install ok installed\tforeign-package\t1.22.2\n', b''):
            check(status, good_owners)
        for owners in (good_owners.replace(b'golang-1.22-go:', b'foreign-package:', 1),
                       f'golang-1.22-go: {go}\n'.encode(), good_owners + b'extra: /foreign\n'):
            check(good_status, owners)
        check(good_status, good_owners, toolchain / 'bin/foreign-go')
        notice.unlink()
        check(good_status, good_owners)
        notice.symlink_to(go)
        check(good_status, good_owners)

    def test_existing_invalid_canonical_license_never_uses_distro_fallback(self):
        _, _, toolchain, go, notice = self.debian_layout()
        canonical = toolchain / 'LICENSE'
        for value in (b'', b'\x00invalid', b'x' * 65537):
            canonical.write_bytes(value)
            with patch.object(packager, 'run_build', return_value=(str(toolchain) + '\n').encode()) as query, \
                    self.assertRaises(packager.PackagingError):
                packager.read_go_license(str(go), self.root)
            self.assertEqual(query.call_count, 1)
        canonical.unlink()
        canonical.symlink_to(notice)
        with patch.object(packager, 'run_build', return_value=(str(toolchain) + '\n').encode()) as query, \
                self.assertRaises(packager.PackagingError):
            packager.read_go_license(str(go), self.root)
        self.assertEqual(query.call_count, 1)

    def test_private_cache_and_temp_work_without_windows_user_cache_environment(self):
        roots = []
        def build(argv, **kwargs):
            env = kwargs['env']
            # Model a Windows host without LOCALAPPDATA or preconfigured GOCACHE.
            self.assertNotIn('LOCALAPPDATA', env)
            self.assertIn('GOCACHE', env, 'Go needs an explicit cache when user cache discovery is unavailable')
            cache = Path(env['GOCACHE'])
            scratch = Path(env['GOTMPDIR'])
            self.assertEqual((env['TMPDIR'], env['TMP'], env['TEMP']), (str(scratch),) * 3)
            self.assertEqual(cache.parent, scratch.parent)
            self.assertEqual(cache.parent, Path(argv[argv.index('-o') + 1]).parent)
            for directory in (cache, scratch):
                self.assertTrue(directory.is_absolute())
                self.assertTrue(directory.is_dir())
                self.assertFalse(directory.is_symlink())
                if os.name != 'nt':
                    self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
            self.assertNotIn('ANTHROPIC_API_KEY', env)
            roots.append(cache.parent)
            self.build(argv, **kwargs)
        with patch.dict(os.environ, {'ANTHROPIC_API_KEY': 'synthetic-sentinel'}, clear=True):
            self.package(['windows-amd64', 'windows-arm64'], build)
        self.assertEqual(len(roots), 2)
        self.assertEqual(roots[0], roots[1], 'targets should share one private cache')
        self.assertFalse(roots[0].exists(), 'private build storage must be cleaned')

    def test_bad_version_target_and_output_refused_before_build(self):
        with patch.object(packager, 'run_build') as build:
            for version in ('../escape', 'v1.2.3', '1.2', '01.2.3', '1.2.3\n', '1.2.3;echo bad'):
                with self.subTest(version=repr(version)), self.assertRaises(packager.PackagingError):
                    packager.package(self.output, version, ['linux-amd64'])
            for target in ('linux-amd64;echo bad', '../darwin-amd64', 'windows-386'):
                with self.subTest(target=target), self.assertRaises(packager.PackagingError):
                    packager.package(self.output, '1.2.3', [target])
            for output in (Path('relative'), self.root / '..' / 'release', self.root / 'missing' / 'out'):
                with self.subTest(output=output), self.assertRaises(packager.PackagingError):
                    packager.package(output, '1.2.3', ['linux-amd64'])
            build.assert_not_called()
        self.assertFalse(self.output.exists())

    def test_existing_output_and_symlink_untouched(self):
        self.output.mkdir()
        sentinel = self.output / 'keep.txt'
        sentinel.write_text('keep')
        with self.assertRaises(packager.PackagingError):
            self.package(['linux-amd64'])
        self.assertEqual(sentinel.read_text(), 'keep')
        link = self.root / 'link'
        link.symlink_to(self.output, target_is_directory=True)
        with self.assertRaises(packager.PackagingError):
            packager.package(link / 'new', '1.2.3', ['linux-amd64'])
        self.assertFalse((self.output / 'new').exists())

    def test_failed_second_build_publishes_nothing(self):
        def fail(argv, **kwargs):
            self.build(argv, **kwargs)
            if len(self.calls) == 2:
                raise packager.PackagingError('go build failed (exit 1)')
        with self.assertRaisesRegex(packager.PackagingError, 'linux-arm64.*exit 1'):
            self.package(['linux-amd64', 'linux-arm64'], fail)
        self.assertFalse(self.output.exists())
        self.assertEqual(list(self.root.iterdir()), [])

    def test_empty_or_symlink_binary_never_archived(self):
        def invalid(argv, **kwargs):
            Path(argv[argv.index('-o') + 1]).write_bytes(b'')
        with self.assertRaisesRegex(packager.PackagingError, 'linux-amd64.*empty'):
            self.package(['linux-amd64'], invalid)
        self.assertFalse(self.output.exists())
        foreign = self.root / 'foreign'
        foreign.write_bytes(b'not our build')
        def symlink(argv, **kwargs):
            Path(argv[argv.index('-o') + 1]).symlink_to(foreign)
        with self.assertRaisesRegex(packager.PackagingError, 'linux-amd64.*regular'):
            self.package(['linux-amd64'], symlink)
        self.assertEqual(foreign.read_bytes(), b'not our build')
        self.assertFalse(self.output.exists())

    def test_archive_write_failure_has_no_output_or_success_manifest(self):
        with patch.object(packager, 'write_archive', side_effect=OSError('synthetic disk failure')):
            with self.assertRaisesRegex(packager.PackagingError, 'linux-amd64.*archive'):
                self.package(['linux-amd64'])
        self.assertFalse(self.output.exists())

    def test_publish_failure_never_creates_success_manifest(self):
        with patch.object(packager, 'publish_archive', side_effect=OSError('synthetic disk failure')):
            with self.assertRaisesRegex(packager.PackagingError, 'publish'):
                self.package(['linux-amd64'])
        self.assertFalse((self.output / 'SHA256SUMS').exists())

    def test_cli_failure_nonzero_with_target_reason_without_success_message(self):
        import contextlib
        import io
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(packager, 'package', side_effect=packager.PackagingError('linux-arm64: build deadline exceeded')), \
                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            result = packager.main(['--output-dir', str(self.output), '--version', '1.2.3'])
        self.assertEqual(result, 1)
        self.assertEqual(stdout.getvalue(), '')
        self.assertIn('linux-arm64: build deadline exceeded', stderr.getvalue())

    def test_reproducible_archives_and_manifest(self):
        self.package(['linux-amd64', 'windows-arm64'])
        first = {path.name: path.read_bytes() for path in self.output.iterdir()}
        self.output = self.root / 'second'
        self.package(['linux-amd64', 'windows-arm64'])
        self.assertEqual(first, {path.name: path.read_bytes() for path in self.output.iterdir()})

    def test_runner_success_failure_timeout_and_output_bound(self):
        # Real Python subprocesses exercise runner mechanics, not Go or providers.
        import sys
        env = {'PATH': os.defpath}
        self.assertEqual(packager.run_build([sys.executable, '-c', 'print("ok")'],
                                           cwd=self.root, env=env, timeout=2).splitlines(), [b'ok'])
        for script, timeout, reason in (
            ('raise SystemExit(3)', 2, 'exit 3'),
            ('import time;time.sleep(2)', 0.05, 'deadline'),
            ('import sys;sys.stdout.write("x"*100000)', 2, 'output limit'),
        ):
            with self.subTest(reason=reason), self.assertRaisesRegex(packager.PackagingError, reason):
                packager.run_build([sys.executable, '-c', script], cwd=self.root, env=env, timeout=timeout)

    def test_manifest_is_renamed_last(self):
        real_replace = os.replace
        observed = []
        def replace(source, destination):
            self.assertEqual(Path(destination).name, 'SHA256SUMS')
            self.assertEqual(len(list(self.output.glob('*.tar.gz'))), 2)
            observed.append(Path(source).read_text())
            return real_replace(source, destination)
        with patch.object(packager.os, 'replace', side_effect=replace):
            self.package(['linux-amd64', 'linux-arm64'])
        self.assertEqual(len(observed), 1)
        self.assertEqual(len(observed[0].splitlines()), 2)


if __name__ == '__main__':
    unittest.main()
