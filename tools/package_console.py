#!/usr/bin/env python3
"""Build unsigned standalone console archives using the installed Go toolchain.

Example: python3 tools/package_console.py --output-dir /absolute/new-release --version 0.1.0
The output must not exist. SHA256SUMS is published last; without it a release is
incomplete. Builds are compile checks, not proof of target runtime/UI behavior.
"""

import argparse
import gzip
import hashlib
import io
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TARGETS = ('darwin-amd64', 'darwin-arm64', 'linux-amd64', 'linux-arm64',
           'windows-amd64', 'windows-arm64')
BUILD_TIMEOUT = 300
OUTPUT_LIMIT = 65536
DEBIAN_LIB_ROOT = Path('/usr/lib')
DEBIAN_DOC_ROOT = Path('/usr/share/doc')
VERSION = re.compile(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)', re.ASCII)


class PackagingError(Exception):
    """A refused or incomplete package operation; no success is implied."""


def validate_output(output):
    output = Path(output)
    if (not output.is_absolute() or '..' in output.parts or
            any(ord(char) < 32 or ord(char) == 127 for char in str(output))):
        raise PackagingError('output directory must be an absolute path without traversal or controls')
    for ancestor in reversed((output, *output.parents)):
        if ancestor.is_symlink():
            raise PackagingError('output directory and its parents must not be symlinks')
    if output.exists():
        raise PackagingError('output directory already exists; choose a new directory')
    if not output.parent.is_dir():
        raise PackagingError('output parent must be an existing directory')
    return output


def build_environment(target, staging):
    goos, goarch = target.split('-')
    # Do not inherit credentials, compiler flags, tool executors or proxy settings.
    env = {key: os.environ[key] for key in ('HOME', 'USERPROFILE', 'SYSTEMROOT', 'SystemRoot')
           if key in os.environ}
    env.update(PATH=os.defpath, GOOS=goos, GOARCH=goarch, CGO_ENABLED='0', GOENV='off',
               GOWORK='off', GOTOOLCHAIN='local', GOPROXY='off', GOSUMDB='off')
    # Windows Go cache discovery normally needs LOCALAPPDATA, which is deliberately
    # not inherited. One private cache is shared by these six builds and then
    # removed; scratch paths also avoid depending on host user/temp discovery.
    scratch = str(staging / 'tmp')
    env.update(GOCACHE=str(staging / 'cache'), GOTMPDIR=scratch,
               TMPDIR=scratch, TMP=scratch, TEMP=scratch)
    return env


def run_build(argv, *, cwd, env, timeout):
    """Bound both wall time and captured output; do not print private build paths."""
    try:
        process = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   start_new_session=(os.name != 'nt'))
    except OSError as exc:
        raise PackagingError('could not start installed Go toolchain') from exc
    oversized = threading.Event()
    size = [0]
    captured = bytearray()

    def drain():
        try:
            while True:
                block = process.stdout.read(8192)
                if not block:
                    break
                size[0] += len(block)
                if size[0] > OUTPUT_LIMIT:
                    oversized.set()
                else:
                    captured.extend(block)
        except OSError:
            oversized.set()

    reader = threading.Thread(target=drain, daemon=True)
    reader.start()
    deadline = time.monotonic() + timeout
    reason = None
    while process.poll() is None:
        if oversized.is_set():
            reason = 'build output limit exceeded'
            break
        if time.monotonic() >= deadline:
            reason = 'build deadline exceeded'
            break
        time.sleep(0.01)
    if reason:
        try:
            if os.name != 'nt':
                os.killpg(process.pid, signal.SIGKILL)
            else:
                process.kill()
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired as exc:
            raise PackagingError(reason + '; toolchain termination unconfirmed') from exc
    reader.join(timeout=1)
    if reader.is_alive():
        raise PackagingError(reason or 'build output stream did not close')
    process.stdout.close()
    if reason or oversized.is_set():
        raise PackagingError(reason or 'build output limit exceeded')
    if process.returncode:
        raise PackagingError(f'Go command failed (exit {process.returncode}); inspect source with go test/build')
    return bytes(captured)


def read_license(path, label):
    """Read only a bounded regular UTF-8 notice; never archive a link or device."""
    try:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode):
            raise PackagingError(f'{label} must be a regular text file')
        descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
        with os.fdopen(descriptor, 'rb') as stream:
            metadata = os.fstat(stream.fileno())
            if not stat.S_ISREG(metadata.st_mode) or not 0 < metadata.st_size <= OUTPUT_LIMIT:
                raise PackagingError(f'{label} must be nonempty bounded regular text')
            contents = stream.read(OUTPUT_LIMIT + 1)
        if not contents or len(contents) > OUTPUT_LIMIT:
            raise PackagingError(f'{label} is missing or exceeds the text limit')
        text = contents.decode('utf-8')
        if any(ord(char) < 32 and char not in '\t\r\n' for char in text):
            raise PackagingError(f'{label} contains nontext data')
        return contents
    except (OSError, UnicodeError) as exc:
        raise PackagingError(f'{label} is missing or is not readable UTF-8 text') from exc


def read_go_license(go, staging):
    # Fixed toolchain query; no caller-supplied GOROOT or arbitrary license path.
    raw = run_build([go, 'env', 'GOROOT'], cwd=ROOT / 'console',
                    env=build_environment(TARGETS[0], staging), timeout=10)
    try:
        lines = raw.decode('utf-8').splitlines()
        if len(lines) != 1:
            raise ValueError('expected one toolchain directory')
        root_text = lines[0]
        if not root_text or any(ord(char) < 32 or ord(char) == 127 for char in root_text):
            raise ValueError('invalid toolchain directory')
        root = Path(root_text)
        if not root.is_absolute():
            raise ValueError('toolchain directory is not absolute')
        root = root.resolve(strict=True)
    except (OSError, UnicodeError, ValueError) as exc:
        raise PackagingError('Go license discovery returned an invalid toolchain directory') from exc
    canonical = root / 'LICENSE'
    try:
        canonical.lstat()
    except FileNotFoundError:
        return read_debian_go_license(go, root, staging)
    except OSError as exc:
        raise PackagingError('Go toolchain license is unavailable') from exc
    # An existing invalid notice must never activate the distro fallback.
    return read_license(canonical, 'Go toolchain license')


def read_debian_go_license(go, root, staging):
    """Accept only the full notice owned by this exact installed distro Go package."""
    try:
        relative = root.relative_to(DEBIAN_LIB_ROOT)
        match = re.fullmatch(r'go-([1-9][0-9]*\.(?:0|[1-9][0-9]*))', str(relative))
        executable = Path(go).resolve(strict=True)
        if not match or executable != root / 'bin/go' or not executable.is_file():
            raise ValueError('unsupported distro toolchain layout')
        package_name = 'golang-' + match[1] + '-go'
        notice = DEBIAN_DOC_ROOT / package_name / 'copyright'
        if notice.resolve(strict=True) != notice:
            raise ValueError('distro notice is linked')
    except (OSError, ValueError) as exc:
        raise PackagingError('canonical Go license missing; no supported regular distro notice') from exc

    env = build_environment(TARGETS[0], staging)
    try:
        status = run_build(['/usr/bin/dpkg-query', '--show',
                            '--showformat=${Status}\t${Package}\t${Version}\n', package_name],
                           cwd=ROOT / 'console', env=env, timeout=10).decode('utf-8').splitlines()
        fields = status[0].split('\t') if len(status) == 1 else []
        if (len(fields) != 3 or fields[0] not in ('install ok installed', 'hold ok installed') or
                fields[1] != package_name or
                re.fullmatch(r'(?:[0-9]+:)?' + re.escape(match[1]) + r'(?:[.+~:-][0-9A-Za-z.+:~_-]*)?', fields[2]) is None):
            raise ValueError('matching Go package is not installed')
        owners = run_build(['/usr/bin/dpkg-query', '--search', '--', str(executable), str(notice)],
                           cwd=ROOT / 'console', env=env, timeout=10).decode('utf-8').splitlines()
        expected = {f'{package_name}: {executable}', f'{package_name}: {notice}'}
        if len(owners) != 2 or set(owners) != expected:
            raise ValueError('Go executable and notice do not share the exact package owner')
    except (UnicodeError, ValueError, PackagingError) as exc:
        raise PackagingError('distro Go license package ownership verification failed') from exc
    return read_license(notice, 'distro Go toolchain license')


def run_document(target, version):
    command = '.\\harness-console.exe' if target.startswith('windows-') else './harness-console'
    return (
        f'Agent Harness Console — archive label {version}, target {target}\n\n'
        f'Extract this archive, then run {command} from a terminal.\n'
        'The app opens its local browser interface. Use --help for options.\n'
        'No Go, Node or Python installation is needed to run this executable.\n'
        'Install and sign in to Codex CLI and/or Claude Code separately for model sessions.\n'
        'Provider availability, account access and permissions are checked at runtime.\n\n'
        'This is an unsigned, unnotarized build. Follow your organization\'s software policy.\n'
        'This compile-only check does not prove execution on this target,\n'
        'browser rendering, provider authentication, or production readiness.\n'
        'The archive label does not override the application\'s embedded version.\n'
        'SHA256SUMS detects corruption; it is not a signature or publisher identity proof.\n'
        'LICENSE contains the application MIT license; GO-LICENSE is the installed\n'
        'Go toolchain notice covering the Go code compiled into this executable.\n'
        'Close the app through its shutdown control to stop its owned processes.\n'
        'Documentation: https://github.com/ericmacdougall/agent-harness/blob/main/docs/console.md\n'
    ).encode('utf-8')


def write_archive(destination, binary, target, version, licenses):
    executable = 'harness-console.exe' if target.startswith('windows-') else 'harness-console'
    document = run_document(target, version)
    notices = (('RUN.txt', document), ('LICENSE', licenses['LICENSE']), ('GO-LICENSE', licenses['GO-LICENSE']))
    if target.startswith('windows-'):
        with zipfile.ZipFile(destination, 'x', compression=zipfile.ZIP_DEFLATED) as archive:
            for name, data, mode in ((executable, binary.read_bytes(), 0o755),
                                     *((name, data, 0o644) for name, data in notices)):
                info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
                info.create_system = 3
                info.external_attr = (stat.S_IFREG | mode) << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                archive.writestr(info, data)
    else:
        with destination.open('xb') as raw, gzip.GzipFile(filename='', fileobj=raw, mode='wb', mtime=0) as gz:
            with tarfile.open(fileobj=gz, mode='w', format=tarfile.USTAR_FORMAT) as archive:
                info = tarfile.TarInfo(executable)
                info.size, info.mode = binary.stat().st_size, 0o755
                with binary.open('rb') as data:
                    archive.addfile(info, data)
                for name, data in notices:
                    info = tarfile.TarInfo(name)
                    info.size, info.mode = len(data), 0o644
                    archive.addfile(info, io.BytesIO(data))


def digest_file(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def publish_archive(source, destination):
    with source.open('rb') as reader, destination.open('xb') as writer:
        shutil.copyfileobj(reader, writer)
        writer.flush()
        os.fsync(writer.fileno())
    destination.chmod(0o644)


def package(output, version, targets=TARGETS):
    if not isinstance(version, str) or len(version) > 64 or VERSION.fullmatch(version) is None:
        raise PackagingError('version must be a numeric SemVer such as 0.1.0')
    targets = tuple(targets)
    if not targets or len(set(targets)) != len(targets) or any(target not in TARGETS for target in targets):
        raise PackagingError('choose distinct supported targets only')
    output = validate_output(output)
    go = shutil.which('go')
    if not go:
        raise PackagingError('installed Go toolchain not found; Go 1.22 or newer is required')
    go = str(Path(go).resolve())
    licenses = {'LICENSE': read_license(ROOT / 'LICENSE', 'repository license')}
    archives = []
    try:
        with tempfile.TemporaryDirectory(prefix='.console-package-', dir=output.parent) as folder:
            staging = Path(folder)
            (staging / 'cache').mkdir(mode=0o700)
            (staging / 'tmp').mkdir(mode=0o700)
            try:
                licenses['GO-LICENSE'] = read_go_license(go, staging)
            except PackagingError as exc:
                raise PackagingError(f'Go license discovery failed: {exc}') from exc
            for target in targets:
                binary = staging / ('build-' + target)
                argv = [go, 'build', '-trimpath', '-buildvcs=false', '-mod=readonly',
                        '-ldflags=-buildid=', '-o', str(binary), '.']
                try:
                    run_build(argv, cwd=ROOT / 'console', env=build_environment(target, staging), timeout=BUILD_TIMEOUT)
                    metadata = binary.lstat()
                    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                        raise PackagingError('build output is not a private regular file')
                    if metadata.st_size == 0:
                        raise PackagingError('build output is empty')
                except (OSError, PackagingError) as exc:
                    reason = str(exc) if isinstance(exc, PackagingError) else 'build output unavailable'
                    raise PackagingError(f'{target}: {reason}') from exc
                extension = '.zip' if target.startswith('windows-') else '.tar.gz'
                archive = staging / f'harness-console-{version}-{target}{extension}'
                try:
                    write_archive(archive, binary, target, version, licenses)
                except OSError as exc:
                    raise PackagingError(f'{target}: archive write failed') from exc
                archives.append(archive)
                binary.unlink()

            # Reserve exclusively only after every build/archive succeeds. A partial
            # publication is retained for inspection, never presented as complete.
            validate_output(output)
            output.mkdir(mode=0o700)
            try:
                checksums = []
                for archive in archives:
                    destination = output / archive.name
                    publish_archive(archive, destination)
                    checksums.append(f'{digest_file(destination)}  {destination.name}\n')
                manifest = output / '.SHA256SUMS.tmp'
                with manifest.open('x', encoding='ascii', newline='\n') as writer:
                    writer.write(''.join(checksums))
                    writer.flush()
                    os.fsync(writer.fileno())
                manifest.chmod(0o644)
                output.chmod(0o755)
                os.replace(manifest, output / 'SHA256SUMS')
            except OSError as exc:
                raise PackagingError('publish failed; output is incomplete without SHA256SUMS; choose a new output directory') from exc
    except OSError as exc:
        raise PackagingError('could not create package staging or exclusive output directory') from exc
    return output


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--output-dir', required=True, type=Path, help='absolute new directory; parent must exist')
    parser.add_argument('--version', required=True, help='numeric archive version, e.g. 0.1.0')
    parser.add_argument('--target', action='append', choices=TARGETS,
                        help='repeat to select fixed targets; default is all six')
    args = parser.parse_args(argv)
    try:
        output = package(args.output_dir, args.version, args.target or TARGETS)
    except PackagingError as exc:
        print(f'Packaging failed: {exc}', file=sys.stderr)
        return 1
    print(f'Packaged {len(args.target or TARGETS)} unsigned compile-only targets; SHA256SUMS in {output}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
