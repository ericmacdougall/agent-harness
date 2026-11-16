#!/usr/bin/env python3
"""derive-job-secrets.py -- goodqa#16148 spec v4 AC-1, AC-2, AC-9.

Run as root on the self-host app VM, as `python3 -I derive-job-secrets.py [--check]`. It derives
/etc/goodqa/job-secrets/github-app-private-key (root:goodqa-jobsecret 0440, in a root:root 0711
directory) from the GITHUB_APP_PRIVATE_KEY line of /etc/goodqa/api.env. Only the job-dispatcher
mounts that directory (read-only, group_add 64910), and the dispatcher reads the file per launch
(JOB_ENVFILE_INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY).

Output is exactly one line, never the value:
    job secret github-app-private-key: written | unchanged | REFUSED <reason>
    job secret github-app-private-key: same | different | REFUSED <reason>        (--check)
Exit 0 on written/unchanged/same/different, 2 on REFUSED.

Parsing matches Docker Compose 5.6.0 `env_file: format: raw` (probed with fake values):
  - `#` lines are comments; leading whitespace before the key is dropped;
  - a line splits on its first `=`; the value is verbatim (quotes, trailing spaces, inner `#` kept);
  - a final CR is stripped; a key holding whitespace (an `export KEY=` line) makes compose refuse.
derive is stricter: it refuses no line, more than one line, an `export` form, an empty value, a
value byte outside printable ASCII 0x20-0x7E, and any line compose itself would refuse.

The value is written byte for byte (no decoding). Every write is relative to a directory fd that
was opened O_DIRECTORY|O_NOFOLLOW and checked with fstat; the file is created under a random
temp name with O_CREAT|O_EXCL|O_NOFOLLOW, fchown/fchmod on the fd, written, fsynced, renamed
within the directory fd, and the directory is fsynced. An unchanged value leaves the file alone.
The value never appears in argv, output, a log or a hash.
"""
import os
import secrets
import subprocess
import sys

NAME = 'github-app-private-key'
SOURCE_KEY = 'GITHUB_APP_PRIVATE_KEY'
GROUP = 'goodqa-jobsecret'
GID = 64910
DIR_MODE = 0o711
FILE_MODE = 0o440
MAX_SOURCE = 1024 * 1024


class Refused(Exception):
    pass


def _p(root, path):
    return os.path.join(root, path.lstrip('/')) if root != '/' else path


# ---- AC-1: parse ----------------------------------------------------------------------------
def parse_api_env(data):
    """Return the GITHUB_APP_PRIVATE_KEY value (bytes) exactly as compose would deliver it, or raise Refused."""
    found = []
    for raw in data.split(b'\n'):
        line = raw[:-1] if raw.endswith(b'\r') else raw
        stripped = line.lstrip(b' \t')
        if stripped == b'' or stripped.startswith(b'#'):
            continue
        key, eq, value = stripped.partition(b'=')
        if not eq:
            if any(c in key for c in b' \t'):
                raise Refused('api.env has a line compose would refuse')
            continue
        if key.split()[:2] == [b'export', SOURCE_KEY.encode()] or key.startswith(b'export ' + SOURCE_KEY.encode()):
            raise Refused('export form')
        if any(c in key for c in b' \t\x0b\x0c'):
            raise Refused('api.env has a line compose would refuse')
        if key == SOURCE_KEY.encode():
            found.append(value)
    if not found:
        raise Refused('no GITHUB_APP_PRIVATE_KEY line')
    if len(found) > 1:
        raise Refused('more than one GITHUB_APP_PRIVATE_KEY line')
    value = found[0]
    if value == b'':
        raise Refused('empty value')
    if any(b < 0x20 or b > 0x7e for b in value):
        raise Refused('value holds a byte outside printable ASCII')
    return value


def read_source(root):
    path = _p(root, '/etc/goodqa/api.env')
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        raise Refused('api.env unreadable')
    try:
        st = os.fstat(fd)
        if not _is_reg(st.st_mode):
            raise Refused('api.env is not a regular file')
        chunks, total = [], 0
        while True:
            b = os.read(fd, 65536)
            if not b:
                break
            total += len(b)
            if total > MAX_SOURCE:
                raise Refused('api.env too large')
            chunks.append(b)
        return b''.join(chunks)
    finally:
        os.close(fd)


def _is_reg(mode):
    import stat
    return stat.S_ISREG(mode)


def _is_dir(mode):
    import stat
    return stat.S_ISDIR(mode)


# ---- AC-2: the group (files and NSS) --------------------------------------------------------
def _group_rows(text):
    rows = []
    for line in text.splitlines():
        parts = line.split(':')
        if len(parts) >= 4 and parts[0] and parts[2].isdigit():
            rows.append((parts[0], int(parts[2]), [m for m in parts[3].split(',') if m]))
    return rows


def _passwd_primary_gids(text):
    out = []
    for line in text.splitlines():
        parts = line.split(':')
        if len(parts) >= 4 and parts[3].isdigit():
            out.append((parts[0], int(parts[3])))
    return out


def _read_text(path):
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            return f.read()
    except FileNotFoundError:
        return ''


def _getent(*args):
    try:
        r = subprocess.run(['getent', *args], capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        raise Refused('getent failed')
    if r.returncode == 2:
        return ''
    if r.returncode != 0:
        raise Refused('getent failed')
    return r.stdout


def check_group(root):
    """Return True if the group exists correctly, False if absent; raise Refused on any collision."""
    sources = [_read_text(_p(root, '/etc/group')), _getent('group', GROUP) + _getent('group', str(GID))]
    present = False
    for text in sources:
        for name, gid, members in _group_rows(text):
            if name == GROUP and gid != GID:
                raise Refused('group name goodqa-jobsecret has another gid')
            if gid == GID and name != GROUP:
                raise Refused('gid 64910 has another name')
            if name == GROUP and gid == GID:
                if members:
                    raise Refused('group goodqa-jobsecret has members')
                present = True
    for text in (_read_text(_p(root, '/etc/passwd')), _getent('passwd')):
        for _user, gid in _passwd_primary_gids(text):
            if gid == GID:
                raise Refused('an account has gid 64910 as its primary group')
    return present


def ensure_group(root):
    if check_group(root):
        return
    cmd = ['groupadd', '-r', '-g', str(GID), GROUP]
    if root != '/':
        cmd[1:1] = ['-R', root]
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        raise Refused('groupadd failed')
    if r.returncode != 0:
        raise Refused('groupadd failed')
    if not check_group(root):
        raise Refused('group not present after groupadd')


# ---- AC-2: directory and file ---------------------------------------------------------------
def _check_parent(root):
    parent = _p(root, '/etc/goodqa')
    try:
        pfd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError:
        raise Refused('/etc/goodqa is missing, a symlink or not a directory')
    st = os.fstat(pfd)
    if st.st_uid != 0 or st.st_mode & 0o022:
        os.close(pfd)
        raise Refused('/etc/goodqa is not root-owned or is group or world writable')
    return pfd


def open_secrets_dir(root, create):
    pfd = _check_parent(root)
    try:
        try:
            dfd = os.open('job-secrets', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=pfd)
        except FileNotFoundError:
            if not create:
                return None
            os.mkdir('job-secrets', 0o700, dir_fd=pfd)
            dfd = os.open('job-secrets', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=pfd)
            os.fchown(dfd, 0, 0)
            os.fchmod(dfd, DIR_MODE)
            os.fsync(pfd)
        except OSError:
            raise Refused('job-secrets is a symlink or not a directory')
        st = os.fstat(dfd)
        if not _is_dir(st.st_mode) or st.st_uid != 0 or st.st_gid != 0 or (st.st_mode & 0o7777) != DIR_MODE:
            os.close(dfd)
            raise Refused('job-secrets has another owner, mode or type')
        return dfd
    finally:
        os.close(pfd)


def read_existing(dfd):
    """The current file's bytes, None if absent; refuse a link, a non-regular file or wrong owner/mode."""
    try:
        fd = os.open(NAME, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dfd)
    except FileNotFoundError:
        return None
    except OSError:
        raise Refused('the secret file is a symlink or unreadable')
    try:
        st = os.fstat(fd)
        if not _is_reg(st.st_mode) or st.st_uid != 0 or st.st_gid != GID or (st.st_mode & 0o7777) != FILE_MODE:
            raise Refused('the secret file has another owner, mode or type')
        chunks = []
        while True:
            b = os.read(fd, 65536)
            if not b:
                break
            chunks.append(b)
        return b''.join(chunks)
    finally:
        os.close(fd)


def sweep_temps(dfd):
    for entry in os.listdir(dfd):
        if entry.startswith('.tmp-'):
            os.unlink(entry, dir_fd=dfd)


def write_secret(dfd, value, hooks):
    tmp = '.tmp-' + secrets.token_hex(8)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=dfd)
    try:
        # The fd stays open until the check after the rename, so its inode cannot be freed and
        # its number reused by a swapped-in link.
        own = os.fstat(fd)
        os.fchown(fd, 0, GID)
        os.fchmod(fd, FILE_MODE)
        view = memoryview(value)
        while view:
            n = os.write(fd, view)
            view = view[n:]
        os.fsync(fd)
        if hooks and hooks.get('before_rename'):
            hooks['before_rename'](tmp)
        os.rename(tmp, NAME, src_dir_fd=dfd, dst_dir_fd=dfd)
        os.fsync(dfd)
        # The name must now be the very inode this run wrote through its fd (never a swapped-in link).
        now = os.stat(NAME, dir_fd=dfd, follow_symlinks=False)
        if not _is_reg(now.st_mode) or (now.st_dev, now.st_ino) != (own.st_dev, own.st_ino):
            raise Refused('the secret file changed during the write')
    except BaseException:
        try:
            os.unlink(tmp, dir_fd=dfd)
        except OSError:
            pass
        raise
    finally:
        os.close(fd)


def run(argv, root='/', hooks=None):
    check = argv == ['--check']
    if argv not in ([], ['--check']):
        return 'REFUSED usage: derive-job-secrets.py [--check]', 2
    try:
        value = parse_api_env(read_source(root))
        if check:
            check_group(root)
            dfd = open_secrets_dir(root, create=False)
            if dfd is None:
                return 'different', 0
            try:
                return ('same' if read_existing(dfd) == value else 'different'), 0
            finally:
                os.close(dfd)
        ensure_group(root)
        dfd = open_secrets_dir(root, create=True)
        try:
            sweep_temps(dfd)
            if read_existing(dfd) == value:
                return 'unchanged', 0
            write_secret(dfd, value, hooks)
            return 'written', 0
        finally:
            os.close(dfd)
    except Refused as e:
        return 'REFUSED ' + str(e), 2
    except OSError as e:
        return 'REFUSED os error (%s)' % (type(e).__name__,), 2


def main(root='/'):
    # The CLI always works on the real root; tests import this module and pass a fake root.
    word, code = run(sys.argv[1:], root=root)
    sys.stdout.write('job secret %s: %s\n' % (NAME, word))
    return code


if __name__ == '__main__':
    sys.exit(main())
