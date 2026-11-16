#!/usr/bin/env python3
"""apply-job-secrets-host.py -- goodqa#16148 spec v4 AC-11 (build conditions R1 to R4).

Applies, on the self-host app VM, the parts of the job-secret wiring that no release applies:
  * in the live compose.yaml, the job-dispatcher service gets two marked lines:
        group_add: ["64910"] # goodqa#16148 AC-11
        volumes: ["/etc/goodqa/job-secrets:/run/goodqa-secrets:ro"] # goodqa#16148 AC-11
  * /etc/goodqa/dispatcher.env gets the key line
        JOB_ENVFILE_INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY=/run/goodqa-secrets/github-app-private-key
    (a path, not a secret; raw env_file lines cannot carry a comment, so this line is matched exactly).
The goodqa-jobsecret group and the /etc/goodqa/job-secrets directory are created by
derive-job-secrets.py, which apply-job-secrets.sh streams first under the same deploy lock; this
script only checks them. It never reads or prints a secret value and never recreates a container.

Not run directly: apply-job-secrets.sh (on the release runner) takes the deploy lock and streams
it as root:  ssh <app> sudo python3 -I - --dir D --env-dir E (--check | apply --stamp S | restore)

  --check   read-only; one line per item: `<item>: present|absent|conflict`.
  apply     refuses unless every item is present or absent (no conflict); validates the new
            compose with `docker compose config -q` before any file changes; writes a backup of
            each file it will change (<file>.pre-16148-<S>, O_EXCL|O_NOFOLLOW, root 0600, kept for the
            newest 3 stamps); then dispatcher.env, then compose.yaml, each through a directory fd,
            a temp file and a rename, keeping the file's owner and mode. Idempotent.
  restore   removes exactly the lines apply inserted (R1): a later release pin or set-secret-env
            key is kept. Refuses if a marked line was changed.
Exit 0 ok, 2 refused.
"""
import argparse
import os
import re
import secrets
import stat
import subprocess
import sys

MARK = '# goodqa#16148 AC-11'
GROUP_LINE = '    group_add: ["64910"] ' + MARK
VOL_LINE = '    volumes: ["/etc/goodqa/job-secrets:/run/goodqa-secrets:ro"] ' + MARK
ENV_KEY = 'JOB_ENVFILE_INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY'
ENV_LINE = ENV_KEY + '=/run/goodqa-secrets/github-app-private-key'
SECRETS_DIR = 'job-secrets'
GID = 64910
GROUP = 'goodqa-jobsecret'
BACKUP_INFIX = '.pre-16148-'
KEEP_BACKUPS = 3
STAMP_RE = re.compile(r'^\d{8}T\d{6}Z$')


class Refused(Exception):
    pass


# ---- safe file io (directory fd, no links, temp + rename) --------------------------------------
def open_dir(path):
    try:
        return os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError:
        raise Refused('%s is missing, a symlink or not a directory' % path)


def read_file(dfd, name):
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dfd)
    except FileNotFoundError:
        raise Refused('%s is missing' % name)
    except OSError:
        raise Refused('%s is a symlink or unreadable' % name)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise Refused('%s is not a regular file' % name)
        chunks = []
        while True:
            b = os.read(fd, 65536)
            if not b:
                break
            chunks.append(b)
        return b''.join(chunks), st
    finally:
        os.close(fd)


def write_new(dfd, name, data, uid, gid, mode):
    """Create `name` (must not exist) with O_EXCL|O_NOFOLLOW, owner and mode set on the fd."""
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=dfd)
    try:
        os.fchown(fd, uid, gid)
        os.fchmod(fd, mode)
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view):]
        os.fsync(fd)
    finally:
        os.close(fd)


def replace_file(dfd, name, data, st, hooks=None, validate=None):
    tmp = '.%s.tmp-%s' % (name, secrets.token_hex(6))
    write_new(dfd, tmp, data, st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode))
    try:
        if validate:
            validate(tmp)
        if hooks and hooks.get('before_rename_' + name):
            hooks['before_rename_' + name]()
        os.rename(tmp, name, src_dir_fd=dfd, dst_dir_fd=dfd)
        os.fsync(dfd)
    except BaseException:
        try:
            os.unlink(tmp, dir_fd=dfd)
        except OSError:
            pass
        raise


# ---- compose edits ---------------------------------------------------------------------------
def _service_block(lines, service):
    """(start, end) line indexes of `  service:` up to the next top-level or service key."""
    try:
        start = lines.index('  %s:' % service)
    except ValueError:
        raise Refused('compose.yaml has no %s service' % service)
    end = start + 1
    while end < len(lines) and (lines[end] == '' or lines[end].startswith('    ') or lines[end].lstrip().startswith('#')):
        end += 1
    while end > start + 1 and lines[end - 1].strip() == '':
        end -= 1
    return start, end


def compose_status(text):
    lines = text.split('\n')
    start, end = _service_block(lines, 'job-dispatcher')
    block = lines[start:end]
    out = {}
    for item, want, key in (('group_add', GROUP_LINE, '    group_add:'), ('mount', VOL_LINE, '    volumes:')):
        have = [l for l in block if l.startswith(key)]
        if have == [want]:
            out[item] = 'present'
        elif not have and not any(MARK in l and l.startswith(key) for l in lines):
            out[item] = 'absent'
        else:
            out[item] = 'conflict'
    if sum(1 for l in lines if '/etc/goodqa/job-secrets' in l or '64910' in l) != sum(1 for l in block if l in (GROUP_LINE, VOL_LINE)):
        out['mount'] = 'conflict'
    return out


def compose_apply(text):
    lines = text.split('\n')
    st = compose_status(text)
    _start, end = _service_block(lines, 'job-dispatcher')
    add = [l for item, l in (('group_add', GROUP_LINE), ('mount', VOL_LINE)) if st[item] == 'absent']
    return '\n'.join(lines[:end] + add + lines[end:])


def compose_restore(text):
    lines = text.split('\n')
    marked = [l for l in lines if MARK in l]
    if any(l not in (GROUP_LINE, VOL_LINE) for l in marked):
        raise Refused('a goodqa#16148 marked line in compose.yaml was changed; restore by hand')
    return '\n'.join(l for l in lines if l not in (GROUP_LINE, VOL_LINE))


# ---- dispatcher.env edits --------------------------------------------------------------------
def env_status(data):
    lines = data.split(b'\n')
    have = [l for l in lines if l.lstrip().startswith(ENV_KEY.encode() + b'=') or l.strip() == ENV_KEY.encode()]
    if have == [ENV_LINE.encode()]:
        return 'present'
    if not have:
        return 'absent'
    return 'conflict'


def env_apply(data):
    if env_status(data) == 'present':
        return data
    if data and not data.endswith(b'\n'):
        raise Refused('dispatcher.env does not end with a newline')
    return data + ENV_LINE.encode() + b'\n'


def env_restore(data):
    st = env_status(data)
    if st == 'conflict':
        raise Refused('dispatcher.env holds another %s line; restore by hand' % ENV_KEY)
    if st == 'absent':
        return data
    lines = data.split(b'\n')
    i = lines.index(ENV_LINE.encode())
    return b'\n'.join(lines[:i] + lines[i + 1:])


# ---- group and directory (made by derive; checked here) -------------------------------------
def _getent(*args):
    try:
        r = subprocess.run(['getent', *args], capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        raise Refused('getent failed')
    return r.stdout if r.returncode == 0 else ''


def group_status():
    rows = [l.split(':') for l in (_getent('group', GROUP) + _getent('group', str(GID))).splitlines() if l.count(':') >= 3]
    if not rows:
        return 'absent'
    if all(r[0] == GROUP and r[2] == str(GID) and r[3] == '' for r in rows):
        return 'present'
    return 'conflict'


def dir_status(env_dfd):
    try:
        st = os.stat(SECRETS_DIR, dir_fd=env_dfd, follow_symlinks=False)
    except FileNotFoundError:
        return 'absent'
    if stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and st.st_gid == 0 and stat.S_IMODE(st.st_mode) == 0o711:
        return 'present'
    return 'conflict'


# ---- commands --------------------------------------------------------------------------------
def status_lines(a):
    ddfd, edfd = open_dir(a.dir), open_dir(a.env_dir)
    try:
        comp, _ = read_file(ddfd, 'compose.yaml')
        env, _ = read_file(edfd, 'dispatcher.env')
        cs = compose_status(comp.decode('utf-8'))
        return [
            ('compose job-dispatcher group_add', cs['group_add']),
            ('compose job-dispatcher mount', cs['mount']),
            ('dispatcher.env ' + ENV_KEY, env_status(env)),
            ('group ' + GROUP, group_status()),
            ('dir /etc/goodqa/' + SECRETS_DIR, dir_status(edfd)),
        ]
    finally:
        os.close(ddfd)
        os.close(edfd)


def backup(dfd, name, data, stamp):
    write_new(dfd, name + BACKUP_INFIX + stamp, data, 0, 0, 0o600)


def prune_backups(dfd, name):
    pat = re.compile(re.escape(name + BACKUP_INFIX) + r'(\d{8}T\d{6}Z)$')
    found = sorted((m.group(1), e) for e in os.listdir(dfd) for m in [pat.match(e)] if m)
    for _s, entry in found[:-KEEP_BACKUPS]:
        if stat.S_ISREG(os.stat(entry, dir_fd=dfd, follow_symlinks=False).st_mode):
            os.unlink(entry, dir_fd=dfd)


def validate_compose(dir_path, tmp_name):
    r = subprocess.run(['docker', 'compose', '-f', os.path.join(dir_path, tmp_name), '--project-directory', dir_path, 'config', '-q'],
                       capture_output=True, timeout=120)
    if r.returncode != 0:
        raise Refused('the new compose.yaml does not validate (docker compose config -q exit %d)' % r.returncode)


def cmd_apply(a, hooks=None):
    if not STAMP_RE.match(a.stamp or ''):
        raise Refused('--stamp must be YYYYMMDDTHHMMSSZ')
    items = status_lines(a)
    bad = [i for i, s in items if s == 'conflict']
    if bad:
        raise Refused('conflict: ' + ', '.join(bad))
    if dict(items)['group ' + GROUP] != 'present' or dict(items)['dir /etc/goodqa/' + SECRETS_DIR] != 'present':
        raise Refused('the group or the secrets directory is absent: derive-job-secrets.py must run first')
    ddfd, edfd = open_dir(a.dir), open_dir(a.env_dir)
    try:
        comp, cst = read_file(ddfd, 'compose.yaml')
        env, est = read_file(edfd, 'dispatcher.env')
        new_comp = compose_apply(comp.decode('utf-8')).encode('utf-8')
        new_env = env_apply(env)
        if new_comp == comp and new_env == env:
            return 'unchanged'
        # Validate before any file changes: a temp copy of the new compose, then removed.
        if new_comp != comp:
            probe = '.compose.yaml.validate-%s' % secrets.token_hex(6)
            write_new(ddfd, probe, new_comp, cst.st_uid, cst.st_gid, stat.S_IMODE(cst.st_mode))
            try:
                validate_compose(a.dir, probe)
            finally:
                os.unlink(probe, dir_fd=ddfd)
        if new_env != env:
            backup(edfd, 'dispatcher.env', env, a.stamp)
        if new_comp != comp:
            backup(ddfd, 'compose.yaml', comp, a.stamp)
        if new_env != env:
            replace_file(edfd, 'dispatcher.env', new_env, est, hooks)
        if hooks and hooks.get('between_files'):
            hooks['between_files']()
        if new_comp != comp:
            replace_file(ddfd, 'compose.yaml', new_comp, cst, hooks)
        prune_backups(edfd, 'dispatcher.env')
        prune_backups(ddfd, 'compose.yaml')
        return 'applied'
    finally:
        os.close(ddfd)
        os.close(edfd)


def cmd_restore(a):
    ddfd, edfd = open_dir(a.dir), open_dir(a.env_dir)
    try:
        comp, cst = read_file(ddfd, 'compose.yaml')
        env, est = read_file(edfd, 'dispatcher.env')
        new_comp = compose_restore(comp.decode('utf-8')).encode('utf-8')
        new_env = env_restore(env)
        if new_comp != comp:
            replace_file(ddfd, 'compose.yaml', new_comp, cst)
        if new_env != env:
            replace_file(edfd, 'dispatcher.env', new_env, est)
        return 'restored' if (new_comp != comp or new_env != env) else 'nothing to restore'
    finally:
        os.close(ddfd)
        os.close(edfd)


def run(argv, hooks=None):
    p = argparse.ArgumentParser(prog='apply-job-secrets-host.py')
    p.add_argument('--dir', required=True)
    p.add_argument('--env-dir', required=True)
    p.add_argument('--check', action='store_true')
    p.add_argument('cmd', nargs='?', choices=['apply', 'restore'])
    p.add_argument('--stamp')
    a = p.parse_args(argv)
    try:
        if a.check == bool(a.cmd):
            raise Refused('give exactly one of --check, apply, restore')
        if a.check:
            return ['%s: %s' % (i, s) for i, s in status_lines(a)], 0
        if a.cmd == 'apply':
            return ['job secrets host apply: ' + cmd_apply(a, hooks)], 0
        return ['job secrets host restore: ' + cmd_restore(a)], 0
    except Refused as e:
        return ['job secrets host %s: REFUSED %s' % (a.cmd or 'check', e)], 2
    except OSError as e:
        return ['job secrets host %s: REFUSED os error (%s)' % (a.cmd or 'check', type(e).__name__)], 2


def main():
    argv = sys.argv[1:]
    lines, code = run(argv)
    sys.stdout.write(''.join(l + '\n' for l in lines))
    return code


if __name__ == '__main__':
    sys.exit(main())
