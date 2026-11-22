#!/usr/bin/env python3
"""Apply a reviewed, hash-bound module patch on the local host and physical t2-dev."""
from __future__ import annotations
import argparse
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile

MAX_BYTES = 8 * 1024 * 1024
TARGETS = {'.claude/hooks/native_main.py', '.codex/agent-harness/native_main.py'}

def digest(data):
    return hashlib.sha256(data).hexdigest()

def regular(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid() or info.st_mode & 0o022:
        raise ValueError('Unqualified module or journal file')
    if info.st_size > MAX_BYTES:
        raise ValueError('File exceeds size limit')
    return path.read_bytes()

def parents(home, path):
    if home.resolve(strict=True) != home:
        raise ValueError('Home directory is aliased')
    current = home
    for part in path.relative_to(home).parts[:-1]:
        current = current / part
        info = current.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o022:
            raise ValueError('Unqualified parent directory')

def atomic(path, data, mode):
    fd, scratch = tempfile.mkstemp(prefix=path.name + '.takeover-', dir=path.parent)
    pending = Path(scratch)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fchmod(stream.fileno(), mode)
            os.fsync(stream.fileno())
        os.replace(pending, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if pending.exists():
            pending.unlink()

def validate(manifest, host):
    if manifest.get('version') != 1 or not re.fullmatch(r'[a-z0-9-]{8,80}', manifest.get('id', '')):
        raise ValueError('Invalid manifest identity')
    entries = manifest.get('files')
    if not isinstance(entries, list) or not 1 <= len(entries) <= 24:
        raise ValueError('Invalid module count')
    seen = set()
    for entry in entries:
        target = entry['target']
        if not isinstance(target, str) or target not in TARGETS or Path(target).suffix != '.py' or '..' in Path(target).parts or target in seen:
            raise ValueError('Unqualified module target')
        seen.add(target)
        data = base64.b64decode(entry['content'], validate=True)
        if len(data) > MAX_BYTES or digest(data) != entry['after']:
            raise ValueError('Candidate digest mismatch')
        if not re.fullmatch('[a-f0-9]{64}', entry['before'][host]):
            raise ValueError('Missing exact installed digest')
        compile(data, target, 'exec')
    return entries

def worker(manifest, host, action, home=None):
    home = Path(home) if home is not None else Path.home()
    entries = validate(manifest, host)
    for entry in entries:
        target = home / entry['target']
        parents(home, target)
        current = digest(regular(target))
        if current not in (entry['before'][host], entry['after']):
            raise ValueError('Installed module changed: ' + entry['target'])
    if action == 'plan':
        return {'host': host, 'status': 'READY', 'files': len(entries)}
    state = home / '.agent-harness' / 'takeover-patches' / manifest['id']
    for directory in (home / '.agent-harness', home / '.agent-harness' / 'takeover-patches', state):
        directory.mkdir(mode=0o700, exist_ok=True)
        parents(home, directory / 'placeholder')
    lock = os.open(state / 'lock', os.O_CREAT | os.O_NOFOLLOW | os.O_RDWR, 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX)
        identity = json.dumps(manifest, sort_keys=True).encode()
        manifest_path = state / 'manifest.json'
        if manifest_path.exists():
            if regular(manifest_path) != identity:
                raise ValueError('Patch identity already belongs to different bytes')
        else:
            atomic(manifest_path, identity, 0o600)
        changed = []
        try:
            for index, entry in enumerate(entries):
                target = home / entry['target']
                parents(home, target)
                current = regular(target)
                current_hash = digest(current)
                backup = state / (str(index) + '.before')
                mode_file = state / (str(index) + '.mode')
                if backup.exists():
                    if digest(regular(backup)) != entry['before'][host]:
                        raise ValueError('Backup digest mismatch')
                    if not mode_file.exists():
                        # A prior attempt can stop after persisting the backup.
                        mode = stat.S_IMODE(target.stat().st_mode)
                        atomic(mode_file, str(mode).encode(), 0o600)
                    mode = int(regular(mode_file))
                    if mode & ~0o777 or mode & 0o022:
                        raise ValueError('Invalid recorded permissions')
                elif current_hash == entry['before'][host]:
                    mode = stat.S_IMODE(target.stat().st_mode)
                    atomic(backup, current, 0o600)
                    atomic(mode_file, str(mode).encode(), 0o600)
                else:
                    raise ValueError('Installed candidate lacks its recovery backup')
                expected = entry['before'][host] if action == 'rollback' else entry['after']
                if current_hash == expected:
                    continue
                if current_hash not in (entry['before'][host], entry['after']):
                    raise ValueError('Concurrent module modification')
                data = regular(backup) if action == 'rollback' else base64.b64decode(entry['content'], validate=True)
                changed.append((target, backup, mode))
                atomic(target, data, mode)
                if digest(regular(target)) != expected:
                    raise ValueError('Postinstall digest mismatch')
        except BaseException:
            if action == 'apply':
                for target, backup, mode in reversed(changed):
                    entry = next(e for e in entries if home / e['target'] == target)
                    actual = digest(regular(target))
                    if actual == entry['before'][host]:
                        continue
                    if actual != entry['after']:
                        raise ValueError('Recovery refused concurrent module change')
                    atomic(target, regular(backup), mode)
            raise
        receipt = {'host': host, 'status': 'ROLLED_BACK' if action == 'rollback' else 'APPLIED', 'files': len(entries), 'manifest': digest(identity)}
        atomic(state / 'receipt.json', json.dumps(receipt).encode(), 0o600)
        return receipt
    finally:
        os.close(lock)

def call_remote(source, manifest, action, ssh_config):
    payload = json.dumps({'manifest': manifest, 'action': action}).encode()
    code = source + '\nrequest=json.loads(sys.stdin.read())\nprint(json.dumps(worker(request["manifest"],"t2-dev",request["action"])))\n'
    import shlex
    command = 'python3 -B -c ' + shlex.quote(code)
    result = subprocess.run(['ssh', '-F', ssh_config, '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes', '-o', 'UpdateHostKeys=no', 't2-dev', command], input=payload, capture_output=True, timeout=90)
    if result.returncode:
        raise RuntimeError('t2-dev patch operation failed; inspect the private recovery directory on t2-dev')
    return json.loads(result.stdout)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--manifest-sha256', required=True)
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--rollback', action='store_true')
    parser.add_argument('--ssh-config', default=str(Path.home() / '.ssh/config_fleetops'))
    args = parser.parse_args()
    if args.apply and args.rollback:
        parser.error('Choose apply or rollback')
    raw_manifest = regular(args.manifest.absolute())
    if digest(raw_manifest) != args.manifest_sha256:
        parser.error('Manifest digest does not match the reviewed release')
    manifest = json.loads(raw_manifest)
    source = Path(__file__).read_text().split('\n# TAKEOVER_CLI_ENTRY\n')[0]
    print(json.dumps(worker(manifest, 'local', 'plan')))
    print(json.dumps(call_remote(source, manifest, 'plan', args.ssh_config)))
    if args.apply or args.rollback:
        action = 'rollback' if args.rollback else 'apply'
        print(json.dumps(worker(manifest, 'local', action)))
        try:
            print(json.dumps(call_remote(source, manifest, action, args.ssh_config)))
        except BaseException:
            if action == 'apply':
                print(json.dumps(worker(manifest, 'local', 'rollback')))
            raise
    print('Module operation verified.' if args.apply or args.rollback else 'Module preflight verified.')
    print('Broker activation, capacity recovery, native hook trust and actual release qualification require their own evidence.')

# TAKEOVER_CLI_ENTRY
if __name__ == '__main__':
    main()
