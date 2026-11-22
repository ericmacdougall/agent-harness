"""Metadata-only diagnostic prototype. RELATED/UNKNOWN never grants clearance.

Not registered with installers or command_guard. Privileged use requires a
separately reviewed root-owned deployment; imports support offline fixtures.
"""
import argparse
import json
import os
import re
import stat
import sys
import time

INSTALLED = '/usr/local/lib/agent-harness/process-visibility.py'
POLICY = '/usr/local/lib/agent-harness/process-visibility.json'
MAX_ENTRIES = 20000
MAX_REFERENCES = 512


class Refused(Exception):
    pass


def identity(info):
    return info.st_dev, info.st_ino


def bounded_names(path, limit):
    names = []
    with os.scandir(path) as entries:
        for entry in entries:
            if len(names) >= limit:
                raise Refused('metadata-cap')
            names.append(entry.name)
    return names


def inventory(path, limit, deadline):
    """Pin and walk metadata only. Never follow links or cross filesystems."""
    if os.path.realpath(path) != path or not os.path.isabs(path):
        raise Refused('target-policy')
    root = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    before = os.fstat(root)
    found = {identity(before)}
    complete = True

    def walk(fd, depth=0):
        nonlocal complete
        info = os.fstat(fd)
        try:
            names = bounded_names(fd, limit)
        except Refused:
            complete = False
            return
        if depth > 32 or len(names) + len(found) > limit or time.monotonic() > deadline:
            complete = False
            return
        for name in sorted(names):
            row = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if row.st_dev != before.st_dev or not (stat.S_ISREG(row.st_mode) or stat.S_ISDIR(row.st_mode)):
                complete = False
                continue
            found.add(identity(row))
            if len(found) > limit or time.monotonic() > deadline:
                complete = False
                return
            if stat.S_ISDIR(row.st_mode):
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                try:
                    if identity(os.fstat(child)) != identity(row):
                        raise Refused('source-changed')
                    walk(child, depth + 1)
                finally:
                    os.close(child)
        after = os.fstat(fd)
        if (info.st_ino, info.st_mtime_ns, info.st_ctime_ns) != (after.st_ino, after.st_mtime_ns, after.st_ctime_ns):
            raise Refused('source-changed')

    try:
        walk(root)
        return root, before, found, complete
    except BaseException:
        os.close(root)
        raise


class ProcView:
    """Fixed kernel interface; no caller-selected proc root or raw path output."""
    @staticmethod
    def read(path, limit=16384):
        with open(path, 'rb', buffering=0) as file:
            raw = file.read(limit + 1)
        if len(raw) > limit:
            raise Refused('metadata-cap')
        return raw.decode('ascii', 'strict')

    def boot(self):
        value = self.read('/proc/sys/kernel/random/boot_id', 64).strip()
        if not re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', value):
            raise Refused('boot-identity')
        return value

    def snapshot(self, pid):
        base = '/proc/' + str(pid)
        status = self.read(base + '/status')
        uid = next(line.split()[1:] for line in status.splitlines() if line.startswith('Uid:'))
        fields = self.read(base + '/stat').rsplit(')', 1)[1].split()
        namespaces = [os.readlink(base + '/ns/' + name) for name in ('user', 'mnt')]
        own = [os.readlink('/proc/self/ns/' + name) for name in ('user', 'mnt')]
        mapping = [[int(x) for x in line.split()] for line in self.read(base + '/uid_map').splitlines()]
        return {'start': int(fields[19]), 'uids': [int(x) for x in uid],
                'namespaces': namespaces, 'uid_map': mapping,
                'namespace_class': 'same-observer' if namespaces == own else 'foreign-or-unknown'}

    def references(self, pid):
        base = '/proc/' + str(pid)
        found, complete = [], True
        for name in ('cwd', 'root', 'exe'):
            try:
                ref = base + '/' + name
                if os.readlink(ref).endswith(' (deleted)'):
                    complete = False
                    continue
                fd = os.open(ref, os.O_PATH | os.O_CLOEXEC)
                try:
                    found.append(identity(os.fstat(fd)))
                finally:
                    os.close(fd)
            except OSError:
                complete = False
        for directory in ('fd', 'map_files'):
            try:
                parent = base + '/' + directory
                names = bounded_names(parent, MAX_REFERENCES)
                if len(names) + len(found) > MAX_REFERENCES:
                    complete = False
                    continue
                for name in names:
                    if not re.fullmatch(r'[0-9]+' if directory == 'fd' else r'[0-9a-f]+-[0-9a-f]+', name):
                        complete = False
                        continue
                    ref = parent + '/' + name
                    try:
                        if os.readlink(ref).endswith(' (deleted)'):
                            complete = False
                            continue
                        fd = os.open(ref, os.O_PATH | os.O_CLOEXEC)
                        try:
                            found.append(identity(os.fstat(fd)))
                        finally:
                            os.close(fd)
                    except OSError:
                        complete = False
                if sorted(bounded_names(parent, MAX_REFERENCES)) != sorted(names):
                    complete = False
            except (OSError, Refused):
                complete = False
        return found, complete


def valid_snapshot(row, start, caller_uid):
    return (isinstance(row, dict) and row.get('start') == start
            and row.get('uids') == [caller_uid] * 4
            and isinstance(row.get('namespaces'), list) and len(row['namespaces']) == 2
            and all(isinstance(n, str) and re.fullmatch(kind + r'(?::\[[0-9]+\]|:[0-9]+)', n)
                    for kind, n in zip(('user', 'mnt'), row['namespaces']))
            and isinstance(row.get('uid_map'), list) and 0 < len(row['uid_map']) <= 8
            and all(isinstance(m, list) and len(m) == 3 and all(type(v) is int and 0 <= v <= 4294967295 for v in m)
                    and m[2] > 0 for m in row['uid_map']))


def observe(path, requests, view, *, caller_uid, expected_target=None, max_entries=MAX_ENTRIES):
    if (not 0 < len(requests) <= 9 or len(set(requests)) != len(requests)
            or any(type(pid) is not int or type(start) is not int or pid <= 0 or start <= 0
                   for pid, start in requests)):
        raise Refused('request-policy')
    deadline = time.monotonic() + 5
    root, before, objects, complete = inventory(path, max_entries, deadline)
    rows = []
    try:
        if expected_target is not None and identity(before) != expected_target:
            raise Refused('source-identity')
        boot = view.boot()
        for pid, start in requests:
            row = {'pid': pid, 'start': start, 'relation': 'UNKNOWN', 'reason': 'incomplete-metadata'}
            try:
                snapshot = view.snapshot(pid)
                if not valid_snapshot(snapshot, start, caller_uid):
                    raise Refused('process-identity')
                references, refs_complete = view.references(pid)
                if view.snapshot(pid) != snapshot or view.boot() != boot or time.monotonic() > deadline:
                    raise Refused('process-changed')
                row.update(reference_count=len(references), references_complete=refs_complete,
                           source_inventory_complete=complete, uid_fields_valid=True,
                           source_object_count=len(objects),
                           namespace_class=snapshot.get('namespace_class', 'foreign-or-unknown'),
                           mount_class='unclassified-no-clearance')
                if set(references) & objects:
                    row.update(relation='RELATED', reason='direct-object-hit')
                else:
                    row['reason'] = 'no-clearance-supported'
            except (OSError, ValueError, IndexError, KeyError, StopIteration, Refused):
                pass
            rows.append(row)
        # No success survives source replacement or changes during observation.
        current = os.stat(path, follow_symlinks=False)
        pinned = os.fstat(root)
        if (identity(current) != identity(before) or identity(pinned) != identity(before)
                or current.st_mtime_ns != before.st_mtime_ns or current.st_ctime_ns != before.st_ctime_ns):
            for row in rows:
                row.update(relation='UNKNOWN', reason='source-changed')
        return {'v': 1, 'diagnostic_only': True, 'clearance': False,
                'target': {'device': before.st_dev, 'inode': before.st_ino}, 'observations': rows}
    finally:
        os.close(root)


def authorize(target, environ, euid, policy):
    if (euid != 0 or environ.get('SUDO_UID') != str(policy['caller_uid'])
            or environ.get('SUDO_USER') != policy['caller_name'] or target not in policy['targets']):
        raise Refused('invocation-policy')


def load_policy():
    protected(POLICY)
    fd = os.open(POLICY, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != 0 or info.st_mode & 0o077:
            raise Refused('policy-trust')
        raw = os.read(fd, 16385)
        if len(raw) > 16384:
            raise Refused('policy-cap')
    finally:
        os.close(fd)
    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                raise Refused('policy-schema')
            result[key] = value
        return result
    value = json.loads(raw, object_pairs_hook=pairs)
    if (not isinstance(value, dict) or set(value) != {'v', 'caller_uid', 'caller_name', 'targets'}
            or value['v'] != 1 or type(value['caller_uid']) is not int or value['caller_uid'] <= 0
            or not isinstance(value['caller_name'], str)
            or not re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}', value['caller_name'])
            or not isinstance(value['targets'], dict) or not 0 < len(value['targets']) <= 8):
        raise Refused('policy-schema')
    prefix = '/home/' + value['caller_name'] + '/'
    for path, binding in value['targets'].items():
        if (not isinstance(path, str) or len(path) > 256 or not path.startswith(prefix)
                or os.path.normpath(path) != path or any(part.startswith('.') for part in path.split('/') if part)
                or not isinstance(binding, list) or len(binding) != 2
                or any(type(n) is not int or n < 0 for n in binding)):
            raise Refused('policy-schema')
    return value


def protected(path):
    path = os.path.abspath(path)
    for candidate in (path, os.path.realpath(path)):
        while True:
            info = os.lstat(candidate)
            if info.st_uid != 0 or info.st_mode & 0o022:
                # Root-owned system symlinks have nominal0777 modes.
                if not (stat.S_ISLNK(info.st_mode) and info.st_uid == 0):
                    raise Refused('runtime-policy')
            if candidate == '/':
                break
            candidate = os.path.dirname(candidate)


def runtime():
    if (os.path.abspath(__file__) != INSTALLED or os.path.realpath(INSTALLED) != INSTALLED
            or os.path.realpath(sys.executable) != '/usr/bin/python3.12'
            or not sys.flags.isolated or not sys.flags.no_site or not sys.dont_write_bytecode):
        raise Refused('runtime-policy')
    protected(INSTALLED)
    protected('/usr/bin/python3.12')
    for module in tuple(sys.modules.values()):
        path = getattr(module, '__file__', None)
        if path:
            protected(path)


def main(argv=None):
    class SafeParser(argparse.ArgumentParser):
        def error(self, message):
            raise Refused('request-policy')
    parser = SafeParser(description=__doc__)
    parser.add_argument('--target', required=True)
    parser.add_argument('--pid', action='append', required=True, help='exact PID:start tuple, at most9')
    try:
        actual = sys.argv[1:] if argv is None else argv
        if len(actual) > 25 or any(len(value) > 256 for value in actual):
            raise Refused('request-policy')
        args = parser.parse_args(actual)
        runtime()
        policy = load_policy()
        authorize(args.target, os.environ, os.geteuid(), policy)
        pairs = []
        for value in args.pid:
            if not re.fullmatch(r'[1-9][0-9]{0,9}:[1-9][0-9]{0,19}', value):
                raise Refused('request-policy')
            pairs.append(tuple(map(int, value.split(':'))))
        os.chdir('/')
        os.environ.clear()
        result = observe(args.target, pairs, ProcView(), caller_uid=policy['caller_uid'],
                         expected_target=tuple(policy['targets'][args.target]))
        runtime()
        print(json.dumps(result, sort_keys=True))
        return 0
    except (OSError, ValueError, Refused, RecursionError):
        print(json.dumps({'v': 1, 'diagnostic_only': True, 'clearance': False,
                          'error': 'diagnostic-unavailable'}))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
