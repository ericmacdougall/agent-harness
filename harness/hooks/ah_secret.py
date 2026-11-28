#!/usr/bin/env python3
"""`ah secret`: move a secret from the clipboard into a secret store, and use it, without the value passing through a
model, an argv, an environment of this process's children (except `exec`'s), a log or the transcript.

    ah secret put NAME [--from clipboard|stdin|file:PATH] [--to gcp|keychain|file:PATH] [--project P]
                       [--keep-clipboard] [--raw] [--lines [--sep S --field N [--label-field M]]]
    ah secret exec --env VAR=NAME [--env VAR=NAME ...] [--store gcp|keychain|file:DIR] [--project P] -- CMD ARGS...
    ah secret list [--store ...] [--project P]
    ah secret rm NAME [--store ...] [--project P]

Any agent may run put, exec and list: the value never reaches its output. `rm` deletes, so it runs only for the owner
(a terminal outside any agent) or a session launched or recorded as a supervisor (ah_roles.launch_role); a worker or
reviewer is refused with the command the owner runs. The command guard that once judged these commands is deleted;
this tool runs outside the sandbox (sandbox_base.json harness_tools), so the role check here is the only gate.

put prints only name, store, version id and byte length per secret, never the value or a hash of it. The value is
stripped of surrounding whitespace (a copied key often carries a newline) unless --raw. After every secret is stored
the clipboard is cleared unless --keep-clipboard; on any failure it is kept so nothing is lost.

Stores:
  gcp       Google Secret Manager via gcloud: `secrets create NAME --replication-policy=automatic` when missing, then
            `secrets versions add NAME --data-file=-` with the value on stdin.
  keychain  macOS login keychain via `security -i`, the command on stdin with the value hex-encoded (-X), so it is on
            no argv. Items use account `ah-secret` (config: keychain_account) and service NAME.
  file:P    0600 file written atomically; P is the file, or a directory (existing, or ending in /) holding NAME.
Defaults come from ~/.agent-harness/secrets.json ({"store": ..., "project": ..., "keychain_account": ...}), else gcp.

Standard library only (plus redact.py beside it for exec's output masking).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import threading
from pathlib import Path

NAME_RE = re.compile(r'^[A-Za-z0-9_-]{1,255}$')
VAR_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9_]{0,127}$')
PROJECT_RE = re.compile(r'^[A-Za-z0-9_.:-]{1,100}$')
LABEL_RE = re.compile(r'^[A-Za-z0-9 _.:/@+-]{1,64}$')
KEYLIKE_RUN = re.compile(r'[A-Za-z0-9]{24,}')  # a label holding a run like this is probably the key: refuse it
MAX_VALUE = 64 * 1024  # GCP's payload limit
TIMEOUT = 120
HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:  # redact.py lives beside this file
    sys.path.insert(0, str(HERE))


class SecretError(Exception):
    def __init__(self, code, message, exit_code=2):
        super().__init__(message)
        self.code, self.exit_code = code, exit_code


def config(home=None) -> dict:
    path = Path(home or Path.home()) / '.agent-harness' / 'secrets.json'
    try:
        # input-ok: the user's own secret store or file, read by the user's CLI command
        data = json.loads(path.read_text())
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _tool(name):
    path = shutil.which(name)
    if not path:
        raise SecretError('missing_tool', '%s is not on PATH' % name, 4)
    return path


def _run(argv, data=None, capture=True):
    """Run a store tool. The value only ever goes in as `data` (stdin). Its stderr is returned for a masked message."""
    try:
        done = subprocess.run(argv, input=data if data is not None else b'', stdout=subprocess.PIPE if capture else None,
                              stderr=subprocess.PIPE, timeout=TIMEOUT, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise SecretError('tool_failed', '%s could not run (%s)' % (os.path.basename(argv[0]), type(error).__name__), 4)
    return done


def _fail(done, what, values=()):
    import redact  # noqa: PLC0415
    text = redact.redact(redact.mask_values((done.stderr or b'').decode('utf-8', 'replace'), list(values)))
    raise SecretError('store_failed', '%s failed (exit %d): %s' % (what, done.returncode, text.strip()[-400:]), 4)


# ---- clipboard ------------------------------------------------------------------------------------------------

def read_clipboard() -> bytes:
    for argv in (['pbpaste'], ['wl-paste', '--no-newline'], ['xclip', '-selection', 'clipboard', '-o']):
        if shutil.which(argv[0]):
            done = _run([shutil.which(argv[0])] + argv[1:])
            if done.returncode != 0:
                raise SecretError('clipboard', 'could not read the clipboard (%s exit %d)' % (argv[0], done.returncode))
            return done.stdout or b''
    raise SecretError('clipboard', 'no clipboard tool found (pbpaste, wl-paste or xclip)', 4)


def clear_clipboard() -> bool:
    for argv in (['pbcopy'], ['wl-copy', '--clear'], ['xclip', '-selection', 'clipboard', '-i']):
        if shutil.which(argv[0]):
            return _run([shutil.which(argv[0])] + argv[1:], data=b'').returncode == 0
    return False


# ---- stores ---------------------------------------------------------------------------------------------------

class Store:
    kind = ''

    def put(self, name, value, label=None) -> str:
        raise NotImplementedError

    def get(self, name) -> bytes:
        raise NotImplementedError

    def names(self) -> list:
        raise NotImplementedError

    def remove(self, name) -> None:
        raise NotImplementedError


class GcpStore(Store):
    kind = 'gcp'

    def __init__(self, project=None):
        self.project = project

    def _argv(self, *args):
        argv = [_tool('gcloud'), 'secrets', *args, '--quiet']
        if self.project:
            argv.append('--project=' + self.project)
        return argv

    def put(self, name, value, label=None):
        exists = _run(self._argv('describe', name, '--format=value(name)')).returncode == 0
        if not exists:
            argv = self._argv('create', name, '--replication-policy=automatic')
            if label:
                argv.append('--set-annotations=label=' + label)
            done = _run(argv)
            if done.returncode != 0:
                _fail(done, 'gcloud secrets create', [value])
        elif label:
            done = _run(self._argv('update', name, '--update-annotations=label=' + label))
            if done.returncode != 0:
                _fail(done, 'gcloud secrets update', [value])
        done = _run(self._argv('versions', 'add', name, '--data-file=-', '--format=value(name)'), data=value)
        if done.returncode != 0:
            _fail(done, 'gcloud secrets versions add', [value])
        version = (done.stdout or b'').decode('utf-8', 'replace').strip().rsplit('/', 1)[-1]
        return version if re.fullmatch(r'[0-9]{1,12}', version) else '?'

    def get(self, name):
        done = _run(self._argv('versions', 'access', 'latest', '--secret=' + name))
        if done.returncode != 0:
            _fail(done, 'gcloud secrets versions access')
        return done.stdout or b''

    def names(self):
        done = _run(self._argv('list', '--format=value(name)'))
        if done.returncode != 0:
            _fail(done, 'gcloud secrets list')
        return [line.strip().rsplit('/', 1)[-1] for line in done.stdout.decode('utf-8', 'replace').splitlines() if line.strip()]

    def remove(self, name):
        done = _run(self._argv('delete', name))
        if done.returncode != 0:
            _fail(done, 'gcloud secrets delete')


class KeychainStore(Store):
    """`security -i` reads its commands from stdin, so the hex-encoded value is on no argv. `security`'s own -w/-X
    options would put it on argv, visible to every process of this user while it runs."""
    kind = 'keychain'

    def __init__(self, account='ah-secret'):
        self.account = account

    def put(self, name, value, label=None):
        line = 'add-generic-password -U -a %s -s %s %s-X %s\n' % (
            self.account, name, ('-l "%s" ' % label) if label else '', value.hex())
        done = _run([_tool('security'), '-i'], data=line.encode())
        if done.returncode != 0 or b'error' in (done.stderr or b'').lower():
            _fail(done, 'security add-generic-password', [value, value.hex().encode()])
        return '-'

    def get(self, name):
        done = _run([_tool('security'), 'find-generic-password', '-a', self.account, '-s', name, '-w'])
        if done.returncode != 0:
            _fail(done, 'security find-generic-password')
        value = done.stdout or b''
        return value[:-1] if value.endswith(b'\n') else value

    def names(self):
        done = _run([_tool('security'), 'dump-keychain'])  # attributes only: without -d no secret is printed
        out, account, service = [], None, None
        for line in (done.stdout or b'').decode('utf-8', 'replace').splitlines():
            if line.startswith('keychain:'):
                if account == self.account and service:
                    out.append(service)
                account = service = None
            m = re.search(r'"(acct|svce)"<blob>="([^"]*)"', line)
            if m:
                account, service = (m.group(2), service) if m.group(1) == 'acct' else (account, m.group(2))
        if account == self.account and service:
            out.append(service)
        return sorted(set(n for n in out if NAME_RE.match(n)))

    def remove(self, name):
        done = _run([_tool('security'), 'delete-generic-password', '-a', self.account, '-s', name])
        if done.returncode != 0:
            _fail(done, 'security delete-generic-password')


class FileStore(Store):
    kind = 'file'

    def __init__(self, path):
        self.path = Path(os.path.expanduser(path))
        self.is_dir = path.endswith('/') or self.path.is_dir()

    def _target(self, name):
        return self.path / name if self.is_dir else self.path

    def put(self, name, value, label=None):
        target = self._target(name)
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        temporary = target.parent / ('.%s.%d.tmp' % (target.name, os.getpid()))
        fd = os.open(str(temporary), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, 'wb') as handle:
                handle.write(value)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, target)
        except BaseException:
            try:
                temporary.unlink()
            except OSError:
                pass
            raise
        if label and self.is_dir:
            (self.path / (name + '.label')).write_text(label + '\n')
        return '-'

    def get(self, name):
        try:
            # input-ok: the user's own secret store or file, read by the user's CLI command
            return self._target(name).read_bytes()
        except OSError as error:
            raise SecretError('not_found', 'cannot read %s (%s)' % (name, type(error).__name__))

    def names(self):
        if not self.is_dir:
            return [self.path.name] if self.path.is_file() else []
        return sorted(p.name for p in self.path.iterdir() if p.is_file() and NAME_RE.match(p.name))

    def remove(self, name):
        self._target(name).unlink()


def open_store(spec, project, conf) -> Store:
    spec = spec or conf.get('store') or 'gcp'
    project = project or conf.get('project')
    if project and not PROJECT_RE.match(str(project)):
        raise SecretError('bad_request', 'the project id has characters a project id does not have')
    if spec == 'gcp':
        return GcpStore(project)
    if spec == 'keychain':
        account = str(conf.get('keychain_account') or 'ah-secret')
        if not NAME_RE.match(account):
            raise SecretError('bad_request', 'keychain_account in secrets.json must be letters, digits, _ or -')
        return KeychainStore(account)
    if spec.startswith('file:') and len(spec) > 5:
        return FileStore(spec[5:])
    raise SecretError('bad_request', 'store must be gcp, keychain or file:PATH')


# ---- put ------------------------------------------------------------------------------------------------------

def _source(spec) -> bytes:
    if spec in (None, 'clipboard'):
        return read_clipboard()
    if spec == 'stdin':
        return sys.stdin.buffer.read(MAX_VALUE * 64 + 1)
    if spec.startswith('file:') and len(spec) > 5:
        try:
            # input-ok: the user's own secret store or file, read by the user's CLI command
            return Path(os.path.expanduser(spec[5:])).read_bytes()
        except OSError as error:
            raise SecretError('bad_request', 'cannot read the source file (%s)' % type(error).__name__)
    raise SecretError('bad_request', '--from must be clipboard, stdin or file:PATH')


def _label(text, number):
    text = text.strip()
    if not text:
        return None
    if not LABEL_RE.match(text) or KEYLIKE_RUN.search(text):
        raise SecretError('bad_request', 'line %d: the label field looks like a key or has characters a label may not '
                                         'have (check --field and --label-field); nothing was stored' % number)
    return text


def plan(name, data, args):
    """[(name, value, label)] from the source bytes. Validates everything before anything is stored."""
    if not args.lines:
        value = data if args.raw else data.strip()
        if not value:
            raise SecretError('empty', 'the source is empty; nothing was stored')
        return [(name, value, None)]
    items, number = [], 0
    for line_no, line in enumerate(data.split(b'\n'), 1):
        line = line.rstrip(b'\r')
        if not line.strip():
            continue
        number += 1
        label = None
        if args.sep is not None:
            parts = line.split(args.sep.encode())
            if args.field > len(parts) or (args.label_field and args.label_field > len(parts)):
                raise SecretError('bad_request', 'line %d has fewer than the fields asked for; nothing was stored' % line_no)
            value = parts[args.field - 1].strip()
            if args.label_field:
                label = _label(parts[args.label_field - 1].decode('utf-8', 'replace'), line_no)
        else:
            value = line.strip()
        if not value:
            raise SecretError('empty', 'line %d has an empty value; nothing was stored' % line_no)
        items.append(('%s-%d' % (name, number), value, label))
    if not items:
        raise SecretError('empty', 'the source has no non-empty line; nothing was stored')
    return items


def cmd_put(args, conf):
    if not NAME_RE.match(args.name):
        raise SecretError('bad_request', 'NAME must be 1-255 letters, digits, _ or -')
    if (args.field or args.label_field) and args.sep is None:
        raise SecretError('bad_request', '--field and --label-field need --sep')
    if args.sep is not None and not args.lines:
        raise SecretError('bad_request', '--sep needs --lines')
    if args.sep == '':
        raise SecretError('bad_request', '--sep must not be empty')
    store = open_store(args.to, args.project, conf)
    data = _source(args.source)
    items = plan(args.name, data, args)
    if any(len(value) > MAX_VALUE for _n, value, _l in items):
        raise SecretError('too_large', 'a value is larger than %d bytes; nothing was stored' % MAX_VALUE)
    if len(items) > 1 and isinstance(store, FileStore) and not store.is_dir:
        raise SecretError('bad_request', '--lines with a file store needs a directory (file:DIR/)')
    stored = []
    try:
        for name, value, label in items:
            version = store.put(name, value, label)
            stored.append({'name': name, 'store': store.kind, 'version': version, 'bytes': len(value)})
    except SecretError as error:
        error.stored = stored
        raise
    clip = 'not used'
    if args.source in (None, 'clipboard'):
        clip = 'kept' if args.keep_clipboard else ('cleared' if clear_clipboard() else 'could not clear')
    return {'ok': True, 'stored': stored, 'clipboard': clip}


# ---- exec, list, rm -------------------------------------------------------------------------------------------

def _pump(source, sink, masker):
    try:
        while True:
            chunk = os.read(source.fileno(), 65536)
            if not chunk:
                break
            sink.write(masker.feed(chunk))
            sink.flush()
        sink.write(masker.flush())
        sink.flush()
    except (OSError, ValueError):
        pass


def cmd_exec(args, conf):
    import redact  # noqa: PLC0415
    command = list(args.command)
    if command[:1] == ['--']:
        command = command[1:]
    if not command:
        raise SecretError('bad_request', 'give the command after --')
    pairs = []
    for item in args.env or []:
        var, sep, name = item.partition('=')
        if not sep or not VAR_RE.match(var) or not NAME_RE.match(name):
            raise SecretError('bad_request', '--env takes VAR=NAME (a variable name and a secret name)')
        pairs.append((var, name))
    if not pairs:
        raise SecretError('bad_request', 'give at least one --env VAR=NAME')
    store = open_store(args.store, args.project, conf)
    env = dict(os.environ)
    values = []
    for var, name in pairs:
        value = store.get(name)
        if b'\0' in value:
            raise SecretError('bad_value', '%s holds a NUL byte and cannot go into an environment variable' % name)
        env[var] = value.decode('utf-8', 'surrogateescape')
        values.append(value)
        stripped = value.strip()
        if stripped != value:
            values.append(stripped)
    try:
        child = subprocess.Popen(command, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError as error:
        raise SecretError('exec_failed', 'cannot run %s (%s)' % (os.path.basename(command[0])[:80], type(error).__name__),
                          127)
    threads = [threading.Thread(target=_pump, args=(child.stdout, sys.stdout.buffer, redact.ExactMasker(values))),
               threading.Thread(target=_pump, args=(child.stderr, sys.stderr.buffer, redact.ExactMasker(values)))]
    for thread in threads:
        thread.start()
    code = child.wait()
    for thread in threads:
        thread.join()
    return code


def cmd_list(args, conf):
    store = open_store(args.store, args.project, conf)
    return {'ok': True, 'store': store.kind, 'names': store.names()}


RM_ROLES = ('owner', 'supervisor')


def cmd_rm(args, conf):
    if not NAME_RE.match(args.name):
        raise SecretError('bad_request', 'NAME must be 1-255 letters, digits, _ or -')
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import ah_roles  # noqa: PLC0415 - a sibling module
    role, source = ah_roles.role_and_source()
    if role not in RM_ROLES:
        raise SecretError('refused', 'ah secret rm deletes a secret, which only the owner or a supervisor does; this '
                          f'session is a {role} ({source}). The owner runs `ah secret rm {args.name}` in his own '
                          'terminal', 3)
    store = open_store(args.store, args.project, conf)
    store.remove(args.name)
    return {'ok': True, 'removed': args.name, 'store': store.kind}


def parser():
    p = argparse.ArgumentParser(prog='ah secret', description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.allow_abbrev = False
    sub = p.add_subparsers(dest='cmd', required=True)
    put = sub.add_parser('put', help='store a secret from the clipboard (default), stdin or a file')
    put.add_argument('name')
    put.add_argument('--from', dest='source', help='clipboard (default), stdin or file:PATH')
    put.add_argument('--to', help='gcp (default), keychain or file:PATH')
    put.add_argument('--project')
    put.add_argument('--keep-clipboard', action='store_true')
    put.add_argument('--raw', action='store_true', help='keep surrounding whitespace')
    put.add_argument('--lines', action='store_true', help='one secret per non-empty line, named NAME-1..N')
    put.add_argument('--sep', help='with --lines: field separator')
    put.add_argument('--field', type=int, default=0, help='with --sep: the 1-based field that is the value')
    put.add_argument('--label-field', type=int, default=0, help='with --sep: the 1-based field stored as a label')
    ex = sub.add_parser('exec', help='run a command with secrets in its environment only, output masked')
    ex.add_argument('--env', action='append', metavar='VAR=NAME')
    ex.add_argument('--store')
    ex.add_argument('--project')
    ex.add_argument('command', nargs=argparse.REMAINDER)
    ls = sub.add_parser('list', help='secret names only')
    ls.add_argument('--store')
    ls.add_argument('--project')
    rm = sub.add_parser('rm', help='delete a secret (the owner or a supervisor only)')
    rm.add_argument('name')
    rm.add_argument('--store')
    rm.add_argument('--project')
    for child in sub.choices.values():
        child.allow_abbrev = False
    return p


def main(argv=None) -> int:
    args = parser().parse_args(argv)
    if args.cmd == 'put':
        if args.sep is not None and args.field < 1:
            print(json.dumps({'ok': False, 'code': 'bad_request', 'message': '--sep needs --field N (1-based)'}))
            return 2
    try:
        conf = config()
        if args.cmd == 'exec':
            return cmd_exec(args, conf)
        data = {'put': cmd_put, 'list': cmd_list, 'rm': cmd_rm}[args.cmd](args, conf)
    except SecretError as error:
        out = {'ok': False, 'code': error.code, 'message': str(error)}
        if getattr(error, 'stored', None):
            out['stored'] = error.stored
            out['clipboard'] = 'kept'
        print(json.dumps(out))
        return error.exit_code
    print(json.dumps(data))
    return 0


if __name__ == '__main__':
    sys.exit(main())
