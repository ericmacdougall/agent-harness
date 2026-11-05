#!/usr/bin/env python3
"""Host table and ssh target resolution for ah-run and the placement guard (GoodQA goodqa#14548, AC-4, AC-5).

`resource_policy.json` holds `hosts: {NAME|NAME:PORT: {role, ah_run, floor, reroute}}` and `self: [names]`.
`classify(target, ssh_args)` resolves the ssh target with `ssh -G` (1 s timeout, since `Match exec` in
~/.ssh/config can run commands) and answers local, a table entry, or external. The table is keyed by the
RESOLVED hostname plus port so aliases from ~/.ssh/config find their entry; loopback is local only on the
default port with no ProxyCommand or ProxyJump (`ssh -p 2222 localhost` is a VM tunnel). A timeout or an
error classes the host external and is logged. Every failure to read the table gives an empty table.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess

RESOLVE_TIMEOUT = 1.0
MAX_POLICY_BYTES = 1 << 20
ROLES = ('interactive', 'worker', 'external')
LOOPBACK = frozenset(('127.0.0.1', '::1', 'localhost', '[::1]'))
SSH_WITH_ARG = frozenset('pliJLobcDEeFImOQRSWwBP')
RESOLVE_FLAGS = frozenset('pl')  # the only options forwarded to `ssh -G`: port and user
# -F names a config file, -o can carry Include, Match or ProxyCommand, -J a jump host: `ssh -G` evaluates `Match exec`
# (it runs a command), so a model-supplied config never reaches it; such a call is classed external instead.
UNSAFE_FLAGS = frozenset('FoJ')
# `-o` keys that cannot change the destination or run anything. They are never forwarded to `ssh -G`, so the host is
# resolved as without them and the line keeps its rewrite. Any other key, or a value outside the plain form, is unsafe.
SAFE_O_KEYS = frozenset(('connecttimeout', 'batchmode', 'stricthostkeychecking', 'userknownhostsfile', 'serveraliveinterval',
                         'serveralivecountmax', 'loglevel', 'identitiesonly'))
SAFE_O_FORM = re.compile(r'([A-Za-z]+)(?:[ \t]*=[ \t]*|[ \t]+)[A-Za-z0-9_./~:@+-]+')


def policy_path(home=None, env=None):
    env = os.environ if env is None else env
    given = env.get('AGENT_HARNESS_RESOURCE_POLICY') or env.get('AGENT_HARNESS_POLICY_FILE')
    return Path(given) if given else Path(home or Path.home()) / '.agent-harness' / 'resource_policy.json'


def _read(path):
    try:
        data = json.loads(Path(path).read_bytes()[:MAX_POLICY_BYTES])
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def load(path=None):
    """The `hosts` table (lower-cased keys). A missing or corrupt file, or key, is an empty table, never an exception."""
    hosts = _read(path or policy_path()).get('hosts')
    table = {}
    if isinstance(hosts, dict):
        for key, entry in hosts.items():
            if isinstance(key, str) and isinstance(entry, dict):
                table[key.strip().lower()] = entry
    return table


def own_names(path=None):
    """The host's own names and loopback addresses recorded by the installer under the table's `self` key."""
    names = _read(path or policy_path()).get('self')
    found = {name.strip().lower() for name in names if isinstance(name, str)} if isinstance(names, list) else set()
    return found | LOOPBACK


class SshCall:
    """An ssh argv split into the words before the target, the target, the option words after it and the remote command."""

    def __init__(self, opts, target, remote, flags, resolve_args, post_opts=(), unsafe_o=True):
        self.opts, self.target, self.remote, self.flags, self.resolve_args = opts, target, remote, flags, resolve_args
        self.post_opts = list(post_opts)
        self.unsafe = set(flags) & UNSAFE_FLAGS
        if not unsafe_o:
            self.unsafe.discard('o')


def safe_o_value(value):
    found = SAFE_O_FORM.fullmatch(value or '')
    return bool(found) and found.group(1).lower() in SAFE_O_KEYS


def parse_ssh(args):
    """Parse the words after `ssh` (values, quotes already removed). None when there is no target. Like OpenSSH, options
    are read before the target and again after it, up to the first other word, which starts the remote command."""
    flags, resolve, state = set(), [], {'unsafe_o': False}

    def options(index):
        opts = []
        while index < len(args):
            word = args[index]
            if word == '--':
                opts.append(word); index += 1
                break
            if not (word.startswith('-') and len(word) > 1):
                break
            letters, taken = word[1:], 1
            for position, letter in enumerate(letters):
                if letter in SSH_WITH_ARG:
                    flags.add(letter)
                    attached = position < len(letters) - 1
                    value = letters[position + 1:] if attached else (args[index + 1] if index + 1 < len(args) else '')
                    taken = 1 if attached else 2
                    if letter == 'o' and not safe_o_value(value):
                        state['unsafe_o'] = True
                    if letter in RESOLVE_FLAGS and (attached or index + 1 < len(args)):
                        resolve.extend([word] if attached else [word, value])
                    break
                flags.add(letter)
            opts.extend(args[index:index + taken])
            index += taken
        return index, opts

    index, opts = options(0)
    if index >= len(args):
        return None
    target = args[index]
    index, post_opts = options(index + 1)
    return SshCall(opts, target, list(args[index:]), flags, resolve, post_opts, state['unsafe_o'])


class Resolved:
    def __init__(self, host, port, proxycommand=None, proxyjump=None, error=None):
        self.host, self.port, self.proxycommand, self.proxyjump, self.error = host, port, proxycommand, proxyjump, error


def resolve(target, ssh_args=(), run=subprocess.run):
    """`ssh -G` for the target: hostname, port, proxycommand, proxyjump; `error` set on a timeout or failure.
    Never runs with -F, -o or -J (see UNSAFE_FLAGS); the user's default config is the only one evaluated."""
    for word in ssh_args:
        if word.startswith('-') and not word.startswith('--') and any(letter in UNSAFE_FLAGS for letter in word[1:2]):
            return Resolved(None, None, error='unsafe-option')
    try:
        done = run(['ssh', '-G', *ssh_args, '--', target], capture_output=True, text=True, timeout=RESOLVE_TIMEOUT,
                   stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        return Resolved(None, None, error='timeout')
    except (OSError, ValueError) as error:
        return Resolved(None, None, error=type(error).__name__)
    if done.returncode != 0:
        return Resolved(None, None, error='ssh -G exit %s' % done.returncode)
    values = {}
    for line in done.stdout.splitlines():
        key, _sep, value = line.partition(' ')
        values.setdefault(key.strip().lower(), value.strip())
    host = values.get('hostname')
    if not host:
        return Resolved(None, None, error='no hostname in ssh -G output')
    try:
        port = int(values.get('port') or 22)
    except ValueError:
        port = 22
    none = ('', 'none')
    return Resolved(host.lower().strip('[]'), port,
                    values.get('proxycommand') if values.get('proxycommand', '').lower() not in none else None,
                    values.get('proxyjump') if values.get('proxyjump', '').lower() not in none else None)


class HostClass:
    """kind is `local`, `table` (an entry exists and is not external) or `external`."""

    def __init__(self, kind, name, host, port, entry=None, reason=None):
        self.kind, self.name, self.host, self.port, self.entry, self.reason = kind, name, host, port, entry or {}, reason

    @property
    def role(self):
        return 'local' if self.kind == 'local' else (self.entry.get('role') if self.kind == 'table' else 'external')

    @property
    def ah_run(self):
        value = self.entry.get('ah_run')
        return value if isinstance(value, str) and value else False


def lookup(table, host, port):
    """The table entry for a resolved hostname and port: `host:port` first, then bare `host` on the default port."""
    for key in ('%s:%d' % (host, port), host if port == 22 else None):
        if key and key in table:
            return key, table[key]
    return None, None


def classify(target, ssh_args=(), table=None, policy=None, resolver=None, warn=None):
    """HostClass for an ssh target. `warn(text)` is told about a resolution failure (the ledger warn path)."""
    table = load(policy) if table is None else table
    found = (resolver or resolve)(target, ssh_args)
    if found.error:
        if warn:
            warn('ssh -G %s for a host (%s); classed external with the escape check only'
                 % ('failed' if found.error != 'timeout' else 'timed out', found.error))
        return HostClass('external', None, None, None, reason='resolve-' + found.error)
    host, port = found.host, found.port
    if host in own_names(policy):
        if port == 22 and not found.proxycommand and not found.proxyjump:
            return HostClass('local', None, host, port)
        return HostClass('external', None, host, port, reason='loopback-tunnel')
    name, entry = lookup(table, host, port)
    if entry is None or entry.get('role') not in ROLES or entry.get('role') == 'external':
        return HostClass('external', name, host, port, entry, reason='not-in-table' if entry is None else 'external-role')
    return HostClass('table', name, host, port, entry)
