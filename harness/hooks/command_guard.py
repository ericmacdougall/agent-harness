#!/usr/bin/env python3
"""PreToolUse guard for Bash and PowerShell commands: secret dumps, log deletion, broad process kills.

    command_guard.py hook [--format exit2|json]    PreToolUse hook (JSON on stdin); exit 2 + stderr blocks
    command_guard.py check [--ps] 'COMMAND'        print the decision for a command, run nothing
    command_guard.py explain --file F [--cwd D]   decision and findings for a command stored in a file
    command_guard.py doctor                        check the installed guard and run its self-test probes
    command_guard.py replay TRANSCRIPT.jsonl...    decision counts over real transcripts (never prints commands)
    command_guard.py approve-delete --path P --remote R --wal W [--backup-verified-sha256 D] [--ttl S]
    command_guard.py approve-delete --path P --archive R:x.tar.zst --archive-sha256 R:x.tar.zst.sha256 \
        --archive-listing R:x.listing --wal W [--ttl S]
    command_guard.py approve-delete --path P --no-backup --user-source answer:S/U --wal W [--ttl S]
                                                   user-approved, no backup: clean pushed git tree or detached image
    command_guard.py revoke-delete                 remove every delete approval
    command_guard.py scan-wal PATH...              report secret shapes in WAL/transcript files (never prints values)

Categories (modes live in the installed command_guard_policy.json, never in an environment variable or a repo):
  secret_dump  Commands that print credentials into the transcript (rclone config show, --reveal, printenv,
               cat of credential files, ...).  Always enforced.
  log_delete   rm/mv/truncate/find -delete/rsync --delete/... on Claude and Codex logs and WALs without a
               verified-backup approval marker (see approve-delete).  Always enforced.
  broad_kill   pkill -f / killall with a short, generic or unscoped pattern.  warn by default, enforce on request.

The command is lexed like a shell (quotes, $'..', escapes, line continuations, here-docs, $(..), backticks,
pipes, redirections, env prefixes, command/exec/sudo/env/xargs/timeout wrappers, sh -c, ssh and docker exec
strings, absolute binary paths, brace expansion, case and Unicode lookalikes) before any rule looks at it.
Inputs the guard cannot analyse within its budget (oversized, too deeply nested, too slow) are blocked, never
waved through. An internal error falls back to a raw-text scan: sensitive-looking commands are blocked, others run.

Threat model: careless or hurried agents, not an adversary who can edit the installed hooks. Best effort for
interpreter one-liners (python -c, node -e): their code text is scanned, not executed or parsed.
"""

from __future__ import annotations

import argparse
import errno
import fnmatch
import hashlib
import hmac
import json
import os
import posixpath
import re
import secrets as _secrets
import shlex
import shutil
import stat
import signal
import subprocess
import sys
import time
import unicodedata
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:  # python3 -I (3.11+) no longer puts the script's directory on sys.path
    sys.path.insert(0, str(HERE))
POLICY_FILE = HERE / 'command_guard_policy.json'

DEFAULT_POLICY = {
    'version': 1,
    'modes': {'secret_dump': 'enforce', 'log_delete': 'enforce', 'broad_kill': 'warn'},
    'limits': {'max_command_bytes': 262144, 'max_depth': 8, 'max_nodes': 600000, 'max_seconds': 3.0,
               'max_stdin_bytes': 4194304},
    # Tier A: logs, WALs and approval state. Every destructive form is refused, including overwrites.
    'protected_log_roots': ['{home}/.claude/projects', '{home}/.claude/wals', '{home}/.claude/sessions',
                            '{home}/.claude/transcripts', '{home}/.claude/history.jsonl',
                            '{home}/.claude/file-history',
                            '{home}/.codex/sessions', '{home}/.codex/archived_sessions',
                            '{home}/.codex/history*', '{home}/.agent-harness/state',
                            '{home}/.agent-harness/codex-wals', '{home}/.claude/.credentials.json',
                            '{home}/.codex/auth.json',
                            # the guard itself: deleting or replacing it would switch the protection off
                            '{home}/.claude/hooks/command_guard*', '{home}/.claude/hooks/redact.py',
                            '{home}/.claude/hooks/safe_input.py',
                            '{home}/.codex/agent-harness/command_guard*', '{home}/.codex/agent-harness/redact.py',
                            '{home}/.codex/agent-harness/safe_input.py'],
    # The guard's own files (and any policy file next to it): refused even when the target does not exist yet,
    # because creating one is how the protection would be replaced or reconfigured.
    'guard_files': ['{home}/.claude/hooks/command_guard*', '{home}/.claude/hooks/redact.py',
                    '{home}/.claude/hooks/safe_input.py', '{home}/.codex/agent-harness/command_guard*',
                    '{home}/.codex/agent-harness/redact.py', '{home}/.codex/agent-harness/safe_input.py'],
    # wal, wals, wal-*, wal_*, wal.* and *.wal.jsonl; not walker/ or wallet/
    'protected_work_wal_regex': r'^{home}/\.agent-harness/work/[^/]+/(?:.*/)?(?:wals?|wal[-_.][^/]*|[^/]*\.wal\.jsonl)(?:/.*)?$',
    # Tier A anywhere on disk: a `wals` directory segment, main.jsonl and *.wal.jsonl files.
    'protected_segment_names': ['wals'],
    'protected_file_names': ['main.jsonl'],
    'protected_file_suffixes': ['.wal.jsonl'],
    # Tier B: whole harness trees. Deletes, moves out and truncation are refused; edits and new files are not.
    'protected_roots': ['{home}/.claude', '{home}/.codex', '{home}/.agent-harness'],
    # Literal paths inside these stay deletable (disposable scratch). A wildcard position must be filled by a
    # literal name: a glob there could reach other sessions. Under work/ only the agent's own git worktree is
    # deletable (see Analyzer._own_worktree); cleanup of task folders goes through workdir.py prune --apply.
    'allow_subtrees': ['{home}/.agent-harness/scratch/*/*/*/*'],
    # Never deletable anywhere under a harness root, whatever exception applies: run kits, JSONL logs, state.
    'keep_names': ['kit.json'],
    'keep_suffixes': ['.jsonl'],
    'keep_segments': ['state'],
    # Homes on other machines (ssh targets) are matched with these patterns as well as the local homes.
    'generic_homes': ['/users/*', '/home/*', '/root', '/var/root'],
    'ancestor_roots': ['{home}', '{home}/.claude', '{home}/.codex', '{home}/.agent-harness',
                       '{home}/.agent-harness/work'],
    'rclone_allow_redacted': False,
    # Temp trees where the anywhere-on-disk WAL names (wals/, main.jsonl) are test data, not real WALs.
    'temp_roots': ['/tmp', '/private/tmp', '/var/tmp', '/var/folders', '/private/var/folders'],
    'state_files': ['{home}/.agent-harness/state/log-delete-ok.json', '{home}/.agent-harness/state/log-delete.key',
                    # goodqa#14908: prod_delete_guard's signed grant store and its key; only `grant` writes them
                    '{home}/.agent-harness/state/prod-delete-grants.json',
                    '{home}/.agent-harness/state/prod-delete.key'],
    # path suffixes (/-separated, case-folded) of checkouts a timer or service builds from; a directory holding a
    # `.harness-owned` file is owned too. goodqa#15307
    'owned_checkouts': [],
    'credential_path_regexes': [
        r'(^|/)\.config/rclone/rclone\.conf$', r'(^|/)rclone\.conf$',
        r'(^|/)\.aws/credentials$', r'(^|/)\.aws/sso/cache/[^/]+$',
        r'(^|/)\.ssh/id_[^/]*$', r'(^|/)id_(?:rsa|dsa|ecdsa|ed25519)$',
        r'\.p8$', r'\.key$', r'\.pem$', r'\.p12$', r'\.pfx$',
        r'(^|/)\.env(?:\.[^/]*)?$',
        r'(^|/)\.claude/\.credentials\.json$', r'(^|/)\.codex/auth\.json$',
        r'(^|/)\.npmrc$', r'(^|/)\.netrc$', r'(^|/)\.pgpass$', r'(^|/)\.git-credentials$',
        r'(^|/)\.docker/config\.json$', r'(^|/)\.config/gh/hosts\.yml$', r'(^|/)\.kube/config$',
        r'(^|/)\.vault-token$',
        r'(^|/)\.config/gcloud/(?:credentials\.db|access_tokens\.db|application_default_credentials\.json|legacy_credentials/.*)$',
        r'(^|/)\.gnupg/(?:private-keys-v1\.d/.*|secring\.gpg)$',
        r'^/proc/(?:self|[0-9]+|\*)/environ$', r'^/proc/[^/]+/environ$'],
    'credential_allow_regexes': [r'\.pub$', r'\.env\.(?:example|sample|template|dist|defaults)$', r'-cert\.pub$'],
    'credential_dirs': ['{home}/.ssh', '{home}/.aws', '{home}/.config/rclone', '{home}/.claude/goodqa-hive',
                        '{home}/.gnupg', '{home}/.docker', '{home}/.config/gh', '{home}/.config/gcloud',
                        '{home}/.kube'],
    'credential_samples': ['{home}/.ssh/id_rsa', '{home}/.ssh/id_ed25519', '{home}/.ssh/id_ecdsa',
                           '{home}/.aws/credentials', '{home}/.config/rclone/rclone.conf', '{home}/.npmrc',
                           '{home}/.netrc', '{home}/.docker/config.json', '{home}/.claude/goodqa-hive/member.key',
                           '{home}/.config/gh/hosts.yml', '{home}/.claude/.credentials.json',
                           '{home}/.codex/auth.json', '{home}/.pgpass', '{home}/.git-credentials', '{cwd}/.env'],
    'secret_env_regex': r'(?:SECRET|TOKEN|PASSWORD|PASSWD|PASSPHRASE|CREDENTIAL|APIKEY|ACCESSKEY|PRIVATEKEY)|(?:^|_)(?:KEY|PAT)(?:_|$)',
    'secret_env_exclude_regex': r'(?:_FILE|_PATH|_DIR|_NAME|_COUNT|_LIMIT|_BUDGET|_URL|_ID|_TTL|_EXPIRY|_TIMEOUT)$|^(?:KEYCHAIN|SSH_AUTH_SOCK)',
    'rclone_blocked_config': ['show', 'dump', 'reconnect', 'file', 'redacted', 'paste'],
    'kill': {'min_pattern_length': 12,
             'generic_names': ['python', 'python3', 'node', 'nodejs', 'claude', 'codex', 'unittest', 'pytest', 'chrome',
                               'chromium', 'ssh', 'sshd', 'bash', 'sh', 'zsh', 'java', 'ruby', 'go', 'npm', 'pnpm',
                               'yarn', 'tmux', 'git', 'rclone', 'docker', 'electron', 'code', 'safari', 'firefox',
                               'tests', 'test', 'server', 'worker', 'agent', 'harness', 'deliver', 'peer_review']},
    # goodqa#14817: deleting a git clone whose every commit is on the remote needs no Dropbox backup (see
    # reproducible_clone_refusal). ignored_ok: build/cache directory names that may be ignored in such a clone.
    'reproducible_clone': {'enabled': True, 'total_seconds': 4.0, 'remote_seconds': 2.5,
                           'remote_hosts': ['github.com', 'ssh.github.com', 'gitlab.com', 'bitbucket.org'],
                           # at any depth: caches that are only ever generated; generic names only at the top level
                           'ignored_ok': ['node_modules', '__pycache__', '.pytest_cache', '.mypy_cache', '.ruff_cache'],
                           'ignored_top_ok': ['.venv', 'venv', 'dist', 'build', 'target', '.next', '.gradle']},
    'marker': {'default_ttl_seconds': 900, 'max_ttl_seconds': 86400, 'max_walk_entries': 200000,
               'max_walk_seconds': 2.0, 'max_hash_bytes': 21474836480, 'recent_change_seconds': 600,
               'approve_remote_types': ['dropbox'], 'no_backup_remote_hosts': ['github.com', 't2-dev']},
}

SECRET_DUMP, LOG_DELETE, BROAD_KILL = 'secret_dump', 'log_delete', 'broad_kill'
PARSE = 'parse'  # warn-only notes: input the guard could not fully parse
ALWAYS_ENFORCED = (SECRET_DUMP, LOG_DELETE)


# --------------------------------------------------------------------------- policy

# A policy file can only add protection: these lists are unioned with the defaults, broad_kill's mode may be set,
# and every other key in the file is ignored. Allow-lists, regexes and limits are never taken from a file, so a
# written or replaced policy cannot switch the guard off.
ADDITIVE_LISTS = ('protected_log_roots', 'protected_segment_names', 'protected_file_names', 'protected_file_suffixes',
                  'protected_roots', 'keep_names', 'keep_suffixes', 'keep_segments', 'generic_homes', 'ancestor_roots',
                  'state_files', 'credential_path_regexes', 'credential_dirs', 'credential_samples',
                  'rclone_blocked_config', 'guard_files', 'owned_checkouts')


def _merge(base, override):
    out = json.loads(json.dumps(base))
    if not isinstance(override, dict):
        return out
    for key in ADDITIVE_LISTS:
        extra = override.get(key)
        if isinstance(extra, list):
            for item in extra:
                if isinstance(item, str) and item and item not in out[key]:
                    if key == 'credential_path_regexes':
                        try:
                            re.compile(item)
                        except re.error:
                            continue
                    out[key].append(item)
    kill = override.get('kill')
    if isinstance(kill, dict) and isinstance(kill.get('generic_names'), list):
        out['kill']['generic_names'] += [n for n in kill['generic_names'] if isinstance(n, str) and n]
    modes = override.get('modes')
    if isinstance(modes, dict) and modes.get(BROAD_KILL) in ('warn', 'enforce'):
        out['modes'][BROAD_KILL] = modes[BROAD_KILL]
    return out


def load_policy(path=None):
    """Installed user-level policy only. A missing, corrupt or hostile file means built-in defaults (enforce)."""
    policy = json.loads(json.dumps(DEFAULT_POLICY))
    path = Path(path) if path else POLICY_FILE
    try:
        import safe_input
        data = safe_input.safe_json_loads(safe_input.read_bounded(str(path), 1 << 20).decode('utf-8'))
        if isinstance(data, dict):
            policy = _merge(policy, data)
    except Exception:  # noqa: BLE001 - any failure leaves the (strict) defaults in force
        pass
    modes = policy.get('modes') if isinstance(policy.get('modes'), dict) else {}
    clean = {}
    for category in (SECRET_DUMP, LOG_DELETE, BROAD_KILL):
        mode = modes.get(category, DEFAULT_POLICY['modes'][category])
        if mode not in ('warn', 'enforce'):
            mode = DEFAULT_POLICY['modes'][category]
        if category in ALWAYS_ENFORCED:
            mode = 'enforce'  # never warn-only, whatever the file says
        clean[category] = mode
    policy['modes'] = clean
    return policy


class Compiled:
    """Policy plus the home directories and regexes derived from it."""

    def __init__(self, policy, home=None, cwd=None):
        self.policy = policy
        homes = []
        for candidate in (home, os.path.expanduser('~'), _pw_home()):
            if not candidate:
                continue
            for variant in (os.path.normpath(candidate), _realpath(candidate)):
                if variant and variant not in homes:
                    homes.append(variant)
        self.homes = homes
        self.home = homes[0]
        try:
            self.cwd = cwd or os.getcwd()
        except OSError:
            self.cwd = self.home
        self.limits = policy['limits']
        fmt = lambda template, h: template.replace('{home}', h).replace('{cwd}', self.cwd)  # noqa: E731
        # Matching homes: the local ones (exact) plus glob patterns for other machines' homes.
        match_homes = homes + [g for g in policy.get('generic_homes', []) if isinstance(g, str)]
        self.match_homes = [self._segs(g.casefold()) for g in policy.get('generic_homes', []) if isinstance(g, str)]
        self.protected = [self._segs(fmt(t, h)) for t in policy['protected_log_roots'] for h in match_homes]
        self.roots = [self._segs(fmt(t, h)) for t in policy.get('protected_roots', []) for h in match_homes]
        self.allow = []
        for t in policy.get('allow_subtrees', []):
            if not isinstance(t, str):
                continue
            for h in match_homes:
                segs = self._segs(fmt(t, h))
                if self._safe_allow(segs, h):
                    self.allow.append(segs)
        self.temp_roots = [self._segs(t) for t in policy.get('temp_roots', []) if isinstance(t, str)]
        self.seg_names = {s.casefold() for s in policy.get('protected_segment_names', [])}
        self.file_names = {s.casefold() for s in policy.get('protected_file_names', [])}
        self.file_suffixes = tuple(s.casefold() for s in policy.get('protected_file_suffixes', []))
        self.keep_names = {s.casefold() for s in policy.get('keep_names', [])}
        self.keep_suffixes = tuple(s.casefold() for s in policy.get('keep_suffixes', []))
        self.keep_segments = {s.casefold() for s in policy.get('keep_segments', [])}
        self.ancestors = [self._segs(fmt(t, h)) for t in policy['ancestor_roots'] for h in homes]
        self.guard_globs = [fmt(t, h).casefold() for t in policy.get('guard_files', []) for h in homes]
        self.state_files = [fmt(t, h).casefold() for t in policy['state_files'] for h in homes]
        # session transcripts are the record of user answers (approve-delete --no-backup reads them): Bash never
        # writes there, except memory notes under projects/<dir>/memory/
        self.transcript_roots = sorted({fmt('{home}/.claude/projects', h).casefold() for h in homes})
        # every home form, not only this machine's: a WAL under another host's work dir is still a WAL
        self.wal_regexes = [re.compile(policy['protected_work_wal_regex'].replace(
            '{home}', re.escape(h).replace(r'\*', '[^/]+')), re.I)
            for h in homes + [g for g in policy.get('generic_homes', []) if isinstance(g, str)]]
        self.cred = [re.compile(r, re.I) for r in policy['credential_path_regexes']]
        self.cred_allow = [re.compile(r, re.I) for r in policy['credential_allow_regexes']]
        self.cred_dirs = [self._segs(fmt(t, h)) for t in policy['credential_dirs'] for h in homes]
        self.cred_samples = [fmt(t, h) for t in policy['credential_samples'] for h in homes]
        self.secret_env = re.compile(policy['secret_env_regex'])
        self.secret_env_excl = re.compile(policy['secret_env_exclude_regex'])
        self.kill = policy['kill']
        self.generic = set(self.kill['generic_names'])
        self.rclone_blocked = set(policy['rclone_blocked_config'])
        self.fallback = _build_fallback(self)

    @staticmethod
    def _segs(path):
        return [s for s in path.casefold().replace('\\', '/').split('/') if s]

    def _safe_allow(self, segs, home):
        """An allow_subtrees entry must sit at least two levels below a protected root and not cover Tier A."""
        if any(s in ('..', '.', '**') for s in segs):
            return False
        for r in self.protected:
            if _prefix_match(segs, r):
                return False
        deep_enough = False
        for r in self.roots:
            if _prefix_match(segs, r) and len(segs) >= len(r) + 2:
                deep_enough = True
        return deep_enough

    def is_guard_file(self, path):
        folded = path.casefold()
        real = (_realpath(path) or path).casefold()
        return any(_fnmatchcase(p, g) for g in self.guard_globs for p in (folded, real))

    def secret_name(self, name):
        upper = name.upper()
        return bool(self.secret_env.search(upper)) and not self.secret_env_excl.search(upper)


def _looks_clean(value):
    """A literal value the redactor leaves alone and that is not long and opaque."""
    if len(value) > 200 or re.fullmatch(r'[A-Za-z0-9+/_=-]{24,}', value):
        return False
    try:
        import redact
        return redact.redact(value) == value
    except Exception:  # noqa: BLE001
        return False


def _realpath(path):
    try:
        return os.path.realpath(path) if path and len(path) < 4096 else None
    except (OSError, ValueError):
        return None


def _pw_home():
    try:
        import pwd
        return pwd.getpwuid(os.getuid()).pw_dir
    except Exception:  # noqa: BLE001
        return None


# --------------------------------------------------------------------------- one-off pinned routes

# Two credential tools the user chose to allow for the pve evacuation (GoodQA goodqa#14518). A route is the whole command
# string, a file with this exact SHA-256 at this exact path, and a time before the expiry. This is a fixed table on purpose:
# no policy file, flag or environment variable can add to it, and a later change removes it.
# Paths are relative to HOME's work folder so no home name is published. The tools check their own names and values, so the
# argument shapes only need to rule out shell syntax.
PINNED_ROUTE_BASE = '.agent-harness/work/dev-decom'
PINNED_ROUTE_EXPIRES = 1794182400  # 2026-11-09T00:00:00Z, the day the host these routes serve shuts down
PINNED_ROUTES = (
    ('unit-mig/t2-rclone/user-run-store-dropbox-secret.sh',
     '92438a47d6b8083266e42922a2d151d0d0d65475fcc20744ea54359f2af501f3',
     # -p (privileged mode): bash then runs no $BASH_ENV or $ENV file and imports no exported function before the script,
     # which sets its own PATH and calls tools by absolute path
     r'/bin/bash -p {path}'),
    ('unit-mig/cf-dns/cf_dns_prod_move.py',
     '30c688923554c09f93128a7d9b89831557acd06d1f04949c235b09ea05cf89a6',
     r'/usr/bin/python3 -I {path} (?:list'
     r'|set-ttl --name [a-z.]{{1,40}} --ttl [0-9]{{1,5}} --expect-ttl [0-9]{{1,5}}'
     r'|set-content --name [a-z.]{{1,40}} --content [0-9.]{{7,15}} --expect-content [0-9.]{{7,15}})'),
)
# Existing scripts keep only log deletion and the credential-read rules (SCRIPT_CREDENTIAL_RULES); other printing rules
# inside them still pass (goodqa#14993 follow-up). This also refuses
# scripts whose own text, outside comment lines, names the rclone config or the token secret or dumps the config. Text only.
# Python prose does not count as a dump: there the command must open a string or be an argument list. It runs as its own
# pass after main's analysis (credential_findings), so it only ever adds a finding and cannot use main's time. It does
# not run inside scripts on disk, whose own commands keep only log deletion and credential reads. It does not catch a
# script that builds the name at runtime or calls another script, a name past the read limit, a path the guard cannot
# resolve, a runner it does not unwrap (`uv run`, `tmux`, `python3 -m cProfile`), a test in a folder named tests, or one of
# the guard's own files.
_CREDENTIAL_NAMES = (rb'\.config/rclone/?(?=["\'\s;|&)*$]|\Z)'  # the config directory as a whole word, or a glob or variable
                     rb'|/rclone/rclone\.conf(?![\w.-])'  # the file under any base, such as $XDG_CONFIG_HOME
                     rb'|["\']rclone\.conf["\']'  # the quoted file name: os.path.join, pathlib, read("...")
                     rb'|\bGOODQA_CLOUDFLARE_API_TOKEN\b')
# The option count is bounded: an unbounded loop here is quadratic, and a padded script could then outlast the time limit.
_RCLONE_DUMP = rb'rclone(?:\s|\\)+(?:-\S+(?:\s+"?\$?\{?\w+\}?"?)?\s+){0,8}config(?:\s|\\)+"?(?:show|dump)\b'
CREDENTIAL_SHELL_TEXT = re.compile(_CREDENTIAL_NAMES + rb'|\b' + _RCLONE_DUMP)
CREDENTIAL_PYTHON_TEXT = re.compile(_CREDENTIAL_NAMES + rb'|[f]?["\'](?:[^"\'\s]*/)?' + _RCLONE_DUMP
                                    + rb'|["\']rclone["\']\s*,\s*["\']config["\']\s*,\s*["\'](?:show|dump)["\']')
CREDENTIAL_SCRIPT_READ = 1048576
# The check's own pass starts no new read after this long. Main's analysis (at most its 3 s limit) plus this stays under
# the hook's 7 s alarm; a single read that stalls past the alarm ends the pass, and main's verdict stands.
CREDENTIAL_PASS_SECONDS = 1.5
CREDENTIAL_SCRIPT_SUFFIXES = ('.sh', '.bash', '.zsh', '.py')
CREDENTIAL_DATA_SUFFIXES = ('.json', '.jsonl', '.md')
CREDENTIAL_SCRIPT_SHEBANG = re.compile(rb'#![^\n]*\b(?:ba|z|k|da|)sh\b|#![^\n]*\bpython')
GUARD_OWN_FILES = ('command_guard.py', 'command_guard_hook.py', 'command_guard_corpus.py', 'live_guard_canary.py',
                   'holds_guard.py')
ROUTE_HOME = re.compile(r'/[A-Za-z0-9_./-]+')  # HOME goes into a command string, so it must not hold shell syntax
PYTHON_NAME = re.compile(r'(?:python|pypy)(?:[0-9.]+t?(?:-intel64)?|w)?')
SHELL_LONG_OPTS = frozenset(('norc', 'noprofile', 'login', 'posix', 'verbose', 'version', 'help', 'restricted', 'noediting',
                             'debugger', 'dump-strings', 'dump-po-strings', 'rpm-requires'))
SHELL_LONG_VALUE_OPTS = frozenset(('rcfile', 'init-file'))


def shell_script_word(texts):
    """Index of the script a POSIX shell would run, or None for -c, -n or no script. Used only to add a credential check,
    so a misreading here can miss a script but cannot weaken any other rule."""
    i, on = 0, set()
    while i < len(texts):
        t = texts[i]
        if t in ('-', '--'):
            i += 1
            break
        if t[:1] not in ('-', '+'):
            break
        i += 1
        word = t.lstrip('-')
        if t[0] == '-' and word in SHELL_LONG_OPTS:
            continue
        if t[0] == '-' and word in SHELL_LONG_VALUE_OPTS:
            i += 1
            continue
        if t.startswith('--'):
            on.update('c' if word.startswith('command') else '')
            continue
        for ch in t[1:]:
            if ch in 'oO':
                i += 1
            elif t[0] == '-':
                on.add(ch)
            else:
                on.discard(ch)
    return i if i < len(texts) and not on & {'c', 'n'} else None


def python_script_word(texts):
    """Index of the script Python would run, or None for -c, -m, stdin or no script. Same use as shell_script_word."""
    i = 0
    while i < len(texts):
        t = texts[i]
        if t == '--':
            return i + 1 if i + 1 < len(texts) else None
        if t == '-':
            return None
        if not t.startswith('-'):
            return i
        i += 1
        if t.startswith('--'):
            i += 1 if t == '--check-hash-based-pycs' else 0
            continue
        for pos, ch in enumerate(t[1:], 1):
            if ch in 'cm':
                return None
            if ch in 'WX':  # takes a value: the rest of this word, or the next word
                i += 1 if pos == len(t) - 1 else 0
                break
    return None


def _read_prefix(path, limit):
    """Read a regular file without blocking: a FIFO swapped in after a check would otherwise hang until the alarm."""
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NONBLOCK', 0))
    with os.fdopen(fd, 'rb') as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise OSError('not a regular file')
        return handle.read(limit)


def pinned_route(command, now=None):
    """True only for the exact command string of an unexpired route whose file is a regular file with the pinned hash."""
    if not isinstance(command, str) or (time.time() if now is None else now) >= PINNED_ROUTE_EXPIRES:
        return False
    home = os.environ.get('HOME')
    if not home or not ROUTE_HOME.fullmatch(home):
        return False
    for rel, digest, shape in PINNED_ROUTES:
        path = os.path.join(home, PINNED_ROUTE_BASE, rel)
        if not re.fullmatch(shape.format(path=re.escape(path)), command):
            continue
        try:
            if not stat.S_ISREG(os.lstat(path).st_mode):
                return False
            data = _read_prefix(path, CREDENTIAL_SCRIPT_READ + 1)
        except (OSError, ValueError):
            return False
        return len(data) <= CREDENTIAL_SCRIPT_READ and hashlib.sha256(data).hexdigest() == digest
    return False


# --------------------------------------------------------------------------- budget and data model

class Blocked(Exception):
    """Analysis could not complete inside its budget: the command is refused, not waved through."""


class Budget:
    def __init__(self, limits):
        self.nodes = int(limits['max_nodes'])
        self.deadline = time.monotonic() + float(limits['max_seconds'])
        self.max_depth = int(limits['max_depth'])
        self.count = 0

    def has_room(self, ticks, seconds):
        """Could about this much more work finish inside the budget?"""
        return self.count + ticks <= self.nodes and time.monotonic() + seconds <= self.deadline

    def tick(self, weight=1):
        self.count += weight
        if self.count > self.nodes:
            raise Blocked('command is too large or complex to analyse safely')
        if self.count % 256 == 0 and time.monotonic() > self.deadline:
            raise Blocked('analysis exceeded its time budget')


class Word:
    __slots__ = ('alts', 'subs', 'vars', 'glob', 'quoted', 'dynamic', 'single_only', 'overflow', 'raw')

    def __init__(self):
        self.alts = ['']
        self.subs = []       # inner scripts of $(..), `..`, <(..)
        self.vars = []       # variable names expanded inside the word (for secret-print checks)
        self.glob = False
        self.quoted = False
        self.dynamic = False  # contains an unresolved expansion
        self.single_only = False
        self.overflow = None  # raw text of a brace expansion that exceeded the 32-alternative cap
        self.raw = None       # the word's exact source text; None for a word the lexer did not read from the input

    @property
    def text(self):
        return self.alts[0]

    def all_alts(self):
        """Every expansion for target checks: an overflowed brace word is re-expanded with a 4096 cap.
        None means it is still too large, so its targets are unknown."""
        if self.overflow is None:
            return self.alts[:32]
        raw = self.overflow
        more = brace_expand(raw, limit=4096) if raw.count('{') <= 64 and len(raw) <= 65536 else []
        if more and len(more) <= 4096:
            return [_unq(a) for a in more]
        return None


class Redir:
    __slots__ = ('fd', 'op', 'target', 'body', 'delim', 'quoted', 'strip')

    def __init__(self, fd, op):
        self.fd, self.op, self.target, self.body, self.delim, self.quoted, self.strip = fd, op, None, '', None, False, False


class Cmd:
    def __init__(self):
        self.words = []
        self.redirs = []


class Pipeline:
    def __init__(self):
        self.cmds = []
        self.bg = False


Q = {'*': '', '?': '', '[': '', '{': '', '}': '', ',': '', ' ': ''}
UNQ = {v: k for k, v in Q.items()}
SUB_MARK, ARITH_MARK = '', ''
VAR_OPEN, VAR_CLOSE = chr(0xE030), chr(0xE031)
VAR_MARKER = re.compile(VAR_OPEN + '([A-Za-z_][A-Za-z0-9_]*)' + VAR_CLOSE)
WS = ' \t\r\f\v'
RESERVED = {'if', 'then', 'else', 'elif', 'do', 'while', 'until', '{', '}', '!', 'time', 'fi', 'done', 'esac',
            'function', 'coproc', ';;'}
NONEXEC_HEADS = {'for', 'case', 'select'}


def _unq(text):
    return ''.join(UNQ.get(ch, ch) for ch in text)


def decode_ansi(body):
    out, i = [], 0
    simple = {'n': '\n', 't': '\t', 'r': '\r', 'a': '\a', 'b': '\b', 'e': '\x1b', 'E': '\x1b', 'f': '\f',
              'v': '\v', '\\': '\\', "'": "'", '"': '"', '?': '?'}
    while i < len(body):
        ch = body[i]
        if ch != '\\' or i + 1 >= len(body):
            out.append(ch)
            i += 1
            continue
        nxt = body[i + 1]
        if nxt in simple:
            out.append(simple[nxt])
            i += 2
        elif nxt == 'x':
            m = re.match(r'[0-9a-fA-F]{1,2}', body[i + 2:i + 4])
            out.append(chr(int(m.group(0), 16)) if m else 'x')
            i += 2 + (len(m.group(0)) if m else 0)
        elif nxt in 'uU':
            width = 4 if nxt == 'u' else 8
            m = re.match(r'[0-9a-fA-F]{1,%d}' % width, body[i + 2:i + 2 + width])
            try:
                out.append(chr(int(m.group(0), 16)) if m else nxt)
            except (ValueError, OverflowError):
                out.append('?')
            i += 2 + (len(m.group(0)) if m else 0)
        elif nxt in '01234567':
            m = re.match(r'[0-7]{1,3}', body[i + 1:i + 4])
            out.append(chr(int(m.group(0), 8) & 0xFF))
            i += 1 + len(m.group(0))
        else:
            out.append(nxt)
            i += 2
    return ''.join(out)


def scan_balanced(s, i, open_ch='(', close_ch=')'):
    """Index just past the delimiter closing the one opened before s[i]; quote and nesting aware."""
    depth, n = 1, len(s)
    while i < n:
        c = s[i]
        if c == '\\':
            i += 2
            continue
        if c == "'":
            j = s.find("'", i + 1)
            i = n if j < 0 else j + 1
            continue
        if c == '"':
            i += 1
            while i < n and s[i] != '"':
                i += 2 if s[i] == '\\' else 1
            i += 1
            continue
        if c == '`':
            j = i + 1
            while j < n and s[j] != '`':
                j += 2 if s[j] == '\\' else 1
            i = j + 1
            continue
        if c == open_ch:
            depth += 1
        elif c == close_ch:
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return n + 1  # unterminated: caller takes the rest


def scan_backtick(s, i):
    """Index just past the backtick closing the one opened before s[i] (unterminated: len(s) + 1)."""
    n = len(s)
    while i < n:
        if s[i] == '\\':
            i += 2
            continue
        if s[i] == '`':
            return i + 1
        i += 1
    return n + 1


def brace_expand(text, limit=32):
    """Bash brace expansion on a string whose quoted braces were replaced by sentinels."""
    out = [text]
    for _ in range(6):
        changed, nxt = False, []
        for item in out:
            m = _find_brace(item)
            if not m:
                nxt.append(item)
                continue
            changed = True
            start, end, parts = m
            for part in parts:
                nxt.append(item[:start] + part + item[end:])
                if len(nxt) > limit:
                    return nxt[:limit + 1]  # one extra item tells the caller the expansion overflowed
        out = nxt
        if not changed:
            break
    return out[:limit]


def _find_brace(text):
    i = text.find('{')
    while i >= 0:
        depth, j, commas = 1, i + 1, []
        while j < len(text) and depth:
            if text[j] == '{':
                depth += 1
            elif text[j] == '}':
                depth -= 1
            elif text[j] == ',' and depth == 1:
                commas.append(j)
            j += 1
        if depth == 0 and commas:
            parts, last = [], i + 1
            for c in commas:
                parts.append(text[last:c])
                last = c + 1
            parts.append(text[last:j - 1])
            return i, j, parts
        i = text.find('{', i + 1)
    return None


# zsh clobber forms (the Bash tool may run zsh): judged as the bash operator with the same effect
ZSH_CLOBBER = {'>!': '>|', '>>!': '>>', '>>|': '>>', '&>!': '&>', '&>|': '&>', '>&!': '&>', '>&|': '&>',
               '&>>!': '&>>', '&>>|': '&>>', '>>&': '&>>', '>>&!': '&>>', '>>&|': '&>>'}


class Lexer:
    """`bang_operators` picks how `>!` and its relatives read. zsh takes them as one clobber operator. bash and sh do
    not have them: they stop the operator before the `!`, which starts the next word, so `>! w` writes a file named
    `!` and w is a command word. `saw_bang` reports whether the text had such an operator, so that a caller knows a
    second reading exists (Analyzer.script)."""

    def __init__(self, ctx, ps=False, bang_operators=True):
        self.ctx = ctx
        self.ps = ps
        self.budget = ctx.budget
        self.bang_operators = bang_operators
        self.saw_bang = False

    # ---- words
    def read_word(self, s, i, at_start=True):
        n = len(s)
        w = Word()
        buf = []
        started = i
        any_char = False
        while i < n:
            self.budget.tick()
            c = s[i]
            if c in WS or c == '\n' or c in ';&|()' or (c in '<>' and not (c in '<>' and i + 1 < n and s[i + 1] == '(' and i == started)):
                break
            any_char = True
            if (not self.ps and c == '\\') or (self.ps and c == '`'):
                if i + 1 < n:
                    ch = s[i + 1]
                    buf.append(Q.get(ch, ch))
                    w.quoted = True
                    i += 2
                else:
                    i += 1
                continue
            if c == "'":
                j = s.find("'", i + 1)
                if j < 0:
                    self.ctx.unterminated = True
                body = s[i + 1:] if j < 0 else s[i + 1:j]
                buf.append(''.join(Q.get(ch, ch) for ch in body))
                w.quoted = True
                i = n if j < 0 else j + 1
                continue
            if c == '"':
                i = self._double(s, i + 1, w, buf)
                w.quoted = True
                continue
            if c == '$':
                i = self._dollar(s, i, w, buf, in_dq=False)
                continue
            if c == '`' and not self.ps:
                j = scan_backtick(s, i + 1)
                inner = s[i + 1:j - 1] if j <= n else s[i + 1:]
                w.subs.append(inner.replace('\\`', '`').replace('\\\\', '\\'))
                w.dynamic = True
                buf.append(SUB_MARK)
                i = min(j, n)
                continue
            if c in '<>' and i + 1 < n and s[i + 1] == '(':
                j = scan_balanced(s, i + 2)
                w.subs.append(s[i + 2:j - 1] if j <= n else s[i + 2:])
                w.dynamic = True
                buf.append(SUB_MARK)
                i = min(j, n)
                continue
            if c == '~' and i == started and not self.ps or (c == '~' and i == started and self.ps):
                nxt = s[i + 1] if i + 1 < n else ''
                if nxt in ('', '/', '\\') or nxt in WS:
                    buf.append(self.ctx.home.replace(' ', Q[' ']))
                    i += 1
                    continue
            if c in '*?[':
                w.glob = True
            if c == '$' and False:
                pass
            buf.append(c)
            i += 1
        if not any_char and i == started:
            return None, i
        raw = ''.join(buf)
        alts = [raw]
        if '{' in raw and ',' in raw:
            expandable = raw.count('{') <= 24 and len(raw) <= 2048
            if expandable:
                alts = brace_expand(raw)
            if len(alts) > 32 or not expandable:
                # too many alternatives (or too big to expand): target checks re-expand it with a larger cap
                # and treat anything past that as unknown (see Analyzer.target_class)
                w.overflow = raw
                alts = alts[:32]
        w.alts = [_unq(a) for a in alts]
        return w, i

    def _double(self, s, i, w, buf):
        n = len(s)
        while i < n and s[i] != '"':
            self.budget.tick()
            c = s[i]
            if c == '\\' and i + 1 < n and (s[i + 1] in '$`"\\' or s[i + 1] == '\n'):
                if s[i + 1] != '\n':
                    buf.append(Q.get(s[i + 1], s[i + 1]))
                i += 2
            elif c == '`' and not self.ps:
                j = scan_backtick(s, i + 1)
                w.subs.append((s[i + 1:j - 1] if j <= n else s[i + 1:]).replace('\\`', '`'))
                w.dynamic = True
                buf.append(SUB_MARK)
                i = min(j, n)
            elif c == '$':
                i = self._dollar(s, i, w, buf, in_dq=True)
            elif self.ps and c == '`' and i + 1 < n:
                buf.append(Q.get(s[i + 1], s[i + 1]))
                i += 2
            else:
                buf.append(Q.get(c, c))
                i += 1
        if i >= n:
            self.ctx.unterminated = True
        return i + 1

    def _dollar(self, s, i, w, buf, in_dq):
        n = len(s)
        nxt = s[i + 1] if i + 1 < n else ''
        if nxt == "'" and not in_dq:
            j = i + 2
            while j < n and s[j] != "'":
                j += 2 if s[j] == '\\' else 1
            buf.append(''.join(Q.get(ch, ch) for ch in decode_ansi(s[i + 2:j])))
            w.quoted = True
            return min(j + 1, n)
        if nxt == '"' and not in_dq:
            return i + 1  # $"..." locale string: the quote branch handles the rest
        if nxt == '(':
            if s[i + 2:i + 3] == '(':
                j = scan_balanced(s, i + 3)
                w.dynamic = True
                buf.append(ARITH_MARK)
                return min(j + 1, n)
            j = scan_balanced(s, i + 2)
            if j > n:
                self.ctx.unterminated = True
            w.subs.append(s[i + 2:j - 1] if j <= n else s[i + 2:])
            w.dynamic = True
            buf.append(SUB_MARK)
            return min(j, n)
        if nxt == '{':
            j = scan_balanced(s, i + 2, '{', '}')
            body = s[i + 2:j - 1] if j <= n else s[i + 2:]
            self._expand_braced(body, w, buf)
            return min(j, n)
        if self.ps and s[i + 1:i + 5].lower() == 'env:':
            m = re.match(r'[A-Za-z_][A-Za-z0-9_]*', s[i + 5:i + 135])
            if m:
                w.vars.append(m.group(0))
                w.dynamic = True
                buf.append('$env:' + m.group(0))
                return i + 5 + len(m.group(0))
        m = re.match(r'[A-Za-z_][A-Za-z0-9_]*', s[i + 1:i + 130])
        if m:
            self._use_var(m.group(0), w, buf)
            return i + 1 + len(m.group(0))
        if nxt and nxt in '?$!@*#0123456789-':
            if nxt in '@*0123456789':
                w.vars.append(nxt)  # positional parameter: a flow variable (see _hint_points_at_protected)
                w.dynamic = True
            buf.append('$' + nxt)
            return i + 2
        if self.ps and s[i + 1:i + 5].lower() == 'env:':
            m = re.match(r'[A-Za-z_][A-Za-z0-9_]*', s[i + 5:i + 135])
            if m:
                w.vars.append(m.group(0))
                w.dynamic = True
                buf.append('$env:' + m.group(0))
                return i + 5 + len(m.group(0))
        buf.append('$')
        return i + 1

    def _expand_braced(self, body, w, buf):
        if body.startswith('#'):                    # ${#VAR}: a length, not the value
            buf.append(ARITH_MARK)
            return
        if body.startswith('!'):                    # ${!VAR}: indirect, value of the variable named by VAR
            w.vars.append('!' + body[1:].split(':')[0])
            w.dynamic = True
            buf.append(SUB_MARK)
            return
        m = re.match(r'([A-Za-z_][A-Za-z0-9_]*)(.*)$', body, re.S)
        if not m:
            buf.append('${' + body + '}')
            return
        name, rest = m.group(1), m.group(2)
        if rest[:2] == ':+' or rest[:1] == '+':     # ${VAR:+word}: only reveals whether VAR is set
            buf.append(ARITH_MARK)
            return
        if not rest:
            self._use_var(name, w, buf)
            return
        w.vars.append(name)
        w.dynamic = True
        buf.append('${' + name + rest + '}')

    def _use_var(self, name, w, buf):
        w.vars.append(name)
        if name == 'HOME':
            buf.append(''.join(Q.get(ch, ch) for ch in self.ctx.home))
        else:  # resolved later, when the command runs, so earlier assignments on the same line apply
            buf.append(VAR_OPEN + name + VAR_CLOSE)

    # ---- tokens
    def lex(self, text):
        s = text.replace('\x00', '')
        s = re.sub(r'`\r?\n' if self.ps else r'\\\r?\n', '', s)
        n, i = len(s), 0
        tokens, pending = [], []
        prev_end = -1
        wait_target = None
        while i < n:
            self.budget.tick()
            c = s[i]
            if c in WS:
                i += 1
                continue
            if c == '\n':
                tokens.append(('op', '\n'))
                i += 1
                for rd in pending:
                    i = self._heredoc_body(s, i, rd)
                pending = []
                continue
            if c == '#':
                j = s.find('\n', i)
                i = n if j < 0 else j
                continue
            if c in ';&|()<>' and not (c in '<>' and s[i + 1:i + 2] == '('):
                op = self._operator(s, i)
                # the whole operator, not its first character: `&>` and `&>>` start with `&` (GoodQA #14471 follow-up)
                if op in ('<', '>', '&>', '>&', '<&', '<>', '<<', '<<<', '<<-', '&>>', '>>', '>|') or op in ZSH_CLOBBER:
                    fd = None
                    if tokens and tokens[-1][0] == 'w' and prev_end == i and re.fullmatch(r'[0-9]', tokens[-1][1].text or 'x'):
                        fd = tokens.pop()[1].text
                    rd = Redir(fd, ZSH_CLOBBER.get(op, op))
                    tokens.append(('redir', rd))
                    wait_target = rd
                    if op in ('<<', '<<-'):
                        rd.strip = op == '<<-'
                        pending.append(rd)
                    i += len(op)
                    continue
                tokens.append(('op', op))
                i += len(op)
                continue
            w, j = self.read_word(s, i)
            if w is None:
                i += 1
                continue
            w.raw = s[i:j]
            if wait_target is not None:
                wait_target.target = w
                if wait_target.op in ('<<', '<<-'):
                    wait_target.delim = w.text
                    wait_target.quoted = w.quoted
                wait_target = None
            else:
                tokens.append(('w', w))
            prev_end = j
            i = j
        return tokens

    def _operator(self, s, i):
        for op in ('>>&!', '>>&|', '&>>!', '&>>|', '<<<', '<<-', '>>&', '&>>', '>>!', '>>|', '&>!', '&>|', '>&!', '>&|', '&&',
                   '||', '|&', '>>', '>&', '<&', '<>', '<<', '&>', '>|', '>!', ';', '&', '|', '(', ')', '<', '>'):
            if s.startswith(op, i):
                if op.endswith('!'):
                    self.saw_bang = True
                    if not self.bang_operators:
                        return op[:-1]
                return op
        return s[i]

    def _heredoc_body(self, s, i, rd):
        n, lines, delim = len(s), [], (rd.delim or '')
        size = 0
        while i < n:
            self.budget.tick()
            j = s.find('\n', i)
            line = s[i:] if j < 0 else s[i:j]
            i = n if j < 0 else j + 1
            check = line.lstrip('\t') if rd.strip else line
            if check.rstrip('\r') == delim:
                break
            size += len(line) + 1
            if size > 1 << 20:
                raise Blocked('here-document larger than 1 MiB')
            lines.append(line)
        rd.body = '\n'.join(lines)
        return i


MKTEMP_FLAGS = {'-d', '-q', '-u', '--directory', '--quiet', '--dry-run'}
# commands that only read, write through, or remove their operands; a temp path handed to anything else (mv, cp,
# rsync, tar, an interpreter, a function) could be replaced by a symlink, so it keeps the normal rules
TEMP_SAFE_COMMANDS = {'rm', 'cat', 'echo', 'printf', 'cut', 'grep', 'egrep', 'fgrep', 'sed', 'awk', 'sort', 'uniq',
                      'head', 'tail', 'wc', 'tr', 'diff', 'cmp', 'jq', 'base64', 'ssh-keyscan', 'ssh-keygen', 'openssl',
                      'curl', 'wget', 'chmod', 'test', '[', '[[', 'stat', 'ls', 'file', 'xxd', 'od', 'shasum',
                      'sha256sum', 'md5', 'md5sum', 'touch', 'mkdir', 'tee', 'rmdir'}


def mktemp_directory(text, cwd):
    """The directories a plain `mktemp [-dqu] [-t prefix] [-p dir] [template]` may create its file in, or None when
    the hook cannot tell (any other word, option or expansion). TMPDIR is the command's, which the hook does not see:
    $TMPDIR / ${TMPDIR:-x} and the default are tried with the hook's TMPDIR (or /tmp) and with CLAUDE_CODE_TMPDIR,
    and the caller requires every candidate to be safe. goodqa#15122 AC-1."""
    candidates = [os.environ.get('TMPDIR') or '/tmp']
    if os.environ.get('CLAUDE_CODE_TMPDIR'):
        candidates.append(os.environ['CLAUDE_CODE_TMPDIR'])
    out = []
    for env_tmp in candidates:
        base = _mktemp_base(text, cwd, env_tmp)
        if base is None:
            return None
        out.append(base)
    return tuple(dict.fromkeys(out))


def _mktemp_base(text, cwd, env_tmp):
    t = re.sub(r'\$\{TMPDIR(?::?-[^}$`]*)?\}|\$TMPDIR(?!\w)', lambda _m: env_tmp.rstrip('/') or '/', text.strip())
    if re.search(r'[$`\\(){};&|<>*?\[\]~!#\n]', t):
        return None
    try:
        args = shlex.split(t)
    except ValueError:
        return None
    if not args or args[0] not in ('mktemp', '/usr/bin/mktemp', '/bin/mktemp'):
        return None
    tdir, template, t_flag, i = None, None, False, 1
    while i < len(args):
        a = args[i]
        if a in MKTEMP_FLAGS or re.fullmatch(r'-[dqu]+', a):
            pass
        elif a == '-t':
            t_flag = True
            if i + 1 < len(args) and not args[i + 1].startswith('-'):
                if template is not None or '/' in args[i + 1]:
                    return None
                template = args[i + 1]
                i += 1
        elif a in ('-p', '--tmpdir') and i + 1 < len(args):
            tdir = args[i + 1]
            i += 1
        elif a.startswith('--tmpdir='):
            tdir = a.split('=', 1)[1]
        elif a.startswith('-') or template is not None:
            return None
        else:
            template = a
        i += 1
    if tdir is not None:
        if template and '/' in template:
            return None
        base = tdir
    elif template and '/' in template:
        base = os.path.dirname(template)
    elif template and not t_flag:
        base = cwd  # a bare template is made in the working directory
    else:
        base = env_tmp
    if not base:
        return None
    if not base.startswith('/'):
        if not cwd:
            return None
        base = os.path.join(cwd, base)
    return os.path.normpath(base)


def _strip_case_patterns(tokens):
    """`case X in a|b) cmd;; *) cmd;; esac`: drop the pattern lists so `a|b` is not a pipeline and `*` is not a
    command whose name is a glob. The bodies stay as ordinary commands."""
    out, stack, i, n = [], [], 0, len(tokens)
    while i < n:
        kind, val = tokens[i]
        at_start = not out or out[-1][0] == 'op' or (out[-1][0] == 'w' and not out[-1][1].quoted
                                                       and out[-1][1].text in RESERVED)
        if kind == 'w' and not val.quoted and val.text == 'case' and at_start and i + 2 < n \
                and tokens[i + 2][0] == 'w' and tokens[i + 2][1].text == 'in':
            out.append(tokens[i])
            out.append(tokens[i + 1])
            stack.append('patterns')
            i += 3
            continue
        if stack and stack[-1] == 'patterns':
            if kind == 'w' and not val.quoted and val.text == 'esac':
                stack.pop()
                out.append(tokens[i])
            elif kind == 'op' and val == ')':
                stack[-1] = 'body'
                out.append(('op', ';'))
            # pattern words, `|` and a leading `(` are dropped; newlines between items are kept
            elif kind == 'op' and val == '\n':
                out.append(tokens[i])
            i += 1
            continue
        if stack and kind == 'op' and val == ';' and i + 1 < n and tokens[i + 1] == ('op', ';'):
            stack[-1] = 'patterns'
            out.append(('op', ';'))
            i += 2
            continue
        if stack and kind == 'op' and val == ';' and i + 1 < n and tokens[i + 1] in (('op', '&'), ('op', ';;&')):
            stack[-1] = 'patterns'
            out.append(('op', ';'))
            i += 2
            continue
        if stack and kind == 'w' and not val.quoted and val.text == 'esac' and at_start:
            stack.pop()
        out.append(tokens[i])
        i += 1
    return out


def parse(tokens):
    tokens = _strip_case_patterns(tokens)
    pipelines, pl, cmd = [], Pipeline(), Cmd()

    def end_cmd():
        nonlocal cmd
        if cmd.words or cmd.redirs:
            pl.cmds.append(cmd)
        cmd = Cmd()

    def end_pl(bg=False):
        nonlocal pl
        end_cmd()
        if pl.cmds:
            pl.bg = bg
            pipelines.append(pl)
        pl = Pipeline()

    for kind, val in tokens:
        if kind == 'w':
            cmd.words.append(val)
        elif kind == 'redir':
            cmd.redirs.append(val)
        elif val in ('|', '|&'):
            end_cmd()
        else:
            end_pl(val == '&')
    end_pl()
    return pipelines


def strip_reserved(words):
    words = list(words)
    while words and not words[0].quoted and words[0].text in RESERVED:
        words.pop(0)
    return words


# --------------------------------------------------------------------------- name and path helpers

CONFUSABLE = {ord(a): b for a, b in zip('аеорсуіѕјԁһԛԝхѕ', 'aeopcyisjdhqwxs')}
CONFUSABLE.update({ord(a): b for a, b in zip('αεορυνιτκχ', 'aeopuvitkx')})
CF = {'Cf', 'Mn', 'Me'}


def norm_name(text):
    text = unicodedata.normalize('NFKC', text)
    text = ''.join(ch for ch in text if unicodedata.category(ch) not in CF)
    text = text.translate(CONFUSABLE).casefold()
    base = re.split(r'[\\/]', text.rstrip('/\\'))[-1]
    for suffix in ('.exe', '.cmd', '.bat', '.ps1', '.com'):
        if base.endswith(suffix):
            base = base[:-len(suffix)]
    return base


TRANSCRIPT_CODE_WRITE = re.compile(r'open\s*\([^)]*,\s*[\'"][^\'"]*[wax+]|\.write_(?:text|bytes)\s*\(|symlink|'
                                   r'shutil\.(?:copy|move)|os\.(?:rename|replace|link)\s*\(|'
                                   r'fs\.(?:write|append|symlink|copy|rename)|copyfile|hardlink')


def transcript_write(c, folded):
    """True when `folded` (an absolute casefolded path) is ~/.claude/projects or inside it, outside a memory folder."""
    for root in getattr(c, 'transcript_roots', ()):
        if folded == root:
            return True
        if folded.startswith(root + '/'):
            parts = folded[len(root) + 1:].split('/')
            return not (len(parts) >= 3 and parts[1] == 'memory')
    return False


def norm_path(text, ctx, cwd=None):
    """Absolute, normalised path with / separators (case kept; match with casefold). Unresolved vars stay $NAME."""
    text = unicodedata.normalize('NFKC', text.replace('\\', '/') if ctx.ps else text)
    text = ''.join(ch for ch in text if unicodedata.category(ch) != 'Cf')
    if text == '~' or text.startswith('~/'):
        text = ctx.home + text[1:]
    elif re.match(r'~[A-Za-z0-9_.][A-Za-z0-9_.-]*(?:/|$)', text):
        # ~user/...: that user's home; an unknown user still lands under a generic home pattern
        user, _, rest = text[1:].partition('/')
        expanded = os.path.expanduser('~' + user)
        base = expanded if expanded != '~' + user else '/home/' + user
        text = base + ('/' + rest if rest else '')
    text = re.sub(r'^(?:\$env:USERPROFILE|%USERPROFILE%)', lambda _m: ctx.home, text, flags=re.I)
    if not text.startswith('/') and not re.match(r'^[A-Za-z]:/', text):
        text = posixpath.join(cwd if cwd is not None else ctx.cwd_value(), text)
    return posixpath.normpath(text) if text else ''


GLOB_CHARS = '*?['


def _has_glob(seg):
    return any(ch in seg for ch in GLOB_CHARS)


def _fnmatchcase(name, pattern):
    """fnmatch that cannot raise: Python 3.9 raises re.error on a reversed range such as [z-a], and an exception here
    would cost the whole command its findings. It may still match in a shell ([z-ae] matches e), so an unreadable
    pattern counts as a match: every caller only gets stricter."""
    try:
        return fnmatch.fnmatchcase(name, pattern)
    except re.error:
        return True


def _seg_eq(p, r):
    """One path segment against one pattern segment; either side may be a glob."""
    if p == r:
        return True
    gp, gr = _has_glob(p), _has_glob(r)
    if gp and gr:
        return True  # two patterns may overlap: assume they do
    if gp:
        return _fnmatchcase(r, p)
    if gr:
        return _fnmatchcase(p, r)
    return False


def _prefix_match(path_segs, root_segs):
    n = min(len(path_segs), len(root_segs))
    return all(_seg_eq(path_segs[k], root_segs[k]) for k in range(n))


# Raw text that names a protected location: used for unresolved variables, substitutions and fallbacks.
PROTECTED_TEXT = re.compile(r'(?i)\.(?:claude|codex|agent-harness)(?![\w-])|(?:^|[/\s\'"])wals?(?:/|$|[\s\'"])|'
                            r'main\.jsonl|\.wal\.jsonl')
PROTECTED_VAR_NAME = re.compile(r'(?i)claude|codex|harness|(?:^|_)wals?(?:_|$)')
RELATIVE_PROTECTED_NAMES = {'projects', 'wals', 'sessions', 'history.jsonl', 'transcripts', 'archived_sessions',
                            '.claude', '.codex', '.agent-harness', 'file-history', 'main.jsonl'}


def _lexists(path):
    try:
        return len(path) < 4096 and os.path.lexists(path)
    except (OSError, ValueError):
        return False


def _resolve_prefix(path):
    """realpath of the longest existing prefix (symlinks resolved), with the unresolved rest appended."""
    if not path or len(path) > 4096 or '\x00' in path:
        return None
    try:
        return os.path.realpath(path)
    except (OSError, ValueError, RuntimeError):
        return None


def _real_git_marker(marker):
    """A .git directory holding HEAD, or a .git file starting with `gitdir:` (linked worktree)."""
    try:
        if os.path.isdir(marker) and not os.path.islink(marker):
            return os.path.isfile(os.path.join(marker, 'HEAD'))
        if os.path.isfile(marker) and not os.path.islink(marker):
            with open(marker, 'rb') as handle:
                return handle.read(8) == b'gitdir: '
    except OSError:
        return False
    return False


# ----------------------------------------------------------------------------- reproducible clones (goodqa#14817)
# A git clone of pushed work is recreated by `git clone`, so making the user back it up to Dropbox first is waste
# (a 6.7 GB release clone, tonight). Deleting one is allowed ONLY when git itself proves nothing in it is unique:
# the path is a real, unlinked top-level checkout (full .git directory), the tree is clean with nothing untracked and
# nothing ignored beyond regenerable build dirs, no stash, no linked worktrees or submodules, and every local ref tip
# is reachable from a remote-tracking ref whose tip equals what the remote reports right now. Any error, timeout or
# surprise means "not reproducible" and the existing approve-delete rule applies. Repository-local config can name
# programs git would run (fsmonitor, filters, ssh command ...), so the config is whitelisted before git runs at all.

CLONE_ENV_KEEP = ('PATH', 'HOME', 'LANG', 'LC_ALL', 'TMPDIR', 'SSH_AUTH_SOCK', 'USER', 'LOGNAME')
CLONE_CONFIG_SECTIONS = {'core', 'remote', 'branch', 'user', 'gc', 'pack', 'fetch', 'pull', 'push', 'init', 'advice'}
CLONE_CONFIG_BAD_KEYS = {'core.fsmonitor', 'core.hookspath', 'core.sshcommand', 'core.gitproxy', 'core.pager',
                         'core.editor', 'core.askpass', 'core.attributesfile', 'core.excludesfile', 'core.worktree',
                         'core.alternaterefscommand',
                         'remote.proxy', 'remote.vcs', 'remote.uploadpack', 'remote.receivepack', 'remote.proxyauthmethod'}
CLONE_CONFIG_BAD_KEYS_CORE = {'trustctime', 'checkstat', 'ignorestat', 'fsmonitor', 'hookspath', 'sshcommand', 'gitproxy', 'pager', 'editor',
                              'askpass', 'attributesfile', 'excludesfile', 'worktree', 'alternaterefscommand'}
CLONE_URL = re.compile(r'^(?:(?:https|ssh|git)://(?:[^/@\s]+@)?(?P<h1>[A-Za-z0-9.-]+)(?::[0-9]{1,5})?/[^\s]+'
                       r'|(?:[A-Za-z0-9._+-]+@)?(?P<h2>[A-Za-z0-9.-]+):(?![:/])[^\s]+)$')


def _remote_host(url):
    """The host of an https/ssh/git/scp-style URL, lower-cased, else None (local paths, file:, ext::, fd:: ...)."""
    match = CLONE_URL.match(url)
    return (match.group('h1') or match.group('h2')).lower() if match else None


def _clone_env():
    env = {k: os.environ[k] for k in CLONE_ENV_KEEP if k in os.environ}
    env['PATH'] = os.pathsep.join(p for p in env.get('PATH', '').split(os.pathsep) if p.startswith('/')) or '/usr/bin:/bin'
    env.update(GIT_CONFIG_GLOBAL='/dev/null', GIT_CONFIG_NOSYSTEM='1', GIT_TERMINAL_PROMPT='0', GIT_OPTIONAL_LOCKS='0',
               GIT_ATTR_NOSYSTEM='1', GIT_ASKPASS='/bin/true', GIT_CEILING_DIRECTORIES=os.path.dirname(os.sep))
    return env


def _git_out(repo, args, timeout, stdin=None):
    import subprocess
    done = subprocess.run(['git', '-c', 'core.fsmonitor=false', '-c', 'core.hooksPath=/dev/null',
                           '-c', 'protocol.allow=never', '-c', 'protocol.https.allow=always',
                           '-c', 'protocol.ssh.allow=always', '-c', 'protocol.git.allow=always', '-C', repo] + list(args),
                          capture_output=True, timeout=max(0.2, timeout), env=_clone_env(),
                          input=stdin.encode() if stdin is not None else None)
    if done.returncode != 0 or len(done.stdout) > 8 * 1024 * 1024:
        raise ValueError('git %s failed' % (args[0] if args else ''))
    return done.stdout.decode('utf-8', 'surrogateescape')


def _git_try(repo, args, timeout):
    """Like _git_out (same sanitized environment and flags) but returns (returncode, stdout, stderr) so a caller can tell
    "not a git repository" from every other failure."""
    done = subprocess.run(['git', '-c', 'core.fsmonitor=false', '-c', 'core.hooksPath=/dev/null',
                           '-c', 'protocol.allow=never', '-c', 'protocol.https.allow=always',
                           '-c', 'protocol.ssh.allow=always', '-c', 'protocol.git.allow=always', '-C', repo] + list(args),
                          capture_output=True, timeout=max(0.2, timeout), env=_try_env())
    return (done.returncode, done.stdout[:65536].decode('utf-8', 'surrogateescape'),
            done.stderr[:4096].decode('utf-8', 'surrogateescape'))


def _try_env():
    """_clone_env for a caller that reads git's own error text: the C locale (a translated "not a git repository" must not
    be mistaken for another failure) and a repository search as wide as the real command's (the user's shell may allow
    crossing filesystems)."""
    env = _clone_env()
    env['LC_ALL'] = 'C'
    env.pop('LANGUAGE', None)
    env.pop('GIT_CEILING_DIRECTORIES', None)  # _clone_env pins it to /, the real command has none
    env['GIT_DISCOVERY_ACROSS_FILESYSTEM'] = '1'
    return env


def _live_remote_refs(url, repo, timeout):
    """ref -> sha as the remote reports it now (read-only ls-remote). Replaced in tests."""
    out = _git_out(repo, ['ls-remote', '--heads', '--tags', '--', url], timeout)
    refs = {}
    for line in out.splitlines():
        sha, _, ref = line.partition('\t')
        if re.fullmatch(r'[0-9a-f]{40,64}', sha) and ref and not ref.endswith('^{}'):
            refs[ref] = sha
    return refs


REMOTE_LS = _live_remote_refs


_TRUE_WORDS = ('true', 'yes', 'on', '1')
_BOOL_WORDS = ('true', 'false', 'yes', 'no', 'on', 'off', '0', '1')
_FALSE_WORDS = ('false', 'no', 'off', '0')
WORKTREE_CONFIG_BYTES = 64 * 1024


def _config_refusal(listing, allow_worktree_config=False):
    """`git config --local -z --list` output (git's own parse: a BOM, quoting or case games cannot hide a key).
    Refuses an include, a section outside the whitelist, or a key that names a program git would run.
    `allow_worktree_config` (the linked-worktree verifier only) accepts exactly one extension, `extensions.worktreeConfig`,
    once and plainly true; any other extensions key, a subsection spelling, a duplicate or another value still refuses.
    A bare key and an explicit empty value differ (the item has no newline for a bare key, which git reads as true)."""
    seen = 0
    for item in filter(None, listing.split('\x00')):
        key, has_value, value = item.partition('\n')
        key = key.lower()
        section, _, rest = key.partition('.')
        leaf = key.rsplit('.', 1)[-1]
        if allow_worktree_config and key == 'extensions.worktreeconfig':
            seen += 1
            if seen > 1:
                return 'extensions.worktreeConfig is set more than once'
            if has_value and value.strip().lower() not in _TRUE_WORDS:
                return 'extensions.worktreeConfig is not plainly true'
            continue
        if section in ('include', 'includeif'):
            return 'the repository config includes another file'
        if section not in CLONE_CONFIG_SECTIONS:
            return 'the repository config has a [%s] section' % section[:20]
        if key == 'core.logallrefupdates' and has_value and value.strip().lower() not in _TRUE_WORDS + ('always',):
            return 'reflogs are switched off in the repository config'  # git also reads 00, 0k and an empty value as false
        if '%s.%s' % (section, leaf) in CLONE_CONFIG_BAD_KEYS or (section == 'core' and leaf in CLONE_CONFIG_BAD_KEYS_CORE):
            return 'the repository config sets %s.%s' % (section, leaf)
    return None


def _worktree_config_enabled(listing):
    return any(item.partition('\n')[0].lower() == 'extensions.worktreeconfig' for item in listing.split('\x00') if item)


def _per_worktree_items_refusal(listing):
    """What a per-worktree config file may hold: sparse-checkout switches, `index.sparse` (a sparse index changes the
    index format only) and `core.bare` false. Anything else refuses (names only in the message, never a value)."""
    for item in filter(None, listing.split('\x00')):
        key, has_value, value = item.partition('\n')
        key, word = key.lower(), value.strip().lower()
        if key in ('core.sparsecheckout', 'core.sparsecheckoutcone', 'index.sparse'):
            if has_value and word not in _BOOL_WORDS:
                return 'a per-worktree config sets %s to a non-boolean value' % key
            continue
        if key == 'core.bare':
            if not has_value or word not in _FALSE_WORDS:
                return 'a per-worktree config makes the worktree bare'
            continue
        return 'a per-worktree config sets %s.%s' % (re.sub(r'[^a-z0-9_-]', '?', key.partition('.')[0])[:20],
                                                      re.sub(r'[^a-z0-9_-]', '?', key.rsplit('.', 1)[-1])[:30])  # never a subsection: it can hold a URL with a token
    return None


def _per_worktree_config_refusal(path, common, git_dir, cwd, step):
    """With `extensions.worktreeConfig` on, git reads $common/config.worktree for the primary worktree and
    $common/worktrees/ID/config.worktree for a linked one. The programs a removal can start are decided by the worktrees
    whose git commands run: the PRIMARY (the delegated removal runs from there), the TARGET (the cleanliness check runs
    in it) and the worktree the caller stands in (the hook form runs from the caller's directory). Each of those files
    is vetted (lstat first, plain file, size cap, `git config --file` read) before any git command that could start a
    program named by config (`ls-files`, `status`, the removal); a missing file is fine. Four git calls run earlier and do
    read an unvetted config.worktree (`rev-parse` in the target, `rev-parse` in the caller, `worktree list`, `config
    --local --list`): they are safe because every git call here carries `core.fsmonitor=false` and `core.hooksPath=/dev/null`
    and none refreshes the index or runs a filter or helper; the call-order test pins that the vetting precedes `ls-files`
    and `status`. An unrelated linked worktree's file is never read by this removal and does not
    decide it."""
    files = [os.path.join(common, 'config.worktree'), os.path.join(git_dir, 'config.worktree')]
    if cwd and os.path.isdir(cwd):
        # The caller's own file is vetted whenever the caller stands inside ANY repository: comparing its common directory
        # with ours by path text is fooled by a case spelling or a firmlink on macOS (red-team F1), so no match is tried.
        # Only git's own "not a git repository" lets the lookup be skipped; any other failure or odd output refuses.
        code, out, err = _git_try(cwd, ['rev-parse', '--path-format=absolute', '--absolute-git-dir'], step(2.0))
        if code != 0:
            if not (err.splitlines() or [''])[0].startswith('fatal: not a git repository'):  # the first line only
                return 'could not determine the calling worktree'
        else:
            lines = out.splitlines()
            if len(lines) != 1 or not lines[0].startswith('/'):
                return 'could not determine the calling worktree'
            files.append(os.path.join(os.path.realpath(lines[0]), 'config.worktree'))
    seen = set()
    for file in files:
        if file in seen:
            continue
        seen.add(file)
        try:
            info = os.lstat(file)
        except FileNotFoundError:
            continue
        except OSError:
            return 'a per-worktree config file cannot be inspected'
        if not stat.S_ISREG(info.st_mode):
            return 'a per-worktree config file is not a plain file'
        if info.st_size > WORKTREE_CONFIG_BYTES:
            return 'a per-worktree config file is unusually large'
        bad = _per_worktree_items_refusal(_git_out(path, ['config', '--file', file, '-z', '--list'], step(2.0)))
        if bad:
            return bad
    return None


def _nested_repo(directory, limit=250000, deep=False, seconds=1.5):
    """True for a repository (.git or a bare repo) in the directory or below it (one level for caches, eight for
    generic build dirs); 'large' when the scan hit its entry or time bound; False otherwise."""
    seen = 0
    stop = time.monotonic() + seconds
    stack = [(directory, 0)]
    while stack:
        current, depth = stack.pop()
        if os.path.lexists(os.path.join(current, '.git')) or (
                os.path.isfile(os.path.join(current, 'HEAD')) and os.path.isdir(os.path.join(current, 'objects'))):
            return True  # a checkout, or a bare repository
        if depth >= (8 if deep else 2):
            continue
        with os.scandir(current) as entries:
            for entry in entries:
                seen += 1
                if seen > limit or time.monotonic() > stop:
                    return 'large'
                if entry.is_dir(follow_symlinks=False) and (deep or depth == 0 or entry.name.startswith('@')
                                                            or current.rsplit('/', 1)[-1].startswith('@')):
                    stack.append((entry.path, depth + 1))
    return False


def reproducible_clone_refusal(path, policy=None, now=None):
    """None when `path` is provably a reproducible clone, else the reason it is not."""
    cfg = dict(DEFAULT_POLICY['reproducible_clone'], **((policy or {}).get('reproducible_clone') or {}))
    if not cfg.get('enabled'):
        return 'the exemption is switched off'
    started = time.monotonic()
    total = float(cfg['total_seconds'])

    def left():
        remaining = total - (time.monotonic() - started)
        if remaining <= 0.2:
            raise TimeoutError('time budget')
        return remaining
    try:
        if not path or '\x00' in path or not os.path.isabs(path):
            return 'not a literal absolute path'
        path = path.rstrip('/') or '/'
        if os.path.normpath(path) != path or os.path.realpath(path) != path:
            return 'the path contains a symlink, dot segment or alias'
        if os.path.islink(path) or not os.path.isdir(path):
            return 'not a plain directory'
        gitdir = os.path.join(path, '.git')
        if os.path.islink(gitdir) or not os.path.isdir(gitdir):
            return '.git is not a real directory (linked worktree or not a clone)'
        for forbidden, why in (('worktrees', 'it owns linked worktrees'), ('modules', 'it has submodules'),
                               (os.path.join('info', 'grafts'), 'it has grafts'), ('refs/replace', 'it has replace refs')):
            if os.path.lexists(os.path.join(gitdir, forbidden)):
                return why
        if os.path.lexists(os.path.join(path, '.gitmodules')):
            return 'it has submodules'
        if os.path.getsize(os.path.join(gitdir, 'config')) > 256 * 1024:
            return 'the repository config is unusually large'
        bad = _config_refusal(_git_out(path, ['config', '--local', '-z', '--list'], min(left(), 2.0)))
        if bad:
            return bad
        hooks_dir = os.path.join(gitdir, 'hooks')
        if os.path.isdir(hooks_dir) and any(not n.endswith('.sample') for n in os.listdir(hooks_dir)):
            return 'it has hand-written git hooks'
        for entry in _git_out(path, ['ls-files', '-s', '-z'], min(left(), 3.0)).split('\x00'):
            if entry.startswith('160000'):
                return 'a tracked path is an embedded repository (gitlink); its commits are not in this repository'
        for entry in _git_out(path, ['ls-files', '-v', '-z'], min(left(), 3.0)).split('\x00'):
            if entry and entry[0] != 'H':
                return 'a tracked file is marked assume-unchanged, skip-worktree or otherwise hidden from git status'
        ignored_ok, ignored_top_ok = set(cfg['ignored_ok']), set(cfg['ignored_top_ok'])
        status = _git_out(path, ['status', '--porcelain=v1', '-z', '--untracked-files=normal', '--ignored=traditional',
                                 '--no-renames'], min(left(), 3.0))
        for entry in filter(None, status.split('\x00')):
            if entry.startswith('!! '):
                name = entry[3:]
                leaf = name.rstrip('/').rsplit('/', 1)[-1]
                top = '/' not in name.rstrip('/')
                if not (name.endswith('/') and (leaf in ignored_ok or (top and leaf in ignored_top_ok))):
                    return 'it holds an ignored file or folder that is not a whole regenerable build directory'
                found = _nested_repo(os.path.join(path, name), deep=leaf not in ignored_ok)
                if found == 'large':
                    return 'an ignored build directory is too large to check for nested repositories in time'
                if found:
                    return 'an ignored build directory holds a nested repository'
            else:
                return 'the working tree is not clean (modified, staged or untracked files)'
        refs = {}
        for line in _git_out(path, ['for-each-ref', '--format=%(refname)%09%(objectname)'], min(left(), 2.0)).splitlines():
            name, _, sha = line.partition('\t')
            refs[name] = sha
        if 'refs/stash' in refs:
            return 'it has a stash'
        if any(r.startswith('refs/replace/') for r in refs):
            return 'it has replace refs'
        head = _git_out(path, ['rev-parse', '--verify', 'HEAD'], min(left(), 2.0)).strip()
        remotes = [r for r in _git_out(path, ['remote'], min(left(), 2.0)).split() if re.fullmatch(r'[\w.-]+', r)]
        if not remotes:
            return 'it has no remote'
        live_all = {}
        for remote in remotes:
            urls = _git_out(path, ['remote', 'get-url', '--all', remote], min(left(), 2.0)).split()
            hosts = [_remote_host(u) for u in urls]
            if not urls or any(h is None or h not in cfg['remote_hosts'] for h in hosts):
                return 'remote %s is not on a known hosting service (%s), so it is no proof of a backup' % (
                    remote[:30], ', '.join(cfg['remote_hosts'][:4]))
            live = REMOTE_LS(urls[0], path, min(left(), float(cfg['remote_seconds'])))
            if not live:
                return 'the remote did not answer (cannot prove the commits are pushed)'
            live_all[remote] = live
        verified = set()
        for name, sha in refs.items():
            if not name.startswith('refs/remotes/'):
                continue
            remote, _, branch = name[len('refs/remotes/'):].partition('/')
            live = live_all.get(remote)
            if live is None or not branch or branch == 'HEAD':
                continue
            if live.get('refs/heads/' + branch) == sha:
                verified.add(sha)
            elif 'refs/heads/' + branch in live:
                return 'the remote branch %s moved since the last fetch; run `git fetch` first so it can be verified' % branch[:40]
        for name, sha in refs.items():
            if name.startswith('refs/tags/') and any(v.get(name) == sha for v in live_all.values()):
                verified.add(sha)
        local = {sha for name, sha in refs.items() if not name.startswith('refs/remotes/')} | {head}
        for pointer in ('ORIG_HEAD', 'MERGE_HEAD', 'CHERRY_PICK_HEAD', 'REVERT_HEAD'):
            pfile = os.path.join(gitdir, pointer)
            if os.path.isfile(pfile):
                local |= set(re.findall(r'[0-9a-f]{40,64}', open(pfile, errors='replace').read(512)))
        local |= set(re.findall(r'[0-9a-f]{40,64}', _git_out(path, ['reflog', 'show', '--all', '--format=%H'], min(left(), 3.0))))
        if not verified:
            return 'no remote-tracking branch matches the remote'
        spec = '\n'.join(sorted(local)) + '\n--not\n' + '\n'.join(sorted(verified)) + '\n'
        unpushed = _git_out(path, ['rev-list', '--count', '--stdin'], min(left(), 3.0), stdin=spec).strip()
        if unpushed != '0':
            return '%s local commit(s) are not on the remote' % unpushed[:8]
        return None
    except Exception as error:  # noqa: BLE001 - any surprise means "not provably reproducible"
        return 'could not verify (%s)' % type(error).__name__


def linked_worktree_remove_refusal(path, cwd, policy=None, remote_ls=None):
    """None only for a clean, registered linked worktree whose exact HEAD is live on an allowlisted remote.

    This deliberately does not call reproducible_clone_refusal(): a linked worktree has a .git file, shares its
    common refs with the other worktrees, and must not inherit the full-clone requirement that no worktrees exist.
    Only the checkout being removed is judged; unrelated branches and other worktrees stay out of the decision.

    Known window (#134 red-team P6): this runs in the PreToolUse hook, before the command. A file that appears
    after this check and before `git worktree remove` runs is not seen here. That includes CONFIG files: a
    `config.worktree` written after the vetting is read by the real command, and in the hook form the user's command
    carries no `-c core.fsmonitor=false` (the delegated `ah worktree-remove` route does), so a program-valued key added in
    that window can run (goodqa#15741 tracks the wider hook-form environment gap). Git itself refuses a worktree with
    modified or untracked files, but it removes ignored files (for example a fresh `.env`) without `--force`.
    The guard cannot close that window. Callers must not remove a worktree that another process may still be
    writing to: stop its servers and agents first.
    """
    cfg = dict(DEFAULT_POLICY['reproducible_clone'], **((policy or {}).get('reproducible_clone') or {}))
    if not cfg.get('enabled'):
        return 'the exemption is switched off'
    started = time.monotonic()
    total = float(cfg['total_seconds'])
    scale = float(cfg.get('scale', 1.0))  # the delegated verifier sizes its budget for large worktrees

    def left():
        remaining = total - (time.monotonic() - started)
        if remaining <= 0.2:
            raise TimeoutError('time budget')
        return remaining

    def step(seconds):
        return min(left(), seconds * scale)

    try:
        if not path or '\x00' in path or not os.path.isabs(path):
            return 'not a literal absolute path'
        if os.path.normpath(path) != path or os.path.realpath(path) != path or os.path.islink(path) \
                or not os.path.isdir(path):
            return 'the path contains a symlink, dot segment or alias, or is not a plain directory'
        if not cwd or not os.path.isabs(cwd) or os.path.realpath(cwd) != cwd or not os.path.isdir(cwd):
            return 'the calling directory is not a real literal directory'
        marker = os.path.join(path, '.git')
        if os.path.islink(marker) or not os.path.isfile(marker):
            return '.git is not a plain file (not a linked worktree)'
        with open(marker, 'rb') as handle:
            raw_marker = handle.read(4097)
        if len(raw_marker) > 4096 or not raw_marker.startswith(b'gitdir: '):
            return 'the .git file is not an ordinary linked-worktree marker'
        try:
            linked_dir = os.path.realpath(raw_marker.decode('utf-8').strip()[len('gitdir: '):])
        except UnicodeError:
            return 'the .git file is not readable as a linked-worktree marker'
        top = os.path.realpath(_git_out(path, ['rev-parse', '--show-toplevel'], step(2.0)).strip())
        git_dir = os.path.realpath(_git_out(path, ['rev-parse', '--absolute-git-dir'], step(2.0)).strip())
        common = os.path.realpath(_git_out(path, ['rev-parse', '--git-common-dir'], step(2.0)).strip())
        if top != path or git_dir != linked_dir or not os.path.isdir(git_dir) or not os.path.isdir(common):
            return 'the path is not the exact top of its registered linked worktree'
        if os.path.dirname(git_dir) != os.path.join(common, 'worktrees'):
            return 'the .git file points outside the common worktree registry'
        try:
            current = os.path.realpath(_git_out(cwd, ['rev-parse', '--show-toplevel'], step(2.0)).strip())
        except ValueError:
            current = None  # the calling directory is not inside any repository (for example $HOME): it is not `path`
        if current == path:
            return 'the current worktree cannot remove itself'
        listing = _git_out(path, ['worktree', 'list', '--porcelain'], step(2.0))
        trees = [os.path.realpath(line[len('worktree '):]) for line in listing.splitlines()
                 if line.startswith('worktree ')]
        if len(trees) < 2 or trees[0] == path or trees.count(path) != 1:
            return 'the path is not a non-primary entry in the worktree registry'
        for other in trees:
            if other == path:
                continue
            if other.startswith(path + os.sep) or path.startswith(other + os.sep):
                return 'nested worktrees are not removable through this exemption'
        for forbidden, why in ((os.path.join(common, 'modules'), 'it has submodules'),
                               (os.path.join(common, 'info', 'grafts'), 'it has grafts'),
                               (os.path.join(common, 'refs', 'replace'), 'it has replace refs'),
                               (os.path.join(common, 'lfs'), 'it has a git LFS store')):
            if os.path.lexists(forbidden):
                return why
        if os.path.lexists(os.path.join(path, '.gitmodules')):
            return 'it has submodules'
        for attributes in (os.path.join(common, 'info', 'attributes'), os.path.join(git_dir, 'info', 'attributes')):
            if os.path.lexists(attributes):
                return 'local git attributes could hide changes or run filters'
        if os.path.getsize(os.path.join(common, 'config')) > 256 * 1024:
            return 'the repository config is unusually large'
        shared = _git_out(path, ['config', '--local', '-z', '--list'], step(2.0))
        bad = _config_refusal(shared, allow_worktree_config=True)
        if not bad and _worktree_config_enabled(shared):
            bad = _per_worktree_config_refusal(path, common, git_dir, cwd, step)
        if bad:
            return bad
        # A bare `git worktree remove` DOES run a hook (post-index-change, through the status it starts), so the hook form and
        # every other caller keep this rule. The delegated route is safe for two reasons: every git call carries
        # core.hooksPath=/dev/null and the sanitized environment sets GIT_OPTIONAL_LOCKS=0 (no index write, so no hook), and
        # config-defined hooks (git 2.54 reads hook.NAME.event and .command; hooksPath does not switch them off) are stopped by
        # the [hook] section refusal in _config_refusal. Only that route (policy allow_hooks exactly True) skips this rule.
        hooks_dir = os.path.join(common, 'hooks')
        if cfg.get('allow_hooks') is not True and os.path.isdir(hooks_dir) \
                and any(not n.endswith('.sample') for n in os.listdir(hooks_dir)):
            return 'it has hand-written git hooks'
        for entry in _git_out(path, ['ls-files', '-s', '-z'], step(3.0)).split('\x00'):
            if entry.startswith('160000'):
                return 'a tracked path is an embedded repository (gitlink); its commits are not in this repository'
        for entry in _git_out(path, ['ls-files', '-v', '-z'], step(3.0)).split('\x00'):
            if entry and entry[0] != 'H':
                return 'a tracked file is marked assume-unchanged, skip-worktree or otherwise hidden from git status'
        ignored_ok, ignored_top_ok = set(cfg['ignored_ok']), set(cfg['ignored_top_ok'])
        status = _git_out(path, ['status', '--porcelain=v1', '-z', '--untracked-files=normal', '--ignored=traditional',
                                 '--no-renames'], step(3.0))
        for entry in filter(None, status.split('\x00')):
            if entry.startswith('!! '):
                name = entry[3:]
                leaf = name.rstrip('/').rsplit('/', 1)[-1]
                top_ignored = '/' not in name.rstrip('/')
                if not (name.endswith('/') and (leaf in ignored_ok or (top_ignored and leaf in ignored_top_ok))):
                    return 'it holds an ignored file or folder that is not a whole regenerable build directory'
                found = _nested_repo(os.path.join(path, name), limit=int(250000 * scale), deep=leaf not in ignored_ok,
                                     seconds=max(0.2, min(left(), 1.5 * scale)))  # inside the budget that is left
                if found == 'large':
                    return 'an ignored build directory is too large to check for nested repositories in time'
                if found:
                    return 'an ignored build directory holds a nested repository'
            else:
                return 'the working tree is not clean (modified, staged or untracked files)'
        head = _git_out(path, ['rev-parse', '--verify', 'HEAD'], step(2.0)).strip()
        if not re.fullmatch(r'[0-9a-f]{40,64}', head):
            return 'the worktree has no exact commit HEAD'
        refs = {}
        for line in _git_out(path, ['for-each-ref', '--format=%(refname)%09%(objectname)'],
                             step(2.0)).splitlines():
            name, _, sha = line.partition('\t')
            refs[name] = sha
        if any(name.startswith('refs/replace/') for name in refs):
            return 'it has replace refs'
        remotes = _git_out(path, ['remote'], step(2.0)).splitlines()
        if not remotes or any(not re.fullmatch(r'[\w.-]+', remote) for remote in remotes):
            return 'it has no safely named remote'
        live_all = {}
        for remote in remotes:
            urls = _git_out(path, ['remote', 'get-url', '--all', remote], step(2.0)).split()
            hosts = [_remote_host(url) for url in urls]
            if not urls or any(host is None or host not in cfg['remote_hosts'] for host in hosts):
                return 'remote %s is not on a known hosting service' % remote[:30]
            try:
                live = (remote_ls or REMOTE_LS)(urls[0], path, min(left(), float(cfg['remote_seconds'])))
            except ValueError:  # the guard's ls-remote runs without credentials: a private repository is not readable
                live = None
            if not live:
                return 'the remote did not answer (private, unreachable or deleted: cannot prove the exact HEAD is published)'
            live_all[remote] = live
        # goodqa#15334: after a merge and branch cleanup the commit is published through the remote's default branch even
        # though no live branch points at it. The live default sha is the tip the remote reports now; a commit counts as
        # published when it is an ancestor of that tip, which needs the tip's objects locally (else it is not proven).
        defaults = []
        for remote, live in live_all.items():
            names = []
            try:
                target = _git_out(path, ['symbolic-ref', '-q', 'refs/remotes/%s/HEAD' % remote], step(2.0)).strip()
                if target.startswith('refs/remotes/%s/' % remote):
                    names.append(target[len('refs/remotes/%s/' % remote):])
            except ValueError:
                pass
            names += ['main', 'master']
            for name in names:
                if re.fullmatch(r'[\w./-]{1,100}', name) and live.get('refs/heads/' + name):
                    defaults.append(live['refs/heads/' + name])
                    break

        def merged(sha):
            for tip in defaults:
                try:
                    _git_out(path, ['merge-base', '--is-ancestor', sha, tip], step(2.0))
                    return True
                except ValueError:
                    continue
            return False
        for name, sha in refs.items():
            if not name.startswith('refs/remotes/'):
                continue
            remote, _, branch = name[len('refs/remotes/'):].partition('/')
            if not branch or branch == 'HEAD' or remote not in live_all:
                continue
            if live_all[remote].get('refs/heads/' + branch) != sha and not merged(sha):
                return 'a remote-tracking ref is stale or names a moved/deleted remote branch; fetch --prune first'
        if not any(head in live.values() for live in live_all.values()) and not merged(head):
            return 'the exact HEAD is not present on a live allowlisted remote (unpublished or detached-unpublished)'
        # Removing the worktree deletes its own admin directory: the HEAD reflog and refs/worktree, refs/bisect and
        # refs/rewritten live there. A commit reachable only from those would be lost (red-team F1), so it must be
        # published, or kept by a shared branch, tag or remote-tracking ref.
        if _git_out(path, ['for-each-ref', '--count=1', 'refs/worktree', 'refs/bisect', 'refs/rewritten'],
                    step(2.0)).strip():
            return 'the worktree holds private refs (refs/worktree, refs/bisect or refs/rewritten)'
        entries = [e for e in _git_out(path, ['reflog', 'show', '--format=%H', 'HEAD'], step(3.0)).split() if e]
        if len(entries) > 300:
            return 'the worktree HEAD reflog is too long to check'
        live_shas = {sha for live in live_all.values() for sha in live.values()}
        for sha in dict.fromkeys(entries):
            if not re.fullmatch(r'[0-9a-f]{40,64}', sha) or sha in live_shas or merged(sha):
                continue
            if _git_out(path, ['for-each-ref', '--count=1', '--contains', sha, 'refs/heads', 'refs/tags', 'refs/remotes'],
                        step(3.0)).strip():
                continue
            return 'a commit only this worktree HEAD reflog reaches would be lost with the worktree'
        return None
    except Exception as error:  # noqa: BLE001 - every surprise keeps the ordinary refusal
        return 'could not verify (%s)' % type(error).__name__


WORKTREE_HOME_DENY = ('.claude', '.codex', '.ssh', '.config', '.gnupg', '.aws', '.kimi-code', 'library', '.trash')
VERIFIER_VERSION = 2  # `ah worktree-remove` refuses a verifier that does not report this (an old install on the target)
GITHUB_REMOTE = re.compile(r'(?:https://github\.com/[\w.-]+/[\w.-]+?(?:\.git)?|git@github\.com:[\w.-]+/[\w.-]+?(?:\.git)?)')


def worktree_scope_refusal(path):
    """Where `ah worktree-remove` may act: strictly under the caller's home, never the home itself, never the harness
    or credential state, and under ~/.agent-harness only inside work/. Names are compared case-folded (APFS is case
    insensitive)."""
    home = os.path.realpath(os.path.expanduser('~'))
    if not path.casefold().startswith(home.casefold() + os.sep):
        return 'the path is outside the home directory'
    parts = path[len(home) + 1:].split(os.sep)
    if parts[0].casefold() in WORKTREE_HOME_DENY:
        return 'the path is inside protected state (%s)' % parts[0][:30]
    if parts[0].casefold() == '.agent-harness' and (len(parts) < 3 or parts[1].casefold() != 'work'):
        return 'under ~/.agent-harness only a worktree inside work/ is removable'
    return None


def _primary_and_urls(path):
    """(primary worktree path, {remote: [urls]}) read-only, for the report."""
    listing = _git_out(path, ['worktree', 'list', '--porcelain'], 2.0)
    primary = next((os.path.realpath(line[len('worktree '):]) for line in listing.splitlines()
                    if line.startswith('worktree ')), None)
    urls = {}
    for remote in _git_out(path, ['remote'], 2.0).splitlines():
        if re.fullmatch(r'[\w.-]+', remote):
            urls[remote] = _git_out(path, ['remote', 'get-url', '--all', remote], 2.0).split()
    return primary, urls


def _authenticated_env():
    """The only environment the credentialed ls-remote sees: no GIT_* variable, no global or system git config (so no
    url.insteadOf rewrite, helper or ssh command can redirect it), the caller's agent socket and home for credentials."""
    env = {'HOME': os.path.expanduser('~'), 'GIT_TERMINAL_PROMPT': '0', 'GIT_CONFIG_GLOBAL': '/dev/null',
           'GIT_CONFIG_NOSYSTEM': '1', 'GIT_ASKPASS': '/bin/true', 'LC_ALL': 'C',
           'PATH': os.pathsep.join(q for q in os.environ.get('PATH', '').split(os.pathsep) if q.startswith('/'))
           or '/usr/bin:/bin'}
    if os.environ.get('SSH_AUTH_SOCK'):
        env['SSH_AUTH_SOCK'] = os.environ['SSH_AUTH_SOCK']
    return env


def authenticated_remote_refs(url, repo, timeout):
    """ref -> sha like _live_remote_refs, but read with this host's own credentials (a private repository). The caller
    cannot supply the refs: only the real remote's answer counts. Only a github.com URL; cwd is `/`, the environment is
    _authenticated_env(), and the credential helper is gh's, named explicitly."""
    if not isinstance(url, str) or not GITHUB_REMOTE.fullmatch(url):
        raise ValueError('not a github.com remote')
    gh = shutil.which('gh', path=_authenticated_env()['PATH'])
    command = ['git', '-c', 'core.hooksPath=/dev/null', '-c', 'protocol.allow=never', '-c', 'protocol.https.allow=always',
               '-c', 'protocol.ssh.allow=always']
    if gh:
        command += ['-c', 'credential.helper=', '-c', 'credential.helper=!%s auth git-credential' % shlex.quote(gh)]
    done = subprocess.run(command + ['ls-remote', '--heads', '--tags', '--', url], capture_output=True, cwd=os.sep,
                          timeout=max(0.2, timeout), env=_authenticated_env())
    if done.returncode != 0 or len(done.stdout) > 8 * 1024 * 1024:
        raise ValueError('git ls-remote failed')
    refs = {}
    for line in done.stdout.decode('utf-8', 'surrogateescape').splitlines():
        sha, _, ref = line.partition('\t')
        if re.fullmatch(r'[0-9a-f]{40,64}', sha) and ref and not ref.endswith('^{}'):
            refs[ref] = sha
    return refs


def _proc_status(pid):
    """{'name': Name, 'uid': real uid, 'ppid': parent pid} from /proc/PID/status, which any user can read whatever the process set about
    being inspected; 'gone' when the process has exited; None when it cannot be read or parsed. The real uid is used, not
    the owner of /proc/PID: a same-user process that made itself non-dumpable shows /proc/PID owned by root, and the
    owner would call it another user's (red-team F4)."""
    try:
        name = uid = ppid = None
        with open('/proc/%s/status' % pid) as handle:
            for line in handle:
                if line.startswith('Name:'):
                    name = line.partition(':')[2].strip()
                elif line.startswith('Uid:'):
                    uid = int(line.partition(':')[2].split()[0])
                elif line.startswith('PPid:'):
                    ppid = int(line.partition(':')[2].split()[0])
        return {'name': name, 'uid': uid, 'ppid': ppid} if uid is not None else None
    except (FileNotFoundError, ProcessLookupError):
        return 'gone'
    except (OSError, ValueError, IndexError):
        return None


def _proc_cmd0(pid):
    """The basename of argv[0] from /proc/PID/cmdline (world readable), or None when it cannot be read or is empty."""
    try:
        with open('/proc/%s/cmdline' % pid, 'rb') as handle:
            first = handle.read(4096).split(b'\x00')[0]
    except OSError:
        return None
    return os.path.basename(first.decode('utf-8', 'replace')) or None


def busy_scan(path, skip_names=()):
    """Scan the processes for one whose working directory is the worktree or inside it. Returns {'busy': [(pid, command)],
    'unreadable': [(pid, name)], 'failed': bool}: `unreadable` lists processes of THIS user whose cwd link cannot be read
    and that are not on the service list (a shell run through sg or sudo, a setgid helper), `failed` is set when the scan
    could not be completed at all (fail closed). A process that has exited (ENOENT, ESRCH) is skipped, and so is one that
    cannot be read because its REAL uid (from the world-readable /proc/PID/status) is another user's (a Linux host has
    root daemons whose /proc/PID/cwd a normal user cannot read; goodqa#15739); a same-user unreadable process is skipped
    only by exact Name in `skip_names`. Limits, stated: other users' processes are invisible without root, and open files
    other than the working directory are not checked; plain `git worktree remove` also deletes ignored files."""
    result = {'busy': [], 'unreadable': [], 'failed': False}
    try:
        if os.path.isdir('/proc/self'):
            for entry in os.listdir('/proc'):
                if entry.isdigit() and int(entry) != os.getpid():
                    try:
                        cwd = os.readlink('/proc/%s/cwd' % entry)
                    except OSError as error:
                        if error.errno in (errno.ENOENT, errno.ESRCH):
                            continue  # exited while we looked
                        if error.errno not in (errno.EACCES, errno.EPERM):
                            result['failed'] = True  # any other error: a process we could not see
                            return result
                        status = _proc_status(entry)
                        if status == 'gone':
                            continue  # exited between the two reads
                        if status is None:
                            result['failed'] = True  # an identity we cannot determine is a process we could not see
                            return result
                        if status['uid'] != os.getuid():
                            # Another user's process is invisible without root (the documented limit). A process whose real uid
                            # is 0 and whose parent is a process of THIS user (sudo -s, sudo -i run from the callers shell) is
                            # the caller's own work, not a daemon: it is listed and refuses. A boot-time root daemon (parent
                            # root or init) and a kernel thread (parent 0 or 2) are skipped; a parent that cannot be read
                            # does not make a root process skippable.
                            if status['uid'] == 0 and status.get('ppid') not in (0, 2):
                                parent = _proc_status(str(status.get('ppid')))
                                if not isinstance(parent, dict) or parent['uid'] == os.getuid():
                                    result['unreadable'].append((int(entry), status['name'] or '?'))
                            continue
                        # A same-user process whose cwd link is unreadable is skipped only for the few programs that are known
                        # to change to / when they start (the user systemd manager, ssh-agent): the process Name must be on the
                        # policy list AND the command line (argv[0] basename) must agree. comm can be set by the process itself
                        # (prctl PR_SET_NAME, exec -a) and so can argv[0]: this protects against accident, not against a
                        # hostile same-user process; it is a standing limit, not a control. Anything else (a shell run through
                        # sg, the docker client, a helper, any other name, an unreadable command line) is reported and refuses.
                        if skip_names and status['name'] in skip_names and _proc_cmd0(entry) == status['name']:
                            continue
                        result['unreadable'].append((int(entry), status['name'] or '?'))
                        continue
                    if cwd == path or cwd.startswith(path + os.sep):
                        result['busy'].append((int(entry), 'pid'))
            return result
        done = subprocess.run(['lsof', '-a', '-d', 'cwd', '-F', 'pcn'], capture_output=True, text=True, timeout=20,
                              env={'PATH': '/usr/sbin:/usr/bin:/bin', 'LC_ALL': 'C'}, cwd=os.sep)
        if done.returncode not in (0, 1) or (done.returncode == 1 and (done.stderr or '').strip()):
            result['failed'] = True  # exit 1 is "nothing found" only when lsof said nothing else
            return result
        pid = command = None
        for line in done.stdout.splitlines():
            if line.startswith('p') and line[1:].isdigit():
                pid, command = int(line[1:]), ''
            elif line.startswith('c'):
                command = line[1:40]
            elif line.startswith('n') and pid != os.getpid():
                name = os.path.realpath(line[1:]) if line[1:].startswith('/') else line[1:]
                if name == path or name.startswith(path + os.sep):
                    result['busy'].append((pid, command))
        return result
    except (OSError, subprocess.SubprocessError, ValueError):
        result['failed'] = True
        return result


def busy_processes(path, skip_names=()):
    """[(pid, command)] of processes working inside the worktree, or None when the scan cannot be trusted to be complete
    (it failed, or a process of this user could not be inspected): fail closed. See busy_scan for the details."""
    scan = busy_scan(path, skip_names)
    if scan['failed'] or scan['unreadable']:
        return None
    return scan['busy']


def registry_lists(repo, path):
    """Whether `git worktree list --porcelain` run in `repo` names exactly `path` (compared line by line, not as a
    substring: /x/wt-1 is not /x/wt-10). Raises on a git failure."""
    listing = _git_out(repo, ['worktree', 'list', '--porcelain'], 10.0)
    return any(os.path.realpath(line[len('worktree '):]) == path for line in listing.splitlines()
               if line.startswith('worktree '))


# The delegated verifier is not the hook: its budget is sized for the large worktrees it exists for. The whole call is
# bounded by VERIFY_SECONDS (every git step by its own cap times the scale), the removal by REMOVE_SECONDS, and `ah`
# allows their sum plus the process scan and the ssh connect (ah_worktree.CALL_TIMEOUT).
VERIFY_SECONDS = 120.0
REMOVE_SECONDS = 900
WORKTREE_POLICY = {'reproducible_clone': {'total_seconds': VERIFY_SECONDS, 'remote_seconds': 30.0, 'scale': 15.0,
                                         'allow_hooks': True,
                                         'busy_skip_names': ('systemd', 'ssh-agent')}}


def delegated_policy(base=None):
    """The user policy (when given) with the delegated route's own rules laid over its reproducible_clone section: the
    scaled budget and allow_hooks. The route always applies them, whatever the caller loaded (the real t2-dev proof showed
    the command line passed the loaded user policy straight down, so the delegated rules were never in force); a policy
    can still switch the exemption off with enabled false when it is passed in by code (a policy FILE cannot: load_policy
    ignores the reproducible_clone section of a file)."""
    base = base if isinstance(base, dict) else {}
    section = base.get('reproducible_clone')
    merged = dict(section) if isinstance(section, dict) else {}
    merged.update(WORKTREE_POLICY['reproducible_clone'])
    return dict(base, reproducible_clone=merged)


def verify_worktree(path, authenticated=False, policy=None):
    """Read-only verdict as a dict {removable, reason, head, repo, urls, verifier}. `authenticated` reads the remote with
    this host's own credentials (authenticated_remote_refs) instead of the guard's anonymous ls-remote."""
    report = {'path': path, 'removable': False, 'reason': None, 'head': None, 'repo': None, 'urls': {},
              'verifier': VERIFIER_VERSION}
    reason = worktree_scope_refusal(path) if isinstance(path, str) and os.path.isabs(path) else 'not a literal absolute path'
    if reason is None:
        effective = delegated_policy(policy)
        reason = linked_worktree_remove_refusal(path, os.sep, effective,
                                                remote_ls=authenticated_remote_refs if authenticated else None)
        try:
            report['head'] = _git_out(path, ['rev-parse', '--verify', 'HEAD'], 2.0).strip()
            report['repo'], report['urls'] = _primary_and_urls(path)
        except (ValueError, OSError, subprocess.SubprocessError):
            pass
    if reason is None:
        scan = busy_scan(path, tuple(delegated_policy(policy)['reproducible_clone'].get('busy_skip_names') or ()))
        if scan['busy']:
            reason = 'a process is using the worktree as its working directory (pid %d, %s)' % scan['busy'][0]
        elif scan['failed']:
            reason = 'could not check for processes using the worktree'
        elif scan['unreadable']:
            named = ', '.join('pid %d (%s)' % (pid, re.sub(r'[^A-Za-z0-9_.()-]', '?', name)[:20])
                              for pid, name in scan['unreadable'][:3])
            more = len(scan['unreadable']) - 3
            reason = ('could not check for processes using the worktree: %d process(es) of this user cannot be inspected '
                      '(%s%s); let them end, then retry' % (len(scan['unreadable']), named,
                                                            ' and %d more' % more if more > 0 else ''))
    report['reason'] = reason
    report['removable'] = reason is None and bool(report['repo']) and bool(report['head'])
    return report


def _worktree_audit(record):
    """One row in the target host's own ~/.agent-harness/worktree-audit.jsonl; never raises."""
    try:
        folder = os.path.join(os.path.expanduser('~'), '.agent-harness')
        os.makedirs(folder, mode=0o700, exist_ok=True)
        record = dict(record, at=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), by='command_guard')
        fd = os.open(os.path.join(folder, 'worktree-audit.jsonl'),
                     os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            os.write(fd, (json.dumps(record, separators=(',', ':')) + '\n').encode())
        finally:
            os.close(fd)
    except (OSError, TypeError, ValueError):
        pass


def remove_worktree(path, authenticated=False, expect_head=None, policy=None):
    """Verify, then run the plain non-forced `git worktree remove` from the primary worktree. The directory identity is
    compared before and after the verification, and an expected HEAD must still match. Every attempt that reaches the
    removal is audited on this host (the audit of `ah` lives on the caller's host)."""
    try:
        before = os.lstat(path)
    except OSError as error:
        return {'path': path, 'removable': False, 'removed': False, 'verifier': VERIFIER_VERSION,
                'reason': 'cannot stat the path (%s)' % type(error).__name__}
    report = verify_worktree(path, authenticated, policy)
    report['removed'] = False
    if not report['removable']:
        return report
    try:
        after = os.lstat(path)
    except OSError:
        after = None
    if after is None or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
        report.update(removable=False, reason='the path changed while it was verified')
        return report
    if expect_head and report['head'] != expect_head:
        report.update(removable=False, reason='HEAD moved since it was verified')
        return report
    home = os.path.realpath(os.path.expanduser('~'))
    try:
        free_before = shutil.disk_usage(home).free
    except OSError:
        free_before = None
    _worktree_audit({'event': 'remove', 'path': path, 'head': report['head'], 'repo': report['repo']})
    problem = None
    try:
        done = subprocess.run(['git', '-c', 'core.hooksPath=/dev/null', '-c', 'core.fsmonitor=false', '-C', report['repo'],
                               'worktree', 'remove', '--', path],
                              capture_output=True, text=True, timeout=REMOVE_SECONDS, env=_clone_env())
        returned, stderr = done.returncode, (done.stderr or '').strip()[:200]
    except (subprocess.SubprocessError, OSError, ValueError) as error:
        # git may have been killed partway through deleting: the report must say what is left, never nothing
        returned, stderr, problem = None, '', type(error).__name__
    finally:
        # What is on disk now, whatever happened above. The audit row is written from here, never skipped.
        gone = not os.path.lexists(path)
        try:
            listed = registry_lists(report['repo'], path) if os.path.isdir(report['repo']) else False
        except (ValueError, OSError, subprocess.SubprocessError):
            listed = None  # unknown: reported as such
        report['directory_removed'] = gone
        report['registry_entry_left'] = listed
        try:
            report['freed_bytes'] = (max(0, shutil.disk_usage(home).free - free_before)
                                     if free_before is not None else None)
        except OSError:
            report['freed_bytes'] = None
        report['removed'] = returned == 0 and gone and listed is False
        if not report['removed']:
            report['reason'] = ('git worktree remove did not complete cleanly (%s; directory %s, registry entry %s): %s' % (
                problem or 'exit %s' % returned, 'gone' if gone else 'still there',
                {True: 'left', False: 'gone', None: 'unknown'}[listed], stderr)).strip()
        _worktree_audit({'event': 'result', 'path': path, 'removed': report['removed'], 'directory_removed': gone,
                         'registry_entry_left': listed, 'problem': problem})
    return report


def _clean_reason(reason):
    """A verifier reason made safe to print: printable ASCII only, 160 characters, no path."""
    return re.sub(r'[^\x20-\x7e]', '?', str(reason))[:160]


def _worktree_instead(reason):
    """The advice for a refused `git worktree remove`: the verifier's reason, its next step, and the delegated route
    (ah worktree-remove runs the full verifier, on this Mac or t2-dev). None when no reason is known."""
    if not reason:
        return None
    return ('verifier: %s. %s%s' % (_clean_reason(reason), (_worktree_next_step(reason) or '') + '; or ' if
                                    _worktree_next_step(reason) else '',
                                    'python3 -I ~/.claude/hooks/ah.py worktree-remove --host local|t2-dev --path <abs path> '
                                    '--reason <why> (no --force; audited)'))


def _worktree_next_step(reason):
    """What to do about a verifier reason (None when there is nothing specific to say). Never advises discarding work."""
    reason = str(reason or '')
    if 'stale or names a moved' in reason:
        return 'run git fetch --prune <remote> in the repository, then repeat the removal'
    if 'did not answer' in reason:
        return ('the guard reads the remote without credentials; for a private repository use '
                'python3 -I ~/.claude/hooks/ah.py worktree-remove --host local --path <abs path> --reason <why> '
                '--remote-auth')
    if 'not clean' in reason or 'ignored' in reason:
        return ('if the worktree is yours, commit and push what you need and move out any ignored files you want to keep; '
                'if it belongs to another owner, leave it')
    if 'not present on a live' in reason or 'unpublished' in reason:
        return 'push the worktree HEAD to its remote, then repeat the removal'
    if 'process is using' in reason:
        return 'stop the process that works in the worktree first'
    return None


def classify_segs(c, segs):
    """'log' (Tier A), 'root' (Tier B), 'ancestor' (contains a protected root) or None, for case-folded segments."""
    for r in c.protected:
        if _prefix_match(segs, r):
            return 'log' if len(segs) >= len(r) else 'ancestor'
    leaf = segs[-1] if segs else ''
    in_root = None
    for r in c.roots:
        if _prefix_match(segs, r):
            in_root = 'root' if len(segs) >= len(r) else 'ancestor'
            break
    in_temp = not in_root and any(len(segs) > len(t) and segs[:len(t)] == t for t in c.temp_roots)
    if not in_temp and (any(s in c.seg_names for s in segs)
                        or (leaf and (leaf in c.file_names or leaf.endswith(c.file_suffixes)))):
        return 'log' if in_root else 'log-name'
    if in_root == 'root':
        # inside a harness tree a glob that can reach a WAL name counts as a WAL path
        for s in segs:
            if _has_glob(s) and any(_fnmatchcase(n, s) for n in c.seg_names | c.file_names):
                return 'log'
        if _has_glob(leaf) and any(_fnmatchcase('x' + suf, leaf) for suf in c.file_suffixes):
            return 'log'
        if leaf in c.keep_names or leaf.endswith(c.keep_suffixes) or any(x in c.keep_segments for x in segs):
            return 'root'
        if leaf.endswith(('.output', '.log')) or 'tasks' in segs[len(r):]:
            return 'root'  # agent task output and logs: never deleted without a verified backup
        for a in c.allow:
            if len(segs) >= len(a) and all(
                    (segs[k] == a[k]) or (a[k] == '*' and not _has_glob(segs[k])) for k in range(len(a))):
                return None
    if in_root:
        return in_root
    for a in c.ancestors:
        if _prefix_match(segs, a) and len(segs) <= len(a):
            return 'ancestor'
    return None


def is_dynamic_path(text):
    return '$' in text or SUB_MARK in text or ARITH_MARK in text or '`' in text


def _glob_to_segments(path):
    return [s for s in path.split('/') if s]


def seg_match(pattern_segs, concrete_segs):
    """Pattern (may have globs) vs concrete path segments, over the shorter length: True if one reaches the other."""
    n = min(len(pattern_segs), len(concrete_segs))
    for k in range(n):
        if not _fnmatchcase(concrete_segs[k], pattern_segs[k]):
            return False
    return True


# --------------------------------------------------------------------------- findings

class Finding:
    def __init__(self, category, rule, reason, alternative):
        self.category, self.rule, self.reason, self.alternative = category, rule, reason, alternative


NONPRINT_SINKS = {'wc', 'shasum', 'sha1sum', 'sha256sum', 'sha512sum', 'md5sum', 'md5', 'cksum', 'b2sum', 'pbcopy',
                  'xclip', 'xsel', 'wl-copy', 'true', 'false', 'test', '[', 'clip', 'set-clipboard'}
PASS_FILTERS = {'cat', 'tee', 'sed', 'awk', 'gawk', 'mawk', 'cut', 'tr', 'head', 'tail', 'sort', 'uniq', 'base64', 'xxd',
                'od', 'rev', 'fold', 'paste', 'nl', 'tac', 'less', 'more', 'jq', 'column', 'fmt', 'pr', 'strings',
                'hexdump', 'bat', 'batcat', 'grep', 'egrep', 'fgrep', 'rg', 'select-string', 'sls', 'out-string',
                'out-host', 'foreach-object', 'write-output', 'sort-object'}
PRINT_FILE_CMDS = {'cat', 'head', 'tail', 'less', 'more', 'most', 'bat', 'batcat', 'nl', 'tac', 'od', 'xxd', 'hexdump',
                   'hd', 'strings', 'base64', 'base32', 'uuencode', 'awk', 'gawk', 'mawk', 'sed', 'cut', 'paste', 'sort',
                   'uniq', 'fold', 'fmt', 'rev', 'diff', 'colordiff', 'comm', 'vi', 'vim', 'view', 'nano', 'pico',
                   'emacs', 'pr', 'column', 'jq', 'yq', 'tee', 'type', 'get-content', 'gc', 'select-string', 'sls',
                   'openssl', 'cmp', 'xargs-cat', 'highlight', 'ccat', 'pygmentize', 'tr', 'look', 'expand', 'unexpand',
                   'split', 'csplit', 'tar', 'zip', 'gzip', 'bzip2', 'xz', 'zstd', 'lz4', '7z', 'zcat', 'cpio'}
GREP_CMDS = {'grep', 'egrep', 'fgrep', 'rg', 'ag', 'ack', 'zgrep', 'select-string', 'sls', 'pt'}
EXFIL_CMDS = {'curl', 'wget', 'scp', 'sftp', 'nc', 'ncat', 'netcat', 'socat', 'rsync', 'http', 'https', 'xh', 'telnet'}
ECHO_CMDS = {'echo', 'printf', 'print', 'write-output', 'write-host', 'out-host', 'out-string', 'say', 'logger',
             'osascript', 'notify-send'}
SHELLS = {'sh', 'bash', 'zsh', 'dash', 'ksh', 'ash', 'fish', 'csh', 'tcsh', 'busybox', 'mksh'}
PS_SHELLS = {'pwsh', 'powershell'}
INTERPRETERS = {'python', 'python3', 'python2', 'node', 'nodejs', 'perl', 'ruby', 'php', 'deno', 'bun', 'lua', 'rscript',
                'osascript', 'pypy', 'pypy3', 'tclsh', 'awk-script'}
WRAPPER_VALUE_OPTS = {'nice': ('-n', '--adjustment'), 'ionice': ('-c', '-n', '-p', '-t'), 'chrt': ('-p',),
                      'stdbuf': ('-i', '-o', '-e'), 'caffeinate': ('-t', '-w'), 'watch': ('-n', '-d', '--interval'),
                      'strace': ('-o', '-e', '-p', '-s', '-u'), 'ltrace': ('-o', '-e', '-p', '-s', '-u'),
                      'runuser': ('-u', '-g', '-G'), 'su': ('-s', '-g', '-G'), 'sg': (), 'setsid': (),
                      'nsenter': ('-t', '--target'), 'firejail': ('--profile',), 'sandbox-exec': ('-f', '-p', '-n'),
                      'start-process': ('-FilePath', '-ArgumentList'), 'unbuffer': (), 'time': ('-o', '-f')}
WRAPPERS_SIMPLE = {'command', 'builtin', 'exec', 'nohup', 'time', 'nice', 'ionice', 'setsid', 'stdbuf', 'caffeinate',
                   'noglob', 'unbuffer', 'chrt', 'taskset', 'doas', 'sudo', 'env', 'xargs', 'timeout', 'watch', 'gosu',
                   'chroot', 'runuser', 'strace', 'ltrace', 'script', 'dtruss', 'arch', 'nsenter', 'firejail', 'sandbox-exec',
                   'start-process', 'invoke-expression', 'iex', 'invoke-command', 'icm', 'call', 'start'}
RM_CMDS = {'rm', 'unlink', 'rmdir', 'shred', 'srm', 'trash', 'trash-put', 'remove-item', 'ri', 'del', 'erase', 'rd',
           'rimraf', 'gio-trash'}
MV_CMDS = {'mv', 'move-item', 'mi', 'move', 'rename-item', 'ren', 'rni'}
OVERWRITE_CMDS = {'tee', 'set-content', 'out-file', 'sc', 'clear-content', 'clc', 'truncate', 'dd', 'cp', 'copy-item',
                  'cpi', 'copy', 'install', 'ln', 'rsync'}
KILLERS = {'pkill', 'killall', 'kill', 'taskkill', 'stop-process', 'spps', 'pgrep', 'skill', 'killall5'}
READ_ONLY_ENV_NAMES = set()
PS_ALIASES = {'gc': 'cat', 'get-content': 'cat', 'type': 'cat', 'cat': 'cat', 'sls': 'grep', 'select-string': 'grep',
              'gci': 'ls', 'dir': 'ls', 'get-childitem': 'ls', 'ls': 'ls'}


def _flag_letters(args):
    """Letters of all single-dash short-option clusters (not --long)."""
    letters = set()
    for a in args:
        t = a.text
        if len(t) > 1 and t[0] == '-' and t[1] != '-':
            letters.update(t[1:])
    return letters


def _longs(args):
    return {a.text.split('=')[0] for a in args if a.text.startswith('--')}


def _nondash(args):
    out = []
    after_dd = False
    for a in args:
        t = a.text
        if after_dd or not t.startswith('-') or t == '-':
            out.append(a)
        elif t == '--':
            after_dd = True
    return out


def _is_subseq(required, tokens):
    it = iter(tokens)
    return all(any(r == t for t in it) for r in required)


SECRET_CLIS = [
    ('aws', ('secretsmanager', 'get-secret-value'), None, 'aws secretsmanager describe-secret (metadata only)'),
    ('aws', ('ssm', 'get-parameter'), r'with-decryption', 'aws ssm describe-parameters (names only)'),
    ('aws', ('ssm', 'get-parameters'), r'with-decryption', 'aws ssm describe-parameters (names only)'),
    ('aws', ('ssm', 'get-parameters-by-path'), r'with-decryption', 'aws ssm describe-parameters (names only)'),
    ('aws', ('configure', 'get'), r'secret|access_key|session_token', 'aws sts get-caller-identity'),
    ('aws', ('ecr', 'get-login-password'), None, 'pipe it straight into docker login --password-stdin'),
    ('gh', ('auth', 'token'), None, 'gh auth status (shows login, never the token)'),
    ('gh', ('config', 'get'), r'oauth_token|token', 'gh auth status'),
    ('kubectl', ('config', 'view'), r'--raw|--flatten', 'kubectl config view (redacted by default)'),
    ('aws', ('configure', 'export-credentials'), None, 'aws sts get-caller-identity'),
    ('gh', ('auth', 'status'), r'(?:^| )(?:-t|--show-token)(?: |$)', 'gh auth status without --show-token'),
    ('gcloud', ('secrets', 'versions', 'access'), None, 'gcloud secrets versions list / describe (metadata only)'),
    ('gcloud', ('print-access-token',), None, 'let the tool call gcloud itself; never print the token'),
    ('gcloud', ('print-identity-token',), None, 'let the tool call gcloud itself; never print the token'),
    ('vault', ('kv', 'get'), None, 'vault kv metadata get (no values)'),
    ('vault', ('read',), None, 'vault kv metadata get (no values)'),
    ('az', ('keyvault', 'secret', 'show'), None, 'az keyvault secret list (names only)'),
    ('az', ('account', 'get-access-token'), None, 'let the tool call az itself; never print the token'),
    ('kubectl', ('get', 'secret'), r'-o ?(?:yaml|json|jsonpath|go-template)|--output', 'kubectl get secret (names only)'),
    ('kubectl', ('get', 'secrets'), r'-o ?(?:yaml|json|jsonpath|go-template)|--output', 'kubectl get secrets (names only)'),
    ('op', ('read',), None, 'op run -- <command> (secrets only in that command environment)'),
    ('op', ('item', 'get'), r'reveal|fields|format', 'op item get (without --reveal)'),
    ('pass', ('show',), None, 'pass ls (names only)'),
    ('lpass', ('show',), None, 'lpass ls (names only)'),
    ('bw', ('get', 'password'), None, 'bw list items --search NAME (no secrets)'),
    ('bw', ('get', 'item'), None, 'bw list items --search NAME (no secrets)'),
    ('bw', ('get', 'totp'), None, 'bw list items --search NAME (no secrets)'),
    ('heroku', ('auth:token',), None, 'heroku auth:whoami'),
    ('fly', ('auth', 'token'), None, 'fly auth whoami'),
    ('flyctl', ('auth', 'token'), None, 'fly auth whoami'),
    ('doppler', ('secrets', 'get'), None, 'doppler secrets --only-names'),
    ('doppler', ('secrets', 'download'), None, 'doppler run -- <command>'),
    ('sops', (), r'(?:^| )(?:-d|--decrypt)(?: |$)', 'sops exec-env FILE <command>'),
    ('secret-tool', ('lookup',), None, 'secret-tool search --all (attributes only)'),
    ('npm', ('config', 'get'), r'authtoken|_auth|password', 'npm whoami'),
    ('npm', ('token', 'create'), None, 'create tokens in the registry UI, never in a transcript'),
    ('docker', ('config',), None, None),
]


def _hash_stat(path):
    return os.stat(path, follow_symlinks=False)


# --------------------------------------------------------------------------- fallback text scan

def _build_fallback(c):
    rules = []
    add = rules.append
    S, L = SECRET_DUMP, LOG_DELETE
    add((S, 'rclone-config', re.compile(r'\brclone\b[^;|&\n]{0,200}?\bconfig\b[^;|&\n]{0,100}?\b(?:show|dump|reconnect)\b'),
         'rclone config show/dump/reconnect prints OAuth access and refresh tokens', 'rclone listremotes'))
    add((S, 'rclone-authorize', re.compile(r'\brclone\b[^;|&\n]{0,200}?\b(?:authorize|reveal)\b'),
         'rclone authorize/reveal prints tokens or passwords', 'rclone listremotes'))
    add((S, 'reveal-flag', re.compile(r'(?<![\w-])--reveal\b'), 'a --reveal flag prints secret values', 'goodqa run --mask -- <command>'))
    add((S, 'secret-cli', re.compile(r'\bsecrets\s+versions\s+access\b|\bfind-(?:generic|internet)-password\b|\bgh\s+auth\s+token\b|'
                                     r'\bprint-(?:access|identity)-token\b|\bget-secret-value\b'),
         'a secret-manager read prints the secret value', 'use the tool\'s metadata-only listing'))
    cred_alts = []
    for rx in c.policy['credential_path_regexes']:
        core = rx
        lead = r'(?:^|[\s/\'"=(,\[])'
        if core.startswith('(^|/)'):
            core = core[len('(^|/)'):]
        elif core.startswith('^'):
            core = core[1:]
            lead = r'(?:^|[\s\'"=(,\[])'
        if core.endswith('$'):
            core = core[:-1]
        cred_alts.append(lead + core + r'(?=$|[\s\'")\],;|&])')
    if cred_alts:
        cred = re.compile('|'.join(cred_alts), re.I)
        reader = re.compile(r'\b(?:cat|head|tail|less|more|type|get-content|gc|strings|xxd|od|base64|print|read|open|sed|awk|grep|'
                            r'cut|bat|nl|tac|readfile|read_text|read_bytes|file_get_contents|readfilesync|dump|echo)\b')
        add((S, 'credential-file-text', ('and', cred, reader),
             'reads a credential file and prints it', 'check that the file exists with `test -s FILE`; never print it'))
    # path pieces may be joined by /, path.join commas, + or pathlib's / (quotes are spaces by now)
    sep = r'(?:\s*[/,+\\]\s*|\s+)'
    protected = re.compile(r'\.(?:claude' + sep + r'(?:projects|wals|sessions|transcripts|history|file-history)|'
                           r'codex' + sep + r'(?:sessions|archived_sessions|history)|'
                           r'agent-harness' + sep + r'(?:state|codex-wals)(?![\w-])|'
                           r'agent-harness' + sep + r'work' + sep + r'[^\s/]+' + sep + r'[^\s]*wal)', re.I)
    destroyer = re.compile(r'\b(?:rm|rmdir|unlink|mv|shred|truncate|rmtree|remove|delete|rimraf|trash|rename|unlinksync|rmsync|'
                           r'remove-item|rsync|find|rm_rf|rm_r|remove_tree|remove_dir|removedirs|rmdirsync|unlink_|'
                           r'write_text|write_bytes|writefilesync|file_put_contents|sponge)\b|'
                           r'\bopen\b[^\n]{0,200}?\s(?:w|wb|w\+|a\+)(?:\s|$)|\bfs\.(?:rm|rmdir|unlink)\b')
    add((L, 'log-delete-text', ('and', protected, destroyer),
         'removes or rewrites Claude/Codex logs or WALs', 'back them up to Dropbox, run command_guard.py approve-delete, then delete'))
    # the secret word must be part of the variable's own name: `os.environ['API_TOKEN']`, `getenv("DB_PASSWORD")`,
    # `process.env.GH_TOKEN`; quotes and brackets are already spaces here. Not `os.environ['SCRATCH'] ... 'key'`.
    envs = re.compile(r'(?:\benviron(?:\.get)?|\bgetenv|\bprocess\.env\.?|\$env:|\benv\b(?:\.fetch)?)\s*'
                      r'[a-z0-9_]*(?:secret|token|key|password|passwd|credential)', re.I)
    add((S, 'env-secret-text', envs, 'prints a secret environment variable', 'test it with `[ -n "$NAME" ]`; never print the value'))
    return rules


def _scan_text(text):
    """The form the raw-text rules read: no confusables or format characters, quotes as spaces, casefolded."""
    t = unicodedata.normalize('NFKC', text[:2_000_000])
    t = ''.join(ch for ch in t if unicodedata.category(ch) != 'Cf').translate(CONFUSABLE).replace('\x00', '')
    t = re.sub(r'[\'",\[\](){}]', ' ', t)
    return re.sub(r'\s+', ' ', t).casefold()


# a line of a script that names a harness root under a home, outside the work and scratch dirs owners clean up routinely,
# and calls something that destroys or replaces a file (quotes are spaces by now, see _scan_text). One character class
# for the separator, so a long run of spaces cannot make the regex backtrack
_ROOT_SEP = r'[\s/,+\\]+'
ROOT_DELETE_VERB = re.compile(r'\b(?:rm|rmdir|unlink|shred|truncate|rmtree|remove|rimraf|trash|rm_rf|rm_r|remove_tree|removedirs|'
                              r'rmdirsync|unlinksync|rmsync|write_text|write_bytes|writefilesync|sponge)\b|'
                              r'\bopen\b[^\n]{0,200}?\s(?:w|wb|wt|w\+)(?:\s|$)|\bfs\.(?:rm|rmdir|unlink)\b')


def _root_text(home):
    start = r'(?<![\w./-])'  # the start of a path or a name: /tmp/fake/home/.claude and /tmp/root/.claude are not homes
    # the real home's spellings. A bare `home` is a variable, often a test's temp dir, and variables are not followed
    anchor = (r'(?:' + start + r'(?:~|/users/[^/\s+\\]+|/home/[^/\s+\\]+|/root\b|' + re.escape(home.casefold().rstrip('/'))
              + r')|\.home\b|(?:\$\s*|\benviron(?:\.get)?\s+|\bgetenv\s+)home\b)')
    return re.compile(anchor + _ROOT_SEP + r'\.(?:(?:claude|codex)(?![\w-])|agent-harness(?![\w-])(?!' + _ROOT_SEP
                      + r'(?:work|scratch)(?![\w.-])))')


def written_code_destroys_root(code, home):
    """A path and the call that destroys it on one line. Anywhere in the script would refuse every script that reads a
    harness file and writes its own output (replay: 13 of 13 false). A path held in a variable is not followed."""
    root = _root_text(home)
    if not root.search(_scan_text(code)):
        return False
    return any(root.search(line) and ROOT_DELETE_VERB.search(line) for line in map(_scan_text, code.splitlines()))


_RE_PATTERN_FUNCS = frozenset(('search', 'match', 'fullmatch', 'findall', 'finditer', 'sub', 'subn', 'split', 'compile'))
_PROTECTED_WORDS = ('.claude', '.codex', '.agent-harness', 'wals', 'transcripts', 'sessions', 'projects', 'history',
                    'archived_sessions', 'codex-wals')
# F1 (PR 146 delta red-team): a script may drop the log-delete finding for a regex pattern only when everything it calls
# is on this read-only list. Anything else (a delete, a write, subprocess, getattr, exec, eval, an unknown function) keeps
# the finding, so a spelling nobody listed fails toward block.
_SAFE_NAME_CALLS = frozenset((
    'open', 'print', 'len', 'str', 'int', 'float', 'bool', 'list', 'dict', 'set', 'tuple', 'frozenset', 'sorted', 'enumerate',
    'range', 'min', 'max', 'sum', 'any', 'all', 'zip', 'map', 'filter', 'isinstance', 'repr', 'reversed', 'abs', 'round',
    'next', 'iter', 'Counter', 'defaultdict', 'Path'))
_SAFE_ATTR_CALLS = frozenset((
    'search', 'match', 'fullmatch', 'findall', 'finditer', 'sub', 'subn', 'split', 'compile', 'escape',
    'read', 'readline', 'readlines', 'get', 'items', 'keys', 'values', 'append', 'add', 'extend', 'update', 'format', 'join',
    'strip', 'lstrip', 'rstrip', 'rsplit', 'splitlines', 'startswith', 'endswith', 'lower', 'upper', 'find', 'rfind',
    'index', 'count', 'group', 'groups', 'groupdict', 'start', 'end', 'span', 'loads', 'dumps', 'load', 'isoformat',
    'sort', 'copy', 'setdefault', 'pop', 'close', 'exists', 'isfile', 'isdir', 'basename', 'dirname', 'getsize', 'getmtime',
    'expanduser', 'glob', 'iterdir', 'stat', 'is_file', 'is_dir', 'read_text', 'read_bytes', 'most_common', 'encode', 'decode',
    'timestamp', 'fromisoformat', 'strftime', 'time', 'now', 'Path'))


def _literal_mode_is_read(call):
    mode = call.args[1] if len(call.args) > 1 else next((k.value for k in call.keywords if k.arg == 'mode'), None)
    if mode is None:
        return True
    import ast
    return isinstance(mode, ast.Constant) and isinstance(mode.value, str) and mode.value in ('r', 'rb', 'rt', 'br', 'tr')


def read_only_pattern_script(code):
    """True when `code` parses and every call in it is a read-only operation on the list above, with no local `re`,
    no use of a compiled pattern's text (`.pattern`, `.flags`), no write-mode open and no dynamic dispatch."""
    try:
        import ast
        tree = ast.parse(code)
    except Exception:  # noqa: BLE001
        return False
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr in ('pattern', 'flags', 'groupindex', 're', '__dict__', '__class__'):
            return False
        if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.Global, ast.Nonlocal)):
            return False
        if isinstance(node, ast.Name) and node.id == 're' and isinstance(node.ctx, (ast.Store, ast.Del)):
            return False
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                if alias.asname == 're' or (alias.name.split('.')[0] == 're' and alias.asname not in (None, 're')):
                    return False
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name):
                if func.id not in _SAFE_NAME_CALLS or (func.id == 'open' and not _literal_mode_is_read(node)):
                    return False
            elif isinstance(func, ast.Attribute):
                if func.attr not in _SAFE_ATTR_CALLS:
                    return False
                if func.attr == 'open':  # unreachable by the list, kept for clarity
                    return False
            else:
                return False
    return True


def blank_regex_patterns(code):
    """Python source with the pattern literal of each `re.<fn>(PATTERN, ...)` call emptied, except a literal that names a
    protected location (a WAL, log or transcript path is never blanked). A regex pattern cannot run anything, so a
    destroyer word inside one (`re.search(r'delete|rewrite', line)`) is not a deletion. Source that does not parse is
    returned unchanged."""
    try:
        import ast
        tree = ast.parse(code)
    except Exception:  # noqa: BLE001 - not Python (or too deep): the caller scans the text as before
        return code
    starts, pos = [], 0
    for ln in code.splitlines(keepends=True):
        starts.append(pos)
        pos += len(ln.encode('utf-8'))
    raw = code.encode('utf-8')
    spans = []
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in _RE_PATTERN_FUNCS
                and isinstance(node.func.value, ast.Name) and node.func.value.id == 're' and node.args
                and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, (str, bytes))):
            a = node.args[0]
            text = a.value if isinstance(a.value, str) else a.value.decode('utf-8', 'replace')
            if any(word in text.casefold() for word in _PROTECTED_WORDS):
                continue
            spans.append((starts[a.lineno - 1] + a.col_offset, starts[a.end_lineno - 1] + a.end_col_offset))
    for b, e in sorted(spans, reverse=True):
        raw = raw[:b] + b"''" + raw[e:]
    return raw.decode('utf-8', 'replace')


def fallback_scan(text, ctx):
    """Raw-text rules for unresolved indirection, interpreter code, oversized input and internal errors."""
    findings = []
    t = _scan_text(text)
    for category, rule, pattern, reason, alt in ctx.fallback:
        if isinstance(pattern, tuple):
            hit = pattern[1].search(t) and pattern[2].search(t)
        else:
            hit = pattern.search(t)
        if hit:
            findings.append(Finding(category, rule, reason, alt))
    return findings


# --------------------------------------------------------------------------- analysis

class Ctx:
    """Mutable state for analysing one command line."""

    def __init__(self, compiled, cwd=None, ps=False, marker=None):
        self.c = compiled
        self.ps = ps
        self.budget = Budget(compiled.limits)
        self.home = compiled.home
        self.cwd = cwd or compiled.cwd
        self.origin_cwd = cwd  # the payload's working directory, None when the host sent none
        self.cwd_known = bool(cwd)  # becomes True after an absolute or home `cd` in the command
        self.work_refusal = False
        self.token_sink_ok = False
        self.token_allowed = 0
        self.top_commands = 0
        self.cwd_unknown = False
        self.cwd_protected_unknown = False  # cd to an unresolved path whose text names a protected location
        self.var_hints = {}  # raw text of dynamic assignments, for variables the guard cannot resolve
        self.temp_vars = {}  # NAME=$(mktemp ...): name -> (its var_hints text, directories mktemp may create in)
        self.seen_texts = []  # every script text analysed (top command, -c strings, script files): goodqa#15122
        self.temp_tainted = set()  # temp variables passed to a command that could replace the file (goodqa#15122)
        self.created = set()  # case-folded paths written earlier in this command (count as existing)
        self.links = {}  # symlinks created earlier in this command: link path -> target path
        self.written = {}  # case-folded path -> text written to it earlier in this command (echo/printf/heredoc)
        self.one_sided = set()  # files only one reading of `>!` wrote: what is on disk may still be what runs
        self.secret_files = set()  # files that received a secret value earlier in this command
        self.unterminated = False
        self.vars = {}
        self.tainted = set()
        self.aliases = {}
        self.findings = []
        self.secret_seen = 0
        self.tail_visible = True
        self.kill_seen = False
        self.pending_kill = []
        self.marker = marker  # callable(path) -> bool, injectable for tests
        self.fixed_cwd = None
        self.fork_depth = 0  # readings of `>!` being analysed around the current script (Analyzer._both_readings)
        self.readings_capped = False  # `>!` could not be judged both ways: too deep, no budget, or the readings disagree
        self.fs_cache = {}  # per-analysis memo of disk probes (lexists/realpath/markers): the command has not run,
        # so the disk cannot change mid-analysis. Cleared wherever the analysis models a filesystem change
        # (note_created, a made link) or restores a reading's snapshot, which make earlier answers stale.

    def cwd_value(self):
        return self.cwd

    # what one reading of a script can change; findings accumulate across readings and the rest is not analysis state
    NOT_STATE = ('findings', 'budget', 'c', 'marker', 'raw_top', 'ps', 'tail_visible', 'fork_depth', 'readings_capped',
                 'fs_cache', 'seen_texts')

    def state(self):
        return {k: (v.copy() if isinstance(v, (set, dict, list)) else v) for k, v in vars(self).items()
                if k not in self.NOT_STATE}

    def restore(self, saved):
        self.fs_cache.clear()  # the restored snapshot's model of created paths/links may differ from the probe era
        for k in [k for k in vars(self) if k not in self.NOT_STATE and k not in saved]:
            delattr(self, k)
        for k, v in saved.items():
            setattr(self, k, v.copy() if isinstance(v, (set, dict, list)) else v)

    def disputes(self, other):
        """Can a later command depend on which reading was right? Sets and flags combine without loss. These values do
        not: a merged variable is only a hint on a path operand, and is lost as a command name, an option or a script."""
        return (any(getattr(self, k) != other[k] for k in ('vars', 'var_hints', 'aliases', 'links', 'cwd', 'cwd_unknown'))
                # not bash's file named `!`: every nested `>!` rewrites it, so it would always differ. merge keeps
                # both texts, so running it is still judged
                or any(other['written'].get(path, text) != text for path, text in self.written.items()
                       if os.path.basename(path) != '!'))

    def merge(self, other):
        """Combine another reading's end state into this one for the commands that follow. Either reading may be the
        real one, so nothing it knows can be lost: a variable they disagree on is no longer known and both values
        become hints, a file keeps both texts, and if they end in different directories the current one is unknown,
        judged as protected if either names a protected location."""
        hints = dict(self.var_hints)
        for name, value in other['var_hints'].items():
            hints[name] = value if hints.get(name) in (None, value) else hints[name] + ' ' + value
        known = {name: value for name, value in self.vars.items() if name in other['vars'] and other['vars'][name] == value}
        for name in (set(self.vars) | set(other['vars'])) - set(known):
            values = [hints.get(name), self.vars.get(name), other['vars'].get(name)]
            hints[name] = ' '.join(v for v in values if isinstance(v, str))[:4096]
        self.vars, self.var_hints = known, hints
        for k, theirs in other.items():
            if k in self.NOT_STATE or k in ('vars', 'var_hints'):
                continue
            mine = getattr(self, k, None)
            if k == 'written':
                both = dict(theirs)
                for path, text in (mine or {}).items():
                    both[path] = text if both.get(path) in (None, text) else (both[path] + '\n' + text)[:524288]
                self.written = both
                self.one_sided = self.one_sided | (set(theirs) ^ set(mine or {}))
            elif isinstance(theirs, set):
                setattr(self, k, (mine or set()) | theirs)
            elif isinstance(theirs, dict):
                setattr(self, k, {**(mine or {}), **theirs})
            elif isinstance(theirs, list):
                setattr(self, k, (mine or []) + [x for x in theirs if x not in (mine or [])])
            elif isinstance(theirs, int):  # counters only rise, and a flag set by either reading stays set
                setattr(self, k, max(mine or 0, theirs))
            elif k == 'cwd' and mine != theirs:
                self.cwd_protected_unknown = self.cwd_protected_unknown or bool(
                    PROTECTED_TEXT.search((mine or '') + ' ' + (theirs or '') + '/'))
                self.cwd = theirs
                self.cwd_unknown = True
            else:
                setattr(self, k, theirs)

    def add(self, category, rule, reason, alternative):
        self.findings.append(Finding(category, rule, reason, alternative))


# Each nesting level with a `>!` doubles the parses. This keeps a small command inside the budget, which matters because
# a budget stop loses whatever the guard has not reached yet. Past it a script gets one reading, and analyze() treats
# the command as unanalysable.
MAX_READING_FORKS = 3


# SECRET_DUMP rules still enforced inside an existing script on disk (Kimi audit F02, goodqa#14995): these read
# credential material wholesale, which repository tooling has no routine reason to do. Lookups that tooling does use
# (env dumps, `gh auth token`, one keychain password, ${!name}, git config listings, obfuscation) stay exempt there.
SCRIPT_CREDENTIAL_RULES = frozenset((
    'credential-file', 'credential-stdin', 'credential-script', 'find-exec-credentials', 'keychain-dump',
    'docker-credential', 'git-credential', 'git-credential-helper', 'goodqa-reveal', 'rclone-dump', 'rclone-authorize',
))


class Analyzer:
    # The credential-script check (goodqa#14518) runs only in its own second pass, credential_findings(), so the analysis
    # that decides everything else is exactly main's. disk_depth counts scripts on disk being analysed: their
    # commands are judged only for log deletion and credential reads (SCRIPT_CREDENTIAL_RULES), so the
    # check skips them rather than spend its time there.
    credential_pass = False
    credential_candidate = False
    disk_depth = 0

    def __init__(self, compiled, cwd=None, ps=False, marker=None):
        self.ctx = Ctx(compiled, cwd, ps, marker)
        self.c = compiled

    def _probe(self, kind, path, fn):
        """One disk probe per analysis. The command has not run, so a path's lexists/realpath/marker answer is
        fixed for the whole analysis; repeat probes (both `>!` readings, every redirect alternative, each path
        prefix) reuse it. The cache is cleared whenever the analysis models a filesystem change or restores a
        reading, so a stale answer is impossible (see Ctx.fs_cache). Exceptions are cached and re-raised, so
        callers keep their current try/except behaviour. The key is the probe function itself, not `kind`:
        os.path.realpath and _resolve_prefix answer differently (None versus a path or an exception) for the
        same path, so a shared label would hand one caller the other's answer (audit2 F-014 port, goodqa#15002)."""
        cache = self.ctx.fs_cache
        key = (fn, path)
        if key not in cache:
            try:
                cache[key] = (True, fn(path))
            except (OSError, ValueError, RuntimeError) as exc:
                cache[key] = (False, exc)
        ok, value = cache[key]
        if ok:
            return value
        raise value

    # ---- entry
    def run(self, text):
        ctx = self.ctx
        ctx.raw_top = text if isinstance(text, str) else ' '.join(map(str, text))
        self.script(text, depth=0)
        if ctx.kill_seen:
            for finding in ctx.pending_kill:
                ctx.findings.append(finding)
        if ctx.token_allowed and ctx.top_commands > 1:
            ctx.add(SECRET_DUMP, 'gh-secret', 'gh auth token is allowed only as VAR=$(gh auth token) gh <subcommand> '
                    'on its own', 'run that gh command by itself')
        return ctx.findings

    def check_tokens(self, tokens):
        """Seam for a subclass that must see the token stream before parse() ends a command at an operator."""

    def script(self, text, depth, tail_visible=None, ps=None):
        ctx = self.ctx
        if depth > ctx.budget.max_depth:
            raise Blocked('command nesting is deeper than %d levels' % ctx.budget.max_depth)
        saved_ps, saved_tail = ctx.ps, ctx.tail_visible
        if ps is not None:
            ctx.ps = ps
        if tail_visible is not None:
            ctx.tail_visible = tail_visible
        if isinstance(text, str) and len(ctx.seen_texts) < 256:
            ctx.seen_texts.append(text[:200000])
        try:
            lexer = Lexer(ctx, ctx.ps)
            tokens = lexer.lex(text)
            if lexer.saw_bang and ctx.fork_depth < MAX_READING_FORKS:
                ctx.fork_depth += 1
                try:
                    self._both_readings(tokens, text, depth)
                finally:
                    ctx.fork_depth -= 1
            else:
                ctx.readings_capped = ctx.readings_capped or lexer.saw_bang
                self._run_tokens(tokens, depth)
        finally:
            ctx.ps, ctx.tail_visible = saved_ps, saved_tail

    def _run_tokens(self, tokens, depth):
        self.check_tokens(tokens)
        for pipeline in parse(tokens):
            self.pipeline(pipeline, depth)

    def _both_readings(self, zsh_tokens, text, depth):
        """zsh and bash read `>! w` differently and the guard cannot know which shell runs the text, so judge the text
        once per reading: anything either one refuses is refused. One shell reads every `>!` in a script the same way,
        so two parses cover a script however many it has. This runs per script rather than per command line because a
        nested shell can read the operator differently from its parent (`>! f bash -c '...'`). Each reading starts from
        the same state: a `cd` or an assignment made in one did not happen in the other (GoodQA #14657)."""
        ctx = self.ctx
        start = ctx.state()
        mark = len(ctx.findings)
        count, began = ctx.budget.count, time.monotonic()
        self._run_tokens(zsh_tokens, depth)
        # a second reading that cannot finish would stop the analysis and lose every later command, so skip it instead;
        # analyze() then treats the command as unanalysable
        if not ctx.budget.has_room(2 * (ctx.budget.count - count) + len(text), 2 * (time.monotonic() - began)):
            ctx.readings_capped = True
            return
        after_zsh = ctx.state()
        ctx.restore(start)
        mid = len(ctx.findings)
        self._run_tokens(Lexer(ctx, ctx.ps, bang_operators=False).lex(text), depth)
        seen = {(f.category, f.rule, f.reason) for f in ctx.findings[mark:mid]}
        ctx.findings[mid:] = [f for f in ctx.findings[mid:] if (f.category, f.rule, f.reason) not in seen]
        # at the top level each reading has already seen its own later commands; nested text has more to come
        if depth > 0 and ctx.disputes(after_zsh):
            ctx.readings_capped = True
        ctx.merge(after_zsh)

    # ---- visibility of a stage's stdout
    def consumer_class(self, cmd):
        words = strip_reserved(cmd.words)
        words = self._skip_assigns(words)[1]
        if not words:
            return 'unknown'
        name = self._alias(norm_name(words[0].text))
        args = words[1:]
        if name in NONPRINT_SINKS:
            return 'sink'
        if name in GREP_CMDS and (_flag_letters(args) & set('cqlL') or _longs(args) & {'--count', '--quiet', '--silent', '--files-with-matches', '--files-without-match'}):
            return 'sink'
        if name == 'cut' and any(a.text.startswith('-d=') or a.text == '-d' for a in args) and any(a.text.startswith('-f1') or a.text == '-f' for a in args):
            return 'names'
        if name == 'sed' and any(re.search(r's[/|#]=\.\*[/|#]', a.text) for a in args):
            return 'names'
        if name == 'awk' and any('-F=' in a.text or 'print $1' in a.text for a in args) and any('$1' in a.text for a in args):
            return 'names'
        if name == 'docker' and 'login' in [a.text for a in args] or name == 'gh' and 'login' in [a.text for a in args]:
            return 'sink'
        if name in PASS_FILTERS:
            return 'pass'
        return 'unknown'

    def stdout_redirected(self, cmd):
        for r in cmd.redirs:
            if r.op in ('>', '>>', '>|', '&>', '&>>') and r.fd in (None, '1'):
                target = r.target.text if r.target else ''
                if target in ('/dev/stdout', '/dev/stderr', '/dev/tty') or target.startswith('&'):
                    continue
                return True
            if r.op == '>&' and r.fd in (None, '1') and r.target is not None and not re.fullmatch(r'[0-9-]+', r.target.text):
                return True
        return False

    def out_visible(self, pl, idx, unknown_visible):
        ctx = self.ctx
        cmd = pl.cmds[idx]
        if self.stdout_redirected(cmd):
            return False
        if idx == len(pl.cmds) - 1:
            return ctx.tail_visible
        cls = self.consumer_class(pl.cmds[idx + 1])
        if cls in ('sink', 'names'):
            return False
        if cls == 'pass':
            return self.out_visible(pl, idx + 1, unknown_visible)
        return unknown_visible

    # ---- pipeline
    def pipeline(self, pl, depth):
        ctx = self.ctx
        ctx.budget.tick()
        names = []
        for idx, cmd in enumerate(pl.cmds):
            self.command(cmd, pl, idx, depth)
        # shell reading its program from a decoder pipeline: `... | base64 -d | sh`
        for idx, cmd in enumerate(pl.cmds):
            words = self._skip_assigns(strip_reserved(cmd.words))[1]
            if not words or idx == 0:
                continue
            name = norm_name(words[0].text)
            job_queue = name in ('at', 'batch') and not any(a.text == '-f' for a in words[1:])
            if job_queue or name in SHELLS | PS_SHELLS and not any(a.text in ('-c', '-command', '-Command', '/c') or re.fullmatch(r'-[a-z]*c[a-z]*', a.text) for a in words[1:]) \
                    and not [a for a in words[1:] if not a.text.startswith('-')]:
                for prev in pl.cmds[:idx]:
                    pw = self._skip_assigns(strip_reserved(prev.words))[1]
                    if pw and self._decoder(pw):
                        ctx.add(SECRET_DUMP, 'obfuscated-shell-input',
                                'a shell is fed a decoded (obfuscated) program, so the guard cannot see what runs',
                                'write the command in plain text')
                        break
                # `echo 'cmd' | sh`, `printf ... | bash`, `cat file.sh | sh`: the text is the program
                prev = self._skip_assigns(strip_reserved(pl.cmds[idx - 1].words))[1]
                if prev:
                    pname = norm_name(prev[0].text)
                    ptexts = [w.text for w in prev[1:]]
                    if pname in ('echo', 'printf', 'print'):
                        body = ' '.join(t for t in ptexts if t not in ('-n', '-e', '-ne', '-en'))
                        self.script(decode_ansi(body) if pname == 'printf' or '-e' in ptexts else body, depth + 1,
                                    tail_visible=True)
                    elif pname == 'cat':
                        for w in _nondash(prev[1:])[:4]:
                            self.credential_entry(None, '.', [w], [w], [w.text])
                            self.script_file(w, depth)
        # `... | xargs rm`: the operands come from the earlier stages, so judge what those stages name
        for idx, cmd in enumerate(pl.cmds):
            words = self._skip_assigns(strip_reserved(cmd.words))[1]
            if idx == 0 or not words or norm_name(words[0].text) not in ('xargs', 'parallel'):
                continue
            inner = [norm_name(w.text) for w in words[1:] if not w.text.startswith('-')]
            joined = ' '.join(w.text for w in words[1:])
            if not (set(inner) & (RM_CMDS | MV_CMDS | {'truncate', 'shred', 'unlink'})
                    or re.search(r'\b(?:rm|rmdir|unlink|shred|mv|truncate)\b', joined)):
                continue
            for prev in pl.cmds[:idx]:
                pw = self._skip_assigns(strip_reserved(prev.words))[1]
                for w in pw[1:]:
                    if w.text.startswith('-') or w.text in ('(', ')', '!'):
                        continue
                    if self.refuse('xargs deletion of paths listed by an earlier stage', w,
                                   tiers=('log', 'root', 'ancestor', 'unknown')):
                        break
        # `find ~/.aws -type f | xargs cat`: a printing reader over paths listed by an earlier stage
        for idx, cmd in enumerate(pl.cmds):
            words = self._skip_assigns(strip_reserved(cmd.words))[1]
            if idx == 0 or not words or norm_name(words[0].text) not in ('xargs', 'parallel'):
                continue
            inner = [norm_name(w.text) for w in words[1:] if not w.text.startswith('-')]
            if not inner or inner[0] not in PRINT_FILE_CMDS | GREP_CMDS | {'base64', 'strings'}:
                continue
            if not self.out_visible(pl, idx, True):
                continue
            hit = False
            for prev in pl.cmds[:idx]:
                for w in self._skip_assigns(strip_reserved(prev.words))[1][1:]:
                    t = w.text
                    if t.startswith('-') or not t:
                        continue
                    if self._home_cred(t, w) or self.under_cred_dir(norm_path(t, ctx), or_above=False):
                        hit = True
                        break
            if hit:
                ctx.secret_seen += 1
                ctx.add(SECRET_DUMP, 'credential-file', 'xargs %s prints credential files listed by an earlier stage'
                        % inner[0][:20], 'list names only: find DIR -type f, or ls -l')
        # a kill verb anywhere in the pipeline makes the pid-finding stages relevant
        kills = [i for i, cmd in enumerate(pl.cmds) if self._is_kill_stage(cmd)]
        if kills:
            for i, cmd in enumerate(pl.cmds):
                if i in kills:
                    continue
                words = self._skip_assigns(strip_reserved(cmd.words))[1]
                if not words:
                    continue
                name = norm_name(words[0].text)
                args = words[1:]
                if name in GREP_CMDS:
                    pos = [a.text for a in _nondash(args)]
                    if pos:
                        self._kill_pattern(pos[0], scoped=False, strong=False, source='grep')
                elif name == 'pgrep':
                    self.kill_args(name, args, immediate=True)

    def _decoder(self, words):
        name = norm_name(words[0].text)
        args = [a.text for a in words[1:]]
        if name in ('base64', 'base32', 'basenc') and any(a in ('-d', '-D', '--decode', '-decode') for a in args):
            return True
        if name == 'xxd' and '-r' in args:
            return True
        if name == 'openssl' and ('-d' in args or '-base64' in args or 'base64' in args):
            return True
        return name in ('rev', 'uudecode', 'unhex')

    def _is_kill_stage(self, cmd):
        words = self._skip_assigns(strip_reserved(cmd.words))[1]
        if not words:
            return False
        name = norm_name(words[0].text)
        if name in ('kill', 'pkill', 'killall', 'taskkill', 'stop-process'):
            return True
        if name == 'xargs':
            return any(norm_name(a.text) in ('kill', 'pkill') for a in words[1:])
        return False

    TEMP_ROOT_VARS = ('TMPDIR', 'CLAUDE_CODE_TMPDIR')

    def _temp_root_candidates(self, name):
        """Values the shell's $TMPDIR or $CLAUDE_CODE_TMPDIR may hold. The hook does not see the command's
        environment, and the harness install relocates the Claude Code temp root to ~/.agent-harness/scratch, so every
        plausible value is tried and the strongest protection among them decides (goodqa#15280)."""
        values = [os.environ.get(name) or '', os.environ.get('CLAUDE_CODE_TMPDIR') or '',
                  self.ctx.home.rstrip('/') + '/.agent-harness/scratch']
        if name == 'TMPDIR':
            values.append('/tmp')
        return [v for v in dict.fromkeys(values) if v.startswith('/')]

    def _temp_root_alts(self, alts):
        """Expand an unassigned $TMPDIR or $CLAUDE_CODE_TMPDIR marker into one alternative per candidate value, so a
        scratchpad path spelled through them is judged like its literal form: allowed inside a session scratchpad,
        refused on task-output logs or the scratch root. Assigned names are left to resolve(). Past 32 alternatives
        nothing is expanded, so the markers stay unresolved (judged as unknown) instead of a candidate being dropped."""
        ctx = self.ctx
        out = []
        for alt in alts:
            todo = [alt]
            for name in self.TEMP_ROOT_VARS:
                marker = VAR_OPEN + name + VAR_CLOSE
                if marker not in alt or (name in ctx.vars and name not in ctx.tainted) or name in ctx.tainted:
                    continue
                todo = [t.replace(marker, ''.join(Q.get(ch, ch) for ch in v.rstrip('/')))
                        for t in todo for v in self._temp_root_candidates(name)]
            out.extend(todo)
        return alts if len(out) > 32 else out

    def resolve(self, word):
        """Expand $NAME markers with the values assigned so far; unknown or tainted names stay as $NAME."""
        if word is None or not any(VAR_OPEN in a for a in word.alts):
            return word
        ctx = self.ctx
        unresolved = False

        def sub(match):
            nonlocal unresolved
            name = match.group(1)
            if name in ctx.vars and name not in ctx.tainted:
                return ctx.vars[name]
            unresolved = True
            return '$' + name

        out = Word()
        out.alts = [VAR_MARKER.sub(sub, a) for a in self._temp_root_alts(word.alts)]
        out.subs, out.vars, out.glob, out.quoted = word.subs, word.vars, word.glob, word.quoted
        out.dynamic = word.dynamic or unresolved
        out.raw = word.raw
        return out

    # ---- single command
    @staticmethod
    def _skip_assigns(words):
        assigns = []
        i = 0
        while i < len(words) and re.match(r'^[A-Za-z_][A-Za-z0-9_]*\+?=', words[i].text) and not words[i].text.startswith('='):
            assigns.append(words[i])
            i += 1
        return assigns, words[i:]

    def _alias(self, name):
        return name

    def command(self, cmd, pl, idx, depth):
        ctx = self.ctx
        ctx.budget.tick()
        words = [self.resolve(w) for w in strip_reserved(cmd.words)]
        head_nonexec = bool(words) and not words[0].quoted and words[0].text in NONEXEC_HEADS
        assigns, rest = self._skip_assigns(words)
        self._note_temp_uses(assigns, rest)
        # redirections apply to every command, including the bare `> file` truncation
        self.redirects(cmd, pl, idx, bool(rest), depth)
        if head_nonexec:
            self.bind_loop_var(words)
            rest = []
        if not rest:
            self.assignments(assigns, depth)
            for w in (words if head_nonexec else []):
                self.subs(w, depth, visible=False)
            return
        if depth == 0:
            ctx.top_commands += 1
        token_ok = (depth == 0 and len(assigns) == 1 and len(pl.cmds) == 1 and not cmd.redirs and norm_name(rest[0].text) == 'gh'
                    and not rest[0].dynamic and self._gh_sub_ok(rest[1:]))
        for a in assigns:
            ctx.token_sink_ok = token_ok
            try:
                self.subs(a, depth, visible=False)
            finally:
                ctx.token_sink_ok = False
        # substitutions inside arguments run first; their output is visible only when the outer command prints it
        outer = norm_name(rest[0].text)
        printer = outer in ECHO_CMDS or outer in PRINT_FILE_CMDS or outer in PASS_FILTERS
        for w in rest:
            self.subs(w, depth, visible=printer and self.out_visible(pl, idx, False))
        if printer and any(v.startswith('!') for w in rest[1:] for v in w.vars) and self.out_visible(pl, idx, False):
            ctx.secret_seen += 1
            ctx.add(SECRET_DUMP, 'indirect-var', 'printing ${!name} prints the value of whatever variable name holds',
                    'print variable names only (compgen -v), never their values')
        before = ctx.secret_seen
        self.dispatch(rest, cmd, pl, idx, depth)
        if outer in ('cp', 'install', 'ditto', 'ln', 'rsync', 'mv') and len(rest) >= 3:
            ops = _nondash(rest[1:])
            if len(ops) >= 2 and any(self._cred_one(norm_path(o.text, ctx)) for o in ops[:-1]):
                ctx.secret_files.add(norm_path(ops[-1].text, ctx).casefold())
                dest = norm_path(ops[-1].text, ctx)
                for o in ops[:-1]:
                    ctx.secret_files.add((dest.rstrip('/') + '/' + posixpath.basename(o.text)).casefold())
        if ctx.secret_seen > before:
            for r in cmd.redirs:
                if r.op in ('>', '>>', '>|', '&>', '&>>') and r.target is not None:
                    for alt in r.target.alts[:8]:
                        ctx.secret_files.add(norm_path(alt, ctx).casefold())
            if norm_name(rest[0].text) == 'tee' or any(norm_name(c.words[0].text) == 'tee'
                                                       for c in pl.cmds[idx + 1:] if c.words):
                for c in pl.cmds[idx:]:
                    if c.words and norm_name(c.words[0].text) == 'tee':
                        for w in _nondash(c.words[1:]):
                            ctx.secret_files.add(norm_path(w.text, ctx).casefold())

    def bind_loop_var(self, words):
        """`for d in LIST`: bind d to the first protected-looking item (else the first item) so `rm "$d"` resolves."""
        if words[0].text != 'for' or len(words) < 4 or words[2].text != 'in':
            return
        name, items = words[1].text, [w for w in words[3:] if w.text not in (';', 'do')]
        if not items:
            return
        # the loop runs the body once per item: bind the most protected one so every check sees the worst case
        chosen, rank = items[0], -1
        for item in items[:256]:
            probe = norm_path(item.text, self.ctx)
            r = self.RANK[self._path_class(probe)]
            if r <= 0 and (is_dynamic_path(item.text) or any(ch in item.text for ch in '*?[')) \
                    and any(seg_match(Compiled._segs(probe), pr) for pr in self.c.protected):
                r = self.RANK['log']
            if r > rank:
                chosen, rank = item, r
        self.ctx.temp_vars.pop(name, None)
        if re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', name):
            if any(item.dynamic or item.glob or item.subs for item in items):
                if not hasattr(self.ctx, 'flow_vars'):
                    self.ctx.flow_vars = set()
                self.ctx.flow_vars.add(name)
            self.ctx.vars[name] = chosen.text
            self.ctx.tainted.discard(name)
            # `for t in "$GH_TOKEN"`: the loop variable carries whatever secret its items expand to
            if any(self.c.secret_name(v.lstrip('!')) or v in self.ctx.tainted for item in items for v in item.vars):
                self.ctx.tainted.add(name)

    def subs(self, w, depth, visible):
        for inner in w.subs:
            self.script(inner, depth + 1, tail_visible=visible)

    def assignments(self, assigns, depth):
        ctx = self.ctx
        for a in assigns:
            text = a.text
            name, _, value = text.partition('=')
            name = name.rstrip('+')
            before = ctx.secret_seen
            self.subs(a, depth, visible=False)
            tainted = ctx.secret_seen > before or any(ctx.c.secret_name(v.lstrip('!')) or v in ctx.tainted for v in a.vars)
            if tainted:
                ctx.tainted.add(name)
            ctx.temp_vars.pop(name, None)
            if not a.dynamic and not tainted:
                ctx.vars[name] = value
                ctx.tainted.discard(name)
                ctx.var_hints.pop(name, None)
            elif a.dynamic:
                ctx.vars.pop(name, None)
                ctx.var_hints[name] = (value + ' ' + ' '.join(a.subs) + ' ' + ' '.join(
                    ctx.var_hints.get(v, '') for v in a.vars))[:4096]
                if value == SUB_MARK and len(a.subs) == 1 and not a.vars and not tainted:
                    made = mktemp_directory(a.subs[0], None if ctx.cwd_unknown else ctx.cwd)
                    if made is not None:
                        ctx.temp_vars[name] = (ctx.var_hints[name], made)

    # ---- redirections and heredocs
    def redirects(self, cmd, pl, idx, has_command, depth):
        ctx = self.ctx
        words = self._skip_assigns(strip_reserved(cmd.words))[1]
        name = norm_name(words[0].text) if words else ''
        arg_texts = [w.text for w in words[1:]]
        # pure truncation: nothing (or nothing meaningful) is written, so the redirect only empties the file
        # `cat > f <<EOF` writes content; an empty heredoc writes nothing, so that stays a pure truncation
        has_body = any(r.op == '<<<' or r.op in ('<<', '<<-') and r.body.strip('\n') for r in cmd.redirs)
        pure = (not words or name in (':', 'true', 'false')
                or (name == 'cat' and not has_body and all(t == '/dev/null' for t in arg_texts))
                or (name in ('echo', 'printf') and all(t in ('', '-n', '-e', '-ne', '-en') for t in arg_texts)))
        written = None
        if name in ('echo', 'printf'):
            written = ' '.join(t for t in arg_texts if t not in ('-n', '-e', '-ne', '-en'))
            if name == 'printf' or '-e' in arg_texts:
                written = decode_ansi(written)
        bodies = [r.body for r in cmd.redirs if r.op in ('<<', '<<-')]
        if bodies and name in ('cat', 'tee', ''):
            written = '\n'.join(bodies)
        for r in cmd.redirs:
            r.target = self.resolve(r.target)
            target = r.target.text if r.target is not None else ''
            if r.target is not None:
                self.subs(r.target, depth, visible=False)
            is_write = False
            # `3&> f`: bash and zsh read the digit as an argument, so `&>` always writes the file
            if r.op in ('>', '>|', '>&') and r.fd in (None, '1', '2') or r.op in ('>>', '&>>', '&>'):
                if target and r.op != '>&' or (r.op == '>&' and target and not re.fullmatch(r'[0-9-]+', target)):
                    self.write_target(r.target, truncating=r.op not in ('>>', '&>>'), via='redirect', pure=pure)
                    is_write = True
            elif r.op in ('>>', '&>>') or r.op in ('>', '>|') and r.fd not in (None, '1', '2'):
                if target:
                    self.write_target(r.target, truncating=r.op in ('>', '>|'), via='redirect', pure=pure)
                    is_write = True
            elif r.op == '<>' and target and (r.fd in ('1', '2') or name == 'exec' or any(
                    x.op == '>&' and x.target is not None and x.target.text == (r.fd or '0') for x in cmd.redirs)):
                # `1<> f`: stdout opened read-write without truncation; what the command prints overwrites the file
                # in place, so it is judged like `>`. So is any `N<> f` that a `>&N` dup writes to, and an `exec N<>`
                # whose descriptor later commands can write; a plain fd-0 `<>` only feeds input and stays a read
                self.write_target(r.target, truncating=True, via='redirect', pure=False)
                is_write = True
            if is_write and written is not None and r.target is not None:
                self.note_created(r.target, written)
            if r.op in ('<', '<>') and target:
                if self.is_cred_path(target, r.target):
                    ctx.secret_seen += 1
                    if not (name in NONPRINT_SINKS or name in ('test', '[') or (name in GREP_CMDS and self._count_only(words[1:]))):
                        if not has_command or self.out_visible(pl, idx, True):
                            ctx.add(SECRET_DUMP, 'credential-stdin',
                                    'feeds a credential file to a command that can print it',
                                    'check the file with `test -s FILE`; use the tool\'s own --config flag instead of reading it')
            if r.op == '<<<' and r.target is not None:
                self.herestring(r.target, name, pl, idx)
            if r.op in ('<<', '<<-'):
                self.heredoc(r, name, words, pl, idx, depth)

    def herestring(self, word, name, pl, idx):
        if name in ECHO_CMDS or name in PRINT_FILE_CMDS or name in PASS_FILTERS:
            if self.out_visible(pl, idx, False):
                self.check_secret_vars(word)

    def heredoc(self, rd, name, words, pl, idx, depth):
        ctx = self.ctx
        body = rd.body
        if body and PROTECTED_TEXT.search(body) and any(f.category == LOG_DELETE for f in fallback_scan(body, ctx.c)):
            # writing deletion text for a protected location through a shell heredoc (even into a data file) is the
            # incident mechanism: warn, and point at the file-writing tool. A real deletion still blocks below.
            ctx.add(PARSE, 'heredoc-destructive-text',
                    'a heredoc body contains a deletion of a protected harness location, and heredoc text passes '
                    'through the shell', 'write test data or scripts with the editor\'s file-writing tool instead')
        if name in SHELLS or name in PS_SHELLS or name in ('at', 'batch') or (
                name in ('source', '.') and any(w.text in ('/dev/stdin', '-') for w in words[1:])):
            self.script(body, depth + 1, tail_visible=True, ps=name in PS_SHELLS)
            return
        if name in WRAPPERS_SIMPLE or name in ('flock', 'unshare'):
            # sudo bash <<EOF, env X=1 sh <<EOF: find the real consumer behind the wrapper words
            inner = [norm_name(w.text) for w in words[1:] if not w.text.startswith('-') and '=' not in w.text]
            if any(n in SHELLS or n in ('ssh',) for n in inner):
                self.script(body, depth + 1, tail_visible=True)
                return
            if any(n in INTERPRETERS for n in inner):
                self.code(body, depth)
                return
        if name in INTERPRETERS:
            self.code(body, depth)
            return
        if name == 'ssh':
            self.script(body, depth + 1, tail_visible=True)
            return
        if rd.quoted:
            return
        # unquoted delimiter: $(..), `..` and $VAR expand inside the body
        visible = (name in ECHO_CMDS or name in PRINT_FILE_CMDS or name in PASS_FILTERS) and self.out_visible(pl, idx, False)
        probe = Word()
        lexer = Lexer(ctx, False)
        buf = []
        i = 0
        while i < len(body):
            ctx.budget.tick()
            if body[i] == '\\':
                i += 2
            elif body[i] == '$':
                i = lexer._dollar(body, i, probe, buf, in_dq=True)
            elif body[i] == '`':
                j = scan_backtick(body, i + 1)
                probe.subs.append(body[i + 1:j - 1] if j <= len(body) else body[i + 1:])
                i = min(j, len(body))
            else:
                i += 1
            if len(probe.subs) > 200:
                raise Blocked('here-document has too many substitutions')
        for inner in probe.subs:
            self.script(inner, depth + 1, tail_visible=visible)
        if visible:
            self.check_secret_vars(probe)

    # ---- secret variable printing
    def check_secret_vars(self, word):
        ctx = self.ctx
        for v in word.vars:
            bare = v.lstrip('!')
            known = ctx.vars.get(bare)
            if isinstance(known, str) and bare not in ctx.tainted and not v.startswith('!') \
                    and not is_dynamic_path(known) and _looks_clean(known):
                continue  # bound earlier in this command to a literal non-secret value (`for pat in a b c`)
            if ctx.c.secret_name(bare) or v in ctx.tainted or bare in ctx.tainted:
                ctx.add(SECRET_DUMP, 'print-secret-variable',
                        'prints a variable whose name or content marks it as a secret (%s)' % bare[:40],
                        'test presence with `[ -n "$NAME" ]` or print only its length `${#NAME}`')
                return

    # ---- dispatch
    def dispatch(self, words, cmd, pl, idx, depth):
        ctx = self.ctx
        ctx.budget.tick()
        if depth > ctx.budget.max_depth:
            raise Blocked('command nesting is deeper than %d levels' % ctx.budget.max_depth)
        head = words[0]
        if ctx.ps:
            # the lexer splits at the parentheses, so read the call (and its argument) from the raw command
            joined_ps = (getattr(ctx, 'raw_top', '') or '')[:20000] + ' ' + ' '.join(w.text for w in words)
            m = re.search(r'(?i)\[(?:system\.)?environment\]::getenvironmentvariable(s?)\b\s*\(?\s*[\'"]?([A-Za-z0-9_]*)', joined_ps)
            if m and (m.group(1) or ctx.c.secret_name(m.group(2) or 'X_TOKEN') or not m.group(2)) \
                    and self.out_visible(pl, idx, True):
                ctx.secret_seen += 1
                ctx.add(SECRET_DUMP, 'env-dump', '[Environment]::GetEnvironmentVariable(s) prints environment values',
                        'test presence with [string]::IsNullOrEmpty($env:NAME)')
        if head.vars and not head.quoted and re.search(r'\s', head.text) and all(v in ctx.vars for v in head.vars) \
                and not getattr(self, '_resplit', False):
            # `R="rm -rf"; $R path`: an unquoted expansion is split into words, so it names a command plus flags
            rebuilt = head.text + ' ' + ' '.join(_quote_for_rebuild(w.text) for w in words[1:])
            self._resplit = True
            try:
                self.script(rebuilt, depth + 1, tail_visible=ctx.tail_visible)
            finally:
                self._resplit = False
            return
        names = self.names_for(head)
        which = self._which_name(head)
        if which:
            names = [which]
        if head.dynamic and not head.text.strip('') or (head.dynamic and any(v not in ctx.vars for v in head.vars) or SUB_MARK in head.text):
            # unresolved command word: judge the whole line as text
            joined = ' '.join(w.text for w in words)
            for f in fallback_scan(joined, ctx.c):
                ctx.findings.append(f)
            for w in words:
                pass
        for name in names:
            self.apply(name, words, cmd, pl, idx, depth)

    def _which_name(self, head):
        """`$(which rm)`, `$(command -v rm)`, `` `type -p rm` ``: the named command."""
        if len(head.subs) != 1 or head.text.replace(SUB_MARK, '').strip():
            return None
        m = re.fullmatch(r'\s*(?:which|command\s+-[vV]|type\s+-[pP]|whence\s+-p)\s+([^\s;|&]+)\s*', head.subs[0])
        return norm_name(m.group(1)) if m else None

    def names_for(self, head):
        out = []
        for alt in head.alts[:32]:
            name = norm_name(alt)
            if head.glob or any(ch in name for ch in '*?['):
                for known in KNOWN_NAMES:
                    if _fnmatchcase(known, name):
                        out.append(known)
            if name:
                out.append(name)
        seen, uniq = set(), []
        for n in out:
            if n not in seen:
                seen.add(n)
                uniq.append(n)
        return uniq[:40]

    def apply(self, name, words, cmd, pl, idx, depth):
        ctx = self.ctx
        args = words[1:]
        texts = [a.text for a in args]
        self.credential_entry(cmd, name, words, args, texts)
        if ctx.ps:
            name = {'remove-item': 'rm', 'ri': 'rm', 'del': 'rm', 'erase': 'rm', 'rd': 'rm', 'move-item': 'mv',
                    'mi': 'mv', 'move': 'mv', 'gc': 'cat', 'get-content': 'cat', 'type': 'cat', 'clear-content': 'truncate',
                    'clc': 'truncate', 'set-content': 'set-content', 'sc': 'set-content'}.get(name, name)
        # aliases defined earlier on this line
        if name in ctx.aliases:
            rebuilt = ctx.aliases[name] + ' ' + ' '.join(_quote_for_rebuild(t) for t in texts)
            self.script(rebuilt, depth + 1, tail_visible=ctx.tail_visible)
            return
        if name == 'alias':
            for t in texts:
                if '=' in t:
                    k, _, v = t.partition('=')
                    ctx.aliases[k] = v
            return
        if name in ('cd', 'pushd', 'set-location', 'sl', 'chdir'):
            self.chdir(args)
            return
        if name in ('read', 'mapfile', 'readarray'):
            # `... | while read f`: the variable holds whatever the upstream stage printed
            if not hasattr(ctx, 'flow_vars'):
                ctx.flow_vars = set()
            for a in args:
                if re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', a.text):
                    ctx.flow_vars.add(a.text)
                    ctx.vars.pop(a.text, None)
            return
        if name in ('popd', 'pop-location'):
            ctx.cwd_unknown = True
            return
        if name in ('eval', 'invoke-expression', 'iex'):
            self.eval_words(args, depth, pl, idx)
            return
        if self.package_runner(name, args, depth, pl, idx):
            return
        if name in ('.', 'source'):
            nd = _nondash(args)
            if nd:
                if nd[0].subs:
                    self.program_text(nd[0], depth)  # source <(echo ...)
                else:
                    self.script_file(nd[0], depth)
            return
        if '/' in name or '/' in words[0].text:
            # ./run.sh or /path/to/script: analyse the script text when it is a shell script
            self.script_file(words[0], depth, require_shell=True)
        if name in ('flock', 'unshare', 'parallel', 'tmux', 'screen', 'osascript', 'at', 'batch', 'script'):
            if self.launcher(name, args, depth, pl, idx):
                return
        if name == 'busybox' and args and not args[0].text.startswith('-') \
                and norm_name(args[0].text) not in ('sh', 'ash', 'hush'):
            self.dispatch(args, cmd, pl, idx, depth)  # busybox APPLET ARGS runs the applet
            return
        if name == 'gio' and args and args[0].text in ('trash', 'remove', 'rm'):
            for w in _nondash(args[1:]):
                self.refuse('gio ' + args[0].text, w)
            return
        if name == 'sponge':
            for w in _nondash(args):
                if not self.state_dest(w):
                    self.overwrite_dest('sponge', w)
        if name == 'sort':
            for k, a in enumerate(args):
                val = args[k + 1] if (a.text == '-o' or re.fullmatch(r'-[A-Za-z]*o', a.text)) and k + 1 < len(args) \
                    else (_literal_word(a.text.split('=', 1)[1]) if a.text.startswith('--output=') else None)
                if val is not None and not self.state_dest(val):
                    self.overwrite_dest('sort -o', val)
        if name in ('fd', 'fdfind'):
            texts_ = [a.text for a in args]
            for k, t in enumerate(texts_):
                if t in ('-x', '-X', '--exec', '--exec-batch') and k + 1 < len(texts_):
                    inner = norm_name(texts_[k + 1])
                    if inner in RM_CMDS or inner in MV_CMDS or inner in ('truncate', 'shred'):
                        pos = [a for a in args[:k] if not a.text.startswith('-')]
                        for w in pos[1:] or pos:
                            self.refuse('fd --exec ' + inner, w)
                    break
        if name in SHELLS or name in PS_SHELLS:
            self.shell(name, args, depth, pl, idx)
            return
        if name == 'ssh' or name == 'mosh':
            self.ssh(args, depth)
            return
        if name in ('docker', 'podman', 'nerdctl', 'kubectl', 'oc'):
            self.secret_clis(name, [a.text for a in args], visible=self.out_visible(pl, idx, True))
            self.container(name, args, words, depth, pl, idx)
            return
        if name.startswith('docker-credential-') and 'get' in [a.text for a in args] \
                and self.out_visible(pl, idx, True):
            ctx.secret_seen += 1
            ctx.add(SECRET_DUMP, 'docker-credential', '%s get prints the stored registry password' % name[:40],
                    'docker login status: docker info, or test with docker pull')
            return
        if name == 'goodqa':
            self.goodqa(args, depth, pl, idx)
            return
        if name in WRAPPERS_SIMPLE or name in ('su', 'sg', 'runuser'):
            self.wrapper(name, args, depth, pl, idx)
            return
        if name == 'find':
            self.find(args, depth, pl, idx)
            return
        if name == 'git':
            self.git(args, words, cmd.words)
        if name == 'rclone':
            self.rclone(args, pl, idx)
        elif name == 'security':
            self.security(args)
        elif name in ('printenv', 'env', 'set', 'export', 'declare', 'typeset', 'readonly', 'compgen', 'get-childitem', 'ls', 'dir', 'gci', 'get-item', 'ps', 'launchctl'):
            self.env_dump(name, args, pl, idx)
        if name in ECHO_CMDS or name in ('cat',):
            self.echo_check(name, args, pl, idx)
        self.secret_clis(name, texts, visible=self.out_visible(pl, idx, True))
        if name in INTERPRETERS or name in ('awk', 'gawk', 'mawk', 'nawk'):
            self.interpreter(name, args, texts, depth)
        if (name.startswith('python') or name.startswith('pypy')) and '-m' in texts:
            # python3 -m json.tool FILE (and other printing modules) prints the file
            k = texts.index('-m')
            if k + 1 < len(texts) and texts[k + 1] in ('json.tool', 'base64', 'tokenize', 'pickletools', 'quopri',
                                                       'uu', 'zipfile', 'tarfile', 'gzip', 'http.server'):
                self.read_creds('cat', args[k + 2:], pl, idx)
        if name in PRINT_FILE_CMDS or name in GREP_CMDS or name in EXFIL_CMDS or name in ('openssl', 'source'):
            self.read_creds(name, args, pl, idx)
        if name in RM_CMDS or name in MV_CMDS or name in OVERWRITE_CMDS or name in (
                'sed', 'perl', 'ruby', 'awk', 'gawk', 'rsync', 'scp', 'rclone', 'tar', 'zip', 'dd', 'truncate', 'set-content',
                'out-file', 'curl', 'wget', 'touch', 'mkdir', 'unzip', 'bsdtar', 'gtar'):
            self.destructive(name, args, texts)
        if not (name in PRINT_FILE_CMDS or name in GREP_CMDS or name in EXFIL_CMDS):
            self.unlisted_cred_reader(name, args, cmd, pl, idx)
        if name in KILLERS:
            self.kill_cmd(name, args, texts)

    def credential_entry(self, cmd, name, words, args, texts):
        """Add a refusal when this command runs an existing script that names a credential (goodqa#14518). Only ever adds a
        finding, and any failure here means no finding, so no other rule's verdict changes."""
        if self.disk_depth:
            return
        if not self.credential_pass:
            # main's pass only notes that a script is run, so the check's pass is skipped for commands that run none.
            # Nothing here reads a file or adds a finding, and the alarm's TimeoutError is not caught.
            if not self.credential_candidate:
                try:
                    self.credential_candidate = any(w is not None and not w.dynamic and w.text
                                                    for w, _ in self._credential_words(cmd, name, words, args, texts))
                except (IndexError, AttributeError, TypeError, ValueError):
                    self.credential_candidate = True
            return
        try:
            for word, runner in self._credential_words(cmd, name, words, args, texts):
                if word is not None and not word.dynamic and word.text:
                    self.credential_script(norm_path(word.text, self.ctx), runner)
        except Blocked:
            raise
        except Exception:  # noqa: BLE001
            return

    def _credential_words(self, cmd, name, words, args, texts):
        if self.ctx.ps:
            return
        if name in ('.', 'source'):
            nd = _nondash(args)
            yield (nd[0] if nd else None), 'shell'
        if '/' in name or '/' in words[0].text:
            yield words[0], None
        if name in SHELLS:
            at = shell_script_word(texts)
            yield (args[at] if at is not None else None), 'shell'
            for r in cmd.redirs:
                if r.op == '<' and r.fd in (None, '0') and not any(t.startswith('-') and 'c' in t for t in texts):
                    yield r.target, 'shell'
        if PYTHON_NAME.fullmatch(name):
            at = python_script_word(texts)
            yield (args[at] if at is not None else None), 'python'

    def credential_script(self, path, runner=None):
        """`runner` is 'shell' or 'python' when one was named to run this file, so its name says nothing about what it is."""
        lower = path.lower()
        base = os.path.basename(path)
        in_tests = os.path.basename(os.path.dirname(path)) == 'tests' and base.startswith('test_') and base.endswith('.py')
        if base in GUARD_OWN_FILES or in_tests or lower.endswith(CREDENTIAL_DATA_SUFFIXES):
            return  # these hold the names as data
        # Each (path, runner) is read once per pass, so the second shell reading of `>!` repeats no read.
        seen = self.__dict__.setdefault('credential_seen', {})
        if (path, runner) in seen:
            if seen[(path, runner)]:
                self._credential_finding()
            return
        seen[(path, runner)] = False
        if time.monotonic() > self.ctx.budget.deadline:
            return  # the pass is out of time: start no new read
        try:
            if not os.path.isfile(path):
                return
            data = _read_prefix(path, CREDENTIAL_SCRIPT_READ)
            shebang = CREDENTIAL_SCRIPT_SHEBANG.match(data)
            if b'\0' in data or (runner is None and not lower.endswith(CREDENTIAL_SCRIPT_SUFFIXES) and not shebang):
                return  # a data file or a binary, not a script
            python = runner == 'python' or (runner is None and (lower.endswith('.py') or (shebang and b'python' in shebang.group())))
            code = b'\n'.join(line for line in data.split(b'\n') if not line.lstrip().startswith(b'#'))
            if (CREDENTIAL_PYTHON_TEXT if python else CREDENTIAL_SHELL_TEXT).search(code):
                seen[(path, runner)] = True
                self._credential_finding()
        except (OSError, ValueError):
            return

    def _credential_finding(self):
        self.ctx.add(SECRET_DUMP, 'credential-script', 'this script names a credential file or secret, and only a '
                     'pinned route may run one', 'read the task for a pinned route, or take a path that does not need this credential')

    def script_file(self, word, depth, require_shell=False):
        """Analyse a shell script named on the command line (or written earlier in this command)."""
        ctx = self.ctx
        if word is None or word.dynamic or not word.text:
            return
        path = norm_path(word.text, ctx)
        key = path.casefold()
        if key in ctx.written:
            # the disk first: in the reading where the disk is what runs, the recorded text never ran, so its cd or
            # alias must not colour this read
            if key in ctx.one_sided:
                self._script_on_disk(path, depth, require_shell)
            self.script(ctx.written[key], depth + 1, tail_visible=True)
            return
        self._script_on_disk(path, depth, require_shell)

    def _script_on_disk(self, path, depth, require_shell):
        ctx = self.ctx
        ctx.files_read = getattr(ctx, 'files_read', 0) + 1
        if ctx.files_read > 8:
            return
        try:
            if not os.path.isfile(path) or os.path.getsize(path) > 262144:
                return
            with open(path, 'rb') as handle:
                data = handle.read(262145)
        except (OSError, ValueError):
            return
        text = data.decode('utf-8', 'replace')
        if require_shell:
            first = text.split('\n', 1)[0]
            if not (first.startswith('#!') and re.search(r'\b(?:ba|z|k|da|)sh\b', first)) \
                    and not path.endswith(('.sh', '.bash', '.zsh')):
                return
        # An existing script is the repository's own tooling: its deletions of protected logs count, and so do
        # reads of credential material itself (SCRIPT_CREDENTIAL_RULES: a private key, a credentials file, a
        # keychain or credential-helper dump). Its environment handling and secret lookups are routine there
        # (replay false positives), and what it prints is not knowable from here. Scripts written earlier in this
        # same command are judged in full.
        # It also runs as its own process, so its cd, variables and recorded files do not carry into this command.
        before = len(ctx.findings)
        keep = {k: (v.copy() if isinstance(v, (set, dict, list)) else v) for k, v in vars(ctx).items()
                if k not in ('findings', 'budget', 'c', 'marker', 'files_read', 'unterminated', 'readings_capped')}
        self.disk_depth += 1
        try:
            self.script(text, depth + 1, tail_visible=True)
        finally:
            self.disk_depth -= 1
            for k, v in keep.items():
                setattr(ctx, k, v)
            ctx.findings[before:] = [f for f in ctx.findings[before:] if f.category == LOG_DELETE
                                     or f.category == SECRET_DUMP and f.rule in SCRIPT_CREDENTIAL_RULES]

    def launcher(self, name, args, depth, pl, idx):
        """Commands that run another command given as text or as trailing words. True when handled."""
        texts = [a.text for a in args]
        if name == 'flock':
            for k, t in enumerate(texts):
                if t in ('-c', '--command') and k + 1 < len(texts):
                    self.script(texts[k + 1], depth + 1, tail_visible=True)
                    return True
            pos = [k for k, t in enumerate(texts) if not t.startswith('-')]
            if len(pos) >= 2:
                self.inner_words(args[pos[1]:], depth, pl, idx)
            return True
        if name in ('unshare', 'script'):
            for k, t in enumerate(texts):
                if (t in ('-c', '--command') or name == 'script' and re.fullmatch(r'-[A-Za-z]*c', t)) \
                        and k + 1 < len(texts):
                    self.script(texts[k + 1], depth + 1, tail_visible=True)
                    return True
                if t.startswith('--command='):
                    self.script(t.split('=', 1)[1], depth + 1, tail_visible=True)
                    return True
            k = 0
            while k < len(texts) and texts[k].startswith('-'):
                k += 1
            if name == 'unshare' and k < len(args):
                self.inner_words(args[k:], depth, pl, idx)
            return True
        if name == 'parallel':
            if ':::' in texts:
                cut = texts.index(':::')
                head = [t for t in texts[:cut] if not t.startswith('-')]
                for item in texts[cut + 1:][:32]:
                    self.script(' '.join(head).replace('{}', _quote_for_rebuild(item)) + ' ' +
                                _quote_for_rebuild(item), depth + 1, tail_visible=True)
            else:
                k = 0
                while k < len(texts) and texts[k].startswith('-'):
                    k += 1
                if k < len(args):
                    self.inner_words(args[k:], depth, pl, idx)
            return True
        if name in ('tmux', 'screen'):
            if 'send-keys' in texts or 'send' in texts or 'stuff' in texts:
                payload = [t for t in texts if not t.startswith('-') and t not in ('send-keys', 'send', 'stuff', 'Enter', 'C-m')]
                self.script(' '.join(payload[1:] if 'send-keys' in texts and len(payload) > 1 else payload),
                            depth + 1, tail_visible=True)
            return False
        if name == 'osascript':
            for t in texts:
                for m in re.finditer(r'do shell script\s+"((?:[^"\\]|\\.)*)"', t, re.I):
                    self.script(m.group(1).replace('\\"', '"'), depth + 1, tail_visible=True)
            return False  # interpreter() still text-scans the AppleScript (Finder delete)
        if name in ('at', 'batch'):
            return False  # the heredoc body is analysed by heredoc()
        return False

    # ---- wrappers
    def wrapper(self, name, args, depth, pl, idx):
        ctx = self.ctx
        texts = [a.text for a in args]
        i = 0
        if name == 'env':
            while i < len(args):
                t = texts[i]
                if t == '-S' or t == '--split-string':
                    if i + 1 < len(args):
                        self.script(texts[i + 1] + ' ' + ' '.join(_quote_for_rebuild(x) for x in texts[i + 2:]), depth + 1)
                    return
                if t.startswith('-S') and len(t) > 2:
                    self.script(t[2:] + ' ' + ' '.join(_quote_for_rebuild(x) for x in texts[i + 1:]), depth + 1)
                    return
                if t in ('-C', '--chdir') and i + 1 < len(args):
                    self.chdir([args[i + 1]])
                    i += 2
                elif t.startswith('--chdir='):
                    self.chdir([_literal_word(t.split('=', 1)[1])])
                    i += 1
                elif t in ('-u', '--unset'):
                    i += 2
                elif t.startswith('-') or re.match(r'^[A-Za-z_][A-Za-z0-9_]*=', t):
                    i += 1
                else:
                    break
            if i >= len(args):
                self.env_dump('env', [], pl, idx)
                return
        elif name == 'sudo' or name == 'doas':
            while i < len(args):
                t = texts[i]
                if t in ('-u', '-g', '-h', '-p', '-C', '-D', '-R', '-T', '-U', '--user', '--group', '--host', '--prompt', '--chdir'):
                    i += 2
                elif t in ('-s', '-i', '--shell', '--login') and i + 1 < len(args) and False:
                    break
                elif t.startswith('-') and t != '--':
                    i += 1
                else:
                    i += 1 if t == '--' else 0
                    break
        elif name in ('timeout',):
            while i < len(args) and (texts[i].startswith('-') or i == 0 and False):
                i += 2 if texts[i] in ('-s', '-k', '--signal', '--kill-after') else 1
            i += 1  # duration
        elif name in ('nice', 'ionice', 'chrt', 'taskset', 'stdbuf', 'caffeinate', 'watch', 'strace', 'ltrace', 'setsid', 'arch', 'nohup', 'unbuffer', 'dtruss', 'chroot', 'nsenter', 'firejail', 'sandbox-exec', 'script', 'gosu', 'runuser', 'su', 'sg', 'time', 'noglob', 'command', 'builtin', 'exec', 'start-process', 'start', 'call', 'invoke-command', 'icm'):
            valued = WRAPPER_VALUE_OPTS.get(name, ())
            while i < len(args) and texts[i].startswith('-'):
                i += 2 if texts[i] in valued else 1
            if name in ('chroot', 'gosu', 'runuser', 'sg', 'taskset', 'chrt'):
                i += 1
            if name == 'su':
                for j, t in enumerate(texts):
                    if t in ('-c', '--command') and j + 1 < len(args):
                        self.script(texts[j + 1], depth + 1)
                return
            if name in ('start-process', 'start', 'call'):
                pass
        elif name == 'xargs':
            self.xargs_input(args, pl.cmds[idx] if pl is not None and idx < len(pl.cmds) else None)
            while i < len(args) and texts[i].startswith('-'):
                i += 2 if texts[i] in ('-n', '-I', '-P', '-d', '-L', '-a', '-E', '-s', '-i', '-l') else 1
            if i < len(args):
                self.inner_words(args[i:], depth, pl, idx, via_xargs=True)
            else:
                pass
            return
        elif name in ('watch',):
            pass
        if i < len(args):
            self.inner_words(args[i:], depth, pl, idx)

    def xargs_input(self, args, cmd):
        """xargs deleting what its own input names: a here-string, `< <(..)` or `-a <(..)`."""
        joined = ' '.join(a.text for a in args)
        if not re.search(r'(?:^|[\s/])(?:rm|rmdir|unlink|shred|srm|mv|truncate|rimraf|trash(?:-put)?)(?:\s|$)', joined):
            return
        sources = [r.target for r in (cmd.redirs if cmd is not None else []) if r.target is not None and (
            r.op == '<<<' or (r.op in ('<', '<>') and r.fd in (None, '0') and r.target.subs))]
        for i, a in enumerate(args[:-1]):
            if a.text in ('-a', '--arg-file') and args[i + 1].subs:
                sources.append(args[i + 1])
        heredocs = [r.body for r in (cmd.redirs if cmd is not None else []) if r.op in ('<<', '<<-') and r.body]
        for body in heredocs:
            for line in body.splitlines()[:2000]:
                line = line.strip().strip('\'"')
                if line and self.refuse('xargs deletion of paths given in its heredoc', _literal_word(line)):
                    return  # each line is an operand, relative to the working directory
            if any(self._raw_path_class(m.group(0)) in ('log', 'root', 'ancestor', 'unknown')
                   for m in self.RAW_PATH.finditer(body[:200000])):
                self.ctx.add(LOG_DELETE, 'log-delete',
                             'xargs deletes paths given in its heredoc, and that heredoc names a protected harness '
                             'location', 'delete only paths inside your own task worktree, named directly')
                return
        for src in sources:
            if self.refuse('xargs deletion of paths given on its input', src):
                return
            bodies = [src.text] + list(src.subs)
            if any(self._raw_path_class(m.group(0)) in ('log', 'root', 'ancestor', 'unknown')
                   for body in bodies for m in self.RAW_PATH.finditer(body[:200000])):
                self.ctx.add(LOG_DELETE, 'log-delete',
                             'xargs deletes paths given on its input, and that input names a protected harness location',
                             'delete only paths inside your own task worktree, named directly')
                return

    def inner_words(self, words, depth, pl, idx, via_xargs=False):
        if not words:
            return
        cmd = Cmd()
        cmd.words = list(words)
        for name in self.names_for(words[0]):
            self.apply(name, words, cmd, pl, idx, depth + 1)
        if via_xargs and norm_name(words[0].text) in PRINT_FILE_CMDS:
            pass

    PKG_RUNNERS = {'npx': 0, 'bunx': 0, 'pnpx': 0, 'uvx': 0, 'pnpm': ('dlx', 'exec'), 'yarn': ('dlx', 'exec'),
                   'bun': ('x',), 'npm': ('exec', 'x'), 'pipx': ('run',)}
    PKG_DELETERS = {'del-cli': 'rm', 'trash-cli': 'trash', 'rimraf': 'rimraf', 'del': 'rm', 'trash': 'trash'}
    PKG_PASSTHROUGH = set(PKG_DELETERS) | {'shx', 'cross-env', 'trash-put'}

    def package_runner(self, name, args, depth, pl, idx):
        """`npx rimraf PATH`, `pnpm dlx del-cli PATH`, `uvx trash-cli PATH`: the package runs as a command."""
        if name == 'shx' and args:
            self.inner_words(list(args), depth, pl, idx)  # shx rm -rf PATH: the first word is the command
            return True
        if name == 'cross-env':
            rest = list(args)
            while rest and (rest[0].text.startswith('-') or re.match(r'^[A-Za-z_][A-Za-z0-9_]*=', rest[0].text)):
                rest = rest[1:]
            if rest:
                self.inner_words(rest, depth, pl, idx)
            return True
        if name == 'cross-env-shell':
            self.script(' '.join(a.text for a in args if not re.match(r'^[A-Za-z_][A-Za-z0-9_]*=', a.text)),
                        depth + 1, tail_visible=True)  # cross-env-shell 'cmd': the string runs in a shell
            return True
        sub = self.PKG_RUNNERS.get(name)
        if sub is None:
            return False
        i = 0
        if sub:
            if args and name in ('yarn', 'pnpm') and norm_name(args[0].text) in self.PKG_PASSTHROUGH:
                i = 0  # `yarn rimraf PATH`: a package bin run directly
            elif len(args) > 1 and name in ('yarn', 'pnpm') and args[0].text == 'run' \
                    and norm_name(args[1].text) in self.PKG_PASSTHROUGH:
                i = 1  # `yarn run rimraf PATH`
            elif not args or args[0].text not in sub:
                return False
            else:
                i = 1
        while i < len(args):
            t = args[i].text
            if t == '--':
                i += 1
                break
            if t in ('-c', '--call', '-x', '--shell') and i + 1 < len(args):
                self.script(args[i + 1].text, depth + 1, tail_visible=True)
                i += 2
            elif t in ('-p', '--package', '--from', '--spec', '--python', '--with') and i + 1 < len(args):
                i += 2
            elif t.startswith('-'):
                i += 1
            else:
                break
        if i >= len(args):
            return True
        pkg = re.sub(r'(?<=.)@[^/]*$', '', args[i].text)  # rimraf@5, @scope/tool@1.2
        base = norm_name(pkg.rsplit('/', 1)[-1])
        head = _literal_word(self.PKG_DELETERS.get(base, base))
        self.inner_words([head] + list(args[i + 1:]), depth, pl, idx)
        return True

    def eval_words(self, args, depth, pl, idx):
        text = ' '.join(a.text for a in args)
        for a in args:
            if a.subs:
                self.program_text(a, depth)  # eval "$(echo rm ...)": the substitution's output is the program
            if any(self._decoder_in(s) for s in a.subs):
                self.ctx.add(SECRET_DUMP, 'obfuscated-eval', 'eval of decoded (obfuscated) text hides the command from the guard',
                             'write the command in plain text')
        self.script(text, depth + 1, tail_visible=True)

    def _decoder_in(self, script):
        return bool(re.search(r'\b(?:base64|base32|xxd|openssl)\b[^|;&]*(?:\s-d\b|\s-D\b|--decode|\s-r\b|-base64)', script))

    def program_text(self, word, depth):
        """A shell program given as `$(..)` or `<(..)`: judge what the inner command prints. Literal
        echo/printf text is analysed as a script; anything else is scanned as raw text, and a decoder
        stage means the program is hidden."""
        ctx = self.ctx
        for inner in word.subs:
            if self._decoder_in(inner):
                ctx.add(SECRET_DUMP, 'obfuscated-shell-input',
                        'a shell is fed a decoded (obfuscated) program, so the guard cannot see what runs',
                        'write the command in plain text')
                return
            m = re.match(r'\s*(echo|printf|print)\s+(.*)$', inner, re.S)
            if m:
                body = re.sub(r'^(?:-[neE]+\s+)+', '', m.group(2))
                body = body.strip().strip('\'"')
                self.script(decode_ansi(body) if m.group(1) == 'printf' else body, depth + 1, tail_visible=True)
            for f in fallback_scan(inner, ctx.c):
                ctx.findings.append(f)

    def shell_stdin(self, cmd, depth):
        """`bash <<< 'text'`, `sh < file`: the shell reads its program from the redirect."""
        for r in cmd.redirs:
            if r.op == '<<<' and r.target is not None:
                if r.target.subs:
                    self.program_text(r.target, depth)
                self.script(r.target.text, depth + 1, tail_visible=True)
            elif r.op == '<' and r.fd in (None, '0') and r.target is not None:
                if r.target.subs:
                    self.program_text(r.target, depth)
                else:
                    self.script_file(r.target, depth)

    def shell(self, name, args, depth, pl, idx):
        texts = [a.text for a in args]
        ps = name in PS_SHELLS
        for i, t in enumerate(texts):
            is_c = (not ps and (t == '-c' or (re.fullmatch(r'-[a-zA-Z]*c[a-zA-Z]*', t) is not None) or t.startswith('--command'))) \
                or (ps and t.lower() in ('-c', '-command', '-encodedcommand', '-e', '-ec') or ps and t.lower() == '/c')
            if is_c and i + 1 < len(texts):
                payload = ' '.join(texts[i + 1:]) if ps else texts[i + 1]
                if ps and t.lower() in ('-encodedcommand', '-e', '-ec'):
                    try:
                        import base64
                        payload = base64.b64decode(payload + '=' * (-len(payload) % 4)).decode('utf-16-le', 'replace')
                    except Exception:  # noqa: BLE001
                        self.ctx.add(SECRET_DUMP, 'obfuscated-shell-input', 'encoded PowerShell cannot be inspected', 'pass the command in plain text')
                        return
                if not ps and args[i + 1].subs:
                    self.program_text(args[i + 1], depth)
                self.script(payload, depth + 1, tail_visible=True, ps=ps)
                return
        if not ps:
            self.shell_stdin(pl.cmds[idx], depth)
        # `bash script.sh`: read and analyse the script; `bash -s` + heredoc is handled by heredoc()
        if not ps:
            k = 0
            while k < len(args) and args[k].text.startswith('-'):
                k += 2 if args[k].text in ('-o', '+o', '-O', '+O', '--rcfile', '--init-file') else 1
            if k < len(args):
                if args[k].subs:
                    self.program_text(args[k], depth)  # bash <(echo ...)
                else:
                    self.script_file(args[k], depth)

    def ssh(self, args, depth):
        texts = [a.text for a in args]
        value_opts = set('bcDEeFIiJLlmOopQRSWw')
        i, host_seen = 0, False
        while i < len(texts):
            t = texts[i]
            if not host_seen:
                if t.startswith('-') and len(t) > 1:
                    flag = t[1]
                    if t[1:] and flag in value_opts and len(t) == 2:
                        i += 2
                    else:
                        i += 1
                    continue
                host_seen = True
                i += 1
                break
            i += 1
        rest = texts[i:]
        if rest and rest[0] == '--':
            rest = rest[1:]
        if rest:
            self.script(' '.join(rest), depth + 1, tail_visible=True)

    def container(self, name, args, words, depth, pl, idx):
        texts = [a.text for a in args]
        if name in ('docker', 'podman', 'nerdctl'):
            if 'exec' in texts:
                k = texts.index('exec')
                opts = {'-e', '--env', '-u', '--user', '-w', '--workdir', '--env-file', '--detach-keys'}
                j = k + 1
                while j < len(texts) and texts[j].startswith('-'):
                    j += 2 if texts[j] in opts else 1
                j += 1  # container name
                if j < len(texts):
                    self.inner_words(args[j:], depth, pl, idx)
            elif 'run' in texts:
                k = texts.index('run')
                opts = {'-e', '--env', '-u', '--user', '-w', '--workdir', '-v', '--volume', '--name', '-p', '--publish', '--entrypoint', '--network', '-l', '--label', '--env-file', '--mount', '--platform', '-m', '--memory'}
                j = k + 1
                while j < len(texts) and texts[j].startswith('-'):
                    j += 2 if texts[j] in opts else 1
                j += 1  # image
                if j < len(texts):
                    self.inner_words(args[j:], depth, pl, idx)
        else:
            if 'exec' in texts and '--' in texts:
                self.inner_words(args[texts.index('--') + 1:], depth, pl, idx)
            elif 'get' in texts and any(t in ('secret', 'secrets') for t in texts):
                self.secret_clis(name, texts)

    def goodqa(self, args, depth, pl, idx):
        ctx = self.ctx
        texts = [a.text for a in args]
        if any(t == '--reveal' or t.startswith('--reveal=') for t in texts):
            ctx.secret_seen += 1
            ctx.add(SECRET_DUMP, 'goodqa-reveal', 'goodqa --reveal prints secret values into the transcript',
                    'goodqa secrets list (names only) or goodqa run --secrets NAME -- <command> (value stays in that command)')
        if 'run' in texts and '--' in texts:
            self.inner_words(args[texts.index('--') + 1:], depth, pl, idx)

    def chdir(self, args):
        ctx = self.ctx
        pos = _nondash(args)
        if not pos:
            ctx.cwd = ctx.home
            ctx.cwd_unknown = ctx.cwd_protected_unknown = False
            ctx.cwd_known = True
            return
        word = pos[0]
        target = word.text
        if target == '-' or is_dynamic_path(target) or word.dynamic:
            ctx.cwd_unknown = True
            ctx.cwd_protected_unknown = bool(PROTECTED_TEXT.search(target) or self._hint_points_at_protected(word))
            return
        if ctx.cwd_unknown and not target.startswith(('/', '~')):
            # relative to a directory the guard could not resolve: still unknown, and a protected name stays visible
            ctx.cwd_protected_unknown = ctx.cwd_protected_unknown or bool(PROTECTED_TEXT.search(target))
            return
        if target.startswith(('/', '~')):
            ctx.cwd_known = True
        ctx.cwd = norm_path(target, ctx, ctx.cwd)
        ctx.cwd_unknown = ctx.cwd_protected_unknown = False

    # ---- find
    def find(self, args, depth, pl, idx):
        ctx = self.ctx
        texts = [a.text for a in args]
        roots = []
        k = 0
        # leading global options come before the start directories: GNU -P -H -L -D ARG -O<n>, BSD -E -X -d -s -x
        # -f ROOT, and `--`; skipping them keeps `find -P ~/.claude ...` from defaulting to `.`
        while k < len(args):
            t = texts[k]
            if t in ('-P', '-H', '-L', '-E', '-X', '-d', '-s', '-x', '--') or re.fullmatch(r'-O\d*', t) \
                    or re.fullmatch(r'-[EHLPXdsx]+', t):
                k += 1  # BSD getopt also accepts clusters such as -xd or -sE
            elif t.startswith('-f') and len(t) > 2:
                # BSD -fPATH, or a GNU expression such as -fprint, -fls, -false: judge both readings (the attached
                # path and the default `.`) and stop scanning options, since what follows is an expression
                roots.append(_literal_word(t[2:]))
                default_root = Word()
                default_root.alts = ['.']
                roots.append(default_root)
                break
            elif t == '-D' and k + 1 < len(args):
                k += 2
            elif t == '-f' and k + 1 < len(args):
                roots.append(args[k + 1])  # BSD: -f names a start directory
                k += 2
            else:
                break
        for a in args[k:]:
            if a.text.startswith('-') or a.text in ('(', '!', ')'):
                break
            roots.append(a)
        if '-files0-from' in texts:
            unknown = Word()
            unknown.alts = ['$FILES0_FROM']
            unknown.dynamic = True
            roots.append(unknown)  # start directories read from a file: not known to the guard
        if not roots:
            roots = [Word()]
            roots[0].alts = ['.']
        exec_cmds = []
        for i, t in enumerate(texts):
            if t in ('-exec', '-execdir', '-ok', '-okdir'):
                j = i + 1
                body = []
                while j < len(args) and texts[j] not in (';', '+', '\\;'):
                    body.append(args[j])
                    j += 1
                exec_cmds.append(body)
        destroyers = RM_CMDS | MV_CMDS | {'unlink', 'shred', 'truncate'}
        if '-delete' in texts or any(norm_name(b[0].text) in destroyers for b in exec_cmds if b):
            leading = texts[:k]
            if '-follow' in texts or any(re.fullmatch(r'-[EHLPXdsx]*L[EHLPXdsx]*', t) for t in leading):
                # following symlinks while deleting walks into whatever a link inside the tree points at
                ctx.add(LOG_DELETE, 'log-delete',
                        'find follows symlinks (-L or -follow) while deleting, so a link inside the tree can lead '
                        'into a protected harness location',
                        'drop -L/-follow; find does not need to follow links to clean a build tree')
            for r in roots:
                self.protected_target('find -delete/-exec', r)
        for body in exec_cmds:
            if not body:
                continue
            bname = norm_name(body[0].text)
            if bname in destroyers:
                # `-exec rm -rf ~/.claude/projects {} +`, `-exec mv {} ~/.claude/hooks/ \;`: the body's own operands
                for w in body[1:]:
                    if w.text in ('{}', ';', '+', '\\;') or w.text.startswith('-') or '{}' in w.text:
                        continue
                    self.protected_target('find -exec %s' % bname, w)
            if bname in PRINT_FILE_CMDS or bname in GREP_CMDS or bname in EXFIL_CMDS:
                for r in roots:
                    p = norm_path(r.text, ctx, ctx.cwd)
                    if self.under_cred_dir(p) or self.is_cred_path(r.text, r):
                        ctx.secret_seen += 1
                        if self.out_visible(pl, idx, True) and not (bname in GREP_CMDS and self._count_only(body[1:])):
                            ctx.add(SECRET_DUMP, 'find-exec-credentials',
                                    'find -exec prints files from a credential directory',
                                    'list names only: find DIR -name PATTERN -print')
            if bname in WRAPPERS_SIMPLE | SHELLS:
                cmd = Cmd()
                cmd.words = list(body)
                for name in self.names_for(body[0]):
                    self.apply(name, body, cmd, pl, idx, depth + 1)
        for r in roots:
            self.subs(r, depth, visible=False)

    # ---- git
    OWNED_CHANGES = frozenset(('checkout', 'switch', 'reset', 'pull', 'merge', 'rebase', 'clean', 'stash', 'restore',
                               'cherry-pick', 'revert', 'commit', 'am', 'apply', 'rm', 'mv', 'add', 'update-ref',
                               'symbolic-ref', 'read-tree', 'checkout-index', 'branch', 'tag', 'gc', 'prune', 'bisect',
                               'sparse-checkout', 'submodule', 'update-index', 'filter-branch', 'push', 'remote', 'config',
                               'notes', 'worktree', 'replace', 'reflog', 'fast-import', 'init', 'clone', 'lfs'))
    # with `-c alias.X=...` any subcommand outside this list may expand to a change
    OWNED_READ_SUBS = frozenset(('status', 'log', 'diff', 'show', 'ls-files', 'ls-tree', 'rev-parse', 'rev-list', 'describe',
                                 'blame', 'grep', 'cat-file', 'shortlog', 'show-ref', 'for-each-ref', 'merge-base', 'fetch',
                                 'version', 'help', 'check-ignore', 'name-rev', 'diff-tree', 'diff-index', 'count-objects'))

    def owned_checkout(self, sub, rest, cwd_word, locations=(), alias=False):
        """goodqa#15307: an agent's git command may not change a checkout a timer or service builds from. Owned means a
        `.harness-owned` marker in the directory or a parent (first line `owner: ...`, optional `branch: NAME`, default
        main), or a policy owned_checkouts suffix (for a checkout on another host the marker cannot be read from here).
        Reads, plain fetch and `git checkout|switch <declared branch>` stay allowed. `locations` are further places the
        command acts on: --work-tree, --git-dir (either spelling) and GIT_DIR / GIT_WORK_TREE."""
        ctx = self.ctx
        if not self._owned_change(sub, rest, alias):
            return
        where = ctx.cwd
        for word in (cwd_word if isinstance(cwd_word, list) else [cwd_word] if cwd_word is not None else []):
            where = norm_path(word.text, ctx, where)  # git -C a -C b: each is relative to the one before
        places = [where]
        for text in locations:
            path = norm_path(text, ctx, where)
            places.append(path[:-len('/.git')] if path.endswith('/.git') else path)
        for place in places:
            if not place or '$' in place:
                continue
            owner, branch = self.owned_dir(place)
            if owner is None:
                continue
            if sub in ('checkout', 'switch') and rest == [branch] and len(places) == 1:
                return
            ctx.add(LOG_DELETE, 'owned-checkout',
                    'git %s changes %s, a checkout owned by %s that a timer or service builds from' % (sub, place, owner),
                    'work in your own git worktree (git worktree add) or export (git archive); to restore the owner\'s state '
                    'use git checkout %s alone' % branch)
            return

    def _owned_change(self, sub, rest, alias):
        if alias and sub not in self.OWNED_READ_SUBS and sub not in self.OWNED_CHANGES:
            return True  # an alias.* from -c may expand to anything
        if sub == 'fetch':
            return '--update-head-ok' in rest or any(':' in t and not t.startswith('-') for t in rest)
        if sub not in self.OWNED_CHANGES:
            return False
        if sub == 'remote':
            return bool(rest) and rest[0] not in ('-v', '--verbose', 'show', 'get-url')
        if sub == 'config':
            return not any(t in ('--get', '--get-all', '--get-regexp', '--list', '-l', '--show-origin', '--get-urlmatch')
                           for t in rest)
        if sub == 'notes':
            return not rest or rest[0] not in ('show', 'list')
        if sub == 'worktree':
            return bool(rest) and rest[0] in ('remove', 'move', 'prune', 'lock', 'unlock', 'repair')
        if sub in ('reflog',):
            return bool(rest) and rest[0] in ('expire', 'delete')
        if sub in ('branch', 'tag'):
            return any(t in ('-d', '-D', '-f', '-m', '-M', '-c', '-C', '--delete', '--force', '--move', '--copy', '-u',
                             '--set-upstream-to', '--unset-upstream', '--edit-description') for t in rest) \
                or any(not t.startswith('-') for t in rest)
        return True

    def owned_dir(self, path):
        """(owner, branch) when path is inside an owned checkout, else (None, None)."""
        folded = path.replace('\\', '/').rstrip('/').casefold()
        for suffix in self.ctx.c.policy.get('owned_checkouts', []):
            suf = suffix.replace('\\', '/').strip('/').casefold()
            if suf and (folded.endswith('/' + suf) or ('/' + suf + '/') in folded + '/'):
                return 'policy:' + suffix, 'main'
        cur = path
        for _ in range(64):
            marker = os.path.join(cur, '.harness-owned')
            try:
                if os.path.isfile(marker):
                    owner, branch = 'a harness-owned marker', 'main'
                    with open(marker, encoding='utf-8', errors='replace') as handle:
                        for line in handle.read(4096).splitlines():
                            key, _, value = line.partition(':')
                            if key.strip() == 'owner' and value.strip():
                                owner = value.strip()[:80]
                            elif key.strip() == 'branch' and value.strip():
                                branch = value.strip()[:80]
                    return owner, branch
            except OSError:
                pass
            parent = os.path.dirname(cur)
            if parent == cur:
                break
            cur = parent
        return None, None

    def git(self, args, words, cmd_words=None):
        ctx = self.ctx
        texts = [a.text for a in args]
        i = 0
        cwd_word = None
        cwd_words = []
        locations = []
        alias = False
        while i < len(texts):
            t = texts[i]
            if t in ('-C', '-c', '--git-dir', '--work-tree', '--namespace', '--exec-path', '--super-prefix', '--config-env'):
                if t in ('-C', '--work-tree') and i + 1 < len(args):
                    cwd_word = args[i + 1]
                    if t == '-C':
                        cwd_words.append(args[i + 1])
                if t in ('--git-dir', '--work-tree') and i + 1 < len(args):
                    locations.append(args[i + 1].text)
                if t == '-c' and i + 1 < len(args) and args[i + 1].text.casefold().startswith('alias.'):
                    alias = True
                i += 2
            elif t.startswith(('--git-dir=', '--work-tree=')):
                locations.append(t.split('=', 1)[1])
                i += 1
            elif t.startswith('-'):
                i += 1
            else:
                break
        for assign in (cmd_words or ()):  # GIT_DIR=... GIT_WORK_TREE=... git ...
            m = re.match(r'(GIT_DIR|GIT_WORK_TREE)=(.+)$', assign.text if hasattr(assign, 'text') else str(assign))
            if m:
                locations.append(m.group(2))
        for name in ('GIT_DIR', 'GIT_WORK_TREE'):
            if isinstance(self.ctx.vars.get(name), str):
                locations.append(self.ctx.vars[name])
        sub = texts[i] if i < len(texts) else ''
        rest = texts[i + 1:]
        self.owned_checkout(sub, rest, cwd_words, locations, alias)
        if sub == 'clean':
            self.git_clean(args[i + 1:], rest, cwd_word)
        if sub == 'worktree' and rest[:1] == ['remove'] and self._removable_linked_worktree(args[i + 1:], cwd_words):
            return  # the only exemption: one literal, clean, published, registered linked-worktree top
        if sub == 'worktree' and rest[:1] in (['remove'], ['prune']):
            targets = _nondash(args[i + 2:])
            one_target = len(targets) == 1  # the verifier judged ONE path; with several its reason belongs to none
            for w in targets:
                refused = self.refuse('git worktree remove', w,
                                      instead=_worktree_instead(getattr(self, '_worktree_reason', None) if rest[:1] == ['remove'] and one_target else None))
                if rest[:1] == ['remove'] and not refused:
                    reason = getattr(self, '_worktree_reason', None) if one_target else None
                    ctx.add(LOG_DELETE, 'linked-worktree-remove',
                            'git worktree remove is allowed only for one verified clean, published, registered linked '
                            'worktree top; this target or command shape is not verified'
                            + (' (verifier: %s)' % _clean_reason(reason) if reason else ''),
                            _worktree_next_step(reason) or
                            'use the standalone literal non-forced form after cleaning and publishing the worktree')
        if sub == 'init' and rest:
            for w in _nondash(args[i + 1:])[-1:]:
                self.note_created(_join_word(w, '.git'))
        elif sub == 'init':
            self.note_created(_literal_word(posixpath.join(ctx.cwd, '.git')))
        if sub == 'config':
            letters = _flag_letters(args[i + 1:])
            longs = {t.split('=')[0] for t in rest if t.startswith('--')}
            if 'l' in letters and not rest[0:1] == ['--add'] or '--list' in longs:
                ctx.secret_seen += 1
                ctx.add(SECRET_DUMP, 'git-config-list', 'git config --list prints every key including credential helpers and URLs with embedded tokens',
                        'git config --get <one specific key>')
            elif '--get-regexp' in longs or '--get-urlmatch' in longs:
                pattern = ' '.join(t for t in rest if not t.startswith('-'))
                if re.search(r'(?i)cred|token|pass|secret|url|helper|auth|key|^\.\*|^\.|^\*', pattern or '.'):
                    ctx.secret_seen += 1
                    ctx.add(SECRET_DUMP, 'git-config-regexp', 'git config --get-regexp over credential/url keys can print embedded tokens',
                            'git config --get <one specific key>')
        elif sub == 'credential' and rest[:1] and rest[0] in ('fill', 'approve', 'reject', 'capability'):
            ctx.secret_seen += 1
            ctx.add(SECRET_DUMP, 'git-credential', 'git credential %s prints or handles the stored password' % rest[0],
                    'let git call its own credential helper during fetch/push')
        elif sub.startswith('credential-') and rest[:1] == ['get']:
            ctx.secret_seen += 1
            ctx.add(SECRET_DUMP, 'git-credential-helper', 'a credential helper `get` prints the stored password', 'let git call its helper itself')

    # ---- rclone
    def rclone(self, args, pl, idx):
        ctx = self.ctx
        texts = [a.text for a in args]
        low = [t.casefold() for t in texts]
        if any(t.startswith('--dump') for t in low):
            vals = [t.split('=', 1)[1] for t in low if t.startswith('--dump=')]
            vals += [t[len('--dump-'):] for t in low if t.startswith('--dump-')]
            for k, t in enumerate(low):
                if t == '--dump' and k + 1 < len(low):
                    vals.append(low[k + 1])
            if any(re.search(r'auth|headers|bodies', v) for v in vals):
                ctx.secret_seen += 1
                ctx.add(SECRET_DUMP, 'rclone-dump', 'rclone --dump headers/bodies/auth prints Authorization headers and tokens',
                        'use -v or --stats for progress; never --dump auth')
        nd = [t for t in low if not t.startswith('-')]
        if 'config' in nd:
            after = nd[nd.index('config') + 1:]
            sub = after[0] if after else ''
            secret_args = (not after or sub == 'password' or sub == 'create' and len(after) > 3
                           or sub == 'update' and len(after) > 2)
            if secret_args or any(a in ctx.c.rclone_blocked for a in after[:2]):
                ctx.secret_seen += 1
                ctx.add(SECRET_DUMP, 'rclone-config-dump',
                        'rclone config show/dump/reconnect prints OAuth access and refresh tokens into the transcript',
                        # goodqa#15122: never name a form this guard blocks (rclone config file is blocked above)
                        'rclone listremotes (names), rclone lsd dropbox: (access check), command_guard.py doctor '
                        '(where the config lives)')
        if nd[:1] in (['authorize'], ['reveal']) or (nd and nd[0] in ('authorize', 'reveal')):
            ctx.secret_seen += 1
            ctx.add(SECRET_DUMP, 'rclone-authorize', 'rclone authorize/reveal prints tokens or passwords',
                    'rclone listremotes; ask the user to run authorize in their own terminal')

    def security(self, args):
        ctx = self.ctx
        texts = [a.text for a in args]
        nd = [t for t in texts if not t.startswith('-')]
        sub = nd[0] if nd else ''
        letters = _flag_letters(args)
        if sub in ('find-generic-password', 'find-internet-password', 'find-key', 'find-certificate') and (letters & set('wg') or sub == 'find-key' and 'w' in letters):
            ctx.secret_seen += 1
            ctx.add(SECRET_DUMP, 'keychain-password', 'security %s -w/-g prints the stored password' % sub,
                    'security find-generic-password -s SERVICE (without -w/-g) checks that an item exists')
        elif sub == 'dump-keychain' and 'd' in letters:
            ctx.secret_seen += 1
            ctx.add(SECRET_DUMP, 'keychain-dump', 'security dump-keychain -d prints decrypted keychain items', 'security list-keychains')

    GH_TOKEN_BANNED_SUBS = {'auth', 'config', 'extension', 'extensions', 'ext', 'alias', 'secret'}

    def _gh_sub_ok(self, args):
        for a in args:
            if a.dynamic:
                return False
            if a.text.startswith('-'):
                continue
            return a.text.casefold() not in self.GH_TOKEN_BANNED_SUBS
        return False

    def secret_clis(self, name, texts, visible=True):
        ctx = self.ctx
        nd = [t for t in texts if not t.startswith('-')]
        joined = ' '.join(texts).casefold()
        for binary, required, extra, alt in SECRET_CLIS:
            if name != binary or alt is None:
                continue
            if required and not _is_subseq(required, [t.casefold() for t in nd]):
                continue
            if extra and not re.search(extra, joined):
                continue
            ctx.secret_seen += 1
            if binary == 'gh' and required == ('auth', 'token'):
                if not visible and ctx.token_sink_ok:
                    ctx.token_allowed += 1
                    return  # VAR=$(gh auth token) gh <subcommand>: the value goes straight into gh's environment
            elif not visible and binary in ('aws', 'gcloud', 'az', 'op', 'heroku', 'fly', 'flyctl'):
                return  # the value goes into a variable or a --password-stdin sink, not the transcript
            ctx.add(SECRET_DUMP, '%s-secret' % binary, '%s %s prints a secret value into the transcript' % (binary, ' '.join(required) or 'decrypt'), alt)
            return

    # ---- environment dumps
    def env_dump(self, name, args, pl, idx):
        ctx = self.ctx
        texts = [a.text for a in args]
        nd = [a.text for a in _nondash(args)]
        dump = False
        if name == 'printenv':
            if not nd:
                dump = True
            else:
                for t in nd:
                    if ctx.c.secret_name(t):
                        ctx.secret_seen += 1
                        ctx.add(SECRET_DUMP, 'printenv-secret', 'printenv %s prints a secret environment variable' % t[:40],
                                'test it with `[ -n "$%s" ]`' % t[:40])
        elif name == 'env':
            dump = not [t for t in texts if not t.startswith('-') or t in ('-i',)] or all(t.startswith('-') for t in texts)
        elif name == 'set':
            dump = not texts
        elif name in ('export', 'declare', 'typeset', 'readonly'):
            letters = _flag_letters(args)
            dump = (not nd) and (name == 'export' and (not texts or letters & {'p'}) or name != 'export' and letters & {'p', 'x'})
        elif name == 'compgen':
            dump = False
        elif name in ('get-childitem', 'ls', 'dir', 'gci', 'get-item'):
            if ctx.ps and any(re.match(r'(?i)^env:?(?:\\\*?)?$', t) or t.lower().startswith('env:') for t in texts):
                dump = not any(re.search(r'(?i)^env:[\\/]?[A-Za-z_]', t) and not ctx.c.secret_name(re.sub(r'(?i)^env:[\\/]?', '', t)) for t in texts)
        elif name == 'ps':
            for a in args:
                t = a.text
                if t and (not t.startswith('-') and 'e' in t and re.fullmatch(r'[a-zA-Z]+', t)
                          or re.fullmatch(r'-[A-Za-z]*E[A-Za-z]*', t)):
                    ctx.secret_seen += 1
                    ctx.add(SECRET_DUMP, 'ps-environment', '`ps e` prints every process environment, including secrets', 'ps -o pid,command -p PID')
                    break
            return
        elif name == 'launchctl':
            if nd[:1] == ['getenv'] and nd[1:2] and ctx.c.secret_name(nd[1]):
                ctx.add(SECRET_DUMP, 'launchctl-getenv', 'prints a secret environment variable', 'test presence only')
            return
        if dump:
            ctx.secret_seen += 1
            if self.out_visible(pl, idx, True) and not self._env_name_filter(pl, idx):
                ctx.add(SECRET_DUMP, 'env-dump', '`%s` with no filter prints every environment variable, including tokens and keys' % name,
                        "printenv NAME, env | grep '^NAME=' for exact non-secret names (a prefix or substring "
                        "filter also matches *_TOKEN names), or env | cut -d= -f1 for names only")

    def _env_name_filter(self, pl, idx):
        """`env | grep -E '^(LANE|RUNNER_)'`: the next stage keeps only lines naming the variables it lists, and
        none of those names is secret. Inverted, empty or wildcard-led patterns do not count."""
        if idx + 1 >= len(pl.cmds):
            return False
        words = self._skip_assigns(strip_reserved(pl.cmds[idx + 1].words))[1]
        if not words or norm_name(words[0].text) not in GREP_CMDS:
            return False
        args = words[1:]
        if _flag_letters(args) & set('vfr') or _longs(args) & {'--invert-match', '--file', '--recursive'}:
            return False
        pats, prev = [], ''
        for a in args:
            t = a.text
            if prev in ('-e', '--regexp'):
                pats.append(t)
            elif not t.startswith('-') and not pats and prev not in ('-m', '-A', '-B', '-C', '--max-count'):
                pats.append(t)
            prev = t
        if not pats or any(w.dynamic for w in args):
            return False
        for pat in pats:
            names = re.findall(r'[A-Za-z][A-Za-z0-9_]{2,}', pat)
            if not names or re.match(r'\^?\.', pat):
                return False
            if any(self.ctx.c.secret_name(n) or re.search(r'(?i)secret|token|key|pass|cred|auth', n) for n in names):
                return False
            # exact names only: `^HOME=`, `(HOME|SHELL)=` or grep -w. A prefix or substring (`-i GITHUB`,
            # `^LANE[A-Z_]*=`) also matches GITHUB_TOKEN-style names, so it is not a filter.
            exact = re.search(r'[A-Za-z0-9_)]=', pat) and not re.search(r'[*+?.\]]\)?=', pat)
            if not exact and not ('w' in _flag_letters(args) or '--word-regexp' in _longs(args)):
                return False
        return True

    def echo_check(self, name, args, pl, idx):
        if not any(a.vars for a in args):
            return
        if name == 'cat':
            return
        if self.out_visible(pl, idx, False):
            for a in args:
                self.check_secret_vars(a)
        # PowerShell: $env:TOKEN
        if self.ctx.ps:
            for a in args:
                for v in a.vars:
                    pass

    # ---- credential reads
    NON_REVEALING = {'ssh', 'ssh-add', 'ssh-keygen', 'ssh-copy-id', 'cp', 'mv', 'ln', 'chmod', 'chown', 'chgrp',
                     'chflags', 'xattr', 'ls', 'stat', 'test', '[', '[[', 'wc', 'file', 'touch', 'shasum', 'sha1sum',
                     'sha256sum', 'sha512sum', 'md5sum', 'md5', 'cksum', 'b2sum', 'rm', 'unlink', 'trash', 'mkdir',
                     'git', 'docker', 'docker-compose', 'podman', 'source', '.', 'export', 'rsync', 'rclone', 'install',
                     'realpath', 'readlink', 'dirname', 'basename', 'du', 'find', 'echo', 'printf', 'cd', 'pushd',
                     'open', 'code', 'gpg', 'age', 'sops', 'op', 'aws', 'gh', 'gcloud', 'kubectl', 'helm', 'terraform',
                     'npm', 'pnpm', 'yarn', 'pip', 'uv', 'make', 'dotenv', 'direnv', 'env', 'sudo', 'command', 'type',
                     'which', 'tar', 'zip', 'gzip', 'xz', 'zstd', 'scp', 'sftp', 'curl', 'wget', 'nc', 'set-acl',
                     'get-acl', 'test-path', 'get-item', 'icacls', 'setfacl', 'getfacl', 'lsof', 'fuser'}

    def unlisted_cred_reader(self, name, args, cmd, pl, idx):
        """Fallback for readers missing from the printing-reader list: a home credential file in a positional
        slot of a verb outside the non-revealing allowlist, with stdout reaching the transcript."""
        ctx = self.ctx
        if name in self.NON_REVEALING or name in SHELLS or name in INTERPRETERS or name in WRAPPERS_SIMPLE \
                or name in KILLERS or self.stdout_redirected(cmd):
            return
        prev = ''
        for w in args:
            t = w.text
            flag_value = prev.startswith('-') and '=' not in prev and len(prev) > 1
            prev = t
            if t.startswith('-') or flag_value:
                continue
            if self._home_cred(t, w):
                ctx.secret_seen += 1
                if self.out_visible(pl, idx, True):
                    ctx.add(SECRET_DUMP, 'credential-file',
                            '`%s` is given a credential file and its output reaches the transcript' % name[:40],
                            'check existence with `test -s FILE`; pass the file through the owning tool\'s own '
                            '--config or -i flag')
                return

    def _home_cred(self, text, word):
        """A credential path in a home credential location (not a project's .env or a repo's test key)."""
        if not self.is_cred_path(text, word):
            return False
        path = norm_path(text, self.ctx)
        folded = path.casefold()
        if self.under_cred_dir(path) or folded in self.ctx.secret_files:
            return True
        samples = {norm_path(x, self.ctx, self.ctx.cwd).casefold() for x in self.c.cred_samples if '{cwd}' not in x}
        if folded in samples:
            return True
        return any(_prefix_match(Compiled._segs(folded), r) and len(Compiled._segs(folded)) > len(r)
                   for r in self.c.roots)

    def is_cred_path(self, text, word=None):
        ctx = self.ctx
        c = ctx.c
        alts = (word.all_alts() or word.alts[:32]) if word is not None else [text]
        for alt in alts:
            if self._cred_one(alt):
                return True
        return False

    def _cred_one(self, text):
        ctx = self.ctx
        c = ctx.c
        if not text or len(text) > 4096:
            return False
        path = norm_path(text, ctx)
        if path.casefold() in ctx.secret_files:
            return True
        candidates = {path}
        try:
            if self._probe('le', path, os.path.lexists) and len(path) < 1024:
                candidates.add(self._probe('rp', path, os.path.realpath))
        except (OSError, ValueError):
            pass
        for p in candidates:
            if any(rx.search(p) for rx in c.cred) and not any(rx.search(p) for rx in c.cred_allow):
                return True
        if any(ch in text for ch in '*?['):
            for sample in c.cred_samples:
                if _fnmatchcase(norm_path(sample, ctx, ctx.cwd).casefold(), path.casefold()):
                    return True
        if is_dynamic_path(text):
            tail = path.split('$')[-1] if '$' in path else ''
            tail = tail.split('/', 1)[1] if '/' in tail else ''
            if tail and any(rx.search('/' + tail) for rx in c.cred) and not any(rx.search('/' + tail) for rx in c.cred_allow):
                return True
        return False

    def under_cred_dir(self, path, or_above=False):
        segs = Compiled._segs(path)
        for d in self.c.cred_dirs:
            if len(segs) >= len(d) and segs[:len(d)] == d:
                return True
            if or_above and len(segs) < len(d) and d[:len(segs)] == segs:
                return True
        return False

    @staticmethod
    def _count_only(args):
        return bool(_flag_letters(args) & set('cqlL') or _longs(args) & {'--count', '--quiet', '--silent', '--files-with-matches', '--files-without-match'})

    def read_creds(self, name, args, pl, idx):
        ctx = self.ctx
        texts = [a.text for a in args]
        words = list(args)
        if name in GREP_CMDS:
            skip_next = {'-e', '-f', '-m', '-A', '-B', '-C', '--regexp', '--file', '--max-count', '--include', '--exclude', '-g', '--glob'}
            kept, i, pattern_taken = [], 0, any(t in ('-e', '--regexp', '-f', '--file') or t.startswith('--regexp=') for t in texts)
            while i < len(words):
                t = words[i].text
                if t in skip_next:
                    i += 2
                    continue
                if t.startswith('-') and t != '-':
                    i += 1
                    continue
                if not pattern_taken:
                    pattern_taken = True
                    i += 1
                    continue
                kept.append(words[i])
                i += 1
            words = kept
            count_only = self._count_only(args)
        else:
            words = [w for w in words if not (w.text.startswith('-') and len(w.text) > 1)]
            count_only = False
        if name == 'sed' or name == 'awk' or name in ('gawk', 'mawk', 'jq', 'yq'):
            words = words[1:] if words else words  # first positional is the program
        if name in EXFIL_CMDS:
            words = [w for w in args]
        recursive = name in GREP_CMDS and (_flag_letters(args) & set('rR') or name in ('rg', 'ag', 'ack') or '--recursive' in _longs(args))
        for w in words:
            t = w.text
            if name in EXFIL_CMDS:
                t = t[1:] if t.startswith('@') else t
                t = t[len('file://'):] if t.startswith('file://') else t
                if '=@' in t:
                    t = t.split('=@', 1)[1]
                if ':' in t and not t.startswith('/') and name in ('scp', 'rsync', 'sftp'):
                    continue
            hit = self.is_cred_path(t, w) if t == w.text else self._cred_one(t)
            dir_hit = recursive and self.under_cred_dir(norm_path(t, ctx), or_above=True)
            if hit or dir_hit:
                ctx.secret_seen += 1
                if count_only:
                    continue
                if name in EXFIL_CMDS:
                    visible = True
                else:
                    visible = self.out_visible(pl, idx, True)
                if visible:
                    ctx.add(SECRET_DUMP, 'credential-file',
                            '`%s` of a credential file can print or send secrets (%s)' % (name, posixpath.basename(norm_path(t, ctx))[:40]),
                            'check existence with `test -s FILE` or `ls -l FILE`; use the owning tool\'s own config flag; to count entries use `grep -c`')
                    return

    def interpreter(self, name, args, texts, depth, words=None):
        code = None
        flags = {'python': ('-c',), 'node': ('-e', '--eval', '-p', '--print'), 'perl': ('-e', '-E'), 'ruby': ('-e',),
                 'php': ('-r',), 'deno': ('eval',), 'bun': ('-e', '--eval'), 'lua': ('-e',), 'osascript': ('-e',),
                 'rscript': ('-e',)}
        key = 'python' if name.startswith('python') or name.startswith('pypy') else name
        for i, t in enumerate(texts):
            if t in flags.get(key, ()) or (key == 'python' and re.fullmatch(r'-[A-Za-z]*c', t)):
                if i + 1 < len(texts):
                    code = texts[i + 1]
                    break
        if code is None and name in ('awk', 'gawk', 'mawk', 'nawk'):
            nd = [t for t in texts if not t.startswith('-')]
            code = nd[0] if nd else None
        if code:
            self.code(code, depth)
            return
        # `python3 file.py` for a script written earlier in this same command: judge its text. Existing files are
        # the repository's or harness's own tooling; a raw text scan of their source would block routine runs.
        if key in flags or key == 'python':
            nd = [a for a in args if not a.text.startswith('-')] if args else []
            if nd and nd[0].text != '-':
                text = self.ctx.written.get(norm_path(nd[0].text, self.ctx).casefold())
                if text:
                    self.code(text, depth)
                    # a script this same command wrote and now runs is the incident's shape, so a deletion under a
                    # harness root counts here, not only logs (GoodQA #14657). Existing scripts and one-liners keep
                    # the log-only rule: harness tooling reads and edits these files routinely
                    if written_code_destroys_root(text, self.ctx.home):
                        self.ctx.add(LOG_DELETE, 'written-script-root',
                                     'a line of a script written in this command names a harness root and a call that '
                                     'can destroy or replace a file',
                                     'edit the file with the editor tool, or keep the change out of the harness roots')

    def code(self, code, depth):
        ctx = self.ctx
        # destroyer words inside a regex pattern are data: the log-delete text rule reads the code without them
        blanked = blank_regex_patterns(code) if read_only_pattern_script(code) else code
        for f in fallback_scan(code, ctx.c):
            if f.category == LOG_DELETE and blanked != code and not any(
                    g.rule == f.rule and g.category == LOG_DELETE for g in fallback_scan(blanked, ctx.c)):
                continue
            ctx.findings.append(f)
        low = code.casefold()
        if re.search(r'print\s*\(\s*(?:dict\s*\(\s*)?os\.environ\s*\)|json\.dumps\s*\(\s*(?:dict\s*\(\s*)?os\.environ(?![.\[\w])|'
                     r'os\.environ\.(?:items|values)\s*\(|\{\s*\*\*\s*os\.environ\s*\}|'
                     r'console\.(?:log|dir)\s*\(\s*process\.env\s*\)|json\.stringify\s*\(\s*process\.env\s*[,)]|'
                     r'object\.(?:entries|values)\s*\(\s*process\.env\s*\)|^\s*process\.env\s*;?\s*$|'
                     r'puts\s+env\.to_h|env\.(?:to_h|each|inspect|to_a)\b|\bp{1,2}\s+env\b|'
                     r'print\s+join\s*\([^)]*%env|\bkeys\s*%env\b|print[^;]*%env\b|'
                     r'for\s*\(\s*\w+\s+in\s+environ\s*\)|getenvironmentvariables\s*\(', low):
            ctx.add(SECRET_DUMP, 'interpreter-env-dump', 'script code prints the whole environment', 'print only specific non-secret names')
        for sample in ctx.c.state_files:
            if sample in low.replace('\\', '/') and re.search(r'open|write|copy|rename|replace|echo|dump', low):
                ctx.add(LOG_DELETE, 'state-forgery', 'writes the delete-approval marker or key directly', 'use command_guard.py approve-delete')
        if '.claude/projects' in low.replace('\\', '/') and TRANSCRIPT_CODE_WRITE.search(low):
            ctx.add(LOG_DELETE, 'transcript-forgery', 'script code writes under ~/.claude/projects (session '
                    'transcripts)', 'only Claude Code writes transcripts')

    # ---- destructive
    #
    # Every target goes through target_class(): it expands the word's alternatives (brace expansion), resolves
    # ~, $HOME, cd and symlinks, and returns the strongest protection that applies:
    #   'log'      Tier A: logs, WALs, approval state. Every destructive form is refused.
    #   'root'     Tier B: anything else in ~/.claude, ~/.codex, ~/.agent-harness (minus allow_subtrees).
    #   'ancestor' a directory that contains a protected root (/, /Users, ~, ~/.claude, a glob reaching one).
    #   'unknown'  an unresolved variable or substitution whose text points at a protected location.
    # A literal, existing target covered by a single-use approval (approve-delete) is let through.

    RANK = {None: 0, 'root': 1, 'unknown': 2, 'log': 3, 'ancestor': 3}

    def _path_class(self, path):
        c = self.c
        folded = path.casefold()
        if any(ch in path for ch in GLOB_CHARS) and not getattr(self, '_in_glob', False):
            expanded = self._expand_work_glob(path)
            if expanded is not self.NO_EXPANSION:
                return expanded
        best = classify_segs(c, Compiled._segs(folded))
        if best == 'log-name':
            # a WAL-shaped name outside the harness trees: test data inside a git working tree is not a WAL
            best = None if self._git_top(path, 0) else 'log'
        if folded in c.state_files:
            return 'log'
        if best != 'log' and any(rx.search(folded) for rx in c.wal_regexes):
            best = 'log'
        if best is None or best == 'root':
            real = self._probe('rp', self._through_links(path), _resolve_prefix)
            if real and real.casefold() != folded:
                other = classify_segs(c, Compiled._segs(real.casefold()))
                other = 'log' if other == 'log-name' else other
                if self.RANK[other] > self.RANK[best]:
                    best = other
        if best == 'root' and not is_dynamic_path(path) and not self._kept(path):
            real = None if self._foreign_home(path) else self._probe('rp', self._through_links(path), _resolve_prefix)
            if real and real.casefold() != folded and not any(ch in path for ch in GLOB_CHARS) \
                    and not getattr(self, '_in_real', False):
                # an exception must hold where the path really leads: a symlink inside the agent's own worktree
                # can point into ~/.claude
                self._in_real = True
                try:
                    return self._path_class(real)
                finally:
                    self._in_real = False
            work = self._under_work(path)
            literal = not any(ch in path for ch in GLOB_CHARS)
            if work is not None:
                if literal and self._task_tmp(path, work) or self._own_worktree(path, work):
                    return None
                self.ctx.work_refusal = True
            elif literal and self._inside_repo(path):
                return None
        return best

    NO_EXPANSION = object()
    GLOB_MATCH_CAP = 2000  # across the whole command; beyond it the pattern rule applies (fail closed)

    def _glob_with_hidden(self, pattern, limit):
        """Expand `pattern` like a shell with dotglob set (a wildcard also matches names starting with a dot,
        never `.` or `..`), so a hidden symlink cannot hide behind `*`. None when over `limit` or unreadable."""
        out = ['/']
        segs = [x for x in pattern.split('/') if x]
        for k, seg in enumerate(segs):
            last = k == len(segs) - 1
            nxt = []
            for base in out:
                if not _has_glob(seg):
                    cand = os.path.join(base, seg)
                    if os.path.lexists(cand) if last else os.path.isdir(cand):
                        nxt.append(cand)
                    continue
                if not os.path.isdir(base):
                    continue
                try:
                    names = sorted(e.name for e in os.scandir(base))
                except OSError:
                    return None
                for name in names:
                    if not _fnmatchcase(name, seg):
                        continue
                    cand = os.path.join(base, name)
                    if last or os.path.isdir(cand):
                        self.ctx.budget.tick()
                        nxt.append(cand)
                        if len(nxt) > limit:
                            return None
            out = nxt
            if not out:
                return []
        return out

    def _expand_work_glob(self, path):
        """`rm -rf build/*` under ~/.agent-harness/work: judge what the glob actually matches on disk (as the
        shell will expand it) instead of every name it could match. Only for globs whose wildcard segments
        cannot match dot-names; NO_EXPANSION means "judge the pattern as before"."""
        if is_dynamic_path(path) or self._foreign_home(path) or self._under_work(path) is None:
            return self.NO_EXPANSION
        segs = [x for x in path.replace('\\', '/').split('/') if x]  # original case: Linux is case-sensitive
        if any(_has_glob(x) and x[:1] in ('.', '?', '[') for x in segs) or '..' in segs:
            return self.NO_EXPANSION
        first = next(i for i, x in enumerate(segs) if _has_glob(x))
        prefix = '/' + '/'.join(segs[:first])
        top = self._git_top(prefix, self._under_work(path) + 3)
        if not top or len(Compiled._segs(top)) >= first:
            return self.NO_EXPANSION  # a wildcard directly in the worktree top level (or above it) empties the tree
        try:
            if os.path.realpath(prefix) != os.path.abspath(prefix):
                return self.NO_EXPANSION  # the shell walks the link (and resolves `..` physically after it)
        except (OSError, ValueError):
            return self.NO_EXPANSION
        ctx = self.ctx
        remaining = self.GLOB_MATCH_CAP - getattr(ctx, 'glob_matches', 0)
        matches = self._glob_with_hidden('/' + '/'.join(segs), remaining)
        if matches is None:
            return self.NO_EXPANSION
        ctx.glob_matches = getattr(ctx, 'glob_matches', 0) + len(matches)
        if not matches:
            # nothing matches yet: the shell passes the pattern through literally, so judge one ordinary name in
            # place of each wildcard segment (a later match is judged when that command runs)
            matches = ['/'.join(re.sub(r'\[[^\]]*\]|[*?]', 'x', x) if _has_glob(x) else x for x in path.split('/'))]
        self._in_glob = True
        try:
            classes = [self._path_class(m) for m in matches]
        finally:
            self._in_glob = False
        return max(classes, key=lambda k: self.RANK[k])

    def _task_tmp(self, path, work_len):
        """Inside work/<session>/<task>/tmp/: the place for an agent's disposable packets and scripts."""
        segs = Compiled._segs(path)
        return len(segs) > work_len + 3 and segs[work_len + 2] == 'tmp'

    def _kept(self, path):
        segs = Compiled._segs(path.casefold())
        leaf = segs[-1] if segs else ''
        c = self.c
        return leaf in c.keep_names or leaf.endswith(c.keep_suffixes) or any(x in c.keep_segments for x in segs)

    def _under_work(self, path):
        """Segment count of the matching ~/.agent-harness/work prefix when `path` is below it, else None."""
        segs = Compiled._segs(path)
        for h in self.c.homes:
            base = Compiled._segs(h) + ['.agent-harness', 'work']
            if len(segs) > len(base) and segs[:len(base)] == base:
                return len(base)
        return None

    def _own_worktree(self, path, work_len):
        """Inside the git worktree that contains the hook's working directory, at work/<session>/<task>/..."""
        ctx = self.ctx
        if not ctx.cwd_known or ctx.cwd_unknown or not ctx.cwd:
            return False  # neither the host nor the command says where the agent is working
        origin = ctx.cwd
        segs = Compiled._segs(path)
        if '.git' in segs:
            return False
        top = self._git_top(path, work_len + 3)  # strictly below work/<session>/<task>
        if not top:
            return False
        top_len = len(Compiled._segs(top))
        if any(_has_glob(x) for x in segs[:top_len]):
            return False  # a wildcard at or above the top level could reach the worktree itself or its siblings
        if any(_has_glob(x) and x[:1] in ('.', '?', '[') for x in segs[top_len:]):
            return False  # could match .git, . or .. (and so reach the top or a parent)
        try:
            here = self._probe('rp', origin, os.path.realpath)
            top_real = self._probe('rp', top, os.path.realpath)
        except (OSError, ValueError):
            return False
        return here == top_real or here.startswith(top_real.rstrip('/') + '/')

    def _through_links(self, path):
        """Rewrite a prefix that is a symlink created earlier in this command to the link's target."""
        folded = path.casefold()
        for link, target in self.ctx.links.items():
            lf = link.casefold()
            if folded == lf or folded.startswith(lf + '/'):
                return target + path[len(link):]
        return path

    def _session_file(self, path):
        """A regular file directly in ~/.agent-harness/work/<session>/ (no longer an exception; used in messages)."""
        segs = Compiled._segs(path)
        for h in self.c.homes:
            base = Compiled._segs(h) + ['.agent-harness', 'work']
            if len(segs) == len(base) + 2 and segs[:len(base)] == base:
                return not self._probe('id', path, os.path.isdir) and not self._probe('il', path, os.path.islink)
        return False

    def _inside_repo(self, path):
        """Inside a git working tree whose top level is strictly below a Tier B root (never the root itself)."""
        segs = Compiled._segs(path)
        root_len = None
        for r in self.c.roots:
            if len(segs) > len(r) and _prefix_match(segs, r):
                root_len = len(r)
                break
        if root_len is None:
            return False
        # the top must sit two or more levels below the root, so ~/.claude/hooks or ~/.agent-harness/work being
        # a repository never exempts the harness's own infrastructure
        min_len = root_len + 2
        return bool(self._git_top(path, min_len))

    def _git_top(self, path, min_len):
        """True when an ancestor of `path` (not path itself) with at least min_len segments holds a `.git` that
        existed before this command."""
        parts = [s for s in path.split('/') if s]
        for k in range(len(parts) - 1, max(min_len, 1) - 1, -1):
            top = '/' + '/'.join(parts[:k])
            marker = top + '/.git'
            if marker.casefold() in self.ctx.created:
                return None  # made by this same command
            try:
                if self._probe('le', marker, os.path.lexists):
                    return top if self._probe('gm', marker, _real_git_marker) else None
            except (OSError, ValueError):
                return None
        return None

    FLOW_POSITIONAL = re.compile(r'[0-9@*#]')
    RAW_ASSIGN = re.compile(r'(?:^|[\s;&|(])(?:(?:export|declare|typeset|readonly|local)(?:\s+-\w+)*\s+)?'
                            r'([A-Za-z_][A-Za-z0-9_]*)=("[^"]*"|\'[^\']*\'|[^\s;&|)]*)')
    RAW_PATH = re.compile(r"(?:~[A-Za-z0-9_.-]*|\$HOME|\$\{HOME\}|\$env:USERPROFILE|/)[^\s'\";|&()<>`,]*")

    def _raw_path_class(self, text):
        text = text.strip('\'"')
        text = re.sub(r'^(?:\$\{HOME\}|\$HOME|(?i:\$env:USERPROFILE))', '~', text).replace('\\', '/')
        if text.startswith('~') and not text.startswith('~/') and text != '~':
            text = '~/' + text.split('/', 1)[1] if '/' in text else '~'  # ~user: some home
        if len(text) < 2 and text != '~':
            return None
        return self._path_class(norm_path(text.rstrip('/') or '/', self.ctx))

    def _raw_protected_paths(self):
        """Some path written anywhere in this command resolves into a protected tier (cached per command)."""
        ctx = self.ctx
        cached = getattr(ctx, 'raw_protected', None)
        if cached is not None:
            return cached
        ctx.raw_protected = False
        raw = getattr(ctx, 'raw_top', '') or ''
        if not PROTECTED_TEXT.search(raw):
            return False
        for m in self.RAW_PATH.finditer(raw[:200000]):
            if self._raw_path_class(m.group(0)) in ('log', 'root', 'ancestor', 'unknown'):
                ctx.raw_protected = True
                break
        return ctx.raw_protected

    def _hint_points_at_protected(self, word):
        texts = list(word.subs)
        ctx = self.ctx
        for inner in word.subs:  # `rm -rf "$(ls -d ~/.c*)"`: the substitution lists protected paths
            for m in self.RAW_PATH.finditer(inner[:20000]):
                if self._raw_path_class(m.group(0)) in ('log', 'root', 'ancestor'):
                    return True
        raw = getattr(ctx, 'raw_top', '') or ''
        for v in word.vars:
            name = v.lstrip('!')
            # positional parameters and loop/read variables carry paths from elsewhere in the command: that is
            # undecidable here, so they fail closed when the command names a protected location anywhere
            if (self.FLOW_POSITIONAL.fullmatch(name) or name in getattr(ctx, 'flow_vars', ())) \
                    and self._raw_protected_paths():
                return True
            # export/declare/readonly/local NAME=value, which the assignment tracker does not bind
            for m in self.RAW_ASSIGN.finditer(raw[:200000]):
                if m.group(1) == name and (PROTECTED_TEXT.search(m.group(2))
                                           or self._raw_path_class(m.group(2)) in ('log', 'root', 'ancestor')):
                    return True
        for v in word.vars:
            name = v.lstrip('!')
            if name not in self.ctx.vars and PROTECTED_VAR_NAME.search(name):
                return True
            hint = self.ctx.var_hints.get(name)
            if hint:
                texts.append(hint)
        return any(PROTECTED_TEXT.search(t) for t in texts)

    def target_class(self, word):
        """(class, shown path, literal) for the strongest protection any expansion of `word` hits."""
        ctx = self.ctx
        best, shown, literal = None, '', True
        if ctx.cwd_protected_unknown and word.alts and not word.alts[0].startswith(('/', '~')):
            return 'unknown', word.alts[0], False
        alts = word.all_alts()
        if alts is None:
            if PROTECTED_TEXT.search(_unq(word.overflow)):
                return 'unknown', word.alts[0], False
            alts = word.alts[:32]
        for alt in alts:
            path = norm_path(alt, ctx)
            dynamic = is_dynamic_path(alt) or word.dynamic
            cls = self._path_class(path)
            physical = None if dynamic else self._physical_dotdot(alt)
            if physical and physical != path:
                other = self._path_class(physical)
                if self.RANK[other] > self.RANK[cls]:
                    cls, path = other, physical
            if dynamic:
                literal = False
                if cls is None and self._dynamic_suffix_protected(path):
                    cls = 'unknown'
                if cls is None and self._hint_points_at_protected(word):
                    cls = 'unknown'
            if any(ch in alt for ch in GLOB_CHARS):
                literal = False
            if ctx.cwd_unknown and not alt.startswith(('/', '~')) and cls is None:
                head = posixpath.normpath(alt).split('/')[0].casefold()
                if head in RELATIVE_PROTECTED_NAMES or head.startswith('history'):
                    cls = 'unknown'
            if self.RANK[cls] > self.RANK[best]:
                best, shown = cls, path
        return best, shown, literal

    def _physical_dotdot(self, alt):
        """`sub/link/../../x`: the shell (and the kernel) resolve `..` after following `link`, so the real target
        can differ from the lexically normalised path. Resolve the part up to the last `..` physically."""
        text = alt.replace('\\', '/')
        parts = text.split('/')
        if '..' not in parts:
            return None
        last = len(parts) - 1 - parts[::-1].index('..')
        head, rest = '/'.join(parts[:last + 1]), '/'.join(parts[last + 1:])
        ctx = self.ctx
        if head.startswith('~/') or head == '~':
            head = (ctx.home or '') + head[1:]
        elif not head.startswith('/'):
            if not ctx.cwd or ctx.cwd_unknown:
                return None
            head = ctx.cwd.rstrip('/') + '/' + head
        if head.startswith('~'):
            return None
        try:
            real = self._probe('rp', head, os.path.realpath)
        except (OSError, ValueError):
            return None
        return norm_path(real.rstrip('/') + ('/' + rest if rest else ''), ctx)

    TEMP_WORD = re.compile(r'^\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))(/[^/$*?\[\]{}`~\\]+)?$')
    TEMP_SYMLINKS = re.compile(r'(?<![\w.$-])(?:ln|symlink|symlinkSync|link)(?![\w.-])|os\.link|\bmklink\b')

    def _own_temp_file(self, word):
        """goodqa#15122 AC-1: `"$T"` (or `"$T/name"`) where this command set T=$(mktemp ...) exactly once and mktemp
        creates in a directory outside protected logs (TMPDIR may be relocated under the harness). NEG-2: not when T
        is reassigned, read, exported or looped over, passed to a command outside TEMP_SAFE_COMMANDS (mv, cp, an
        interpreter: it could become a symlink), the command makes a symlink or sets TMPDIR, the name climbs with
        `..`, or the directory resolves into protected logs; those keep the normal rules."""
        ctx = self.ctx
        if word.subs or word.glob or len(word.vars) != 1:
            return False
        alts = getattr(word, 'alts', None) or [word.text]
        if len(alts) != 1:
            return False
        m = self.TEMP_WORD.match(alts[0])
        if not m:
            return False
        name, suffix = m.group(1) or m.group(2), m.group(3) or ''
        entry = ctx.temp_vars.get(name)
        if not entry or name in ctx.vars or name in ctx.temp_tainted or ctx.var_hints.get(name) != entry[0] \
                or suffix in ('/.', '/..'):
            return False
        texts = ctx.seen_texts or [getattr(ctx, 'raw_top', '') or '']
        # the name as a shell word (assigned, read, exported, looped over, unset), not `$T` and not a path part `/T/`
        bare = re.compile(r'(?:^|(?<=[\s;&|(`"\']))' + re.escape(name) + r'(?=[\s;&|)`"\'=+\[}]|$)', re.M)
        made = re.compile(r'(?:^|(?<=[\s;&|(`"\']))' + re.escape(name) + r'=(?:"?\$\(|`)\s*(?:/usr/bin/|/bin/)?mktemp'
                          r'(?![\w-])', re.M)
        for text in texts:
            if self.TEMP_SYMLINKS.search(text) or re.search(r'(?<![\w${])TMPDIR(?!\w)', text):
                return False
            found = bare.findall(text)
            if len(found) > 1 or (found and not made.search(text)):
                return False
        for directory in entry[1]:
            for candidate in (directory, self._probe('rp', directory, os.path.realpath)):
                probe = norm_path(candidate.rstrip('/') + '/tmp.XXXXXXXXXX' + suffix, ctx)
                if self._path_class(probe) == 'log':
                    return False
        return True

    def _note_temp_uses(self, assigns, rest):
        """A temp variable handed to anything but a plain reader, writer or rm loses the AC-1 exemption."""
        ctx = self.ctx
        if not ctx.temp_vars:
            return
        safe = bool(rest) and not rest[0].dynamic and norm_name(rest[0].text) in TEMP_SAFE_COMMANDS
        for w in list(assigns) + ([] if safe else list(rest)):
            for v in w.vars:
                if v.lstrip('!') in ctx.temp_vars:
                    ctx.temp_tainted.add(v.lstrip('!'))

    def _dynamic_suffix_protected(self, path):
        """`$X/projects`, `$DIR/.claude`, `$(..)/wals`: an unresolved prefix followed by a protected tail."""
        folded = path.casefold()
        marker = folded.rfind('$')
        for m in (SUB_MARK, ARITH_MARK):
            marker = max(marker, folded.rfind(m))
        tail = folded[marker + 1:]
        tail = tail.split('/', 1)[1] if '/' in tail else ''
        tail_segs = Compiled._segs(tail)
        if not tail_segs:
            return False
        if any(s in self.c.seg_names for s in tail_segs) or tail_segs[-1] in self.c.file_names:
            return True
        for r in self.c.protected + self.c.roots:
            for k in range(1, len(r) + 1):
                if all(_seg_eq(tail_segs[i], r[len(r) - k + i]) for i in range(min(k, len(tail_segs)))) \
                        and r[len(r) - k].startswith('.'):
                    return True
        return False

    def refuse(self, what, word, tiers=('log', 'root', 'ancestor', 'unknown'), need_existing=False, instead=None):
        """Add a log_delete finding when `word` resolves into one of `tiers`. Returns True when it did."""
        ctx = self.ctx
        if self._own_temp_file(word):
            return False
        cls, path, literal = self.target_class(word)
        if cls is None or cls not in tiers:
            return False
        if need_existing and literal and cls in ('log', 'root') and not self._probe('le', path, _lexists) \
                and path.casefold() not in ctx.created and not self._foreign_home(path) \
                and not self.c.is_guard_file(path):
            return False  # creating a new file is not destructive
        if literal and cls in ('log', 'root') and ctx.marker is not None and ctx.marker(path):
            return False
        if literal and cls == 'root' and what in RM_CMDS and self._reproducible_clone(path):
            return False
        label = {'log': 'a protected log, WAL or approval-state location', 'root': 'a protected harness directory',
                 'ancestor': 'a directory that contains protected logs', 'unknown':
                 'a path the guard cannot resolve that points at protected logs'}[cls]
        name = posixpath.basename(path.rstrip('/')) or path
        ctx.add(LOG_DELETE, 'log-delete',
                ('%s targets %s (%s). Claude/Codex/harness logs and state are never deleted, moved or truncated '
                 'without a verified backup' % (what, label, name[:60]))[:300],
                instead or 'back up to Dropbox (rclone copy), then `command_guard.py approve-delete --path P --remote '
                'REMOTE`, then delete the literal path' + ('' if literal else '; spell out the literal path, globs and '
                                                           'variables cannot be approved')
                + self._clone_hint(path))
        return True

    LONE_RM = re.compile(r'^[ \t]*(?:/bin/|/usr/bin/)?(?:rm|rmdir)(?:[ \t]+-[A-Za-z-]+)*(?:[ \t]+--)?(?:[ \t]+[^ \t\x00-\x1f\x7f;&|<>`$()\\"\'*?\[\]{}~#!]+)+[ \t]*$')

    def _lone_rm(self):
        """The whole command is one plain rm of literal paths. Anything around it (an earlier write or commit, `cd`,
        CDPATH, a variable, a redirect, a second command) could change what the rm deletes after the clone was judged
        clean, so those keep the backup rule (red-team 2026-11-05)."""
        raw = getattr(self.ctx, 'raw_top', '') or ''
        return bool(self.LONE_RM.match(raw)) and not re.search(r'[\x00-\x08\x0b-\x1f\x7f]', raw.strip())

    _LITERAL = r'[^ \t\x00-\x1f\x7f;&|<>`$()\\"\'*?\[\]{}~#!]+'
    # `git [-C /abs/repo] worktree remove [--] /abs/worktree`: a caller whose working directory is not a repository (a
    # subagent's shell resets to $HOME on every call) names the registry repository with one literal -C
    LONE_WORKTREE_REMOVE = re.compile(
        r'^[ \t]*git[ \t]+(?:-C[ \t]+(' + _LITERAL + r')[ \t]+)?worktree[ \t]+remove[ \t]+(?:--[ \t]+)?'
        r'(' + _LITERAL + r')[ \t]*$')

    def _removable_linked_worktree(self, args, cwd_words=()):
        """A standalone `git [-C /literal/repo] worktree remove /literal/top`; every other shape keeps the ordinary
        refusal."""
        self._worktree_reason = None
        if len(args) not in (2, 3) or args[0].text != 'remove' or (len(args) == 3 and args[1].text != '--'):
            return False
        word = args[-1]
        if word.dynamic or word.subs or word.glob:
            return False
        match = self.LONE_WORKTREE_REMOVE.fullmatch(getattr(self.ctx, 'raw_top', '') or '')
        if not match or match.group(2) != word.text:
            return False
        calling = self.ctx.cwd
        if match.group(1) is not None or cwd_words:
            repo_word = cwd_words[0] if len(cwd_words) == 1 else None
            if repo_word is None or repo_word.dynamic or repo_word.subs or repo_word.glob \
                    or repo_word.text != match.group(1):
                return False
            calling = repo_word.text
            if not os.path.isabs(calling) or os.path.realpath(calling) != calling or self._foreign_home(calling):
                return False
        cls, path, literal = self.target_class(word)
        if cls != 'root' or not literal or path != word.text or self._foreign_home(path):
            self._worktree_reason = 'the path is not a literal top inside a harness work root, so the guard does not verify it'
            return False
        started = time.monotonic()
        try:
            reason = linked_worktree_remove_refusal(path, calling, self.c.policy)
            if reason is None and calling != self.ctx.cwd:
                reason = self._dash_c_refusal(path, calling)
        finally:
            self.ctx.budget.deadline += time.monotonic() - started
        self._worktree_reason = reason
        return reason is None

    def _dash_c_refusal(self, path, repo):
        """With a -C the verification ran from the -C directory. Red-team F1: the shell may itself stand inside the
        target (the plain form refuses that), and F2: the -C repository must be the target's own registry."""
        try:
            here = os.path.realpath(_git_out(self.ctx.cwd, ['rev-parse', '--show-toplevel'], 2.0).strip())
        except (ValueError, OSError, TimeoutError):
            here = None  # the calling directory is not inside any repository
        except Exception:  # noqa: BLE001 - any surprise keeps the refusal
            return 'could not check the calling directory'
        if here == path or os.path.realpath(self.ctx.cwd).startswith(path + os.sep) or os.path.realpath(self.ctx.cwd) == path:
            return 'the current worktree cannot remove itself'
        # delta red-team N1 and N3: strings do not fold case or firmlinks, so compare files. Neither the shell's directory
        # nor the -C directory may be the target, inside it, or inside the git directory that the removal also deletes.
        try:
            gitdir = os.path.realpath(_git_out(path, ['rev-parse', '--absolute-git-dir'], 2.0).strip())
            targets = [os.stat(path), os.stat(gitdir)]
            for start in (self.ctx.cwd, repo):
                node = os.path.realpath(start)
                for _ in range(200):
                    st = os.stat(node)
                    if any(os.path.samestat(st, target) for target in targets):
                        return 'the calling directory is inside the worktree or its git directory'
                    parent = os.path.dirname(node)
                    if parent == node:
                        break
                    node = parent
        except Exception:  # noqa: BLE001 - an unreadable ancestor or git directory keeps the refusal
            return 'could not compare the calling directory with the worktree'
        try:
            theirs = os.path.realpath(_git_out(repo, ['rev-parse', '--path-format=absolute', '--git-common-dir'], 2.0).strip())
            ours = os.path.realpath(_git_out(path, ['rev-parse', '--path-format=absolute', '--git-common-dir'], 2.0).strip())
        except Exception:  # noqa: BLE001
            return 'could not compare the -C repository with the worktree registry'
        if theirs != ours:
            return 'the -C repository is not the worktree registry'
        return None

    def _clone_hint(self, path):
        reason = getattr(self.ctx, 'clone_reasons', {}).get(path)
        return '' if not reason else ('. Not exempt as a reproducible git clone: %s (a clean clone whose every commit is '
                                      'on the remote can be deleted without a backup)' % reason[:160])

    def _reproducible_clone(self, path):
        """rm of a provably reproducible git clone (goodqa#14817). The time git and the network take is credited
        back to the analysis budget, bounded by the exemption's own total_seconds."""
        if self._foreign_home(path) or not self._lone_rm():
            return False
        cache = self.ctx.__dict__.setdefault('clone_cache', {})
        if path in cache:
            return cache[path]
        cache[path] = False
        started = time.monotonic()
        try:
            reason = reproducible_clone_refusal(path, self.c.policy)
        finally:
            self.ctx.budget.deadline += time.monotonic() - started
        if reason is None:
            cache[path] = True
            return True
        self.ctx.clone_reasons = getattr(self.ctx, 'clone_reasons', {})
        self.ctx.clone_reasons[path] = reason
        return False

    def _foreign_home(self, path):
        """A /home/x or /Users/x path that is not one of this machine's homes (an ssh or container target)."""
        folded = path.casefold()
        if any(folded == h.casefold() or folded.startswith(h.casefold().rstrip('/') + '/') for h in self.c.homes):
            return False
        return any(_prefix_match(Compiled._segs(folded), g) for g in self.c.match_homes)

    def protected_target(self, what, word):
        self.refuse(what, word)

    def write_target(self, target_word, truncating, via, pure=True):
        if target_word is None:
            return
        target = target_word.text
        if not target or target in ('/dev/null', '/dev/stdout', '/dev/stderr', '/dev/tty') or target.startswith('&'):
            return
        if self.state_dest(target_word):
            return
        if truncating:
            # `echo x > existing` replaces the file's content just as `: >` empties it, so an existing literal file
            # under a protected root is refused like `tee` is; new files and `>>` appends stay allowed. A dynamic
            # target keeps the narrower tiers: its existence cannot be checked, and new-file writes are common.
            cls, path, exact = self.target_class(target_word)
            literal = pure or exact
            tiers = ('log', 'root', 'unknown') if literal else ('log', 'unknown')
            # another host's home: nothing can be checked from here, so only a fully literal path may be narrowed
            foreign = cls == 'root' and self._foreign_home(path)
            if foreign and not exact:
                tiers = ('log', 'root', 'unknown')
            # `link/../x`: the shell resolves `..` after following the link, so check that path as well
            physical = self._physical_dotdot(target_word.text) if not target_word.dynamic else None
            # zsh multios: `> {a,b}` writes every expansion, so each one must be a plain work file
            every = [norm_path(a, self.ctx) for a in (target_word.all_alts() or target_word.alts)]
            dotted = any('..' in a.replace('\\', '/').split('/') for a in (target_word.all_alts() or target_word.alts))
            if not pure and cls == 'root' and self._plain_work_file(path) and all(map(self._plain_work_file, every)) \
                    and (physical is None or self._plain_work_file(physical)) and not (foreign and (dotted or not exact)):
                # owners routinely rerun `cmd > <task dir>/x.log`; only receipts (*.json) and .keep-marked
                # directories under the work dir keep the overwrite refusal (replay over real transcripts)
                tiers = ('log', 'unknown')
            what = 'truncation by redirect' if pure else 'overwrite by redirect'
            done = self.refuse(what, target_word, tiers=tiers, need_existing=True, instead=self._overwrite_hint(path))
            raw_alts = target_word.all_alts() or target_word.alts
            if not done and len(raw_alts) > 1:
                # refuse() checks existence only for the strongest alt it shows; multios writes all of them,
                # so an existing protected file behind a new first alt must still count (delta review F2)
                if len(raw_alts) > 256:  # too many to stat one by one: judge them as if they all existed
                    done = self.refuse(what, target_word, tiers=tiers)
                for alt in ([] if len(raw_alts) > 256 else raw_alts):
                    one = Word()
                    one.alts, one.dynamic = [alt], target_word.dynamic
                    if self.refuse(what, one, tiers=tiers, need_existing=True):
                        done = True
                        break
            if not done and cls is not None and target_word.glob and not target_word.dynamic:
                # `> ~/.claude/settings.jso?`: bash and zsh expand a redirect glob that matches one file, so judge
                # the files it matches now as literal targets (delta review F4). Only below a protected root, and
                # through the budgeted walker: an exception or a stall here would lose every other finding in the
                # command, because the launcher then falls back to its raw-text check (re-review N1)
                pattern = norm_path(target_word.text, self.ctx)
                hits = self._glob_with_hidden(pattern, 256) if pattern.startswith('/') and '\x00' not in pattern else None
                if hits is None:  # too many matches, unreadable or not expandable: its targets are not known
                    done = self.refuse(what, target_word, tiers=('log', 'root', 'unknown'))
                for hit in hits or []:
                    one = Word()
                    one.alts = [hit]
                    hit_tiers = ('log', 'unknown') if not pure and self._plain_work_file(hit) \
                        else ('log', 'root', 'unknown')
                    if self.refuse(what, one, tiers=hit_tiers, need_existing=True):
                        done = True
                        break
            if not done and physical and physical.casefold() != norm_path(target_word.text, self.ctx).casefold():
                real = Word()
                real.alts = [physical]
                self.refuse(what, real, tiers=tiers, need_existing=True)  # the file the shell really opens
        self.note_created(target_word)

    def _work_base(self, segs):
        """Segment count of the ~/.agent-harness/work or /scratch prefix of `segs`, for this machine's homes and for
        /home/<user> on another host (`ssh dev2 'cmd > /home/someone/...'`), else None."""
        other = ['/'.join(segs[:2])] if len(segs) > 2 and segs[0] == 'home' else []
        for h in list(self.c.homes) + other:
            for top in ('work', 'scratch'):
                base = Compiled._segs(h) + ['.agent-harness', top]
                if len(segs) > len(base) and segs[:len(base)] == base:
                    return len(base)
        return None

    def _overwrite_hint(self, path):
        """What to do instead when a redirect is refused for a layout reason under work or scratch, else None."""
        segs = Compiled._segs(path)
        base_len = self._work_base(segs)
        if base_len is None:
            return None
        rest = segs[base_len:]
        if len(rest) == 1:
            return 'write to a subfolder of it instead; files directly in the work or scratch dir are not replaced'
        if any(s in self.c.keep_segments for s in rest[:-1]):
            return 'write to a differently named folder instead; files under a folder named state are kept'
        return None

    def _plain_work_file(self, path):
        """A plain file at least two levels below ~/.agent-harness/work or ~/.agent-harness/scratch, both as typed
        and where it really leads (symlinks): not a JSON receipt, not a kept name (kit.json, *.jsonl, state), and no
        `.keep` in any directory between it and the work or scratch dir. Also true for another host's
        /home/<user>/.agent-harness tree, where the `.keep` and symlink checks can only see this machine's disk."""
        try:
            real = self._probe('rp', path, os.path.realpath)
        except (OSError, ValueError):
            return False
        # macOS makes /home itself a symlink, so that prefix alone must not fail the check. A /home/<user> path that
        # does exist here (another user on this machine) is still followed, so a link out of the tree is refused
        if real.startswith('/System/Volumes/Data/home/') and self._foreign_home(path):
            real = real[len('/System/Volumes/Data'):]
        for cand in (path, real):
            if self._kept(cand) or any(rx.search(cand.casefold()) for rx in self.c.wal_regexes):
                return False
            segs = Compiled._segs(cand)
            raw = [s for s in cand.replace('\\', '/').split('/') if s]
            base_len = self._work_base(segs)
            if base_len is None or len(raw) != len(segs):
                return False
            rest = segs[base_len:]
            if len(rest) < 2 or '..' in rest or rest[-1].casefold().endswith('.json'):
                return False
            for k in range(1, len(rest)):
                if self._probe('le', '/' + '/'.join(raw[:base_len + k]) + '/.keep', _lexists):
                    return False
        return True

    def note_created(self, word, text=None):
        self.ctx.fs_cache.clear()  # created paths change what the next probes must see
        for alt in word.alts[:32]:
            path = norm_path(alt, self.ctx).casefold()
            self.ctx.created.add(path)
            if text is not None:
                self.ctx.written[path] = text[:262144]

    def state_dest(self, word):
        ctx = self.ctx
        for alt in word.all_alts() or word.alts[:32]:
            folded = norm_path(alt, ctx).casefold()
            if folded in ctx.c.state_files:
                ctx.add(LOG_DELETE, 'state-forgery', 'writes the delete-approval marker or its key directly',
                        'use command_guard.py approve-delete after the Dropbox backup is verified')
                return True
            if transcript_write(ctx.c, folded):
                ctx.add(LOG_DELETE, 'transcript-forgery', 'writes into ~/.claude/projects, where session transcripts '
                        '(the record of user answers) live', 'only Claude Code writes transcripts; memory notes go '
                        'under projects/<dir>/memory/')
                return True
        return False

    def destructive(self, name, args, texts):
        ctx = self.ctx
        nd = _nondash(args)
        if name in RM_CMDS:
            if ctx.ps:
                nd = [a for a in args if not re.match(r'^-[A-Za-z]+$', a.text)]
            for w in nd:
                self.refuse(name, w)
        elif name in MV_CMDS:
            dest, sources = None, nd
            if '-t' in texts or '--target-directory' in texts:
                k = texts.index('-t') if '-t' in texts else texts.index('--target-directory')
                dest = args[k + 1] if k + 1 < len(args) else None
                sources = [a for a in nd if a is not dest]
            elif len(nd) >= 2:
                dest, sources = nd[-1], nd[:-1]
            for w in sources:
                self.refuse(name + ' (moves it away)', w)
            if dest is not None and not self.state_dest(dest):
                self.overwrite_dest(name, dest)
        elif name == 'truncate':
            skip = False
            for i, w in enumerate(args):
                if skip:
                    skip = False
                    continue
                if w.text in ('-s', '--size', '-r', '--reference'):
                    skip = True
                    continue
                if w.text.startswith('-'):
                    continue
                self.refuse('truncate', w, tiers=('log', 'root', 'unknown'), need_existing=True)
        elif name in ('tee', 'out-file', 'set-content'):
            if ctx.ps:  # -Value/-FilePath/-LiteralPath are not bundles of short flags in PowerShell
                appending = any(len(t) >= 3 and '-append'.startswith(t.lower()) for t in texts)
            else:
                appending = _flag_letters(args) & {'a'} or '--append' in texts or any(t.lower() == '-append' for t in texts)
            for w in nd:
                if self.state_dest(w):
                    continue
                if not appending:
                    self.refuse(name + ' (overwrites)', w, tiers=('log', 'root', 'unknown'), need_existing=True)
        elif name == 'dd':
            for a in args:
                if a.text.startswith('of='):
                    fake = Word()
                    fake.alts = [x[3:] for x in a.alts]
                    fake.dynamic, fake.subs, fake.vars = a.dynamic, a.subs, a.vars
                    if not self.state_dest(fake):
                        self.refuse('dd of=', fake, tiers=('log', 'root', 'unknown'), need_existing=True)
        elif name in ('touch', 'mkdir'):
            for w in nd:
                self.note_created(w)
        elif name in ('curl', 'wget'):
            flags = ('-o', '--output') if name == 'curl' else ('-O', '--output-document')
            for k, a in enumerate(args):
                val = None
                short = flags[0][1]
                if (a.text in flags or re.fullmatch(r'-[A-Za-z]*' + short, a.text)) and k + 1 < len(args):
                    val = args[k + 1]
                elif a.text.startswith(flags[1] + '='):
                    val = _literal_word(a.text.split('=', 1)[1])
                if val is not None and val.text != '-' and not self.state_dest(val):
                    self.overwrite_dest(name + ' download', val)
                    self.note_created(val)
        elif name in ('awk', 'gawk', 'ruby'):
            if any(t in ('-i', '-iinplace') or t.startswith('-i') and name == 'ruby' for t in texts) and \
                    (name == 'ruby' or 'inplace' in ' '.join(texts)):
                for w in nd[1:] if name != 'ruby' else nd:
                    self.refuse(name + ' in-place rewrite', w, tiers=('log', 'unknown'))
        elif name == 'unzip':
            if '-d' in texts and texts.index('-d') + 1 < len(args) and ('-o' in texts or '-of' in texts):
                self.refuse('unzip -o (overwrites files)', args[texts.index('-d') + 1], tiers=('log', 'unknown'))
        elif name in ('cp', 'copy-item', 'cpi', 'copy', 'install', 'ln'):
            symbolic = bool(_flag_letters(args) & {'s'}) or any(a.text in ('--symbolic', '--symbolic-link')
                                                                  for a in args)
            if name in ('ln', 'cp') and symbolic and nd and \
                    transcript_write(ctx.c, norm_path(nd[0].text, ctx).casefold()):
                ctx.add(LOG_DELETE, 'transcript-forgery', 'links to ~/.claude/projects, an alias Bash could write '
                        'transcripts through', 'only Claude Code writes transcripts')
                return
            if name == 'ln' and _flag_letters(args) & {'s'} and len(nd) >= 2:
                target_path = norm_path(nd[0].text, ctx)
                link = norm_path(nd[-1].text, ctx)
                if os.path.isdir(link) and not os.path.islink(link):
                    link = posixpath.join(link, posixpath.basename(target_path.rstrip('/')))
                ctx.links[link] = target_path
            elif name == 'ln' and _flag_letters(args) & {'s'} and len(nd) == 1:
                target_path = norm_path(nd[0].text, ctx)
                ctx.links[posixpath.join(ctx.cwd, posixpath.basename(target_path.rstrip('/')))] = target_path
            if len(nd) >= 2 or (nd and name == 'ln'):
                dest = nd[-1]
                if self.state_dest(dest):
                    return
                sources = [a.text for a in nd[:-1]]
                if any(s in ('/dev/null', '/dev/zero') for s in sources):
                    self.refuse(name + ' from /dev/null (truncates)', dest, tiers=('log', 'root', 'unknown'),
                                need_existing=True)
                else:
                    self.overwrite_dest(name, dest)
        elif name in ('sed', 'perl'):
            if _flag_letters(args) & {'i'} or any(t.startswith('-i') or t.startswith('--in-place') for t in texts):
                for w in (nd[1:] if name == 'sed' and nd else nd):
                    if not self.state_dest(w):
                        self.refuse(name + ' -i (rewrites in place)', w, tiers=('log', 'unknown'))
        elif name == 'scp':
            self.remote_copy_dest(name, args, texts)
        elif name == 'rsync':
            self.remote_copy_dest(name, args, texts)
            if any(t.startswith('--delete') or t.startswith('--del') or t == '--remove-source-files'
                   or t == '--remove-sent-files' for t in texts):
                pos = [a for a in nd if not self._remote_spec(a.text)]
                if any(t.startswith('--del') for t in texts) and nd and not self._remote_spec(nd[-1].text):
                    self.refuse('rsync --delete (destination)', nd[-1])
                if '--remove-source-files' in texts or '--remove-sent-files' in texts:
                    for w in pos[:-1] if pos and pos[-1] is nd[-1] else pos:
                        self.refuse('rsync --remove-source-files (source)', w)
        elif name == 'rclone':
            # flags without `=` take the next word as their value unless they are known switches, so
            # `--exclude '*.tmp' SRC` and `--min-age 30d SRC` still name SRC as the target
            switches = {'-v', '-vv', '-vvv', '-q', '-p', '-n', '-i', '-l', '-c', '-u', '-l', '--progress', '--dry-run',
                        '--interactive', '--verbose', '--quiet', '--fast-list', '--checksum', '--update',
                        '--ignore-existing', '--no-traverse', '--rmdirs', '--leave-root', '--stats-one-line', '--links',
                        '--copy-links', '--ignore-case', '--ignore-size', '--size-only', '--immutable', '--check-first',
                        '--no-update-modtime', '--delete-empty-src-dirs', '--create-empty-src-dirs', '--delete-before',
                        '--delete-during', '--delete-after', '--track-renames', '--metadata', '-m', '--human-readable',
                        '--use-server-modtime', '--no-check-dest', '--server-side-across-configs', '--resync', '--force'}
            nd, skip = [], False
            for a in args:
                if skip:
                    skip = False
                    continue
                t = a.text.casefold()
                if t.startswith('-') and len(t) > 1:
                    if '=' not in t and t not in switches and not re.fullmatch(r'-[a-z]+', t):
                        skip = True
                    continue
                nd.append(a)
            subs = [a.text.casefold() for a in nd]
            for i, s in enumerate(subs):
                if s in ('move', 'moveto'):
                    for w in nd[i + 1:i + 2]:
                        self.refuse('rclone %s (deletes the source after copy)' % s, w)
                    break
                if s in ('sync', 'bisync'):
                    for w in nd[i + 1:i + 3] if s == 'bisync' else nd[i + 2:i + 3]:
                        self.refuse('rclone %s (deletes files in the destination)' % s, w)
                    break
                if s in ('copy', 'copyto', 'check', 'ls', 'lsf', 'lsd', 'lsjson', 'size', 'about'):
                    break
                if s in ('delete', 'deletefile', 'purge', 'rmdir', 'rmdirs', 'cleanup'):
                    for w in nd[i + 1:i + 2]:
                        self.refuse('rclone %s' % s, w)
                    break
        elif name in ('tar', 'zip', 'bsdtar', 'gtar'):
            if '--remove-files' in texts or (name == 'zip' and (_flag_letters(args) & {'m'} or '--move' in texts)):
                for w in nd:
                    self.refuse(name + ' (removes source files)', w)

    @staticmethod
    def _remote_spec(text):
        return bool(re.match(r'^[A-Za-z0-9_.@-]+:(?!/)', text)) or bool(re.match(r'^[A-Za-z0-9_.@-]+::', text)) \
            or bool(re.match(r'^[A-Za-z0-9_.@-]+:/', text) and not text.startswith('/'))

    REMOTE_DEST = re.compile(r'^(?:[A-Za-z0-9_.-]+@)?(?:[A-Za-z0-9_.-]+|\[[0-9a-fA-F:.%]+\]):(?!:)(.*)$', re.S)
    REMOTE_URL = re.compile(r'^(?:scp|sftp|ssh)://(?:[^@/]+@)?(?:\[[^\]]+\]|[^/:]+)(?::\d+)?(?:/(.*))?$', re.S)
    REMOTE_DAEMON = re.compile(r'^(?:(?:[A-Za-z0-9_.-]+@)?(?:[A-Za-z0-9_.-]+|\[[0-9a-fA-F:.%]+\])::|rsync://(?:[^@/]+@)?(?:\[[^\]]+\]|[^/:]+)(?::\d+)?/)'
                               r'(?:[^/]*)(?:/(.*))?$', re.S)
    SCP_VALUE_FLAGS = {'-P', '-i', '-o', '-F', '-c', '-l', '-S', '-J', '-D', '-X'}
    RSYNC_VALUE_FLAGS = {'-e', '-f', '-T', '-B', '-M', '--rsh', '--chmod', '--exclude', '--include', '--filter', '--rsync-path', '--files-from',
                         '--log-file', '--exclude-from', '--include-from', '--bwlimit', '--timeout', '--contimeout', '--port', '--backup-dir',
                         '--partial-dir', '--suffix', '--compare-dest', '--copy-dest', '--link-dest', '--max-size', '--min-size', '--block-size',
                         '--modify-window', '--protocol', '--chown', '--usermap', '--groupmap', '--iconv', '--out-format', '--password-file',
                         '--address', '--sockopts', '--write-batch', '--only-write-batch', '--read-batch', '--info', '--debug',
                         '--compress-level', '--skip-compress', '--temp-dir', '--max-delete', '--checksum-choice', '--cc', '--stop-after',
                         '--stop-at', '--outbuf', '--remote-option', '-M'}

    def _copy_operands(self, name, args):
        """The positional operands of scp or rsync with option VALUES skipped (a value after the destination must not hide it)."""
        flags = self.SCP_VALUE_FLAGS if name == 'scp' else self.RSYNC_VALUE_FLAGS
        out, skip, ended = [], False, False
        for word in args:
            text = word.text
            if skip:
                skip = False
                continue
            if not ended and text == '--':
                ended = True
                continue
            if not ended and text.startswith('-') and len(text) > 1:
                key = text.split('=', 1)[0] if text.startswith('--') else text
                if key in flags and '=' not in text:
                    skip = True
                continue
            out.append(word)
        return out

    def remote_paths(self, text):
        """Candidate remote paths when `text` is a remote operand (host:path, user@[v6]:path, scp:// and rsync:// urls, host::module),
        else None. A path relative to the remote home reads as `~/relative`; a url path is judged both absolute and home-relative
        and url-decoded (the module root of an rsync daemon is unknown, so its rest is judged the same way)."""
        from urllib.parse import unquote
        if not text or text.startswith(('/', './', '../', '~')) or re.match(r'^[A-Za-z]:[\\/]', text):
            return None
        rest, urlish = None, False
        match = self.REMOTE_URL.match(text)
        if match:
            rest, urlish = match.group(1) or '', True
        else:
            match = self.REMOTE_DAEMON.match(text)
            if match:
                rest, urlish = match.group(1) or '', True
            else:
                match = self.REMOTE_DEST.match(text)
                if match:
                    rest = match.group(1)
        if rest is None or rest == '':
            return None
        rest = unquote(rest) if urlish else rest
        if urlish:
            rest = rest[2:] if rest.startswith(('/~/', '~/')) else rest
            out = ['/' + rest.lstrip('/'), '~/' + rest.lstrip('/')]
            return out
        return [rest if rest.startswith(('/', '~')) else '~/' + rest]

    def remote_copy_dest(self, name, args, texts):
        """scp and rsync copying TO a remote path that names a protected harness location (hooks, WALs, state): the same refusal
        as a local or ssh-wrapped cp (goodqa#15759; the 2026-11-11 t2-dev install of command_guard.py used scp after the cp was
        refused). Option values never hide the destination; IPv6 hosts, scp:// and rsync:// urls and `host::module` are read; a
        recursive copy or an rsync --delete into a directory that CONTAINS protected files is refused too (it overwrites or
        removes them in one command). Downloads (a remote SOURCE, a local destination) are not touched. Stated limits: sftp batch
        commands, tar | ssh and a directory SOURCE (its contents are not expanded) are not seen; a variable in the file position is
        judged like the local cp."""
        operands = self._copy_operands(name, args)
        if len(operands) < 2:
            return
        dest = operands[-1]
        paths = self.remote_paths(dest.text)
        if not paths:
            return
        letters = _flag_letters(args)
        recursive = bool(letters & {'r', 'R'}) or '--recursive' in texts or (name == 'rsync' and (bool(letters & {'a'}) or '--archive' in texts or
                                                                                        any(s.text.endswith('/') for s in operands[:-1])))
        deleting = name == 'rsync' and any(t.startswith('--del') or t in ('--remove-source-files', '--remove-sent-files') for t in texts)
        candidates = list(paths)
        for source in operands[:-1]:
            base = posixpath.basename(source.text.rstrip('/'))
            if base and not self.remote_paths(source.text):
                candidates += [p.rstrip('/') + '/' + base for p in paths]
        for candidate in candidates:
            fake = Word()
            fake.alts = [candidate]
            fake.dynamic, fake.subs, fake.vars = dest.dynamic, dest.subs, dest.vars
            cls, _resolved, _literal = self.target_class(fake)
            contains = cls == 'ancestor' and (recursive or deleting)
            if cls in ('log', 'unknown') or contains:
                self.refuse(name + ' to a remote harness path (the sanctioned route is `ah install-files`)', fake,
                            tiers=('log', 'unknown', 'ancestor') if contains else ('log', 'unknown'))
                return

    def overwrite_dest(self, what, word):
        """cp/mv/ln/install onto an existing Tier A file (or into a protected dir by glob/variable)."""
        cls, path, literal = self.target_class(word)
        if cls == 'log' and literal and self._probe('id', path, os.path.isdir):
            return  # copying into a log directory adds a file; it does not replace one
        if cls in ('log', 'unknown') or cls == 'ancestor' and literal and not self._probe('id', path, os.path.isdir):
            self.refuse(what + ' (overwrites)', word, tiers=('log', 'unknown', 'ancestor'), need_existing=True)
        self.note_created(word)

    def exact_protected(self, word, what):
        self.overwrite_dest(what, word)

    def git_clean(self, args, texts, cwd_word):
        """git clean -f inside a protected tree removes untracked logs and state."""
        letters = _flag_letters(args)
        if not ('f' in letters or '--force' in texts) or 'n' in letters or '--dry-run' in texts:
            return
        base = norm_path(cwd_word.text, self.ctx) if cwd_word is not None and not cwd_word.dynamic else (
            None if cwd_word is not None else self.ctx.cwd)
        if base is None:
            self.refuse('git clean', cwd_word)
            return
        specs = [a for a in _nondash(args) if a.text not in ('--',)]
        targets = [norm_path(a.text, self.ctx, base) for a in specs] or [base]
        for t in targets:
            # git clean removes untracked files below t, so judge a path inside it, not t itself
            fake = Word()
            fake.alts = [t.rstrip('/') + '/.git-clean-interior']
            self.refuse('git clean', fake)

    # ---- kills
    def kill_cmd(self, name, args, texts):
        ctx = self.ctx
        if name in ('pkill', 'killall', 'skill', 'killall5'):
            ctx.kill_seen = True
            self.kill_args(name, args, immediate=True)
        elif name == 'pgrep':
            self.kill_args(name, args, immediate=False)
        elif name == 'kill':
            ctx.kill_seen = True
            nd = [t for t in texts if not t.startswith('-') or re.fullmatch(r'-[0-9]+', t) and t != '-0']
            if any(t in ('-1', '0', '-0') for t in texts) or any(t in ('-1',) for t in nd):
                ctx.add(BROAD_KILL, 'kill-everything', '`kill` with pid -1 or 0 signals every process (or the whole process group)',
                        'kill <pid> for one pid found with `pgrep -f -l <specific pattern>`')
        elif name in ('taskkill', 'stop-process', 'spps'):
            ctx.kill_seen = True
            low = [t.casefold() for t in texts]
            names = []
            for i, t in enumerate(low):
                if t in ('/im', '-name', '-processname') and i + 1 < len(low):
                    names.append(low[i + 1])
            for n in names:
                base = re.sub(r'\.exe$', '', n)
                if len(base) < ctx.c.kill['min_pattern_length'] or base in ctx.c.generic:
                    ctx.add(BROAD_KILL, 'broad-kill', 'killing every process named %r' % base[:40], 'Stop-Process -Id <pid> / taskkill /PID <pid> after listing with Get-Process')

    def kill_args(self, name, args, immediate):
        ctx = self.ctx
        short_value = set('uUgGPstFcOXnoT') if name != 'killall' else set('uUgGstyoOiq')
        long_value = {'--parent', '--pgroup', '--session', '--uid', '--euid', '--group', '--terminal', '--signal', '--ns', '--nslist', '--pidfile', '--user', '--younger-than', '--older-than'}
        strong, weak, pattern, full = False, False, [], False
        i = 0
        texts = [a.text for a in args]
        while i < len(texts):
            t = texts[i]
            if t == '--':
                pattern.extend(texts[i + 1:])
                break
            if t.startswith('--'):
                key = t.split('=')[0]
                if key in ('--parent', '--pgroup', '--session', '--pidfile', '--terminal'):
                    strong = True
                elif key in ('--uid', '--euid', '--user'):
                    weak = True
                elif key == '--full':
                    full = True
                i += 2 if key in long_value and '=' not in t else 1
                continue
            if t.startswith('-') and len(t) > 1:
                cluster = t[1:]
                if re.fullmatch(r'[0-9]+|[A-Z0-9]+', cluster) and len(cluster) > 1 and not re.fullmatch(r'[A-Za-z]', cluster):
                    i += 1
                    continue  # -9, -KILL, -HUP
                consumed = False
                for k, ch in enumerate(cluster):
                    if ch == 'f':
                        full = True
                    if ch in short_value and ch != 'f':
                        if ch in 'PgsFt':
                            strong = True
                        if ch in 'uU':
                            weak = True
                        consumed = k == len(cluster) - 1
                        if k < len(cluster) - 1:
                            consumed = False
                        break
                i += 2 if consumed else 1
                continue
            pattern.append(t)
            i += 1
        pat = ' '.join(pattern).strip()
        self._kill_scope(name, pat, strong, weak, full, immediate)

    def _kill_scope(self, name, pat, strong, weak, full, immediate):
        ctx = self.ctx
        k = ctx.c.kill
        if strong:
            return
        problem = None
        if not pat:
            problem = 'no pattern: it matches every process of the selected user'
        else:
            toks = [t for t in re.split(r'[^a-z0-9_.-]+', pat.casefold()) if t]
            unique = '/' in pat or re.search(r'\w+\.(?:py|js|ts|sh|rb|go|jar)\b', pat) or any(len(t) >= 24 for t in toks)
            if len(pat) < k['min_pattern_length']:
                problem = 'pattern %r is shorter than %d characters' % (pat[:40], k['min_pattern_length'])
            elif any(t in ctx.c.generic for t in toks) and not unique:
                problem = 'pattern %r is generic and can match processes you did not start' % pat[:60]
            elif not weak:
                problem = 'pattern %r is not scoped to a parent, process group, session or user' % pat[:60]
        if problem:
            finding = Finding(BROAD_KILL, 'broad-kill', '`%s` is broad: %s' % (name, problem),
                              'list candidates with `pgrep -f -l <pattern>`, then `kill <pid>` for the ones you started (or use -P <parent pid> / -g <pgid>)')
            if immediate:
                ctx.findings.append(finding)
            else:
                ctx.pending_kill.append(finding)

    def _kill_pattern(self, pat, scoped, strong, source):
        self._kill_scope('kill via ' + source, pat, strong, scoped, True, False)


def _literal_word(text):
    w = Word()
    w.alts = [text]
    return w


def _join_word(word, leaf):
    w = Word()
    w.alts = [posixpath.join(a, leaf) for a in word.alts[:8]]
    w.dynamic, w.subs, w.vars = word.dynamic, word.subs, word.vars
    return w


def _quote_for_rebuild(text):
    return "'" + text.replace("'", "'\\''") + "'"


KNOWN_NAMES = ['rclone', 'goodqa', 'gcloud', 'security', 'printenv', 'env', 'pkill', 'killall', 'shred', 'truncate', 'unlink',
               'cat', 'head', 'tail', 'less', 'more', 'find', 'rsync', 'ssh', 'kill', 'rm', 'mv', 'git', 'gh', 'aws', 'vault']


# --------------------------------------------------------------------------- decision

def analyze(command, compiled=None, cwd=None, ps=False, marker=None):
    """Return the list of Findings for a command string. Raises Blocked when it cannot be analysed in budget."""
    compiled = compiled or Compiled(load_policy())
    if isinstance(command, (list, tuple)):
        command = ' '.join(_quote_for_rebuild(str(c)) for c in command)
    if len(command.encode('utf-8', 'replace')) > int(compiled.limits['max_command_bytes']):
        raise Blocked('command is larger than %d bytes' % int(compiled.limits['max_command_bytes']))
    if pinned_route(command):
        return []
    analyzer = Analyzer(compiled, cwd=cwd, ps=ps, marker=marker)
    try:
        findings = analyzer.run(command)
    except Exception as stop:  # noqa: BLE001 - re-raised: a budget stop, the hook's alarm or a bug
        stop.findings = list(analyzer.ctx.findings)  # what the guard already refused still counts (decide)
        raise
    if analyzer.ctx.unterminated and not any(f.category in ALWAYS_ENFORCED for f in findings):
        if raw_sensitive(command, compiled, cwd=cwd):
            findings.append(Finding(LOG_DELETE if PROTECTED_TEXT.search(command) else SECRET_DUMP, 'unanalysable',
                                    'the command has an unterminated quote or substitution and names a protected '
                                    'location or secret', 'close the quote, or split the command'))
        else:
            findings.append(Finding(PARSE, 'unterminated', 'the command has an unterminated quote or substitution',
                                    'check the quoting'))
    if analyzer.ctx.readings_capped and not any(f.category in ALWAYS_ENFORCED for f in findings):
        if raw_sensitive(command, compiled, cwd=cwd):
            findings.append(Finding(LOG_DELETE if PROTECTED_TEXT.search(command) else SECRET_DUMP, 'unanalysable',
                                    '`>!` cannot be judged under both shell readings (too large, too deeply nested, or '
                                    'they disagree on what a later command uses) and the command names a protected '
                                    'location or secret', 'split the command, or use `>|`'))
        else:
            findings.append(Finding(PARSE, 'readings-capped', '`>!` cannot be judged under both shell readings (too large, too '
                                    'deeply nested, or they disagree on what a later command uses)',
                                    'split the command, or use `>|`'))
    modes = compiled.policy['modes']
    if analyzer.credential_candidate and not any(modes.get(f.category) == 'enforce' for f in findings):
        findings = findings + credential_findings(command, compiled, cwd=cwd, ps=ps)
    return findings


def credential_findings(command, compiled, cwd=None, ps=False):
    """The credential-script check (goodqa#14518) as a separate pass, run after main's analysis has finished with its own
    budget untouched. It has its own time cap and adds only credential-script findings. Any stop here, including the
    hook's alarm, keeps what it found before the stop and adds nothing more, so the verdict is never looser than main's.
    The pass is skipped when main already blocks, since a further finding changes nothing, and when main's pass saw no
    script being run."""
    analyzer = Analyzer(compiled, cwd=cwd, ps=ps, marker=None)
    analyzer.credential_pass = True
    budget = analyzer.ctx.budget
    budget.deadline = time.monotonic() + min(CREDENTIAL_PASS_SECONDS, float(compiled.limits['max_seconds']))
    try:
        analyzer.run(command)
    except Exception:  # noqa: BLE001 - a budget stop, the alarm's TimeoutError or a bug: main's verdict stands
        pass
    return [f for f in analyzer.ctx.findings if f.rule == 'credential-script']


SECRET_TEXT = re.compile(r'(?i)\brclone\b|\bauth\s+token\b|--show-token|\bprintenv\b|(?:^|[;&|(\s])(?:env|set|export'
                         r'|declare|typeset)(?:\s+-[px])?\s*(?:$|[;&|)])|credentials|\bid_(?:rsa|dsa|ecdsa|ed25519)\b'
                         r'|\.env\b|auth\.json|\.npmrc|\.netrc|\.pgpass|hosts\.yml|rclone\.conf|find-(?:generic|'
                         r'internet)-password|dump-keychain|/environ\b|(?:TOKEN|SECRET|PASSWORD|API_?KEY)\b')


def raw_sensitive(text, compiled=None, cwd=None):
    """Cheap raw-text probe: does this text name a protected location or a secret source? A destructive verb run
    from a working directory inside a harness root counts too (`cd ~/.claude` then `rm -rf projects`)."""
    if not isinstance(text, str):
        text = ' '.join(map(str, text))
    t = text[:4_000_000]
    if PROTECTED_TEXT.search(t) or SECRET_TEXT.search(t):
        return True
    if cwd and DESTROY_TEXT.search(t):
        for place in (cwd, _realpath(cwd) or cwd):
            if PROTECTED_TEXT.search(place.replace('\\', '/') + '/'):
                return True
    # code execution the guard could not follow, combined with a destructive verb
    return bool(EXEC_TEXT.search(t) and DESTROY_TEXT.search(t))


EXEC_TEXT = re.compile(r'(?i)\|\s*(?:sudo\s+)?(?:ba|z|k|da|)sh\b|\beval\b|\b(?:ba|z|)sh\s+-[a-z]*c\b|'
                       r'\b(?:python[0-9.]*|node|perl|ruby)\s+-[a-z]*[ce]\b|base64\s+-[dD]|xxd\s+-r|\bsource\s+<\(')
DESTROY_TEXT = re.compile(r'(?i)\b(?:rm|rmdir|unlink|shred|truncate|mv|rmtree|remove|unlinksync|rmsync|dd|find)\b')


def decide(command, compiled=None, cwd=None, ps=False, marker=None):
    """('allow'|'warn'|'block', message). Never raises: budget failures block, bugs fall back to a raw-text scan."""
    compiled = compiled or Compiled(load_policy(), cwd=cwd)
    modes = compiled.policy['modes']
    if approval_env_override(command):
        return 'block', format_block(Finding(LOG_DELETE, 'approval-env', 'runs approve-delete with HOME, '
                                             'CLAUDE_CONFIG_DIR or an env wrapper, which could point it at a forged '
                                             'transcript or state', 'run command_guard.py approve-delete plainly'))
    try:
        findings = analyze(command, compiled, cwd=cwd, ps=ps, marker=marker)
    except (Blocked, RecursionError) as stop:
        reason = str(stop) if isinstance(stop, Blocked) else 'command nesting is too deep'
        already = [f for f in getattr(stop, 'findings', []) if modes.get(f.category) == 'enforce']
        if already:
            return 'block', format_block(already[0], more=len(already) - 1)
        if raw_sensitive(command, compiled, cwd=cwd):
            category = LOG_DELETE if PROTECTED_TEXT.search(command if isinstance(command, str) else ' '.join(command)) \
                else SECRET_DUMP
            return 'block', format_block(Finding(category, 'unanalysable', reason + ' and it names a protected location '
                                                 'or secret', 'split it into smaller commands or put it in a script file'))
        return 'warn', format_block(Finding(PARSE, 'unanalysable', reason, 'split it into smaller commands'), warn=True)
    except Exception as error:  # noqa: BLE001 - fail closed for sensitive-looking text, open for the rest
        already = [f for f in getattr(error, 'findings', []) if modes.get(f.category) == 'enforce']
        if already:
            return 'block', format_block(already[0], more=len(already) - 1)
        try:
            text = command if isinstance(command, str) else ' '.join(map(str, command))
            raw = [f for f in fallback_scan(text, compiled) if modes.get(f.category) == 'enforce']
            if not raw and raw_sensitive(command, compiled, cwd=cwd):
                raw = [Finding(LOG_DELETE if PROTECTED_TEXT.search(text) else SECRET_DUMP, 'guard-error',
                               'it names a protected location or secret', 'retry with a simpler command')]
        except Exception:  # noqa: BLE001
            raw = [Finding(SECRET_DUMP, 'guard-error', 'the guard failed twice', 'retry with a simpler command')]
        if raw:
            raw[0].reason = 'guard internal error (%s) and the raw text looks sensitive: %s' % (type(error).__name__, raw[0].reason)
            return 'block', format_block(raw[0])
        print('command_guard: internal error (%s); raw text looked clean, allowed' % type(error).__name__, file=sys.stderr)
        return 'allow', ''
    enforce = [f for f in findings if modes.get(f.category) == 'enforce']
    if not enforce and getattr(marker, 'no_backup', None) and not sole_delete(command, marker.no_backup):
        enforce = [Finding(LOG_DELETE, 'no-backup-compound', 'a no-backup delete approval is used only by a command '
                           'that is just the delete; other segments could create work that exists nowhere else',
                           'run `rm -rf <approved path>` on its own')]
    if enforce:
        return 'block', format_block(enforce[0], more=len(enforce) - 1)
    if findings:
        return 'warn', format_block(findings[0], warn=True)
    return 'allow', ''


def sole_delete(command, paths):
    """True when `command` is exactly `rm [flags] [--] <path>` for one of `paths`: no other segment, no
    substitution, redirect, background job or second line."""
    import shlex
    text = command if isinstance(command, str) else ' '.join(_quote_for_rebuild(str(c)) for c in command)
    text = text.strip()
    if not text or any(s in text for s in ('\n', '\r', '$', '`', '<(', '>(')):
        return False
    try:
        lex = shlex.shlex(text, posix=True, punctuation_chars=';&|()<>')
        lex.whitespace_split = True
        tokens = list(lex)
    except ValueError:
        return False
    if not tokens or tokens[0] not in ('rm', '/bin/rm') or any(t and set(t) <= set(';&|()<>') for t in tokens):
        return False
    rest, operands, ended = tokens[1:], [], False
    for t in rest:
        if not ended and t == '--':
            ended = True
        elif not ended and re.fullmatch(r'-[rRfv]+|--(?:recursive|force|verbose)', t):
            continue
        elif not ended and t.startswith('-'):
            return False
        else:
            operands.append(t)
    return len(operands) == 1 and os.path.isabs(operands[0]) and os.path.realpath(operands[0]) in paths


APPROVAL_ENV_RE = re.compile(r'(?:^|[\s;&|(`])(?:(?:export\s+|declare\s+-x\s+|typeset\s+-x\s+)?'
                             r'(?:HOME|CLAUDE_CONFIG_DIR|ZDOTDIR|PATH|GIT_\w+|LD_\w+|DYLD_\w+|PYTHON\w*|RCLONE_\w+)\s*=|'
                             r'(?:/usr)?(?:/bin/)?env(?:\s|$)|'
                             r'unset\s+[^;&|]*\b(?:HOME|CLAUDE_CONFIG_DIR|PATH)\b)')


def approval_env_override(command):
    """True when a command that runs approve-delete also sets HOME/CLAUDE_CONFIG_DIR or goes through `env`."""
    text = command if isinstance(command, str) else ' '.join(map(str, command or ()))
    return 'approve-delete' in text and bool(APPROVAL_ENV_RE.search(text))


def format_block(f, more=0, warn=False):
    head = 'command_guard WARNING' if warn else 'command_guard BLOCKED'
    text = '%s [%s/%s]: %s. Safe alternative: %s.' % (head, f.category, f.rule, f.reason, f.alternative)
    try:  # names taken from the command (basenames) must never carry a secret into the transcript
        import redact
        text = redact.redact(text)
    except Exception:  # noqa: BLE001 - without the redactor, drop everything after the rule label
        text = '%s [%s/%s]: blocked; see the command_guard docs.' % (head, f.category, f.rule)
    if more > 0:
        text += ' (%d more finding(s))' % more
    if not warn:
        text += ' There is no override variable; ask the user if this command is really needed.'
    return text[:1500]


# --------------------------------------------------------------------------- delete approval (single use)
#
# approve-delete writes one entry per approved path into ~/.agent-harness/state/log-delete-ok.json, MAC'd with a
# local key. The hook lets a destructive command through only when every protected operand is the exact approved
# path, the path's device, inode and stat manifest are unchanged, and the entry can be removed under an exclusive
# lock (so two commands cannot share one approval). Everything is appended to log-delete-audit.jsonl and, for
# approve-delete, to the WAL named with --wal. The agent itself may approve after a verified Dropbox backup: the
# safeguard is the verified copy, the single use and the audit trail, not a human prompt.

ARCHIVE_KIND = 'archive'  # an approval backed by one verified remote tar archive (goodqa#15068)
MARKER_NAME, KEY_NAME, AUDIT_NAME, LOCK_NAME = 'log-delete-ok.json', 'log-delete.key', 'log-delete-audit.jsonl', \
    'log-delete.lock'


def state_dir(home=None):
    return Path(home or os.path.expanduser('~')) / '.agent-harness' / 'state'


def _mac(key, entry):
    body = json.dumps({k: v for k, v in entry.items() if k != 'mac'}, sort_keys=True, separators=(',', ':')).encode()
    return hmac.new(key, body, hashlib.sha256).hexdigest()


def _read_small(path, limit):
    import safe_input
    return safe_input.read_bounded(str(path), limit)


def load_marker(home=None):
    sd = state_dir(home)
    try:
        data = json.loads(_read_small(sd / MARKER_NAME, 1 << 20).decode('utf-8'))
        key = _read_small(sd / KEY_NAME, 256)
    except Exception:  # noqa: BLE001 - no marker, no approvals
        return [], b''
    entries = data.get('entries') if isinstance(data, dict) else None
    return (entries if isinstance(entries, list) else []), key


def audit(event, fields, home=None, wal=None, strict=False, to_file=True):
    """Append one redacted line to the approval audit log (and the WAL when given). Never raises, except that with
    strict=True a failed audit-file write raises ValueError (callers that count from the log need the line)."""
    record = {'ts': round(time.time(), 3), 'event': event}
    record.update({k: v for k, v in fields.items() if k in ('path', 'remote', 'manifest_sha256', 'files', 'reason',
                                                             'expires_at', 'nonce', 'rule', 'kind', 'target',
                                                             'user_source', 'bytes', 'archive', 'archive_sha256',
                                                             'archive_listing')})
    try:
        import redact
        line = json.dumps(redact.redact_obj(record), sort_keys=True)  # values, so a span cannot eat JSON syntax
    except Exception:  # noqa: BLE001
        line = json.dumps({'ts': record['ts'], 'event': event})
    try:
        if to_file:
            sd = state_dir(home)
            sd.mkdir(parents=True, exist_ok=True)
            fd = os.open(str(sd / AUDIT_NAME), os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            with os.fdopen(fd, 'a') as handle:
                handle.write(line + '\n')
                if strict:
                    handle.flush()
                    os.fsync(handle.fileno())
    except OSError as error:
        if strict:
            raise ValueError('the approval audit log could not be written (%s); nothing approved'
                             % type(error).__name__)
    if wal:
        note = 'command_guard %s: %s' % (event, line[:900])
        helper = HERE / 'wal_note.py'
        try:
            if helper.is_file():
                subprocess.run([sys.executable, str(helper), '--wal', str(wal), '--event', 'status', '--note', note,
                                '--source', 'inferred: from command_guard approve-delete ; ticket:GoodQA goodqa#14471 '
                                            '-- approval audit record'],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30, check=False)
            else:
                fd = os.open(str(wal), os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
                with os.fdopen(fd, 'a') as handle:
                    handle.write(json.dumps({'ts': record['ts'], 'event': 'status', 'note': note}) + '\n')
        except (OSError, subprocess.SubprocessError):
            pass


def _identity(path):
    st = os.stat(path)
    return st.st_dev, st.st_ino


def stat_manifest(path, limits, deadline=None):
    """sha256 over (relative path, type, size, mtime_ns) of a tree; raises ValueError when over budget."""
    max_entries = int(limits.get('max_approve_files', 20000))
    deadline = deadline if deadline is not None else time.monotonic() + float(limits['max_walk_seconds'])
    h = hashlib.sha256()
    count = 0
    root = path
    stack = [root]
    while stack:
        current = stack.pop()
        st = os.lstat(current)
        count += 1
        if count > max_entries + 1 or time.monotonic() > deadline:
            raise ValueError('tree is too large to check inside the time budget; approve a smaller subtree')
        rel = os.path.relpath(current, root)
        kind = 'd' if os.path.isdir(current) and not os.path.islink(current) else ('l' if os.path.islink(current) else 'f')
        h.update(('%s\0%s\0%d\0%d\n' % (rel, kind, st.st_size if kind == 'f' else 0,
                                        st.st_mtime_ns if kind != 'd' else 0)).encode('utf-8', 'surrogateescape'))
        if kind == 'd':
            with os.scandir(current) as it:
                stack.extend(sorted((e.path for e in it), reverse=True))
    return h.hexdigest()


class Approvals:
    """Marker callable for the analyser: covers(path) -> bool, remembering which entries a command would use."""

    def __init__(self, home=None, compiled=None, now=None):
        self.home = home
        self.limits = (compiled.policy['marker'] if compiled else DEFAULT_POLICY['marker'])
        self.now = time.time() if now is None else now
        self.entries, self.key = load_marker(home)
        self.used = {}
        self.used_archive = {}  # path -> archive URL, for the delete receipt (goodqa#15068)
        self.no_backup = set()  # real paths covered by a no-backup entry: decide() then requires a sole delete

    def __call__(self, path):
        return self.covers(path)

    def _valid(self, entry):
        try:
            if not self.key or not hmac.compare_digest(_mac(self.key, entry), str(entry.get('mac', ''))):
                return False
            if float(entry['expires_at']) <= self.now or float(entry['verified_at']) > self.now + 60:
                return False
            return True
        except (KeyError, TypeError, ValueError):
            return False

    def covers(self, path):
        if not self.entries:
            return False
        try:
            real = os.path.realpath(path)
        except (OSError, ValueError):
            return False
        for entry in self.entries:
            if not isinstance(entry, dict) or not self._valid(entry):
                continue
            if os.path.normpath(str(entry.get('path'))) != real:
                continue
            try:
                if list(_identity(real)) != list(entry.get('identity') or []):
                    continue
                if entry.get('kind') == NO_BACKUP_KIND:
                    # no copy exists, so the state that made the deletion safe is checked again right now
                    if _no_backup_state(real, entry.get('target'), self.home) != entry.get('state'):
                        continue
                elif stat_manifest(real, self.limits) != entry.get('stat_sha256'):
                    continue
            except (OSError, ValueError):
                continue
            if entry.get('kind') == NO_BACKUP_KIND:
                self.no_backup.add(real)
            self.used[real] = entry.get('nonce')
            if entry.get('archive'):
                self.used_archive[real] = entry.get('archive')
            return True
        return False

    def consume(self):
        """Remove every used entry under an exclusive lock. True when all of them were still present."""
        if not self.used:
            return True
        sd = state_dir(self.home)
        try:
            import fcntl
        except ImportError:  # pragma: no cover - non-POSIX: refuse rather than allow a reusable approval
            return False
        try:
            fd = os.open(str(sd / LOCK_NAME), os.O_WRONLY | os.O_CREAT, 0o600)
        except OSError:
            return False
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            entries, key = load_marker(self.home)
            wanted = set(self.used.values())
            remaining = [e for e in entries if not (isinstance(e, dict) and e.get('nonce') in wanted)]
            if len(entries) - len(remaining) != len(wanted):
                return False  # another command used one of them first
            tmp = sd / ('.marker.%d.%s.tmp' % (os.getpid(), _secrets.token_hex(4)))
            wfd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(wfd, 'w') as handle:
                json.dump({'version': 2, 'entries': remaining}, handle, indent=1)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(str(tmp), str(sd / MARKER_NAME))
        except OSError:
            return False
        finally:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)
        for path, nonce in self.used.items():
            fields = {'path': path, 'nonce': nonce}
            if self.used_archive.get(path):
                fields.update(archive=self.used_archive[path], kind=ARCHIVE_KIND)
            audit('consumed', fields, home=self.home)
        return True


def marker_covers(path, home=None, now=None, compiled=None):
    """Read-only check (used by `check`): does a valid approval cover exactly this path?"""
    return Approvals(home=home, compiled=compiled, now=now).covers(path)


class VerifyResult:
    def __init__(self, ok, checked=0, missing=None, mismatched=None, error=''):
        self.ok, self.checked, self.missing, self.mismatched, self.error = ok, checked, missing or [], mismatched or [], error


class Verifier:
    """Compares a local tree with its remote backup. Subclass and implement verify()."""

    def verify(self, local_root, manifest, remote):  # pragma: no cover - interface
        raise NotImplementedError


def dropbox_content_hash(path):
    """Dropbox content_hash: sha256 over the concatenated sha256 of each 4 MiB block."""
    outer = hashlib.sha256()
    with open(path, 'rb') as handle:
        while True:
            block = handle.read(4 * 1024 * 1024)
            if not block:
                break
            outer.update(hashlib.sha256(block).digest())
    return outer.hexdigest()


def _file_hash(path, kind):
    if kind == 'dropbox':
        return dropbox_content_hash(path)
    h = hashlib.new({'sha256': 'sha256', 'sha1': 'sha1', 'md5': 'md5'}[kind])
    with open(path, 'rb') as handle:
        while True:
            block = handle.read(1 << 20)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


class RcloneVerifier(Verifier):
    """Real verifier: `rclone lsjson -R --hash --files-only REMOTE`, then size and checksum per local file.

    The remote must mirror `local_root` (a directory) or hold the single file's basename. Hashes compared are the
    first of dropbox, sha256, sha1, md5 that rclone reports for the remote. A file with no common hash, a missing
    file or any mismatch fails the verification; output from rclone is parsed, never printed.
    """

    PREFERENCE = ('sha256', 'dropbox', 'sha1', 'md5')

    def __init__(self, rclone='rclone', runner=None, timeout=900):
        self.rclone, self.runner, self.timeout = rclone, runner or self._run, timeout

    def _run(self, argv):
        done = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=self.timeout, check=False)
        return done.returncode, done.stdout[:512 * 1024 * 1024]

    def remote_types(self):
        """{remote name: backend type} from `rclone listremotes --long` (names and types only, no secrets)."""
        code, out = self.runner([self.rclone, 'listremotes', '--long'])
        if code != 0:
            return {}
        found = {}
        for line in out.decode('utf-8', 'replace').splitlines()[:500]:
            m = re.match(r'\s*([^:\s][^:]*):\s+(\S+)', line)
            if m:
                found[m.group(1)] = m.group(2)
        return found

    def verify(self, local_root, manifest, remote):
        code, out = self.runner([self.rclone, 'lsjson', '-R', '--hash', '--files-only', remote])
        if code != 0:
            return VerifyResult(False, error='rclone lsjson failed (exit %s)' % code)
        try:
            listing = json.loads(out.decode('utf-8'))
        except ValueError:
            return VerifyResult(False, error='rclone lsjson output was not JSON')
        remote_files = {item.get('Path'): item for item in listing if isinstance(item, dict)}
        missing, mismatched, checked = [], [], 0
        single = os.path.isfile(local_root)
        for rel, size, _sha in manifest:
            item = remote_files.get(rel if not single else os.path.basename(local_root))
            if item is None:
                missing.append(rel)
                continue
            checked += 1
            if int(item.get('Size', -1)) != size:
                mismatched.append(rel)
                continue
            hashes = {k.lower(): v for k, v in (item.get('Hashes') or {}).items()}
            kind = next((k for k in self.PREFERENCE if k in hashes), None)
            local_path = local_root if single else os.path.join(local_root, rel)
            if kind is None or _file_hash(local_path, kind) != str(hashes[kind]).lower():
                mismatched.append(rel)
        return VerifyResult(not missing and not mismatched and checked > 0, checked, missing[:20], mismatched[:20])


_SHA_LINE = re.compile(r'^([0-9a-fA-F]{64})(?:\s+\*?(\S.*))?$')
# bsdtar / GNU tar `tar -tvf` regular-file line: mode, links or owner/group, size, date, path.
_TVF_BSD = re.compile(r'^-[rwxsStT-]{9}[@+.]?\s+\d+\s+\S+\s+\S+\s+(\d+)\s+\w{3}\s+\d{1,2}\s+(?:\d{1,2}:\d{2}|\d{4})\s(.+)$')
_TVF_GNU = re.compile(r'^-[rwxsStT-]{9}[@+.]?\s+\S+/\S+\s+(\d+)\s+\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}(?::\d{2})?\s(.+)$')


def _safe_member(name):
    """The member path with any leading './' removed, or None when it is absolute, climbs out, or holds NUL/CR/LF."""
    if not name or '\x00' in name or '\n' in name or '\r' in name or name.startswith('/'):
        return None
    while name.startswith('./'):
        name = name[2:]
    parts = name.rstrip('/').split('/')
    if not name or any(p in ('..', '') for p in parts):
        return None
    return name.rstrip('/')


class _HashingReader:
    """A read-only wrapper that feeds every byte read through sha256 and counts it, refusing past `limit`."""

    def __init__(self, raw, limit):
        self.raw, self.limit, self.sha, self.count = raw, limit, hashlib.sha256(), 0

    def read(self, n=-1):
        data = self.raw.read(n if n is not None and n >= 0 else 1 << 20)
        self.count += len(data)
        if self.count > self.limit:
            raise ValueError('archive is larger than the approval limit')
        self.sha.update(data)
        return data

    def drain(self):
        while self.read(1 << 20):
            pass


class _GunzipReader:
    """Decompresses every member of a concatenated gzip stream, as gzip -dc and bsdtar do (red-team F3: Python's
    tarfile r|gz stops after the first member, so a second member was hashed but never compared)."""

    def __init__(self, raw):
        import zlib
        self.raw, self.zlib, self.pending = raw, zlib, b''
        self.inflater, self.done = zlib.decompressobj(31), False

    def read(self, n=-1):
        n = n if n is not None and n > 0 else 1 << 20
        while len(self.pending) < n and not self.done:
            if self.inflater.eof:
                rest = self.inflater.unused_data
                if not rest:
                    rest = self.raw.read(1 << 16)
                    if not rest:
                        self.done = True
                        break
                if not rest.startswith(b'\x1f'):
                    raise ValueError('the archive has bytes after its gzip stream that are not another gzip member')
                self.inflater = self.zlib.decompressobj(31)
                self.pending += self.inflater.decompress(rest, 1 << 20)
                continue
            chunk = self.inflater.unconsumed_tail or self.raw.read(1 << 16)
            if not chunk:
                raise ValueError('the archive is truncated or corrupt (the gzip stream ends early)')
            self.pending += self.inflater.decompress(chunk, 1 << 20)
        data, self.pending = self.pending[:n], self.pending[n:]
        return data


class _InflateLimit:
    """Counts the decompressed tar bytes and refuses past `limit` (red-team F4: a decompression bomb)."""

    def __init__(self, source, limit):
        self.source, self.limit, self.count = source, limit, 0

    def read(self, n=-1):
        data = self.source.read(n if n is not None and n >= 0 else 1 << 20)
        self.count += len(data)
        if self.count > self.limit:
            raise ValueError('the archive inflates far beyond the size of the local tree')
        return data


def _pinned_tool(name):
    """An absolute path for a decompressor from the usual install dirs, before any PATH lookup (red-team F7)."""
    for folder in ('/opt/homebrew/bin', '/usr/local/bin', '/usr/bin', '/bin'):
        candidate = os.path.join(folder, name)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return __import__('shutil').which(name) or name


APPLEDOUBLE_MAGIC = b'\x00\x05\x16\x07'


class ArchiveVerifier(Verifier):
    """Verifies that one remote tar archive (plain, .gz or .zst) holds exactly the local tree (goodqa#15068).

    Nothing is trusted from the uploader except as something to compare: the guard streams the archive itself (never
    extracting it, never writing it to disk), computes its sha256 and requires it to equal the .sha256 file, and
    requires the archive's regular-file members (path, size, content sha256) to equal the local tree, prefixed by the
    tree's own directory name, and the listing's (path, size) set to equal the same members. Unsafe or duplicate
    member names, a truncated or corrupt stream, a failed download or a decompressor error refuse."""

    def __init__(self, sha256_remote, listing_remote, rclone='rclone', zstd=None, opener=None, types=None,
                 timeout=3600, limit=64 << 30):
        self.sha256_remote, self.listing_remote = sha256_remote, listing_remote
        self.rclone, self.timeout, self.limit = rclone, timeout, limit
        self.zstd = zstd or _pinned_tool('zstd')
        self.inflate_slack = 256 << 20  # tar headers, padding and AppleDouble companions on top of 2x the tree
        self.max_members = None  # set by verify() from the local manifest
        self.opener = opener or self._open
        self._types = types or RcloneVerifier(rclone=rclone).remote_types

    def remote_types(self):
        return self._types()

    def _open(self, remote):
        """(binary stream, wait() -> exit code) of `rclone cat REMOTE`; rclone output is parsed, never printed."""
        proc = subprocess.Popen([self.rclone, 'cat', '--', remote], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)

        def wait():
            try:
                return proc.wait(timeout=self.timeout)
            except subprocess.TimeoutExpired:
                proc.terminate()
                return -1
        return proc.stdout, wait

    def _small(self, remote, limit, label):
        stream, wait = self.opener(remote)
        data = stream.read(limit + 1)  # a pipe read returns short only at end of stream
        if len(data) > limit:
            try:  # red-team F5: stop here; draining an endless stream would hang approve-delete
                stream.close()
            except OSError:
                pass
            wait()
            raise ValueError('the %s is larger than %d bytes' % (label, limit))
        if wait() != 0:
            raise ValueError('could not download the %s (%s)' % (label, remote[:120]))
        return data

    def expected_sha256(self, archive):
        text = self._small(self.sha256_remote, 4096, 'archive sha256 file').decode('utf-8', 'replace').strip()
        m = _SHA_LINE.match(text.splitlines()[0].strip() if text else '')
        if not m:
            raise ValueError('the archive sha256 file does not start with a 64-hex sha256')
        named = (m.group(2) or '').strip()
        if named and named != posixpath.basename(archive.split(':', 1)[1]):
            raise ValueError('the archive sha256 file names %r, not this archive' % named[:80])
        if m.group(1).lower() == hashlib.sha256(b'').hexdigest():
            # a failed upload run can leave the digest of empty input behind (pp407 review-full, 2026-11-07)
            raise ValueError('the archive sha256 file holds the sha256 of empty input')
        return m.group(1).lower()

    def listing(self):
        """{member path: size} of the regular files in a `tar -tvf` listing (bsdtar or GNU style)."""
        found = {}
        for line in self._small(self.listing_remote, 256 << 20, 'archive listing').decode('utf-8', 'replace').splitlines():
            if not line.startswith('-'):
                continue  # directories, links and blank lines
            m = _TVF_BSD.match(line) or _TVF_GNU.match(line)
            name = _safe_member(m.group(2)) if m else None
            if not name:
                raise ValueError('the archive listing has a regular-file line it cannot read')
            if name in found:
                raise ValueError('the archive listing names one file twice')
            found[name] = int(m.group(1))
        if not found:
            # a failed listing step leaves a 0-byte or directory-only listing (pp407 review-full, 2026-11-07)
            raise ValueError('the archive listing names no regular files')
        return found

    def members(self, archive):
        """({member path: (size, sha256)}, archive sha256) read from the streamed archive."""
        import tarfile
        import threading
        stream, wait = self.opener(archive)
        raw = _HashingReader(stream, self.limit)
        lower = archive.lower()
        zstd_proc, pump_error = None, []
        if lower.endswith(('.tar.zst', '.tzst')):
            zstd_proc = subprocess.Popen([self.zstd, '-dc', '-q'], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                         stderr=subprocess.DEVNULL)

            def pump():
                try:
                    while True:
                        block = raw.read(1 << 20)
                        if not block:
                            break
                        zstd_proc.stdin.write(block)
                except (OSError, ValueError) as error:
                    pump_error.append(error)
                finally:
                    try:
                        zstd_proc.stdin.close()
                    except OSError:
                        pass
            thread = threading.Thread(target=pump, daemon=True)
            thread.start()
            source = zstd_proc.stdout
        elif lower.endswith(('.tar.gz', '.tgz')):
            source = _GunzipReader(raw)
        elif lower.endswith('.tar'):
            source = raw
        else:
            stream.close()
            wait()
            raise ValueError('the archive must be .tar, .tar.gz/.tgz or .tar.zst')
        source = _InflateLimit(source, self.inflate_limit)
        found, self.names, self.appledouble, seen = {}, set(), set(), set()
        deadline = time.monotonic() + self.timeout
        try:
            with tarfile.open(fileobj=source, mode='r|') as tar:
                for count, info in enumerate(tar, 1):
                    tar.members = []  # red-team F4: stream mode would otherwise keep every header in memory
                    if self.max_members is not None and count > self.max_members:
                        raise ValueError('the archive has far more members than the local tree has files')
                    if time.monotonic() > deadline:
                        raise ValueError('reading the archive took longer than %d seconds' % self.timeout)
                    name = _safe_member(info.name)
                    if name is None:
                        raise ValueError('the archive holds an unsafe member name')
                    # red-team F2: a later member of ANY type with the same name (or one that is the same file on a
                    # case-insensitive or normalising disk) replaces the verified file on restore.
                    folded = unicodedata.normalize('NFC', name).casefold()
                    if folded in seen:
                        raise ValueError('the archive names one path twice (%s)' % name[:120])
                    seen.add(folded)
                    self.names.add(name)
                    if info.isdir():
                        continue
                    if not info.isreg():
                        raise ValueError('the archive holds a link or special member (%s); only regular files and '
                                         'directories can be compared' % name[:120])
                    member = tar.extractfile(info)
                    h, size, head = hashlib.sha256(), 0, b''
                    while True:
                        block = member.read(1 << 20)
                        if not block:
                            break
                        if size < 4:
                            head = (head + block)[:4]
                        size += len(block)
                        h.update(block)
                    if size != info.size:
                        raise ValueError('the archive is truncated inside a member')
                    if head == APPLEDOUBLE_MAGIC:
                        self.appledouble.add(name)
                    found[name] = (size, h.hexdigest())
                # red-team F3: nothing but zero padding may follow the end-of-archive block.
                while True:
                    rest = tar.fileobj.read(1 << 20)
                    if not rest:
                        break
                    if rest.strip(b'\0'):
                        raise ValueError('the archive has data after the end of the tar')
            if zstd_proc is not None:
                thread.join(self.timeout)
            raw.drain()
        except (tarfile.TarError, EOFError, OSError, zlib_error(), ValueError) as error:
            # Stop the decompressor and the download: a refused archive must leave no child process behind.
            if zstd_proc is not None:
                zstd_proc.terminate()
                zstd_proc.wait(timeout=30)
            try:
                stream.close()
            except OSError:
                pass
            wait()
            if isinstance(error, ValueError):
                raise
            raise ValueError('the archive is truncated or corrupt (%s)' % type(error).__name__)
        finally:
            if zstd_proc is not None:
                try:
                    zstd_proc.stdout.close()
                except OSError:
                    pass
        if pump_error:
            raise ValueError(str(pump_error[0])[:120] if isinstance(pump_error[0], ValueError) else
                             'the archive download failed')
        if zstd_proc is not None and zstd_proc.wait(timeout=self.timeout) != 0:
            raise ValueError('the archive is truncated or corrupt (zstd failed)')
        if wait() != 0:
            raise ValueError('could not download the archive (%s)' % archive[:120])
        return found, raw.sha.hexdigest()

    def verify(self, local_root, manifest, remote):
        if self.max_members is None:
            self.max_members = 4 * len(manifest) + 1000  # files, their AppleDouble companions and directories
        self.inflate_limit = 2 * sum(size for _rel, size, _sha in manifest) + self.inflate_slack
        try:
            expected = self.expected_sha256(remote)
            listed = self.listing()
            found, actual = self.members(remote)
        except ValueError as error:
            return VerifyResult(False, error=str(error)[:200])
        if actual != expected:
            return VerifyResult(False, error='archive sha256 does not match its .sha256 file')
        if not found:
            return VerifyResult(False, error='the archive holds no regular files')
        prefix = os.path.basename(os.path.realpath(local_root).rstrip('/'))
        local = {'%s/%s' % (prefix, rel): (size, sha) for rel, size, sha in manifest}
        # macOS bsdtar stores extended attributes as AppleDouble companions `<dir>/._<name>` beside each member; its own
        # `tar -tvf` merges them back and does not list them. Such a companion is metadata, not a file of the tree,
        # when it is not a local file, starts with the AppleDouble magic 00 05 16 07, and its sibling (a file or a
        # directory, both of which get companions) is in the archive; drop it from both comparisons.
        names = getattr(self, 'names', set(found))
        apple = getattr(self, 'appledouble', set())
        for n in [n for n in found if n not in local and n in apple and posixpath.basename(n).startswith('._')]:
            sibling = posixpath.join(posixpath.dirname(n), posixpath.basename(n)[2:])
            if sibling in names:
                del found[n]
                listed.pop(n, None)
        missing = sorted(set(local) - set(found))
        extra = sorted(set(found) - set(local))
        differs = sorted(n for n in set(local) & set(found) if local[n] != found[n])
        if missing or extra:
            return VerifyResult(False, len(found), missing[:20], extra[:20],
                                error='archive members differ from the local tree (%d local files missing, %d extra)'
                                      % (len(missing), len(extra)))
        if differs:
            return VerifyResult(False, len(found), [], differs[:20], error='archive content differs from the local files')
        if listed != {n: s for n, (s, _h) in found.items()}:
            return VerifyResult(False, len(found), error='archive listing does not match the archive members')
        self.verified_sha256 = actual
        return VerifyResult(bool(found), len(found))


def zlib_error():
    import zlib
    return zlib.error


def tree_manifest(path, limits):
    """[(relative path, size, sha256)] for a file or directory, bounded; raises ValueError over budget."""
    path = os.path.realpath(path)
    entries, total = [], 0
    deadline = time.monotonic() + max(60.0, float(limits['max_walk_seconds']) * 600)
    files = []
    if os.path.isfile(path):
        files.append((os.path.basename(path), path))
    else:
        for root, dirs, names in os.walk(path):
            dirs.sort()
            for name in sorted(names):
                full = os.path.join(root, name)
                if os.path.islink(full):
                    continue
                files.append((os.path.relpath(full, path).replace(os.sep, '/'), full))
                if len(files) > int(limits['max_walk_entries']):
                    raise ValueError('too many files to approve at once; approve subdirectories')
    for rel, full in files:
        if time.monotonic() > deadline:
            raise ValueError('hashing exceeded its time budget')
        h = hashlib.sha256()
        size = 0
        with open(full, 'rb') as handle:
            while True:
                block = handle.read(1 << 20)
                if not block:
                    break
                size += len(block)
                total += len(block)
                if total > int(limits['max_hash_bytes']):
                    raise ValueError('tree is larger than the approval limit')
                h.update(block)
        entries.append((rel, size, h.hexdigest()))
    return entries


def manifest_digest(manifest):
    return hashlib.sha256('\n'.join('%s\t%d\t%s' % e for e in manifest).encode()).hexdigest()


def _approval_refusal(real, policy, home=None):
    """Reason an approval for `real` must be refused (protected roots, top-level log dirs, ancestors), or None."""
    c = Compiled(policy, home=home)
    segs = Compiled._segs(real.casefold())
    for group in (c.roots, c.protected, c.ancestors):
        for r in group:
            if _prefix_match(segs, r) and len(segs) <= len(r):
                return 'approving a protected root, a top-level log directory or one of their parents is refused; ' \
                       'approve a subdirectory or file inside it'
    if len(segs) <= 2:
        return 'approving a home directory or a top-level directory is refused'
    return None


def _check_remote(remote, policy, verifier):
    """Only named remotes of an allowed backend type (default dropbox); never local paths or on-the-fly backends."""
    if not isinstance(remote, str) or ':' not in remote or remote.startswith((':', '/', '.', '~')) or ',' in \
            remote.split(':', 1)[0] or '\\x00' in remote:
        raise ValueError('remote must be a named rclone remote such as dropbox:backups/claude (not a local path, '
                         'an on-the-fly :backend: or a connection string)')
    name = remote.split(':', 1)[0]
    allowed = [t.casefold() for t in policy['marker'].get('approve_remote_types', ['dropbox'])]
    types = getattr(verifier, 'remote_types', None)
    found = types() if callable(types) else {}
    kind = (found or {}).get(name)
    if kind is None:
        raise ValueError('remote %r is not configured in rclone' % name[:40])
    if kind.casefold() not in allowed:
        raise ValueError('remote %r has backend type %r; approvals need one of %s' % (name[:40], kind[:20], allowed))


def _first_symlink(path):
    """Relative path of the first symlink under `path` (or `path` itself), else None."""
    if os.path.islink(path):
        return '.'
    for root, dirs, names in os.walk(path):
        for name in sorted(dirs + names):
            if os.path.islink(os.path.join(root, name)):
                return os.path.relpath(os.path.join(root, name), path)
    return None


def _recent_change(path, seconds, now, limits):
    deadline = time.monotonic() + max(10.0, float(limits['max_walk_seconds']) * 10)
    for root, dirs, names in os.walk(path):
        for name in names + dirs:
            if time.monotonic() > deadline:
                return True
            try:
                if os.lstat(os.path.join(root, name)).st_mtime > now - seconds:
                    return True
            except OSError:
                return True
    try:
        return os.lstat(path).st_mtime > now - seconds and os.path.isfile(path)
    except OSError:
        return True


def approve_delete(path, remote, verifier=None, pinned_digest=None, ttl=None, home=None, policy=None, now=None,
                   wal=None, archive=None):
    """Verify the backup, then write a signed single-use approval for `path`. Returns the entry.

    Raises ValueError on refusal (and audits the refusal)."""
    policy = policy or load_policy()
    limits = policy['marker']
    now = time.time() if now is None else now
    verifier = verifier or RcloneVerifier()
    real = os.path.realpath(path)
    try:
        if any(ch in path for ch in GLOB_CHARS) or '$' in path:
            raise ValueError('spell out the literal path; globs and variables cannot be approved')
        if not os.path.exists(real):
            raise ValueError('path does not exist')
        reason = _approval_refusal(real, policy, home=home)
        if reason:
            raise ValueError(reason)
        ttl = int(ttl or limits['default_ttl_seconds'])
        if ttl <= 0 or ttl > int(limits['max_ttl_seconds']):
            raise ValueError('ttl must be between 1 and %d seconds' % int(limits['max_ttl_seconds']))
        recent = int(limits.get('recent_change_seconds', 600))
        if recent > 0 and _recent_change(real, recent, now, limits):
            raise ValueError('something under the path changed in the last %d seconds (a live log?); wait, back it '
                             'up again and retry' % recent)
        _check_remote(remote, policy, verifier)
        if archive is not None:
            # goodqa#15068: `remote` is one tar archive; its .sha256 and listing must be named remotes of an allowed
            # backend too, and the verifier is the archive verifier, never the per-file mirror one.
            for extra in archive:
                _check_remote(extra, policy, verifier)
            if not isinstance(verifier, ArchiveVerifier):
                verifier = ArchiveVerifier(archive[0], archive[1])
        # PR #120 red-team F1: the delete-time stat check must describe the tree the backup was compared with, so it
        # is taken before hashing and must be unchanged after the (possibly hour-long) verification.
        stat_before = stat_manifest(real, limits, deadline=time.monotonic() + 60)
        if archive is not None:
            link = _first_symlink(real)
            if link:
                raise ValueError('the tree holds a symlink (%s), which the archive comparison does not cover; '
                                 'refused' % link[:120])
        manifest = tree_manifest(real, limits)
        if not manifest:
            raise ValueError('nothing to approve: the path holds no files')
        if len(manifest) > int(limits.get('max_approve_files', 20000)):
            raise ValueError('more than %d files; approve smaller subtrees' % int(limits.get('max_approve_files', 20000)))
        digest = manifest_digest(manifest)
        if pinned_digest and pinned_digest.lower() != digest:
            raise ValueError('--backup-verified-sha256 does not match the local manifest digest')
        result = verifier.verify(real, manifest, remote)
        if not result.ok:
            raise ValueError('backup is not verified: checked=%d missing=%d mismatched=%d %s' % (
                result.checked, len(result.missing), len(result.mismatched), (result.error or '')[:120]))
        stat_digest = stat_manifest(real, limits, deadline=time.monotonic() + 60)
        if stat_digest != stat_before:
            raise ValueError('the tree changed while its backup was being verified; back it up again and retry')
        if recent > 0 and _recent_change(real, recent, time.time(), limits):
            raise ValueError('something under the path changed while its backup was being verified; retry')
        identity = list(_identity(real))
    except ValueError as error:
        audit('refused', {'path': real, 'remote': remote, 'reason': str(error)[:200]}, home=home, wal=wal)
        raise
    entry = {'path': real, 'identity': identity, 'files': len(manifest), 'manifest_sha256': digest,
             'stat_sha256': stat_digest, 'remote': remote, 'verified_at': now, 'expires_at': now + ttl,
             'nonce': _secrets.token_hex(8)}
    if archive is not None:
        entry.update({'kind': ARCHIVE_KIND, 'archive': remote, 'archive_sha256': verifier.verified_sha256,
                      'archive_listing': archive[1], 'archive_sha256_file': archive[0]})
    _store_entry(entry, real, now, home)
    audit('approved', entry, home=home, wal=wal)
    return entry


def _store_entry(entry, real, now, home=None, under_lock=None):
    """MAC `entry` with the local key and write it to the marker, replacing any live entry for the same path.
    `under_lock`, when given, runs while the marker lock is held and before the write; raising aborts the write."""
    sd = state_dir(home)
    sd.mkdir(parents=True, exist_ok=True)
    os.chmod(str(sd), 0o700)
    key_path = sd / KEY_NAME
    try:
        fd = os.open(str(key_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as handle:
            handle.write(_secrets.token_bytes(32))
    except FileExistsError:
        pass
    key = _read_small(key_path, 256)
    entry['mac'] = _mac(key, entry)
    import fcntl
    lock = os.open(str(sd / LOCK_NAME), os.O_WRONLY | os.O_CREAT, 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if under_lock is not None:
            under_lock()
        entries, _ = load_marker(home)
        live = [e for e in entries if isinstance(e, dict) and float(e.get('expires_at', 0) or 0) > now
                and e.get('path') != real]
        live.append(entry)
        tmp = sd / ('.marker.%d.%s.tmp' % (os.getpid(), _secrets.token_hex(4)))
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as handle:
            json.dump({'version': 2, 'entries': live}, handle, indent=1)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(str(tmp), str(sd / MARKER_NAME))
    finally:
        fcntl.flock(lock, fcntl.LOCK_UN)
        os.close(lock)
    return entry


# --------------------------------------------------------------------------- no-backup approval (goodqa#14911)
#
# A deletion the user approved in an AskUserQuestion answer, with no backup because the data is disposable. Only two
# kinds of target qualify, and only when nothing would be lost:
#   'git'    the root of a git working tree whose every file is committed (no untracked, ignored or changed file, no
#            assume-unchanged entry, no skip-worktree file present on disk), with no stash, no linked worktree, no
#            submodule, no replace ref or graft, no commit on any ref (branches, tags, notes, anything outside
#            refs/remotes) missing from a remote-tracking ref, and a network remote on an allowlisted host whose live
#            branch tip (ls-remote, run outside the repository) is a tracking ref that contains HEAD;
#   'image'  a disk image file (.sparseimage, .dmg) or bundle (.sparsebundle) under ~/.agent-harness/work that is not
#            attached.
# The source must be an `answer:` whose AskUserQuestion names the literal path, whose selected answer says delete,
# and whose session is the session of the --wal. Transcripts are read from the pinned ~/.claude of the account's
# home (pwd), never from CLAUDE_CONFIG_DIR or $HOME. Logs, WALs, transcripts and approval state are refused here
# unconditionally. The approval is single use, MAC'd, bound to the exact literal path and its inode, and the hook
# re-checks every local fact that made it safe.

NO_BACKUP_KIND = 'no-backup'
IMAGE_FILE_SUFFIXES = ('.sparseimage', '.dmg')
IMAGE_DIR_SUFFIXES = ('.sparsebundle',)
NO_BACKUP_SOURCE_RE = re.compile(r'^answer:([A-Za-z0-9._-]{1,80})/([0-9a-fA-F-]{8,64})$')
# the selected option must be exactly this label: "Delete after a backup" and similar must never approve a
# no-backup delete
NO_BACKUP_LABEL = re.compile(r'^Delete, no backup(?: \(Recommended\))?$')
APPROVE_WORDS = NO_BACKUP_LABEL
# "Delete, no backup" is an approval, so a bare "no" is not a decline word
# defence in depth only: no answer matching the exact NO_BACKUP_LABEL holds one of these words; keep it so a
# later label change cannot lean on the label alone
DECLINE_WORDS = re.compile(r"\b(?:not|don'?t|keep|leave|cancel|nothing|never|later|yet|skip|hold|wait|instead)\b",
                           re.I)
# an absolute path in question text: ends at whitespace, a quote or bracket, or sentence punctuation
QUESTION_PATH_RE = re.compile(r'(?<![\w.~-])/[^\s"\'`,;:()<>\[\]{}?!*|]+')
DEFAULT_REMOTE_HOSTS = ('github.com', 't2-dev')
# Repository config must not run anything while the guard inspects a clone: no fsmonitor, hooks, ext transport,
# custom ssh command, credential helper or pager, and no prompt.
_SAFE_GIT = ['git', '-c', 'core.fsmonitor=false', '-c', 'core.hooksPath=/dev/null', '-c', 'protocol.ext.allow=never',
             '-c', 'protocol.file.allow=never', '-c', 'core.sshCommand=/usr/bin/ssh', '-c', 'credential.helper=',
             '-c', 'core.pager=cat', '-c', 'core.untrackedCache=false', '-c', 'core.attributesFile=/dev/null',
             '-c', 'core.checkStat=default', '-c', 'core.trustctime=true', '-c', 'core.ignoreStat=false']
# git is run by an absolute system path, never looked up on the caller's PATH
_GIT_BIN_CANDIDATES = ('/usr/bin/git', '/opt/homebrew/bin/git', '/usr/local/bin/git')


def _git_bin():
    for candidate in _GIT_BIN_CANDIDATES:
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    raise ValueError('no system git found (%s)' % ', '.join(_GIT_BIN_CANDIDATES))


def _git_env():
    """A constructed environment: nothing from the caller but the ssh agent socket. PATH, GIT_EXEC_PATH,
    GIT_CONFIG_GLOBAL, loader and Python variables cannot point git or ssh at a shim."""
    env = {'PATH': '/usr/bin:/bin', 'HOME': _pinned_home(), 'LC_ALL': 'C', 'GIT_CONFIG_NOSYSTEM': '1',
           'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_ATTR_NOSYSTEM': '1', 'GIT_TERMINAL_PROMPT': '0',
           'GIT_OPTIONAL_LOCKS': '0', 'GIT_PAGER': 'cat', 'GIT_NO_REPLACE_OBJECTS': '1'}
    sock = os.environ.get('SSH_AUTH_SOCK', '')
    if sock.startswith('/') and '\n' not in sock:
        env['SSH_AUTH_SOCK'] = sock
    return env


def _pinned_home():
    """The account's real home from the password database: an agent can set $HOME, not this."""
    import pwd
    return os.path.realpath(pwd.getpwuid(os.getuid()).pw_dir)


def _git(repo, *args, timeout=60, stdin=None):
    """Run git against `repo` (or, with repo None, outside any repository so no repository config applies), by
    an absolute path with a constructed environment."""
    where = ['-C', repo] if repo else ['-C', '/']
    done = subprocess.run([_git_bin()] + _SAFE_GIT[1:] + where + list(args), stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, env=_git_env(), timeout=timeout, check=False,
                          **({'input': stdin.encode()} if stdin is not None else {}))
    return done.returncode, done.stdout.decode('utf-8', 'replace')


def _attached_images():
    """Real paths of attached disk images (macOS hdiutil). Raises ValueError when that cannot be checked."""
    import plistlib
    try:
        done = subprocess.run(['/usr/bin/hdiutil', 'info', '-plist'], stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL, env={'PATH': '/usr/bin:/bin'}, timeout=30, check=False)
        data = plistlib.loads(done.stdout) if done.returncode == 0 else None
    except (OSError, subprocess.SubprocessError, ValueError) as error:
        raise ValueError('cannot check whether the image is attached (hdiutil: %s)' % type(error).__name__)
    if not isinstance(data, dict):
        raise ValueError('cannot check whether the image is attached (hdiutil info failed)')
    return {os.path.realpath(str(i.get('image-path'))) for i in data.get('images') or []
            if isinstance(i, dict) and i.get('image-path')}


def _target_kind(real, home=None):
    low = real.casefold()
    if low.endswith(IMAGE_FILE_SUFFIXES + IMAGE_DIR_SUFFIXES):
        work = os.path.join(home or _pinned_home(), '.agent-harness', 'work') + os.sep
        if not real.startswith(work):
            raise ValueError('a disk image is deleted without a backup only under ~/.agent-harness/work')
        if (os.path.isfile(real) and low.endswith(IMAGE_FILE_SUFFIXES)) or \
                (os.path.isdir(real) and low.endswith(IMAGE_DIR_SUFFIXES)):
            return 'image'
    dot_git = os.path.join(real, '.git')
    if os.path.isdir(real) and os.path.isdir(dot_git) and not os.path.islink(dot_git):
        return 'git'
    raise ValueError('only a git working tree root or a detached disk image can be deleted without a backup')


def _image_size(real):
    if os.path.isfile(real):
        return os.lstat(real).st_size
    total = 0
    for root, _dirs, names in os.walk(real):
        for name in names:
            total += os.lstat(os.path.join(root, name)).st_size
    return total


def _no_backup_state(real, target, home=None, attached=None):
    """Every local fact that makes deleting `real` lose nothing, as a comparable dict. Raises ValueError when unsafe.
    The hook runs it again at delete time, so a change after approval voids the approval."""
    if target == 'image':
        if real in (attached or _attached_images)():
            raise ValueError('the disk image is attached; detach it first (hdiutil detach)')
        st = os.lstat(real)
        return {'size': st.st_size, 'mtime_ns': st.st_mtime_ns}
    if target != 'git':
        raise ValueError('unknown target kind')
    git_dir = os.path.join(real, '.git')
    code, top = _git(real, 'rev-parse', '--show-toplevel')
    if code != 0 or os.path.realpath(top.strip()) != real:
        raise ValueError('the path is not the top of its git working tree')
    # filters run inside `git status` (clean, process): refuse any before status is asked anything
    code, filters = _git(real, 'config', '--get-regexp', r'^filter\.')
    if code not in (0, 1) or filters.strip():
        raise ValueError('the repository configures a filter driver, which could hide edits and runs a program; '
                         'refused')
    if os.path.lexists(os.path.join(git_dir, 'info', 'attributes')):
        raise ValueError('the repository has .git/info/attributes (local attributes, possibly filters); refused')
    if os.path.lexists(os.path.join(git_dir, 'lfs')):
        raise ValueError('the repository has a git LFS store (.git/lfs), whose objects may be pushed nowhere; refused')
    # submodules first: a gitlink also shows in status, and the accurate reason is the submodule
    code, staged = _git(real, 'ls-files', '-s', '-z')
    if code != 0 or any(rec.startswith('160000 ') for rec in staged.split('\0')) or \
            os.path.lexists(os.path.join(real, '.gitmodules')) or os.path.lexists(os.path.join(git_dir, 'modules')):
        raise ValueError('the repository has submodules; their commits are not checked, so it is refused')
    code, status = _git(real, 'status', '--porcelain=v1', '--ignored', '--untracked-files=all', '-z')
    if code != 0 or status:
        raise ValueError('the working tree has changed, untracked or ignored files; they exist nowhere else')
    code, flagged = _git(real, 'ls-files', '-v', '-z')
    if code != 0:
        raise ValueError('cannot list the index')
    for rec in flagged.split('\0'):
        if len(rec) < 3:
            continue
        tag, name = rec[0], rec[2:]
        if tag.islower():
            raise ValueError('an index entry is marked assume-unchanged, so status cannot see its changes')
        if tag == 'S' and os.path.lexists(os.path.join(real, name)):
            raise ValueError('a skip-worktree file is present on disk, so status cannot see its changes')
    code, replaced = _git(real, 'for-each-ref', '--format=%(refname)', 'refs/replace')
    # A shallow boundary is fine: it cannot hide an unpushed tip, which rev-list below still lists itself.
    if code != 0 or replaced.strip() or os.path.lexists(os.path.join(git_dir, 'info', 'grafts')):
        raise ValueError('the repository has replace refs or grafts; refused')
    code, _ = _git(real, 'rev-parse', '-q', '--verify', 'refs/stash')
    if code == 0:
        raise ValueError('the repository has a stash; it exists nowhere else')
    code, trees = _git(real, 'worktree', 'list', '--porcelain')
    if code != 0 or sum(1 for line in trees.splitlines() if line.startswith('worktree ')) != 1:
        raise ValueError('the repository has linked worktrees; delete those first')
    code, extra = _git(real, 'rev-list', '--max-count=1', '--exclude=refs/remotes/*', '--all', '--not', '--remotes')
    if code != 0 or extra.strip():
        raise ValueError('a commit on a local branch, tag or other ref is on no remote-tracking ref (unpushed work)')
    code, head = _git(real, 'rev-parse', '--verify', 'HEAD')
    if code != 0 or not head.strip():
        raise ValueError('the working tree has no commit')
    code, refs = _git(real, 'for-each-ref', '--format=%(objectname) %(refname)')
    if code != 0:
        raise ValueError('cannot list refs')
    return {'head': head.strip(), 'refs_sha256': hashlib.sha256(refs.encode()).hexdigest(), 'worktrees': 1}


def _remote_host(url):
    """The host of a network git URL (https, ssh, git+ssh or scp-like), else ''. Local paths and file:// give ''."""
    url = str(url or '').strip()
    m = re.match(r'^(?:https|ssh|git\+ssh)://(?:[^@/\s]+@)?([A-Za-z0-9.-]+)(?::\d+)?/\S+$', url, re.I)
    if not m and not url.startswith(('/', '.', '~')) and '://' not in url:
        m = re.match(r'^(?:[A-Za-z0-9._-]+@)?([A-Za-z0-9.-]+):\S+$', url)
    return m.group(1).casefold() if m else ''


def _check_git_pushed(real, ls_remote=None, hosts=DEFAULT_REMOTE_HOSTS):
    """Every commit reachable from HEAD or any ref (tracking refs included) is reachable from a live head or tag
    of an allowlisted network remote, listed now by ls-remote from outside the repository (no repository insteadOf
    or config applies). Local remote-tracking refs are never proof: they can be stale or hand-set.
    Raises ValueError otherwise."""
    allowed = {h.casefold() for h in hosts}
    code, urls = _git(real, 'config', '--get-regexp', r'^remote\..*\.url$')
    live, answered, seen_hosts = set(), [], []
    for line in urls.splitlines()[:8] if code == 0 else []:
        key, _, url = line.partition(' ')
        url = url.strip()
        host = _remote_host(url)
        seen_hosts.append(host or '(local or unparsed)')
        if not host or host not in allowed:
            continue
        shas = (ls_remote or _ls_remote)(url)
        if shas is None:
            continue
        answered.append((key[len('remote.'):-len('.url')], host))
        live.update(s for s in shas if re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}', str(s)))
    if not answered:
        raise ValueError('no allowlisted network remote answered a live listing (remote hosts seen: %s; allowed: '
                         '%s)' % (', '.join(seen_hosts[:4]) or 'none', ', '.join(sorted(allowed))))
    # live shas this clone lacks cannot be negated; leaving them out only lists more, never hides a commit
    present = []
    if live:
        code, out = _git(real, 'cat-file', '--batch-check=%(objectname) %(objecttype)', stdin='\n'.join(sorted(live))
                         + '\n')
        present = [line.split()[0] for line in out.splitlines() if line.endswith((' commit', ' tag'))]
    missing = len(live) - len(present)
    # every ref counts, tracking refs too: a commit only a stale tracking ref still holds exists nowhere else
    code, extra = _git(real, 'rev-list', '--max-count=1', '--all', 'HEAD', '--stdin',
                       stdin=''.join('^%s\n' % s for s in present))
    if code != 0 or extra.strip():
        raise ValueError('a commit on HEAD or a branch, tag, tracking or other ref is on no live ref of an '
                         'allowlisted network remote (%s); run `git fetch --prune`, or push it%s' % (
                             ', '.join('%s@%s' % a for a in answered[:3]),
                             '; %d live refs are not in this clone: fetch first' % missing if missing else ''))
    return {'remote': answered[0][0], 'url_host': answered[0][1][:60], 'live_refs': len(live),
            'answered': ['%s@%s' % (n[:40], h[:60]) for n, h in answered[:8]]}


def _ls_remote(url):
    """Live head and tag shas of `url` (one listing), or None when the remote did not answer."""
    code, out = _git(None, 'ls-remote', '--upload-pack=git-upload-pack', url, 'refs/heads/*', 'refs/tags/*',
                     timeout=60)
    if code != 0:
        return None
    return [line.split()[0] for line in out.splitlines() if line.split()]


def _askuser_question(provenance, path, record):
    """The input (a dict) of the main-conversation AskUserQuestion that `record` answers, or None."""
    blocks = (record.get('message') or {}).get('content') if isinstance(record, dict) else None
    use_id = blocks[0].get('tool_use_id') if isinstance(blocks, list) and blocks and isinstance(blocks[0], dict) \
        else None
    if not isinstance(use_id, str) or not use_id:
        return None
    for line in provenance._lines_containing(path, use_id.encode()):
        if line is None:
            continue
        try:
            rec = provenance.loads_line(line)
        except ValueError:
            continue
        if not isinstance(rec, dict) or rec.get('type') != 'assistant' or rec.get('isSidechain'):
            continue
        for block in (rec.get('message') or {}).get('content') or []:
            if isinstance(block, dict) and block.get('type') == 'tool_use' and block.get('id') == use_id \
                    and block.get('name') == 'AskUserQuestion':
                return block.get('input') if isinstance(block.get('input'), dict) else None
    return None


def _real_transcript(provenance, session, claude):
    """The transcript of `session` under <claude>/projects, refusing symlinks anywhere on the way and a session id
    that is not the file's exact name (case-insensitive file systems would match a case variant)."""
    projects = Path(claude) / 'projects'
    if os.path.islink(str(projects)):
        raise ValueError('the transcript store ~/.claude/projects is a symlink; refused')
    tpath = Path(provenance.find_transcript(session, claude))
    folder = tpath.parent
    if os.path.islink(str(folder)) or os.path.islink(str(tpath)) or not os.path.isfile(str(tpath)):
        raise ValueError('the transcript or its project folder is a symlink; refused')
    if os.path.realpath(str(tpath)) != os.path.join(os.path.realpath(str(projects)), folder.name, tpath.name):
        raise ValueError('the transcript is not inside ~/.claude/projects; refused')
    if tpath.name not in os.listdir(str(folder)):
        raise ValueError('the session id is not the transcript\'s exact name (case differs); refused')
    return tpath


def resolve_user_source(source, now=None, max_age=None, home=None):
    """{'kind', 'session', 'uid', 'at', 'text', 'question'} of the AskUserQuestion answer named by
    `answer:<session>/<uuid>`, read from <home>/.claude (home: the account home, pinned when None). Raises
    ValueError otherwise. No excerpt or other trailing text is accepted."""
    import datetime
    m = NO_BACKUP_SOURCE_RE.match(str(source or ''))
    if not m:
        raise ValueError('--user-source must be exactly answer:<session>/<uuid> (an AskUserQuestion answer that '
                         'names the path; no excerpt)')
    session, uid = m.groups()
    claude = Path(home or _pinned_home()) / '.claude'
    try:
        if str(HERE) not in sys.path:
            sys.path.insert(0, str(HERE))
        import provenance
        tpath = _real_transcript(provenance, session, claude)
        turn = provenance.answer_turn(session, uid, home=claude)
    except ValueError as error:
        raise ValueError(str(error))
    except Exception as error:  # noqa: BLE001 - any failure to prove the turn is a refusal
        raise ValueError('the user source does not resolve to a real answer turn (%s)' % (
            str(getattr(error, 'code', '') or type(error).__name__)[:40]))
    try:
        record = provenance.load_record(tpath, 'uuid', uid)
        asked = _askuser_question(provenance, tpath, record)
    except Exception:  # noqa: BLE001 - no question found: refused below
        record, asked = None, None
    questions = asked.get('questions') if isinstance(asked, dict) else None
    answers = (record.get('toolUseResult') or {}).get('answers') if isinstance(record, dict) and \
        isinstance(record.get('toolUseResult'), dict) else None
    if not isinstance(questions, list) or len(questions) != 1 or not isinstance(questions[0], dict) or \
            questions[0].get('multiSelect') or not isinstance(answers, dict) or len(answers) != 1:
        raise ValueError('the answer must come from a single question, single-choice AskUserQuestion call; ask the '
                         'user again with one question per path')
    question = str(questions[0].get('question') or '')
    (key, selected), = answers.items()
    labels = [str(o.get('label')) for o in questions[0].get('options') or [] if isinstance(o, dict)]
    if key != question or not isinstance(selected, str):
        raise ValueError('the answer does not key the question that was asked; refused')
    predefined = selected in labels
    stamp = str(turn.get('timestamp') or '')
    try:
        at = datetime.datetime.fromisoformat(stamp.replace('Z', '+00:00')).timestamp()
    except ValueError:
        raise ValueError('the user source has no usable timestamp')
    now = time.time() if now is None else now
    if max_age is not None and now - at > max_age:
        raise ValueError('the user source is older than %d hours; ask again' % (max_age // 3600))
    if at > now + 300:
        raise ValueError('the user source is dated in the future')
    return {'kind': 'answer', 'session': session, 'uid': uid.lower(), 'at': at, 'text': selected,
            'question': question, 'predefined': predefined}


def _canonical_source(source):
    m = NO_BACKUP_SOURCE_RE.match(str(source or ''))
    return 'answer:%s/%s' % (m.group(1).casefold(), m.group(2).lower()) if m else ''


def _question_names_only(question, real):
    """'' when the question names `real` as a whole path and every other absolute path it names is an ancestor
    of `real` (context such as "under ~/.agent-harness/work/"), else the reason."""
    named = [p.rstrip('.').rstrip('/') or '/' for p in QUESTION_PATH_RE.findall(question or '')]
    if real not in named:
        return 'does not name the literal path %s' % real
    others = [p for p in named if p != real and not real.startswith(p.rstrip('/') + '/')]
    if others:
        return 'names another path too (%s); ask one question per path' % others[0][:120]
    return ''


def _hook_wal_predates(wal_real, at, limit=4 << 20):
    """True when the WAL holds a hook-written (pretool) entry dated before `at` (an epoch)."""
    import datetime
    try:
        fd = os.open(wal_real, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
    except OSError:
        return False
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return False
        raw = os.read(fd, limit)
    finally:
        os.close(fd)
    for line in raw.decode('utf-8', 'replace').splitlines():
        if '"pretool"' not in line:
            continue
        try:
            rec = json.loads(line)
            when = datetime.datetime.fromisoformat(str(rec.get('at')).replace('Z', '+00:00')).timestamp()
        except (ValueError, TypeError, AttributeError):
            continue
        if isinstance(rec, dict) and rec.get('event') == 'pretool' and rec.get('tool_use_id') and when < at:
            return True
    return False


def _uses_of_source(canonical, home=None):
    """How many no-backup approvals this canonical source already gave. An audit log that exists but cannot be
    read counts as the cap (fail closed)."""
    path = state_dir(home) / AUDIT_NAME
    if not path.exists():
        return 0
    try:
        raw = _read_small(path, 64 << 20).decode('utf-8', 'replace')
    except Exception:  # noqa: BLE001 - unreadable: refuse rather than reset the count
        return 1 << 30
    count = 0
    for line in raw.splitlines():
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if isinstance(rec, dict) and rec.get('event') == 'approved' and rec.get('kind') == NO_BACKUP_KIND and \
                _canonical_source(rec.get('user_source')) == canonical:
            count += 1
    return count


def _environment_refusal(user_home):
    """Why the caller's environment points transcript or state lookups away from the account, else ''."""
    configured = os.environ.get('CLAUDE_CONFIG_DIR')
    if configured and os.path.realpath(configured) != os.path.join(user_home, '.claude'):
        return 'CLAUDE_CONFIG_DIR points away from the account\'s ~/.claude; unset it'
    env_home = os.environ.get('HOME')
    if env_home and os.path.realpath(env_home) != user_home:
        return 'HOME is not the account\'s home; unset the override'
    return ''


def approve_delete_no_backup(path, user_source, wal, ttl=None, home=None, policy=None, now=None, resolver=None,
                             attached=None, ls_remote=None):
    """Write a single-use approval for deleting `path` without a backup, on a user's approval. Returns the entry.
    Raises ValueError on refusal (and audits it)."""
    policy = policy or load_policy()
    limits = policy['marker']
    now = time.time() if now is None else now
    real = os.path.realpath(path) if isinstance(path, str) else ''
    source = str(user_source or '')[:300]
    user_home = os.path.realpath(home) if home else _pinned_home()
    try:
        if home is None:
            problem = _environment_refusal(user_home)
            if problem:
                raise ValueError(problem)
        if not wal:
            raise ValueError('--wal is required: the approval is recorded there')
        if not isinstance(path, str) or not os.path.isabs(path):
            raise ValueError('give the absolute literal path')
        if any(ch in path for ch in GLOB_CHARS) or '$' in path or '`' in path:
            raise ValueError('spell out the literal path; globs and variables cannot be approved')
        if os.path.islink(path) or os.path.normpath(path) != path or path != real:
            raise ValueError('give the real path, not a symlink or a path through one')
        if not os.path.exists(real):
            raise ValueError('path does not exist')
        c = Compiled(policy, home=home)
        folded = real.casefold()
        tier = classify_segs(c, Compiled._segs(folded))
        if tier in ('log', 'log-name') or folded in c.state_files or any(rx.search(folded) for rx in c.wal_regexes):
            raise ValueError('logs, WALs, transcripts and approval state are never deleted without a verified backup')
        reason = _approval_refusal(real, policy, home=home)
        if reason:
            raise ValueError(reason)
        max_ttl = int(limits.get('no_backup_max_ttl_seconds', 3600))
        ttl = int(ttl or min(int(limits['default_ttl_seconds']), max_ttl))
        if ttl <= 0 or ttl > max_ttl:
            raise ValueError('ttl must be between 1 and %d seconds' % max_ttl)
        canonical = _canonical_source(source)
        if not canonical:
            raise ValueError('--user-source must be exactly answer:<session>/<uuid> (an AskUserQuestion answer that '
                             'names the path; no excerpt)')
        turn = (resolver or resolve_user_source)(source, now=now, max_age=int(limits.get(
            'no_backup_max_source_age_seconds', 86400)), home=user_home)
        wal_text = str(wal)
        wal_real = os.path.realpath(wal_text)
        wals_root = os.path.realpath(os.path.join(user_home, '.claude', 'wals'))
        if os.path.dirname(wal_real) != os.path.join(wals_root, turn['session']):
            raise ValueError('the answer is from session %s, but --wal is not a WAL of that session' % turn['session'])
        if os.path.islink(wal_text) or wal_text != wal_real or not os.path.isfile(wal_real) or \
                turn['session'] not in os.listdir(wals_root):
            raise ValueError('--wal must be the existing, real WAL file of the session (no symlink, exact name)')
        if not _hook_wal_predates(wal_real, float(turn['at'])):
            raise ValueError('--wal has no hook-written entry that predates the answer; give the WAL of the session '
                             'that asked (its main.jsonl)')
        if turn.get('predefined') is not True:
            raise ValueError('the answer is free text ("Other"), not a predefined option; ask the user again')
        problem = _question_names_only(str(turn.get('question') or ''), real)
        if problem:
            raise ValueError('the AskUserQuestion this answer answers %s; ask the user again naming it' % problem)
        if not APPROVE_WORDS.fullmatch(turn.get('text') or '') or DECLINE_WORDS.search(turn.get('text') or ''):
            raise ValueError('the selected answer does not say delete (or it declines): the option must be exactly '
                             '"Delete, no backup" (optionally "(Recommended)"); ask the user again')
        target = _target_kind(real, home=user_home)
        state = _no_backup_state(real, target, home, attached=attached)
        where = _check_git_pushed(real, ls_remote=ls_remote, hosts=limits.get('no_backup_remote_hosts')
                                  or DEFAULT_REMOTE_HOSTS) if target == 'git' else None
        size = _image_size(real) if target == 'image' else None
        identity = list(_identity(real))
        entry = {'kind': NO_BACKUP_KIND, 'target': target, 'path': real, 'identity': identity, 'state': state,
                 'user_source': canonical, 'remote': 'none: user-approved, no backup', 'files': 0,
                 'manifest_sha256': '', 'verified_at': now, 'expires_at': now + ttl, 'nonce': _secrets.token_hex(8)}
        if where:
            entry['pushed_to'] = where
        if size is not None:
            entry['bytes'] = size
        cap = int(limits.get('no_backup_max_paths_per_source', 4))

        def count_and_audit():
            # under the marker lock: concurrent approvals cannot both pass the cap, and an approval whose audit
            # record cannot be written (the cap is counted from it) is never stored
            if _uses_of_source(canonical, home) >= cap:
                raise ValueError('this user source already approved %d deletions; ask the user again' % cap)
            audit('approved', entry, home=home, strict=True)
        _store_entry(entry, real, now, home, under_lock=count_and_audit)
    except ValueError as error:
        # a refusal never creates the WAL: only an existing, real WAL file gets the record
        wal_ok = bool(wal) and os.path.isfile(str(wal)) and not os.path.islink(str(wal))
        audit('refused', {'path': real, 'kind': NO_BACKUP_KIND, 'user_source': _canonical_source(source) or 'invalid',
                          'reason': str(error)[:200]}, home=home, wal=wal if wal_ok else None)
        raise
    audit('approved', entry, home=home, wal=wal, to_file=False)
    return entry


# --------------------------------------------------------------------------- scan-wal

def scan_paths(paths, max_files=2000, max_seconds=60.0):
    """[(file, line, {kind: count})] for secret-shaped text; values are never returned."""
    import redact
    import safe_input
    deadline = time.monotonic() + max_seconds
    files = []
    for p in paths:
        if os.path.isdir(p):
            for root, _dirs, names in os.walk(p):
                for name in sorted(names):
                    if name.endswith(('.jsonl', '.json', '.log', '.txt', '.md')):
                        files.append(os.path.join(root, name))
                        if len(files) >= max_files:
                            break
        else:
            files.append(p)
    report = []
    for f in files[:max_files]:
        if time.monotonic() > deadline:
            report.append((f, 0, {'scan-stopped': 1}))
            break
        try:
            for number, raw in safe_input.iter_jsonl_lines(f, 8 * 1024 * 1024, max_total_bytes=4 << 30, max_seconds=max(1.0, deadline - time.monotonic())):
                if raw is None:
                    report.append((f, number, {'oversize-line': 1}))
                    continue
                kinds = {}
                for kind, _s, _e in redact.find(raw.decode('utf-8', 'replace')):
                    kinds[kind] = kinds.get(kind, 0) + 1
                if kinds:
                    report.append((f, number, kinds))
        except safe_input.InputRejected as rejected:
            report.append((f, 0, {'unreadable:' + rejected.code: 1}))
    return report


# --------------------------------------------------------------------------- hook and CLI

SHELL_TOOLS = {'bash', 'powershell', 'shell', 'local_shell', 'exec_command', 'container.exec', 'unified_exec',
               'write_stdin'}
COMMAND_KEYS = ('command', 'cmd', 'script', 'chars', 'input')


def extract_command(payload):
    """(command string or argv list, is_powershell) from a PreToolUse payload, or (None, False).

    Codex sends exec_command/shell as tool_name Bash; write_stdin text typed into a running shell is not checked
    again by the host, so its `chars` are analysed as shell input here."""
    if not isinstance(payload, dict):
        return None, False
    tool = str(payload.get('tool_name') or payload.get('toolName') or '')
    tool_input = payload.get('tool_input') or payload.get('toolInput') or {}
    if isinstance(tool_input, str) and tool_input.lstrip().startswith('{'):
        try:  # a host that sends tool_input as a JSON-encoded string
            decoded = json.loads(tool_input)
            if isinstance(decoded, dict):
                tool_input = decoded
        except ValueError:
            pass
    if isinstance(tool_input, (str, list)) and tool.casefold() in SHELL_TOOLS:
        tool_input = {'command': tool_input}
    if not isinstance(tool_input, dict):
        return None, False
    if tool and tool.casefold() not in SHELL_TOOLS and not tool.casefold().startswith(('bash', 'shell', 'exec')):
        return None, False
    command, texts = None, []
    for key in COMMAND_KEYS:
        value = tool_input.get(key)
        if isinstance(value, str) and value.strip():
            if value not in texts:
                texts.append(value)
        elif isinstance(value, list) and value and command is None:
            command = value
    if command is not None and texts:
        # a list command and a string field together: judge both
        texts.insert(0, ' '.join(_quote_for_rebuild(str(c)) for c in command))
        command = None
    if texts:
        # every non-blank command field is judged: a blank `command` must not hide a real `cmd`
        command = '\n'.join(texts) if len(texts) > 1 else texts[0]
    if isinstance(command, list):
        command = [str(c) for c in command]
        if len(command) >= 3 and norm_name(command[0]) in SHELLS and command[1] in ('-c', '-lc', '-ic', '-l', '-i'):
            command = command[2] if command[1].endswith('c') else ' '.join(command[2:])
    if isinstance(command, (str, list)) and command:
        return command, tool.casefold() == 'powershell'
    return None, False


def payload_cwd(payload):
    """Working directory for relative paths: Codex tool_input.workdir, else the payload cwd."""
    if not isinstance(payload, dict):
        return None
    tool_input = payload.get('tool_input') if isinstance(payload.get('tool_input'), dict) else {}
    if str(payload.get('tool_name') or '').casefold() == 'write_stdin' and not tool_input.get('workdir'):
        return None  # text typed into a running shell: its directory may have changed since the session cwd
    for value in (tool_input.get('workdir'), tool_input.get('cwd'), payload.get('cwd')):
        if isinstance(value, str) and value.startswith('/') and len(value) < 4096 and '\x00' not in value:
            return value
    return None


def hook_main(fmt='exit2', stdin_bytes=None, compiled=None, marker=True):
    """PreToolUse entry point. Exit 2 + stderr blocks; exit 0 allows (warnings go to stdout as context).

    Always run behind command_guard_hook.py, which turns a crash or timeout of this process into a raw-text
    decision instead of the host's fail-open default."""
    limits = (compiled.limits if compiled else DEFAULT_POLICY['limits'])
    alarm = False
    if hasattr(signal, 'SIGALRM'):
        def _timeout(_s, _f):
            raise TimeoutError('command_guard wall-clock limit')
        signal.signal(signal.SIGALRM, _timeout)
        signal.alarm(int(float(limits['max_seconds']) * 2) + 1)
        alarm = True
    raw_text = ''
    try:
        import safe_input
        try:
            data = stdin_bytes if stdin_bytes is not None else safe_input.read_stdin_bounded(int(limits['max_stdin_bytes']))
        except safe_input.InputRejected:
            return emit('block', format_block(Finding(SECRET_DUMP, 'oversized-input', 'the tool input is larger than '
                                                      'the guard will analyse', 'put the commands in a script file and '
                                                      'run it')), fmt)
        raw_text = data.decode('utf-8', 'replace')
        try:
            payload = safe_input.safe_json_loads(raw_text)
        except Exception:  # noqa: BLE001
            payload = None
        cwd = payload_cwd(payload)
        c = compiled or Compiled(load_policy(), cwd=cwd)
        if payload is None:
            if raw_sensitive(raw_text, c):
                return emit('block', format_block(Finding(SECRET_DUMP, 'unparsable-payload', 'the hook payload is not '
                                                          'valid JSON and names a protected location or secret',
                                                          'retry the command')), fmt)
            return 0
        command, ps = extract_command(payload)
        if command is None:
            return 0
        approvals = Approvals(compiled=c) if marker else None
        verdict, message = decide(command, c, cwd=cwd, ps=ps, marker=approvals)
        if verdict != 'block' and approvals is not None and approvals.used and not approvals.consume():
            verdict, message = 'block', format_block(Finding(LOG_DELETE, 'approval-used', 'the delete approval was '
                                                             'already used or changed', 'approve again after a fresh '
                                                             'verified backup'))
        return emit(verdict, message, fmt)
    except TimeoutError:
        verdict = 'block' if raw_sensitive(raw_text) else 'warn'
        return emit(verdict, format_block(Finding(SECRET_DUMP if verdict == 'block' else PARSE, 'unanalysable',
                                                  'analysis exceeded its wall-clock limit', 'split it into smaller '
                                                  'commands or put it in a script file'), warn=verdict == 'warn'), fmt)
    except Exception as error:  # noqa: BLE001 - fail closed for sensitive-looking text, open for the rest
        if not raw_text and stdin_bytes is None:
            try:
                raw_text = sys.stdin.buffer.read(8 << 20).decode('utf-8', 'replace')
            except Exception:  # noqa: BLE001
                raw_text = ''
        if raw_sensitive(raw_text):
            return emit('block', format_block(Finding(SECRET_DUMP, 'guard-error', 'guard internal error (%s) on a '
                                                      'command that names a protected location or secret'
                                                      % type(error).__name__, 'split the command into simple steps; '
                                                      'run command_guard.py doctor')), fmt)
        print('command_guard: internal error (%s); the command looked harmless and was allowed'
              % type(error).__name__, file=sys.stderr)
        return 0
    finally:
        if alarm:
            signal.alarm(0)


def emit(verdict, message, fmt):
    """Never emits an explicit allow decision: exit 0 with no decision leaves the host's own permission flow."""
    if verdict == 'allow':
        return 0
    if verdict == 'warn':
        print(json.dumps({'hookSpecificOutput': {'hookEventName': 'PreToolUse', 'additionalContext': message}}))
        return 0
    if fmt == 'json':
        print(json.dumps({'hookSpecificOutput': {'hookEventName': 'PreToolUse', 'permissionDecision': 'deny',
                                                 'permissionDecisionReason': message}}))
        return 2
    print(message, file=sys.stderr)
    return 2


# --------------------------------------------------------------------------- doctor, explain, replay

MIN_CLAUDE_VERSION = (2, 1, 295)  # first Claude Code release with hook `onFailure: block`
DOCTOR_PROBES = (  # (command text, expected verdict); data only, analysed and never executed
    ('rclone config show', 'block'), ('rm -rf ~/.claude/projects', 'block'), ('printenv', 'block'),
    ("cat <<'EOF'\nx\nEOF\nrm -rf ~/.codex/sessions", 'block'), ('git status', 'allow'), ('ls ~/.claude', 'allow'),
)


def _version_tuple(text):
    m = re.search(r'(\d+)\.(\d+)\.(\d+)', text or '')
    return tuple(int(x) for x in m.groups()) if m else None


def claude_version(runner=None):
    try:
        if runner:
            return _version_tuple(runner())
        done = subprocess.run(['claude', '--version'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=20,
                              check=False)
        return _version_tuple(done.stdout.decode('utf-8', 'replace'))
    except (OSError, subprocess.SubprocessError):
        return None


def _hook_entries(data, needle):
    out = []
    groups = ((data or {}).get('hooks') or {}).get('PreToolUse') or []
    for group in groups if isinstance(groups, list) else []:
        for hook in (group.get('hooks') or []) if isinstance(group, dict) else []:
            text = isinstance(hook, dict) and ' '.join([str(hook.get('command', ''))] + [str(a) for a in hook.get('args') or []])
            if text and needle in text:
                out.append((group, hook))
    return out


def doctor(home=None, version_runner=None):
    """[(check, ok, detail)] for the installed guard on this machine."""
    import safe_input
    home = Path(home or os.path.expanduser('~'))
    checks = [('python>=3.9', sys.version_info >= (3, 9), '%d.%d' % sys.version_info[:2])]
    for label, d in (('claude', home / '.claude' / 'hooks'), ('codex', home / '.codex' / 'agent-harness')):
        if not d.parent.is_dir():
            continue
        names = ('command_guard.py', 'command_guard_hook.py', 'redact.py', 'safe_input.py')
        missing = [n for n in names if not (d / n).is_file()]
        checks.append(('%s files' % label, not missing, 'missing: ' + ', '.join(missing) if missing else str(d)))
        settings = home / '.claude' / 'settings.json' if label == 'claude' else home / '.codex' / 'hooks.json'
        try:
            data = safe_input.safe_json_loads(safe_input.read_bounded(str(settings), 4 << 20).decode('utf-8'))
        except Exception:  # noqa: BLE001
            data = None
        entries = _hook_entries(data, 'command_guard_hook.py')
        checks.append(('%s registered' % label, bool(entries), str(settings)))
        if label == 'claude' and entries:
            group, hook = entries[0]
            checks.append(('claude onFailure block', hook.get('onFailure') == 'block', 'hook entry'))
            matcher = str(group.get('matcher', ''))
            checks.append(('claude matcher covers Bash', matcher in ('', '*') or 'Bash' in matcher, matcher or '(all)'))
            version = claude_version(version_runner)
            ok = version is not None and version >= MIN_CLAUDE_VERSION
            checks.append(('claude >= 2.1.295', ok, '.'.join(map(str, version)) if version else 'unknown: '
                           'fail-closed then rests on the launcher alone'))
        if label == 'codex' and entries:
            group, _hook = entries[0]
            checks.append(('codex no matcher', not group.get('matcher'), 'every tool reaches the guard (write_stdin)'))
    c = Compiled(load_policy(), home=str(home), cwd=str(home))
    bad = [cmd.split('\n')[0][:30] for cmd, want in DOCTOR_PROBES if decide(cmd, c, cwd=str(home))[0] != want]
    checks.append(('self-test probes', not bad, 'wrong: ' + '; '.join(bad) if bad else '%d ok' % len(DOCTOR_PROBES)))
    return checks


def explain(text, cwd=None, ps=False):
    c = Compiled(load_policy(), cwd=cwd)
    analyzer = Analyzer(c, cwd=cwd, ps=ps)
    try:
        findings = analyzer.run(text)
        detail = [{'category': f.category, 'rule': f.rule, 'reason': f.reason, 'alternative': f.alternative}
                  for f in findings]
    except Exception as error:  # noqa: BLE001
        detail = [{'error': type(error).__name__}]
    verdict, message = decide(text, c, cwd=cwd, ps=ps)
    import redact
    return {'verdict': verdict, 'message': message, 'findings': redact.redact_obj(detail)}


def iter_transcript_commands(path, max_bytes=256 << 20):
    """(cwd, command) for every Bash-like tool call in a Claude Code or Codex JSONL transcript."""
    try:
        size = os.path.getsize(path)
    except OSError:
        return
    if size > max_bytes:
        return
    with open(path, 'rb') as handle:
        for raw in handle:
            if len(raw) > 4 << 20:
                continue
            try:
                record = json.loads(raw)
            except ValueError:
                continue
            if not isinstance(record, dict):
                continue
            cwd = record.get('cwd') if isinstance(record.get('cwd'), str) else None
            stack = [record]
            seen = 0
            while stack and seen < 2000:
                node = stack.pop()
                seen += 1
                if isinstance(node, dict):
                    name = str(node.get('name') or node.get('tool_name') or '')
                    args = node.get('input') if isinstance(node.get('input'), dict) else node.get('arguments')
                    if isinstance(args, str):
                        try:
                            args = json.loads(args)
                        except ValueError:
                            args = None
                    if name and isinstance(args, dict):
                        command, _ps = extract_command({'tool_name': name, 'tool_input': args})
                        if command:
                            yield (payload_cwd({'cwd': cwd, 'tool_input': args}),
                                   command if isinstance(command, str) else ' '.join(command))
                            continue
                    stack.extend(v for v in node.values() if isinstance(v, (dict, list)))
                elif isinstance(node, list):
                    stack.extend(v for v in node if isinstance(v, (dict, list)))


def replay(paths, max_commands=200000):
    """Decision counts over real transcripts; commands are never printed, only rule counts and digests."""
    counts = {'allow': 0, 'warn': 0, 'block': 0}
    by_rule, failure_path, samples = {}, 0, []
    c_cache = {}
    total = 0
    for path in paths:
        for cwd, command in iter_transcript_commands(path):
            total += 1
            if total > max_commands:
                break
            c = c_cache.get(cwd)
            if c is None:
                c = c_cache[cwd] = Compiled(load_policy(), cwd=cwd)
            verdict, message = decide(command, c, cwd=cwd)
            counts[verdict] += 1
            if verdict != 'allow':
                m = re.match(r'command_guard \w+ \[([^\]]+)\]', message)
                rule = m.group(1) if m else 'unknown'
                by_rule[rule] = by_rule.get(rule, 0) + 1
                if rule.endswith(('/unanalysable', '/guard-error', '/unterminated', '/unparsable-payload')):
                    failure_path += 1
                if len(samples) < 200:
                    samples.append({'verdict': verdict, 'rule': rule,
                                    'sha256': hashlib.sha256(command.encode('utf-8', 'replace')).hexdigest()[:16]})
    return {'commands': total, 'counts': counts, 'by_rule': by_rule, 'failure_path_blocks_or_warnings': failure_path,
            'samples': samples}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest='cmd', required=True)
    hook = sub.add_parser('hook')
    hook.add_argument('--format', choices=('exit2', 'json'), default='exit2')
    check = sub.add_parser('check', help='decision for one command given as an argument (runs nothing)')
    check.add_argument('command')
    check.add_argument('--ps', action='store_true')
    check.add_argument('--cwd')
    exp = sub.add_parser('explain', help='decision and every finding for a command read from a file')
    exp.add_argument('--file', required=True)
    exp.add_argument('--ps', action='store_true')
    exp.add_argument('--cwd')
    sub.add_parser('doctor', help='check the installed guard, its registration and a self-test')
    rep = sub.add_parser('replay', help='decision counts over transcript JSONL files (never prints commands)')
    rep.add_argument('paths', nargs='+')
    appr = sub.add_parser('approve-delete')
    appr.add_argument('--path', required=True)
    appr.add_argument('--remote', help='named rclone remote mirroring --path, e.g. dropbox:backups/x')
    appr.add_argument('--archive', help='named rclone remote of ONE tar archive (.tar, .tar.gz or .tar.zst) of --path, '
                                        'whose members start with the directory name of --path (goodqa#15068)')
    appr.add_argument('--archive-sha256', dest='archive_sha256', help='remote .sha256 file of --archive')
    appr.add_argument('--archive-listing', dest='archive_listing', help='remote `tar -tvf` listing of --archive')
    appr.add_argument('--no-backup', action='store_true',
                      help='user-approved deletion without a backup: a clean, pushed git working tree or a detached '
                           'disk image under ~/.agent-harness/work only; needs --user-source (goodqa#14911)')
    appr.add_argument('--user-source', help='answer:<session>/<uuid> of the AskUserQuestion answer that names the '
                                            'path (same session as --wal)')
    appr.add_argument('--wal', required=True, help='WAL that records this approval')
    appr.add_argument('--backup-verified-sha256', dest='digest')
    appr.add_argument('--ttl', type=int)
    for name in ('verify-worktree', 'remove-worktree'):
        wt = sub.add_parser(name, help='JSON verdict for one linked worktree (ah worktree-remove runs this on the target host)')
        wt.add_argument('--path', required=True)
        wt.add_argument('--remote-auth', action='store_true',
                        help='read the remote with this host\'s own credentials (private repository); refs cannot be supplied')
        if name == 'remove-worktree':
            wt.add_argument('--expect-head')
    sub.add_parser('revoke-delete')
    scan = sub.add_parser('scan-wal')
    scan.add_argument('paths', nargs='+')
    args = parser.parse_args(argv)
    if args.cmd == 'hook':
        return hook_main(args.format)
    if args.cmd == 'check':
        c = Compiled(load_policy(), cwd=args.cwd)
        verdict, message = decide(args.command, c, cwd=args.cwd, ps=args.ps, marker=Approvals(compiled=c))
        print(json.dumps({'verdict': verdict, 'message': message}))
        return 0 if verdict != 'block' else 2
    if args.cmd == 'explain':
        import safe_input
        text = safe_input.read_bounded(args.file, 4 << 20).decode('utf-8', 'replace')
        result = explain(text, cwd=args.cwd, ps=args.ps)
        print(json.dumps(result, indent=1))
        return 0 if result['verdict'] != 'block' else 2
    if args.cmd == 'doctor':
        checks = doctor()
        for name, ok, detail in checks:
            print(json.dumps({'check': name, 'ok': bool(ok), 'detail': detail}))
        healthy = all(ok for _n, ok, _d in checks)
        print(json.dumps({'status': 'HEALTHY' if healthy else 'UNHEALTHY'}))
        return 0 if healthy else 1
    if args.cmd == 'replay':
        print(json.dumps(replay(args.paths), indent=1))
        return 0
    if args.cmd == 'approve-delete' and (args.no_backup or args.user_source) and \
            (args.archive or args.archive_sha256 or args.archive_listing):
        print('approve-delete refused: --no-backup and --archive are different approvals; give one of them',
              file=sys.stderr)
        return 2
    if args.cmd == 'approve-delete' and (args.no_backup or args.user_source):
        if not (args.no_backup and args.user_source) or args.remote or args.digest:
            print('approve-delete refused: --no-backup needs --user-source and takes no --remote or '
                  '--backup-verified-sha256', file=sys.stderr)
            return 2
        try:
            entry = approve_delete_no_backup(args.path, args.user_source, args.wal, ttl=args.ttl)
        except (ValueError, OSError, subprocess.SubprocessError) as error:
            print('approve-delete refused: %s' % error, file=sys.stderr)
            return 2
        print(json.dumps({'status': 'APPROVED', 'kind': NO_BACKUP_KIND, 'target': entry['target'],
                          'path': entry['path'], 'expires_at': entry['expires_at']}))
        return 0
    if args.cmd == 'approve-delete' and (args.archive or args.archive_sha256 or args.archive_listing):
        if not (args.archive and args.archive_sha256 and args.archive_listing) or args.remote:
            print('approve-delete refused: --archive needs --archive-sha256 and --archive-listing and takes no '
                  '--remote', file=sys.stderr)
            return 2
        try:
            entry = approve_delete(args.path, args.archive, pinned_digest=args.digest, ttl=args.ttl, wal=args.wal,
                                   archive=(args.archive_sha256, args.archive_listing))
        except (ValueError, OSError, subprocess.SubprocessError) as error:
            print('approve-delete refused: %s' % error, file=sys.stderr)
            return 2
        print(json.dumps({'status': 'APPROVED', 'kind': ARCHIVE_KIND, 'path': entry['path'],
                          'expires_at': entry['expires_at'], 'manifest_sha256': entry['manifest_sha256'],
                          'files': entry['files'], 'archive': entry['archive'],
                          'archive_sha256': entry['archive_sha256']}))
        return 0
    if args.cmd == 'approve-delete':
        if not args.remote:
            print('approve-delete refused: --remote is required (or --no-backup with --user-source)', file=sys.stderr)
            return 2
        try:
            entry = approve_delete(args.path, args.remote, pinned_digest=args.digest, ttl=args.ttl, wal=args.wal)
        except (ValueError, OSError) as error:
            print('approve-delete refused: %s' % error, file=sys.stderr)
            return 2
        print(json.dumps({'status': 'APPROVED', 'path': entry['path'], 'expires_at': entry['expires_at'],
                          'manifest_sha256': entry['manifest_sha256'], 'files': entry['files']}))
        return 0
    if args.cmd in ('verify-worktree', 'remove-worktree'):
        policy = load_policy()
        if args.cmd == 'verify-worktree':
            result = verify_worktree(args.path, args.remote_auth, policy)
        else:
            result = remove_worktree(args.path, args.remote_auth, args.expect_head, policy)
        print(json.dumps(result))
        return 0 if result.get('removable') and (args.cmd == 'verify-worktree' or result.get('removed')) else 1
    if args.cmd == 'revoke-delete':
        try:
            os.unlink(str(state_dir() / MARKER_NAME))
        except FileNotFoundError:
            pass
        audit('revoked', {})
        print('{"status": "REVOKED"}')
        return 0
    if args.cmd == 'scan-wal':
        report = scan_paths(args.paths)
        for f, line, kinds in report:
            print(json.dumps({'file': f, 'line': line, 'kinds': kinds}))
        print(json.dumps({'status': 'FOUND' if report else 'CLEAN', 'findings': len(report)}))
        return 1 if report else 0
    return 3


if __name__ == '__main__':
    sys.exit(main())
