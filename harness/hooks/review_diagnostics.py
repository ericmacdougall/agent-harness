#!/usr/bin/env python3
"""Reliability helpers for peer_review.py: executable discovery, failure diagnostics, packet lint.

Why a separate module: the review helper kept failing in ways that looked identical from outside
(codex missing from PATH, vague usage-limit prose, a huge-repo fetch timing out, partial or sparse
clones) and each failure tempted the operator into an unreviewed fallback. This module gives every
failure a stable code, an exact next step, and a fixed disclosure that native evidence is not a
helper receipt. Stdlib only; must run on Python 3.9.
"""

from __future__ import annotations

import json
import math
import os
import re
import shlex
import stat
import sys
import time
import unicodedata
from pathlib import Path

try:  # imported as a hook sibling; absent only in odd embeddings
    from safe_input import InputRejected, read_bounded
except ImportError:  # pragma: no cover
    InputRejected = Exception
    read_bounded = None

POLICY_ENV = 'AGENT_HARNESS_REVIEW_POLICY'
POLICY_BYTES = 65536
PROVIDERS = ('codex', 'claude')
SNAPSHOT_MAX = 7200

DEFAULT_POLICY = {
    'known_install_locations': {
        'codex': ['/Applications/ChatGPT.app/Contents/Resources/codex-cli/bin/codex', '/usr/bin/codex',
                  '/usr/local/bin/codex', '/opt/homebrew/bin/codex'],
        'claude': ['~/.claude/local/claude', '~/.local/bin/claude', '/usr/local/bin/claude',
                   '/opt/homebrew/bin/claude'],
    },
    'snapshot_timeout': {'base_seconds': 1800, 'per_gib_seconds': 60, 'max_seconds': SNAPSHOT_MAX},
    'usage_limit_phrases': ['hit your usage limit', 'usage limit reached', 'reached your usage limit',
                            'exceeded your usage limit', "you've hit your limit"],
}

NATIVE_EVIDENCE = ('Native evidence: if you continue without a helper receipt, record the native review as '
                   'native evidence only. It is disclosed, it is not a helper receipt, and it never carries '
                   'the PR pass marker.')

# code -> (usage-guard reason, cause, next steps). Tests iterate this table; keep codes stable.
CONTRACT = {
    'EXEC_NOT_FOUND': ('TRANSIENT_INFRA', 'The reviewer CLI was not found on PATH or in the policy install locations.',
                       ['Run `command -v codex claude` in a normal shell and note the absolute path.',
                        'Add that absolute path to known_install_locations in review_policy.json, or set '
                        'AGENT_HARNESS_REVIEW_POLICY to a private copy you own (its list for a provider replaces the '
                        'default list, so copy the defaults you still want), then rerun the same command once.']),
    'EXEC_UNTRUSTED': ('TRANSIENT_INFRA', 'A reviewer CLI was found but refused: it sits inside the repo or cwd, '
                       'is writable by others, or has an unsafe parent directory.',
                       ['Install the CLI in a directory only you or root can write (for example ~/.local/bin).',
                        'Do not point the policy at a binary inside the reviewed repository.']),
    'PROVIDER_USAGE_LIMIT': ('QUOTA', 'The provider reported a usage limit in free text (no structured code).',
                             ['Wait for the limit to reset or use the other authorized provider; the helper '
                              'already tries one independent fallback and will not retry this provider.',
                              'No account-pool cooldown is written because the text is unstructured.']),
    'PROVIDER_AUTH': ('AUTH', 'The provider rejected authentication.',
                      ['Sign in again with the provider CLI, then rerun once.']),
    'PROVIDER_UNAVAILABLE': ('TRANSIENT_INFRA', 'The provider was overloaded, rate limited or its model was unavailable.',
                             ['Rerun once later; the helper already tried the independent fallback if one was allowed.']),
    'REVIEW_NOT_STARTED': ('TRANSIENT_INFRA', 'Local review infrastructure refused before the provider launch boundary (NOT_STARTED); no provider response was observed.',
                           ['Inspect the local run receipt and provider-pool reservation or cooldown. Reconcile only with the required ownership evidence; do not retry unchanged.']),
    'REVIEW_LAUNCH_UNCONFIRMED': ('UNKNOWN', 'No reviewer exit status was recorded; a provider process may have started. This does not establish a provider outage.',
                                ['Inspect the run and child records and reconcile uncertain process ownership before any retry. Do not assume best-effort cleanup succeeded.']),
    'BUDGET_EXHAUSTED': ('BUDGET_EXHAUSTED', 'The 1440 second review budget (720 per provider) was used up.',
                         ['Do not loop. Reconcile the usage store, then decide with the main agent whether one repeat with --repeat-reason is justified.']),
    'PROVIDER_TIMEOUT': ('TIMEOUT', 'The provider exceeded its 720 second deadline.',
                         ['Reconcile the run in the usage store before any retry; do not loop.']),
    'PROVIDER_IO_UNKNOWN': ('UNKNOWN', 'The provider process could not be supervised to a known end.',
                            ['Reconcile the unknown run in the usage store before any retry.']),
    'PROVIDER_INVALID_OUTPUT': ('INVALID_OUTPUT', 'The provider produced no valid stage verdict.',
                                ['Inspect the excerpt below; a rerun needs a changed packet or a declared repeat reason.']),
    'FALLBACK_NO_RESULT': ('INVALID_OUTPUT', 'The independent fallback produced no valid result and no more providers remain.',
                           ['Check the exit code and excerpt below, fix the cause, and rerun once with --repeat-reason.']),
    'SNAPSHOT_TIMEOUT': ('TRANSIENT_INFRA', 'Preparing the review snapshot exceeded its deadline.',
                         ['Rerun with a larger --snapshot-timeout (maximum 7200) or tune snapshot_timeout in review_policy.json.',
                          'The snapshot deadline is separate from the 720 second per-provider budget.']),
    'SNAPSHOT_GIT_FAILED': ('TRANSIENT_INFRA', 'An isolated Git step failed.',
                            ['Run `git -C <repo> fsck --connectivity-only` and `git -C <repo> status` to see why.']),
    'SNAPSHOT_PARTIAL_CLONE': ('TRANSIENT_INFRA', 'The repository is a partial clone (promisor remote).',
                               ['Review from a full clone: `git clone --no-local <repo> <fresh-dir>`, check out the commit, rerun with --repo <fresh-dir>.']),
    'SNAPSHOT_SPARSE_INDEX': ('TRANSIENT_INFRA', 'The index has skip-worktree (sparse checkout) entries.',
                              ['Review from a fresh full clone, or in this clone run `git sparse-checkout disable`.']),
    'SNAPSHOT_HIDDEN_INDEX_FLAG': ('TRANSIENT_INFRA', 'The index has assume-unchanged or other hidden entry flags.',
                                   ['List them with `git ls-files -v | grep "^[a-z]"` and clear with `git update-index --no-assume-unchanged <path>`.']),
    'SNAPSHOT_SHALLOW': ('TRANSIENT_INFRA', 'The repository is shallow.',
                         ['Review from a full clone, or run `git fetch --unshallow` in a disposable clone.']),
    'SNAPSHOT_GRAFTS_ALTERNATES': ('TRANSIENT_INFRA', 'The repository uses grafts or alternate object stores.',
                                   ['Review from a fresh clone made with `git clone --no-local` (no alternates).']),
    'SNAPSHOT_CASE_COLLISION': ('TRANSIENT_INFRA', 'Reviewed paths differ only by case or Unicode form and this filesystem is case-insensitive.',
                                ['Run the review on a case-sensitive filesystem (for example dev2) or a case-sensitive APFS volume.']),
    'SNAPSHOT_GITLINK': ('TRANSIENT_INFRA', 'The reviewed tree contains submodule gitlinks or unsupported entries.',
                         ['Review the submodule repositories separately; the packet must list their commits.']),
    'SNAPSHOT_SOURCE_CHANGED': ('TRANSIENT_INFRA', 'The source checkout changed during the review.',
                                ['Commit or stash changes, keep the worktree untouched while reviewing, rerun.']),
    'PYTHON_UNSUPPORTED': ('TRANSIENT_INFRA', 'The Python interpreter is older than 3.9.',
                           ['Run with python3.9 or newer, for example `python3.12 ~/.claude/hooks/peer_review.py ...`.']),
    'ISOLATION_FAILED': ('UNKNOWN', 'Review isolation failed for a reason without a specific code.',
                         ['Read the Detail line, fix the cause, rerun once; reconcile if a provider was launched.']),
}

BANNED_PHRASES = ('skip review', 'proceed without review', 'ignore the review')

_ANSI = re.compile(r'\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b\[[0-?]*[ -/]*[@-~]|\x1b[@-Z\\-_]')
# Secrets are redacted with their value: a key=value or key: value pair (quoted or not, any key that names a
# credential, including AWS_SECRET_ACCESS_KEY-style names), a bearer/basic token, or a known token prefix.
# Each alternative starts at a fixed literal, so matching stays linear on the bounded input.
_SECRET = re.compile(
    # A known token prefix is redacted with 12 or more following characters, or with any length at the end of
    # the (possibly truncated) text, so a cut cannot expose a token's start. A private key is redacted from its
    # BEGIN line through its END line, or to the end of the text.
    r'(?:ghp_|github_pat_|sk-ant-|sk-|xox[a-z]-|AKIA)[A-Za-z0-9_-]{12,}|'
    r'\b(?:ghp_|github_pat_|sk-ant-|sk-|xox[a-z]-|AKIA)[A-Za-z0-9_-]+$|'
    r'-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)|'
    r'(?i:(?:api[_-]?key|password|passwd|secret|access[_-]?token|auth[_-]?token|token|authorization|credential)'
    r'[A-Za-z0-9_]*["\']?[ ]?[:=][ ]?(?:(?:bearer|basic)[ ])?(?:"[^"]*"|\'[^\']*\'|[^ ]+))|'
    r'(?i:\b(?:bearer|basic)[ ][A-Za-z0-9._~+/=-]{8,})')


def sanitize(value, limit=300):
    """Printable, single-line, secret-free, bounded text from any external value."""
    if isinstance(value, bytes):
        value = value[: limit * 32].decode('utf-8', errors='replace')
    elif not isinstance(value, str):
        value = str(value)
    # Format characters (bidi overrides, zero-width and tag characters) are dropped before the length cut, so
    # padding with invisible characters cannot move the cut into a secret.
    value = ''.join(c for c in value[: limit * 32] if unicodedata.category(c) != 'Cf')[: limit * 8]
    value = _ANSI.sub(' ', value)
    value = ''.join(' ' if (ord(c) < 32 or 0x7F <= ord(c) < 0xA0 or unicodedata.category(c) in ('Cc', 'Cs', 'Co'))
                    else c for c in value)
    value = _SECRET.sub('[redacted]', re.sub(r'\s+', ' ', value)).strip()
    return value[:limit]


# ---------------------------------------------------------------- policy

def _clamp_number(value, low, high, default):
    if type(value) not in (int, float) or isinstance(value, bool) or not math.isfinite(value):
        return default
    return min(max(value, low), high)


def _ancestor_problem(real):
    """Why a directory above real lets another user swap it, or None.

    Every ancestor must be owned by the current uid or root, and must not be world-writable unless it is
    sticky and root-owned (such as /tmp). Raises OSError when an ancestor cannot be inspected.
    """
    parent = os.path.dirname(real)
    while True:
        pinfo = os.stat(parent)
        if pinfo.st_uid not in (os.geteuid(), 0):
            return 'parent directory owned by another user'
        if pinfo.st_mode & 0o002 and not (pinfo.st_mode & stat.S_ISVTX and pinfo.st_uid == 0):
            return 'parent directory is world-writable'
        if parent == os.sep:
            return None
        parent = os.path.dirname(parent)


def _policy_trusted(path):
    """The override must be a private regular file in directories no other user can rewrite."""
    real = os.path.realpath(path)
    info = os.stat(real)
    return (stat.S_ISREG(info.st_mode) and info.st_uid in (os.geteuid(), 0) and not info.st_mode & 0o022
            and _ancestor_problem(real) is None)


def load_policy(path=None, warn=None):
    """Return a validated policy. Any problem falls back to built-in defaults, never to a wider policy."""
    warn = warn or (lambda message: None)
    override = path is not None or POLICY_ENV in os.environ
    chosen = path or os.environ.get(POLICY_ENV) or Path(__file__).with_name('review_policy.json')
    result = json.loads(json.dumps(DEFAULT_POLICY))
    try:
        if override and not _policy_trusted(chosen):
            warn('review policy ignored: it must be a regular file owned by you or root, not group/world-writable, '
                 'in directories owned by you or root that no other user can write')
            return result
        if read_bounded is None:
            return result
        raw = json.loads(read_bounded(chosen, POLICY_BYTES).decode('utf-8'))
    except (OSError, ValueError, InputRejected, UnicodeError, RecursionError):
        if override:
            warn('review policy ignored: unreadable or malformed')
        return result
    if not isinstance(raw, dict):
        return result
    locations = raw.get('known_install_locations')
    if isinstance(locations, dict):
        for name in PROVIDERS:
            entries = locations.get(name)
            if isinstance(entries, list):
                good = [e for e in entries[:32] if isinstance(e, str) and len(e) <= 1024 and '\0' not in e
                        and (e.startswith('/') or e.startswith('~/'))]
                result['known_install_locations'][name] = good
    snap = raw.get('snapshot_timeout')
    if isinstance(snap, dict):
        base = DEFAULT_POLICY['snapshot_timeout']
        result['snapshot_timeout'] = {
            'base_seconds': _clamp_number(snap.get('base_seconds'), 1, SNAPSHOT_MAX, base['base_seconds']),
            'per_gib_seconds': _clamp_number(snap.get('per_gib_seconds'), 0, SNAPSHOT_MAX, base['per_gib_seconds']),
            'max_seconds': _clamp_number(snap.get('max_seconds'), 1, SNAPSHOT_MAX, base['max_seconds'])}
    phrases = raw.get('usage_limit_phrases')
    if isinstance(phrases, list):
        good = [p.lower() for p in phrases[:32] if isinstance(p, str) and 6 <= len(p) <= 128]
        if good:
            result['usage_limit_phrases'] = good
    return result


# ---------------------------------------------------------------- executable discovery

def _home():
    try:  # the account database, not an attacker-settable $HOME
        import pwd
        return pwd.getpwuid(os.geteuid()).pw_dir
    except (ImportError, KeyError, OSError):
        return os.path.expanduser('~')


def _expand(location):
    return os.path.join(_home(), location[2:]) if location.startswith('~/') else location


def _fold(path):
    return unicodedata.normalize('NFC', path).casefold()


def _inside(real, roots):
    """True when real is a root or below one.

    Path text is compared NFC-normalized and case-folded, because macOS volumes are usually case-insensitive
    and realpath keeps the spelling it was given. Ancestors are also compared by device and inode, which
    catches any alias the text comparison misses. On a case-sensitive volume the folding can only refuse
    more, never accept a path inside a root.
    """
    folded = _fold(real)
    for root in roots:
        base = _fold(root).rstrip(os.sep)
        if folded == base or folded.startswith(base + os.sep) or (not base and folded.startswith(os.sep)):
            return True
    identities = set()
    for root in roots:
        try:
            info = os.stat(root)
        except (OSError, ValueError):
            continue
        identities.add((info.st_dev, info.st_ino))
    if not identities:
        return False
    current = real
    for _ in range(256):  # bounded walk to the filesystem root
        try:
            info = os.stat(current)
        except (OSError, ValueError):
            info = None
        if info is not None and (info.st_dev, info.st_ino) in identities:
            return True
        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent
    return False


def untrusted_roots(repo=None, snapshot=None, cwd=None):
    """Directories whose contents are the reviewed project's, never a source of tools to run."""
    roots = []
    home = os.path.realpath(_home())
    for item in (repo, snapshot):
        if item:
            roots.append(os.path.realpath(os.fspath(item)))
    here = os.path.realpath(os.fspath(cwd if cwd is not None else os.getcwd()))
    # A cwd that contains the home directory (or is it) would reject every user-installed tool.
    if here != os.sep and here != home and not (home + os.sep).startswith(here + os.sep):
        roots.append(here)
    return roots


def child_path(path_value, roots):
    """PATH for a reviewer child process: absolute entries outside the reviewed roots only.

    A trusted reviewer can still be a `#!/usr/bin/env node` script; its interpreter is looked up on this
    PATH, so an empty, relative or repo/snapshot/cwd entry would let committed files act as the interpreter.
    """
    kept = []
    for entry in (path_value or '').split(os.pathsep):
        if not entry or not os.path.isabs(entry):
            continue
        try:
            real = os.path.realpath(entry)
        except (OSError, ValueError):
            continue
        if _inside(real, roots) or entry in kept:
            continue
        kept.append(entry)
    return os.pathsep.join(kept)


def check_executable(path, roots):
    """(real path, None) for a trustworthy regular executable, else (None, reason)."""
    try:
        real = os.path.realpath(path)
        if _inside(real, roots):
            return None, 'inside the repository, snapshot or working directory'
        info = os.stat(real)
        if not stat.S_ISREG(info.st_mode) or not info.st_mode & 0o111 or not os.access(real, os.X_OK):
            return None, 'not an executable regular file'
        if info.st_uid not in (os.geteuid(), 0):
            return None, 'owned by another user'
        if info.st_mode & 0o022:
            return None, 'writable by group or others'
        problem = _ancestor_problem(real)
        if problem:
            return None, problem
    except (OSError, ValueError):
        return None, 'not accessible'
    return real, None


def discover_executable(name, *, policy, roots, path_env=None):
    """Find a reviewer CLI: PATH (absolute entries only), then policy locations.

    Returns {'name','path','source','rejected'}; path is None when nothing trustworthy exists.
    One answer per provider: callers must make exactly one exec attempt with it.
    """
    rejected, seen, searched = [], set(), []
    candidates = []
    for entry in (os.environ.get('PATH', '') if path_env is None else path_env).split(os.pathsep):
        if entry and os.path.isabs(entry):
            candidates.append((os.path.join(entry, name), 'PATH'))
    for location in policy.get('known_install_locations', {}).get(name, []):
        candidates.append((_expand(location), 'policy'))
    for candidate, source in candidates:
        if candidate in seen:
            continue
        seen.add(candidate)
        searched.append(sanitize(candidate, 120))
        if not os.path.lexists(candidate):
            continue
        real, reason = check_executable(candidate, roots)
        if real:
            return {'name': name, 'path': real, 'source': source, 'rejected': rejected, 'searched': searched}
        rejected.append({'path': sanitize(candidate, 200), 'reason': reason})
    return {'name': name, 'path': None, 'source': None, 'rejected': rejected, 'searched': searched}


def executable_record(resolutions):
    """Run-record usage field: provider -> bounded path and source."""
    return {name: {'path': sanitize(item['path'], 512), 'source': item['source']}
            for name, item in resolutions.items() if item.get('path')}


# ---------------------------------------------------------------- snapshot timeout

def parse_pack_bytes(count_objects_output):
    """Sum size and size-pack (KiB) from `git count-objects -v`; 0 when unparseable."""
    total = 0
    for line in str(count_objects_output)[:4096].splitlines():
        match = re.fullmatch(r'(size|size-pack|size-garbage):\s*(\d{1,15})', line.strip())
        if match and match[1] != 'size-garbage':
            total += int(match[2]) * 1024
    return total


def scaled_snapshot_timeout(pack_bytes, policy, requested=None):
    if requested is not None:
        return requested
    snap = policy['snapshot_timeout']
    gib = max(0, pack_bytes) / float(1024 ** 3)
    return int(min(snap['max_seconds'], snap['base_seconds'] + gib * snap['per_gib_seconds']))


# ---------------------------------------------------------------- filesystem shape checks

def collision_key(path):
    return unicodedata.normalize('NFC', unicodedata.normalize('NFD', path).casefold())


def path_collisions(paths, limit=5):
    seen, found = {}, []
    for path in paths:
        key = collision_key(path)
        if key in seen and seen[key] != path:
            found.append((seen[key], path))
            if len(found) >= limit:
                break
        else:
            seen.setdefault(key, path)
    return found


def fs_is_case_insensitive(directory):
    probe = Path(directory) / ('.CaseProbe' + str(os.getpid()))
    try:
        probe.write_bytes(b'')
        try:
            return (Path(directory) / probe.name.lower()).exists()
        finally:
            probe.unlink()
    except OSError:
        return False


# ---------------------------------------------------------------- diagnostics

def python_diagnostic(version_info=None):
    version = tuple(version_info if version_info is not None else sys.version_info[:3])
    return diagnostic('PYTHON_UNSUPPORTED', detail='python ' + '.'.join(map(str, version[:3]))) if version < (3, 9) else None


def diagnostic(code, *, provider=None, detail='', excerpt=None, exit_code=None):
    reason, cause, steps = CONTRACT[code]
    return {'code': code, 'reason': reason, 'cause': cause, 'steps': list(steps), 'provider': provider,
            'detail': sanitize(detail, 600), 'excerpt': None if excerpt is None else sanitize(excerpt, 300),
            'exit_code': exit_code}


def classify_isolation_error(error):
    """Map an isolation exception to a stable diagnostic; message text is matched, never echoed raw."""
    text = str(error)
    rules = (
        (r'exceeded --snapshot-timeout|timed out after', 'SNAPSHOT_TIMEOUT'),
        (r'partial repositories', 'SNAPSHOT_PARTIAL_CLONE'),
        (r'shallow repositories', 'SNAPSHOT_SHALLOW'),
        (r'grafts and alternate|gained grafts', 'SNAPSHOT_GRAFTS_ALTERNATES'),
        (r"hidden or unsupported (?:entry )?flags? \('S'\)", 'SNAPSHOT_SPARSE_INDEX'),
        (r'hidden or unsupported (?:entry )?flags?', 'SNAPSHOT_HIDDEN_INDEX_FLAG'),
        (r'differ only by case', 'SNAPSHOT_CASE_COLLISION'),
        (r'gitlinks', 'SNAPSHOT_GITLINK'),
        (r'source changed|worktree changed during|HEAD or worktree changed', 'SNAPSHOT_SOURCE_CHANGED'),
        (r'isolated Git operation failed', 'SNAPSHOT_GIT_FAILED'),
    )
    if isinstance(error, TimeoutError) or type(error).__name__ == 'TimeoutExpired':
        return diagnostic('SNAPSHOT_TIMEOUT', detail=text)
    for pattern, code in rules:
        if re.search(pattern, text):
            return diagnostic(code, detail=text)
    return diagnostic('ISOLATION_FAILED', detail=text)


PROVIDER_REASON_CODES = {'TRANSIENT_INFRA': 'PROVIDER_UNAVAILABLE', 'BUDGET_EXHAUSTED': 'BUDGET_EXHAUSTED', 'QUOTA': 'PROVIDER_USAGE_LIMIT', 'AUTH': 'PROVIDER_AUTH', 'TIMEOUT': 'PROVIDER_TIMEOUT',
                         'UNKNOWN': 'PROVIDER_IO_UNKNOWN', 'INVALID_OUTPUT': 'PROVIDER_INVALID_OUTPUT'}


def provider_attempt(provider, resolution, code, stdout, stderr, outcome, *, launch_state=None, local_detail=''):
    """Bounded, sanitized diagnostic for one provider launch (None when it needs none)."""
    if resolution is None or not resolution.get('path'):
        rejected = (resolution or {}).get('rejected') or []
        searched = (resolution or {}).get('searched') or []
        detail = ('; '.join('%s: %s' % (r['path'], r['reason']) for r in rejected[:3]) if rejected else
                  'searched %d locations (PATH and policy): %s' % (len(searched), ', '.join(searched[:8])))
        return diagnostic('EXEC_UNTRUSTED' if rejected else 'EXEC_NOT_FOUND', provider=provider, detail=detail)
    reason = outcome.get('reason')
    if code is None:
        # Only the caller's trusted pre-launch stage can prove no launch. In particular,
        # Popen may succeed before an on_spawn/child-record failure leaves code unset.
        code_name = 'REVIEW_NOT_STARTED' if launch_state == 'NOT_STARTED' else 'REVIEW_LAUNCH_UNCONFIRMED'
        typed_reason = reason if reason in PROVIDER_REASON_CODES else 'UNKNOWN'
        detail = ('Local outcome: ' + typed_reason + '. ' + sanitize(local_detail, 400)).strip()
        return {**diagnostic(code_name, provider=provider, detail=detail), 'reason': typed_reason}
    if reason in ('NONE', 'CODE_FINDINGS'):
        return None
    return diagnostic(PROVIDER_REASON_CODES.get(reason, 'PROVIDER_INVALID_OUTPUT'), provider=provider,
                      exit_code=code, detail='exit code %s' % code,
                      excerpt=(stderr or '') + ' ' + (stdout or ''))


def final_diagnostic(attempts, error, outcome_reason=None):
    """Pick the diagnostic to print for a failed review."""
    if error is not None and not attempts:
        return classify_isolation_error(error)
    if attempts:
        last = attempts[-1]
        if last is None:
            return classify_isolation_error(error) if error is not None else diagnostic('ISOLATION_FAILED')
        if last['code'] in ('EXEC_NOT_FOUND', 'EXEC_UNTRUSTED') and len([a for a in attempts if a]) >= 2:
            merged = '; '.join('%s: %s' % (a['provider'], a['detail']) for a in attempts if a and a['code'] == last['code'])
            return {**last, 'detail': sanitize(merged, 600)}
        if len([a for a in attempts if a]) >= 2 and last['code'] == 'PROVIDER_INVALID_OUTPUT':
            return {**diagnostic('FALLBACK_NO_RESULT', provider=last['provider'], excerpt=last['excerpt'],
                                 exit_code=last['exit_code'], detail=last['detail'])}
        return last
    return diagnostic('ISOLATION_FAILED')


def render(diag, *, stage=None, head=None):
    note = ("python3 ~/.claude/hooks/wal_note.py --wal '<hook-supplied-WAL-path>' --event blocker --note "
            + shlex.quote('PEER_REVIEW_INFRA code=%s reason=%s stage=%s head=%s' % (
                diag['code'], diag['reason'], sanitize(stage or 'unknown', 20), sanitize((head or 'unknown')[:64], 64))))
    lines = ['REVIEW_DIAGNOSTIC code=%s reason=%s%s' % (diag['code'], diag['reason'],
                                                       ' provider=' + diag['provider'] if diag.get('provider') else ''),
             'Cause: ' + diag['cause']]
    if diag.get('detail'):
        lines.append('Detail: ' + diag['detail'])
    if diag.get('exit_code') is not None:
        lines.append('Provider exit code: %s' % diag['exit_code'])
    if diag.get('excerpt'):
        lines.append('Provider output excerpt (sanitized, at most 300 characters): ' + diag['excerpt'])
    for number, step in enumerate(diag['steps'], 1):
        lines.append('Next %d: %s' % (number, step))
    lines.append('Record: ' + note)
    lines.append(NATIVE_EVIDENCE)
    return '\n'.join(lines)


# ---------------------------------------------------------------- usage-limit prose

def usage_limit_prose(message, policy=None):
    if not isinstance(message, str) or len(message) > 4096:
        return False
    text = message.replace('’', "'").replace('‘', "'").lower()
    phrases = (policy or DEFAULT_POLICY)['usage_limit_phrases']
    return any(phrase in text for phrase in phrases)


# ---------------------------------------------------------------- packet lint

_COMMAND = re.compile(r'^\s*(?:\$ |> ?\$ |Command:|Testing:|Ran:)|`[^`\n]{2,}`')
# No two unbounded whitespace runs are adjacent, so a long blank run after "exit" is scanned in linear time.
_EXIT = re.compile(r'\b(?:exit(?:ed)?(?:[ \t]+(?:code|status))?[ \t]*(?:[:=][ \t]*)?|rc[ \t]*[:=][ \t]*)(\d{1,3})\b',
                   re.IGNORECASE)
_COUNT = re.compile(r'\bRan (\d+) tests?\b|\b(\d+) (?:passed|tests?|checks?)\b', re.IGNORECASE)
_FENCE = re.compile(r'^[ \t]*(?:`{3,}|~{3,})')
EVIDENCE_WINDOW = 12
LINT_LINE_CHARS = 2048   # evidence lines are short; longer lines are inspected only up to this length
LINT_SECONDS = 5.0       # fail closed if the lint ever runs this long


def lint_packet(stage, content, expected_head, *, clock=time.monotonic):
    """Problems (empty list when acceptable). Format guard only: it cannot prove a run happened."""
    if stage not in ('code-inspection', 'pr'):
        return []
    problems = []
    deadline = clock() + LINT_SECONDS
    head = (expected_head or '').strip().lower()
    if not re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}', head) or not re.search(
            r'(?<![0-9a-fA-F])' + re.escape(head) + r'(?![0-9a-fA-F])', content, re.IGNORECASE):
        problems.append('The packet must contain the full expected HEAD commit SHA (not an abbreviation): ' + head[:64])
    lines = [line[:LINT_LINE_CHARS] for line in content.replace('\0', ' ').splitlines()]
    fence, open_before = None, []
    for line in lines:  # fence state before each line; a fence closes only with its own character
        open_before.append(fence)
        marker = _FENCE.match(line)
        if marker:
            char = marker.group(0).strip()[0]
            if fence is None:
                fence = char
            elif fence == char:
                fence = None
    passing, failing = False, False
    for index, line in enumerate(lines):
        if index % 256 == 0 and clock() > deadline:
            problems.append('Packet lint stopped at its %d-second limit; shorten the packet.' % LINT_SECONDS)
            return problems
        if _FENCE.match(line) or not _COMMAND.search(line):
            continue
        # Evidence belongs to the command's own fenced block. A command written just above a fence may have
        # its output in that fence; any other fence boundary ends the block.
        # `fence` is the character of the block holding the command (None when it is outside any fence).
        block, fence, opened = [line], open_before[index], False
        for follower in lines[index + 1:index + EVIDENCE_WINDOW + 1]:
            marker = _FENCE.match(follower)
            if marker:
                char = marker.group(0).strip()[0]
                if fence is not None:
                    if char == fence:
                        break      # the command's own block closes
                    continue       # a different fence character is content of this block
                if opened or any(item.strip() for item in block[1:]):
                    break
                fence, opened = char, True
                continue
            block.append(follower)
        window = '\n'.join(block)
        exits = [int(m[1]) for m in _EXIT.finditer(window)]
        counts = [int(a or b) for a, b in ((m[1], m[2]) for m in _COUNT.finditer(window))]
        if exits and exits[0] == 0 and any(c > 0 for c in counts):
            passing = True
            break
        if exits and exits[0] != 0:
            failing = True
    if not passing:
        problems.append(
            ('A command in the packet reports a non-zero exit status, which is not passing evidence. ' if failing else '')
            + 'The packet needs at least one command line with its exact exit status and a positive count, for '
            'example: `$ python3 -m unittest discover tests` then `Ran 78 tests ... OK` and `exit 0` within 12 lines. '
            'A statement such as "tests pass" is not evidence. (Format check only; reviewers still verify.)')
    return problems


def render_lint(problems, stage):
    lines = ['Packet lint failed for the %s stage; no provider was launched.' % stage]
    lines += ['  - ' + problem for problem in problems]
    lines.append('Fix the packet (it is signed byte-for-byte, so the helper never rewrites it) and rerun.')
    lines.append(NATIVE_EVIDENCE)
    return '\n'.join(lines)
