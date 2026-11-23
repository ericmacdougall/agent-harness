"""Signed self-serve policy: the one place that decides whether an agent holds a self-serve capability.

The user enables self-serve by running the enabler, which writes ~/.agent-harness/policy/self-serve.json signed with a
purpose-bound Ed25519 key. Guards call grant(); it returns a grant only when every check passes and returns None on any
failure, including every unexpected exception. Hooks fail open on a crash, so this module must never raise and must
never treat an error as permission.

Checks, in order: kill switch file, revocation files, policy file hygiene (regular file, owned by this user, no group
or world bits, size cap, strict JSON), schema and closed capability list, key pinned for purpose "self-serve", Ed25519
signature over a domain-separated canonical body, validity window, capability enabled and not disabled or revoked,
actor proven as main Claude or a Codex root (helpers never qualify), then the scope preconditions against the evidence.

A signature made with the central-decisions key cannot verify here: the key id, the signed domain and the payload
purpose all differ, and a pinned key record must itself name the purpose "self-serve".

Revocation is fail-safe: any caller may create a file under policy/revoked/ (see revoke()) and it is honoured at once.
Nothing in this module deletes one or re-enables a policy; that takes the user's enabler or a newly signed policy.

Same-user trust: file modes and the signature stop careless agents, not a malicious process running as this user. The
trust anchor (policy, pins, key) is local and same-user writable, so protection rests on the command guard covering
policy/, private/self-serve and the pins file (lane L6 is a hard dependency: never install this library without it) and on
the independent t2-dev pin, which this library does not consult. It does what it can on its own side of that line:

  * Nothing the caller passes decides who is main, where the policy lives or what time it is. The proof root is the real
    account's ~/.claude (from the password database, never HOME or CLAUDE_CONFIG_DIR), `home=` must name the real home,
    and `now=` is clamped to the real clock plus or minus CLOCK_SKEW_SECONDS. Tests alone reach those three through the
    private _SEAM dictionary; no argument, environment variable or file can set it. The actor payload must come from the
    consuming hook's own stdin, never from argv or an environment variable (consumers enforce this).
  * A Codex root cannot be told from a Codex helper (see CLAUDE_MAIN_ONLY), so merge-class capabilities are Claude main only.
  * single_use binds the object (default repo, PR, head), never a caller-chosen key, and is spent only by consume().
  * ttl_seconds is the validity of one returned grant object, not a cumulative limit. The policy expires_at is the only hard stop.
  * same_harness_fallback_review has a built-in path denylist that no policy can lower (FALLBACK_FLOOR).

Importing this module has no side effects: no file access, no process probe, no cryptography import.
"""
from __future__ import annotations

import base64
import copy
import fnmatch
import hashlib
import json
import os
import posixpath
import pwd
import re
import stat
import sys
import time
import unicodedata
from datetime import datetime, timezone
from pathlib import Path

CAPABILITIES = ('same_harness_fallback_review', 'merge_reviewed_pr', 'harness_repair', 'pool_cleanup',
                'install_files_manifest', 'central_decisions_agent_steps')
SCHEMA = 'self-serve/1'
PUBKEYS_SCHEMA = 'self-serve-pubkeys/1'
PURPOSE = 'self-serve'
DOMAIN = b'agent-harness-self-serve-policy/1\x00'
KEY_DOMAIN = b'agent-harness-self-serve-key\x00'
MAX_BYTES = 65536
CLOCK_SKEW_SECONDS = 300
TOP_KEYS = {'schema', 'purpose', 'policy_id', 'key_id', 'issued_at', 'expires_at', 'capabilities', 'disabled',
            'signature'}
ACTOR_KINDS = ('claude_main', 'codex_root')
# A Codex root and a Codex helper share one desktop process tree and the probe is process ancestry, so a verified OpenAI
# origin does not say which of the two is calling. Until native_context can, these stay with Claude main.
CLAUDE_MAIN_ONLY = ('same_harness_fallback_review', 'merge_reviewed_pr', 'central_decisions_agent_steps')
# Payload keys that only a helper (Claude subagent or Codex spawned thread) carries. Deny-only hints, never proof.
HELPER_KEYS = ('agent_id', 'agent_type', 'agent_role', 'agent_path', 'parent_thread_id')
FALLBACK_CAPABILITY = 'same_harness_fallback_review'
SINGLE_USE_DEFAULT_BIND = ('repo', 'pr', 'head')
MAX_USE_FIELD = 512
# Paths that never take a same-harness review, whatever the signed policy says; a policy may add patterns, never remove.
# Equal to the denylist in merge_gate (lane L2), which should call fallback_path_denied() rather than keep a copy.
FALLBACK_FLOOR = re.compile(
    r"(?:^|[/_.\-])(?:auth|authn|authz|oauth|login|signin|secrets?|credentials?|passwords?|passwd|tokens?|"
    r"migrations?|migrate|command_guard\w*|merge_gate\w*|peer_review\w*|caller_identity|self_serve\w*|"
    r"central_decisions|escalation|keys?|keygen|keyring|keychain|ed25519|pubkeys?|private|sudoers|"
    r"workflows?|usage_guard)(?:$|[/_.\-])|(?:^|/)\.env|\.pem$|id_rsa|\.p12$|\.pfx$", re.I)

# Private test seam. Production never sets it and nothing a caller can pass reaches it: 'home' is the account home tests
# run under (and arms an explicit home=), 'claude_dir' the proof root, 'clock' lets now= be any value.
_SEAM = {'home': None, 'claude_dir': None, 'clock': False}

_HEX32 = re.compile(r'[0-9a-f]{32}')
_HEX16 = re.compile(r'[0-9a-f]{16}')
_B64URL = re.compile(r'[A-Za-z0-9_-]+')
_TIME = re.compile(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ')


class _Deny(Exception):
    """Internal: a check failed. The reason is a short code, never a value read from the policy."""


# ------------------------------------------------------------------ paths

def _real_home() -> str:
    """The account's home from the password database. HOME and CLAUDE_CONFIG_DIR are the caller's, so never consulted."""
    try:
        return pwd.getpwuid(os.getuid()).pw_dir
    except (KeyError, OSError):
        return os.path.expanduser('~')


def _root(home=None) -> Path:
    return Path(home or _SEAM['home'] or _real_home()) / '.agent-harness'


def _resolve_home(home) -> str:
    """The one choke point for home=. Production: None or the real home, anything else is refused. Tests arm _SEAM."""
    if _SEAM['home'] is not None:
        return home if home is not None else _SEAM['home']
    real = _real_home()
    if home is None:
        return real
    try:
        if os.path.realpath(home) == os.path.realpath(real):
            return real
    except (OSError, ValueError, TypeError):
        pass
    raise _Deny('home_override_refused')


def _claude_dir() -> str:
    """Where a main transcript must live. Never taken from the actor, a payload or the environment."""
    return _SEAM['claude_dir'] or str(Path(_real_home()) / '.claude')


def _clock(now) -> float:
    """The time every check uses. A supplied now is clamped to the real clock within CLOCK_SKEW_SECONDS (tests aside), so
    a past now cannot revive an expired policy and a future one cannot start a policy early."""
    real = time.time()
    if now is None:
        return real
    if isinstance(now, bool) or not isinstance(now, (int, float)) or now != now or now in (float('inf'), float('-inf')):
        raise _Deny('bad_clock')
    if _SEAM['clock']:
        return float(now)
    return min(max(float(now), real - CLOCK_SKEW_SECONDS), real + CLOCK_SKEW_SECONDS)


def policy_dir(home=None) -> Path:
    return _root(home) / 'policy'


def policy_path(home=None) -> Path:
    return policy_dir(home) / 'self-serve.json'


def pubkeys_path(home=None) -> Path:
    return policy_dir(home) / 'self-serve-pubkeys.json'


def kill_switch_path(home=None) -> Path:
    return policy_dir(home) / 'disabled'


def revoked_dir(home=None) -> Path:
    return policy_dir(home) / 'revoked'


def private_key_path(home=None) -> Path:
    return _root(home) / 'private' / 'self-serve' / 'ed25519.key'


def audit_path(home=None) -> Path:
    return _root(home) / 'state' / 'self-serve-audit.jsonl'


def _spent_dir(home=None) -> Path:
    return _root(home) / 'state' / 'self-serve-spent'


# ------------------------------------------------------------------ encoding (shared with the enabler)

def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode('ascii').rstrip('=')


def b64url_decode(text) -> bytes:
    if not isinstance(text, str) or not _B64URL.fullmatch(text) or len(text) % 4 == 1:
        raise _Deny('malformed_base64')
    raw = base64.urlsafe_b64decode(text + '=' * (-len(text) % 4))
    if b64url(raw) != text:
        raise _Deny('malformed_base64')
    return raw


def key_id_of(public_raw: bytes) -> str:
    return hashlib.sha256(KEY_DOMAIN + public_raw).hexdigest()[:16]


def signed_message(body: dict) -> bytes:
    return DOMAIN + canonical(body)


def _strict_json(raw: bytes):
    def pairs(items):
        result = dict(items)
        if len(result) != len(items):
            raise ValueError('duplicate key')
        return result
    return json.loads(raw.decode('utf-8'), object_pairs_hook=pairs, parse_constant=_no_constant)


def _no_constant(_name):
    raise ValueError('non-finite number')


def parse_time(value) -> float:
    if not isinstance(value, str) or not _TIME.fullmatch(value):
        raise _Deny('malformed_time')
    return datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc).timestamp()


def iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def _crypto():
    try:
        from cryptography.exceptions import InvalidSignature  # noqa: PLC0415
        from cryptography.hazmat.primitives import serialization  # noqa: PLC0415
        from cryptography.hazmat.primitives.asymmetric import ed25519  # noqa: PLC0415
    except ImportError:
        raise _Deny('no_crypto') from None
    return ed25519, serialization, InvalidSignature


# ------------------------------------------------------------------ signing helpers (used by the enabler and tests)

def sign_policy(body: dict, private_key) -> dict:
    """Return body plus its signature. private_key is a cryptography Ed25519PrivateKey. Never called by guards."""
    out = {k: v for k, v in body.items() if k != 'signature'}
    out['signature'] = b64url(private_key.sign(signed_message(out)))
    return out


def public_record(public_raw: bytes) -> dict:
    return {'key_id': key_id_of(public_raw), 'public_key': b64url(public_raw), 'purpose': PURPOSE}


# ------------------------------------------------------------------ file reading

def _dir_ok(path: Path):
    try:
        st = os.lstat(path)
    except OSError:
        raise _Deny('policy_dir_unreadable') from None
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o022:
        raise _Deny('policy_dir_unsafe')


def _read_private(path: Path) -> bytes:
    """Read a small regular file that only this user can write or read. No symlinks, no FIFOs, no oversize."""
    try:
        fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, 'O_CLOEXEC', 0))
    except OSError:
        raise _Deny('file_unreadable') from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o077 or st.st_nlink != 1:
            raise _Deny('file_unsafe')
        if st.st_size > MAX_BYTES:
            raise _Deny('file_too_large')
        raw = os.read(fd, MAX_BYTES + 1)
    except OSError:
        raise _Deny('file_unreadable') from None
    finally:
        os.close(fd)
    if len(raw) > MAX_BYTES:
        raise _Deny('file_too_large')
    return raw


def _absent(path: Path) -> bool:
    """True only when the path definitely does not exist. Any other error counts as present (fail closed)."""
    try:
        os.lstat(path)
    except FileNotFoundError:
        return True
    except OSError:
        return False
    return False


# ------------------------------------------------------------------ kill switch and revocation

def kill_switch_active(home=None) -> bool:
    try:
        return not _absent(kill_switch_path(home))
    except Exception:  # noqa: BLE001 - fail closed
        return True


def _revoked_names(policy_id, capability):
    names = ['all']
    if policy_id:
        names.append(policy_id)
    if capability:
        names.append('cap-' + capability)
    return names


def _revoked(home, policy_id=None, capability=None) -> bool:
    directory = revoked_dir(home)
    try:
        st = os.lstat(directory)
    except FileNotFoundError:
        return False
    except OSError:
        return True
    if not stat.S_ISDIR(st.st_mode):
        return True
    return any(not _absent(directory / name) for name in _revoked_names(policy_id, capability))


def revoke(target: str = 'all', *, home=None) -> bool:
    """Revoke at once. target is 'all', a 32-hex policy id, or a capability name. Any caller may do this: it can only
    remove authority. True when the revocation is in place. Never raises; nothing here can undo one."""
    try:
        if not (target == 'all' or target in CAPABILITIES or (isinstance(target, str) and _HEX32.fullmatch(target))):
            return False
        name = 'cap-' + target if target in CAPABILITIES else target
        directory = revoked_dir(home)
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            fd = os.open(str(directory / name), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        except FileExistsError:
            return True
        try:
            os.write(fd, canonical({'revoked_at': iso(time.time())}) + b'\n')
        finally:
            os.close(fd)
        return True
    except Exception:  # noqa: BLE001
        return False


# ------------------------------------------------------------------ policy loading and verification

def _load_pins(home) -> dict:
    raw = _read_private(pubkeys_path(home))
    data = _strict_json(raw)
    if not isinstance(data, dict) or set(data) != {'schema', 'keys'} or data['schema'] != PUBKEYS_SCHEMA \
            or not isinstance(data['keys'], list):
        raise _Deny('pins_malformed')
    pins = {}
    for item in data['keys']:
        if not isinstance(item, dict) or set(item) - {'key_id', 'public_key', 'purpose', 'revoked'}:
            raise _Deny('pins_malformed')
        if item.get('purpose') != PURPOSE or item.get('revoked') is True:
            continue  # a key pinned for another purpose, or withdrawn, is simply not a self-serve key
        key_id, public = item.get('key_id'), b64url_decode(item.get('public_key'))
        if not isinstance(key_id, str) or not _HEX16.fullmatch(key_id) or len(public) != 32 \
                or key_id_of(public) != key_id:
            raise _Deny('pins_malformed')
        pins[key_id] = public
    return pins


def _check_shape(policy: dict):
    if set(policy) - TOP_KEYS or not {'schema', 'purpose', 'policy_id', 'key_id', 'issued_at', 'expires_at',
                                      'capabilities', 'signature'} <= set(policy):
        raise _Deny('policy_shape')
    if policy['schema'] != SCHEMA:
        raise _Deny('policy_schema')
    if policy['purpose'] != PURPOSE:
        raise _Deny('wrong_purpose')
    if not isinstance(policy['policy_id'], str) or not _HEX32.fullmatch(policy['policy_id']):
        raise _Deny('policy_id')
    if not isinstance(policy['key_id'], str) or not _HEX16.fullmatch(policy['key_id']):
        raise _Deny('key_id')
    caps = policy['capabilities']
    if not isinstance(caps, dict) or set(caps) - set(CAPABILITIES):
        raise _Deny('unknown_capability')  # unknown keys fail closed
    for entry in caps.values():
        if not isinstance(entry, dict) or set(entry) - {'scope', 'ttl_seconds'} or 'scope' not in entry \
                or not isinstance(entry['scope'], dict):
            raise _Deny('capability_shape')
        ttl = entry.get('ttl_seconds')
        if ttl is not None and (isinstance(ttl, bool) or not isinstance(ttl, int) or ttl <= 0):
            raise _Deny('capability_ttl')
        _check_scope(entry['scope'])
    disabled = policy.get('disabled', [])
    if not isinstance(disabled, list) or any(not isinstance(c, str) or c not in CAPABILITIES for c in disabled):
        raise _Deny('disabled_shape')
    if not isinstance(policy['signature'], str):
        raise _Deny('signature_shape')


def _string_list(value):
    return isinstance(value, list) and all(isinstance(v, str) and v for v in value)


def _check_scope(scope: dict):
    """Known scope keys are typed because this module enforces them. Other keys belong to the consuming lane."""
    if 'repos' in scope and not _string_list(scope['repos']):
        raise _Deny('scope_repos')
    if 'denylist_paths' in scope and not _string_list(scope['denylist_paths']):
        raise _Deny('scope_denylist')
    if 'single_use' in scope and not isinstance(scope['single_use'], bool):
        raise _Deny('scope_single_use')
    if 'single_use_bind' in scope:
        bind = scope['single_use_bind']
        if not _string_list(bind) or not bind or len(set(bind)) != len(bind):
            raise _Deny('scope_single_use_bind')


def _load_policy(home, now: float) -> dict:
    policy_directory = policy_dir(home)
    _dir_ok(policy_directory)
    raw = _read_private(policy_path(home))
    try:
        policy = _strict_json(raw)
    except (ValueError, UnicodeDecodeError, RecursionError):
        raise _Deny('policy_json') from None
    if not isinstance(policy, dict):
        raise _Deny('policy_shape')
    _check_shape(policy)
    pins = _load_pins(home)
    public = pins.get(policy['key_id'])
    if public is None:
        raise _Deny('key_not_pinned')
    signature = b64url_decode(policy['signature'])
    body = {k: v for k, v in policy.items() if k != 'signature'}
    ed25519, _serialization, invalid = _crypto()
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(public).verify(signature, signed_message(body))
    except (invalid, ValueError):
        raise _Deny('bad_signature') from None
    issued = parse_time(policy['issued_at'])
    if issued > now + CLOCK_SKEW_SECONDS:
        raise _Deny('not_yet_valid')
    if policy['expires_at'] is not None:
        expires = parse_time(policy['expires_at'])
        if expires <= issued:
            raise _Deny('window_inverted')
        if now >= expires:
            raise _Deny('expired')
    return policy


# ------------------------------------------------------------------ actor proof

def _origin_probe():
    from native_context import probe_runtime_origin  # noqa: PLC0415
    return probe_runtime_origin()


def _prove_actor(actor, capability=None):
    """Only 'kind' and 'payload' of the actor are read; every other key is ignored. In particular the actor cannot name
    the directory its transcript is proven against: that is _claude_dir(), fixed by the library."""
    if not isinstance(actor, dict) or actor.get('kind') not in ACTOR_KINDS:
        raise _Deny('actor_unproven')
    payload = actor.get('payload')
    if payload is not None and not isinstance(payload, dict):
        raise _Deny('actor_unproven')
    if isinstance(payload, dict) and (any(payload.get(key) for key in HELPER_KEYS)
                                      or payload.get('thread_source') == 'subagent'):
        raise _Deny('helper_actor')  # helpers never receive grants
    if actor['kind'] == 'claude_main':
        import caller_identity  # noqa: PLC0415
        if not caller_identity.is_main(payload, _claude_dir()):
            raise _Deny('not_main')
        return
    if capability in CLAUDE_MAIN_ONLY:
        raise _Deny('codex_root_not_allowed')
    seen = _origin_probe()
    if getattr(seen, 'origin', None) != 'openai' or getattr(seen, 'reason', None) != 'running_code_verified':
        raise _Deny('not_codex_root')


# ------------------------------------------------------------------ scope preconditions

def _norm_path(value) -> str:
    text = posixpath.normpath(str(value).replace('\\', '/'))
    return text[2:] if text.startswith('./') else text.lstrip('/')


def _denied_path(paths, globs) -> bool:
    folded = [g.casefold() for g in globs]
    return any(fnmatch.fnmatchcase(_norm_path(p).casefold(), g) for p in paths for g in folded)


def _narrowing(evidence) -> dict:
    """A repo file may only narrow. Anything it says that would widen, or that is not understood, is ignored; a
    malformed narrowing fails closed."""
    narrowing = evidence.get('repo_narrowing')
    if narrowing is None:
        return {}
    if not isinstance(narrowing, dict):
        raise _Deny('narrowing_malformed')
    out = {}
    for key in ('disable', 'repos', 'denylist_paths'):
        if key in narrowing:
            if not _string_list(narrowing[key]):
                raise _Deny('narrowing_malformed')
            out[key] = narrowing[key]
    return out


def fallback_path_denied(path) -> bool:
    """True when a same-harness review may not cover this changed path. A malformed, absolute or traversing path counts
    as denied. The one shared floor: consumers call this instead of keeping their own copy."""
    if not isinstance(path, str) or not path or len(path) > 1024:
        return True
    text = unicodedata.normalize('NFKC', path).replace('\\', '/')
    if text.startswith('/') or '..' in text.split('/') or any(ord(ch) < 32 or ord(ch) == 127 for ch in text):
        return True
    return FALLBACK_FLOOR.search(text) is not None


def _use_key(capability, scope, evidence, policy_id) -> str:
    """The identity of the object a single-use grant is spent on, derived from the evidence the signed scope names
    (default repo, PR number, head SHA). The caller cannot supply or shorten it, so one object is granted once."""
    fields = scope.get('single_use_bind') or list(SINGLE_USE_DEFAULT_BIND)
    parts = []
    for name in fields:
        value = evidence.get(name)
        if isinstance(value, bool) or not isinstance(value, (str, int)) or value == '' \
                or (isinstance(value, str) and len(value) > MAX_USE_FIELD):
            raise _Deny('use_binding_required')
        parts.append([name, value])
    return hashlib.sha256(canonical([policy_id, capability, parts])).hexdigest()


def _check_scope_against_evidence(capability, scope, evidence, policy, home, now, spend=False):
    if evidence is not None and not isinstance(evidence, dict):
        raise _Deny('evidence_malformed')
    evidence = evidence or {}
    narrow = _narrowing(evidence)
    if capability in narrow.get('disable', []):
        raise _Deny('narrowed_off')
    repos = scope.get('repos')
    if 'repos' in narrow:
        repos = narrow['repos'] if repos is None else [r for r in repos if r in narrow['repos']]
    if repos is not None:
        repo = evidence.get('repo')
        if not isinstance(repo, str) or repo.casefold() not in {r.casefold() for r in repos}:
            raise _Deny('repo_out_of_scope')
    globs = list(scope.get('denylist_paths', [])) + list(narrow.get('denylist_paths', []))
    floor = capability == FALLBACK_CAPABILITY
    if globs or floor:
        paths = evidence.get('changed_paths')
        if not isinstance(paths, list) or not paths or any(not isinstance(p, str) for p in paths):
            raise _Deny('changed_paths_required')
        if (floor and any(fallback_path_denied(p) for p in paths)) or (globs and _denied_path(paths, globs)):
            raise _Deny('path_denylisted')
    if scope.get('single_use'):
        if not spend:
            raise _Deny('single_use_requires_consume')
        key = _use_key(capability, scope, evidence, policy['policy_id'])
        _spend(home, key)


def _spend(home, digest):
    directory = _spent_dir(home)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        fd = os.open(str(directory / digest), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        raise _Deny('already_used') from None
    os.close(fd)


# ------------------------------------------------------------------ audit

def _audit(home, row: dict):
    path = audit_path(home)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, canonical(row) + b'\n')
    finally:
        os.close(fd)


# ------------------------------------------------------------------ public API

def _decide(capability, actor, evidence, now, home, spend=False):
    if not isinstance(capability, str) or capability not in CAPABILITIES:
        raise _Deny('unknown_capability')
    now = _clock(now)
    home = _resolve_home(home)
    if kill_switch_active(home):
        raise _Deny('kill_switch')
    if _revoked(home):
        raise _Deny('revoked')
    policy = _load_policy(home, now)
    if _revoked(home, policy['policy_id'], capability):
        raise _Deny('revoked')
    if capability in policy.get('disabled', []):
        raise _Deny('capability_disabled')
    entry = policy['capabilities'].get(capability)
    if entry is None:
        raise _Deny('capability_not_granted')
    _prove_actor(actor, capability)
    scope = copy.deepcopy(entry['scope'])
    _check_scope_against_evidence(capability, scope, evidence, policy, home, now, spend)
    expires = parse_time(policy['expires_at']) if policy['expires_at'] is not None else None
    ttl = entry.get('ttl_seconds')  # the validity of this one grant object, not a cumulative limit
    if ttl is not None:
        expires = min(now + ttl, expires) if expires is not None else now + ttl
    result = {'capability': capability, 'policy_id': policy['policy_id'], 'key_id': policy['key_id'],
              'expires_at': iso(expires) if expires is not None else None, 'scope': scope}
    _audit(home, {'at': iso(now), 'event': 'consume' if spend and scope.get('single_use') else 'grant',
                  'capability': capability, 'policy_id': policy['policy_id'], 'actor': actor.get('kind'),
                  'expires_at': result['expires_at']})
    return result


def explain(capability, *, actor, evidence=None, now=None, home=None, consume=False):
    """Like grant() (or consume() when consume=True) but also returns a short reason code, never a policy value."""
    try:
        return _decide(capability, actor, evidence, now, home, spend=bool(consume)), 'granted'
    except _Deny as denied:
        return None, str(denied)
    except Exception:  # noqa: BLE001
        return None, 'error'


def grant(capability: str, *, actor: dict, evidence: dict | None = None, now: float | None = None,
          home: str | None = None) -> dict | None:
    """The grant for capability, or None on ANY failure. Never raises. A capability whose policy scope is single_use is
    not handed out here (it needs consume()), so a consumer that has not adopted consume() gets no grant, not a free one."""
    try:
        return _decide(capability, actor, evidence, now, home)
    except BaseException as error:  # noqa: BLE001 - a crash is never permission
        if isinstance(error, (KeyboardInterrupt, SystemExit)):
            raise
        return None


def consume(capability: str, *, actor: dict, evidence: dict | None = None, now: float | None = None,
            home: str | None = None) -> dict | None:
    """grant() plus, for a single_use scope, the atomic spend of the object named by the evidence (default repo, pr, head).
    Call it once, immediately before acting. Every other precondition is checked first, so a refused call spends
    nothing; an actor that is not proven main or Codex root can never spend. Once spent, the object is never granted
    again under this policy, even if the action then fails. Never raises."""
    try:
        return _decide(capability, actor, evidence, now, home, spend=True)
    except BaseException as error:  # noqa: BLE001 - a crash is never permission
        if isinstance(error, (KeyboardInterrupt, SystemExit)):
            raise
        return None


def status(home: str | None = None, *, now: float | None = None) -> dict:
    """What the policy looks like right now. Never raises; every field is safe to print."""
    out = {'enabled': False, 'policy_id': None, 'capabilities': [], 'disabled': [], 'key_id': None,
           'kill_switch': False, 'revoked': False, 'expires_at': None, 'reason': 'error'}
    try:
        try:
            home, now = _resolve_home(home), _clock(now)
        except _Deny as denied:
            out['reason'] = str(denied)
            return out
        out['kill_switch'] = kill_switch_active(home)
        out['revoked'] = _revoked(home)
        try:
            policy = _load_policy(home, now)
        except _Deny as denied:
            out['reason'] = str(denied)
            return out
        out['policy_id'] = policy['policy_id']
        out['key_id'] = policy['key_id']
        out['expires_at'] = policy['expires_at']
        out['disabled'] = sorted(policy.get('disabled', []))
        out['revoked'] = out['revoked'] or _revoked(home, policy['policy_id'])
        out['capabilities'] = sorted(c for c in policy['capabilities'] if c not in out['disabled']
                                     and not _revoked(home, policy['policy_id'], c))
        if out['kill_switch']:
            out['reason'] = 'kill_switch'
        elif out['revoked']:
            out['reason'] = 'revoked'
        else:
            out['enabled'] = True
            out['reason'] = 'ok'
        return out
    except Exception:  # noqa: BLE001
        out['enabled'] = False
        return out


def main(argv=None) -> int:
    """`self_serve.py status` prints the status as JSON. Read-only."""
    args = list(sys.argv[1:] if argv is None else argv)
    if args[:1] != ['status']:
        print('usage: self_serve.py status', file=sys.stderr)
        return 2
    print(json.dumps(status(), indent=2, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
