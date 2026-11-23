#!/usr/bin/env python3
"""Signed central top-rung decisions on a GoodQA ledger ticket (GoodQA goodqa#16651).

A top-rung (Fable/Astra) permission that `ah approve-top` recorded for ONE task on the Mac can be published once
as an Ed25519-signed comment on a ledger ticket. Every host whose user pinned the public key then accepts it at
use time for exactly that task key, until it expires (never later than the assent turn + 12 h) or is revoked.

Trust model (stated, not more): the root of trust is the user's own words in the Mac transcript, re-verified at
publish by the same checks approve-top uses (ask pair, assenting sentence, age), plus a later-turn scan. The
signature proves that the Mac's publish tool ran those checks; it protects against accidental damage, against
forged, edited, replayed or reordered GoodQA comments (agents on every host hold GoodQA credentials that can post),
and against tampering in transit. It does NOT protect against a malicious local agent on the Mac that reads the
signing key or edits these hooks, nor against an agent that replaces the pinned public key on a host.

Revocation is fail-safe: a comment whose whole body is one revoke line denies, whoever posted it, archived or not.

  ah decision keygen                         create the Mac signing key (once; the installer runs it)
  ah decision pubkey                         print the public key record to pin on other hosts
  ah decision pin --pubkey-file F            pin a public key on this host (installer)
  ah decision enable --project P --number N  point this host at the ledger ticket (installer)
  ah decision publish --task K               sign and post the verified local permission of task K
  ah decision verify --task K --family F     exit 0 only when a valid central decision covers K for F now
  ah decision withdraw --task K | --session S | --decision ID | --all
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import sys
import time
import uuid
from datetime import datetime, timezone

import escalation as esc

SCHEMA = 'agent-harness.central-decision.v1'
CONFIG_SCHEMA = 'agent-harness.central-decisions.config.v1'
KEYS_SCHEMA = 'agent-harness.central-decisions.keys.v1'
DOMAIN = b'agent-harness-central-decision-v1\x00'
DECISION_PREFIX = 'agent-harness-decision v1 '
FAMILIES = ('astra', 'fable')
MAX_LIFETIME = esc.TOP_ASSENT_MAX_AGE  # 12 h: central never grants longer than a local grant
SKEW = 120
PER_TURN_CAP = 3
UNDATED_REVOKE_AT = 253402300799.0  # 9999-12-31: a revoke without a server time counts as newer than every grant
MAX_PAGES = 10
PAGE_LIMIT = 200
MAX_BODY = 8192
HOOK_DEADLINE = 6.0  # seconds for one ledger read inside a hook whose timeout is 10 s (onFailure block)
DECISION_KEYS = frozenset({'schema', 'decision_id', 'task', 'families', 'source', 'session', 'turn_uuid', 'sentence',
                           'sentence_sha256', 'assent_at', 'issued_at', 'expires_at', 'key_id', 'issuer_host', 'ask_id'})
HEX32 = re.compile(r'[0-9a-f]{32}')
UUID = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}')
B64URL = re.compile(r'[A-Za-z0-9_-]+')
KEY_ID = re.compile(r'[0-9a-f]{16}')
REVOKE = re.compile(r'agent-harness-revoke (?:(all)|task ([A-Za-z0-9][A-Za-z0-9._-]{0,63})|session (%s)|decision ([0-9a-f]{32}))'
                    % UUID.pattern)
# A superset of the T2Scan adapter's own withdrawal openers (no, stop, cancel, revoke, do not, don't), so the prompt
# hook revokes at least whenever the adapter's local transcript scan would deny.
BARE_WITHDRAWAL = re.compile(r"\s*(?:stop|cancel|revoke|withdraw|no|do\s+not|don'?t)\b", re.I)


def withdrawal_signal(text):
    """THE later-turn predicate (goodqa#16651, PR 14 class A). Every revocation trigger uses it: the publish-time
    later-turn scan, the prompt hook, the question-answer hook and the transcript sweep. True when the text names the
    top rung, retracts, or opens with a bare withdrawal, judged on the raw text and on the text with wrapper blocks
    removed (the T2Scan adapter judges the stripped text). It is a superset of the adapter's later_withdrawal trigger,
    which adds only a narrowing task-name filter; the cross-repo contract test pins that relation."""
    if not isinstance(text, str) or not text.strip():
        return False
    import provenance as prov  # noqa: PLC0415
    for candidate in (text, prov.strip_blocks(text)):
        if candidate and (esc.TOP_TERMS.search(candidate) or esc.TOP_RETRACT.search(candidate)
                          or BARE_WITHDRAWAL.match(candidate)):
            return True
    return False


class Denied(Exception):
    """No valid central decision (every failure, including an unreachable ledger, lands here: fail closed)."""

    def __init__(self, code, message):
        super().__init__(message)
        self.code, self.message = code, message


# ------------------------------------------------------------------ store (paths never come from the environment)

class Store:
    """Where this host keeps its config, pinned keys, signing key and tombstones. Production uses the installed
    home from the passwd database; only tests pass another root, never an environment variable, so a launcher an
    agent controls cannot point a consumer at its own key file."""

    def __init__(self, home=None):
        self.home = Path(home) if home is not None else esc.installed_home()
        self.dir = self.home / '.agent-harness' / 'decisions'
        self.private = self.home / '.agent-harness' / 'private' / 'decisions'
        self.config = self.dir / 'config.json'
        self.keys = self.dir / 'trusted-keys.json'
        self.tombstones = self.dir / 'tombstones.jsonl'
        self.published = self.dir / 'published.jsonl'
        self.pending = self.dir / 'pending-revocations.jsonl'
        self.signing_key = self.private / 'signing-ed25519.key'

    def ensure_dirs(self):
        for path, mode in ((self.dir, 0o700), (self.private, 0o700)):
            path.mkdir(mode=mode, parents=True, exist_ok=True)
            info = path.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
                raise Denied('store_unsafe', 'decision store directory is not a private directory: %s' % path)
            os.chmod(path, mode)


def _read_private_json(path, limit=65536):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        return None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022 or info.st_size > limit:
            raise Denied('store_unsafe', 'decision file is not a private regular file: %s' % path.name)
        raw = os.read(fd, limit + 1)
    finally:
        os.close(fd)
    try:
        return strict_json(raw)
    except ValueError:
        raise Denied('store_corrupt', 'decision file is not valid JSON: %s' % path.name) from None


def _write_private(path, data: bytes, mode=0o600):
    tmp = path.with_name('.%s.%d.tmp' % (path.name, os.getpid()))
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, path)


def _append_private(path, row: dict):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, (json.dumps(row, sort_keys=True) + '\n').encode())
    finally:
        os.close(fd)


def _read_jsonl(path, limit=4 << 20):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return []
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_size > limit:
            raise Denied('store_unsafe', 'decision log is not a private regular file: %s' % path.name)
        raw = os.read(fd, limit + 1)
    finally:
        os.close(fd)
    rows = []
    for line in raw.decode('utf-8', 'replace').splitlines():
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if isinstance(row, dict):
            rows.append(row)
    return rows


def load_config(store):
    config = _read_private_json(store.config)
    if config is None:
        raise Denied('not_configured', 'central decisions are not enabled on this host (run the installer)')
    ledger = config.get('ledger') if isinstance(config, dict) else None
    if (not isinstance(config, dict) or config.get('schema') != CONFIG_SCHEMA or config.get('enabled') is not True
            or not isinstance(ledger, dict) or not isinstance(ledger.get('project'), str)
            or type(ledger.get('number')) is not int or not UUID.fullmatch(str(ledger.get('issue_id') or ''))):
        raise Denied('not_configured', 'central decision config is disabled or malformed')
    return config


def load_trusted_keys(store):
    data = _read_private_json(store.keys)
    keys = data.get('keys') if isinstance(data, dict) and data.get('schema') == KEYS_SCHEMA else None
    if not isinstance(keys, list) or not keys:
        raise Denied('no_pinned_key', 'no public key is pinned on this host (run the installer)')
    out = {}
    for item in keys:
        if not isinstance(item, dict) or set(item) != {'key_id', 'public_key'}:
            raise Denied('store_corrupt', 'pinned key record is malformed')
        raw = b64url_decode(item['public_key'])
        if len(raw) != 32 or key_id_of(raw) != item['key_id']:
            raise Denied('store_corrupt', 'pinned key record does not match its key id')
        out[item['key_id']] = raw
    return out


# ------------------------------------------------------------------ encoding

def strict_json(raw):
    def pairs(items):
        result = dict(items)
        if len(result) != len(items):
            raise ValueError('duplicate key')
        return result
    if isinstance(raw, bytes):
        raw = raw.decode('utf-8')
    return json.loads(raw, object_pairs_hook=pairs)


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode('ascii').rstrip('=')


def b64url_decode(text) -> bytes:
    if not isinstance(text, str) or not B64URL.fullmatch(text) or len(text) % 4 == 1:
        raise Denied('malformed', 'not canonical base64url')
    raw = base64.urlsafe_b64decode(text + '=' * (-len(text) % 4))
    if b64url(raw) != text:
        raise Denied('malformed', 'not canonical base64url')
    return raw


def key_id_of(public_raw: bytes) -> str:
    return hashlib.sha256(b'agent-harness-decision-key\x00' + public_raw).hexdigest()[:16]


def signed_message(issue_id: str, payload: bytes) -> bytes:
    return DOMAIN + issue_id.encode('ascii') + b'\x00' + payload


def parse_time(value):
    if not isinstance(value, str) or not re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?Z', value):
        raise Denied('malformed', 'timestamp is not an exact UTC instant')
    return datetime.fromisoformat(value.replace('Z', '+00:00')).timestamp()


def iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def _crypto():
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519  # noqa: PLC0415
        from cryptography.hazmat.primitives import serialization  # noqa: PLC0415
        from cryptography.exceptions import InvalidSignature  # noqa: PLC0415
    except ImportError:
        raise Denied('no_crypto', 'the Python cryptography package is not importable on this host') from None
    return ed25519, serialization, InvalidSignature


def families_of(sentence: str):
    return sorted({word.lower() for word in re.findall(r'\b(fable|astra)\b', sentence, re.I)})


# ------------------------------------------------------------------ ledger client

def _uuid_operation_id(operation_id):
    """GoodQA rejects a non-UUID operationId (MCP -32602). A UUID passes through; any other key maps to a uuid5 of
    it, so a retry of the same decision or revoke line reuses the same id (same convention as ah.operation_id)."""
    try:
        return str(uuid.UUID(str(operation_id)))
    except ValueError:
        return str(uuid.uuid5(uuid.NAMESPACE_URL, 'central-decisions:' + str(operation_id)))


class GoodQALedger:
    """The ledger ticket through the harness's GoodQA adapter (the commit-policy credential of this host)."""

    def __init__(self, adapter=None, deadline_seconds=None):
        if adapter is None:
            import commit_policy  # noqa: PLC0415
            import ticket_adapters  # noqa: PLC0415
            hooks = Path(__file__).resolve().parent
            cfg = commit_policy.load_policy(hooks / 'commit_policy.json')['ticket_systems']['goodqa']
            if deadline_seconds is not None:
                # One overall budget for every request of this read, well under the hook's own timeout.
                cfg = dict(cfg, total_deadline_seconds=float(deadline_seconds),
                           timeout_seconds=min(float(cfg.get('timeout_seconds', 15)), float(deadline_seconds)))
            adapter = ticket_adapters.GoodQAAdapter(cfg)
        self.adapter = adapter

    def issue_state(self, project, number):
        ticket = self.adapter.lookup(project, number)
        if ticket is None:
            return None
        return {'id': ticket.id, 'closed': bool(getattr(ticket, 'closed', False))}

    def comments(self, issue_id):
        """Every comment, archived included, oldest first. Running out of pages fails closed."""
        found, cursor = [], None
        for _ in range(MAX_PAGES):
            arguments = {'issueId': issue_id, 'order': 'asc', 'limit': PAGE_LIMIT}
            if cursor:
                arguments['cursor'] = cursor
            data = self.adapter.call('get_issue_comments', arguments)
            if not isinstance(data, dict) or '__error__' in data or not isinstance(data.get('comments'), list):
                raise Denied('ledger_unreadable', 'the ledger comments could not be read')
            for item in data['comments']:
                if not isinstance(item, dict) or not isinstance(item.get('id'), str):
                    raise Denied('ledger_unreadable', 'the ledger returned a malformed comment')
                found.append({'id': item['id'], 'body': item.get('body'), 'createdAt': item.get('createdAt'),
                              'archived': bool(item.get('archivedAt') or item.get('deletedAt'))})
            cursor = data.get('nextCursor')
            if not data.get('hasMore') or not cursor:
                return found
        raise Denied('ledger_truncated', 'the ledger holds more comments than the page budget; refusing to guess')

    def server_time(self):
        """The GoodQA server's clock from the HTTP Date header of the latest response (each verify reads fresh), so a
        slow host clock cannot keep an expired grant alive on a quiet ledger. Missing or unparsable: deny."""
        import email.utils  # noqa: PLC0415
        value = getattr(self.adapter, 'last_server_date', None)
        try:
            stamp = email.utils.parsedate_to_datetime(value).timestamp() if isinstance(value, str) else None
        except (TypeError, ValueError, IndexError, OverflowError):
            stamp = None
        if stamp is None:
            raise Denied('no_server_time', 'the ledger response carried no usable server time')
        return stamp

    def post(self, issue_id, body, operation_id):
        data = self.adapter.call('comment_on_issue', {'issueId': issue_id, 'body': body,
                                                      'operationId': _uuid_operation_id(operation_id)})
        if not isinstance(data, dict) or '__error__' in data:
            raise Denied('ledger_write_failed', 'the ledger refused the comment')
        return data


def _client(client, deadline_seconds=None):
    if client is not None:
        return client
    try:
        return GoodQALedger(deadline_seconds=deadline_seconds)
    except Denied:
        raise
    except Exception as error:  # noqa: BLE001  any adapter or config failure: fail closed
        raise Denied('ledger_unreachable', 'GoodQA ledger client unavailable (%s)' % type(error).__name__) from None


# ------------------------------------------------------------------ reading the ledger

def _parse_decision(body, issue_id, trusted, ed25519, InvalidSignature):
    """The verified payload of one decision comment body, else None. Pure: no time rules here."""
    if not isinstance(body, str) or len(body) > MAX_BODY:
        return None
    line = body.strip()
    if '\n' in line or '\r' in line or not line.startswith(DECISION_PREFIX):
        return None
    token = line[len(DECISION_PREFIX):]
    if token.count('.') != 1:
        return None
    try:
        payload_text, signature_text = token.split('.')
        payload_raw, signature = b64url_decode(payload_text), b64url_decode(signature_text)
        payload = strict_json(payload_raw)
    except (Denied, ValueError, UnicodeDecodeError):
        return None
    if not isinstance(payload, dict) or set(payload) != DECISION_KEYS or canonical(payload) != payload_raw:
        return None
    public = trusted.get(payload.get('key_id')) if isinstance(payload.get('key_id'), str) else None
    if public is None or len(signature) != 64:
        return None
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(public).verify(signature, signed_message(issue_id, payload_raw))
    except InvalidSignature:
        return None
    return payload


def _shape_ok(p):
    return (p.get('schema') == SCHEMA and isinstance(p.get('decision_id'), str) and HEX32.fullmatch(p['decision_id'])
            and isinstance(p.get('task'), str) and esc.SAFE_KEY.fullmatch(p['task'])
            and isinstance(p.get('families'), list) and p['families'] and p['families'] == sorted(set(p['families']))
            and all(f in FAMILIES for f in p['families'])
            and isinstance(p.get('session'), str) and UUID.fullmatch(p['session'])
            and isinstance(p.get('turn_uuid'), str) and UUID.fullmatch(p['turn_uuid'])
            and isinstance(p.get('source'), str) and p['source'].startswith('user:%s/%s "' % (p['session'], p['turn_uuid']))
            and isinstance(p.get('sentence'), str) and 0 < len(p['sentence']) <= 600
            and p.get('sentence_sha256') == hashlib.sha256(p['sentence'].encode('utf-8')).hexdigest()
            and families_of(p['sentence']) == p['families']
            and isinstance(p.get('issuer_host'), str) and len(p['issuer_host']) <= 64
            and isinstance(p.get('ask_id'), str) and len(p['ask_id']) <= 32)


def read_ledger(store, client, config, trusted, crypto, with_newest=False):
    """(decisions, revocations[, newest server time]): signed decision payloads with their comment facts, and revoke
    facts."""
    ed25519, _, InvalidSignature = crypto
    ledger = config['ledger']
    try:
        state = client.issue_state(ledger['project'], ledger['number'])
    except Denied:
        raise
    except Exception as error:  # noqa: BLE001  unreachable, HTTP error, timeout: fail closed
        raise Denied('ledger_unreachable', 'GoodQA ledger unreachable (%s)' % type(error).__name__) from None
    if state is None or state.get('id') != ledger['issue_id']:
        raise Denied('ledger_missing', 'the pinned ledger ticket is missing or is not the pinned issue')
    if state.get('closed'):
        raise Denied('ledger_closed', 'the ledger ticket is closed, which revokes every central decision')
    try:
        comments = client.comments(ledger['issue_id'])
    except Denied:
        raise
    except Exception as error:  # noqa: BLE001
        raise Denied('ledger_unreachable', 'GoodQA ledger comments unreadable (%s)' % type(error).__name__) from None
    decisions, revocations, newest = [], [], None
    for item in comments:
        body = item.get('body')
        try:
            created = parse_time(_norm_server_time(item.get('createdAt')))
        except Denied:
            created = None
        if isinstance(body, str) and len(body) <= MAX_BODY:
            match = REVOKE.fullmatch(body.strip())
            if match:
                # A revoke without a usable server time still denies: it is treated as newer than every grant.
                revocations.append(_revoke_fact(match, created if created is not None else UNDATED_REVOKE_AT,
                                                'ledger:' + item['id']))
                if created is not None:
                    newest = created if newest is None or created > newest else newest
                continue
        if created is None:
            continue  # a grant without a server time cannot be ordered against revocations: not valid
        newest = created if newest is None or created > newest else newest
        payload = _parse_decision(body, ledger['issue_id'], trusted, ed25519, InvalidSignature)
        if payload is not None and _shape_ok(payload):
            decisions.append({'payload': payload, 'created': created, 'archived': item.get('archived'),
                              'comment_id': item['id']})
    return (decisions, revocations, newest) if with_newest else (decisions, revocations)


def _norm_server_time(value):
    """GoodQA createdAt (ISO with Z or +00:00, optional fraction) to the exact form parse_time accepts."""
    if not isinstance(value, str):
        return None
    text = value.replace('+00:00', 'Z')
    match = re.fullmatch(r'(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(\.\d+)?Z', text)
    if not match:
        return None
    return match.group(1) + ((match.group(2) or '')[:7]) + 'Z'


def _revoke_fact(match, created, origin):
    scope = 'all' if match.group(1) else 'task' if match.group(2) else 'session' if match.group(3) else 'decision'
    value = match.group(2) or match.group(3) or match.group(4)
    return {'scope': scope, 'value': value, 'at': created, 'origin': origin}


def covers(revoke, payload):
    """A revocation covers a decision named by id at any time; a task, session or all revocation covers every
    decision whose user words came before it (so a re-publish of the same words after a revoke stays revoked, and
    new words after a revoke-all are a new decision)."""
    scope, value = revoke.get('scope'), revoke.get('value')
    if scope == 'decision':
        return value == payload['decision_id']
    try:
        assent = parse_time(payload['assent_at'])
    except Denied:
        return True
    if not isinstance(revoke.get('at'), (int, float)) or revoke['at'] < assent:
        return False
    return (scope == 'all' or (scope == 'task' and value == payload['task'])
            or (scope == 'session' and value == payload['session']))


def local_tombstones(store):
    out = []
    for row in _read_jsonl(store.tombstones):
        if row.get('scope') in ('all', 'task', 'session', 'decision') and isinstance(row.get('at'), (int, float)):
            out.append({'scope': row['scope'], 'value': row.get('value'), 'at': row['at'], 'origin': 'tombstone'})
    return out


def remember_revocations(store, revocations):
    """Sticky local copy of every ledger revocation seen, so a revoke later hidden on the tracker still denies here."""
    seen = {(r.get('scope'), r.get('value'), r.get('at')) for r in local_tombstones(store)}
    try:
        store.ensure_dirs()
        for revoke in revocations:
            key = (revoke['scope'], revoke['value'], revoke['at'])
            if key not in seen:
                _append_private(store.tombstones, {'scope': revoke['scope'], 'value': revoke['value'],
                                                   'at': revoke['at'], 'origin': revoke.get('origin')})
                seen.add(key)
    except (OSError, Denied):
        pass  # the revocation still denies in this call; only stickiness is lost


def _time_ok(p, now):
    assent, issued, expires = parse_time(p['assent_at']), parse_time(p['issued_at']), parse_time(p['expires_at'])
    return assent <= issued <= now + SKEW and assent <= now + SKEW and issued < expires <= assent + MAX_LIFETIME and now < expires


def verify(task, family, *, store=None, client=None, now=None, deadline_seconds=None, max_age_seconds=None):
    """The valid central decision for exactly `task` and `family` at `now`, else Denied. Reads the ledger fresh
    on every call (no cache), so a revocation posted between two checks denies the second one."""
    store = store or Store()
    if not isinstance(task, str) or not esc.SAFE_KEY.fullmatch(task):
        raise Denied('bad_task', 'task key must match %s exactly' % esc.SAFE_KEY.pattern)
    if family not in FAMILIES:
        raise Denied('bad_family', 'family must be fable or astra')
    now = time.time() if now is None else now
    if max_age_seconds is not None and (type(max_age_seconds) is not int or not 0 < max_age_seconds <= MAX_LIFETIME):
        raise Denied('bad_max_age', 'max_age_seconds must be an int in (0, %d]' % MAX_LIFETIME)
    config = load_config(store)
    trusted = load_trusted_keys(store)
    crypto = _crypto()
    client = _client(client, deadline_seconds)
    decisions, revocations, newest = read_ledger(store, client, config, trusted, crypto, with_newest=True)
    server_now = client.server_time() if callable(getattr(client, 'server_time', None)) else None
    reference = max([t for t in (newest, server_now) if t is not None], default=None)
    if reference is not None and reference > now + SKEW:
        raise Denied('clock_behind', 'this host clock is behind the ledger server by more than %d s' % SKEW)
    remember_revocations(store, revocations)
    revokes = revocations + local_tombstones(store)
    per_turn = {}
    for item in decisions:
        per_turn.setdefault((item['payload']['session'], item['payload']['turn_uuid']), set()).add(item['payload']['task'])
    best, reasons = None, []
    for item in decisions:
        p = item['payload']
        if p['task'] != task:
            continue
        if item['archived']:
            reasons.append('archived'); continue
        if family not in p['families']:
            reasons.append('family'); continue
        try:
            if not _time_ok(p, now):
                reasons.append('expired_or_out_of_window'); continue
            if max_age_seconds is not None and now - parse_time(p['assent_at']) > max_age_seconds:
                reasons.append('older_than_caller_limit'); continue
        except Denied:
            reasons.append('time'); continue
        if any(covers(r, p) for r in revokes):
            reasons.append('revoked'); continue
        if len(per_turn[(p['session'], p['turn_uuid'])]) > PER_TURN_CAP:
            reasons.append('turn_cap'); continue
        if best is None or p['issued_at'] > best['payload']['issued_at']:
            best = item
    if best is None:
        raise Denied('no_decision', 'no valid central decision for task %s and family %s%s'
                     % (task, family, (' (' + ', '.join(sorted(set(reasons))) + ')') if reasons else ''))
    p = best['payload']
    return {'task': p['task'], 'decision_id': p['decision_id'], 'families': p['families'], 'sentence': p['sentence'],
            'session': p['session'], 'turn_uuid': p['turn_uuid'], 'source': p['source'], 'assent_at': p['assent_at'],
            'expires_at': p['expires_at'], 'key_id': p['key_id'], 'comment_id': best['comment_id']}


# ------------------------------------------------------------------ publishing (Mac)

def later_mentions(session, turn_uuid, claude_home):
    """True when any human turn, queued message or answer after the cited turn names the top rung, retracts or
    starts with a bare withdrawal. Reads the transcript up to its size at open (a live session keeps appending);
    publish rescans after posting and withdraws at once if a later turn arrived meanwhile. Unreadable: raise."""
    import provenance as prov  # noqa: PLC0415
    path = prov.find_transcript(session, claude_home)
    seen, asks = False, set()
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as transcript:
        before = os.fstat(transcript.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid() or before.st_size > 64 * 1024 * 1024:
            raise Denied('transcript_unsafe', 'the session transcript is not a private regular file')
        cited_text, remaining = None, before.st_size
        while remaining > 0 and (raw := transcript.readline(min(4 * 1024 * 1024 + 1, remaining))):
            remaining -= len(raw)
            if len(raw) > 4 * 1024 * 1024:
                raise Denied('transcript_unsafe', 'oversized transcript line')
            try:
                record = prov.loads_line(raw)
            except ValueError:
                continue
            if not isinstance(record, dict):
                continue
            kind = record.get('type')
            if kind == 'assistant':
                asks.update(prov.askuser_use_ids(record))
                continue
            text = None
            if kind == 'user':
                text, _ = prov.user_authorship(record)
                if text and record.get('uuid') == turn_uuid:
                    if seen:
                        raise Denied('transcript_unsafe', 'the cited turn appears twice')
                    seen, cited_text = True, text
                    continue
                text = text or prov.answer_text(record, asks)
            elif kind == 'queue-operation':
                queued = prov.queue_user_text(record)
                text = prov.strip_blocks(queued) if queued else None
                # The queued copy of the cited words is the same message, written next to it; not a later turn.
                if text is not None and cited_text is not None and text.strip() == cited_text.strip():
                    continue
            if seen and withdrawal_signal(text):
                return True
    if not seen:
        raise Denied('transcript_unsafe', 'the cited turn is not in the session transcript')
    return False


def _private_key(store, ed25519, serialization):
    try:
        fd = os.open(store.signing_key, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        raise Denied('no_signing_key', 'no signing key on this host (run `ah decision keygen` from the installer)') from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077 or info.st_size > 4096:
            raise Denied('store_unsafe', 'the signing key must be a private (0600) regular file')
        raw = os.read(fd, 4097)
    finally:
        os.close(fd)
    try:
        key = serialization.load_pem_private_key(raw, password=None)
    except (ValueError, TypeError):
        raise Denied('store_corrupt', 'the signing key could not be loaded') from None
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        raise Denied('store_corrupt', 'the signing key is not Ed25519')
    return key


def public_raw(key, serialization):
    return key.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)


def keygen(store=None):
    store = store or Store()
    ed25519, serialization, _ = _crypto()
    store.ensure_dirs()
    if store.signing_key.exists():
        key = _private_key(store, ed25519, serialization)
        created = False
    else:
        key = ed25519.Ed25519PrivateKey.generate()
        pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        fd = os.open(store.signing_key, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            os.write(fd, pem)
            os.fsync(fd)
        finally:
            os.close(fd)
        created = True
    raw = public_raw(key, serialization)
    return {'created': created, 'key_id': key_id_of(raw), 'public_key': b64url(raw)}


def pin(public_key, store=None):
    store = store or Store()
    raw = b64url_decode(public_key)
    if len(raw) != 32:
        raise Denied('malformed', 'an Ed25519 public key is 32 bytes')
    store.ensure_dirs()
    record = {'schema': KEYS_SCHEMA, 'keys': [{'key_id': key_id_of(raw), 'public_key': b64url(raw)}]}
    _write_private(store.keys, json.dumps(record, sort_keys=True, indent=1).encode() + b'\n', 0o600)
    return record['keys'][0]


def enable(project, number, issue_id, store=None):
    store = store or Store()
    if not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,62}', project or '') or type(number) is not int or number < 1 \
            or not UUID.fullmatch(issue_id or ''):
        raise Denied('bad_request', 'enable needs a project slug, a ticket number and the ticket issue id')
    store.ensure_dirs()
    config = {'schema': CONFIG_SCHEMA, 'enabled': True, 'ledger': {'project': project, 'number': number, 'issue_id': issue_id}}
    _write_private(store.config, json.dumps(config, sort_keys=True, indent=1).encode() + b'\n', 0o600)
    return config


def publish(task, *, ledger=None, store=None, client=None, now=None, claude_home=None, host=None, test_mode=False):
    """Sign and post the verified local permission of `task`. Every refusal writes nothing.

    `test_mode` (tests only, never set by the CLI) lets a test ledger read its env-selected WAL and transcript roots,
    exactly as escalation's non-default ledger does. The CLI refuses a non-default escalation root."""
    import provenance as prov  # noqa: PLC0415
    store = store or Store()
    ledger = ledger or esc.Ledger()
    if not isinstance(task, str) or not esc.SAFE_KEY.fullmatch(task):
        raise Denied('bad_task', 'task key must match %s exactly (no wildcards)' % esc.SAFE_KEY.pattern)
    allow_env = ledger._non_default_root()
    if allow_env and not test_mode:
        raise Denied('non_default_root', 'publish reads only the installed escalation ledger')
    now = time.time() if now is None else now
    try:
        state = ledger.load(task)
    except esc.LedgerError as error:
        raise Denied('no_local_permission', 'escalation state for %s unreadable (%s)' % (task, error.code)) from None
    permission = state.get('permission')
    if not isinstance(permission, dict) or permission.get('task') != task:
        raise Denied('no_local_permission', 'task %s has no local top-rung permission; run `ah approve-top --task %s` first'
                     % (task, task))
    ask, wal, source = permission.get('ask_id'), permission.get('wal'), permission.get('source')
    if not (isinstance(ask, str) and isinstance(wal, str) and isinstance(source, str) and source.startswith('user:')):
        raise Denied('not_user_turn', 'central publication needs a user: (human turn) source; answer: and queue: are refused')
    try:
        proof = esc.verify_ask_pair(Path(wal), ask, task, allow_env_root=allow_env)
        if proof.get('source') != source:
            raise Denied('evidence_mismatch', 'the WAL ask source differs from the recorded permission')
        assent = esc.verify_top_source(source, allow_env_root=allow_env, max_age_seconds=MAX_LIFETIME, now_ts=now)
        parsed = prov.parse_source(source)
    except esc.LedgerError as error:
        raise Denied(error.code, error.message) from None
    except prov.Problem as error:
        raise Denied('bad_source', str(error)) from None
    session, turn = parsed.get('session'), parsed.get('uuid')
    if (parsed.get('variant') not in (None, 'user', 'uuid') or not isinstance(session, str) or not UUID.fullmatch(session)
            or not isinstance(turn, str) or not UUID.fullmatch(turn) or assent.get('session') != session
            or Path(wal).resolve().parent.name != session):
        raise Denied('evidence_mismatch', 'session or turn id in the evidence does not match exactly')
    home = claude_home if claude_home is not None else (None if allow_env else esc.installed_home() / '.claude')
    try:
        if later_mentions(session, turn, home):
            raise Denied('later_turn', 'the user named the top rung again or withdrew after the cited turn; the latest '
                                       'words decide. Ask the user, then approve-top the new turn.')
    except prov.Problem as error:
        raise Denied('transcript_unreadable', str(error)) from None
    sentence = assent['sentence']
    families = families_of(sentence)
    if not families:
        raise Denied('no_family', 'the assenting sentence names neither fable nor astra')
    assent_ts = parse_time(_norm_server_time(assent['timestamp']) or '')
    expires = assent_ts + MAX_LIFETIME
    if now >= expires or assent_ts > now + SKEW:
        raise Denied('expired', 'the cited user turn is outside the 12 h window')
    ed25519, serialization, _ = crypto = _crypto()
    key = _private_key(store, ed25519, serialization)
    raw_public = public_raw(key, serialization)
    config = load_config(store)
    trusted = load_trusted_keys(store)
    if key_id_of(raw_public) not in trusted:
        raise Denied('key_not_pinned', 'the signing key is not pinned on this host; run the installer')
    client = _client(client)
    decisions, revocations, newest = read_ledger(store, client, config, trusted, crypto, with_newest=True)
    # assent_at comes from this Mac's transcript clock and revoke times from the server: refuse to sign when the
    # two disagree by more than the skew, so a scope revoke is never misordered against the user's words.
    server_now = client.server_time() if callable(getattr(client, 'server_time', None)) else None
    if (server_now is not None and abs(server_now - now) > SKEW) or (newest is not None and newest > now + SKEW):
        raise Denied('clock_skew', 'this host clock differs from the ledger server by more than %d s' % SKEW)
    probe = {'decision_id': '0' * 32, 'task': task, 'session': session, 'assent_at': iso(assent_ts)}
    if any(r['scope'] != 'decision' and covers(r, probe) for r in revocations + local_tombstones(store)):
        raise Denied('revoked', 'a revocation after the cited words covers this task or session')
    for item in decisions:
        p = item['payload']
        if p['turn_uuid'] == turn and any(r['scope'] == 'decision' and r['value'] == p['decision_id']
                                          for r in revocations + local_tombstones(store)):
            raise Denied('revoked', 'a decision from the same user turn was revoked; ask the user again')
    tasks = {item['payload']['task'] for item in decisions if item['payload']['turn_uuid'] == turn}
    if task not in tasks and len(tasks) >= PER_TURN_CAP:
        raise Denied('turn_cap', 'one user turn may back at most %d task keys on the ledger' % PER_TURN_CAP)
    payload = {'schema': SCHEMA, 'decision_id': uuid.uuid4().hex, 'task': task, 'families': families,
               'source': source, 'session': session, 'turn_uuid': turn, 'sentence': sentence,
               'sentence_sha256': hashlib.sha256(sentence.encode('utf-8')).hexdigest(),
               'assent_at': iso(assent_ts), 'issued_at': iso(min(now, expires - 1)), 'expires_at': iso(expires),
               'key_id': key_id_of(raw_public),
               'issuer_host': (host or socket.gethostname().split('.')[0])[:64], 'ask_id': ask}
    if not _shape_ok(payload):
        raise Denied('malformed', 'the decision record failed its own shape check')
    payload_raw = canonical(payload)
    signature = key.sign(signed_message(config['ledger']['issue_id'], payload_raw))
    body = DECISION_PREFIX + b64url(payload_raw) + '.' + b64url(signature)
    try:
        store.ensure_dirs()
        _append_private(store.published, {'decision_id': payload['decision_id'], 'task': task, 'session': session,
                                          'turn_uuid': turn, 'expires_at': payload['expires_at']})
    except (OSError, Denied):
        # Without the index the prompt hook could not auto-revoke this decision later: refuse before posting.
        raise Denied('index_unwritable', 'the published-decisions index could not be written; nothing was posted') from None
    client.post(config['ledger']['issue_id'], body, 'central-decision-' + payload['decision_id'])
    try:
        late = later_mentions(session, turn, home)
    except (Denied, prov.Problem, OSError):
        late = True  # cannot prove that no later turn arrived while publishing: withdraw (fail safe)
    if late:
        result = withdraw('decision', payload['decision_id'], store=store, client=client, now=now,
                          reason='later-turn-during-publish')
        raise Denied('later_turn', 'a later user turn arrived while publishing; the decision was withdrawn at once (%s)'
                     % ('posted' if result.get('posted') else 'revoke queued'))
    return {'published': True, 'task': task, 'decision_id': payload['decision_id'], 'families': families,
            'expires_at': payload['expires_at'], 'key_id': payload['key_id']}


# ------------------------------------------------------------------ revocation

class _PendingLock:
    """An exclusive lock around every change to pending-revocations.jsonl, so a hook in one session that rewrites
    the queue after posting cannot drop a row another session appended meanwhile."""

    def __init__(self, store):
        self.path = store.dir / 'pending-revocations.lock'

    def __enter__(self):
        import fcntl  # noqa: PLC0415
        self.fd = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        fcntl.flock(self.fd, fcntl.LOCK_EX)
        return self

    def __exit__(self, *exc):
        os.close(self.fd)  # closing releases the lock


def _op_id(line, at):
    return 'central-revoke-' + hashlib.sha256((line + str(at)).encode()).hexdigest()[:32]


def _drop_pending(store, posted):
    """Remove exactly the posted (line, at) rows, re-reading the queue under the lock."""
    with _PendingLock(store):
        rows = _read_jsonl(store.pending)
        left = [r for r in rows if (r.get('line'), r.get('at')) not in posted]
        if len(left) != len(rows):
            _write_private(store.pending, b''.join((json.dumps(r, sort_keys=True) + '\n').encode() for r in left), 0o600)


def withdraw(scope, value=None, *, store=None, client=None, now=None, reason='withdrawn', deadline_seconds=None,
             post=True):
    """The queued ledger line, then the local tombstone (denies on this host at once), then (with `post`) the
    post; the queue row is removed only after the post succeeded. A process stopped at any point after the queue
    row is written leaves the line queued, and every hook verb retries the queue; one stopped before it wrote
    anything leaves nothing. The caller hears whether it was posted."""
    store = store or Store()
    line = 'agent-harness-revoke ' + ('all' if scope == 'all' else '%s %s' % (scope, value))
    match = REVOKE.fullmatch(line)
    if not match:
        raise Denied('bad_request', 'revoke scope must be all, task <key>, session <uuid> or decision <id>')
    now = time.time() if now is None else now
    store.ensure_dirs()
    # queue row before tombstone: a tombstone hides the decision from later hooks (live_published), so a process
    # stopped between the two writes must leave the row, never a tombstone alone. The tombstone still lands before
    # any network call, so this host denies at once.
    with _PendingLock(store):
        _append_private(store.pending, {'line': line, 'at': now, 'error': 'not_posted_yet'})
    _append_private(store.tombstones, {'scope': scope, 'value': value, 'at': now, 'origin': 'local:' + reason})
    if not post:
        return {'revoked': line, 'posted': False, 'queued': True}
    try:
        config = load_config(store)
        _client(client, deadline_seconds).post(config['ledger']['issue_id'], line, _op_id(line, now))
    except Exception as error:  # noqa: BLE001  any failure to post (the GoodQA client raises its own types): stays queued
        code = error.code if isinstance(error, Denied) else type(error).__name__
        return {'revoked': line, 'posted': False, 'error': code, 'queued': True}
    _drop_pending(store, {(line, now)})
    return {'revoked': line, 'posted': True}


def retry_pending(store=None, client=None, deadline_seconds=None):
    """Post every queued revoke line; rows leave the queue only after their post succeeded."""
    store = store or Store()
    rows = _read_jsonl(store.pending)
    if not rows:
        return []
    config = load_config(store)
    client = _client(client, deadline_seconds)
    posted, done = set(), []
    for row in rows:
        line = row.get('line')
        if not isinstance(line, str) or not REVOKE.fullmatch(line):
            continue
        try:
            client.post(config['ledger']['issue_id'], line, _op_id(line, row.get('at')))
        except Exception:  # noqa: BLE001  stays queued whatever the client raised
            continue
        posted.add((line, row.get('at')))
        done.append(line)
    if posted:
        _drop_pending(store, posted)
    return done


def live_published(store, session, now):
    """{decision_id: turn_uuid} of this session's published, unexpired decisions that this host has not already
    tombstoned (a revoked decision is not withdrawn again on every later hook)."""
    done = {row['value'] for row in local_tombstones(store) if row['scope'] == 'decision'}
    live = {}
    for row in _read_jsonl(store.published):
        try:
            if (row.get('session') == session and HEX32.fullmatch(str(row.get('decision_id')))
                    and UUID.fullmatch(str(row.get('turn_uuid'))) and parse_time(row.get('expires_at')) > now
                    and row['decision_id'] not in done):
                live[row['decision_id']] = row['turn_uuid']
        except Denied:
            continue
    return live


def on_hook_event(session, *, text=None, unreadable=False, sweep=True, claude_home=None, store=None, client=None,
                  now=None):
    """Every hook verb (prompt, question answer, stop) lands here, so every withdrawal channel the local grant path
    honours produces a ledger revocation (PR 14 class A). One HOOK_DEADLINE budget covers the whole run:
      1. if this session has live published decisions: choose to revoke all of them when `text` (a prompt or an
         answer) meets withdrawal_signal, or when the answer could not be read (`unreadable`, fail safe); otherwise,
         with `sweep`, rescan the session transcript after each decision's cited turn with later_mentions (the same
         record extraction as the adapter: typed turns, question answers, queued mid-turn messages); a transcript
         that cannot be read revokes too, as publish does;
      2. write each chosen revocation's local tombstone and queue row (no network yet), so a process killed later
         still leaves it queued;
      3. post the whole queue (this run's rows and older ones) with one client inside what is left of the budget;
         rows leave the queue only after their post succeeded.
    Returns a short note or None. Never raises. A session without live decisions costs one small index read."""
    store = store or Store()
    end = time.monotonic() + HOOK_DEADLINE
    notes, revoked = [], []
    try:
        if UUID.fullmatch(str(session or '')):
            now = time.time() if now is None else now
            live = live_published(store, session, now)
            targets = {}
            if live and unreadable:
                targets = dict.fromkeys(live, 'unreadable-answer')
            elif live and withdrawal_signal(text):
                targets = dict.fromkeys(live, 'later-user-turn')
            elif live and sweep:
                for turn in sorted(set(live.values())):
                    try:
                        late, why = later_mentions(session, turn, claude_home), 'later-turn-in-transcript'
                    except Exception:  # noqa: BLE001  cannot prove no later turn: fail safe, as publish does
                        late, why = True, 'transcript-unreadable'
                    if late:
                        targets.update((decision_id, why) for decision_id, cited in live.items() if cited == turn)
            for decision_id in sorted(targets):
                revoked.append(withdraw('decision', decision_id, store=store, now=now, reason=targets[decision_id],
                                        post=False)['revoked'])
    except Exception as error:  # noqa: BLE001
        notes.append('central-decision revocation failed (%s)' % type(error).__name__)
    posted = []
    try:
        left = end - time.monotonic()
        if store.pending.exists() and left > 0.5:
            posted = retry_pending(store, client, left)
    except Exception:  # noqa: BLE001
        pass
    for line in revoked:
        notes.append('revoked central decision %s (%s)' % (
            line.rsplit(' ', 1)[-1][:8], 'posted' if line in posted else
            'NOT posted: queued for retry by the next hook; other hosts still accept it until it is posted, or run '
            'python3 ~/.claude/hooks/ah.py decision withdraw --all'))
    older = len([line for line in posted if line not in revoked])
    if older:
        notes.append('posted %d queued central-decision revocation(s)' % older)
    if store.pending.exists() and not revoked and not posted:
        try:
            if _read_jsonl(store.pending):
                notes.append('queued central-decision revocations still unposted; to deny everywhere now run '
                             'python3 ~/.claude/hooks/ah.py decision withdraw --all')
        except Exception:  # noqa: BLE001
            pass
    return '; '.join(notes) or None


def on_user_prompt(session, text, *, store=None, client=None, now=None, claude_home=None):
    """Prompt hook: the submitted text is not in the transcript yet, so it is judged directly; then the sweep."""
    return on_hook_event(session, text=text if isinstance(text, str) else None, claude_home=claude_home, store=store,
                         client=client, now=now)


def on_ask_answer(session, tool_response, *, store=None, client=None, now=None, claude_home=None):
    """PostToolUse hook for AskUserQuestion: the user's selections, read by the same extractor the local path uses
    (provenance.ask_answers_text). An answer that cannot be read revokes (fail safe)."""
    import provenance as prov  # noqa: PLC0415
    text = prov.ask_answers_text(tool_response)
    return on_hook_event(session, text=text, unreadable=text is None, claude_home=claude_home, store=store,
                         client=client, now=now)


def on_stop(session, *, store=None, client=None, now=None, claude_home=None):
    """Stop hook: the transcript sweep catches queued mid-turn messages and anything the direct paths missed."""
    return on_hook_event(session, claude_home=claude_home, store=store, client=client, now=now)


# ------------------------------------------------------------------ CLI

def main(argv=None):
    parser = argparse.ArgumentParser(prog='ah decision', description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest='action', required=True)
    sub.add_parser('keygen')
    sub.add_parser('pubkey')
    p = sub.add_parser('pin'); p.add_argument('--pubkey-file', required=True, type=Path)
    e = sub.add_parser('enable'); e.add_argument('--project', required=True); e.add_argument('--number', required=True, type=int)
    e.add_argument('--issue-id', help='ledger issue id (default: looked up through GoodQA)')
    pub = sub.add_parser('publish'); pub.add_argument('--task', required=True)
    v = sub.add_parser('verify'); v.add_argument('--task', required=True); v.add_argument('--family', required=True, choices=FAMILIES)
    w = sub.add_parser('withdraw'); g = w.add_mutually_exclusive_group(required=True)
    g.add_argument('--task'); g.add_argument('--session'); g.add_argument('--decision'); g.add_argument('--all', action='store_true')
    args = parser.parse_args(argv)
    try:
        if args.action == 'keygen':
            value = keygen()
        elif args.action == 'pubkey':
            ed25519, serialization, _ = _crypto()
            raw = public_raw(_private_key(Store(), ed25519, serialization), serialization)
            value = {'key_id': key_id_of(raw), 'public_key': b64url(raw)}
        elif args.action == 'pin':
            if str(args.pubkey_file) == '-':  # stdin, for `ssh host ... --pubkey-file - < file` (/dev/stdin is refused on Linux)
                raw_key = sys.stdin.buffer.read(4096)
            else:
                raw_key = args.pubkey_file.read_bytes()[:4096]  # input-ok: a public key record, bounded
            data = strict_json(raw_key)
            if not isinstance(data, dict) or not isinstance(data.get('public_key'), str):
                raise Denied('bad_request', 'the pubkey file must hold {"public_key": ...}')
            value = pin(data['public_key'])
        elif args.action == 'enable':
            issue_id = args.issue_id
            if not issue_id:
                state = GoodQALedger().issue_state(args.project, args.number)
                if state is None:
                    raise Denied('ledger_missing', 'no such ledger ticket')
                issue_id = state['id']
            value = enable(args.project, args.number, issue_id)
        elif args.action == 'publish':
            value = publish(args.task)
        elif args.action == 'verify':
            value = {'valid': True, **verify(args.task, args.family)}
        else:
            scope, val = (('all', None) if args.all else ('task', args.task) if args.task else
                          ('session', args.session) if args.session else ('decision', args.decision))
            value = withdraw(scope, val)
    except Denied as error:
        print(json.dumps({'ok': False, 'code': error.code, 'message': error.message[:400]}))
        return 2
    except (OSError, ValueError) as error:
        print(json.dumps({'ok': False, 'code': type(error).__name__, 'message': str(error)[:200]}))
        return 2
    print(json.dumps({'ok': True, **value}, sort_keys=True, indent=1))
    return 0


if __name__ == '__main__':
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    raise SystemExit(main())
