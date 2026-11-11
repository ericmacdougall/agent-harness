#!/usr/bin/env python3
"""Deterministic per-task model-ladder state (GoodQA goodqa#14527).

State lives in ~/.agent-harness/escalation/<task>.json (0600) under a flock. Failure events come only
from machine receipts: usage_guard FINAL records (review verdicts, provider launches, test results) and
spec_flow review records. Each event is keyed by the sha256 of the receipt bytes, so replaying one is
a no-op. The rung is a pure function of the event list and the tier table. Anything the ledger cannot
read or classify resets the task to the lowest rung with a durable reset record, never a guess.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
import re
import shutil
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import model_tiers as tiers  # noqa: E402

SCHEMA = 1
TASK_KEY = re.compile(r'\[task:([A-Za-z0-9][A-Za-z0-9._-]{0,63})\]')
SAFE_KEY = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$')
MAX_STATE = 1 << 20
MAX_EVENTS = 4096


def installed_home():
    """The account's home from the passwd database, so a caller's HOME cannot relabel the installed roots."""
    try:
        import pwd
        return Path(pwd.getpwuid(os.getuid()).pw_dir)
    except (ImportError, KeyError, OSError):
        return Path.home()


DEFAULT_ROOT = installed_home() / '.agent-harness' / 'escalation'
DEFAULT_USAGE_ROOT = installed_home() / '.agent-harness' / 'usage'
PENDING_BATCH = 256
LOCK_SECONDS = 2.0
# The fixed classifier table (user requirement, deterministic): what each receipt means for the ladder.
NOT_COUNTED_REASONS = {'TRANSIENT_INFRA', 'LOW_DISK', 'QUOTA', 'AUTH', 'TIMEOUT', 'UNKNOWN', 'BUDGET_EXHAUSTED'}
RESET_CODES = {'missing_task_key', 'state_unreadable', 'state_corrupt', 'lock_timeout', 'unclassifiable_evidence',
               'tier_table_error', 'schema_mismatch'}


class LedgerError(RuntimeError):
    def __init__(self, code, message):
        super().__init__(message)
        self.code, self.message = code, message


def now():
    return datetime.now(timezone.utc).isoformat()


def rotate_log(path, limit=4 << 20):
    """Keep append-only logs bounded: above the limit the file is renamed to .1 (one generation kept)."""
    try:
        if path.exists() and path.stat().st_size > limit:
            os.replace(path, path.with_suffix(path.suffix + '.1'))
    except OSError:
        pass


def state_root():
    root = Path(os.environ.get('AGENT_HARNESS_ESCALATION_DIR') or Path.home() / '.agent-harness' / 'escalation')
    if root.is_symlink():
        raise LedgerError('state_unreadable', 'escalation state directory cannot be a symlink')
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(root, 0o700)
    return root


def task_key_from(*texts):
    """The [task:<key>] token from a spawn prompt or description, else None."""
    for text in texts:
        if isinstance(text, str):
            found = TASK_KEY.search(text)
            if found:
                return found.group(1)
    return None


def generated_key(*texts):
    digest = hashlib.sha256('\x1f'.join(str(t) for t in texts).encode('utf-8', 'replace')).hexdigest()[:16]
    return 'auto-' + digest


NAMED = re.compile(r'^[A-Za-z][A-Za-z0-9._-]{0,63}$')


def named_findings(findings):
    """Only findings with a real id count: UNSPECIFIED, empty and non-string ids are not named."""
    kept = []
    for item in findings or ():
        ident = item.get('id') if isinstance(item, dict) else str(item).split(':', 1)[0]
        if isinstance(ident, str) and NAMED.fullmatch(ident.strip()) and ident.strip().upper() != 'UNSPECIFIED':
            kept.append(item)
    return kept


def fingerprint(findings):
    """A deterministic hash of normalized finding ids, files and categories; None when there are none."""
    rows = []
    for item in named_findings(findings):
        if isinstance(item, dict):
            ident, path, category = item.get('id'), item.get('file'), item.get('category')
        else:
            parts = str(item).split(':', 2) + ['', '']
            ident, path, category = parts[0], parts[1], parts[2]
        rows.append('|'.join(str(part or '').strip().lower() for part in (ident, path, category)))
    if not rows:
        return None
    return hashlib.sha256('\n'.join(sorted(set(rows))).encode('utf-8')).hexdigest()


def classify(receipt, *, kind, claimed_heads=()):
    """FAIL, PASS or NOT_COUNTED for one machine receipt; never from prose.

    kind: 'review' (usage_guard FINAL with a review dict), 'test' (usage_guard FINAL for a guarded test run),
    'spec_review' (spec_flow review record with verdict/findings).
    """
    if not isinstance(receipt, dict):
        return 'NOT_COUNTED', 'receipt is not an object', None
    if kind in ('review', 'test'):
        if receipt.get('kind') != 'final' or receipt.get('evidence') != 'EXECUTED':
            return 'NOT_COUNTED', 'not an executed FINAL receipt', None
        usage = receipt.get('usage') if isinstance(receipt.get('usage'), dict) else {}
        launches = usage.get('provider_launches')
        reason = receipt.get('reason')
        if kind == 'review' and (type(launches) is not int or launches == 0):
            return 'NOT_COUNTED', 'zero-launch attempt', None
        if reason in NOT_COUNTED_REASONS or receipt.get('execution') in ('NOT_STARTED', 'INTERRUPTED', 'UNKNOWN'):
            return 'NOT_COUNTED', 'infrastructure or uncertain result (%s)' % reason, None
        if kind == 'review':
            review = receipt.get('review')
            if not isinstance(review, dict):
                return 'NOT_COUNTED', 'no review verdict in receipt', None
            if review.get('verdict') == 'BLOCK' and named_findings(review.get('findings')):
                return 'FAIL', 'material review finding', fingerprint(review['findings'])
            if review.get('verdict') == 'ACCEPT':
                return 'PASS', 'review accepted', None
            return 'NOT_COUNTED', 'blocked without named findings', None
        head = (receipt.get('subject') or {}).get('head')
        if receipt.get('result') == 'CHECK_OK':
            return 'PASS', 'tests green', None
        if reason == 'CODE_FINDINGS' and head and head in set(claimed_heads):
            invocation = (receipt.get('invocation') or {}).get('fingerprint') or 'unknown-invocation'
            return 'FAIL', 'tests red at the same HEAD after a claimed fix', fingerprint(['tests', invocation, 'red'])
        if reason == 'CODE_FINDINGS':
            return 'NOT_COUNTED', 'tests red but no claimed fix at this HEAD', None
        return 'NOT_COUNTED', 'result %s/%s' % (receipt.get('result'), reason), None
    if kind == 'spec_review':
        if receipt.get('verdict') == 'BLOCK' and named_findings(receipt.get('findings')):
            return 'FAIL', 'spec review blocked with findings', fingerprint(receipt['findings'])
        if receipt.get('verdict') == 'ACCEPT':
            return 'PASS', 'spec review accepted', None
        return 'NOT_COUNTED', 'spec review without a usable verdict', None
    return 'NOT_COUNTED', 'unknown receipt kind', None


def rung_of(events, policy):
    """Pure: replay FAIL events into (rung, failures_at_rung, fingerprint, climbs)."""
    rung = policy['lowest_rung']
    fails, current, climbs = 0, None, 0
    last_head, fixed_since = None, True
    for event in events:
        if event.get('class') == 'CLAIM':
            fixed_since = True
            continue
        if event.get('class') != 'FAIL':
            continue
        if event.get('fingerprint') != current:
            current, fails = event.get('fingerprint'), 0
        elif not fixed_since and event.get('head') and event.get('head') == last_head:
            continue  # the same finding at the same HEAD with no claimed fix between: one failure, not two
        fails += 1
        last_head, fixed_since = event.get('head'), False
        if fails >= policy['failures_per_rung']:
            above = tiers.next_writing_rung(policy, rung)
            if above is None:
                break  # top of the automatic ladder: stays, the hook asks the user
            rung, fails, current, climbs = above, 0, None, climbs + 1
    return {'rung': rung, 'failures_at_rung': fails, 'fingerprint': current, 'climbs': climbs}


def ladder_status(state, policy):
    """What the ladder allows now: the computed rung, whether a climb limit or cost ceiling blocks."""
    computed = rung_of(state['events'], policy)
    limits = policy['ladder_limits']
    blocked = []
    if computed['climbs'] > limits['max_rung_climbs']:
        blocked.append('max_rung_climbs')
    if state.get('launches', 0) >= limits['max_review_launches']:
        blocked.append('max_review_launches')
    if state.get('spend_usd', 0) >= limits['max_total_review_usd']:
        blocked.append('max_total_review_usd')
    needs_permission = policy['rungs'][computed['rung']]['needs_user_permission']
    return {**computed, 'blocked_by': blocked, 'needs_user_permission': needs_permission,
            'permission': state.get('permission'), 'task': state['task']}


class Ledger:
    def __init__(self, root=None, policy=None):
        self.root = Path(root) if root else state_root()
        self.policy = policy or tiers.load_policy()

    def path(self, task):
        if not SAFE_KEY.fullmatch(task):
            raise LedgerError('missing_task_key', 'task key is not safe')
        return self.root / (task + '.json')

    def _lock(self, task):
        fd = os.open(self.root / (task + '.lock'), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        import time
        deadline = time.monotonic() + LOCK_SECONDS
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return fd
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    os.close(fd)
                    raise LedgerError('lock_timeout', 'ledger lock busy for task ' + task)
                time.sleep(0.02)

    def fresh(self, task, *, generated=False):
        return {'schema': SCHEMA, 'task': task, 'generated_key': generated, 'created_at': now(),
                'events': [], 'escalations': [], 'resets': [], 'claims': [], 'launches': 0, 'spend_usd': 0.0,
                'permission': None}

    def _read(self, task):
        """State dict, or a fresh state plus a reset record when the file is missing or unusable."""
        path = self.path(task)
        if not path.exists():
            return self.fresh(task), None
        raw = None
        try:
            info = os.stat(path, follow_symlinks=False)
            if not os.path.isfile(path) or os.path.islink(path) or info.st_size > MAX_STATE:
                raise ValueError('oversized or not a regular file')
            raw = path.read_bytes()  # input-ok: size checked above
            state = json.loads(raw)
            if (not isinstance(state, dict) or state.get('schema') != SCHEMA or state.get('task') != task
                    or not isinstance(state.get('events'), list)):
                raise ValueError('schema')
            return state, None
        except (OSError, ValueError, UnicodeError) as error:
            code = 'state_unreadable' if isinstance(error, OSError) else 'state_corrupt'
            prior_hash = hashlib.sha256(raw).hexdigest() if isinstance(raw, bytes) else None
            copy = None
            try:
                copy = str(path) + '.corrupt.' + now().replace(':', '') + '.json'
                shutil.copyfile(path, copy)
                os.chmod(copy, 0o600)
            except OSError:
                copy = None
            state = self.fresh(task)
            reset = {'at': now(), 'code': code, 'prior_state_sha256': prior_hash, 'preserved_copy': copy,
                     'detail': type(error).__name__}
            state['resets'].append(reset)
            return state, reset

    def _write(self, task, state):
        path = self.path(task)
        body = json.dumps(state, sort_keys=True, separators=(',', ':')).encode('utf-8')
        if len(body) > MAX_STATE:
            raise LedgerError('state_corrupt', 'state would exceed its size bound')
        temporary = path.with_suffix('.tmp')
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as handle:
            handle.write(body); handle.flush(); os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)

    def pending_reset(self, task, code, detail):
        """Record a reset that could not take the lock (lock_timeout) in a lock-free O_APPEND side file."""
        record = {'at': now(), 'code': code, 'prior_state_sha256': None, 'preserved_copy': None, 'detail': detail,
                  'pending': True}
        path = self.root / (task + '.pending-resets.jsonl')
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'a', encoding='utf-8') as handle:
            handle.write(json.dumps(record, sort_keys=True) + '\n')
        self._notify(task, 'reset', record, None)
        return record

    def _absorb_pending(self, task, state):
        path = self.root / (task + '.pending-resets.jsonl')
        if not path.exists():
            return False
        try:
            lines = path.read_text(encoding='utf-8').splitlines()  # input-ok: own 0600 side file, batched below
        except OSError:
            return False
        absorbed = False
        for line in lines[:PENDING_BATCH]:
            try:
                record = json.loads(line)
            except ValueError:
                continue
            if record not in state['resets']:
                state['resets'].append(record); absorbed = True
        remainder = lines[PENDING_BATCH:]
        try:
            if remainder:  # never drop a durable reset: the rest is absorbed on the next load
                tmp = path.with_suffix('.tmp')
                tmp.write_text('\n'.join(remainder) + '\n', encoding='utf-8'); os.chmod(tmp, 0o600); os.replace(tmp, path)
            else:
                os.unlink(path)
        except OSError:
            pass
        return absorbed

    def load(self, task):
        fd = self._lock(task)
        try:
            state, reset = self._read(task)
            if self._absorb_pending(task, state) or reset is not None:
                self._write(task, state)
            return state
        finally:
            os.close(fd)

    def record(self, task, receipt_bytes, *, kind, source, head=None, notify=None):
        """Append one receipt-derived event; replaying the same bytes is a no-op. Returns the ladder status."""
        if not isinstance(receipt_bytes, (bytes, bytearray)):
            raise LedgerError('unclassifiable_evidence', 'receipt must be raw bytes')
        sha = hashlib.sha256(receipt_bytes).hexdigest()
        try:
            receipt = json.loads(receipt_bytes.decode('utf-8'))
        except (ValueError, UnicodeError):
            receipt = None
        fd = self._lock(task)
        try:
            state, reset = self._read(task)
            self._absorb_pending(task, state)
            if any(event.get('receipt_sha256') == sha for event in state['events']):
                status = ladder_status(state, self.policy)
                status['replayed'] = True
                return status
            if len(state['events']) >= MAX_EVENTS:
                raise LedgerError('state_corrupt', 'event bound reached for task ' + task)
            before = rung_of(state['events'], self.policy)
            klass, why, fp = classify(receipt, kind=kind, claimed_heads=[c['head'] for c in state['claims']])
            if receipt is None:
                klass, why, fp = 'NOT_COUNTED', 'receipt is not JSON', None
                state['resets'].append({'at': now(), 'code': 'unclassifiable_evidence', 'receipt_sha256': sha,
                                        'prior_state_sha256': None, 'preserved_copy': None, 'detail': 'not JSON'})
            if head is None and isinstance(receipt, dict):
                head = (receipt.get('subject') or {}).get('head')  # the receipt's own HEAD, never a caller claim
            event = {'seq': len(state['events']) + 1, 'at': now(), 'kind': kind, 'class': klass, 'why': why,
                     'fingerprint': fp, 'receipt_sha256': sha, 'source': source, 'head': head,
                     'rung_at': before['rung']}
            launched = isinstance(receipt, dict) and isinstance(receipt.get('usage'), dict) \
                and type(receipt['usage'].get('provider_launches')) is int and receipt['usage']['provider_launches'] >= 1
            if kind == 'review' and launched and klass != 'PASS':
                # Only failing or not-counted paid launches spend the launch ceiling; accepted reviews are
                # the healthy path and never block a task (assumption, recorded in the spec).
                state['launches'] = state.get('launches', 0) + 1
                # Until helpers report real cost, each counted launch spends the rung's review budget
                # as a conservative upper bound so the ceiling has effect.
                rung_now = before['rung']
                budget = self.policy['rungs'][rung_now].get('review_budget_usd') or 0
                state['spend_usd'] = round(float(state.get('spend_usd', 0.0)) + float(budget), 4)
            state['events'].append(event)
            after = rung_of(state['events'], self.policy)
            if after['rung'] != before['rung']:
                escalation = {'at': now(), 'from': before['rung'], 'to': after['rung'], 'reason': why,
                              'evidence': sha, 'fingerprint': fp, 'seq': event['seq']}
                state['escalations'].append(escalation)
            self._write(task, state)
            status = ladder_status(state, self.policy)
            status['event'] = event
            pending = []
            if after['rung'] != before['rung']:
                status['escalation'] = escalation
                pending.append(('escalation', escalation))
            if reset is not None:
                pending.append(('reset', reset))
        finally:
            os.close(fd)
        for event_name, record in pending:
            self._notify(task, event_name, record, notify)
        return status

    def claim_fix(self, task, head):
        """The owner declares a fix at HEAD; a later red test receipt at that HEAD then counts as a failure."""
        if not re.fullmatch(r'[0-9a-f]{7,64}', head or ''):
            raise LedgerError('unclassifiable_evidence', 'head must be a commit sha')
        fd = self._lock(task)
        try:
            state, _ = self._read(task)
            if not any(c['head'] == head for c in state['claims']):
                state['claims'].append({'head': head, 'at': now()})
                state['events'].append({'seq': len(state['events']) + 1, 'at': now(), 'kind': 'claim', 'class': 'CLAIM',
                                        'why': 'owner claimed a fix', 'fingerprint': None, 'receipt_sha256': None,
                                        'source': 'claim-fix', 'head': head, 'rung_at': rung_of(state['events'], self.policy)['rung']})
                self._write(task, state)
            return ladder_status(state, self.policy)
        finally:
            os.close(fd)

    def add_spend(self, task, usd):
        fd = self._lock(task)
        try:
            state, _ = self._read(task)
            state['spend_usd'] = round(float(state.get('spend_usd', 0.0)) + float(usd), 4)
            self._write(task, state)
            return ladder_status(state, self.policy)
        finally:
            os.close(fd)

    def reset(self, task, code, detail, notify=None):
        """Reset to the lowest rung with a durable record (the hook's unknown-rung path)."""
        if code not in RESET_CODES:
            raise LedgerError('state_corrupt', 'unknown reset code')
        fd = self._lock(task)
        try:
            state, _ = self._read(task)
            prior = hashlib.sha256(json.dumps(state, sort_keys=True).encode()).hexdigest()
            copy = None
            if self.path(task).exists():
                copy = str(self.path(task)) + '.reset.' + now().replace(':', '') + '.json'
                shutil.copyfile(self.path(task), copy); os.chmod(copy, 0o600)
            record = {'at': now(), 'code': code, 'prior_state_sha256': prior, 'preserved_copy': copy, 'detail': detail}
            fresh = self.fresh(task, generated=state.get('generated_key', False))
            fresh['resets'] = state.get('resets', []) + [record]
            fresh['permission'] = state.get('permission')
            self._write(task, fresh)
        finally:
            os.close(fd)
        self._notify(task, 'reset', record, notify)
        return ladder_status(fresh, self.policy)

    def approve_top(self, task, ask_id, wal, session=None):
        """Record user permission for the top writing rung on this one task, after verifying the ask pair in the
        WAL AND re-reading the cited user turn: its own words must ask for the top rung (review F2: a hand-written
        ask pair citing an unrelated human turn used to pass). There is no session-wide grant (review F1; main:
        grants are per task only), so `session` is accepted for compatibility and ignored."""
        proof = verify_ask_pair(Path(wal), ask_id, task, allow_env_root=self._non_default_root())
        caps = self.policy.get('caps', {})
        assent = verify_top_source(proof['source'], allow_env_root=self._non_default_root(),
                                   max_age_seconds=int(caps.get('top_assent_max_age_seconds', TOP_ASSENT_MAX_AGE)))
        permission = {'ask_id': ask_id, 'wal': str(wal), 'at': now(), 'source': proof['source'], 'task': task,
                      'assent': assent['sentence'][:300], 'assent_at': assent['timestamp']}
        fd = self._lock(task)
        try:
            state, _ = self._read(task)
            state['permission'] = permission
            self._write(task, state)
            status = ladder_status(state, self.policy)
        finally:
            os.close(fd)
        return status

    def status(self, task):
        return ladder_status(self.load(task), self.policy)

    def _non_default_root(self):
        """Env-selected WAL and usage roots are honoured only for a test ledger, never for the installed one."""
        try:
            return self.root.resolve() != DEFAULT_ROOT.resolve()
        except OSError:
            return False

    def gate_digest(self, limit=200):
        """What the hook would have refused (warn mode) or refused (enforce): evidence for the flip."""
        path = self.root / 'gate.jsonl'
        rows = []
        try:
            lines = path.read_text(encoding='utf-8').splitlines()[-limit:]  # input-ok: bounded by limit lines
        except OSError:
            return rows
        for line in lines:
            try:
                record = json.loads(line)
            except ValueError:
                continue
            if record.get('decision') == 'deny' or (record.get('facts') or {}).get('reset'):
                rows.append({'at': record.get('at'), 'tool': record.get('tool'), 'mode': record.get('mode'),
                             'decision': record.get('decision'), 'reason': record.get('reason'),
                             'task': (record.get('facts') or {}).get('task'), 'reset': (record.get('facts') or {}).get('reset')})
        return rows

    def digest(self):
        rows = []
        for path in sorted(self.root.glob('*.json')):
            if '.corrupt.' in path.name or '.reset.' in path.name:
                continue
            try:
                rows.append(self.status(path.stem))
            except LedgerError as error:
                rows.append({'task': path.stem, 'error': error.code})
        return rows

    def _notify(self, task, event, record, notify):
        """Durable notification for main plus a WAL decision entry when a WAL path is given."""
        line = {'at': now(), 'task': task, 'event': event, **record}
        target = self.root / 'notifications.jsonl'
        rotate_log(target)
        with open(target, 'a', encoding='utf-8') as handle:
            handle.write(json.dumps(line, sort_keys=True) + '\n')
        os.chmod(target, 0o600)
        wal = notify or os.environ.get('AGENT_HARNESS_MAIN_WAL')
        if wal:
            note = ('LADDER %s task %s: %s' % (event.upper(), task, json.dumps(record, sort_keys=True)))[:900]
            try:
                # No invented source: the entry is unsourced (the hook warns) and cites the state file in its text.
                subprocess.run([sys.executable, str(Path(__file__).resolve().parent / 'wal_note.py'), '--wal', str(wal),
                                '--event', 'decision', '--note', note + ' state=' + str(self.path(task)), '--by', 'escalation'],
                               capture_output=True, text=True, timeout=20)
            except (OSError, subprocess.SubprocessError):
                pass


def verified_final(run_id, allow_env_root=False):
    """The FINAL receipt bytes of a usage-guard run, verified against the store's completion reference.

    The installed ledger reads the installed usage store; AGENT_HARNESS_USAGE_DIR applies only to a test ledger."""
    import usage_guard
    store = usage_guard.UsageStore(None if allow_env_root else DEFAULT_USAGE_ROOT)
    directory = store._run_directory(run_id)
    completion = usage_guard.read_json(directory / 'completion.json')
    reference = completion.get('reference') if isinstance(completion, dict) else None
    if not isinstance(reference, dict) or reference.get('run_id') != run_id or reference.get('record') != 'final':
        raise LedgerError('unclassifiable_evidence', 'run has no completion reference')
    store.load_ref(reference)  # digest and schema check
    return (directory / 'final.json').read_bytes()  # input-ok: verified by load_ref, bounded by MAX_JSON


USER_SOURCE_KINDS = ('user', 'answer', 'queue')  # provenance.parse_source maps all three to kind "user"


def user_sourced(source):
    """True when the ask's source is a real user turn as provenance.py classifies it: user:, plus the queue: (mid-turn
    queued message) and answer: (AskUserQuestion reply) variants it treats as the same trust class. approve-top
    refused a queue: grant on 2026-11-06 although the user typed it (main WAL w69761822b47). This is a
    classification only: wal_note enforces the syntax and resolution of an ask's source when the ask is written."""
    return bool(re.match(r'^(%s):' % '|'.join(USER_SOURCE_KINDS), str(source or '')))


def verify_ask_pair(wal, ask_id, task, allow_env_root=False):
    """A registered ask with a user: source naming the task, resolved by an ask_resolved that refs it.

    The wals root is the installed one unless the caller's ledger is itself non-default (allow_env_root),
    so an agent cannot point the installed ledger at a WAL of its own through the environment."""
    override = os.environ.get('AGENT_HARNESS_WALS_DIR') if allow_env_root else None
    wals_root = Path(override or installed_home() / '.claude' / 'wals').resolve()
    resolved_wal = Path(wal).resolve()
    if wals_root not in resolved_wal.parents or resolved_wal.name != 'main.jsonl':
        raise LedgerError('unclassifiable_evidence', 'permission must come from a session main WAL under ' + str(wals_root))
    try:
        lines = wal.read_text(encoding='utf-8', errors='replace').splitlines()  # input-ok: session WAL, bounded by the hooks
    except OSError:
        raise LedgerError('unclassifiable_evidence', 'WAL unreadable') from None
    ask = resolved = None
    for line in lines:
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        if entry.get('id') == ask_id and entry.get('event') == 'ask':
            ask = entry
        if entry.get('event') == 'ask_resolved' and entry.get('ref') == ask_id:
            resolved = entry
    fix = ' Fix: ' + approve_fix(task, wal)
    if ask is None:
        raise LedgerError('unclassifiable_evidence', 'no ask entry %s in %s.%s' % (ask_id, resolved_wal.name, fix))
    if resolved is None:
        raise LedgerError('unclassifiable_evidence', 'ask %s has no ask_resolved entry yet.%s' % (ask_id, fix))
    source = str(ask.get('source') or '')
    note = str(ask.get('note') or '')
    if not user_sourced(source):
        raise LedgerError('unclassifiable_evidence', 'ask %s is not user-sourced (its source must be user:, answer: or queue:, '
                          'a real human turn).%s' % (ask_id, fix))
    if not re.search(r'\[task:' + re.escape(task) + r'\]', note):
        raise LedgerError('unclassifiable_evidence', 'ask %s does not carry [task:%s] in its note.%s' % (ask_id, task, fix))
    # No magic words (scenario B24): the resolution carries an explicit decision field, written by ah approve-top
    # or wal_note --decision. Free-text notes are never parsed for "approved".
    if resolved.get('decision') != 'approved':
        raise LedgerError('unclassifiable_evidence', 'ask_resolved for %s has no decision=approved field (free text is not '
                          'read).%s' % (ask_id, fix))
    return {'source': source, 'ask': ask_id}


# ---------------------------------------------------------------- top-rung assent (review F1/F2)

TOP_ASSENT_MAX_AGE = 12 * 3600
TOP_TERMS = re.compile(r"\b(?:fable|astra|top[ -](?:writing[ -])?(?:rung|model|tier))\b", re.I)
TOP_REQUEST = re.compile(r"\b(?:use|using|run|pass|give|switch|let|allow|approve[ds]?|try|go (?:ahead )?with|"
                         r"escalate|enable|bring in|put|ok to|okay to|you may|go ahead)\b", re.I)
TOP_NEGATION = re.compile(r"\b(?:not|no|never|don'?t|do not|doesn'?t|won'?t|stop|disabled?|disabling|off|without|"
                          r"instead|avoid|cancel|revoke[ds]?|nope|refuse[ds]?|wait|later|unless|if)\b|n't\b", re.I)
_SENTENCES = re.compile(r"(?<=[.!?;])\s+|\n+")
TOP_RETRACT = re.compile(r"\b(?:never ?mind|scratch that|forget (?:it|that)|hold (?:on|off)|belay)\b", re.I)


def top_assent(text):
    """The sentence of the user's own words that asks for the top rung, else None.

    Review F1: a mention is assent only when the same sentence holds request language (use, pass, switch, let,
    approve ...), no negation or condition anywhere in it (not, never, off, disabled, stop, without, instead,
    unless, if, later), and is not a question. "keep fable disabled", "fable? absolutely not", "why did fable cost
    so much" and "use opus, fable is off" are all refusals or unrelated.

    Delta review D1: the latest word decides. Only the LAST sentence that names the top rung can be assent, it
    must pass those rules itself, and any later sentence that negates or retracts ("no, stop", "never mind",
    "scratch that") voids it. An earlier request never survives a later refusal."""
    sentences = [part.strip() for part in _SENTENCES.split(text or '') if part.strip()]
    mentions = [index for index, sentence in enumerate(sentences) if TOP_TERMS.search(sentence)]
    if not mentions:
        return None
    candidate = sentences[mentions[-1]]
    if '?' in candidate or not TOP_REQUEST.search(candidate) or TOP_NEGATION.search(candidate):
        return None
    for later in sentences[mentions[-1] + 1:]:
        if TOP_NEGATION.search(later) or TOP_RETRACT.search(later):
            return None
    return candidate


def _turn_for(parsed, home):
    import provenance as prov  # noqa: PLC0415
    variant = parsed.get('variant')
    if variant == 'answer':
        return prov.answer_turn(parsed['session'], parsed['ident'], home)
    if variant == 'queue':
        return prov.queue_turn(parsed['session'], parsed['ident'], home)
    return prov.user_turn(parsed['session'], parsed['uuid'], home)


def verify_top_source(source, allow_env_root=False, max_age_seconds=TOP_ASSENT_MAX_AGE, now_ts=None):
    """Re-read the user turn a top-rung ask cites and prove it asks for the top rung (review F2).

    The transcript is read from the installed Claude home, never from an environment override, unless the ledger
    itself is a non-default test ledger. The cited excerpt must lie inside the assenting sentence (so the WAL
    source shows the words that granted it), and the turn must be younger than max_age_seconds."""
    import provenance as prov  # noqa: PLC0415
    fix = ' Nothing was recorded; cite the user message that asks for it (ah user-msg --text-match fable).'
    try:
        parsed = prov.parse_source(source)
    except prov.Problem as error:
        raise LedgerError('no_assent', 'the ask source does not parse (%s).%s' % (error, fix)) from None
    if parsed.get('kind') != 'user' or parsed.get('variant') == 'mc':
        raise LedgerError('no_assent', 'top-rung permission needs a user:, answer: or queue: source.' + fix)
    home = None if allow_env_root else installed_home() / '.claude'
    try:
        turn = _turn_for(parsed, home)
    except prov.Problem as error:
        raise LedgerError('no_assent', 'the cited user turn could not be read (%s).%s' % (error, fix)) from None
    sentence = top_assent(turn.get('text') or '')
    if sentence is None:
        raise LedgerError('no_assent', 'the cited user turn does not ask for the top rung in a plain sentence '
                                       '(a mention must sit with request words such as use, pass or switch, with no '
                                       'negation, condition or question in that sentence).' + fix)
    if prov.excerpt_in(sentence, parsed.get('excerpt') or ''):
        raise LedgerError('no_assent', 'the cited excerpt is not part of the sentence that asks for the top rung; '
                                       'cite that sentence: "%s".%s' % (sentence[:160], fix))
    try:
        stamp = datetime.fromisoformat(str(turn.get('timestamp') or '').replace('Z', '+00:00'))
        age = (now_ts if now_ts is not None else datetime.now(timezone.utc).timestamp()) - stamp.timestamp()
    except ValueError:
        raise LedgerError('no_assent', 'the cited user turn has no readable timestamp.' + fix) from None
    if age > max_age_seconds:
        raise LedgerError('no_assent', 'the cited user turn is %d h old; top-rung permission needs words from the '
                                       'last %d h.%s' % (age // 3600, max_age_seconds // 3600, fix))
    return {'sentence': sentence, 'timestamp': turn.get('timestamp'), 'session': parsed['session']}


def approve_fix(task, wal=None):
    """The exact command that records a top-rung permission in one step (scenario B24)."""
    hooks = Path(__file__).resolve().parent
    return ('python3 %s approve-top --task %s --user-msg <id from `python3 %s user-msg --recent 3`> --wal %s'
            % (hooks / 'ah.py', task or '<task>', hooks / 'ah.py', wal or '<main WAL>'))


def session_key(session):
    return re.sub(r'[^A-Za-z0-9_.-]', '_', str(session or ''))[:80]


def session_from_wal(wal):
    """The session id is the WAL's directory name (~/.claude/wals/<session>/main.jsonl)."""
    try:
        return Path(wal).resolve().parent.name
    except OSError:
        return None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path)
    parser.add_argument('--policy', type=Path)
    sub = parser.add_subparsers(dest='action', required=True)
    rec = sub.add_parser('record'); rec.add_argument('--task', required=True)
    rec.add_argument('--run-id', help='usage-guard run id: the FINAL receipt is read and verified inside the store')
    rec.add_argument('--receipt', type=Path, help='a spec_flow review record file (kind spec_review only)')
    rec.add_argument('--kind', required=True, choices=('review', 'test', 'spec_review')); rec.add_argument('--source', required=True)
    rec.add_argument('--head'); rec.add_argument('--notify-wal')
    claim = sub.add_parser('claim-fix'); claim.add_argument('--task', required=True); claim.add_argument('--head', required=True)
    spend = sub.add_parser('spend'); spend.add_argument('--task', required=True); spend.add_argument('--usd', required=True, type=float)
    reset = sub.add_parser('reset'); reset.add_argument('--task', required=True); reset.add_argument('--code', required=True, choices=sorted(RESET_CODES))
    reset.add_argument('--detail', required=True); reset.add_argument('--notify-wal')
    top = sub.add_parser('approve-top', help='record the user permission for the top writing rung; prefer `ah.py approve-top --user-msg`, which writes the ask pair for you')
    top.add_argument('--task', required=True); top.add_argument('--ask', required=True); top.add_argument('--wal', required=True)
    top.add_argument('--session', help='session the grant also covers (default: the WAL directory name)')
    status = sub.add_parser('status'); status.add_argument('--task', required=True)
    sub.add_parser('digest')
    gate = sub.add_parser('gate-digest'); gate.add_argument('--limit', type=int, default=200)
    args = parser.parse_args(argv)
    try:
        ledger = Ledger(args.root, tiers.load_policy(args.policy))
        if args.action == 'record':
            if args.kind in ('review', 'test'):
                if not args.run_id:
                    raise LedgerError('unclassifiable_evidence', 'review and test receipts are read by --run-id from the usage store')
                receipt_bytes = verified_final(args.run_id, allow_env_root=ledger._non_default_root())
            else:
                if not args.receipt:
                    raise LedgerError('unclassifiable_evidence', 'spec_review needs --receipt')
                receipt_bytes = args.receipt.read_bytes()  # input-ok: spec_flow record, bounded by MAX_STATE below
                if len(receipt_bytes) > MAX_STATE:
                    raise LedgerError('unclassifiable_evidence', 'receipt oversized')
            # Review and test events carry the receipt's own HEAD; --head applies to spec_review records only.
            value = ledger.record(args.task, receipt_bytes, kind=args.kind, source=args.source,
                                  head=args.head if args.kind == 'spec_review' else None, notify=args.notify_wal)
        elif args.action == 'claim-fix':
            value = ledger.claim_fix(args.task, args.head)
        elif args.action == 'spend':
            value = ledger.add_spend(args.task, args.usd)
        elif args.action == 'reset':
            value = ledger.reset(args.task, args.code, args.detail, notify=args.notify_wal)
        elif args.action == 'approve-top':
            value = ledger.approve_top(args.task, args.ask, args.wal, session=args.session)
        elif args.action == 'status':
            value = ledger.status(args.task)
        elif args.action == 'gate-digest':
            value = ledger.gate_digest(args.limit)
        else:
            value = ledger.digest()
    except (LedgerError, tiers.TierError, OSError, ValueError) as error:
        print(json.dumps({'error': getattr(error, 'code', type(error).__name__), 'message': str(error)[:300]}))
        return 2
    except Exception as error:  # noqa: BLE001  usage_guard.GuardError and friends: still a JSON refusal
        print(json.dumps({'error': getattr(error, 'reason', type(error).__name__), 'message': str(error)[:300]}))
        return 2
    print(json.dumps(value, sort_keys=True, indent=1))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
