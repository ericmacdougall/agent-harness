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


def state_root():
    root = Path(os.environ.get('AGENT_HARNESS_ESCALATION_DIR') or Path.home() / '.agent-harness' / 'escalation')
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


def fingerprint(findings):
    """A deterministic hash of normalized finding ids, files and categories; None when there are none."""
    rows = []
    for item in findings or ():
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
            if review.get('verdict') == 'BLOCK' and review.get('findings'):
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
        if receipt.get('verdict') == 'BLOCK' and receipt.get('findings'):
            return 'FAIL', 'spec review blocked with findings', fingerprint(receipt['findings'])
        if receipt.get('verdict') == 'ACCEPT':
            return 'PASS', 'spec review accepted', None
        return 'NOT_COUNTED', 'spec review without a usable verdict', None
    return 'NOT_COUNTED', 'unknown receipt kind', None


def rung_of(events, policy):
    """Pure: replay FAIL events into (rung, failures_at_rung, fingerprint, climbs)."""
    rung = policy['lowest_rung']
    fails, current, climbs = 0, None, 0
    for event in events:
        if event.get('class') != 'FAIL':
            continue
        if event.get('fingerprint') != current:
            current, fails = event.get('fingerprint'), 0
        fails += 1
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
            raw = path.read_bytes()
            if len(raw) > MAX_STATE:
                raise ValueError('oversized')
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
            lines = path.read_text(encoding='utf-8').splitlines()[:256]
        except OSError:
            return False
        absorbed = False
        for line in lines:
            try:
                record = json.loads(line)
            except ValueError:
                continue
            if record not in state['resets']:
                state['resets'].append(record); absorbed = True
        try:
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
            event = {'seq': len(state['events']) + 1, 'at': now(), 'kind': kind, 'class': klass, 'why': why,
                     'fingerprint': fp, 'receipt_sha256': sha, 'source': source, 'head': head,
                     'rung_at': before['rung']}
            if kind == 'review' and klass != 'NOT_COUNTED':
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
            if after['rung'] != before['rung']:
                status['escalation'] = escalation
                self._notify(task, 'escalation', escalation, notify)
            if reset is not None:
                self._notify(task, 'reset', reset, notify)
            return status
        finally:
            os.close(fd)

    def claim_fix(self, task, head):
        """The owner declares a fix at HEAD; a later red test receipt at that HEAD then counts as a failure."""
        if not re.fullmatch(r'[0-9a-f]{7,64}', head or ''):
            raise LedgerError('unclassifiable_evidence', 'head must be a commit sha')
        fd = self._lock(task)
        try:
            state, _ = self._read(task)
            if not any(c['head'] == head for c in state['claims']):
                state['claims'].append({'head': head, 'at': now()})
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
            self._notify(task, 'reset', record, notify)
            return ladder_status(fresh, self.policy)
        finally:
            os.close(fd)

    def approve_top(self, task, ask_id, wal):
        """Record user permission for the top writing rung after verifying the ask pair in the WAL."""
        proof = verify_ask_pair(Path(wal), ask_id, task)
        fd = self._lock(task)
        try:
            state, _ = self._read(task)
            state['permission'] = {'ask_id': ask_id, 'wal': str(wal), 'at': now(), 'source': proof['source']}
            self._write(task, state)
            return ladder_status(state, self.policy)
        finally:
            os.close(fd)

    def status(self, task):
        return ladder_status(self.load(task), self.policy)

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
        with open(self.root / 'notifications.jsonl', 'a', encoding='utf-8') as handle:
            handle.write(json.dumps(line, sort_keys=True) + '\n')
        os.chmod(self.root / 'notifications.jsonl', 0o600)
        wal = notify or os.environ.get('AGENT_HARNESS_MAIN_WAL')
        if wal:
            note = ('LADDER %s task %s: %s' % (event.upper(), task, json.dumps(record, sort_keys=True)))[:900]
            try:
                subprocess.run([sys.executable, str(Path(__file__).resolve().parent / 'wal_note.py'), '--wal', str(wal),
                                '--event', 'decision', '--note', note, '--source',
                                'wal:%s#ladder-%s' % (wal, hashlib.sha256(note.encode()).hexdigest()[:12])],
                               capture_output=True, text=True, timeout=20)
            except (OSError, subprocess.SubprocessError):
                pass


def verify_ask_pair(wal, ask_id, task):
    """A registered ask with a user: source naming the task, resolved by an ask_resolved that refs it."""
    try:
        lines = wal.read_text(encoding='utf-8', errors='replace').splitlines()
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
    if ask is None or resolved is None:
        raise LedgerError('unclassifiable_evidence', 'no ask/ask_resolved pair for ' + ask_id)
    source = str(ask.get('source') or '')
    note = str(ask.get('note') or '')
    if not source.startswith('user:') or not re.search(r'\[task:' + re.escape(task) + r'\]', note):
        raise LedgerError('unclassifiable_evidence', 'ask is not user-sourced or does not name [task:%s]' % task)
    resolution = str(resolved.get('note') or '')
    if resolved.get('decision') != 'approved' and not re.match(r'\s*approved\b', resolution, re.I):
        raise LedgerError('unclassifiable_evidence', 'ask_resolved does not record an approval for ' + ask_id)
    return {'source': source, 'ask': ask_id}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path)
    parser.add_argument('--policy', type=Path)
    sub = parser.add_subparsers(dest='action', required=True)
    rec = sub.add_parser('record'); rec.add_argument('--task', required=True); rec.add_argument('--receipt', required=True, type=Path)
    rec.add_argument('--kind', required=True, choices=('review', 'test', 'spec_review')); rec.add_argument('--source', required=True)
    rec.add_argument('--head'); rec.add_argument('--notify-wal')
    claim = sub.add_parser('claim-fix'); claim.add_argument('--task', required=True); claim.add_argument('--head', required=True)
    spend = sub.add_parser('spend'); spend.add_argument('--task', required=True); spend.add_argument('--usd', required=True, type=float)
    reset = sub.add_parser('reset'); reset.add_argument('--task', required=True); reset.add_argument('--code', required=True, choices=sorted(RESET_CODES))
    reset.add_argument('--detail', required=True); reset.add_argument('--notify-wal')
    top = sub.add_parser('approve-top'); top.add_argument('--task', required=True); top.add_argument('--ask', required=True); top.add_argument('--wal', required=True)
    status = sub.add_parser('status'); status.add_argument('--task', required=True)
    sub.add_parser('digest')
    args = parser.parse_args(argv)
    try:
        ledger = Ledger(args.root, tiers.load_policy(args.policy))
        if args.action == 'record':
            value = ledger.record(args.task, args.receipt.read_bytes(), kind=args.kind, source=args.source,
                                  head=args.head, notify=args.notify_wal)
        elif args.action == 'claim-fix':
            value = ledger.claim_fix(args.task, args.head)
        elif args.action == 'spend':
            value = ledger.add_spend(args.task, args.usd)
        elif args.action == 'reset':
            value = ledger.reset(args.task, args.code, args.detail, notify=args.notify_wal)
        elif args.action == 'approve-top':
            value = ledger.approve_top(args.task, args.ask, args.wal)
        elif args.action == 'status':
            value = ledger.status(args.task)
        else:
            value = ledger.digest()
    except (LedgerError, tiers.TierError, OSError) as error:
        print(json.dumps({'error': getattr(error, 'code', type(error).__name__), 'message': str(error)[:300]}))
        return 2
    print(json.dumps(value, sort_keys=True, indent=1))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
