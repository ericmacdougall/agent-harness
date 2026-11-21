#!/usr/bin/env python3
"""Append a human-readable event to this user's Claude Code WAL."""

import argparse
import json
import os
import re
import shlex
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

from wal import append
import ask_state


EVENTS = {'intent', 'scope', 'decision', 'risk', 'check', 'commit', 'blocker', 'status', 'handoff', 'result',
          'requirement', 'ask', 'ask_resolved', 'deploy'}
# Structured evidence (goodqa#15754): `ah goals` and `ah status` read these fields instead of guessing from prose.
GOAL_RE = re.compile(r'^[a-z0-9][a-z0-9_-]{0,63}$')
TICKET_RE = re.compile(r'^\s*(?:GoodQA\s+)?[A-Za-z][A-Za-z0-9-]{0,62}\s*#\s*[1-9][0-9]{0,9}\s*$')
REALLY_TESTED_RE = re.compile(r'^\s*REALLY_TESTED\s+[A-Za-z0-9._-]+')
SHA_OR_VERSION_RE = re.compile(r"\b(?=[0-9a-f]*[a-f])[0-9a-f]{7,40}\b|\bv\d+\.\d+(?:\.\d+)?\b|\b\d+\.\d+\.\d+\b")  # as goals_view.SHA_OR_VERSION
# Events whose origin must be traceable (provenance.py). The mode per event is in provenance_policy.json.
SOURCED = ('requirement', 'ask', 'blocker', 'scope', 'decision')
TOOL_WRITERS = frozenset({'escalation', 'ahd', 'dropped_gate', 'ah-run'})  # rows these tools write on an agent's behalf (goodqa#14791)
# provenance.py problem codes that mean the caller wrote a source that can never resolve: refused outright, nothing
# written (goodqa#14927). Transient or environmental codes (scan-timeout, transcript-malformed, wal-missing,
# file-unreadable, internal ...) keep the warn-mode quarantine path so a busy host does not drop a note.
CALLER_ERROR_CODES = frozenset({
    'bad-syntax', 'unknown-kind', 'no-source', 'excerpt-missing', 'excerpt-short', 'excerpt-not-found',
    'inferred-no-inputs', 'inferred-no-rationale', 'inferred-nested', 'inferred-ungrounded', 'file-path', 'file-line',
    'wal-bad-path', 'wal-entry-not-found', 'wal-unsourced', 'user-session-invalid', 'not-user-authored',
    'message-not-found', 'ticket-missing', 'transcript-missing', 'item-not-found', 'cycle', 'too-deep',
    'too-many-sources', 'ambiguous'})


def caller_error(problem) -> bool:
    """True when a provenance_check problem is a rejection whose code is the caller's own error (see CALLER_ERROR_CODES)."""
    match = re.match(r'source rejected \(([a-z-]+)\)', problem or '')
    return bool(match) and match.group(1) in CALLER_ERROR_CODES
SECRET_PATTERN = re.compile(
    r'(?i)(?:\bgh[pousr]_[A-Za-z0-9_]+|\bgithub_pat_[A-Za-z0-9_]+|'
    r'\bsk-[A-Za-z0-9-]{12,}|\bAKIA[A-Z0-9]{12}|'
    r'\bBearer\s+\S+|\bxox[baprs]-[A-Za-z0-9-]{6,}|'
    # Match credential names at the end of snake/kebab keys, including quoted
    # JSON keys. Do not mistake metrics such as token_count for credentials.
    r'\b(?:[a-z0-9]+[_-])*(?:password|passwd|secret|token|api[_-]?key|'
    r'access[_-]?key|private[_-]?key|credentials?)(?:[_-]value)?[\x22\x27]?\s*[:=]\s*[\x22\x27]?\S+|'
    r'\b[a-z][a-z0-9]*(?:Secret|Token|Password|ApiKey|AccessKey|PrivateKey|Credentials?)'
    r'[\x22\x27]?\s*[:=]\s*[\x22\x27]?\S+|'
    # Any userinfo in a URL authority may contain a credential or private user.
    # The authority ends at /, ?, or #, so ordinary path/query @ signs are safe.
    r'\b[a-z][a-z0-9+.-]*://[^\s/?#@]+@[^\s/?#]+|'
    r'-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----)'
)


def provenance_check(event, source, allow_mc=False):
    """(mode, problem-or-None, is_assumption). Never raises: a resolver failure is a problem, not a crash."""
    try:
        import provenance
    except ImportError:
        return 'enforce' if event in ('requirement', 'ask') else 'warn', 'provenance.py is not installed', False
    try:
        mode = provenance.load_policy()['wal'].get(event, 'warn')
        if mode == 'off':
            return mode, None, False
        if not source:
            return mode, f'{event} has no --source', False
        result = provenance.resolve(source, {'allow_mc': True} if allow_mc else None)
        if not result['ok']:
            first = result['problems'][0] if result['problems'] else {'code': 'rejected', 'message': 'rejected'}
            return mode, f"source rejected ({first['code']}): {first['message']}", result['assumption']
        if event in ('requirement', 'ask') and provenance.weak_problem(result):
            return mode, provenance.weak_problem(result), result['assumption']
        if provenance.unreachable_warning(result):  # tracker outage: warn, never refuse
            return 'warn', provenance.unreachable_warning(result), result['assumption']
        return mode, None, result['assumption']
    except Exception as error:
        return 'enforce' if event in ('requirement', 'ask') else 'warn', f'provenance check failed ({type(error).__name__})', False


def _tail_records(path):
    """Parsed records of the last 4 MiB of this WAL, or None when it cannot be read."""
    try:
        import safe_input  # noqa: PLC0415
        return list(ask_state.parse_lines(safe_input.read_tail(path, 4 << 20).splitlines()))
    except Exception:  # noqa: BLE001
        return None


def ask_entry(path, ref: str):
    """The `ask` entry with id `ref` in this WAL (bounded tail read), or None."""
    return (ask_state.fold(_tail_records(path) or []).get(ref) or {}).get('ask')


def open_ask_exists(path, ref: str) -> bool:
    """True when `ref` is an `ask` entry of this WAL that nothing closed (bounded tail read; the rule is ask_state.fold)."""
    row = ask_state.fold(_tail_records(path) or []).get(ref)  # a WAL that cannot be read cannot hold an open ask
    return bool(row) and row['resolved'] is None


def sibling_ask_wal(path, ref: str):
    """goodqa#15319: the stem of the one other WAL of this session (an owner's agent-*.jsonl) that holds `ref` as an ask
    nobody has resolved, in any WAL of the session; else None. Main may then resolve an owner's ask by citing the answer."""
    folder = path.parent
    if path.name != 'main.jsonl':  # red-team F1: only main resolves an owner's ask, never an owner another WAL's ask
        return None
    real_folder = os.path.realpath(folder)
    wals = [w for w in sorted(folder.glob('*.jsonl'))
            if w.name == 'main.jsonl' or w.name.startswith('agent-')]
    # red-team F4: a symlinked WAL could point into another session
    wals = [w for w in wals if not w.is_symlink() and os.path.dirname(os.path.realpath(w)) == real_folder]
    holders = [w for w in wals if w != path and w.name.startswith('agent-') and open_ask_exists(w, ref)]
    if len(holders) != 1:
        return None
    needle = ref.encode()
    for other in wals:  # a resolution anywhere in the session closes it (provenance ledger rule)
        try:
            import provenance  # noqa: PLC0415
            # red-team F2 and M2: the whole file (not a 4 MiB tail), through the bounded reader that opens regular files
            # only (a FIFO cannot hang it), caps the size and the scan time, and reports an oversized line as None
            for raw in provenance._lines_containing(other, needle):
                if raw is None:
                    return None  # a line too long to read could hold the resolution: do not guess that it is open
                if b'"ask_resolved"' in raw:
                    rec = json.loads(raw)
                    if isinstance(rec, dict) and rec.get('event') == 'ask_resolved' and rec.get('ref') == ref:
                        return None
        except Exception:  # noqa: BLE001 - unreadable, too large or not a regular file: do not guess that it is open
            return None
    return holders[0].stem


UNBOUND_MIN = 20


def last_resolution(path, ref: str):
    """The last `ask_resolved` row naming `ref` in this WAL (bounded tail read), whether or not the ask row is here."""
    found = None
    for rec in _tail_records(path) or []:
        if ask_state.record_ok(rec) and rec.get('event') == 'ask_resolved' and rec.get('ref') == ref:
            found = rec
    return found


def ask_resolved_fields(path, ref, source, decision=None, unbound_reason=None):
    """(fields, None) for an ask_resolved row closing ask `ref`, or (None, refusal) with nothing to write. This is the one
    path that closes an ask: wal_note and the ask-close hook (provenance_hooks.py) both call it, so a hook-written
    resolution passes exactly the checks a typed one does (goodqa#16599). Fields: ref, source, and when they apply
    ask_wal, decision, assumption, answer_unbound."""
    ask_wal = None
    supersedes = None
    if not open_ask_exists(path, ref):
        ask_wal = sibling_ask_wal(path, ref)
    if not open_ask_exists(path, ref) and ask_wal is None:
        # The ask-close hook closed it from an answered card and cannot tell approve from decline. One typed
        # resolution WITH a decision may follow it (escalation.py and ah kill read the decision, never the hook's row).
        last = last_resolution(path, ref)
        if last is not None and ask_state.auto_closed(last) and decision:
            supersedes = last.get('id')
            ask_wal = last.get('ask_wal')
        elif last is not None and ask_state.auto_closed(last):
            return None, {'problem': f'ask {ref} was closed from its answered card by the ask-close hook, which records no decision',
                          'hint': 'to record the outcome repeat with --decision approved|declined and the answer: or user: source; '
                                  'escalation and ah kill read that field'}
        else:
            return None, {'problem': f'no open ask {ref} in this WAL',
                          'hint': 'ask_resolved --ref must name an ask entry of this WAL that is not already resolved'}
    if not source or not source.strip():
        return None, {'problem': 'ask_resolved needs --source',
                      'hint': 'cite the answer: user:<session>/<uuid> "words", answer:<id> or queue:<id> (ah user-msg)'}
    source = source.strip()
    if not re.match(r'^(user:|uuid:|answer:|queue:|mc:|ticket:)', source):
        return None, {'problem': 'ask_resolved source must be the answer: user:, answer:, queue:, mc: or ticket:',
                      'hint': 'an ask cannot be closed on an inferred: or file: source'}
    mode, problem, assumption = provenance_check('ask', source, allow_mc=True)  # the answer is sourced like an ask (M1)
    if problem:
        return None, {'problem': problem[:300], 'hint': 'the resolution source must resolve: user:, answer:, queue: or ticket:'}
    unbound = None
    if source.lower().startswith('mc:'):
        import provenance as _prov  # noqa: PLC0415
        # The decision must be for THIS session's ask as it reads in THIS main WAL now (spec rev 2: ids repeat
        # across sessions and WALs, and an ask an owner registered is never closed by a dashboard click).
        bound = _prov.mc_bind(source, ref, decision, ask=ask_entry(path, ref),
                              session=path.parent.name, wal=path.stem if ask_wal is None else ask_wal)
        if bound:
            return None, {'problem': bound[:300], 'hint': 'an mc: source closes only the ask it names, with its own decision'}
    elif source.lower().startswith('answer:'):
        import provenance as _prov  # noqa: PLC0415
        # AC-4: an answer card closes the ask its question names; anything else needs a stated reason (audited on the row)
        not_named = _prov.answer_names_ask(source, ref, session=path.parent.name)
        if not_named:
            reason = (unbound_reason or '').strip()
            if len(reason) < UNBOUND_MIN:
                return None, {'problem': not_named[:300],
                              'hint': f'an answer: source must come from the card that asks [ask:{ref}]. If the user answered it '
                                      f'in free text on another card, repeat the command with --unbound-reason "<why, '
                                      f'{UNBOUND_MIN}+ characters>" (recorded on the row); a typed reply can be cited as user:'}
            unbound = reason[:300]
    fields = {'ref': ref}
    if ask_wal:
        fields['ask_wal'] = ask_wal
    fields['source'] = source[:2000]
    if decision:
        fields['decision'] = decision
    if assumption:
        fields['assumption'] = True
    if unbound:
        fields['answer_unbound'] = unbound
    if supersedes:
        fields['supersedes'] = supersedes
    return fields, None


def close_ask(path, ref, source, note, by=None, decision=None):
    """Close ask `ref` through ask_resolved_fields and append the row; (record, None) or (None, refusal). Used by the
    ask-close hook, which passes no decision (only a typed or approval-card resolution may say approved or declined)."""
    fields, refusal = ask_resolved_fields(path, ref, source, decision)
    if refusal:
        return None, refusal
    record = {'at': datetime.now(timezone.utc).isoformat(), 'event': 'ask_resolved', 'note': note.strip()[:4000],
              'id': 'w' + uuid.uuid4().hex[:11], **fields}
    if by:
        record['by'] = by
    append(path, record)
    return record, None


ANSWER_SOURCE_RE = re.compile(r'^(?:answer|user|uuid|queue):', re.I)
SOURCE_SESSION_RE = re.compile(r'^(?:answer|user|uuid|queue):\s*([0-9a-fA-F]{8}-[0-9a-fA-F-]{27})/')


def ask_holder_wal(path, ident, source):
    """The main WAL command target for closing `ident`: this WAL when it (or one of this session's owner WALs) holds the
    open ask; else the main WAL of the session the answer's source names (a successor cites its predecessor's answer, and the
    ask lives in the predecessor's WAL). None when no open ask is found. Reads only; closes nothing."""
    if open_ask_exists(path, ident) or sibling_ask_wal(path, ident):
        return path
    found = SOURCE_SESSION_RE.match((source or '').strip())
    if found and found.group(1).lower() != path.parent.name:
        other = path.parent.parent / found.group(1).lower() / 'main.jsonl'
        if other.is_file() and not other.is_symlink() and (open_ask_exists(other, ident) or sibling_ask_wal(other, ident)):
            return other
    return None
BARE_ASK_ID_RE = re.compile(r'\bw[0-9a-f]{11}\b')


def unclosed_ask_hint(path, event, source, *texts):
    """GoodQA goodqa#16599: a row backed by the user's words (answer:, user:, queue:) that names an ask still open in this
    WAL (or an owner WAL of this session) is usually that ask's answer; say how to close it. Never closes anything: a
    mention in note text is not an answer to the question. None when nothing applies."""
    if event in ('ask', 'ask_resolved') or not source or not ANSWER_SOURCE_RE.match(source.strip()):
        return None
    named = []
    for text in texts:
        for ident in ask_state.tagged_ids(text) + BARE_ASK_ID_RE.findall(text or ''):
            if ident not in named:
                named.append(ident)
    commands = []
    for ident in named[:5]:
        holder = ask_holder_wal(path, ident, source)
        if holder:
            commands.append(f"python3 ~/.claude/hooks/wal_note.py --wal {shlex.quote(str(holder))} --event ask_resolved "
                            f"--ref {ident} --source {shlex.quote(source.strip())} --note 'answered'")
    if not commands:
        return None
    return ('this row names an ask that is still open; the row does not close it (a mention is not an answer), so the '
            'reminders continue. If the user answered it, close it with: ' + ' ; '.join(commands) +
            ' (an answer: source must come from the card that names the ask, or add --unbound-reason "<why>")')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--wal', type=Path, required=True)
    parser.add_argument('--event', choices=sorted(EVENTS), required=True)
    parser.add_argument('--note', required=True)
    parser.add_argument('--source', help='origin: user:<session>/<uuid> "excerpt" | ticket: | wal: | file: | inferred: (see provenance.py)')
    parser.add_argument('--reason', help='why this is asked of the user (required for ask)')
    parser.add_argument('--owner', help='ask only: the agent id whose stream this ask belongs to (a wait on it excuses only that owner)')
    parser.add_argument('--ref', help='id of the ask being closed (ask_resolved)')
    parser.add_argument('--decision', choices=('approved', 'declined'),
                        help='ask_resolved only: the explicit outcome (escalation.py reads this field, never the note text)')
    parser.add_argument('--unbound-reason', help='ask_resolved with an answer: source only: why the answered card does not name the ask '
                                                 '(a free-text answer to another question); recorded on the row as answer_unbound')
    parser.add_argument('--by', help='tool that writes this row on an agent\'s behalf (never quarantined; cites its state in the note)')
    parser.add_argument('--recites', help='id of an unsourced entry of this WAL that this sourced row re-cites (clears its quarantine)')
    parser.add_argument('--goal', help='mission goal id this row is evidence for (ah goals lists it as a tag candidate)')
    parser.add_argument('--ticket', help='ticket this row is about, e.g. goodqa#123')
    parser.add_argument('--result', choices=('PASS', 'FAIL'), help='REALLY_TESTED rows: the stated result')
    parser.add_argument('--live', action='store_true', help='REALLY_TESTED rows: the test ran against the live system')
    args = parser.parse_args()
    root = Path.home() / '.claude' / 'wals'
    path = args.wal.absolute()
    if path.parent.parent != root or path.suffix != '.jsonl' or not re.fullmatch(r'[A-Za-z0-9._-]{1,120}', path.parent.name):
        parser.error('WAL path must be a per-session JSONL under ~/.claude/wals')
    note = args.note.strip()
    if not note or len(note) > 4000:
        parser.error('note must be 1 to 4000 characters')
    if SECRET_PATTERN.search(note):
        parser.error('note appears to contain a credential; redact it first')
    if args.source and len(args.source.strip()) > 2000:
        parser.error('source is longer than 2000 characters; shorten the excerpts')
    for label, value in (('source', args.source), ('reason', args.reason)):
        if value and SECRET_PATTERN.search(value):
            parser.error(label + ' appears to contain a credential; redact it first')
    if args.goal is not None and not GOAL_RE.match(args.goal):
        parser.error('--goal: a goal id (lower-case letters, digits, - and _)')
    if args.ticket is not None and not TICKET_RE.match(args.ticket):
        parser.error('--ticket: like goodqa#123')
    if (args.result or args.live) and not REALLY_TESTED_RE.match(note):
        parser.error('--result and --live apply to a note starting REALLY_TESTED <check id>')
    if args.event == 'deploy' and not SHA_OR_VERSION_RE.search(note):
        parser.error('a deploy row names the deployed sha or version (merged is not live)')
    record = {'at': datetime.now(timezone.utc).isoformat(), 'event': args.event, 'note': note,
              'id': 'w' + uuid.uuid4().hex[:11]}
    if args.owner:
        if args.event != 'ask' or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,63}', args.owner):
            parser.error('--owner applies to an ask and names an agent id')
        record['owner'] = args.owner
    if args.goal:
        record['goal'] = args.goal
    if args.ticket:
        record['ticket'] = re.sub(r'\s+', '', args.ticket)
    if args.result:
        record['result'] = args.result
    if args.live:
        record['live'] = True
    warnings = []
    if args.event == 'ask':
        if not args.reason or len(args.reason.strip()) < 10:
            parser.error('an ask needs --reason (10+ characters): why the user is being asked')
        record['reason'] = args.reason.strip()[:1000]
    if args.event == 'ask_resolved':
        if not args.ref or not re.fullmatch(r'[A-Za-z0-9_-]{4,40}', args.ref):
            parser.error('ask_resolved needs --ref <ask id>')
        if args.unbound_reason is not None and SECRET_PATTERN.search(args.unbound_reason):
            parser.error('--unbound-reason appears to contain a credential; redact it first')
        fields, refusal = ask_resolved_fields(path, args.ref, args.source, args.decision, args.unbound_reason)
        if refusal:
            print(json.dumps(dict(refusal, status='REFUSED', event='ask_resolved')), file=sys.stderr)
            return 2
        record.update(fields)
    elif args.decision:
        parser.error('--decision applies to ask_resolved only')
    elif args.unbound_reason is not None:
        parser.error('--unbound-reason applies to ask_resolved only')
    if args.event in SOURCED:
        mode, problem, assumption = provenance_check(args.event, args.source)
        if problem and args.source and caller_error(problem):
            # A source that was given but can never resolve is a caller error, whatever the mode: writing it
            # anyway (quarantined) only moved the failure to the stop hook (main WAL w842c8dfc127, 2026-11-06).
            print(json.dumps({'status': 'REFUSED', 'event': args.event, 'problem': problem[:300],
                              'hint': 'nothing was written; fix the --source (see provenance.py) and retry'}), file=sys.stderr)
            return 2
        if problem:
            if mode == 'enforce':
                print(json.dumps({'status': 'REFUSED', 'event': args.event, 'problem': problem[:300],
                                  'hint': 'cite the origin with --source; see provenance.py find-user'}), file=sys.stderr)
                return 2
            if mode == 'warn':
                warnings.append(problem[:300])
                record['provenance'] = 'missing' if not args.source else 'unverified'
                if not args.source or 'rejected' in problem or 'failed' in problem:  # missing, rejected or unresolvable: quarantined (P11)
                    record['unsourced'] = True  # an unverifiable ticket (tracker unreachable) is not a quarantine case
        if args.source:
            record['source'] = args.source.strip()[:2000]
            if assumption:
                record['assumption'] = True
    if args.by:
        if args.by.strip() not in TOOL_WRITERS:
            parser.error(f'--by must be one of {sorted(TOOL_WRITERS)}: tool-written rows are an allowlist, not a claim')
        record['by'] = args.by.strip()
    if args.recites:
        if not re.fullmatch(r'w[0-9a-f]{11}', args.recites) or not args.source:
            parser.error('--recites needs an entry id (w + 11 hex) and a --source on this row')
        record['recites'] = args.recites
    append(path, record)
    for warning in warnings:
        print('wal_note: provenance warning: ' + warning, file=sys.stderr)
    hint = unclosed_ask_hint(path, args.event, args.source, note, args.reason)
    print(json.dumps({'status': 'WROTE', 'event': args.event, 'id': record['id'], 'wal': str(path),
                      **({'warnings': warnings} if warnings else {}), **({'hint': hint} if hint else {})}))


if __name__ == '__main__':
    sys.exit(main())
