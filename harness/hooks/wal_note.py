#!/usr/bin/env python3
"""Append a human-readable event to this user's Claude Code WAL."""

import argparse
import json
import os
import re
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

from wal import append


EVENTS = {'intent', 'scope', 'decision', 'risk', 'check', 'commit', 'blocker', 'status', 'handoff', 'result',
          'requirement', 'ask', 'ask_resolved'}
# Events whose origin must be traceable (provenance.py). The mode per event is in provenance_policy.json.
SOURCED = ('requirement', 'ask', 'blocker', 'scope', 'decision')
TOOL_WRITERS = frozenset({'escalation', 'ahd', 'dropped_gate', 'ah-run', 'ask-sweep'})  # rows these tools write on an agent's behalf (goodqa#14791)
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


def provenance_check(event, source):
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
        result = provenance.resolve(source)
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


def outcome_evidence_problem(source, ref):
    """Why `source` cannot back an --outcome close, else None (GoodQA #15565 red-team F3): the ask's own entry is not
    evidence about it, and a source that traces back to a human turn is an answer, which closes an ask the normal way."""
    source = (source or '').strip()
    if re.search(r'#' + re.escape(ref) + r'\s*$', source):
        return 'the evidence is the ask itself'
    line = re.match(r'^wal:(.+)#L(\d{1,9})\s*$', source)
    if line:  # the line-number form can name the ask's own entry too
        try:
            with open(line.group(1), 'rb') as handle:
                for number, raw in enumerate(handle, 1):
                    if number == int(line.group(2)):
                        if json.loads(raw).get('id') == ref:
                            return 'the evidence is the ask itself (by line number)'
                        break
        except (OSError, ValueError, AttributeError):
            pass
    try:
        import provenance
        result = provenance.resolve(source)
        if result.get('ok') and result.get('origin') == 'user':
            return 'the evidence traces to a human turn: close the ask with that answer (answer:/user:), not as obsolete'
    except Exception:  # noqa: BLE001 - provenance_check reports an unresolvable source
        return None
    return None


def open_ask_exists(path, ref: str) -> bool:
    """True when `ref` is an `ask` entry of this WAL with no later `ask_resolved` naming it (bounded tail read)."""
    try:
        import safe_input  # noqa: PLC0415
        tail = safe_input.read_tail(path, 4 << 20)
    except Exception:  # noqa: BLE001 - a WAL that cannot be read cannot hold an open ask
        return False
    seen, resolved = False, False
    for raw in tail.splitlines():
        try:
            rec = json.loads(raw)
        except ValueError:
            continue
        if not isinstance(rec, dict):
            continue
        if rec.get('event') == 'ask' and rec.get('id') == ref:
            seen, resolved = True, False
        elif rec.get('event') == 'ask_resolved' and rec.get('ref') == ref:
            resolved = True
    return seen and not resolved


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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--wal', type=Path, required=True)
    parser.add_argument('--event', choices=sorted(EVENTS), required=True)
    parser.add_argument('--note', required=True)
    parser.add_argument('--source', help='origin: user:<session>/<uuid> "excerpt" | ticket: | wal: | file: | inferred: (see provenance.py)')
    parser.add_argument('--reason', help='why this is asked of the user (required for ask)')
    parser.add_argument('--ref', help='id of the ask being closed (ask_resolved)')
    parser.add_argument('--decision', choices=('approved', 'declined'),
                        help='ask_resolved only: the explicit outcome (escalation.py reads this field, never the note text)')
    parser.add_argument('--outcome', choices=('obsolete', 'not_user'),
                        help='ask_resolved only: close an ask nobody can answer any more (obsolete) or that was never the user\'s to answer '
                             '(not_user) on wal:/file:/ticket: evidence; never an approval (no decision field), so it cannot authorize anything')
    parser.add_argument('--by', help='tool that writes this row on an agent\'s behalf (never quarantined; cites its state in the note)')
    parser.add_argument('--recites', help='id of an unsourced entry of this WAL that this sourced row re-cites (clears its quarantine)')
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
    record = {'at': datetime.now(timezone.utc).isoformat(), 'event': args.event, 'note': note,
              'id': 'w' + uuid.uuid4().hex[:11]}
    warnings = []
    if args.event == 'ask':
        if not args.reason or len(args.reason.strip()) < 10:
            parser.error('an ask needs --reason (10+ characters): why the user is being asked')
        record['reason'] = args.reason.strip()[:1000]
    if args.event == 'ask_resolved':
        if not args.ref or not re.fullmatch(r'[A-Za-z0-9_-]{4,40}', args.ref):
            parser.error('ask_resolved needs --ref <ask id>')
        # G5 (goodqa#14791): a resolution names an open ask of this WAL and carries the source of the answer
        ask_wal = None
        if not open_ask_exists(path, args.ref):
            ask_wal = sibling_ask_wal(path, args.ref)
        if not open_ask_exists(path, args.ref) and ask_wal is None:
            print(json.dumps({'status': 'REFUSED', 'event': 'ask_resolved', 'problem': f'no open ask {args.ref} in this WAL',
                              'hint': 'ask_resolved --ref must name an ask entry of this WAL that is not already resolved'}),
                  file=sys.stderr)
            return 2
        if not args.source or not args.source.strip():
            print(json.dumps({'status': 'REFUSED', 'event': 'ask_resolved', 'problem': 'ask_resolved needs --source',
                              'hint': 'cite the answer: user:<session>/<uuid> "words", answer:<id> or queue:<id> (ah user-msg)'}),
                  file=sys.stderr)
            return 2
        if args.outcome:
            if args.decision:
                parser.error('--outcome closes an ask without an approval: do not combine it with --decision')
            if not re.match(r'^(wal:|file:|ticket:)', args.source.strip()):
                print(json.dumps({'status': 'REFUSED', 'event': 'ask_resolved', 'problem': '--outcome needs wal:, file: or ticket: evidence',
                                  'hint': 'cite the entry or commit that shows the ask is obsolete or not the user\'s; inferred: is not evidence'}),
                      file=sys.stderr)
                return 2
        elif not re.match(r'^(user:|uuid:|answer:|queue:|ticket:)', args.source.strip()):
            print(json.dumps({'status': 'REFUSED', 'event': 'ask_resolved', 'problem': 'ask_resolved source must be the answer: user:, answer:, queue: or ticket:',
                              'hint': 'an ask cannot be closed on an inferred: or file: source; use --outcome obsolete|not_user with wal:/file: evidence'}), file=sys.stderr)
            return 2
        if args.outcome:
            evidence = outcome_evidence_problem(args.source, args.ref)
            if evidence:
                print(json.dumps({'status': 'REFUSED', 'event': 'ask_resolved', 'problem': evidence,
                                  'hint': 'cite a different entry that shows the ask is obsolete; a user answer closes it the normal way'}),
                      file=sys.stderr)
                return 2
        mode, problem, assumption = provenance_check('ask', args.source)  # the answer is sourced like an ask (M1)
        if problem:
            print(json.dumps({'status': 'REFUSED', 'event': 'ask_resolved', 'problem': problem[:300],
                              'hint': 'the resolution source must resolve: user:, answer:, queue: or ticket:'}), file=sys.stderr)
            return 2
        record['ref'] = args.ref
        if ask_wal:
            record['ask_wal'] = ask_wal
        record['source'] = args.source.strip()[:2000]
        if args.decision:
            record['decision'] = args.decision
        if args.outcome:
            record['outcome'] = args.outcome
            record['closed_by'] = 'agent'  # an audit mark: no user words back this close
        if assumption:
            record['assumption'] = True
    elif args.decision or args.outcome:
        parser.error('--decision and --outcome apply to ask_resolved only')
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
        if args.event == 'ask_resolved' and args.decision:
            parser.error('a tool close (--by) is bookkeeping and cannot carry --decision: only a person approves')
        if args.event == 'ask_resolved':
            record.setdefault('closed_by', record['by'])  # a tool close is bookkeeping, not a user approval
    if args.recites:
        if not re.fullmatch(r'w[0-9a-f]{11}', args.recites) or not args.source:
            parser.error('--recites needs an entry id (w + 11 hex) and a --source on this row')
        record['recites'] = args.recites
    append(path, record)
    for warning in warnings:
        print('wal_note: provenance warning: ' + warning, file=sys.stderr)
    print(json.dumps({'status': 'WROTE', 'event': args.event, 'id': record['id'], 'wal': str(path),
                      **({'warnings': warnings} if warnings else {})}))


if __name__ == '__main__':
    sys.exit(main())
