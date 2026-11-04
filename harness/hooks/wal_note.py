#!/usr/bin/env python3
"""Append a human-readable event to this user's Claude Code WAL."""

import argparse
import json
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--wal', type=Path, required=True)
    parser.add_argument('--event', choices=sorted(EVENTS), required=True)
    parser.add_argument('--note', required=True)
    parser.add_argument('--source', help='origin: user:<session>/<uuid> "excerpt" | ticket: | wal: | file: | inferred: (see provenance.py)')
    parser.add_argument('--reason', help='why this is asked of the user (required for ask)')
    parser.add_argument('--ref', help='id of the ask being closed (ask_resolved)')
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
        record['ref'] = args.ref
    if args.event in SOURCED:
        mode, problem, assumption = provenance_check(args.event, args.source)
        if problem:
            if mode == 'enforce':
                print(json.dumps({'status': 'REFUSED', 'event': args.event, 'problem': problem[:300],
                                  'hint': 'cite the origin with --source; see provenance.py find-user'}), file=sys.stderr)
                return 2
            if mode == 'warn':
                warnings.append(problem[:300])
                record['provenance'] = 'missing' if not args.source else 'unverified'
        if args.source:
            record['source'] = args.source.strip()[:2000]
            if assumption:
                record['assumption'] = True
    append(path, record)
    for warning in warnings:
        print('wal_note: provenance warning: ' + warning, file=sys.stderr)
    print(json.dumps({'status': 'WROTE', 'event': args.event, 'id': record['id'], 'wal': str(path),
                      **({'warnings': warnings} if warnings else {})}))


if __name__ == '__main__':
    sys.exit(main())
