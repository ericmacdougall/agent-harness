#!/usr/bin/env python3
"""Append a human-readable event to this user's Claude Code WAL."""

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

from wal import append


EVENTS = {'intent', 'scope', 'decision', 'risk', 'check', 'commit', 'blocker', 'status', 'handoff', 'result'}
SECRET_PATTERN = re.compile(
    r'(?i)(?:\bgh[pousr]_[A-Za-z0-9_]+|\bgithub_pat_[A-Za-z0-9_]+|'
    r'\bsk-[A-Za-z0-9-]{12,}|\bAKIA[A-Z0-9]{12}|'
    r'\bBearer\s+\S+|\bxox[baprs]-[A-Za-z0-9-]{6,}|'
    # Include environment-style and quoted assignment keys, not only bare names.
    r'\b(?:[a-z0-9]+[_-])*(?:password|passwd|secret|token|api[_-]?key|'
    r'access[_-]?key|private[_-]?key|credentials?)(?:[_-][a-z0-9]+)*[\x22\x27]?\s*[:=]\s*[\x22\x27]?\S+|'
    r'\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^\s/@:]+:[^\s/@]+@|'
    r'-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----)'
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--wal', type=Path, required=True)
    parser.add_argument('--event', choices=sorted(EVENTS), required=True)
    parser.add_argument('--note', required=True)
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
    record = {'at': datetime.now(timezone.utc).isoformat(), 'event': args.event, 'cwd': os.getcwd(), 'note': note}
    append(path, record)
    print(json.dumps({'status': 'WROTE', 'event': args.event, 'wal': str(path)}))


if __name__ == '__main__':
    sys.exit(main())
