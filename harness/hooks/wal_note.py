#!/usr/bin/env python3
"""Append a human-readable event to this user's Claude Code WAL."""

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path


EVENTS = {'intent', 'scope', 'decision', 'risk', 'check', 'commit', 'blocker', 'status', 'handoff', 'result'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--wal', type=Path, required=True)
    parser.add_argument('--event', choices=sorted(EVENTS), required=True)
    parser.add_argument('--note', required=True)
    args = parser.parse_args()
    root = (Path.home() / '.claude' / 'wals').resolve()
    path = args.wal.resolve()
    if path.parent.parent != root or path.suffix != '.jsonl' or not re.fullmatch(r'[A-Za-z0-9._-]{1,120}', path.parent.name):
        parser.error('WAL path must be a per-session JSONL under ~/.claude/wals')
    note = args.note.strip()
    if not note or len(note) > 4000:
        parser.error('note must be 1 to 4000 characters')
    if re.search(r'(?i)\b(gh[pousr]_|github_pat_|sk-[A-Za-z0-9]{12}|AKIA[A-Z0-9]{12})', note):
        parser.error('note appears to contain a credential; redact it first')
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    record = {'at': datetime.now(timezone.utc).isoformat(), 'event': args.event, 'cwd': os.getcwd(), 'note': note}
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.write(fd, (json.dumps(record, ensure_ascii=False, separators=(',', ':')) + '\n').encode())
        os.fsync(fd)
    finally:
        os.close(fd)
    print(json.dumps({'status': 'WROTE', 'event': args.event, 'wal': str(path)}))


if __name__ == '__main__':
    sys.exit(main())
