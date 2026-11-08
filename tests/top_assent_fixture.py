"""Test helper: a real user turn in a temp transcript, so the top-rung permission (review F2) re-reads the user's
own words instead of trusting a hand-written ask pair. Point CLAUDE_CONFIG_DIR at the returned claude home."""

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

SESSION = '11111111-2222-4333-8444-555555555555'
UID = '00000000-0000-4000-8000-0000000000f1'


def stamp(age_seconds=60):
    when = datetime.now(timezone.utc) - timedelta(seconds=age_seconds)
    return when.strftime('%Y-%m-%dT%H:%M:%S.000Z')


def user_turn(claude_home, words, *, session=SESSION, uid=UID, age_seconds=60, excerpt=None):
    """Append a human turn and return its user: source citing `excerpt` (default: the whole words)."""
    path = Path(claude_home) / 'projects' / '-proj' / (session + '.jsonl')
    path.parent.mkdir(parents=True, exist_ok=True)
    record = {'type': 'user', 'uuid': uid, 'timestamp': stamp(age_seconds), 'origin': {'kind': 'human'},
              'message': {'role': 'user', 'content': words}}
    with open(path, 'a') as handle:
        handle.write(json.dumps(record) + '\n')
    return 'user:%s/%s "%s"' % (session, uid, excerpt if excerpt is not None else words)


def use_claude_home(test, claude_home):
    """Set CLAUDE_CONFIG_DIR for the test (provenance reads transcripts from it for a test ledger)."""
    old = os.environ.get('CLAUDE_CONFIG_DIR')
    os.environ['CLAUDE_CONFIG_DIR'] = str(claude_home)

    def restore():
        if old is None:
            os.environ.pop('CLAUDE_CONFIG_DIR', None)
        else:
            os.environ['CLAUDE_CONFIG_DIR'] = old
    test.addCleanup(restore)
