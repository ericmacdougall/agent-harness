#!/usr/bin/env python3
"""goodqa#14903 K2: controlled broken variants. Runs on t2-dev in ~/wt/q3-kimi-create.

Each variant patches ai-thread-lifecycle.ts, runs the K2 file filtered to the test that must catch it, and restores
the original byte for byte (checked by sha256). Usage: k2-variants.py  -> prints VARIANT <name> caught=<bool>.
"""
import hashlib
import os
import re
import subprocess
import sys

WT = os.path.expanduser('~/wt/q3-kimi-create')
F = os.path.join(WT, 'apps/api/src/modules/messaging/ai-thread-lifecycle.ts')
LOG = os.path.expanduser('~/wt/aab3-k2-variant')

LOOKUP = (
    "      const [prior] = await tx.select().from(chatMessages)\n"
    "        .where(and(eq(chatMessages.authorId, userId), eq(chatMessages.clientMsgId, key))).limit(1);\n"
    "      if (prior) return replayOrConflict(tx, userId, orgId, input, prior);\n"
)
LOCK_SET = "    if (key !== undefined) await tx.execute(sql.raw(`set local lock_timeout = '${lockTimeoutMs}ms'`));\n"


def v1(s: str) -> str:
    # Lookup before the advisory lock: two racing retries both miss and both create.
    assert s.count(LOOKUP) == 1 and s.count(LOCK_SET) == 1
    s = s.replace(LOOKUP, '')
    early = "    if (key !== undefined) {\n" + LOOKUP + "    }\n"
    return s.replace(LOCK_SET, early + LOCK_SET)


def v2(s: str) -> str:
    # Hash over the raw body instead of the credential-redacted body the stored hash uses.
    old = "  const prepared = await prepareConversationCredentialBody(db, conversationId, message);\n"
    assert s.count(old) == 1
    return s.replace(old, "  const prepared = { body: message }; void prepareConversationCredentialBody; void conversationId; void db;\n")


VARIANTS = [('lookup-before-lock', v1, 'AC-3'), ('hash-raw-body', v2, 'NEG-13')]


def main() -> int:
    orig = open(F, 'rb').read()
    digest = hashlib.sha256(orig).hexdigest()
    rc_all = 0
    for name, fn, test in VARIANTS:
        open(F, 'w').write(fn(orig.decode()))
        try:
            log = f'{LOG}.{name}.log'
            with open(log, 'w') as out:
                rc = subprocess.run(
                    ['timeout', '1200', 'python3', os.path.expanduser('~/repos/harness/lanes/pgpool.py'), 'run', '--mode', 'server',
                     '--job', f'aab3-k2-var-{name}', '--lane', 'qacq3', '--ttl', '1300', '--', 'pnpm', '--filter', '@bugtracker/api',
                     'exec', 'vitest', 'run', 'test/ai-thread-create-idempotency.test.ts', '-t', test],
                    cwd=WT, stdout=out, stderr=subprocess.STDOUT).returncode
            text = re.sub(r'\x1b\[[0-9;]*m', '', open(log).read())
            summary = next((l.strip() for l in text.splitlines() if l.strip().startswith('Tests ')), 'no summary')
            caught = rc != 0 and 'failed' in summary
            print(f'VARIANT {name} test={test} rc={rc} {summary} caught={caught}')
            if not caught:
                rc_all = 1
        finally:
            open(F, 'wb').write(orig)
            assert hashlib.sha256(open(F, 'rb').read()).hexdigest() == digest, 'restore failed'
    print('RESTORED sha256', digest[:12])
    return rc_all


if __name__ == '__main__':
    sys.exit(main())
