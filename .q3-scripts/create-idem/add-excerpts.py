#!/usr/bin/env python3
"""goodqa#14903 K2 spec: add the cited base-commit line (7b738654) as an excerpt to each NEG file source.

Main asked for excerpts on the NEG sources. The excerpts were read with `git show 7b7386543f6:<path>` on t2-dev.
Idempotent: a source that already carries an excerpt is left alone.
"""
import re
import sys

EXCERPTS = {
    'apps/api/src/modules/messaging/ai-thread-lifecycle.ts:28': 'if (input.projectId) {',
    'apps/api/src/modules/messaging/ai-thread-lifecycle.ts:39': 'select pg_advisory_xact_lock(hashtextextended(ai-thread:orgId:userId, 0))',
    'apps/api/src/modules/messaging/ai-thread-lifecycle.ts:51': 'if ((count?.count ?? 0) >= 60)',
    'apps/api/src/modules/messaging/messages.ts:1016': 'tx.select().from(chatMessages).where(historyAnd(messageHistoryPredicate(), ... clientMsgId',
    'apps/api/src/modules/messaging/messages.ts:1023': 'if (prior.clientRequestHash !== requestHash) {',
    'apps/api/src/modules/messaging/messages.ts:891': 'const requestHash = input.clientMsgId',
    'apps/api/src/modules/messaging/routes.ts:5355': "r.post('/orgs/:orgId/ai-threads', { schema: { ... z.object({ ... }).strict()",
    'apps/web/src/components/messaging/new-ai-thread-dialog.tsx:32': 'if (!create.isPending) onOpenChange(next);',
    'apps/web/src/components/messaging/new-ai-thread-dialog.tsx:43': 'if (!message.trim() || create.isPending) return;',
    'packages/db/src/schema/chat.ts:343': "uniqueIndex('chat_messages_client_msg_uq')",
}


def main(path: str) -> int:
    lines = open(path).read().split('\n')
    added = 0
    for i, line in enumerate(lines):
        if not line.startswith('- NEG-'):
            continue

        def rep(m: re.Match) -> str:
            nonlocal added
            key = m.group(1)
            if key not in EXCERPTS:
                return m.group(0)
            added += 1
            return f'file:{key}@7b738654 -- "{EXCERPTS[key]}";'

        lines[i] = re.sub(r'file:([^ @]+)@7b738654 --(?! ")', rep, line)
    open(path, 'w').write('\n'.join(lines))
    print('excerpts added', added)
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1]))
