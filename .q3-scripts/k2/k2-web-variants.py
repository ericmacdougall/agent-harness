#!/usr/bin/env python3
"""goodqa#14903 K2 web: failing-first and controlled broken variants. Runs on t2-dev in ~/wt/q3-kimi-create.

Variant 'old-ui' restores the three changed UI files from HEAD (the K2 test file stays). The others break one rule
in the patched panel. Every file is restored byte for byte (sha256 checked) whatever happens.
"""
import hashlib
import os
import re
import subprocess
import sys

WT = os.path.expanduser('~/wt/q3-kimi-create')
M = 'apps/web/src/components/messaging/'
PANEL, DIALOG, HOOK = M + 'ai-thread-panel.tsx', M + 'new-ai-thread-dialog.tsx', M + 'use-ai-threads.ts'
DRAFT = M + 'use-new-thread-draft.ts'
TEST = M + 'new-ai-thread-idempotency.test.tsx'
LOG = os.path.expanduser('~/wt/aab3-k2-webvar')


def head(path: str) -> str:
    return subprocess.run(['git', 'show', f'HEAD:{path}'], cwd=WT, check=True, capture_output=True, text=True).stdout


def edit(old: str, new: str, path: str = PANEL):
    def apply(files: dict) -> dict:
        s = files[path]
        assert s.count(old) == 1, old[:60]
        return {path: s.replace(old, new)}
    return apply


VARIANTS = [
    ('old-ui', lambda files: {PANEL: head(PANEL), DIALOG: head(DIALOG), HOOK: head(HOOK)}, None),
    ('no-abort-on-close', edit('      abortRef.current?.abort();\n      setStopped(true);', '      setStopped(true);'), 'AC-5'),
    ('fresh-id-every-send', edit('const clientRequestId = draft.requestIdFor(message, scope);',
                                 'const clientRequestId = (draft.rotate(), draft.requestIdFor(message, scope));'), 'AC-6: the request id'),
    ('conflict-keeps-id', edit("if (failure instanceof ApiError && failure.code === 'client_request_conflict') draft.rotate();",
                               'void ApiError;'), 'NEG-17'),
    ('scope-not-pinned', edit('    setDraft((d) => (d.scope === scope ? d : { ...d, orgId, scope }));\n', '', DRAFT), 'an untouched draft'),
    ('org-change-keeps-call', edit('''  useEffect(() => () => {
    abortRef.current?.abort();
    abortRef.current = null;
    callRef.current += 1;
  }, [orgId]);''', '  useEffect(() => () => abortRef.current?.abort(), []);'), 'changing org'),
    ('close-decides-by-isPending', edit('  const closeDialog = () => {\n    if (abortRef.current) {', '  const closeDialog = () => {\n    if (create.isPending) {'), 'K2-RT-4'),
    ('dismiss-drops-focus', edit('                setStopped(false);\n                newThreadRef.current?.focus();\n', '                setStopped(false);\n'), 'K2-RT-3'),
]


def run(name: str, test_filter):
    log = f'{LOG}.{name}.log'
    cmd = ['timeout', '900', 'pnpm', '--filter', '@bugtracker/web', 'exec', 'vitest', 'run', TEST.replace('apps/web/', '')]
    if test_filter:
        cmd += ['-t', test_filter]
    with open(log, 'w') as out:
        rc = subprocess.run(cmd, cwd=WT, stdout=out, stderr=subprocess.STDOUT).returncode
    text = re.sub(r'\x1b\[[0-9;]*m', '', open(log).read())
    summary = next((l.strip() for l in text.splitlines() if l.strip().startswith('Tests ')), 'no summary')
    return rc, summary


def main() -> int:
    paths = [PANEL, DIALOG, HOOK, DRAFT]
    orig = {p: open(os.path.join(WT, p), 'rb').read() for p in paths}
    digests = {p: hashlib.sha256(b).hexdigest() for p, b in orig.items()}
    bad = 0
    try:
        for name, fn, test_filter in VARIANTS:
            changed = fn({p: b.decode() for p, b in orig.items()})
            for p, s in changed.items():
                open(os.path.join(WT, p), 'w').write(s)
            try:
                rc, summary = run(name, test_filter)
            finally:
                for p in paths:
                    open(os.path.join(WT, p), 'wb').write(orig[p])
            caught = rc != 0 and 'failed' in summary
            print(f'VARIANT {name} filter={test_filter!r} rc={rc} {summary} caught={caught}')
            bad += 0 if caught else 1
    finally:
        for p in paths:
            open(os.path.join(WT, p), 'wb').write(orig[p])
            assert hashlib.sha256(open(os.path.join(WT, p), 'rb').read()).hexdigest() == digests[p], f'restore failed {p}'
    print('RESTORED', {p.rsplit('/', 1)[1]: d[:10] for p, d in digests.items()})
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main())
