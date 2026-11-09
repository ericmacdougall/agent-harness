#!/usr/bin/env python3
"""goodqa#14903 K2 red-team fixes, web side (RT-3, RT-4). Run from the repo root on claude/qac-kimi-create-web."""
import sys

P = 'apps/web/src/components/messaging/ai-thread-panel.tsx'


def sub(s: str, old: str, new: str) -> str:
    if s.count(old) != 1:
        sys.exit(f'anchor x{s.count(old)}: {old[:70]!r}')
    return s.replace(old, new)


s = open(P).read()
# RT-4: abortRef is set synchronously on submit; isPending lags one render.
s = sub(s, """  const closeDialog = () => {
    if (create.isPending) {""", """  const closeDialog = () => {
    if (abortRef.current) {""")
# RT-3: the live region is always mounted, so adding the text is announced; Dismiss hands focus back.
s = sub(s, """      {stopped && (
        <div role="status" className="mx-2 mb-2 flex items-start gap-2 rounded bg-surface-2 px-3 py-2 text-sm text-muted">
          <span className="min-w-0 flex-1">
            Stopped waiting. If the thread was already created, sending the same message again opens it.
          </span>
          <button
            type="button"
            aria-label="Dismiss"
            onClick={() => setStopped(false)}
            className="inline-flex min-h-11 min-w-11 items-center justify-center rounded focus-visible:ring-2 focus-visible:ring-ring"
          >
            <X className="size-4" aria-hidden="true" />
          </button>
        </div>
      )}""", """      {/* Always mounted: a live region added together with its text is often not announced. */}
      <div
        role="status"
        data-testid="ai-thread-stopped-notice"
        className={stopped ? 'mx-2 mb-2 flex items-start gap-2 rounded bg-surface-2 px-3 py-2 text-sm text-muted' : 'sr-only'}
      >
        {stopped && (
          <>
            <span className="min-w-0 flex-1">
              Stopped waiting. If the thread was already created, sending the same message again opens it.
            </span>
            <button
              type="button"
              aria-label="Dismiss"
              onClick={() => {
                setStopped(false);
                newThreadRef.current?.focus();
              }}
              className="inline-flex min-h-11 min-w-11 items-center justify-center rounded focus-visible:ring-2 focus-visible:ring-ring"
            >
              <X className="size-4" aria-hidden="true" />
            </button>
          </>
        )}
      </div>""")
open(P, 'w').write(s)
print('K2_RT_WEB_FIXED')
