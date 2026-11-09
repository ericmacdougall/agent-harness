#!/usr/bin/env python3
"""goodqa#14903 K2 web: patch use-ai-threads.ts and ai-thread-panel.tsx in place (run from the repo root).

New files (use-new-thread-draft.ts, new-ai-thread-dialog.tsx) are copied separately. Each edit asserts its anchor
occurs exactly once, so a drifted tree fails loudly instead of half-patching.
"""
import sys

M = 'apps/web/src/components/messaging/'


def sub(path: str, old: str, new: str) -> None:
    s = open(path).read()
    n = s.count(old)
    if n != 1:
        sys.exit(f'anchor x{n} in {path}: {old[:70]!r}')
    open(path, 'w').write(s.replace(old, new))


H = M + 'use-ai-threads.ts'
sub(H, """    mutationFn: (input: { message: string; projectId?: string }) =>
      api<{ conversation: Conversation }>(`/v1/orgs/${orgId}/ai-threads`, {
        method: 'POST',
        body: { ...input, type: 'general' },
      }),""", """    // goodqa#14903 K2: `clientRequestId` makes a resend of the same draft replay instead of duplicating; `signal`
    // lets the dialog stop waiting (a cancellation rejects with AbortError and is never shown as a failure).
    mutationFn: ({ signal, ...input }: { message: string; projectId?: string; clientRequestId?: string; signal?: AbortSignal }) =>
      api<{ conversation: Conversation; replayed?: boolean }>(`/v1/orgs/${orgId}/ai-threads`, {
        method: 'POST',
        body: { ...input, type: 'general' },
        ...(signal ? { signal } : {}),
      }),""")

P = M + 'ai-thread-panel.tsx'
sub(P, """import { useState } from 'react';
import { CalendarClock, MessageCircle, Mic, Pin, Ticket } from 'lucide-react';""", """import { useEffect, useRef, useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { CalendarClock, MessageCircle, Mic, Pin, Ticket, X } from 'lucide-react';
import { ApiError } from '@/lib/api';""")
sub(P, "import { NewAiThreadDialog } from './new-ai-thread-dialog';\n",
    "import { NewAiThreadDialog } from './new-ai-thread-dialog';\nimport { useCreateAiThread } from './use-ai-threads';\nimport { useNewThreadDraft } from './use-new-thread-draft';\n")
sub(P, """  const [creating, setCreating] = useState(false);
  const rows = threads""", """  const [creating, setCreating] = useState(false);
  // goodqa#14903 K2 (Kimi create-hang): the draft, its request id, the create and its abort live here, so the
  // dialog can always close. A close while pending stops waiting (abort, no failure shown) and keeps the draft;
  // sending the same draft again reuses the id, so the server replays a thread it already made.
  const qc = useQueryClient();
  const draft = useNewThreadDraft(orgId, projectId ?? '');
  const create = useCreateAiThread(orgId);
  const abortRef = useRef<AbortController | null>(null);
  const callRef = useRef(0);
  const newThreadRef = useRef<HTMLButtonElement>(null);
  const [stopped, setStopped] = useState(false);
  // Leaving the org (or unmounting) abandons a pending create: abort it and never run its callbacks.
  useEffect(() => () => {
    abortRef.current?.abort();
    abortRef.current = null;
    callRef.current += 1;
  }, [orgId]);
  const resetCreate = create.reset;
  useEffect(() => { resetCreate(); setStopped(false); }, [orgId, resetCreate]);
  const closeDialog = () => {
    if (create.isPending) {
      abortRef.current?.abort();
      setStopped(true);
      void qc.invalidateQueries({ queryKey: ['messaging', 'ai-threads', orgId] });
    }
    abortRef.current = null;
    callRef.current += 1; // a late answer to an abandoned call never opens or closes anything
    create.reset();
    setCreating(false);
  };
  const submitCreate = () => {
    // Set synchronously below and cleared only when this call settles or is abandoned: a second submit in the
    // same tick, before isPending re-renders, sends nothing.
    if (abortRef.current) return;
    setStopped(false);
    const message = draft.message.trim();
    const scope = draft.scope;
    const clientRequestId = draft.requestIdFor(message, scope);
    const controller = new AbortController();
    abortRef.current = controller;
    const call = ++callRef.current;
    create.mutate(
      { message, ...(scope ? { projectId: scope } : {}), clientRequestId, signal: controller.signal },
      {
        onSuccess: (result) => {
          if (call !== callRef.current) return;
          abortRef.current = null;
          draft.clear();
          setCreating(false);
          onCreated(result.conversation.id);
        },
        onError: (failure) => {
          if (call !== callRef.current) return;
          abortRef.current = null;
          if (failure instanceof ApiError && failure.code === 'client_request_conflict') draft.rotate();
        },
      },
    );
  };
  const rows = threads""")
sub(P, """        <Button type="button" variant="secondary" onClick={() => setCreating(true)}>
          + New thread
        </Button>""", """        <Button ref={newThreadRef} type="button" variant="secondary" onClick={() => setCreating(true)}>
          + New thread
        </Button>""")
sub(P, """      {projectId && (
        <div className="px-3 pb-2 text-xs text-muted">""", """      {stopped && (
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
      )}
      {projectId && (
        <div className="px-3 pb-2 text-xs text-muted">""")
sub(P, """        <NewAiThreadDialog
          open
          onOpenChange={setCreating}
          orgId={orgId}
          projects={projects}
          projectId={projectId}
          commanderName={commanderName}
          onCreated={onCreated}
        />""", """        <NewAiThreadDialog
          projects={projects}
          commanderName={commanderName}
          draft={draft}
          create={create}
          restoreFocusRef={newThreadRef}
          onSubmit={submitCreate}
          onClose={closeDialog}
        />""")
print('K2_WEB_PATCHED')
