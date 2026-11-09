'use client';
import type { RefObject } from 'react';
import { Button } from '@/components/ui/button';
import { Dialog, DialogContent } from '@/components/ui/dialog';
import { Label, Textarea } from '@/components/ui/input';
import { ApiError } from '@/lib/api';
import type { useCreateAiThread } from './use-ai-threads';
import type { useNewThreadDraft } from './use-new-thread-draft';

const CONFLICT_COPY = 'That message was already used for a different thread. Your draft is kept; send it again to start a new thread.';
const IN_PROGRESS_COPY = 'Still starting your last thread. Try again in a moment.';

/** goodqa#14903 K2: fixed copy for the idempotency outcomes; any other failure keeps the api's own message. */
export function createErrorCopy(error: unknown): string {
  if (error instanceof ApiError && error.code === 'client_request_conflict') return CONFLICT_COPY;
  if (error instanceof ApiError && error.code === 'create_in_progress') return IN_PROGRESS_COPY;
  return error instanceof Error ? error.message : 'Could not start the thread.';
}

/**
 * The draft, its request id, the mutation and the abort live in AiThreadPanel (goodqa#14903 K2), so this dialog
 * can always close: every close path, pending or not, goes through `onClose`, which aborts a pending create.
 */
export function NewAiThreadDialog({
  projects,
  commanderName,
  draft,
  create,
  restoreFocusRef,
  onSubmit,
  onClose,
}: {
  projects: { id: string; name: string }[];
  commanderName: string;
  draft: ReturnType<typeof useNewThreadDraft>;
  create: ReturnType<typeof useCreateAiThread>;
  /** Focus goes back here on every close (the panel's New thread button). */
  restoreFocusRef?: RefObject<HTMLElement | null>;
  onSubmit: () => void;
  onClose: () => void;
}) {
  return (
    <Dialog
      open
      onOpenChange={(next) => {
        if (!next) onClose();
      }}
    >
      <DialogContent
        title="New thread"
        description={`Ask ${commanderName} anything. Only you can see this thread.`}
        restoreFocusRef={restoreFocusRef}
      >
        <form
          className="flex flex-col gap-3"
          onSubmit={(event) => {
            event.preventDefault();
            if (!draft.message.trim() || create.isPending) return;
            onSubmit();
          }}
        >
          <Label htmlFor="new-ai-message">{`Ask ${commanderName} anything…`}</Label>
          <Textarea
            id="new-ai-message"
            autoFocus
            rows={5}
            value={draft.message}
            maxLength={20_000}
            disabled={create.isPending}
            onChange={(event) => draft.setMessage(event.target.value)}
          />
          <Label htmlFor="new-ai-project">In</Label>
          <select
            id="new-ai-project"
            value={draft.scope}
            disabled={create.isPending}
            onChange={(event) => draft.setScope(event.target.value)}
            className="min-h-11 w-full rounded border border-border bg-surface px-3 text-sm text-foreground focus-visible:ring-2 focus-visible:ring-ring"
          >
            <option value="">General</option>
            {projects.map((project) => (
              <option key={project.id} value={project.id}>
                {project.name}
              </option>
            ))}
          </select>
          {create.error && (
            <p role="alert" className="text-sm text-danger">
              {createErrorCopy(create.error)}
            </p>
          )}
          <div className="flex justify-end gap-2">
            <Button type="button" variant="secondary" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" disabled={!draft.message.trim() || create.isPending}>
              {create.isPending ? 'Starting…' : 'Start thread'}
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}
