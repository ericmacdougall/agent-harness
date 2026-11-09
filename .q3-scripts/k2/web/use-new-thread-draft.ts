'use client';
import { useCallback, useRef, useState } from 'react';

/**
 * goodqa#14903 K2: the New thread draft and its idempotency key outlive the dialog, so Cancel and reopen keep both.
 *
 * The key (`clientRequestId`) is tied to the normalized payload (trimmed message + scope): sending the same draft
 * again reuses it, so a resend after a lost or abandoned response replays the thread the server already made
 * instead of making a second one. A different payload gets a new key. Cosmetic edits that normalize to the same
 * payload keep it. A conflict rotates it; a confirmed success clears the draft and the key. Not persisted: a page
 * reload is a new intent. A different org starts empty.
 */
export function newClientRequestId(): string {
  const c = globalThis.crypto;
  if (typeof c?.randomUUID === 'function') return c.randomUUID();
  const b = new Uint8Array(16);
  c.getRandomValues(b);
  b[6] = (b[6]! & 0x0f) | 0x40;
  b[8] = (b[8]! & 0x3f) | 0x80;
  const h = Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

// scope null = not chosen yet: an untouched draft follows the panel's current project, as a fresh dialog did.
type Draft = { orgId: string; message: string; scope: string | null };

export function useNewThreadDraft(orgId: string, defaultScope: string) {
  const [draft, setDraft] = useState<Draft>({ orgId, message: '', scope: null });
  const key = useRef<{ orgId: string; payload: string; id: string } | null>(null);
  // A different org never inherits a draft or a key.
  const current: Draft = draft.orgId === orgId ? draft : { orgId, message: '', scope: null };
  if (draft.orgId !== orgId) setDraft(current);

  const setMessage = useCallback((message: string) => setDraft((d) => ({ ...d, orgId, message })), [orgId]);
  const setScope = useCallback((scope: string) => setDraft((d) => ({ ...d, orgId, scope })), [orgId]);
  /** The key for this payload: reused while the normalized payload is unchanged, otherwise a new one. Sending
   *  pins the scope, so a resend after Cancel goes to the same place even if the panel moved to another project. */
  const requestIdFor = useCallback((message: string, scope: string) => {
    setDraft((d) => (d.scope === scope ? d : { ...d, orgId, scope }));
    const payload = JSON.stringify([message.trim(), scope]);
    const k = key.current;
    if (k && k.orgId === orgId && k.payload === payload) return k.id;
    const id = newClientRequestId();
    key.current = { orgId, payload, id };
    return id;
  }, [orgId]);
  /** After a conflict: the next send of the same draft starts a new thread. */
  const rotate = useCallback(() => { key.current = null; }, []);
  /** After a confirmed success (create or replay). */
  const clear = useCallback(() => {
    key.current = null;
    setDraft({ orgId, message: '', scope: null });
  }, [orgId]);
  return { message: current.message, scope: current.scope ?? defaultScope, setMessage, setScope, requestIdFor, rotate, clear };
}
