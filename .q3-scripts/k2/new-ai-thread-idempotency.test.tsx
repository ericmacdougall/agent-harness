// @vitest-environment jsdom
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
vi.mock('@/lib/api', async (original) => ({ ...await original<typeof import('@/lib/api')>(), api: vi.fn() }));
import { api, ApiError } from '@/lib/api';
import { AiThreadPanel } from './ai-thread-panel';

/**
 * goodqa#14903 K2 (Kimi create-hang): the New thread dialog can always be closed, a close while pending aborts the
 * request without showing a failure, and every create carries a clientRequestId that is reused for the same draft
 * (so a resend after a lost response replays instead of making a second thread) and rotated for a new one.
 */
type Call = { body: { message: string; projectId?: string; clientRequestId?: string }; signal?: AbortSignal };
type Pending = { resolve: (value: unknown) => void; reject: (error: unknown) => void };
let calls: Call[];
let pending: Pending[];
let respond: 'hold' | ((call: Call) => unknown);

beforeEach(() => {
  calls = [];
  pending = [];
  respond = 'hold';
  vi.mocked(api).mockImplementation(async (path: string, options?: { method?: string; body?: unknown; signal?: AbortSignal }) => {
    if (options?.method === 'POST' && /\/ai-threads$/.test(path)) {
      const call = { body: options.body as Call['body'], signal: options.signal };
      calls.push(call);
      if (respond === 'hold') return new Promise((resolve, reject) => { pending.push({ resolve, reject }); });
      return respond(call);
    }
    return { members: [], threads: [], nextCursor: null };
  });
});
afterEach(cleanup);

const conversation = (id: string) => ({ conversation: { id, kind: 'channel', name: id, topic: null, visibility: 'private', projectId: null, issueId: null, headSeq: 0, archivedAt: null, ai: { type: 'general', title: id, titleSource: 'ai', mode: 'tiered', ownerId: 'me', label: null } }, message: null });

function setup(orgId = 'org', onCreated = vi.fn(), projectId?: string) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  qc.setQueryData(['me'], { user: { id: 'me' } });
  qc.setQueryData(['messaging', 'ai-threads', orgId, 'me'], { pages: [{ threads: [], nextCursor: null }], pageParams: [undefined] });
  const invalidate = vi.spyOn(qc, 'invalidateQueries');
  const ui = (org: string, project = projectId) => (
    <QueryClientProvider client={qc}>
      <AiThreadPanel orgId={org} commanderName="Assistant" onOpenMaster={() => {}} masterBusy={false} threads={[]} pending={false}
        error={false} onRetry={() => {}} projects={[{ id: 'p1', name: 'Alpha' }, { id: 'p2', name: 'Beta' }]} projectId={project} onShowAll={() => {}} selectedId={null}
        onSelect={() => {}} onCreated={onCreated} onOpenResult={() => {}} />
    </QueryClientProvider>
  );
  const view = render(ui(orgId));
  return { qc, invalidate, onCreated, rerenderOrg: (org: string) => view.rerender(ui(org)), rerenderProject: (project?: string) => view.rerender(ui(orgId, project)) };
}
const newThreadButton = () => screen.getByRole('button', { name: '+ New thread' });
const open = () => fireEvent.click(newThreadButton());
const textarea = () => screen.getByLabelText('Ask Assistant anything…') as HTMLTextAreaElement;
const type = (text: string) => fireEvent.change(textarea(), { target: { value: text } });
const submit = () => fireEvent.click(screen.getByRole('button', { name: 'Start thread' }));
const dialog = () => screen.queryByRole('dialog');
const STOPPED = 'Stopped waiting. If the thread was already created, sending the same message again opens it.';
const closers = {
  'the Cancel button': () => fireEvent.click(screen.getByRole('button', { name: 'Cancel' })),
  'the Escape key': () => fireEvent.keyDown(document.activeElement ?? document.body, { key: 'Escape' }),
  'an overlay click': () => fireEvent.pointerDown(document.body),
} as const;

it.each(Object.keys(closers) as (keyof typeof closers)[])('AC-5: %s closes a pending create, aborts it, and shows no failure', async (how) => {
  const { invalidate } = setup();
  open();
  type('Plan my week');
  submit();
  await waitFor(() => expect(calls).toHaveLength(1));
  expect(calls[0]!.signal).toBeInstanceOf(AbortSignal);
  expect((screen.getByRole('button', { name: 'Cancel' }) as HTMLButtonElement).disabled).toBe(false);
  act(() => closers[how]());
  await waitFor(() => expect(dialog()).toBeNull());
  expect(calls[0]!.signal!.aborted).toBe(true);
  // The abort surfaces as the api's AbortError; it must never be shown as a failure.
  await act(async () => { pending[0]!.reject(new DOMException('The operation was aborted.', 'AbortError')); });
  expect((screen.getByRole('status')).textContent).toContain(STOPPED);
  expect(screen.queryByRole('alert')).toBeNull();
  expect(invalidate).toHaveBeenCalledWith(expect.objectContaining({ queryKey: ['messaging', 'ai-threads', 'org'] }));
  await waitFor(() => expect(document.activeElement).toBe(newThreadButton()));
  open();
  expect(textarea().value).toBe('Plan my week');
  expect(screen.queryByRole('alert')).toBeNull();
});

it('NEG-8: a late success after cancel opens nothing and shows no error, but the list learns the thread', async () => {
  const { qc, onCreated, invalidate } = setup();
  open();
  type('Plan my week');
  submit();
  await waitFor(() => expect(calls).toHaveLength(1));
  act(() => closers['the Cancel button']());
  await waitFor(() => expect(dialog()).toBeNull());
  await act(async () => { pending[0]!.resolve(conversation('late')); });
  expect(onCreated).not.toHaveBeenCalled();
  expect(dialog()).toBeNull();
  expect(screen.queryByRole('alert')).toBeNull();
  const cached = qc.getQueryData<{ pages: { threads: { id: string }[] }[] }>(['messaging', 'ai-threads', 'org', 'me']);
  expect(cached!.pages[0]!.threads.map((row) => row.id)).toEqual(['late']);
  expect(invalidate).toHaveBeenCalledWith(expect.objectContaining({ queryKey: ['messaging', 'ai-threads', 'org'] }));
});

it('AC-6: the request id follows the draft: same text reuses it, a new text or scope rotates it, success clears both', async () => {
  const { onCreated } = setup();
  open();
  type('First');
  submit();
  await waitFor(() => expect(calls).toHaveLength(1));
  const first = calls[0]!.body.clientRequestId!;
  expect(first).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  act(() => closers['the Cancel button']());
  await waitFor(() => expect(dialog()).toBeNull());
  open();
  type('First   '); // cosmetic: trims to the same message
  submit();
  await waitFor(() => expect(calls).toHaveLength(2));
  expect(calls[1]!.body).toMatchObject({ message: 'First', clientRequestId: first });
  act(() => closers['the Escape key']());
  await waitFor(() => expect(dialog()).toBeNull());
  open();
  type('Second');
  submit();
  await waitFor(() => expect(calls).toHaveLength(3));
  const second = calls[2]!.body.clientRequestId!;
  expect(second).not.toBe(first);
  act(() => closers['the Cancel button']());
  await waitFor(() => expect(dialog()).toBeNull());
  open();
  fireEvent.change(screen.getByLabelText('In'), { target: { value: 'p1' } });
  submit();
  await waitFor(() => expect(calls).toHaveLength(4));
  expect(calls[3]!.body).toMatchObject({ message: 'Second', projectId: 'p1' });
  expect(calls[3]!.body.clientRequestId).not.toBe(second);
  await act(async () => { pending[3]!.resolve(conversation('made')); });
  await waitFor(() => expect(onCreated).toHaveBeenCalledWith('made'));
  expect(dialog()).toBeNull();
  open();
  expect(textarea().value).toBe('');
  type('Second');
  respond = () => conversation('again');
  submit();
  await waitFor(() => expect(calls).toHaveLength(5));
  expect([first, second, calls[3]!.body.clientRequestId]).not.toContain(calls[4]!.body.clientRequestId);
});

it('AC-6: another org starts with an empty draft and a fresh id', async () => {
  const { rerenderOrg } = setup('org');
  open();
  type('Org A plan');
  submit();
  await waitFor(() => expect(calls).toHaveLength(1));
  act(() => closers['the Cancel button']());
  await waitFor(() => expect(dialog()).toBeNull());
  rerenderOrg('org-b');
  open();
  expect(textarea().value).toBe('');
  type('Org A plan');
  submit();
  await waitFor(() => expect(calls).toHaveLength(2));
  expect(calls[1]!.body.clientRequestId).not.toBe(calls[0]!.body.clientRequestId);
});

it('NEG-11: two rapid submits send one request; Cancel and resubmit sends the same id again', async () => {
  setup();
  open();
  type('Once');
  const form = textarea().closest('form')!;
  act(() => { fireEvent.submit(form); fireEvent.submit(form); });
  await waitFor(() => expect(calls).toHaveLength(1));
  await new Promise((resolve) => setTimeout(resolve, 20));
  expect(calls).toHaveLength(1);
  act(() => closers['the Cancel button']());
  await waitFor(() => expect(dialog()).toBeNull());
  open();
  submit();
  await waitFor(() => expect(calls).toHaveLength(2));
  expect(calls[1]!.body.clientRequestId).toBe(calls[0]!.body.clientRequestId);
});

it('NEG-9: a network error or 5xx keeps the draft and the retry reuses the id', async () => {
  setup();
  respond = () => { throw new ApiError(503, 'service_unavailable', 'Service unavailable'); };
  open();
  type('Retry me');
  submit();
  await screen.findByRole('alert');
  expect(textarea().value).toBe('Retry me');
  respond = () => { throw new TypeError('Failed to fetch'); };
  submit();
  await waitFor(() => expect(calls).toHaveLength(2));
  expect(calls[0]!.body.clientRequestId).toMatch(/^[0-9a-f-]{36}$/);
  expect(calls[1]!.body.clientRequestId).toBe(calls[0]!.body.clientRequestId);
});

it('NEG-17: a client_request_conflict shows fixed copy, keeps the draft, and the next submit uses a new id', async () => {
  setup();
  respond = () => { throw new ApiError(409, 'client_request_conflict', 'server wording that must not show'); };
  open();
  type('Conflicted');
  submit();
  const alert = await screen.findByRole('alert');
  expect((alert).textContent).toContain('That message was already used for a different thread. Your draft is kept; send it again to start a new thread.');
  expect((alert).textContent).not.toContain('server wording');
  expect(textarea().value).toBe('Conflicted');
  respond = () => conversation('fresh');
  submit();
  await waitFor(() => expect(calls).toHaveLength(2));
  expect(calls[1]!.body.clientRequestId).not.toBe(calls[0]!.body.clientRequestId);
});

it('NEG-16: create_in_progress shows the wait copy and keeps the id', async () => {
  setup();
  respond = () => { throw new ApiError(409, 'create_in_progress', 'x'); };
  open();
  type('Busy');
  submit();
  expect((await screen.findByRole('alert')).textContent).toContain('Still starting your last thread. Try again in a moment.');
  submit();
  await waitFor(() => expect(calls).toHaveLength(2));
  expect(calls[0]!.body.clientRequestId).toMatch(/^[0-9a-f-]{36}$/);
  expect(calls[1]!.body.clientRequestId).toBe(calls[0]!.body.clientRequestId);
});

it('AC-6: a replay (200 replayed) opens that thread like a create and clears the draft', async () => {
  const { onCreated } = setup();
  respond = () => ({ ...conversation('replayed'), replayed: true });
  open();
  type('Again');
  submit();
  await waitFor(() => expect(onCreated).toHaveBeenCalledWith('replayed'));
  expect(dialog()).toBeNull();
  open();
  expect(textarea().value).toBe('');
});

it('a new create clears the stopped notice', async () => {
  setup();
  open();
  type('Plan');
  submit();
  await waitFor(() => expect(calls).toHaveLength(1));
  act(() => closers['the Cancel button']());
  await screen.findByText(STOPPED);
  open();
  respond = () => conversation('ok');
  submit();
  await waitFor(() => expect(screen.queryByText(STOPPED)).toBeNull());
});

it('an untouched draft follows the panel project; a sent draft keeps the scope it was sent to', async () => {
  const { rerenderProject } = setup('org', vi.fn(), 'p1');
  rerenderProject('p2');
  open();
  expect((screen.getByLabelText('In') as HTMLSelectElement).value).toBe('p2');
  type('Where');
  submit();
  await waitFor(() => expect(calls).toHaveLength(1));
  expect(calls[0]!.body.projectId).toBe('p2');
  act(() => closers['the Cancel button']());
  await waitFor(() => expect(dialog()).toBeNull());
  rerenderProject('p1');
  open();
  expect((screen.getByLabelText('In') as HTMLSelectElement).value).toBe('p2');
  submit();
  await waitFor(() => expect(calls).toHaveLength(2));
  expect(calls[1]!.body).toMatchObject({ projectId: 'p2', clientRequestId: calls[0]!.body.clientRequestId });
});

it('changing org while a create is pending abandons it: no callback runs for the old org', async () => {
  const { rerenderOrg, onCreated } = setup('org');
  open();
  type('Old org');
  submit();
  await waitFor(() => expect(calls).toHaveLength(1));
  rerenderOrg('org-b');
  expect(calls[0]!.signal!.aborted).toBe(true);
  await act(async () => { pending[0]!.resolve(conversation('old-org-thread')); });
  await waitFor(() => expect(textarea().disabled).toBe(false));
  expect(textarea().value).toBe('');
  expect(onCreated).not.toHaveBeenCalled();
});

it('K2-RT-4: a close in the same batch as the submit still aborts and tells the user', async () => {
  setup();
  open();
  type('Same tick');
  act(() => {
    submit();
    closers['the Cancel button']();
  });
  await waitFor(() => expect(calls).toHaveLength(1));
  expect(calls[0]!.signal!.aborted).toBe(true);
  expect(screen.getByTestId('ai-thread-stopped-notice').textContent).toContain(STOPPED);
});

it('K2-RT-3: the status region exists before the notice, and Dismiss returns focus to New thread', async () => {
  setup();
  const region = screen.getByTestId('ai-thread-stopped-notice');
  expect(region.getAttribute('role')).toBe('status');
  expect(region.textContent).toBe('');
  open();
  type('Plan');
  submit();
  await waitFor(() => expect(calls).toHaveLength(1));
  act(() => closers['the Cancel button']());
  await waitFor(() => expect(screen.getByTestId('ai-thread-stopped-notice')).toBe(region));
  expect(region.textContent).toContain(STOPPED);
  const dismiss = screen.getByRole('button', { name: 'Dismiss' });
  dismiss.focus();
  fireEvent.click(dismiss);
  expect(region.textContent).toBe('');
  expect(document.activeElement).toBe(newThreadButton());
});
