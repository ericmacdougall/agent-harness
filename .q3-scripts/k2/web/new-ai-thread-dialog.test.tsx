// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, expect, it, vi } from 'vitest';
import { AiThreadPanel } from './ai-thread-panel';

// goodqa#14903 K2: the dialog's draft and create now live in AiThreadPanel, so these render through the panel.
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});
const projects = [
  { id: 'alpha', name: 'Alpha' },
  { id: 'beta', name: 'Beta' },
];
function dialog(projectId?: string, onCreated = vi.fn()) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  render(
    <QueryClientProvider client={client}>
      <AiThreadPanel orgId="org" commanderName="Jarvis" onOpenMaster={() => {}} masterBusy={false} threads={[]}
        pending={false} error={false} onRetry={() => {}} projects={projects} projectId={projectId}
        onShowAll={() => {}} selectedId={null} onSelect={() => {}} onCreated={onCreated} onOpenResult={() => {}} />
    </QueryClientProvider>,
  );
  fireEvent.click(screen.getByRole('button', { name: '+ New thread' }));
  return onCreated;
}
/** Only the create POSTs; the panel's other reads get an empty answer. */
function stubFetch(answer: (attempt: number) => Response) {
  const requests: { path: string; body: object }[] = [];
  let attempts = 0;
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string, options: RequestInit = {}) => {
      const path = new URL(url, 'http://localhost:4000').pathname;
      if (options.method !== 'POST' || !path.endsWith('/ai-threads')) {
        return new Response(JSON.stringify({ members: [], threads: [], nextCursor: null }));
      }
      requests.push({ path, body: JSON.parse(options.body as string) });
      return answer(++attempts);
    }),
  );
  return requests;
}
it.each([undefined, 'alpha', 'beta'])(
  'starts a composer-first General thread in scope %s with a private server-owned audience',
  async (projectId) => {
    const requests = stubFetch(() => new Response(JSON.stringify({ conversation: { id: 'created' } })));
    const onCreated = dialog(projectId);
    expect(screen.getByLabelText('In').getAttribute('id')).toBe('new-ai-project');
    expect((screen.getByLabelText('In') as HTMLSelectElement).value).toBe(projectId ?? '');
    expect(
      (screen.getByRole('button', { name: 'Start thread' }) as HTMLButtonElement).disabled,
    ).toBe(true);
    fireEvent.change(screen.getByLabelText('Ask Jarvis anything…'), {
      target: { value: '  Help with the release  ' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Start thread' }));
    await waitFor(() => expect(onCreated).toHaveBeenCalledWith('created'));
    expect(requests).toEqual([
      {
        path: '/v1/orgs/org/ai-threads',
        body: {
          type: 'general',
          message: 'Help with the release',
          clientRequestId: expect.stringMatching(/^[0-9a-f-]{36}$/),
          ...(projectId ? { projectId } : {}),
        },
      },
    ]);
  },
);
it('surfaces a failed create, preserves the draft and allows retry with a changed scope', async () => {
  const requests = stubFetch((attempt) =>
    attempt === 1
      ? new Response(JSON.stringify({ error: { code: 'not_found', message: 'Project not found' } }), { status: 404 })
      : new Response(JSON.stringify({ conversation: { id: 'retried' } })),
  );
  const created = dialog('alpha');
  fireEvent.change(screen.getByLabelText('Ask Jarvis anything…'), {
    target: { value: 'Keep this draft' },
  });
  fireEvent.click(screen.getByRole('button', { name: 'Start thread' }));
  await screen.findByRole('alert');
  expect((screen.getByLabelText('Ask Jarvis anything…') as HTMLTextAreaElement).value).toBe(
    'Keep this draft',
  );
  fireEvent.change(screen.getByLabelText('In'), { target: { value: 'beta' } });
  fireEvent.click(screen.getByRole('button', { name: 'Start thread' }));
  await waitFor(() => expect(created).toHaveBeenCalledWith('retried'));
  // A changed scope is a different request: a new id.
  expect((requests[1]!.body as { clientRequestId: string }).clientRequestId).not.toBe(
    (requests[0]!.body as { clientRequestId: string }).clientRequestId,
  );
});
