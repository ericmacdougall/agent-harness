// @vitest-environment jsdom
vi.mock('@/lib/credential-guard', () => ({ useCredentialGuard: () => false }));
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';

/**
 * Kimi finding qac-attach-001 (goodqa#14903): a file the client itself refuses before any request
 * (too large, empty, unsupported type) must show that reason, not the generic "Could not upload that file".
 * The real `uploadConversationFile` runs here, so the reason comes from the real precheck; a network-free
 * failure that is not a client refusal (a raw TypeError) still gets the generic text.
 */
vi.mock('@/lib/hooks', () => ({
  useIssues: () => ({ data: { issues: [] } }),
  useOrgIssues: () => ({ data: { issues: [] } }),
  useIssueByNumber: () => ({ data: undefined, isPending: false }),
}));
vi.mock('@/lib/uploads', async () => {
  const actual = await vi.importActual<typeof import('@/lib/uploads')>('@/lib/uploads');
  return { ...actual, uploadConversationFile: vi.fn(actual.uploadConversationFile) };
});
vi.mock('sonner', () => ({ toast: { error: vi.fn() } }));

const { MessageComposer } = await import('./message-composer');
const uploads = await import('@/lib/uploads');
const { toast } = await import('sonner');

afterEach(() => {
  cleanup();
  vi.mocked(toast.error).mockReset();
});

function pasteFile(file: File) {
  return { clipboardData: { items: [{ kind: 'file', type: file.type, getAsFile: () => file }] } };
}
function composer() {
  render(<MessageComposer conversationId="c1" mentionables={[]} onSubmit={vi.fn().mockResolvedValue(undefined)} />);
  return screen.getByRole('textbox', { name: 'Message' });
}

it('an oversize file shows the size limit, not the generic upload error, and sends no request', async () => {
  const fetchSpy = vi.fn();
  vi.stubGlobal('fetch', fetchSpy);
  const file = new File([new Uint8Array([1, 2, 3])], 'huge.png', { type: 'image/png' });
  Object.defineProperty(file, 'size', { value: 524_288_001 });
  fireEvent.paste(composer(), pasteFile(file));
  await waitFor(() => expect(toast.error).toHaveBeenCalledTimes(1));
  const shown = String(vi.mocked(toast.error).mock.calls[0]![0]);
  expect(shown).toMatch(/larger than the .+ limit/);
  expect(shown).not.toBe('Could not upload that file');
  expect(fetchSpy).not.toHaveBeenCalled();
  vi.unstubAllGlobals();
});

it('a failure that is not a client refusal keeps the generic text (no raw browser error is shown)', async () => {
  vi.mocked(uploads.uploadConversationFile).mockRejectedValueOnce(new TypeError('Failed to fetch'));
  const file = new File([new Uint8Array([1, 2, 3])], 'ok.png', { type: 'image/png' });
  fireEvent.paste(composer(), pasteFile(file));
  await waitFor(() => expect(toast.error).toHaveBeenCalledTimes(1));
  expect(vi.mocked(toast.error).mock.calls[0]![0]).toBe('Could not upload that file');
});
