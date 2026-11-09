"""Kimi QAC findings, batch 1 (goodqa#14903): attachment reason and empty-submit hint. Runs at the worktree root.
Mode 'test' adds tests only (for the red run); mode 'src' applies the source change."""
import pathlib, sys

def sub(text, old, new, label):
    assert text.count(old) == 1, f'{label}: anchor count {text.count(old)}'
    return text.replace(old, new)

mode = sys.argv[1]
web = pathlib.Path('apps/web/src')

if mode == 'test':
    t = web / 'components/messaging/new-ai-thread-dialog.test.tsx'
    s = t.read_text()
    s += """
it('an empty message explains why Start thread is not available, and the hint goes once there is text', () => {
  dialog();
  const start = screen.getByRole('button', { name: 'Start thread' }) as HTMLButtonElement;
  expect(start.disabled).toBe(true);
  const hint = screen.getByText('Write a message to start the thread.');
  expect(start.getAttribute('aria-describedby')).toBe(hint.getAttribute('id'));
  fireEvent.change(screen.getByLabelText('Ask Jarvis anything…'), { target: { value: '   ' } });
  expect(screen.queryByText('Write a message to start the thread.')).not.toBeNull();
  fireEvent.change(screen.getByLabelText('Ask Jarvis anything…'), { target: { value: 'Hi' } });
  expect(screen.queryByText('Write a message to start the thread.')).toBeNull();
  expect(start.getAttribute('aria-describedby')).toBeNull();
  expect(start.disabled).toBe(false);
});
"""
    t.write_text(s)
    print('tests ok')
    sys.exit(0)

u = web / 'lib/uploads.ts'
s = u.read_text()
s = sub(s, """function rejectIfOversize(file: File | Blob): void {
  if (file.size > MAX_UPLOAD_BYTES) {
    throw new Error(`That file is larger than the ${formatFileSize(MAX_UPLOAD_BYTES)} limit`);
  }
}
""", """function rejectIfOversize(file: File | Blob): void {
  if (file.size > MAX_UPLOAD_BYTES) {
    throw new UploadRejectedError(`That file is larger than the ${formatFileSize(MAX_UPLOAD_BYTES)} limit`);
  }
}

/**
 * A file this client refuses before sending anything (too large, empty, unsupported type). Its message is written
 * for the person and is safe to show as is (goodqa#14903, Kimi qac-attach-001). Other thrown errors, such as a
 * browser network TypeError, are not, so callers show a generic line for those.
 */
export class UploadRejectedError extends Error {
  override name = 'UploadRejectedError';
}

/** The line to show when an upload fails: the server's or the precheck's own message, else a generic one. */
export function uploadFailureMessage(error: unknown, fallback = 'Could not upload that file'): string {
  if (error instanceof UploadRejectedError) return error.message;
  if (error instanceof ApiError) return error.message;
  return fallback;
}
""", 'oversize')
n = s.count('throw new Error(EMPTY_UPLOAD_MESSAGE)')
assert n >= 2, n
s = s.replace('throw new Error(EMPTY_UPLOAD_MESSAGE)', 'throw new UploadRejectedError(EMPTY_UPLOAD_MESSAGE)')
m = s.count('if (unsupported) throw new Error(unsupported);')
assert m >= 1, m
s = s.replace('if (unsupported) throw new Error(unsupported);', 'if (unsupported) throw new UploadRejectedError(unsupported);')
s = sub(s, "import { api, API_URL, uploadSessionResponse } from './api';", "import { api, API_URL, ApiError, uploadSessionResponse } from './api';", 'uploads import')
u.write_text(s)

c = web / 'components/messaging/message-composer.tsx'
s = c.read_text()
s = sub(s, "toast.error(error instanceof ApiError ? error.message : 'Could not upload that file');",
        'toast.error(uploadFailureMessage(error));', 'composer toast')
s = sub(s, "import { imagesFromClipboard, uploadConversationFile, type Attachment } from '@/lib/uploads';",
        "import { imagesFromClipboard, uploadConversationFile, uploadFailureMessage, type Attachment } from '@/lib/uploads';", 'composer import')
if s.count('ApiError') == 1:
    s = sub(s, "import { ApiError } from '@/lib/api';\n", '', 'drop ApiError import')
c.write_text(s)

d = web / 'components/messaging/new-ai-thread-dialog.tsx'
s = d.read_text()
s = sub(s, """          {create.error && (""", """          {!message.trim() && (
            <p id="new-ai-message-hint" className="text-sm text-muted">
              Write a message to start the thread.
            </p>
          )}
          {create.error && (""", 'hint')
s = sub(s, """            <Button type="submit" disabled={!message.trim() || create.isPending}>""",
        """            <Button
              type="submit"
              disabled={!message.trim() || create.isPending}
              aria-describedby={message.trim() ? undefined : 'new-ai-message-hint'}
            >""", 'button')
d.write_text(s)
print('src ok')
