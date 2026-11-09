#!/usr/bin/env python3
"""Batch 1 red-team Lows (goodqa#14903): L2 textarea describedby, L3 useId hint id, L4 test hygiene and gaps."""
import pathlib, sys

root = pathlib.Path(sys.argv[1]) / 'apps/web/src'


def sub(path, old, new, count=1):
    p = root / path
    s = p.read_text()
    if s.count(old) != count:
        sys.exit(f'PATCH_MISS {path}: expected {count} of {old[:60]!r}, found {s.count(old)}')
    p.write_text(s.replace(old, new))


d = 'components/messaging/new-ai-thread-dialog.tsx'
sub(d, "import { useState } from 'react';", "import { useId, useState } from 'react';")
sub(d, "  const create = useCreateAiThread(orgId);\n", "  const create = useCreateAiThread(orgId);\n  const hintId = useId();\n  const empty = !message.trim();\n")
sub(d, "            onChange={(event) => setMessage(event.target.value)}\n",
    "            onChange={(event) => setMessage(event.target.value)}\n            aria-describedby={empty ? hintId : undefined}\n")
sub(d, '          {!message.trim() && (\n            <p id="new-ai-message-hint" className="text-sm text-muted">',
    '          {empty && (\n            <p id={hintId} className="text-sm text-muted">')
sub(d, "              aria-describedby={message.trim() ? undefined : 'new-ai-message-hint'}",
    "              aria-describedby={empty ? hintId : undefined}")

t = 'components/messaging/new-ai-thread-dialog.test.tsx'
sub(t, "  expect(start.getAttribute('aria-describedby')).toBe(hint.getAttribute('id'));\n",
    "  expect(hint.getAttribute('id')).toBeTruthy();\n"
    "  expect(start.getAttribute('aria-describedby')).toBe(hint.getAttribute('id'));\n"
    "  // The textarea has focus when the dialog opens and a disabled button cannot take focus: the hint must reach it too.\n"
    "  expect(screen.getByLabelText('Ask Jarvis anything…').getAttribute('aria-describedby')).toBe(hint.getAttribute('id'));\n")
sub(t, "  expect(start.getAttribute('aria-describedby')).toBeNull();\n",
    "  expect(start.getAttribute('aria-describedby')).toBeNull();\n"
    "  expect(screen.getByLabelText('Ask Jarvis anything…').getAttribute('aria-describedby')).toBeNull();\n")

u = 'components/messaging/message-composer-upload-reason.test.tsx'
sub(u, " * (too large, empty, unsupported type) must show that reason",
    " * (too large, empty) must show that reason; a server refusal (ApiError, e.g. an unsupported type) keeps its message")
sub(u, "  vi.mocked(toast.error).mockReset();\n});",
    "  vi.mocked(toast.error).mockReset();\n  vi.unstubAllGlobals();\n});")
sub(u, "  expect(fetchSpy).not.toHaveBeenCalled();\n  vi.unstubAllGlobals();\n});",
    "  expect(fetchSpy).not.toHaveBeenCalled();\n});\n\n"
    "it('an empty file shows the empty-file reason and sends no request', async () => {\n"
    "  const fetchSpy = vi.fn();\n"
    "  vi.stubGlobal('fetch', fetchSpy);\n"
    "  fireEvent.paste(composer(), pasteFile(new File([], 'empty.txt', { type: 'text/plain' })));\n"
    "  await waitFor(() => expect(toast.error).toHaveBeenCalledTimes(1));\n"
    "  expect(vi.mocked(toast.error).mock.calls[0]![0]).toBe(EMPTY_UPLOAD_MESSAGE);\n"
    "  expect(fetchSpy).not.toHaveBeenCalled();\n"
    "});\n\n"
    "it('a server refusal keeps the server message', async () => {\n"
    "  vi.mocked(uploads.uploadConversationFile).mockRejectedValueOnce(new ApiError(415, 'unsupported_media_type', 'That file type is not supported'));\n"
    "  fireEvent.paste(composer(), pasteFile(new File([new Uint8Array([1])], 'x.bin', { type: 'application/x-msdownload' })));\n"
    "  await waitFor(() => expect(toast.error).toHaveBeenCalledTimes(1));\n"
    "  expect(vi.mocked(toast.error).mock.calls[0]![0]).toBe('That file type is not supported');\n"
    "});")
sub(u, "const { toast } = await import('sonner');\n",
    "const { toast } = await import('sonner');\nconst { ApiError } = await import('@/lib/api');\nconst { EMPTY_UPLOAD_MESSAGE } = await import('@bugtracker/shared');\n")
print('PATCHED')
