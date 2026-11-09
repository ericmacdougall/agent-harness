Why: Kimi QAC findings qac-001 and web-qac-attach-001 (goodqa#14903). The New AI thread dialog disabled Start thread on an empty message with no reason, and the message composer replaced client-side upload refusals (too large, empty) with "Could not upload that file".

What:
- `uploads.ts`: client prechecks throw `UploadRejectedError`; `uploadFailureMessage()` returns its reason or an `ApiError` message, else the generic fallback. Network, PUT and unknown errors stay generic. About 15 other upload callers are unchanged (same messages, still `instanceof Error`).
- `message-composer.tsx`: the toast uses `uploadFailureMessage()`.
- `new-ai-thread-dialog.tsx`: an empty message shows "Write a message to start the thread."; the hint id comes from `useId()`, and both the focused textarea and the disabled button point to it.
- Correction to the first commit message: the composer has no client unsupported-type precheck. An unsupported type is a server `ApiError`, which was already shown, and a test now covers it.

Testing: on t2-dev in apps/web.
- `npx vitest run src/components/messaging/message-composer-upload-reason.test.tsx src/components/messaging/new-ai-thread-dialog.test.tsx`: the new tests on the old code gave 2 failed | 5 passed; with 37f928ff, 7 passed. The textarea-hint assertion against the 37f928ff component gave 1 failed | 4 passed; with 63aa7ed0, all 9 pass.
- `npx vitest run src/components/messaging/new-ai-thread-dialog.test.tsx src/components/messaging/message-composer*.test.tsx src/components/messaging/thread-panel*.test.tsx`: 247 passed.
- `npx tsc --noEmit -p .`: the same 3 errors as base 7b738654, none in changed files.
- `node infra/lint.mjs`: the same 7 over-baseline rules with identical counts as base 7b738654 (no new findings).
- Red-team (native, Opus): PASS_WITH_LOWS. L2 to L4 are fixed in 63aa7ed0, and L1 is corrected above.
- Not run: browser click-test. The agent browser refuses the local stack (goodqa#15479).

Refs: GoodQA #14903

Risk: UI copy and accessibility only; no API or data change. Rollback: revert the PR.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
