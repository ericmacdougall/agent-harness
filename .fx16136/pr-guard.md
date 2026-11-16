GoodQA goodqa#16136, spec v2.1 AC-16, NEG-12, NEG-13 and Opus build notes D2 to D5.

## What

The create-guard gets a mode hold. With `GUARD_HELD_ENV=TRANSCODER_MODE=transcribe` set in its own environment, the guard refuses any `/containers/create` that would start the transcoder in transcription mode. MP4 transcodes, frames and the other three job images are allowed unchanged. With the variable unset or empty, behavior is exactly as today.

- `apps/job-dispatcher/src/held-env.ts` (new): `parseHeldEnv` refuses startup on anything but the one supported pair. `heldEnvViolation` refuses a create in these cases:
  - an Env name equal to the held key after trim and upper-casing, whose value equals the held value after trim and lower-casing;
  - the held key repeated;
  - the held key with no `=`;
  - NUL or control characters in its value;
  - an Env that is not an array of strings;
  - any non-null Entrypoint.
- `Cmd` stays allowed. It is argv after the image ENTRYPOINT (`pnpm start`), and MP4 sends `[attachmentId, runId]`.
- `apps/transcoder/src/mode.ts` (new): `transcoderMode()`, the worker's exact parse, now used by `index.ts`. The guard tests import it and pin the two together: every value the worker treats as transcription must be refused.
- The guard startup line names the hold (`heldEnv=...` or `heldEnv=none`). The release runner checks that line after the switch.

This is an honest-path policy. It is not a boundary against a compromised dispatcher; the image allowlist and the HostConfig checks remain that boundary.

## Release coupling (AC-17)

This must reach production in the same release as the release-harness fix (bugtracker `fix/16136-job-images-rh`, ef4e011a53e3). The runner probes the built dispatcher image: only a guard that refuses a malformed `GUARD_HELD_ENV` gets `--guard-hold`. Any other release holds the whole transcode image, so transcription never launches unheld. The next production ship SHA carries everything on main since 7e66a853.

## Testing (t2-dev)

- `pnpm exec vitest run test/held-env.test.ts` failed first (module missing), then 62 passed.
- `vitest run --exclude "**/*.docker.test.ts" --exclude "**/*.e2e.*"`: 323 passed.
- `tsc --noEmit` is clean for job-dispatcher and transcoder.
- Seven broken variants of held-env.ts each fail held-env.test.ts.

🤖 Generated with [Claude Code](https://claude.com/claude-code)

https://claude.ai/code/session_011PwJaRQM1UYqY3vZNrYjVv
