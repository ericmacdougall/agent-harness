/**
 * goodqa#16136 AC-16: the create-guard's mode hold.
 *
 * `GUARD_HELD_ENV=TRANSCODER_MODE=transcribe` on the guard's OWN environment
 * makes it refuse any `/containers/create` whose `Env` would start the
 * transcoder in its transcription mode, while MP4 transcodes, frame splicing
 * and the other three job images are allowed unchanged. Unset or empty, the
 * guard behaves exactly as before (NEG-13).
 *
 * Matching. The worker decides its mode with `transcoderMode()`
 * (apps/transcoder/src/mode.ts): an exact `TRANSCODER_MODE === 'transcribe'`.
 * The guard refuses a strict superset of that, failing closed:
 *   - any Env entry whose NAME, trimmed and upper-cased, is the held key, and
 *     whose VALUE, trimmed and lower-cased, is the held value;
 *   - the held key appearing more than once (which occurrence a process sees
 *     depends on its libc; refusing makes that question moot);
 *   - the held key with no `=` (a pass-through whose value the guard cannot see);
 *   - a NUL or other control character anywhere in the held key's value;
 *   - an `Env` that is not an array of strings;
 *   - any non-null `Entrypoint` (the image's own ENTRYPOINT is the only one
 *     that reads the mode through `transcoderMode()`).
 * `Cmd` stays allowed: it is the job's argv after the image ENTRYPOINT
 * (`pnpm start`; the API sends `[attachmentId, runId]` for MP4) and selects
 * no mode.
 *
 * Scope. This is an honest-path policy: it keeps the release's own API and
 * dispatcher from launching transcription while it is held. It is not a
 * boundary against a compromised dispatcher beyond what the rest of this
 * guard already enforces; the image allowlist and HostConfig checks remain
 * the security boundary.
 */

export interface HeldEnv {
  key: string;
  value: string;
}

/** The only holds a release may set: key -> allowed held values. */
const HOLDABLE: Readonly<Record<string, readonly string[]>> = { TRANSCODER_MODE: ['transcribe'] };

function hasControlChars(value: string): boolean {
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    if (code < 0x20 || code === 0x7f) return true;
  }
  return false;
}

function describe(raw: string): string {
  return JSON.stringify(raw.length > 80 ? `${raw.slice(0, 80)}...` : raw);
}

/** Parses the guard's own GUARD_HELD_ENV; throws (refusing startup) on anything but one supported KEY=VALUE pair. */
export function parseHeldEnv(raw: string | undefined): HeldEnv | null {
  if (raw === undefined || raw === '') return null;
  const m = /^([A-Z][A-Z0-9_]*)=([a-z][a-z0-9-]*)$/.exec(raw);
  const key = m?.[1];
  const value = m?.[2];
  const allowed = key !== undefined ? HOLDABLE[key] : undefined;
  if (key === undefined || value === undefined || !allowed || !allowed.includes(value)) {
    throw new Error(
      `GUARD_HELD_ENV must be empty or exactly one of ${Object.entries(HOLDABLE)
        .flatMap(([k, vs]) => vs.map((v) => `${k}=${v}`))
        .join(', ')}; refusing to start with ${describe(raw)}.`,
    );
  }
  return { key, value };
}

/** Why this create body is refused under HELD, or null when it is allowed (always null without a hold). */
export function heldEnvViolation(top: Record<string, unknown>, held: HeldEnv | null | undefined): string | null {
  if (!held) return null;
  const tag = `${held.key}=${held.value} is held on this guard`;
  if (top.Entrypoint !== undefined && top.Entrypoint !== null) {
    return `Entrypoint overrides are refused while ${tag}`;
  }
  const env = top.Env;
  if (env === undefined || env === null) return null;
  if (!Array.isArray(env)) return `Env must be an array of strings while ${tag}`;
  let seen = 0;
  for (const entry of env) {
    if (typeof entry !== 'string') return `Env must be an array of strings while ${tag}`;
    const eq = entry.indexOf('=');
    const name = eq < 0 ? entry : entry.slice(0, eq);
    if (name.trim().toUpperCase() !== held.key) continue;
    seen += 1;
    if (eq < 0) return `${held.key} without a value is refused while ${tag}`;
    const value = entry.slice(eq + 1);
    if (hasControlChars(value)) return `${held.key} with control characters is refused while ${tag}`;
    if (value.trim().toLowerCase() === held.value) return `create refused: ${tag}`;
  }
  if (seen > 1) return `${held.key} repeated in Env is refused while ${tag}`;
  return null;
}
