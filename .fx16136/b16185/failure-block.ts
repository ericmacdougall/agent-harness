
/**
 * goodqa#16185 (goodqa#16148 spec v4 AC-7): what a failed `docker run` may say.
 *
 * docker's stderr and execFile's err.message/err.cmd can echo the full argv, and with it every
 * `-e KEY=VALUE` job secret. They are never forwarded. The message is always
 * `docker run failed: CATEGORY (stderr N bytes)`, CATEGORY from a fixed set. At most one
 * allow-listed first line is appended:
 *   - a create-guard refusal of a held mode is rebuilt from constants (never echoed), so the
 *     hold reason survives exactly (goodqa#16136 AC-13 pairs on it);
 *   - any other allow-listed line has every secret-source value removed from the FULL stderr,
 *     longest first, before any cut; it is dropped if a value under 8 bytes appears in it as a
 *     whole token, if any 8-byte window of a value (raw, base64 in three alignments, hex,
 *     JSON-escaped, or a decimal byte list) remains, or if it holds anything but printable ASCII;
 *     then it is cut to 200 characters.
 * Only the dispatcher's base env for the kind is a secret source; the caller's allow-listed
 * request env is not redacted (build condition P1). Residual risk, accepted in the spec: a
 * secret under 8 bytes that sits inside a longer token is not detected.
 */
export type DockerFailureCategory = 'guard_refused' | 'image_not_found' | 'invalid_reference' | 'daemon_unreachable' | 'other';

const GUARD_PREFIX = 'docker: Error response from daemon: job-dispatcher-create-guard: refused (';
const ALLOWED_LINE_PREFIXES: readonly string[] = [
  GUARD_PREFIX,
  'Unable to find image',
  'docker: invalid reference format',
  'invalid reference format',
];
const MAX_LINE = 200;
const MIN_WINDOW = 8;

/**
 * The create-guard's held-mode refusal texts (apps/job-dispatcher/src/held-env.ts on the
 * goodqa#16136 branch). Literal here so this fix can ship alone (goodqa#16148 Q1); the
 * cross-constant test against the guard's own text lands with the first PR after #16136.
 */
const HOLDABLE: Readonly<Record<string, readonly string[]>> = { TRANSCODER_MODE: ['transcribe'] };

function heldRefusalLines(): Set<string> {
  const lines = new Set<string>();
  for (const [key, values] of Object.entries(HOLDABLE)) {
    for (const value of values) {
      const tag = `${key}=${value} is held on this guard`;
      for (const reason of [
        `Entrypoint overrides are refused while ${tag}`,
        `${key} without a value is refused while ${tag}`,
        `${key} with control characters is refused while ${tag}`,
        `create refused: ${tag}`,
        `${key} repeated in Env is refused while ${tag}`,
      ]) {
        lines.add(`${GUARD_PREFIX}${reason})`);
      }
    }
  }
  return lines;
}
const HELD_REFUSAL_LINES = heldRefusalLines();

function categorize(stderr: string): DockerFailureCategory {
  if (stderr.includes('job-dispatcher-create-guard: refused (')) return 'guard_refused';
  if (/Unable to find image|No such image|pull access denied|manifest unknown/.test(stderr)) return 'image_not_found';
  if (stderr.includes('invalid reference format')) return 'invalid_reference';
  if (/Cannot connect to the Docker daemon|permission denied while trying to connect to the Docker daemon/i.test(stderr)) {
    return 'daemon_unreachable';
  }
  return 'other';
}

function valueForms(value: string): string[] {
  const bytes = Buffer.from(value, 'utf8');
  const hex = bytes.toString('hex');
  return [
    value,
    bytes.toString('base64'),
    Buffer.concat([Buffer.from('x'), bytes]).toString('base64').slice(2),
    Buffer.concat([Buffer.from('xx'), bytes]).toString('base64').slice(3),
    hex,
    hex.toUpperCase(),
    JSON.stringify(value).slice(1, -1),
    [...bytes].join(' '),
  ];
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function hasResidue(rawLine: string, values: readonly string[]): boolean {
  // A backslash-interleaved echo (`F\\A\\K\\E`) is checked with the backslashes removed too.
  return [rawLine, rawLine.replace(/\\/g, '')].some((line) => hasResidueIn(line, values));
}

function hasResidueIn(line: string, values: readonly string[]): boolean {
  for (const value of values) {
    if (value.length < MIN_WINDOW) {
      if (new RegExp(`(^|[^A-Za-z0-9])${escapeRegExp(value)}($|[^A-Za-z0-9])`).test(line)) return true;
      continue;
    }
    for (const form of valueForms(value)) {
      for (let i = 0; i + MIN_WINDOW <= line.length; i += 1) {
        if (form.includes(line.slice(i, i + MIN_WINDOW))) return true;
      }
    }
  }
  return false;
}

function isPrintableAscii(s: string): boolean {
  return /^[\x20-\x7e]*$/.test(s);
}

export function describeDockerFailure(stderr: string, secretValues: readonly string[]): string {
  const category = categorize(stderr);
  const head = `docker run failed: ${category} (stderr ${Buffer.byteLength(stderr, 'utf8')} bytes)`;
  const firstLine = (stderr.split('\n', 1)[0] ?? '').replace(/\r$/, '').trimEnd();

  if (HELD_REFUSAL_LINES.has(firstLine)) {
    // Appended from the constant set, never from stderr.
    for (const constant of HELD_REFUSAL_LINES) if (constant === firstLine) return `${head}: ${constant}`;
  }
  if (!ALLOWED_LINE_PREFIXES.some((p) => firstLine.startsWith(p))) return head;

  const values = [...new Set(secretValues.filter((v) => v.length > 0))];
  let redacted = stderr;
  for (const value of [...values].filter((v) => v.length >= MIN_WINDOW).sort((a, b) => b.length - a.length)) {
    redacted = redacted.split(value).join('[redacted]');
  }
  const line = (redacted.split('\n', 1)[0] ?? '').replace(/\r$/, '').trimEnd();
  if (!ALLOWED_LINE_PREFIXES.some((p) => line.startsWith(p))) return head;
  if (!isPrintableAscii(line) || hasResidue(line, values)) return head;
  const cut = line.slice(0, MAX_LINE);
  if (hasResidue(cut, values)) return head;
  return `${head}: ${cut}`;
}
