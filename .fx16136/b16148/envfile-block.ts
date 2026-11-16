
/**
 * goodqa#16148 spec v4 AC-6: job env goes to docker through `--env-file`, never `-e KEY=VALUE`.
 * A docker CLI process's argv is world-readable in the host PID namespace (/proc/PID/cmdline).
 *
 * Each launch gets a fresh mkdtemp directory (0700) under the dispatcher's tmpfs /tmp, holding
 * one file (O_CREAT|O_EXCL|O_NOFOLLOW, 0600) with one `KEY=VALUE` line per variable. A line
 * without `=` is never written (docker would fill it from the CLI's own environment). The
 * directory is removed in a finally on every path. docker reads the value verbatim after the
 * first `=` (probed on t2-dev: spaces, quotes, `#`, `=` and an empty value round-trip), but a
 * line cannot carry CR, LF or NUL, so those are refused, with a named error that never holds the
 * value. Boot removes any leftover directory (sweepStaleEnvFileDirs).
 */
export const ENVFILE_DIR_PREFIX = 'goodqa-envfile-';
export const ENV_KEY_PATTERN = /^[A-Za-z_][A-Za-z0-9_]*$/;

/** A job env that cannot be written to an env-file. Never carries a value. */
export class JobEnvError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'JobEnvError';
  }
}

function describeKey(key: string): string {
  return /^[\x21-\x7e]{1,128}$/.test(key) && !key.includes('=') ? key : `(a key of ${key.length} chars)`;
}

/** Why this env entry cannot be written, naming the key only; null when it can. */
export function envEntryProblem(key: string, value: string): string | null {
  if (!ENV_KEY_PATTERN.test(key)) return `env key ${describeKey(key)} is not a valid name`;
  if (/[\r\n\0]/.test(value)) return `env ${key}: value holds CR, LF or NUL`;
  if (!value.isWellFormed()) return `env ${key}: value is not valid UTF-8`;
  return null;
}

function writeLaunchEnvFile(env: Record<string, string>): { dir: string; file: string } | null {
  const entries = Object.entries(env);
  for (const [key, value] of entries) {
    const problem = envEntryProblem(key, value);
    if (problem) throw new JobEnvError(`job ${problem}`);
  }
  if (entries.length === 0) return null;
  const dir = mkdtempSync(join(tmpdir(), ENVFILE_DIR_PREFIX));
  try {
    chmodSync(dir, 0o700);
    const file = join(dir, 'env');
    const fd = openSync(file, fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW, 0o600);
    try {
      fchmodSync(fd, 0o600);
      writeSync(fd, Buffer.from(entries.map(([k, v]) => `${k}=${v}\n`).join(''), 'utf8'));
    } finally {
      closeSync(fd);
    }
    return { dir, file };
  } catch (error) {
    rmSync(dir, { recursive: true, force: true });
    throw error;
  }
}

/** Boot: remove leftover per-launch env-file directories (and unlink, never follow, a symlink). */
export function sweepStaleEnvFileDirs(root: string = tmpdir()): number {
  let removed = 0;
  for (const name of readdirSync(root)) {
    if (!name.startsWith(ENVFILE_DIR_PREFIX)) continue;
    const path = join(root, name);
    const st = lstatSync(path);
    if (st.isSymbolicLink() || !st.isDirectory()) unlinkSync(path);
    else rmSync(path, { recursive: true, force: true });
    removed += 1;
  }
  return removed;
}
