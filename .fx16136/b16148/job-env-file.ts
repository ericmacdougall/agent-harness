/**
 * goodqa#16148 spec v4 AC-4, AC-5, AC-9: file-backed job env.
 *
 * `JOB_ENVFILE_<KIND>__<VAR>=<PATH>` in the dispatcher's own env makes <VAR> part of that kind's
 * job env, read from <PATH> at every launch (so a rotated file is picked up without a restart).
 * Only keys in the compiled allow-list are honoured; any other JOB_ENVFILE_ key is ignored and
 * named at boot. The prefix differs from `JOB_ENV_I...` at its eighth character, so an older
 * dispatcher (which matches only `JOB_ENV_<KIND>__`) ignores these keys entirely.
 *
 * The read never resolves the path twice and never follows a link: PATH must be absolute, hold no
 * `..` segment, and have exactly the secrets directory as its parent; it is opened
 * O_RDONLY|O_NOFOLLOW|O_NONBLOCK (a FIFO cannot block the launch), fstat on the same fd must show
 * a regular file, and at most 64 KiB + 1 byte is read from that fd. One trailing LF is removed.
 * Every failure is a fixed phrase that names the key and never holds the value.
 */
import { closeSync, constants as fsConstants, fstatSync, openSync, readSync } from 'node:fs';
import { dirname, isAbsolute } from 'node:path';
import type { JobKind } from './jobs';
import { JOB_KINDS } from './jobs';

export const JOB_ENVFILE_PREFIX = 'JOB_ENVFILE_';
export const JOB_ENVFILE_ALLOWLIST: ReadonlySet<string> = new Set(['INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY']);
/** The only directory a JOB_ENVFILE path may live in: the job-dispatcher's read-only secrets mount. */
export const JOB_ENVFILE_DIR = '/run/goodqa-secrets';
export const JOB_ENVFILE_MAX_BYTES = 64 * 1024;

export interface JobEnvFileEntry {
  /** `INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY` */
  id: string;
  kind: JobKind;
  varName: string;
  path: string;
}

export interface JobEnvFiles {
  entries: JobEnvFileEntry[];
  ignored: string[];
}

function envPrefixForKind(kind: JobKind): string {
  return kind.toUpperCase().replace(/-/g, '_');
}

export function parseJobEnvFiles(env: NodeJS.ProcessEnv): JobEnvFiles {
  const entries: JobEnvFileEntry[] = [];
  const ignored: string[] = [];
  for (const [key, value] of Object.entries(env)) {
    if (value === undefined || !key.startsWith(JOB_ENVFILE_PREFIX)) continue;
    const id = key.slice(JOB_ENVFILE_PREFIX.length);
    const kind = JOB_KINDS.find((k) => id.startsWith(`${envPrefixForKind(k)}__`));
    if (!kind || !JOB_ENVFILE_ALLOWLIST.has(id)) {
      ignored.push(key);
      continue;
    }
    entries.push({ id, kind, varName: id.slice(envPrefixForKind(kind).length + 2), path: value });
  }
  ignored.sort();
  return { entries, ignored };
}

export type JobEnvFileRead = { ok: true; value: string } | { ok: false; reason: string };

export function readJobEnvFile(path: string, allowedDir: string): JobEnvFileRead {
  if (!isAbsolute(path) || path.split('/').includes('..') || dirname(path) !== allowedDir) {
    return { ok: false, reason: 'path outside the secrets directory' };
  }
  let fd: number;
  try {
    fd = openSync(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | fsConstants.O_NONBLOCK);
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === 'ENOENT') return { ok: false, reason: 'missing' };
    if (code === 'ELOOP') return { ok: false, reason: 'is a symlink' };
    if (code === 'EACCES' || code === 'EPERM') return { ok: false, reason: 'unreadable' };
    return { ok: false, reason: `cannot open (${code ?? 'error'})` };
  }
  try {
    if (!fstatSync(fd).isFile()) return { ok: false, reason: 'not a regular file' };
    const buf = Buffer.alloc(JOB_ENVFILE_MAX_BYTES + 1);
    let total = 0;
    for (;;) {
      let n: number;
      try {
        n = readSync(fd, buf, total, buf.length - total, null);
      } catch (error) {
        const code = (error as NodeJS.ErrnoException).code;
        if (code === 'EACCES' || code === 'EPERM') return { ok: false, reason: 'unreadable' };
        return { ok: false, reason: `cannot read (${code ?? 'error'})` };
      }
      if (n === 0) break;
      total += n;
      if (total > JOB_ENVFILE_MAX_BYTES) return { ok: false, reason: 'over 64 KiB' };
    }
    let bytes = buf.subarray(0, total);
    if (bytes.length > 0 && bytes[bytes.length - 1] === 0x0a) bytes = bytes.subarray(0, bytes.length - 1);
    if (bytes.length === 0) return { ok: false, reason: 'empty' };
    if (bytes.includes(0x0d) || bytes.includes(0x0a) || bytes.includes(0x00)) return { ok: false, reason: 'value holds CR, LF or NUL' };
    const value = bytes.toString('utf8');
    if (!Buffer.from(value, 'utf8').equals(bytes)) return { ok: false, reason: 'value is not valid UTF-8' };
    return { ok: true, value };
  } finally {
    closeSync(fd);
  }
}

export function envFileError(entry: Pick<JobEnvFileEntry, 'id'>, reason: string): string {
  return `job env file for ${entry.id}: ${reason}`;
}

/** Resolve a kind's file-backed env for one launch, or the first named error. */
export function resolveJobEnvFiles(
  files: JobEnvFiles,
  allowedDir: string,
  kind: JobKind,
  baseEnv: Record<string, string>,
): { ok: true; env: Record<string, string> } | { ok: false; error: string } {
  const env: Record<string, string> = {};
  for (const entry of files.entries) {
    if (entry.kind !== kind) continue;
    if (Object.prototype.hasOwnProperty.call(baseEnv, entry.varName)) {
      return { ok: false, error: envFileError(entry, 'both JOB_ENV_ and JOB_ENVFILE_ are set') };
    }
    const read = readJobEnvFile(entry.path, allowedDir);
    if (!read.ok) return { ok: false, error: envFileError(entry, read.reason) };
    env[entry.varName] = read.value;
  }
  return { ok: true, env };
}

/** Boot: one status line per JOB_ENVFILE key (rw-ship's unhold gate reads `: ok`). Never throws. */
export function bootEnvFileStatusLines(config: { jobEnvFiles: JobEnvFiles; jobEnvFileDir: string }): string[] {
  const lines: string[] = [];
  for (const entry of config.jobEnvFiles.entries) {
    let read: JobEnvFileRead;
    try {
      read = readJobEnvFile(entry.path, config.jobEnvFileDir);
    } catch {
      read = { ok: false, reason: 'cannot read (error)' };
    }
    lines.push(read.ok ? `job env file ${entry.id}: ok` : envFileError(entry, read.reason));
  }
  for (const key of config.jobEnvFiles.ignored) lines.push(`job env file key ignored (not allow-listed): ${key}`);
  return lines;
}
