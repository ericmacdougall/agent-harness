/**
 * The transcoder's one mode switch, read from `TRANSCODER_MODE` on the
 * execution's env override. Exact comparison: anything other than
 * `transcribe` or `frames` is the historical MP4 transcode, byte for byte.
 *
 * Kept dependency-free so the job-dispatcher create-guard's mode hold
 * (apps/job-dispatcher/src/held-env.ts, goodqa#16136) can import it in a test
 * and prove it refuses every value this function treats as transcription.
 */
export type TranscoderMode = 'transcode' | 'transcribe' | 'frames';

export function transcoderMode(env: Readonly<Record<string, string | undefined>>): TranscoderMode {
  const mode = env.TRANSCODER_MODE;
  if (mode === 'transcribe') return 'transcribe';
  if (mode === 'frames') return 'frames';
  return 'transcode';
}
