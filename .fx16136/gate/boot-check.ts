/**
 * goodqa#16148 spec v4 AC-8 / P3: the trial boot. Before an unholding switch, rw-ship runs the release's dispatcher
 * image once, isolated, with the CLI flag `--boot-check` and a throwaway secrets directory holding a fake value.
 * This mode only loads the config and prints the JOB_ENVFILE boot status lines (names and status only), then
 * exits. It binds no port and never runs docker. It is selected by argv alone (lead ruling Q2), so no compose or
 * env change can turn it on in a serving container.
 *
 * Exit: 0 when at least one key is configured and every line is `job env file KIND__VAR: ok`; 1 when any line is
 * not ok (an error or an ignored key); 2 when the config is refused (error name only); 3 when no key is configured.
 */
import { loadConfig } from './config';
import { bootEnvFileStatusLines, JOB_ENVFILE_DIR } from './job-env-file';

export const BOOT_CHECK_FLAG = '--boot-check';

export function isBootCheck(argv: readonly string[]): boolean {
  return argv.length === 1 && argv[0] === BOOT_CHECK_FLAG;
}

const OK_LINE = /^job env file [A-Z0-9_]+__[A-Z0-9_]+: ok$/;

export function runBootCheck(
  env: NodeJS.ProcessEnv,
  write: (line: string) => void,
  envFileDir: string = JOB_ENVFILE_DIR,
): number {
  let config;
  try {
    config = loadConfig(env);
  } catch (error) {
    write(`boot check: config refused (${error instanceof Error ? error.name : 'unknown'})`);
    return 2;
  }
  const lines = bootEnvFileStatusLines({ jobEnvFiles: config.jobEnvFiles, jobEnvFileDir: envFileDir });
  if (lines.length === 0) {
    write('boot check: no JOB_ENVFILE key configured');
    return 3;
  }
  for (const line of lines) write(line);
  return lines.every((l) => OK_LINE.test(l)) ? 0 : 1;
}
