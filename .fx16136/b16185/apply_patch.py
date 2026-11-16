"""goodqa#16185: apply the docker failure-message change to apps/job-dispatcher (run from that dir)."""
import sys

block = open(sys.argv[1]).read()


def edit(path, pairs):
    s = open(path).read()
    for old, new in pairs:
        assert s.count(old) == 1, (path, old[:80])
        s = s.replace(old, new)
    open(path, "w").write(s)


edit("src/docker.ts", [
    ("export async function dockerRunDetached(\n  dockerBin: string,\n  image: string,\n  args: string[],\n  env: Record<string, string>,\n  timeoutMs: number,\n  security: ContainerSecurityProfile,\n): Promise<DockerRunResult> {\n",
     block + "\n/**\n * `secretValues`: the values from a secret source (the dispatcher's base env for the kind) that a\n * failure message must never carry (goodqa#16185). Omitted, every env value is treated as secret.\n */\nexport async function dockerRunDetached(\n  dockerBin: string,\n  image: string,\n  args: string[],\n  env: Record<string, string>,\n  timeoutMs: number,\n  security: ContainerSecurityProfile,\n  secretValues: readonly string[] = Object.values(env),\n): Promise<DockerRunResult> {\n"),
    ("    const stderr = typeof err.stderr === 'string' ? err.stderr.trim().slice(0, 500) : '';\n    throw new DockerLaunchError(\n      'synchronous_failure',\n      `docker run failed before starting a container: ${stderr || err.message}`,\n    );\n",
     "    // goodqa#16185: never err.message or err.cmd (both hold the full argv), never raw stderr.\n    const stderr = typeof err.stderr === 'string' ? err.stderr : '';\n    throw new DockerLaunchError('synchronous_failure', describeDockerFailure(stderr, secretValues));\n"),
])

edit("src/server.ts", [
    ("    timeoutMs: number,\n    security: ContainerSecurityProfile,\n  ): Promise<DockerRunResult>;",
     "    timeoutMs: number,\n    security: ContainerSecurityProfile,\n    secretValues?: readonly string[],\n  ): Promise<DockerRunResult>;"),
    ("export function buildServer(config: Config, deps: DockerDeps = realDockerDeps): FastifyInstance {\n  // Quiet in tests (vitest sets NODE_ENV=test) so a passing test run isn't\n  // drowned in per-request access logs; still on by default in dev/prod.\n  const app = Fastify({ logger: process.env.NODE_ENV !== 'test' });\n",
     "export interface BuildServerOptions {\n  /** Test hook: capture the server's log lines (goodqa#16185 asserts they carry no value). */\n  logStream?: { write(line: string): void };\n}\n\nexport function buildServer(config: Config, deps: DockerDeps = realDockerDeps, options: BuildServerOptions = {}): FastifyInstance {\n  // Quiet in tests (vitest sets NODE_ENV=test) so a passing test run isn't\n  // drowned in per-request access logs; still on by default in dev/prod.\n  const app = Fastify({ logger: options.logStream ? { stream: options.logStream } : process.env.NODE_ENV !== 'test' });\n"),
    ("        JOB_SECURITY_PROFILE[kind],\n      );\n      const execution = recordExecution(",
     "        JOB_SECURITY_PROFILE[kind],\n        // goodqa#16185 / #16148 P1: only the base env is a secret source; the caller's allow-listed\n        // request env is not redacted from a failure message.\n        Object.values(config.jobBaseEnv[kind]),\n      );\n      const execution = recordExecution("),
    ("      req.log.error({ err: error, jobKind: kind }, 'job-dispatcher: unexpected error launching docker run');",
     "      // goodqa#16185: the error name only; an error's message or cmd may hold the argv and its env values.\n      req.log.error({ errName: error instanceof Error ? error.name : typeof error, jobKind: kind }, 'job-dispatcher: unexpected error launching docker run');"),
])

edit("test/server.test.ts", [
    ("      // AUD-032: the server picks this per job kind itself -- never\n      // something a request body can influence.\n      JOB_SECURITY_PROFILE.scan,\n    );",
     "      // AUD-032: the server picks this per job kind itself -- never\n      // something a request body can influence.\n      JOB_SECURITY_PROFILE.scan,\n      // goodqa#16185: the base env values only (the secret sources), never the caller's env.\n      ['postgres://base', 'sk-base'],\n    );"),
])
print("patched")
