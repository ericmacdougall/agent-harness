"""goodqa#16148 step 2a: --env-file for every launch. Run from apps/job-dispatcher. argv[1] = block file."""
import sys

block = open(sys.argv[1]).read().replace(
    "  if (!value.isWellFormed()) return",
    "  if (Buffer.from(value, 'utf8').toString('utf8') !== value) return",
)


def edit(path, pairs):
    s = open(path).read()
    for old, new in pairs:
        assert s.count(old) == 1, (path, old[:90])
        s = s.replace(old, new)
    open(path, "w").write(s)


edit("src/docker.ts", [
    ("import { execFile, type ExecFileException } from 'node:child_process';\n",
     "import { execFile, type ExecFileException } from 'node:child_process';\n"
     "import { chmodSync, closeSync, constants as fsConstants, fchmodSync, lstatSync, mkdtempSync, openSync, readdirSync, rmSync, unlinkSync, writeSync } from 'node:fs';\n"
     "import { tmpdir } from 'node:os';\n"
     "import { join } from 'node:path';\n"),
    ("\n/**\n * `secretValues`: the values from a secret source", block + "\n/**\n * `secretValues`: the values from a secret source"),
    ("  for (const [key, value] of Object.entries(env)) {\n    execArgs.push('-e', `${key}=${value}`);\n  }\n  execArgs.push(image, ...args);\n\n  let stdout: string;\n  try {\n",
     "  // goodqa#16148 AC-6: validated and written before docker is touched; removed in the finally.\n"
     "  const envFile = writeLaunchEnvFile(env);\n"
     "  if (envFile) execArgs.push('--env-file', envFile.file);\n"
     "  execArgs.push(image, ...args);\n\n"
     "  let stdout: string;\n  try {\n  try {\n"),
    ("    throw new DockerLaunchError('synchronous_failure', describeDockerFailure(stderr, secretValues));\n  }\n",
     "    throw new DockerLaunchError('synchronous_failure', describeDockerFailure(stderr, secretValues));\n  }\n"
     "  } finally {\n    if (envFile) rmSync(envFile.dir, { recursive: true, force: true });\n  }\n"),
])

edit("src/server.ts", [
    ("    const mergedEnv = { ...config.jobBaseEnv[kind], ...validation.env };\n",
     "    // goodqa#16148 AC-6 / NEG-8: an env-file line cannot carry CR, LF or NUL. A request value is\n"
     "    // the caller's fault (400); a base value is a dispatcher misconfiguration (501). Key names only.\n"
     "    for (const [key, value] of Object.entries(validation.env)) {\n"
     "      const problem = envEntryProblem(key, value);\n"
     "      if (problem) return reply.code(400).send({ error: `request ${problem}` });\n"
     "    }\n"
     "    for (const [key, value] of Object.entries(config.jobBaseEnv[kind])) {\n"
     "      const problem = envEntryProblem(key, value);\n"
     "      if (problem) {\n"
     "        req.log.error({ jobKind: kind }, `job-dispatcher: base ${problem}`);\n"
     "        return reply.code(501).send({ error: `job base ${problem}` });\n"
     "      }\n"
     "    }\n"
     "    const mergedEnv = { ...config.jobBaseEnv[kind], ...validation.env };\n"),
    ("      if (error instanceof DockerLaunchError) {\n",
     "      if (error instanceof JobEnvError) {\n"
     "        return reply.code(501).send({ error: error.message });\n"
     "      }\n"
     "      if (error instanceof DockerLaunchError) {\n"),
    ("  DockerLaunchError,\n", "  DockerLaunchError,\n  JobEnvError,\n  envEntryProblem,\n"),
])

edit("src/index.ts", [
    ("import { buildServer, realDockerDeps } from './server';\n",
     "import { sweepStaleEnvFileDirs } from './docker';\nimport { buildServer, realDockerDeps } from './server';\n"),
    ("async function main(): Promise<void> {\n",
     "async function main(): Promise<void> {\n"
     "  // goodqa#16148 AC-6: a crash between writing a launch env-file and its finally leaves a\n"
     "  // directory on the tmpfs; remove any before serving.\n"
     "  app.log.info({ removed: sweepStaleEnvFileDirs() }, 'job-dispatcher: swept stale env-file dirs');\n"),
])

edit("test/docker.test.ts", [
    ("    expect(args).toEqual([\n      'run',\n      '--rm',\n      '-d',\n      '-e',\n      'SCAN_CLONE_TOKEN=ghs_fake',\n      'registry.example/bugtracker/scan:tag',\n      'scan-id-1',\n    ]);\n",
     "    // goodqa#16148 AC-6: the env goes through a private --env-file, never `-e KEY=VALUE`.\n"
     "    expect(args).toEqual([\n      'run',\n      '--rm',\n      '-d',\n      '--env-file',\n      expect.stringMatching(/goodqa-envfile-[^/]+\\/env$/),\n      'registry.example/bugtracker/scan:tag',\n      'scan-id-1',\n    ]);\n"
     "    expect(args.join(' ')).not.toContain('ghs_fake');\n"),
    ("    const [, args] = execFileMock.mock.calls[0]!;\n    expect(args).toContain('-e');\n    // The dangerous value is the ENTIRE next argv element, not split by the\n    // shell metacharacters it contains -- there is no shell to split it.\n    expect(args).toContain('PAYLOAD=$(rm -rf /); echo pwned `whoami`');\n    expect(args).toHaveLength(6); // run, --rm, -d, -e, KEY=VALUE, image -- one element each\n",
     "    const [, args] = execFileMock.mock.calls[0]!;\n    // goodqa#16148 AC-6: the value never reaches argv at all; it rides in the env-file.\n"
     "    expect(args).not.toContain('-e');\n    expect((args as string[]).join(' ')).not.toContain('whoami');\n"
     "    expect(args).toHaveLength(6); // run, --rm, -d, --env-file, PATH, image -- one element each\n"),
    ("      '/tmp:rw,noexec,nosuid,size=1024m',\n      '-e',\n      'K=V',\n      'image:tag',\n",
     "      '/tmp:rw,noexec,nosuid,size=1024m',\n      '--env-file',\n      expect.stringMatching(/goodqa-envfile-[^/]+\\/env$/),\n      'image:tag',\n"),
])
print("patched")
