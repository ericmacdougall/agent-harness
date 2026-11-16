"""goodqa#16148 step 2b: JOB_ENVFILE wiring. Run from apps/job-dispatcher."""


def edit(path, pairs):
    s = open(path).read()
    for old, new in pairs:
        assert s.count(old) == 1, (path, old[:90])
        s = s.replace(old, new)
    open(path, "w").write(s)


edit("src/config.ts", [
    ("export type Config = z.infer<typeof envSchema> & {\n  jobImages: Record<JobKind, string>;\n  jobBaseEnv: Record<JobKind, Record<string, string>>;\n};\n",
     "export type Config = z.infer<typeof envSchema> & {\n  jobImages: Record<JobKind, string>;\n  jobBaseEnv: Record<JobKind, Record<string, string>>;\n"
     "  /** goodqa#16148 AC-4: allow-listed JOB_ENVFILE_KIND__VAR keys (paths only; files are read per launch). */\n"
     "  jobEnvFiles: JobEnvFiles;\n"
     "  /** The only directory a JOB_ENVFILE path may live in. Compiled, never read from the env. */\n"
     "  jobEnvFileDir: string;\n};\n"),
    ("  return { ...parsed, jobImages, jobBaseEnv };\n",
     "  return { ...parsed, jobImages, jobBaseEnv, jobEnvFiles: parseJobEnvFiles(env), jobEnvFileDir: JOB_ENVFILE_DIR };\n"),
])
s = open("src/config.ts").read()
first_import = s.index("import ")
s = s[:first_import] + "import { JOB_ENVFILE_DIR, parseJobEnvFiles, type JobEnvFiles } from './job-env-file';\n" + s[first_import:]
open("src/config.ts", "w").write(s)

edit("src/server.ts", [
    ("    for (const [key, value] of Object.entries(config.jobBaseEnv[kind])) {\n      const problem = envEntryProblem(key, value);\n",
     "    // goodqa#16148 AC-4/AC-5: file-backed env, read now (per launch); a failure is per kind and\n"
     "    // definitive (501, docker never called), logged with the key name and reason only.\n"
     "    const fileEnv = resolveJobEnvFiles(config.jobEnvFiles, config.jobEnvFileDir, kind, config.jobBaseEnv[kind]);\n"
     "    if (!fileEnv.ok) {\n"
     "      req.log.error({ jobKind: kind }, fileEnv.error);\n"
     "      return reply.code(501).send({ error: fileEnv.error });\n"
     "    }\n"
     "    const baseEnv = { ...config.jobBaseEnv[kind], ...fileEnv.env };\n"
     "    for (const [key, value] of Object.entries(baseEnv)) {\n      const problem = envEntryProblem(key, value);\n"),
    ("    const mergedEnv = { ...config.jobBaseEnv[kind], ...validation.env };\n",
     "    const mergedEnv = { ...baseEnv, ...validation.env };\n"),
    ("        Object.values(config.jobBaseEnv[kind]),\n",
     "        Object.values(baseEnv),\n"),
])
s = open("src/server.ts").read()
first_import = s.index("import ")
s = s[:first_import] + "import { resolveJobEnvFiles } from './job-env-file';\n" + s[first_import:]
open("src/server.ts", "w").write(s)

edit("src/index.ts", [
    ("import { sweepStaleEnvFileDirs } from './docker';\n",
     "import { sweepStaleEnvFileDirs } from './docker';\nimport { bootEnvFileStatusLines } from './job-env-file';\n"),
    ("  app.log.info({ removed: sweepStaleEnvFileDirs() }, 'job-dispatcher: swept stale env-file dirs');\n",
     "  app.log.info({ removed: sweepStaleEnvFileDirs() }, 'job-dispatcher: swept stale env-file dirs');\n"
     "  // goodqa#16148 AC-5: one status line per JOB_ENVFILE key (names and status only); rw-ship's\n"
     "  // unhold gate reads `job env file KIND__VAR: ok` from this container's log. Never fails boot.\n"
     "  for (const line of bootEnvFileStatusLines(config)) app.log.info(line);\n"),
])
print("patched")
