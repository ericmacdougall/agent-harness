"""goodqa#16148 AC-8/P3: index.ts takes the --boot-check path from argv before building any server. Run in apps/job-dispatcher.
The normal start is unchanged: the same loadConfig, buildServer, main and failure handler, now inside the else branch."""
p = 'src/index.ts'
s = open(p).read()
edits = [
    ("import { loadConfig } from './config';\n",
     "import { isBootCheck, runBootCheck } from './boot-check';\nimport { loadConfig, type Config } from './config';\n"),
    ("const config = loadConfig();\nconst app = buildServer(config);\n\nasync function main(): Promise<void> {\n",
     "async function main(config: Config, app: ReturnType<typeof buildServer>): Promise<void> {\n"),
    ("main().catch((error) => {\n  app.log.error(error, 'job-dispatcher failed to start');\n  process.exit(1);\n});\n",
     "// goodqa#16148 AC-8 / P3: rw-ship's isolated trial boot. Selected by the CLI argument only (never env), so a serving\n"
     "// container cannot enter it; it prints the JOB_ENVFILE status lines and exits without a server, port or docker.\n"
     "if (isBootCheck(process.argv.slice(2))) {\n"
     "  process.exitCode = runBootCheck(process.env, (line) => process.stdout.write(`${line}\\n`));\n"
     "} else {\n"
     "  const config = loadConfig();\n"
     "  const app = buildServer(config);\n"
     "  main(config, app).catch((error) => {\n"
     "    app.log.error(error, 'job-dispatcher failed to start');\n"
     "    process.exit(1);\n"
     "  });\n"
     "}\n"),
]
for o, n in edits:
    assert s.count(o) == 1, o[:60]
    s = s.replace(o, n)
open(p, 'w').write(s)
print('patched')
