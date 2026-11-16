"""goodqa#16148 code review F4: cut the redacted first line to SCAN_LIMIT before the scans. Run in apps/job-dispatcher."""
p = 'src/docker.ts'
s = open(p).read()
old1 = "const MAX_LINE = 200;\n"
new1 = ("const MAX_LINE = 200;\n"
        "/**\n"
        " * Only this much of the (already redacted) first line is scanned for residue, so a 1 MiB stderr line\n"
        " * cannot stall the event loop (code review F4). Anything past it can never reach the 200-char output.\n"
        " */\n"
        "const SCAN_LIMIT = 4096;\n")
old2 = "  const line = (redacted.split('\\n', 1)[0] ?? '').replace(/\\r$/, '').trimEnd();\n"
new2 = "  const line = (redacted.split('\\n', 1)[0] ?? '').replace(/\\r$/, '').trimEnd().slice(0, SCAN_LIMIT);\n"
for o, n in ((old1, new1), (old2, new2)):
    assert s.count(o) == 1, o
    s = s.replace(o, n)
open(p, 'w').write(s)
print('patched')
