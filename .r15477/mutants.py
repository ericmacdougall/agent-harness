"""goodqa#15477 rescue mutants: each edits host.ts, runs the unit tests and the real-Electron tests, then restores."""
import json, pathlib, re, subprocess, sys

D = pathlib.Path.home() / "wt-15477-rescue/apps/desktop"
HOST = D / "src/agent-browser/host.ts"
OUT = pathlib.Path.home() / "rt-15477-rescue/mutants"
OUT.mkdir(exist_ok=True)
orig = HOST.read_text()

MUTANTS = {
    "M1_no_unload_override": ("    contents.on('will-prevent-unload', allowUnload);\n", ""),
    "M2_no_blank_fallback": ("      const second = await step('about:blank');", "      const second = 'skipped';"),
    "M3_indicator_early": ("    const token = Symbol('revocation');\n", "    const token = Symbol('revocation');\n    t.media = false;\n"),
    "M4_swallow_failures": ("    const log = (at: string, code: string) =>\n      console.error(`[agent-browser] revoke_failed id=${t.id} reason=${reason} step=${at} code=${code}`);",
                            "    const log = (_at: string, _code: string) => {};"),
    "M5_override_leaks": ("      contents.removeListener('will-prevent-unload', allowUnload);\n", ""),
    "M6_no_bound": ("      const timer = setTimeout(() => done('timeout'), REVOKE_STEP_MS);", "      const timer = setTimeout(() => done('timeout'), 60000);"),
    "M7_old_freshdocument": ("  private freshDocument(t: Tab, reason: string): void {\n",
                             "  private freshDocument(t: Tab, reason: string): void {\n    if (reason) { const c = t.view.webContents; if (!c.isDestroyed()) void c.loadURL(c.getURL()).catch(() => {}); return; }\n"),
}

def run(cmd, log):
    with open(log, "w") as f:
        return subprocess.run(cmd, cwd=D, stdout=f, stderr=subprocess.STDOUT, timeout=900).returncode

def counts(log):
    s = re.sub(r"\x1b\[[0-9;]*m", "", pathlib.Path(log).read_text())
    m = re.findall(r"Tests\s+(.*)", s)
    return m[-1].strip() if m else "no summary"

only = sys.argv[1:]
results = {}
try:
    for name, (old, new) in MUTANTS.items():
        if only and name not in only:
            continue
        assert orig.count(old) == 1, name
        HOST.write_text(orig.replace(old, new))
        unit_log = OUT / f"{name}-unit.log"
        rc_unit = run(["npx", "vitest", "run", "src/agent-browser/host.test.ts"], unit_log)
        rc_build = run(["pnpm", "run", "build"], OUT / f"{name}-build.log")
        real_log = OUT / f"{name}-real.log"
        rc_real = run(["xvfb-run", "-a", "npx", "vitest", "run", "src/agent-browser/revocation-capture.test.ts"], real_log) if rc_build == 0 else None
        results[name] = {"unit_rc": rc_unit, "unit": counts(unit_log), "build_rc": rc_build, "real_rc": rc_real, "real": counts(real_log) if rc_real is not None else None,
                         "killed": rc_unit != 0 or (rc_real not in (0, None))}
        print(name, json.dumps(results[name]), flush=True)
finally:
    HOST.write_text(orig)
    subprocess.run(["pnpm", "run", "build"], cwd=D, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
(OUT / "summary.json").write_text(json.dumps(results, indent=1))
