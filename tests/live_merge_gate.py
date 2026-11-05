"""Live check of the merge gate hook as the agent installs it.

Run on dev2 only (safety rule S2), for example:
  env -i HOME=$(mktemp -d) PATH=/usr/bin:/bin <python> tests/live_merge_gate.py --python <python>

It installs the harness into the scratch HOME (install.install), puts a fake gh first on PATH, plants a canary file,
and feeds the installed hook the payloads of tests/data/merge_gate_live.json on stdin. The payload commands are data and
are never executed. It then checks the waiver flow (single use, wrong head) and that the canary survived.
Exit 0 only when every case matches."""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HEAD = "a" * 40
OTHER = "b" * 40


def run_hook(python, script, payload, env, timeout=60):
    return subprocess.run([python, str(script), "hook"], input=json.dumps(payload).encode(), env=env,
                          capture_output=True, timeout=timeout)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--python", default=sys.executable)
    args = parser.parse_args()
    home = Path(os.environ["HOME"]).resolve()
    import pwd
    if str(home) in ("/", str(Path(pwd.getpwuid(os.getuid()).pw_dir).resolve())):
        sys.exit("refusing to run with the real HOME; use env -i HOME=$(mktemp -d)")
    sys.path.insert(0, str(ROOT))
    import install
    install.install(home, True)
    settings = json.loads((home / ".claude" / "settings.json").read_text())
    gate = [h for g in settings["hooks"]["PreToolUse"] for h in g["hooks"]
            if (h.get("args") or [""])[0].endswith("merge_gate.py")]
    assert len(gate) == 1 and gate[0]["onFailure"] == "block", gate
    script = Path(gate[0]["args"][0])
    assert script.exists() and str(script).startswith(str(home)), script
    canary = home / "canary.txt"
    canary.write_text("canary-alive\n")
    bindir = home / "bin"
    bindir.mkdir(exist_ok=True)
    fake = bindir / "gh"
    fake.write_text(f"#!/bin/sh\nexec {args.python} {ROOT / 'tests' / 'live_fake_gh.py'} \"$@\"\n")
    fake.chmod(0o755)
    env = {"HOME": str(home), "PATH": f"{bindir}:/usr/bin:/bin"}
    cases = json.loads((ROOT / "tests" / "data" / "merge_gate_live.json").read_text())["cases"]
    failures = 0
    for case in cases:
        (home / "scenario").write_text(case["scenario"])
        (home / "prviews").write_text("0")
        payload = {"tool_name": "Bash", "tool_input": {"command": case["command"].replace("{HEAD}", HEAD)},
                   "cwd": str(home), "session_id": "live-check"}
        result = run_hook(args.python, script, payload, env)
        ok = result.returncode == case["expect"] and canary.read_text() == "canary-alive\n"
        failures += not ok
        print(("PASS" if ok else "FAIL"), case["id"], "exit", result.returncode, "want", case["expect"],
              "|", result.stderr.decode().strip().splitlines()[:1])
    # Waiver flow: red merge blocked, waived once, replay blocked, other head blocked.
    state = home / ".agent-harness" / "state"
    (home / "scenario").write_text("red_netwatch")
    cmd = f"gh pr merge 5 -R o/r --match-head-commit {HEAD}"
    payload = {"tool_name": "Bash", "tool_input": {"command": cmd}, "cwd": str(home), "session_id": "live-check"}
    waive = subprocess.run([args.python, str(script), "waive", "--state-dir", str(state), "--repo", "o/r", "--pr", "5",
                            "--head", HEAD, "--ticket", "GoodQA #14502", "--reason", "live check waiver for red",
                            "--approved-by", "main:live-check"], env=env, capture_output=True)
    steps = [("waive-recorded", waive.returncode, 0)]
    for name, want in (("waived-merge-allowed", 0), ("replay-blocked", 2)):
        (home / "prviews").write_text("0")
        steps.append((name, run_hook(args.python, script, payload, env).returncode, want))
    subprocess.run([args.python, str(script), "waive", "--state-dir", str(state), "--repo", "o/r", "--pr", "5",
                    "--head", OTHER, "--ticket", "GoodQA #14502", "--reason", "waiver for another head",
                    "--approved-by", "main:live-check"], env=env, capture_output=True)
    (home / "prviews").write_text("0")
    steps.append(("other-head-waiver-blocked", run_hook(args.python, script, payload, env).returncode, 2))
    sub = dict(payload, agent_id="sub-1", tool_input={"command": f"python3 {script} waive --repo o/r --pr 5 --head {HEAD} "
                                                                f"--ticket 'GoodQA #1' --reason 'forged by subagent'"})
    steps.append(("subagent-waive-blocked", run_hook(args.python, script, sub, env).returncode, 2))
    report = subprocess.run([args.python, str(script), "report", "--state-dir", str(state)], env=env, capture_output=True)
    steps.append(("report-lists-used", 0 if b"used" in report.stdout and b"asserted" in report.stdout else 1, 0))
    for name, got, want in steps:
        ok = got == want and canary.read_text() == "canary-alive\n"
        failures += not ok
        print(("PASS" if ok else "FAIL"), name, "exit", got, "want", want)
    if canary.read_text() != "canary-alive\n":
        failures += 1
    print("canary", "alive" if canary.exists() else "MISSING", "failures", failures, "python", args.python)
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
