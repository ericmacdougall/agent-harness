#!/usr/bin/env python3
"""harness doctor: is every hook we ship actually wired, and does each rule map to a live mechanism?

The 2026-11-04 incident: a command guard was written, reviewed and tested but never wired into settings.json, so
nothing stopped a recursive delete. Nothing noticed. This tool makes that visible and testable.

  check         expected hooks (what install.py would write, plus hooks_manifest.json extras) against a live
                settings.json or Codex hooks.json (local file, or read-only `ssh HOST cat PATH`).
                exit 0 all required hooks wired, 1 something required is missing, 2 settings unreadable.
  rules-report  rules.json (docs/rules/rules.json) joined with `check`: ENFORCED / ALERT-ONLY / NOT-ENFORCED /
                ADVISORY per rule. exit 1 if a rule has no mechanism mapping and is not marked advisory.

Read-only: never writes a settings file, never runs a hook script except a data canary under a scratch HOME.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
MANIFEST = HERE / "hooks_manifest.json"
RULES = HERE / "rules.json"

WIRED, MISSING, SCRIPT_MISSING, PENDING, CANARY_FAIL = "WIRED", "MISSING", "SCRIPT_MISSING", "PENDING", "CANARY_FAIL"


def load_json(path: Path):
    return json.loads(path.read_text())


def flatten(handler: dict) -> list[str]:
    """Token list of a hook handler whether it is {command, args} (Claude Code) or one command string (Codex)."""
    cmd = handler.get("command", "")
    args = handler.get("args")
    if args:
        return [cmd, *[str(a) for a in args]]
    try:
        return shlex.split(cmd)
    except ValueError:
        return [cmd]


def matcher_covers(matcher, tools: list[str]) -> bool:
    if not matcher:
        return True
    try:
        rx = re.compile(matcher)
    except re.error:
        return False
    return all(rx.search(t) for t in tools)


def find_hook(hooks: dict, event: str, script: str, arg: str | None, tools: list[str]):
    """Return the matching handler or None. The script is matched by file name so ~ and absolute paths agree."""
    for group in hooks.get(event, []) or []:
        if not isinstance(group, dict) or not matcher_covers(group.get("matcher"), tools):
            continue
        for handler in group.get("hooks", []) or []:
            if not isinstance(handler, dict):
                continue
            toks = flatten(handler)
            if any(Path(t).name == script for t in toks) and (arg is None or arg in toks):
                return handler
    return None


def expected(manifest: dict, flavor: str, claude_dir: Path) -> list[dict]:
    """Expected hooks for 'claude' or 'codex': the manifest rows whose flavors include it. The manifest is the single
    list; tests/test_doctor.py proves it covers everything install.py and install_codex.py write."""
    return [row for row in manifest["hooks"] if flavor in row["flavors"]]


def run_canary(row: dict, script_path: Path) -> tuple[bool, str]:
    canary = row.get("canary")
    if not canary:
        return True, "no canary"
    with tempfile.TemporaryDirectory(prefix="doctor-home-") as home:
        env = {"HOME": home, "PATH": "/usr/bin:/bin:/usr/local/bin", "LANG": "C.UTF-8"}
        argv = ["python3", "-I", str(script_path)] + ([row["arg"]] if row.get("arg") else [])
        try:
            r = subprocess.run(argv, input=json.dumps(canary["payload"]), capture_output=True, text=True,
                               timeout=30, env=env, cwd=home)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return False, f"canary could not run: {type(exc).__name__}"
        denied = '"deny"' in r.stdout or r.returncode == 2
        want_deny = canary.get("expect") == "deny"
        ok = denied == want_deny and r.returncode in (0, 2)
        return ok, f"rc={r.returncode} denied={denied} expected={'deny' if want_deny else 'allow'}"


def check_hooks(manifest: dict, flavor: str, live: dict, hooks_dir: Path, canary: bool = True, exists=None) -> list[dict]:
    hooks = live.get("hooks", {}) if isinstance(live, dict) else {}
    out = []
    for row in expected(manifest, flavor, hooks_dir.parent):
        found = find_hook(hooks, row["event"], row["script"], row.get("arg"), row.get("tools", []))
        script = hooks_dir / row["script"]
        if found is None:
            state = PENDING if row["status"] == "pending" else MISSING
            detail = "not in live hooks"
        elif not (exists(row["script"]) if exists else script.exists()):
            state, detail = SCRIPT_MISSING, f"wired but {script} does not exist (hook would exit 0 silently)"
        else:
            state, detail = WIRED, "wired"
            if canary:
                ok, info = run_canary(row, script)
                if not ok:
                    state, detail = CANARY_FAIL, info
        out.append({"id": row["id"], "state": state, "detail": detail, "required": row["status"] == "installed",
                    "owner": row.get("owner", ""), "rules": row.get("rules", [])})
    return out


def read_live(path: str, ssh: str | None) -> dict:
    if ssh:
        r = subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", ssh, "cat", path],
                           capture_output=True, text=True, timeout=30)
        if r.returncode != 0:
            raise OSError(f"ssh {ssh} cat failed rc={r.returncode}")
        return json.loads(r.stdout)
    return load_json(Path(path).expanduser())


def remote_names(ssh: str, path: str) -> set[str]:
    r = subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", ssh, "ls", path],
                       capture_output=True, text=True, timeout=30)
    if r.returncode != 0:
        raise OSError(f"ssh {ssh} ls failed rc={r.returncode}")
    return set(r.stdout.split())


def verdict(findings: list[dict]) -> int:
    return 0 if all(f["state"] == WIRED or not f["required"] for f in findings) else 1


def policy_mode(hooks_dir: Path, spec: dict | None) -> str:
    """Mode string from a policy JSON next to the hooks ('enforce' when the rule names none)."""
    if not spec:
        return "enforce"
    try:
        return str(load_json(hooks_dir / spec["file"]).get(spec["key"], "enforce"))
    except (OSError, ValueError, KeyError):
        return "unknown"


def rules_report(rules: list[dict], findings: list[dict], hooks_dir: Path) -> list[dict]:
    by_id = {f["id"]: f for f in findings}
    rows = []
    for rule in rules:
        mech = rule.get("mechanisms", [])
        if mech:
            wired = all(by_id.get(m, {"state": MISSING})["state"] == WIRED for m in mech)
            mode = policy_mode(hooks_dir, rule.get("mode"))
            state = "NOT-ENFORCED" if not wired else ("ENFORCED" if mode == "enforce" else "ALERT-ONLY")
        elif rule.get("advisory_reason"):
            state = "ADVISORY"
        elif rule.get("planned_batch"):
            state = "PLANNED"
        else:
            state = "UNMAPPED"
        rows.append({"id": rule["id"], "priority": rule.get("priority"), "state": state,
                     "planned": rule.get("planned_batch", "")})
    return rows


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check")
    c.add_argument("--flavor", choices=["claude", "codex"], default="claude")
    c.add_argument("--settings", default="~/.claude/settings.json")
    c.add_argument("--hooks-dir", default="~/.claude/hooks")
    c.add_argument("--ssh")
    c.add_argument("--no-canary", action="store_true")
    c.add_argument("--json", action="store_true")
    r = sub.add_parser("rules-report")
    r.add_argument("--settings", default="~/.claude/settings.json")
    r.add_argument("--hooks-dir", default="~/.claude/hooks")
    a = ap.parse_args(argv)
    manifest = load_json(MANIFEST)
    try:
        live = read_live(a.settings, getattr(a, "ssh", None))
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        print(f"doctor: cannot read {a.settings}: {type(exc).__name__}", file=sys.stderr)
        return 2
    hooks_dir = Path(a.hooks_dir).expanduser()
    if a.cmd == "check":
        exists = None
        if a.ssh:  # remote: names listed read-only over ssh; the canary only runs against local copies
            try:
                names = remote_names(a.ssh, a.hooks_dir)
            except (OSError, subprocess.TimeoutExpired) as exc:
                print(f"doctor: cannot list {a.hooks_dir}: {type(exc).__name__}", file=sys.stderr)
                return 2
            exists = names.__contains__
        findings = check_hooks(manifest, a.flavor, live, hooks_dir, canary=not (a.no_canary or a.ssh), exists=exists)
        if a.json:
            print(json.dumps(findings, indent=1))
        else:
            for f in findings:
                print(f"{f['state']:14} {f['id']:34} {f['detail']}")
        return verdict(findings)
    findings = check_hooks(manifest, "claude", live, hooks_dir)
    rules = load_json(RULES)
    rows = rules_report(rules, findings, hooks_dir)
    for row in rows:
        print(f"{row['state']:13} {row['priority']} {row['id']} {row['planned']}")
    return 1 if any(x["state"] == "UNMAPPED" for x in rows) else 0


if __name__ == "__main__":
    sys.exit(main())
