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


MAX_JSON_BYTES = 4_000_000


def load_json(path: Path):
    """Bounded read of a regular file (settings, manifest, rules); anything oversized or not a regular file is a ValueError."""
    sys.path.insert(0, str(HERE))
    import safe_input
    try:
        return safe_input.safe_json_loads(safe_input.read_bounded(path, MAX_JSON_BYTES))
    except safe_input.InputRejected as exc:
        raise ValueError(f"{path}: {exc.message}") from None


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
    """Claude Code semantics: empty or * matches every tool; otherwise the matcher is a regex that must match the
    whole tool name (so a plain name is an exact match and 'Ba' does not cover 'Bash')."""
    if matcher in (None, "", "*"):
        return True
    try:
        rx = re.compile(matcher)
    except re.error:
        return False
    return all(rx.fullmatch(t) for t in tools)


def is_interpreter(tok: str) -> bool:
    return re.fullmatch(r"python[0-9.]*", Path(tok).name) is not None


def wired_path_ok(toks: list[str], script: str, arg, hooks_dir: Path) -> bool:
    """The handler must run an interpreter on exactly hooks_dir/script (then arg), not merely mention its name."""
    want = os.path.normpath(str(hooks_dir / script))
    if not toks or not is_interpreter(toks[0]):
        return False
    i = 1
    while i < len(toks) and toks[i].startswith("-"):
        i += 1
    if i >= len(toks) or os.path.normpath(os.path.expanduser(toks[i])) != want:
        return False
    rest = toks[i + 1:]
    return rest == [] if arg is None else rest[:1] == [arg]


def find_hook(hooks: dict, event: str, script: str, arg, tools: list[str], hooks_dir: Path):
    for group in hooks.get(event, []) or []:
        if not isinstance(group, dict) or not matcher_covers(group.get("matcher"), tools):
            continue
        for handler in group.get("hooks", []) or []:
            if (isinstance(handler, dict) and handler.get("type", "command") == "command"
                    and wired_path_ok(flatten(handler), script, arg, hooks_dir)):
                return handler
    return None


def expected(manifest: dict, flavor: str, claude_dir: Path) -> list[dict]:
    """Expected hooks for 'claude' or 'codex': the manifest rows whose flavors include it. The manifest is the single
    list; tests/test_doctor.py proves it covers everything install.py and install_codex.py write."""
    return [row for row in manifest["hooks"] if flavor in row["flavors"]]


def run_canary(row: dict, script_path: Path) -> tuple[bool, str]:
    """Every canary payload goes to the hook on stdin under a scratch HOME. A deny is a deny decision in stdout or
    exit 2; a crash (Traceback, usage error, any other exit code) satisfies neither an allow nor a deny canary."""
    canaries = row.get("canaries") or []
    if not canaries:
        return True, "no canary"
    notes = []
    for canary in canaries:
        with tempfile.TemporaryDirectory(prefix="doctor-home-") as home:
            env = {"HOME": home, "PATH": "/usr/bin:/bin:/usr/local/bin", "LANG": "C.UTF-8"}
            argv = ["python3", "-I", str(script_path)] + ([row["arg"]] if row.get("arg") else [])
            try:
                r = subprocess.run(argv, input=json.dumps(canary["payload"]), capture_output=True, text=True,
                                   timeout=30, env=env, cwd=home)
            except (OSError, subprocess.TimeoutExpired) as exc:
                return False, f"canary could not run: {type(exc).__name__}"
        out = r.stdout + r.stderr
        crashed = "Traceback" in out or "usage:" in out.lower() or r.returncode not in (0, 2)
        denied = ('"permissionDecision": "deny"' in r.stdout.replace('":"', '": "')) or r.returncode == 2
        want_deny = canary.get("expect") == "deny"
        ok = not crashed and denied == want_deny
        notes.append(f"rc={r.returncode} denied={denied} want={'deny' if want_deny else 'allow'}")
        if not ok:
            return False, "; ".join(notes) + (" (crashed)" if crashed else "")
    return True, "; ".join(notes)


def check_hooks(manifest: dict, flavor: str, live: dict, hooks_dir: Path, canary: bool = True, exists=None) -> list[dict]:
    hooks = live.get("hooks", {}) if isinstance(live, dict) else {}
    disabled = isinstance(live, dict) and live.get("disableAllHooks") is True
    out = []
    for row in expected(manifest, flavor, hooks_dir.parent):
        found = None if disabled else find_hook(hooks, row["event"], row["script"], row.get("arg"),
                                                row.get("tools", []), hooks_dir)
        script = hooks_dir / row["script"]
        if found is None:
            state = PENDING if row["status"] == "pending" else MISSING
            detail = "disableAllHooks is true in this settings file" if disabled else "not in live hooks (or wired to another path/interpreter)"
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


HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def check_host(host: str) -> str:
    if not HOST_RE.match(host):
        raise OSError("invalid ssh host name")
    return host


def remote_home(ssh: str) -> str:
    r = subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", "--", check_host(ssh),
                        'printf "%s" "$HOME"'], capture_output=True, text=True, timeout=30)
    home = r.stdout.strip()
    if r.returncode != 0 or not home.startswith("/"):
        raise OSError(f"ssh {ssh} home lookup failed")
    return home


def remote_path(ssh: str, path: str) -> str:
    """Absolute path on the remote host: a leading ~ means the REMOTE home, never the local one."""
    if path == "~" or path.startswith("~/"):
        return remote_home(ssh) + path[1:]
    return path


def read_live(path: str, ssh: str | None) -> dict:
    if ssh:
        # `head -c cap+1` keeps the remote read bounded (a remote /dev/zero or huge file cannot fill local memory);
        # one byte over the cap is refused, and parsing goes through the same depth/size checks as a local read.
        r = subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", "--", check_host(ssh),
                            "head", "-c", str(MAX_JSON_BYTES + 1), "--", shlex.quote(path)],
                           capture_output=True, timeout=30)
        if r.returncode != 0:
            raise OSError(f"ssh {ssh} read failed rc={r.returncode}")
        if len(r.stdout) > MAX_JSON_BYTES:
            raise ValueError(f"{path}: remote file is larger than {MAX_JSON_BYTES} bytes")
        sys.path.insert(0, str(HERE))
        import safe_input
        return safe_input.safe_json_loads(r.stdout)
    return load_json(Path(path).expanduser())


def remote_names(ssh: str, path: str) -> set[str]:
    r = subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", "--", check_host(ssh),
                        "ls", shlex.quote(path)],
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
            if not wired:
                state = "NOT-ENFORCED"
            elif mode != "enforce":
                state = "ALERT-ONLY"
            else:
                state = "PARTIAL" if rule.get("partial_reason") else "ENFORCED"
            if wired and rule.get("static_mode") == "warn":
                state = "ALERT-ONLY"  # the hook can only warn by design
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
    r.add_argument("--canary", action="store_true", help="also run canaries (default: wiring only)")
    r.add_argument("--fail-on-p0", action="store_true", help="exit 1 when any P0 rule is not ENFORCED/PARTIAL")
    a = ap.parse_args(argv)
    try:
        manifest = load_json(MANIFEST)
    except (OSError, ValueError) as exc:
        print(f"doctor: cannot read {MANIFEST}: {type(exc).__name__}: {str(exc)[:200]}", file=sys.stderr)
        return 2
    ssh = getattr(a, "ssh", None)
    try:
        if ssh:
            a.settings, a.hooks_dir = remote_path(ssh, a.settings), remote_path(ssh, a.hooks_dir)
        live = read_live(a.settings, ssh)
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        print(f"doctor: cannot read {a.settings}: {type(exc).__name__}: {str(exc)[:200]}", file=sys.stderr)
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
    findings = check_hooks(manifest, "claude", live, hooks_dir, canary=a.canary)
    try:
        rules = load_json(RULES)
    except (OSError, ValueError) as exc:
        print(f"doctor: cannot read {RULES}: {type(exc).__name__}: {str(exc)[:200]}", file=sys.stderr)
        return 2
    rows = rules_report(rules, findings, hooks_dir)
    for row in rows:
        print(f"{row['state']:13} {row['priority']} {row['id']} {row['planned']}")
    p0_gaps = [x["id"] for x in rows if x["priority"] == "P0" and x["state"] in ("NOT-ENFORCED", "PLANNED", "UNMAPPED")]
    print(f"P0 gaps: {', '.join(p0_gaps) or 'none'}")
    if any(x["state"] == "UNMAPPED" for x in rows):
        return 1
    return 1 if (a.fail_on_p0 and p0_gaps) else 0


if __name__ == "__main__":
    sys.exit(main())
