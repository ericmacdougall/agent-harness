#!/usr/bin/env python3
"""AC-7 live check for the checkout registry (goodqa#16947, spec v3.2).

Runs three disposable `claude -p` sessions that load this checkout's registry hooks (and a payload capture hook) through
`--settings`, IN ADDITION to the user's own settings and guard hooks, which stay active. Everything happens in
`mktemp -d $HOME/streamd-live.XXXXXX`: a small source repo, the clones and worktrees the sessions make, and the captured
payloads. The user's settings files are not changed.

Expected rows (each exactly one): a main-session clone; `git clone ... && false`; a subagent clone; a subagent
`git -C REPO worktree add`; two isolation worktrees (one whose subagent makes one tool call and stops). No row, with a
reason code: a clone into a path that already exists (`existed-at-pre`); a clone a deny rule refuses.

Recorded facts: which event fires for a non-zero Bash exit; the form of a subagent's `transcript_path` in its Pre and
Post payloads; the PreToolUse `cwd` after a `cd` in an earlier call; whether PermissionDenied fired for the deny rule.

Afterwards the disposable folder is removed, `checkout_registry.py retire --path P` retires each row (Rule 14), and the
listing must show no row held under the folder. The receipt (counts, codes and facts; no ids, no command output) and
redacted payload fixtures go to RECEIPT_DIR.

    python3 -I tests/live/checkout_registry_live.py RECEIPT_DIR [--claude PATH] [--model MODEL]

Cost: three short sessions on the subscription, each under `timeout 300`.

Exit 0 PASS, 1 FAIL, 2 BLOCKED. BLOCKED means a session did not run (an account limit, for one) or the user's own
guards refused a clone before it ran (copy_hygiene's free-disk floor, for one); the checks then prove nothing and the
receipt lists the reason in `blocked_by`. The kit never works around such a refusal.
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
REG = os.path.join(ROOT, "harness", "hooks", "checkout_registry.py")
CAPTURE = os.path.join(ROOT, "tests", "live", "capture_payload.py")
EVENTS = (("PreToolUse", ".*", "pretool"), ("PostToolUse", "Bash", "posttool"),
          ("PostToolUseFailure", "Bash", "posttool-failure"), ("PermissionDenied", "Bash", "denied"),
          ("SubagentStart", ".*", "subagent-start"), ("SubagentStop", ".*", "subagent-stop"))
GIT_ENV = {"GIT_AUTHOR_NAME": "live", "GIT_AUTHOR_EMAIL": "live@example.invalid", "GIT_COMMITTER_NAME": "live",
           "GIT_COMMITTER_EMAIL": "live@example.invalid"}


def settings(payloads: str) -> dict:
    hooks = {}
    for event, matcher, verb in EVENTS:
        hooks[event] = [{"matcher": matcher, "hooks": [
            {"type": "command", "command": "python3", "args": [CAPTURE, event, payloads], "timeout": 10},
            {"type": "command", "command": "python3", "args": [REG, "hook", verb],
             "timeout": 20 if event.startswith("Subagent") else 10}]}]
    return {"hooks": hooks}


def registry(*args) -> dict:
    r = subprocess.run([sys.executable, REG, *args], capture_output=True, text=True, timeout=60)
    return json.loads(r.stdout or "{}")


def run_session(claude: str, model: str, cwd: str, live: str, live_settings: str, prompt: str, deny: list) -> dict:
    """Run one session. Returns its exit code and the commands Claude Code itself refused (from the JSON result), so a
    missing row can be told apart from a command that never ran."""
    allowed = ["Bash(git clone:*)", "Bash(git -C:*)", "Bash(cd:*)", "Bash(pwd)", "Bash(ls:*)", "Bash(false)", "Agent"]
    cmd = [claude, "-p", prompt, "--settings", live_settings, "--model", model, "--output-format", "json",
           "--add-dir", live, "--allowedTools", *allowed]
    if deny:
        cmd += ["--disallowedTools", *deny]
    r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=300, stdin=subprocess.DEVNULL)
    try:
        result = json.loads(r.stdout or "{}")
    except ValueError:
        result = {}
    denied = [((d.get("tool_input") or {}).get("command") or d.get("tool_name") or "?")
              for d in result.get("permission_denials") or [] if isinstance(d, dict)]
    return {"exit": r.returncode, "is_error": bool(result.get("is_error")), "permission_denials": denied,
            "result_excerpt": str(result.get("result") or "")[:600]}


def redact(obj, live: str, ids: dict):
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if k in ("session_id", "agent_id", "tool_use_id") and isinstance(v, str):
                out[k] = ids.setdefault(v, "%s-%d" % (k.split("_")[0], len(ids) + 1))
            else:
                out[k] = redact(v, live, ids)
        return out
    if isinstance(obj, list):
        return [redact(v, live, ids) for v in obj]
    if isinstance(obj, str):
        s = obj.replace(live, "/HOME/live")
        s = s.replace(os.path.expanduser("~"), "/HOME")
        for real, fake in ids.items():
            s = s.replace(real, fake)
        return s
    return obj


def transcript_form(tp) -> str:
    if not isinstance(tp, str):
        return "missing"
    if re.search(r"/subagents/agent-[^/]+\.jsonl$", tp):
        return "subagent"
    if re.search(r"/projects/[^/]+/[^/]+\.jsonl$", tp):
        return "main"
    return "other"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("receipt_dir")
    ap.add_argument("--claude", default=shutil.which("claude") or os.path.expanduser("~/.local/bin/claude"))
    ap.add_argument("--model", default="sonnet")
    a = ap.parse_args()
    os.makedirs(a.receipt_dir, mode=0o700, exist_ok=True)
    live = os.path.realpath(tempfile.mkdtemp(prefix="streamd-live.", dir=os.path.expanduser("~")))
    payloads = os.path.join(live, "payloads.jsonl")
    src = os.path.join(live, "src")
    env = dict(os.environ, **GIT_ENV)
    subprocess.run(["git", "init", "-q", "-b", "main", src], check=True, env=env)
    with open(os.path.join(src, "README"), "w") as fh:
        fh.write("live check\n")
    subprocess.run(["git", "-C", src, "add", "README"], check=True, env=env)
    subprocess.run(["git", "-C", src, "commit", "-q", "-m", "live"], check=True, env=env)
    exists = os.path.join(live, "c-exists")
    subprocess.run(["git", "clone", "-q", src, exists], check=True, env=env)
    live_settings = os.path.join(live, "LIVE.json")
    with open(live_settings, "w") as fh:
        json.dump(settings(payloads), fh)
    decisions = os.path.expanduser("~/.agent-harness/state/checkouts/decisions.jsonl")
    start = os.path.getsize(decisions) if os.path.exists(decisions) else 0
    t0 = time.time()

    p = {"src": src, "live": live}
    sessions = [
        ("main", [], "Run these Bash commands one at a time, each as its own Bash tool call, in this order, and do "
                     "nothing else. Do not fix or retry failures.\n"
                     "1. git clone {src} {live}/c-main\n2. git clone {src} {live}/c-fail && false\n"
                     "3. git clone {src} {live}/c-exists\n4. git clone {src} {live}/c-denied\n5. cd {live}\n6. pwd"),
        ("subagent", [], "Use the Agent tool once, with subagent_type general-purpose, and tell the subagent to run "
                         "exactly these two Bash commands, each as its own Bash call, and nothing else:\n"
                         "1. git clone {src} {live}/c-sub\n2. git -C {src} worktree add {live}/wt-sub -b live-sub\n"
                         "Do nothing else yourself."),
        ("isolation", [], "Use the Agent tool twice, one after the other, each with isolation set to worktree and "
                          "subagent_type general-purpose. Tell the first subagent to run `pwd` and then `ls`, as two "
                          "separate Bash calls. Tell the second subagent to run only `pwd`. Do nothing else yourself."),
    ]
    deny = ["Bash(git clone {src} {live}/c-denied)".format(**p)]
    codes = {}
    for name, _, prompt in sessions:
        codes[name] = run_session(a.claude, a.model, src, live, live_settings, prompt.format(**p),
                                  deny if name == "main" else [])

    listing = registry("list").get("local", {})
    rows = [r for r in listing.get("rows", []) if r.get("event") == "created" and r.get("created_at", "") >= time.strftime(
        "%Y-%m-%dT%H:%M:%SZ", time.gmtime(t0 - 1)) and r.get("path", "").startswith(live + "/")]
    by_path = {}
    for r in rows:
        by_path.setdefault(os.path.relpath(r["path"], live), []).append(r)
    new_codes = []
    if os.path.exists(decisions):
        with open(decisions, "rb") as fh:
            fh.seek(start)
            for line in fh.read().decode("utf-8", "replace").splitlines():
                try:
                    d = json.loads(line)
                except ValueError:
                    continue
                if live in json.dumps(d) or d.get("code", "").startswith("iso-"):
                    new_codes.append((d.get("code"), os.path.relpath(d["path"], live) if d.get("path", "").startswith(
                        live) else None))
    captured = []
    if os.path.exists(payloads):
        with open(payloads) as fh:
            captured = [json.loads(l) for l in fh if l.strip()]

    def cmd_of(c):
        return ((c["payload"].get("tool_input") or {}).get("command") or "")
    fail_events = sorted({c["event"] for c in captured if c["event"].startswith("PostToolUse") and "c-fail" in cmd_of(c)})
    sub_forms = sorted({"%s:%s" % (c["event"], transcript_form(c["payload"].get("transcript_path"))) for c in captured
                        if c["payload"].get("agent_id") and c["event"] in ("PreToolUse", "PostToolUse")})
    pwd_cwd = [c["payload"].get("cwd") for c in captured if c["event"] == "PreToolUse" and cmd_of(c).strip() == "pwd"
               and not c["payload"].get("agent_id")]
    denied_fired = any(c["event"] == "PermissionDenied" and "c-denied" in cmd_of(c) for c in captured)
    iso = [k for k in by_path if k.startswith("src/.claude/worktrees/agent-")]
    checks = {
        "main clone: one row": len(by_path.get("c-main", [])) == 1,
        "clone && false: one row": len(by_path.get("c-fail", [])) == 1,
        "existing path: no row": "c-exists" not in by_path and ("existed-at-pre", "c-exists") in new_codes,
        "denied clone: no row": "c-denied" not in by_path and not os.path.exists(os.path.join(live, "c-denied")),
        "subagent clone: one row with an agent": [bool(r.get("agent")) for r in by_path.get("c-sub", [])] == [True],
        "subagent worktree add: one row with an agent": [r.get("kind") for r in by_path.get("wt-sub", [])] == ["worktree"],
        "isolation worktrees: two rows": len(iso) == 2 and all(len(by_path[k]) == 1 for k in iso),
    }
    events_by_target = {}
    for c in captured:
        m = re.search(re.escape(live) + r"/((?:c|wt)-[a-z]+)\b", cmd_of(c))
        if m:
            events_by_target.setdefault(m.group(1), set()).add(c["event"])
    fixtures = {}
    ids = {}
    for c in captured:
        fixtures.setdefault(c["event"], []).append(redact(c["payload"], live, ids))
    with open(os.path.join(a.receipt_dir, "live-payload-fixtures.json"), "w") as fh:
        json.dump(fixtures, fh, indent=1, sort_keys=True)

    shutil.rmtree(live)                                          # the kit's own disposable folder, nothing else
    retired = sum(registry("retire", "--path", r["path"]).get("retired", 0) for r in rows)
    still = [r for r in registry("list").get("local", {}).get("rows", []) if r.get("path", "").startswith(live + "/")]
    held_after = sum(1 for r in still if r.get("event") == "created") - sum(1 for r in still if r.get("event") == "removed")
    checks["cleanup: no row held under the folder"] = held_after == 0
    receipt = {
        "host": os.uname().nodename.split(".")[0], "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "sessions": {k: dict(v, permission_denials=[redact(x, live, {}) for x in v["permission_denials"]],
                             result_excerpt=redact(v["result_excerpt"], live, {})) for k, v in codes.items()},
        "hook events per target": {k: sorted(v) for k, v in sorted(events_by_target.items())},
        "rows_by_path": {k: len(v) for k, v in by_path.items()},
        "codes": sorted({"%s %s" % (c, p or "") for c, p in new_codes}),
        "facts": {"event for a non-zero Bash exit": fail_events, "subagent transcript_path form": sub_forms,
                  "PreToolUse cwd after an earlier cd": [redact(x, live, {}) for x in pwd_cwd],
                  "PermissionDenied fired for the deny rule": denied_fired},
        "checks": checks, "retired": retired,
    }
    # A check over commands that never ran proves nothing either way: report BLOCKED with the reason, never PASS/FAIL.
    blocked = ["session %s did not run (%s)" % (k, redact(v["result_excerpt"][:120], live, {}))
               for k, v in codes.items() if v["is_error"] or v["exit"] != 0]
    blocked += ["%s refused before it ran" % redact(x, live, {}) for v in codes.values()
                for x in v["permission_denials"] if "c-denied" not in x]
    receipt["blocked_by"] = blocked
    receipt["result"] = "BLOCKED" if blocked else ("PASS" if all(checks.values()) else "FAIL")
    with open(os.path.join(a.receipt_dir, "live-receipt.json"), "w") as fh:
        json.dump(receipt, fh, indent=1, sort_keys=True)
    print(json.dumps(receipt, indent=1, sort_keys=True))
    return {"PASS": 0, "FAIL": 1}.get(receipt["result"], 2)


if __name__ == "__main__":
    sys.exit(main())
