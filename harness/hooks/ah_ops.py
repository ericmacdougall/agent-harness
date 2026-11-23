"""`ah ops`: journaled recipes the main agent may run itself once the user has enabled self-serve (self-serve lane L3).

  ah ops merge             --pr N --receipt FILE [--repo OWNER/REPO]   merge ONE reviewed PR at its reviewed head
  ah ops repair            --ref SHA [--host t2-dev]                   install a canonical-main commit on this Mac and a host
  ah ops central-decisions --harness-pr N --harness-receipt FILE ...   merge, repair, enable, adapter, then STOP
  ah ops doctor                                                        (ah.py hands it to ah_parity.py, lane L7)

Every recipe is `--check` (read only, the default) or `--apply`, journals each step under
~/.agent-harness/work/self-serve/<run>/journal.jsonl (counts, statuses and short redacted reasons only) and is resumable with
`--resume RUN`. Every `--apply` first asks `self_serve.grant(<capability>, ...)` (lazy import). No grant, or any failure of the
policy, means a refusal that names the user's step; nothing was changed. A grant is never cached in the journal: a resume asks again.

What these recipes never do, by construction (one choke point, `Context.cmd`, refuses these words in any command it would run):
approve-top, decision keygen|pin|publish|withdraw, merge_gate waive, `gh pr merge --admin`. The user's own words for the gated
tier stay the user's: the central-decisions recipe stops and prints the one approve-top command for the user to run.

A step whose result cannot be known (lost link, timeout, a non-zero exit of the two-host install) is journaled `uncertain`,
reported as REMOTE_UNCERTAIN and never worked around: there is no local-copy path anywhere in this module.

Threat model: careless or hurried agents, not one that edits this module or the journal.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import os
import re
import shlex
import subprocess
import sys
import time
import uuid
from pathlib import Path

HARNESS_REPO = "ericmacdougall/agent-harness"
T2SCAN_REPO = "ericmacdougall/transition2-scanner"
LEDGER_PROJECT, LEDGER_NUMBER, LEDGER_ISSUE = "goodqa", 16652, "df6e5927-0772-414a-be9b-03ad45c3d608"
HOSTS = ("t2-dev", "ah-mac-mini")
CAP_MERGE, CAP_REPAIR, CAP_CENTRAL = "merge_reviewed_pr", "harness_repair", "central_decisions_agent_steps"
ENABLER = "python3 ~/.agent-harness/bin/ah_enable_self_serve.py --apply"

REF_RE = re.compile(r"[0-9a-f]{40}")
REPO_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}")
RUN_RE = re.compile(r"ops-[0-9a-f]{12}")
NAME_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]*")
USER_MSG_RE = re.compile(r"uuid:[0-9a-f-]{36}/[0-9a-f-]{36}")
ITEM_RE = re.compile(r"(executive|assurance|delivery)-synthesis:(prj_[A-Za-z0-9_-]{4,64}):(run_[A-Za-z0-9_-]{4,64}):(wrk_[A-Za-z0-9_-]{4,64})")
GOOD_CHECKS = ("SUCCESS", "NEUTRAL", "SKIPPED")
HOOK = None  # tests only: called as HOOK(step, "before"|"after"); raising from it simulates a crash at that point

# Words no command of this module may carry (the user's steps, and the waiver / admin routes). Class-level control: the one
# place commands run is Context.cmd, so a recipe added later cannot reach them without editing this list and its test.
FORBIDDEN = re.compile(r"approve-top|\bdecision\s+(keygen|pin|publish|withdraw)\b|\bwaive\b|--admin\b|\bgcloud\s+secrets\b|\bkeygen\b")
PROGRAMS = ("gh", "ssh", "python3", "repair-harness", "git")

# Constant remote programs: text never built from caller input; the values arrive as quoted arguments that were validated.
REMOTE_BLOBS = r'''import hashlib, json, os, re, sys
out = {}
for n in json.loads(sys.argv[1]):
    if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*", n) or ".." in n:
        raise SystemExit("bad name")
    p = os.path.join(os.path.expanduser("~/.claude/hooks"), n)
    if os.path.isfile(p) and not os.path.islink(p):
        d = open(p, "rb").read()
        out[n] = hashlib.sha1(b"blob %d\0" % len(d) + d).hexdigest()
    else:
        out[n] = None
print(json.dumps(out))
'''
ADAPTER_SCRIPT = r'''set -euo pipefail
merge=$1
checkout="$HOME/t2scan-runtime/t2scan"
adapter="$HOME/.config/t2/assessment-adapters/claude-assessment.py"
cd "$checkout"
[[ -z $(git status --porcelain) ]] || { echo "trusted checkout is dirty"; exit 1; }
echo "previous trusted checkout: $(git rev-parse HEAD)"
git fetch -q origin
git merge-base --is-ancestor "$merge" origin/main
git checkout -q --detach "$merge"
install -m 0700 cli/adapters/claude-assessment.py "$adapter"
cmp -s cli/adapters/claude-assessment.py "$adapter"
echo "adapter: installed from $merge"
'''
# hooks the central-decisions recipe compares byte for byte after the repair (only those the installer lists at the ref)
CENTRAL_HOOKS = ("central_decisions.py", "tier_gate.py", "provenance_hooks.py", "escalation.py", "ticket_adapters.py", "ah.py", "ah_ops.py")
REPAIR_HOOKS = ("ah.py", "ah_ops.py", "ah_install.py", "self_serve.py", "command_guard.py", "central_decisions.py")


class OpsError(Exception):
    def __init__(self, code, message, exit_code=2, data=None):
        super().__init__(message)
        self.code, self.exit_code, self.data = code, exit_code, data or {}


def refuse(message, code="refused", exit_code=2, data=None):
    raise OpsError(code, message, exit_code, data)


def uncertain(message, data=None):
    raise OpsError("remote_uncertain", "REMOTE_UNCERTAIN: " + message + " Nothing was worked around; inspect the host, then resume with --resume.", 5, data)


# ----------------------------------------------------------------------------- grants
def actor_facts(env=None):
    """What this process can say about itself. The policy library decides whether that proves main; this module only refuses the
    obvious helper (an agent id in the environment) before asking."""
    env = os.environ if env is None else env
    session = env.get("CLAUDE_CODE_SESSION_ID") or env.get("CLAUDE_SESSION_ID") or ""
    agent = env.get("AH_AGENT_ID") or env.get("CLAUDE_AGENT_ID") or ""
    harness = "claude" if session else ("codex" if any(k.startswith("CODEX_") for k in env) else "unknown")
    return {"session": session or None, "agent_id": agent or None, "harness": harness, "pid": os.getpid(), "ppid": os.getppid(),
            "entry": "ah-ops", "stdin_tty": bool(getattr(sys.stdin, "isatty", lambda: False)())}


def user_step(capability):
    return ("no self-serve grant for %s. That is the user's step: run `%s` yourself (it needs a terminal and your typed nonce), or run "
            "the underlying command yourself. Nothing was changed." % (capability, ENABLER))


def require_grant(capability, *, evidence=None, home=None, now=None, actor=None):
    """The grant for one capability, or OpsError naming the user step. self_serve is imported here, lazily and defensively: a
    missing, broken or older library is simply no grant."""
    actor = actor if actor is not None else actor_facts()
    if actor.get("agent_id"):
        refuse("a helper or sub-agent (agent id %s) cannot hold a self-serve grant for %s; the main agent runs this" % (str(actor["agent_id"])[:40], capability), "no_grant")
    try:
        module = importlib.import_module("self_serve")
        granted = module.grant(capability, actor=actor, evidence=evidence, now=now, home=str(home) if home else None)
    except Exception:  # noqa: BLE001 - the library contract says it never raises; if it does, that is no grant
        granted = None
    if not isinstance(granted, dict) or granted.get("capability") != capability:
        refuse(user_step(capability), "no_grant")
    return granted


# ----------------------------------------------------------------------------- journal
def iso(ts=None):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts if ts is not None else time.time()))


_SECRET = re.compile(r"(?i)(gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|(token|secret|password|passwd|apikey|api_key)\s*[=:]\s*\S+|Bearer\s+\S+)")


def scrub(text, limit=240):
    return _SECRET.sub("[redacted]", str(text or ""))[:limit].replace("\n", " ")


class Journal:
    """Append-only JSON lines in a private directory; each row is fsynced. A write failure raises: no step runs without its row."""

    def __init__(self, home, run=None):
        self.run = run or "ops-" + uuid.uuid4().hex[:12]
        if not RUN_RE.fullmatch(self.run):
            refuse("a run id looks like ops-0123456789ab")
        base = Path(home) / ".agent-harness" / "work" / "self-serve"
        base.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.dir = base / self.run
        self.dir.mkdir(mode=0o700, exist_ok=True)
        if self.dir.is_symlink() or self.dir.stat().st_uid != os.getuid():
            refuse("the journal directory is a symlink or belongs to another user")
        self.path = self.dir / "journal.jsonl"

    def rows(self):
        out = []
        try:
            with open(self.path, encoding="utf-8") as handle:
                for line in handle:
                    try:
                        out.append(json.loads(line))
                    except ValueError:
                        continue
        except FileNotFoundError:
            pass
        return out

    def append(self, row):
        row = dict(row, t=iso(), run=self.run)
        fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            os.write(fd, (json.dumps(row, sort_keys=True, default=str) + "\n").encode())
            os.fsync(fd)
        finally:
            os.close(fd)

    def start_row(self):
        return next((r for r in self.rows() if r.get("event") == "start"), None)

    def states(self):
        """step name -> (last state, last result) from the journal."""
        out = {}
        for r in self.rows():
            if r.get("event") == "step":
                out[r["name"]] = (r["state"], r.get("result") or {})
        return out


# ----------------------------------------------------------------------------- command choke point
def _default_runner(argv, input=None, timeout=120):
    return subprocess.run(argv, input=input, capture_output=True, text=True, timeout=timeout)


class Context:
    def __init__(self, home, runner=None, sleep=time.sleep):
        self.home = Path(home)
        self.runner = runner or _default_runner
        self.sleep = sleep
        self.results = {}

    def cmd(self, argv, *, timeout=120, input=None, what="command"):
        """The only place a command runs. Returns the completed process; a timeout is REMOTE_UNCERTAIN."""
        argv = [str(a) for a in argv]
        if not argv or os.path.basename(argv[0]) not in PROGRAMS:
            refuse("%s: %s is not a program this recipe may run" % (what, argv[:1]), "forbidden")
        if FORBIDDEN.search(" ".join(argv)):
            refuse("%s: this recipe never runs approve-top, decision keygen|pin|publish|withdraw, a waiver or an admin merge: those stay the user's" % what, "forbidden")
        try:
            return self.runner(argv, input=input, timeout=timeout)
        except subprocess.TimeoutExpired:
            uncertain("%s did not answer within %d s." % (what, timeout))
        except OSError as error:
            refuse("%s could not start (%s)" % (what, type(error).__name__), "unavailable")

    def ssh(self, host, remote, *, timeout=120, input=None, what="ssh"):
        if host not in HOSTS:
            refuse("--host must be one of %s" % ", ".join(HOSTS))
        return self.cmd(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", "--", host, remote], timeout=timeout, input=input, what=what)


def _ok(done, what, code="command_failed", write=False):
    if write and done.returncode == 255:  # ssh's own failure: the remote command may or may not have run
        uncertain("the link to the host was lost during %s." % what)
    if done.returncode != 0:
        refuse("%s failed (exit %s): %s" % (what, done.returncode, scrub(done.stderr or done.stdout)), code)
    return done


# ----------------------------------------------------------------------------- the step runner
def execute(journal, recipe, args, steps, ctx):
    """Run the steps in order. A step journaled `done` is skipped on resume unless it is an `always` step (grants are re-asked).
    `uncertain` and `failed` steps run again on resume. Stops at the first failure; returns the report dict."""
    previous = journal.states()
    if journal.start_row() is None:
        journal.append({"event": "start", "recipe": recipe, "args": args, "steps": [s[0] for s in steps]})
    summary = {}
    for name, fn, always in steps:
        state, result = previous.get(name, (None, {}))
        if state == "done" and not always:
            ctx.results[name] = result
            summary[name] = {"state": "skipped_done"}
            continue
        journal.append({"event": "step", "name": name, "state": "started"})
        if HOOK:
            HOOK(name, "before")
        try:
            result = fn(ctx) or {}
        except OpsError as error:
            state = "uncertain" if error.code == "remote_uncertain" else "failed"
            journal.append({"event": "step", "name": name, "state": state, "result": {"code": error.code, "reason": scrub(error, 400)}})
            journal.append({"event": "end", "state": state})
            return {"ok": False, "run": journal.run, "recipe": recipe, "stopped_at": name, "state": state, "code": error.code,
                    "reason": str(error), "steps": summary, "resume": "ah ops %s --resume %s" % (recipe, journal.run), "journal": str(journal.path)}
        if HOOK:
            HOOK(name, "after")
        journal.append({"event": "step", "name": name, "state": "done", "result": result})
        ctx.results[name] = result
        summary[name] = {"state": "done", **{k: v for k, v in result.items() if isinstance(v, (str, int, bool))}}
    journal.append({"event": "end", "state": "done"})
    return {"ok": True, "run": journal.run, "recipe": recipe, "steps": summary, "journal": str(journal.path)}


# ----------------------------------------------------------------------------- source proof and installed bytes
def _install():
    import ah_install  # noqa: PLC0415 - lazy: this module is imported by ah_install's gate
    return ah_install


def prove_on_canonical_main(ctx, ref):
    """ref is a commit of the canonical harness repository's main history and an ancestor of its tip (ah_install's fresh-repository
    proof, reused, not re-implemented). Returns the HOOKS list at that ref."""
    _, listed, main = _fetch(ctx, ref, [])
    return {"main": main, "listed": listed}


def _fetch(ctx, ref, names):
    try:
        return _install().fetch_source(ref, names, ctx.home, True)
    except OpsError:
        raise
    except Exception as error:  # noqa: BLE001 - InstallError, a git timeout or anything else: the proof did not hold, nothing was changed
        detail = str(error) if getattr(error, "code", None) else type(error).__name__
        refuse("canonical-main proof failed: %s" % detail, "not_on_main")


def blob_id(data):
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


def verify_installed(ctx, ref, host, wanted):
    """Compare the installed hook bytes on this Mac and on HOST with the git blobs at ref (the hooks the installer lists)."""
    proof = prove_on_canonical_main(ctx, ref)
    names = [n for n in wanted if n in proof["listed"]]
    if not names:
        return {"compared": 0, "note": "none of the verify hooks are in the installer list at that ref"}
    sources, _, _ = _fetch(ctx, ref, names)
    expected = {n: sources[n][1] for n in names}
    mac = {}
    for n in names:
        p = ctx.home / ".claude" / "hooks" / n
        mac[n] = blob_id(p.read_bytes()) if p.is_file() and not p.is_symlink() else None
    done = _ok(ctx.ssh(host, "python3 -I -c %s %s" % (shlex.quote(REMOTE_BLOBS), shlex.quote(json.dumps(names))), what="remote hash read-back"),
               "remote hash read-back", "verify_failed")
    try:
        remote = json.loads(done.stdout)
    except ValueError:
        uncertain("the read-back from %s was not readable." % host)
    wrong = sorted(n for n in names if mac[n] != expected[n] or remote.get(n) != expected[n])
    if wrong:
        refuse("installed hook bytes differ from the merged commit for: %s (mac %s, %s %s)" % (
            ", ".join(wrong), sum(1 for n in wrong if mac[n] != expected[n]), host, sum(1 for n in wrong if remote.get(n) != expected[n])), "drift")
    return {"compared": len(names), "equal": len(names)}


def repair_harness_path(ctx):
    path = ctx.home / ".agent-harness" / "bin" / "repair-harness"
    if not (path.is_file() and os.access(path, os.X_OK)):
        refuse("%s is not installed; installing repair-harness is a user step (the installer, run once)" % path, "unavailable")
    return str(path)


def run_repair(ctx, ref, host, apply):
    argv = [repair_harness_path(ctx), "--ref", ref, "--host", host, "--apply" if apply else "--check"]
    done = ctx.cmd(argv, timeout=1500 if apply else 600, what="repair-harness " + ("apply" if apply else "preview"))
    if done.returncode != 0:
        if apply:  # both hosts may be half done: unknown, never a plain failure, never a local copy
            uncertain("repair-harness apply exited %s (%s)." % (done.returncode, scrub(done.stderr or done.stdout)))
        refuse("repair-harness preview exited %s: %s" % (done.returncode, scrub(done.stderr or done.stdout)), "preview_failed")
    return {"exit": 0, "mode": "apply" if apply else "check", "output_lines": len((done.stdout or "").splitlines())}


# ----------------------------------------------------------------------------- merge
def read_receipt(path):
    p = Path(path)
    if not p.is_file() or p.is_symlink() or p.stat().st_size > (1 << 20):
        refuse("--receipt must be a regular file under 1 MiB (the exact-HEAD peer_review.py pr report)", "bad_receipt")
    return p.read_text(encoding="utf-8", errors="replace")


def receipt_problems(text, repo, pr, head):
    header, _, _ = text.partition("\n\n")
    fields = dict(line.split(": ", 1) for line in header.splitlines() if ": " in line)
    problems = []
    if fields.get("Stage") != "pr":
        problems.append("Stage is not pr")
    if fields.get("Reviewed repository") != repo:
        problems.append("Reviewed repository is not %s" % repo)
    if fields.get("Reviewed PR") != str(pr):
        problems.append("Reviewed PR is not %s" % pr)
    if fields.get("Reviewed HEAD") != head:
        problems.append("Reviewed HEAD %s is not the PR head %s" % (fields.get("Reviewed HEAD"), head))
    if not re.fullmatch(r"[0-9a-f]{64}", fields.get("Reviewed packet SHA-256", "")):
        problems.append("Reviewed packet SHA-256 is missing")
    verdict = re.search(r"^VERDICT: (PASS-WITH-TICKETS|PASS|BLOCK)\b", text, re.M)
    if not verdict or verdict.group(1) == "BLOCK":
        problems.append("the verdict is not PASS")
    return problems


def checks_problems(rollup):
    """Every reported check on the head must be finished and green. Nothing reported is also a problem (CI may not have started)."""
    if not rollup:
        return ["no check results are reported on the head"]
    out = []
    for item in rollup:
        name = item.get("name") or item.get("context") or "check"
        if item.get("__typename") == "StatusContext" or "state" in item and "conclusion" not in item:
            if item.get("state") != "SUCCESS":
                out.append("%s is %s" % (name, item.get("state")))
        elif item.get("status") != "COMPLETED" or item.get("conclusion") not in GOOD_CHECKS:
            out.append("%s is %s/%s" % (name, item.get("status"), item.get("conclusion")))
    return out


def gh_json(ctx, argv, what):
    done = _ok(ctx.cmd(argv, timeout=90, what=what), what, "gh_failed")
    try:
        return json.loads(done.stdout)
    except ValueError:
        refuse("%s returned unreadable output" % what, "gh_failed")


def pr_view(ctx, repo, pr):
    return gh_json(ctx, ["gh", "pr", "view", str(pr), "--repo", repo, "--json", "state,isDraft,headRefOid,baseRefName,mergeCommit,statusCheckRollup"], "gh pr view")


def merge_one(ctx, repo, pr, receipt_path, scope, apply):
    """Merge ONE PR at its reviewed head, or report what would happen. Idempotent: a PR that is already merged is only re-verified."""
    allowed = (scope or {}).get("repos") or [HARNESS_REPO]
    if repo not in allowed:
        refuse("the grant does not cover %s (it covers %s)" % (repo, ", ".join(allowed)), "out_of_scope")
    view = pr_view(ctx, repo, pr)
    head, state = view.get("headRefOid") or "", view.get("state")
    if not REF_RE.fullmatch(head):
        refuse("the PR has no verifiable head commit", "no_head")
    if view.get("baseRefName") != "main":
        refuse("%s#%s does not target main" % (repo, pr))
    if state not in ("OPEN", "MERGED"):
        refuse("%s#%s is %s" % (repo, pr, state))
    problems = receipt_problems(read_receipt(receipt_path), repo, pr, head)
    if problems:
        refuse("%s#%s receipt refused: %s" % (repo, pr, "; ".join(problems)), "receipt")
    if state == "OPEN":
        if view.get("isDraft"):
            refuse("%s#%s is a draft; mark it ready for review first (the PR author's step)" % (repo, pr), "draft")
        bad = checks_problems(view.get("statusCheckRollup"))
        if bad and bad == ["no check results are reported on the head"] and (scope or {}).get("allow_no_checks"):
            bad = []
        if bad:
            refuse("%s#%s checks are not green on the reviewed head: %s" % (repo, pr, "; ".join(bad[:6])), "checks")
        if not apply:
            return {"would_merge": True, "repo": repo, "pr": pr, "head": head, "state": "OPEN"}
        _ok(ctx.cmd(["gh", "pr", "merge", str(pr), "--repo", repo, "--merge", "--match-head-commit", head], timeout=180, what="gh pr merge"), "gh pr merge", "merge_refused")
    elif not apply:
        return {"would_merge": False, "already_merged": True, "repo": repo, "pr": pr, "head": head}
    merge = ""
    for attempt in range(6):
        merge = ((pr_view(ctx, repo, pr).get("mergeCommit") or {}).get("oid")) or ""
        if merge:
            break
        ctx.sleep(5)
    if not REF_RE.fullmatch(merge):
        uncertain("%s#%s has no merge commit after the merge call." % (repo, pr))
    done = _ok(ctx.cmd(["gh", "api", "repos/%s/commits/%s" % (repo, merge), "--jq", ".parents[1].sha // empty"], timeout=90, what="gh api"), "gh api", "gh_failed")
    if done.stdout.strip() != head:
        refuse("merge %s of %s#%s does not have the reviewed head %s as its second parent" % (merge[:12], repo, pr, head[:12]), "merge_parent")
    return {"merged": True, "repo": repo, "pr": pr, "head": head, "merge_commit": merge, "was": state}


# ----------------------------------------------------------------------------- recipes
def recipe_merge(a, home, ctx, journal):
    grant_box = {}

    def grant(c):
        grant_box["g"] = require_grant(CAP_MERGE, evidence={"repo": a["repo"], "pr": a["pr"]}, home=home)
        g = grant_box["g"]
        return {"policy_id": g.get("policy_id"), "key_id": g.get("key_id"), "expires_at": g.get("expires_at")}

    def merge(c):
        return merge_one(c, a["repo"], a["pr"], a["receipt"], (grant_box.get("g") or {}).get("scope"), a["apply"])

    steps = [("grant", grant, True)] if a["apply"] else []
    return steps + [("merge" if a["apply"] else "inspect", merge, False)]


def recipe_repair(a, home, ctx, journal):
    box = {}

    def ancestor(c):
        proof = prove_on_canonical_main(c, a["ref"])
        return {"main": proof["main"], "hooks_listed": len(proof["listed"])}

    def grant(c):
        g = box["g"] = require_grant(CAP_REPAIR, evidence={"ref": a["ref"], "host": a["host"]}, home=home)
        return {"policy_id": g.get("policy_id"), "key_id": g.get("key_id"), "expires_at": g.get("expires_at")}

    steps = [("ancestor", ancestor, False)]
    if a["apply"]:
        steps.append(("grant", grant, True))
    steps.append(("preview", lambda c: run_repair(c, a["ref"], a["host"], False), False))
    if a["apply"]:
        steps.append(("apply", lambda c: run_repair(c, a["ref"], a["host"], True), False))
        steps.append(("verify", lambda c: verify_installed(c, a["ref"], a["host"], REPAIR_HOOKS), False))
    return steps


def task_key(prj, run, wrk):
    """Derived exactly as the scanner adapter derives it (the trust script's rule), so a mistyped key cannot be approved."""
    return "t2scan-audit-" + hashlib.sha256(json.dumps([prj, run, wrk], separators=(",", ":"), sort_keys=True).encode()).hexdigest()[:32]


def approve_command(task, user_msg, wal):
    return "python3 ~/.claude/hooks/ah.py approve-top --task %s --user-msg %s --wal %s" % (
        task, user_msg or "<uuid:SESSION/UUID from `ah user-msg`>", shlex.quote(wal) if wal else "<~/.claude/wals/SESSION/main.jsonl>")


def recipe_central(a, home, ctx, journal):
    box = {}
    item = ITEM_RE.fullmatch(a["item"])
    task = task_key(item.group(2), item.group(3), item.group(4))

    def grant(c):
        g = box["g"] = require_grant(CAP_CENTRAL, evidence={"harness_pr": a["harness_pr"], "t2scan_pr": a.get("t2scan_pr"), "host": a["host"], "task": task}, home=home)
        return {"policy_id": g.get("policy_id"), "key_id": g.get("key_id"), "expires_at": g.get("expires_at")}

    def merges(repo, pr, receipt):
        def go(c):
            scope = dict((box.get("g") or {}).get("scope") or {})
            scope.setdefault("repos", [HARNESS_REPO, T2SCAN_REPO])  # this recipe is about these two repositories by definition
            return merge_one(c, repo, pr, receipt, scope, a["apply"])
        return go

    def preconditions(c):
        _ok(c.cmd(["python3", "-c", "import cryptography"], timeout=30, what="local cryptography import"), "this Mac's python3 cannot import cryptography", "precondition")
        _ok(c.ssh(a["host"], 'python3 -c "import cryptography" && /usr/bin/python3 -I -c "import cryptography"', timeout=60, what="host cryptography check"),
            "%s is unreachable or its python3 cannot import cryptography" % a["host"], "precondition")
        repair_harness_path(c)
        return {"host": a["host"], "ready": True}

    def repair(c):
        merge = c.results["merge_harness"].get("merge_commit")
        if not merge:
            refuse("no harness merge commit to install", "no_merge")
        proof = prove_on_canonical_main(c, merge)
        run_repair(c, merge, a["host"], False)
        run_repair(c, merge, a["host"], True)
        return {"ref": merge, "main": proof["main"]}

    def verify(c):
        return verify_installed(c, c.results["merge_harness"]["merge_commit"], a["host"], CENTRAL_HOOKS)

    def enable(c):
        args = ["decision", "enable", "--project", LEDGER_PROJECT, "--number", str(LEDGER_NUMBER), "--issue-id", LEDGER_ISSUE]
        _ok(c.cmd(["python3", str(c.home / ".claude" / "hooks" / "ah.py")] + args, timeout=120, what="decision enable (this Mac)"), "enabling central decisions on this Mac", "enable_failed")
        _ok(c.ssh(a["host"], 'python3 "$HOME/.claude/hooks/ah.py" ' + " ".join(args), what="decision enable (host)"), "enabling central decisions on %s" % a["host"], "enable_failed", write=True)
        return {"enabled_on": ["this Mac", a["host"]]}

    def adapter(c):
        merge = c.results["merge_t2scan"].get("merge_commit")
        if not REF_RE.fullmatch(merge or ""):
            refuse("no scanner merge commit for the adapter", "no_merge")
        done = _ok(c.ssh(a["host"], "bash -s -- %s" % merge, input=ADAPTER_SCRIPT, what="adapter update"), "updating the scanner adapter on %s" % a["host"], "adapter_failed", write=True)
        previous = re.search(r"previous trusted checkout: ([0-9a-f]{40})", done.stdout or "")
        return {"adapter_commit": merge, "previous_head": previous.group(1) if previous else "unknown"}

    def stop(c):
        command = approve_command(task, a.get("user_msg"), a.get("wal"))
        return {"stopped_before": "approve-top", "task": task, "user_command": command}

    steps = []
    if a["apply"]:
        steps.append(("grant", grant, True))
    steps.append(("preconditions", preconditions, False))
    steps.append(("merge_harness", merges(HARNESS_REPO, a["harness_pr"], a["harness_receipt"]), False))
    if a.get("t2scan_pr"):
        steps.append(("merge_t2scan", merges(T2SCAN_REPO, a["t2scan_pr"], a["t2scan_receipt"]), False))
    if a["apply"]:
        steps += [("repair", repair, False), ("verify", verify, False), ("enable", enable, False)]
        if a.get("t2scan_pr"):
            steps.append(("adapter", adapter, False))
        steps.append(("stop", stop, False))
    return steps


# ----------------------------------------------------------------------------- command line
class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise OpsError("bad_arguments", "%s: %s" % (self.prog, message))


def build_parser():
    p = Parser(prog="ah ops", description=__doc__.split("\n\n")[0], allow_abbrev=False)
    sub = p.add_subparsers(dest="recipe", required=True, parser_class=Parser)

    def modes(q):
        g = q.add_mutually_exclusive_group()
        g.add_argument("--check", action="store_true", help="read only (default)")
        g.add_argument("--apply", action="store_true", help="do it (needs the signed self-serve grant)")
        q.add_argument("--resume", metavar="RUN", help="continue an interrupted run (takes no other option)")

    m = sub.add_parser("merge", help="merge ONE reviewed PR at its reviewed head")
    m.add_argument("--repo", help="OWNER/REPO (default: the harness repository)")
    m.add_argument("--pr", type=int)
    m.add_argument("--receipt", help="the exact-HEAD `peer_review.py pr` report")
    modes(m)
    r = sub.add_parser("repair", help="install a canonical-main commit on this Mac and HOST through repair-harness")
    r.add_argument("--ref", help="full 40-hex commit on the canonical main")
    r.add_argument("--host", help="default t2-dev")
    modes(r)
    c = sub.add_parser("central-decisions", help="merge, repair, enable, adapter; then stop at the user's approve-top")
    c.add_argument("--harness-pr", type=int, dest="harness_pr")
    c.add_argument("--harness-receipt", dest="harness_receipt")
    c.add_argument("--t2scan-pr", type=int, dest="t2scan_pr")
    c.add_argument("--t2scan-receipt", dest="t2scan_receipt")
    c.add_argument("--item", help="ASSIGNMENT:PROJECT:RUN:WORK_ITEM (exactly one: one approve-top command is printed)")
    c.add_argument("--user-msg", dest="user_msg", help="uuid:<session>/<uuid> from `ah user-msg` (only echoed into the printed command)")
    c.add_argument("--wal", help="the session's main.jsonl (only echoed into the printed command)")
    c.add_argument("--host", help="default t2-dev")
    modes(c)
    return p


def validate(a):
    recipe = a["recipe"]
    if a.get("host") is not None and a["host"] not in HOSTS:
        refuse("--host must be one of %s" % ", ".join(HOSTS))
    if recipe == "merge":
        if not isinstance(a.get("pr"), int) or a["pr"] < 1 or a["pr"] > 9999999:
            refuse("--pr must be one PR number")
        if not REPO_RE.fullmatch(a.get("repo") or ""):
            refuse("--repo must look like OWNER/REPO")
        if not a.get("receipt"):
            refuse("--receipt must name the exact-HEAD peer_review.py pr report")
    elif recipe == "repair":
        if not REF_RE.fullmatch(a.get("ref") or ""):
            refuse("--ref must be a full 40-hex lowercase commit sha")
    else:
        if not isinstance(a.get("harness_pr"), int) or not a.get("harness_receipt"):
            refuse("--harness-pr and --harness-receipt are required")
        if bool(a.get("t2scan_pr")) != bool(a.get("t2scan_receipt")):
            refuse("--t2scan-pr needs --t2scan-receipt (and the reverse)")
        if not ITEM_RE.fullmatch(a.get("item") or ""):
            refuse("--item must be <executive|assurance|delivery>-synthesis:prj_...:run_...:wrk_... (exactly one item per run)")
        if a.get("user_msg") and not USER_MSG_RE.fullmatch(a["user_msg"]):
            refuse("--user-msg must be a uuid:<session>/<uuid> id from `ah user-msg`")
        if a.get("wal") and (os.path.basename(a["wal"]) != "main.jsonl" or "\x00" in a["wal"]):
            refuse("--wal must be the session's main.jsonl")


RECIPES = {"merge": recipe_merge, "repair": recipe_repair, "central-decisions": recipe_central}
KEEP = {"merge": ("repo", "pr", "receipt"), "repair": ("ref", "host"),
        "central-decisions": ("harness_pr", "harness_receipt", "t2scan_pr", "t2scan_receipt", "item", "user_msg", "wal", "host")}


def run(rest, home, runner=None, sleep=time.sleep):
    """Entry point from ah.py: returns the report dict (ok False for a stopped run) or raises OpsError."""
    ns = vars(build_parser().parse_args(list(rest)))
    recipe = ns["recipe"]
    ctx = Context(home, runner, sleep)
    if ns.get("resume"):
        given = [k for k in KEEP[recipe] + ("apply",) if ns.get(k) not in (None, False)]
        if given:
            refuse("--resume takes the run id only (got --%s)" % given[0].replace("_", "-"))
        if not RUN_RE.fullmatch(ns["resume"]):
            refuse("--resume takes a run id like ops-0123456789ab")
        journal = Journal(home, ns["resume"])
        start = journal.start_row()
        if start is None or start.get("recipe") != recipe:
            refuse("no %s run %s on this machine" % (recipe, ns["resume"]))
        args = dict(start["args"], recipe=recipe)
    else:
        args = {"recipe": recipe, "apply": bool(ns.get("apply")), **{k: ns.get(k) for k in KEEP[recipe]}}
        if "host" in args:
            args["host"] = args["host"] or "t2-dev"
        if recipe == "merge":
            args["repo"] = args["repo"] or HARNESS_REPO
        validate(args)
        journal = Journal(home)
    validate(args)
    steps = RECIPES[recipe](args, Path(home), ctx, journal)
    report = execute(journal, recipe, {k: v for k, v in args.items() if k != "recipe"}, steps, ctx)
    report["mode"] = "apply" if args["apply"] else "check"
    if report["ok"] and recipe == "central-decisions" and args["apply"]:
        result = ctx.results.get("stop") or journal.states().get("stop", (None, {}))[1]
        report.update(result)
        report["user_steps"] = [
            "Run the printed approve-top command yourself: it checks your own words, so no agent can run it for you.",
            "Then `python3 ~/.claude/hooks/ah.py decision publish --task %s` is yours too (it re-verifies your words and signs)." % result.get("task"),
            "If no decisions key is pinned, `decision keygen` and `decision pin` are yours as well."]
    elif report["ok"] and not args["apply"]:
        report["note"] = "check only: nothing was changed; pass --apply to run it (needs the signed self-serve grant)"
    return report


def main(argv=None):
    try:
        out = run(sys.argv[1:] if argv is None else argv, Path(os.environ.get("AH_HOME") or Path.home()))
    except OpsError as error:
        json.dump({"ok": False, "code": error.code, "message": str(error)}, sys.stdout)
        sys.stdout.write("\n")
        return error.exit_code
    json.dump(out, sys.stdout, indent=2, default=str)
    sys.stdout.write("\n")
    return 0 if out.get("ok") else 3


if __name__ == "__main__":
    sys.exit(main())
