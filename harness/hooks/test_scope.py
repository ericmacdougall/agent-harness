#!/usr/bin/env python3
"""Test-scope guard: a full suite is the exception, not the default (GoodQA #14552, rules batch B6).

Why: owners ran a full branch suite plus a full main control, in parallel, for two-file deltas (dev2 load ~117).

Rules, enforced where a full-suite launch is detected (PreToolUse Bash, on the Mac and on dev2):
  a. BASELINE CACHE. A main control (the suite run at the current main SHA) is recorded once per repo and SHA in a
     shared store on dev2/T2. Anyone reuses it; a second control for that SHA is refused and the recorded result is
     printed. Record one with `test_scope.py run-control` or `baseline-record`.
  b. EVIDENCE. A full suite at a feature head is allowed only after the head has accepted code-inspection evidence
     (`test_scope.py accept --head H --report <helper report>`). A repair delta is pointed at focused tests for the
     changed files and their dependents (`test_scope.py scope`).
  c. ONE FULL RUN PER HEAD. A second full run for the same repo and head is refused (unless the first was released as
     an infrastructure failure with `test_scope.py release`). A reservation nobody finishes expires after 12 hours.
  Investigation escape: prefix the command with HARNESS_SCOPE_OK=<reason of 10+ characters>; it is allowed and logged.

Store: <root>/<repo-id>/{baseline-<sha>,control-<sha>,full-<head>,accepted-<head>}.json, every mutation under one
flock per repo directory. On the Mac the CLI runs the same command on the store host over ssh (BatchMode, short
timeout); an unreachable store warns and allows (a guard must not stop work because dev2 is down). Records are
checked against the key they were found under, so a hand-edited file is ignored rather than trusted.

CLI (JSON on stdout; exit 0 allowed/ok, 2 refused, 3 usage, 4 store unreachable):
  test_scope.py baseline-get|baseline-record|control|accept|full|finish|release|scope|run-control|hook ...
Stdlib only, Python 3.9 compatible.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
POLICY = HERE / "test_scope_policy.json"
SCHEMA = 1
MAX_RECORD = 65_536
MAX_REPORT = 1_000_000
CONTROL_TTL = 6 * 3600
FULL_TTL = 12 * 3600
SAFE_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
HATCH_RE = re.compile(r"^\s*(?:[A-Za-z_][A-Za-z0-9_]*=\S*\s+)*HARNESS_SCOPE_OK=(?:'([^']{10,200})'|\"([^\"]{10,200})\"|(\S{10,200}))")
DEFAULT_POLICY = {"host": "dev2", "root": "~/.agent-harness/test-scope", "ssh_timeout_s": 8}


class Refused(Exception):
    def __init__(self, code: str, message: str, **facts):
        super().__init__(message)
        self.code, self.message, self.facts = code, message, facts


def now() -> float:
    return time.time()


def safe(value: str, what: str) -> str:
    if not isinstance(value, str) or not SAFE_RE.match(value) or value in (".", ".."):
        raise ValueError(f"{what} must be 1-128 characters of letters, digits, dot, dash, underscore")
    return value


def full_sha(value: str, what: str) -> str:
    if not isinstance(value, str) or not SHA_RE.match(value):
        raise ValueError(f"{what} must be a full 40-character lowercase commit SHA")
    return value


def load_policy(path: Path = POLICY) -> dict:
    policy = dict(DEFAULT_POLICY)
    try:
        data = json.loads(path.read_text())
        if isinstance(data, dict):
            for key in DEFAULT_POLICY:
                if isinstance(data.get(key), type(DEFAULT_POLICY[key])):
                    policy[key] = data[key]
    except (OSError, ValueError):
        pass
    return policy


class Store:
    """JSON records under <root>/<repo-id>/; every mutation holds a per-repo flock."""

    def __init__(self, root):
        self.root = Path(os.path.expanduser(str(root)))

    def dir(self, repo_id: str) -> Path:
        path = self.root / safe(repo_id, "repo id")
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        return path

    def lock(self, repo_id: str):
        return _Lock(self.dir(repo_id) / ".lock")

    def read(self, repo_id: str, name: str, expect: dict):
        """The record, or None when absent, oversized, a symlink, malformed or filed under the wrong key."""
        path = self.dir(repo_id) / name
        try:
            if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_RECORD:
                return None
            data = json.loads(path.read_text())
        except (OSError, ValueError):
            return None
        if not isinstance(data, dict) or data.get("schema") != SCHEMA:
            return None
        if any(data.get(k) != v for k, v in expect.items()):
            return None
        return data

    def write(self, repo_id: str, name: str, record: dict) -> None:
        path = self.dir(repo_id) / name
        if path.is_symlink():
            raise OSError("refusing a symlinked record")
        tmp = path.with_name(f"{name}.tmp.{os.getpid()}")
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w") as fh:
            json.dump(record, fh, indent=1, sort_keys=True)
        os.replace(str(tmp), str(path))


class _Lock:
    def __init__(self, path: Path):
        self.path = path

    def __enter__(self):
        self.fd = os.open(str(self.path), os.O_WRONLY | os.O_CREAT, 0o600)
        fcntl.flock(self.fd, fcntl.LOCK_EX)
        return self

    def __exit__(self, *exc):
        fcntl.flock(self.fd, fcntl.LOCK_UN)
        os.close(self.fd)


def base_record(repo_id: str, **kw) -> dict:
    return {"schema": SCHEMA, "repo_id": repo_id, "at": now(), **kw}


# ---- a. baseline cache ------------------------------------------------------------------------------------------

def baseline_get(store: Store, repo_id: str, main_sha: str):
    full_sha(main_sha, "main SHA")
    return store.read(repo_id, f"baseline-{main_sha}.json", {"repo_id": repo_id, "main_sha": main_sha, "kind": "baseline"})


def baseline_record(store: Store, repo_id: str, main_sha: str, command: str, result: str, counts=None, failing=None,
                    replace: bool = False, host: str = "") -> dict:
    full_sha(main_sha, "main SHA")
    if result not in ("pass", "fail"):
        raise ValueError("result must be pass or fail")
    with store.lock(repo_id):
        if baseline_get(store, repo_id, main_sha) and not replace:
            raise Refused("baseline-exists", "a baseline for this repo and main SHA is already recorded (use --replace "
                          "only for a recorded infrastructure failure)", record=baseline_get(store, repo_id, main_sha))
        record = base_record(repo_id, kind="baseline", main_sha=main_sha, command=str(command)[:500], result=result,
                             counts=counts if isinstance(counts, dict) else {},
                             failing=[str(x)[:200] for x in (failing or [])][:200], host=host)
        store.write(repo_id, f"baseline-{main_sha}.json", record)
        return record


def reserve_control(store: Store, repo_id: str, main_sha: str, token: str) -> dict:
    full_sha(main_sha, "main SHA")
    with store.lock(repo_id):
        recorded = baseline_get(store, repo_id, main_sha)
        if recorded:
            raise Refused("baseline-exists", "a baseline for this main SHA is already recorded: reuse it", record=recorded)
        name = f"control-{main_sha}.json"
        held = store.read(repo_id, name, {"repo_id": repo_id, "main_sha": main_sha, "kind": "control"})
        if held and held.get("state") == "reserved" and now() - held.get("at", 0) < CONTROL_TTL:
            if held.get("token") == token:
                return {"allowed": True, "idempotent": True, "reservation": held}
            raise Refused("control-in-flight", "another owner is already running the main control for this SHA: wait "
                          "for its baseline instead of starting a second one", record=held)
        record = base_record(repo_id, kind="control", main_sha=main_sha, token=token, state="reserved")
        store.write(repo_id, name, record)
        return {"allowed": True, "idempotent": False, "reservation": record}


# ---- b. evidence ------------------------------------------------------------------------------------------------

def parse_report(text: str) -> dict:
    fields = {}
    for line in text.splitlines()[:40]:
        m = re.match(r"^(Stage|Reviewed HEAD|Reviewed packet SHA-256|Worktree status): (.+)$", line)
        if m:
            fields[m.group(1)] = m.group(2).strip()
    verdict = re.search(r"(?m)^(CODE_INSPECTION_RESULT|PLAN_RESULT|VERDICT): (ACCEPT|BLOCK|PASS)\b", text)
    fields["verdict"] = verdict.group(0) if verdict else ""
    return fields


def accept_evidence(store: Store, repo_id: str, head: str, report: Path, packet: Path = None) -> dict:
    full_sha(head, "head")
    report = Path(report)
    if report.is_symlink() or not report.is_file() or report.stat().st_size > MAX_REPORT:
        raise Refused("bad-evidence", "the review report is missing, not a regular file or too large")
    text = report.read_text(errors="replace")
    fields = parse_report(text)
    problems = []
    if fields.get("Stage") != "code-inspection":
        problems.append("stage is not code-inspection")
    if fields.get("Reviewed HEAD") != head:
        problems.append("Reviewed HEAD does not equal the head")
    if fields["verdict"] != "CODE_INSPECTION_RESULT: ACCEPT":
        problems.append("the report does not begin with CODE_INSPECTION_RESULT: ACCEPT")
    if fields.get("Worktree status") != "clean":
        problems.append("the reviewed worktree was not clean")
    if packet is not None:
        packet = Path(packet)
        digest = hashlib.sha256(packet.read_bytes()).hexdigest() if packet.is_file() else ""
        if fields.get("Reviewed packet SHA-256") != digest:
            problems.append("Reviewed packet SHA-256 does not match the packet")
    if problems:
        raise Refused("bad-evidence", "not accepted code-inspection evidence: " + "; ".join(problems))
    record = base_record(repo_id, kind="accepted", head=head, report_sha256=hashlib.sha256(text.encode()).hexdigest())
    with store.lock(repo_id):
        store.write(repo_id, f"accepted-{head}.json", record)
    return record


def has_evidence(store: Store, repo_id: str, head: str):
    full_sha(head, "head")
    return store.read(repo_id, f"accepted-{head}.json", {"repo_id": repo_id, "head": head, "kind": "accepted"})


# ---- c. one full run per head -----------------------------------------------------------------------------------

def reserve_full(store: Store, repo_id: str, head: str, token: str, focused: list = None) -> dict:
    full_sha(head, "head")
    with store.lock(repo_id):
        if not has_evidence(store, repo_id, head):
            raise Refused("no-evidence", "a full suite runs only at a frozen head with accepted code-inspection evidence "
                          "(test_scope.py accept); run the focused tests for the changed files instead",
                          focused=focused or [])
        name = f"full-{head}.json"
        held = store.read(repo_id, name, {"repo_id": repo_id, "head": head, "kind": "full"})
        guarded = store.read("_guarded", name, {"repo_id": "_guarded", "head": head, "kind": "full"}) \
            if repo_id != "_guarded" else None  # a run reserved through usage_guard counts too
        for other in (guarded, held):
            if other and other.get("state") != "released":
                fresh = now() - other.get("at", 0) < FULL_TTL
                if other.get("state") == "finished" or fresh:
                    if other is held and other.get("token") == token and other.get("state") == "reserved":
                        return {"allowed": True, "idempotent": True, "reservation": other}
                    raise Refused("duplicate-full", "a full run for this head was already started or finished (one full "
                                  "run per head); read its result, or release it if it was an infrastructure failure",
                                  record=other)
        record = base_record(repo_id, kind="full", head=head, token=token, state="reserved")
        store.write(repo_id, name, record)
        return {"allowed": True, "idempotent": False, "reservation": record}


def finish_full(store: Store, repo_id: str, head: str, result: str, summary: str = "") -> dict:
    full_sha(head, "head")
    if result not in ("pass", "fail"):
        raise ValueError("result must be pass or fail")
    with store.lock(repo_id):
        held = store.read(repo_id, f"full-{head}.json", {"repo_id": repo_id, "head": head, "kind": "full"})
        if not held:
            raise Refused("no-reservation", "no full run is reserved for this head")
        held.update(state="finished", result=result, summary=str(summary)[:300], finished_at=now())
        store.write(repo_id, f"full-{head}.json", held)
        return held


def release(store: Store, repo_id: str, kind: str, key: str, reason: str) -> dict:
    full_sha(key, "key")
    if kind not in ("control", "full") or len(str(reason).strip()) < 10:
        raise ValueError("kind is control or full and the reason needs 10+ characters")
    name = f"{kind}-{key}.json"
    field = "main_sha" if kind == "control" else "head"
    with store.lock(repo_id):
        held = store.read(repo_id, name, {"repo_id": repo_id, field: key, "kind": kind})
        if not held:
            raise Refused("no-reservation", f"no {kind} reservation for that SHA")
        held.update(state="released", release_reason=str(reason)[:300], released_at=now())
        store.write(repo_id, name, held)
        return held


def guarded_full_start(head: str, token: str, root=None) -> None:
    """usage_guard's kind=full path: refuse a head whose full run already finished or is in flight under another
    token, and reserve it. Local store only (dev2/T2 or HARNESS_TEST_SCOPE_ROOT); the caller treats OSError as
    'no store here' and proceeds (fail open)."""
    full_sha(head, "head")
    store = Store(root or os.environ.get("HARNESS_TEST_SCOPE_ROOT") or load_policy()["root"])
    repo_id = next((d.name for d in sorted(store.root.glob("*")) if (d / f"full-{head}.json").is_file()), "_guarded")
    with store.lock(repo_id):
        held = store.read(repo_id, f"full-{head}.json", {"repo_id": repo_id, "head": head, "kind": "full"})
        if held and held.get("state") != "released":
            if held.get("state") == "finished" or (now() - held.get("at", 0) < FULL_TTL and held.get("token") != token):
                raise Refused("duplicate-full", "a full run for this head was already started or finished (one full run "
                              "per head); read its result or release it if it was an infrastructure failure", record=held)
            return
        store.write(repo_id, f"full-{head}.json", base_record(repo_id, kind="full", head=head, token=token,
                                                             state="reserved"))


# ---- focused scope for repair deltas ----------------------------------------------------------------------------

IMPORT_RE = re.compile(r"^[ \t]*(?:from[ \t]+([A-Za-z_]\w*)|import[ \t]+([A-Za-z_]\w*(?:[ \t]*,[ \t]*[A-Za-z_]\w*)*))", re.M)


def git(repo: str, *args: str) -> str:
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(Path.home()), "GIT_TERMINAL_PROMPT": "0",
           "GIT_OPTIONAL_LOCKS": "0"}
    done = subprocess.run(["git", "-C", repo, "-c", "core.fsmonitor=false", *args], capture_output=True, text=True,
                          timeout=20, env=env)
    if done.returncode != 0:
        raise OSError(f"git {args[0]} failed")
    return done.stdout


def imports_of(path: Path, known: set) -> set:
    try:
        text = path.read_text(errors="replace")[:400_000]
    except OSError:
        return set()
    names = set()
    for m in IMPORT_RE.finditer(text):
        for part in ([m.group(1)] if m.group(1) else m.group(2).split(",")):
            names.add(part.strip())
    return names & known


def focused_scope(repo: str, base: str, head: str) -> dict:
    """Changed files, the modules that depend on them, and the test modules to run (harness/hooks + tests layout)."""
    changed = [p for p in git(repo, "diff", "--name-only", base, head).splitlines() if p]
    root = Path(repo)
    src_dirs = [root / d for d in ("harness/hooks", "src", "lib") if (root / d).is_dir()] or [root]
    tests_dir = root / "tests"
    modules = {}
    for d in src_dirs:
        for f in d.glob("*.py"):
            modules[f.stem] = f
    known = set(modules)
    test_files = {f.stem: f for f in tests_dir.glob("test_*.py")} if tests_dir.is_dir() else {}
    deps = {name: imports_of(f, known) for name, f in modules.items()}  # module -> modules it imports
    touched = set()
    for path in changed:
        p = Path(path)
        stem = re.sub(r"_(policy|checklists|template)$", "", p.stem) if p.suffix in (".json", ".md") else p.stem
        if p.suffix == ".py" and p.parts[0] == "tests":
            touched.add(("test", p.stem))
        elif stem in known:
            touched.add(("mod", stem))
    closure = {name for kind, name in touched if kind == "mod"}
    grew = True
    while grew:
        grew = False
        for name, imported in deps.items():
            if name not in closure and imported & closure:
                closure.add(name)
                grew = True
    tests = {name for kind, name in touched if kind == "test"}
    for name in closure:
        tests.update(t for t in test_files if t == f"test_{name}" or t.startswith(f"test_{name}_"))
    for tname, f in test_files.items():
        if imports_of(f, known) & closure:
            tests.add(tname)
    tests = sorted(t for t in tests if t in test_files)
    commands = [f"python3 -m unittest {' '.join('tests.' + t for t in tests)}"] if tests else []
    return {"changed": changed, "dependents": sorted(closure), "tests": tests, "commands": commands,
            "note": "" if tests else "no mapped tests: run the tests your plan names for the changed paths"}


# ---- hook -------------------------------------------------------------------------------------------------------

def repo_context(cwd: str) -> dict:
    top = git(cwd, "rev-parse", "--show-toplevel").strip()
    head = git(top, "rev-parse", "HEAD").strip()
    url = ""
    try:
        url = git(top, "remote", "get-url", "origin").strip()
    except OSError:
        pass
    repo_id = re.sub(r"[^A-Za-z0-9._-]+", "-", re.sub(r"^(?:https?://|git@|ssh://git@)", "", url).replace(":", "/")
                     .removesuffix(".git") if url else Path(top).name).strip("-")[:100] or "repo"
    main = ""
    for ref in ("origin/main", "origin/master"):
        try:
            main = git(top, "rev-parse", "--verify", "-q", ref).strip()
            break
        except OSError:
            continue
    return {"top": top, "head": head, "repo_id": repo_id, "main_sha": main}


def run_remote(host: str, args: list, timeout: int):
    cmd = ["ssh", "-o", "BatchMode=yes", "-o", f"ConnectTimeout={timeout}", host,
           "python3 ~/.claude/hooks/test_scope.py " + " ".join(shlex.quote(a) for a in args)]
    try:
        done = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 10)
    except (OSError, subprocess.SubprocessError):
        return None
    try:
        return done.returncode, json.loads(done.stdout)
    except ValueError:
        return None


def store_call(policy: dict, args: list):
    """Run one CLI command on the store: locally on Linux/dev2 or with HARNESS_TEST_SCOPE_ROOT, else over ssh."""
    root = os.environ.get("HARNESS_TEST_SCOPE_ROOT")
    host = os.environ.get("HARNESS_TEST_SCOPE_HOST", policy["host"])
    if root or sys.platform != "darwin" or not host:
        return cli(["--root", root or policy["root"], *args], capture=True)
    return run_remote(host, args, int(policy["ssh_timeout_s"]))


def hatch_reason(command: str):
    m = HATCH_RE.match(command or "")
    return next((g for g in m.groups() if g), "") if m else ""


def deny(text: str) -> int:
    print(text, file=sys.stderr)
    return 2


def hook_decision(payload: dict, policy: dict):
    """(exit_code, stderr_text). 0 allows. Only full-suite launches are judged."""
    if payload.get("tool_name") != "Bash" or not isinstance(payload.get("tool_input"), dict):
        return 0, ""
    command = payload["tool_input"].get("command")
    if not isinstance(command, str) or "test_scope.py" in command.split("&&")[0].split(";")[0]:
        return 0, ""
    import heavy_job_guard as hjg
    cwd = payload.get("cwd") if isinstance(payload.get("cwd"), str) else os.getcwd()
    _hatch, findings = hjg.scan_state(command, cwd)
    if not any(f[0] == "full-suite" for f in findings):
        return 0, ""
    reason = hatch_reason(command)
    ctx = repo_context(cwd)
    token = f"{payload.get('session_id', '')}:{payload.get('agent_id', '')}"
    if reason:
        store_call(policy, ["ungated", "--repo-id", ctx["repo_id"], "--head", ctx["head"], "--reason", reason])
        return 0, ""
    is_control = bool(ctx["main_sha"]) and ctx["head"] == ctx["main_sha"]
    if is_control:
        got = store_call(policy, ["control", "--repo-id", ctx["repo_id"], "--main-sha", ctx["head"], "--token", token])
        if got is None:
            return 0, "test_scope: store unreachable; allowing (warn only)"
        code, data = got
        if code == 2:
            rec = data.get("record", {})
            return 2, ("Test-scope guard [baseline]: " + data.get("message", "") + (
                f" Recorded baseline: result={rec.get('result')} command={rec.get('command')} counts={rec.get('counts')} "
                f"failing={rec.get('failing')}. Read it with `python3 ~/.claude/hooks/test_scope.py baseline-get --repo-id "
                f"{ctx['repo_id']} --main-sha {ctx['head']}`." if rec.get("kind") == "baseline" else ""))
        return 0, ""
    base = ctx["main_sha"] or ""
    focused = []
    if base:
        try:
            focused = focused_scope(ctx["top"], base, ctx["head"])["commands"]
        except (OSError, subprocess.SubprocessError):
            focused = []
    got = store_call(policy, ["full", "--repo-id", ctx["repo_id"], "--head", ctx["head"], "--token", token])
    if got is None:
        return 0, "test_scope: store unreachable; allowing (warn only)"
    code, data = got
    if code == 2:
        hint = (" Focused tests for the changed files and their dependents: " + " ; ".join(focused)) if focused else ""
        if data.get("code") == "no-evidence":
            return 2, ("Test-scope guard [evidence]: " + data.get("message", "") + hint + " After accepted evidence: "
                       f"`python3 ~/.claude/hooks/test_scope.py accept --repo-id {ctx['repo_id']} --head {ctx['head']} "
                       "--report <report>`. For an investigation, prefix HARNESS_SCOPE_OK=<reason>.")
        return 2, "Test-scope guard [one full run per head]: " + data.get("message", "") + hint
    return 0, ""


def run_hook() -> int:
    try:
        import safe_input
        raw = safe_input.read_stdin_bounded(8 * 1024 * 1024)
        payload = json.loads(raw)
        if not isinstance(payload, dict):
            return 0
        code, text = hook_decision(payload, load_policy())
        if text:
            print(text, file=sys.stderr)
        return code
    except Exception as exc:  # noqa: BLE001 - fail open: a guard bug must not block every Bash call
        print(f"test_scope: internal error {type(exc).__name__}; failing open", file=sys.stderr)
        return 0


# ---- CLI --------------------------------------------------------------------------------------------------------

def cli(argv: list, capture: bool = False):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", default=None)
    sub = ap.add_subparsers(dest="cmd", required=True)

    def add(name, *flags):
        p = sub.add_parser(name)
        for flag in flags:
            required = not (flag == "--token" and os.environ.get("AGENT_HARNESS_RUN_ID"))
            p.add_argument(flag, required=required, default=os.environ.get("AGENT_HARNESS_RUN_ID") if flag == "--token" else None)
        return p

    p = add("baseline-get", "--repo-id", "--main-sha")
    p = add("baseline-record", "--repo-id", "--main-sha", "--command", "--result")
    p.add_argument("--counts", default="{}")
    p.add_argument("--failing", default="")
    p.add_argument("--replace", action="store_true")
    p = add("control", "--repo-id", "--main-sha", "--token")
    p = add("accept", "--repo-id", "--head", "--report")
    p.add_argument("--packet", default=None)
    p = add("full", "--repo-id", "--head", "--token")
    p = add("finish", "--repo-id", "--head", "--result")
    p.add_argument("--summary", default="")
    p = add("release", "--repo-id", "--kind", "--key", "--reason")
    p = add("ungated", "--repo-id", "--head", "--reason")
    p = sub.add_parser("scope")
    p.add_argument("--repo", default=".")
    p.add_argument("--base", required=True)
    p.add_argument("--head", required=True)
    sub.add_parser("hook")
    p = sub.add_parser("run-control")
    p.add_argument("--repo", default=".")
    p.add_argument("command", nargs=argparse.REMAINDER)
    args = ap.parse_args(argv)
    store = Store(args.root or load_policy()["root"])

    def out(code: int, data: dict):
        if capture:
            return code, data
        print(json.dumps(data, sort_keys=True))
        return code

    try:
        if args.cmd == "hook":
            return run_hook()
        if args.cmd == "scope":
            return out(0, focused_scope(args.repo, args.base, args.head))
        if args.cmd == "baseline-get":
            rec = baseline_get(store, args.repo_id, args.main_sha)
            return out(0 if rec else 1, {"found": bool(rec), "record": rec})
        if args.cmd == "baseline-record":
            rec = baseline_record(store, args.repo_id, args.main_sha, args.command, args.result,
                                  json.loads(args.counts), [x for x in args.failing.split(",") if x], args.replace)
            return out(0, {"recorded": True, "record": rec})
        if args.cmd == "control":
            return out(0, reserve_control(store, args.repo_id, args.main_sha, args.token))
        if args.cmd == "accept":
            return out(0, {"accepted": True, "record": accept_evidence(store, args.repo_id, args.head, Path(args.report),
                                                                       Path(args.packet) if args.packet else None)})
        if args.cmd == "full":
            return out(0, reserve_full(store, args.repo_id, args.head, args.token))
        if args.cmd == "finish":
            return out(0, {"record": finish_full(store, args.repo_id, args.head, args.result, args.summary)})
        if args.cmd == "release":
            return out(0, {"record": release(store, args.repo_id, args.kind, args.key, args.reason)})
        if args.cmd == "ungated":
            with store.lock(args.repo_id):
                with open(store.dir(args.repo_id) / "ungated.jsonl", "a") as fh:
                    fh.write(json.dumps({"at": now(), "head": args.head, "reason": args.reason[:200]}) + "\n")
            return out(0, {"logged": True})
        if args.cmd == "run-control":
            cmd = [c for c in args.command if c != "--"]
            if not cmd:
                return out(3, {"error": "usage: run-control --repo R -- <test command>"})
            ctx = repo_context(args.repo)
            if not ctx["main_sha"] or ctx["head"] != ctx["main_sha"]:
                return out(2, {"code": "not-main", "message": "run-control runs the suite at origin/main's SHA only"})
            res = reserve_control(store, ctx["repo_id"], ctx["head"], f"run-control:{os.getpid()}")
            started = now()
            done = subprocess.run(cmd, cwd=ctx["top"])
            baseline_record(store, ctx["repo_id"], ctx["head"], " ".join(cmd), "pass" if done.returncode == 0 else "fail",
                            {"exit": done.returncode, "seconds": int(now() - started)}, replace=True)
            return out(done.returncode, {"recorded": True, "reservation": res["reservation"]["state"]})
    except Refused as r:
        return out(2, {"allowed": False, "code": r.code, "message": r.message, **r.facts})
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        return out(3, {"error": f"{type(exc).__name__}: {exc}"})
    return out(3, {"error": "unknown command"})


def main(argv=None) -> int:
    return cli(list(sys.argv[1:] if argv is None else argv))


if __name__ == "__main__":
    sys.exit(main())
