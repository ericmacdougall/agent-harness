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

This is a cooperative control: `accept` records evidence an owner presents (it checks the report's fields and packet
digest, not that a reviewer really ran), and the HARNESS_SCOPE_OK hatch is logged, not authorized. It stops accidental
duplicate and premature full suites, not a determined bypass.

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
import uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent
POLICY = HERE / "test_scope_policy.json"
SCHEMA = 1
MAX_RECORD = 65_536
MAX_REPORT = 1_000_000
CONTROL_TTL = 6 * 3600
FULL_TTL = 12 * 3600
IDEMPOTENT_S = 120  # the same owner re-sending a launch within this window is a retry, later it is a duplicate
SAFE_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
HATCH_RE = re.compile(r"(?:^|&&|;)\s*(?:[A-Za-z_][A-Za-z0-9_]*=\S*\s+)*HARNESS_SCOPE_OK=(?:'([^']{10,200})'|\"([^\"]{10,200})\"|(\S{10,200}))")
DEFAULT_POLICY = {"host": "dev2", "local_hostnames": ["dev2"], "root": "~/.agent-harness/test-scope", "ssh_timeout_s": 8}


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
                if isinstance(data.get(key), type(DEFAULT_POLICY[key])) and data[key] != "":
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
            if held.get("token") == token and now() - held.get("at", 0) < IDEMPOTENT_S:
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


def validate_report(head: str, report: Path, packet: Path) -> str:
    """Raise Refused unless the report is code-inspection ACCEPT evidence for this head over this packet; return its digest."""
    full_sha(head, "head")
    report = Path(report)
    if report.is_symlink() or not report.is_file() or report.stat().st_size > MAX_REPORT:
        raise Refused("bad-evidence", "the review report is missing, not a regular file or too large")
    text = report.read_text(errors="replace")
    header, _sep, body = text.partition("\n\n")
    fields = parse_report(header)
    problems = []
    if fields.get("Stage") != "code-inspection":
        problems.append("stage is not code-inspection")
    if fields.get("Reviewed HEAD") != head:
        problems.append("Reviewed HEAD does not equal the head")
    if not body.lstrip().startswith("CODE_INSPECTION_RESULT: ACCEPT"):
        problems.append("the report body does not begin with CODE_INSPECTION_RESULT: ACCEPT")
    if fields.get("Worktree status") != "clean":
        problems.append("the reviewed worktree was not clean")
    packet = Path(packet)
    digest = hashlib.sha256(packet.read_bytes()).hexdigest() if packet.is_file() and not packet.is_symlink() else ""
    if not digest or fields.get("Reviewed packet SHA-256") != digest:
        problems.append("Reviewed packet SHA-256 is absent or does not match the packet")
    if problems:
        raise Refused("bad-evidence", "not accepted code-inspection evidence: " + "; ".join(problems))
    return hashlib.sha256(text.encode()).hexdigest()


def register_accepted(store: Store, repo_id: str, head: str, report_sha256: str) -> dict:
    full_sha(head, "head")
    if not re.match(r"^[0-9a-f]{64}$", str(report_sha256)):
        raise ValueError("report digest must be 64 lowercase hex characters")
    record = base_record(repo_id, kind="accepted", head=head, report_sha256=report_sha256)
    with store.lock(repo_id):
        store.write(repo_id, f"accepted-{head}.json", record)
    return record


def accept_evidence(store: Store, repo_id: str, head: str, report: Path, packet: Path) -> dict:
    return register_accepted(store, repo_id, head, validate_report(head, report, packet))


def has_evidence(store: Store, repo_id: str, head: str):
    full_sha(head, "head")
    return store.read(repo_id, f"accepted-{head}.json", {"repo_id": repo_id, "head": head, "kind": "accepted"})


# ---- c. one full run per head -----------------------------------------------------------------------------------

def reserve_full(store: Store, repo_id: str, head: str, token: str, focused: list = None, source: str = "hook") -> dict:
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
                    if (other is held and other.get("token") == token and other.get("state") == "reserved"
                            and now() - other.get("at", 0) < IDEMPOTENT_S):
                        return {"allowed": True, "idempotent": True, "reservation": other}
                    raise Refused("duplicate-full", "a full run for this head was already started or finished (one full "
                                  "run per head); read its result, or release it if it was an infrastructure failure: test_scope.py release "
                                  "--kind full --key <head> --reason <10+ characters>", record=other)
        record = base_record(repo_id, kind="full", head=head, token=token, state="reserved", source=source)
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
    guarded owner, and reserve it. A reservation the PreToolUse hook made for this same launch is adopted. Local store
    only (dev2/T2 or HARNESS_TEST_SCOPE_ROOT); the caller treats OSError as 'no store here' and proceeds (fail open)."""
    full_sha(head, "head")
    store = Store(root or os.environ.get("HARNESS_TEST_SCOPE_ROOT") or load_policy()["root"])
    repo_id = next((d.name for d in sorted(store.root.glob("*")) if (d / f"full-{head}.json").is_file()), "_guarded")
    with store.lock(repo_id):
        held = store.read(repo_id, f"full-{head}.json", {"repo_id": repo_id, "head": head, "kind": "full"})
        if held and held.get("state") != "released":
            if held.get("state") == "finished":
                raise Refused("duplicate-full", "a full run for this head already finished (one full run per head); "
                              "release it if it was an infrastructure failure", record=held)
            if held.get("source") == "hook" and now() - held.get("at", 0) < FULL_TTL:
                held.update(source="both", guarded_token=token)  # the hook reserved this very launch
                store.write(repo_id, f"full-{head}.json", held)
                return
            if now() - held.get("at", 0) < FULL_TTL and held.get("token") != token:
                raise Refused("duplicate-full", "a full run for this head was already started under another owner (one "
                              "full run per head)", record=held)
            return
        store.write(repo_id, f"full-{head}.json", base_record(repo_id, kind="full", head=head, token=token,
                                                             state="reserved", source="guarded"))


# ---- focused scope for repair deltas ----------------------------------------------------------------------------

IMPORT_RE = re.compile(r"^[ \t]*(?:from[ \t]+\.*([A-Za-z_]\w*)(?:\.\w+)*[ \t]+import|from[ \t]+\.+[ \t]+import[ \t]+"
                       r"([A-Za-z_]\w*(?:[ \t]*,[ \t]*[A-Za-z_]\w*)*)|import[ \t]+([A-Za-z_]\w*(?:\.\w+)*"
                       r"(?:[ \t]+as[ \t]+\w+)?(?:[ \t]*,[ \t]*[A-Za-z_]\w*(?:\.\w+)*(?:[ \t]+as[ \t]+\w+)?)*))", re.M)


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
        if m.group(1):
            names.add(m.group(1))
        for group in (m.group(2), m.group(3)):
            for part in (group or "").split(","):
                names.add(re.split(r"[ \t.]", part.strip())[0])
    return names & known


REF_RE = re.compile(r"^[0-9A-Za-z._/~^@{}-]{1,200}$")


def focused_scope(repo: str, base: str, head: str) -> dict:
    """Changed files (deleted ones too), the modules that depend on them, and the test modules to run
    (harness/hooks + tests layout, plus root-level modules such as install.py)."""
    for ref in (base, head):
        if not REF_RE.match(ref) or ref.startswith("-"):
            raise ValueError("base and head must be plain git refs")
    changed = [p for p in git(repo, "diff", "--name-only", base, head, "--").splitlines() if p]
    root = Path(repo)
    src_dirs = [root / d for d in ("harness/hooks", "src", "lib") if (root / d).is_dir()] + [root]
    tests_dir = root / "tests"
    modules = {}
    for d in src_dirs:
        for f in d.glob("*.py"):
            modules[f.stem] = f
    known = set(modules)
    deleted_mods = [Path(d).stem for d in git(repo, "diff", "--name-only", "--diff-filter=D", base, head, "--").splitlines()
                    if d.endswith(".py") and Path(d).parts[0] != "tests"]
    known.update(deleted_mods)  # an importer of a deleted module must still be found
    test_files = {f.stem: f for f in tests_dir.glob("test_*.py")} if tests_dir.is_dir() else {}
    deps = {name: imports_of(f, known) for name, f in modules.items()}  # module -> modules it imports
    for name, f in list(modules.items()):
        deps.setdefault(name, set())
    touched = set()
    for name in deleted_mods:
        deps.setdefault(name, set())
        touched.add(("mod", name))
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

def repo_id_for(url: str, fallback: str) -> str:
    """owner-name slug of the remote without credentials, plus a hash of the normalized URL (or of the fallback key for
    a repo with no remote, such as its root commit), so different repos never share a store directory."""
    key = fallback
    slug = "repo"
    if url:
        norm = re.sub(r"^[a-z+]+://", "", url.strip().lower())
        norm = re.sub(r"^[^@/]*@", "", norm).replace(":", "/", 1) if "@" in norm.split("/")[0] or ":" in norm.split("/")[0] \
            else norm
        norm = re.sub(r"\.git$", "", norm).strip("/")
        key = norm
        slug = re.sub(r"[^a-z0-9._-]+", "-", norm.replace("/", "-")).strip("-")[:60] or "repo"
    return f"{slug}-{hashlib.sha256(key.encode()).hexdigest()[:8]}"


def repo_context(cwd: str) -> dict:
    top = git(cwd, "rev-parse", "--show-toplevel").strip()
    head = git(top, "rev-parse", "HEAD").strip()
    url = ""
    try:
        url = git(top, "remote", "get-url", "origin").strip()
    except OSError:
        pass
    try:
        root_commit = git(top, "rev-list", "--max-parents=0", "HEAD").split()[0]
    except (OSError, IndexError):
        root_commit = top
    repo_id = repo_id_for(url, root_commit if not url else "")
    main = ""
    for ref in ("origin/main", "origin/master"):
        try:
            main = git(top, "rev-parse", "--verify", "-q", ref).strip()
            break
        except OSError:
            continue
    return {"top": top, "head": head, "repo_id": repo_id, "main_sha": main}


CD_PREFIX_RE = re.compile(r"^\s*(?:[A-Za-z_]\w*=\S*\s+)*cd\s+(\"[^\"]+\"|'[^']+'|\S+)\s*(?:&&|;)")


def effective_cwd(command: str, cwd: str) -> str:
    """The directory the suite will run in when the command starts with `cd <dir> &&` (the common form)."""
    m = CD_PREFIX_RE.match(command or "")
    if not m:
        return cwd
    target = os.path.expanduser(m.group(1).strip("\"'"))
    path = target if os.path.isabs(target) else os.path.join(cwd, target)
    return os.path.realpath(path) if os.path.isdir(path) else cwd


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


def store_is_remote(policy: dict, root=None) -> bool:
    """True when the store lives on another host: not on the store host itself, and no local root override."""
    if root or os.environ.get("HARNESS_TEST_SCOPE_ROOT") or not policy.get("host"):
        return False
    import socket
    name = socket.gethostname().split(".")[0].lower()
    return name not in [h.lower() for h in policy.get("local_hostnames", [])]


def store_call(policy: dict, args: list):
    """Run one CLI command on the store: locally on the store host or with HARNESS_TEST_SCOPE_ROOT, else over ssh."""
    if store_is_remote(policy):
        return run_remote(os.environ.get("HARNESS_TEST_SCOPE_HOST", policy["host"]), args, int(policy["ssh_timeout_s"]))
    return cli(["--root", os.environ.get("HARNESS_TEST_SCOPE_ROOT") or policy["root"], *args], capture=True)


def hatch_reason(command: str):
    m = HATCH_RE.search(command or "")
    return next((g for g in m.groups() if g), "") if m else ""


def deny(text: str) -> int:
    print(text, file=sys.stderr)
    return 2


def hook_decision(payload: dict, policy: dict):
    """(exit_code, stderr_text). 0 allows. Only full-suite launches are judged."""
    if payload.get("tool_name") != "Bash" or not isinstance(payload.get("tool_input"), dict):
        return 0, ""
    command = payload["tool_input"].get("command")
    if not isinstance(command, str):
        return 0, ""
    import heavy_job_guard as hjg
    cwd = payload.get("cwd") if isinstance(payload.get("cwd"), str) else os.getcwd()
    _hatch, findings = hjg.scan_state(command, cwd)
    if not any(f[0] == "full-suite" for f in findings):
        return 0, ""
    reason = hatch_reason(command)
    ctx = repo_context(effective_cwd(command, cwd))
    owner = f"{payload.get('session_id', '')}:{payload.get('agent_id', '')}"
    token = owner if owner != ":" else f"anon:{uuid.uuid4().hex}"  # no identity: never share one with another caller
    if reason:
        store_call(policy, ["ungated", f"--repo-id={ctx['repo_id']}", f"--head={ctx['head']}", f"--reason={reason}"])
        return 0, ""
    is_control = bool(ctx["main_sha"]) and ctx["head"] == ctx["main_sha"]
    if is_control:
        got = store_call(policy, ["control", f"--repo-id={ctx['repo_id']}", f"--main-sha={ctx['head']}", f"--token={token}"])
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
    got = store_call(policy, ["full", f"--repo-id={ctx['repo_id']}", f"--head={ctx['head']}", f"--token={token}"])
    if got is None:
        return 0, "test_scope: store unreachable; allowing (warn only)"
    code, data = got
    if code == 2:
        hint = (" Focused tests for the changed files and their dependents: " + " ; ".join(focused)) if focused else ""
        if data.get("code") == "no-evidence":
            return 2, ("Test-scope guard [evidence]: " + data.get("message", "") + hint + " After accepted evidence: "
                       f"`python3 ~/.claude/hooks/test_scope.py accept --repo-id {ctx['repo_id']} --head {ctx['head']} "
                       "--report <report> --packet <packet>`. For an investigation, prefix HARNESS_SCOPE_OK=<reason>.")
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
    except (Exception, SystemExit) as exc:  # noqa: BLE001 - fail open: a guard bug must not block every Bash call
        print(f"test_scope: internal error {type(exc).__name__}; failing open", file=sys.stderr)
        return 0


# ---- CLI --------------------------------------------------------------------------------------------------------

REMOTE_CMDS = {"baseline-get", "baseline-record", "control", "full", "finish", "release", "ungated", "register-accepted"}
REMOTE_FLAGS = {"baseline-get": ("repo_id", "main_sha"), "baseline-record": ("repo_id", "main_sha", "command", "result",
                                                                            "counts", "failing"),
                "control": ("repo_id", "main_sha", "token"), "full": ("repo_id", "head", "token"),
                "finish": ("repo_id", "head", "result", "summary"), "release": ("repo_id", "kind", "key", "reason"),
                "ungated": ("repo_id", "head", "reason"), "register-accepted": ("repo_id", "head", "report_sha256")}


def remote_args(args) -> list:
    """The parsed command re-rendered as (flag, value) pairs for the store host; the subcommand is the first pair."""
    pairs = [("", args.cmd)]
    for name in REMOTE_FLAGS[args.cmd]:
        value = getattr(args, name, None)
        if value not in (None, ""):
            pairs.append((name.replace("_", "-"), value))
    if getattr(args, "replace", False):
        pairs.append(("", "--replace"))
    return pairs


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
    p = add("accept", "--repo-id", "--head", "--report", "--packet")
    p = add("register-accepted", "--repo-id", "--head", "--report-sha256")
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
    policy = load_policy()
    store = Store(args.root or policy["root"])

    def out(code: int, data: dict):
        if capture:
            return code, data
        print(json.dumps(data, sort_keys=True))
        return code

    try:
        if args.cmd == "hook":
            return run_hook()
        remote = store_is_remote(policy, args.root)
        if args.cmd == "accept":
            digest = validate_report(args.head, Path(args.report), Path(args.packet))  # checked here, filed on the store host
            argv = ["register-accepted", f"--repo-id={args.repo_id}", f"--head={args.head}", f"--report-sha256={digest}"]
            if remote:
                got = run_remote(os.environ.get("HARNESS_TEST_SCOPE_HOST", policy["host"]), argv, int(policy["ssh_timeout_s"]))
                return out(*(got or (4, {"error": "store unreachable"})))
            return out(0, {"accepted": True, "record": register_accepted(store, args.repo_id, args.head, digest)})
        if remote and args.cmd in REMOTE_CMDS:
            got = run_remote(os.environ.get("HARNESS_TEST_SCOPE_HOST", policy["host"]),
                             [f"--{k}={v}" if k else v for k, v in remote_args(args)], int(policy["ssh_timeout_s"]))
            return out(*(got or (4, {"error": "store unreachable"})))
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
        if args.cmd == "register-accepted":
            return out(0, {"accepted": True, "record": register_accepted(store, args.repo_id, args.head, args.report_sha256)})
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
            if remote:
                return out(3, {"error": "run-control records into the store: run it on the store host (dev2/T2)"})
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
