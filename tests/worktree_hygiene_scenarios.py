#!/usr/bin/env python3
"""harness/hooks/worktree_hygiene.py (vendored from Hawkeye, goodqa#14908), proven by running it.

Hawkeye's scenario suite, adapted only where the harness differs: hook path, state and config locations,
no ##HAWKEYE-RULES switch, and the commit suggestion. It runs with block_unpushed on (Hawkeye's
semantics); tests/test_worktree_hygiene.py covers the harness default and wraps this script.

AGENTS.md "## Worktree and branch hygiene (you cannot stop with a mess --
enforced)", Eric 2026-09-25: a session may not end its turn while a worktree
it created or worked in has uncommitted work or commits on no origin branch;
merged-but-present worktrees and duplicates are named for cleanup.

Every scenario builds REAL git repos (a bare "origin", a clone under a temp
~/repos, real `git worktree add` linked worktrees), writes a transcript in
the JSONL shape Claude Code writes (assistant records carrying tool_use blocks,
the same shape tests/test-hawkeye-supervisor.py uses), and runs the hook as a
subprocess with the stdin JSON Claude Code sends a Stop / SubagentStop hook
(session_id, transcript_path, cwd, hook_event_name, stop_hook_active, and on
SubagentStop agent_id + agent_transcript_path). HOME is a temp dir throughout:
the real ~/.hawkeye, ~/.claude and ~/repos are never read or written.

  python3 tests/test-worktree-hygiene-hook.py

HAWKEYE_TEST_WORKTREE_HOOK=<path> runs a mutated copy (negative controls).
Exit 0 pass / 1 fail.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
HOOK = os.environ.get("WTH_HOOK") or os.path.join(REPO, "harness", "hooks", "worktree_hygiene.py")

PASS: list = []
FAIL: list = []


def check(name: str, cond: bool, detail: object = "") -> None:
    if cond:
        PASS.append(name)
        print("  ok    " + name)
    else:
        FAIL.append(name)
        print("  FAIL  " + name)
        if detail != "":
            print("        " + str(detail)[:1500].replace("\n", "\n        "))


TMP = tempfile.mkdtemp(prefix="hawkeye-wt-hygiene-")
HOME = os.path.join(TMP, "home")
REPOS = os.path.join(HOME, "repos")
WTS = os.path.join(REPOS, ".tmp-worktrees")
PROJECTS = os.path.join(HOME, ".claude", "projects")
os.makedirs(WTS)
os.makedirs(PROJECTS)

_SCRUB_PREFIX = ("HAWKEYE_WORKTREE_HYGIENE_", "HARNESS_WORKTREE_", "GITHEAD_")
BASE_ENV = {k: v for k, v in os.environ.items()
            if not k.startswith(_SCRUB_PREFIX) and k not in (
                "HAWKEYE_NO_WORKTREE_GATE", "GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE")}
BASE_ENV.update({"HOME": HOME, "GIT_CONFIG_NOSYSTEM": "1", "LC_ALL": "C",
                 "HARNESS_WORKTREE_HYGIENE_BLOCK_UNPUSHED": "1",
                 "GIT_AUTHOR_NAME": "Test", "GIT_AUTHOR_EMAIL": "t@t.test",
                 "GIT_COMMITTER_NAME": "Test", "GIT_COMMITTER_EMAIL": "t@t.test"})


def git(cwd: str, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git"] + list(args), cwd=cwd, env=BASE_ENV, capture_output=True,
                          text=True, timeout=120)


def must(r: subprocess.CompletedProcess, what: str) -> str:
    if r.returncode != 0:
        raise SystemExit("SETUP FAILED (%s): %s\n%s" % (what, r.stdout, r.stderr))
    return r.stdout


def write(path: str, text: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


_N = [0]


def mk_repo(parent: str = REPOS) -> str:
    """A clone under `parent` of a fresh bare origin, one commit on main."""
    _N[0] += 1
    name = "proj%02d" % _N[0]
    bare = os.path.join(TMP, "origins", name + ".git")
    os.makedirs(os.path.dirname(bare), exist_ok=True)
    must(git(TMP, "init", "-q", "--bare", "-b", "main", bare), "bare")
    seed = os.path.join(TMP, "seed-" + name)
    must(git(TMP, "init", "-q", "-b", "main", seed), "seed")
    write(os.path.join(seed, "app.py"), "x = 1\n")
    write(os.path.join(seed, "README.md"), "seed\n")
    must(git(seed, "add", "-A"), "add")
    must(git(seed, "commit", "-q", "-m", "seed"), "commit")
    must(git(seed, "remote", "add", "origin", bare), "remote")
    must(git(seed, "push", "-q", "origin", "main"), "push")
    repo = os.path.join(parent, name)
    must(git(TMP, "clone", "-q", bare, repo), "clone")
    return repo


def add_worktree(repo: str, name: str, branch: "str | None" = None, start: str = "origin/main") -> str:
    wt = os.path.join(WTS, name)
    args = ["worktree", "add", "-q"]
    if branch:
        args += ["-b", branch, wt, start]
    else:
        args += ["--detach", wt, start]
    must(git(repo, *args), "worktree add " + name)
    return wt


def iso(t: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(t)) + ".%03dZ" % int((t % 1) * 1000)


class Transcript(object):
    """A Claude Code session transcript: ~/.claude/projects/<slug>/<sid>.jsonl,
    and its subagents under <sid>/subagents/agent-<id>.jsonl."""
    _n = [0]

    def __init__(self, cwd: str, parent: "Transcript | None" = None, agent_id: str = ""):
        Transcript._n[0] += 1
        self.cwd = cwd
        if parent is None:
            self.sid = "0000%04d-aaaa-bbbb-cccc-%012d" % (Transcript._n[0], Transcript._n[0])
            slug = "".join(c if c.isalnum() or c == "-" else "-" for c in cwd)
            self.path = os.path.join(PROJECTS, slug, self.sid + ".jsonl")
            self.agent_id = ""
        else:
            self.sid = parent.sid
            self.agent_id = agent_id or "a%015d" % Transcript._n[0]
            self.path = os.path.join(os.path.dirname(parent.path), parent.sid, "subagents",
                                     "agent-%s.jsonl" % self.agent_id)
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        open(self.path, "a").close()

    def _w(self, rec: dict) -> None:
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec) + "\n")

    def tool(self, name: str, inp: dict, ago: float = 0.0, cwd: "str | None" = None) -> None:
        self._w({"type": "assistant", "timestamp": iso(time.time() - ago), "cwd": cwd or self.cwd,
                 "sessionId": self.sid, "isSidechain": bool(self.agent_id),
                 "message": {"id": "m%d" % time.time_ns(), "role": "assistant", "type": "message",
                             "content": [{"type": "tool_use", "id": "toolu_%d" % time.time_ns(),
                                          "name": name, "input": inp}]}})

    def bash(self, command: str, ago: float = 0.0, cwd: "str | None" = None) -> None:
        self.tool("Bash", {"command": command, "description": "x"}, ago, cwd)

    def edit(self, path: str, ago: float = 0.0) -> None:
        self.tool("Edit", {"file_path": path, "old_string": "a", "new_string": "b"}, ago)

    def noise(self, text: str) -> None:
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(text)


def run_hook(t: Transcript, event: str = "Stop", stop_active: bool = False,
             env: "dict | None" = None, raw: "str | None" = None, cwd: "str | None" = None):
    ev = {"session_id": t.sid, "transcript_path": t.path, "cwd": cwd or t.cwd,
          "permission_mode": "default", "hook_event_name": event, "stop_hook_active": stop_active,
          "last_assistant_message": "done", "background_tasks": [], "session_crons": []}
    if event == "SubagentStop":
        ev["agent_id"] = t.agent_id
        ev["agent_type"] = "general-purpose"
        ev["agent_transcript_path"] = t.path
        ev["transcript_path"] = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(t.path))),
                                             t.sid + ".jsonl")
    e = dict(BASE_ENV)
    if env:
        e.update(env)
    t0 = time.monotonic()
    try:
        r = subprocess.run([sys.executable, HOOK], input=raw if raw is not None else json.dumps(ev),
                           env=e, capture_output=True, text=True, timeout=45, cwd=TMP)
    except subprocess.TimeoutExpired as exc:
        # A hook that hangs is a FAILURE to report, not a crash of this suite.
        r = subprocess.CompletedProcess(exc.cmd, None, exc.stdout or "", exc.stderr or "")
        r.stdout = r.stdout.decode() if isinstance(r.stdout, bytes) else r.stdout
        r.stderr = r.stderr.decode() if isinstance(r.stderr, bytes) else r.stderr
    r.elapsed = time.monotonic() - t0
    return r


def sysmsg(r) -> str:
    try:
        return json.loads(r.stdout).get("systemMessage", "") if r.stdout.strip() else ""
    except ValueError:
        return ""


def blocked(r) -> bool:
    return r.returncode == 2 and "WORK THAT EXISTS ONLY ON THIS DISK" in r.stderr


def snapshot(repo: str, wt: str) -> str:
    """Every byte and mtime under the repo's .git (incl. each worktree's index)
    and every file in the worktree, so any write by the hook shows up."""
    h = hashlib.sha256()
    for root in (os.path.join(repo, ".git"), wt):
        for dp, dns, fns in os.walk(root):
            dns.sort()
            for fn in sorted(fns):
                p = os.path.join(dp, fn)
                try:
                    st = os.lstat(p)
                    h.update(p.encode())
                    h.update(str(st.st_mtime_ns).encode())
                    if stat.S_ISREG(st.st_mode):
                        with open(p, "rb") as fh:
                            h.update(fh.read())
                except OSError:
                    h.update(b"gone:" + p.encode())
    return h.hexdigest()


def main() -> int:
    if not os.path.isfile(HOOK):
        print("INCOMPLETE: no hook at %s" % HOOK, file=sys.stderr)
        return 2
    try:
        scenarios()
    finally:
        shutil.rmtree(TMP, ignore_errors=True)
    print("\n%d passed, %d failed" % (len(PASS), len(FAIL)))
    return 1 if FAIL else 0


def scenarios() -> None:
    # ---- 1. a worktree this session created, left dirty ----
    print("\n[1] a created worktree with uncommitted work blocks the stop, once")
    repo = mk_repo()
    t = Transcript(repo)
    wt = os.path.join(WTS, "lane-a")
    t.bash("git -C %s worktree add -b feat/a %s origin/main" % (repo, wt), ago=120)
    must(git(repo, "worktree", "add", "-q", "-b", "feat/a", wt, "origin/main"), "wt")
    write(os.path.join(wt, "app.py"), "x = 2\n")
    write(os.path.join(wt, "new_module.py"), "y = 1\n")
    t.edit(os.path.join(wt, "app.py"), ago=60)
    # Racy-git bait: a tracked file whose mtime moved but content did not. A
    # `git status` allowed to take index.lock would refresh and REWRITE the
    # index here; the hook must not.
    os.utime(os.path.join(wt, "README.md"), (time.time() + 5, time.time() + 5))
    before = snapshot(repo, wt)
    r = run_hook(t)
    check("exit 2 (blocks the stop)", blocked(r), (r.returncode, r.stderr, r.stdout))
    check("names the exact worktree path and branch", wt in r.stderr and "feat/a" in r.stderr, r.stderr)
    check("lists the uncommitted paths", "app.py" in r.stderr and "new_module.py" in r.stderr, r.stderr)
    check("gives the commit + push commands (per-command identity, never git config)",
          ("git -C %s add -A" % wt) in r.stderr and ("git -C %s commit -F" % wt) in r.stderr
          and ("git -C %s push -u origin feat/a" % wt) in r.stderr and "git config" not in r.stderr, r.stderr)
    check("READ-ONLY: repo .git, the worktree's index and files are byte- and mtime-identical",
          snapshot(repo, wt) == before)
    check("no index.lock left behind", not any(fn == "index.lock" for _, _, fns in os.walk(os.path.join(repo, ".git"))
                                                for fn in fns))
    r2 = run_hook(t)
    check("the SAME state a second time: the stop is allowed (asked once per state)", r2.returncode == 0,
          (r2.returncode, r2.stderr))
    check("...and the operator is told once what is being left behind",
          "already asked once" in sysmsg(r2) and wt in sysmsg(r2), r2.stdout)
    r3 = run_hook(t)
    check("third stop on the same state: silent", r3.returncode == 0 and not r3.stdout.strip() and not r3.stderr,
          (r3.stdout, r3.stderr))
    write(os.path.join(wt, "another.py"), "z = 1\n")
    r4 = run_hook(t)
    check("a NEW state (another file) is a new ask: blocks again", blocked(r4), r4.stderr)

    # ---- 2. stop_hook_active ----
    print("\n[2] stop_hook_active is honoured")
    write(os.path.join(wt, "yet_another.py"), "w = 1\n")
    r = run_hook(t, stop_active=True)
    check("a dirty, never-asked state with stop_hook_active=true: NOT blocked", r.returncode == 0, r.stderr)
    check("...the operator is told why it did not block",
          "stop hook is already making it continue" in sysmsg(r), r.stdout)
    r = run_hook(t)
    check("...and that state's one ask is still owed: the next ordinary stop blocks", blocked(r), r.stderr)

    # ---- 3. committed but not pushed; then pushed ----
    print("\n[3] commits that exist on no origin ref")
    must(git(wt, "add", "-A"), "add")
    must(git(wt, "commit", "-q", "-m", "work"), "commit")
    r = run_hook(t)
    check("clean but unpushed: blocks, saying HEAD is on no origin ref",
          blocked(r) and "contained in no origin/* ref" in r.stderr and "uncommitted:" not in r.stderr, r.stderr)
    check("...with the push command and the fetch+compare check",
          ("push -u origin feat/a") in r.stderr and "rev-parse HEAD origin/feat/a" in r.stderr, r.stderr)
    must(git(wt, "push", "-q", "-u", "origin", "feat/a"), "push")
    r = run_hook(t)
    check("pushed to a pending feature branch: the stop is allowed, silently",
          r.returncode == 0 and not r.stderr, (r.returncode, r.stderr, r.stdout))

    # ---- 4. merged but still on disk -> reported, not blocked ----
    print("\n[4] merged-but-present worktrees are reported with cleanup commands")
    must(git(repo, "fetch", "-q", "origin"), "fetch")
    must(git(repo, "merge", "-q", "--no-ff", "-m", "merge feat/a", "origin/feat/a"), "merge")
    must(git(repo, "push", "-q", "origin", "main"), "push main")
    must(git(repo, "fetch", "-q", "origin"), "fetch")
    r = run_hook(t)
    msg = sysmsg(r)
    check("not blocked (exit 0)", r.returncode == 0 and not r.stderr, (r.returncode, r.stderr))
    check("systemMessage names the merged worktree", "MERGED, still on disk: %s" % wt in msg, r.stdout)
    check("...with worktree remove, branch -d and the origin branch delete",
          ("worktree remove %s" % wt) in msg and "branch -d feat/a" in msg
          and "push origin --delete feat/a" in msg, msg)
    r = run_hook(t)
    check("the same report is not repeated on the next stop", r.returncode == 0 and not r.stdout.strip(),
          r.stdout)

    # ---- 5. a fresh, clean worktree is not "merged" ----
    print("\n[5] controls: fresh clean worktrees")
    repo = mk_repo()
    t = Transcript(repo)
    wt = os.path.join(WTS, "fresh")
    t.bash("cd %s && git worktree add ../.tmp-worktrees/fresh -b feat/fresh origin/main" % repo)
    must(git(repo, "worktree", "add", "-q", "-b", "feat/fresh", wt, "origin/main"), "wt")
    r = run_hook(t)
    check("CONTROL: a fresh clean worktree on origin/main (relative path + cd, found from the transcript): "
          "no block and no 'merged' report", r.returncode == 0 and "MERGED" not in r.stdout and not r.stderr,
          (r.returncode, r.stdout, r.stderr))

    # ---- 6. leftover detached + duplicate ----
    print("\n[6] leftover detached worktrees and duplicates")
    wt2 = os.path.join(WTS, "baseline")
    t.bash("git -C %s worktree add --detach %s origin/main" % (repo, wt2))
    must(git(repo, "worktree", "add", "-q", "--detach", wt2, "origin/main"), "detached")
    r = run_hook(t)
    msg = sysmsg(r)
    check("a clean detached worktree is reported as leftover, with the remove command",
          "LEFTOVER DETACHED worktree: %s" % wt2 in msg and ("worktree remove %s" % wt2) in msg, r.stdout)
    check("it and the fresh branch worktree at the same commit are named as duplicates",
          "DUPLICATE" in msg and wt in msg and wt2 in msg, msg)
    check("the primary checkout is never called a duplicate", ("and %s " % repo) not in msg, msg)
    check("reporting never blocks", r.returncode == 0 and not r.stderr, r.stderr)

    # ---- 7. ownership: somebody else worked in it more recently ----
    print("\n[7] worktrees another transcript is working in are skipped")
    repo = mk_repo()
    a = Transcript(repo)
    wt = os.path.join(WTS, "shared")
    a.bash("git -C %s worktree add -b feat/shared %s origin/main" % (repo, wt), ago=300)
    must(git(repo, "worktree", "add", "-q", "-b", "feat/shared", wt, "origin/main"), "wt")
    a.edit(os.path.join(wt, "app.py"), ago=200)
    b = Transcript(os.path.join(REPOS, "elsewhere"))
    b.edit(os.path.join(wt, "app.py"), ago=10)
    write(os.path.join(wt, "app.py"), "x = 'b is mid-edit'\n")
    r = run_hook(a)
    check("session A (creator, older touch): NOT blocked while B works in it", r.returncode == 0 and not r.stderr,
          (r.returncode, r.stderr))
    r = run_hook(b)
    check("session B (most recent editor): blocked for it", blocked(r) and wt in r.stderr, r.stderr)

    # ---- 8. a subagent the session delegated the tree to ----
    print("\n[8] main session created the tree, its subagent is working in it")
    repo = mk_repo()
    main_t = Transcript(repo)
    wt = os.path.join(WTS, "delegated")
    main_t.bash("git -C %s worktree add -b feat/del %s origin/main" % (repo, wt), ago=100)
    must(git(repo, "worktree", "add", "-q", "-b", "feat/del", wt, "origin/main"), "wt")
    sub = Transcript(repo, parent=main_t)
    sub.edit(os.path.join(wt, "app.py"), ago=5)
    write(os.path.join(wt, "app.py"), "x = 'subagent mid-edit'\n")
    r = run_hook(main_t)
    check("main session's Stop: NOT blocked (its subagent is the one working in it)",
          r.returncode == 0 and not r.stderr, (r.returncode, r.stderr))
    r = run_hook(sub, event="SubagentStop")
    check("the subagent's SubagentStop (its own agent_transcript_path): blocked",
          blocked(r) and wt in r.stderr, (r.returncode, r.stderr))

    # ---- 9. scope: repos dir, primary checkouts, removed trees ----
    print("\n[9] scope")
    other_parent = os.path.join(TMP, "not-repos")
    os.makedirs(other_parent)
    repo = mk_repo(parent=other_parent)
    t = Transcript(repo)
    wt = os.path.join(TMP, "outside-wt")
    t.bash("git -C %s worktree add -b feat/out %s origin/main" % (repo, wt))
    must(git(repo, "worktree", "add", "-q", "-b", "feat/out", wt, "origin/main"), "wt")
    write(os.path.join(wt, "app.py"), "x = 9\n")
    r = run_hook(t)
    check("a worktree of a repo OUTSIDE ~/repos is out of scope by default", r.returncode == 0 and not r.stderr,
          r.stderr)
    r = run_hook(t, env={"HAWKEYE_WORKTREE_HYGIENE_REPOS_DIRS": other_parent})
    check("...and in scope once HAWKEYE_WORKTREE_HYGIENE_REPOS_DIRS names its parent", blocked(r), r.stderr)
    t2 = Transcript(repo)
    t2.bash("git -C %s worktree add -b feat/out2 %s/outside-wt2 origin/main" % (repo, TMP))
    must(git(repo, "worktree", "add", "-q", "-b", "feat/out2", os.path.join(TMP, "outside-wt2"), "origin/main"), "wt")
    write(os.path.join(TMP, "outside-wt2", "app.py"), "x = 10\n")
    write(os.path.join(HOME, ".agent-harness", "state", "worktree-hygiene.json"),
          json.dumps({"repos_dirs": [other_parent]}))
    r = run_hook(t2)
    check("...or once ~/.agent-harness/state/worktree-hygiene.json lists it", blocked(r), r.stderr)
    os.unlink(os.path.join(HOME, ".agent-harness", "state", "worktree-hygiene.json"))

    repo = mk_repo()
    t = Transcript(repo)
    write(os.path.join(repo, "app.py"), "x = 'primary edit'\n")
    t.edit(os.path.join(repo, "app.py"))
    r = run_hook(t)
    check("CONTROL: edits in a PRIMARY checkout (shared by many sessions) never block",
          r.returncode == 0 and not r.stderr, r.stderr)
    wt = os.path.join(WTS, "gone")
    t.bash("git -C %s worktree add -b feat/gone %s origin/main" % (repo, wt))
    must(git(repo, "worktree", "add", "-q", "-b", "feat/gone", wt, "origin/main"), "wt")
    must(git(repo, "worktree", "remove", "--force", wt), "remove")
    r = run_hook(t)
    check("a worktree the session already removed is ignored", r.returncode == 0 and not r.stderr, r.stderr)

    # ---- 10. fail open ----
    print("\n[10] fails open")
    repo = mk_repo()
    t = Transcript(repo)
    wt = os.path.join(WTS, "failopen")
    t.noise("this is not json\n{\"type\": \"assistant\", \"message\": 7}\n\n")
    t.bash("git -C %s worktree add -b feat/fo %s origin/main" % (repo, wt))
    must(git(repo, "worktree", "add", "-q", "-b", "feat/fo", wt, "origin/main"), "wt")
    write(os.path.join(wt, "app.py"), "x = 11\n")
    r = run_hook(t)
    check("garbage lines around a real record: still finds it and blocks", blocked(r), r.stderr)
    for label, raw in (("malformed stdin", "{not json"), ("empty stdin", ""), ("a JSON list", "[1, 2]"),
                       ("missing transcript", json.dumps({"hook_event_name": "Stop",
                                                          "transcript_path": os.path.join(TMP, "nope.jsonl")})),
                       ("transcript is a directory", json.dumps({"hook_event_name": "Stop",
                                                                 "transcript_path": TMP})),
                       ("another event", json.dumps({"hook_event_name": "PreToolUse",
                                                     "transcript_path": t.path}))):
        r = run_hook(t, raw=raw)
        check("%s: exit 0, nothing printed" % label, r.returncode == 0 and not r.stderr,
              (r.returncode, r.stderr))
    ro_home = os.path.join(TMP, "readonly-home")
    os.makedirs(ro_home)
    os.chmod(ro_home, 0o500)
    r = run_hook(t, env={"HOME": ro_home, "HAWKEYE_WORKTREE_HYGIENE_REPOS_DIRS": REPOS})
    os.chmod(ro_home, 0o700)
    check("state dir unwritable (so 'asked once' cannot be recorded): allowed, never an unbounded block",
          r.returncode == 0 and "Traceback" not in r.stderr, (r.returncode, r.stderr))

    # ---- 11. opt-outs ----
    print("\n[11] opt-outs")
    write(os.path.join(wt, "more.py"), "m = 1\n")
    r = run_hook(t, env={"HAWKEYE_NO_WORKTREE_GATE": "1"})
    check("HAWKEYE_NO_WORKTREE_GATE=1: allowed", r.returncode == 0 and not r.stderr, r.stderr)
    r = run_hook(t, env={"HARNESS_WORKTREE_GATE": "off"})
    check("HARNESS_WORKTREE_GATE=off: allowed", r.returncode == 0 and not r.stderr, r.stderr)

    # ---- 11b. the state dir does not grow forever ----
    print("\n[11b] old 'asked' markers are pruned")
    sd = os.path.join(HOME, ".agent-harness", "state", "worktree-hygiene", "asked")
    os.makedirs(sd, exist_ok=True)
    old_m, new_m = os.path.join(sd, "0000-stale"), os.path.join(sd, "0000-fresh")
    for pth in (old_m, new_m):
        with open(pth, "w") as fh:
            fh.write("1")
    past = time.time() - 20 * 86400
    os.utime(old_m, (past, past))
    run_hook(t, env={"HAWKEYE_NO_WORKTREE_GATE": "0"})
    check("a 20-day-old marker is removed by a later stop", not os.path.exists(old_m))
    check("CONTROL: a fresh marker is kept", os.path.exists(new_m))

    # ---- 12. the budget: a hanging git cannot hold the session ----
    print("\n[12] runtime is capped")
    fakebin = os.path.join(TMP, "fakebin")
    os.makedirs(fakebin)
    # A git that never returns AND leaves a long-lived child behind (the way a
    # real git can: a credential helper, an fsmonitor, a pager). Both carry
    # this unique fakebin path in their argv, which the orphan check greps for.
    write(os.path.join(fakebin, "git.child"), "#!/bin/sh\nwhile :; do sleep 1; done\n")
    write(os.path.join(fakebin, "git"), "#!/bin/sh\n/bin/sh %s &\nwhile :; do sleep 1; done\n"
          % os.path.join(fakebin, "git.child"))
    os.chmod(os.path.join(fakebin, "git"), 0o755)
    marker = fakebin
    hang_env = {"PATH": fakebin + os.pathsep + BASE_ENV.get("PATH", "")}
    write(os.path.join(wt, "hang.py"), "h = 1\n")
    r = run_hook(t, env=dict(hang_env, HAWKEYE_WORKTREE_HYGIENE_BUDGET_S="2"))
    check("git hangs, 2s budget: exit 0 (fail open) in well under 10s",
          r.returncode == 0 and r.elapsed < 10, (r.returncode, round(r.elapsed, 1), r.stderr))
    r = run_hook(t, env=hang_env)
    check("git hangs, DEFAULT budget: exit 0 within the ~15s cap",
          r.returncode == 0 and r.elapsed < 17, (r.returncode, round(r.elapsed, 1)))
    time.sleep(0.5)
    left = subprocess.run(["pgrep", "-f", marker], capture_output=True, text=True)
    check("no hung git process, nor its child, outlives the hook (process group killed)",
          not left.stdout.strip(), left.stdout)
    # Never leave a looping process on a shared box, even when that check is red.
    subprocess.run(["pkill", "-f", marker], capture_output=True)

    # ---- 12b. later git calls get only what is left of the budget ----
    # [12]'s git never returns, so it only proves the FIRST call is cut off.
    # This git is slow but finite: every call takes SLOW seconds and then really
    # runs. With a BUDGET-second budget the first calls complete and the one
    # that would cross the budget must be cut at the budget's end -- not given
    # its own full per-call timeout, and not followed by more calls.
    print("\n[12b] per-call git timeouts shrink with the remaining budget")
    real_git = shutil.which("git", path=BASE_ENV.get("PATH")) or "/usr/bin/git"
    slowbin = os.path.join(TMP, "slowbin")
    os.makedirs(slowbin)
    slow_log = os.path.join(TMP, "slowgit.log")
    SLOW, BUDGET = 1.5, 4.0
    write(os.path.join(slowbin, "git"), "#!/bin/sh\necho start >> %s\nsleep %s\necho end >> %s\nexec %s \"$@\"\n"
          % (slow_log, SLOW, slow_log, real_git))
    os.chmod(os.path.join(slowbin, "git"), 0o755)
    repo = mk_repo()
    t = Transcript(repo)
    wt = os.path.join(WTS, "slowgit")
    t.bash("git -C %s worktree add -b feat/slow %s origin/main" % (repo, wt))
    must(git(repo, "worktree", "add", "-q", "-b", "feat/slow", wt, "origin/main"), "wt")
    write(os.path.join(wt, "app.py"), "x = 'slow'\n")
    r = run_hook(t, env={"PATH": slowbin + os.pathsep + BASE_ENV.get("PATH", ""),
                         "HAWKEYE_WORKTREE_HYGIENE_BUDGET_S": str(BUDGET)})
    with open(slow_log, encoding="utf-8") as fh:
        log = fh.read().split()
    starts, ends = log.count("start"), log.count("end")
    check("a slow (%.1fs/call) git under a %.0fs budget: exit 0 (fail open) and done by the budget's end, "
          "not after further full-length calls" % (SLOW, BUDGET),
          r.returncode == 0 and r.elapsed < BUDGET + 1.5, (r.returncode, round(r.elapsed, 2), log))
    check("...exactly one git call was cut short, and it was the last one (%d started, %d finished)"
          % (starts, ends), starts >= 2 and starts - ends == 1, log)

    # ---- 13. a Bash `git commit` as the ONLY signal ----
    print("\n[13] a mutating git command, alone, is enough to own a worktree")
    repo = mk_repo()
    wt = add_worktree(repo, "commit-only", "feat/commit-only")
    write(os.path.join(wt, "app.py"), "x = 'committed, never pushed'\n")
    must(git(wt, "add", "-A"), "add")
    must(git(wt, "commit", "-q", "-m", "local only"), "commit")
    for label, cmd in (("cd <tree> && git commit", "cd %s && git commit -q -m local-only" % wt),
                       ("git -C <tree> commit", "git -C %s commit -q -m local-only" % wt)):
        t = Transcript(repo)          # nothing else: no Edit, no `worktree add`
        t.bash(cmd)
        r = run_hook(t)
        check("%s is the transcript's only touch: blocks (HEAD on no origin ref)" % label,
              blocked(r) and wt in r.stderr and "contained in no origin/* ref" in r.stderr, (r.returncode, r.stderr))
    t = Transcript(repo)
    t.bash("git -C %s status --short && git -C %s log --oneline -3" % (wt, wt))
    r = run_hook(t)
    check("CONTROL: only read-only git (status, log) in it: not this session's tree, no block",
          r.returncode == 0 and not r.stderr, (r.returncode, r.stderr))

    # ---- 14. an unresolvable target is DROPPED, never pinned on the cwd ----
    print("\n[14] git -C / cd targets the hook cannot resolve are dropped, not given to the cwd")
    repo = mk_repo()
    here = add_worktree(repo, "cwd-tree", "feat/cwd-tree")     # the session merely sits in it
    write(os.path.join(here, "app.py"), "x = 'somebody else is mid-edit'\n")
    elsewhere = os.path.join(TMP, "plain-dir")
    os.makedirs(elsewhere, exist_ok=True)
    # A second dirty worktree as the target of a cd that may or may not have
    # run: it must not be claimed either.
    maybe = add_worktree(repo, "cd-maybe", "feat/cd-maybe")
    write(os.path.join(maybe, "app.py"), "x = 'also not this session\'s'\n")
    for label, cmd in (
            ('git -C "$WT" commit', 'git -C "$WT" commit -q -m x'),
            ("git -C $WT commit (unquoted)", "git -C $WT commit -q -m x"),
            ('git -C "${WT}/sub" commit', 'git -C "${WT}/sub" commit -q -m x'),
            ('git -C "$(git rev-parse --show-toplevel)" commit',
             'git -C "$(git -C /somewhere rev-parse --show-toplevel)" commit -q -m x'),
            ("git -C `pwd` add", "git -C `mktemp -d` add -A"),
            ('cd "$WT" && git commit', 'cd "$WT" && git commit -q -m x'),
            ("cd $(mktemp -d) && git add", "cd $(mktemp -d) && git add -A"),
            ("cd - && git commit", "cd - && git commit -q -m x"),
            ("popd && git commit", "popd && git commit -q -m x"),
            ("git --git-dir=... --work-tree=<not a worktree> commit",
             "git --git-dir=%s/.git --work-tree=%s commit -q -m x" % (elsewhere, elsewhere)),
            ("GIT_DIR=... git commit", "GIT_DIR=%s/.git git commit -q -m x" % elsewhere),
            ("GIT_WORK_TREE=$X git commit", "GIT_WORK_TREE=$X GIT_DIR=$X/.git git commit -q -m x"),
            ("test -d x && cd x; git commit (cd may not have run)",
             "test -d %s && cd %s; git commit -q -m x" % (maybe, maybe)),
            ("cd x || true; git commit (cd may have failed)", "cd %s || true; git commit -q -m x" % maybe),
            ("cd <plain dir> && git init && git add", "cd %s && git init -q && git add -A" % elsewhere),
            # Shell variables: followed only when this command assigned a literal
            # unconditionally, outside a subshell, and nothing re-set it since.
            ("W=<tree> as a PREFIX only sets that command's env: W=x true; git -C \"$W\" commit",
             'W=%s true; git -C "$W" commit -q -m x' % maybe),
            ("a conditional assignment: test -d x && W=x; git -C \"$W\" commit",
             'test -d %s && W=%s; git -C "$W" commit -q -m x' % (maybe, maybe)),
            ("W re-set by read: W=x; read -r W < f; git -C \"$W\" commit",
             'W=%s; read -r W < /dev/null; git -C "$W" commit -q -m x' % maybe),
            ("an assignment inside a subshell does not leak: (W=x); git -C \"$W\" commit",
             '(W=%s); git -C "$W" commit -q -m x' % maybe),
            ("a loop re-sets W: W=x; for W in a b; do git -C \"$W\" commit; done",
             'W=%s; for W in a b; do git -C "$W" commit -q -m x; done' % maybe),
            ("W from a command substitution: W=$(...); git -C \"$W\" commit",
             'W=$(echo %s); git -C "$W" commit -q -m x' % maybe),
            ("eval may re-set anything: W=x; eval \"$SETUP\"; git -C \"$W\" commit",
             'W=%s; eval "$SETUP"; git -C "$W" commit -q -m x' % maybe),
            ("so may source: W=x; . ./env.sh; git -C \"$W\" commit",
             'W=%s; . ./env.sh; git -C "$W" commit -q -m x' % maybe)):
        t = Transcript(repo)
        t.bash(cmd, cwd=here)
        r = run_hook(t)
        check("%s, run from inside a dirty worktree: NOT attributed to that worktree (nor any other)" % label,
              r.returncode == 0 and not r.stderr, (r.returncode, r.stderr))
    for label, cmd, run_from in (
            ("CONTROL: a bare `git commit` in the cwd tree", "git commit -q -m x", here),
            ("CONTROL: `git -C .` with a literal path", "git -C . commit -q -m x", here),
            ("CONTROL: a subshell's cd does not leak: (cd /x && make); git commit",
             "(cd %s && true); git commit -q -m x" % elsewhere, here),
            ("CONTROL: a piped cd runs in a subshell: cd /x | cat; git commit",
             "cd %s | cat; git commit -q -m x" % elsewhere, here),
            ("CONTROL: cd <tree> || exit 1; git commit (git runs only if that cd worked)",
             "cd %s || exit 1; git commit -q -m x" % here, elsewhere),
            ("CONTROL: a multi-line command: cd <tree> on one line, git commit on the next",
             "cd %s\ngit add -A\ngit commit -q -m x" % here, elsewhere),
            ("CONTROL: git -C <relative path> after cd", "cd %s && git -C .tmp-worktrees/cwd-tree commit -q -m x"
             % REPOS, elsewhere),
            ('CONTROL: git -C "" commit (an empty -C is a no-op)', 'git -C "" commit -q -m x', here),
            ("CONTROL: GIT_WORK_TREE=<the tree> git commit", "GIT_WORK_TREE=%s git commit -q -m x" % here,
             elsewhere),
            ("CONTROL: W=<tree> on its own line, then cd $W && git commit",
             "W=%s\ncd $W && git commit -q -m x" % here, elsewhere),
            ('CONTROL: export W=<tree>; X=$W; git -C "${X}" commit',
             'export W=%s; X=$W; git -C "${X}" commit -q -m x' % here, elsewhere),
            ('CONTROL: git -C "$HOME/..." resolves $HOME',
             'git -C "$HOME/repos/.tmp-worktrees/cwd-tree" commit -q -m x', elsewhere)):
        t = Transcript(repo)
        t.bash(cmd, cwd=run_from)
        r = run_hook(t)
        check("%s: IS attributed, blocks" % label, blocked(r) and here in r.stderr, (r.returncode, r.stderr))

    # ---- 15. heredoc / here-string / multi-line quoted text is data ----
    print("\n[15] a heredoc or here-string body that quotes a git command is not a command")
    repo = mk_repo()
    quoted = add_worktree(repo, "quoted-only", "feat/quoted-only")
    write(os.path.join(quoted, "app.py"), "x = 'dirty, and this session never worked here'\n")
    real = add_worktree(repo, "really-used", "feat/really-used")
    write(os.path.join(real, "app.py"), "x = 'this one the session did commit in'\n")
    notes = os.path.join(TMP, "notes.md")
    for label, cmd, real_used in (
            ("cat > notes <<'EOF' (body quotes cd+commit and git -C add)",
             "cat > %s <<'EOF'\ncd %s && git commit -m y\ngit -C %s add -A\nEOF" % (notes, quoted, quoted), False),
            ("unquoted <<EOF delimiter", "cat > %s <<EOF\ngit -C %s commit -m y\nEOF\n" % (notes, quoted), False),
            ("<<-EOF with a tab-indented body and delimiter (and a real command after it)",
             "cat > %s <<-EOF\n\tgit -C %s commit -m y\n\tEOF\ngit -C %s commit -q -m x" % (notes, quoted, real),
             True),
            ("two heredocs on one line",
             "cat <<A > %s; cat <<B >> %s\ngit -C %s reset --hard\nA\ngit -C %s rebase main\nB\n"
             % (notes, notes, quoted, quoted), False),
            ("a heredoc piped into python", "python3 - <<'PY' | tee %s\nimport os\n"
             "os.system('git -C %s commit -m y')\ngit -C %s commit -m z\nPY\n" % (notes, quoted, quoted), False),
            ("here-string, multi-line single-quoted",
             "cat <<< 'intro\ngit -C %s commit -m y\noutro'" % quoted, False),
            ("here-string, one line", 'wc -l <<< "git -C %s commit -m y"' % quoted, False),
            ("the commit-message heredoc idiom (body quotes git -C <other> reset, and an apostrophe)",
             "git -C %s commit -q -m \"$(cat <<'EOF'\nfix: don't lose \"work (a lone quote) or a ) paren\n\n"
             "git -C %s reset --hard\nEOF\n)\""
             % (real, quoted), True),
            ("git commit -F - <<'EOF' with a body quoting another tree",
             "git -C %s commit -q -F - <<'EOF'\nsubject\n\ncd %s && git commit -m nope\nEOF" % (real, quoted), True),
            ("a multi-line double-quoted -m",
             "git -C %s commit -q -m \"subject\n\ngit -C %s rebase main\n\"" % (real, quoted), True),
            ("a # comment naming a git command", "true # ; git -C %s commit -m y\ngit -C %s commit -q -m x"
             % (quoted, real), True),
            ("odd whitespace (no-break space, vertical tab, form feed) in an earlier command",
             "echo a\u00a0b\x0bc\x0cd; git -C %s commit -q -m \"na\u00efve\u00a0msg\"" % real, True)):
        t = Transcript(repo)
        t.bash(cmd)
        r = run_hook(t)
        ok_quoted = quoted not in r.stderr
        ok_real = blocked(r) and real in r.stderr if real_used else (r.returncode == 0 and not r.stderr)
        check("%s: the quoted tree is NOT this session's%s" % (
            label, "; the real command's tree still IS" if real_used else ", nothing blocks"),
            ok_quoted and ok_real, (r.returncode, r.stderr))
    t = Transcript(repo)
    t.bash("cat > %s <<'EOF'\njust text\nEOF\ngit -C %s commit -q -m after" % (notes, quoted))
    r = run_hook(t)
    check("CONTROL: a command AFTER the heredoc's closing delimiter is still seen (blocks for that tree)",
          blocked(r) and quoted in r.stderr, (r.returncode, r.stderr))

    # ---- 16. repos without an `origin` remote ----
    print("\n[16] no `origin`: commits on no remote at all are disk-only")
    # (a) no remote of any kind
    local = os.path.join(REPOS, "local-only")
    must(git(TMP, "init", "-q", "-b", "main", local), "init local")
    write(os.path.join(local, "app.py"), "x = 1\n")
    must(git(local, "add", "-A"), "add")
    must(git(local, "commit", "-q", "-m", "seed"), "seed")
    t = Transcript(local)
    fresh = os.path.join(WTS, "local-fresh")
    t.bash("git -C %s worktree add -b feat/local-fresh %s main" % (local, fresh))
    must(git(local, "worktree", "add", "-q", "-b", "feat/local-fresh", fresh, "main"), "wt")
    r = run_hook(t)
    check("CONTROL: a clean worktree holding no commit of its own in a no-remote repo: no block",
          r.returncode == 0 and not r.stderr, (r.returncode, r.stderr))
    t = Transcript(local)
    lw = os.path.join(WTS, "local-work")
    t.bash("git -C %s worktree add -b feat/local-work %s main" % (local, lw))
    must(git(local, "worktree", "add", "-q", "-b", "feat/local-work", lw, "main"), "wt")
    write(os.path.join(lw, "app.py"), "x = 'only here'\n")
    must(git(lw, "commit", "-q", "-am", "work that exists nowhere else"), "commit")
    t.bash("git -C %s commit -q -am 'work that exists nowhere else'" % lw)
    r = run_hook(t)
    check("no remote at all + a commit no other branch holds: blocks, and says WHY (no remote)",
          blocked(r) and lw in r.stderr and "no remote" in r.stderr, (r.returncode, r.stderr))
    check("...and tells a deliberately local-only repo how to answer (say so and stop)",
          "local-only" in r.stderr and "say so" in r.stderr, r.stderr)
    write(os.path.join(lw, "app.py"), "x = 'only here, v2'\n")
    must(git(lw, "commit", "-q", "-am", "another local commit"), "commit")
    r = run_hook(t)
    check("a further commit in the same no-remote tree is not a new ask (once per session per tree)",
          r.returncode == 0 and not r.stderr, (r.returncode, r.stderr))
    # (b) a remote, just not called origin
    repo = mk_repo()
    must(git(repo, "remote", "rename", "origin", "upstream"), "rename remote")
    t = Transcript(repo)
    uw = os.path.join(WTS, "upstream-only")
    t.bash("git -C %s worktree add -b feat/up %s upstream/main" % (repo, uw))
    must(git(repo, "worktree", "add", "-q", "-b", "feat/up", uw, "upstream/main"), "wt")
    write(os.path.join(uw, "app.py"), "x = 'up'\n")
    must(git(uw, "commit", "-q", "-am", "up"), "commit")
    t.bash("git -C %s commit -q -am up" % uw)
    r = run_hook(t)
    check("only an `upstream` remote, HEAD on none of its refs: blocks with `push -u upstream feat/up`",
          blocked(r) and uw in r.stderr and "push -u upstream feat/up" in r.stderr, (r.returncode, r.stderr))
    must(git(uw, "push", "-q", "-u", "upstream", "feat/up"), "push upstream")
    r = run_hook(t)
    check("...and once pushed to upstream: allowed, silently", r.returncode == 0 and not r.stderr,
          (r.returncode, r.stderr))


if __name__ == "__main__":
    sys.exit(main())
