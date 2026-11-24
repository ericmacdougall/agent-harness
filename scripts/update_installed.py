#!/usr/bin/env python3
"""Update the installed harness on this Mac and on t2-dev to one merged commit. USER-RUN: an agent never runs it.

    python3 -I scripts/update_installed.py --preview                  # what would change; installs nothing
    python3 -I scripts/update_installed.py --ticket "GoodQA goodqa#N"  # install origin/main HEAD
    python3 -I scripts/update_installed.py --commit <sha> --ticket "GoodQA goodqa#N"

`-I` is required: without it, a file next to this script or PYTHONPATH could replace a module it imports.

Steps, each of which stops the run when it fails (nothing after a failed step runs):
  0. Refuse when an agent marker is set in the environment (CLAUDECODE, CODEX_THREAD_ID, CODEX_TOOL_CALL_ID,
     CODEX_SANDBOX, AI_AGENT), for a preview too: its remote dry runs are a main-only command. A mitigation, not a
     boundary (an agent can unset them); the command_guard rule that refuses agent calls is goodqa#17036.
  1. Fetch the canonical main into a FRESH bare repository (~/.agent-harness/update-cache/run-XXXXXXXXXXXX, created
     exclusively, deleted at the end) with hardened git: no system or global config, no hooks, no fsmonitor, no
     replace objects, https only, every fetched object fsck-checked. Grafts, shallow history and replace refs stop the run.
  2. The commit (default: main HEAD) must be an ancestor of that main.
  3. Export the commit's tree into the run folder. Every object is re-hashed against its id; only regular files and
     folders are accepted.
  4. Derive the file lists, never hand-kept: every name in install.py's AGENTS, HOOKS, TOOLS and SKILLS literal tuples
     at the commit whose copy under ~/.claude is missing, a symlink, or differs from the commit's bytes; for each remote
     host, every HOOKS name that `ah install-files --dry-run` does not report as already current. A Mac file that main
     changed after the commit stops the run (it would be a downgrade); ah_install refuses the same for the host.
  5. A real run asks for the first 12 characters of the commit on /dev/tty (a person at a terminal); no flag skips it.
  6. Mac: `python3 -B -E -s install.py --apply --hooks-only --home H` from the export (CLAUDE.md and settings.json are
     not touched; replaced files are backed up). Every listed file is then compared with the commit.
  7. Each remote host: `ah install-files --host H --from-ref <sha> --file ... --ticket T` in batches of 20, with
     command_guard.py in the last batch; each batch's run id is printed. A second dry run must report every file current.
  8. Registration: hooks the new manifest declares that settings.json does not register are reported (doctor on the
     Mac, ah_install's `unregistered` on a host). --hooks-only never edits settings.json, so the run then exits 3.

Run time: a preview makes ceil(N/20) dry runs per host, N = the HOOKS count at the commit (about 110 today, so 6);
a real run makes those, one install per batch of changed files, and the same dry runs again.

Exit: 0 installed and registered (or preview), 1 stopped, 2 usage or not started with -I, 3 installed with hooks that
need registering.
"""
import sys

if __name__ == "__main__" and not sys.flags.isolated:
    sys.stderr.write("STOP: run it as `python3 -I scripts/update_installed.py ...`: without -I, a file next to the "
                     "script or PYTHONPATH could replace a module it imports.\n")
    sys.exit(2)

import argparse  # noqa: E402
import ast  # noqa: E402
import hashlib  # noqa: E402
import json  # noqa: E402
import math  # noqa: E402
import os  # noqa: E402
import re  # noqa: E402
import shutil  # noqa: E402
import subprocess  # noqa: E402
import time  # noqa: E402
import uuid  # noqa: E402
from pathlib import Path  # noqa: E402

CANONICAL_URL = "https://github.com/ericmacdougall/agent-harness.git"
ALLOW_FILE = False              # tests only: lets the fetch read a local bare repository standing in for the URL
REMOTE_HOSTS = ("t2-dev",)
BATCH = 20                      # ah_install.MAX_FILES (contract test)
GUARD = "command_guard.py"      # ah_install.order() puts it last in a call; here it goes in the LAST batch too
FOLDERS = (("agents", "AGENTS"), ("hooks", "HOOKS"), ("tools", "TOOLS"), ("skills", "SKILLS"))
SHA_RE = re.compile(r"[0-9a-f]{40}")
TICKET_RE = re.compile(r"GoodQA [A-Za-z0-9_-]+#[0-9]+")
NAME_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]*")
AGENT_MARKERS = ("CLAUDECODE", "CODEX_THREAD_ID", "CODEX_TOOL_CALL_ID", "CODEX_SANDBOX", "AI_AGENT")  # = commit_policy
GIT_TIMEOUT = 300
FETCH_TIMEOUT = 600
INSTALL_TIMEOUT = 1800
DOCTOR_TIMEOUT = 300
MAX_EXPORT_BYTES = 256 << 20
MAX_EXPORT_FILES = 20000
UNREGISTERED = "MISSING"        # doctor's state for a declared, required hook that settings.json does not register
NOT_REGISTERED_BEFORE = ("PENDING", "OFF")
EXIT_OK, EXIT_STOP, EXIT_USAGE, EXIT_REGISTER = 0, 1, 2, 3


class Stop(Exception):
    """A refusal: nothing after the failed step ran."""


# ----------------------------------------------------------------------------- hardened git (mirrors ah_install)

def git_env(home):
    """Built from an allowlist, so GIT_DIR, GIT_CONFIG_COUNT/KEY/VALUE, GIT_TEMPLATE_DIR and the like never reach git.
    Equal to ah_install.git_env (contract test)."""
    env = {k: os.environ[k] for k in ("PATH", "LANG", "LC_ALL", "TMPDIR") if k in os.environ}
    env["PATH"] = os.pathsep.join(p for p in env.get("PATH", "").split(os.pathsep) if p.startswith("/")) or "/usr/bin:/bin"
    env.update(HOME=str(home), GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_NOSYSTEM="1", GIT_TERMINAL_PROMPT="0",
               GIT_NO_REPLACE_OBJECTS="1", GIT_OPTIONAL_LOCKS="0", GIT_ASKPASS="/bin/true", LC_ALL="C")
    return env


def git_argv(repo, args):
    argv = ["git", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", "-c", "core.commitGraph=false",
            "-c", "protocol.allow=never", "-c", "protocol.https.allow=always"]
    if ALLOW_FILE:
        argv += ["-c", "protocol.file.allow=always"]
    return argv + ["-C", str(repo)] + list(args)


def git(repo, args, home, timeout=GIT_TIMEOUT, check=True, data=None):
    try:
        done = subprocess.run(git_argv(repo, args), capture_output=True, timeout=timeout, env=git_env(home), input=data)
    except subprocess.TimeoutExpired:
        raise Stop("git %s timed out after %d s" % (args[0], timeout))
    except OSError as e:
        raise Stop("git %s could not start: %s" % (args[0], e))
    if check and done.returncode != 0:
        raise Stop("git %s failed: %s" % (args[0], done.stderr.decode("utf-8", "replace").strip()[-300:]))
    return done


def verified(kind, oid, body):
    if hashlib.sha1(("%s %d\0" % (kind, len(body))).encode() + body).hexdigest() != oid:
        raise Stop("the %s object %s does not hash to its own id" % (kind, oid[:12]))
    return body


def read_object(repo, home, kind, oid):
    """Bytes of one object, re-hashed here: git does not hash-check an object on a plain read."""
    if not SHA_RE.fullmatch(oid):
        raise Stop("the repository uses an object format other than sha1")
    return verified(kind, oid, git(repo, ["cat-file", kind, oid], home).stdout)


def tree_entries(body):
    out, i = [], 0
    while i < len(body):
        sp = body.index(b" ", i)
        nul = body.index(b"\0", sp)
        out.append((body[i:sp].decode(), body[sp + 1:nul].decode("utf-8", "surrogateescape"), body[nul + 1:nul + 21].hex()))
        i = nul + 21
    return out


# ----------------------------------------------------------------------------- fresh source

def new_run_dir(home):
    root = Path(home) / ".agent-harness" / "update-cache"
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    st = os.lstat(root)
    if os.path.islink(root) or st.st_uid != os.getuid() or st.st_mode & 0o077:
        raise Stop("%s is a symlink, belongs to another user or is open to others" % root)
    for old in root.iterdir():          # this tool's own leftovers older than an hour, by the fixed name pattern only
        try:
            if re.fullmatch(r"run-[0-9a-f]{12}", old.name) and not old.is_symlink() and old.is_dir() \
                    and time.time() - old.lstat().st_mtime > 3600:
                shutil.rmtree(old)
        except OSError:
            pass
    run = root / ("run-" + uuid.uuid4().hex[:12])
    try:
        os.mkdir(run, 0o700)            # exclusive: an existing folder of that name stops the run
    except FileExistsError:
        raise Stop("%s already exists" % run)
    return run


def fetch_main(run, home):
    repo = run / "main.git"
    os.mkdir(repo, 0o700)
    git(repo, ["init", "-q", "--bare"], home)
    for key in ("transfer.fsckObjects", "fetch.fsckObjects", "receive.fsckObjects"):
        git(repo, ["config", key, "true"], home)
    git(repo, ["fetch", "-q", "--no-tags", "--no-write-fetch-head", CANONICAL_URL, "+refs/heads/main:refs/heads/main"],
        home, timeout=FETCH_TIMEOUT)
    for forbidden in ("info/grafts", "shallow"):
        if (repo / forbidden).exists():
            raise Stop("the fetched repository has a %s file" % forbidden)
    if git(repo, ["for-each-ref", "refs/replace"], home).stdout.strip():
        raise Stop("the fetched repository has replace refs")
    return repo, git(repo, ["rev-parse", "--verify", "refs/heads/main^{commit}"], home).stdout.decode().strip()


def resolve_commit(repo, home, main, commit):
    commit = commit or main
    if git(repo, ["cat-file", "-e", commit + "^{commit}"], home, check=False).returncode != 0:
        raise Stop("%s is not a commit of the canonical main history; nothing was changed" % commit)
    if git(repo, ["merge-base", "--is-ancestor", commit, main], home, check=False).returncode != 0:
        raise Stop("%s is not on origin/main; nothing was changed" % commit)
    return commit


def export_commit(repo, home, commit, dest):
    """Write the commit's tree under `dest` from re-hashed objects only. Returns the commit subject."""
    body = read_object(repo, home, "commit", commit)
    m = re.match(rb"tree ([0-9a-f]{40})\n", body)
    if not m:
        raise Stop("the commit has no tree line")
    blobs, todo = [], [(m.group(1).decode(), dest)]
    while todo:
        oid, path = todo.pop()
        os.mkdir(path, 0o700)
        for mode, name, child in tree_entries(read_object(repo, home, "tree", oid)):
            if name in ("", ".", "..", ".git") or "/" in name or "\0" in name:
                raise Stop("the commit has an unsafe path entry %r" % name)
            if mode == "40000":
                todo.append((child, path / name))
            elif mode in ("100644", "100755"):
                blobs.append((child, path / name, mode))
            else:
                raise Stop("%s is not a regular file or folder in the commit (mode %s)" % (path / name, mode))
            if len(blobs) > MAX_EXPORT_FILES:
                raise Stop("the commit has more than %d files" % MAX_EXPORT_FILES)
    data = git(repo, ["cat-file", "--batch"], home, data="".join(oid + "\n" for oid, _, _ in blobs).encode()).stdout
    pos, total = 0, 0
    for oid, path, mode in blobs:
        nl = data.index(b"\n", pos)
        head = data[pos:nl].decode().split()
        if len(head) != 3 or head[0] != oid or head[1] != "blob":
            raise Stop("git cat-file --batch answered %r for %s" % (head, oid[:12]))
        size = int(head[2])
        total += size
        if total > MAX_EXPORT_BYTES:
            raise Stop("the commit is larger than %d bytes" % MAX_EXPORT_BYTES)
        content = verified("blob", oid, data[nl + 1:nl + 1 + size])
        pos = nl + 2 + size
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                     0o755 if mode == "100755" else 0o644)
        try:
            os.write(fd, content)
        finally:
            os.close(fd)
    msg = body.split(b"\n\n", 1)
    return msg[1].decode("utf-8", "replace").splitlines()[0][:120] if len(msg) == 2 and msg[1].strip() else ""


# ----------------------------------------------------------------------------- derivation

def installer_lists(export):
    """{folder: [names]} from the exported install.py (literal tuples of bare names only; anything else stops)."""
    found = {}
    for stmt in ast.parse((Path(export) / "install.py").read_bytes().decode("utf-8")).body:
        if not isinstance(stmt, ast.Assign):
            continue
        for target in stmt.targets:
            for folder, var in FOLDERS:
                if isinstance(target, ast.Name) and target.id == var:
                    try:
                        names = ast.literal_eval(stmt.value)
                    except (ValueError, SyntaxError, TypeError):
                        raise Stop("install.py %s is not a literal tuple" % var)
                    if not isinstance(names, tuple) or not all(isinstance(n, str) and NAME_RE.fullmatch(n)
                                                               for n in names):
                        raise Stop("install.py %s is not a tuple of bare file names" % var)
                    found[folder] = list(names)
    if "hooks" not in found:
        raise Stop("install.py has no HOOKS list")
    return {folder: found.get(folder, []) for folder, _ in FOLDERS}


def file_sha(path):
    p = Path(path)
    if p.is_symlink() or not p.is_file():
        return None
    return hashlib.sha256(p.read_bytes()).hexdigest()


def local_changes(export, home, lists):
    """Installed files (folder/name) that are missing, a symlink, or differ from the commit."""
    out = []
    for folder, _ in FOLDERS:
        for name in lists[folder]:
            rel = "%s/%s" % (folder, name)
            want = file_sha(Path(export) / "harness" / rel)
            if want is None:
                raise Stop("install.py lists %s but the commit has no harness/%s" % (rel, rel))
            if file_sha(Path(home) / ".claude" / rel) != want:
                out.append(rel)
    return out


def downgrades(repo, home, commit, main, rels):
    """Files main changed after the commit: installing the commit's copy would put an older version in place
    (the same test as ah_install's `older_ref`)."""
    out = []
    for rel in rels:
        if git(repo, ["log", "--format=%H", "%s..%s" % (commit, main), "--", "harness/" + rel], home).stdout.strip():
            out.append(rel)
    return out


def ordered(names):
    """ah_install.order(): everything else first, command_guard.py LAST."""
    return [n for n in names if n != GUARD] + ([GUARD] if GUARD in names else [])


def batches(names):
    names = ordered(names)
    return [names[i:i + BATCH] for i in range(0, len(names), BATCH)]


# ----------------------------------------------------------------------------- the person at the terminal

def agent_markers(environ):
    return [k for k in AGENT_MARKERS if environ.get(k)]


def read_tty(prompt):
    try:
        with open("/dev/tty", "r+") as tty:
            tty.write(prompt)
            tty.flush()
            return tty.readline()
    except OSError:
        raise Stop("no terminal: a real run is confirmed by a person typing at a terminal")


def confirm(commit, reader):
    got = (reader("Install %s on this Mac and the listed hosts? Type its first 12 characters to go on: " % commit)
           or "").strip()
    if got != commit[:12]:
        raise Stop("not confirmed; nothing was installed")


# ----------------------------------------------------------------------------- ah install-files and doctor

def ah_argv(home, host, commit, names, ticket, dry_run):
    argv = [sys.executable, "-I", str(Path(home) / ".claude" / "hooks" / "ah.py"), "install-files", "--host", host,
            "--from-ref", commit]
    for name in names:
        argv += ["--file", name]
    return argv + (["--dry-run"] if dry_run else ["--ticket", ticket])


def ah_call(runner, argv, what):
    try:
        r = runner(argv, capture_output=True, text=True, timeout=INSTALL_TIMEOUT)
    except subprocess.TimeoutExpired:
        raise Stop("%s timed out after %d s" % (what, INSTALL_TIMEOUT))
    except OSError as e:
        raise Stop("%s could not start: %s" % (what, e))
    try:
        data = json.loads(r.stdout)
    except (TypeError, ValueError):
        data = None
    files = data.get("files") if isinstance(data, dict) else None
    if r.returncode != 0 or not isinstance(files, dict) or not all(isinstance(v, dict) for v in files.values()):
        raise Stop("%s failed with exit %s: %s" % (what, r.returncode, (r.stdout or r.stderr or "")[-400:]))
    return data


def remote_changes(home, host, commit, hooks, runner):
    plan = {}
    for batch in batches(hooks):
        plan.update(ah_call(runner, ah_argv(home, host, commit, batch, None, True), "the dry run on %s" % host)["files"])
    missing = [n for n in hooks if n not in plan]
    if missing:
        raise Stop("the dry run on %s did not report %s" % (host, ", ".join(missing[:5])))
    return [n for n in ordered(hooks) if plan[n].get("action") != "already_current"]


def unfinished_since(home, host, since):
    """Install runs on `host` started at or after `since` (this run) with no result row yet, from ah_install's audit."""
    opened, closed = [], set()
    try:
        with open(Path(home) / ".agent-harness" / "install-audit.jsonl", errors="replace") as fh:
            for line in fh:
                try:
                    row = json.loads(line)
                except ValueError:
                    continue
                if not isinstance(row, dict) or row.get("host") != host or not row.get("run"):
                    continue
                if row.get("event") == "start" and str(row.get("at", "")) >= since:
                    opened.append(row["run"])
                elif row.get("event") == "result":
                    closed.add(row["run"])
    except OSError:
        return None
    return [r for r in opened if r not in closed]


def remote_install(home, host, commit, names, ticket, runner, since):
    """Install `names` in batches; returns the `unregistered` names the host reported."""
    groups, done, unregistered = batches(names), [], []
    for i, group in enumerate(groups, 1):
        try:
            data = ah_call(runner, ah_argv(home, host, commit, group, ticket, False),
                           "the install on %s (batch %d of %d)" % (host, i, len(groups)))
        except Stop as e:
            raise Stop(str(e) + resume_guidance(home, host, ticket, done, since))
        done.append((data.get("run") or "?", group))
        unregistered += [str(n) for n in data.get("unregistered") or []]
        print("%s: batch %d of %d installed (run %s): %s" % (host, i, len(groups), data.get("run") or "?", " ".join(group)))
    return unregistered


def resume_guidance(home, host, ticket, done, since):
    lines = ["", "Batches already installed on %s: %s" % (
        host, "; ".join("run %s (%s)" % (run, " ".join(g)) for run, g in done) or "none")]
    open_runs = unfinished_since(home, host, since)
    if open_runs is None:
        lines.append("ah_install's audit could not be read; check it before anything else: ~/.agent-harness/install-audit.jsonl")
    for run in open_runs or []:
        lines.append("Run %s has no result yet. Finish it with one of:" % run)
        for verb in ("--resume", "--rollback"):
            lines.append("  python3 -I ~/.claude/hooks/ah.py install-files %s %s --ticket %r" % (verb, run, ticket))
    lines.append("Then rerun this command: its dry run lists only what still differs.")
    return "\n".join(lines)


def doctor_states(runner, home, doctor):
    """{check id: state} from a doctor at `doctor`, or None when it is missing or does not answer."""
    if not Path(doctor).is_file():
        return None
    claude = Path(home) / ".claude"
    try:
        r = runner([sys.executable, "-I", str(doctor), "check", "--json", "--no-canary", "--settings",
                    str(claude / "settings.json"), "--hooks-dir", str(claude / "hooks")],
                   capture_output=True, text=True, timeout=DOCTOR_TIMEOUT)
        items = json.loads(r.stdout)
    except (subprocess.TimeoutExpired, OSError, TypeError, ValueError):
        return None
    if not isinstance(items, list):
        return None
    return {str(i.get("id")): str(i.get("state")) for i in items if isinstance(i, dict) and i.get("id")}


def registration(before, after):
    """(lost, new, old) doctor ids: wired before and not after (a regression); declared now and unregistered, and not
    registered before either (ah_install.newly_declared_unregistered); unregistered before and after."""
    if after is None:
        return [], [], []
    before = before or {}
    lost = sorted(i for i, s in before.items() if s == "WIRED" and after.get(i) != "WIRED")
    unreg = [i for i, s in after.items() if s == UNREGISTERED]
    new = sorted(i for i in unreg if i not in before or before[i] in NOT_REGISTERED_BEFORE)
    old = sorted(i for i in unreg if i not in new)
    return lost, new, old


# ----------------------------------------------------------------------------- main

def main(argv=None, runner=subprocess.run, reader=read_tty, environ=None):
    environ = os.environ if environ is None else environ
    ap = argparse.ArgumentParser(description="User-run: update the installed harness to one commit on origin/main.")
    ap.add_argument("--commit", help="full 40-hex lowercase sha on origin/main (default: origin/main HEAD)")
    ap.add_argument("--preview", action="store_true", help="show what would change; install nothing")
    ap.add_argument("--host", action="append", choices=REMOTE_HOSTS, help="remote host (default: t2-dev)")
    ap.add_argument("--no-remote", action="store_true", help="update this Mac only")
    ap.add_argument("--ticket", help="GoodQA project#N; required for a real run with a remote host")
    ap.add_argument("--home", default=str(Path.home()), help=argparse.SUPPRESS)
    a = ap.parse_args(argv)
    hosts = [] if a.no_remote else (a.host or list(REMOTE_HOSTS))
    run = None
    try:
        markers = agent_markers(environ)
        if markers:
            raise Stop("an agent is running this (%s is set). The updater is user-run: its installs and its remote dry "
                       "runs are main-only commands. Ask the user to run it." % ", ".join(markers))
        if a.commit is not None and not SHA_RE.fullmatch(a.commit):
            raise Stop("--commit must be a full 40-hex lowercase sha")
        if a.ticket is not None and not TICKET_RE.fullmatch(a.ticket):
            raise Stop("--ticket must look like 'GoodQA project#123'")
        if not a.preview and hosts and not a.ticket:
            raise Stop("--ticket 'GoodQA project#N' is required for a real run")
        since = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        run = new_run_dir(a.home)
        repo, main_sha = fetch_main(run, a.home)
        commit = resolve_commit(repo, a.home, main_sha, a.commit)
        export = run / "export"
        subject = export_commit(repo, a.home, commit, export)
        lists = installer_lists(export)
        mac = local_changes(export, a.home, lists)
        older = downgrades(repo, a.home, commit, main_sha, mac)
        if older:
            raise Stop("main changed these files after %s, so installing it would put older versions in place: %s. "
                       "Use a newer --commit." % (commit[:12], " ".join(older)))
        remote = {h: remote_changes(a.home, h, commit, lists["hooks"], runner) for h in hosts}
        print("Commit %s (%s)" % (commit, subject))
        print("Mac: %d file(s) differ: %s" % (len(mac), " ".join(mac) or "-"))
        for h, names in remote.items():
            print("%s: %d hook file(s) differ: %s (%d dry run(s))"
                  % (h, len(names), " ".join(names) or "-", math.ceil(len(lists["hooks"]) / BATCH)))
        if a.preview:
            print("Preview only: nothing was installed.")
            return EXIT_OK
        if mac or any(remote.values()):
            confirm(commit, reader)
        claude_hooks = Path(a.home) / ".claude" / "hooks"
        lost = new = old = []
        if mac:
            before = doctor_states(runner, a.home, claude_hooks / "doctor.py")
            try:
                r = runner([sys.executable, "-B", "-E", "-s", str(export / "install.py"), "--apply", "--hooks-only",
                            "--home", a.home], cwd=str(export), capture_output=True, text=True, timeout=INSTALL_TIMEOUT)
            except subprocess.TimeoutExpired:
                raise Stop("install.py timed out after %d s; replaced files were backed up by install.py. Run "
                           "--preview to see what still differs." % INSTALL_TIMEOUT)
            if r.returncode != 0:
                raise Stop("install.py failed with exit %s: %s" % (r.returncode, (r.stderr or r.stdout or "")[-400:]))
            still = local_changes(export, a.home, lists)
            if still:
                raise Stop("after install.py these Mac files still differ from the commit: %s" % " ".join(still))
            lost, new, old = registration(before, doctor_states(runner, a.home, claude_hooks / "doctor.py"))
            if lost:
                raise Stop("hooks wired before this install are not wired now: %s. install.py backed up the replaced "
                           "files under ~/.claude." % " ".join(lost))
        print("Mac: every installed file matches %s" % commit[:12])
        unregistered = {}
        for h, names in remote.items():
            if names:
                unregistered[h] = remote_install(a.home, h, commit, names, a.ticket, runner, since)
            left = remote_changes(a.home, h, commit, lists["hooks"], runner)
            if left:
                raise Stop("%s: these hook files still differ after the install: %s" % (h, " ".join(left)))
            print("%s: every hook file matches %s" % (h, commit[:12]))
        if old:
            print("Mac: already unregistered before this run: %s" % " ".join(old))
        gaps = [("Mac", new)] + [(h, sorted(set(u))) for h, u in unregistered.items()]
        gaps = [(where, ids) for where, ids in gaps if ids]
        if gaps:
            for where, ids in gaps:
                print("%s: declared but not registered in settings.json, so not running yet: %s" % (where, " ".join(ids)))
            print("Installed commit %s, NOT fully active: register these hooks with install.py --apply (without "
                  "--hooks-only) from a checkout of that commit." % commit)
            return EXIT_REGISTER
        print("Done. Installed commit: %s" % commit)
        return EXIT_OK
    except Stop as e:
        print("STOP: %s" % e, file=sys.stderr)
        return EXIT_STOP
    finally:
        if run is not None:
            shutil.rmtree(run, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
