#!/usr/bin/env python3
"""Update the installed harness on this Mac and on t2-dev to one merged commit. USER-RUN: an agent never runs it.

    python3 -I -S scripts/update_installed.py --preview                  # what would change; installs nothing
    python3 -I -S scripts/update_installed.py --ticket "GoodQA goodqa#N"  # install origin/main HEAD
    python3 -I -S scripts/update_installed.py --commit <sha> --ticket "GoodQA goodqa#N"

`-I -S` is required: without -I a file next to this script or PYTHONPATH could replace a module it imports, and without
-S a `.pth` file in site-packages runs first.

Steps, each of which stops the run when it fails (nothing after a failed step runs):
  0. Refuse when an agent marker is set in the environment (CLAUDECODE, CODEX_THREAD_ID, CODEX_TOOL_CALL_ID,
     CODEX_SANDBOX, AI_AGENT), for a preview too: its remote dry runs are a main-only command. A mitigation, not a
     boundary (an agent can unset them); the command_guard rule that refuses agent calls is goodqa#17036.
  1. Fetch the canonical main into a FRESH bare repository (~/.agent-harness/update-cache/run-XXXXXXXXXXXX, created
     exclusively, deleted at the end) with hardened git: no system or global config, no hooks, no fsmonitor, no
     replace objects, https only, every fetched object fsck-checked. Grafts, shallow history and replace refs stop the run.
  2. This running copy of the updater must be main's own scripts/update_installed.py (same git blob id); a copy from a
     feature branch, an agent's worktree or an edited checkout stops. The commit (default: main HEAD) must be an
     ancestor of that main. With an older commit and a remote host, a hook main changed after it stops the run (the
     remote installer refuses an older commit for such a hook).
  3. Export the commit's tree into the run folder. Every object is re-hashed against its id; only regular files and
     folders are accepted. The sha256 of every exported file is kept in memory; later steps trust only those digests.
  4. Each remote host: an install, resume or rollback run with no definite result in ~/.agent-harness/
     install-audit.jsonl (the remote installer's own rule) stops the run before anything is installed anywhere, for a
     preview too, with the resume and rollback commands. Checked again after the confirmation.
  5. Derive the file lists, never hand-kept: every name in install.py's AGENTS, HOOKS, TOOLS and SKILLS literal tuples
     at the commit (bare names; SKILLS also <folder>/<file>) whose copy under ~/.claude is missing, a symlink, or
     differs from the commit's digests; for each remote host, every HOOKS name that `ah install-files --dry-run` does
     not report as already current. A Mac file that main changed after the commit stops the run (it would be a
     downgrade); ah_install refuses the same for the host.
  6. A real run asks for the first 12 characters of the commit on /dev/tty (a person at a terminal); no flag skips it.
  7. Mac: the doctor runs; then, immediately before install.py, the whole export is checked against the digests: the
     same files and folders as the commit and nothing else (no extra module, no __pycache__, no symlink), every byte
     equal. Then `python3 -B -E -s -S install.py --apply --hooks-only --home H` runs from the export (CLAUDE.md and
     settings.json are not touched; replaced files are backed up under ~/.claude/agent-harness-backups). Every listed
     file is compared with the digests again, and the doctor runs again.
  8. Each remote host: `ah install-files --host H --from-ref <sha> --file ... --ticket T` in batches of 20, with
     command_guard.py in the last batch; each batch's run id is printed. A second dry run must report every file current.
  9. Registration, for the Mac and for every host whether or not anything was installed there: the doctor (for a host
     `doctor.py check --ssh H`, read-only) must answer, with an exit code that agrees with its rows; otherwise the run
     stops (registration not proven). A required hook that is unregistered (MISSING) gives exit 3; any other required
     hook that is not WIRED (SCRIPT_MISSING, CANARY_FAIL) stops the run.

Run time: a preview makes ceil(N/20) dry runs per host, N = the HOOKS count at the commit (about 110 today, so 6);
a real run makes those, one install per batch of changed files, and the same dry runs again.

Exit: 0 every listed file matches the commit and every doctor reports every required hook wired (or a clean
preview); 1 stopped (files installed before the failed step stay installed, and the message says what was done);
2 usage (a bad option or value), or not started with -I -S; 3 installed, with hooks that need registering.
"""
import sys

if __name__ == "__main__" and not (sys.flags.isolated and sys.flags.no_site):
    sys.stderr.write("STOP: run it as `python3 -I -S scripts/update_installed.py ...`: without -I a file next to the "
                     "script or PYTHONPATH could replace a module it imports, and without -S a .pth file in "
                     "site-packages runs first.\n")
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
SELF_REL = "scripts/update_installed.py"
AGENT_MARKERS = ("CLAUDECODE", "CODEX_THREAD_ID", "CODEX_TOOL_CALL_ID", "CODEX_SANDBOX", "AI_AGENT")  # = commit_policy
GIT_TIMEOUT = 300
FETCH_TIMEOUT = 600
INSTALL_TIMEOUT = 1800
DOCTOR_TIMEOUT = 300
MAX_EXPORT_BYTES = 256 << 20
MAX_EXPORT_FILES = 20000
WIRED = "WIRED"                 # = doctor.WIRED (contract test)
UNREGISTERED = "MISSING"        # = doctor.MISSING: a declared, required hook that settings.json does not register
NOT_REGISTERED_BEFORE = ("PENDING",)  # = ah_install.NOT_REGISTERED_BEFORE (contract test)
BACKUPS = "~/.claude/agent-harness-backups"   # where install.py keeps the files it replaced (contract test)
CLEARING = ("installed", "rolled_back", "restored", "already_current", "refused")  # = ah_install.CLEARING (contract)
EXIT_OK, EXIT_STOP, EXIT_USAGE, EXIT_REGISTER = 0, 1, 2, 3


class Stop(Exception):
    """A refusal: nothing after the failed step ran."""


def _own_bytes():
    try:
        with open(__file__, "rb") as fh:
            return fh.read()
    except OSError:
        return None


SELF_BYTES = _own_bytes()   # read at start-up, as close as possible to the bytes Python loaded


def blob_id(data):
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


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


def check_self(repo, home):
    """F4: the code that enforces every check must be main's reviewed copy, not whatever checkout it was run from."""
    if SELF_BYTES is None:
        raise Stop("the updater could not read its own file")
    r = git(repo, ["rev-parse", "--verify", "-q", "refs/heads/main:" + SELF_REL], home, check=False)
    want = r.stdout.decode().strip()
    if r.returncode != 0 or not SHA_RE.fullmatch(want):
        raise Stop("main has no %s; nothing was changed" % SELF_REL)
    have = blob_id(SELF_BYTES)
    if have != want:
        raise Stop("this copy of the updater (blob %s) is not main's %s (blob %s). Run it from a clean, up-to-date "
                   "checkout of origin/main; nothing was changed" % (have[:12], SELF_REL, want[:12]))


def resolve_commit(repo, home, main, commit):
    commit = commit or main
    if git(repo, ["cat-file", "-e", commit + "^{commit}"], home, check=False).returncode != 0:
        raise Stop("%s is not a commit of the canonical main history; nothing was changed" % commit)
    if git(repo, ["merge-base", "--is-ancestor", commit, main], home, check=False).returncode != 0:
        raise Stop("%s is not on origin/main; nothing was changed" % commit)
    return commit


def export_commit(repo, home, commit, dest):
    """Write the commit's tree under `dest` from re-hashed objects only. Returns (subject, {relative path: sha256}):
    the digests stay in memory, so later checks never trust the export's bytes again (F5)."""
    body = read_object(repo, home, "commit", commit)
    m = re.match(rb"tree ([0-9a-f]{40})\n", body)
    if not m:
        raise Stop("the commit has no tree line")
    blobs, todo, digests = [], [(m.group(1).decode(), dest)], {}
    while todo:
        oid, path = todo.pop()
        try:
            os.mkdir(path, 0o700)
        except OSError as e:
            raise Stop("could not export %s (%s); nothing was installed" % (path, e.strerror or e))
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
        digests[path.relative_to(dest).as_posix()] = hashlib.sha256(content).hexdigest()
        try:
            fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                         0o755 if mode == "100755" else 0o644)
        except OSError as e:   # e.g. two names that differ only in case on a case-insensitive file system
            raise Stop("could not export %s (%s); nothing was installed" % (path.relative_to(dest), e.strerror or e))
        try:
            os.write(fd, content)
        finally:
            os.close(fd)
    msg = body.split(b"\n\n", 1)
    subject = msg[1].decode("utf-8", "replace").splitlines()[0][:120] if len(msg) == 2 and msg[1].strip() else ""
    return subject, digests


def verify_export(export, digests):
    """R5 F1, the one choke point before anything from the export runs: the export holds exactly the commit's files
    and the folders above them, nothing else (no planted module, no __pycache__, no symlink, no device), and every
    file's sha256 equals the digest taken at export time. lstat only; nothing is followed."""
    export = Path(export)
    want_dirs = {""}
    for rel in digests:
        parts = rel.split("/")[:-1]
        for i in range(1, len(parts) + 1):
            want_dirs.add("/".join(parts[:i]))
    seen_files, seen_dirs, problems = set(), {""}, []
    stack = [""]
    while stack:
        rel_dir = stack.pop()
        try:
            entries = list(os.scandir(export / rel_dir if rel_dir else export))
        except OSError as e:
            raise Stop("the export cannot be read (%s); nothing was installed" % (e.strerror or e))
        for entry in entries:
            rel = (rel_dir + "/" + entry.name) if rel_dir else entry.name
            try:
                st = entry.stat(follow_symlinks=False)
            except OSError:
                problems.append(rel)
                continue
            if entry.is_dir(follow_symlinks=False):
                seen_dirs.add(rel)
                stack.append(rel)
            elif entry.is_file(follow_symlinks=False) and st.st_nlink == 1:
                seen_files.add(rel)
                try:
                    with open(export / rel, "rb") as fh:
                        if hashlib.sha256(fh.read()).hexdigest() != digests.get(rel):
                            problems.append(rel)
                except OSError:
                    problems.append(rel)
            else:
                problems.append(rel)   # a symlink, fifo, device, socket, or a hard link to something else
    problems += sorted((seen_files ^ set(digests)) | (seen_dirs ^ want_dirs))
    if problems:
        raise Stop("the export changed after it was verified (%s); nothing from it ran and nothing was installed"
                   % ", ".join(sorted(set(problems))[:8]))


# ----------------------------------------------------------------------------- derivation

def valid_name(folder, name):
    """A bare file name; for skills also <folder>/<file> (install.py's skills layout), each part a bare name."""
    if not isinstance(name, str):
        return False
    parts = name.split("/")
    if folder == "skills" and len(parts) == 2:
        return all(NAME_RE.fullmatch(p) and p not in (".", "..") for p in parts)
    return len(parts) == 1 and bool(NAME_RE.fullmatch(name))


def installer_lists(export, digests=None):
    """{folder: [names]} from the exported install.py (literal tuples only; anything else stops). With `digests`, the
    bytes parsed must be the ones verified at export time."""
    data = (Path(export) / "install.py").read_bytes()
    if digests is not None and hashlib.sha256(data).hexdigest() != digests.get("install.py"):
        raise Stop("the exported install.py changed after it was verified; nothing was installed")
    found = {}
    for stmt in ast.parse(data.decode("utf-8")).body:
        if not isinstance(stmt, ast.Assign):
            continue
        for target in stmt.targets:
            for folder, var in FOLDERS:
                if isinstance(target, ast.Name) and target.id == var:
                    try:
                        names = ast.literal_eval(stmt.value)
                    except (ValueError, SyntaxError, TypeError):
                        raise Stop("install.py %s is not a literal tuple" % var)
                    if not isinstance(names, tuple) or not all(valid_name(folder, n) for n in names):
                        raise Stop("install.py %s is not a tuple of bare file names (skills: <folder>/<file>)" % var)
                    found[folder] = list(names)
    if "hooks" not in found:
        raise Stop("install.py has no HOOKS list")
    return {folder: found.get(folder, []) for folder, _ in FOLDERS}


def file_sha(path):
    p = Path(path)
    if p.is_symlink() or not p.is_file():
        return None
    return hashlib.sha256(p.read_bytes()).hexdigest()


def local_changes(digests, home, lists):
    """Installed files (folder/name) that are missing, a symlink, or differ from the commit's export digests."""
    out = []
    for folder, _ in FOLDERS:
        for name in lists[folder]:
            rel = "%s/%s" % (folder, name)
            want = digests.get("harness/" + rel)
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


def unfinished_runs(home, host):
    """Runs on `host` with an install, resume or rollback attempt and no definite result, by the remote installer's own
    rule (ah_install.unfinished_runs; a contract test runs both on the same audit files): only installed, rolled_back,
    restored, already_current or refused clear an attempt; `unknown` and `attempt_refused` leave it open. None when the
    audit cannot be read."""
    opened = {}
    try:
        with open(Path(home) / ".agent-harness" / "install-audit.jsonl", errors="replace") as fh:
            lines = fh.readlines()
    except FileNotFoundError:
        lines = []
    except OSError:
        return None
    for line in lines:
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if not isinstance(row, dict) or row.get("host") != host or not row.get("run"):
            continue
        run, kind_ = row["run"], row.get("kind")
        if row.get("event") == "start" and kind_ in ("install", "resume", "rollback"):
            opened[(run, "rollback" if kind_ == "rollback" else "install")] = True
        elif row.get("event") == "result" and row.get("result") in CLEARING:
            if kind_ == "rollback" or row.get("result") == "restored":
                opened[(run, "rollback")] = False
            if row.get("result") == "restored" or kind_ != "rollback":
                opened[(run, "install")] = False
    return sorted({run for (run, _which), is_open in opened.items() if is_open})


def remote_install(home, host, commit, names, ticket, runner):
    """Install `names` in batches; returns the `unregistered` names the host reported."""
    groups, done, unregistered = batches(names), [], []
    for i, group in enumerate(groups, 1):
        try:
            data = ah_call(runner, ah_argv(home, host, commit, group, ticket, False),
                           "the install on %s (batch %d of %d)" % (host, i, len(groups)))
        except Stop as e:
            raise Stop(str(e) + resume_guidance(home, host, ticket, done))
        done.append((data.get("run") or "?", group))
        unregistered += [str(n) for n in data.get("unregistered") or []]
        print("%s: batch %d of %d installed (run %s): %s" % (host, i, len(groups), data.get("run") or "?", " ".join(group)))
    return unregistered


def finish_commands(host, run, ticket):
    """The two commands that finish an open run, exactly as ah's parser takes them (contract test runs them)."""
    t = ticket or "GoodQA <project>#<n>"
    return ["python3 -I ~/.claude/hooks/ah.py install-files --host %s %s %s --ticket '%s'" % (host, verb, run, t)
            for verb in ("--resume", "--rollback")]


def open_run_lines(home, host):
    """[] when the host has no open run; else the lines that say which run and how to finish it. Stops when the audit
    cannot be read: nothing may be installed on a host whose state is unknown."""
    open_runs = unfinished_runs(home, host)
    if open_runs is None:
        raise Stop("the remote installer's audit ~/.agent-harness/install-audit.jsonl cannot be read, so whether %s "
                   "has an unfinished run is unknown; nothing was installed" % host)
    return open_runs


def guidance(host, ticket, open_runs):
    lines = []
    for run in open_runs:
        lines.append("Run %s on %s is unfinished (no result yet, or `unknown`); the remote installer refuses a new "
                     "install there until it is finished. Finish it with one of:" % (run, host))
        lines += ["  " + c for c in finish_commands(host, run, ticket)]
    return lines


def check_no_open_runs(home, hosts, ticket):
    """R5 F3: before any dry run, and again after the confirmation: an open run on any host stops the whole update
    before anything is installed anywhere (otherwise the Mac would be updated and the host refused)."""
    lines = []
    for h in hosts:
        lines += guidance(h, ticket, open_run_lines(home, h))
    if lines:
        raise Stop("\n".join(["a remote host has an unfinished install run; nothing was installed on this Mac or any "
                              "host."] + lines + ["Then rerun this command."]))


def resume_guidance(home, host, ticket, done):
    lines = ["", "Batches already installed on %s: %s" % (
        host, "; ".join("run %s (%s)" % (run, " ".join(g)) for run, g in done) or "none")]
    open_runs = unfinished_runs(home, host)
    if open_runs is None:
        lines.append("the remote installer's audit could not be read; check it before anything else: "
                     "~/.agent-harness/install-audit.jsonl")
    lines += guidance(host, ticket, open_runs or [])
    lines.append("Then rerun this command: its dry run lists only what still differs.")
    return "\n".join(lines)


def doctor_argv(home, host=None):
    claude = Path(home) / ".claude"
    argv = [sys.executable, "-I", str(claude / "hooks" / "doctor.py"), "check", "--json", "--no-canary"]
    if host:   # read-only over ssh: the host's own settings.json and hooks folder, judged by this Mac's manifest
        return argv + ["--ssh", host]
    return argv + ["--settings", str(claude / "settings.json"), "--hooks-dir", str(claude / "hooks")]


def doctor_check(runner, home, host=None):
    """{check id: (state, required)} from the installed doctor, or None when it is missing, does not answer, or its
    exit code disagrees with its own rows (doctor.verdict: 0 exactly when every required row is WIRED)."""
    if not (Path(home) / ".claude" / "hooks" / "doctor.py").is_file():
        return None
    try:
        r = runner(doctor_argv(home, host), capture_output=True, text=True, timeout=DOCTOR_TIMEOUT)
        items = json.loads(r.stdout)
    except (subprocess.TimeoutExpired, OSError, TypeError, ValueError):
        return None
    if not isinstance(items, list) or not all(isinstance(i, dict) and i.get("id") for i in items):
        return None
    rows = {str(i["id"]): (str(i.get("state")), i.get("required") is True) for i in items}
    gaps = any(req and state != WIRED for state, req in rows.values())
    if r.returncode != (1 if gaps else 0):
        return None
    return rows


def registration(before, after, where="the Mac"):
    """(lost, new, old): ids wired before and not after (a regression); required and unregistered now, and not
    registered before either (ah_install.newly_declared_unregistered); unregistered before and after. A doctor that
    did not answer means registration is not proven, and a required row that is neither WIRED nor MISSING
    (SCRIPT_MISSING, CANARY_FAIL, ...) is a broken install, not a registration step: both stop."""
    if after is None:
        raise Stop("the doctor did not answer for %s (or its exit code disagreed with its rows), so hook registration "
                   "is not proven. Files already installed stay installed (install.py backed up the ones it replaced "
                   "under %s); run `python3 -I ~/.claude/hooks/doctor.py check%s` and fix it before relying on this "
                   "install." % (where, BACKUPS, "" if where == "the Mac" else " --ssh " + where))
    before = before or {}
    lost = sorted(i for i, (s, _r) in before.items() if s == WIRED and after.get(i, ("", False))[0] != WIRED)
    broken = sorted(i for i, (s, req) in after.items() if req and s not in (WIRED, UNREGISTERED))
    if broken:
        raise Stop("on %s these required hooks are not working (%s); this is not fixed by registering them: %s"
                   % (where, ", ".join(sorted({after[i][0] for i in broken})), " ".join(broken)))
    unreg = [i for i, (s, req) in after.items() if req and s == UNREGISTERED]
    new = sorted(i for i in unreg if i not in before or before[i][0] in NOT_REGISTERED_BEFORE)
    old = sorted(i for i in unreg if i not in new)
    return lost, new, old


# ----------------------------------------------------------------------------- main

def main(argv=None, runner=subprocess.run, reader=read_tty, environ=None, home=None):
    """`home` is for tests only (no command-line flag: the home also decides which ah.py and doctor.py run)."""
    environ = os.environ if environ is None else environ
    ap = argparse.ArgumentParser(description="User-run: update the installed harness to one commit on origin/main.")
    ap.add_argument("--commit", help="full 40-hex lowercase sha on origin/main (default: origin/main HEAD)")
    ap.add_argument("--preview", action="store_true", help="show what would change; install nothing")
    ap.add_argument("--host", action="append", choices=REMOTE_HOSTS, help="remote host (default: t2-dev)")
    ap.add_argument("--no-remote", action="store_true", help="update this Mac only")
    ap.add_argument("--ticket", help="GoodQA project#N; required for a real run with a remote host")
    a = ap.parse_args(argv)
    if a.commit is not None and not SHA_RE.fullmatch(a.commit):
        ap.error("--commit must be a full 40-hex lowercase sha")
    if a.ticket is not None and not TICKET_RE.fullmatch(a.ticket):
        ap.error("--ticket must look like 'GoodQA project#123'")
    home = str(home or Path.home())
    hosts = [] if a.no_remote else (a.host or list(REMOTE_HOSTS))
    run = None
    try:
        markers = agent_markers(environ)
        if markers:
            raise Stop("an agent is running this (%s is set). The updater is user-run: its installs and its remote dry "
                       "runs are main-only commands. Ask the user to run it." % ", ".join(markers))
        if not a.preview and hosts and not a.ticket:
            raise Stop("--ticket 'GoodQA project#N' is required for a real run")
        check_no_open_runs(home, hosts, a.ticket)
        run = new_run_dir(home)
        repo, main_sha = fetch_main(run, home)
        check_self(repo, home)
        commit = resolve_commit(repo, home, main_sha, a.commit)
        export = run / "export"
        subject, digests = export_commit(repo, home, commit, export)
        lists = installer_lists(export, digests)
        mac = local_changes(digests, home, lists)
        older = downgrades(repo, home, commit, main_sha, mac)
        if older:
            raise Stop("main changed these files after %s, so installing it would put older versions in place: %s. "
                       "Use a newer --commit." % (commit[:12], " ".join(older)))
        if hosts and commit != main_sha:
            older = downgrades(repo, home, commit, main_sha, ["hooks/" + n for n in lists["hooks"]])
            if older:
                raise Stop("main changed these hooks after %s, and the remote installer refuses an older commit for "
                           "them (even where the host already has them): %s. Use a newer --commit, or --no-remote."
                           % (commit[:12], " ".join(older)))
        remote = {h: remote_changes(home, h, commit, lists["hooks"], runner) for h in hosts}
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
            check_no_open_runs(home, hosts, a.ticket)   # the wait at the prompt may have been long
        before = doctor_check(runner, home)
        if mac:
            verify_export(export, digests)               # nothing slow between this walk and the exec below
            try:
                r = runner([sys.executable, "-B", "-E", "-s", "-S", str(export / "install.py"), "--apply",
                            "--hooks-only", "--home", home], cwd=str(export), capture_output=True, text=True,
                           timeout=INSTALL_TIMEOUT)
            except subprocess.TimeoutExpired:
                raise Stop("install.py timed out after %d s; replaced files were backed up under %s. Run --preview "
                           "to see what still differs." % (INSTALL_TIMEOUT, BACKUPS))
            if r.returncode != 0:
                raise Stop("install.py failed with exit %s: %s" % (r.returncode, (r.stderr or r.stdout or "")[-400:]))
            still = local_changes(digests, home, lists)
            if still:
                raise Stop("after install.py these Mac files are live but are NOT the commit's bytes: %s. The files "
                           "they replaced are under %s; restore them or rerun this command." % (" ".join(still), BACKUPS))
        lost, new, old = registration(before, doctor_check(runner, home))
        if lost:
            raise Stop("hooks wired before this install are not wired now: %s. The replaced files are under %s."
                       % (" ".join(lost), BACKUPS))
        print("Mac: every listed file matches %s" % commit[:12])
        gaps = [("Mac", new), ("Mac (already before this run)", old)]
        for h, names in remote.items():
            if names:
                reported = remote_install(home, h, commit, names, a.ticket, runner)
                if reported:
                    print("%s: the remote installer reports these hooks unregistered: %s" % (h, " ".join(reported)))
            left = remote_changes(home, h, commit, lists["hooks"], runner)
            if left:
                raise Stop("%s: these hook files still differ after the install: %s" % (h, " ".join(left)))
            print("%s: every hook file matches %s" % (h, commit[:12]))
            # R5 F4: every host is checked, whether or not anything was installed there
            _lost, h_new, h_old = registration(None, doctor_check(runner, home, h), h)
            gaps.append((h, sorted(set(h_new + h_old))))
        gaps = [(where, ids) for where, ids in gaps if ids]
        if gaps:
            for where, ids in gaps:
                print("%s: declared but not registered in settings.json, so not running yet: %s" % (where, " ".join(ids)))
            print("Commit %s: files in place, NOT fully active: register these hooks with install.py --apply (without "
                  "--hooks-only) from a checkout of that commit, on each host named." % commit)
            return EXIT_REGISTER
        checked = "the Mac's doctor" + "".join(" and %s's" % h for h in hosts)
        if mac or any(remote.values()):
            print("Done. Installed commit %s; %s report every required hook wired." % (commit, checked))
        else:
            print("Nothing to install: everything listed already matches %s; %s report every required hook wired."
                  % (commit, checked))
        return EXIT_OK
    except Stop as e:
        print("STOP: %s" % e, file=sys.stderr)
        return EXIT_STOP
    finally:
        if run is not None:
            shutil.rmtree(run, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
