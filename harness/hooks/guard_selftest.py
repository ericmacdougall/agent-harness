#!/usr/bin/env python3
"""ah guard-selftest: a sanctioned live test of a guard rule (GoodQA goodqa#15876).

    python3 -I ~/.claude/hooks/ah.py guard-selftest --rule bulk_staging --expect-manifest SHA256 --expect-policy SHA256|absent
    python3 -I ~/.claude/hooks/ah.py guard-selftest --print-manifest

Worktree isolation refuses any command whose text carries git commands it cannot verify, so a guard rule for git commands
could never be live-tested. This tool runs a FIXED table of commands (code, reviewed, tested) through the INSTALLED hook entry
in disposable repositories of its own and prints one JSON object. It never takes a command, a path or a directory from the
caller: the only inputs are a rule name from the table and two hashes, and the code under test is the copy installed in
~/.claude/hooks (home from the system user record), pinned by a manifest of the hook launcher, the guard and every module and
data file the guard names. The expected hashes MUST come from the merged commit (`git rev-parse MERGE_SHA:harness/hooks/NAME`
in the caller's own worktree), never from the installed files, or the check passes whatever is installed.

Exit codes: 0 every case matched, 1 a case mismatched, 3 refused before running anything, 4 setup failed.

Stated limits: a same-user process that edits the hooks between the hashing and the hook run defeats the pin (it protects against
an accidentally stale or wrong install, not a hostile same-user process); a sibling loaded through a computed name is not found;
the hook entry is exercised with a Bash payload, not through Claude Code or Codex; the table covers the documented shapes of the
shipped rule, not every shape.
"""

import argparse
import ast
import hashlib
import json
import os
import pwd
import re
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
TIMEOUT = 20  # seconds, around each hook run: a hang fails the case even when the launcher's own watchdog is broken
PREFIX = "ah-guard-selftest-"
GIT_CANDIDATES = ("/usr/bin/git", "/opt/homebrew/bin/git", "/usr/local/bin/git")
LAUNCHER, GUARD, POLICY = "command_guard_hook.py", "command_guard.py", "command_guard_policy.json"
RE_DIGEST, RE_POLICY = re.compile(r"[0-9a-f]{64}"), re.compile(r"[0-9a-f]{64}|absent")
FINDING = "[bulk_staging/bulk-staging]"


class Refused(Exception):
    """Exit 3: nothing was run."""


class SetupFailed(Exception):
    """Exit 4."""


# ---- the table (code, never input) -------------------------------------------------------------------------------------
def bulk_staging_cases(paths):
    """(label, command, kind) for the bulk_staging rule: kind `bulk` expects the finding, `quiet` expects nothing at all."""
    orig, wt, clean, plain = paths["orig"], paths["wt"], paths["clean"], paths["plain"]
    return [
        ("bulk add in the dirty original checkout", "cd %s && git add -A" % orig, "bulk", orig),
        ("bulk commit -a in the dirty original checkout", "cd %s && git commit -am x" % orig, "bulk", orig),
        ("git -C into the original from the linked worktree", "cd %s && git -C %s add ." % (wt, orig), "bulk", wt),
        ("explicit-path add in the dirty original checkout", "cd %s && git add b.txt" % orig, "quiet", orig),
        ("bulk add in the linked worktree", "cd %s && git add -A" % wt, "quiet", wt),
        ("bulk add in the clean checkout", "cd %s && git add -A" % clean, "quiet", clean),
        ("bulk add in a plain directory", "cd %s && git add -A" % plain, "quiet", plain),
    ]


RULES = {"bulk_staging": {"cases": bulk_staging_cases, "default_mode": "warn"}}


# ---- pin ---------------------------------------------------------------------------------------------------------------
def user_home():
    """The home of the running user from the system user record, never $HOME."""
    return Path(pwd.getpwuid(os.getuid()).pw_dir)


def installed_dir(home):
    return Path(os.path.realpath(str(Path(home) / ".claude" / "hooks")))


def blob_id(data):
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


def _sibling_names(path):
    """Import statements and string literals in one Python file that could name a sibling file."""
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, SyntaxError, ValueError):
        return set(), set()
    mods, literals = set(), set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            mods.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            mods.add(node.module.split(".")[0])
        elif isinstance(node, ast.Constant) and isinstance(node.value, str) and re.fullmatch(r"[A-Za-z0-9_.-]+\.(py|json)", node.value):
            literals.add(node.value)
    return mods, literals


def manifest(hooks_dir):
    """[(name, blob id)] of the launcher, the guard and every sibling module and data file they name (imports, and string
    literals naming an existing .py or .json file), sorted; the policy file is pinned separately."""
    hooks_dir = Path(hooks_dir)
    names, todo = {LAUNCHER, GUARD}, [LAUNCHER, GUARD]
    seen = set()
    while todo:
        name = todo.pop()
        if name in seen:
            continue
        seen.add(name)
        if not name.endswith(".py"):
            continue
        mods, literals = _sibling_names(hooks_dir / name)
        for found in [m + ".py" for m in mods] + sorted(literals):
            if found != POLICY and (hooks_dir / found).is_file() and found not in names:
                names.add(found)
                todo.append(found)
    out = []
    for name in sorted(names):
        try:
            out.append((name, blob_id((hooks_dir / name).read_bytes())))
        except OSError:
            out.append((name, "missing"))
    return out


def manifest_digest(items):
    return hashlib.sha256("".join("%s %s\n" % item for item in items).encode()).hexdigest()


def policy_state(hooks_dir):
    """('absent', None) or (sha256 of the policy file, parsed JSON)."""
    path = Path(hooks_dir) / POLICY
    if not path.exists():
        return "absent", None
    data = path.read_bytes()
    try:
        parsed = json.loads(data.decode("utf-8"))
    except ValueError:
        parsed = None
    return hashlib.sha256(data).hexdigest(), parsed


def effective_mode(rule, parsed):
    """The mode of the rule in the policy file; an unknown value is refused, not guessed."""
    mode = RULES[rule]["default_mode"]
    modes = parsed.get("modes") if isinstance(parsed, dict) else None
    if isinstance(modes, dict) and rule in modes:
        if modes[rule] not in ("warn", "enforce"):
            raise Refused("the policy sets an unknown mode for %s" % rule)
        mode = modes[rule]
    return mode


# ---- setup -------------------------------------------------------------------------------------------------------------
def trusted_git():
    me = os.getuid()
    for candidate in GIT_CANDIDATES:
        try:
            st = os.lstat(candidate)
        except OSError:
            continue
        if stat.S_ISREG(st.st_mode) and st.st_uid in (0, me):
            return candidate
    raise SetupFailed("no trusted git (usr/bin, opt/homebrew/bin, usr/local/bin) is a regular file owned by root or this user")


def git_env(git, home):
    return {"PATH": "%s:/usr/bin:/bin" % os.path.dirname(git), "HOME": str(home), "LANG": "C", "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_TERMINAL_PROMPT": "0", "GIT_AUTHOR_NAME": "selftest",
            "GIT_AUTHOR_EMAIL": "selftest@example.invalid", "GIT_COMMITTER_NAME": "selftest",
            "GIT_COMMITTER_EMAIL": "selftest@example.invalid"}


def _git(git, env, cwd, *args):
    done = subprocess.run([git, "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false", "-c", "core.fsmonitor=false", *args],
                          cwd=str(cwd), env=env, capture_output=True, timeout=TIMEOUT)
    if done.returncode != 0:
        raise SetupFailed("git %s failed" % (args[0] if args else ""))


def build_repositories(root, git):
    """A dirty original checkout, a linked worktree of it, a clean checkout and a plain directory under `root`."""
    root = Path(root)
    env = git_env(git, root)
    paths = {name: root / name for name in ("orig", "wt", "clean", "plain")}
    for name in ("orig", "clean", "plain"):
        paths[name].mkdir()
    for name in ("orig", "clean"):
        _git(git, env, paths[name], "init", "-q", "-b", "main", "--template=")
        (paths[name] / "a.txt").write_text("a\n")
        (paths[name] / "b.txt").write_text("b\n")
        _git(git, env, paths[name], "add", "a.txt", "b.txt")
        _git(git, env, paths[name], "commit", "-q", "-m", "init")
    (paths["orig"] / "a.txt").write_text("changed by another session\n")  # the dirt that must not be swept
    _git(git, env, paths["orig"], "worktree", "add", "-q", "--detach", str(paths["wt"]))
    (paths["wt"] / "b.txt").write_text("mine\n")
    (paths["plain"] / "x.txt").write_text("x\n")
    return paths


# ---- the hook run ------------------------------------------------------------------------------------------------------
def hook_env(git, home):
    return {"PATH": "%s:/usr/bin:/bin" % os.path.dirname(git), "HOME": str(home), "LANG": "C"}


def run_hook(hooks_dir, command, cwd, git, home):
    """The installed launcher exactly as it is registered: [python, -I, launcher, hook], the case directory as cwd, a fixed
    environment, and a payload built only from the table."""
    payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": command}, "cwd": str(cwd)})
    argv = [sys.executable, "-I", str(Path(hooks_dir) / LAUNCHER), "hook"]
    try:
        done = subprocess.run(argv, input=payload.encode(), cwd=str(cwd), env=hook_env(git, home), capture_output=True, timeout=TIMEOUT)
        return {"exit": done.returncode, "stdout": done.stdout.decode("utf-8", "replace"), "stderr": done.stderr.decode("utf-8", "replace"),
                "timed_out": False}
    except subprocess.TimeoutExpired:
        return {"exit": None, "stdout": "", "stderr": "", "timed_out": True}
    except OSError as error:
        return {"exit": None, "stdout": "", "stderr": "could not start (%s)" % type(error).__name__, "timed_out": False}


def evaluate(kind, mode, got):
    """True when the hook's answer is the expected one (D3 of the spec): the channels are those of the real hook."""
    if got["timed_out"] or got["exit"] is None:
        return False
    if kind == "quiet":
        return got["exit"] == 0 and got["stdout"].strip() == "" and got["stderr"].strip() == ""
    if mode == "enforce":
        return got["exit"] == 2 and FINDING in got["stderr"] and got["stdout"].strip() == ""
    if got["exit"] != 0 or got["stderr"].strip():
        return False  # any stderr note in a warn case is a launcher fallback or a crash, never a pass
    try:
        text = json.loads(got["stdout"])["hookSpecificOutput"]["additionalContext"]
    except (ValueError, KeyError, TypeError):
        return False
    return isinstance(text, str) and FINDING in text


def _excerpt(text, n=240):
    return re.sub(r"[^\x20-\x7e\n]", "?", text)[:n]


# ---- the private directory and its removal -----------------------------------------------------------------------------
def private_parent(home):
    parent = Path(home) / ".agent-harness" / "tmp"
    try:
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        st = os.lstat(str(parent))
    except OSError as error:
        raise SetupFailed("the private directory cannot be made (%s)" % type(error).__name__)
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o077:
        raise SetupFailed("the private directory is not a real directory owned by this user with mode 0700")
    return parent


def _rm_children(fd):
    with os.scandir(fd) as it:
        entries = list(it)
    for entry in entries:
        st = os.stat(entry.name, dir_fd=fd, follow_symlinks=False)
        if stat.S_ISDIR(st.st_mode):
            sub = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            try:
                inner = os.fstat(sub)
                if (inner.st_dev, inner.st_ino) != (st.st_dev, st.st_ino):
                    raise OSError("directory changed while it was removed")
                _rm_children(sub)
            finally:
                os.close(sub)
            os.rmdir(entry.name, dir_fd=fd)
        else:
            os.unlink(entry.name, dir_fd=fd)  # a symlink is unlinked, never followed


def remove_own_directory(parent_fd, name, dir_fd, ident):
    """Remove the directory created by this run through its open descriptors, after the device and inode recorded at creation
    still match both the descriptor and the entry under the parent. Returns True; raises OSError when the identity is not the
    one recorded (it then removes nothing)."""
    now = os.fstat(dir_fd)
    under = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if (now.st_dev, now.st_ino) != ident or (under.st_dev, under.st_ino) != ident or not stat.S_ISDIR(under.st_mode):
        raise OSError("the directory is not the one this run created")
    _rm_children(dir_fd)
    os.rmdir(name, dir_fd=parent_fd)
    return True


# ---- audit -------------------------------------------------------------------------------------------------------------
def _bound(value):
    return re.sub(r"[^\x20-\x7e]", "?", str(value))[:80]


def write_audit(home, row):
    folder = Path(home) / ".agent-harness"
    folder.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(str(folder / "guard-selftest-audit.jsonl"), os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, (json.dumps({k: (_bound(v) if isinstance(v, str) else v) for k, v in row.items()}, separators=(",", ":")) + "\n").encode())
    finally:
        os.close(fd)


# ---- the run -----------------------------------------------------------------------------------------------------------
def run_selftest(rule, expect_manifest, expect_policy, hooks_dir=None, home=None, cli=True, session="", agent="",
                 _before_cleanup=None):
    """The result dict (with `exit_code`). `hooks_dir` and `home` exist for the tests only: the command line never sets them, and a
    command-line run (cli=True, the default) refuses unless this module is the installed copy."""
    home = Path(home) if home else user_home()
    result = {"ok": False, "exit_code": 3, "rule": _bound(rule), "refused": None}
    audit = {"at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "session": session or None, "agent": agent or None, "rule": rule,
             "expect_manifest": expect_manifest, "expect_policy": expect_policy}
    created = {}
    try:
        try:
            if rule not in RULES:
                raise Refused("unknown rule (known: %s)" % ", ".join(sorted(RULES)))
            if not isinstance(expect_manifest, str) or not RE_DIGEST.fullmatch(expect_manifest):
                raise Refused("--expect-manifest must be 64 lowercase hex characters")
            if not isinstance(expect_policy, str) or not RE_POLICY.fullmatch(expect_policy):
                raise Refused("--expect-policy must be 64 lowercase hex characters or the word absent")
            module_dir = Path(os.path.realpath(str(HERE)))
            target = Path(os.path.realpath(str(hooks_dir))) if hooks_dir else module_dir
            if cli and module_dir != installed_dir(home):
                raise Refused("this is not the installed copy: %s is not %s" % (module_dir, installed_dir(home)))
            result["hooks_dir"] = str(target)
            items = manifest(target)
            digest = manifest_digest(items)
            result["manifest"] = {"files": [{"name": n, "blob": b} for n, b in items], "digest": digest}
            if any(b == "missing" for _n, b in items):
                raise Refused("a file of the manifest is missing")
            if digest != expect_manifest:
                raise Refused("the manifest digest %s is not the expected one" % digest)
            policy, parsed = policy_state(target)
            result["policy"] = policy
            if policy != expect_policy:
                raise Refused("the policy is %s, not the expected %s" % (policy, expect_policy))
            mode = effective_mode(rule, parsed)
            result["mode"] = mode
        except Refused as error:
            result.update(refused=str(error), exit_code=3)
            audit.update(verdict="refused", reason=str(error))
            return result
        try:
            git = trusted_git()
            parent = private_parent(home)
            run_dir = Path(tempfile.mkdtemp(prefix=PREFIX, dir=str(parent)))
            os.chmod(str(run_dir), 0o700)
            created["name"] = run_dir.name
            created["parent_fd"] = os.open(str(parent), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            created["dir_fd"] = os.open(str(run_dir), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            st = os.fstat(created["dir_fd"])
            created["ident"] = (st.st_dev, st.st_ino)
            paths = build_repositories(run_dir, git)
            records, ok = [], True
            for label, command, kind, cwd in RULES[rule]["cases"](paths):
                got = run_hook(target, command, cwd, git, home)
                good = evaluate(kind, mode, got)
                ok = ok and good
                expected = {"quiet": "exit 0, empty stdout, empty stderr",
                            "bulk": ("exit 2 and %s on stderr" if mode == "enforce" else "exit 0 and %s in the stdout JSON") % FINDING}[kind]
                records.append({"label": label, "command": command, "expected": expected, "exit": got["exit"], "timed_out": got["timed_out"],
                                "stdout": _excerpt(got["stdout"]), "stderr": _excerpt(got["stderr"]), "ok": good})
            result.update(cases=records, ok=ok, exit_code=0 if ok else 1, refused=None)
            audit.update(verdict="ok" if ok else "mismatch", cases=len(records))
        except SetupFailed as error:
            result.update(ok=False, exit_code=4, setup_failed=str(error))
            audit.update(verdict="setup failed", reason=str(error))
        except subprocess.SubprocessError as error:
            result.update(ok=False, exit_code=4, setup_failed="a subprocess failed (%s)" % type(error).__name__)
            audit.update(verdict="setup failed", reason=type(error).__name__)
        return result
    finally:
        try:
            if _before_cleanup and created:
                _before_cleanup(home, created.get("name"))
            if created.get("dir_fd") is not None:
                try:
                    remove_own_directory(created["parent_fd"], created["name"], created["dir_fd"], created["ident"])
                    result["removed"] = True
                except OSError as error:
                    result["removed"] = False
                    result["cleanup_refused"] = str(error)[:120]
        finally:
            for key in ("dir_fd", "parent_fd"):
                if created.get(key) is not None:
                    try:
                        os.close(created[key])
                    except OSError:
                        pass
            audit.setdefault("verdict", "error")
            audit.update(hooks_dir=result.get("hooks_dir"), manifest=(result.get("manifest") or {}).get("digest"),
                         policy=result.get("policy"), mode=result.get("mode"), removed=result.get("removed"))
            try:
                write_audit(home, audit)
            except OSError as error:
                result["audit_warning"] = "the audit row could not be written (%s)" % type(error).__name__


# ---- command line ------------------------------------------------------------------------------------------------------
class _Parser(argparse.ArgumentParser):
    def error(self, message):
        raise Refused(message)


def _parser():
    parser = _Parser(prog="ah guard-selftest", allow_abbrev=False, add_help=False,
                     description="Live-test a guard rule with the installed hook, on disposable repositories of its own.")
    parser.add_argument("--rule")
    parser.add_argument("--expect-manifest", dest="expect_manifest")
    parser.add_argument("--expect-policy", dest="expect_policy")
    parser.add_argument("--print-manifest", dest="print_manifest", action="store_true")
    return parser


def cli_main(argv):
    """Print one JSON object and return the exit code. Anything not exactly the documented arguments is refused (exit 3)."""
    try:
        args = _parser().parse_args(list(argv))
        if args.print_manifest:
            if args.rule or args.expect_manifest or args.expect_policy:
                raise Refused("--print-manifest takes no other argument")
            module_dir = Path(os.path.realpath(str(HERE)))
            if module_dir != installed_dir(user_home()):
                raise Refused("this is not the installed copy: %s is not %s" % (module_dir, installed_dir(user_home())))
            items = manifest(module_dir)
            policy, _parsed = policy_state(module_dir)
            result = {"ok": True, "exit_code": 0, "hooks_dir": str(module_dir), "policy": policy,
                      "manifest": {"files": [{"name": n, "blob": b} for n, b in items], "digest": manifest_digest(items)}}
        else:
            if not (args.rule and args.expect_manifest and args.expect_policy):
                raise Refused("--rule, --expect-manifest and --expect-policy are all required")
            result = run_selftest(args.rule, args.expect_manifest, args.expect_policy, cli=True,
                                  session=os.environ.get("CLAUDE_CODE_SESSION_ID") or os.environ.get("CLAUDE_SESSION_ID") or "",
                                  agent=os.environ.get("AH_AGENT_ID", ""))
    except Refused as error:
        result = {"ok": False, "exit_code": 3, "refused": str(error)}
    sys.stdout.write(json.dumps(result, indent=2) + "\n")
    return result["exit_code"]


if __name__ == "__main__":
    sys.exit(cli_main(sys.argv[1:]))
