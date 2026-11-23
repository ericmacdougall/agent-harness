"""`ah ops doctor` and `ah ops verify-parity`: are the installed hooks the bytes of canonical main? (goodqa#16754)

The self-serve policy (docs/operations.md, Agent self-serve) is only as trustworthy as the guards that read it, so the
enabler refuses to run, and `doctor` reports, when any installed hook differs from the reviewed canonical bytes.

What it does, all read only:

  * fetches the canonical repository's main into a FRESH temporary repository this tool owns (never a checkout the
    caller names), blobless, and reads only tree entries: the git blob sha of every file in harness/hooks/ at that
    commit. The two name lists come from that commit's own install.py (HOOKS, the Claude set) and install_codex.py
    (DELIVERY_HELPERS, the Codex set), parsed with ast, never imported or executed;
  * compares them with ~/.claude/hooks and ~/.codex/agent-harness on this Mac, and over one constant ssh command on
    t2-dev. The remote program is this very file piped to `python3 -I -` on stdin; names are validated and passed as
    JSON data, so nothing the caller types is ever part of a shell line;
  * lists the Codex hooks that Codex will skip (no trust entry, or a hash that no longer matches hooks.json). It never
    writes trusted_hash or any other file: the /hooks click stays the user's (spec NEG-11);
  * `--probe` (AC-14) checks the user-level settings for the exact allow rule `Bash(python3 ~/.claude/hooks/ah.py ops *)`
    and for deny or ask rules that shadow it, then runs ONE read-only allow-listed recipe (`ah.py ops doctor --host mac
    --json`: no argument beyond itself, no journal, no write). A PASS is labelled "rule present and recipe runs": the
    subprocess bypasses the permission system, so the fresh-session no-prompt run is the click-test's. A denial is a
    limitation plus a ready P0 ticket (`--file-ticket` files it).

An unreachable or unparsable host is UNKNOWN, never clean, and never falls back to a local copy (NEG-12). Exit codes:
0 every host CLEAN, 1 drift found, 3 something unknown (no canonical bytes, host unreachable), 2 usage.

What CLEAN means. Every name the commit's installers list must be shipped at that commit and must match byte for byte
(a name the tree does not ship, or an empty tree, is UNKNOWN: nothing was compared, so nothing is clean). Beyond the
listed bytes, CLEAN also needs: no importable file in the hooks directories that the canonical tree does not ship
(a planted json.py or sitecustomize.py would run before the guards' own imports), every fail-closed guard registered in
~/.claude/settings.json as the installer writes it (GUARD_REGISTRATIONS, pinned to install.py by a contract test) and
hooks not switched off, and, for Codex, the guard commands present in hooks.json. Project-level and managed settings
are not read: CLEAN is "installed bytes and user-level registrations match", not proof a session runs every guard.

Two entry points. `verify(..., ref=...)` is for the doctor and may compare an older ancestor. `verify_gate()` is the
only call the enabler may make: it has no host argument and no free `ref`. Without a pin it compares the tip of canonical
main on every host. The one way to compare anything else is `pinned_sha`, which must be the release SHA the USER typed
on the enabler's own command line (the enabler runs only from the user's terminal) and must be an ancestor of main; an
agent-supplied or leftover ref has no path to the gate. The gate also refuses on untrusted or changed Codex hooks.

Threat model: careless or hurried agents, not one that edits this module.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import io
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

CANONICAL_URL = "https://github.com/ericmacdougall/agent-harness.git"
ALLOW_FILE = False  # tests only: lets the fetch read a local bare repository standing in for the canonical URL
REMOTE_HOSTS = ("t2-dev",)
LOCAL_HOST = "mac"
NAME_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]*")
REF_RE = re.compile(r"[0-9a-f]{40}")
MAX_FILE = 16 * 1024 * 1024
MAX_REMOTE_OUTPUT = 4 * 1024 * 1024
GIT_TIMEOUT = 180
SSH_TIMEOUT = 90
PROBE_TIMEOUT = 200
# The one allow-listed recipe the probe runs. `ops repair --check` is not usable: it needs --ref and journals under
# ~/.agent-harness/work/self-serve/ (so it is neither argument-free nor write-free). `ops doctor` is read only, journals
# nothing and needs no argument, and ah.py dispatches it to this module.
PROBE_RECIPE = ("ops", "doctor", "--host", "mac", "--json")
PROBE_SCOPE = "rule-present-and-recipe-runs"  # what a probe PASS proves; the fresh-session check is the click-test
CLAUDE_DIR = (".claude", "hooks")
CODEX_DIR = (".codex", "agent-harness")
CODEX_HOOKS_JSON = (".codex", "hooks.json")
CODEX_CONFIG = (".codex", "config.toml")
CLAUDE_SETTINGS = (".claude", "settings.json")
CLAUDE_SETTINGS_LOCAL = (".claude", "settings.local.json")
MAX_ENTRIES = 2000
IMPORTABLE_SUFFIXES = (".py", ".pyc", ".so", ".pyd")
BLOB_RE = re.compile(r"[0-9a-f]{40}")
# The fail-closed handlers `install.managed_hooks` registers (onFailure "block"): (event, matcher, script, args).
# tests/test_ah_parity.py::Contract compares this table with the real installer, so a change there fails CI here.
GUARD_REGISTRATIONS = (
    ("UserPromptSubmit", None, "wal.py", ("prompt",)),
    ("PreToolUse", "Bash|PowerShell", "command_guard_hook.py", ("hook",)),
    ("PreToolUse", "Bash|PowerShell", "kill_guard.py", ("hook",)),
    ("PreToolUse", "Agent|Task|Workflow|Bash|PowerShell|Write|Edit|MultiEdit|NotebookEdit", "wal.py", ("pretool",)),
    ("PreToolUse", "Agent|Task|Workflow|Bash|PowerShell|Write|Edit|MultiEdit|NotebookEdit", "merge_gate.py", ("hook",)),
    ("PreToolUse", "Agent|Task|Workflow|Bash", "tier_gate.py", ("hook",)),
    ("PreToolUse", "Bash", "commit_policy.py", ("hook",)),
    ("PreToolUse", "^mcp__.*[Gg][Oo][Oo][Dd][Qq][Aa].*__(close_issue_done|close_issue_wont_fix|update_issue|"
                   "bulk_update_issues|archive_issue|reassign_issue|call_api)$", "spec_flow.py", ("hook",)),
)
# Files install_codex.install() writes into ~/.codex/agent-harness/ besides DELIVERY_HELPERS, with the repository path each
# comes from (the Codex wal.py is NOT harness/hooks/wal.py). Pinned here and by Contract against the real installer.
CODEX_INSTALLED_ELSEWHERE = {"wal.py": "codex/hooks/wal.py", "ops_watch.py": "harness/hooks/ops_watch.py",
                             "watch-tests.py": "harness/tools/watch-tests.py"}
TREE_DIRS = ("harness/hooks", "harness/tools", "codex/hooks")
# Codex registers the same guards as command strings in hooks.json: (event, script) must appear in a handler command.
CODEX_GUARDS = (("PreToolUse", "command_guard_hook.py"), ("PreToolUse", "kill_guard.py"),
                ("PreToolUse", "merge_gate.py"), ("PreToolUse", "commit_policy.py"))


class ParityError(Exception):
    pass


# ----------------------------------------------------------------------------- canonical side

def _git_env(home):
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(home), "GIT_CONFIG_NOSYSTEM": "1",
           "GIT_CONFIG_GLOBAL": os.devnull, "GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0", "LC_ALL": "C"}
    return env


def _git(repo, args, home, timeout=GIT_TIMEOUT):
    cmd = ["git", "-C", str(repo)]
    if ALLOW_FILE:
        cmd += ["-c", "protocol.file.allow=always"]
    p = subprocess.run(cmd + list(args), capture_output=True, text=True, timeout=timeout, env=_git_env(home))
    if p.returncode != 0:
        raise ParityError("git %s failed (exit %d)" % (args[0], p.returncode))
    return p.stdout


def _tuple_assignment(source, name):
    """The string tuple assigned to a module-level `name`, from source text, without executing it."""
    for node in ast.parse(source).body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in node.targets):
            value = ast.literal_eval(node.value)
            if isinstance(value, (tuple, list)) and all(isinstance(x, str) for x in value):
                return tuple(value)
    raise ParityError("%s is not a literal string tuple at the canonical commit" % name)


def check_snapshot(snap):
    """The one validator of canonical data (canonical_snapshot and judge both call it): an empty tree, an empty name
    list, an unsafe name or a listed name with no blob is a ParityError, so no host is ever judged against nothing."""
    try:
        claude, codex, blobs = tuple(snap["claude"]), tuple(snap["codex"]), snap["blobs"]
    except (KeyError, TypeError):
        raise ParityError("canonical snapshot has the wrong shape")
    if not isinstance(blobs, dict) or not blobs:
        raise ParityError("canonical commit ships no files under harness/hooks/ (nothing to compare with)")
    if not claude or not codex:
        raise ParityError("canonical installer name list is empty (nothing to compare with)")
    names = set(claude) | set(codex)
    if any(not isinstance(n, str) or not NAME_RE.fullmatch(n) for n in names):
        raise ParityError("canonical name list holds an unsafe name")
    codex_blobs = snap.get("codex_blobs")
    if not isinstance(codex_blobs, dict):
        raise ParityError("canonical snapshot has no Codex blob table")
    for flavor, listed, table in (("claude", claude, blobs), ("codex", codex, codex_blobs)):
        absent = sorted(n for n in set(listed) if not isinstance(table.get(n), str) or not BLOB_RE.fullmatch(table[n]))
        if absent:
            raise ParityError("%s installer lists files the canonical commit does not ship: %s" % (flavor, ", ".join(absent[:8])))


def build_snapshot(sha, tip, install_source, install_codex_source, tree):
    """The validated snapshot of one commit. `tree` maps repository path -> git blob sha for every file under TREE_DIRS.
    Expected Claude files: install.py HOOKS from harness/hooks/. Expected Codex files: install_codex.py DELIVERY_HELPERS
    from harness/hooks/, plus what install_codex.install() writes from elsewhere (CODEX_INSTALLED_ELSEWHERE)."""
    claude = _tuple_assignment(install_source, "HOOKS")
    delivery = _tuple_assignment(install_codex_source, "DELIVERY_HELPERS")
    blobs = {path.rsplit("/", 1)[-1]: blob for path, blob in tree.items() if path.rsplit("/", 1)[0] == "harness/hooks"}
    codex_blobs = {n: blobs[n] for n in delivery if n in blobs}
    for dest, source in CODEX_INSTALLED_ELSEWHERE.items():
        if source in tree:
            codex_blobs[dest] = tree[source]
    codex = tuple(delivery) + tuple(n for n in CODEX_INSTALLED_ELSEWHERE if n not in delivery)
    snap = {"sha": sha, "tip": tip, "claude": claude, "codex": codex, "blobs": blobs, "codex_blobs": codex_blobs,
            "not_in_ref": []}
    check_snapshot(snap)
    return snap


def canonical_snapshot(ref=None, url=None):
    """{sha, claude, codex, blobs, not_in_ref}: the canonical main commit, the two name lists and each hook's blob sha."""
    if ref is not None and not REF_RE.fullmatch(ref):
        raise ParityError("--ref must be a full 40 hex commit that is an ancestor of canonical main")
    work = Path(tempfile.mkdtemp(prefix="ah-parity-"))
    try:
        os.chmod(work, 0o700)
        _git(work, ["init", "-q"], work)
        fetch = ["fetch", "-q", "--no-tags", "--filter=blob:none"]
        if ref is None:
            fetch += ["--depth=1"]
        _git(work, fetch + [url or CANONICAL_URL, "main"], work)
        tip = _git(work, ["rev-parse", "FETCH_HEAD"], work).strip()
        sha = tip
        if ref is not None:
            _git(work, ["cat-file", "-e", ref + "^{commit}"], work)
            _git(work, ["merge-base", "--is-ancestor", ref, tip], work)
            sha = ref
        listing = _git(work, ["ls-tree", "-r", sha, "--"] + list(TREE_DIRS), work)
        tree = {}
        for line in listing.splitlines():
            meta, _, rel = line.partition("\t")
            parts = meta.split()
            if len(parts) == 3 and parts[1] == "blob":
                tree[rel] = parts[2]
        return build_snapshot(sha, tip, _git(work, ["show", sha + ":install.py"], work),
                              _git(work, ["show", sha + ":install_codex.py"], work), tree)
    except subprocess.TimeoutExpired:
        raise ParityError("canonical fetch timed out")
    finally:
        shutil.rmtree(work, ignore_errors=True)


# ----------------------------------------------------------------------------- host side (also runs remotely)

def blob_sha(data):
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


def hash_dir(directory, names):
    """{name: git blob sha | 'missing' | 'symlink' | 'not-file' | 'too-big'}; a symlink is never followed."""
    out = {}
    for name in names:
        path = os.path.join(directory, name)
        try:
            st = os.lstat(path)
        except OSError:
            out[name] = "missing"
            continue
        import stat as _stat
        if _stat.S_ISLNK(st.st_mode):
            out[name] = "symlink"
        elif not _stat.S_ISREG(st.st_mode):
            out[name] = "not-file"
        elif st.st_size > MAX_FILE:
            out[name] = "too-big"
        else:
            with open(path, "rb") as fh:
                out[name] = blob_sha(fh.read())
    return out


CODEX_HASHED_FIELDS = ("type", "command", "timeout", "async", "statusMessage")
TRUST_RE = re.compile(r'^\[hooks\.state\."([^"]+)"\][ \t]*\r?\n(?:[ \t]*\r?\n)*[ \t]*trusted_hash[ \t]*=[ \t]*"([^"]+)"',
                      re.M)


def _snake(event):
    return re.sub(r"(?<!^)([A-Z])", r"_\1", event).lower()


def codex_hook_hash(label, matcher, handler):
    """Codex's trust hash of one handler (same algorithm as ops_watch.codex_hook_hash; a test keeps them equal)."""
    h = {k: v for k, v in handler.items() if k in CODEX_HASHED_FIELDS}
    h.setdefault("async", False)
    ident = {"event_name": label, "hooks": [h]}
    if matcher is not None:
        ident["matcher"] = matcher
    blob = json.dumps(ident, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "sha256:" + hashlib.sha256(blob.encode()).hexdigest()


def codex_trust(hooks_path, config_path):
    """Read only. {present, untrusted: [pos], changed: [pos], hooks: n}; positions are `event:group:handler`."""
    if not os.path.isfile(hooks_path):
        return {"present": False, "untrusted": [], "changed": [], "hooks": 0, "commands": {}}
    with open(hooks_path, "rb") as fh:
        data = json.loads(fh.read(MAX_FILE).decode("utf-8"))
    expected = {}
    commands = {}
    for event, groups in (data.get("hooks") or {}).items():
        label = _snake(event)
        for gi, group in enumerate(groups or []):
            for hi, handler in enumerate(group.get("hooks") or []):
                expected["%s:%s:%d:%d" % (hooks_path, label, gi, hi)] = codex_hook_hash(label, group.get("matcher"), handler)
                if isinstance(handler.get("command"), str):
                    commands.setdefault(event, []).append(handler["command"])
    trusted = {}
    if os.path.isfile(config_path):
        with open(config_path, "rb") as fh:
            trusted = dict(TRUST_RE.findall(fh.read(MAX_FILE).decode("utf-8", "replace")))
    prefix = hooks_path + ":"
    return {"present": True, "hooks": len(expected), "commands": commands,
            "untrusted": sorted(k[len(prefix):] for k in expected if k not in trusted),
            "changed": sorted(k[len(prefix):] for k, v in expected.items() if k in trusted and trusted[k] != v)}


def importable_extras(directory, names):
    """{entry: hash | 'package'} for every file or package in `directory` that Python could import and that the
    installer does not list. Hook scripts run with their own directory first on sys.path, so such an entry (a planted
    json.py, sitecustomize.py or a package) runs before the guard's own imports. Fails closed when the listing is cut."""
    out = {}
    try:
        entries = sorted(os.listdir(directory))
    except OSError:
        return out
    if len(entries) > MAX_ENTRIES:
        out["__too_many_entries__"] = "truncated"
        entries = entries[:MAX_ENTRIES]
    skip = set(names)
    files = []
    for entry in entries:
        if entry in skip or entry == "__pycache__":
            continue
        path = os.path.join(directory, entry)
        stem = entry.split(".")[0]
        if entry.endswith(IMPORTABLE_SUFFIXES) or ".cpython-" in entry:
            if stem.isidentifier():
                files.append(entry)
        elif stem == entry and entry.isidentifier() and os.path.isdir(path) and not os.path.islink(path):
            if os.path.lexists(os.path.join(path, "__init__.py")):
                out[entry] = "package"
        elif entry.isidentifier() and os.path.islink(path):
            out[entry] = "symlink"  # a link under an importable name: never followed
    out.update(hash_dir(directory, files))
    return out


def _handler_script(handler, hooks_dir):
    """(script basename, args tuple) of a settings.json command handler whose script lives in `hooks_dir`, else None."""
    if not isinstance(handler, dict) or handler.get("type") != "command":
        return None
    if isinstance(handler.get("args"), list) and all(isinstance(a, str) for a in handler["args"]):
        argv = list(handler["args"])
    elif isinstance(handler.get("command"), str):
        try:
            argv = shlex.split(handler["command"])
        except ValueError:
            return None
        if argv and os.path.basename(argv[0]).startswith("python"):
            argv = argv[1:]
    else:
        return None
    if not argv or os.path.dirname(argv[0]) != hooks_dir:
        return None
    return os.path.basename(argv[0]), tuple(argv[1:]), handler.get("onFailure")


def settings_facts(home):
    """Read only facts about the user-level Claude settings: the hook handlers whose script is in the hooks directory,
    and whether hooks are switched off. {present, error, disabled, registrations: [[event, matcher, script, args, onFailure]]}"""
    hooks_dir = os.path.join(str(home), *CLAUDE_DIR)
    out = {"present": False, "error": None, "disabled": False, "registrations": []}
    path = os.path.join(str(home), *CLAUDE_SETTINGS)
    local = os.path.join(str(home), *CLAUDE_SETTINGS_LOCAL)
    if os.path.isfile(local):
        try:
            with open(local, "rb") as fh:
                if (json.loads(fh.read(MAX_FILE).decode("utf-8")) or {}).get("disableAllHooks"):
                    out["disabled"] = True
        except (OSError, ValueError, AttributeError):
            out["error"] = "settings.local.json is not readable JSON"
    if not os.path.isfile(path):
        return out
    out["present"] = True
    try:
        with open(path, "rb") as fh:
            data = json.loads(fh.read(MAX_FILE).decode("utf-8"))
        if not isinstance(data, dict):
            raise ValueError("not an object")
        out["disabled"] = out["disabled"] or bool(data.get("disableAllHooks"))
        for event, groups in (data.get("hooks") or {}).items():
            for group in groups or []:
                for handler in group.get("hooks") or []:
                    found = _handler_script(handler, hooks_dir)
                    if found:
                        out["registrations"].append([event, group.get("matcher"), found[0], list(found[1]), found[2]])
    except (OSError, ValueError, AttributeError, TypeError) as exc:
        out["error"] = "settings.json is not readable JSON (%s)" % type(exc).__name__
        out["registrations"] = []
    return out


def collect(home, claude_names, codex_names):
    """Everything a host has to say, as JSON-able data. Runs unchanged on the Mac and, piped, on the remote host."""
    home = str(home)
    claude_dir = os.path.join(home, *CLAUDE_DIR)
    codex_dir = os.path.join(home, *CODEX_DIR)
    return {"home_ok": os.path.isdir(home),
            "claude": {"dir": claude_dir, "present": os.path.isdir(claude_dir), "hashes": hash_dir(claude_dir, claude_names),
                       "extras": importable_extras(claude_dir, claude_names)},
            "codex": {"dir": codex_dir, "present": os.path.isdir(codex_dir), "hashes": hash_dir(codex_dir, codex_names),
                      "extras": importable_extras(codex_dir, codex_names)},
            "settings": settings_facts(home),
            "trust": codex_trust(os.path.join(home, *CODEX_HOOKS_JSON), os.path.join(home, *CODEX_CONFIG))}


def _collect_cli(names_json):
    """Entry point of the piped remote program: print collect() as one JSON line."""
    names = json.loads(names_json)
    sys.stdout.write(json.dumps(collect(os.path.expanduser("~"), names["claude"], names["codex"])) + "\n")


# ----------------------------------------------------------------------------- comparison

def judge(snapshot, info):
    """One host's verdict from its collected data and the canonical snapshot. Raises ParityError when nothing could be
    compared (the caller records UNKNOWN): a verdict of CLEAN needs every listed name compared and equal."""
    check_snapshot(snapshot)
    result = {"claude": {"differ": [], "missing": [], "unexpected": [], "registrations": [], "ok": 0},
              "codex": {"differ": [], "missing": [], "unexpected": [], "registrations": [], "ok": 0, "present": True}}
    for flavor in ("claude", "codex"):
        section = info.get(flavor) or {}
        hashes = section.get("hashes") or {}
        r = result[flavor]
        r["present"] = bool(section.get("present"))
        if flavor == "codex" and not r["present"]:
            continue  # a host without Codex installed is not drift
        names = tuple(dict.fromkeys(snapshot[flavor]))
        table = snapshot["codex_blobs"] if flavor == "codex" else snapshot["blobs"]
        for name in names:
            want = table[name]  # check_snapshot guarantees every listed name has a blob
            have = hashes.get(name, "missing")
            if have == want:
                r["ok"] += 1
            elif have == "missing":
                r["missing"].append(name)
            else:
                r["differ"].append(name)
        if r["ok"] + len(r["differ"]) + len(r["missing"]) != len(set(names)) or len(set(names)) == 0:
            raise ParityError("%s: the comparison did not cover every listed name" % flavor)
        for name, have in (section.get("extras") or {}).items():
            if table.get(name) != have:  # shipped at the commit with the same bytes is fine; anything else is not
                r["unexpected"].append(name)
        r["differ"].sort()
        r["missing"].sort()
        r["unexpected"].sort()
    settings = info.get("settings") or {}
    reg = result["claude"]["registrations"]
    have_regs = {(e, m, sc, tuple(a or ())) : f for e, m, sc, a, f in settings.get("registrations") or []}
    for event, matcher, script, args in GUARD_REGISTRATIONS:
        if have_regs.get((event, matcher, script, args)) != "block":
            reg.append("%s %s %s" % (event, script, " ".join(args)))
    if settings.get("disabled"):
        reg.append("disableAllHooks is set")
    if settings.get("error"):
        reg.append(str(settings["error"]))
    trust = info.get("trust") or {}
    if result["codex"]["present"]:
        commands = trust.get("commands") or {}
        for event, script in CODEX_GUARDS:
            if not any("/agent-harness/%s" % script in c for c in commands.get(event, [])):
                result["codex"]["registrations"].append("%s %s" % (event, script))
    result["trust"] = {"present": bool(trust.get("present")), "untrusted": list(trust.get("untrusted") or []),
                       "changed": list(trust.get("changed") or [])}
    drift = any(result[f][k] for f in ("claude", "codex") for k in ("differ", "missing", "unexpected", "registrations"))
    complete = result["claude"]["ok"] == len(set(snapshot["claude"])) and (
        not result["codex"]["present"] or result["codex"]["ok"] == len(set(snapshot["codex"])))
    result["status"] = "DRIFT" if drift else ("CLEAN" if complete else "UNKNOWN")
    if result["status"] == "UNKNOWN":
        raise ParityError("no clean verdict is possible: the comparison was incomplete")
    return result


def _valid_remote(info):
    try:
        return (isinstance(info, dict) and isinstance(info["claude"]["hashes"], dict)
                and isinstance(info["codex"]["hashes"], dict) and isinstance(info["trust"], dict)
                and isinstance(info["claude"]["extras"], dict) and isinstance(info["codex"]["extras"], dict)
                and isinstance(info["settings"], dict) and isinstance(info["settings"].get("registrations"), list))
    except (KeyError, TypeError):
        return False


def default_runner(argv, stdin=None, timeout=SSH_TIMEOUT):
    p = subprocess.run(argv, input=stdin, capture_output=True, text=True, timeout=timeout)
    return p.returncode, p.stdout, p.stderr


def remote_collect(host, snapshot, runner=default_runner):
    """Run the read-only collector on `host` over one constant ssh command. Any failure raises ParityError."""
    if host not in REMOTE_HOSTS:
        raise ParityError("unknown host %s" % host)
    names = json.dumps({"claude": list(snapshot["claude"]), "codex": list(snapshot["codex"])})
    payload = Path(__file__).read_text(encoding="utf-8") + "\n_collect_cli(%r)\n" % names
    try:
        rc, out, _err = runner(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", host, "python3", "-I", "-"],
                               payload, SSH_TIMEOUT)
    except (subprocess.TimeoutExpired, OSError) as exc:
        raise ParityError("ssh to %s did not complete (%s)" % (host, type(exc).__name__))
    if rc != 0:
        raise ParityError("ssh to %s failed (exit %s)" % (host, rc))
    if len(out) > MAX_REMOTE_OUTPUT:
        raise ParityError("remote output too large")
    try:
        info = json.loads(out.strip().splitlines()[-1])
    except (ValueError, IndexError):
        raise ParityError("remote output from %s was not JSON" % host)
    if not _valid_remote(info):
        raise ParityError("remote output from %s had the wrong shape" % host)
    return info


def _verify(hosts, ref, home, runner, url, strict):
    hosts = list(hosts or (LOCAL_HOST,) + REMOTE_HOSTS)
    report = {"ok": False, "ref": None, "ref_is_tip": None, "not_in_ref": [], "hosts": {}, "error": None, "gate": []}
    try:
        snap = canonical_snapshot(ref, url)
    except (ParityError, OSError, ValueError, SyntaxError) as exc:
        report["error"] = "canonical bytes unavailable: %s" % exc
        for h in hosts:
            report["hosts"][h] = {"status": "UNKNOWN", "error": "no canonical bytes to compare with"}
        return report
    except subprocess.SubprocessError as exc:
        report["error"] = "canonical bytes unavailable: %s" % type(exc).__name__
        for h in hosts:
            report["hosts"][h] = {"status": "UNKNOWN", "error": "no canonical bytes to compare with"}
        return report
    report["ref"] = snap["sha"]
    report["ref_is_tip"] = snap["sha"] == snap["tip"]
    for h in hosts:
        try:
            if h == LOCAL_HOST:
                info = collect(home or Path.home(), snap["claude"], snap["codex"])
            else:
                info = remote_collect(h, snap, runner)  # a remote failure is UNKNOWN: never a local fallback
            report["hosts"][h] = judge(snap, info)
        except (ParityError, OSError, ValueError) as exc:
            report["hosts"][h] = {"status": "UNKNOWN", "error": str(exc)}
    if strict:
        for h, v in report["hosts"].items():
            t = v.get("trust") or {}
            if t.get("untrusted") or t.get("changed"):
                report["gate"].append("%s: Codex will skip %d hook(s) (untrusted or changed); the user reviews them with /hooks"
                                      % (h, len(t["untrusted"]) + len(t["changed"])))
    report["ok"] = bool(report["hosts"]) and all(v["status"] == "CLEAN" for v in report["hosts"].values()) and not report["gate"]
    return report


def verify(hosts=None, ref=None, home=None, runner=default_runner, url=None):
    """The doctor's entry point. {ok, ref, ref_is_tip, hosts: {host: verdict}, error, gate}.

    `ref` may name an older ancestor of canonical main, so a True here says nothing about the CURRENT reviewed hooks:
    the enabler must call verify_gate(), never this. ok is True only when every requested host is CLEAN.
    Never raises, never writes."""
    return _verify(hosts, ref, home, runner, url, strict=False)


def verify_gate(pinned_sha=None, home=None, runner=default_runner, url=None):
    """The only parity call the enabler may make (AC-11, NEG-3). No host list and no free ref: every host is checked.

    `pinned_sha` is None (compare the tip of canonical main) or the release SHA from the USER's own command line, which
    must be a full 40 hex ancestor of canonical main. The enabler passes nothing else; `ah ops verify-parity` has no
    --ref at all. The gate is also strict about Codex: any untrusted or changed Codex hook is a refusal.
    Never raises, never writes; ok is True only when every host is CLEAN and nothing in report["gate"] remains."""
    try:
        if pinned_sha is not None and not (isinstance(pinned_sha, str) and REF_RE.fullmatch(pinned_sha)):
            return {"ok": False, "ref": None, "ref_is_tip": None, "pinned": True, "not_in_ref": [], "hosts": {},
                    "error": "pinned SHA must be a full 40 hex commit", "gate": ["pinned SHA is malformed"]}
        report = _verify(None, pinned_sha, home, runner, url, strict=True)
        report["pinned"] = pinned_sha is not None
        return report
    except Exception as exc:  # the contract is "never raises": any surprise is a refusal
        return {"ok": False, "ref": None, "ref_is_tip": None, "pinned": pinned_sha is not None, "not_in_ref": [], "hosts": {},
                "error": "parity check failed: %s" % type(exc).__name__, "gate": ["parity check failed"]}


# ----------------------------------------------------------------------------- probe (AC-14)

def _rule_inner(rule):
    """The pattern inside a `Bash(...)` permission rule; '*' for a bare `Bash`; None for any other tool or malformed rule."""
    if not isinstance(rule, str):
        return None
    rule = rule.strip()
    if rule == "Bash":
        return "*"
    if rule.startswith("Bash(") and rule.endswith(")"):
        return rule[5:-1]
    return None


def rule_matches(rule, command):
    """Does one permission rule (allow, ask or deny) match this exact command string? The one matcher the probe uses."""
    inner = _rule_inner(rule)
    if inner is None:
        return False
    if inner.endswith(":*"):
        prefix = inner[:-2]
        return command == prefix or command.startswith(prefix + " ")
    if "*" in inner:
        return re.fullmatch("".join(".*" if c == "*" else re.escape(c) for c in inner), command, re.S) is not None
    return command == inner


def _ah_forms(home):
    return ("~/.claude/hooks/ah.py", str(Path(home) / ".claude" / "hooks" / "ah.py"))


def probe_commands(home):
    """Every spelling of the recipe command a permission rule could be asked about (with and without -I)."""
    return ["python3 %s%s %s" % (flag, ah, " ".join(PROBE_RECIPE)) for ah in _ah_forms(home) for flag in ("", "-I ")]


def is_exact_allow_rule(rule, home):
    """Exactly the rule the enabler writes, `Bash(python3 ~/.claude/hooks/ah.py ops *)` (the absolute-path and `:*`
    spellings too): that prefix and no other. The enabler's literal is pinned by Contract."""
    inner = _rule_inner(rule)
    if inner is None or not (inner.endswith(" *") or inner.endswith(":*")):
        return False
    return inner[:-2].split(" ") in [["python3", ah, PROBE_RECIPE[0]] for ah in _ah_forms(home)]


def _permission_rules(home, key):
    rules = []
    for rel in (CLAUDE_SETTINGS, CLAUDE_SETTINGS_LOCAL):
        try:
            data = json.loads(home.joinpath(*rel).read_text(encoding="utf-8"))
            got = (data.get("permissions") or {}).get(key) or []
        except (OSError, ValueError, AttributeError):
            continue
        rules.extend(r for r in got if isinstance(r, str))
    return rules


def permission_limitation(home):
    """None when the user-level settings carry the exact allow rule and no deny or ask rule shadows the probe command,
    else the reason. Reads ~/.claude/settings.json and settings.local.json only (project and managed settings are not read)."""
    commands = probe_commands(home)
    allow = [r for r in _permission_rules(home, "allow") if is_exact_allow_rule(r, home)]
    if not allow:
        return "no exact-prefix allow rule `Bash(python3 %s ops *)` in ~/.claude/settings.json: the host will prompt" % _ah_forms(home)[0]
    for key in ("deny", "ask"):
        for r in _permission_rules(home, key):
            if any(rule_matches(r, c) for c in commands):
                return "a %s rule shadows the allow rule (%s): the host will %s" % (key, r[:80], "refuse" if key == "deny" else "prompt")
    return None


def probe(home=None, runner=default_runner, ah_path=None, ah_clean=None):
    """Run the one allow-listed recipe in dry run. {status, reason, scope, ticket}.

    PASS means only "the exact allow rule is present and not shadowed, and the recipe ran and printed its report". The
    recipe runs through subprocess, which bypasses the permission system: whether a FRESH SESSION runs it without a
    prompt is the click-test's job (AC-14). `ah_clean` False (the installed ah.py is not canonical) is a limitation."""
    home = Path(home or Path.home())
    ah = Path(ah_path) if ah_path else home / ".claude" / "hooks" / "ah.py"
    limitation = permission_limitation(home)
    if ah_clean is False:
        limitation = limitation or "the installed ah.py is not the canonical bytes, so a clean exit proves nothing"
    if not ah.is_file():
        return _limited("installed ah.py not found at %s" % ah)
    argv = [sys.executable, "-I", str(ah)] + list(PROBE_RECIPE)
    try:
        rc, out, err = runner(argv, None, PROBE_TIMEOUT)
    except (subprocess.TimeoutExpired, OSError) as exc:
        return _limited("probe recipe did not complete (%s)" % type(exc).__name__)
    text = ((out or "") + (err or "")).lower()
    if "blocked" in text or "denied" in text or "permission" in text:
        return _limited("the recipe was denied: %s" % (err or out or "").strip().splitlines()[0][:200])
    if "invalid choice" in text or "unknown" in text or "unrecognized" in text or "not_available" in text or "not installed" in text:
        return _limited("the recipe is not installed yet (`ops doctor` missing or not wired in the installed ah.py)")
    # `ops doctor` exits 0 (clean), 1 (drift) or 3 (unknown): all mean the recipe ran. Anything else is not a run.
    if rc in (0, 1, 3) and _ran(out):
        if limitation is None:
            return {"status": "PASS", "scope": PROBE_SCOPE, "ticket": None,
                    "reason": "allow rule present and recipe runs: `ah.py %s` ran (exit %d, report printed) in a subprocess; "
                              "that bypasses the permission system, so the fresh-session no-prompt run is the click-test"
                              % (" ".join(PROBE_RECIPE), rc)}
        return _limited(limitation)
    if rc == 0:
        return _limited("the recipe exited 0 but did not print an `ops doctor` report")
    return _limited("the recipe exited %d" % rc)


def _ran(out):
    """True when stdout is the doctor's JSON report (an object with a `hosts` object) or its text header."""
    out = out or ""
    try:
        data = json.loads(out)
        return isinstance(data, dict) and isinstance(data.get("hosts"), dict) and bool(data["hosts"])
    except ValueError:
        return out.lstrip().startswith("canonical main:")


def _limited(reason):
    body = ("`ah ops doctor --probe` could not run an allow-listed recipe in dry run without a prompt.\n\n"
            "Limitation: %s\n\nNo retry by re-encoding or another route (rule 3). Fix the allow rule or the recipe "
            "so a fresh agent session executes `ah.py %s` with no prompt." % (reason, " ".join(PROBE_RECIPE)))
    return {"status": "LIMITATION", "reason": reason, "scope": PROBE_SCOPE,
            "ticket": {"project": "goodqa", "priority": "P0",
                       "title": "Self-serve probe limitation: agent cannot run an allow-listed ah ops recipe", "body": body}}


def file_probe_ticket(ticket, home=None, runner=default_runner):
    home = Path(home or Path.home())
    workdir = home / ".agent-harness" / "work" / "self-serve-parity"
    workdir.mkdir(parents=True, exist_ok=True)
    os.chmod(workdir, 0o700)
    body = workdir / "probe-ticket.md"
    body.write_text(ticket["body"] + "\n", encoding="utf-8")
    argv = [sys.executable, "-I", str(home / ".claude" / "hooks" / "ah.py"), "ticket", "create", "--project", ticket["project"],
            "--title", ticket["title"], "--body-file", str(body), "--priority", ticket["priority"]]
    rc, _out, _err = runner(argv, None, 60)
    return rc == 0


# ----------------------------------------------------------------------------- CLI

def render(report):
    lines = ["canonical main: %s" % (report["ref"] or "unavailable")]
    if report["error"]:
        lines.append("ERROR: %s" % report["error"])
    if report.get("ref_is_tip") is False:
        lines.append("NOTE: compared with an older ancestor of main, not its tip: this is a doctor view, never a gate result")
    for reason in report.get("gate") or []:
        lines.append("GATE REFUSES: %s" % reason)
    for host, v in report["hosts"].items():
        lines.append("%s: %s" % (host, v["status"]))
        if v["status"] == "UNKNOWN":
            lines.append("  reason: %s (not compared; never assumed clean)" % v.get("error"))
            continue
        for flavor in ("claude", "codex"):
            r = v[flavor]
            if flavor == "codex" and not r["present"]:
                lines.append("  codex: not installed on this host")
                continue
            lines.append("  %s: %d match, %d differ, %d missing, %d unexpected" % (
                flavor, r["ok"], len(r["differ"]), len(r["missing"]), len(r["unexpected"])))
            for n in r["differ"]:
                lines.append("    DIFFERS %s" % n)
            for n in r["missing"]:
                lines.append("    MISSING %s" % n)
            for n in r["unexpected"]:
                lines.append("    UNEXPECTED importable file or package (not shipped by canonical main): %s" % n)
            for n in r["registrations"]:
                lines.append("    GUARD NOT REGISTERED as the installer writes it: %s" % n)
        t = v["trust"]
        if t["present"]:
            skipped = t["untrusted"] + t["changed"]
            if skipped:
                lines.append("  codex hooks Codex will skip (user review with /hooks): %s" % ", ".join(skipped))
                lines.append("    untrusted: %d, changed since trust: %d. This tool never writes trusted_hash." %
                             (len(t["untrusted"]), len(t["changed"])))
            else:
                lines.append("  codex hook trust: every hook trusted")
    return "\n".join(lines)


def exit_code(report, strict_trust=False):
    if not report["hosts"]:
        return 3
    statuses = [v["status"] for v in report["hosts"].values()]
    if "UNKNOWN" in statuses:
        return 3
    if "DRIFT" in statuses:
        return 1
    if strict_trust and any(v["trust"]["untrusted"] or v["trust"]["changed"] for v in report["hosts"].values()):
        return 1
    if report.get("gate"):
        return 1
    return 0


def main(argv=None, home=None, runner=default_runner, out=None):
    """Dispatch target for `ah ops <doctor|verify-parity> ...` (argv excludes `ops`). Returns the exit code."""
    out = out or sys.stdout
    p = argparse.ArgumentParser(prog="ah ops", description="installed hooks versus canonical main")
    sub = p.add_subparsers(dest="cmd", required=True)
    for name in ("doctor", "verify-parity"):
        s = sub.add_parser(name)
        s.add_argument("--host", action="append", choices=(LOCAL_HOST,) + REMOTE_HOSTS + ("all",),
                       help="host to check (repeatable; default all)")
        s.add_argument("--json", action="store_true")
        if name == "doctor":
            s.add_argument("--ref", help="doctor only: a canonical-main ancestor commit to compare against (default: main)")
            s.add_argument("--strict-trust", action="store_true", help="untrusted Codex hooks also fail the exit code")
            s.add_argument("--probe", action="store_true",
                           help="also run one allow-listed recipe in dry run (AC-14)")
            s.add_argument("--file-ticket", action="store_true", help="file the P0 ticket when the probe finds a limitation")
    try:
        args = p.parse_args(argv if argv is not None else sys.argv[1:])
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    hosts = None if not args.host or "all" in args.host else list(dict.fromkeys(args.host))
    if args.cmd == "doctor":
        report = verify(hosts, args.ref, home, runner)
        code = exit_code(report, args.strict_trust)
    else:  # verify-parity is the gate form: tip of main only, strict about Codex trust, no --ref
        report = verify_gate(home=home, runner=runner) if hosts is None else _verify(hosts, None, home, runner, None, True)
        code = exit_code(report, True)
    probe_result = None
    if args.cmd == "doctor" and args.probe:
        mac = report["hosts"].get(LOCAL_HOST) or {}
        ah_clean = None
        if mac.get("status") in ("CLEAN", "DRIFT"):
            ah_clean = "ah.py" not in (mac["claude"]["differ"] + mac["claude"]["missing"])
        probe_result = probe(home, runner, ah_clean=ah_clean)
        report["probe"] = probe_result
        if probe_result["status"] != "PASS":
            code = code or 1
            if args.file_ticket and probe_result["ticket"]:
                report["probe"]["ticket_filed"] = file_probe_ticket(probe_result["ticket"], home, runner)
    if args.json:
        out.write(json.dumps(report, indent=1, sort_keys=True) + "\n")
    else:
        out.write(render(report) + "\n")
        if probe_result:
            out.write("probe: %s (%s)\n" % (probe_result["status"], probe_result["reason"]))
            if probe_result["ticket"]:
                t = probe_result["ticket"]
                out.write("  limitation, not a failure to retry. P0 ticket: %s%s\n" % (
                    t["title"], " (filed)" if report["probe"].get("ticket_filed") else " (rerun with --file-ticket)"))
    return code


def doctor(rest, home=None):
    """What ah.py's `ops doctor` imports (`ah_parity.doctor(rest, home)`): runs the doctor with argv `rest` and returns
    the JSON-able report plus `exit_code`, so ah.py can print it. `--json` is implied; the report never carries secrets."""
    buf = io.StringIO()
    argv = ["doctor"] + [a for a in rest if a != "--json"] + ["--json"]
    code = main(argv, home, default_runner, buf)
    try:
        report = json.loads(buf.getvalue())
    except ValueError:
        report = {"ok": False, "error": "usage error or no report (exit %s)" % code, "hosts": {}}
    report["ok"] = code == 0
    report["exit_code"] = code
    return report


def verify_parity(rest, home=None):
    """What ah.py's `ops verify-parity` imports: the gate form (tip of canonical main, strict about Codex trust, no --ref)
    with argv `rest`, returned as the JSON-able report plus `ok` and `exit_code`, like doctor()."""
    buf = io.StringIO()
    argv = ["verify-parity"] + [a for a in rest if a != "--json"] + ["--json"]
    code = main(argv, home, default_runner, buf)
    try:
        report = json.loads(buf.getvalue())
    except ValueError:
        report = {"ok": False, "error": "usage error or no report (exit %s)" % code, "hosts": {}}
    report["ok"] = code == 0
    report["exit_code"] = code
    return report


if __name__ == "__main__" and len(sys.argv) > 1:
    sys.exit(main())
