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
  * `--probe` (AC-14) runs ONE allow-listed recipe in dry run (ah.py ops repair --check) exactly as a fresh agent
    session would, and reports a denial as a limitation plus a ready P0 ticket (`--file-ticket` files it).

An unreachable or unparsable host is UNKNOWN, never clean, and never falls back to a local copy (NEG-12). Exit codes:
0 every host CLEAN, 1 drift found, 3 something unknown (no canonical bytes, host unreachable), 2 usage. Untrusted
Codex hooks are listed and do not change the exit code unless --strict-trust is given.

Threat model: careless or hurried agents, not one that edits this module.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import re
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
PROBE_TIMEOUT = 120
PROBE_RECIPE = ("ops", "repair", "--check")  # the one allow-listed recipe the probe runs, always a dry run
CLAUDE_DIR = (".claude", "hooks")
CODEX_DIR = (".codex", "agent-harness")
CODEX_HOOKS_JSON = (".codex", "hooks.json")
CODEX_CONFIG = (".codex", "config.toml")
CLAUDE_SETTINGS = (".claude", "settings.json")


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
        tree = _git(work, ["ls-tree", sha, "harness/hooks/"], work)
        blobs = {}
        for line in tree.splitlines():
            meta, _, rel = line.partition("\t")
            parts = meta.split()
            if len(parts) == 3 and parts[1] == "blob":
                blobs[rel.rsplit("/", 1)[-1]] = parts[2]
        claude = _tuple_assignment(_git(work, ["show", sha + ":install.py"], work), "HOOKS")
        codex = _tuple_assignment(_git(work, ["show", sha + ":install_codex.py"], work), "DELIVERY_HELPERS")
        names = set(claude) | set(codex)
        bad = [n for n in names if not NAME_RE.fullmatch(n)]
        if bad:
            raise ParityError("canonical name list holds an unsafe name")
        return {"sha": sha, "tip": tip, "claude": claude, "codex": codex, "blobs": blobs,
                "not_in_ref": sorted(n for n in names if n not in blobs)}
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
        return {"present": False, "untrusted": [], "changed": [], "hooks": 0}
    with open(hooks_path, "rb") as fh:
        data = json.loads(fh.read(MAX_FILE).decode("utf-8"))
    expected = {}
    for event, groups in (data.get("hooks") or {}).items():
        label = _snake(event)
        for gi, group in enumerate(groups or []):
            for hi, handler in enumerate(group.get("hooks") or []):
                expected["%s:%s:%d:%d" % (hooks_path, label, gi, hi)] = codex_hook_hash(label, group.get("matcher"), handler)
    trusted = {}
    if os.path.isfile(config_path):
        with open(config_path, "rb") as fh:
            trusted = dict(TRUST_RE.findall(fh.read(MAX_FILE).decode("utf-8", "replace")))
    prefix = hooks_path + ":"
    return {"present": True, "hooks": len(expected),
            "untrusted": sorted(k[len(prefix):] for k in expected if k not in trusted),
            "changed": sorted(k[len(prefix):] for k, v in expected.items() if k in trusted and trusted[k] != v)}


def collect(home, claude_names, codex_names):
    """Everything a host has to say, as JSON-able data. Runs unchanged on the Mac and, piped, on the remote host."""
    home = str(home)
    claude_dir = os.path.join(home, *CLAUDE_DIR)
    codex_dir = os.path.join(home, *CODEX_DIR)
    return {"home_ok": os.path.isdir(home),
            "claude": {"dir": claude_dir, "present": os.path.isdir(claude_dir), "hashes": hash_dir(claude_dir, claude_names)},
            "codex": {"dir": codex_dir, "present": os.path.isdir(codex_dir), "hashes": hash_dir(codex_dir, codex_names)},
            "trust": codex_trust(os.path.join(home, *CODEX_HOOKS_JSON), os.path.join(home, *CODEX_CONFIG))}


def _collect_cli(names_json):
    """Entry point of the piped remote program: print collect() as one JSON line."""
    names = json.loads(names_json)
    sys.stdout.write(json.dumps(collect(os.path.expanduser("~"), names["claude"], names["codex"])) + "\n")


# ----------------------------------------------------------------------------- comparison

def judge(snapshot, info):
    """One host's verdict from its collected data and the canonical snapshot."""
    result = {"claude": {"differ": [], "missing": [], "ok": 0}, "codex": {"differ": [], "missing": [], "ok": 0, "present": True}}
    for flavor in ("claude", "codex"):
        section = info.get(flavor) or {}
        hashes = section.get("hashes") or {}
        r = result[flavor]
        r["present"] = bool(section.get("present"))
        if flavor == "codex" and not r["present"]:
            continue  # a host without Codex installed is not drift
        for name in snapshot[flavor]:
            want = snapshot["blobs"].get(name)
            if want is None:
                continue  # listed by the installer but not shipped at this commit: reported once as not_in_ref
            have = hashes.get(name, "missing")
            if have == want:
                r["ok"] += 1
            elif have == "missing":
                r["missing"].append(name)
            else:
                r["differ"].append(name)
        r["differ"].sort()
        r["missing"].sort()
    trust = info.get("trust") or {}
    result["trust"] = {"present": bool(trust.get("present")), "untrusted": list(trust.get("untrusted") or []),
                       "changed": list(trust.get("changed") or [])}
    drift = any(result[f]["differ"] or result[f]["missing"] for f in ("claude", "codex"))
    result["status"] = "DRIFT" if drift else "CLEAN"
    return result


def _valid_remote(info):
    try:
        return (isinstance(info, dict) and isinstance(info["claude"]["hashes"], dict)
                and isinstance(info["codex"]["hashes"], dict) and isinstance(info["trust"], dict))
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


def verify(hosts=None, ref=None, home=None, runner=default_runner, url=None):
    """The library entry point (the enabler calls this). {ok, ref, hosts: {host: verdict}, error}.

    ok is True only when every requested host is CLEAN. Never raises, never writes."""
    hosts = list(hosts or (LOCAL_HOST,) + REMOTE_HOSTS)
    report = {"ok": False, "ref": None, "not_in_ref": [], "hosts": {}, "error": None}
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
    report["not_in_ref"] = snap["not_in_ref"]
    for h in hosts:
        try:
            if h == LOCAL_HOST:
                info = collect(home or Path.home(), snap["claude"], snap["codex"])
            else:
                info = remote_collect(h, snap, runner)  # a remote failure is UNKNOWN: never a local fallback
            report["hosts"][h] = judge(snap, info)
        except (ParityError, OSError, ValueError) as exc:
            report["hosts"][h] = {"status": "UNKNOWN", "error": str(exc)}
    report["ok"] = all(v["status"] == "CLEAN" for v in report["hosts"].values())
    return report


# ----------------------------------------------------------------------------- probe (AC-14)

def probe(home=None, runner=default_runner, ah_path=None):
    """Run the one allow-listed recipe in dry run the way an agent session would. {status, reason, ticket}."""
    home = Path(home or Path.home())
    ah = Path(ah_path) if ah_path else home / ".claude" / "hooks" / "ah.py"
    limitation = None
    settings = home.joinpath(*CLAUDE_SETTINGS)
    try:
        rules = json.loads(settings.read_text(encoding="utf-8")).get("permissions", {}).get("allow", [])
    except (OSError, ValueError, AttributeError):
        rules = []
    if not any(isinstance(r, str) and "ah.py ops" in r and r.rstrip(")").endswith("*") for r in rules):
        limitation = "no exact-prefix allow rule for `ah.py ops *` in ~/.claude/settings.json: the host will prompt"
    if not ah.is_file():
        return _limited("installed ah.py not found at %s" % ah)
    argv = [sys.executable, "-I", str(ah)] + list(PROBE_RECIPE)
    try:
        rc, out, err = runner(argv, None, PROBE_TIMEOUT)
    except (subprocess.TimeoutExpired, OSError) as exc:
        return _limited("probe recipe did not complete (%s)" % type(exc).__name__)
    text = ((out or "") + (err or "")).lower()
    if rc == 0 and limitation is None:
        return {"status": "PASS", "reason": "`ah.py %s` ran in dry run with exit 0" % " ".join(PROBE_RECIPE), "ticket": None}
    if rc == 0:
        return _limited(limitation)
    if "blocked" in text or "denied" in text or "permission" in text:
        return _limited("the recipe was denied: %s" % (err or out or "").strip().splitlines()[0][:200])
    if "invalid choice" in text or "unknown" in text or "unrecognized" in text:
        return _limited("the recipe is not installed yet (ops repair --check missing in the installed ah.py)")
    return _limited("the recipe exited %d" % rc)


def _limited(reason):
    body = ("`ah ops doctor --probe` could not run an allow-listed recipe in dry run without a prompt.\n\n"
            "Limitation: %s\n\nNo retry by re-encoding or another route (rule 3). Fix the allow rule or the recipe "
            "so a fresh agent session executes `ah.py ops repair --check` with no prompt." % reason)
    return {"status": "LIMITATION", "reason": reason,
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
    if report["not_in_ref"]:
        lines.append("listed by the installers but not shipped at this commit: %s" % ", ".join(report["not_in_ref"]))
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
            lines.append("  %s: %d match, %d differ, %d missing" % (flavor, r["ok"], len(r["differ"]), len(r["missing"])))
            for n in r["differ"]:
                lines.append("    DIFFERS %s" % n)
            for n in r["missing"]:
                lines.append("    MISSING %s" % n)
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
    statuses = [v["status"] for v in report["hosts"].values()]
    if "UNKNOWN" in statuses:
        return 3
    if "DRIFT" in statuses:
        return 1
    if strict_trust and any(v["trust"]["untrusted"] or v["trust"]["changed"] for v in report["hosts"].values()):
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
        s.add_argument("--ref", help="a canonical-main ancestor commit to compare against (default: main)")
        s.add_argument("--json", action="store_true")
        s.add_argument("--strict-trust", action="store_true", help="untrusted Codex hooks also fail the exit code")
        if name == "doctor":
            s.add_argument("--probe", action="store_true",
                           help="also run one allow-listed recipe in dry run (AC-14)")
            s.add_argument("--file-ticket", action="store_true", help="file the P0 ticket when the probe finds a limitation")
    try:
        args = p.parse_args(argv if argv is not None else sys.argv[1:])
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    hosts = None if not args.host or "all" in args.host else list(dict.fromkeys(args.host))
    report = verify(hosts, args.ref, home, runner)
    code = exit_code(report, args.strict_trust)
    probe_result = None
    if args.cmd == "doctor" and args.probe:
        probe_result = probe(home, runner)
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


if __name__ == "__main__" and len(sys.argv) > 1:
    sys.exit(main())
