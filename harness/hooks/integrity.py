#!/usr/bin/env python3
"""Tamper evidence for the installed harness hooks (GoodQA goodqa#14543, holds guard B1). Stdlib only, Python 3.9+.

holds_guard.py stops ACCIDENTAL edits of the hooks and settings; it can not stop a deliberate one by the same Unix
user. This tool makes such a change visible: it hashes what must not change silently and mirrors the hashes OFF-HOST.

  integrity.py record [--mirror-dir DIR] [--no-goodqa] [--host-label L]
      sha256 of every tracked hook file (hooks_manifest.json "integrity_files" plus the manifest's hook scripts),
      holds.json, holds.state.json and the `hooks` object of settings.json ("settings-hooks"), written as one record
      {schema, host, at, digest, files} to every mirror: the ssh hosts of integrity_policy.json (dev2; T2 when listed)
      at <dir>/<host>.jsonl, append-only under flock, and a comment on the registered GoodQA ticket (hashes and a
      timestamp only). install.py runs it after a successful install; `holds.py lift` runs it after writing the state.
  integrity.py verify [--alert] [--json] [--mirror-dir DIR] [--host-label L]
      recompute and compare with the newest mirrored record of this host:
        MATCH         exit 0
        UNVERIFIABLE  exit 0, warning (no mirror reachable or no record yet): not a change
        CHANGED       exit 1, lists each key with expected and actual hashes (a holds.state.json change without a
                      record is a lift that was never recorded: "lifted-but-unrecorded")
      --alert emits transition-only alert events (one raise per key, a clear when it matches again) through deliver().

The ssh mirror runs a small inline program on the mirror host with a `--local` marker, so a mirror never hops on;
BatchMode, ConnectTimeout and a subprocess timeout bound every call. Detection limits (a user or agent who edits both
the files and every mirror, a change made and reverted between two verifies) are listed in docs/holds-guard.md.
"""
from __future__ import annotations

import argparse
import datetime
import fcntl
import hashlib
import json
import os
import re
import shlex
import socket
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCHEMA = 1
SOURCE = "harness-integrity"
COMMENT_TAG = "harness-integrity-record v1"
HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
DEFAULT_POLICY = {"mirrors": [{"kind": "ssh", "host": "dev2", "dir": "~/.agent-harness/integrity"}],
                  "local_hostnames": ["dev2"], "ssh_timeout_s": 8, "goodqa": {}}
MAX_MESSAGE, MAX_DETAIL = 512, 4096

# Runs on the mirror host: `python3 -c REMOTE --local append|latest DIR HOST`. Append-only, flock, 0700/0600.
REMOTE = r'''
import fcntl, json, os, sys
a = sys.argv[1:]
if len(a) != 4 or a[0] != "--local" or a[1] not in ("append", "latest"):
    sys.exit(64)
op, d, host = a[1], os.path.expanduser(a[2]), a[3]
if not host or "/" in host or host.startswith("."):
    sys.exit(64)
p = os.path.join(d, host + ".jsonl")
if op == "append":
    line = sys.stdin.read(65536).strip()
    rec = json.loads(line)
    if not isinstance(rec, dict) or rec.get("host") != host:
        sys.exit(65)
    os.makedirs(d, mode=0o700, exist_ok=True)
    fd = os.open(p, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        os.write(fd, (line + "\n").encode())
        os.fsync(fd)
    finally:
        os.close(fd)
    print("APPENDED")
else:
    best = None
    try:
        with open(p) as fh:
            for raw in fh:
                try:
                    rec = json.loads(raw)
                except ValueError:
                    continue
                if isinstance(rec, dict) and rec.get("host") == host:
                    best = rec
    except FileNotFoundError:
        pass
    print(json.dumps(best) if best else "NONE")
'''


class MirrorError(Exception):
    """A mirror could not be written or read (unreachable, refused, malformed)."""


def now_iso(precise: bool = False) -> str:
    now = datetime.datetime.now(datetime.timezone.utc)
    return (now if precise else now.replace(microsecond=0)).isoformat()


def short_host() -> str:
    return socket.gethostname().split(".")[0]


def load_json(path: Path, default=None):
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return default


def load_policy(hooks_dir: Path) -> dict:
    data = load_json(hooks_dir / "integrity_policy.json", {})
    policy = dict(DEFAULT_POLICY)
    if isinstance(data, dict):
        policy.update({k: v for k, v in data.items() if k in DEFAULT_POLICY})
    return policy


def sha256_file(path: Path):
    try:
        if path.is_symlink():
            return "symlink:" + hashlib.sha256(os.readlink(path).encode()).hexdigest()
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for block in iter(lambda: fh.read(1 << 20), b""):
                h.update(block)
        return h.hexdigest()
    except FileNotFoundError:
        return None
    except OSError as exc:
        return f"unreadable:{type(exc).__name__}"


def tracked_names(hooks_dir: Path) -> list[str]:
    """Hook files to hash: the manifest's integrity_files and every manifest hook script (pending ones hash to null
    until they ship). holds.json and holds.state.json have their own keys."""
    manifest = load_json(hooks_dir / "hooks_manifest.json", {}) or {}
    names = list(manifest.get("integrity_files", [])) + [r.get("script", "") for r in manifest.get("hooks", [])]
    names += ["integrity.py", "hooks_manifest.json", "integrity_policy.json", "holds_guard.py", "holds.py"]
    return sorted({n for n in names if n and "/" not in n and n not in ("holds.json", "holds.state.json")})


def settings_digest(settings: Path):
    data = load_json(settings)
    if not isinstance(data, dict):
        return None if not settings.exists() else "unreadable"
    return hashlib.sha256(json.dumps(data.get("hooks"), sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def snapshot(hooks_dir: Path, settings: Path) -> dict:
    files = {f"hooks:{n}": sha256_file(hooks_dir / n) for n in tracked_names(hooks_dir)}
    files["holds.json"] = sha256_file(hooks_dir / "holds.json")
    files["holds.state.json"] = sha256_file(hooks_dir / "holds.state.json")
    files["settings-hooks"] = settings_digest(settings)
    return files


def make_record(files: dict, host: str) -> dict:
    digest = hashlib.sha256(json.dumps(files, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {"schema": SCHEMA, "host": host, "at": now_iso(precise=True), "digest": digest, "files": files}


# ---------------------------------------------------------------- mirrors (injectable runner)

def _run(argv, stdin_text=None, timeout=30, run=None):
    run = run or subprocess.run  # resolved per call, so tests can replace subprocess.run
    try:
        return run(argv, input=stdin_text, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        raise MirrorError(f"{Path(argv[0]).name} could not run ({type(exc).__name__})") from None


def ssh_argv(mirror_host: str, op: str, directory: str, host: str, timeout: int) -> list[str]:
    if not HOST_RE.match(mirror_host) or not HOST_RE.match(host):
        raise MirrorError("invalid host name")
    remote = "python3 -c " + shlex.quote(REMOTE) + " --local " + " ".join(shlex.quote(x) for x in (op, directory, host))
    return ["ssh", "-o", "BatchMode=yes", "-o", f"ConnectTimeout={int(timeout)}", "--", mirror_host, remote]


def local_argv(op: str, directory: str, host: str) -> list[str]:
    return [sys.executable, "-I", "-S", "-c", REMOTE, "--local", op, directory, host]


def mirror_argv(mirror: dict, op: str, host: str, policy: dict, mirror_dir: str | None) -> list[str]:
    directory = mirror_dir or mirror.get("dir") or "~/.agent-harness/integrity"
    if mirror.get("host") in policy.get("local_hostnames", []) and short_host() == mirror.get("host"):
        return local_argv(op, directory, host)  # on the mirror host itself: no hop
    return ssh_argv(str(mirror.get("host", "")), op, directory, host, int(policy.get("ssh_timeout_s", 8)))


def ssh_append(mirror, record, policy, mirror_dir=None, run=None) -> str:
    r = _run(mirror_argv(mirror, "append", record["host"], policy, mirror_dir), json.dumps(record), 45, run)
    if r.returncode != 0 or "APPENDED" not in (r.stdout or ""):
        raise MirrorError(f"ssh {mirror.get('host')} append exit {r.returncode}")
    return "ok"


def ssh_latest(mirror, host, policy, mirror_dir=None, run=None):
    r = _run(mirror_argv(mirror, "latest", host, policy, mirror_dir), None, 45, run)
    if r.returncode != 0:
        raise MirrorError(f"ssh {mirror.get('host')} read exit {r.returncode}")
    out = (r.stdout or "").strip().splitlines()
    if not out or out[-1] == "NONE":
        return None
    try:
        rec = json.loads(out[-1])
    except ValueError:
        raise MirrorError(f"ssh {mirror.get('host')} returned a malformed record") from None
    return rec if valid_record(rec, host) else None


def valid_record(rec, host) -> bool:
    return (isinstance(rec, dict) and rec.get("schema") == SCHEMA and rec.get("host") == host
            and isinstance(rec.get("files"), dict) and isinstance(rec.get("at"), str))


def gq_argv(goodqa: dict, tool: str, args: dict, maxchars: int) -> list[str]:
    gq = os.path.expanduser(str(goodqa.get("gq", "~/.claude/goodqa-p0p1/gq.py")))
    return [sys.executable, "-I", gq, tool, json.dumps(args), str(maxchars)]


def goodqa_append(goodqa: dict, record: dict, run=None) -> str:
    if not goodqa.get("issue_id"):
        raise MirrorError("no GoodQA mirror ticket in integrity_policy.json")
    body = f"{COMMENT_TAG}\n{json.dumps(record, sort_keys=True)}"
    r = _run(gq_argv(goodqa, "comment_on_issue", {"issueId": goodqa["issue_id"], "body": body}, 2000), None, 90, run)
    if r.returncode != 0 or '"comment"' not in (r.stdout or ""):
        raise MirrorError(f"GoodQA comment exit {r.returncode}")
    return "ok"


def goodqa_latest(goodqa: dict, host: str, run=None):
    if not goodqa.get("issue_id"):
        raise MirrorError("no GoodQA mirror ticket in integrity_policy.json")
    r = _run(gq_argv(goodqa, "get_issue_comments", {"issueId": goodqa["issue_id"]}, 8_000_000), None, 90, run)
    if r.returncode != 0:
        raise MirrorError(f"GoodQA read exit {r.returncode}")
    try:
        comments = json.loads(r.stdout).get("comments", [])
    except (ValueError, AttributeError):
        raise MirrorError("GoodQA returned malformed comments") from None
    best = None
    for c in comments if isinstance(comments, list) else []:
        body = str(c.get("body", "")) if isinstance(c, dict) else ""
        if not body.startswith(COMMENT_TAG + "\n"):
            continue
        try:
            rec = json.loads(body.split("\n", 1)[1])
        except ValueError:
            continue
        if valid_record(rec, host) and (best is None or rec["at"] >= best["at"]):
            best = rec
    return best


def record(hooks_dir: Path, settings: Path, mirror_dir=None, goodqa=True, host=None, run=None) -> tuple[dict, dict]:
    policy = load_policy(hooks_dir)
    rec = make_record(snapshot(hooks_dir, settings), host or short_host())
    results = {}
    for m in policy["mirrors"]:
        try:
            results[f"ssh:{m.get('host')}"] = ssh_append(m, rec, policy, mirror_dir, run)
        except MirrorError as exc:
            results[f"ssh:{m.get('host')}"] = f"FAILED ({exc})"
    if goodqa:
        try:
            results["goodqa"] = goodqa_append(policy.get("goodqa") or {}, rec, run)
        except MirrorError as exc:
            results["goodqa"] = f"FAILED ({exc})"
    return rec, results


def latest(hooks_dir: Path, host: str, mirror_dir=None, goodqa=True, run=None) -> tuple[dict | None, str, list]:
    """(newest record of host across reachable mirrors, the mirror it came from, [errors])."""
    policy = load_policy(hooks_dir)
    found, errors = [], []
    for m in policy["mirrors"]:
        try:
            rec = ssh_latest(m, host, policy, mirror_dir, run)
            if rec:
                found.append((rec, str(m.get("host"))))
        except MirrorError as exc:
            errors.append(str(exc))
    if goodqa:
        try:
            rec = goodqa_latest(policy.get("goodqa") or {}, host, run)
            if rec:
                found.append((rec, "goodqa"))
        except MirrorError as exc:
            errors.append(str(exc))
    if not found:
        return None, "", errors
    rec, src = max(found, key=lambda x: x[0]["at"])
    return rec, src, errors


def compare(expected: dict, actual: dict) -> list[dict]:
    out = []
    for key in sorted(set(expected) | set(actual)):
        if expected.get(key) != actual.get(key):
            item = {"key": key, "expected": expected.get(key), "actual": actual.get(key)}
            if key == "holds.state.json":
                item["note"] = "lifted-but-unrecorded: the lift state changed without an integrity record"
            out.append(item)
    return out


def verify(hooks_dir: Path, settings: Path, mirror_dir=None, goodqa=True, host=None, run=None) -> dict:
    host = host or short_host()
    actual = snapshot(hooks_dir, settings)
    rec, src, errors = latest(hooks_dir, host, mirror_dir, goodqa, run)
    if rec is None:
        why = "; ".join(errors) if errors else "no record for this host on any mirror (run integrity.py record)"
        return {"status": "UNVERIFIABLE", "host": host, "reason": why, "changed": [], "mirror": ""}
    changed = compare(rec["files"], actual)
    return {"status": "CHANGED" if changed else "MATCH", "host": host, "mirror": src, "recorded_at": rec["at"],
            "changed": changed, "errors": errors}


# ---------------------------------------------------------------- alerts (G10 / ops-watch)

def safe_text(text: str, limit: int) -> str:
    text = re.sub(r"[\x00-\x1f\x7f]+", " ", str(text))
    return text[:limit]


def alert_event(event: str, severity: str, key: str, message: str, detail: dict, host: str) -> dict:
    detail_text = json.dumps(detail, sort_keys=True)
    if len(detail_text.encode()) > MAX_DETAIL:
        detail = {"truncated": True, "keys": [c.get("key") for c in detail.get("changed", [])][:40],
                  "mirror": detail.get("mirror", "")}
    return {"schema": 1, "at": now_iso(), "host": host, "source": SOURCE, "event": event, "severity": severity,
            "key": key, "message": safe_text(message, MAX_MESSAGE), "detail": detail}


def agent_home() -> Path:
    return Path(os.path.expanduser("~")) / ".agent-harness"


def deliver(event: dict, hooks_dir: Path = HERE, home: Path | None = None) -> str:
    """THE delivery function (one place to change). The ops-watch writer when installed (ops_watch.emit into the
    ~/.agent-harness/state/alerts.jsonl ring); until then the deadman reserve file ~/.agent-harness/reserve/
    alerts-in.jsonl (0700 dir, 0600 file, append under flock). The ring is never written directly: its slots belong
    to its writer. Errors raise OSError for the caller to surface."""
    if (hooks_dir / "ops_watch.py").is_file():
        if str(hooks_dir) not in sys.path:
            sys.path.insert(0, str(hooks_dir))
        import ops_watch  # noqa: E402 - provided by the ops-watch owner (goodqa#14591)
        ops_watch.emit(event, home)
        return "ops_watch"
    base = (home or agent_home()) / "reserve"
    base.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(base, 0o700)
    fd = os.open(base / "alerts-in.jsonl", os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        os.write(fd, (json.dumps(event, sort_keys=True) + "\n").encode())
        os.fsync(fd)
    finally:
        os.close(fd)
    return "reserve"


SEVERITY_RANK = {"info": 0, "warning": 1, "high": 2, "critical": 3}


def alert(result: dict, hooks_dir: Path = HERE, home: Path | None = None, deliver_fn=None) -> list[dict]:
    """Transition-only events for a verify result, against this host's own alert state (so an hourly run does not
    repeat): raise per changed key (re-raise only when severity rises), clear for keys that match again."""
    deliver_fn = deliver_fn or (lambda ev: deliver(ev, hooks_dir, home))
    state_path = (home or agent_home()) / "integrity" / "alert-state.json"
    state = load_json(state_path, {}) or {}
    active = state.get("active", {}) if isinstance(state.get("active"), dict) else {}
    host, emitted, want = result["host"], [], {}
    if result["status"] == "CHANGED":
        for c in result["changed"]:
            want[c["key"]] = ("high", c)
    elif result["status"] == "UNVERIFIABLE":
        want["mirror"] = ("warning", {"reason": result.get("reason", "")})
    for key, (sev, info) in want.items():
        prev = active.get(key)
        if prev and SEVERITY_RANK.get(prev, 0) >= SEVERITY_RANK[sev]:
            continue
        if key == "mirror":
            msg = f"integrity mirrors unreachable on {host}: hashes not verifiable"
            detail = {"reason": safe_text(info["reason"], 600)}
        else:
            msg = f"{key} on {host} differs from the off-host integrity record; inspect it and reinstall from a reviewed branch"
            detail = {"changed": [info], "mirror": result.get("mirror", ""), "recorded_at": result.get("recorded_at", "")}
        ev = alert_event("raise", sev, key, msg, detail, host)
        deliver_fn(ev)
        emitted.append(ev)
        active[key] = sev
    if result["status"] != "UNVERIFIABLE":
        for key in [k for k in active if k not in want]:
            ev = alert_event("clear", "info", key, "cleared", {"mirror": result.get("mirror", "")}, host)
            deliver_fn(ev)
            emitted.append(ev)
            del active[key]
    state_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = state_path.with_name(f"{state_path.name}.{os.getpid()}.tmp")
    tmp.write_text(json.dumps({"active": active}, sort_keys=True))
    os.chmod(tmp, 0o600)
    os.replace(tmp, state_path)
    return emitted


# ---------------------------------------------------------------- CLI

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--hooks-dir", default=str(HERE))
    ap.add_argument("--settings", default=None, help="default: <hooks-dir>/../settings.json")
    ap.add_argument("--mirror-dir", default=None, help="mirror directory on the ssh hosts (tests: a /tmp scratch dir)")
    ap.add_argument("--no-goodqa", action="store_true", help="skip the GoodQA mirror")
    ap.add_argument("--host-label", default=None, help="record/verify under this label instead of the host name")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("record")
    v = sub.add_parser("verify")
    v.add_argument("--alert", action="store_true")
    v.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    hooks_dir = Path(a.hooks_dir).expanduser().resolve()
    settings = Path(a.settings).expanduser() if a.settings else hooks_dir.parent / "settings.json"
    if a.host_label and not HOST_RE.match(a.host_label):
        print("integrity: invalid --host-label", file=sys.stderr)
        return 2
    if a.cmd == "record":
        rec, results = record(hooks_dir, settings, a.mirror_dir, not a.no_goodqa, a.host_label)
        ok = [k for k, v in results.items() if v == "ok"]
        print(" ".join(f"{k}={v}" for k, v in results.items()))
        print(f"RECORDED host={rec['host']} at={rec['at']} digest={rec['digest'][:16]} mirrors_ok={len(ok)}/{len(results)}")
        return 0 if ok else 1
    result = verify(hooks_dir, settings, a.mirror_dir, not a.no_goodqa, a.host_label)
    rc = 1 if result["status"] == "CHANGED" else 0
    if a.alert:
        try:
            alert(result, hooks_dir)
        except OSError as exc:
            print(f"integrity: alert delivery failed: {type(exc).__name__}: {exc}", file=sys.stderr)
            rc = rc or 3
    if a.json:
        print(json.dumps(result, indent=1, sort_keys=True))
    else:
        print(f"{result['status']} host={result['host']} mirror={result.get('mirror') or '-'}")
        for c in result["changed"]:
            print(f"  {c['key']}: expected {c['expected']} actual {c['actual']}" + (f" ({c['note']})" if c.get("note") else ""))
        if result["status"] == "UNVERIFIABLE":
            print(f"  warning: {result['reason']}", file=sys.stderr)
    return rc


if __name__ == "__main__":
    sys.exit(main())
