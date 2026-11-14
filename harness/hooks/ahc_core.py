"""ahc core (GoodQA goodqa#16034): queue request validation, live PR resolution, receipt verification.

Pure logic with an injectable `gh` runner `run(argv, timeout) -> (rc, stdout, stderr)`. No shell anywhere: every
child gets an argv list. Queue requests are untrusted input (spec D4): repo, PR, head and base are re-read from
GitHub and must match. Stdlib only.
"""
from __future__ import annotations

import errno
import hashlib
import json
import math
import os
import re
import signal
import stat
import subprocess
import tempfile
import time
from pathlib import Path

HEAD_RE = re.compile(r"[0-9a-f]{40}")
REPO_RE = re.compile(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}")
TICKET_RE = re.compile(r"GoodQA (?:[A-Za-z0-9_-]{1,40})?#\d{1,9}")
OWNER_RE = re.compile(r"[A-Za-z0-9_.:-]{3,80}")
PACKET_MAX_BYTES = 150_000
GH_TIMEOUT = 60  # = TIMEOUTS["gh"]


TIMEOUTS = {"gh": 60, "git": 900, "ah": 60, "review": 1440}   # spec D21; leases are timeout + 60 s
TIMEOUT_RC = 124


def run_argv(argv, timeout, cwd=None, env=None):
    """Run one child (argv list, never a shell) in its own process group. On timeout the whole group gets SIGTERM,
    then SIGKILL after 5 s, so a hung gh or git cannot leave helpers behind. Returns (rc, stdout, stderr)."""
    try:
        proc = subprocess.Popen(list(argv), cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True, start_new_session=True)
    except OSError as error:
        return 127, "", str(error)
    try:
        out, err = proc.communicate(timeout=timeout)
        return proc.returncode, out, err
    except subprocess.TimeoutExpired:
        gone = _kill_group(proc)
        try:
            out, err = proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            out, err = "", ""
        status = "process group killed" if gone else "process group cleanup incomplete"
        return TIMEOUT_RC, out or "", (err or "") + "\ntimeout after %ss; %s" % (timeout, status)


def _group_alive(pgid):
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _kill_group(proc, grace=5.0):
    """Terminate the whole process group and supervise it until it is gone, independent of the leader's exit
    (code-inspection r1 F2). Returns True only when no member of the group remains."""
    pgid = proc.pid
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(pgid, sig)
        except ProcessLookupError:
            proc.poll()
            return True
        except PermissionError:
            return False
        deadline = time.monotonic() + grace
        while time.monotonic() < deadline:
            proc.poll()  # reap the leader so a zombie does not keep the group id alive
            if not _group_alive(pgid):
                return True
            time.sleep(0.05)
    proc.poll()
    return not _group_alive(pgid)


class Refused(ValueError):
    """The request can never succeed as submitted; tell the owner why."""


class Stale(Refused):
    """The live PR head moved after submission; the owner must resubmit at the new head."""


class Retry(RuntimeError):
    """A transient failure (gh, network); retry later with backoff. Never treated as PASS."""


class Paths:
    def __init__(self, home=None):
        self.home = Path(home or Path.home())
        self.root = self.home / ".agent-harness" / "coordinator"
        self.queue = self.root / "queue"
        self.items = self.root / "items"
        self.inbox = self.root / "inbox"
        self.clones = self.root / "clones"
        self.reports = self.root / "reports"
        self.digest = self.root / "digest.md"

    def ensure(self):
        for path in (self.root, self.queue, self.items, self.inbox, self.clones, self.reports):
            path.mkdir(parents=True, exist_ok=True, mode=0o700)


REPORT_MAX_BYTES = 2_000_000
CONFIG_MAX_BYTES = 1_000_000


class Unreadable(Refused):
    """read_regular refused a file. `kind` is absent, symlink, non-regular, oversize or error."""
    def __init__(self, kind, message):
        super().__init__(message)
        self.kind = kind


_WALK_DIR_FLAGS = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)


def read_regular_resolved(real_path, cap):
    """read_regular on an already-resolved absolute path (the exact path the caller's containment check approved),
    opened one component at a time with O_DIRECTORY|O_NOFOLLOW from the filesystem root (r4 F1). It deliberately does
    NOT resolve again: a directory swapped for a symlink after the check makes the open fail instead of being followed,
    so the file read is the file whose path was checked."""
    real = str(real_path)
    if not os.path.isabs(real):
        raise Unreadable("error", "path must be absolute and already resolved")
    parts = [p for p in real.split(os.sep) if p]
    if not parts:
        raise Unreadable("non-regular", "not a regular file")
    try:
        fd = os.open(os.sep, _WALK_DIR_FLAGS)
    except OSError as error:
        raise Unreadable("error", "root cannot be opened: %s" % type(error).__name__) from None
    try:
        for part in parts[:-1]:
            try:
                nxt = os.open(part, _WALK_DIR_FLAGS, dir_fd=fd)
            except OSError as error:
                kind = "symlink" if error.errno in (errno.ELOOP, errno.ENOTDIR) else "error"
                raise Unreadable(kind, "a directory on the path changed or is a symlink") from None
            os.close(fd)
            fd = nxt
        return read_regular(parts[-1], cap, dir_fd=fd)
    finally:
        os.close(fd)


def read_regular(path, cap, dir_fd=None):
    """The only way ahc reads a file another actor can write or replace (r3 F5/F6 class fix). It opens with
    O_NOFOLLOW|O_NONBLOCK so neither a symlink nor a FIFO or device can redirect or block it, checks the OPENED
    descriptor with fstat (regular file, size <= cap) and reads at most cap+1 bytes. Every failure is Unreadable;
    it never blocks and never follows a link."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(str(path), flags, dir_fd=dir_fd) if dir_fd is not None else os.open(str(path), flags)
    except FileNotFoundError:
        raise Unreadable("absent", "file does not exist") from None
    except OSError as error:
        if error.errno == errno.ELOOP:
            raise Unreadable("symlink", "file is a symlink") from None
        raise Unreadable("error", "file cannot be opened: %s" % type(error).__name__) from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise Unreadable("non-regular", "not a regular file")
        if info.st_size > cap:
            raise Unreadable("oversize", "file is %d bytes; the cap is %d" % (info.st_size, cap))
        chunks, total = [], 0
        while total <= cap:
            chunk = os.read(fd, min(65536, cap + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
    except OSError as error:
        raise Unreadable("error", "file cannot be read: %s" % type(error).__name__) from None
    finally:
        os.close(fd)
    data = b"".join(chunks)
    if len(data) > cap:
        raise Unreadable("oversize", "file grew past the cap of %d bytes while reading" % cap)
    return data


def _full(value, field):
    if not isinstance(value, str) or not HEAD_RE.fullmatch(value):
        raise Refused(f"{field} must be the full 40-character lowercase commit SHA")
    return value


def _packet_ok(path_value, roots):
    """The packet must be a regular, non-symlinked file inside a work root, at most PACKET_MAX_BYTES."""
    if not isinstance(path_value, str) or "\x00" in path_value or not os.path.isabs(path_value):
        raise Refused("packet must be an absolute path")
    path = Path(path_value)
    try:
        info = os.lstat(path)
    except OSError:
        raise Refused("packet does not exist") from None
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise Refused("packet must be a regular file, not a symlink")
    real = os.path.realpath(path)
    if not any(real == r or real.startswith(r.rstrip(os.sep) + os.sep) for r in map(os.path.realpath, roots)):
        raise Refused("packet must be inside a work root")
    if info.st_size > PACKET_MAX_BYTES:
        raise Refused(f"packet is {info.st_size} bytes; the cap is {PACKET_MAX_BYTES}")
    return real


def validate(config, req):
    """A normalized request, or Refused. `config` holds `repos` (allowlist) and `work_roots`."""
    norm = _fields(config, req)
    norm["packet"] = _packet_ok(req.get("packet"), config.get("work_roots", []))
    return norm


def _fields(config, req):
    if not isinstance(req, dict):
        raise Refused("request must be a JSON object")
    repo = req.get("repo")
    if not isinstance(repo, str) or not REPO_RE.fullmatch(repo) or repo.lower() not in {
            r.lower() for r in config.get("repos", [])}:
        raise Refused("repo is not on the coordinator allowlist")
    pr = req.get("pr")
    if type(pr) is not int or pr <= 0:
        raise Refused("pr must be a positive integer")
    ticket, owner = req.get("ticket"), req.get("owner")
    if not isinstance(ticket, str) or not TICKET_RE.fullmatch(ticket):
        raise Refused("ticket must look like 'GoodQA project#123'")
    if not isinstance(owner, str) or not OWNER_RE.fullmatch(owner):
        raise Refused("owner must be a plain agent id")
    return {"repo": repo.lower(), "pr": pr, "head": _full(req.get("head"), "head"),
            "base": _full(req.get("base"), "base"), "ticket": ticket, "owner": owner}


SHA256_RE = re.compile(r"[0-9a-f]{64}")
CLOCK_SKEW = 300


def _inside(path_value, roots):
    real = os.path.realpath(path_value)
    return any(real == r or real.startswith(r.rstrip(os.sep) + os.sep) for r in map(os.path.realpath, roots))


def validate_queued(config, rec, now):
    """Re-validate a queue file at ingest (code-inspection r2 F5): the queue directory is not trusted just because
    submit wrote it. Same field rules as submit; the packet is checked lexically (its bytes are rechecked before
    review, and a vanished packet is an owner notice, not a quarantine); the id must be the recomputed item id."""
    if not isinstance(rec, dict):
        raise Refused("queue record must be a JSON object")
    norm = _fields(config, rec)
    packet = rec.get("packet")
    if not isinstance(packet, str) or "\x00" in packet or not os.path.isabs(packet) or not _inside(
            packet, config.get("work_roots", [])):
        raise Refused("queue record packet is not an absolute path inside a work root")
    sha = rec.get("packet_sha256")
    if not isinstance(sha, str) or not SHA256_RE.fullmatch(sha):
        raise Refused("queue record packet_sha256 must be 64 lowercase hex characters")
    submitted = rec.get("submitted")
    if type(submitted) not in (int, float) or not math.isfinite(submitted) or not 0 < submitted <= now + CLOCK_SKEW:
        raise Refused("queue record submitted time is missing, non-finite or in the future")
    norm.update(packet=packet, packet_sha256=sha, submitted=float(submitted))
    if rec.get("id") != item_id(norm, sha):
        raise Refused("queue record id does not match its content")
    norm["id"] = rec["id"]
    return norm


def inbox_path(paths, owner, name, resolve=True):
    """The owner's inbox file, or Refused if it would leave the inbox directory (F5 defense in depth).
    resolve=False does only the lexical checks; it is for building a notice inside a ledger transaction, where the
    filesystem state must not be able to raise. The write itself is fd-based and never follows a symlink."""
    if not isinstance(owner, str) or not OWNER_RE.fullmatch(owner) or owner in (".", ".."):
        raise Refused("owner is not a plain agent id")
    if not isinstance(name, str) or "/" in name or "\x00" in name or name in ("", ".", ".."):
        raise Refused("inbox file name is not plain")
    path = paths.inbox / owner / name
    if not resolve:
        return path
    root = os.path.realpath(str(paths.inbox))
    real = os.path.realpath(str(path))  # resolves a symlinked owner directory or file before the check
    if os.path.dirname(os.path.dirname(real)) != root or not real.startswith(root + os.sep):
        raise Refused("inbox path escapes the inbox directory")
    return path


def item_id(req, packet_sha):
    """Deterministic id: the same repo, PR, head and packet bytes is the same item (one review attempt, spec D7)."""
    key = f"{req['repo']}|{req['pr']}|{req['head']}|{packet_sha}"
    return "ahc-" + hashlib.sha256(key.encode()).hexdigest()[:20]


def _atomic_write(path, data):
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".tmp-")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.link(tmp, path)  # fails if the item already exists: first writer wins, no overwrite
    finally:
        os.unlink(tmp)


def submit(paths, config, req, now=None, data=None):
    """Validate and enqueue. Returns {"id", "duplicate"}. Raises Refused; writes nothing on refusal. `data` is the
    packet bytes the caller already read (and linted); when given they are the bytes hashed."""
    norm = validate(config, req)
    if data is None:
        data = read_regular(norm["packet"], PACKET_MAX_BYTES)
    packet_sha = hashlib.sha256(data).hexdigest()
    norm.update(packet_sha256=packet_sha, submitted=now or time.time())
    iid = item_id(norm, packet_sha)
    norm["id"] = iid
    paths.ensure()
    target = paths.queue / (iid + ".json")
    try:
        _atomic_write(target, json.dumps(norm, sort_keys=True))
    except FileExistsError:
        return {"id": iid, "duplicate": True}
    return {"id": iid, "duplicate": False}


def resolve(req, run):
    """Re-read the PR from GitHub. Returns the live facts, or raises Refused / Stale / Retry (spec AC-2, NEG-2)."""
    argv = ["gh", "pr", "view", str(req["pr"]), "-R", req["repo"], "--json",
            "number,state,headRefOid,baseRefOid,baseRefName,isCrossRepository"]
    rc, out, _err = run(argv, GH_TIMEOUT)
    if rc != 0:
        raise Retry("gh pr view failed")
    try:
        pr = json.loads(out)
    except ValueError:
        raise Retry("gh pr view returned malformed JSON") from None
    if not isinstance(pr, dict) or pr.get("number") != req["pr"]:
        raise Retry("gh pr view returned a different PR")
    if pr.get("state") != "OPEN":
        raise Refused(f"PR is {str(pr.get('state')).lower()}, not open")
    head, base = pr.get("headRefOid"), pr.get("baseRefOid")
    if not (isinstance(head, str) and HEAD_RE.fullmatch(head) and isinstance(base, str) and HEAD_RE.fullmatch(base)):
        raise Retry("gh pr view returned no full head or base SHA")
    if head != req["head"]:
        raise Stale(f"the PR head is now {head[:12]}; resubmit at the new head with a fresh packet")
    facts = {"head": head, "base": base, "base_ref": pr.get("baseRefName"),
             "cross_repo": bool(pr.get("isCrossRepository"))}
    if base != req["base"]:
        # The base branch advanced after submit (spec AC-2 repair, D4 ruling): the live base wins and is recorded.
        facts["base_repaired_from"] = f"submitted base {req['base'][:12]} replaced by live base {base[:12]}"
    return facts


_REQUIRED = ("Stage", "Reviewed HEAD", "Reviewed packet SHA-256")
_HEADER_LINE = re.compile(r"^([A-Za-z][A-Za-z0-9 -]{0,60}):[ \t]*(.*?)[ \t]*$")
_PASS_LINE = re.compile(r"VERDICT: (PASS-WITH-TICKETS|PASS)")
_BLOCK_LINE = re.compile(r"VERDICT: BLOCK(?![A-Za-z0-9_-]).*")


def _parse_report(text):
    """(headers, verdict line) or raise ValueError. The header block is every line before the first blank line;
    each required header must appear there exactly once. The authoritative verdict is the first non-blank line after
    that block, as peer_review writes it; nothing later in the body (quotes, examples) counts (r1 F4)."""
    head, sep, body = text.replace("\r\n", "\n").partition("\n\n")
    if not sep:
        raise ValueError("report has no header block")
    fields = {}
    for line in head.split("\n"):
        match = _HEADER_LINE.match(line)
        if not match:
            continue
        name, value = match.group(1), match.group(2)
        if name in _REQUIRED:
            if name in fields:
                raise ValueError("duplicate %s header" % name)
            fields[name] = value
    missing = [name for name in _REQUIRED if name not in fields]
    if missing:
        raise ValueError("missing header(s): " + ", ".join(missing))
    first = next((line.strip() for line in body.split("\n") if line.strip()), "")
    return fields, first


EXIT_PASS, EXIT_ERROR, EXIT_BLOCK, EXIT_ADVISORY = 0, 2, 3, 4   # peer_review.py main()


def verify_receipt(rc, report_path, head, packet_path):
    """{"verdict": PASS|PASS-WITH-TICKETS|BLOCK|ADVISORY|INVALID|ERROR, "reason"} (spec AC-5, NEG-5).

    PASS needs exit 0, stage pr, the exact head, the raw-byte SHA-256 of the packet that was passed and an exact
    `VERDICT: PASS`. PASS-WITH-TICKETS is its own non-pass verdict. A BLOCK verdict with exit 0 or 3 is BLOCK (the
    safe direction). Exit 4 is advisory, never a pass; exit 2 or anything else is ERROR even when a report exists,
    because peer_review can leave a digest-bound historical report after a failed final publication check."""
    if rc == EXIT_ADVISORY:
        return {"verdict": "ADVISORY", "reason": "peer_review published an advisory opinion, not a signoff"}
    if rc not in (EXIT_PASS, EXIT_BLOCK):
        return {"verdict": "ERROR", "reason": f"peer_review exited {rc}"}
    try:
        text = read_regular(report_path, REPORT_MAX_BYTES).decode("utf-8", errors="replace")
    except Unreadable as error:
        if error.kind == "absent":
            return {"verdict": "ERROR", "reason": "no report was written"}
        return {"verdict": "INVALID", "reason": "report unreadable: %s" % error}
    try:
        fields, first = _parse_report(text)
    except ValueError as error:
        return {"verdict": "INVALID", "reason": str(error)}
    try:
        packet_sha = hashlib.sha256(read_regular(packet_path, PACKET_MAX_BYTES)).hexdigest()
    except Unreadable as error:
        return {"verdict": "INVALID", "reason": "reviewed packet unreadable: %s" % error}
    if fields.get("Stage") != "pr":
        return {"verdict": "INVALID", "reason": "report stage is not pr"}
    if fields.get("Reviewed HEAD") != head:
        return {"verdict": "INVALID", "reason": "Reviewed HEAD does not match"}
    if fields.get("Reviewed packet SHA-256") != packet_sha:
        return {"verdict": "INVALID", "reason": "Reviewed packet SHA-256 does not match the packet bytes"}
    if _BLOCK_LINE.fullmatch(first):
        return {"verdict": "BLOCK", "reason": ""}
    match = _PASS_LINE.fullmatch(first)
    if not match:
        return {"verdict": "INVALID", "reason": "the first line after the header block is not a supported verdict"}
    verdict = match.group(1)
    if rc != EXIT_PASS:
        return {"verdict": "ERROR", "reason": f"verdict {verdict} with exit {rc}"}
    return {"verdict": verdict, "reason": ""}
