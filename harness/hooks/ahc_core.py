"""ahc core (GoodQA goodqa#16034): queue request validation, live PR resolution, receipt verification.

Pure logic with an injectable `gh` runner `run(argv, timeout) -> (rc, stdout, stderr)`. No shell anywhere: every
child gets an argv list. Queue requests are untrusted input (spec D4): repo, PR, head and base are re-read from
GitHub and must match. Stdlib only.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
import time
from pathlib import Path

HEAD_RE = re.compile(r"[0-9a-f]{40}")
REPO_RE = re.compile(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}")
TICKET_RE = re.compile(r"GoodQA (?:[A-Za-z0-9_-]{1,40})?#\d{1,9}")
OWNER_RE = re.compile(r"[A-Za-z0-9_.:-]{3,80}")
PACKET_MAX_BYTES = 150_000
GH_TIMEOUT = 60


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
            "base": _full(req.get("base"), "base"), "packet": _packet_ok(req.get("packet"), config.get("work_roots", [])),
            "ticket": ticket, "owner": owner}


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


def submit(paths, config, req, now=None):
    """Validate and enqueue. Returns {"id", "duplicate"}. Raises Refused; writes nothing on refusal."""
    norm = validate(config, req)
    packet_sha = hashlib.sha256(Path(norm["packet"]).read_bytes()).hexdigest()
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
    if base != req["base"]:
        raise Refused(f"the PR base is {base[:12]}, not the submitted {req['base'][:12]}; resubmit")
    return {"head": head, "base": base, "base_ref": pr.get("baseRefName"), "cross_repo": bool(pr.get("isCrossRepository"))}


_HEADER = re.compile(r"^(Stage|Reviewed HEAD|Reviewed packet SHA-256):[ \t]*(\S+)[ \t]*$", re.M)
_VERDICT = re.compile(r"^(?:VERDICT|PR_RESULT):[ \t]*(PASS|BLOCK)\b", re.M)


def verify_receipt(rc, report_path, head, packet_path):
    """{"verdict": PASS|BLOCK|INVALID|ERROR, "reason"}. PASS only with exit 0, stage pr, the exact head and the
    raw-byte SHA-256 of the packet that was passed (spec AC-5, NEG-5)."""
    if rc != 0:
        return {"verdict": "ERROR", "reason": f"peer_review exited {rc}"}
    try:
        text = Path(report_path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {"verdict": "ERROR", "reason": "no report was written"}
    fields = {}
    for name, value in _HEADER.findall(text):
        fields.setdefault(name, value)
    packet_sha = hashlib.sha256(Path(packet_path).read_bytes()).hexdigest()
    if fields.get("Stage") != "pr":
        return {"verdict": "INVALID", "reason": "report stage is not pr"}
    if fields.get("Reviewed HEAD") != head:
        return {"verdict": "INVALID", "reason": "Reviewed HEAD does not match"}
    if fields.get("Reviewed packet SHA-256") != packet_sha:
        return {"verdict": "INVALID", "reason": "Reviewed packet SHA-256 does not match the packet bytes"}
    match = _VERDICT.search(text)
    if not match:
        return {"verdict": "INVALID", "reason": "no verdict line"}
    return {"verdict": match.group(1), "reason": ""}
