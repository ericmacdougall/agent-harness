#!/usr/bin/env python3
"""Spec-driven ticket flow: spec documents, spec reviews, evidence, click-tests, sign-off, done gate.

The ticket is the record of truth. Every write posts one comment holding a readable summary and a
fenced ```harness-spec-record``` JSON block, with its files attached. The done gate trusts an attached
file only when GoodQA lists it as completed, on that comment, with the server-computed sha256 the
record names. Threat model: careless or hurried agents, not adversarial ones (an agent can edit these
hooks). Every check that rests on a name nobody verified is printed under "Self-attested".

Exit codes: 0 ok/READY, 2 refused or missing items, 3 usage or spec error, 4 ticket system
unreachable (fail closed), 5 the tracker refused the done transition.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import time
import unicodedata
import urllib.parse
import uuid
from datetime import datetime, timezone
from pathlib import Path

import ticket_adapters as ta

HERE = Path(__file__).resolve().parent
POLICY_FILE = HERE / "spec_policy.json"
TEMPLATE_FILE = HERE / "spec_template.md"
RECORD_FENCE = "harness-spec-record"
RECORD_BLOCK = re.compile(r"```" + RECORD_FENCE + r"\n(.*?)\n```", re.S)
NAMESPACE = uuid.UUID("8f2a4f2e-3c1b-4b7e-9d55-6a1f0c2b7e10")
KINDS = ("spec", "evidence", "click_test", "signoff")
ROLES = ("adversarial", "acceptance")
LOGGED_AGENT_TYPES = ("task-owner", "click-tester", "fixer", "red-team")
OPEN_STATUSES = {"triage", "backlog", "todo", "in_progress", "in_review", "on_dev", "verified_on_dev",
                 "on_staging", "verified_on_staging", "on_production"}
REASON_STATUSES = {"wont_fix", "duplicate"}
SPEC_STATUSES = {"done"}
TOOL_PATTERN = re.compile(r"^mcp__.*goodqa.*__(close_issue_done|close_issue_wont_fix|update_issue|"
                          r"bulk_update_issues|archive_issue|reassign_issue|call_api)$", re.IGNORECASE)
UUID = r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
MEDIA = {".png": ("image/png", (b"\x89PNG",)), ".jpg": ("image/jpeg", (b"\xff\xd8",)),
         ".jpeg": ("image/jpeg", (b"\xff\xd8",)), ".gif": ("image/gif", (b"GIF8",)),
         ".webm": ("video/webm", (b"\x1a\x45\xdf\xa3",)), ".mp4": ("video/mp4", ())}
EXIT_OK, EXIT_MISSING, EXIT_USAGE, EXIT_UNREACHABLE, EXIT_TRACKER = 0, 2, 3, 4, 5

try:  # same id transform the WAL writer uses for agent ids and file names
    from wal import safe_id
except ImportError:  # pragma: no cover - Codex flavour without wal.safe_id
    def safe_id(value):
        return re.sub(r"[^A-Za-z0-9._-]", "_", str(value or "unknown"))


class SpecError(Exception):
    def __init__(self, message, code=EXIT_MISSING):
        super().__init__(message)
        self.code = code


# --------------------------------------------------------------------------- configuration

def load_spec_policy(path: Path = POLICY_FILE) -> dict:
    with open(path, encoding="utf-8") as handle:
        policy = json.load(handle)
    if not isinstance(policy, dict) or policy.get("schema") != 1:
        raise ValueError(f"{path} is not a schema 1 spec policy")
    for key in ("mode", "plan_ticket_gate"):
        if policy.get(key) not in ("off", "warn", "enforce"):
            raise ValueError(f"{path}: {key} must be off, warn or enforce")
    if not isinstance(policy.get("projects", {}), dict) or not isinstance(policy.get("enforced_projects", []), list):
        raise ValueError(f"{path}: projects must be an object and enforced_projects a list")
    return policy


def ticket_config(spec_policy: dict):
    import commit_policy
    policy = commit_policy.load_policy()
    name = spec_policy.get("ticket_system", "goodqa")
    config = policy["ticket_systems"].get(name)
    if not isinstance(config, dict):
        raise ValueError(f"commit_policy.json has no ticket system {name!r}")
    return commit_policy, policy, config


def make_adapter(config: dict, spec_policy: dict, project: str | None, deadline: float):
    merged = ta.project_config(config, project, spec_policy.get("projects") or {})
    merged = dict(merged, upload_host_suffixes=spec_policy.get("upload_host_suffixes"))
    return ta.adapter_for(merged, deadline=deadline)


def enforced_ids(spec_policy: dict) -> set:
    found = set()
    for item in spec_policy.get("enforced_projects") or []:
        if isinstance(item, dict) and item.get("project_id"):
            found.add(str(item["project_id"]).lower())
        elif isinstance(item, str):
            route = (spec_policy.get("projects") or {}).get(item.lower()) or {}
            if route.get("project_id"):
                found.add(str(route["project_id"]).lower())
    return found


# --------------------------------------------------------------------------- tickets and identities

TICKET_LINE = re.compile(r"(?im)^[ \t]*Ticket:[ \t]*(.+?)[ \t]*$")


def parse_ticket_ref(text: str, config: dict):
    """One ref; the project slug is required (a bare `GoodQA #N` never resolves to a default)."""
    match = re.search(config["ref_pattern"], text, re.I)
    if not match:
        raise SpecError(f"not a ticket reference: {text.strip()[:80]!r}; write e.g. GoodQA harness#168", EXIT_USAGE)
    project = match.groupdict().get("project")
    if not project:
        raise SpecError("name the project in the ticket reference, e.g. GoodQA harness#168 "
                        "(a bare GoodQA #N is not accepted)", EXIT_USAGE)
    return project.lower(), int(match.group("number"))


def norm_identity(value: str) -> str:
    return " ".join(unicodedata.normalize("NFC", str(value or "")).casefold().split())


def identity_key(kind: str, value: str) -> str:
    kind = {"helper": "model"}.get(kind, kind)
    return f"{kind}:{norm_identity(value)}"


def parse_author(value: str) -> str:
    """`agent:<id> (model)` / `human:<name>` / `model:<name>` -> identity key."""
    match = re.match(r"^\s*(agent|human|model)\s*:\s*([^()]+?)\s*(?:\(.*\))?\s*$", value or "")
    if not match:
        raise SpecError("Author must look like agent:<agent id> (model), human:<name> or model:<name>", EXIT_USAGE)
    kind, name = match.group(1), match.group(2)
    return identity_key(kind, safe_id(name) if kind == "agent" else name)


# --------------------------------------------------------------------------- spec documents

def normalize_text(text: str) -> str:
    text = unicodedata.normalize("NFC", text).replace("\r\n", "\n").replace("\r", "\n")
    return "\n".join(line.rstrip() for line in text.split("\n")).strip("\n") + "\n"


REVIEWS_HEADING = re.compile(r"(?m)^## Reviews[ \t]*$")


def spec_core(text: str) -> str:
    text = normalize_text(text)
    match = REVIEWS_HEADING.search(text)
    core = text[:match.start()] if match else text
    return core.rstrip("\n") + "\n"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def core_sha(text: str) -> str:
    return sha256_bytes(spec_core(text).encode("utf-8"))


def parse_spec(text: str) -> dict:
    core = spec_core(text)
    header, sections, current = {}, {}, None
    title = None
    for line in core.split("\n"):
        heading = re.match(r"^## (.+?)\s*$", line)
        if heading:
            current = heading.group(1)
            sections.setdefault(current, [])
            continue
        if current is None:
            if line.startswith("# ") and title is None:
                title = line[2:].strip()
            field = re.match(r"^(Ticket|Author|Click-test|Sign-off):\s*(.*)$", line)
            if field:
                header[field.group(1)] = field.group(2).strip()
        else:
            sections[current].append(line)
    criteria, negatives, stray = [], [], []
    for line in sections.get("Acceptance criteria", []):
        match = re.match(r"^- (AC-\d+):\s*(.+)$", line)
        if match:
            criteria.append((match.group(1), match.group(2)))
        elif line.startswith("- "):
            stray.append(line)
    for line in sections.get("Negative cases", []):
        match = re.match(r"^- (NEG-\d+)\s*\(([^)]*)\):\s*(.+)$", line)
        if match:
            refs = [item.strip() for item in match.group(2).split(",") if item.strip()]
            negatives.append((match.group(1), refs, match.group(3)))
        elif line.startswith("- "):
            stray.append(line)
    return {"title": title, "header": header, "sections": sections, "criteria": criteria,
            "negatives": negatives, "stray": stray, "core": core}


PLACEHOLDER = re.compile(r"<[^<>\n]{2,80}>")


def lint(text: str, config: dict | None = None, check_provenance: bool = True) -> list:
    spec = parse_spec(text)
    problems = []
    header = spec["header"]
    if not header.get("Ticket"):
        problems.append("missing `Ticket: GoodQA <project>#<number>` header line")
    elif config is not None:
        try:
            parse_ticket_ref(header["Ticket"], config)
        except SpecError as error:
            problems.append(str(error))
    try:
        parse_author(header.get("Author", ""))
    except SpecError as error:
        problems.append(str(error))
    click = header.get("Click-test", "")
    reason = re.match(r"^not-applicable\s*\((.{10,})\)$", click)
    if click != "required" and not reason:
        problems.append("Click-test must be `required` or `not-applicable (<reason, 10+ chars>)`")
    if header.get("Sign-off", "main") not in ("main", "human"):
        problems.append("Sign-off must be `main` or `human`")
    for name in ("Outcome", "Scope", "Acceptance criteria", "Negative cases", "Risks"):
        body = "\n".join(spec["sections"].get(name, [])).strip()
        if name not in spec["sections"]:
            problems.append(f"missing section `## {name}`")
        elif not body:
            problems.append(f"section `## {name}` is empty")
        elif PLACEHOLDER.search(body):
            problems.append(f"section `## {name}` still holds a template placeholder like <...>")
    ids = [ident for ident, _ in spec["criteria"]]
    if not ids:
        problems.append("no acceptance criteria: add `- AC-1: <observable result>. Verify by: <check>.`")
    if len(set(ids)) != len(ids):
        problems.append("duplicate acceptance criterion ids")
    for ident, body in spec["criteria"]:
        verify = re.search(r"Verify by:\s*(.{5,})", body)
        if not verify:
            problems.append(f"{ident} has no `Verify by: <check>`")
    negs = [ident for ident, _, _ in spec["negatives"]]
    if not negs:
        problems.append("no negative cases: add `- NEG-1 (AC-1): <what must be refused or handled>.`")
    if len(set(negs)) != len(negs):
        problems.append("duplicate negative case ids")
    for ident, refs, _ in spec["negatives"]:
        unknown = [ref for ref in refs if ref not in ids]
        if not refs or unknown:
            problems.append(f"{ident} must name existing criteria in parentheses (unknown: {', '.join(unknown) or 'none given'})")
    for line in spec["stray"]:
        problems.append(f"unrecognized bullet (use `- AC-n:` / `- NEG-n (AC-n):`): {line[:80]}")
    if check_provenance:
        problems.extend(provenance_problems(text))
    return problems


def provenance_problems(text: str) -> list:
    """Every AC-n and NEG-n needs a resolvable `Source:` (provenance.py). Additive: needs provenance.py installed."""
    try:
        import provenance
    except ImportError:
        return []  # older install: no provenance module, no gate
    try:
        problems, warnings = provenance.spec_lint(text)
    except Exception as error:  # a resolver bug must be visible, not silent
        return [f"provenance check failed ({type(error).__name__}); fix provenance.py or the spec"]
    for warning in warnings:
        print(warning, file=sys.stderr)
    return problems


# --------------------------------------------------------------------------- blockchain domain gates

def _domain_gates():
    try:
        import domain_gates
        return domain_gates
    except ImportError:  # older install without the domain gates: behave as before
        return None


def append_domain_block(text: str, repo, spec_policy: dict) -> str:
    """Append the `## Domain checklist` block when blockchain work is detected; otherwise return text unchanged."""
    dg = _domain_gates()
    if dg is None:
        return text
    try:
        if dg.settings(repo, spec_policy)["disabled"]:
            return text
        detected = dg.detect(Path(repo))
        block = dg.render_block([d["domain"] for d in detected], repo, detected) if detected else ""
    except Exception:  # guidance must never block writing a spec
        return text
    return text.rstrip("\n") + "\n\n" + block if block else text


def domain_lint(text: str, repo, spec_policy: dict):
    """Return (warnings, problems) for the domain checklist; problems only when domain_gates.mode is enforce."""
    dg = _domain_gates()
    if dg is None:
        return [], []
    try:
        config = dg.settings(repo, spec_policy)
        env_warning = [config["warning"]] if config.get("warning") else []
        if config["disabled"]:
            # stay silent for non-blockchain repos, but leave a trace when a blockchain repo is opted out
            found = dg.detect(Path(repo)) if config["source"] != "env HARNESS_DOMAIN_GATES" else []
            return ([f"domain gates disabled by {config['source']} although blockchain work was detected"] if found else []), []
        detected, failure = dg.detect_full(Path(repo))
        domains = [d["domain"] for d in detected]
        missing = dg.missing_items(text, domains, repo, strict=config["mode"] == "enforce")
        skipped = failure is not None
    except Exception as error:
        note = f"domain gates could not run ({type(error).__name__})"
        enforcing = isinstance(spec_policy.get("domain_gates"), dict) and spec_policy["domain_gates"].get("mode") == "enforce"
        return ([], [note + "; enforce mode fails closed"]) if enforcing else ([note + "; skipped"], [])
    notes = list(env_warning)
    if skipped:
        note = f"domain detection could not run: {failure} (pass --repo <worktree>)"
        if failure.startswith("scan truncated") and dg.allow_truncated(spec_policy):
            notes.append(note)  # a monorepo that legitimately exceeds the caps can opt in; still visible
        elif config["mode"] == "enforce":  # a Domains: line in the spec never excuses a failed scan
            return env_warning, [note + "; enforce mode fails closed"]
        else:
            notes.append(note)
    if not missing:
        return notes, []
    note = (f"domain checklist items without a NEG case naming them or `Domain-gate: <id> waived (<reason>)`: "
            f"{', '.join(missing)}")
    return (notes + [note], []) if config["mode"] != "enforce" else (notes, [note])


# --------------------------------------------------------------------------- reviews (local sidecar)

def reviews_path(spec_path: Path) -> Path:
    return spec_path.with_name(spec_path.name + ".reviews.json")


def load_reviews(spec_path: Path) -> list:
    path = reviews_path(spec_path)
    if not path.exists():
        return []
    data = (_domain_gates().safe_json_loads if _domain_gates() else json.loads)(read_spec_text(path))
    if not isinstance(data, dict) or data.get("v") != 1 or not isinstance(data.get("reviews"), list):
        raise SpecError(f"{path} is not a v1 reviews file", EXIT_USAGE)
    return data["reviews"]


def atomic_write(path: Path, data: bytes):
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    with open(tmp, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, path)


def current_reviews(entries: list, core: str) -> dict:
    """Latest review per role bound to this core hash (a later BLOCK supersedes an ACCEPT)."""
    latest = {}
    for entry in entries:
        if entry.get("core_sha") == core and entry.get("role") in ROLES:
            latest[entry["role"]] = entry
    return latest


def review_problems(entries: list, core: str, author_key: str | None) -> list:
    problems = []
    latest = current_reviews(entries, core)
    for role in ROLES:
        entry = latest.get(role)
        if not entry:
            stale = any(item.get("role") == role for item in entries)
            problems.append(f"no {role} review of the current spec" + (" (earlier reviews are stale: the spec "
                            "changed after review)" if stale else ""))
        elif entry.get("verdict") != "ACCEPT":
            problems.append(f"{role} review is {entry.get('verdict')}: fix the spec and get a new review")
    keys = {role: latest[role].get("key") for role in ROLES if role in latest}
    if len(keys) == 2 and keys["adversarial"] == keys["acceptance"]:
        problems.append("both reviews come from the same reviewer/model; get the other role from a different model, "
                        "a native red-team agent, or a human")
    for role, key in keys.items():
        if author_key and key == author_key:
            problems.append(f"the {role} reviewer is the spec author")
    return problems


def render_reviews(entries: list, core: str) -> str:
    latest = current_reviews(entries, core)
    lines = ["## Reviews", "", f"Spec core sha256: `{core}`", "",
             "| Role | Verdict | Reviewer | Kind | Source | Bound to |", "|---|---|---|---|---|---|"]
    for entry in entries:
        current = latest.get(entry.get("role")) is entry
        bound = "current" if current else ("superseded" if entry.get("core_sha") == core else "stale")
        cell = lambda value: str(value or "").replace("|", "/").replace("\n", " ")[:120]  # noqa: E731
        lines.append(f"| {cell(entry.get('role'))} | {cell(entry.get('verdict'))} | {cell(entry.get('identity'))}"
                     f"{' (' + cell(entry.get('model')) + ')' if entry.get('model') and entry.get('model') != entry.get('identity') else ''}"
                     f" | {cell(entry.get('kind'))} | {cell(entry.get('source'))} | {bound} |")
    if not entries:
        lines.append("| - | - | no reviews recorded yet | - | - | - |")
    return "\n".join(lines) + "\n"


def write_spec_with_reviews(spec_path: Path, entries: list):
    text = read_spec_text(spec_path)
    core = spec_core(text)
    tail = normalize_text(text)[len(core):]
    lines = tail.splitlines()
    start = next((i for i, line in enumerate(lines) if line.startswith("## Reviews")), len(lines))
    later = [line for line in lines[start + 1:] if line.startswith("## ")]
    if later:  # the Reviews section is regenerated, so anything after it would be lost
        raise SpecError(f"{spec_path} has content after `## Reviews` ({later[0]}); move it above the Reviews "
                        "section", EXIT_USAGE)
    rendered = core + "\n" + render_reviews(entries, core_sha(text))
    atomic_write(spec_path, rendered.encode("utf-8"))
    atomic_write(reviews_path(spec_path), json.dumps({"v": 1, "reviews": entries}, indent=1).encode("utf-8"))


def parse_review_report(path: Path):
    data = read_regular(path, 1_000_000).decode("utf-8", "replace")
    header, body = {}, []
    lines = data.split("\n")
    index = 0
    while index < len(lines) and lines[index].strip():
        field = re.match(r"^([A-Za-z][A-Za-z0-9 -]*):\s*(.*)$", lines[index])
        if field:
            header[field.group(1)] = field.group(2).strip()
        index += 1
    body = [line for line in lines[index:] if line.strip()]
    verdict = re.match(r"^PLAN_RESULT: (ACCEPT|BLOCK)\b", body[0].strip()) if body else None
    return header, (verdict.group(1) if verdict else None), sha256_bytes(data.encode("utf-8", "surrogateescape"))


# --------------------------------------------------------------------------- files, WALs and git

def read_regular(path: Path, limit: int, *, tail: bool = False):
    try:
        fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))  # never wait on a FIFO
    except OSError as error:
        raise SpecError(f"cannot open {path} ({error.strerror}); symlinks are refused", EXIT_USAGE) from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise SpecError(f"{path} is not a regular file", EXIT_USAGE)
        if info.st_size > limit and not tail:
            raise SpecError(f"{path} is larger than {limit} bytes", EXIT_USAGE)
        if tail and info.st_size > limit:
            os.lseek(fd, info.st_size - limit, os.SEEK_SET)
        chunks, remaining = [], min(limit, info.st_size)
        while remaining > 0:
            chunk = os.read(fd, min(remaining, 1 << 20))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
    finally:
        os.close(fd)
    if tail:
        return data, info.st_size
    return data


MAX_SPEC_BYTES = 1_000_000


def read_spec_bytes(path: Path) -> bytes:
    """Spec and review sidecar files: one regular, unlinked, bounded file (they are uploaded to the ticket)."""
    return read_regular(Path(path), MAX_SPEC_BYTES)


def read_spec_text(path: Path) -> str:
    try:
        return read_spec_bytes(path).decode("utf-8")
    except UnicodeDecodeError:
        raise SpecError(f"{path} is not valid UTF-8", EXIT_USAGE) from None


KEY_FRAGMENT = re.compile(r"-----(?:BEGIN|END) [A-Z0-9 ]*PRIVATE KEY-----")
BASE64_BLOCK = re.compile(r"(?m)^(?:[A-Za-z0-9+/=]{60,76}\n){4,}")


def prepare_log(path: Path, max_bytes: int):
    """Tail-cut, redact and refuse anything that still looks like key material."""
    data, original = read_regular(path, max_bytes, tail=True)
    if b"\x00" in data:
        raise SpecError(f"{path} looks binary; attach screenshots with --screenshot and logs as text", EXIT_USAGE)
    text = data.decode("utf-8", "replace")
    cut = original > len(data)
    if cut and (KEY_FRAGMENT.search(text[:8192]) or BASE64_BLOCK.search(text[:8192])):
        raise SpecError(f"{path}: the 2 MB tail cut lands inside what looks like key material; trim the log "
                        "or remove the key and retry", EXIT_MISSING)
    try:
        from integrate_local import redact_output
    except ImportError:  # pragma: no cover
        raise SpecError("redaction helper integrate_local.redact_output is not installed", EXIT_USAGE) from None
    text = redact_output(text)
    if KEY_FRAGMENT.search(text) or BASE64_BLOCK.search(text):
        raise SpecError(f"{path} still contains private-key material after redaction; remove it and retry")
    header = (f"# spec_flow log {path.name}: original {original} bytes, kept last {len(data)} bytes, "
              "redacted (tokens, cookies, bearer, keys)\n")
    return (header + text).encode("utf-8")


def prepare_media(path: Path, max_bytes: int):
    kind = MEDIA.get(path.suffix.lower())
    if not kind:
        raise SpecError(f"{path}: screenshots/recordings must be one of {', '.join(sorted(MEDIA))}", EXIT_USAGE)
    data = read_regular(path, max_bytes)
    mime, magics = kind
    if magics and not any(data.startswith(magic) for magic in magics):
        raise SpecError(f"{path} does not look like a {mime} file", EXIT_USAGE)
    if mime == "video/mp4" and data[4:8] != b"ftyp":
        raise SpecError(f"{path} does not look like an mp4 file", EXIT_USAGE)
    return data, mime


def wal_root() -> Path:
    return Path.home() / ".claude" / "wals"


def checked_wal(path: Path) -> Path:
    raw = Path(os.path.expanduser(str(path)))
    path = raw.absolute().resolve()
    if ".." in raw.parts or path.parent.parent != wal_root().resolve() or path.suffix != ".jsonl":
        raise SpecError("WAL path must be a per-session JSONL under ~/.claude/wals", EXIT_USAGE)
    return path


def wal_entries(path: Path):
    try:
        raw = read_regular(path, 64_000_000)
    except SpecError:
        return []
    entries = []
    for line in raw.decode("utf-8", "replace").splitlines():
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        if isinstance(entry, dict):
            entries.append(entry)
    return entries


def really_tested(entries: list, ident: str):
    """The REALLY_TESTED note for `ident`, newer than any PENDING_REAL_TEST for it."""
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,40}", ident or ""):
        raise SpecError("--really-tested takes an id like RT1", EXIT_USAGE)
    found, pending_at = None, ""
    for entry in entries:
        note = str(entry.get("note") or "")
        if note.startswith(f"PENDING_REAL_TEST {ident}:"):
            pending_at = max(pending_at, str(entry.get("at") or ""))
        elif note.startswith(f"REALLY_TESTED {ident}:"):
            found = entry
    if not found:
        return None
    if pending_at and str(found.get("at") or "") < pending_at:
        return None
    return {"id": ident, "at": found.get("at"), "note": str(found.get("note"))[:4000]}


def git_commit(repo: Path, sha: str, target: str | None):
    def run(*args):
        return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, timeout=30)
    resolved = run("rev-parse", "--verify", "--quiet", sha + "^{commit}")
    if resolved.returncode:
        raise SpecError(f"commit {sha} does not exist in {repo}")
    full = resolved.stdout.strip()
    subject = run("log", "-1", "--format=%s", full).stdout.strip()[:200]
    item = {"sha": full, "subject": subject}
    if target:
        if run("merge-base", "--is-ancestor", full, target).returncode:
            raise SpecError(f"commit {full[:12]} is not reachable from {target}")
        item["reachable_from"] = target
    return item


# --------------------------------------------------------------------------- ticket records

_SAFE_CHARS = re.compile(r"[^A-Za-z0-9 ._:@/#()+=,-]")
MAX_HOOK_TEXT = 4000


def safe(value, limit: int = 80) -> str:
    """Comment-derived text shown to an agent: a narrow character set and a length cap, so a forged record
    cannot smuggle instructions into hook output or CLI reports."""
    text = _SAFE_CHARS.sub("?", str(value))
    return text if len(text) <= limit else text[:limit] + "...(cut)"


def record_body(summary: str, record: dict) -> str:
    return f"{summary}\n\n```{RECORD_FENCE}\n{json.dumps(record, sort_keys=True, separators=(',', ':'))}\n```"


_FIELD_TYPES = {"attachments": list, "commits": list, "ac": list, "reviews": list, "tester": dict,
                "deployed_commit": dict, "covers_commits": list, "click_test": dict, "really_tested": dict}
_NESTED_STRINGS = {"id", "role", "sha256", "name", "key", "verdict", "core_sha", "kind", "sha", "identity",
                   "at", "text", "id_hint"}
_STRING_FIELDS = ("key", "actor", "author", "spec_core_sha", "spec_file_sha", "by", "signer_kind", "result", "url",
                  "pass_source", "signoff", "note")


def record_shape_problem(record: dict):
    """Records come from ticket comments anyone can write; refuse shapes the gate would trip over."""
    for name, kind in _FIELD_TYPES.items():
        if name in record and record[name] is not None and not isinstance(record[name], kind):
            return f"field {name} is not a {kind.__name__}"
    for name in _STRING_FIELDS:
        if name in record and record[name] is not None and not isinstance(record[name], str):
            return f"field {name} is not a string"
    for name, inner in (("attachments", dict), ("commits", dict), ("reviews", dict), ("ac", str),
                        ("covers_commits", str)):
        if any(not isinstance(item, inner) for item in record.get(name) or []):
            return f"field {name} holds an entry that is not a {inner.__name__}"
    # Nested objects hold only scalars, and the fields the gate keys on are strings.
    nested = [(name, item) for name in ("attachments", "commits", "reviews") for item in record.get(name) or []]
    nested += [(name, record[name]) for name in ("tester", "deployed_commit", "click_test", "really_tested")
               if isinstance(record.get(name), dict)]
    for name, item in nested:
        for field, value in item.items():
            if not isinstance(value, (str, bool, int, float, type(None))):
                return f"field {name}.{safe(field, 40)} is not a scalar"
            if field in _NESTED_STRINGS and value is not None and not isinstance(value, str):
                return f"field {name}.{safe(field, 40)} is not a string"
    return None


def _nesting_depth(text: str) -> int:
    depth = deepest = 0
    in_string = escaped = False
    for ch in text:
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string, escaped = True, False
        elif ch in "[{":
            depth += 1
            deepest = max(deepest, depth)
        elif ch in "]}":
            depth -= 1
    return deepest


def ticket_records(comments: list, max_bytes: int):
    records, ignored = [], []
    for comment in comments:
        for match in RECORD_BLOCK.finditer(str(comment.get("body") or "")):
            raw = match.group(1)
            if len(raw) > max_bytes:
                ignored.append(f"comment {comment['id'][:8]}: record larger than {max_bytes} bytes")
                continue
            try:
                if _nesting_depth(raw) > 32:
                    raise ValueError("nested too deeply")
                record = json.loads(raw)
            except (ValueError, RecursionError):
                ignored.append(f"comment {comment['id'][:8]}: record is not JSON")
                continue
            if not isinstance(record, dict) or record.get("v") != 1 or record.get("kind") not in KINDS:
                ignored.append(f"comment {comment['id'][:8]}: unknown record version or kind")
                continue
            shape = record_shape_problem(record)
            if shape:
                ignored.append(f"comment {comment['id'][:8]}: malformed {record['kind']} record ({shape})")
                continue
            record["_comment"] = comment["id"]
            record["_at"] = str(comment.get("createdAt") or "")
            records.append(record)
    records.sort(key=lambda item: (item["_at"], item["_comment"]))
    return records, ignored


def attachment_problems(record: dict, index: dict) -> list:
    problems = []
    attachments = record.get("attachments")
    if not isinstance(attachments, list):
        return ["record lists no attachments"]
    for item in attachments:
        if not isinstance(item, dict):
            problems.append("malformed attachment entry")
            continue
        row = index.get(item.get("id"))
        name = item.get("name") or item.get("id")
        if row is None:
            problems.append(f"attachment {safe(name)} is not on the ticket")
        elif row.get("commentId") != record["_comment"]:
            problems.append(f"attachment {safe(name)} belongs to a different comment")
        elif row.get("completionState") != "completed" or row.get("deletedAt") or row.get("archivedAt"):
            problems.append(f"attachment {safe(name)} is not a completed upload")
        elif row.get("sha256") != item.get("sha256"):
            problems.append(f"attachment {safe(name)} sha256 differs from the record (replaced or tampered)")
    return problems


def kind_problems(record: dict) -> list:
    """Shape rules beyond attachment integrity: a record must carry the files its kind is trusted for."""
    attachments = [item for item in record.get("attachments") or [] if isinstance(item, dict)]
    roles = {item.get("role"): item for item in attachments}
    problems = []
    if any(not re.fullmatch(r"AC-[0-9]{1,3}", str(ac)) for ac in record.get("ac") or []):
        problems.append("criteria ids must look like AC-<n>")
    if record["kind"] == "spec":
        if (roles.get("spec") or {}).get("sha256") != record.get("spec_file_sha") or not record.get("spec_file_sha"):
            problems.append("no attached spec file matches the record's spec_file_sha")
        if "reviews" not in roles:
            problems.append("no reviews file is attached")
        if not record.get("ac"):
            problems.append("the spec record lists no acceptance criteria")
    elif record["kind"] == "evidence":
        if not (record.get("really_tested") or roles.get("log") or (record.get("commits") and record.get("note"))):
            problems.append("the evidence record carries no proof")
    elif record["kind"] == "click_test":
        if not (roles.get("log") or roles.get("report")):
            problems.append("the click-test record has no log or report attached")
    return problems


def verified(records: list, index: dict, kind: str):
    good, bad = [], []
    for record in records:
        if record["kind"] != kind:
            continue
        try:
            problems = attachment_problems(record, index) + kind_problems(record)
        except Exception as exc:  # comments are untrusted: a shape the checks missed is ignored, not fatal
            problems = [f"record could not be checked ({type(exc).__name__})"]
        (bad if problems else good).append((record, problems))
    return [record for record, _ in good], bad


def op_id(issue_id: str, key: str) -> str:
    return str(uuid.uuid5(NAMESPACE, f"{issue_id}:{key}"))


def content_key(kind: str, parts) -> str:
    return kind + ":" + sha256_bytes(json.dumps(parts, sort_keys=True, default=str).encode())[:32]


class Session:
    """One ticket, one adapter, one deadline."""

    def __init__(self, ref: str, spec_policy: dict, *, deadline_seconds: float | None = None):
        self.spec_policy = spec_policy
        _, _, self.config = ticket_config(spec_policy)
        self.project, self.number = parse_ticket_ref(ref, self.config)
        seconds = deadline_seconds or float(spec_policy.get("command_deadline_seconds", 300))
        self.adapter = make_adapter(self.config, spec_policy, self.project, time.monotonic() + seconds)
        self.ticket = self.adapter.lookup(self.project, self.number)
        if self.ticket is None:
            raise SpecError(f"ticket GoodQA {self.project}#{self.number} was not found with this credential")
        route = (spec_policy.get("projects") or {}).get(self.project) or {}
        self.project_id = getattr(self.ticket, "project_id", None) or route.get("project_id")

    def records(self):
        comments = self.adapter.all_comments(self.ticket.id)
        records, ignored = ticket_records(comments, int(self.spec_policy.get("max_record_bytes", 65536)))
        index = {row.get("id"): row for row in self.adapter.attachments(self.ticket.id)}
        return records, ignored, index

    def latest_spec(self, records, index):
        good, _ = verified(records, index, "spec")
        if not good:
            raise SpecError(f"no verified spec is attached to {self.ticket.label}; run spec_flow.py attach first")
        return good[-1]

    def post(self, kind: str, summary: str, record: dict, files, records):
        """files: [(role, name, mime, bytes)]. Idempotent on the record key."""
        index = {row.get("id"): row for row in self.adapter.attachments(self.ticket.id)}
        trusted = verified(records, index, record["kind"])[0] if record["kind"] != "signoff" else \
            [item for item in records if item["kind"] == "signoff"]
        if any(item.get("key") == record["key"] for item in trusted):
            print(json.dumps({"status": "ALREADY_RECORDED", "kind": kind, "key": record["key"]}))
            return None
        # A same-key record that failed verification must not be replayed by GoodQA's idempotent comment:
        # fold the rejected comment ids into the operationId so this attempt creates a new comment.
        rejected = sorted(item["_comment"] for item in records
                          if item.get("key") == record["key"] and item not in trusted)
        op_key = record["key"] + ("|retry:" + ",".join(rejected) if rejected else "")
        if not self.project_id:
            raise SpecError("cannot upload: the ticket's project id is unknown", EXIT_UNREACHABLE)
        attachments = []
        for role, name, mime, data in files:
            digest = sha256_bytes(data)
            attachment = self.adapter.upload(self.project_id, name, mime, data, digest)
            attachments.append({"id": attachment, "sha256": digest, "role": role, "name": name})
        record = dict(record, attachments=attachments)
        comment = self.adapter.comment_with_files(self.ticket.id, record_body(summary, record),
                                                  op_id(self.ticket.id, op_key),
                                                  [item["id"] for item in attachments])
        if comment.get("id") in rejected:
            raise SpecError("GoodQA replayed an earlier rejected comment instead of recording this one", EXIT_TRACKER)
        bound = {row.get("id"): row for row in self.adapter.attachments(self.ticket.id)}
        unbound = [item["name"] for item in attachments if (bound.get(item["id"]) or {}).get("commentId") != comment.get("id")]
        if unbound:
            raise SpecError(f"GoodQA did not bind {', '.join(unbound)} to the new comment; the record will not "
                            "verify", EXIT_TRACKER)
        print(json.dumps({"status": "RECORDED", "kind": kind, "ticket": self.ticket.label,
                          "comment": comment["id"], "attachments": len(attachments)}))
        return comment


# --------------------------------------------------------------------------- the done gate

def tester_key(tester: dict) -> str:
    kind = tester.get("kind")
    identity = str(tester.get("identity") or "")
    return identity_key(kind, safe_id(identity) if kind == "agent" else identity) if kind else ""


def evaluate(records: list, index: dict, issue: dict, ignored=()):
    """Return {"ready", "missing", "self_attested", "notes"} for one ticket."""
    missing, attested, notes = [], [], list(ignored)
    label = issue.get("_label") or issue.get("id")
    specs, bad_specs = verified(records, index, "spec")
    for record, problems in bad_specs:
        notes.append(f"spec record {record['_comment'][:8]} ignored: {'; '.join(problems)}")
    if not specs:
        missing.append("No verified spec is attached. Fix: spec_flow.py new --ticket '<ref>' --out spec.md; "
                       "get adversarial + acceptance reviews (spec_flow.py review); spec_flow.py attach spec.md")
        return {"ready": False, "missing": missing, "self_attested": attested, "notes": notes}
    spec = specs[-1]
    core = spec.get("spec_core_sha")
    attested.append("spec core sha, criteria and review verdicts are read from the spec record; the attached spec "
                    "file is checked by sha256 but the core is not re-derived from it")
    author = spec.get("author")
    reviews = {entry.get("role"): entry for entry in spec.get("reviews") or [] if isinstance(entry, dict)}
    review_keys, valid_roles = set(), 0
    for role in ROLES:
        entry = reviews.get(role)
        if not entry or entry.get("verdict") != "ACCEPT" or entry.get("core_sha") != core:
            missing.append(f"{role} spec review: no ACCEPT bound to spec core {str(core)[:12]}. Fix: "
                           f"spec_flow.py review spec.md --role {role} ...; then spec_flow.py attach spec.md")
            continue
        review_keys.add(entry.get("key"))
        valid_roles += 1
        if entry.get("kind") in ("human",):
            attested.append(f"{role} review by human {safe(entry.get('identity'))!r} (name not verified)")
    if valid_roles == 2 and len(review_keys) == 1:
        missing.append("both spec reviews come from the same reviewer/model")
    if author in review_keys:
        missing.append("a spec reviewer is the spec author")
    owners = {author} | {r.get("actor") for r in records if r["kind"] in ("spec", "evidence", "click_test")}
    owners.discard(None)
    # acceptance criteria
    evidence, bad_evidence = verified(records, index, "evidence")
    for record, problems in bad_evidence:
        notes.append(f"evidence record {record['_comment'][:8]} ignored: {'; '.join(problems)}")
    for ac in spec.get("ac") or []:
        proofs = [r for r in evidence if r.get("spec_core_sha") == core and ac in (r.get("ac") or [])
                  and (r.get("really_tested") or any(a.get("role") == "log" for a in r.get("attachments") or [])
                       or (r.get("commits") and r.get("note")))]
        if not proofs:
            stale = any(ac in (r.get("ac") or []) for r in evidence)
            missing.append(f"{ac}: no evidence on the current spec{' (only stale evidence for an older spec)' if stale else ''}. "
                           f"Fix: spec_flow.py evidence --ticket '{label}' --ac {ac} --really-tested <RT id> --wal <WAL> "
                           "[--commit <sha> --repo <checkout>] [--log <file>]")
    current = [r for r in evidence if r.get("spec_core_sha") == core]
    if any(r.get("really_tested") or (r.get("commits") and r.get("note")) for r in current):
        attested.append("REALLY_TESTED notes, commit citations and notes in evidence records are checked when posted, "
                        "not re-checked against the WAL or repository by done")
    if spec.get("ac") and not any(r.get("commits") for r in current):
        missing.append(f"commits: no evidence on the current spec cites a commit. Fix: spec_flow.py evidence "
                       f"--ticket '{label}' --ac <AC> --commit <sha> --repo <checkout> --note <check>")
    if spec.get("ac") and not any(any(a.get("role") == "log" for a in r.get("attachments") or []) for r in current):
        missing.append(f"execution logs: no evidence on the current spec attaches a log. Fix: spec_flow.py "
                       f"evidence --ticket '{label}' --ac <AC> --log <test or run output>")
    # click test
    click = spec.get("click_test") or {}
    if click.get("required", True):
        all_tests, bad_tests = verified(records, index, "click_test")
        tests = [r for r in all_tests if r.get("spec_core_sha") == core]
        for record, problems in bad_tests:
            notes.append(f"click-test record {record['_comment'][:8]} ignored: {'; '.join(problems)}")
        latest = tests[-1] if tests else None
        if latest is None and all_tests:
            missing.append("click-test: only click-tests of an older spec version exist (stale); record a new "
                           "click-test after deploying the current spec's work")
        elif latest is None:
            missing.append("click-test: none recorded. Fix: spec_flow.py click-test --ticket '<ref>' --agent-id <id> "
                           "--wal-dir <session WAL dir> --url <url> --deployed-commit <sha> --repo <checkout> --result pass "
                           "--report <click-tester report> --log <file>")
        elif latest.get("result") != "pass":
            missing.append("click-test: the latest click-test failed; fix and record a new passing click-test")
        elif not any(a.get("role") in ("log", "report") for a in latest.get("attachments") or []):
            missing.append("click-test: the passing record has no log or report attached")
        elif not (latest.get("deployed_commit") or {}).get("sha"):
            missing.append("click-test: the passing record names no deployed commit; rerun click-test with "
                           "--deployed-commit <sha> after deploy")
        elif uncovered := sorted({c.get("sha") for r in evidence if r.get("spec_core_sha") == core
                                  for c in r.get("commits") or [] if c.get("sha")}
                                 - set(latest.get("covers_commits") or [])):
            missing.append(f"click-test: evidence commits {', '.join(s[:12] for s in uncovered)} came after the "
                           "deployed commit that was click-tested; deploy them and record a new click-test")
        elif tester_key(latest.get("tester") or {}) in (
                {author} | review_keys | {r.get("actor") for r in evidence if r.get("actor")}):
            missing.append("click-test: the tester is the spec author, a spec reviewer or posted the evidence; "
                           "an independent click-tester must run it")
        else:
            tester = latest.get("tester") or {}
            attested.append(f"deployed commit {safe(latest['deployed_commit'].get('sha'), 12)} at "
                            f"{safe(latest.get('url'), 160)} is declared by the recorder, not read back from the deployment")
            if latest.get("pass_source") == "self-attested":
                attested.append(f"click-test pass by {safe(tester.get('kind'))} {safe(tester.get('identity'))!r} is self-attested")
            if not tester.get("ended_at"):
                notes.append("click-test end time not recorded (no subagent_stop event); last activity "
                             f"{safe(tester.get('last_activity_at'))}")
    else:
        notes.append(f"click-test not applicable: {safe(click.get('reason'), 160)}")
    # sign-off
    human_required = spec.get("signoff") == "human" or "human sign-off" in str(issue.get("description") or "").lower()
    signoffs = [r for r in records if r["kind"] == "signoff" and r.get("spec_core_sha") == core]
    testers = {tester_key(r.get("tester") or {}) for r in records if r["kind"] == "click_test"}
    excluded = owners | review_keys | (testers - {""})
    valid = [r for r in signoffs if r.get("by") not in excluded
             and (not human_required or r.get("signer_kind") == "human")]
    if not valid:
        why = []
        if any(r.get("by") in excluded for r in signoffs):
            why.append("a sign-off came from the owner, author, a spec reviewer, an evidence poster or a click-tester")
        if human_required and signoffs:
            why.append("this ticket requires a human sign-off")
        missing.append("sign-off: none valid on the current spec" + (f" ({'; '.join(why)})" if why else "")
                       + ". Fix: spec_flow.py signoff --ticket '<ref>' --by <main agent id or person> "
                       "--kind agent|human --source <where it was given>")
    else:
        signer = valid[-1]
        attested.append(f"sign-off by {safe(signer.get('signer_kind'))} {safe(signer.get('by'))!r} (identity is self-declared; independence is checked only "
                        "against the declared author, reviewer, poster and tester ids)")
    return {"ready": not missing, "missing": missing, "self_attested": attested, "notes": notes,
            "spec_core_sha": core}


def format_result(label: str, result: dict) -> str:
    lines = [f"{label}: {'READY' if result['ready'] else 'NOT READY'}"]
    if result["missing"]:
        lines.append("Missing:")
        lines += [f"  {n}. {item}" for n, item in enumerate(result["missing"], 1)]
    if result["self_attested"]:
        lines.append("Self-attested (not verified by the helper):")
        lines += [f"  - {item}" for item in result["self_attested"]]
    if result["notes"]:
        lines.append("Notes:")
        lines += [f"  - {item}" for item in result["notes"]]
    return "\n".join(lines)


# --------------------------------------------------------------------------- PreToolUse hook

def classify(tool: str, tool_input: dict, min_reason: int):
    """Yield (issue_id, action, detail). action in open|done|reason|unknown|archive|stage|delete|scope."""
    tool_input = tool_input if isinstance(tool_input, dict) else {}
    if tool == "close_issue_done":
        # GoodQA's close_issue_done schema: status enum on_production|done, default on_production (deploy,
        # not done). Pinned by Hook.test_other_tools_and_open_statuses_need_no_network.
        status = tool_input.get("status") or "on_production"
        yield tool_input.get("issueId"), _status_action(status), status
    elif tool == "close_issue_wont_fix":
        note = str(tool_input.get("note") or "").strip()
        yield tool_input.get("issueId"), "open" if len(note) >= min_reason else "reason", "wont_fix"
    elif tool == "update_issue":
        patch = tool_input.get("patch") if isinstance(tool_input.get("patch"), dict) else {}
        status = _one_status(tool_input, patch)
        if status is not None:
            yield tool_input.get("issueId"), _status_action(status, ""), status
        if any(key in patch for key in ("projectId", "pipelineId", "stageId")):
            # Moving an issue out of an enforced project (or across a pipeline) would escape the gate.
            yield tool_input.get("issueId"), "stage", "project/pipeline/stage move"
    elif tool == "bulk_update_issues":
        items = tool_input.get("items")
        if items is not None and not isinstance(items, list):
            yield None, "scope", "bulk_update_issues with items that are not a list"
        for item in items if isinstance(items, list) else []:
            if isinstance(item, dict):
                yield item.get("issueId"), _status_action(_item_status(item), str(item.get("note") or ""),
                                                          min_reason), _item_status(item)
            else:
                yield None, "scope", "bulk_update_issues with a malformed item"
    elif tool == "archive_issue":
        yield tool_input.get("issueId"), "archive", "archive"
    elif tool == "reassign_issue":
        if tool_input.get("stageId") or tool_input.get("pipelineId"):
            yield tool_input.get("issueId"), "stage", "pipeline/stage move"
    elif tool == "call_api":
        yield from _classify_call_api(tool_input, min_reason)

_SAFE_SUBRESOURCE = re.compile(r"(/v\d+)?/issues/(" + UUID + r")/(comments|attachments|time-entries)(/" + UUID + r")?")
_ISSUE_PATH = re.compile(r"(/v\d+)?/issues/(" + UUID + r")")
# Fields on a single-issue write that cannot change status, archive or location.
_SINGLE_ISSUE_KEYS = {"status", "patch", "note", "projectId", "pipelineId", "stageId", "title", "description",
                      "priority", "type", "labels", "tags", "assigneeId", "assigneeIds", "dueDate", "estimate",
                      "severity", "operationId"}
_NON_CREATE_KEYS = {"items", "status", "patch", "issueId", "issueIds", "ids", "projectId", "pipelineId", "stageId",
                    "filter", "where", "query", "set", "update"}
_COLLECTION_PATH = re.compile(r"(/v\d+)?(/projects/" + UUID + r")?/issues(/bulk)?")


def _classify_call_api(tool_input: dict, min_reason: int):
    """Default-deny for writes that mention issues: only known shapes are read, everything else is unchecked."""
    method = str(tool_input.get("method") or "GET").upper()
    if method == "GET":
        return
    original = str(tool_input.get("path") or "")
    parsed = urllib.parse.urlsplit(original)
    path = parsed.path.lower()
    found = re.search(UUID, original)
    issue_id = found.group(0).lower() if found else None
    unusual = (not original.startswith("/") or parsed.query or parsed.fragment or parsed.scheme or parsed.netloc
               or "%" in original or "\\" in original or any(seg in ("", ".", "..") for seg in path.split("/")[1:]))
    if unusual:
        yield issue_id, ("unknown" if issue_id else "scope"), f"{method} {original} (unusual path)"
        return
    if "issue" not in path:
        # Not an issue route. Other routes (stages, tickets, batches) might still move or close issues, and the
        # gate cannot read them, so every such write is unchecked: it warns, and blocks while anything is enforced.
        yield None, "scope", f"{method} {original} (not an issue route)"
        return
    raw = tool_input.get("body")
    body = raw if isinstance(raw, dict) else {}
    patch = body.get("patch") if isinstance(body.get("patch"), dict) else {}
    status = _one_status(body, patch)
    if _SAFE_SUBRESOURCE.fullmatch(path):
        if status is not None or "patch" in body:
            yield issue_id, "unknown", f"{method} {original} carries a status"
        return
    single = _ISSUE_PATH.fullmatch(path)
    if single:
        issue_id = single.group(2)
        if method == "DELETE":
            yield issue_id, "delete", "DELETE issue"
        elif raw is not None and not isinstance(raw, dict):
            yield issue_id, "unknown", f"{method} {original} with a non-object body"
        else:
            if status is not None:
                yield issue_id, _status_action(status, str(body.get("note") or ""), min_reason), status
            if any(key in body or key in patch for key in ("projectId", "pipelineId", "stageId")):
                yield issue_id, "stage", "project/pipeline/stage move"
            other = (set(body) | set(patch)) - _SINGLE_ISSUE_KEYS
            if other:  # archivedAt, closedAt, resolution, action, ...: effect on status is unknown
                yield issue_id, "unknown", f"{method} {original} sets {', '.join(sorted(other)[:5])}"
        return
    if _COLLECTION_PATH.fullmatch(path) and method in ("POST", "PATCH", "PUT"):
        items = body.get("items") if isinstance(body.get("items"), list) else None
        creates = (method == "POST" and not path.endswith("/bulk") and isinstance(raw, dict)
                   and not set(body) & _NON_CREATE_KEYS)
        if items is None and not creates:
            yield None, "scope", f"{method} {original} (not a plain create)"
        elif items is not None:
            for item in items:
                if isinstance(item, dict):
                    yield item.get("issueId"), _status_action(_item_status(item), str(item.get("note") or ""),
                                                              min_reason), _item_status(item)
                else:
                    yield None, "scope", f"{original} with a malformed item"
        elif (raw is not None and not isinstance(raw, dict)) or "status" in body or "patch" in body:
            yield None, "scope", original
        else:
            yield None, "scope-path", original  # e.g. creating an issue: only checked by the project in the path
        return
    # Any other write mentioning issues (sub-resources such as /close, unknown routes): unchecked.
    yield issue_id, ("unknown" if issue_id else "scope"), f"{method} {original} (unrecognised issue route)"


def _item_status(item: dict):
    status = _one_status(item, item.get("patch"))
    return "<missing status>" if status is None else status


def _one_status(*sources):
    """The status a write sets, or None. Two different values, or an explicit null, are unknown."""
    values = {repr(src["status"]) for src in sources if isinstance(src, dict) and "status" in src}
    if not values:
        return None
    if len(values) > 1:
        return "<conflicting statuses>"
    value = next(src["status"] for src in sources if isinstance(src, dict) and "status" in src)
    return "<null>" if value is None else value


def _status_action(status, note=None, min_reason=20):
    if status in OPEN_STATUSES:
        return "open"
    if status in SPEC_STATUSES:
        return "done"
    if status in REASON_STATUSES:
        return "open" if note is not None and len(note.strip()) >= min_reason else "reason"
    return "unknown"


def dead_enforced_keys(config: dict, spec_policy: dict, deadline: float) -> list:
    """Enforced projects whose routed key can no longer read the project itself (key liveness probe)."""
    dead = []
    routes = spec_policy.get("projects") or {}
    for entry in spec_policy.get("enforced_projects") or []:
        if isinstance(entry, dict):
            project_id = str(entry.get("project_id") or "")
            slug = next((name for name, route in routes.items()
                         if str(route.get("project_id") or "").lower() == project_id.lower()), None)
            label = slug or project_id
        else:
            slug = str(entry).lower()
            project_id = str((routes.get(slug) or {}).get("project_id") or "")
            label = slug
        if not project_id:
            dead.append(f"{label} (no route)")
            continue
        data = make_adapter(config, spec_policy, slug, deadline).call("get_project", {"projectId": project_id})
        slug = label
        if not isinstance(data, dict) or "__error__" in data:
            dead.append(f"{label} ({data.get('__error__') if isinstance(data, dict) else 'bad response'})")
    return dead


def resolve_issue(issue_id: str, config: dict, spec_policy: dict, deadline: float, refusals=None):
    """Find the issue with the default key, then each routed project's key.

    `refusals`, when given, collects the error ("not_found" / "forbidden") from each key that could not read it.
    """
    tried = set()
    for project in [None] + sorted((spec_policy.get("projects") or {}).keys()):
        merged = ta.project_config(config, project, spec_policy.get("projects") or {})
        key = (merged.get("key_file"), merged.get("endpoint"))
        if key in tried:
            continue
        tried.add(key)
        adapter = ta.adapter_for(dict(merged, upload_host_suffixes=spec_policy.get("upload_host_suffixes")),
                                 deadline=deadline)
        issue, refusal = adapter.issue_access(issue_id)
        if issue is not None:
            return adapter, issue
        if refusals is not None:
            refusals.append(refusal)
    return None, None


def run_hook(payload: dict, spec_policy: dict, config_loader=None) -> tuple:
    name = str(payload.get("tool_name") or "")
    match = TOOL_PATTERN.match(name)
    mode = spec_policy.get("mode", "warn")
    if not match or mode == "off":
        return 0, ""
    min_reason = int(spec_policy.get("close_reason_min_chars", 20))
    items = [item for item in classify(match.group(1).lower(), payload.get("tool_input") or {}, min_reason)
             if item[1] != "open"]
    if not items:
        return 0, ""
    enforced = enforced_ids(spec_policy)
    deadline = time.monotonic() + float(spec_policy.get("hook_deadline_seconds", 40))
    blocking, warnings, dead_keys = [], [], None
    try:
        _, _, config = (config_loader or ticket_config)(spec_policy)
        for issue_id, action, detail in items:
            if action == "scope-path":
                if any(pid in detail.lower() for pid in enforced):
                    blocking.append(f"call_api write to {detail} touches an enforced project and its effect on "
                                    "issue status can't be checked; use the named GoodQA tools")
                continue
            if action == "scope":
                (blocking if enforced else warnings).append(
                    f"call_api write to {detail} may change issue status in ways the spec gate can't check; "
                    "use the named GoodQA tools")
                continue
            # update_issue and reassign_issue declare issueId as a uuid, but close_issue_done, bulk_update_issues
            # and archive_issue only describe it as one. An id the gate cannot resolve might still reach an issue,
            # so it fails closed wherever anything is enforced.
            if not isinstance(issue_id, str) or not re.fullmatch(UUID, issue_id):
                (blocking if enforced else warnings).append(
                    f"{detail}: missing or non-uuid issueId; the spec gate only checks issues by uuid")
                continue
            refusals = []
            adapter, issue = resolve_issue(issue_id, config, spec_policy, deadline, refusals)
            if issue is None:
                if "forbidden" in refusals:
                    # A key that can see the issue exists but is refused: revoked, rotated or lost membership.
                    # That may be an enforced project's key, so fail closed wherever anything is enforced.
                    (blocking if enforced else warnings).append(
                        f"issue {issue_id}: a routed GoodQA key was refused (forbidden), so the spec gate cannot "
                        "check it; re-run spec_flow.py doctor --project <slug> for the enforced projects")
                else:
                    # not_found under every key. GoodQA also answers not_found to a key without membership, so
                    # first prove each enforced project's key still reads its own project; only then is the
                    # issue known to be outside every enforced project.
                    if enforced and dead_keys is None:
                        dead_keys = dead_enforced_keys(config, spec_policy, deadline)
                    if dead_keys:
                        blocking.append(f"issue {issue_id} is not found, and the routed key for enforced "
                                        f"project(s) {', '.join(dead_keys)} can no longer read its project; "
                                        "fix the key and re-run spec_flow.py doctor")
                    else:
                        warnings.append(f"issue {issue_id} is not found with any routed key, and every enforced "
                                        "project's key still reads its project; not checked")
                continue
            project_id = str(issue.get("projectId") or "").lower()
            if not project_id and enforced:
                blocking.append(f"issue {issue_id[:8]} has no readable project id, so the gate cannot tell "
                                "whether it is enforced")
                continue
            target = blocking if project_id in enforced else warnings
            label = f"issue #{issue.get('number')} ({issue_id[:8]})"
            if action == "done":
                comments = adapter.all_comments(issue_id)
                records, ignored = ticket_records(comments, int(spec_policy.get("max_record_bytes", 65536)))
                index = {row.get("id"): row for row in adapter.attachments(issue_id)}
                issue["_label"] = label
                result = evaluate(records, index, issue, ignored)
                if not result["ready"]:
                    target.append(format_result(label, result))
            elif action == "reason":
                target.append(f"{label}: {detail} needs a reason of at least {min_reason} characters (note)")
            elif action == "unknown":
                target.append(f"{label}: unknown status {detail!r}; refusing to guess whether it closes the ticket")
            elif action == "archive":
                if not (issue.get("closedAt") or issue.get("status") in SPEC_STATUSES | REASON_STATUSES):
                    target.append(f"{label}: archiving an open ticket hides unfinished work; close it first")
            elif action == "stage":
                target.append(f"{label}: pipeline/stage moves can change status without the spec gate; "
                              "use update_issue with an explicit status")
            elif action == "delete":
                target.append(f"{label}: deleting an issue through call_api is not allowed by the spec gate")
    except (ta.TicketSystemUnavailable, OSError, ValueError, ImportError) as error:
        text = f"spec-flow: could not check this GoodQA status change ({error})."
        if mode == "enforce" and enforced:
            return 2, text + " Failing closed for enforced projects; retry, or check the credential."
        return 0, text + " (warn mode: allowed)"
    if blocking and mode == "enforce":
        return 2, "Blocked by the Agent Harness spec gate:\n" + "\n".join(blocking)
    notes = blocking + warnings
    if notes:
        return 0, "spec-flow (not blocking):\n" + "\n".join(notes)
    return 0, ""


# --------------------------------------------------------------------------- plan-review ticket gate

def plan_ticket_gate(repo: Path, packet: str, *, spec_policy: dict | None = None, config_loader=None):
    """(exit_code, text) for peer_review.py plan. Tracked repos need a verifiable Ticket line."""
    try:
        spec_policy = spec_policy or load_spec_policy()
    except (OSError, ValueError) as error:
        return 0, f"spec-flow: plan ticket gate skipped (spec policy unavailable: {error})"
    mode = spec_policy.get("plan_ticket_gate", "warn")
    if mode == "off":
        return 0, ""
    try:
        commit_policy, policy, config = (config_loader or ticket_config)(spec_policy)
    except (ImportError, OSError, ValueError) as error:
        return (2 if mode == "enforce" else 0), f"spec-flow: commit policy unavailable ({error})"
    try:
        return _plan_ticket_gate(repo, packet, mode, commit_policy, policy, config, spec_policy, config_loader)
    except Exception as error:  # never let a gate bug decide silently
        text = f"spec-flow: plan ticket gate failed ({type(error).__name__}: {str(error)[:160]})"
        return (2, text + "; enforce mode stops here") if mode == "enforce" else (0, text + "; warn mode continues")


def _plan_ticket_gate(repo, packet, mode, commit_policy, policy, config, spec_policy, config_loader):
    origin = subprocess.run(["git", "-C", str(repo), "remote", "get-url", "origin"], capture_output=True,
                            text=True, timeout=30).stdout.strip()
    if not commit_policy.tickets_required_for(origin, policy):
        return 0, ""
    problems, unverified = [], []
    lines = TICKET_LINE.findall(packet)
    if not lines:
        problems.append("the plan packet has no `Ticket: GoodQA <project>#<number>` line. File or find the ticket "
                        "first (every piece of work gets one), then add the line; spec_flow.py new writes it for specs.")
    deadline = time.monotonic() + 30
    for line in lines:
        try:
            project, number = parse_ticket_ref(line, config)
            adapter = make_adapter(config, spec_policy, project, deadline)
            if adapter.lookup(project, number) is None:
                problems.append(f"ticket GoodQA {project}#{number} does not exist (or this key cannot see it)")
        except SpecError as error:
            problems.append(str(error))
        except ta.TicketSystemUnavailable as error:
            unverified.append(f"{line}: {error}")
    if not problems and unverified:
        subject = "plan-" + sha256_bytes(packet.encode())[:20]
        if commit_policy.find_waiver("tickets", subject, policy):
            return 0, "spec-flow: ticket unverified, covered by a tickets waiver for " + subject
        text = ("spec-flow: TICKETS_UNVERIFIED: " + "; ".join(unverified)
                + f"\nOffline? Record a waiver: commit_policy.py waive --kind tickets --subject {subject} ...")
        return (6 if mode == "enforce" else 0), text
    if problems:
        text = "spec-flow plan ticket gate:\n" + "\n".join("  - " + p for p in problems)
        if mode == "warn":
            return 0, text + "\n(warn mode: review continues)"
        return 2, text
    return 0, ""


# --------------------------------------------------------------------------- commands

def cmd_new(args, spec_policy):
    out = Path(args.out)
    if out.exists():
        raise SpecError(f"{out} exists; refusing to overwrite", EXIT_USAGE)
    session = Session(args.ticket, spec_policy)
    parse_author(args.author)
    description = getattr(session.ticket, "description", "")
    text = TEMPLATE_FILE.read_text(encoding="utf-8").format(
        title=session.ticket.title or f"{session.project}#{session.number}", project=session.project,
        number=session.number, author=args.author,
        signoff="human" if "human sign-off" in description.lower() else "main")
    text = append_domain_block(text, getattr(args, "repo", None) or ".", spec_policy)
    atomic_write(out, text.encode("utf-8"))
    print(json.dumps({"status": "CREATED", "spec": str(out), "ticket": session.ticket.label}))
    return EXIT_OK


def cmd_lint(args, spec_policy):
    text = read_spec_text(Path(args.spec))
    _, _, config = ticket_config(spec_policy)
    problems = lint(text, config)
    warnings, domain_problems = domain_lint(text, getattr(args, "repo", None) or ".", spec_policy)
    problems = problems + domain_problems
    print(json.dumps({"status": "FAIL" if problems else "PASS", "problems": problems, "warnings": warnings,
                      "spec_core_sha": core_sha(text)}, indent=1))
    return EXIT_MISSING if problems else EXIT_OK


def cmd_packet(args, spec_policy):
    text = read_spec_text(Path(args.spec))
    try:
        _, _, config = ticket_config(spec_policy)
    except (OSError, ValueError, ImportError) as error:
        raise SpecError(f"cannot load the ticket configuration to lint the spec: {error}", EXIT_USAGE)
    problems = lint(text, config)
    if problems:  # reviewers should never be handed a spec that cannot be attached
        print(json.dumps({"status": "FAIL", "problems": problems}, indent=1))
        return EXIT_MISSING
    out = Path(args.out)
    if out.exists():
        raise SpecError(f"{out} exists; write the packet to a fresh path outside the worktree", EXIT_USAGE)
    atomic_write(out, spec_core(text).encode("utf-8"))
    print(json.dumps({"status": "WROTE", "packet": str(out), "sha256": core_sha(text)}))
    return EXIT_OK


def cmd_review(args, spec_policy):
    spec_path = Path(args.spec)
    text = read_spec_text(spec_path)
    core = core_sha(text)
    entries = load_reviews(spec_path)
    now = datetime.now(timezone.utc).isoformat()
    if args.report:
        header, verdict, report_sha = parse_review_report(Path(args.report))
        if header.get("Stage") != "plan":
            raise SpecError("the review report is not a peer_review.py plan report", EXIT_USAGE)
        if verdict is None:
            raise SpecError("the review report has no PLAN_RESULT verdict", EXIT_USAGE)
        if header.get("Reviewed packet SHA-256") != core:
            raise SpecError("the report reviewed a different packet; run spec_flow.py packet spec.md --out <path> "
                            "and review exactly that file")
        model = header.get("Reviewer") or "unknown"
        entry = {"kind": "helper", "identity": model, "model": model, "verdict": verdict,
                 "source": f"peer_review plan report {Path(args.report).name}",
                 "report": {"path": str(Path(args.report).absolute()), "sha256": report_sha}}
    elif args.agent:
        if not args.wal or not args.verdict or not args.report_file:
            raise SpecError("--agent needs --wal <main WAL>, --verdict and --report-file", EXIT_USAGE)
        agent = safe_id(args.agent)
        types = [e.get("agent_type") for e in wal_entries(checked_wal(Path(args.wal)))
                 if e.get("event") == "subagent" and e.get("agent_id") == agent]
        if not types:
            raise SpecError(f"agent {args.agent} has no subagent record in {args.wal}; only "
                            f"{', '.join(LOGGED_AGENT_TYPES)} agents are logged")
        if args.role == "adversarial" and types[0] != "red-team":
            raise SpecError("the adversarial review must come from a red-team agent, a helper receipt or a human")
        data = read_regular(Path(args.report_file), 1_000_000)
        entry = {"kind": "agent", "identity": agent, "model": types[0], "verdict": args.verdict,
                 "source": f"WAL-verified {types[0]} agent", "agent_type": types[0],
                 "report": {"path": str(Path(args.report_file).absolute()), "sha256": sha256_bytes(data)}}
    elif args.human:
        if not args.verdict or not args.source:
            raise SpecError("--human needs --verdict and --source <where the review was given>", EXIT_USAGE)
        entry = {"kind": "human", "identity": args.human.strip(), "model": None, "verdict": args.verdict,
                 "source": args.source.strip()[:200], "report": None}
        if args.report_file:
            data = read_regular(Path(args.report_file), 1_000_000)
            entry["report"] = {"path": str(Path(args.report_file).absolute()), "sha256": sha256_bytes(data)}
    else:
        raise SpecError("give one review source: --report, --agent or --human", EXIT_USAGE)
    entry.update(role=args.role, core_sha=core, at=now,
                 key=identity_key(entry["kind"], entry["model"] if entry["kind"] == "helper" else entry["identity"]))
    entries.append(entry)
    write_spec_with_reviews(spec_path, entries)
    print(json.dumps({"status": "RECORDED", "role": args.role, "verdict": entry["verdict"], "key": entry["key"],
                      "spec_core_sha": core}))
    return EXIT_OK


def cmd_attach(args, spec_policy):
    spec_path = Path(args.spec)
    entries = load_reviews(spec_path)
    write_spec_with_reviews(spec_path, entries)  # refresh the rendered Reviews section first
    text = read_spec_text(spec_path)
    spec = parse_spec(text)
    _, _, config = ticket_config(spec_policy)
    problems = lint(text, config)
    core = core_sha(text)
    author = parse_author(spec["header"].get("Author", ""))
    domain_warnings, domain_problems = domain_lint(text, getattr(args, "repo", None) or ".", spec_policy)
    problems += domain_problems  # only fails in enforce mode
    for warning in domain_warnings:
        print(f"spec-flow: warning: {warning}", file=sys.stderr)
    problems += review_problems(entries, core, author)
    if problems:
        raise SpecError("spec not attached:\n" + "\n".join("  - " + p for p in problems))
    session = Session(spec["header"]["Ticket"], spec_policy)
    records, _, _ = session.records()
    latest = current_reviews(entries, core)
    files = [("spec", spec_path.name, "text/markdown", read_spec_bytes(spec_path)),
             ("reviews", reviews_path(spec_path).name, "text/plain", read_spec_bytes(reviews_path(spec_path)))]
    for role in ROLES:
        report = latest[role].get("report")
        if report:
            data = read_regular(Path(report["path"]), 1_000_000)
            if sha256_bytes(data) != report["sha256"]:
                raise SpecError(f"the {role} review report changed since it was recorded")
            files.append((f"review-report:{role}", f"{role}-review-{Path(report['path']).name}", "text/markdown", data))
    click = spec["header"].get("Click-test", "required")
    reason = re.match(r"^not-applicable\s*\((.+)\)$", click)
    record = {"v": 1, "kind": "spec", "ticket": session.ticket.label, "issue_id": session.ticket.id,
              "actor": parse_author(args.actor), "author": author, "spec_core_sha": core,
              "spec_file_sha": sha256_bytes(read_spec_bytes(spec_path)),
              "ac": [ident for ident, _ in spec["criteria"]], "neg": [ident for ident, _, _ in spec["negatives"]],
              "click_test": {"required": not reason, "reason": reason.group(1) if reason else None},
              "signoff": spec["header"].get("Sign-off", "main"),
              "reviews": [{k: latest[role].get(k) for k in ("role", "kind", "identity", "model", "verdict",
                                                             "core_sha", "key", "source")} for role in ROLES]}
    record["key"] = content_key("spec", record["spec_file_sha"])
    reviewers = "; ".join(f"{e['role']}: {e['identity']} ({e['kind']}) {e['verdict']}" for e in record["reviews"])
    summary = (f"**Spec attached** for {session.ticket.label}: {len(record['ac'])} acceptance criteria "
               f"({', '.join(record['ac'])}), core sha256 `{core[:16]}`.\nReviewers: {reviewers}.")
    session.post("spec", summary, record, files, records)
    return EXIT_OK


def _actor_and_spec(args, spec_policy):
    session = Session(args.ticket, spec_policy)
    records, ignored, index = session.records()
    return session, records, index, session.latest_spec(records, index)


def cmd_evidence(args, spec_policy):
    session, records, _, spec = _actor_and_spec(args, spec_policy)
    acs = sorted({item.strip() for value in args.ac for item in value.split(",") if item.strip()})
    unknown = [ac for ac in acs if ac not in (spec.get("ac") or [])]
    if not acs or unknown:
        raise SpecError(f"unknown acceptance criteria for the attached spec: {', '.join(unknown) or 'none given'} "
                        f"(spec has {', '.join(spec.get('ac') or [])})", EXIT_USAGE)
    proof = {}
    if args.really_tested:
        if not args.wal:
            raise SpecError("--really-tested needs --wal <WAL that holds the REALLY_TESTED note>", EXIT_USAGE)
        found = really_tested(wal_entries(checked_wal(Path(args.wal))), args.really_tested)
        if not found:
            raise SpecError(f"no REALLY_TESTED {args.really_tested}: note (newer than its PENDING_REAL_TEST) in {args.wal}")
        proof["really_tested"] = found
    commits = [git_commit(Path(args.repo or "."), sha, args.target) for sha in args.commit or []]
    files = []
    for path in args.log or []:
        data = prepare_log(Path(path), int(spec_policy.get("max_log_bytes", 2_000_000)))
        files.append(("log", Path(path).name, "text/plain", data))
    note = (args.note or "").strip()[:2000]
    if not proof and not files and not (commits and note):
        raise SpecError("evidence needs proof: --really-tested <id> --wal <WAL>, a --log, or --commit plus a --note "
                        "naming the check; a note alone is not proof", EXIT_USAGE)
    record = {"v": 1, "kind": "evidence", "ticket": session.ticket.label, "actor": parse_author(args.actor),
              "spec_core_sha": spec["spec_core_sha"], "ac": acs, "commits": commits, "note": note or None, **proof}
    record["key"] = content_key("evidence", [acs, proof, commits, note, [sha256_bytes(f[3]) for f in files]])
    summary = (f"**Evidence** for {', '.join(acs)}: "
               + ", ".join(filter(None, [f"REALLY_TESTED {proof['really_tested']['id']}" if proof else "",
                                         f"{len(commits)} commit(s)" if commits else "",
                                         f"{len(files)} log(s)" if files else "", "note" if note else ""])) + ".")
    session.post("evidence", summary, record, files, records)
    return EXIT_OK


def cmd_click_test(args, spec_policy):
    session, records, _, spec = _actor_and_spec(args, spec_policy)
    max_log = int(spec_policy.get("max_log_bytes", 2_000_000))
    files = [("log", Path(p).name, "text/plain", prepare_log(Path(p), max_log)) for p in args.log or []]
    report_verdict, report_sha = None, None
    if args.report:
        raw = read_regular(Path(args.report), max_log)
        report_sha = sha256_bytes(raw)
        first = next((line.strip() for line in raw.decode("utf-8", "replace").splitlines() if line.strip()), "")
        match = re.match(r"^CLICK_TEST_RESULT: (PASS|FAIL)\b", first)
        if not match:
            raise SpecError("the click-test report must start with `CLICK_TEST_RESULT: PASS` or `... FAIL`", EXIT_USAGE)
        report_verdict = match.group(1).lower()
        if report_verdict != args.result:
            raise SpecError(f"--result {args.result} contradicts the report ({match.group(0)})")
        files.append(("report", Path(args.report).name, "text/plain", prepare_log(Path(args.report), max_log)))
    for path in args.screenshot or []:
        data, mime = prepare_media(Path(path), int(spec_policy.get("max_media_bytes", 15_000_000)))
        files.append(("screenshot", Path(path).name, mime, data))
    if not any(role in ("log", "report") for role, *_ in files):
        raise SpecError("a click-test needs its logs: give --log and/or --report from the click-tester", EXIT_USAGE)
    # "On deploy": bind the click-test to the deployed commit, which must contain every evidence commit so far.
    repo = Path(args.repo or ".")
    deployed = git_commit(repo, args.deployed_commit, None)
    evidence_shas = sorted({c.get("sha") for r in records if r["kind"] == "evidence"
                            and r.get("spec_core_sha") == spec["spec_core_sha"]
                            for c in r.get("commits") or [] if c.get("sha")})
    for sha in evidence_shas:  # raises "commit X is not reachable from <deployed>"
        git_commit(repo, sha, deployed["sha"])
    if args.agent_id:
        if not args.wal_dir:
            raise SpecError("--agent-id needs --wal-dir <the session WAL directory>", EXIT_USAGE)
        wal_dir = Path(os.path.expanduser(args.wal_dir)).absolute()
        if wal_dir.parent != wal_root():
            raise SpecError("--wal-dir must be a session directory under ~/.claude/wals", EXIT_USAGE)
        agent = safe_id(args.agent_id)
        main_entries = wal_entries(wal_dir / "main.jsonl")
        starts = [e for e in main_entries if e.get("event") == "subagent" and e.get("agent_id") == agent
                  and e.get("agent_type") == "click-tester"]
        if not starts:
            raise SpecError(f"agent {args.agent_id} is not a click-tester recorded in {wal_dir}/main.jsonl")
        started = str(starts[0].get("at"))
        agent_entries = wal_entries(wal_dir / f"agent-{agent}.jsonl")
        stops = sorted(str(e.get("at")) for e in main_entries + agent_entries
                       if e.get("event") == "subagent_stop" and e.get("agent_id") == agent
                       and str(e.get("at")) >= started)
        last = max([str(e.get("at")) for e in agent_entries if e.get("at")] or [started])
        tester = {"kind": "agent", "identity": agent, "agent_type": "click-tester", "started_at": started,
                  "ended_at": stops[0] if stops else None, "last_activity_at": last}
        pass_source = None
        if args.result == "pass":
            if report_sha and any(report_sha in str(e.get("note") or "") for e in agent_entries):
                pass_source = "report+agent-wal-sha256"
            elif args.really_tested and really_tested(agent_entries, args.really_tested):
                pass_source = "agent-wal-really-tested"
            else:
                raise SpecError("a pass must come from the click-tester itself: its report's sha256 in a note in "
                                f"agent-{agent}.jsonl, or --really-tested <id> found in that WAL")
    elif args.human:
        if not (args.started and args.ended):
            raise SpecError("--human needs --started and --ended (ISO 8601)", EXIT_USAGE)
        tester = {"kind": "human", "identity": args.human.strip(), "started_at": args.started,
                  "ended_at": args.ended, "last_activity_at": args.ended}
        pass_source = "self-attested" if args.result == "pass" else None
    else:
        raise SpecError("give --agent-id with --wal-dir, or --human", EXIT_USAGE)
    record = {"v": 1, "kind": "click_test", "ticket": session.ticket.label, "actor": parse_author(args.actor),
              "spec_core_sha": spec["spec_core_sha"], "result": args.result, "url": args.url, "tester": tester,
              "pass_source": pass_source, "deployed_commit": deployed, "covers_commits": evidence_shas}
    record["key"] = content_key("click_test", [tester, args.result, args.url, deployed["sha"],
                                               [sha256_bytes(f[3]) for f in files]])
    summary = (f"**Click-test {args.result.upper()}** by {tester['kind']} {tester['identity']} on {args.url} "
               f"at deployed commit {deployed['sha'][:12]} "
               f"({tester['started_at']} to {tester.get('ended_at') or 'end not recorded'}), {len(files)} file(s).")
    session.post("click_test", summary, record, files, records)
    return EXIT_OK


def cmd_signoff(args, spec_policy):
    session, records, _, spec = _actor_and_spec(args, spec_policy)
    signer = identity_key(args.kind, safe_id(args.by) if args.kind == "agent" else args.by)
    excluded = {spec.get("author")} | {r.get("key") for r in spec.get("reviews") or []} | \
        {r.get("actor") for r in records if r["kind"] in ("spec", "evidence", "click_test")}
    if signer in excluded:
        raise SpecError("the sign-off must come from someone other than the owner, the spec author and both "
                        "spec reviewers (normally the main agent, or the user)")
    record = {"v": 1, "kind": "signoff", "ticket": session.ticket.label, "actor": parse_author(args.actor),
              "spec_core_sha": spec["spec_core_sha"], "by": signer, "signer_kind": args.kind,
              "source": args.source.strip()[:300], "note": (args.note or "").strip()[:2000] or None}
    record["key"] = content_key("signoff", [signer, spec["spec_core_sha"], record["source"]])
    session.post("signoff", f"**Sign-off** by {args.kind} {args.by} on spec core `{spec['spec_core_sha'][:16]}`.",
                 record, [], records)
    return EXIT_OK


def cmd_done(args, spec_policy, apply=False):
    session = Session(args.ticket, spec_policy)
    records, ignored, index = session.records()
    issue = session.adapter.issue(session.ticket.id) or {}
    issue["_label"] = session.ticket.label
    result = evaluate(records, index, issue, ignored)
    if args.json:
        print(json.dumps(dict(result, ticket=session.ticket.label), indent=1))
    else:
        print(format_result(session.ticket.label, result))
    if not result["ready"]:
        return EXIT_MISSING
    if not apply:
        return EXIT_OK
    if getattr(session.ticket, "closed", False):
        if session.ticket.status == "done":  # a retry after a lost response: the transition already happened
            print(json.dumps({"status": "ALREADY_DONE", "ticket": session.ticket.label}))
            return EXIT_OK
        print(f"{session.ticket.label} is already closed ({session.ticket.status}); nothing to apply")
        return EXIT_MISSING
    note = (f"Spec gate READY (spec core {result['spec_core_sha'][:16]}): every acceptance criterion has "
            "evidence, both spec reviews accepted, click-test and sign-off recorded on this ticket.")
    ok, detail = session.adapter.close_done(session.ticket.id, note)
    if not ok:
        print(f"TRACKER_REFUSED: GoodQA did not mark {session.ticket.label} done ({detail}); the ticket is unchanged. "
              "GoodQA's own independent-acceptance rule may need a person to close it.")
        return EXIT_TRACKER
    print(f"{session.ticket.label} marked done.")
    return EXIT_OK


def cmd_doctor(args, spec_policy):
    _, _, config = ticket_config(spec_policy)
    route = (spec_policy.get("projects") or {}).get(args.project.lower()) or {}
    if not route.get("project_id"):
        raise SpecError(f"project {args.project} has no route in spec_policy.json projects", EXIT_USAGE)
    adapter = make_adapter(config, spec_policy, args.project, time.monotonic() + 60)
    data = adapter.call("get_project", {"projectId": route["project_id"]})
    if "__error__" in data:
        print(json.dumps({"status": "UNREACHABLE", "project": args.project, "error": data["__error__"]}))
        return EXIT_UNREACHABLE
    permissions = set(data.get("permissions") or [])
    needed = {"attachment:create", "comment:add", "issue:transition"}
    print(json.dumps({"status": "OK" if needed <= permissions else "MISSING_PERMISSIONS", "project": args.project,
                      "missing": sorted(needed - permissions)}))
    return EXIT_OK if needed <= permissions else EXIT_MISSING


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("hook", help="Claude Code PreToolUse hook for GoodQA status changes")
    gate = sub.add_parser("plan-gate", help="run the plan-review ticket gate on a packet")
    gate.add_argument("--repo", required=True)
    gate.add_argument("--packet", required=True)
    new = sub.add_parser("new", help="write a spec skeleton for a ticket")
    new.add_argument("--ticket", required=True)
    new.add_argument("--out", required=True)
    new.add_argument("--author", required=True, help="agent:<id> (model), human:<name> or model:<name>")
    new.add_argument("--repo", default=".", help="repo scanned for blockchain signals (default .)")
    for name in ("lint", "packet"):
        item = sub.add_parser(name)
        item.add_argument("spec")
        if name == "lint":
            item.add_argument("--repo", default=".", help="repo scanned for blockchain signals (default .)")
        if name == "packet":
            item.add_argument("--out", required=True)
    review = sub.add_parser("review", help="record an adversarial or acceptance review of the spec")
    review.add_argument("spec")
    review.add_argument("--role", choices=ROLES, required=True)
    review.add_argument("--report", help="peer_review.py plan report for the spec packet")
    review.add_argument("--agent", help="native agent id (verified in --wal)")
    review.add_argument("--wal", help="main session WAL")
    review.add_argument("--human", help="reviewer name")
    review.add_argument("--source", help="where a human review was given")
    review.add_argument("--verdict", choices=("ACCEPT", "BLOCK"))
    review.add_argument("--report-file")
    attach = sub.add_parser("attach", help="attach the reviewed spec to its ticket")
    attach.add_argument("spec")
    attach.add_argument("--repo", default=".", help="repo scanned for blockchain signals (default .)")
    evidence = sub.add_parser("evidence", help="attach proof for acceptance criteria")
    click = sub.add_parser("click-test", help="attach a click-test record")
    signoff = sub.add_parser("signoff", help="record a sign-off on the current spec")
    for item in (attach, evidence, click, signoff):
        item.add_argument("--actor", required=True, help="who is posting: agent:<id>, human:<name>")
    for item in (evidence, click, signoff):
        item.add_argument("--ticket", required=True)
    evidence.add_argument("--ac", action="append", required=True, help="AC-1 or AC-1,AC-2 (repeatable)")
    evidence.add_argument("--really-tested")
    evidence.add_argument("--wal")
    evidence.add_argument("--commit", action="append")
    evidence.add_argument("--repo")
    evidence.add_argument("--target", help="ref the commits must be reachable from")
    evidence.add_argument("--log", action="append")
    evidence.add_argument("--note")
    click.add_argument("--result", choices=("pass", "fail"), required=True)
    click.add_argument("--url", required=True)
    click.add_argument("--deployed-commit", required=True, help="the commit that was deployed and tested")
    click.add_argument("--repo", help="checkout holding the deployed and evidence commits (default .)")
    click.add_argument("--agent-id")
    click.add_argument("--wal-dir")
    click.add_argument("--human")
    click.add_argument("--started")
    click.add_argument("--ended")
    click.add_argument("--really-tested")
    click.add_argument("--report")
    click.add_argument("--log", action="append")
    click.add_argument("--screenshot", action="append")
    signoff.add_argument("--by", required=True)
    signoff.add_argument("--kind", choices=("agent", "human"), required=True)
    signoff.add_argument("--source", required=True)
    signoff.add_argument("--note")
    for name in ("status", "done"):
        item = sub.add_parser(name)
        item.add_argument("--ticket", required=True)
        item.add_argument("--json", action="store_true")
        if name == "done":
            item.add_argument("--apply", action="store_true", help="request status done when READY")
    doctor = sub.add_parser("doctor", help="check that the routed key can work in a project")
    doctor.add_argument("--project", required=True)
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    if args.command == "hook":
        try:
            payload = json.load(sys.stdin)
        except ValueError:
            return 0  # not ours to judge; the commit-policy hook reports malformed payloads
        if not TOOL_PATTERN.match(str(payload.get("tool_name") or "")):
            return 0  # every other tool call stays independent of the policy file
        try:
            spec_policy = load_spec_policy()
        except (OSError, ValueError) as error:
            print(f"spec-flow: cannot load {POLICY_FILE}: {error}; fix it or set mode off", file=sys.stderr)
            return 2
        try:
            code, text = run_hook(payload, spec_policy)
        except Exception as error:  # never crash into an unexplained block
            code = 2 if spec_policy.get("mode") == "enforce" and enforced_ids(spec_policy) else 0
            text = f"spec-flow hook error ({type(error).__name__}); {'blocking' if code else 'allowing'}"
        if len(text) > MAX_HOOK_TEXT:
            text = text[:MAX_HOOK_TEXT] + "\n...(spec-flow output cut; run spec_flow.py status for the full list)"
        if text:
            print(text, file=sys.stderr)  # exit 2: Claude Code feeds stderr to the model
            if code == 0:
                # Claude never sees stderr from an exit-0 PreToolUse hook; additionalContext reaches the model
                # without making a permission decision, so the normal permission flow still applies.
                print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "additionalContext": text}}))
        return code
    try:
        spec_policy = load_spec_policy()
        if args.command == "plan-gate":
            code, text = plan_ticket_gate(Path(args.repo), read_spec_text(Path(args.packet)),
                                          spec_policy=spec_policy)
            if text:
                print(text, file=sys.stderr)
            return code
        handlers = {"new": cmd_new, "lint": cmd_lint, "packet": cmd_packet, "review": cmd_review,
                    "attach": cmd_attach, "evidence": cmd_evidence, "click-test": cmd_click_test,
                    "signoff": cmd_signoff, "status": cmd_done, "doctor": cmd_doctor}
        if args.command == "done":
            return cmd_done(args, spec_policy, apply=args.apply)
        return handlers[args.command](args, spec_policy)
    except SpecError as error:
        print(f"spec-flow: {error}", file=sys.stderr)
        return error.code
    except ta.TicketSystemUnavailable as error:
        print(f"spec-flow: ticket system unavailable: {error}", file=sys.stderr)
        return EXIT_UNREACHABLE
    except (OSError, ValueError) as error:
        print(f"spec-flow: {error}", file=sys.stderr)
        return EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main())
