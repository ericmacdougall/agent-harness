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

import safe_input
import ticket_adapters as ta

HERE = Path(__file__).resolve().parent
POLICY_FILE = HERE / "spec_policy.json"
TEMPLATE_FILE = HERE / "spec_template.md"
RECORD_FENCE = "harness-spec-record"
RECORD_BLOCK = re.compile(r"```" + RECORD_FENCE + r"\n(.*?)\n```", re.S)
NAMESPACE = uuid.UUID("8f2a4f2e-3c1b-4b7e-9d55-6a1f0c2b7e10")
KINDS = ("spec", "evidence", "click_test", "signoff")
ROLES = ("adversarial", "acceptance")
REVIEW_POLICY_SCHEMA = 1
SINGLE_REVIEW_BASES = ("small", "feature-flag")
SPEC_PLAN_ARTIFACT = "KIMI_SPEC_PLAN_SIGNOFF_V1"
# Every agent type is logged by SubagentStart (goodqa#14613); only these may record a spec review.
REVIEWER_AGENT_TYPES = ("task-owner", "click-tester", "fixer", "red-team")
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

SPEC_LOCAL_KEYS = ("projects", "enforced_projects")


def load_spec_policy(path: Path = POLICY_FILE) -> dict:
    """The shipped policy is generic. Personal values (your GoodQA projects, which projects are enforced)
    live in the untracked spec_policy.local.json beside it, which may set only SPEC_LOCAL_KEYS. A profile
    that exists but cannot be read fails closed (ValueError)."""
    with open(path, encoding="utf-8") as handle:
        policy = json.load(handle)
    local = Path(path).with_name("spec_policy.local.json")
    if os.path.lexists(local) and not local.is_file():
        raise ValueError(f"{local} exists but is not a readable regular file")
    if local.is_file():
        try:
            overlay = safe_input.safe_json_loads(safe_input.read_bounded(local, 1 << 20))
        except (OSError, ValueError, safe_input.InputRejected) as error:
            raise ValueError(f"{local} is not a readable JSON object: {error}") from error
        if not isinstance(overlay, dict):
            raise ValueError(f"{local} is not a JSON object")
        forbidden = sorted(k for k in overlay if k not in SPEC_LOCAL_KEYS and not k.startswith("_"))
        if forbidden:
            raise ValueError(f"{local} may only set {list(SPEC_LOCAL_KEYS)}, not {forbidden}")
        routes = overlay.get("projects") or {}
        if not isinstance(routes, dict) or not isinstance(overlay.get("enforced_projects", []), list):
            raise ValueError(f"{local}: projects must be an object and enforced_projects a list")
        for slug, route in routes.items():
            if not isinstance(route, dict) or set(route) - {"project_id", "org_id", "key_file"}:
                raise ValueError(f"{local}: project route {slug!r} may only set project_id, org_id, key_file")
        policy = {**policy, **{k: v for k, v in overlay.items() if k in SPEC_LOCAL_KEYS}}
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


def declared_owners(spec):
    """None is legacy; a malformed explicit declaration never selects legacy."""
    header = spec["header"]
    if "Owners" not in header:
        return None
    values = [item.strip() for item in header["Owners"].split(",")]
    if ("Owners" in spec.get("duplicate_headers", ()) or not 1 <= len(values) <= 8
            or any(re.fullmatch("agent:" + UUID.lower(), value) is None or value != value.lower() for value in values)
            or len(set(values)) != len(values) or parse_author(header.get("Author", "")) not in values):
        raise SpecError("Owners must list 1..8 unique canonical native agent UUID identities and include the author", EXIT_USAGE)
    return values


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
    header, sections, current, duplicate_headers = {}, {}, None, []
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
            field = re.match(r"^(Ticket|Author|Owners|Click-test|Sign-off|Review-policy):\s*(.*)$", line)
            if field:
                if field.group(1) in header:
                    duplicate_headers.append(field.group(1))
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
            "negatives": negatives, "stray": stray, "core": core, "duplicate_headers": duplicate_headers}


def standard_review_policy() -> dict:
    return {"schema": REVIEW_POLICY_SCHEMA, "mode": "standard", "basis": None, "reason": None}


# #134 red-team P5: a spec whose text touches these keeps both reviews, whatever its Review-policy says
TWO_REVIEW_DOMAINS = re.compile(
    # B5 (step-1 red-team): "author" and a harness "session" are not auth; OAuth, sign-in, JWT, DB, truncate, CSRF
    # and ACL are
    r"\bauth(?:n|z|entic|ori[sz]|\b)|unauth|oauth|sign[- ]?in|log[- ]?in\b|password|credential|\btokens?\b|"
    r"\bjwt\b|secret|session (?:token|cookie|key|fixation|hijack)|permission|privilege|\bacl\b|csrf|xss|"
    r"secur|encrypt|privacy|\bpii\b|\bdata\b|database|\bdb\b|\bschema|delet|truncat|\bdrop (?:the )?\w+ "
    r"(?:table|column)|backup|restore|migrat", re.I)


def single_review_domain_problem(text: str):
    """The lint problem for a single-review spec that touches auth/security/data/migration, else None."""
    spec = parse_spec(text)
    policy, _ = review_policy_from_header(spec["header"].get("Review-policy"))
    if policy.get("mode") != "single-adversarial":
        return None
    body = "\n".join([str(spec["header"].get("Review-policy") or "")] + [
        "\n".join(spec["sections"].get(name, [])) for name in
        ("Outcome", "Scope", "Acceptance criteria", "Negative cases", "Risks")])
    hit = TWO_REVIEW_DOMAINS.search(body)
    if hit:
        return ("Review-policy single-adversarial is refused: the spec touches auth, security, data or migration "
                "(%r); keep `standard` (two reviews)" % hit.group(0))
    return None


def review_policy_from_header(value) -> tuple:
    """(canonical policy, lint problem). Missing metadata deliberately means the ordinary two reviews."""
    if value is None:
        return standard_review_policy(), None
    if value == "standard":
        return standard_review_policy(), None
    match = re.fullmatch(r"single-adversarial \((small|feature-flag): ([^<>]+)\)", str(value or "").strip())
    reason = match.group(2).strip() if match else ""
    if match and len(reason) >= 10:
        return {"schema": REVIEW_POLICY_SCHEMA, "mode": "single-adversarial",
                "basis": match.group(1), "reason": reason}, None
    return standard_review_policy(), (
        "Review-policy must be `standard` or `single-adversarial (small: <auditable reason, 10+ chars>)` / "
        "`single-adversarial (feature-flag: <flag and rollout evidence, 10+ chars>)`; missing or ambiguous "
        "metadata always requires both reviews")


def required_review_roles(policy) -> tuple:
    """One central fail-safe role calculation for local attach and remote done evaluation.

    Only the canonical, versioned single-review record produced from an explicit spec header qualifies. Legacy,
    malformed, ambiguous or future-shaped records all fall back to the ordinary two independent reviews.
    """
    if (isinstance(policy, dict) and policy.get("schema") == REVIEW_POLICY_SCHEMA
            and policy.get("mode") == "single-adversarial" and policy.get("basis") in SINGLE_REVIEW_BASES
            and isinstance(policy.get("reason"), str) and len(policy["reason"].strip()) >= 10
            and set(policy) == {"schema", "mode", "basis", "reason"}):
        return ("adversarial",)
    return ROLES


PLACEHOLDER = re.compile(r"<[^<>\n]{2,80}>")


def lint(text: str, config: dict | None = None, check_provenance: bool = True, spec_policy: dict | None = None) -> list:
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
        declared_owners(spec)
    except SpecError as error:
        problems.append(str(error))
    click = header.get("Click-test", "")
    reason = re.match(r"^not-applicable\s*\((.{10,})\)$", click)
    if click != "required" and not reason:
        problems.append("Click-test must be `required` or `not-applicable (<reason, 10+ chars>)`")
    if header.get("Sign-off", "main") not in ("main", "human"):
        problems.append("Sign-off must be `main` or `human`")
    _, review_policy_problem = review_policy_from_header(header.get("Review-policy"))
    if review_policy_problem:
        problems.append(review_policy_problem)
    domain_problem = single_review_domain_problem(text)
    if domain_problem:
        problems.append(domain_problem)
    for name in ("Outcome", "Scope", "Acceptance criteria", "Negative cases", "Risks"):
        body = "\n".join(spec["sections"].get(name, [])).strip()
        if name not in spec["sections"]:
            problems.append(f"missing section `## {name}`")
        elif not body:
            problems.append(f"section `## {name}` is empty")
        elif PLACEHOLDER.search(body):
            problems.append(f"section `## {name}` still holds a template placeholder like <...>")
    if spec_policy and spec_policy.get("resource_budget_gate", "off") == "enforce":
        import resource_budget  # structure only here; peer_review.py plan also compares the numbers to live capacity
        problems.extend(resource_budget.lint_budget(text)[0])
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
        detected, failure = dg.detect_full(Path(repo))
        block = dg.render_block([d["domain"] for d in detected], repo, detected) if detected else ""
        if failure and (failure.startswith("scan truncated") or "too deeply nested" in failure):
            block = (block or "## Domain checklist\n") + dg.incomplete_notice(failure, [d["domain"] for d in detected])
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
        if (failure.startswith("scan truncated") or "too deeply nested" in failure) and dg.allow_truncated(spec_policy):
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


def review_problems(entries: list, core: str, author_key: str | None, required_roles=ROLES, owners=()) -> list:
    problems = []
    latest = current_reviews(entries, core)
    for role in required_roles:
        entry = latest.get(role)
        if not entry:
            stale = any(item.get("role") == role for item in entries)
            problems.append(f"no {role} review of the current spec" + (" (earlier reviews are stale: the spec "
                            "changed after review)" if stale else ""))
        elif entry.get("verdict") != "ACCEPT":
            problems.append(f"{role} review is {entry.get('verdict')}: fix the spec and get a new review")
    keys = {role: latest[role].get("key") for role in required_roles if role in latest}
    if len(keys) == 2 and keys["adversarial"] == keys["acceptance"]:
        problems.append("both reviews come from the same reviewer/model; get the other role from a different model, "
                        "a native red-team agent, or a human")
    for role, key in keys.items():
        if author_key and key == author_key:
            problems.append(f"the {role} reviewer is the spec author")
        elif key in (owners or ()):
            problems.append(f"the {role} reviewer is a declared component owner")
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
    if lines and lines[0].startswith("# "):
        index = 1
        while index < len(lines) and not lines[index].strip():
            index += 1
    while index < len(lines) and lines[index].strip():
        field = re.match(r"^([A-Za-z][A-Za-z0-9 -]*):\s*(.*)$", lines[index])
        if field:
            header[field.group(1)] = field.group(2).strip()
        index += 1
    body = [line for line in lines[index:] if line.strip() and line.strip() != "---"]
    verdict = re.match(r"^PLAN_RESULT: (ACCEPT|BLOCK)\b", body[0].strip()) if body else None
    if re.match(r"(?i)^yes\b", header.get("Advisory", "")):  # an advisory (for example Kimi) opinion is never a review verdict
        verdict = None
    return header, (verdict.group(1) if verdict else None), sha256_bytes(data.encode("utf-8", "surrogateescape"))


def spec_plan_signoff_problem(header: dict, verdict: str | None):
    """Strict shape for the dedicated Kimi spec-plan artifact; legacy advisory reports never enter this path."""
    if header.get("Artifact") != SPEC_PLAN_ARTIFACT:
        return f"Artifact must be {SPEC_PLAN_ARTIFACT}"
    expected = {
        "Stage": "plan",
        "Packet-Binding": "exact-spec-core-sha256",
        "Freshness": "current-packet-only",
        "Review-Input": "exact packet text only (no repository snapshot, no tools)",
        "Advisory": "no; constrained spec-plan signoff only",
    }
    for field, value in expected.items():
        if header.get(field) != value:
            return f"spec-plan signoff has missing or invalid {field}"
    reviewer, model = header.get("Reviewer") or "", header.get("Reviewed-Model") or ""
    if not reviewer or not re.fullmatch(r"kimi-code/[a-z0-9][a-z0-9._-]{0,63}", model) or model not in reviewer:
        return "spec-plan signoff needs bound reviewer identity and Reviewed-Model"
    try:
        reviewed_at = datetime.fromisoformat((header.get("Reviewed-At") or "").replace("Z", "+00:00"))
        if reviewed_at.tzinfo is None:
            raise ValueError("timezone missing")
    except ValueError:
        return "spec-plan signoff needs an ISO 8601 Reviewed-At with timezone"
    if verdict not in ("ACCEPT", "BLOCK"):
        return "spec-plan signoff has no PLAN_RESULT verdict"
    return None


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
    return prepare_log_bytes(path, data, original)


def prepare_log_bytes(path: Path, data: bytes, original: int):
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


_NATIVE_REVIEW_COLUMNS = ("id", "source", "thread_source", "originator", "agent_path", "agent_role",
                          "attached_thread_parent_id")
_NATIVE_REVIEW_QUERY = "SELECT " + ", ".join(
    f"CASE WHEN {name} IS NULL OR (typeof({name})='text' AND length(CAST({name} AS BLOB))<=512) "
    f"THEN {name} ELSE X'' END" for name in _NATIVE_REVIEW_COLUMNS
) + ", CASE WHEN typeof(archived)='integer' THEN archived ELSE X'' END FROM main.threads WHERE id IN (?,?) LIMIT 3"


def _native_path(path, uid, *, directory=False, maximum=None, optional=False):
    try:
        item = path.lstat()
    except FileNotFoundError:
        if optional:
            return None
        raise
    if (path.resolve(strict=True) != path or item.st_uid != uid or item.st_mode & 0o022
            or (not stat.S_ISDIR(item.st_mode) if directory else not stat.S_ISREG(item.st_mode))
            or (not directory and (item.st_nlink != 1 or (maximum is not None and item.st_size > maximum)))):
        raise ValueError("unqualified native metadata path")
    return item.st_dev, item.st_ino, item.st_uid, item.st_mode


def _native_wal_members(path, uid, maximum):
    """[(member path, binding)] for a native WAL's whole segment chain: closed segments in order, then the live file.
    Every member is qualified like a single WAL (regular, one link, our uid, not group/world writable, within
    `maximum`). Any chain problem, a gap, a segment that is not a regular file or a missing live file raises ValueError:
    a native proof is never made over part of a WAL (goodqa#16751)."""
    import wal_segments as ws
    stem, seq = ws.parse_name(path.name)
    if stem is None or seq is not None:
        raise ValueError("native WAL name unavailable")
    chain = ws.chain(str(path.parent), stem)
    if [p for p in chain.problems if p["code"] not in ("schema_newer", "marker_info")] or chain.live is None:
        raise ValueError("native WAL segment chain incomplete")
    members = [path.parent / seg.name for seg in chain.segments] + [path.parent / chain.live.name]
    return [(member, _native_path(member, uid, maximum=maximum)) for member in members]


def _native_wal_binding(path, uid, maximum):
    return tuple(binding for _member, binding in _native_wal_members(path, uid, maximum))


def _native_read_member(member, bound, room, limit):
    """One member of a native WAL chain, read under the _native_read stability rules; returns (bytes, (size, mtime_ns,
    ctime_ns)). `room` is what is left of the chain's `limit`."""
    uid = bound[2]
    fd = os.open(member, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        first = os.fstat(fd)
        if (first.st_dev, first.st_ino, first.st_uid, first.st_mode) != bound:
            raise ValueError("native file changed")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(room + 1)
        last = os.fstat(fd)
        if ((first.st_size, first.st_mtime_ns, first.st_ctime_ns) !=
                (last.st_size, last.st_mtime_ns, last.st_ctime_ns) or len(raw) != first.st_size
                or len(raw) > room or _native_path(member, uid, maximum=limit) != bound):
            raise ValueError("native file changed")
        return raw, (first.st_size, first.st_mtime_ns, first.st_ctime_ns)
    finally:
        os.close(fd)


def _native_read_wal(path, identity, limit, *, binding=None):
    """The logical bytes of a native WAL (open markers dropped), read member by member under the same stability rules
    as _native_read: each member's binding, size, mtime and ctime must hold throughout, the chain must not change
    while it is read, and the sum of the members is bounded by `limit`. For a WAL that never rotated the result is the
    file's bytes unchanged."""
    import wal_segments as ws
    home, uid = identity["home"], identity["uid"]
    parents = [home, *(p for p in reversed(path.parents) if p != home and p.is_relative_to(home))]
    directories = [_native_path(p, uid, directory=True) for p in parents]
    members = _native_wal_members(path, uid, limit)
    before = tuple(item for _member, item in members)
    if binding is not None and before != binding:
        raise ValueError("native identity file changed")
    pieces, total, seen = [], 0, []
    for member, bound in members:
        raw, state = _native_read_member(member, bound, limit - total, limit)
        seen.append((member, state))
        first_line, newline, rest = raw.partition(b"\n")
        if newline and ws.parse_marker(first_line.rstrip(b"\r")) is not None:
            raw = rest  # an open marker is linkage, not a row
        if member is not members[-1][0] and raw and not raw.endswith(b"\n"):
            raise ValueError("native WAL segment is torn")
        total += len(raw)
        pieces.append(raw)
    for member, state in seen:  # nothing may have been appended or rewritten after its member was read
        item = member.lstat()
        if (item.st_size, item.st_mtime_ns, item.st_ctime_ns) != state:
            raise ValueError("native file changed")
    if (tuple(item for _member, item in _native_wal_members(path, uid, limit)) != before
            or [_native_path(p, uid, directory=True) for p in parents] != directories):
        raise ValueError("native file changed")
    return b"".join(pieces)


def _native_database_binding(home, uid):
    db = home / ".codex/state_5.sqlite"
    return (_native_path(home, uid, directory=True),
            _native_path(db.parent, uid, directory=True),
            _native_path(db, uid, maximum=256 * 1024 * 1024),
            _native_path(db.with_name(db.name + "-wal"), uid, maximum=64 * 1024 * 1024, optional=True),
            _native_path(db.with_name(db.name + "-shm"), uid, maximum=4 * 1024 * 1024, optional=True))


def _native_review_rows(home, uid, agent, parent, *, rollout=False):
    """Historical identity projection, never a current-caller or main-role grant."""
    import sqlite3
    db = home / ".codex/state_5.sqlite"
    deadline = time.monotonic() + 0.20
    before = _native_database_binding(home, uid)
    descriptor = os.open(db, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        item = os.fstat(descriptor)
        if (item.st_dev, item.st_ino, item.st_uid, item.st_mode) != before[2]:
            raise ValueError("native database changed")
        header = os.pread(descriptor, 20, 0)
    finally:
        os.close(descriptor)
    if len(header) != 20 or header[:16] != b"SQLite format 3\0":
        raise ValueError("unsupported native database")
    if header[18:20] == b"\x02\x02":
        if before[3] is None or before[4] is None:
            raise ValueError("native WAL companions unavailable")
    elif header[18:20] != b"\x01\x01" or before[3] is not None or before[4] is not None:
        raise ValueError("unsupported native journal state")
    if _native_path(db.with_name(db.name + "-journal"), uid, maximum=64 * 1024 * 1024, optional=True):
        raise ValueError("native journal unavailable")
    connection = sqlite3.connect(db.as_uri() + "?mode=ro", uri=True, timeout=0.05)
    try:
        connection.set_progress_handler(lambda: int(time.monotonic() > deadline), 100)
        connection.execute("PRAGMA trusted_schema=OFF")
        connection.execute("PRAGMA query_only=ON")
        connection.execute("BEGIN")
        tables = connection.execute("PRAGMA main.table_list('threads')").fetchmany(2)
        if len(tables) != 1 or tables[0][:3] != ("main", "threads", "table"):
            raise ValueError("native identity table unavailable")
        columns = (*_NATIVE_REVIEW_COLUMNS, "archived", *(("rollout_path", "model_provider") if rollout else ()))
        slots = ",".join("?" for _ in columns)
        count = connection.execute(
            f"SELECT count(*) FROM pragma_table_xinfo('threads','main') WHERE name IN ({slots}) AND hidden=0",
            columns).fetchone()
        if count != (len(columns),):
            raise ValueError("native identity columns unavailable")
        query = _NATIVE_REVIEW_QUERY
        if rollout:
            query = query.replace(" FROM main.threads", ", CASE WHEN typeof(rollout_path)='text' AND "
                                  "length(CAST(rollout_path AS BLOB))<=1024 THEN rollout_path END, "
                                  "CASE WHEN typeof(model_provider)='text' AND length(CAST(model_provider AS BLOB))<=128 "
                                  "THEN model_provider END FROM main.threads")
        rows = connection.execute(query, (agent, parent)).fetchmany(3)
    finally:
        connection.close()
    if time.monotonic() > deadline or _native_database_binding(home, uid) != before or len(rows) != 2:
        raise ValueError("native identity snapshot unavailable")
    if any(any(value is not None and type(value) is not str for value in row[:7])
           or type(row[7]) is not int or row[7] not in (0, 1) for row in rows):
        raise ValueError("native identity fields unavailable")
    indexed = {row[0]: row for row in rows}
    if set(indexed) != {agent, parent}:
        raise ValueError("native identity rows unavailable")
    return indexed


def _native_review_source(path, agent, role):
    expected = {"adversarial": "harness_red_team", "acceptance": "harness_reviewer"}.get(role)
    identity = _native_agent_source(path, agent, expected, purpose="review")
    if identity is None:
        return None
    return {"family": "codex", "agent_type": expected, "model": None,
            "source": "Codex native reviewer metadata; parent bound to native WAL session"}


def _native_agent_source(path, agent, expected, *, purpose):
    """Bind a native child and its main WAL by the account's stored metadata."""
    click = purpose == "click-test"
    raw = Path(os.path.expanduser(str(path))).absolute()
    try:
        resolved = raw.resolve()
    except (OSError, RuntimeError):
        raise SpecError(f"{purpose} WAL path unavailable", EXIT_USAGE) from None
    # Legacy operation must not acquire a new platform/SQLite prerequisite.
    def native_shape(value):
        return any(value.parts[index:index + 2] == (".agent-harness", "codex-wals")
                   for index in range(len(value.parts) - 1))
    if not native_shape(raw) and not native_shape(resolved):
        return None
    try:
        import pwd
        import sqlite3
    except ImportError:
        raise SpecError(f"native {purpose} metadata unsupported", EXIT_USAGE) from None
    uid = os.getuid()
    try:
        home = Path(pwd.getpwuid(uid).pw_dir)
        root = home / ".agent-harness/codex-wals"
        native = raw.is_relative_to(root) or resolved.is_relative_to(root)
        if not native:
            raise ValueError("unqualified native review family")
        parts = raw.relative_to(root).parts
        if (raw != resolved or ".." in raw.parts or len(parts) != 2 or parts[1] != "main.jsonl"
                or re.fullmatch(UUID, parts[0]) is None or re.fullmatch(UUID, agent) is None or agent == parts[0]):
            raise ValueError("native review WAL shape unavailable")
        parent = parts[0]
        directories = (home, home / ".agent-harness", root, raw.parent)
        before = tuple(_native_path(item, uid, directory=True) for item in directories)
        wal_binding = _native_wal_binding(raw, uid, 64_000_000)
        if click and (parent != parent.lower() or agent != agent.lower()):
            raise ValueError("noncanonical child identity")
        rows = _native_review_rows(home, uid, agent, parent, rollout=True) if click else _native_review_rows(home, uid, agent, parent)
        parent_row, child = rows[parent], rows[agent]
        if (parent_row[1:4] != ("vscode", "user", "Codex Desktop") or any(parent_row[i] is not None for i in (4, 5, 6))
                or (click and parent_row[7] != 0)
                or child[2:4] != ("subagent", "Codex Desktop") or child[5] != expected or expected is None
                or child[6] not in (None, parent)):
            raise ValueError("native reviewer family or role unavailable")
        safe_input.safe_json_loads(child[1], max_depth=8, max_bytes=512)
        def unique_pairs(items):
            value = {}
            for key, item in items:
                if key in value:
                    raise ValueError("duplicate native metadata key")
                value[key] = item
            return value
        source = json.loads(child[1], object_pairs_hook=unique_pairs,
                            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("invalid native number")))
        if (not isinstance(source, dict) or set(source) != {"subagent"}
                or not isinstance(source["subagent"], dict) or set(source["subagent"]) != {"thread_spawn"}):
            raise ValueError("native reviewer source unavailable")
        spawn = source["subagent"]["thread_spawn"]
        if (not isinstance(spawn, dict) or set(spawn) - {"parent_thread_id", "depth", "agent_path", "agent_role", "agent_nickname"}
                or spawn.get("parent_thread_id") != parent or type(spawn.get("depth")) is not int or spawn["depth"] != 1
                or not child[4] or spawn.get("agent_path") != child[4] or spawn.get("agent_role") != expected):
            raise ValueError("native reviewer parent or role conflicts")
        if (tuple(_native_path(item, uid, directory=True) for item in directories) != before
                or _native_wal_binding(raw, uid, 64_000_000) != wal_binding):
            raise ValueError("native review WAL binding changed")
        identity = {"home": home, "uid": uid, "parent": parent, "agent_path": child[4],
                "main": raw, "main_binding": wal_binding, "rollout": child[8] if click else None,
                "archived": bool(child[7]), "child_source": source,
                "child_provider": child[9] if click else None, "parent_provider": parent_row[9] if click else None}
        if purpose == "owner":
            identity["native_binding_sha256"] = sha256_bytes(json.dumps(
                {"parent": parent_row, "owner": child}, sort_keys=True).encode())
        return identity
    except (OSError, ValueError, TypeError, KeyError, sqlite3.Error, RuntimeError):
        label = "click-tester" if click else "reviewer"
        raise SpecError(f"native {label} metadata unavailable or conflicting", EXIT_USAGE) from None


NATIVE_CLICK_PREFIX = "CLICK_TEST_WITNESS_V1 "
NATIVE_CLICK_SOURCE = "codex-native-click-witness-v1"
NATIVE_CLICK_ROLE = "harness_click_tester"
NATIVE_ROLLOUT_LIMIT = 16_000_000
NATIVE_CLICK_WAL_LIMIT = 4_000_000
MAX_NATIVE_CLICK_CANDIDATES = 16


def _native_read(path, identity, limit, *, binding=None):
    """Bound one local file and its ancestors throughout the read."""
    home, uid = identity["home"], identity["uid"]
    parents = [home, *(p for p in reversed(path.parents) if p != home and p.is_relative_to(home))]
    directories = [_native_path(p, uid, directory=True) for p in parents]
    before = _native_path(path, uid, maximum=limit)
    if binding is not None and before != binding:
        raise ValueError("native identity file changed")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        first = os.fstat(fd)
        if (first.st_dev, first.st_ino, first.st_uid, first.st_mode) != before:
            raise ValueError("native file changed")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(limit + 1)
        last = os.fstat(fd)
        if ((first.st_size, first.st_mtime_ns, first.st_ctime_ns) !=
                (last.st_size, last.st_mtime_ns, last.st_ctime_ns) or len(raw) != first.st_size or len(raw) > limit
                or _native_path(path, uid, maximum=limit) != before
                or [_native_path(p, uid, directory=True) for p in parents] != directories):
            raise ValueError("native file changed")
        return raw
    finally:
        os.close(fd)


def _native_json(raw, limit):
    safe_input.safe_json_loads(raw, max_depth=40, max_bytes=limit)
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate native JSON key")
            result[key] = value
        return result
    def constant(_value):
        raise ValueError("non-finite number")
    value = json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    if not isinstance(value, dict):
        raise ValueError("native document is not an object")
    return value


def _native_stamp(value):
    if not isinstance(value, str) or len(value) > 40:
        raise ValueError("native timestamp missing")
    stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if stamp.tzinfo is None:
        raise ValueError("native timestamp is not timezone aware")
    return stamp


def _check_native_inherited_header(entry, identity, first_at, observed_start):
    """Accept the one Desktop fork prologue, which belongs to the already-bound parent."""
    payload = entry.get("payload")
    parent = identity["parent"]
    if (entry.get("type") != "session_meta" or not isinstance(payload, dict)
            or payload.get("id") != parent or payload.get("session_id") != parent
            or payload.get("source") != "vscode" or payload.get("thread_source") != "user"
            or payload.get("originator") != "Codex Desktop" or not identity["parent_provider"]
            or payload.get("model_provider") != identity["parent_provider"]
            or any(payload.get(key) is not None for key in ("parent_thread_id", "forked_from_id", "agent_path",
                                                           "agent_role", "agent_nickname", "subagent_history_start_ordinal"))
            or not first_at <= _native_stamp(entry.get("timestamp")) <= observed_start):
        raise ValueError("native inherited rollout header mismatched")


def _native_click_proof(identity, agent, line, started, ended):
    """Require the same statement in the child's native final answer and own WAL."""
    try:
        raw_rollout = identity["rollout"]
        if not isinstance(raw_rollout, str):
            raise ValueError("native rollout unavailable")
        rollout = Path(raw_rollout)
        codex = identity["home"] / ".codex"
        relative = rollout.relative_to(codex)
        if (not re.fullmatch(rf"rollout-[0-9T-]+-{re.escape(agent)}\.jsonl", rollout.name)
                or not re.fullmatch(r"sessions/[0-9]{4}/[0-9]{2}/[0-9]{2}|archived_sessions", str(relative.parent))
                or (relative.parts[0] == "archived_sessions") != identity["archived"]
                or ".." in relative.parts):
            raise ValueError("native rollout path unavailable")
        start, end = _native_stamp(started), _native_stamp(ended)
        if start > end:
            raise ValueError("native observed time order invalid")
        parent = identity["parent"]
        agent_wal = identity["main"].with_name(f"agent-{agent}.jsonl")
        main_data = _native_read_wal(identity["main"], identity, NATIVE_CLICK_WAL_LIMIT, binding=identity["main_binding"])
        main_rows = [_native_json(raw, 4_000_000) for raw in main_data.splitlines()]
        child_rows = [_native_json(raw, 4_000_000) for raw in _native_read_wal(agent_wal, identity, NATIVE_CLICK_WAL_LIMIT).splitlines()]
        starts = [e for e in main_rows if e.get("event") == "SubagentStart" and e.get("agent_id") == agent]
        child_starts = [e for e in child_rows if e.get("event") == "SubagentStart"]
        notes = [e for e in child_rows if isinstance(e.get("note"), str) and e["note"].startswith(NATIVE_CLICK_PREFIX)]
        if (len(starts) != 1 or starts != child_starts or starts[0].get("agent_type") != NATIVE_CLICK_ROLE
                or len(notes) != 1 or notes[0].get("event") != "check" or notes[0].get("note") != line
                or not _native_stamp(starts[0].get("at")) <= start <= end <= _native_stamp(notes[0].get("at"))):
            raise ValueError("native WAL witness missing or mismatched")
        entries = iter(_native_read(rollout, identity, NATIVE_ROLLOUT_LIMIT).splitlines())
        first = _native_json(next(entries), 4_000_000)
        meta = first.get("payload")
        first_at = _native_stamp(first.get("timestamp"))
        if (first.get("type") != "session_meta" or not isinstance(meta, dict) or meta.get("id") != agent
                or meta.get("session_id") != parent or meta.get("parent_thread_id") != parent
                or meta.get("originator") != "Codex Desktop" or meta.get("thread_source") != "subagent"
                or meta.get("agent_role") != NATIVE_CLICK_ROLE or meta.get("agent_path") != identity["agent_path"]
                or first_at > start):
            raise ValueError("native rollout metadata mismatched")
        cutoff = meta.get("subagent_history_start_ordinal")
        if cutoff is not None:
            if (type(cutoff) is not int or cutoff < 2 or not identity["child_provider"]
                    or meta.get("model_provider") != identity["child_provider"]
                    or meta.get("source") != identity["child_source"]):
                raise ValueError("native fork history boundary unavailable")
        matches = []
        for ordinal, raw in enumerate(entries, start=1):
            entry = _native_json(raw, 4_000_000)
            if cutoff is not None and ordinal == 1:
                _check_native_inherited_header(entry, identity, first_at, start)
                continue
            if entry.get("type") == "session_meta":
                raise ValueError("unexpected native rollout header")
            if cutoff is not None and ordinal < cutoff:
                continue
            payload = entry.get("payload")
            settings = (entry.get("type") == "event_msg" and isinstance(payload, dict)
                        and payload.get("type") == "thread_settings_applied")
            if ordinal == cutoff and (not settings or _native_stamp(entry.get("timestamp")) > start):
                raise ValueError("native fork history boundary unavailable")
            if settings and payload.get("thread_id") != agent:
                raise ValueError("native rollout settings name another thread")
            if (entry.get("type") != "response_item" or not isinstance(payload, dict)
                    or payload.get("type") != "message" or payload.get("role") != "assistant"
                    or payload.get("phase") != "final_answer" or payload.get("status") != "completed"):
                continue
            content = payload.get("content")
            if not isinstance(content, list):
                raise ValueError("native rollout message unavailable")
            for item in content:
                if not isinstance(item, dict) or item.get("type") != "output_text" or not isinstance(item.get("text"), str):
                    raise ValueError("native rollout message unavailable")
                for text in item["text"].splitlines():
                    if text.startswith(NATIVE_CLICK_PREFIX):
                        matches.append((text, _native_stamp(entry.get("timestamp"))))
        if len(matches) != 1 or matches[0][0] != line or matches[0][1] < _native_stamp(notes[0].get("at")):
            raise ValueError("native assistant witness missing, mismatched or replayed")
    except (OSError, ValueError, TypeError, KeyError, RuntimeError, StopIteration):
        raise SpecError("native click-test witness unavailable, conflicting or not authored by this tester", EXIT_USAGE) from None


def _native_click_origin(repo):
    origin = subprocess.run(["git", "-C", str(repo), "config", "--get", "remote.origin.url"],
                            capture_output=True, text=True, timeout=30)
    text = origin.stdout.strip()
    scp = re.fullmatch(r"git@([A-Za-z0-9.-]+):([^\s]+)", text)
    if scp:
        host, name = scp.groups()
    else:
        try:
            parsed = urllib.parse.urlsplit(text)
            if (parsed.scheme not in ("https", "ssh") or parsed.username not in (None, "git") or parsed.password is not None
                    or parsed.query or parsed.fragment or parsed.port is not None):
                raise ValueError("unsupported origin")
            host, name = parsed.hostname, parsed.path.removeprefix("/")
        except ValueError:
            raise SpecError("native click-test needs a credential-free canonical Git origin", EXIT_USAGE) from None
    name = name.removesuffix(".git")
    if (origin.returncode or not host or not re.fullmatch(r"[A-Za-z0-9.-]+", host)
            or not re.fullmatch(r"[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)+", name)
            or any(part in (".", "..") for part in name.split("/"))):
        raise SpecError("native click-test needs a credential-free canonical Git origin", EXIT_USAGE)
    return f"{host.lower()}/{name}"


def _native_click_line(record, attachments):
    tester = record["tester"]
    deployed = record["deployed_commit"]["sha"]
    report = tester["report_sha256"]
    core = record["spec_core_sha"]
    if (not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", deployed)
            or any(not re.fullmatch(r"[0-9a-f]{64}", s) for s in (report, core))
            or record["result"] not in ("pass", "fail") or len(record["url"]) > 512):
        raise ValueError("native witness fields malformed")
    url = urllib.parse.urlsplit(record["url"])
    if (url.scheme not in ("http", "https") or not url.hostname or url.username is not None
            or url.path not in ("", "/") or url.query or url.fragment or url.netloc.endswith(":")
            or (url.port is not None and not 1 <= url.port <= 65535)
            or any(not 33 <= ord(ch) <= 126 for ch in record["url"])):
        raise ValueError("native witness URL is not a credential-free origin")
    bound = {key: record[key] for key in ("ticket", "url", "result", "spec_core_sha", "covers_commits")}
    bound.update({key: tester[key] for key in ("identity", "parent", "repo", "report_sha256", "started_at", "ended_at")})
    bound["deployed_commit"] = deployed
    bound["attachments_sha256"] = sha256_bytes(json.dumps(attachments, ensure_ascii=True, separators=(",", ":")).encode())
    line = NATIVE_CLICK_PREFIX + json.dumps(bound, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    if len(line) > 4000:
        raise ValueError("native witness too large")
    return line


def _native_click_spec_fresh(record, spec):
    try:
        return _native_stamp(record["tester"]["started_at"]) >= _native_stamp(spec["_at"])
    except (KeyError, TypeError, ValueError):
        return False


def _native_click_claim(record):
    tester = record.get("tester")
    if not isinstance(tester, dict):
        tester = {}
    ident = tester.get("identity")
    return (record.get("v") == 2 or tester.get("family") == "codex"
            or tester.get("agent_type") == NATIVE_CLICK_ROLE or record.get("pass_source") == NATIVE_CLICK_SOURCE
            or (isinstance(ident, str) and re.fullmatch(UUID, ident) is not None))


def _native_click_record_line(record, attachments):
    tester = record["tester"]
    if (record.get("v") != 2 or tester.get("family") != "codex" or tester.get("kind") != "agent"
            or tester.get("agent_type") != NATIVE_CLICK_ROLE or record.get("pass_source") != NATIVE_CLICK_SOURCE
            or not re.fullmatch(UUID, tester["parent"]) or not re.fullmatch(UUID, tester["identity"])
            or sum(item["role"] == "report" for item in attachments) != 1):
        raise ValueError("native click-test record shape unavailable")
    manifest = [[f["role"], f["name"], f["sha256"]] for f in attachments]
    return _native_click_line(record, manifest)


def _native_click_record_proof(record, attachments, cache):
    import pwd

    line = _native_click_record_line(record, attachments)
    if cache is not None and line in cache:
        if not cache[line]:
            raise ValueError("native click-test witness unavailable")
        return
    if cache is not None:
        cache[line] = False
    tester = record["tester"]
    home = Path(pwd.getpwuid(os.getuid()).pw_dir)
    main = home / ".agent-harness/codex-wals" / tester["parent"] / "main.jsonl"
    identity = _native_agent_source(main, tester["identity"], NATIVE_CLICK_ROLE, purpose="click-test")
    if identity is None:
        raise ValueError("native click-test identity unavailable")
    _native_click_proof(identity, tester["identity"], line, tester["started_at"], tester["ended_at"])
    if cache is not None:
        cache[line] = True


def _native_owner_proof(main_wal, owner):
    """Check native assignment and freeze an owner-recorded handoff/result, not process completion."""
    agent = owner.removeprefix("agent:")
    native = _native_agent_source(Path(main_wal), agent, "harness_owner", purpose="owner")
    if native is None:
        raise SpecError("Explicit Owners require native assigned-owner metadata", EXIT_USAGE)
    import pwd
    uid = os.getuid()
    home = Path(pwd.getpwuid(uid).pw_dir)
    path = home / ".agent-harness/codex-wals" / native["parent"] / f"agent-{agent}.jsonl"
    try:
        # the owner's whole segment chain (each member bound and read under stability checks, a chain problem raises)
        data = _native_read_wal(path, {"home": home, "uid": uid}, 64_000_000)
        if not data.endswith(b"\n"):
            raise ValueError("owner WAL changed or is incomplete")
        def unique(items):
            value = {}
            for key, item in items:
                if key in value:
                    raise ValueError("duplicate owner event key")
                value[key] = item
            return value
        candidate, start = None, None
        for line in data.splitlines():
            if not line.strip():
                continue
            safe_input.safe_json_loads(line, max_depth=16, max_bytes=65536)
            item = json.loads(line, object_pairs_hook=unique,
                              parse_constant=lambda _: (_ for _ in ()).throw(ValueError("invalid owner number")))
            if not isinstance(item, dict):
                raise ValueError("invalid owner event")
            if item.get("event") == "SubagentStart":
                timestamp = item.get("at")
                if (start is not None or item.get("agent_id") != agent or item.get("agent_type") != "harness_owner"
                        or not isinstance(timestamp, str) or len(timestamp) > 64
                        or datetime.fromisoformat(timestamp).tzinfo is None):
                    raise ValueError("owner start is unavailable or conflicting")
                start = {"started_at": timestamp, "start_event_sha256": sha256_bytes(line)}
            if item.get("event") in {"handoff", "result"} and isinstance(item.get("note"), str) and item["note"].strip():
                timestamp = item.get("at")
                if not isinstance(timestamp, str) or len(timestamp) > 64 or datetime.fromisoformat(timestamp).tzinfo is None:
                    raise ValueError("invalid owner attestation timestamp")
                if start is None or datetime.fromisoformat(timestamp) < datetime.fromisoformat(start["started_at"]):
                    raise ValueError("owner attestation predates the matching start")
                candidate = {"attestation_event": item["event"], "attestation_at": timestamp,
                             "event_sha256": sha256_bytes(line)}
        if candidate is None or _native_agent_source(Path(main_wal), agent, "harness_owner", purpose="owner") != native:
            raise ValueError("owner attestation or stable assignment unavailable")
        return {"owner": owner, "parent": native["parent"], "family": "codex", "agent_type": "harness_owner", **start,
                "native_binding_sha256": native["native_binding_sha256"], "wal_sha256": sha256_bytes(data), **candidate}
    except (OSError, ValueError, TypeError, UnicodeError, RuntimeError):
        raise SpecError("Owner-recorded handoff/result evidence unavailable or changed", EXIT_USAGE) from None


def wal_entries(path: Path):
    """The parsed rows of a WAL's whole segment chain (open markers dropped). A WAL that does not exist has no rows. A
    chain problem (a gap, a non-regular or unreadable segment, an ambiguous name) or a chain over the 64 MB budget is
    an error, never a partial list: evidence is never judged "absent" over rows that were not read."""
    import wal_segments as ws
    probs = []
    try:
        raw = ws.read_logical(path, max_bytes=64_000_000, problems=probs)
    except (OSError, ws.SegmentProblem) as error:
        raise SpecError(f"cannot read the WAL chain of {path} ({type(error).__name__})", EXIT_USAGE) from None
    hard = [p for p in probs if p["code"] not in ("live_missing", "schema_newer", "marker_info")]
    if hard:
        raise SpecError(f"WAL chain problem in {Path(path).name}: {hard[0]['code']} ({hard[0].get('message')}); "
                        "repair or restore the segment before using this WAL as evidence", EXIT_USAGE)
    entries = []
    for line in raw.decode("utf-8", "replace").splitlines():
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        if isinstance(entry, dict):
            entries.append(entry)
    return entries


LOCAL_URL_RE = re.compile(r"^\s*(?:https?://)?(?:localhost|127\.|0\.0\.0\.0|\[::1\])", re.I)
LIVE_TARGET_RE = re.compile(r"\b(live|production|prod)\b|https?://(?!(?:localhost|127\.|0\.0\.0\.0|\[::1\]))", re.I)
DEPLOY_WORD_RE = re.compile(r"\b(deployed|installed|released)\b", re.I)
NOT_LIVE_WORDS_RE = re.compile(  # twin of ah.NOT_LIVE_WORDS_RE: a note that says it was not live proves nothing live
    r"\b(?:not|never|isn't|wasn't|aren't|weren't)\s+(?:(?:yet|on|in|to|the|deployed|released)\s+)*(?:live|prod|production)\b"
    r"|\b(?:staging|pre-?prod(?:uction)?|locally|local[- ]only|dry[- ]run)\b", re.I)
SHA_OR_VERSION_RE = re.compile(r"\b[0-9a-f]{7,40}\b|\bv?\d+\.\d+(?:\.\d+)?\b")


def live_deploy_test(note) -> bool:
    """A REALLY_TESTED note that proves done for work without a UI: it names what was deployed or installed (a sha or
    version) and a live target, and no loopback address (main WAL w07450081c12)."""
    note = str(note or "")
    return bool(DEPLOY_WORD_RE.search(note) and SHA_OR_VERSION_RE.search(note) and LIVE_TARGET_RE.search(note)
                and not re.search(r"https?://(?:localhost|127\.|0\.0\.0\.0|\[::1\])", note, re.I)
                and not NOT_LIVE_WORDS_RE.search(note))


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
                "deployed_commit": dict, "covers_commits": list, "click_test": dict, "really_tested": dict,
                "review_policy": dict, "owners": list, "owner_proofs": list}
_NESTED_STRINGS = {"id", "role", "sha256", "name", "key", "verdict", "core_sha", "kind", "sha", "identity",
                   "at", "text", "id_hint", "mode", "basis", "reason", "artifact", "reviewed_at"}
_STRING_FIELDS = ("key", "actor", "author", "spec_core_sha", "spec_file_sha", "by", "signer_kind", "result", "url",
                  "pass_source", "signoff", "note", "owners_core_sha", "owner_proof_sha256")


def record_shape_problem(record: dict):
    """Records come from ticket comments anyone can write; refuse shapes the gate would trip over."""
    for name, kind in _FIELD_TYPES.items():
        if name in record and record[name] is not None and not isinstance(record[name], kind):
            return f"field {name} is not a {kind.__name__}"
    for name in _STRING_FIELDS:
        if name in record and record[name] is not None and not isinstance(record[name], str):
            return f"field {name} is not a string"
    for name, inner in (("attachments", dict), ("commits", dict), ("reviews", dict), ("ac", str),
                        ("covers_commits", str), ("owners", str), ("owner_proofs", dict)):
        if any(not isinstance(item, inner) for item in record.get(name) or []):
            return f"field {name} holds an entry that is not a {inner.__name__}"
    # Nested objects hold only scalars, and the fields the gate keys on are strings.
    nested = [(name, item) for name in ("attachments", "commits", "reviews", "owner_proofs") for item in record.get(name) or []]
    nested += [(name, record[name]) for name in ("tester", "deployed_commit", "click_test", "really_tested", "review_policy")
               if isinstance(record.get(name), dict)]
    for name, item in nested:
        for field, value in item.items():
            if not isinstance(value, (str, bool, int, float, type(None))):
                return f"field {name}.{safe(field, 40)} is not a scalar"
            if field in _NESTED_STRINGS and value is not None and not isinstance(value, str):
                return f"field {name}.{safe(field, 40)} is not a string"
    return None


_OWNERSHIP_FIELDS = {"owners", "owners_core_sha", "owner_proofs", "owner_proof_sha256"}


def ownership_payload(record):
    return json.dumps({"schema": 1, "spec_core_sha": record["owners_core_sha"], "owners": record["owners"],
                       "proofs": record["owner_proofs"]}, sort_keys=True, separators=(",", ":")).encode()


def explicit_record_owners(record):
    if not _OWNERSHIP_FIELDS.intersection(record) and record.get("v") != 2:
        return None
    fields = {"owner", "parent", "family", "agent_type", "attestation_event", "attestation_at",
              "started_at", "start_event_sha256", "wal_sha256", "event_sha256", "native_binding_sha256"}
    try:
        owners, proofs, core = record["owners"], record["owner_proofs"], record["owners_core_sha"]
        if (record.get("v") != 2 or type(owners) is not list or not 1 <= len(owners) <= 8 or len(set(owners)) != len(owners)
                or any(type(owner) is not str or re.fullmatch("agent:" + UUID, owner) is None
                       or owner != owner.lower() for owner in owners)
                or record.get("author") not in owners or not isinstance(core, str)
                or re.fullmatch(r"[0-9a-f]{64}", core) is None or core != record.get("spec_core_sha")
                or type(proofs) is not list or len(proofs) != len(owners)):
            raise ValueError
        for owner, proof in zip(owners, proofs):
            if (type(proof) is not dict or set(proof) != fields or proof["owner"] != owner
                    or proof["family"] != "codex" or proof["agent_type"] != "harness_owner"
                    or proof["attestation_event"] not in ("handoff", "result")
                    or type(proof["parent"]) is not str or re.fullmatch(UUID, proof["parent"]) is None
                    or proof["parent"] != proof["parent"].lower() or owner == "agent:" + proof["parent"]
                    or type(proof["attestation_at"]) is not str or len(proof["attestation_at"]) > 64
                    or datetime.fromisoformat(proof["attestation_at"]).tzinfo is None
                    or type(proof["started_at"]) is not str or len(proof["started_at"]) > 64
                    or datetime.fromisoformat(proof["started_at"]).tzinfo is None
                    or datetime.fromisoformat(proof["attestation_at"]) < datetime.fromisoformat(proof["started_at"])
                    or any(type(proof[key]) is not str or re.fullmatch(r"[0-9a-f]{64}", proof[key]) is None
                           for key in ("wal_sha256", "event_sha256", "native_binding_sha256", "start_event_sha256"))):
                raise ValueError
        if (len({proof["parent"] for proof in proofs}) != 1
                or record["owner_proof_sha256"] != sha256_bytes(ownership_payload(record))):
            raise ValueError
        return set(owners)
    except (KeyError, TypeError, ValueError, OverflowError):
        raise SpecError("Explicit owner declaration or frozen native provenance is malformed or stale") from None


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


BOOKKEEPING_LABEL = "coordinator bookkeeping (ahc)"   # goodqa#16034 D24 / AC-30: the ahc freshness note


def is_bookkeeping(body) -> bool:
    """True for an ahc D24 bookkeeping note (it starts with the label). It states facts already in git and is never
    owner evidence, a checkpoint, a spec record or a click-test (AC-30)."""
    return str(body or "").lstrip().startswith(BOOKKEEPING_LABEL)


def ticket_records(comments: list, max_bytes: int):
    records, ignored = [], []
    for comment in comments:
        if is_bookkeeping(comment.get("body")):
            ignored.append(f"comment {str(comment.get('id', ''))[:8]}: {BOOKKEEPING_LABEL} note, not a record")
            continue
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
            if (not isinstance(record, dict) or record.get("kind") not in KINDS
                    or not (record.get("v") == 1 or (record.get("v") == 2 and record.get("kind") in ("spec", "click_test")))):
                ignored.append(f"comment {comment['id'][:8]}: unknown record version or kind")
                continue
            shape = record_shape_problem(record)
            if shape:
                if (record.get("v") == 2 and record["kind"] == "spec"
                        and shape.startswith(("field owners", "field owner_proofs", "field owner_proof_sha256"))):
                    record["_ownership_shape_problem"] = shape
                else:
                    ignored.append(f"comment {comment['id'][:8]}: malformed {record['kind']} record ({shape})")
                    if record["kind"] != "click_test" or not _native_click_claim(record):
                        continue
                    # Preserve native failure precedence; never uncover an older pass.
                    record = {"v": 2, "kind": "click_test", "spec_core_sha": record.get("spec_core_sha"),
                              "attachments": [], "tester": {}}
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


def kind_problems(record: dict, *, native_cache=None) -> list:
    """Shape rules beyond attachment integrity: a record must carry the files its kind is trusted for."""
    attachments = [item for item in record.get("attachments") or [] if isinstance(item, dict)]
    roles = {item.get("role"): item for item in attachments}
    problems = []
    if any(not re.fullmatch(r"AC-[0-9]{1,3}", str(ac)) for ac in record.get("ac") or []):
        problems.append("criteria ids must look like AC-<n>")
    if record["kind"] == "spec":
        try:
            explicit = explicit_record_owners(record)
            if explicit is not None and (roles.get("owner-provenance") or {}).get("sha256") != record["owner_proof_sha256"]:
                problems.append("no attached owner provenance matches the frozen owner declaration")
        except SpecError as error:
            problems.append(str(error))
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
        if _native_click_claim(record):
            try:
                _native_click_record_proof(record, attachments, native_cache)
            except (SpecError, OSError, ValueError, TypeError, KeyError):
                problems.append("native click-test witness did not verify on this host")
    return problems


def verified(records: list, index: dict, kind: str, *, native_cache=None):
    good, bad = [], []
    for record in records:
        if record["kind"] != kind:
            continue
        try:
            problems = attachment_problems(record, index)
            if not problems or kind != "click_test" or not _native_click_claim(record):
                problems += kind_problems(record, native_cache=native_cache)
        except Exception as exc:  # comments are untrusted: a shape the checks missed is ignored, not fatal
            problems = [f"record could not be checked ({type(exc).__name__})"]
        (bad if problems else good).append((record, problems))
    return [record for record, _ in good], bad


def current_artifact_spec(records, index, label=None):
    """Select from checked server attachment bytes, never mutable comment role/version."""
    sources, errors = [], []
    for row in index.values():
        if not isinstance(row, dict) or row.get("mime") != "text/markdown" or not row.get("commentId"):
            continue
        timestamp = row.get("_comment_at")
        try:
            order = (_native_stamp(timestamp), row["commentId"])
        except (ValueError, TypeError, KeyError):
            raise SpecError("Attached markdown lacks a verified comment timestamp") from None
        data = row.get("_spec_bytes")
        if (row.get("completionState") != "completed" or row.get("deletedAt") or row.get("archivedAt")
                or row.get("_spec_error") or not isinstance(data, bytes)
                or len(data) > 1_000_000 or sha256_bytes(data) != row.get("sha256")):
            errors.append(order)
            continue
        try:
            text = data.decode("utf-8")
            parsed = parse_spec(text)
            header = parsed["header"]
            looks_spec = text.lstrip().startswith("# Spec:") or ("Ticket" in header and "Author" in header)
            if not looks_spec:
                continue
            if label and norm_identity(header.get("Ticket")) != norm_identity(label):
                continue
            author = parse_author(header.get("Author", ""))
            owners = declared_owners(parsed)
            sources.append({"order": order, "comment": row["commentId"], "at": timestamp,
                            "author": author, "owners": owners, "core": core_sha(text),
                            "sha": row["sha256"], "id": row["id"], "ticket": header.get("Ticket")})
        except (UnicodeError, ValueError, SpecError):
            errors.append(order)
    if not sources:
        if errors or any(r["kind"] == "spec" for r in records):
            raise SpecError("No verified spec: attached specification source bytes cannot be verified")
        return None
    newest = max(source["order"] for source in sources)
    for record in records:
        if record["kind"] == "spec":
            try:
                if (_native_stamp(record["_at"]), record["_comment"]) > newest:
                    raise SpecError("A newer specification record has no verified attached source; older specs cannot substitute")
            except (KeyError, TypeError, ValueError):
                raise SpecError("Specification record timestamp cannot be verified") from None
    if errors and max(errors) >= newest:
        raise SpecError("Current attached specification source is unavailable or corrupt; older specs cannot substitute")
    current = [source for source in sources if source["order"] == newest]
    bindings = {(r["core"], r["author"], None if r["owners"] is None else tuple(r["owners"])) for r in current}
    if len(bindings) != 1:
        raise SpecError("Conflicting specification artifacts are attached to the current comment")
    matches = [r for r in records if r["kind"] == "spec" and r["_comment"] == current[0]["comment"]]
    if len(matches) != 1:
        raise SpecError("Current attached specification has missing or ambiguous record metadata")
    record = matches[0]
    source = next((r for r in current if r["sha"] == record.get("spec_file_sha")), None)
    if (source is None or record.get("author") != source["author"] or record.get("spec_core_sha") != source["core"]
            or norm_identity(record.get("ticket")) != norm_identity(source["ticket"])):
        raise SpecError("Specification record author/core differs from the verified attached source")
    if source["owners"] is not None:
        if record.get("owners") != source["owners"] or explicit_record_owners(record) != set(source["owners"]):
            raise SpecError("Explicit ownership metadata differs from the verified attached specification")
    elif _OWNERSHIP_FIELDS.intersection(record) or record.get("v") == 2:
        raise SpecError("Ownership metadata is not declared by the attached specification")
    problems = attachment_problems(record, index) + kind_problems(record)
    if problems:
        raise SpecError("Current specification verification failed: " + "; ".join(problems))
    return record


def broken_current_ownership(records, index):
    try:
        current_artifact_spec(records, index)
    except SpecError as error:
        return str(error)
    return None


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
        current = current_artifact_spec(records, index, self.ticket.label)
        if current is None:
            raise SpecError(f"no verified spec is attached to {self.ticket.label}; run spec_flow.py attach first")
        return current

    def post(self, kind: str, summary: str, record: dict, files, records):
        """files: [(role, name, mime, bytes)]. Idempotent on the record key."""
        index = {row.get("id"): row for row in self.adapter.attachments(self.ticket.id)}
        key_records = records
        if kind == "click_test":
            native = _native_click_claim(record)
            key_records = [item for item in records if item["kind"] == kind and item.get("key") == record["key"]
                           and _native_click_claim(item) == native]
            if native:
                if len(key_records) > MAX_NATIVE_CLICK_CANDIDATES:
                    raise SpecError("too many native click-test replays for this receipt; reconcile duplicate ticket records")
                manifest = [[role, name, sha256_bytes(data)] for role, name, _mime, data in files]
                line = _native_click_line(record, manifest)
                trusted = [item for item in verified(key_records, index, kind, native_cache={})[0]
                           if _native_click_record_line(item, item["attachments"]) == line]
            else:
                trusted = verified(key_records, index, kind)[0]
        else:
            trusted = verified(records, index, record["kind"])[0] if record["kind"] != "signoff" else \
                [item for item in records if item["kind"] == "signoff"]
        if any(item.get("key") == record["key"] for item in trusted):
            print(json.dumps({"status": "ALREADY_RECORDED", "kind": kind, "key": record["key"]}))
            return None
        # A same-key record that failed verification must not be replayed by GoodQA's idempotent comment:
        # fold the rejected comment ids into the operationId so this attempt creates a new comment.
        rejected = sorted(item["_comment"] for item in key_records
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
        comment_id = comment.get("id")
        if not isinstance(comment_id, str) or not comment_id:
            raise SpecError("GoodQA did not return a comment identifier", EXIT_TRACKER)
        if comment_id in rejected:
            raise SpecError("GoodQA replayed an earlier rejected comment instead of recording this one", EXIT_TRACKER)
        bound = {row.get("id"): row for row in self.adapter.attachments(self.ticket.id)}
        problems = attachment_problems(dict(record, _comment=comment_id), bound)
        if problems:
            raise SpecError("GoodQA attachment verification failed: " + "; ".join(problems), EXIT_TRACKER)
        print(json.dumps({"status": "RECORDED", "kind": kind, "ticket": self.ticket.label,
                          "comment": comment_id, "attachments": len(attachments)}))
        return comment


# --------------------------------------------------------------------------- the done gate

def tester_key(tester: dict) -> str:
    kind = tester.get("kind")
    identity = str(tester.get("identity") or "")
    return identity_key(kind, safe_id(identity) if kind == "agent" else identity) if kind else ""


def independence_roles(spec, records, index):
    """Posting is transport in explicit mode; legacy owner inference stays conservative."""
    explicit = explicit_record_owners(spec)
    author, core = spec.get("author"), spec.get("spec_core_sha")
    owners = ({author} | explicit) if explicit is not None else (
        {author} | {r.get("actor") for r in records if r["kind"] in ("spec", "evidence", "click_test")})
    owners.discard(None)
    reviewers = {r.get("key") for r in spec.get("reviews") or []
                 if r.get("core_sha") == core and r.get("role") in required_review_roles(spec.get("review_policy"))}
    if explicit is None:
        # Preserve legacy final-gate behavior, including historical tester exclusions.
        tests = [r for r in records if r["kind"] == "click_test"]
        click_excluded = {author} | reviewers | {r.get("actor") for r in records if r["kind"] == "evidence"}
    else:
        tests, _ = verified(records, index, "click_test")
        click_excluded = owners | reviewers
    testers = {tester_key(r.get("tester") or {}) for r in tests} - {""}
    return owners | reviewers | testers, click_excluded


def _latest_click_result(records, index, spec, label, notes):
    """Select current native results by witnessed run order, and legacy results by receipt order."""
    core = spec.get("spec_core_sha")
    click_records = [r for r in records if r["kind"] == "click_test"]
    native = [r for r in click_records if r.get("spec_core_sha") == core and _native_click_claim(r)]
    if not native:
        legacy = [r for r in click_records if not _native_click_claim(r)]
        good, bad = verified(legacy, index, "click_test")
        for record, problems in bad:
            notes.append(f"click-test record {record['_comment'][:8]} ignored: {'; '.join(problems)}")
        current = [r for r in good if r.get("spec_core_sha") == core]
        return (current[-1] if current else None), bool(good or any(_native_click_claim(r) for r in click_records)), None
    if len(native) > MAX_NATIVE_CLICK_CANDIDATES:
        return None, True, "too many current native records to verify; reconcile duplicate or obsolete ticket records"
    scoped = [r for r in native if r.get("ticket") == label and _native_click_spec_fresh(r, spec)]
    good, bad = verified(scoped, index, "click_test", native_cache={})
    for record, problems in bad:
        notes.append(f"click-test record {record['_comment'][:8]} ignored: {'; '.join(problems)}")
    observations = {_native_click_record_line(r, r["attachments"]): r for r in good}
    unknown = [r for r in native if r not in good]
    if not observations:
        return None, True, "the latest native result does not verify for this ticket on this host"
    last_end = max(_native_stamp(r["tester"]["ended_at"]) for r in observations.values())
    newest = [r for r in observations.values() if _native_stamp(r["tester"]["ended_at"]) == last_end]
    if len(newest) != 1:
        return None, True, "the latest native observations conflict at the same end time; run a new independent click-test"
    # An unverifiable attempt can only be superseded by a verified run that ends after it was posted.
    try:
        inconclusive = any(_native_stamp(r.get("_at")) >= last_end for r in unknown)
    except ValueError:
        inconclusive = True
    if inconclusive:
        return None, True, "the latest native result does not verify for this ticket on this host"
    latest = newest[0]
    if latest["result"] == "pass":
        legacy_failures = [r for r in click_records if r.get("spec_core_sha") == core and r.get("result") == "fail"
                           and not _native_click_claim(r)]
        for record in verified(legacy_failures, index, "click_test")[0]:
            try:
                failed_at = _native_stamp((record.get("tester") or {}).get("ended_at"))
            except ValueError:
                try:
                    failed_at = _native_stamp(record.get("_at"))
                except ValueError:
                    return None, True, "a legacy failure has no verifiable observation or posting time"
            if failed_at >= last_end:
                return None, True, "a newer legacy click-test failed after the native pass"
    return latest, True, None


def evaluate(records: list, index: dict, issue: dict, ignored=()):
    """Return {"ready", "missing", "self_attested", "notes"} for one ticket."""
    missing, attested, notes = [], [], list(ignored)
    label = issue.get("_label") or issue.get("id")
    try:
        current = current_artifact_spec(records, index, label)
    except SpecError as error:
        return {"ready": False, "missing": [str(error)], "self_attested": [], "notes": notes}
    specs, bad_specs = verified(records, index, "spec")
    for record, problems in bad_specs:
        notes.append(f"spec record {record['_comment'][:8]} ignored: {'; '.join(problems)}")
    if current is None:
        missing.append("No verified spec is attached. Fix: spec_flow.py new --ticket '<ref>' --out spec.md; "
                       "get adversarial + acceptance reviews (spec_flow.py review); spec_flow.py attach spec.md")
        return {"ready": False, "missing": missing, "self_attested": attested, "notes": notes}
    spec = current
    core = spec.get("spec_core_sha")
    attested.append("spec author, Owners and core are derived from checksum-verified attachment bytes; criteria and "
                    "review verdict metadata retain their existing declared-record trust limits")
    author = spec.get("author")
    review_policy = spec.get("review_policy")
    required_roles = required_review_roles(review_policy)
    if required_roles == ("adversarial",):
        attested.append(f"single adversarial review authorized by attached {safe(review_policy.get('basis'))} metadata: "
                        f"{safe(review_policy.get('reason'), 300)!r}; the rationale is recorded, not independently verified")
    elif review_policy is not None and review_policy.get("mode") != "standard":
        notes.append("review policy metadata is missing, old or ambiguous; ordinary two-review requirement applies")
    reviews = {entry.get("role"): entry for entry in spec.get("reviews") or [] if isinstance(entry, dict)}
    review_keys, valid_roles = set(), 0
    for role in required_roles:
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
    excluded, click_excluded = independence_roles(spec, records, index)
    explicit = explicit_record_owners(spec)
    if explicit is not None:
        if explicit & review_keys:
            missing.append("a spec reviewer is a declared component owner")
        attested.append("component owners are declared in the reviewed core; native assigned-owner metadata was "
                        "checked at attachment, while handoff/result is owner-recorded, not process termination "
                        "or cryptographic proof of code ownership; transport reporters are not inferred owners")
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
        latest, had_results, click_problem = _latest_click_result(records, index, spec, label, notes)
        if click_problem:
            missing.append(f"click-test: {click_problem}")
        elif latest is None and had_results:
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
        elif LOCAL_URL_RE.match(str(latest.get("url") or "")):
            missing.append(f"click-test: it ran on {safe(latest.get('url'), 80)}, which is not the live deployment; done "
                           "means deployed to live and tested, so click-test the live URL")
        elif uncovered := sorted({c.get("sha") for r in evidence if r.get("spec_core_sha") == core
                                  for c in r.get("commits") or [] if c.get("sha")}
                                 - set(latest.get("covers_commits") or [])):
            missing.append(f"click-test: evidence commits {', '.join(s[:12] for s in uncovered)} came after the "
                           "deployed commit that was click-tested; deploy them and record a new click-test")
        elif tester_key(latest.get("tester") or {}) in click_excluded:
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
        live = [r for r in evidence if r.get("spec_core_sha") == core and live_deploy_test((r.get("really_tested") or {}).get("note"))]
        if not live:
            missing.append("live test: the click-test is not-applicable, but done still means deployed to live and tested. "
                           f"Fix: spec_flow.py evidence --ticket '{label}' --ac <AC> --really-tested <id> --wal <WAL>, where "
                           "the REALLY_TESTED note names what was deployed or installed (its sha or version) and the live "
                           "target it ran on")
    # sign-off
    human_required = spec.get("signoff") == "human" or "human sign-off" in str(issue.get("description") or "").lower()
    signoffs = [r for r in records if r["kind"] == "signoff" and r.get("spec_core_sha") == core]
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
                        "against the declared owner, author, reviewer and tester roles; legacy specs also infer owners from posters)")
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
    problems = lint(text, config, spec_policy=spec_policy)
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
    problems = lint(text, config, spec_policy=spec_policy)
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
        is_spec_plan = "Artifact" in header
        if is_spec_plan:
            problem = spec_plan_signoff_problem(header, verdict)
            if problem:
                raise SpecError(problem, EXIT_USAGE)
        else:
            if header.get("Stage") != "plan":
                raise SpecError("the review report is not a peer_review.py plan report", EXIT_USAGE)
            if verdict is None:
                raise SpecError("the review report has no PLAN_RESULT verdict (legacy advisory reports are not signoff)",
                                EXIT_USAGE)
        if header.get("Reviewed packet SHA-256") != core:
            raise SpecError("the report reviewed a different packet; run spec_flow.py packet spec.md --out <path> "
                            "and review exactly that file")
        if is_spec_plan:
            identity, model = header["Reviewer"], header["Reviewed-Model"]
            entry = {"kind": "helper", "identity": identity, "model": model, "verdict": verdict,
                     "source": f"{SPEC_PLAN_ARTIFACT} exact-packet report {Path(args.report).name}",
                     "artifact": SPEC_PLAN_ARTIFACT, "reviewed_at": header["Reviewed-At"],
                     "report": {"path": str(Path(args.report).absolute()), "sha256": report_sha}}
        else:
            model = header.get("Reviewer") or "unknown"
            entry = {"kind": "helper", "identity": model, "model": model, "verdict": verdict,
                     "source": f"peer_review plan report {Path(args.report).name}",
                     "report": {"path": str(Path(args.report).absolute()), "sha256": report_sha}}
    elif args.agent:
        if not args.wal or not args.verdict or not args.report_file:
            raise SpecError("--agent needs --wal <main WAL>, --verdict and --report-file", EXIT_USAGE)
        agent = safe_id(args.agent)
        native = _native_review_source(Path(args.wal), agent, args.role)
        if native is None:
            types = [e.get("agent_type") for e in wal_entries(checked_wal(Path(args.wal)))
                     if e.get("event") == "subagent" and e.get("agent_id") == agent]
            if not types:
                raise SpecError(f"agent {args.agent} has no subagent record in {args.wal}")
            if types[0] not in REVIEWER_AGENT_TYPES:
                raise SpecError(f"agent {args.agent} is a {types[0] or 'typeless'} agent; only "
                                f"{', '.join(REVIEWER_AGENT_TYPES)} agents may record a review")
            if args.role == "adversarial" and types[0] != "red-team":
                raise SpecError("the adversarial review must come from a red-team agent, a helper receipt or a human")
            provenance = {"model": types[0], "source": f"WAL-verified {types[0]} agent", "agent_type": types[0]}
        else:
            provenance = native
        data = read_regular(Path(args.report_file), 1_000_000)
        entry = {"kind": "agent", "identity": agent, "verdict": args.verdict, **provenance,
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
    owners = declared_owners(parse_spec(text))
    if owners is not None and entry["key"] in owners:
        raise SpecError("A declared component owner cannot review this specification")
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
    owners = declared_owners(spec)
    review_policy, _ = review_policy_from_header(spec["header"].get("Review-policy"))
    required_roles = required_review_roles(review_policy)
    domain_warnings, domain_problems = domain_lint(text, getattr(args, "repo", None) or ".", spec_policy)
    problems += domain_problems  # only fails in enforce mode
    for warning in domain_warnings:
        print(f"spec-flow: warning: {warning}", file=sys.stderr)
    problems += review_problems(entries, core, author, required_roles, owners=owners)
    if problems:
        raise SpecError("spec not attached:\n" + "\n".join("  - " + p for p in problems))
    owner_fields = {}
    if owners is not None:
        if not getattr(args, "owners_wal", None):
            raise SpecError("Explicit Owners attachment requires --owners-wal with the native main WAL", EXIT_USAGE)
        owner_fields = {"owners": owners, "owners_core_sha": core,
                        "owner_proofs": [_native_owner_proof(args.owners_wal, owner) for owner in owners]}
        owner_fields["owner_proof_sha256"] = sha256_bytes(ownership_payload(owner_fields))
    session = Session(spec["header"]["Ticket"], spec_policy)
    records, _, _ = session.records()
    latest = current_reviews(entries, core)
    files = [("spec", spec_path.name, "text/markdown", read_spec_bytes(spec_path)),
             ("reviews", reviews_path(spec_path).name, "text/plain", read_spec_bytes(reviews_path(spec_path)))]
    if owner_fields:
        files.append(("owner-provenance", "owner-provenance.json", "text/plain", ownership_payload(owner_fields)))
    for role in required_roles:
        report = latest[role].get("report")
        if report:
            data = read_regular(Path(report["path"]), 1_000_000)
            if sha256_bytes(data) != report["sha256"]:
                raise SpecError(f"the {role} review report changed since it was recorded")
            files.append((f"review-report:{role}", f"{role}-review-{Path(report['path']).name}", "text/markdown", data))
    click = spec["header"].get("Click-test", "required")
    reason = re.match(r"^not-applicable\s*\((.+)\)$", click)
    record = {"v": 2 if owner_fields else 1, "kind": "spec", "ticket": session.ticket.label, "issue_id": session.ticket.id,
              "actor": parse_author(args.actor), "author": author, "spec_core_sha": core,
              "spec_file_sha": sha256_bytes(read_spec_bytes(spec_path)),
              "ac": [ident for ident, _ in spec["criteria"]], "neg": [ident for ident, _, _ in spec["negatives"]],
              "click_test": {"required": not reason, "reason": reason.group(1) if reason else None},
              "signoff": spec["header"].get("Sign-off", "main"), "review_policy": review_policy,
              **owner_fields, "reviews": [{k: latest[role].get(k) for k in ("role", "kind", "identity", "model", "verdict",
                                                             "core_sha", "key", "source", "artifact", "reviewed_at")}
                          for role in required_roles]}
    record["key"] = content_key("spec", record["spec_file_sha"])
    reviewers = "; ".join(f"{e['role']}: {e['identity']} ({e['kind']}) {e['verdict']}" for e in record["reviews"])
    summary = (f"**Spec attached** for {session.ticket.label}: {len(record['ac'])} acceptance criteria "
               f"({', '.join(record['ac'])}), core sha256 `{core[:16]}`.\nReview policy: {review_policy['mode']}"
               + (f" ({review_policy['basis']}: {review_policy['reason']})" if review_policy["basis"] else "")
               + f".\nReviewers: {reviewers}.")
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
    session, records, index, spec = _actor_and_spec(args, spec_policy)
    native = None
    if args.agent_id and args.wal_dir:
        wal_dir = Path(os.path.expanduser(args.wal_dir)).absolute()
        native = _native_agent_source(wal_dir / "main.jsonl", args.agent_id, NATIVE_CLICK_ROLE, purpose="click-test")
    if (args.print_native_witness or args.verify_native_witness) and native is None:
        raise SpecError("native witness modes require a native Codex click-tester", EXIT_USAGE)
    if native is None and re.fullmatch(UUID, (args.agent_id or args.human or "").strip()):
        raise SpecError("a native UUID tester must use its native Codex WAL", EXIT_USAGE)
    if native and not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", args.deployed_commit):
        raise SpecError("native click-test needs the full deployed commit", EXIT_USAGE)
    max_log = int(spec_policy.get("max_log_bytes", 2_000_000))
    files = [("log", Path(p).name, "text/plain", prepare_log(Path(p), max_log)) for p in args.log or []]
    report_verdict, report_sha = None, None
    if args.report:
        raw = read_regular(Path(args.report), max_log)
        report_sha = sha256_bytes(raw)
        first = next((line.strip() for line in raw.decode("utf-8", "replace").splitlines() if line.strip()), "")
        match = re.match(r"^CLICK_TEST_RESULT: (PASS|FAIL)\b", first)
        if not match or (native and match.group(0) != first):
            raise SpecError("the click-test report must start with `CLICK_TEST_RESULT: PASS` or `... FAIL`", EXIT_USAGE)
        report_verdict = match.group(1).lower()
        if report_verdict != args.result:
            raise SpecError(f"--result {args.result} contradicts the report ({match.group(0)})")
        files.append(("report", Path(args.report).name, "text/plain", prepare_log_bytes(Path(args.report), raw, len(raw))))
    for path in args.screenshot or []:
        data, mime = prepare_media(Path(path), int(spec_policy.get("max_media_bytes", 15_000_000)))
        files.append(("screenshot", Path(path).name, mime, data))
    if not any(role in ("log", "report") for role, *_ in files):
        raise SpecError("a click-test needs its logs: give --log and/or --report from the click-tester", EXIT_USAGE)
    # "On deploy": bind the click-test to the deployed commit, which must contain every evidence commit so far.
    repo = Path(args.repo or ".")
    deployed = git_commit(repo, args.deployed_commit, None)
    evidence = verified(records, index, "evidence")[0] if native else records
    evidence_shas = sorted({c.get("sha") for r in evidence if r["kind"] == "evidence"
                            and r.get("spec_core_sha") == spec["spec_core_sha"]
                            for c in r.get("commits") or [] if c.get("sha")})
    for sha in evidence_shas:  # raises "commit X is not reachable from <deployed>"
        git_commit(repo, sha, deployed["sha"])
    if native:
        if args.human or args.really_tested or not (args.report and args.started and args.ended):
            raise SpecError("native click-tests require a report and observed --started/--ended, and accept no manual fallback",
                            EXIT_USAGE)
        agent = args.agent_id
        _, excluded = independence_roles(spec, records, index)
        if identity_key("agent", agent) in excluded:
            raise SpecError("the native click-tester must be independent of the author, reviewers and evidence posters")
        tester = {"kind": "agent", "family": "codex", "identity": agent, "agent_type": NATIVE_CLICK_ROLE,
                  "parent": native["parent"], "repo": _native_click_origin(repo), "report_sha256": report_sha,
                  "started_at": args.started, "ended_at": args.ended, "last_activity_at": args.ended}
        pass_source = NATIVE_CLICK_SOURCE
    elif args.agent_id:
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
    if explicit_record_owners(spec) is not None:
        _, click_excluded = independence_roles(spec, records, index)
        if tester_key(tester) in click_excluded:
            raise SpecError("A declared owner, author or spec reviewer cannot be the independent click-tester")
    record = {"v": 2 if native else 1, "kind": "click_test", "ticket": session.ticket.label, "actor": parse_author(args.actor),
              "spec_core_sha": spec["spec_core_sha"], "result": args.result, "url": args.url, "tester": tester,
              "pass_source": pass_source, "deployed_commit": deployed, "covers_commits": evidence_shas}
    manifest = [[role, name, sha256_bytes(data)] for role, name, _mime, data in files]
    key_parts = [tester, args.result, args.url, deployed["sha"], [f[2] for f in manifest]]
    if native:
        if not _native_click_spec_fresh(record, spec):
            raise SpecError("native click-test must start after the current spec attachment timestamp", EXIT_USAGE)
        try:
            line = _native_click_line(record, manifest)
            if _native_stamp(args.started) > _native_stamp(args.ended):
                raise ValueError("invalid observed time bounds")
        except ValueError:
            raise SpecError("native click-test requires valid witness fields and observed time bounds", EXIT_USAGE) from None
        if args.print_native_witness:
            print(line)
            return EXIT_OK
        _native_click_proof(native, args.agent_id, line, args.started, args.ended)
        if args.verify_native_witness:
            print(json.dumps({"status": "VERIFIED", "kind": "native_click_witness",
                              "sha256": sha256_bytes(line.encode())}))
            return EXIT_OK
        key_parts.append(line)
    record["key"] = content_key("click_test", key_parts)
    summary = (f"**Click-test {args.result.upper()}** by {tester['kind']} {tester['identity']} on {args.url} "
               f"at deployed commit {deployed['sha'][:12]} "
               f"({tester['started_at']} to {tester.get('ended_at') or 'end not recorded'}), {len(files)} file(s).")
    session.post("click_test", summary, record, files, records)
    return EXIT_OK


def cmd_signoff(args, spec_policy):
    session, records, index, spec = _actor_and_spec(args, spec_policy)
    signer = identity_key(args.kind, safe_id(args.by) if args.kind == "agent" else args.by)
    excluded, _ = independence_roles(spec, records, index)
    if signer in excluded:
        raise SpecError("the sign-off must come from someone other than the owner, the spec author, both "
                        "spec reviewers and the verified click-tester (normally the main agent, or the user)")
    record = {"v": 1, "kind": "signoff", "ticket": session.ticket.label, "actor": parse_author(args.actor),
              "spec_core_sha": spec["spec_core_sha"], "by": signer, "signer_kind": args.kind,
              "source": args.source.strip()[:300], "note": (args.note or "").strip()[:2000] or None}
    record["key"] = content_key("signoff", [signer, spec["spec_core_sha"], record["source"]])
    session.post("signoff", f"**Sign-off** by {args.kind} {args.by} on spec core `{spec['spec_core_sha'][:16]}`.",
                 record, [], records)
    return EXIT_OK


def default_branch(repo: Path):
    """(ref, error): origin/HEAD when set, else the first of origin/main, origin/master, main, master that exists."""
    def git_out(*a):
        done = subprocess.run(["git", "-C", str(repo), *a], capture_output=True, text=True, timeout=30,
                              env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "GIT_CONFIG_NOSYSTEM": "1",
                                   "GIT_OPTIONAL_LOCKS": "0"})
        return done.returncode, done.stdout.strip()
    code, head = git_out("symbolic-ref", "--short", "refs/remotes/origin/HEAD")
    candidates = ([head] if code == 0 and head else []) + ["origin/main", "origin/master", "main", "master"]
    for name in candidates:
        if git_out("rev-parse", "--verify", "--quiet", f"{name}^{{commit}}")[0] == 0:
            return name, None
    return None, f"no default branch (origin/HEAD, origin/main, origin/master, main, master) found in {repo}"


def legacy_evaluate(args) -> dict:
    """Spec-less READY check for tickets that predate the spec flow: the merge is on the default branch, a deploy
    entry and a REALLY_TESTED entry exist in the given main WAL. Names every missing item exactly."""
    missing = []
    notes = []
    sha = (args.merge or "").strip()
    ref = re.search(r"([A-Za-z0-9_-]+)#(\d+)\s*$", args.ticket or "")
    project, number = (ref.group(1), ref.group(2)) if ref else (None, None)
    if not ref:
        missing.append(f"--ticket {args.ticket} is not a <project>#<n> reference")
    sha7 = sha[:7]
    if not args.repo:
        missing.append("--repo <checkout> was not given")
    if not sha:
        missing.append("--merge <sha> was not given")
    elif not re.fullmatch(r"[0-9a-fA-F]{7,40}", sha):
        missing.append(f"merge sha {sha[:60]} is not a 7-40 character hex commit id")
    elif args.repo:
        repo = Path(os.path.expanduser(args.repo))
        branch, problem = default_branch(repo) if repo.is_dir() else (None, f"repo {args.repo} is not a directory")
        if problem:
            missing.append(problem)
        else:
            def git_code(*a):
                return subprocess.run(["git", "-C", str(repo), *a], capture_output=True, timeout=30).returncode
            if git_code("rev-parse", "--verify", "--quiet", f"{sha}^{{commit}}") != 0:
                missing.append(f"merge sha {sha} is not a commit in {repo}")
            elif git_code("merge-base", "--is-ancestor", sha, branch) != 0:
                missing.append(f"merge sha {sha} is not on {branch}")
            else:
                notes.append(f"merge sha {sha[:12]} is an ancestor of {branch}")
                body = subprocess.run(["git", "-C", str(repo), "log", "-1", "--format=%B", sha], capture_output=True,
                                      text=True, timeout=30).stdout
                if ref and not re.search(rf"(?i)(?<![\w-])(?:{re.escape(project)}|goodqa)#{number}(?!\d)", body):
                    missing.append(f"merge sha {sha} does not cite {args.ticket}")
    entries = None
    if not args.wal:
        missing.append("--wal <main WAL path> was not given")
    else:
        entries = wal_entries(checked_wal(Path(args.wal)))
        if not entries:
            missing.append(f"WAL {args.wal} has no readable entries")
    for flag, ident, label in (("--deploy", args.deploy, "deploy"), ("--really-tested", args.really_tested, "REALLY_TESTED")):
        if not ident:
            missing.append(f"{flag} <wal-id> was not given")
        elif entries:
            entry = next((e for e in entries if e.get("id") == ident), None)
            note = str((entry or {}).get("note") or "")
            if entry is None:
                missing.append(f"{label} WAL entry {ident} was not found in {args.wal}")
            elif label == "deploy" and not (re.search(r"live|deploy", note, re.I) and not NOT_LIVE_WORDS_RE.search(note)):
                missing.append(f"deploy WAL entry {ident} does not mention LIVE or DEPLOYED (or says it was not live)")
            elif label == "REALLY_TESTED" and not note.startswith("REALLY_TESTED"):
                missing.append(f"REALLY_TESTED WAL entry {ident} does not start with REALLY_TESTED")
            elif ref and not (re.search(rf"(?<![\w.])#?{number}(?![\w.])", note) or (sha7 and sha7.lower() in note.lower())):
                kind = "deploy entry" if label == "deploy" else "REALLY_TESTED entry"
                missing.append(f"{kind} {ident} names neither {number} nor {sha7}")
            else:
                notes.append(f"{label} WAL entry {ident}: {note[:100]}")
    # Review F4: this is an evidence report, never a closer. It does not read the ticket's spec records, accepts a
    # local default branch when no origin/* exists, and cannot tell who wrote the two WAL entries.
    notes.append("report only: `done --legacy` never closes a ticket; close it through the spec gate or by a person "
                 "after reading this evidence")
    return {"ready": not missing, "missing": missing, "self_attested": [], "notes": notes, "report_only": True}


def cmd_done(args, spec_policy, apply=False):
    legacy = getattr(args, "legacy", False)
    if legacy and apply:
        print("REFUSED: `done --legacy` is an evidence report only and has no --apply (review F4: it does not check "
              "the ticket's spec records, a remote default branch or who wrote the WAL entries). Run it without "
              "--apply, then close the ticket through the spec gate or have a person close it.")
        return EXIT_MISSING
    if legacy:
        session = None
        label = args.ticket
        result = legacy_evaluate(args)
    else:
        session = Session(args.ticket, spec_policy)
        records, ignored, index = session.records()
        issue = session.adapter.issue(session.ticket.id) or {}
        issue["_label"] = session.ticket.label
        result = evaluate(records, index, issue, ignored)
        label = session.ticket.label
    if args.json:
        print(json.dumps(dict(result, ticket=label), indent=1))
    else:
        print(format_result(label, result))
    if not result["ready"]:
        return EXIT_MISSING
    if not apply:
        return EXIT_OK
    if session is None:
        session = Session(args.ticket, spec_policy)
    if getattr(session.ticket, "closed", False):
        if session.ticket.status == "done":  # a retry after a lost response: the transition already happened
            print(json.dumps({"status": "ALREADY_DONE", "ticket": session.ticket.label}))
            return EXIT_OK
        print(f"{session.ticket.label} is already closed ({session.ticket.status}); nothing to apply")
        return EXIT_MISSING
    note = (f"Spec gate READY (spec core {result['spec_core_sha'][:16]}): every acceptance criterion has "
            "evidence, all required spec reviews accepted, click-test and sign-off recorded on this ticket.")
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
    attach.add_argument("--owners-wal", type=Path, help="native main WAL for explicit Owners assignment and owner-recorded handoff/result proof")
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
    native_witness = click.add_mutually_exclusive_group()
    native_witness.add_argument("--print-native-witness", action="store_true", help="print the exact Codex witness line without posting")
    native_witness.add_argument("--verify-native-witness", action="store_true", help="verify the local Codex witness without posting")
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
            item.add_argument("--legacy", action="store_true",
                              help="evidence report (never --apply) for tickets that predate the spec flow: needs --repo, --merge, "
                                   "--deploy, --really-tested and --wal; READY when the merge is on the default branch and both WAL entries exist")
            item.add_argument("--repo", help="--legacy: checkout holding the merge")
            item.add_argument("--merge", help="--legacy: merge commit sha that must be on the default branch")
            item.add_argument("--deploy", help="--legacy: id of the WAL entry recording the live deploy")
            item.add_argument("--really-tested", dest="really_tested", help="--legacy: id of the REALLY_TESTED WAL entry")
            item.add_argument("--wal", help="--legacy: main session WAL path")
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
