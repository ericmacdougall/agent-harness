#!/usr/bin/env python3
"""PR review map: one self-contained HTML page for pair-programming a pull request.

    review_map.py generate --repo R (--pr N | --branch B) [--out-dir D]
    review_map.py attach   --map FILE [--ticket 'GoodQA goodqa#N' ...] [--dry-run]
    review_map.py list     --repo R [--state open|merged|closed|all]

The page shows the change map (modules, files, size), the reasoning behind each commit
(Why/What/Testing/Risk), known edges with code snippets (spec NEG cases and review
findings), the refinements adversarial reviews caught (finding, fix commit, test),
suggested next steps and prompts. It has no network reference, escapes every string,
pins its one inline script with a CSP hash, redacts secrets and PII on input and
refuses to write a page that still looks like it holds a token.

Sources are matched to the PR only by commit SHA, branch name or ticket reference, and
every attribution carries its basis so a reader can judge it.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import html
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

EXIT_OK, EXIT_USAGE, EXIT_FAILED, EXIT_PARTIAL = 0, 2, 3, 6
MAX_FILES_DETAIL = 60
MAX_HUNK_LINES = 60
MAX_COMMITS = 200
MAX_DIFF_BYTES = 800_000
MAX_SOURCE_BYTES = 400_000
MAX_SCAN_FILES = 4000
MAX_HTML_BYTES = 8 * 1024 * 1024
MAX_WAL_BYTES = 40 * 1024 * 1024
MAX_FINDINGS_PER_REPORT = 40
MAX_LINE = 3000
MAX_JSON_BYTES = 8 * 1024 * 1024
MAX_SCAN = 30000
GIT_TIMEOUT = 60


class MapError(Exception):
    def __init__(self, message, code=EXIT_FAILED):
        super().__init__(message)
        self.code = code


# --------------------------------------------------------------------------- redaction

EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+\b")
HOME_PATH = re.compile(r"(?:/Users|/home)/[A-Za-z0-9._-]+")
EXTRA_TOKENS = re.compile(r"\b(?:[sr]k_(?:live|test)_[A-Za-z0-9]{8,}|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}"
                          r"|glpat-[A-Za-z0-9_-]{16,}|npm_[A-Za-z0-9]{30,}|xox[abprs]-[A-Za-z0-9-]+|ya29\.[A-Za-z0-9_-]{20,}|\d{8,10}:[A-Za-z0-9_-]{35})\b")
# Shapes that must never survive into the page; checked on the final bytes.
LEAK_SHAPES = re.compile(r"(?:-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----|\bgh[pousr]_[A-Za-z0-9]{20,}|\bgithub_pat_[A-Za-z0-9_]{20,}"
                         r"|\bsk-[A-Za-z0-9_-]{16,}|\b(?:AKIA|ASIA)[A-Z0-9]{16}\b|\bAIza[0-9A-Za-z_-]{35}\b"
                         r"|(?i:\bbearer\s+[A-Za-z0-9._~+/=-]{16,})|\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}"
                         r"|\b[sr]k_(?:live|test)_[A-Za-z0-9]{8,}|\bxox[abprs]-[A-Za-z0-9-]{8,}|\bnpm_[A-Za-z0-9]{30,}|\bglpat-[A-Za-z0-9_-]{16,}|\bya29\.[A-Za-z0-9_-]{20,}|\b\d{8,10}:[A-Za-z0-9_-]{35}\b)")


CONTROL = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\u200e\u200f\u202a-\u202e\u2066-\u2069]")
HIGH_ENTROPY = re.compile(r"(?<![A-Za-z0-9_-])(?=[A-Za-z0-9_-]*[A-Z])(?=[A-Za-z0-9_-]*[a-z])(?=[A-Za-z0-9_-]*\d)[A-Za-z0-9_-]{40,}(?![A-Za-z0-9_-])")


def safe_json_loads(text, max_depth=100):
    """json.loads with a bracket-depth pre-scan: deeply nested input from a repo, PR or WAL must not
    recurse into the interpreter (on 3.9 that can abort the process rather than raise)."""
    if isinstance(text, (bytes, bytearray)):
        text = bytes(text).decode("utf-8", "replace")
    if len(text) > MAX_JSON_BYTES:
        raise ValueError("JSON input too large")
    depth, in_string, escaped = 0, False, False
    for ch in text:
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
        elif ch == '"':
            in_string = True
        elif ch in "[{":
            depth += 1
            if depth > max_depth:
                raise ValueError("JSON nesting too deep")
        elif ch in "]}":
            depth -= 1
    try:
        return json.loads(text)
    except RecursionError:
        raise ValueError("JSON nesting too deep") from None


def scrub(value) -> str:
    """Redact tokens, keys, e-mail addresses and home directories from one string."""
    text = "" if value is None else str(value)
    text = CONTROL.sub("", text)  # before redaction, or U+202E-style splitting defeats it
    # redact_output is quadratic on very long lines; cap each line first
    text = "\n".join(l if len(l) <= MAX_LINE else l[:MAX_LINE] + " [line truncated]" for l in text.split("\n"))
    try:
        from integrate_local import redact_output
    except ImportError as error:  # fail closed: never render unredacted text
        raise MapError(f"redaction helper integrate_local.redact_output is not installed: {error}", EXIT_USAGE)
    text = redact_output(text)
    text = EXTRA_TOKENS.sub("[redacted]", text)
    text = EMAIL.sub("[email]", text)
    text = HOME_PATH.sub("~", text)
    text = HIGH_ENTROPY.sub("[redacted-token]", text)
    return CONTROL.sub("", text)


def assert_no_leak(page: str):
    page = re.sub(r"<meta http-equiv=Content-Security-Policy content=\"[^\"]*\">", "", page)  # holds a base64 script hash
    found = LEAK_SHAPES.search(page) or HIGH_ENTROPY.search(page) or EMAIL.search(page) \
        or re.search(r"://[^/@\s]+:[^/@\s]+@", page) or re.search(r"/(?:Users|home)/[A-Za-z0-9._-]+", page)
    if found:
        raise MapError("refusing to write the page: it still contains token-shaped text "
                       f"({found.group(0)[:6]}...); remove the source or extend the redaction")


# --------------------------------------------------------------------------- process helpers

def run(argv, cwd=None, timeout=GIT_TIMEOUT, limit=MAX_DIFF_BYTES):
    """Fixed-argv subprocess (never a shell). Returns (rc, stdout text) with stdout bounded."""
    try:
        proc = subprocess.run(argv, cwd=cwd, capture_output=True, timeout=timeout,
                              env=dict(os.environ, GIT_TERMINAL_PROMPT="0", GIT_OPTIONAL_LOCKS="0", GIT_CONFIG_NOSYSTEM="1", GIT_EXTERNAL_DIFF="", LC_ALL="C"))
    except (OSError, subprocess.TimeoutExpired):
        return 127, ""
    return proc.returncode, proc.stdout[:limit].decode("utf-8", "replace")


def git(repo, *args, limit=MAX_DIFF_BYTES):
    for item in args:
        if item.startswith("-") and not item.startswith(("--no", "--format", "--numstat", "--name-only", "-U", "-M", "-s", "-q", "-e", "--reverse", "--verify", "-t", "-c", "-p", "--parents", "-n", "-z")) and item != "--":
            raise MapError(f"refusing a git argument that looks like an option: {item[:20]}", EXIT_USAGE)
    return run(["git", "--no-pager", "-C", str(repo), "-c", "core.quotepath=off", "-c", "core.fsmonitor=", "-c", "core.pager=cat",
                *args], limit=limit)


def work_root() -> Path:
    return Path(os.path.expanduser("~")) / ".agent-harness" / "work"


def wal_root() -> Path:
    return Path(os.path.expanduser("~")) / ".claude" / "wals"


# --------------------------------------------------------------------------- git and PR data

SECTION = re.compile(r"^(Why|What|Testing|Risk|Refs|Reason|Authorized-by):[ \t]*(.*)$")
SHA = re.compile(r"^[0-9a-f]{40}$")


def parse_message(body: str) -> dict:
    sections, current = {}, None
    for line in body.split("\n"):
        match = SECTION.match(line)
        if match:
            current = match.group(1)
            sections[current] = match.group(2)
        elif current and line.strip() and not line.startswith("Co-Authored-By:"):
            sections[current] += " " + line.strip()
        elif not line.strip():
            current = None if current in ("Refs", "Authorized-by") else current
    return {key: " ".join(value.split()) for key, value in sections.items()}


def commit_info(repo, sha):
    rc, out = git(repo, "show", "-s", "--format=%H%x1f%an%x1f%aI%x1f%s%x1f%B", sha, limit=60_000)
    if rc != 0 or "\x1f" not in out:
        return None
    full, author, date, subject, body = (scrub(part) if i > 2 else part for i, part in enumerate(out.split("\x1f", 4)))
    author = scrub(author)
    rc, files = git(repo, "show", "--format=", "--name-only", "-M", sha, limit=60_000)
    names = [line for line in files.split("\n") if line.strip()] if rc == 0 else []
    return {"sha": full.strip(), "author": author, "date": date, "subject": subject,
            "body": body.strip(), "sections": parse_message(body), "files": names}


def collect_pr(repo: Path, pr, branch, use_gh=True) -> dict:
    meta = {"number": pr, "title": None, "state": None, "url": None, "base": None, "head": None,
            "body": "", "checks": [], "isDraft": None}
    commits = []
    if pr and use_gh:
        rc, out = run(["gh", "pr", "view", str(int(pr)), "--json",
                       "number,title,state,url,baseRefName,headRefName,headRefOid,body,commits,isDraft,"
                       "mergeCommit,statusCheckRollup"], cwd=str(repo), timeout=30)
        if rc == 0:
            try:
                data = safe_json_loads(out)
            except ValueError:
                data = {}
            meta.update(title=data.get("title"), state=data.get("state"), url=data.get("url"),
                        base=data.get("baseRefName"), head=data.get("headRefName"), body=data.get("body") or "",
                        isDraft=data.get("isDraft"), head_oid=data.get("headRefOid"))
            meta["checks"] = [{"name": c.get("name") or c.get("context"), "state": c.get("conclusion") or c.get("state")}
                              for c in (data.get("statusCheckRollup") or []) if isinstance(c, dict)][:40]
            commits = [c.get("oid") for c in (data.get("commits") or []) if isinstance(c, dict) and SHA.match(str(c.get("oid")))]
            if commits and git(repo, "cat-file", "-e", commits[-1] + "^{commit}")[0] != 0 and meta["head"]:
                git(repo, "fetch", "-q", "origin", f"pull/{int(pr)}/head")
        else:
            meta["note"] = "gh pr view failed; falling back to local git only"
    if not commits:
        if branch and not re.match(r"^[A-Za-z0-9][A-Za-z0-9._/@-]{0,200}$", branch):
            raise MapError("invalid branch name", EXIT_USAGE)
        ref = branch or meta.get("head")
        if not ref and pr:
            ref = f"refs/remotes/origin/pr/{pr}"
        if not ref:
            raise MapError("give --pr (with gh available) or --branch", EXIT_USAGE)
        base = None
        for candidate in ("origin/main", "main", "origin/master", "master"):
            if git(repo, "rev-parse", "--verify", "-q", candidate)[0] == 0:
                base = candidate
                break
        if base is None:
            raise MapError("cannot find a main branch to diff against", EXIT_FAILED)
        rc, out = git(repo, "rev-list", "--reverse", "--no-merges", f"{base}..{ref}", limit=40_000)
        if rc != 0:
            raise MapError(f"cannot list commits for {ref} against {base}", EXIT_FAILED)
        commits = [line for line in out.split("\n") if SHA.match(line)]
        meta["head"] = meta["head"] or branch
        meta["base"] = meta["base"] or base
    commits = commits[:MAX_COMMITS]
    infos = [info for info in (commit_info(repo, sha) for sha in commits) if info]
    infos = [i for i in infos if len(git(repo, "rev-list", "--parents", "-n", "1", i["sha"], limit=500)[1].split()) <= 2] or infos
    if not infos:
        raise MapError("no commits found locally for this PR; fetch it first", EXIT_FAILED)
    warnings = []
    if len(infos) != len(commits):
        warnings.append(f"{len(commits) - len(infos)} of {len(commits)} PR commits are not available locally; the map is partial")
    if meta.get("head_oid") and infos[-1]["sha"] != meta["head_oid"]:
        warnings.append("the newest local commit is not the PR head reported by GitHub; fetch the PR and regenerate")
    meta["warnings"] = warnings
    first, last = infos[0]["sha"], infos[-1]["sha"]
    rc, parent = git(repo, "rev-parse", "--verify", "-q", first + "^")
    base_sha = parent.strip() if rc == 0 else "4b825dc642cb8eb36d8e8b3ecdcd8ff4c6a1f87c"
    if str(meta.get("state")).upper() == "OPEN" and meta.get("base"):
        # An open PR can contain merges of its base; diff from the merge-base so base changes are not attributed to it.
        for candidate in ("origin/" + str(meta["base"]), str(meta["base"])):
            rc2, mb = git(repo, "merge-base", candidate, last)
            if rc2 == 0 and SHA.match(mb.strip()):
                base_sha, rc = mb.strip(), 0
                break
    # The empty tree id differs per hash format; ask git for it instead of hard-coding when the PR starts at the root.
    if rc != 0:
        base_sha = git(repo, "hash-object", "-t", "tree", "/dev/null")[1].strip() or base_sha
    return {"meta": meta, "commits": infos, "base_sha": base_sha, "head_sha": last}


def collect_diff(repo, base_sha, head_sha) -> dict:
    rc, out = git(repo, "diff", "--no-ext-diff", "--no-textconv", "--numstat", "-z", "-M", base_sha, head_sha, limit=800_000)
    if rc != 0:
        raise MapError("git diff failed for the PR range")
    files = []
    parts = out.split("\0")
    k = 0
    while k < len(parts):
        row = parts[k].split("\t")
        k += 1
        if len(row) < 3:
            continue
        add, dele, name = row[0], row[1], "\t".join(row[2:])
        if name == "":  # rename: old and new paths follow as separate fields
            name = parts[k + 1] if k + 1 < len(parts) else ""
            k += 2
        binary = add == "-"
        if not name or not (binary or (add.isdigit() and dele.isdigit())):
            continue  # a record cut by the output limit or in an unexpected shape
        files.append({"path": name, "added": 0 if binary else int(add), "deleted": 0 if binary else int(dele),
                      "binary": binary, "hunks": []})
    files.sort(key=lambda f: -(f["added"] + f["deleted"]))
    truncated = len(files) > MAX_FILES_DETAIL or len(out) >= 800_000
    budget = MAX_DIFF_BYTES
    for item in files[:MAX_FILES_DETAIL]:
        if item["binary"] or budget <= 0:
            continue
        rc, patch = git(repo, "diff", "--no-ext-diff", "--no-textconv", "-U2", "-M", base_sha, head_sha, "--", ":(literal)" + item["path"], limit=min(budget, 120_000))
        budget -= len(patch)
        patch = scrub(patch)
        item["hunks"] = split_hunks(patch)
    return {"files": files, "truncated": truncated}


def split_hunks(patch: str) -> list:
    hunks, current = [], None
    for line in patch.split("\n"):
        if line.startswith("@@"):
            current = {"header": line, "lines": []}
            hunks.append(current)
        elif current is not None and (line[:1] in "+- " or not line):
            if len(current["lines"]) < MAX_HUNK_LINES:
                current["lines"].append(line)
    return hunks


def module_of(path: str) -> str:
    parts = path.split("/")
    if len(parts) == 1:
        return "(root)"
    return "/".join(parts[:2]) if parts[0] in ("harness", "console", "plugins", "tests", "docs", "src", "contracts",
                                                "programs", "packages", "apps") and len(parts) > 2 else parts[0]


def is_test_path(path: str) -> bool:
    low = path.lower()
    return bool(re.search(r"(^|/)(tests?|__tests__|spec|specs)/|(^|/)test_[^/]*|_test\.[a-z]+$|\.test\.[a-z]+$|\.t\.sol$", low))


# --------------------------------------------------------------------------- ticket refs

FALLBACK_REF = re.compile(r"\bGoodQA\s+(?:(?P<project>[a-z0-9][a-z0-9-]{0,62})\s*)?#(?P<number>[1-9]\d{0,9})\b", re.I)


def ticket_pattern():
    try:
        import commit_policy
        policy = commit_policy.load_policy()
        return re.compile(policy["ticket_systems"]["goodqa"]["ref_pattern"], re.I), policy["ticket_systems"]["goodqa"]
    except Exception:  # noqa: BLE001 - the map must still build without the policy file
        return FALLBACK_REF, {"default_project": "goodqa", "unreachable_projects": []}


def find_tickets(texts) -> list:
    pattern, config = ticket_pattern()
    default = config.get("default_project") or "goodqa"
    found = []
    for text in texts:
        for match in pattern.finditer(text or ""):
            project = (match.groupdict().get("project") or default).lower()
            ref = f"GoodQA {project}#{int(match.group('number'))}"
            if ref not in found:
                found.append(ref)
    return found


# --------------------------------------------------------------------------- local sources

SCAN_STATE = {"truncated": False}


def iter_files(roots, suffixes, limit=None, depth=4):
    limit = MAX_SCAN if limit is None else limit
    count = 0
    for root in roots:
        root = Path(root)
        if not root.is_dir():
            continue
        base_depth = len(root.parts)
        for current, dirs, names in os.walk(root, followlinks=False):
            dirs[:] = [d for d in dirs if not d.startswith(".") and d not in ("node_modules", "__pycache__")
                       and len(Path(current, d).parts) - base_depth <= depth]
            for name in names:
                if not name.lower().endswith(suffixes):
                    continue
                path = Path(current, name)
                try:
                    info = path.lstat()
                except OSError:
                    continue
                if not path.is_file() or path.is_symlink() or info.st_size > MAX_SOURCE_BYTES:
                    continue
                count += 1
                if count > limit:
                    SCAN_STATE["truncated"] = True
                    return
                yield path, info


def read_raw(path: Path) -> str:
    try:
        with open(path, "rb") as handle:
            return handle.read(MAX_SOURCE_BYTES).decode("utf-8", "replace")
    except OSError:
        return ""


def read_text(path: Path) -> str:
    return scrub(read_raw(path))


def sha_hit(text: str, shas) -> str | None:
    for sha in shas:
        if sha in text or sha[:10] in text:
            return sha[:10]
    return None


def find_specs(roots, tickets) -> list:
    specs = []
    if not tickets:
        return specs
    wanted = {t.lower() for t in tickets}
    try:
        import spec_flow
    except ImportError:
        return specs
    for path, _ in iter_files(roots, (".md",)):
        text = read_raw(path)
        if "## Acceptance criteria" not in text or "Ticket:" not in text:
            continue
        text = scrub(text)
        header_ticket = re.search(r"(?im)^Ticket:[ \t]*(.+?)[ \t]*$", text)
        if not header_ticket:
            continue
        refs = {t.lower() for t in find_tickets([header_ticket.group(1)])}
        if not refs & wanted:
            continue
        try:
            parsed = spec_flow.parse_spec(text)
        except Exception:  # noqa: BLE001
            continue
        specs.append({"path": str(path), "ticket": sorted(refs & wanted)[0], "title": parsed.get("title"),
                      "criteria": parsed["criteria"], "negatives": parsed["negatives"],
                      "risks": [l[2:].strip() for l in parsed["sections"].get("Risks", []) if l.startswith("- ")],
                      "basis": f"spec header names {sorted(refs & wanted)[0]}"})
    return specs[:6]


REPORT_VERDICT = re.compile(r"(VERDICT:\s*(?:PASS|BLOCK)|(?:PLAN|CODE_INSPECTION|CODE|PR)_RESULT:\s*(?:ACCEPT|BLOCK))", re.I)
NUMBERED = re.compile(r"^\s{0,3}(?:[-*]\s+)?(?:\*\*)?(?:(?:F|R|Finding\s*|Issue\s*|#)?(\d{1,3}(?:[.-]\d{1,2})?))(?:\*\*)?[.):]\s+(\S.{12,})$")
SEVERITY = re.compile(r"\b(critical|high|medium|low|blocker|must[- ]fix|nit)\b", re.I)


def parse_report(text: str) -> dict:
    header = {}
    for line in text.split("\n")[:12]:
        match = re.match(r"^(Reviewer|Stage|Reviewed HEAD|Reviewed packet SHA-256):\s*(.+)$", line)
        if match:
            header[match.group(1)] = match.group(2).strip()
    verdict = REPORT_VERDICT.search(text)
    findings = []
    for line in text.split("\n"):
        match = NUMBERED.match(line)
        if match and not line.lstrip().startswith(("1. `", "1) `")):
            body = match.group(2).strip("* ")
            sev = SEVERITY.search(body)
            findings.append({"id": match.group(1), "text": body[:700],
                             "severity": sev.group(1).lower() if sev else "unrated"})
        if len(findings) >= MAX_FINDINGS_PER_REPORT:
            break
    return {"header": header, "verdict": verdict.group(1) if verdict else None, "findings": findings}


def find_reports(roots, shas, branch, tickets) -> list:
    reports = []
    ticket_res = [re.compile(r"(?<![A-Za-z0-9-])" + re.escape(t.split(" ", 1)[1]) + r"\b", re.I) for t in tickets]
    needles = []
    if branch and (len(branch) >= 12 or "/" in branch):
        needles.append(re.compile(r"(?<![A-Za-z0-9._/-])" + re.escape(branch) + r"(?![A-Za-z0-9._/-])"))
    for path, info in iter_files(roots, (".md", ".txt")):
        raw = read_raw(path)
        if not raw:
            continue
        if not (re.search(r"Reviewed HEAD:|(?i:red[- ]?team|review|finding|verdict|_RESULT)", raw[:4000] + path.name)):
            continue
        head = re.search(r"(?m)^Reviewed HEAD:\s*([0-9a-f]{40})", raw)
        basis = None
        if head and head.group(1) in shas:
            basis = f"Reviewed HEAD {head.group(1)[:10]} is a commit of this PR"
        elif re.search(r"(?i)red[- ]?team|review|finding|verdict|_RESULT", path.name + raw[:400]):
            hit = sha_hit(raw, shas)
            if hit:
                basis = f"report cites PR commit {hit}"
            elif any(n.search(raw) for n in needles) and any(r.search(raw) for r in ticket_res):
                basis = "report names the PR branch and ticket"
        if not basis:
            continue  # relevance is decided on raw text; only matching files are redacted and rendered
        text = scrub(raw)
        parsed = parse_report(text)
        if not parsed["findings"] and not parsed["verdict"]:
            continue
        reports.append({"path": str(path), "name": path.name, "basis": basis, "mtime": info.st_mtime,
                        "stage": parsed["header"].get("Stage") or ("red-team" if re.search(r"red[- ]?team", path.name + text[:300], re.I) else "review"),
                        "reviewer": parsed["header"].get("Reviewer"), "reviewed_head": head.group(1) if head else None,
                        "verdict": parsed["verdict"], "findings": parsed["findings"]})
    reports.sort(key=lambda r: r["mtime"])
    return reports[:30]


def find_wal(shas, branch, tickets, since, until) -> list:
    entries = []
    wanted = [t.split("#")[-1] for t in tickets]
    needles = [re.compile(r"(?<![0-9a-f])" + s[:8] + r"[0-9a-f]*(?![0-9a-f])") for s in shas]
    branch_needle = re.compile(r"(?<![A-Za-z0-9._/-])" + re.escape(branch) + r"(?![A-Za-z0-9._/-])") \
        if branch and len(branch) > 7 else None
    ticket_res = []
    for ref in tickets:
        project, number = ref.split(" ", 1)[1].split("#")
        pattern = re.escape(project) + "#" + number
        if project == ticket_pattern()[1].get("default_project"):
            pattern = "(?:" + pattern + r"|GoodQA\s+#" + number + ")"
        ticket_res.append(re.compile(r"(?<![A-Za-z0-9-])" + pattern + r"\b", re.I))
    root = wal_root()
    if not root.is_dir():
        return entries
    for session in root.iterdir():
        if session.is_symlink() or not session.is_dir():
            continue
        for path in session.glob("*.jsonl"):
            try:
                info = path.lstat()
            except OSError:
                continue
            if path.is_symlink() or info.st_size > MAX_WAL_BYTES or info.st_mtime < since - 86400:
                continue
            try:
                handle = open(path, "r", encoding="utf-8", errors="replace")
            except OSError:
                continue
            for line in handle:
                if '"note"' not in line:
                    continue
                try:
                    row = safe_json_loads(line)
                except ValueError:
                    continue
                if not isinstance(row, dict):
                    continue
                note = row.get("note")
                if not isinstance(note, str) or row.get("event") not in ("decision", "risk", "check", "commit", "result",
                                                                      "scope", "status", "handoff", "blocker", "intent"):
                    continue
                basis = None
                ticket_hit = any(r.search(note) for r in ticket_res)
                if any(n.search(note) for n in needles):
                    basis = "note cites a PR commit"
                elif branch_needle and branch_needle.search(note) and ticket_hit:
                    basis = "note cites the PR branch and ticket"  # a branch name alone also matches other repos
                elif ticket_hit:
                    basis = "note cites the PR ticket"
                if basis:
                    entries.append({"at": row.get("at", ""), "event": row["event"], "note": scrub(note)[:900], "basis": basis})
            handle.close()
    entries.sort(key=lambda e: e["at"])
    return entries[:150]


# --------------------------------------------------------------------------- analysis

def keywords(text: str) -> set:
    return {w for w in re.findall(r"[a-z_]{5,}", text.lower())} - {"which", "should", "there", "their", "would", "other", "about"}


def best_snippet(text: str, files: list, hint_paths=()):
    """Pick the hunk that best matches the text: a path named in it first, then keyword overlap."""
    named = [f for f in files if f["path"] in text or Path(f["path"]).name in text]
    pool = named or [f for f in files if not is_test_path(f["path"])]
    want = keywords(text)
    best, score = None, 0
    for item in pool:
        for hunk in item["hunks"]:
            body = " ".join(hunk["lines"])
            overlap = len(want & keywords(body)) + (3 if item in named else 0)
            if overlap > score:
                best, score = (item, hunk), overlap
    if best is None:
        return None
    item, hunk = best
    return {"path": item["path"], "header": hunk["header"], "lines": hunk["lines"][:14], "named": item in named}


def build_edges(specs, reports, diff, commits=()) -> list:
    edges = []
    for commit in commits:
        if commit["sections"].get("Risk"):
            edges.append({"kind": "commit risk", "id": commit["sha"][:8], "refs": [], "text": commit["sections"]["Risk"],
                          "source": commit["sha"], "basis": "Risk section of the commit message",
                          "snippet": best_snippet(commit["sections"]["Risk"], diff["files"])})
    for spec in specs:
        for ident, refs, text in spec["negatives"]:
            edges.append({"kind": "spec NEG", "id": ident, "refs": refs, "text": text, "source": spec["path"],
                          "basis": spec["basis"], "snippet": best_snippet(text, diff["files"])})
        for risk in spec["risks"]:
            edges.append({"kind": "spec risk", "id": "", "refs": [], "text": risk, "source": spec["path"],
                          "basis": spec["basis"], "snippet": best_snippet(risk, diff["files"])})
    for report in reports:
        for finding in report["findings"]:
            edges.append({"kind": f"{report['stage']} finding", "id": finding["id"], "refs": [], "text": finding["text"],
                          "source": report["path"], "basis": report["basis"], "severity": finding["severity"],
                          "snippet": best_snippet(finding["text"], diff["files"])})
    return edges[:120]


def build_refinements(reports, commits, diff) -> list:
    order = {c["sha"]: i for i, c in enumerate(commits)}
    rows = []
    for report in reports:
        index = order.get(report.get("reviewed_head") or "")
        stale = bool(report.get("reviewed_head")) and report["reviewed_head"] != commits[-1]["sha"]
        for finding in report["findings"]:
            words = keywords(finding["text"])
            fix, how = None, "unlinked: no later commit shares terms with the finding"
            candidates = commits[index + 1:] if index is not None else \
                [c for c in commits if re.search(r"red[- ]?team|review|finding", c["body"], re.I)]
            scored = sorted(candidates, key=lambda c: -len(words & keywords(c["subject"] + " " + c["body"])))
            if scored and len(words & keywords(scored[0]["subject"] + " " + scored[0]["body"])) >= 2:
                fix, how = scored[0], "shares terms with the finding (inferred)"
            elif index is not None and candidates:
                fix, how = candidates[0], "next commit after the reviewed head (weak inference)"
            rows.append({"finding": finding["text"], "finding_id": finding["id"], "severity": finding["severity"],
                         "report": report["name"], "stage": report["stage"], "fix": fix, "stale": stale,
                         "tests": [f for f in (fix["files"] if fix else []) if is_test_path(f)], "basis": how + (" [stale: report reviewed an older head]" if stale else "")})
    seen = {r["fix"]["sha"] for r in rows if r["fix"]}
    for commit in commits:
        if commit["sha"] not in seen and re.search(r"red[- ]?team|review (finding|feedback)|peer[- ]review", commit["body"], re.I):
            rows.append({"finding": commit["sections"].get("Why") or commit["subject"], "finding_id": "", "severity": "unrated",
                         "report": "(commit message)", "stage": "review", "fix": commit, "stale": False,
                         "tests": [f for f in commit["files"] if is_test_path(f)], "basis": "commit message cites a review"})
    return rows[:80]


def domain_signals(paths):
    try:
        import domain_gates  # S1; optional here
        if hasattr(domain_gates, "detect_paths"):
            return domain_gates.detect_paths(paths), domain_gates
    except ImportError:
        pass
    domains = []
    low = [p.lower() for p in paths]
    if any(p.endswith(".sol") or p.endswith("foundry.toml") or "hardhat.config" in p for p in low):
        domains.append("evm")
    if any(p.endswith("anchor.toml") or "/programs/" in p or p.startswith("programs/") for p in low):
        domains.append("solana")
    return domains, None


PROMPTS = [
    ("Adversarial pass", "In this repository, red-team the change {base}..{head}. Read the diff and the spec's negative cases. List the three most likely ways it breaks in production and write a failing test for each before proposing a fix."),
    ("Evidence audit", "For the change {base}..{head}, show for each acceptance criterion the exact command, its output and the commit it ran against. Flag any criterion with no observed evidence or only a generated test."),
    ("Edge sweep", "For the code changed in {base}..{head}, enumerate malformed, old-version, concurrent and oversized inputs the new paths accept, and check each against a test."),
    ("Rollback drill", "Describe how to roll back {base}..{head} safely, which persisted state it touches, and write a test that loads data written by the previous version."),
]


def build_next_steps(model) -> list:
    steps, commits, files = [], model["commits"], model["diff"]["files"]
    meta = model["meta"]
    open_findings = [r for r in model["refinements"] if r["fix"] is None]
    for row in open_findings[:6]:
        steps.append(("Resolve review finding", f"{row['finding'][:200]} (from {row['report']}): no fix commit found."))
    src = [f for f in files if not is_test_path(f["path"]) and not f["path"].endswith((".md", ".json", ".txt"))]
    if src and not any(is_test_path(f["path"]) for f in files):
        steps.append(("Add failing-first tests", "Source files changed but no test file did; add tests that fail against the base."))
    heads = {r.get("reviewed_head") for r in model["reports"]}
    if model["head_sha"] not in heads:
        steps.append(("Review the exact head", f"No peer_review report names head {model['head_sha'][:10]}; run code-inspection then pr review on it."))
    if not model["specs"]:
        steps.append(("Write the spec", "No spec for the PR's ticket was found in the work directories; write one with spec_flow.py new and get both reviews."))
    for spec in model["specs"]:
        blob = " ".join(l for f in files for h in f["hunks"] for l in h["lines"] if l.startswith("+"))
        for ident, _, _ in spec["negatives"]:
            if ident not in blob:
                steps.append(("Check negative case coverage", f"{ident} is not named in the added lines; confirm a test covers it."))
    pending = {}
    for entry in model["wal"]:
        for ident in re.findall(r"PENDING_REAL_TEST\s+([A-Za-z0-9_.-]+)", entry["note"]):
            pending[ident] = entry
        for ident in re.findall(r"REALLY_TESTED\s+([A-Za-z0-9_.-]+)", entry["note"]):
            pending.pop(ident, None)
    for ident in list(pending)[:5]:
        steps.append(("Close pending real test", f"WAL id {ident} was promised but no REALLY_TESTED entry matches."))
    if any(f["path"].endswith((".js", ".html", ".css", ".tsx", ".jsx")) for f in files):
        steps.append(("Click-test the UI", "UI files changed; have an independent click-tester run the deployed build and attach a report."))
    failing = [c["name"] for c in meta.get("checks", []) if str(c["state"]).upper() in ("FAILURE", "FAILED", "ERROR", "TIMED_OUT")]
    if failing:
        steps.append(("Fix failing checks", ", ".join(str(n) for n in failing[:5])))
    if not model["tickets"]:
        steps.append(("Cite a ticket", "No commit message cites a GoodQA ticket; add Refs: GoodQA <project>#N."))
    if model["domains"]:
        steps.append(("Run the domain checklist", "Domain signals " + ", ".join(model["domains"]) + ": walk reentrancy/access control, precision, replay/chain id, nonce/idempotency, finality, key custody, gas/DoS, upgradeability and oracle trust, with fuzz or invariant tests."))
    if model.get("diff_truncated"):
        steps.append(("Review omitted files", f"Only the {MAX_FILES_DETAIL} largest files are detailed here; review the rest in git."))
    return steps[:20] or [("No automatic gaps found", "Spot-check the highest-risk edges above with a human review.")]


def build_prompts(model) -> list:
    meta = model["meta"]
    fill = {"head": model["head_sha"][:10], "base": model["base_sha"][:10]}  # SHAs only: PR text is untrusted
    prompts = [(name, text.format(**fill)) for name, text in PROMPTS]
    try:
        import domain_gates
        if model["domains"] and hasattr(domain_gates, "suggested_prompts"):
            prompts += [(f"Domain: {name}", text) for name, text in list(domain_gates.suggested_prompts(model["domains"]))[:8]]
    except ImportError:
        if model["domains"]:
            prompts.append(("Domain: smart contracts", "Write Foundry invariant and fuzz tests for the changed contracts: reentrancy, access control, accounting conservation, signature replay across chain ids, upgrade storage layout. Run them against an anvil fork."))
    return prompts


def build_model(repo: Path, pr, branch, use_gh=True, roots=None, wal=True) -> dict:
    SCAN_STATE["truncated"] = False
    data = collect_pr(repo, pr, branch, use_gh)
    diff = collect_diff(repo, data["base_sha"], data["head_sha"])
    commits, meta = data["commits"], data["meta"]
    shas = [c["sha"] for c in commits]
    tickets = find_tickets([c["body"] for c in commits])  # never the PR body or comments: any editor could add a target
    roots = [work_root()] if roots is None else roots
    specs = find_specs(roots, tickets)
    reports = find_reports(roots, set(shas), meta.get("head") or branch, tickets)
    since = min(_ts(c["date"]) for c in commits) - 3600
    wal_rows = find_wal(shas, meta.get("head") or branch, tickets, since, time.time()) if wal else []
    if SCAN_STATE["truncated"]:
        meta.setdefault("warnings", []).append(f"the work-directory scan stopped after {MAX_SCAN} files; specs or reports may be missing")
    paths = [f["path"] for f in diff["files"]]
    domains, _ = domain_signals(paths)
    model = {"meta": meta, "commits": commits, "base_sha": data["base_sha"], "head_sha": data["head_sha"], "diff": diff,
             "diff_truncated": diff["truncated"], "tickets": tickets, "specs": specs, "reports": reports, "wal": wal_rows,
             "domains": domains, "generated": commits[-1]["date"], "repo": repo.name}
    model["edges"] = build_edges(specs, reports, diff, commits)
    model["refinements"] = build_refinements(reports, commits, diff)
    model["next_steps"] = build_next_steps(model)
    model["prompts"] = build_prompts(model)
    return model


def _ts(value: str) -> float:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return time.time() - 30 * 86400


# --------------------------------------------------------------------------- rendering

def esc(value) -> str:
    return html.escape(scrub(value), quote=True)


CSS = """
:root{--bg:#f6f7f9;--fg:#15181d;--mut:#5a6270;--card:#fff;--line:#d9dde4;--add:#1a7f37;--del:#b42318;--acc:#2457d6;--warn:#b54708}
@media (prefers-color-scheme:dark){:root{--bg:#10131a;--fg:#e8ebf1;--mut:#9aa3b2;--card:#181c25;--line:#2b3140;--add:#4fc26b;--del:#ff7b72;--acc:#8ab4ff;--warn:#f0a65a}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,sans-serif}
header,main{max-width:1180px;margin:0 auto;padding:16px}h1{font-size:22px;margin:.2em 0}h2{font-size:18px;margin:0 0 10px}
nav{top:0;background:var(--bg);border-bottom:1px solid var(--line);z-index:5}nav a{display:inline-block;margin:6px 10px 6px 0;color:var(--acc)}
section{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:14px;margin:14px 0}
.mut{color:var(--mut)}.pill{display:inline-block;border:1px solid var(--line);border-radius:99px;padding:0 8px;font-size:12px;margin-right:4px}
.map{display:flex;flex-wrap:wrap;gap:8px}.group{flex:1 1 220px;border:1px solid var(--line);border-radius:6px;padding:6px}
.group h3{font-size:13px;margin:0 0 4px}.tiles{display:flex;flex-wrap:wrap;gap:3px}
.tile{border:0;border-radius:4px;padding:4px;min-height:34px;font:12px/1.2 ui-monospace,monospace;color:#fff;text-align:left;cursor:pointer;overflow:hidden}
.tile:focus-visible,button:focus-visible,summary:focus-visible,a:focus-visible{outline:3px solid var(--acc);outline-offset:2px}
.t-add{background:#1a7f37}.t-mix{background:#8a5a00}.t-del{background:#b42318}.t-test{box-shadow:inset 0 -4px 0 #2457d6}
pre{background:var(--bg);border:1px solid var(--line);border-radius:6px;padding:8px;overflow:auto;font:12px/1.4 ui-monospace,monospace;margin:6px 0}
.l-add{color:var(--add)}.l-del{color:var(--del)}table{border-collapse:collapse;width:100%}td,th{border-top:1px solid var(--line);padding:6px;text-align:left;vertical-align:top;font-size:14px}
button.act{background:var(--acc);color:#fff;border:0;border-radius:6px;padding:4px 10px;cursor:pointer}details{margin:6px 0}summary{cursor:pointer}
.hidden{display:none}.warn{color:var(--warn)}.sev-critical,.sev-high,.sev-blocker{color:var(--del);font-weight:600}
@media (min-height:760px){nav{position:sticky}}
input{background:var(--card);color:var(--fg);border:1px solid var(--line);border-radius:4px;padding:2px 6px}
@media (max-width:640px){header,main{padding:10px}}
"""

JS = """
(function(){
  var tiles=document.querySelectorAll('.tile');
  tiles.forEach(function(t){t.addEventListener('click',function(){
    var d=document.getElementById(t.getAttribute('data-target'));
    if(d){d.open=true;d.scrollIntoView({block:'center'});}
  });});
  var q=document.getElementById('filter');
  if(q){q.addEventListener('input',function(){
    var v=q.value.toLowerCase();
    document.querySelectorAll('[data-search]').forEach(function(n){
      n.classList.toggle('hidden',v!==''&&n.getAttribute('data-search').indexOf(v)<0);});});}
  document.querySelectorAll('button[data-copy]').forEach(function(b){b.addEventListener('click',function(){
    var s=document.getElementById(b.getAttribute('data-copy'));
    if(s&&navigator.clipboard){navigator.clipboard.writeText(s.textContent).then(function(){b.textContent='Copied';});}
  });});
})();
"""


def tile_class(item) -> str:
    total = item["added"] + item["deleted"]
    cls = "t-mix" if item["added"] and item["deleted"] and min(item["added"], item["deleted"]) / max(total, 1) > .3 else \
        ("t-del" if item["deleted"] > item["added"] else "t-add")
    return cls + (" t-test" if is_test_path(item["path"]) else "")


def render_snippet(snippet) -> str:
    if not snippet:
        return '<p class="mut">No matching hunk found in the diff.</p>'
    lines = "".join(
        f'<span class="{"l-add" if l.startswith("+") else "l-del" if l.startswith("-") else ""}">{esc(l)}</span>\n'
        for l in snippet["lines"])
    note = "named in the text" if snippet.get("named") else "best keyword match (inferred)"
    return f'<p class="mut">{esc(snippet["path"])} {esc(snippet["header"])} ({note})</p><pre>{lines}</pre>'


def render(model: dict) -> str:
    meta, files, commits = model["meta"], model["diff"]["files"], model["commits"]
    title = f"Review map: {meta.get('title') or meta.get('head') or model['head_sha'][:10]}"
    groups = {}
    for item in files:
        groups.setdefault(module_of(item["path"]), []).append(item)
    total_add = sum(f["added"] for f in files)
    total_del = sum(f["deleted"] for f in files)
    out = [f"<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
           f"<meta http-equiv=Content-Security-Policy content=\"__CSP__\"><title>{esc(title)[:120]}</title><style>{CSS}</style></head><body>"]
    pr_bits = []
    if meta.get("number"):
        pr_bits.append(f"PR #{int(meta['number'])}")
    for key in ("state",):
        if meta.get(key):
            pr_bits.append(str(meta[key]))
    out.append(f"<header><h1>{esc(title)}</h1><p class=mut>{esc(model['repo'])} &middot; {esc(' '.join(pr_bits))} &middot; "
               f"{esc(meta.get('head') or '')} onto {esc(meta.get('base') or '')} &middot; head {esc(model['head_sha'][:10])} &middot; "
               f"head commit {esc(model['generated'])}</p><p>")
    out.append(f"<span class=pill>{len(commits)} commits</span><span class=pill>{len(files)} files</span>"
               f"<span class=pill style='color:var(--add)'>+{total_add}</span><span class=pill style='color:var(--del)'>-{total_del}</span>")
    for ref in model["tickets"]:
        out.append(f"<span class=pill>{esc(ref)}</span>")
    for domain in model["domains"]:
        out.append(f"<span class='pill warn'>domain: {esc(domain)}</span>")
    for warning in meta.get("warnings") or []:
        out.append(f"</p><p class=warn role=alert>Warning: {esc(warning)}</p><p>")
    out.append("</p><p><label>Filter <input id=filter type=search placeholder='file, commit, finding'></label></p></header>")
    out.append("<nav><div style='max-width:1180px;margin:0 auto;padding:0 16px'>" + "".join(
        f"<a href='#{a}'>{n}</a>" for a, n in (("map", "Change map"), ("why", "Reasoning"), ("edges", "Edges"),
                                              ("refine", "Refinements"), ("next", "Next steps"), ("prompts", "Prompts"),
                                              ("sources", "Sources"))) + "</div></nav><main>")
    # change map
    out.append("<section id=map aria-labelledby=maph><h2 id=maph>Change map</h2><p class=mut>Tile area tracks changed lines; green is mostly added, red mostly deleted, amber mixed, blue underline is a test file. Click a tile for its diff.</p><div class=map>")
    for name, items in sorted(groups.items(), key=lambda kv: -sum(f["added"] + f["deleted"] for f in kv[1])):
        weight = sum(f["added"] + f["deleted"] for f in items)
        out.append(f"<div class=group style='flex-grow:{max(1, min(weight, 400))}' data-search='{esc(name.lower())}'><h3>{esc(name)} <span class=mut>{len(items)} files, {weight} lines</span></h3><div class=tiles>")
        for item in items[:80]:
            size = item["added"] + item["deleted"]
            idx = files.index(item)
            out.append(f"<button class='tile {tile_class(item)}' style='flex-grow:{max(1, min(size, 200))};flex-basis:{40 + min(size, 120)}px' "
                       f"data-target='f{idx}' data-search='{esc(item['path'].lower())}' title='{esc(item['path'])}'>{esc(Path(item['path']).name)}<br>+{item['added']} -{item['deleted']}</button>")
        out.append("</div></div>")
    out.append("</div>")
    if model["diff_truncated"]:
        out.append(f"<p class=warn>Diff detail truncated: only the {MAX_FILES_DETAIL} largest of {len(files)} files carry hunks.</p>")
    out.append("<h3>Files</h3>")
    for idx, item in enumerate(files[:MAX_FILES_DETAIL]):
        out.append(f"<details id='f{idx}' data-search='{esc(item['path'].lower())}'><summary>{esc(item['path'])} <span class=mut>+{item['added']} -{item['deleted']}</span></summary>")
        if item["binary"]:
            out.append("<p class=mut>Binary file.</p>")
        for hunk in item["hunks"][:6]:
            body = "".join(f'<span class="{"l-add" if l.startswith("+") else "l-del" if l.startswith("-") else ""}">{esc(l)}</span>\n' for l in hunk["lines"])
            out.append(f"<p class=mut>{esc(hunk['header'])}</p><pre>{body}</pre>")
        out.append("</details>")
    out.append("</section>")
    # reasoning
    out.append("<section id=why><h2>Reasoning by commit</h2><p class=mut>From each commit's Why, What, Testing and Risk sections.</p>")
    for commit in commits:
        s = commit["sections"]
        out.append(f"<details data-search='{esc((commit['sha'] + commit['subject']).lower())}' open><summary><strong>{esc(commit['subject'])}</strong> <span class=mut>{esc(commit['sha'][:10])}</span></summary><table>")
        for key in ("Why", "What", "Testing", "Risk", "Refs"):
            if s.get(key):
                out.append(f"<tr><th>{key}</th><td>{esc(s[key])}</td></tr>")
        if not any(s.get(k) for k in ("Why", "What")):
            out.append("<tr><td colspan=2 class=mut>No Why/What sections; the message is unstructured.</td></tr>")
        out.append("</table></details>")
    for spec in model["specs"]:
        out.append(f"<h3>Plan: {esc(spec['title'] or spec['ticket'])}</h3><ul>" + "".join(
            f"<li><strong>{esc(i)}</strong> {esc(t)}</li>" for i, t in spec["criteria"]) + f"</ul><p class=mut>{esc(spec['basis'])}</p>")
    decisions = [w for w in model["wal"] if w["event"] in ("decision", "risk", "scope")]
    if decisions:
        out.append("<h3>WAL decisions</h3><ul>" + "".join(
            f"<li><span class=pill>{esc(w['event'])}</span> {esc(w['note'][:500])} <span class=mut>({esc(w['basis'])})</span></li>" for w in decisions[:20]) + "</ul>")
    out.append("</section>")
    # edges
    out.append("<section id=edges><h2>Known edges and risks</h2>")
    if not model["edges"]:
        out.append("<p class=mut>No spec NEG cases or review findings were found for this PR.</p>")
    for edge in model["edges"]:
        sev = edge.get("severity", "")
        out.append(f"<details data-search='{esc((edge['text'] + edge['id']).lower())}'><summary><span class=pill>{esc(edge['kind'])}</span> "
                   f"<strong>{esc(edge['id'])}</strong> <span class='sev-{esc(sev)}'>{esc(edge['text'][:160])}</span></summary>"
                   f"<p>{esc(edge['text'])}</p>{render_snippet(edge['snippet'])}<p class=mut>Basis: {esc(edge['basis'])}</p></details>")
    out.append("</section>")
    # refinements
    out.append("<section id=refine><h2>Refinements the reviews caught</h2>")
    if not model["refinements"]:
        out.append("<p class=mut>No review findings were attributed to this PR.</p>")
    else:
        out.append("<table><tr><th>Finding</th><th>Fix commit</th><th>Test</th><th>Basis</th></tr>")
        for row in model["refinements"]:
            fix = row["fix"]
            out.append(f"<tr data-search='{esc(row['finding'][:80].lower())}'><td><span class=pill>{esc(row['stage'])}</span> <span class='sev-{esc(row['severity'])}'>{esc(row['finding_id'])}</span> {esc(row['finding'][:300])}</td>"
                       f"<td>{esc(fix['subject'] + ' (' + fix['sha'][:10] + ')') if fix else 'none found'}</td>"
                       f"<td>{esc(', '.join(row['tests'][:3])) or 'none in that commit'}</td><td class=mut>{esc(row['basis'])}</td></tr>")
        out.append("</table>")
    out.append("</section>")
    out.append("<section id=next><h2>Suggested next steps</h2><ol>" + "".join(
        f"<li><strong>{esc(n)}</strong>: {esc(t)}</li>" for n, t in model["next_steps"]) + "</ol></section>")
    out.append("<section id=prompts><h2>Prompts to run next</h2>")
    for idx, (name, text) in enumerate(model["prompts"]):
        out.append(f"<details open><summary>{esc(name)}</summary><pre id='p{idx}'>{esc(text)}</pre><button class=act data-copy='p{idx}' type=button>Copy</button></details>")
    out.append("</section>")
    out.append("<section id=sources><h2>Sources and limits</h2><ul>")
    out.append(f"<li>{len(commits)} commits, {len(model['reports'])} review reports, {len(model['specs'])} specs, {len(model['wal'])} WAL notes matched by commit SHA, branch or ticket.</li>")
    for report in model["reports"]:
        stale = " STALE: reviewed an older head" if report.get("reviewed_head") and report["reviewed_head"] != model["head_sha"] else ""
        out.append(f"<li>{esc(report['name'])}: {esc(report['stage'])} {esc(report['verdict'] or 'no verdict line')} ({esc(report['basis'])}){esc(stale)}</li>")
    out.append("<li>Matching is heuristic. Redaction removed tokens, keys, e-mail addresses and home directories; text still deserves a human look before sharing.</li></ul></section></main>")
    out.append(f"<script>{JS}</script></body></html>")
    page = "".join(out)
    digest = base64.b64encode(hashlib.sha256(JS.encode()).digest()).decode()
    return page.replace("__CSP__", f"default-src 'none'; style-src 'unsafe-inline'; script-src 'sha256-{digest}'; base-uri 'none'; form-action 'none'")


# --------------------------------------------------------------------------- output

def default_out_dir() -> Path:
    override = os.environ.get("HARNESS_REVIEW_WORK")
    return Path(override).expanduser() if override else work_root() / "review-maps"


def out_dir(arg=None) -> Path:
    path = Path(arg).expanduser() if arg else default_out_dir()
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.is_symlink():
        raise MapError(f"{path} is a symlink")
    os.chmod(path, 0o700)
    return path


def write_private(path: Path, data: bytes):
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            tmp.unlink()


def safe_part(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", text)[:60].strip("-") or "x"


def cmd_generate(args) -> int:
    repo = Path(args.repo).expanduser().resolve()
    if args.pr is not None and not isinstance(args.pr, int):
        raise MapError("--pr must be an integer", EXIT_USAGE)
    if not args.pr and not args.branch:
        raise MapError("give --pr or --branch", EXIT_USAGE)
    model = build_model(repo, args.pr, args.branch, use_gh=not args.no_gh,
                        roots=[Path(r) for r in args.work_root] if args.work_root else None, wal=not args.no_wal)
    page = render(model)
    assert_no_leak(page)
    data = page.encode("utf-8")
    if len(data) > MAX_HTML_BYTES:
        raise MapError(f"the page is {len(data)} bytes, over the {MAX_HTML_BYTES} limit")
    label = f"pr{model['meta']['number']}" if model["meta"].get("number") else safe_part(args.branch or "branch")
    directory = out_dir(args.out_dir)
    path = directory / f"{safe_part(repo.name)}-{label}-{model['head_sha'][:8]}.html"
    write_private(path, data)
    digest = hashlib.sha256(data).hexdigest()
    result = {"status": "WROTE", "path": str(path), "sha256": digest, "bytes": len(data), "head": model["head_sha"],
              "pr": model["meta"].get("number"), "tickets": model["tickets"], "repo": repo.name,
              "counts": {"commits": len(model["commits"]), "files": len(model["diff"]["files"]),
                         "edges": len(model["edges"]), "refinements": len(model["refinements"])}}
    write_private(path.with_suffix(".meta.json"), json.dumps(result, indent=1).encode())
    print(json.dumps(result))
    return EXIT_OK


def cmd_list(args) -> int:
    repo = Path(args.repo).expanduser().resolve()
    state = args.state if args.state in ("open", "merged", "closed", "all") else "open"
    rc, out = run(["gh", "pr", "list", "--state", state, "--limit", str(max(1, min(args.limit, 100))), "--json",
                   "number,title,state,isDraft,headRefName,headRefOid,updatedAt,url"], cwd=str(repo), timeout=30)
    if rc != 0:
        raise MapError("gh pr list failed; is gh installed and authenticated for this repository?")
    try:
        rows = safe_json_loads(out)
    except ValueError:
        raise MapError("gh pr list returned unreadable output")
    directory = default_out_dir()
    result = []
    for row in rows:
        oid = str(row.get("headRefOid") or "")
        existing = directory / f"{safe_part(repo.name)}-pr{int(row['number'])}-{oid[:8]}.html"
        result.append({"number": int(row["number"]), "title": scrub(row.get("title")), "state": row.get("state"),
                       "draft": bool(row.get("isDraft")), "branch": scrub(row.get("headRefName")), "head": oid,
                       "updatedAt": row.get("updatedAt"), "map": str(existing) if existing.is_file() else None})
    print(json.dumps({"status": "OK", "repo": repo.name, "prs": result}))
    return EXIT_OK


def cmd_attach(args) -> int:
    path = Path(args.map).expanduser()
    if path.is_symlink() or not path.is_file():
        raise MapError(f"{path} is not a regular file", EXIT_USAGE)
    data = path.read_bytes()
    if len(data) > MAX_HTML_BYTES:
        raise MapError("the map is too large to attach")
    assert_no_leak(data.decode("utf-8", "replace"))
    digest = hashlib.sha256(data).hexdigest()
    meta_path = path.with_suffix(".meta.json")
    meta = {}
    if meta_path.is_file():
        try:
            meta = safe_json_loads(meta_path.read_text())
        except ValueError:
            meta = {}
        if meta.get("sha256") != digest:
            raise MapError("the map changed since it was generated; regenerate it before attaching")
    if args.expect_sha256 and args.expect_sha256 != digest:
        raise MapError("the page is not the one that was reviewed (sha256 differs); regenerate and review it again")
    if not meta and not args.expect_sha256:
        raise MapError("no generation record next to the map; pass --expect-sha256 or regenerate", EXIT_USAGE)
    refs = args.ticket or meta.get("tickets") or []
    if not refs:
        raise MapError("no ticket reference: pass --ticket 'GoodQA project#N' (the PR's commits cite none)", EXIT_USAGE)
    if not args.dry_run and not args.yes:
        raise MapError("attach uploads outward: pass --yes after checking the ticket list " + ", ".join(refs), EXIT_USAGE)
    import spec_flow
    spec_policy = spec_flow.load_spec_policy()
    _, config = ticket_pattern()
    unreachable = {p.lower() for p in config.get("unreachable_projects", [])}
    results, failed = [], False
    for ref in refs:
        row = {"ticket": ref}
        try:
            project, number = spec_flow.parse_ticket_ref(ref, config if "ref_pattern" in config else spec_flow.ticket_config(spec_policy)[2])
            row["ticket"] = f"GoodQA {project}#{number}"
            if project in unreachable:
                row.update(status="UNREACHABLE", detail=f"project {project} is not reachable with the member key; attach by hand")
            elif args.dry_run:
                row.update(status="DRY_RUN", detail="would upload and comment")
            else:
                session = spec_flow.Session(ref, spec_policy)
                marker = "review-map-sha256:" + digest
                if any(marker in ((c.get("body") if isinstance(c, dict) else "") or "") for c in session.adapter.all_comments(session.ticket.id)):
                    row.update(status="ALREADY_ATTACHED", detail="a comment with this map's sha256 exists")
                    results.append(row)
                    continue
                name = path.name
                attachment = session.adapter.upload(session.project_id, name, "text/html", data, digest)
                body = (f"**PR review map** for {meta.get('repo', '')} PR #{meta.get('pr')} head `{str(meta.get('head', ''))[:10]}`.\n"
                        f"File: {name} ({marker}). Open the attachment in a browser; it has no network access.")
                comment = session.adapter.comment_with_files(session.ticket.id, body,
                                                             spec_flow.op_id(session.ticket.id, "review-map:" + digest), [attachment])
                row.update(status="ATTACHED", comment=comment.get("id"), attachment=attachment)
        except Exception as error:  # noqa: BLE001 - report per ticket, never claim success
            row.update(status="FAILED", detail=scrub(str(error))[:300])
        failed = failed or row["status"] in ("FAILED", "UNREACHABLE")
        results.append(row)
    print(json.dumps({"status": "PARTIAL" if failed else "OK", "sha256": digest, "results": results}))
    return EXIT_PARTIAL if failed else EXIT_OK


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    g = sub.add_parser("generate")
    g.add_argument("--repo", required=True)
    g.add_argument("--pr", type=int)
    g.add_argument("--branch")
    g.add_argument("--out-dir")
    g.add_argument("--work-root", action="append", help="extra directory to search for specs and reports (default: the durable work dir)")
    g.add_argument("--no-gh", action="store_true")
    g.add_argument("--no-wal", action="store_true")
    a = sub.add_parser("attach")
    a.add_argument("--map", required=True)
    a.add_argument("--ticket", action="append")
    a.add_argument("--dry-run", action="store_true")
    a.add_argument("--expect-sha256", help="refuse unless the page bytes have this sha256")
    a.add_argument("--yes", action="store_true", help="confirm the ticket list (required to upload)")
    l = sub.add_parser("list")
    l.add_argument("--repo", required=True)
    l.add_argument("--state", default="open")
    l.add_argument("--limit", type=int, default=30)
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return {"generate": cmd_generate, "attach": cmd_attach, "list": cmd_list}[args.command](args)
    except MapError as error:
        print(json.dumps({"status": "ERROR", "error": scrub(str(error))}))
        return error.code


if __name__ == "__main__":
    sys.exit(main())
