#!/usr/bin/env python3
"""`ah export`: one session's WALs as a self-contained, redacted, local-only HTML file (GoodQA goodqa#15788).

The idea is adapted from Pi's /export (pi.dev, earendil-works/pi, MIT). Pi's /share, which uploads a session, is
deliberately absent: this module opens no network connection and never shares the file it writes.

Pipeline:
- Read: each WAL is read once. Symlinks, non-regular files and files over WAL_LIMIT are not read; they are listed
  under "Unread WALs".
- Redact: every string in every row (keys and values) is pre-trimmed, run through redact.redact, masked (e-mail
  local parts, home paths, IPv4 addresses, control and bidi characters) and capped at FIELD_CAP.
- Evidence: the raw, typed rows go to ah.status_report(rows=...), so the classes are exactly the ones `ah status`
  computes (a cap or a mask could change a verdict or a deploy match). The report's own text is never rendered:
  each entry names its source row and is rendered from that row's redacted copy.
- Render: values appear only in HTML text nodes, escaped. The page has no script, no external reference and a
  strict CSP.
- Write: the file is written to a 0600 temporary file in the target directory, then hard-linked to a name that
  must not exist yet. The target is never inside a repository work tree or a sync folder.

The command fails closed: no redactor, an unsafe target or an oversized page means no file.
"""

from __future__ import annotations

import html
import json
import os
from pathlib import Path
import re
import secrets
import stat
import time

FIELD_CAP = 2000  # characters kept per field after redaction
PRE_TRIM = FIELD_CAP + 10240  # wider than every bounded redact pattern; PEM blocks redact to the end of the string
MAX_ROWS = 5000
MAX_OUTPUT = 16 << 20
WAL_LIMIT = 64 << 20  # per file
TOTAL_LIMIT = 256 << 20  # across the session; files past it are listed as unread
MAX_FILES = 4096  # a busy main session had 2,281 WALs (49 MB) on 2026-11-12
MAX_DEPTH = 32

SEMANTIC = frozenset(('intent', 'decision', 'scope', 'requirement', 'result', 'check', 'commit', 'blocker', 'ask',
                      'ask_resolved', 'handoff', 'status', 'risk', 'disposition'))
PRIORITY = frozenset(('scope', 'intent', 'decision', 'requirement', 'ask', 'handoff', 'blocker', 'risk', 'check',
                      'commit'))
RENDER_FIELDS = ('note', 'source', 'reason', 'ref')

BANNER = ("Local and private. Redacted by pattern; this is not a guarantee. Names, hostnames, ticket text and phone "
          "numbers are not removed. Review this file before sharing it with anyone. ah never uploads it.")
CSP = "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"

_EMAIL = re.compile(r"[A-Za-z0-9._%+-]{1,64}@(?=[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,24}\b)")
_HOME = re.compile(r"/(?:Users|home)/[^/\s\"'<>]{1,128}")
_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
# NUL and other C0 controls except tab and newline, DEL, the Arabic letter mark, zero-width and directional marks,
# bidi embedding/override/isolate controls, word joiner and invisible operators, and the BOM. They are removed BEFORE
# redaction, so a token split by an invisible character (ghp_ + U+200B + body) is rejoined and still redacted
# (adversarial delta finding 12).
_CONTROL = re.compile("[\\x00-\\x08\\x0b-\\x1f\\x7f\\u061c\\u200b-\\u200f\\u202a-\\u202e\\u2060-\\u2069\\ufeff]")
SECTION_CAP = 500  # entries rendered per evidence section; the rest are counted in an "N more" line
# Compared case-folded against the resolved path relative to home (APFS is case-insensitive by default).
_SYNC_PREFIXES = ("dropbox", "onedrive", "google drive", "box sync")
_SYNC_EXACT = ("box",)
_SYNC_DIRS = ("library/cloudstorage", "library/mobile documents")
_WARN_DIRS = ("desktop", "documents")


def _load_redactor():
    import redact  # noqa: PLC0415 - loaded at use so a missing redactor is a refusal, not an import crash
    if not callable(getattr(redact, "redact", None)) or not isinstance(getattr(redact, "_KEYS", None), str):
        raise ImportError("redact.redact or redact._KEYS missing")
    return redact.redact, re.compile(r"(?i)" + redact._KEYS)


class _Scrubber:
    def __init__(self, redact_fn, secret_key):
        self.redact, self.secret_key, self.redactions = redact_fn, secret_key, 0

    def text(self, value) -> str:
        if not isinstance(value, str):
            value = json.dumps(value, default=str, ensure_ascii=False) if isinstance(value, (dict, list)) else str(value)
        value = _CONTROL.sub("", value[:PRE_TRIM])
        before = value.count("[REDACTED:")
        value = self.redact(value)
        self.redactions += max(0, value.count("[REDACTED:") - before)
        value = _EMAIL.sub("[email]@", value)
        value = _HOME.sub("~", value)
        value = _IPV4.sub("[ip]", value)
        if len(value) > FIELD_CAP:
            value = value[:FIELD_CAP] + " [... capped at %d characters]" % FIELD_CAP
        return value

    def obj(self, value, depth=0):
        """Same shape, every string scrubbed; a value under a secret-named key is withheld whole."""
        if depth > MAX_DEPTH:
            return "[nested too deep]"
        if isinstance(value, dict):
            out = {}
            for key, item in value.items():
                clean_key = self.text(key)
                base, n = clean_key, 2
                while clean_key in out:  # two keys that redact to the same text must not overwrite each other
                    clean_key, n = "%s #%d" % (base, n), n + 1
                if isinstance(key, str) and self.secret_key.fullmatch(key) and item not in (None, ""):
                    self.redactions += 1
                    out[clean_key] = "[REDACTED:field]"
                else:
                    out[clean_key] = self.obj(item, depth + 1)
            return out
        if isinstance(value, list):
            return [self.obj(item, depth + 1) for item in value[:1000]]
        if value is None or isinstance(value, bool) or isinstance(value, (int, float)):
            return value
        return self.text(value)


def _session(ah, args) -> str:
    session = args.session if args.session is not None else ah.env_session()
    if not session:
        raise ah.AhError("session_unknown", "no session: pass --session or set CLAUDE_CODE_SESSION_ID")
    if not ah.SESSION_RE.fullmatch(session):
        raise ah.AhError("session_invalid", "session id has characters a session directory cannot have")
    return session


def _agent_of(name: str) -> str:
    stem = name[:-len(".jsonl")]
    return "main" if stem == "main" else stem[len("agent-"):] if stem.startswith("agent-") else stem


def _read(ah, sd: Path):
    """[(agent, record)], unread, skipped. One read per WAL; never follows a link."""
    import safe_input  # noqa: PLC0415
    rows, unread, skipped, agents, total, files = [], [], 0, [], 0, 0
    for entry in sorted(os.scandir(sd), key=lambda e: e.name):
        if not entry.name.endswith(".jsonl"):
            continue
        agent = _agent_of(entry.name)
        try:
            info = os.lstat(entry.path)
        except OSError as error:
            unread.append({"wal": entry.name, "agent": agent, "reason": type(error).__name__})
            continue
        reason = ("symlink" if stat.S_ISLNK(info.st_mode) else "not a regular file" if not stat.S_ISREG(info.st_mode)
                  else "over %d bytes" % WAL_LIMIT if info.st_size > WAL_LIMIT
                  else "over the %d-byte session total" % TOTAL_LIMIT if total + info.st_size > TOTAL_LIMIT
                  else "over the %d-file limit" % MAX_FILES if files >= MAX_FILES else None)
        if reason is None:
            total, files = total + info.st_size, files + 1
            try:
                data = safe_input.read_bounded(entry.path, WAL_LIMIT, allowed_roots=[str(sd)])
            except safe_input.InputRejected as rejected:
                reason = rejected.code
        if reason is not None:
            unread.append({"wal": entry.name, "agent": agent, "reason": reason})
            continue
        agents.append(agent)
        for raw in data.decode("utf-8", "replace").splitlines():
            if not raw.strip():
                continue
            try:
                rec = json.loads(raw)
            except (ValueError, RecursionError):  # RecursionError: hostile nesting depth
                skipped += 1
                continue
            if not isinstance(rec, dict) or not rec.get("event"):
                skipped += 1
                continue
            rows.append((agent, rec))
    return rows, unread, skipped, agents


def _has_repo_marker(path: Path) -> bool:
    for directory in (path, *path.parents):
        if os.path.lexists(directory / ".git"):
            return True
    return False


def _relative_to_home(path: Path, home: Path):
    try:
        return path.relative_to(Path(os.path.realpath(home)))
    except ValueError:
        return None


def _check_target_dir(ah, directory: Path, home: Path) -> str | None:
    """Refuse repository and sync-folder targets; return a warning for folders iCloud may sync."""
    if _has_repo_marker(directory):
        raise ah.AhError("out_in_repo", "refusing to write an export inside a repository work tree "
                                        "(it could be committed); pick a folder outside any repository", 2)
    rel = _relative_to_home(Path(os.path.realpath(directory)), home)
    if rel is not None and rel.parts:
        text, first = rel.as_posix().casefold(), rel.parts[0].casefold()
        if first.startswith(_SYNC_PREFIXES) or first in _SYNC_EXACT \
                or any(text == d or text.startswith(d + "/") for d in _SYNC_DIRS):
            raise ah.AhError("out_in_sync_root", "refusing to write an export inside a sync folder "
                                                 "(syncing is uploading); pick a local folder", 2)
        if first in _WARN_DIRS:
            return "may be synced by iCloud"
    return None


def _target(ah, home: Path, session: str, out, now: float):
    """(directory, final path, warning). Validates before anything is created."""
    if out:
        given = Path(os.path.expanduser(out))
        if not given.name.endswith(".html") or given.name.startswith("."):
            raise ah.AhError("bad_request", "--out must name a FILE.html", 2)
        if not given.parent.is_dir():
            raise ah.AhError("bad_request", "--out: the parent directory does not exist", 2)
        directory = Path(os.path.realpath(given.parent))
        final = directory / given.name
        if os.path.islink(final):
            raise ah.AhError("out_symlink", "--out names a symlink; refusing to write through it", 2)
        if os.path.lexists(final):
            raise ah.AhError("out_exists", "--out names an existing file; exports never overwrite", 2)
        return directory, final, _check_target_dir(ah, directory, home)
    base = Path(home) / ".agent-harness" / "work" / session / "exports"
    existing = base
    while not os.path.lexists(existing):
        existing = existing.parent
    if os.path.islink(base):
        raise ah.AhError("out_symlink", "the session exports directory is a symlink; refusing to write through it", 2)
    _check_target_dir(ah, Path(os.path.realpath(existing)), home)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(now))
    return base, base / ("ah-export-%s-%s-%s.html" % (session[:12], stamp, secrets.token_hex(3))), None


def _prepare_default_dir(ah, base: Path) -> None:
    os.makedirs(base.parent, mode=0o700, exist_ok=True)
    try:
        os.mkdir(base, 0o700)
    except FileExistsError:
        pass
    info = os.lstat(base)
    if stat.S_ISLNK(info.st_mode):
        raise ah.AhError("out_symlink", "the session exports directory is a symlink; refusing to write through it", 2)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
        raise ah.AhError("bad_request", "the session exports path is not a directory you own", 2)
    os.chmod(base, 0o700)


def _write(ah, directory: Path, final: Path, data: bytes) -> None:
    """Temp file, fsync, hard link to a name that must not exist, unlink the temp. Every step is relative to one
    directory descriptor opened without following a link, so swapping the directory mid-write cannot redirect it."""
    checked = os.stat(directory)
    dfd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
    try:
        opened = os.fstat(dfd)
        if (opened.st_dev, opened.st_ino) != (checked.st_dev, checked.st_ino):
            raise ah.AhError("out_symlink", "the export directory changed while writing; nothing was written", 2)
        tmp = ".ah-export-%s.tmp" % secrets.token_hex(8)
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0), 0o600,
                     dir_fd=dfd)
        try:
            try:
                os.fchmod(fd, 0o600)
                view = memoryview(data)
                while view:
                    view = view[os.write(fd, view):]
                os.fsync(fd)
            finally:
                os.close(fd)
            try:
                os.link(tmp, final.name, src_dir_fd=dfd, dst_dir_fd=dfd, follow_symlinks=False)
            except FileExistsError:
                raise ah.AhError("out_exists", "the export target appeared while writing; nothing was overwritten",
                                 2) from None
        finally:
            try:
                os.unlink(tmp, dir_fd=dfd)
            except OSError:
                pass
    finally:
        os.close(dfd)


# ------------------------------------------------------------------ rendering

_STYLE = """
:root{--bg:#fbfbf9;--fg:#1d1d1b;--muted:#5d5d58;--line:#dedcd5;--card:#ffffff;--warn-bg:#fff4d6;--warn-fg:#5a4300;
--accent:#2f5d8a}
@media (prefers-color-scheme: dark){:root{--bg:#161615;--fg:#ecebe6;--muted:#a3a29b;--line:#34332f;--card:#1f1f1d;
--warn-bg:#3a3010;--warn-fg:#f3dfa0;--accent:#8db7e0}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 -apple-system,
BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}main{max-width:1100px;margin:0 auto;padding:16px}
header{padding:16px;max-width:1100px;margin:0 auto}h1{font-size:1.4rem;margin:.2rem 0}h2{font-size:1.1rem;
margin:1.4rem 0 .4rem;border-bottom:1px solid var(--line);padding-bottom:.2rem}h3{font-size:1rem;margin:.6rem 0}
p.banner{background:var(--warn-bg);color:var(--warn-fg);padding:10px 12px;border-radius:6px;font-weight:600}
.muted{color:var(--muted)}table{border-collapse:collapse;width:100%;background:var(--card)}th,td{border:1px solid
var(--line);padding:4px 6px;text-align:left;vertical-align:top}td.t{white-space:pre-wrap;overflow-wrap:anywhere;
word-break:break-word}code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.9em}
details{margin:.4rem 0;background:var(--card);border:1px solid var(--line);border-radius:6px;padding:4px 8px}
summary{cursor:pointer;color:var(--accent);font-weight:600}ul{padding-left:1.2rem}
@media (max-width:640px){th,td{font-size:.85rem}}
"""


def _e(value) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def _evidence_rows(entries, columns):
    out = ["<table><thead><tr>" + "".join("<th>%s</th>" % _e(c) for c, _ in columns) + "</tr></thead><tbody>"]
    for entry in entries[:SECTION_CAP]:
        out.append("<tr>" + "".join('<td class="t">%s</td>' % _e(entry.get(key)) for _, key in columns) + "</tr>")
    out.append("</tbody></table>")
    if len(entries) > SECTION_CAP:
        out.append('<p class="muted">%d more not shown (section capped at %d; run ah status for the full list).</p>'
                   % (len(entries) - SECTION_CAP, SECTION_CAP))
    return "".join(out)


def _render(session, generated, report, tree, counts, timeline, omitted, unread, skipped, agent_filter, since_label):
    parts = ["<!doctype html><html lang=\"en\"><head>",
             '<meta http-equiv="Content-Security-Policy" content="%s">' % _e(CSP),
             '<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">',
             "<title>Session export %s</title><style>%s</style></head><body>" % (_e(session[:12]), _STYLE),
             "<header><h1>Session export</h1>",
             '<p class="banner">%s</p>' % _e(BANNER),
             '<p class="muted">Session <code>%s</code>; generated %s; window %s; %d rows rendered, %d omitted, '
             '%d malformed rows skipped.</p></header><main>' % (_e(session), _e(generated), _e(since_label),
                                                                 len(timeline), omitted, skipped)]
    if omitted:
        parts.append("<p>%d older rows omitted to stay under %d; %s rows were kept first.</p>"
                     % (omitted, MAX_ROWS, _e(", ".join(sorted(PRIORITY)))))
    sections = (
        ("VERIFIED (REALLY_TESTED)", report.get("verified"), (("Check", "check"), ("Agent", "agent"), ("At", "at"), ("Note", "note"))),
        ("FAILED (REALLY_TESTED with FAIL; never proof)", report.get("failed"), (("Check", "check"), ("Agent", "agent"), ("At", "at"), ("Note", "note"))),
        ("LIVE (deploy records)", report.get("live"), (("Label", "label"), ("Agent", "agent"), ("At", "at"), ("Note", "note"))),
        ("LIVE_LEGACY (prose live claims, not deploy records)", report.get("live_legacy"), (("Label", "label"), ("Agent", "agent"), ("Note", "note"))),
        ("PENDING checks (declared, not yet REALLY_TESTED)", report.get("pending"), (("Check", "check"), ("Agent", "agent"), ("Note", "note"))),
        ("CLAIMED only (narrative, no evidence entry)", report.get("claimed"), (("Agent", "agent"), ("At", "at"), ("Note", "note"))),
        ("BLOCKED", report.get("blockers"), (("Agent", "agent"), ("At", "at"), ("Note", "note"))),
        ("ASKS open", report.get("asks_open"), (("Ask", "id"), ("Agent", "agent"), ("Note", "note"), ("Reason", "reason"))),
        ("ASSUMPTIONS and TARGET_MISMATCH (no user source)", report.get("assumptions"), (("Label", "label"), ("Agent", "agent"), ("Note", "note"), ("Source", "source"))),
        ("Sourced decisions", report.get("decisions"), (("Agent", "agent"), ("At", "at"), ("Note", "note"), ("Source", "source"))),
        ("COMMITS", report.get("commits"), (("Agent", "agent"), ("At", "at"), ("Note", "note"))),
    )
    parts.append("<section><h2>Evidence (session-wide, by the ah status rules)</h2>")
    for title, entries, columns in sections:
        entries = entries or []
        parts.append("<h3>%s (%d)</h3>" % (_e(title), len(entries)))
        parts.append(_evidence_rows(entries, columns) if entries else '<p class="muted">none</p>')
    owners = report.get("owners") or {}
    if "error" in owners:
        parts.append("<p>Owners: %s</p>" % _e(owners["error"]))
    else:
        parts.append("<p>Owners live: %s. Undisposed: %s. Attention: %s.</p>" % (
            _e(", ".join(owners.get("live") or []) or "none"), _e(", ".join(owners.get("undisposed") or []) or "none"),
            _e(", ".join(owners.get("attention") or []) or "none")))
    parts.append("</section><section><h2>Agents</h2><table><thead><tr><th>Agent</th><th>Type</th><th>Rendered rows</th>"
                 "<th>Hook rows (counted, not shown)</th></tr></thead><tbody>")
    for agent in sorted(set(tree) | set(counts)):
        c = counts.get(agent, {"shown": 0, "hook": 0})
        parts.append('<tr><td class="t"><code>%s</code></td><td class="t">%s</td><td>%d</td><td>%d</td></tr>' % (
            _e(agent), _e(tree.get(agent, "")), c["shown"], c["hook"]))
    parts.append("</tbody></table></section>")
    label = "Timeline" + (" (agents: %s)" % ", ".join(agent_filter) if agent_filter else "")
    parts.append("<section><h2>%s</h2>" % _e(label))
    by_agent = {}
    for agent, at, rec in timeline:
        by_agent.setdefault(agent, []).append((at, rec))
    for agent in sorted(by_agent):
        rows = by_agent[agent]
        parts.append("<details open><summary>%s (%d rows)</summary><table><thead><tr><th>At (UTC)</th><th>Event</th>"
                     "<th>Id</th><th>Text</th></tr></thead><tbody>" % (_e(agent), len(rows)))
        for at, rec in rows:
            text = [str(rec.get("note") or "")]
            for key in RENDER_FIELDS[1:]:
                if rec.get(key) not in (None, ""):
                    text.append("%s: %s" % (key, rec.get(key)))
            parts.append('<tr><td>%s</td><td>%s</td><td><code>%s</code></td><td class="t">%s</td></tr>' % (
                _e(_iso(at)), _e(rec.get("event")), _e(rec.get("id") or ""), _e("\n".join(text))))
        parts.append("</tbody></table></details>")
    if not by_agent:
        parts.append('<p class="muted">no rows in this window</p>')
    parts.append("</section><section><h2>Unread WALs (%d)</h2>" % len(unread))
    if unread:
        parts.append("<ul>" + "".join("<li><code>%s</code>: %s</li>" % (_e(u.get("wal")), _e(u.get("reason")))
                                      for u in unread) + "</ul>")
    else:
        parts.append('<p class="muted">none</p>')
    parts.append("</section></main></body></html>\n")
    return "".join(parts)


_EVIDENCE_KEYS = ("verified", "failed", "live", "live_legacy", "pending", "claimed", "blockers", "asks_open",
                  "assumptions", "decisions", "commits")
_ENUM_KEYS = ("label", "verdict")  # fixed vocabularies computed by status_report; safe to show as they are


def _display(ah, report: dict, count: int, redacted) -> dict:
    """The report with every entry rebuilt from its redacted source row. Classes, labels and verdicts come from the
    report (computed on raw rows); every free-text field comes from redacted(index)."""
    out = {"owners": report.get("owners") or {}}
    for key in _EVIDENCE_KEYS:
        shown = []
        for entry in report.get(key) or []:
            index = entry.get("row")
            if not isinstance(index, int) or not 0 <= index < count:
                shown.append({"agent": "?", "note": "(source row unavailable)"})
                continue
            agent, rec = redacted(index)
            note = str(rec.get("note") or "")
            m = ah._RT.match(note) or ah._PT.match(note)
            item = {"agent": agent, "at": _iso(ah.parse_ts(rec.get("at"))), "id": rec.get("id"), "note": note,
                    "source": rec.get("source"), "reason": rec.get("reason"),
                    "check": m.group(1) if m else ("(redacted)" if entry.get("check") else None)}
            for enum in _ENUM_KEYS:
                if enum in entry:
                    item[enum] = entry[enum]
            shown.append(item)
        out[key] = shown
    return out


def _iso(at: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(at)) if at else "(no time)"


def export(ah, home, args) -> dict:
    session = _session(ah, args)
    home = Path(home)
    try:
        redact_fn, secret_key = _load_redactor()
    except Exception as error:  # noqa: BLE001 - any failure to load means no export (fail closed)
        raise ah.AhError("redactor_unavailable", "the redactor could not be loaded (%s); no export written"
                         % type(error).__name__, 4) from None
    sd = ah.session_dir(home, session)
    if os.path.islink(sd) or not sd.is_dir() or not os.path.isfile(sd / "main.jsonl") \
            or os.path.islink(sd / "main.jsonl"):
        raise ah.AhError("session_unknown", "no main WAL for session %r" % session)
    now = time.time()
    since_s = ah.parse_since(args.since) if args.since else float("inf")
    cutoff = now - since_s
    directory, final, warning = _target(ah, home, session, args.out, now)

    raw_rows, unread_raw, skipped, _read_agents = _read(ah, sd)
    scrub = _Scrubber(redact_fn, secret_key)
    cache = {}

    def redacted(index):
        """The redacted copy of one row, made once and only for rows that are rendered."""
        if index not in cache:
            agent, rec = raw_rows[index]
            cache[index] = (scrub.text(agent), scrub.obj(rec))
        return cache[index]

    # Classes on the raw rows (same verdicts as `ah status`); display from the redacted copies, matched by index.
    report = _display(ah, ah.status_report(home, session, since_s, now=now, rows=raw_rows, unread=unread_raw),
                      len(raw_rows), redacted)

    tree, counts, picked = {a: "" for a in _read_agents}, {}, []
    wanted = set(args.agent or [])
    for index, (agent, rec) in enumerate(raw_rows):
        event = rec.get("event")
        if agent == "main" and event == "subagent":
            child = rec.get("agent_id") or rec.get("agentId")
            if child:
                tree[str(child)] = str(rec.get("agent_type") or rec.get("agentType") or "")
        at = ah.parse_ts(rec.get("at"))
        if at < cutoff:
            continue
        shown = event in SEMANTIC or rec.get("note") not in (None, "")
        c = counts.setdefault(agent, {"shown": 0, "hook": 0})
        if not shown:
            c["hook"] += 1
            continue
        c["shown"] += 1
        if wanted and agent not in wanted:
            continue
        picked.append((at, event in PRIORITY, index))
    picked.sort()
    omitted = max(0, len(picked) - MAX_ROWS)
    if omitted:  # keep priority rows first, then the newest; render the survivors in time order
        keep = set(sorted(range(len(picked)), key=lambda i: (not picked[i][1], -picked[i][0]))[:MAX_ROWS])
        picked = [row for i, row in enumerate(picked) if i in keep]
    candidates = [(redacted(index)[0], at, redacted(index)[1]) for at, _priority, index in picked]
    # Every name shown is WAL-derived (file names, subagent rows): redact it like row text.
    tree = {scrub.text(k): scrub.text(v) for k, v in tree.items()}
    counts = {scrub.text(k): v for k, v in counts.items()}
    unread = [{k: scrub.text(v) for k, v in u.items()} for u in unread_raw]
    agents_read = {scrub.text(a) for a in _read_agents}

    page = _render(session, _iso(now), report, tree, counts, candidates, omitted, unread, skipped,
                   sorted(scrub.text(a) for a in wanted), "every row" if not args.since else "last " + str(args.since))
    data = page.encode("utf-8", "replace")  # a lone surrogate from a JSON \ud800 escape must not raise
    if len(data) > MAX_OUTPUT:
        raise ah.AhError("too_large", "the export would be %d bytes, over the %d-byte limit; narrow it with --since "
                         "or --agent" % (len(data), MAX_OUTPUT), 2)
    if not args.out:
        _prepare_default_dir(ah, directory)
    _write(ah, directory, final, data)
    result = {"ok": True, "path": str(final), "bytes": len(data), "rows_rendered": len(candidates),
              "rows_omitted": omitted, "rows_skipped": skipped, "agents": len(agents_read),
              "redactions": scrub.redactions, "unread": unread,
              "note": "local file only; ah never uploads or shares it. The harness log backup copies the work dir "
                      "(and the raw WALs) to your private backup; use --out for a folder outside it."}
    if warning:
        result["sync_warning"] = warning
    return result
