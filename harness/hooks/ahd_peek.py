#!/usr/bin/env python3
"""ahd_peek: list running Claude Code and Codex agent instances and tail their recent activity, redacted.

Read-only toward transcripts. Interview material (any path, project dir, agent description, cwd or host whose token
starts with a configured prefix, see ahd_policy.json "exclude") is never read, shown or stored: such an instance is
listed only as `excluded`, by stat. Classification fails closed: a path, record or text that cannot be classified is
excluded, and a tail whose working directory cannot be established is refused.

Secrets are removed with redact.py before any cut; if redact.py cannot be imported, no free text is printed at all.
Tool results are never shown (only their size). Every file is opened O_NOFOLLOW | O_NONBLOCK, must be a regular
file, and is read only up to a cap, so a FIFO, device or symlink cannot hang or flood a reader.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
POLICY_FILE = HERE / "ahd_policy.json"

try:  # the shared redactor; without it we print structure only
    sys.path.insert(0, str(HERE))
    import redact as _redact  # noqa: E402
except Exception:  # pragma: no cover - exercised by a test that hides the module
    _redact = None

ID_RE = re.compile(r"^(?:(?P<host>[A-Za-z0-9._-]{1,64})/)?(?P<kind>[csx]):(?P<id>[A-Za-z0-9._-]{1,128})$")
TOKEN_SPLIT = re.compile(r"[^a-z0-9]+")
REDACT_MAX = 256 * 1024
EXCLUDED_TEXT = "[excluded: interview material]"


def load_policy(path=None) -> dict:
    p = Path(path) if path else POLICY_FILE
    try:
        data = json.loads(safe_read(p, 1 << 20).decode("utf-8"))
        if not isinstance(data, dict) or not isinstance(data.get("exclude"), dict):
            raise ValueError("policy has no exclude table")
        return data
    except Exception as exc:
        # fail closed: without an exclusion table every read is refused (classify returns excluded)
        return {"exclude": None, "policy_error": f"{type(exc).__name__}"}


def home() -> Path:
    return Path(os.environ.get("HOME") or os.path.expanduser("~"))


# ---------------------------------------------------------------- safe file access

class NotRegular(OSError):
    pass


def open_regular(path) -> int:
    """fd for a regular file, never following a final symlink and never blocking on a FIFO."""
    fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise NotRegular(f"not a regular file: {path}")
    except BaseException:
        os.close(fd)
        raise
    return fd


def safe_read(path, cap: int, offset: int | None = None) -> bytes:
    """At most `cap` bytes (from `offset`, or the whole file when it fits). Raises if the file is larger than cap
    and no offset was given, so callers can tell "too big" from "empty"."""
    fd = open_regular(path)
    try:
        size = os.fstat(fd).st_size
        if offset is None:
            if size > cap:
                raise NotRegular(f"over cap: {size} > {cap}")
            offset = 0
        out, pos = [], offset
        while pos < offset + cap:
            chunk = os.pread(fd, min(1 << 20, offset + cap - pos), pos)
            if not chunk:
                break
            out.append(chunk)
            pos += len(chunk)
        return b"".join(out)
    finally:
        os.close(fd)


# ---------------------------------------------------------------- classification

def _tokens(text: str) -> list:
    return [t for t in TOKEN_SPLIT.split(text.lower()) if t]


def text_excluded(text, policy: dict) -> bool:
    """True when free text (a path, description, cwd) names interview material. Fails closed on bad input."""
    ex = policy.get("exclude")
    if not isinstance(ex, dict):
        return True
    if text is None:
        return False
    if not isinstance(text, str):
        return True
    low = text.lower()
    for sub in ex.get("path_substrings") or ():
        if isinstance(sub, str) and sub and sub.lower() in low:
            return True
    prefixes = tuple(p.lower() for p in (ex.get("token_prefixes") or ()) if isinstance(p, str) and p)
    return any(tok.startswith(prefixes) for tok in _tokens(low)) if prefixes else False


def value_excluded(value, policy: dict, depth: int = 0) -> bool:
    """text_excluded over every string inside a JSON value (keys too), bounded in depth."""
    if depth > 8:
        return True
    if isinstance(value, str) or value is None:
        return text_excluded(value, policy)
    if isinstance(value, (int, float, bool)):
        return False
    if isinstance(value, dict):
        return any(text_excluded(str(k), policy) or value_excluded(v, policy, depth + 1) for k, v in value.items())
    if isinstance(value, (list, tuple)):
        return any(value_excluded(v, policy, depth + 1) for v in value)
    return True


def host_excluded(host: str, policy: dict) -> bool:
    """For peer peeks (slice 2): a host on the exclusion list is never contacted."""
    ex = policy.get("exclude")
    if not isinstance(ex, dict):
        return True
    h = (host or "").lower()
    return any(h == x.lower() or h.startswith(x.lower() + ".") for x in (ex.get("hosts") or ()) if isinstance(x, str))


def path_excluded(path, policy: dict, roots=None) -> bool:
    """Fail-closed classifier for a transcript path: excluded unless it is a regular file under an allowed root and
    neither its spelled path nor its resolved path names interview material."""
    try:
        p = Path(path)
        if not p.is_absolute():
            return True
        spelled = str(p)
        real = os.path.realpath(spelled)
        spelled.encode("utf-8")
    except Exception:
        return True
    if text_excluded(spelled, policy) or text_excluded(real, policy):
        return True
    if roots is not None:
        ok = False
        for r in roots:
            rr = os.path.realpath(str(r))
            if real == rr or real.startswith(rr.rstrip(os.sep) + os.sep):
                ok = True
                break
        if not ok:
            return True
    return False


def claude_root() -> Path:
    return home() / ".claude" / "projects"


def codex_root() -> Path:
    return home() / ".codex" / "sessions"


def roots() -> list:
    return [claude_root(), codex_root()]


# ---------------------------------------------------------------- discovery (stat only, plus tiny meta files)

def _stat(p: Path):
    try:
        st = os.lstat(p)
        return st if stat.S_ISREG(st.st_mode) else None
    except OSError:
        return None


def _read_small_json(p: Path, limit: int = 16384):
    try:
        return json.loads(safe_read(p, limit).decode("utf-8"))
    except Exception:
        return None


def discover(policy: dict, now=None, window=None, include_all=False) -> list:
    """Every Claude session/subagent transcript and Codex rollout, newest first. Never opens a transcript."""
    now = time.time() if now is None else now
    window = policy.get("peek_list_window_seconds", 7200) if window is None else window
    active_s = policy.get("active_seconds", 600)
    out = []
    croot, xroot = claude_root(), codex_root()
    rts = [croot, xroot]
    try:
        projects = sorted(croot.iterdir()) if croot.is_dir() else []
    except OSError:
        projects = []
    for proj in projects:
        try:
            if proj.is_symlink() or not proj.is_dir():
                continue
            entries = list(proj.iterdir())
        except OSError:
            continue
        proj_excl = text_excluded(proj.name, policy)
        for ent in entries:
            if ent.suffix == ".jsonl":
                st = _stat(ent)
                if st:
                    out.append(_row("s", ent.stem, ent, st, proj.name, None, proj_excl, policy, rts, now, active_s))
            elif ent.is_dir() and not ent.is_symlink():
                sub = ent / "subagents"
                try:
                    files = list(sub.glob("agent-*.jsonl")) if sub.is_dir() else []
                except OSError:
                    files = []
                for f in files:
                    st = _stat(f)
                    if not st:
                        continue
                    aid = f.stem[len("agent-"):]
                    meta = {} if proj_excl else (_read_small_json(f.with_name(f.stem + ".meta.json")) or {})
                    out.append(_row("c", aid, f, st, proj.name, meta, proj_excl, policy, rts, now, active_s,
                                    session=ent.name))
    try:
        rollouts = list(xroot.glob("*/*/*/rollout-*.jsonl")) if xroot.is_dir() else []
    except OSError:
        rollouts = []
    for f in rollouts:
        st = _stat(f)
        if not st:
            continue
        m = re.search(r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\.jsonl$", f.name)
        rid = m.group(1) if m else f.stem
        out.append(_row("x", rid, f, st, "codex", None, False, policy, rts, now, active_s))
    out = [r for r in out if include_all or now - r["mtime"] <= window]
    out.sort(key=lambda r: -r["mtime"])
    return out


def _row(kind, rid, path, st, project, meta, proj_excl, policy, rts, now, active_s, session=None) -> dict:
    meta = meta if isinstance(meta, dict) else {}
    desc = meta.get("description") if isinstance(meta.get("description"), str) else ""
    excluded = proj_excl or path_excluded(path, policy, rts) or value_excluded(
        {k: meta.get(k) for k in ("description", "agentType", "cwd", "name") if k in meta}, policy)
    age = max(0.0, now - st.st_mtime)
    row = {"id": f"{kind}:{rid}", "kind": {"c": "claude-subagent", "s": "claude-session", "x": "codex"}[kind],
           "mtime": st.st_mtime, "age_s": int(age), "active": age <= active_s, "size": st.st_size,
           "excluded": bool(excluded)}
    if excluded:
        return row  # stat only: no project, description, session or path for interview material
    row.update({"project": project, "path": str(path)})
    if session:
        row["session"] = session
    if meta:
        for k in ("agentType", "model"):
            if isinstance(meta.get(k), str):
                row[k] = meta[k][:64]
        row["description"] = scrub(desc, 120)
    return row


def find(ident: str, policy: dict):
    m = ID_RE.match(ident or "")
    if not m or m.group("host"):
        return None
    want = f"{m.group('kind')}:{m.group('id')}"
    for r in discover(policy, include_all=True):
        if r["id"] == want:
            return r
    return None


# ---------------------------------------------------------------- redaction and rendering

PARTIAL_TAIL = re.compile(r"[A-Za-z0-9_+/=.-]{1,63}$")


def scrub(text, limit: int = 300) -> str:
    """Redact the whole (bounded) text first, then cut, then drop a partial token left at the cut, so a secret
    split by the cut can never leave a recognisable fragment."""
    if not isinstance(text, str):
        return ""
    if _redact is None:
        return f"[{len(text)} chars, redactor unavailable]"
    if len(text) > REDACT_MAX:
        text = text[:REDACT_MAX]
        cut_input = True
    else:
        cut_input = False
    one = " ".join(_redact.redact(text).split())
    if len(one) <= limit and not cut_input:
        return one
    out = one[: max(0, limit - 1)]
    if limit < len(one) and not one[limit - 1:limit + 1].startswith(" "):
        out = PARTIAL_TAIL.sub("", out)
    return out.rstrip() + "…"


INPUT_KEYS = ("command", "description", "file_path", "path", "pattern", "url", "query", "prompt", "subagent_type",
              "to", "skill")


def summarize_input(inp, policy: dict) -> str:
    if value_excluded(inp, policy):
        return EXCLUDED_TEXT
    if not isinstance(inp, dict):
        return scrub(json.dumps(inp)[:REDACT_MAX] if inp is not None else "", 200)
    parts = []
    for k in INPUT_KEYS:
        v = inp.get(k)
        if isinstance(v, str) and v:
            parts.append(f"{k}={scrub(v, 160)}")
    return "; ".join(parts) if parts else f"keys={','.join(sorted(map(str, inp))[:8])}"


def _content_text(content) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return " ".join(c.get("text", "") for c in content if isinstance(c, dict) and isinstance(c.get("text"), str))
    return ""


def safe_text(raw: str, limit: int, policy: dict) -> str:
    """Screen the raw, uncut text for interview material, then redact and cut."""
    return EXCLUDED_TEXT if text_excluded(raw, policy) else scrub(raw, limit)


def render_claude(rec: dict, policy: dict) -> list:
    out = []
    ts = rec.get("timestamp") if isinstance(rec.get("timestamp"), str) else ""
    typ = rec.get("type")
    msg = rec.get("message") if isinstance(rec.get("message"), dict) else {}
    content = msg.get("content")
    if typ == "assistant" and isinstance(content, list):
        for c in content:
            if not isinstance(c, dict):
                continue
            if c.get("type") == "text":
                out.append({"at": ts, "kind": "assistant", "text": safe_text(c.get("text") or "", 400, policy)})
            elif c.get("type") == "tool_use":
                name = str(c.get("name", "?"))
                out.append({"at": ts, "kind": "tool_use", "tool": EXCLUDED_TEXT if text_excluded(name, policy) else scrub(name, 64),
                            "text": summarize_input(c.get("input"), policy)})
    elif typ == "user":
        if isinstance(content, list) and any(isinstance(c, dict) and c.get("type") == "tool_result" for c in content):
            for c in content:
                if isinstance(c, dict) and c.get("type") == "tool_result":
                    # never a tool_result body (review D4): results carry file contents and command output
                    out.append({"at": ts, "kind": "tool_result", "error": bool(c.get("is_error")),
                                "text": "", "chars": len(_content_text(c.get("content")))})
        else:
            text = _content_text(content)
            if text:
                out.append({"at": ts, "kind": "user", "text": safe_text(text, 300, policy)})
    return out


def render_codex(rec: dict, policy: dict) -> list:
    ts = rec.get("timestamp") if isinstance(rec.get("timestamp"), str) else ""
    p = rec.get("payload") if isinstance(rec.get("payload"), dict) else {}
    pt = p.get("type")
    if rec.get("type") != "response_item":
        return []
    if pt == "message":
        role = p.get("role") if p.get("role") in ("user", "assistant", "developer", "system") else "?"
        if role in ("developer", "system"):
            return []
        return [{"at": ts, "kind": "assistant" if role == "assistant" else "user",
                 "text": safe_text(_content_text(p.get("content")), 400, policy)}]
    if pt in ("function_call", "custom_tool_call", "local_shell_call"):
        args = p.get("arguments") if isinstance(p.get("arguments"), str) else p.get("input")
        try:
            parsed = json.loads(args) if isinstance(args, str) else args
        except Exception:
            parsed = {"command": args}
        if isinstance(parsed, dict) and isinstance(parsed.get("cmd"), (str, list)) and "command" not in parsed:
            parsed = dict(parsed, command=parsed["cmd"] if isinstance(parsed["cmd"], str) else " ".join(map(str, parsed["cmd"])))
        if isinstance(parsed, dict) and isinstance(parsed.get("command"), list):
            parsed = dict(parsed, command=" ".join(map(str, parsed["command"])))
        name = str(p.get("name", pt))
        return [{"at": ts, "kind": "tool_use", "tool": EXCLUDED_TEXT if text_excluded(name, policy) else scrub(name, 64),
                 "text": summarize_input(parsed, policy)}]
    if pt in ("function_call_output", "custom_tool_call_output"):
        o = p.get("output")
        return [{"at": ts, "kind": "tool_result", "text": "", "chars": len(o) if isinstance(o, str) else 0}]
    return []


def record_cwd(rec: dict):
    if isinstance(rec.get("cwd"), str):
        return rec["cwd"]
    p = rec.get("payload")
    if isinstance(p, dict) and isinstance(p.get("cwd"), str):
        return p["cwd"]
    return None


def record_excluded(rec: dict, policy: dict) -> bool:
    """A record whose working directory is interview material taints the whole instance."""
    cwd = record_cwd(rec)
    return cwd is not None and text_excluded(cwd, policy)


def head_record(path: str, line_max: int):
    """The first record of a transcript (Codex session_meta carries the cwd), read within line_max."""
    try:
        raw = safe_read(path, line_max, offset=0)
    except OSError:
        return None
    line = raw.split(b"\n", 1)[0]
    try:
        obj = json.loads(line.decode("utf-8"))
        return obj if isinstance(obj, dict) else None
    except Exception:
        return None


# ---------------------------------------------------------------- bounded reading

def read_tail_lines(path: str, max_bytes: int, line_max: int):
    """Returns (lines, stats). Reads at most max_bytes from the end. A first partial line is dropped; an
    over-long or undecodable line is skipped and counted. Never raises for content problems."""
    stats = {"malformed": 0, "oversized": 0, "partial_head": False}
    fd = open_regular(path)
    try:
        size = os.fstat(fd).st_size
        start = max(0, size - max_bytes)
        raw = os.pread(fd, max_bytes, start)
    finally:
        os.close(fd)
    chunks = raw.split(b"\n")
    if start > 0 and chunks:
        chunks = chunks[1:]
        stats["partial_head"] = True
    if chunks and chunks[-1] == b"":
        chunks = chunks[:-1]
    elif chunks:  # trailing half line still being written: ignore it, the follower picks it up later
        chunks = chunks[:-1]
    lines = []
    for c in chunks:
        if len(c) > line_max:
            stats["oversized"] += 1
            continue
        lines.append(c)
    return lines, stats


def parse_lines(lines, stats) -> list:
    recs = []
    for c in lines:
        if not c.strip():
            continue
        try:
            obj = json.loads(c.decode("utf-8"))
            if isinstance(obj, dict):
                recs.append(obj)
            else:
                stats["malformed"] += 1
        except Exception:
            stats["malformed"] += 1
    return recs


def refuse(message="interview material is never peeked") -> dict:
    return {"ok": False, "code": "excluded", "message": message}


def tail(row: dict, n: int, policy: dict) -> dict:
    if row.get("excluded"):
        return refuse()
    path = row["path"]
    if path_excluded(path, policy, roots()):
        return refuse("path could not be classified")
    line_max = policy.get("peek_line_max_bytes", 1 << 20)
    try:
        lines, stats = read_tail_lines(path, policy.get("peek_tail_max_bytes", 4 << 20), line_max)
    except OSError:
        return refuse("transcript is not a readable regular file")
    recs = parse_lines(lines, stats)
    head = head_record(path, line_max)
    cwds = [c for c in (record_cwd(r) for r in ([head] if head else []) + recs) if c is not None]
    if not cwds:
        return refuse("working directory unknown; cannot classify")
    if any(text_excluded(c, policy) for c in cwds):
        return refuse()
    render = render_codex if row["kind"] == "codex" else render_claude
    items = []
    for r in recs:
        items.extend(render(r, policy))
    return {"ok": True, "id": row["id"], "items": items[-n:] if n > 0 else [], "stats": stats}


class Follower:
    """Incremental reader that survives truncation and rotation: (dev, ino) change or size < offset restarts at 0."""

    def __init__(self, path: str, offset: int | None = None, line_max: int = 1 << 20):
        self.path = path
        self.line_max = line_max
        st = os.lstat(path)
        self.key = (st.st_dev, st.st_ino)
        self.offset = st.st_size if offset is None else offset
        self.buf = b""
        self.stats = {"malformed": 0, "oversized": 0, "resets": 0}

    def poll(self, max_bytes: int = 1 << 20) -> list:
        try:
            st = os.lstat(self.path)
        except OSError:
            return []
        if not stat.S_ISREG(st.st_mode):
            return []
        if (st.st_dev, st.st_ino) != self.key or st.st_size < self.offset:
            self.key, self.offset, self.buf = (st.st_dev, st.st_ino), 0, b""
            self.stats["resets"] += 1
        if st.st_size == self.offset:
            return []
        try:
            raw = safe_read(self.path, max_bytes, offset=self.offset)
        except OSError:
            return []
        self.offset += len(raw)
        data = self.buf + raw
        parts = data.split(b"\n")
        self.buf = parts.pop()
        if len(self.buf) > self.line_max:
            self.buf = b""
            self.stats["oversized"] += 1
        good = []
        for c in parts:
            if len(c) > self.line_max:
                self.stats["oversized"] += 1
            else:
                good.append(c)
        return parse_lines(good, self.stats)


def follow(row: dict, policy: dict, out=sys.stdout, interval: float = 1.0, max_polls=None) -> int:
    """Local follow only (no -f over ssh, review M13)."""
    if row.get("excluded"):
        return 3
    fol = Follower(row["path"], line_max=policy.get("peek_line_max_bytes", 1 << 20))
    render = render_codex if row["kind"] == "codex" else render_claude
    polls = 0
    while max_polls is None or polls < max_polls:
        polls += 1
        for rec in fol.poll():
            if record_excluded(rec, policy):
                out.write("[excluded: interview material; stopping]\n")
                return 3
            for it in render(rec, policy):
                out.write(fmt(it) + "\n")
        out.flush()
        if max_polls is None or polls < max_polls:
            time.sleep(interval)
    return 0


def fmt(it: dict) -> str:
    at = (it.get("at") or "")[11:19]
    k = it.get("kind")
    if k == "tool_use":
        return f"{at} tool_use {it.get('tool')}: {it.get('text')}"
    if k == "tool_result":
        return f"{at} result{' ERROR' if it.get('error') else ''} ({it.get('chars', 0)} chars)"
    return f"{at} {k}: {it.get('text')}"


def fmt_row(r: dict) -> str:
    state = "active" if r["active"] else f"idle {r['age_s'] // 60}m"
    if r["excluded"]:
        return f"{r['id']:<28} {r['kind']:<16} {state:<10} [excluded]"
    desc = r.get("description") or r.get("project", "")
    return f"{r['id']:<28} {r['kind']:<16} {state:<10} {r.get('agentType', ''):<16} {desc[:70]}"


# ---------------------------------------------------------------- CLI

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="ahd_peek", description="read-only, redacted view of running agents")
    sp = ap.add_subparsers(dest="cmd", required=True)
    l = sp.add_parser("list")
    l.add_argument("--all", action="store_true")
    l.add_argument("--json", action="store_true")
    t = sp.add_parser("tail")
    t.add_argument("id")
    t.add_argument("-n", type=int, default=20)
    t.add_argument("-f", "--follow", action="store_true")
    t.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    policy = load_policy()
    if a.cmd == "list":
        rows = discover(policy, include_all=a.all)
        if a.json:
            print(json.dumps({"ok": True, "items": rows}))
        else:
            for r in rows:
                print(fmt_row(r))
        return 0
    row = find(a.id, policy)
    if row is None:
        print(json.dumps({"ok": False, "code": "not_found"}) if a.json else f"no instance {a.id}", file=sys.stderr if not a.json else sys.stdout)
        return 4
    res = tail(row, max(0, min(a.n, 500)), policy)
    if a.json:
        print(json.dumps(res))
    elif not res["ok"]:
        print(f"refused: {res['message']}", file=sys.stderr)
    else:
        for it in res["items"]:
            print(fmt(it))
    if not res["ok"]:
        return 3
    if a.follow:
        try:
            return follow(row, policy)
        except KeyboardInterrupt:
            return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
