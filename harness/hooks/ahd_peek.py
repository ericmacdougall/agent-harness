#!/usr/bin/env python3
"""ahd_peek: list running Claude Code and Codex agent instances and tail their recent activity, redacted.

Read-only toward transcripts. Interview material (any path, project dir, agent description, cwd or host whose token
starts with a configured prefix, see ahd_policy.json "exclude") is never read, shown or stored: such an instance is
listed only as `excluded`, by stat. Classification fails closed: a path that cannot be classified is excluded.

Secrets are removed with redact.py; if redact.py cannot be imported, no free text is printed at all.
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


def load_policy(path=None) -> dict:
    p = Path(path) if path else POLICY_FILE
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or not isinstance(data.get("exclude"), dict):
            raise ValueError("policy has no exclude table")
        return data
    except Exception as exc:
        # fail closed: without an exclusion table every read is refused (classify returns excluded)
        return {"exclude": None, "policy_error": f"{type(exc).__name__}"}


def home() -> Path:
    return Path(os.environ.get("HOME") or os.path.expanduser("~"))


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


def host_excluded(host: str, policy: dict) -> bool:
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
        st = p.stat()
        return st if stat.S_ISREG(st.st_mode) else None
    except OSError:
        return None


def _read_small_json(p: Path, limit: int = 16384):
    try:
        with open(p, "rb") as fh:
            raw = fh.read(limit + 1)
        if len(raw) > limit:
            return None
        return json.loads(raw.decode("utf-8"))
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
            if not proj.is_dir():
                continue
            entries = list(proj.iterdir())
        except OSError:
            continue
        proj_excl = text_excluded(proj.name, policy)
        for ent in entries:
            if ent.suffix == ".jsonl" and ent.is_file():
                st = _stat(ent)
                if st:
                    out.append(_row("s", ent.stem, ent, st, proj.name, None, proj_excl, policy, rts, now, active_s))
            elif ent.is_dir():
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
                    meta = _read_small_json(f.with_name(f.stem + ".meta.json")) or {}
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
    excluded = proj_excl or path_excluded(path, policy, rts) or text_excluded(desc, policy)
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

def scrub(text, limit: int = 300) -> str:
    if not isinstance(text, str):
        return ""
    if _redact is None:
        return f"[{len(text)} chars, redactor unavailable]"
    one = " ".join(text.split())
    out = _redact.redact(one[: limit * 4])
    return out if len(out) <= limit else out[: limit - 1] + "…"


INPUT_KEYS = ("command", "description", "file_path", "path", "pattern", "url", "query", "prompt", "subagent_type",
              "to", "skill")


def summarize_input(inp) -> str:
    if not isinstance(inp, dict):
        return scrub(json.dumps(inp)[:400] if inp is not None else "", 200)
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


def render_claude(rec: dict) -> list:
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
                out.append({"at": ts, "kind": "assistant", "text": scrub(c.get("text"), 400)})
            elif c.get("type") == "tool_use":
                out.append({"at": ts, "kind": "tool_use", "tool": scrub(str(c.get("name", "?")), 64),
                            "text": summarize_input(c.get("input"))})
    elif typ == "user":
        if isinstance(content, list) and any(isinstance(c, dict) and c.get("type") == "tool_result" for c in content):
            for c in content:
                if isinstance(c, dict) and c.get("type") == "tool_result":
                    body = _content_text(c.get("content"))
                    out.append({"at": ts, "kind": "tool_result", "error": bool(c.get("is_error")),
                                "text": scrub(body, 200), "chars": len(body)})
        else:
            text = _content_text(content)
            if text:
                out.append({"at": ts, "kind": "user", "text": scrub(text, 300)})
    return out


def render_codex(rec: dict) -> list:
    ts = rec.get("timestamp") if isinstance(rec.get("timestamp"), str) else ""
    p = rec.get("payload") if isinstance(rec.get("payload"), dict) else {}
    pt = p.get("type")
    if rec.get("type") != "response_item":
        return []
    if pt == "message":
        role = p.get("role") if p.get("role") in ("user", "assistant", "developer", "system") else "?"
        if role in ("developer", "system"):
            return []
        return [{"at": ts, "kind": "assistant" if role == "assistant" else "user", "text": scrub(_content_text(p.get("content")), 400)}]
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
        return [{"at": ts, "kind": "tool_use", "tool": scrub(str(p.get("name", pt)), 64), "text": summarize_input(parsed)}]
    if pt in ("function_call_output", "custom_tool_call_output"):
        o = p.get("output")
        body = o if isinstance(o, str) else json.dumps(o)[:2000] if o is not None else ""
        return [{"at": ts, "kind": "tool_result", "text": scrub(body, 200), "chars": len(body)}]
    return []


def screen(items: list, policy: dict) -> list:
    """Blank any rendered item whose text or tool name names interview material (fail closed)."""
    out = []
    for it in items:
        if text_excluded(it.get("text", ""), policy) or text_excluded(it.get("tool", ""), policy):
            it = {"at": it.get("at", ""), "kind": it.get("kind"), "text": "[excluded: interview material]"}
        out.append(it)
    return out


def record_excluded(rec: dict, policy: dict) -> bool:
    """A record whose working directory is interview material taints the whole instance."""
    for key in ("cwd",):
        if isinstance(rec.get(key), str) and text_excluded(rec[key], policy):
            return True
    p = rec.get("payload")
    if isinstance(p, dict) and isinstance(p.get("cwd"), str) and text_excluded(p["cwd"], policy):
        return True
    return False


# ---------------------------------------------------------------- bounded reading

def read_tail_lines(path: str, max_bytes: int, line_max: int):
    """Returns (lines, stats). Reads at most max_bytes from the end. A first partial line is dropped; an
    over-long or undecodable line is skipped and counted. Never raises for content problems."""
    stats = {"malformed": 0, "oversized": 0, "partial_head": False}
    with open(path, "rb") as fh:
        size = os.fstat(fh.fileno()).st_size
        start = max(0, size - max_bytes)
        fh.seek(start)
        raw = fh.read(max_bytes)
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


def tail(row: dict, n: int, policy: dict) -> dict:
    if row.get("excluded"):
        return {"ok": False, "code": "excluded", "message": "interview material is never peeked"}
    path = row["path"]
    if path_excluded(path, policy, roots()):
        return {"ok": False, "code": "excluded", "message": "path could not be classified"}
    lines, stats = read_tail_lines(path, policy.get("peek_tail_max_bytes", 4 << 20), policy.get("peek_line_max_bytes", 1 << 20))
    recs = parse_lines(lines, stats)
    if any(record_excluded(r, policy) for r in recs):
        return {"ok": False, "code": "excluded", "message": "interview material is never peeked"}
    render = render_codex if row["kind"] == "codex" else render_claude
    items = []
    for r in recs:
        items.extend(screen(render(r), policy))
    return {"ok": True, "id": row["id"], "items": items[-n:] if n > 0 else [], "stats": stats}


class Follower:
    """Incremental reader that survives truncation and rotation: (dev, ino) change or size < offset restarts at 0."""

    def __init__(self, path: str, offset: int | None = None, line_max: int = 1 << 20):
        self.path = path
        self.line_max = line_max
        st = os.stat(path)
        self.key = (st.st_dev, st.st_ino)
        self.offset = st.st_size if offset is None else offset
        self.buf = b""
        self.stats = {"malformed": 0, "oversized": 0, "resets": 0}

    def poll(self, max_bytes: int = 1 << 20) -> list:
        try:
            st = os.stat(self.path)
        except OSError:
            return []
        if (st.st_dev, st.st_ino) != self.key or st.st_size < self.offset:
            self.key, self.offset, self.buf = (st.st_dev, st.st_ino), 0, b""
            self.stats["resets"] += 1
        if st.st_size == self.offset:
            return []
        with open(self.path, "rb") as fh:
            fh.seek(self.offset)
            raw = fh.read(max_bytes)
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
            for it in screen(render(rec), policy):
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
        return f"{at} result{' ERROR' if it.get('error') else ''} ({it.get('chars', 0)} chars): {it.get('text')}"
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
