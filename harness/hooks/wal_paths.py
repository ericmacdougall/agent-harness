"""The session WAL tree and whose WAL a path is (goodqa#17008). Standard library only.

Session write-ahead logs live under <claude home>/wals/<session>/: main.jsonl is main's, agent-<id>.jsonl a
sub-agent's. Provenance, the chat-send allow-list and other grants read a row of main.jsonl as main's, so only the
sanctioned writers may add one: the harness hooks themselves (wal.py) and wal_note.py, which a guard lets a sub-agent
aim only at its own WAL. This module is the one predicate for "this path is in the WAL tree" that every guard uses:
command_guard.py for shell writes and wal.py's PreToolUse hook for the Write, Edit, MultiEdit and NotebookEdit tools.

These guards are best-effort defence in depth, not the guarantee (main's ruling of 2026-11-24). Sub-agents run as the
same OS user, so a route the guards cannot judge statically (a script already on disk, a decoded path) can still append
a row. The guarantee that a sub-agent cannot forge a row main reads as its own belongs to a non-guard mechanism
(goodqa#17019: rows authenticated with a key only main's hook can read, or WALs written by a separate process).
"""
import hashlib
import os
import posixpath
import re

# A raw text that names the tree, for code and for write targets the guard cannot resolve.
NAMES_TREE = re.compile(r'(?i)\.claude[\\/]+wals\b|\bwals[\\/]+[^\s\'"]*\.jsonl|CLAUDE_CONFIG_DIR')


def safe_id(value: object) -> str:
    """The file-name form of a session or agent id (wal.py names WALs with it)."""
    original = str(value or "unknown")
    cleaned = re.sub(r"[^A-Za-z0-9._-]", "_", original)
    # Only lowercase unescaped IDs use their original spelling. Escaping every
    # uppercase ID keeps Foo and foo distinct on case-insensitive filesystems.
    if (cleaned == original and cleaned == cleaned.lower() and len(cleaned) <= 120
            and cleaned.strip(".") and not cleaned.startswith("z-")):
        return cleaned
    # Escaped IDs live in a reserved namespace. An ordinary ID equal to an
    # escaped result is escaped again, so direct alias construction fails.
    digest = hashlib.sha256(original.encode(errors="replace")).hexdigest()[:20]
    stem = cleaned.lower()[:97].strip(".") or "_"
    return f"z-{stem}-{digest}"


def claude_dirs(homes=None):
    """Every Claude home: <home>/.claude for each home, and CLAUDE_CONFIG_DIR when it is set."""
    out = []
    for home in list(homes or []) + [os.path.expanduser('~')]:
        if isinstance(home, str) and home.startswith('/'):
            out.append(posixpath.join(home, '.claude'))
    configured = os.environ.get('CLAUDE_CONFIG_DIR')
    if configured and configured.startswith('/'):
        out.append(configured)
    return out


def _real(path):
    """Where `path` really leads, resolved the way the kernel does: the deepest existing ancestor of the path AS
    WRITTEN (so `link/..` goes up from the link's target, not from the link), through realpath, with the rest
    appended; casefolded. None when nothing can be resolved."""
    parts = path.split('/')
    for k in range(len(parts), 0, -1):
        head = '/'.join(parts[:k]) or '/'
        try:
            if os.path.lexists(head):
                return posixpath.normpath(posixpath.join(os.path.realpath(head), *[p for p in parts[k:] if p])).casefold()
        except (OSError, ValueError):
            return None
    return None


def _forms(path):
    """The path as written (normalised) and where it really leads (_real). A link to the tree, a `..` after a link, or a
    new file inside the tree is seen."""
    forms = {posixpath.normpath(path).casefold()}
    real = _real(path)
    if real:
        forms.add(real)
    return forms


def wal_roots(homes=None):
    """The WAL tree roots, casefolded, as written and resolved."""
    roots = set()
    for d in claude_dirs(homes):
        roots |= _forms(posixpath.join(d, 'wals'))
    return sorted(roots)


def in_wal_tree(path, roots=None):
    """True when the absolute `path` is a WAL tree root or anything inside one, as written or where it leads."""
    if not isinstance(path, str) or not path.startswith('/') or '\x00' in path:
        return False
    roots = wal_roots() if roots is None else roots
    return any(f == r or f.startswith(r + '/') for f in _forms(path) for r in roots)


def below_toward_tree(path, roots=None):
    """When the absolute `path` is a proper ancestor of a WAL tree root (a recursive copy or an extraction there can
    create the tree's files), the name of the entry directly below `path` on the way to the root (`.claude` for the
    home, `wals` for the Claude home); else None."""
    if not isinstance(path, str) or not path.startswith('/') or '\x00' in path:
        return None
    roots = wal_roots() if roots is None else roots
    for f in _forms(path):
        base = f.rstrip('/') + '/' if f != '/' else '/'
        for r in roots:
            if r.startswith(base) and r != f:
                return r[len(base):].split('/')[0]
    return None


def wal_owner(path, roots=None):
    """(session, owner) for a WAL file path: owner is 'main' or 'agent-<id>'; None outside the tree or for any other
    name in it."""
    roots = wal_roots() if roots is None else roots
    inside = [f for f in _forms(path) if any(f.startswith(r + '/') for r in roots)] if isinstance(path, str) else []
    if not inside or not path.startswith('/'):
        return None
    # where it really leads when that differs from the text (a link, or `..` after one)
    parts = sorted(inside, key=lambda f: f == posixpath.normpath(path).casefold())[0].split('/')
    if len(parts) < 2:
        return None
    session, name = parts[-2], parts[-1]
    if name.casefold() == 'main.jsonl':
        return session, 'main'
    if name.casefold().startswith('agent-') and name.casefold().endswith('.jsonl'):
        return session, name[:-len('.jsonl')]
    return session, None


def own_wal(session_id, agent_id):
    """The WAL a sub-agent may write: ~/.claude/wals/<session>/agent-<id>.jsonl, where wal.py's SubagentStart hook
    put it."""
    return posixpath.join(os.path.expanduser('~'), '.claude', 'wals', safe_id(session_id),
                          'agent-%s.jsonl' % safe_id(agent_id))


def is_own_wal(path, session_id, agent_id):
    """True when `path` leads to the caller's own agent WAL, resolved the way the kernel does (a link named like the
    own WAL that leads to main's is not; `link/../wals/<s>/agent-<id>.jsonl` that leads to the own WAL is)."""
    if not (session_id and agent_id) or not isinstance(path, str) or not path.startswith('/'):
        return False
    real, own = _real(path), _real(own_wal(session_id, agent_id))
    return real is not None and real == own


FILE_TOOLS = {'write', 'edit', 'multiedit', 'notebookedit'}


def file_tool_refusal(tool_name, tool_input, cwd=None):
    """The refusal reason when a file-writing tool targets the WAL tree, else None."""
    if str(tool_name or '').casefold() not in FILE_TOOLS or not isinstance(tool_input, dict):
        return None
    for key in ('file_path', 'notebook_path', 'path'):
        value = tool_input.get(key)
        if not isinstance(value, str) or not value:
            continue
        path = os.path.expanduser(value)
        if not path.startswith('/'):
            path = posixpath.join(cwd if isinstance(cwd, str) and cwd.startswith('/') else os.getcwd(), path)
        if in_wal_tree(path):
            return ('the session WALs under ~/.claude/wals are written only by the harness hooks and wal_note.py, '
                    'never by a file tool (goodqa#17008). Record a row with: python3 ~/.claude/hooks/wal_note.py '
                    '--wal <your WAL> --event <event> --note <text>')
    return None
