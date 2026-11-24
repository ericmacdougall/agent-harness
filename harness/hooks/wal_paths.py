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
import fnmatch
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


# goodqa#17155: the configuration files every session loads. Writes are refused like WAL writes; reads stay allowed.
# A root's last segment may be a pattern (settings*.json covers settings.json and settings.local.json).
CONFIG_NAMES_CLAUDE = ('CLAUDE.md', 'settings*.json')
CONFIG_NAMES_CODEX = ('config.toml', 'hooks.json')


def codex_dirs(homes=None):
    """Every Codex home: <home>/.codex for each home, and CODEX_HOME when it is set."""
    out = []
    for home in list(homes or []) + [os.path.expanduser('~')]:
        if isinstance(home, str) and home.startswith('/'):
            out.append(posixpath.join(home, '.codex'))
    configured = os.environ.get('CODEX_HOME')
    if configured and configured.startswith('/'):
        out.append(configured)
    return out


def config_roots(homes=None):
    """The protected configuration file roots, casefolded: each name under each Claude and Codex home, with the home
    as written and resolved (a link to the home is seen)."""
    roots = set()
    for dirs, names in ((claude_dirs(homes), CONFIG_NAMES_CLAUDE), (codex_dirs(homes), CONFIG_NAMES_CODEX)):
        for d in dirs:
            for form in _forms(d):
                for name in names:
                    roots.add(posixpath.join(form, name.casefold()))
    return sorted(roots)


IN, POSSIBLY_IN, ABOVE, POSSIBLY_ABOVE = 'in', 'possibly-in', 'above', 'possibly-above'
_STRENGTH = {None: 0, POSSIBLY_ABOVE: 1, ABOVE: 2, POSSIBLY_IN: 3, IN: 4}
LANDS = frozenset({IN, POSSIBLY_IN})        # a write here may land in a protected root
REACHES = frozenset({ABOVE, POSSIBLY_ABOVE})  # a directory copy, extraction or link copy here may create one
_GLOB = re.compile(r'[*?\[]')
_BRACE = re.compile(r'\{([^{}]*,[^{}]*)\}')
BRACE_LIMIT = 64


def _braces(text):
    """The brace expansions of `text`, at most BRACE_LIMIT; past the limit every brace group becomes `*`."""
    out, todo = [], [text]
    while todo:
        t = todo.pop()
        m = _BRACE.search(t)
        if not m:
            out.append(t)
        else:
            todo.extend(t[:m.start()] + alt + t[m.end():] for alt in m.group(1).split(','))
        if len(out) + len(todo) > BRACE_LIMIT:
            return [_BRACE.sub('*', text)]
    return out


def _seg_match(a, b):
    """Two path segments (casefolded; either may be a glob) can name the same entry. A pattern the matcher cannot
    parse may match anything."""
    if a == b:
        return True
    ga, gb = bool(_GLOB.search(a)), bool(_GLOB.search(b))
    if ga and gb:
        return True
    try:
        if ga:
            return fnmatch.fnmatchcase(b, a)
        if gb:
            return fnmatch.fnmatchcase(a, b)
    except re.error:
        return True
    return False


def _relation_one(path, roots, file_roots):
    parts = [p for p in path.split('/') if p]
    glob_at = next((k for k, p in enumerate(parts) if _GLOB.search(p)), None)
    if glob_at is None:
        forms = _forms(path)
    else:
        # the literal prefix is resolved like any path (a link in it is followed); the pattern rest is kept
        head = '/' + '/'.join(parts[:glob_at])
        rest = parts[glob_at:]
        if '..' in rest:
            # `..` after a pattern goes up from wherever the pattern leads: anything below the prefix's parent
            forms = {posixpath.dirname(f) + '/*' * max(1, len(rest)) for f in _forms(head)}
        else:
            forms = {posixpath.join(f, *[r.casefold() for r in rest]) for f in _forms(head)}
    best = None
    for f in forms:
        ps = [p for p in f.split('/') if p]
        for r in roots:
            rs = [p for p in r.split('/') if p]
            n = min(len(ps), len(rs))
            if not all(_seg_match(ps[k], rs[k]) for k in range(n)):
                continue
            globbed = any(_GLOB.search(p) for p in ps[:n])
            if len(ps) >= len(rs):
                if file_roots and len(ps) > len(rs):
                    continue  # nothing lives inside a file
                rel = POSSIBLY_IN if globbed else IN
            else:
                rel = POSSIBLY_ABOVE if globbed else ABOVE
            if _STRENGTH[rel] > _STRENGTH[best]:
                best = rel
    return best


def relation(path, roots, file_roots=False):
    """Where an absolute `path` (it may hold glob segments and brace groups) stands to `roots`: IN (a root or inside
    one), POSSIBLY_IN (a pattern that may name one or something inside), ABOVE (a proper ancestor of a root),
    POSSIBLY_ABOVE (a pattern that may be one), or None. Segment by segment: a literal prefix is resolved the way the
    kernel does (_real), a glob segment matches when fnmatch can match the root's segment, braces expand up to
    BRACE_LIMIT alternatives (more: each group counts as `*`), and `..` after a pattern counts as anything below the
    pattern's parent. File roots (the configuration files) have nothing inside them."""
    if not isinstance(path, str) or not path.startswith('/') or '\x00' in path:
        return None
    best = None
    for alt in _braces(path):
        rel = _relation_one(alt, roots, file_roots)
        if _STRENGTH[rel] > _STRENGTH[best]:
            best = rel
    return best


def tree_relation(path, roots=None):
    """relation() to the WAL tree roots."""
    return relation(path, wal_roots() if roots is None else roots)


def config_relation(path, roots=None):
    """relation() to the protected configuration files (goodqa#17155)."""
    return relation(path, config_roots() if roots is None else roots, file_roots=True)


def in_wal_tree(path, roots=None):
    """True when the absolute `path` is a WAL tree root or anything inside one, as written or where it leads (a
    literal path; a pattern counts when it may name one). The file-tool rule and the shell rule share this test."""
    return tree_relation(path, roots) in LANDS


def below_toward_tree(path, roots=None):
    """When the absolute `path` is a proper ancestor of a WAL tree root (a recursive copy or an extraction there can
    create the tree's files), the name of the entry directly below `path` on the way to the root (`.claude` for the
    home, `wals` for the Claude home); else None. A pattern that may be an ancestor gives '*' (the entry is unknown)."""
    rel = tree_relation(path, roots)
    if rel == POSSIBLY_ABOVE:
        return '*'
    if rel != ABOVE:
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
