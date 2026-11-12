"""Quote-aware shell word splitting, shared by the hooks that must not be fooled by quoted punctuation.

Split a Bash command line into the argument lists the shell would run. Quote state is tracked on the raw text, so a
quoted or escaped `;`, `&&`, `|`, `(`, `)` or newline is a word character and never a command separator (receipt r14 F1
on PR 179; goodqa#15684). A line whose words only the shell itself can know (an unbalanced quote, `$(...)`, backticks,
`<(...)`, `$'...'`, a here-document) raises Unparsed, and the callers choose their own safe side: the stamp hooks mint
nothing, the dropped-owner gate falls back to its conservative substring judgement.

`lenient=True` (dropped_gate) reads the forms a real command line uses all the time instead of giving up: a
balanced `$(...)` or backtick span is one computed word (its body is reported through `bodies` so the caller can judge
what it runs), an ANSI-C `$'...'` span is a computed piece of its word (kept raw: its escapes are not decoded), a
here-document is recognised only where the shell would see one (an unquoted `<<` operator; never in a quoted word, a
comment or a `<<<` here-string), its body skipped and handed back on the command it feeds, and a `<<<` here-string's
word is handed back the same way. A Command records whether a pipe feeds it (`piped`).

Stdlib only, Python 3.9 compatible. Used by mission_gate.py and dropped_gate.py.
"""
from __future__ import annotations

# Control operators end a simple command; redirection operators take the next word as their target. Longest first.
SEPARATORS = (";;&", ";;", ";&", "&&", "||", "|&", ";", "&", "|", "(", ")", "\n")
REDIRECTS = ("&>>", "&>", ">>", ">&", "<&", "<>", ">|", "<", ">")
HEREDOCS = ("<<<", "<<-", "<<")
OPERATORS = tuple(sorted(SEPARATORS + REDIRECTS + HEREDOCS, key=len, reverse=True))
OPERATOR_START = set(";&|()<>\n")
MAX_LINE = 20000  # never judge a truncated command line
MAX_NEST = 8  # nested `$(...)` levels read before giving up


class Unparsed(ValueError):
    """The words of this command line cannot be known without running the shell."""


class Word(str):
    """One shell word after quote removal. `computed`: it holds a `$` expansion or an unquoted glob or brace the
    shell may rewrite, so the process could see other text; `splits`: some of that expansion is unquoted, so the
    shell may also split it into several words (or none); `tilde`: it starts with an unquoted `~` (bash expands `~`
    and `~/...`)."""
    computed = False
    splits = False
    tilde = False


class Command(list):
    """The words of one simple command. `heredocs`: the here-document and here-string bodies (str) that feed it
    (lenient mode); `piped`: a `|` or `|&` feeds its standard input."""
    heredocs = ()
    piped = False


def shell_tokens(cmd: str, lenient: bool = False, bodies: list = None) -> list:
    """[(kind, text)] with kind 'op' (an unquoted, unescaped operator), 'word' (a Word) or, lenient only, 'heredoc'
    (the body of a here-document, emitted right after the newline that ends its line). Quote state is tracked on the
    raw text, so `";"`, `';'`, `\\;` and a newline inside quotes are word characters, never operators. `#` starts a
    comment only at the start of a word. Raises Unparsed for forms whose words or commands only the shell knows: an
    unbalanced quote, `<(...)`/`>(...)`, `$'...'`, and (not lenient) `$(...)`, backticks or a here-document.
    `bodies`, if given, collects the text of every `$(...)` and backtick span (and of each substitution in an unquoted
    here-document body) so the caller can judge what they run."""
    tokens, _ = _scan(cmd, 0, False, lenient, bodies, 0)
    return tokens


def _heredoc_delimiter(cmd: str, i: int):
    """(delimiter, quoted, next index) of the word after `<<` at i, or None."""
    n = len(cmd)
    while i < n and cmd[i] in " \t":
        i += 1
    out, quoted, start = [], False, i
    while i < n and cmd[i] not in " \t\r\n" and cmd[i] not in OPERATOR_START:
        c = cmd[i]
        if c in "'\"":
            close = cmd.find(c, i + 1)
            if close < 0:
                return None
            out.append(cmd[i + 1:close])
            quoted, i = True, close + 1
        elif c == "\\" and i + 1 < n:
            out.append(cmd[i + 1])
            quoted, i = True, i + 2
        else:
            out.append(c)
            i += 1
    return ("".join(out), quoted, i) if i > start else None


def _heredoc_body(cmd: str, at: int, delimiter: str, strip_tabs: bool):
    """(body, index after the terminator line) for a body that starts at `at` (just after a newline)."""
    pos = at
    while pos <= len(cmd):
        eol = cmd.find("\n", pos)
        line = cmd[pos:] if eol < 0 else cmd[pos:eol]
        if (line.lstrip("\t") if strip_tabs else line) == delimiter:
            return cmd[at:pos], (len(cmd) if eol < 0 else eol + 1)
        if eol < 0:
            break
        pos = eol + 1
    return cmd[at:], len(cmd)  # no terminator: the body runs to the end of the text


def _scan(cmd: str, i: int, nested: bool, lenient: bool, bodies, level: int):
    """Tokens from index i. nested: stop after the unmatched `)` that closes a `$(`. Returns (tokens, next index)."""
    if level > MAX_NEST:
        raise Unparsed("substitutions nested too deeply")
    out, n = [], len(cmd)
    buf, computed, split, tilde, quoted = None, False, False, False, False
    depth, pending = 0, []

    def flush():
        nonlocal buf, computed, split, tilde, quoted
        if buf is not None:
            word = Word("".join(buf))
            word.computed, word.splits, word.tilde = computed, split, tilde
            out.append(("word", word))
        buf, computed, split, tilde, quoted = None, False, False, False, False

    def ansi_c(start):
        """Index after the `$'...'` span at start, kept raw as a computed (not split) piece of the current word."""
        nonlocal buf, computed
        j = start + 2
        while j < n and cmd[j] != "'":
            j += 2 if cmd[j] == "\\" else 1
        if j >= n:
            raise Unparsed("unbalanced $'")
        buf = [] if buf is None else buf
        buf.append(cmd[start:j + 1])
        computed = True
        return j + 1

    def substitution(start):
        """Index after the `$(...)` or backtick span at start, as one computed piece of the current word."""
        nonlocal buf, computed
        if cmd[start] == "`":
            j = start + 1
            while j < n and cmd[j] != "`":
                j += 2 if cmd[j] == "\\" else 1
            if j >= n:
                raise Unparsed("unbalanced backtick")
            body, end = cmd[start + 1:j], j + 1
        else:
            _, end = _scan(cmd, start + 2, True, lenient, bodies, level + 1)
            body = cmd[start + 2:end - 1]
        if bodies is not None:
            bodies.append(body)
        buf = [] if buf is None else buf
        buf.append(cmd[start:end])
        computed = True
        return end

    while i < n:
        c = cmd[i]
        if c == "\\":
            if cmd.startswith("\\\n", i):  # a line continuation joins the lines
                i += 2
                continue
            buf = [] if buf is None else buf
            quoted = True
            buf.append(cmd[i + 1] if i + 1 < n else "")
            i += 2
        elif c == "'":
            close = cmd.find("'", i + 1)
            if close < 0:
                raise Unparsed("unbalanced single quote")
            buf = [] if buf is None else buf
            quoted = True
            buf.append(cmd[i + 1:close])
            i = close + 1
        elif c == '"':
            buf = [] if buf is None else buf
            quoted = True
            i += 1
            while True:
                if i >= n:
                    raise Unparsed("unbalanced double quote")
                d = cmd[i]
                if d == '"':
                    i += 1
                    break
                if d == "\\" and i + 1 < n and cmd[i + 1] in '$`"\\\n':
                    buf.append("" if cmd[i + 1] == "\n" else cmd[i + 1])
                    i += 2
                    continue
                if d == "`" or cmd.startswith("$(", i):
                    if not lenient:
                        raise Unparsed("command substitution")
                    i = substitution(i)
                    continue
                computed = computed or d == "$"
                buf.append(d)
                i += 1
        elif c == "`" or cmd.startswith("$(", i) or cmd.startswith("$'", i):
            if not lenient:
                raise Unparsed("command substitution or ANSI-C quoting")
            if cmd.startswith("$'", i):
                i = ansi_c(i)
            else:
                i = substitution(i)
                split = True  # an unquoted substitution: its output is split into words
        elif c in " \t\r":
            flush()
            i += 1
        elif c == "#" and buf is None:  # a comment runs to the end of the line (the newline still separates)
            while i < n and cmd[i] != "\n":
                i += 1
        elif c in OPERATOR_START:
            if c in "<>" and cmd.startswith("(", i + 1):
                raise Unparsed("process substitution")
            op = next(o for o in OPERATORS if cmd.startswith(o, i))
            if op in HEREDOCS and not lenient:
                raise Unparsed("here-document")
            if op in REDIRECTS and buf is not None and not quoted and "".join(buf).isdigit():
                buf, computed, split, tilde, quoted = None, False, False, False, False  # `2>&1`: the fd belongs to the op
            flush()
            i += len(op)
            if op in ("<<-", "<<"):
                found = _heredoc_delimiter(cmd, i)
                if found is None:
                    raise Unparsed("here-document without a readable delimiter")
                delimiter, delimiter_quoted, i = found
                pending.append((delimiter, delimiter_quoted, op == "<<-"))
                out.append(("op", op))
                continue
            if op == ")" and nested:
                if depth == 0:
                    return out, i
                depth -= 1
            elif op == "(":
                depth += 1
            out.append(("op", op))
            if op == "\n" and pending:
                for delimiter, delimiter_quoted, strip in pending:
                    body, i = _heredoc_body(cmd, i, delimiter, strip)
                    if not delimiter_quoted and bodies is not None:
                        bodies.extend(_body_substitutions(body, lenient, level))
                    out.append(("heredoc", body))
                pending = []
        else:
            if buf is None:
                buf, tilde = [], c == "~"
            if c in "$*?[{":  # an unquoted expansion or a glob: the process may see other, or more, words
                computed = split = True
            buf.append(c)
            i += 1
    if nested:
        raise Unparsed("unbalanced $(")
    flush()
    return out, i


def _body_substitutions(body: str, lenient: bool, level: int) -> list:
    """The `$(...)` and backtick bodies an unquoted here-document expands (the shell runs them)."""
    found, i, n = [], 0, len(body)
    while i < n:
        if body[i] == "\\":
            i += 2
        elif body.startswith("$(", i):
            try:
                _, end = _scan(body, i + 2, True, lenient, None, level + 1)
            except Unparsed:
                found.append(body[i + 2:])
                break
            found.append(body[i + 2:end - 1])
            i = end
        elif body[i] == "`":
            j = i + 1
            while j < n and body[j] != "`":
                j += 2 if body[j] == "\\" else 1
            found.append(body[i + 1:j])
            i = j + 1
        else:
            i += 1
    return found


def split_commands(cmd: str, lenient: bool = False, bodies: list = None, limit: int = MAX_LINE):
    """The argument lists (lists of Word) the shell would run, split only at unquoted control operators, with
    redirections and their targets removed and comments dropped. None when the words cannot be known (see Unparsed,
    or a line over MAX_LINE characters); an empty list for a line with no command. Lenient: see the module doc; each
    command is a Command whose `heredocs` holds the here-document bodies that feed the command ending that line."""
    if len(cmd) > limit:
        return None
    try:
        tokens = shell_tokens(cmd, lenient, bodies)
    except Unparsed:
        return None
    out, cur, i = [], Command(), 0
    while i < len(tokens):
        kind, text = tokens[i]
        if kind == "word":
            cur.append(text)
        elif kind == "heredoc":
            owner = out[-1] if out else cur
            owner.heredocs = tuple(owner.heredocs) + (text,)
        elif text in SEPARATORS:
            out.append(cur)
            cur = Command()
            cur.piped = text in ("|", "|&")
        elif text == "<<<" and lenient and i + 1 < len(tokens) and tokens[i + 1][0] == "word":
            cur.heredocs = tuple(cur.heredocs) + (tokens[i + 1][1],)  # a here-string feeds its word on stdin
            i += 1
        elif text in ("<<-", "<<"):
            pass  # a here-document operator: its delimiter was consumed by the scanner
        elif i + 1 < len(tokens) and tokens[i + 1][0] == "word":  # a redirection: drop its target too
            i += 1
        i += 1
    out.append(cur)
    # A here-document keeps its command even when the command has no words (`<<EOF` alone): nothing runs it.
    return [c for c in out if c]


def simple_commands(cmd: str) -> list:
    """split_commands, with [] for a line whose words cannot be known: no stamp is better than a wrong one."""
    return split_commands(cmd) or []
