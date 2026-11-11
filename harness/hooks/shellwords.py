"""Quote-aware shell word splitting, shared by the hooks that must not be fooled by quoted punctuation.

Split a Bash command line into the argument lists the shell would run. Quote state is tracked on the raw text, so a
quoted or escaped `;`, `&&`, `|`, `(`, `)` or newline is a word character and never a command separator (receipt r14 F1
on PR 179; goodqa#15684). A line whose words only the shell itself can know (an unbalanced quote, `$(...)`, backticks,
`<(...)`, `$'...'`, a here-document) raises Unparsed, and the callers choose their own safe side: the stamp hooks mint
nothing, the dropped-owner gate falls back to its conservative substring judgement.

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


class Unparsed(ValueError):
    """The words of this command line cannot be known without running the shell."""


class Word(str):
    """One shell word after quote removal. `computed`: it holds a `$` expansion or an unquoted glob or brace the
    shell may rewrite, so the process could see other text; `tilde`: it starts with an unquoted `~` (bash expands `~`
    and `~/...`)."""
    computed = False
    tilde = False


def shell_tokens(cmd: str) -> list:
    """[(kind, text)] with kind 'op' (an unquoted, unescaped operator) or 'word' (a Word). Quote state is tracked on
    the raw text, so `";"`, `';'`, `\\;` and a newline inside quotes are word characters, never operators.
    `#` starts a comment only at the start of a word. Raises Unparsed for forms whose words or commands only the
    shell knows: an unbalanced quote, `$(...)`, backticks, `<(...)`/`>(...)`, `$'...'`, or a here-document."""
    out, i, n = [], 0, len(cmd)
    buf, computed, tilde, quoted = None, False, False, False

    def flush():
        nonlocal buf, computed, tilde, quoted
        if buf is not None:
            word = Word("".join(buf))
            word.computed, word.tilde = computed, tilde
            out.append(("word", word))
        buf, computed, tilde, quoted = None, False, False, False

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
                    raise Unparsed("command substitution")
                computed = computed or d == "$"
                buf.append(d)
                i += 1
        elif c == "`" or cmd.startswith("$(", i) or cmd.startswith("$'", i):
            raise Unparsed("command substitution or ANSI-C quoting")
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
            if op in HEREDOCS:
                raise Unparsed("here-document")
            if op in REDIRECTS and buf is not None and not quoted and "".join(buf).isdigit():
                buf, computed, tilde, quoted = None, False, False, False  # `2>&1`: the fd number belongs to the operator
            flush()
            out.append(("op", op))
            i += len(op)
        else:
            if buf is None:
                buf, tilde = [], c == "~"
            computed = computed or c in "$*?[{"  # an expansion or a glob: the process may see other words
            buf.append(c)
            i += 1
    flush()
    return out


def split_commands(cmd: str):
    """The argument lists (lists of Word) the shell would run, split only at unquoted control operators, with
    redirections and their targets removed and comments dropped. None when the words cannot be known (see Unparsed,
    or a line over MAX_LINE characters); an empty list for a line with no command."""
    if len(cmd) > MAX_LINE:
        return None
    try:
        tokens = shell_tokens(cmd)
    except Unparsed:
        return None
    out, cur, i = [], [], 0
    while i < len(tokens):
        kind, text = tokens[i]
        if kind == "word":
            cur.append(text)
        elif text in SEPARATORS:
            out.append(cur)
            cur = []
        elif i + 1 < len(tokens) and tokens[i + 1][0] == "word":  # a redirection: drop its target too
            i += 1
        i += 1
    out.append(cur)
    return [c for c in out if c]


def simple_commands(cmd: str) -> list:
    """split_commands, with [] for a line whose words cannot be known: no stamp is better than a wrong one."""
    return split_commands(cmd) or []
