"""One conservative POSIX shell word scanner shared by the guards (goodqa#16811).

scan(text) returns a Scan. When Scan.verified is True, bash and zsh (non-interactive, default options) both read
`text` as exactly Scan.segments: simple commands, each with its words, its redirects and the control operator that
ends it. tests/test_shell_words_differential.py checks that claim against the real shells.

Modelled, and only these: unquoted text; single quotes; double quotes; the simple parameter expansions $NAME,
${NAME} and $0-$9 $? $# $$ $! $@ $* $- when the next character cannot extend them in either shell; the control
operators ; & && | || |& and newline; ( and ) around whole commands (a subshell); the redirects < > >> >| <> <& >&
&> &>>, with an optional fd number written right before them.

Everything else makes the scan unverified, with a `kind`, the offset and a message: comments, every backslash, ANSI-C
and locale quoting ($'..' $".."), command, process and arithmetic substitution, heredocs and here-strings, reserved
words in command position, history expansion (`!`), control characters other than tab and newline, non-ASCII quote,
space or format characters, zsh subscripts and modifiers after an expansion ($a[1], $a:h), a parenthesis inside a
command, a redirect glued to a word, a command made only of redirects, `=word` (a zsh path expansion) and syntax
errors. A caller reads an unverified line with its strict legacy rule; a relaxation applies only to a verified scan.

Not modelled, and left to the caller: what an expansion holds (Word.expansions names each one), globbing, brace and
tilde expansion (Word.unquoted lists every unquoted character so a caller can refuse them), and aliases or shell
options that a user's startup files may set.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field

MAX_TEXT = 64 * 1024
NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
BRACED = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")
SPECIAL_PARAMETERS = frozenset("0123456789?#$!@*-")
# After an expansion only these keep both shells reading the same word: no letter or digit (zsh `$10`, `$#a`),
# no `[` (zsh subscript), no `:` (zsh modifier), no `{` or `(`.
AFTER_EXPANSION = frozenset(" \t\n/.,-=+%@\"';&|<>)")
RESERVED = frozenset(("if", "then", "else", "elif", "fi", "case", "esac", "for", "select", "while", "until", "do",
                      "done", "in", "function", "time", "coproc", "{", "}", "!", "[[", "]]", "repeat", "foreach",
                      "end", "-", "nocorrect"))
QUOTE_LIKE = frozenset("‘’‚‛“”„‟′″‵‶«»"
                       "‹›＂＇ʻʼʹʺ´")
CONTROL_OPERATORS = (";", "&&", "&", "||", "|&", "|", "\n")
ASSIGNMENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=")


@dataclass(frozen=True)
class Word:
    value: str            # the word after quote removal; expansions are left as written ($NAME)
    start: int
    end: int
    quoted: bool          # any part was quoted
    unquoted: tuple       # (offset, char) for every unquoted character
    expansions: tuple     # (offset, inside_double_quotes, name)

    @property
    def assignment(self):
        """NAME=value with the name and `=` written unquoted at the start of the word (so both shells assign)."""
        match = ASSIGNMENT.match(self.value)
        if not match:
            return False
        prefix = self.unquoted[:match.end()]
        return (len(prefix) == match.end() and all(at == self.start + i for i, (at, _) in enumerate(prefix))
                and "".join(char for _, char in prefix) == match[0])


@dataclass
class Segment:
    words: list = field(default_factory=list)
    redirects: list = field(default_factory=list)   # (operator, offset, target Word)
    op: str = ""                                     # the control operator after it ('' at the end)
    op_offset: int = -1
    start: int = 0
    end: int = 0
    depth: int = 0                                   # subshell nesting

    @property
    def argv(self):
        """The command words after leading VAR=value assignments."""
        index = 0
        while index < len(self.words) and self.words[index].assignment:
            index += 1
        return [word.value for word in self.words[index:]]


@dataclass
class Scan:
    verified: bool
    segments: list
    kind: str = ""
    offset: int = -1
    message: str = ""
    in_double_quotes: bool = False
    text: str = ""

    @property
    def char(self):
        return self.text[self.offset] if 0 <= self.offset < len(self.text) else ""


class _Unverified(Exception):
    def __init__(self, kind, offset, message, in_double_quotes=False):
        super().__init__(message)
        self.kind, self.offset, self.message, self.in_double_quotes = kind, offset, message, in_double_quotes


def _odd_character(char):
    """A character a shell may read differently from shlex or from each other, or a reader may misread."""
    if char in "\t\n":
        return None
    if char < " " or char == "\x7f":
        return "control"
    if char.isascii():
        return None
    if char in QUOTE_LIKE or unicodedata.category(char) in ("Zs", "Zl", "Zp", "Cc", "Cf", "Pi", "Pf"):
        return "quote_like"
    return None


def scan(text):
    """Scan `text` (see the module doc). Never raises for any str."""
    if not isinstance(text, str):
        return Scan(False, [], "type", -1, "not text")
    if len(text) > MAX_TEXT:
        return Scan(False, [], "too_long", MAX_TEXT, "longer than %d characters" % MAX_TEXT, text=text)
    try:
        return Scan(True, _Scanner(text).run(), text=text)
    except _Unverified as error:
        return Scan(False, [], error.kind, error.offset, error.message, error.in_double_quotes, text)


class _Scanner:
    def __init__(self, text):
        self.text = text
        self.index = 0
        self.segments = []
        self.segment = Segment()
        self.depth = 0
        self.closed = False        # a `)` just ended a subshell: only an operator or redirect may follow
        self.pending = None        # (operator, offset) of a redirect waiting for its target
        self.word = None           # the word being built: dict

    # -- helpers
    def fail(self, kind, message, offset=None, dq=False):
        raise _Unverified(kind, self.index if offset is None else offset, message, dq)

    def peek(self, ahead=0):
        at = self.index + ahead
        return self.text[at] if at < len(self.text) else ""

    def begin_word(self):
        if self.word is None:
            if self.closed:
                self.fail("syntax", "a word right after a closing parenthesis")
            self.word = {"start": self.index, "value": [], "quoted": False, "unquoted": [], "expansions": []}

    def end_word(self):
        if self.word is None:
            return
        built = Word("".join(self.word["value"]), self.word["start"], self.index, self.word["quoted"],
                     tuple(self.word["unquoted"]), tuple(self.word["expansions"]))
        self.word = None
        if self.pending is not None:
            operator, offset = self.pending
            self.pending = None
            self.segment.redirects.append((operator, offset, built))
            return
        if not self.segment.words and not built.quoted:
            if built.value in RESERVED:
                self.fail("reserved_word", "the shell keyword %r" % built.value, built.start)
            if built.value.startswith("="):
                self.fail("equals_word", "zsh expands a word starting with `=` to a command path", built.start)
        if (self.segment.words and all(word.assignment for word in self.segment.words) and not built.quoted
                and built.value in RESERVED):
            self.fail("reserved_word", "the shell keyword %r" % built.value, built.start)
        self.segment.words.append(built)

    def end_segment(self, op, offset):
        self.end_word()
        if self.pending is not None:
            self.fail("syntax", "a redirect with no target", self.pending[1])
        segment = self.segment
        empty = not segment.words and not segment.redirects
        if empty and not self.closed:
            if op in ("\n", "") and (not self.segments or self.segments[-1].op in (";", "&", "\n", "")):
                return  # a blank line or the end after `;`/`&`: nothing to run
            self.fail("syntax", "an operator with no command before it", offset)
        if not empty and not segment.words:
            self.fail("null_command", "a command made only of redirects (zsh runs $NULLCMD)", segment.start)
        if not empty or self.closed:
            segment.op, segment.op_offset, segment.end, segment.depth = op, offset, offset, self.depth
            if not empty:
                self.segments.append(segment)
            elif self.segments:
                self.segments[-1].op, self.segments[-1].op_offset = op, offset
        self.segment = Segment(start=self.index)
        self.closed = False

    # -- the main loop
    def run(self):
        text = self.text
        while self.index < len(text):
            char = text[self.index]
            odd = _odd_character(char)
            if odd:
                self.fail(odd, "a control character %r" % char if odd == "control" else
                          "the non-ASCII quote, space or format character U+%04X" % ord(char))
            if char in " \t":
                self.end_word()
                self.index += 1
                continue
            if char == "\n":
                self.operator("\n", 1)
                continue
            if char in ";&|":
                self.control(char)
                continue
            if char in "<>":
                self.redirect(char)
                continue
            if char == "(":
                self.open_paren()
                continue
            if char == ")":
                self.close_paren()
                continue
            self.word_part(char)
        self.end_segment("", len(text))
        if self.depth:
            self.fail("unbalanced", "an unclosed parenthesis", len(text))
        if self.segments and self.segments[-1].op in ("&&", "||", "|", "|&"):
            self.fail("syntax", "a command line that ends with %r" % self.segments[-1].op, self.segments[-1].op_offset)
        return self.segments

    def operator(self, op, width):
        offset = self.index
        self.index += width
        self.end_segment(op, offset)
        self.segment.start = self.index

    def control(self, char):
        two = self.text[self.index:self.index + 2]
        if char == ";":
            if two in (";;", ";&", ";|"):
                self.fail("syntax", "a case terminator %r" % two)
            self.operator(";", 1)
        elif char == "&":
            if two == "&&":
                self.operator("&&", 2)
            elif two == "&>":
                self.redirect("&")
            else:
                self.operator("&", 1)
        elif two == "||":
            self.operator("||", 2)
        elif two == "|&":
            self.operator("|&", 2)
        else:
            self.operator("|", 1)

    def redirect(self, char):
        start = self.index
        three, two = self.text[self.index:self.index + 3], self.text[self.index:self.index + 2]
        if two in ("<<",):
            self.fail("heredoc", "a heredoc or here-string (`%s`)" % ("<<<" if three == "<<<" else "<<"))
        if two in ("<(", ">("):
            self.fail("process_substitution", "a process substitution (`%s`)" % two)
        if three == "&>>":
            op = "&>>"
        elif two in (">>", ">|", "<>", "<&", ">&", "&>"):
            op = two
        else:
            op = char
        after = self.text[self.index + len(op):self.index + len(op) + 1]
        if op == "<" and (after.isdigit() or after == "-"):
            self.fail("numeric_glob", "zsh may read `<N-M>` as a numeric glob")
        if after in ("(", ")"):
            self.fail("process_substitution", "a parenthesis right after a redirect")
        if self.word is not None:
            # Only an all-digit unquoted word written right before the operator is an fd number.
            digits = "".join(self.word["value"])
            if (not digits.isdigit() or self.word["quoted"] or self.word["expansions"]
                    or op.startswith("&")):
                self.fail("glued_redirect", "a redirect written right after a word")
            self.word = None
        if self.pending is not None:
            self.fail("syntax", "a redirect with no target", self.pending[1])
        if self.closed:
            self.fail("subshell_redirect", "a redirect on a subshell")
        if not self.segment.words and not self.segment.redirects:
            self.segment.start = start
        self.index += len(op)
        self.pending = (op, start)

    def open_paren(self):
        if self.peek(1) == "(":
            self.fail("arithmetic", "an arithmetic command or a nested subshell `((`")
        if self.word is not None or self.segment.words or self.segment.redirects or self.pending or self.closed:
            self.fail("paren_in_word", "a parenthesis inside a command (a function, array, or zsh glob qualifier)")
        self.depth += 1
        self.index += 1
        self.segment.start = self.index

    def close_paren(self):
        if not self.depth:
            self.fail("unbalanced", "a closing parenthesis with no opening one")
        offset = self.index
        self.end_word()
        if self.pending is not None:
            self.fail("syntax", "a redirect with no target", self.pending[1])
        if not self.segment.words:
            if self.segment.redirects:
                self.fail("null_command", "a command made only of redirects (zsh runs $NULLCMD)", self.segment.start)
            inner_closed = self.closed  # `( (a) )`: an inner subshell just ended
            if not inner_closed and (not (self.segments and self.segments[-1].op in (";", "\n", "&"))
                                     or self.segments[-1].depth < self.depth):
                self.fail("syntax", "an empty subshell or an operator before `)`")
        self.index += 1
        if self.segment.words:
            self.segment.op, self.segment.op_offset, self.segment.end, self.segment.depth = ")", offset, offset, self.depth
            self.segments.append(self.segment)
        self.segment = Segment(start=self.index)
        self.depth -= 1
        self.closed = True

    def word_part(self, char):
        self.begin_word()
        word = self.word
        if char == "'":
            word["quoted"] = True
            close = self.text.find("'", self.index + 1)
            if close < 0:
                self.fail("unbalanced", "unbalanced quotes")
            body = self.text[self.index + 1:close]
            for offset, inner in enumerate(body, start=self.index + 1):
                odd = _odd_character(inner)
                if odd:
                    self.fail(odd, "a control character %r" % inner if odd == "control" else
                              "the non-ASCII quote, space or format character U+%04X" % ord(inner), offset)
            word["value"].append(body)
            self.index = close + 1
            return
        if char == '"':
            word["quoted"] = True
            self.index += 1
            while True:
                if self.index >= len(self.text):
                    self.fail("unbalanced", "unbalanced quotes")
                inner = self.text[self.index]
                odd = _odd_character(inner)
                if odd:
                    self.fail(odd, "a control character %r" % inner if odd == "control" else
                              "the non-ASCII quote, space or format character U+%04X" % ord(inner), dq=True)
                if inner == '"':
                    self.index += 1
                    return
                if inner == "\\":
                    self.fail("backslash", "a backslash inside double quotes", dq=True)
                if inner == "`":
                    self.fail("command_substitution", "a command substitution (`` ` ``)", dq=True)
                if inner == "!":
                    self.fail("history", "`!` inside double quotes (history expansion)", dq=True)
                if inner == "$":
                    self.expansion(dq=True)
                    continue
                word["value"].append(inner)
                self.index += 1
        if char == "\\":
            self.fail("backslash", "a backslash escape")
        if char == "`":
            self.fail("command_substitution", "a command substitution (`` ` ``)")
        if char == "!":
            self.fail("history", "an unquoted `!` (history expansion or pipeline negation)")
        if char == "#" and not word["value"] and not word["quoted"] and not word["expansions"]:
            self.fail("comment", "a comment (`#` at the start of a word)")
        if char == "$":
            self.expansion(dq=False)
            return
        word["unquoted"].append((self.index, char))
        word["value"].append(char)
        self.index += 1

    def expansion(self, dq):
        start = self.index
        nxt = self.peek(1)
        if nxt == "(":
            self.fail("command_substitution" if self.peek(2) != "(" else "arithmetic",
                      "a command substitution (`$(`)" if self.peek(2) != "(" else "an arithmetic expansion `$((`",
                      dq=dq)
        if nxt == "'" and not dq:
            self.fail("ansi_c", "ANSI-C quoting (`$'`)")
        if nxt == '"' and not dq:
            self.fail("locale_quote", "locale quoting (`$\"`)")
        if nxt == "{":
            braced = BRACED.match(self.text, start + 1)
            if not braced:
                self.fail("expansion_form", "a parameter expansion with operators (`${...}`)", dq=dq)
            name, end = braced[1], braced.end()
        elif nxt in SPECIAL_PARAMETERS:
            name, end = nxt, start + 2
        else:
            named = NAME.match(self.text, start + 1)
            if not named:
                self.fail("expansion_form", "a `$` that is not a plain parameter expansion", dq=dq)
            name, end = named[0], named.end()
        after = self.text[end:end + 1]
        if after and after not in AFTER_EXPANSION:
            self.fail("expansion_suffix", "%r right after an expansion (zsh may read a subscript, modifier or a "
                      "longer name)" % after, end, dq=dq)
        self.word["expansions"].append((start, dq, name))
        self.word["value"].append(self.text[start:end])
        self.index = end
