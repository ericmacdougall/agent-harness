#!/usr/bin/env python3
"""The Bash half of goodqa#17155: a command that names an instruction or configuration file only reads it, or is refused.

The list is protected_paths.PROTECTED_WRITE_GLOBS, the one the Write/Edit hook uses. command_guard.py calls this module at
one point for every command it dispatches (Analyzer.command) and one point for interpreter code (Analyzer.code).

The rule is refuse by default. A command NAMES a protected file when one whole word, option value, assignment value,
redirect target or string literal of interpreter code resolves to it; text that merely mentions the file (a note, a commit
message, a heredoc body, a search pattern) never counts. A command that names one is allowed only when it is one of the
plain reads granted below. No program is known as a writer, and no launcher's options are modelled: a launcher with
options, a script, an unknown program or an unlisted option is refused, and the refusal names the route. A missing grant
therefore refuses a read; it never allows a write.

Not seen (stated limits): a script on disk that names the file itself (shell scripts the guard reads are judged), a path
computed at run time, a relative name after a `cd` the guard cannot resolve, a directory copied or extracted whole into
~/.claude, a program that reads names from a file, text a program runs from an option, environment or config value, MCP
tools, and anything run outside the hook. Standard library only.
"""

import ast
import fnmatch
import os
import posixpath
import re

import protected_paths

RULE = 'protected-config'
NAMES_FILE = re.compile(r'(?i)\.claude[\\/]+(?:claude\.md|settings[^\\/\s\'"]*\.json)|\.codex[\\/]+(?:config\.toml|hooks\.json)')
REAL_HOME = re.compile(r'~|\bHOME\b|\bexpanduser\b|\.home\(|\bhomedir\b|\bgetpw')
MAX_DISK_WORDS = 600  # words past this are still judged by name, without a disk probe

INERT = frozenset(('echo', 'printf', 'print', ':', 'true', 'false', 'test', '[', '[[', 'export', 'local', 'declare',
                   'typeset', 'readonly', 'unset', 'cd', 'pushd', 'popd', 'type', 'which', 'whence', 'exit', 'return',
                   'basename', 'dirname'))
# programs with no option that writes a file or runs a command
READERS = frozenset(('cat', 'head', 'tail', 'wc', 'nl', 'tac', 'rev', 'cut', 'od', 'hexdump', 'cksum', 'md5', 'md5sum',
                     'shasum', 'sha1sum', 'sha256sum', 'sha512sum', 'stat', 'ls', 'realpath', 'readlink', 'cmp', 'comm',
                     'diff', 'jq', 'du', 'strings', 'paste', 'fold', 'column', 'tr'))
SEARCHERS = frozenset(('grep', 'egrep', 'fgrep', 'ggrep', 'rg'))
SEARCH_LONG = frozenset(('include', 'exclude', 'exclude-dir', 'color', 'colour', 'line-number', 'count', 'ignore-case',
                         'word-regexp', 'fixed-strings', 'extended-regexp', 'perl-regexp', 'recursive', 'no-filename',
                         'files-with-matches', 'files-without-match', 'with-filename', 'only-matching', 'quiet', 'silent',
                         'max-count', 'context', 'after-context', 'before-context', 'invert-match', 'text', 'regexp',
                         'no-messages', 'no-heading', 'glob', 'type', 'hidden', 'no-ignore', 'files', 'json', 'multiline',
                         'line-regexp', 'byte-offset'))
LAUNCHERS = frozenset(('command', 'builtin', 'time', 'nohup', 'nice', 'sudo', 'noglob', 'exec', 'env'))  # bare form only
TEXT_RUNNERS = frozenset(('trap', 'watch', 'sg', 'script', 'entr', 'hyperfine'))  # run a word as shell text
SAFE_ENV = re.compile(r'(?:LC_[A-Z]+|LANG|LANGUAGE|TZ|NO_COLOR|TERM|COLUMNS|CLICOLOR)=')
SYSTEM_DIRS = frozenset(('/bin', '/usr/bin', '/usr/local/bin', '/opt/homebrew/bin', '/sbin', '/usr/sbin'))
# an option whose value is prose for people: a path there is data
PROSE = re.compile(r'--(?:note|notes|reason|message|title|body|summary|text|comment|description|why|source|subject|criterion|'
                   r'evidence)(?:=|$)')
SED_STEP = (r'(?:\d+|\$|/(?:[^/\\\n]|\\.)*/)?(?:,\s*(?:\d+|\$|\+\d+|/(?:[^/\\\n]|\\.)*/))?\s*!?\s*'
            r'(?:[pdq=]|s(?:/(?:[^/\\\n]|\\.)*/(?:[^/\\\n]|\\.)*/|\|[^|\\\n]*\|[^|\\\n]*\||#[^#\\\n]*#[^#\\\n]*#)[gpIi0-9]*)')
SED_SCRIPT = re.compile(r'\s*%s(?:\s*[;\n]\s*%s)*\s*;?\s*' % (SED_STEP, SED_STEP))
GIT_READS = frozenset(('hash-object', 'diff', 'log', 'show', 'status', 'ls-files', 'blame', 'check-ignore', 'cat-file'))


# ---- which file a path names
def _segs(path):
    return [s for s in path.casefold().replace('\\', '/').split('/') if s]


def _fn(name, pattern):
    try:
        return fnmatch.fnmatchcase(name, pattern)
    except re.error:
        return True  # an unreadable pattern counts as a match


def _seg(have, want, globbed):
    """One path segment as written against one segment of the list; either may be a pattern."""
    if _fn(have, want):
        return True
    return bool(globbed and any(ch in have for ch in '*?[')
                and any(_fn(want.replace('*', filler), have) for filler in ('', '.local', '.x')))


PATTERNS = tuple(_segs(g) for g in protected_paths.PROTECTED_WRITE_GLOBS)


def rel_match(segs, globbed=False):
    """The list entry `segs` (relative to a home) may name, else None."""
    for pattern in PATTERNS:
        if len(segs) == len(pattern) and all(_seg(h, w, globbed) for h, w in zip(segs, pattern)):
            return '~/' + '/'.join(pattern)
    return None


class Names:
    """Resolves the words of one analysis against the list: one instance per analyzer."""

    def __init__(self, analyzer):
        self.a, self.ctx = analyzer, analyzer.ctx
        self.homes = [_segs(h) for h in dict.fromkeys(list(analyzer.c.homes) + [analyzer.ctx.home])]
        self.inodes = None
        self.loop_vars = set()

    def rel(self, path):
        segs = _segs(path)
        for h in self.homes:
            if segs[:len(h)] == h:
                yield segs[len(h):]
        if len(segs) > 1 and segs[0] in ('home', 'users'):  # another machine's home (ssh text), another user's here
            yield segs[2:]
        if segs[:1] == ['root']:
            yield segs[1:]

    def lexical(self, path, globbed=False):
        return next((hit for hit in (rel_match(r, globbed) for r in self.rel(path)) if hit), None)

    def _inode_hit(self, path):
        if self.inodes is None:
            self.inodes = protected_paths._protected_inodes(set(self.a.c.homes) | {self.ctx.home})
        try:
            info = self.a._probe('cfg-stat', path, os.stat)
        except (OSError, ValueError):
            return None
        return 'a protected file by another name' if (info.st_dev, info.st_ino) in self.inodes else None

    def real(self, path):
        try:
            return self.a._probe('rp', path, os.path.realpath)
        except (OSError, ValueError, RuntimeError):
            return path

    def path(self, text, globbed=False, disk=True):
        """The protected file the path `text` names, else None."""
        import command_guard as cg
        if not text or len(text) > 4096 or '\n' in text:
            return None
        if not text.startswith(('/', '~')) and self.ctx.cwd_unknown:
            return None
        path = self.a._through_links(cg.norm_path(text, self.ctx))
        hit = self.lexical(path, globbed)
        if hit or not disk:
            return hit
        candidates = [path]
        if '..' in text:  # `link/../x`: the kernel follows the link before the `..`
            candidates.append(cg.norm_path(text.replace('..', '\x01'), self.ctx).replace('\x01', '..'))
        for candidate in candidates:
            hit = self._inode_hit(candidate)
            if not hit and any(_fn(posixpath.basename(candidate).casefold(), p[-1]) for p in PATTERNS):
                hit = self.lexical(self.real(candidate))  # a file that may not exist yet, in a linked directory
            if hit:
                return hit
        return None

    def _hints(self, word):
        return ' '.join([self.ctx.var_hints.get(v, '') for v in word.vars] + list(word.subs))

    def _unresolved(self, word, text):
        """`$X/.claude/CLAUDE.md`, `$(echo ~)/.claude/CLAUDE.md`: a prefix the guard cannot resolve that may be the home."""
        segs, hints = _segs(text), self._hints(word)
        m = re.fullmatch(r'\$\{?(CLAUDE_CONFIG_DIR|CODEX_HOME)\}?/(.+)', text)
        if m:
            return rel_match([{'CLAUDE_CONFIG_DIR': '.claude'}.get(m.group(1), '.codex')] + _segs(m.group(2)), word.glob)
        if len(segs) == 2:  # D=$(cd ~/.claude && pwd); $D/CLAUDE.md
            return next((h for h in (rel_match([p[0], segs[1]], word.glob) for p in PATTERNS if p[0] in hints.casefold())
                         if h), None)
        hit = rel_match(segs[-2:], word.glob) if len(segs) > 2 else None
        unset = any(v not in self.ctx.vars and v not in self.ctx.var_hints and v not in self.ctx.temp_vars
                    for v in word.vars)
        return hit if hit and (unset or REAL_HOME.search(hints + ' ' + text)) else None

    def word(self, word, disk=True):
        """The protected file a word of the command names, as a whole or as an option or assignment value, else None."""
        import command_guard as cg
        if any(v in self.loop_vars for v in word.vars):
            return 'a protected file held by a loop variable'
        globbed = word.glob or word.overflow is not None
        for alt in word.cred_alts():
            text = cg._unq(alt)
            if '$PWD' in text and not self.ctx.cwd_unknown:
                text = text.replace('$PWD', self.ctx.cwd)
            if not text or len(text) > 4096:
                continue
            for cand in [text] + [t for t in cg._derived_texts(text, colon=True) if cg._path_like(t)]:
                cand = cand.rstrip('/') or cand
                if word.dynamic and ('$' in cand or cg.SUB_MARK in cand):
                    hit = self._unresolved(word, cand)
                else:
                    hit = self.path(cand, globbed, disk=disk and cand == text)
                if hit:
                    return hit
        return None

    def directory(self, word):
        """The list directory (`.claude`, `.codex`) the word names, '' for a directory above one, else None."""
        import command_guard as cg
        for alt in word.alts[:8]:
            text = cg._unq(alt)
            for cand in [text] + [t for t in cg._derived_texts(text, colon=True) if cg._path_like(t)]:
                if not cand.startswith(('/', '~')) and (self.ctx.cwd_unknown or not cand.startswith('.')):
                    continue
                path = self.a._through_links(cg.norm_path(cand, self.ctx))
                for p in dict.fromkeys((path, self.real(path))):
                    if p == '/':
                        return ''
                    for rel in self.rel(p):
                        if len(rel) == 1 and any(_seg(rel[0], pat[0], word.glob) for pat in PATTERNS):
                            return rel[0]
                        if not rel:
                            return ''
        return None

    def leaf(self, word, directory):
        """The list file of `directory` ('' = any) that the word's last segment names, else None."""
        import command_guard as cg
        for alt in word.alts[:8]:
            text = cg._unq(alt)
            for cand in [text] + cg._derived_texts(text):
                name = posixpath.basename(cand.rstrip('/')).casefold()
                if len(name) < 3:  # `*`, `**`, `.`, `..`
                    continue
                for pat in PATTERNS:
                    if (not directory or _seg(directory, pat[0], True)) and _seg(name, pat[-1], True):
                        return '~/' + '/'.join(pat)
        return None


# ---- what is a plain read
def _base(word, ctx, raw):
    """The program a head word names, or None when it may be something else (a path, an alias, a function, a variable)."""
    import command_guard as cg
    text = cg._unq(word.text)
    if word.dynamic or word.glob and text not in ('[', '[[') or len(word.alts) != 1 or not text:
        return None  # the test builtins read as globs; the alias and function checks below still apply to them
    if '/' in text and posixpath.dirname(text) not in SYSTEM_DIRS:
        return None
    name = posixpath.basename(text)
    quoted = re.escape(name)
    if name in ctx.aliases or re.search(r'\bfunction\s+%s\b|(?<![\w.-])%s\s*\(\s*\)' % (quoted, quoted), raw):
        return None
    return name if name in ('[', '[[', ':') or cg.norm_name(name) == name else None


def _operands(args):
    return [a for a in args if not a.text.startswith('-') or a.text == '-']


def _options(args):
    return [a.text for a in args if a.text.startswith('-') and a.text != '-']


def granted(words, names, raw, nested=False):
    """True when this command only reads the files it is given."""
    ctx, words = names.ctx, list(words)
    for _ in range(4):
        while words and SAFE_ENV.match(words[0].text):
            words = words[1:]
        if not words:
            return False
        name = _base(words[0], ctx, raw)
        if name in LAUNCHERS and len(words) > 1 and not words[1].text.startswith('-'):
            words = words[1:]
        elif name == 'timeout' and len(words) > 2 and re.fullmatch(r'\d+(?:\.\d+)?[smhd]?', words[1].text):
            words = words[2:]
        else:
            break
    name, args = _base(words[0], ctx, raw), words[1:]
    texts = [a.text for a in args]
    if name is None:
        return False
    if name in INERT or name in READERS:
        return True
    if name in SEARCHERS:
        return all(not t.startswith('--') or t == '--' or t[2:].split('=', 1)[0] in SEARCH_LONG for t in texts)
    if name == 'sort':
        return all(re.fullmatch(r'-[bdfgiMhnRrVcCmsuz]+|-[kt].*', t) for t in _options(args))
    if name == 'uniq':
        return len(_operands(args)) <= 1 and all(re.fullmatch(r'-[cdiu]+', t) for t in _options(args))
    if name in ('sed', 'gsed'):
        return _sed(texts)
    if name in ('awk', 'gawk', 'mawk', 'nawk'):
        return _awk(texts)
    if name == 'find':
        return _find(args, names, raw, nested)
    if name == 'git':
        return _git(texts)
    if name == 'cp':
        return not nested and _copy(args, names)
    if name == 'ssh':
        return not nested and _ssh(texts)
    if name == 'xargs':
        return not nested and _xargs(args, names, raw)
    if re.fullmatch(r'python3?(?:\.\d+)?', name):
        rest = texts[2:]
        return texts[:2] == ['-m', 'json.tool'] and len([t for t in rest if not t.startswith('-')]) == 1 and not any(
            t.startswith(('--i', '-h')) for t in rest)
    return False


def _xargs(args, names, raw):
    k = 0
    while k < len(args) and args[k].text.startswith('-'):
        t = args[k].text
        if re.fullmatch(r'-(?:0|r|t|[nPL]\d+|I\S+)', t):
            k += 1
        elif t in ('-n', '-P', '-L', '-I'):
            k += 2
        else:
            return False
    return k < len(args) and granted(args[k:], names, raw, nested=True)


def _sed(texts):
    scripts, k, explicit = [], 0, False
    while k < len(texts):
        t = texts[k]
        if t == '-e' and k + 1 < len(texts):
            scripts.append(texts[k + 1])
            explicit = True
            k += 2
            continue
        if t.startswith('-') and t != '-' and not re.fullmatch(r'-[nErusz]+', t):
            return False
        if not t.startswith('-') and not explicit:
            scripts.append(t)
            explicit = True
        k += 1
    return bool(scripts) and all(SED_SCRIPT.fullmatch(s) for s in scripts)


def _awk(texts):
    k = 0
    while k < len(texts) and texts[k].startswith('-'):
        if texts[k] in ('-F', '-v'):
            k += 2
        elif re.fullmatch(r'-F.+', texts[k]):
            k += 1
        else:
            return False
    return k < len(texts) and not re.search(r'[>|@]|\bsystem\b|\bARGV\b', texts[k])


def _find(args, names, raw, nested):
    k = 0
    while k < len(args):
        t = args[k].text
        if t in ('-exec', '-execdir') and not nested:
            end = next((j for j in range(k + 1, len(args)) if args[j].text in (';', '+')), None)
            if end is None or not granted(args[k + 1:end], names, raw, nested=True):
                return False
            k = end
        elif t.startswith(('-exec', '-ok', '-delete', '-fprint', '-fls')):
            return False
        k += 1
    return True


def _git(texts):
    k = 0
    while k < len(texts) and texts[k].startswith('-'):
        if texts[k] == '-C':
            k += 2
        elif texts[k] in ('--no-pager', '-P'):
            k += 1
        else:
            return False
    return k < len(texts) and texts[k] in GIT_READS and not any(
        re.match(r'--(?:ou|ext|textc|open)|-O', t) for t in texts[k + 1:])


def _copy(args, names):
    """cp SRC... DEST where only a source is protected."""
    if any(not re.fullmatch(r'-[aprRPfvn]+', t) for t in _options(args)):
        return False
    ops = _operands(args)
    if len(ops) < 2 or ops[-1].dynamic or names.word(ops[-1]):
        return False
    directory = names.directory(ops[-1])
    if directory and any(names.leaf(o, directory) for o in ops[:-1]):
        return False
    dest = ops[-1].text.rstrip('/')
    return not any(names.path(dest + '/' + posixpath.basename(o.text.rstrip('/'))) for o in ops[:-1])


def _ssh(texts):
    """`ssh [-o K=V] [-p N] HOST command...`: the remote words are judged as a script; only these options are granted."""
    k = 0
    while k < len(texts) and texts[k].startswith('-'):
        if re.fullmatch(r'-[46ACTnqtvxX]+', texts[k]):
            k += 1
        elif texts[k] in ('-p', '-l', '-i') and k + 1 < len(texts):
            k += 2
        elif texts[k] == '-o' and k + 1 < len(texts) and re.match(
                r'(?i)(?:BatchMode|ConnectTimeout|StrictHostKeyChecking|LogLevel|ServerAlive\w+)=', texts[k + 1]):
            k += 2
        else:
            return False
    return len(texts) > k + 1 and not texts[k + 1].startswith('-')


# ---- the two entry points
def _names(analyzer):
    names = getattr(analyzer, '_config_names', None)
    if names is None:
        names = analyzer._config_names = Names(analyzer)
    return names


def _refuse(analyzer, what, hit, why):
    import command_guard as cg
    if any(f.rule == RULE for f in analyzer.ctx.findings):
        return
    analyzer.ctx.add(cg.LOG_DELETE, RULE, ('%s names %s, an instruction or configuration file that only the user changes, '
                                           'and %s' % (what[:40], hit, why))[:300],
                     'to read it: cat, head, tail, grep, sed -n, jq, diff, wc, shasum, git diff or hash-object, run without a '
                     'launcher or unlisted option, `PROGRAM < FILE`, cp FILE to your work folder, or the Read tool. To change '
                     'it: put the text in your reply or a ticket, and the user applies it')


def _hits(names, words, prose=True):
    out, skip = [], False
    for k, w in enumerate(words):
        if skip:
            skip = False
            continue
        if prose and PROSE.match(w.text):
            skip = '=' not in w.text
            continue
        hit = names.word(w, disk=k < MAX_DISK_WORDS)
        if hit:
            out.append(hit)
    return out


def _split_hit(names, words, above):
    """A list directory and a list file name given separately: `cp X/CLAUDE.md ~/.claude/`, `env -C ~/.claude tee CLAUDE.md`."""
    words = words[:MAX_DISK_WORDS]
    leaves = [j for j, w in enumerate(words) if j and names.leaf(w, '')] if len(words) > 2 else []
    for k, w in enumerate(words if leaves else []):
        directory = names.directory(w)
        if directory is None or (directory == '' and not above):
            continue
        for j in leaves:
            hit = names.leaf(words[j], directory) if j != k else None
            if hit:
                return hit
    return None


def judge_command(analyzer, assigns, rest, cmd, pl, idx, depth):
    import command_guard as cg
    names, ctx = _names(analyzer), analyzer.ctx
    for r in cmd.redirs:  # only `<` reads
        if r.target is not None and r.op not in ('<', '<<', '<<-', '<<<') and not re.fullmatch(r'[0-9-]+', r.target.text or '-'):
            hit = names.word(analyzer.resolve(r.target))
            if hit:
                _refuse(analyzer, 'a %s redirect' % r.op, hit, 'the redirect can write it')
                return
    if not rest:
        return  # `F=~/.claude/CLAUDE.md` alone: every later use of $F is resolved and judged
    if not rest[0].quoted and rest[0].text in cg.NONEXEC_HEADS:
        if len(rest) > 3 and rest[2].text == 'in' and rest[0].text != 'case' and _hits(names, rest[3:], prose=False):
            names.loop_vars.add(rest[1].text)
        return
    head, earlier = cg.norm_name(rest[0].text), []
    feeds = head in ('read', 'mapfile', 'readarray') or any(cg.norm_name(w.text) in ('xargs', 'parallel') for w in rest)
    for prev in pl.cmds[:idx] if pl is not None and feeds else []:
        words = [analyzer.resolve(w) for w in cg.strip_reserved(prev.words)]
        split = _split_hit(names, words, above=True)
        earlier += _hits(names, words, prose=False) + ([split] if split else [])
    if earlier and head in ('read', 'mapfile', 'readarray'):
        names.loop_vars.update(w.text for w in rest[1:] if re.fullmatch(r'[A-Za-z_]\w*', w.text))
        return
    hits = _hits(names, rest)
    if not hits and head not in INERT:
        hits = [h for h in [_split_hit(names, rest, above=head in ('find', 'fd', 'fdfind'))] if h]
    if not hits and feeds:
        hits = list(earlier)  # the names arrive on stdin
        for r in cmd.redirs:
            lines = [r.target.text] if r.op == '<<<' and r.target is not None else (r.body or '').splitlines()[:2000]
            hits += [h for h in (names.path(line.strip().strip('\'"'), disk=False) for line in lines) if h]
    if head in TEXT_RUNNERS:
        for w in rest[1:]:
            if re.search(r'\s', w.text) and NAMES_FILE.search(w.text):
                analyzer.script(w.text, depth + 1, tail_visible=True)
    safe_env = all(SAFE_ENV.match(a.text) for a in assigns)
    if not hits and not safe_env and head not in INERT:
        hits = [h for h in (names.word(a) for a in assigns) if h]  # a protected path in the program's environment
    if hits and not (safe_env and granted(rest, names, getattr(ctx, 'raw_top', '') or '')):
        _refuse(analyzer, '`%s`' % (head or '?'), hits[0], 'it is not one of the plain reads this guard knows')


# ---- interpreter code
def _literals(code):
    """(tree or None, string literals). Python when it parses as Python, else every quoted literal."""
    try:
        tree = ast.parse(code)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        tree = None
    found = [n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str)] if tree else []
    return tree, found or [m.group(0)[1:-1] for m in re.finditer(
        r'"(?:[^"\\\n]|\\.)*"|\'(?:[^\'\\\n]|\\.)*\'|`(?:[^`\\]|\\.)*`', code)]


def _code_hit(names, code, literals):
    import command_guard as cg
    home, leaves, folders = bool(REAL_HOME.search(code)), [], set()
    for text in literals[:2000]:
        text = text.lstrip('<>+| ')
        if not text or len(text) > 1024 or re.search(r'\s', text):
            continue  # prose or a command, not a path
        rooted = text.startswith(('/', '~'))
        hit = names.path(text) if rooted else None
        if hit:
            return hit
        text = re.sub(r'^(?:\$\{[^}]*\}|\$\w+(?:\{\w+\})?)', '', text)  # `$ENV{HOME}/...`, `${process.env.HOME}/...`
        segs = _segs(text)
        if len(segs) == 2 and rel_match(segs, True) and (home or names.path(text.lstrip('/'), disk=False)):
            return rel_match(segs, True)
        if len(segs) == 1:
            leaves += [pat for pat in PATTERNS if _fn(segs[0], pat[-1])]
        if segs and any(segs[-1] == pat[0] for pat in PATTERNS):
            if home and len(segs) == 1 or rooted and any(len(r) == 1 for r in names.rel(cg.norm_path(text, names.ctx))):
                folders.add(segs[-1])
    for pat in leaves:  # Path.home() / '.claude' / 'CLAUDE.md', or a bare name from inside the directory
        if pat[0] in folders or names.path(pat[-1], disk=False):
            return '~/' + '/'.join(pat)
    return None


SAFE_IMPORTS = frozenset(('json', 'sys', 're', 'os', 'os.path', 'pathlib', 'hashlib', 'collections', 'itertools', 'datetime',
                          'difflib', 'textwrap', 'tomllib', 'math', 'string', 'time', 'glob', 'fnmatch'))
SAFE_FROM = frozenset(('Path', 'PurePath', 'Counter', 'defaultdict', 'OrderedDict', 'datetime', 'date', 'timedelta',
                       'expanduser', 'join', 'dirname', 'basename', 'chain', 'islice', 'dedent', 'sha256', 'unified_diff'))
SAFE_BUILTINS = frozenset(('print', 'len', 'str', 'int', 'float', 'bool', 'list', 'dict', 'set', 'tuple', 'frozenset', 'sorted',
                           'enumerate', 'range', 'min', 'max', 'sum', 'any', 'all', 'zip', 'isinstance', 'repr', 'reversed',
                           'abs', 'round', 'next', 'iter', 'bytes', 'Exception', 'OSError', 'ValueError', 'KeyError',
                           'FileNotFoundError', 'ord', 'chr'))
SAFE_ATTRS = frozenset((
    'read', 'readline', 'readlines', 'read_text', 'read_bytes', 'write', 'get', 'items', 'keys', 'values', 'append', 'add',
    'extend', 'join', 'strip', 'lstrip', 'rstrip', 'split', 'rsplit', 'splitlines', 'startswith', 'endswith', 'lower', 'upper',
    'casefold', 'find', 'rfind', 'index', 'count', 'group', 'groups', 'start', 'end', 'span', 'loads', 'dumps', 'load', 'sort',
    'pop', 'close', 'exists', 'isfile', 'isdir', 'basename', 'dirname', 'getsize', 'getmtime', 'expanduser', 'iterdir', 'stat',
    'is_file', 'is_dir', 'most_common', 'encode', 'decode', 'path', 'home', 'environ', 'search', 'match', 'fullmatch', 'findall',
    'finditer', 'sub', 'compile', 'escape', 'M', 'S', 'I', 'DOTALL', 'MULTILINE', 'IGNORECASE', 'name', 'stem', 'suffix',
    'parent', 'parts', 'st_size', 'st_mtime', 'st_mode', 'st_nlink', 'st_ino', 'lstat', 'sha256', 'md5', 'sha1', 'hexdigest',
    'digest', 'Path', 'Counter', 'defaultdict', 'exit', 'argv', 'stdin', 'unified_diff', 'now', 'isoformat', 'title',
    'partition', 'setdefault', 'isdigit', 'rglob', 'glob', 'realpath', 'abspath', 'format', 'zfill', 'ljust', 'rjust'))


def python_reads_only(tree, names):
    """A closed grammar that grants, never a list of bad calls: every import, builtin name and attribute name in the code
    is on a list of ones that cannot write or run anything, whatever object they are reached through, and `open` appears
    only as the function of a direct call that reads, or that writes a literal path which names no protected file."""
    calls = {id(n.func): n for n in ast.walk(tree) if isinstance(n, ast.Call)}
    bound = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store)}
    bound |= {a.arg for n in ast.walk(tree) if isinstance(n, ast.arguments) for a in n.args + n.kwonlyargs + n.posonlyargs}
    bound |= {n.name for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.ExceptHandler)) and n.name}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            if any(a.name not in SAFE_IMPORTS or a.asname for a in n.names):
                return False
            bound |= {a.name.split('.')[0] for a in n.names}
        elif isinstance(n, ast.ImportFrom):
            if n.level or n.module not in SAFE_IMPORTS or any(a.name not in SAFE_FROM or a.asname for a in n.names):
                return False
            bound |= {a.name for a in n.names}
    for n in ast.walk(tree):
        if isinstance(n, (ast.Global, ast.Nonlocal, ast.ClassDef, ast.AsyncFunctionDef, ast.Delete, ast.Await)):
            return False
        if isinstance(n, ast.FunctionDef) and n.decorator_list:
            return False
        if isinstance(n, ast.Attribute) and (n.attr not in SAFE_ATTRS or not isinstance(n.ctx, ast.Load)):
            return False
        if isinstance(n, ast.Name):
            if n.id == 'open':
                if id(n) not in calls or not isinstance(n.ctx, ast.Load) or not _open_ok(calls[id(n)], names):
                    return False
            elif n.id.startswith('__') or isinstance(n.ctx, ast.Load) and n.id not in bound and n.id not in SAFE_BUILTINS:
                return False
        if isinstance(n, ast.Call) and any(k.arg is None or k.arg in ('file', 'opener') for k in n.keywords):
            return False
        if isinstance(n, ast.Subscript) and not isinstance(n.ctx, ast.Load) and not isinstance(n.value, (ast.Name, ast.Subscript)):
            return False  # os.environ['X'] = ...
    return True


def _open_ok(call, names):
    if len(call.args) > 2 or any(isinstance(a, ast.Starred) for a in call.args) or any(
            k.arg not in ('mode', 'encoding', 'errors', 'newline') for k in call.keywords):
        return False
    mode = call.args[1] if len(call.args) > 1 else next((k.value for k in call.keywords if k.arg == 'mode'), None)
    if mode is None:
        return True
    if not (isinstance(mode, ast.Constant) and isinstance(mode.value, str)):
        return False
    if re.fullmatch(r'[rbt]+', mode.value):
        return True
    target = call.args[0] if call.args else None  # a write: only to a literal path that names no protected file
    return isinstance(target, ast.Constant) and isinstance(target.value, str) and names.path(target.value) is None


SHELL_CALLS = frozenset(('system', 'popen', 'Popen', 'run', 'call', 'check_call', 'check_output', 'getoutput',
                         'getstatusoutput'))


def judge_code(analyzer, code, depth):
    names = _names(analyzer)
    tree, literals = _literals(code)
    for n in ast.walk(tree) if tree is not None else ():  # os.system('printf x >> ~/.claude/CLAUDE.md'): shell text
        if isinstance(n, ast.Call) and n.args and getattr(n.func, 'attr', getattr(n.func, 'id', '')) in SHELL_CALLS:
            arg = n.args[0]
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str) and NAMES_FILE.search(arg.value):
                analyzer.script(arg.value, depth + 1, tail_visible=True)
    hit = _code_hit(names, code, literals)
    if hit and not (tree is not None and python_reads_only(tree, names)):
        _refuse(analyzer, 'interpreter code', hit, 'this guard cannot prove that the code only reads it')
