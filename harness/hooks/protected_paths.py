"""The one list of instruction, settings, hook, transcript and WAL files that only the user changes (goodqa#17155), and
the check that decides whether a file-edit tool call would change one of them.

Covers the four file-edit tools only; shell writes are not covered yet (PR B).

An entry is a directory plus a relative pattern. The directory (or its nearest existing parent, with the missing
segments moved into the pattern) is known by device and inode and also by its text. A target is judged in every form
the tool or the kernel may read it as: as given, trimmed and collapsed, and each resolved through every symlink. Names
are compared NFD, casefold, NFD. A `*` never crosses a `/`; `**` matches any depth and the directory itself.

protected_write_hook.py loads this file by location. Standard library only, Python 3.9. Every file system call goes
through `Files`, so a test can inject a stat table, a clock, a cap or an error; nothing but HOME, CLAUDE_CONFIG_DIR and
CODEX_HOME changes the list at run time, and the last two only add to it.
"""

import errno
import json
import os
import posixpath
import pwd
import stat
import time
import unicodedata

FILE_TOOLS = {"write": "file_path", "edit": "file_path", "multiedit": "file_path", "notebookedit": "notebook_path"}
PATH_KEYS = ("file_path", "notebook_path", "path")

# name -> (literal patterns in the directory, listed trees, pattern trees that are never listed)
LISTS = {
    ".claude": (("CLAUDE.md", "settings*.json", "history.jsonl"), ("rules", "hooks"),
                (("projects", ("**", "*.jsonl")), ("wals", ("**",)))),
    ".codex": (("AGENTS*.md", "config.toml", "hooks.json", "history.jsonl"), ("rules", "agent-harness"),
               (("sessions", ("**",)), ("archived_sessions", ("**",)))),
    ".agent-harness": ((), (), (("codex-wals", ("**",)),)),
}
HOME_FILE = ".claude.json"
LINK_TREES = ("rules",)  # a directory link makes a tree entry only here
UNSCANNED = {"backups", "__pycache__"}
SETTINGS_NAMES = ("settings.json", "settings.local.json")
SETTINGS_KEYS = ("disableAllHooks", "hooks", "env")

# What JavaScript String.trim and Python str.strip remove, together.
TRIM = ("\t\n\x0b\x0c\r\x1c\x1d\x1e\x1f \x85\xa0            "
        "    　﻿")

ALLOW, REFUSE = 0, 2


class Limits:
    """Bounds of one call. Tests pass their own instance."""
    path_bytes = 4096
    links = 40
    rounds = 64                # trim and collapse, until nothing changes
    link_names = 5000          # names per listed tree in the symlink check
    link_seconds = 0.5         # for all listed trees together
    scan_names = 50000         # names per listed tree in the hard-link scan
    chain_levels = 64          # cwd and its ancestors in the project settings lookup
    chain_seconds = 0.25
    settings_bytes = 1 << 20


class Unjudgeable(Exception):
    """The call cannot be judged, so it is refused. The text is a fixed phrase, never input."""


def encode(path):
    return path.encode("utf-8", "surrogateescape")


def decode(path):
    return path.decode("utf-8", "surrogateescape") if isinstance(path, bytes) else path


def fold(name):
    return unicodedata.normalize("NFD", unicodedata.normalize("NFD", name).casefold())


def segments(path):
    return [part for part in path.split("/") if part and part != "."]


def joined(parts):
    return "/" + "/".join(parts)


def collapse(path):
    out = posixpath.normpath(path)
    return out[1:] if out.startswith("//") else out


def glob(name, pattern):
    """One segment, both already folded; at most one `*` in the pattern."""
    head, star, tail = pattern.partition("*")
    if not star:
        return name == pattern
    return len(name) >= len(head) + len(tail) and name.startswith(head) and name.endswith(tail)


def matches(parts, pattern):
    if not pattern:
        return not parts
    if pattern[0] == "**":
        return any(matches(parts[i:], pattern[1:]) for i in range(len(parts) + 1))
    return bool(parts) and glob(parts[0], pattern[0]) and matches(parts[1:], pattern[1:])


class Files:
    """The file system calls of one check, with stat results kept for the call. Paths are str here, bytes below."""

    def __init__(self, stat_call=os.stat, lstat_call=os.lstat, readlink=os.readlink, scandir=os.scandir,
                 clock=time.monotonic):
        self._stat, self._lstat, self.readlink_call, self.scandir_call = stat_call, lstat_call, readlink, scandir
        self.clock = clock
        self._kept = {}

    def _look(self, call, path):
        key = (call is self._stat, path)
        if key not in self._kept:
            try:
                self._kept[key] = ("ok", call(encode(path)))
            except OSError as error:
                status = {errno.ENOENT: "missing", errno.ENOTDIR: "missing", errno.ELOOP: "loop"}.get(error.errno, "error")
                self._kept[key] = (status, None)
        return self._kept[key]

    def stat(self, path):
        return self._look(self._stat, path)

    def lstat(self, path):
        return self._look(self._lstat, path)

    def readlink(self, path):
        return decode(self.readlink_call(encode(path)))

    def scandir(self, path):
        return self.scandir_call(encode(path))


def identity(info):
    """(device, inode), or None when the file system does not give one."""
    return (info.st_dev, info.st_ino) if info is not None and info.st_ino else None


def special(parts):
    """/proc or /dev/fd: a path there can mean another file for the tool than for this process."""
    folded = [part.casefold() for part in parts[:2]]
    return folded[:1] == ["proc"] or folded == ["dev", "fd"]


class Walked:
    def __init__(self, parts, error, proc):
        self.parts, self.error, self.proc = parts, error, proc


def walk(files, path, max_links):
    """The physical path: every symlink followed by reading it, `..` applied to the result. Below a component that is
    missing or cannot be read, the rest is taken as spelled."""
    rest = [part for part in reversed(path.split("/")) if part and part != "."]
    out, links, error, proc, spelled = [], 0, False, False, False
    while rest:
        name = rest.pop()
        if name == "..":
            if out:
                out.pop()
            continue
        out.append(name)
        proc = proc or special(out)
        if spelled:
            continue
        status, info = files.lstat(joined(out))
        if status != "ok":
            spelled, error = True, error or status != "missing"
            continue
        if not stat.S_ISLNK(info.st_mode):
            continue
        links += 1
        try:
            if links > max_links:
                raise OSError(errno.ELOOP, "too many links")
            target = files.readlink(joined(out))
        except OSError:
            spelled = error = True
            continue
        out.pop()
        if target.startswith("/"):
            out = []
        rest.extend(part for part in reversed(target.split("/")) if part and part != ".")
    return Walked(out, error, proc)


class Entries:
    """Entries by text and by identity."""

    def __init__(self, files, max_links):
        self.files, self.max_links = files, max_links
        self.texts, self.table = [], {}

    def add(self, directory, pattern, label):
        """directory: absolute path text. pattern: tuple of segments."""
        pattern = tuple(fold(part) for part in pattern)
        for base in {tuple(segments(collapse(directory))), tuple(walk(self.files, directory, self.max_links).parts)}:
            self.texts.append((tuple(fold(part) for part in base), pattern, label))
            kept = list(base)
            moved = ()
            while True:
                status, info = self.files.stat(joined(kept))
                if status == "missing" and kept:
                    moved = (fold(kept.pop()),) + moved
                    continue
                if status == "ok" and identity(info):
                    self.table.setdefault(identity(info), []).append((moved + pattern, label))
                break

    def find(self, parts, problems):
        """The label of the entry that covers the absolute path, or None. A lookup error is put in `problems`."""
        folded = tuple(fold(part) for part in parts)
        for base, pattern, label in self.texts:
            if folded[:len(base)] == base and matches(folded[len(base):], pattern):
                return label
        for cut in range(len(parts), -1, -1):
            status, info = self.files.stat(joined(parts[:cut]))
            if status in ("error", "loop"):
                problems.add("lookup")
            key = identity(info) if status == "ok" else None
            for pattern, label in self.table.get(key, ()) if key else ():
                if matches(folded[cut:], pattern):
                    return label
        return None


class Root:
    """One protected directory: a home's .claude, .codex or .agent-harness, or a directory named by the environment."""

    def __init__(self, kind, path, label, extra=()):
        self.kind, self.path, self.label = kind, path, label
        names, trees, patterns = LISTS[kind]
        self.literals = tuple(names) + tuple(extra)
        self.trees = tuple((name, path + "/" + name) for name in trees)
        self.patterns = tuple((path + "/" + name, pattern, name) for name, pattern in patterns)


def home_directories(environ, account_home):
    """HOME when it is absolute, and the account's home: whichever of the two resolve."""
    out = []
    value = environ.get(b"HOME", b"")
    if value.startswith(b"/"):
        out.append(collapse(decode(value)))
    try:
        account = account_home()
    except (KeyError, OSError):
        account = None
    if account:
        account = decode(os.fsencode(account))
        if account.startswith("/") and collapse(account) not in out:
            out.append(collapse(account))
    return out


def account_home():
    return pwd.getpwuid(os.getuid()).pw_dir


def root_directories(files, homes, environ):
    roots = []
    for home in homes:
        base = "" if home == "/" else home
        roots += [Root(kind, base + "/" + kind, "~/" + kind) for kind in LISTS]
    for name, kind in ((b"CLAUDE_CONFIG_DIR", ".claude"), (b"CODEX_HOME", ".codex")):
        value = environ.get(name, b"")
        if not value.startswith(b"/"):
            continue
        path = collapse(decode(value))
        status, info = files.stat(path)
        if status == "ok" and stat.S_ISDIR(info.st_mode):
            roots.append(Root(kind, path, "$" + name.decode(), (HOME_FILE,) if kind == ".claude" else ()))
    return roots


class Check:
    """One target. `refusal()` gives (code, text)."""

    def __init__(self, files=None, limits=None, environ=None, account=account_home):
        self.files, self.limits = files or Files(), limits or Limits()
        environ = os.environb if environ is None else environ
        self.homes = home_directories(environ, account)
        self.tilde = self.homes[0] if self.homes else None
        self.roots = root_directories(self.files, self.homes, environ)
        self.entries = Entries(self.files, self.limits.links)
        for home in self.homes:
            self.entries.add(home, (HOME_FILE,), "~/" + HOME_FILE)
        for root in self.roots:
            for name in root.literals:
                self.entries.add(root.path, (name,), root.label + "/" + name)
            for name, path in root.trees:
                self.entries.add(path, ("**",), root.label + "/" + name)
            for path, pattern, name in root.patterns:
                self.entries.add(path, pattern, root.label + "/" + name)
        self.problems = set()
        self.made, self.unmade, self.over = [], [], []  # for doctor: links that made a tree, that made none, trees cut short

    # D2 (b): symlinks in the literal entries and the listed trees

    def _never_a_tree(self):
        """Identities and texts of every home, every ancestor of a home and every ancestor of a protected directory."""
        bases = [(home, True) for home in self.homes]
        for root in self.roots:
            bases += [(root.path, False)] + [(path, False) for _, path in root.trees]
            bases += [(path, False) for path, _, _ in root.patterns]
        idents, texts = set(), set()
        for base, whole in bases:
            for parts in (segments(base), walk(self.files, base, self.limits.links).parts):
                for cut in range(len(parts) + (1 if whole else 0)):
                    texts.add(tuple(fold(part) for part in parts[:cut]))
                    status, info = self.files.stat(joined(parts[:cut]))
                    if status == "ok" and identity(info):
                        idents.add(identity(info))
        return idents, texts

    def _link(self, path, label, tree_allowed, barred):
        found = walk(self.files, path, self.limits.links)
        dest = joined(found.parts)
        status, info = self.files.stat(path)
        if found.error or status not in ("ok", "missing"):
            self.over.append(label + " (a link could not be read)")
        directory = status == "ok" and stat.S_ISDIR(info.st_mode)
        if directory or (status == "missing" and tree_allowed):
            idents, texts = barred
            stop = tuple(fold(part) for part in found.parts) in texts or (directory and identity(info) in idents)
            if tree_allowed and not stop:
                self.entries.add(dest, ("**",), label)
                self.made.append((path, dest))
                return
            if directory:
                self.unmade.append((path, dest))
                return
        if found.parts:
            self.entries.add(joined(found.parts[:-1]), (found.parts[-1],), label)

    def add_links(self):
        files, limits = self.files, self.limits
        barred = self._never_a_tree()
        until = files.clock() + limits.link_seconds
        for home in self.homes:
            self._literal_link(home + "/" + HOME_FILE, "~/" + HOME_FILE, barred)
        for root in self.roots:
            for name in root.literals:
                if "*" not in name:
                    self._literal_link(root.path + "/" + name, root.label + "/" + name, barred)
            globs = [fold(name) for name in root.literals if "*" in name]
            if globs:
                for entry, path in self._names(root.path, root.label, until, deep=False):
                    if any(glob(fold(decode(entry.name)), pattern) for pattern in globs) and entry.is_symlink():
                        self._link(path, root.label, False, barred)
        for root in self.roots:
            for name, tree in root.trees:
                for entry, path in self._names(tree, root.label + "/" + name, until, deep=True):
                    if entry.is_symlink():
                        self._link(path, root.label + "/" + name, name in LINK_TREES, barred)

    def _literal_link(self, path, label, barred):
        status, info = self.files.lstat(path)
        if status == "ok" and stat.S_ISLNK(info.st_mode):
            self._link(path, label, False, barred)

    def _names(self, top, label, until, deep):
        """Directory entries under top within the cap and the budget; what was cut short goes to `over`."""
        stack, seen = [top], 0
        while stack:
            folder = stack.pop()
            try:
                with self.files.scandir(folder) as found:
                    for entry in found:
                        seen += 1
                        if seen > self.limits.link_names or self.files.clock() > until:
                            self.over.append(label + " (the link check stopped early)")
                            return
                        path = folder + "/" + decode(entry.name)
                        if deep and not entry.is_symlink() and entry.is_dir(follow_symlinks=False):
                            if fold(decode(entry.name)) not in UNSCANNED:
                                stack.append(path)
                            continue
                        yield entry, path
            except OSError as error:
                if error.errno not in (errno.ENOENT, errno.ENOTDIR):
                    self.over.append(label + " (a folder could not be read)")

    # D2 (a): hard links

    def hard_link(self, info):
        """The label of the protected file this multi-link file is, or the reason it cannot be told, or None."""
        wanted = identity(info)
        if wanted is None:
            return None
        for home in self.homes:
            label = self._same_file(home + "/" + HOME_FILE, wanted, "~/" + HOME_FILE)
            if label:
                return label
        for root in self.roots:
            for name in root.literals:
                if "*" not in name:
                    label = self._same_file(root.path + "/" + name, wanted, root.label + "/" + name)
                    if label:
                        return label
            globs = [fold(name) for name in root.literals if "*" in name]
            places = [(root.path, root.label, globs)] if globs else []
            for top, label, only in places + [(tree, root.label + "/" + name, None) for name, tree in root.trees]:
                found = self._scan(top, label, wanted, only)
                if found:
                    return found
        return None

    def _same_file(self, path, wanted, label):
        status, info = self.files.stat(path)
        if status == "error":
            return label + " (it could not be read to compare)"
        return label if status == "ok" and identity(info) == wanted else None

    def _scan(self, top, label, wanted, only):
        status, info = self.files.stat(top)
        if status in ("missing", "loop"):
            return None
        if status == "error":
            return label + " (it could not be read to compare)"
        cut = None
        stack, seen = [top], 0
        while stack and cut is None:
            folder = stack.pop()
            try:
                with self.files.scandir(folder) as found:
                    for entry in found:
                        seen += 1
                        if seen > self.limits.scan_names:
                            cut = label + " (it holds too many names to compare)"
                            break
                        name = fold(decode(entry.name))
                        path = folder + "/" + decode(entry.name)
                        if not entry.is_symlink() and entry.is_dir(follow_symlinks=False):
                            if only is None and name not in UNSCANNED:
                                stack.append(path)
                        elif only is None or any(glob(name, pattern) for pattern in only):
                            if entry.is_symlink() or entry.inode() == wanted[1]:
                                state, other = self.files.stat(path)
                                if state == "ok" and identity(other) == wanted:
                                    return label
            except OSError as error:
                if error.errno not in (errno.ENOENT, errno.ENOTDIR):
                    cut = label + " (it could not be read to compare)"
        return cut if cut and info.st_dev == wanted[0] else None

    # the target

    def forms(self, text, cwd):
        """Absolute paths, as lists of segments, that the call may write; and the settings forms among them."""
        limits = self.limits
        if "\x00" in text:
            raise Unjudgeable("the path holds a NUL character")
        try:
            size = len(text.encode("utf-8"))
        except UnicodeEncodeError:
            raise Unjudgeable("the path is not valid text") from None
        if size > limits.path_bytes:
            raise Unjudgeable("the path is too long")
        spelled = [text, text.strip(TRIM)]
        last = spelled[1]
        for _ in range(limits.rounds):
            after = collapse(last).strip(TRIM) if last else last
            if after == last:
                break
            last = after
            spelled.append(last)
        else:
            raise Unjudgeable("the path does not settle")
        whole, guesses = [], []
        for item in spelled:
            if item == "~" or item.startswith("~/"):
                whole += [home + item[1:] for home in self.homes]
                guesses += [cwd + "/" + item] if cwd else []
            elif item.startswith("/"):
                whole.append(item)
            elif cwd:
                whole.append(cwd + "/" + item)
        if not whole:
            raise Unjudgeable("a relative path without an absolute working directory, or without a home")
        out, main = [], set()
        for path, sure in [(p, True) for p in whole] + [(p, False) for p in guesses]:
            flat = collapse(path)
            if special(segments(path)) or special(segments(flat)):
                raise Unjudgeable("the path goes through /proc or /dev/fd")
            for source in (path, flat):
                found = walk(self.files, source, limits.links)
                if found.proc:
                    raise Unjudgeable("the path goes through /proc or /dev/fd")
                if found.error:
                    self.problems.add("lookup")
                out.append(tuple(found.parts))
                if sure:
                    main.add(tuple(found.parts))
            out.append(tuple(segments(flat)))
            if sure:
                main.add(tuple(segments(flat)))
        unique = list(dict.fromkeys(out))
        return unique, [form for form in unique if form in main]

    def could_be_protected(self, forms):
        for parts in forms:
            folded = tuple(fold(part) for part in parts)
            if folded and folded[-1] == HOME_FILE:
                return True
            for at, name in enumerate(folded):
                if name not in LISTS:
                    continue
                literals, trees, patterns = LISTS[name]
                rest = folded[at + 1:]
                if (any(matches(rest, (fold(item),)) for item in literals)
                        or any(matches(rest, (tree, "**")) for tree in trees)
                        or any(matches(rest, (tree,) + pattern) for tree, pattern in patterns)):
                    return True
        return False

    def judge(self, tool, text, tool_input, cwd):
        """(code, text) for one call: tool is a casefolded FILE_TOOLS name, text its path field."""
        forms, main = self.forms(text, cwd)
        label = self._find(forms)
        if label:
            return REFUSE, protected(label)
        self.add_links()
        label = self._find(forms)
        if label:
            return REFUSE, protected(label)
        several = []
        for parts in forms:
            status, info = self.files.stat(joined(parts))
            if status == "ok" and not stat.S_ISDIR(info.st_mode) and info.st_nlink > 1:
                several.append(info)
        for info in {identity(item): item for item in several}.values():
            label = self.hard_link(info)
            if label:
                return REFUSE, protected(label + ", which this file is or may be another name of")
        if (self.problems or not self.homes) and self.could_be_protected(forms):
            return REFUSE, protected("a protected place") + " It could not be looked up."
        settings = self.settings_forms(main, cwd, several)
        if settings:
            reason = settings_result(self.files, self.limits, tool, tool_input, settings)
            if reason:
                return REFUSE, reason
        return ALLOW, "" if self.homes else "no home directory could be found, so only names were compared"

    def _find(self, forms):
        for parts in forms:
            label = self.entries.find(parts, self.problems)
            if label:
                return label
        return None

    # D8: project settings

    def settings_forms(self, forms, cwd, several):
        named = [parts for parts in forms if len(parts) > 1 and fold(parts[-2]) == ".claude"
                 and fold(parts[-1]) in SETTINGS_NAMES]
        chain, linked = self.settings_chain(cwd)
        looks = any(parts and fold(parts[-1]) in SETTINGS_NAMES for parts in forms)
        if not (chain and (looks or several or linked)):
            return named
        known, idents = Entries(self.files, self.limits.links), set()
        for folder in chain:
            for name in SETTINGS_NAMES:
                known.add(folder, (name,), "settings")
                path = folder + "/" + name
                status, info = self.files.lstat(path)
                if status == "ok" and stat.S_ISLNK(info.st_mode):
                    dest = walk(self.files, path, self.limits.links).parts
                    if dest:
                        known.add(joined(dest[:-1]), (dest[-1],), "settings")
                status, info = self.files.stat(path)
                if status == "ok" and identity(info):
                    idents.add(identity(info))
        out = list(named)
        for parts in forms:
            status, info = self.files.stat(joined(parts))
            same = status == "ok" and identity(info) in idents
            if parts not in out and (same or known.find(parts, set())):
                out.append(parts)
        return out

    def settings_chain(self, cwd):
        """The `.claude` directories of cwd and of each ancestor, looked up by name only, within the bounds."""
        if not cwd:
            return [], False
        until, found, linked = self.files.clock() + self.limits.chain_seconds, [], False
        bases = dict.fromkeys((tuple(segments(collapse(cwd))), tuple(walk(self.files, cwd, self.limits.links).parts)))
        for base in bases:
            for cut in range(len(base), max(-1, len(base) - self.limits.chain_levels), -1):
                folder = joined(base[:cut] + (".claude",))
                for path in (folder, folder + "/" + SETTINGS_NAMES[0], folder + "/" + SETTINGS_NAMES[1]):
                    if self.files.clock() > until:
                        return found, linked
                    status, info = self.files.lstat(path)
                    if status != "ok":
                        if path == folder:
                            break
                        continue
                    linked = linked or stat.S_ISLNK(info.st_mode)
                    if folder not in found:
                        found.append(folder)
        return found, linked


def protected(label):
    return ("%s is changed by the user only, so this write is refused. Put the change in your reply or a ticket; the "
            "user applies it." % label)


SETTINGS_REASON = ("A project .claude settings file: %s, so this write is refused. disableAllHooks, hooks and env there "
                   "are changed by the user only. Put the change in your reply or a ticket; the user applies it.")


class _Top(dict):
    """A JSON object that remembers whether a key came twice."""
    twice = False


def _pairs(pairs):
    out = _Top(pairs)
    out.twice = len(out) != len(pairs)
    return out


def _no_constant(_value):
    raise ValueError("non-finite number")


def strict_object(text, loads):
    """The top-level object, or ValueError. `loads` is safe_input.safe_json_loads: it bounds size, depth and numbers."""
    loads(text)
    value = json.loads(text, object_pairs_hook=_pairs, parse_constant=_no_constant)
    if not isinstance(value, _Top) or value.twice:
        raise ValueError("not one plain object")
    return value


def key_values(value):
    """The three keys as canonical text; a key that is not there is not in the result."""
    return {key: json.dumps(value[key], sort_keys=True) for key in SETTINGS_KEYS if key in value}


class _Exact(Exception):
    """The edit cannot be computed exactly. The text is a fixed phrase."""


def current_text(files, limits, parts):
    """(text or None, why). None with why None: the file is missing."""
    path = encode(joined(parts))
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0))
    except FileNotFoundError:
        return None, None
    except OSError:
        return None, "it could not be read"
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > limits.settings_bytes:
            return None, "it is too large or not a plain file"
        data = b""
        while len(data) <= limits.settings_bytes:
            chunk = os.read(fd, limits.settings_bytes + 1 - len(data))
            if not chunk:
                break
            data += chunk
        if len(data) > limits.settings_bytes:
            return None, "it is too large or not a plain file"
        return data.decode("utf-8"), None
    except (OSError, UnicodeDecodeError):
        return None, "it could not be read"
    finally:
        os.close(fd)


def applied(text, edit, stripped):
    """One edit on text. stripped: as a tool that removes the blanks at line ends of the replacement applies it."""
    if not isinstance(edit, dict):
        raise _Exact("the edit cannot be computed")
    old, new, every = edit.get("old_string"), edit.get("new_string"), edit.get("replace_all", False)
    if not isinstance(old, str) or not isinstance(new, str) or not isinstance(every, bool):
        raise _Exact("the edit cannot be computed")
    if "$" in new:
        raise _Exact("a replacement holds a dollar sign")
    if stripped:
        new = "\n".join(line.rstrip(TRIM) for line in new.split("\n"))
    if not old:
        if text.strip():
            raise _Exact("the edit has no text to replace")
        return new
    count = text.count(old)
    if count == 0:
        raise _Exact("the text to replace is not there")
    if count > 1 and not every:
        raise _Exact("the text to replace is there more than once")
    return text.replace(old, new)


def results(tool, tool_input, text, why):
    """Every text the call may leave in the file."""
    if tool == "write":
        content = tool_input.get("content")
        if not isinstance(content, str):
            raise _Exact("the new content is not text")
        return [content]
    edits = [tool_input] if tool == "edit" else tool_input.get("edits")
    if not isinstance(edits, list) or not edits:
        raise _Exact("the edit cannot be computed")
    if why:
        raise _Exact(why)
    if text is not None and "\r" in text:
        raise _Exact("the file holds carriage returns")
    out = []
    for stripped in (False, True):
        after = text or ""
        for edit in edits:
            after = applied(after, edit, stripped)
        out.append(after)
    return out


def settings_result(files, limits, tool, tool_input, forms):
    """None when the call leaves every settings file it may mean as it may be, else the refusal text."""
    if tool == "notebookedit":
        return SETTINGS_REASON % "it is not a notebook"
    seen = {}
    for parts in forms:
        seen.setdefault(tuple(walk(files, joined(parts), limits.links).parts), None)
    for parts in seen:
        text, why = current_text(files, limits, parts)
        try:
            held = key_values(strict_object(text, limits.json_loads)) if text is not None else {}
        except (ValueError, RecursionError):
            held = {}
        try:
            after = results(tool, tool_input, text, why)
        except _Exact as error:
            return SETTINGS_REASON % str(error)
        for item in after:
            try:
                item.encode("utf-8")
                new = key_values(strict_object(item, limits.json_loads))
            except (ValueError, RecursionError):
                return SETTINGS_REASON % "the result is not one plain JSON object"
            changed = [key for key in SETTINGS_KEYS if new.get(key) != held.get(key)]
            if changed:
                return SETTINGS_REASON % ("the result changes " + ", ".join(changed))
    return None


def judge_payload(payload, json_loads, files=None, limits=None, environ=None, account=account_home):
    """(code, text) for a PreToolUse payload. Raises Unjudgeable when it cannot be told what the call writes."""
    if not isinstance(payload, dict):
        raise Unjudgeable("the call is not an object")
    name = payload.get("tool_name")
    if not isinstance(name, str) or not name:
        raise Unjudgeable("the call does not name its tool")
    tool = name.casefold()
    if tool not in FILE_TOOLS:
        return ALLOW, ""
    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict):
        raise Unjudgeable("the tool input is not an object")
    path = tool_input.get(FILE_TOOLS[tool])
    if not isinstance(path, str):
        raise Unjudgeable("the tool input has no path")
    if any(tool_input.get(key) is not None and tool_input[key] != path for key in PATH_KEYS):
        raise Unjudgeable("the tool input has two different paths")
    cwd = payload.get("cwd")
    cwd = cwd if isinstance(cwd, str) and cwd.startswith("/") and "\x00" not in cwd else None
    if cwd is not None:
        try:
            cwd.encode("utf-8")
        except UnicodeEncodeError:
            cwd = None
    limits = limits or Limits()
    limits.json_loads = json_loads
    return Check(files, limits, environ, account).judge(tool, path, tool_input, cwd)


def link_report(files=None, limits=None, environ=None, account=account_home):
    """For doctor and for a look before an install; reads names only. A list of plain lines."""
    check = Check(files, limits, environ, account)
    check.add_links()
    return (["a link makes its whole destination refused: %s -> %s" % pair for pair in check.made]
            + ["a directory link that protects nothing more (goodqa#17248): %s -> %s" % pair for pair in check.unmade]
            + ["not fully checked for links: %s" % item for item in check.over])
