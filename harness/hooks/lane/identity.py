"""Canonical repository identity, lane key, stream key and held-target check for the lane factory (S1).

Design: software-factory/design-final.md section 3 (identity, lane key, stream key) and section 7 (held targets).

* identity: the remote's host and path, lower-cased, without scheme, userinfo, port, ``.git`` or trailing slash
  (``github.com/owner/repo``). Clones, linked worktrees and every URL spelling of one repository agree.
* A repository with no remote, or with several remotes and no ``origin``, uses ``local:<device>:<inode>`` of its
  common git directory. Two remotes with an ``origin`` use ``origin``; the kind records the choice.
* lane key: ``<ticket ref>|<identity>``; stream key: ``stream-`` + first 12 hex of sha256(lane key).
* A URL's credentials are dropped before anything is returned, stored or compared.
"""
from __future__ import annotations

import hashlib
import os
import re
import stat
from pathlib import Path

PART = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
HOST = re.compile(r"^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$")
SCP = re.compile(r"^(?:[^@/\s]+@)?([^:/\s]+):(?!//)(.+)$")
TICKET = re.compile(r"^goodqa ([a-z0-9][a-z0-9-]*)#([0-9]{1,9})$")
SCHEMES = ("http", "https", "ssh", "git")

# Held targets (user memory rules): rule name -> pattern over identity, paths and remote names.
HELD = (
    ("yates", re.compile(r"yates|apex[_-]?app[_-]?pos", re.I)),
    ("optinrouter", re.compile(r"optin[_-]?router", re.I)),
    ("vertex", re.compile(r"vertex|aiplatform", re.I)),
)


class IdentityError(ValueError):
    """Malformed or unusable repository or ticket input (a specific refusal, nothing written)."""


MAX_GIT_FILE = 1 << 20


def _read_text(path) -> str:
    """Bounded read of a small git file: regular, not a symlink, within the size cap."""
    try:
        fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        raise IdentityError("not a git repository: %s" % path) from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_GIT_FILE:
            raise IdentityError("unusable git file: %s" % os.path.basename(str(path)))
        return os.read(fd, MAX_GIT_FILE + 1).decode("utf-8", "replace")
    finally:
        os.close(fd)


def _is_gitdir(path) -> bool:
    return os.path.isfile(os.path.join(str(path), "HEAD")) and os.path.isdir(os.path.join(str(path), "objects"))


def _git_dir(path) -> str:
    """The git directory of ``path`` (a work tree, a linked work tree, a subdirectory or a bare repository), read
    from the file system without starting a process."""
    current = os.path.realpath(str(path))
    for _ in range(64):
        dot = os.path.join(current, ".git")
        if os.path.islink(dot):
            raise IdentityError("not a git repository (symlinked .git): %s" % path)
        if os.path.isdir(dot):
            return os.path.realpath(dot) if _is_gitdir(dot) else _fail(path)
        if os.path.isfile(dot):
            text = _read_text(dot).strip()
            if not text.startswith("gitdir:"):
                raise IdentityError("not a git repository (bad .git file): %s" % path)
            target = text[len("gitdir:"):].strip()
            target = target if os.path.isabs(target) else os.path.join(current, target)
            target = os.path.realpath(target)
            return target if _is_gitdir(target) or os.path.isfile(os.path.join(target, "commondir")) else _fail(path)
        if _is_gitdir(current):
            return current
        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent
    raise IdentityError("not a git repository: %s" % path)


def _fail(path):
    raise IdentityError("not a git repository: %s" % path)


def _clean_path(path_text: str, original: str) -> str:
    path_text = path_text.strip().strip("/")
    if path_text.endswith(".git"):
        path_text = path_text[:-4].rstrip("/")
    parts = [p.lower() for p in path_text.split("/")]
    if len(parts) < 2 or not all(PART.match(p) and p not in (".", "..") for p in parts):
        raise IdentityError("repository path needs owner/name: %r" % _safe(original))
    return "/".join(parts)


def _safe(text: str) -> str:
    """Never echo userinfo back in an error."""
    return re.sub(r"//[^/@]*@", "//", text)[:120]


def _from_url(text: str) -> str:
    text = text.strip()
    if "://" in text:
        scheme, rest = text.split("://", 1)
        if scheme.lower() not in SCHEMES:
            raise IdentityError("unsupported URL scheme: %r" % _safe(text))
        authority, _, path_text = rest.partition("/")
        host = authority.rsplit("@", 1)[-1]
        host = re.sub(r":[0-9]*$", "", host).lower()
    else:
        match = SCP.match(text)
        if not match:
            raise IdentityError("not a repository URL or path: %r" % _safe(text))
        host, path_text = match.group(1).lower(), match.group(2)
    if not HOST.match(host or ""):
        raise IdentityError("repository URL has no usable host: %r" % _safe(text))
    return host + "/" + _clean_path(path_text, text)


def _looks_like_url(text: str) -> bool:
    return "://" in text or (bool(SCP.match(text)) and not os.path.exists(text))


def _common_git_dir(path) -> str:
    gitdir = _git_dir(path)
    common_file = os.path.join(gitdir, "commondir")
    if os.path.isfile(common_file):
        rel = _read_text(common_file).strip()
        common = os.path.realpath(rel if os.path.isabs(rel) else os.path.join(gitdir, rel))
        if not _is_gitdir(common):
            raise IdentityError("not a git repository: %s" % path)
        return common
    return gitdir


SECTION = re.compile(r'^\s*\[\s*([A-Za-z0-9.-]+)(?:\s+"((?:[^"\\]|\\.)*)")?\s*\]\s*(?:[#;].*)?$')
KEYVAL = re.compile(r"^\s*([A-Za-z][A-Za-z0-9-]*)\s*=\s*(.*?)\s*$")


def _remotes(path) -> list:
    """``[(name, first url)]`` from the common git directory's config, in file order."""
    text = _read_text(os.path.join(_common_git_dir(path), "config"))
    remotes, current = [], None
    for line in text.splitlines():
        sect = SECTION.match(line)
        if sect:
            current = None
            if sect.group(1).lower() == "remote" and sect.group(2) is not None:
                current = {"name": sect.group(2).replace('\\"', '"'), "url": ""}
                remotes.append(current)
            continue
        kv = KEYVAL.match(line)
        if current is not None and kv and kv.group(1).lower() == "url" and not current["url"]:
            current["url"] = kv.group(2).strip().strip('"')
    return [(r["name"], r["url"]) for r in remotes]


def canonical_repo(path_or_url: str):
    """Return ``(identity, kind)``; kind is ``remote``, ``remote-origin`` or ``local``."""
    text = str(path_or_url or "").strip()
    if not text:
        raise IdentityError("empty repository")
    if text.startswith("file://"):
        text = text[7:]
    if _looks_like_url(text):
        return _from_url(text), "remote"
    if not os.path.isdir(text):
        raise IdentityError("not a directory: %s" % _safe(text))
    remotes = _remotes(text)
    if len(remotes) == 1 and remotes[0][1]:
        return _from_url(remotes[0][1]), "remote"
    if len(remotes) > 1:
        origin = [url for name, url in remotes if name == "origin" and url]
        if origin:
            return _from_url(origin[0]), "remote-origin"
    common = _common_git_dir(text)
    st = os.stat(common)
    return "local:%d:%d" % (st.st_dev, st.st_ino), "local"


def normalise_ticket(ticket_ref: str) -> str:
    match = TICKET.match(" ".join(str(ticket_ref or "").split()).lower())
    if not match:
        raise IdentityError("ticket reference needs a project slug, e.g. 'GoodQA goodqa#15946': %r"
                            % str(ticket_ref)[:60])
    return "GoodQA %s#%s" % (match.group(1), int(match.group(2)))


def lane_key(ticket_ref: str, identity: str) -> str:
    if not identity or "|" in identity:
        raise IdentityError("invalid repository identity")
    return normalise_ticket(ticket_ref) + "|" + identity


def stream_key(key: str) -> str:
    return "stream-" + hashlib.sha256(key.encode()).hexdigest()[:12]


def held_rule(identity=None, path=None):
    """Name of the held-target rule that refuses this identity or path, else None.

    The path form resolves symlinks, reads the common git directory (so a linked worktree is judged by its main
    repository) and checks every remote under any name. Unparseable remote URLs are checked raw: fail closed.
    """
    texts = []
    if identity:
        texts.append(str(identity))
    if path:
        real = os.path.realpath(str(path))
        texts.append(real)
        try:
            common = _common_git_dir(real)
            texts.extend([common, os.path.dirname(common)])
            for name, url in _remotes(real):
                texts.append(name)
                try:
                    texts.append(_from_url(url))
                except IdentityError:
                    texts.append(url)
        except IdentityError:
            pass
    for text in texts:
        for rule, pattern in HELD:
            if pattern.search(text):
                return rule
    return None
