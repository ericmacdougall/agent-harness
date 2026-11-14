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
import subprocess
from pathlib import Path

GIT_TIMEOUT = 30
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


def _run_git(path, *args) -> str:
    try:
        done = subprocess.run(["git", "-C", str(path)] + list(args), capture_output=True, text=True,
                              timeout=GIT_TIMEOUT)
    except (OSError, subprocess.SubprocessError):
        raise IdentityError("git could not be run on %s" % path) from None
    if done.returncode:
        raise IdentityError("not a git repository: %s" % path)
    return done.stdout


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
    out = _run_git(path, "rev-parse", "--git-common-dir").strip()
    common = Path(out)
    if not common.is_absolute():
        common = Path(path) / common
    return os.path.realpath(common)


def _remotes(path) -> list:
    names = [n for n in _run_git(path, "remote").split() if n]
    found = []
    for name in names:
        urls = _run_git(path, "remote", "get-url", "--all", name).split("\n")
        found.append((name, urls[0].strip() if urls and urls[0].strip() else ""))
    return found


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
