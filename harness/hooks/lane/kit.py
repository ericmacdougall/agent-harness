"""Kit renderer, lint and version selection for the lane factory (S1).

Templates live in ``templates/<kit_version>/``. Rendering is deterministic (sorted files, no clock, no randomness):
the same inputs always give the same bytes. Input values are data: they are validated and substituted in a single
pass, so a value can never introduce a placeholder or an instruction. ``kit_version`` is selected per lane; a canary
is one ticket named in ``LANE_KIT_VERSION`` (``<ticket>=<version>``), recorded in the journal by the caller.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
from pathlib import Path

from . import identity as ident

TEMPLATES = Path(__file__).resolve().parent / "templates"
INPUT_NAMES = ("lane_id", "ticket", "stream_key", "branch", "kit_version", "repo_identity")
PLACEHOLDER = re.compile(r"\{\{\s*([A-Za-z0-9_]*)\s*\}\}")
VALUE = re.compile(r"^[A-Za-z0-9._:/#|@ -]{1,200}$")
VERSION = re.compile(r"^v[0-9]{1,3}$")
REQUIRED_GATES = ("G1", "G2", "G3")
MAX_TEMPLATE = 64 * 1024

LINT = (
    ("a password step", re.compile(r"(?i)\b(type|enter|paste|fill in|put|supply)\b[^.\n]{0,40}\bpasswords?\b")),
    ("a top-rung model literal", re.compile(r"(?i)\b(fable|astra)\b")),
    ("a sleep-poll loop", re.compile(r"(?i)\bwhile\b[^\n]*\bsleep\b|\bsleep\s+[0-9]+|\buntil\b[^\n]*\bsleep\b|\bwatch\s+-n")),
    ("a private hostname or address", re.compile(
        r"\b(10\.[0-9]+\.[0-9]+\.[0-9]+|192\.168\.[0-9]+\.[0-9]+|172\.(1[6-9]|2[0-9]|3[01])\.[0-9]+\.[0-9]+)\b"
        r"|\b[a-z0-9-]+\.(internal|local|lan|corp)\b")),
    ("a pre-filled verdict or sign-off", re.compile(r"(?im)^\s*(verdict|sign-?off|review)\s*:\s*(accept|approved|signed)")),
    ("a runner other than the headed desktop instance", re.compile(r"(?i)headless|claude in chrome|playwright")),
    ("a secret-shaped value", re.compile(r"(?i)\b(api[_-]?key|token|secret)\s*[:=]\s*\S{12,}")),
)


class KitError(Exception):
    pass


def _version_dir(version, root):
    if not VERSION.match(version or ""):
        raise KitError("invalid kit version %r" % str(version)[:20])
    path = Path(root) / version
    if path.is_symlink() or not path.is_dir():
        raise KitError("kit version %s has no template directory" % version)
    return path


def _template_files(version, root):
    base = _version_dir(version, root)
    files = {}
    for p in sorted(base.rglob("*")):
        if p.is_symlink():
            raise KitError("template %s is a symlink" % p.name)
        if p.is_file():
            if p.stat().st_size > MAX_TEMPLATE:
                raise KitError("template %s is over %d bytes" % (p.name, MAX_TEMPLATE))
            files[str(p.relative_to(base))] = p.read_bytes()
    if not files:
        raise KitError("kit version %s is empty" % version)
    try:
        required = json.loads(files["gates.json"].decode()).get("files", [])
    except (KeyError, ValueError, AttributeError):
        raise KitError("kit version %s has no valid gates.json" % version)
    missing = [name for name in required if name not in files]
    if missing:
        raise KitError("kit version %s lacks template files: %s" % (version, ", ".join(missing)))
    return files


def lint_version(version, root) -> list:
    """Problems that refuse a kit version (empty list when clean)."""
    try:
        files = _template_files(version, root)
    except KitError as error:
        return [str(error)]
    problems = []
    gates = files.get("gates.json")
    if gates is None:
        problems.append("kit version %s has no gates.json" % version)
    else:
        try:
            listed = json.loads(gates.decode()).get("gates", [])
        except (ValueError, AttributeError):
            listed, problems = [], problems + ["gates.json is not valid"]
        for gate in REQUIRED_GATES:
            if gate not in listed:
                problems.append("kit version %s drops gate %s" % (version, gate))
    for name, data in files.items():
        try:
            text = data.decode()
        except UnicodeDecodeError:
            problems.append("%s is not text" % name)
            continue
        for label, pattern in LINT:
            if pattern.search(text):
                problems.append("%s contains %s" % (name, label))
        for match in PLACEHOLDER.finditer(text):
            if match.group(1) not in INPUT_NAMES:
                problems.append("%s has an unknown placeholder %r" % (name, match.group(1)))
    return problems


def render_files(version, inputs: dict, root) -> dict:
    """Render in memory: ``{relative path: bytes}``. Refuses unfilled or injected placeholders."""
    files = _template_files(version, root)
    for name in INPUT_NAMES:
        value = inputs.get(name)
        if not isinstance(value, str) or not VALUE.match(value) or "{{" in value:
            raise KitError("input %r is missing or not plain text" % name)

    def fill(match):
        key = match.group(1)
        if key not in inputs or key not in INPUT_NAMES:
            raise KitError("no input fills placeholder %r" % key)
        return inputs[key]

    out = {}
    for name, data in files.items():
        text = PLACEHOLDER.sub(fill, data.decode())
        if "{{" in text or "}}" in text:
            raise KitError("unresolved placeholder text in %s" % name)
        out[name] = text.encode()
    return out


def digests(files: dict) -> dict:
    return {name: hashlib.sha256(data).hexdigest() for name, data in sorted(files.items())}


def template_digest(version, root) -> str:
    h = hashlib.sha256()
    for name, data in sorted(_template_files(version, root).items()):
        h.update(("%s:%s\n" % (name, hashlib.sha256(data).hexdigest())).encode())
    return h.hexdigest()


def digest_list(files: dict) -> str:
    return "".join("%s  %s\n" % (d, n) for n, d in digests(files).items())


def render(version, inputs: dict, dest, root) -> dict:
    """Render into ``dest`` (created here, mode 0700, files 0600); returns the digests. Nothing is written on error."""
    files = render_files(version, inputs, root)
    dest = Path(dest)
    dest.mkdir(mode=0o700, parents=True)
    try:
        for name, data in files.items():
            target = dest / name
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            fd = os.open(str(target), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
    except BaseException:
        shutil.rmtree(str(dest), ignore_errors=True)
        raise
    return digests(files)


def select_version(ticket_ref: str, policy: dict, env: dict):
    """``(version, overridden)``: the policy default, or the per-ticket canary named in LANE_KIT_VERSION."""
    default = policy.get("default", "v1")
    if not VERSION.match(default):
        raise KitError("kit policy default is not a version")
    raw = (env or {}).get("LANE_KIT_VERSION")
    if not raw:
        return default, False
    ticket, sep, version = raw.rpartition("=")
    if not sep or not VERSION.match(version):
        raise KitError("LANE_KIT_VERSION must be '<ticket>=<version>'")
    try:
        named = ident.normalise_ticket(ticket)
    except ident.IdentityError as error:
        raise KitError(str(error))
    if named == ident.normalise_ticket(ticket_ref):
        return version, True
    return default, False
