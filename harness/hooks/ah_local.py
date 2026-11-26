#!/usr/bin/env python3
"""Machine- and owner-specific settings, read from ~/.agent-harness/local.json.

The harness itself names no host, project, person or remote. Everything that differs between installs (the
worker hosts, where heavy work goes, backup remotes, launchd label prefixes, the canonical repo URL, the chat
prefix, the ticket base URL, extra database tools) lives in that one file; see docs/local-config.md and
harness/local.json.example. A missing, unreadable or malformed file is the same as an empty one: every key falls
back to the caller's default, so a fresh install works and simply has no remote hosts.

Stdlib only, never raises, read once per process. `AH_LOCAL_CONFIG` points at another file (tests).
"""
from __future__ import annotations

import json
import os
from pathlib import Path

MAX_BYTES = 256 * 1024
_cache: dict | None = None


def path() -> Path:
    override = os.environ.get("AH_LOCAL_CONFIG")
    if override:
        return Path(override).expanduser()
    return Path.home() / ".agent-harness" / "local.json"


def load() -> dict:
    """The whole config as a dict ({} when absent or unreadable). Cached per process."""
    global _cache
    if _cache is None:
        data: dict = {}
        try:
            with open(path(), "rb") as fh:
                raw = fh.read(MAX_BYTES + 1)
            if len(raw) <= MAX_BYTES:
                parsed = json.loads(raw.decode("utf-8"))
                if isinstance(parsed, dict):
                    data = parsed
        except (OSError, ValueError):
            data = {}
        _cache = data
    return _cache


def reset() -> None:
    """Forget the cached file (tests, or a long-running process that wants a re-read)."""
    global _cache
    _cache = None


def get(key: str, default=None):
    """The value for `key`, or `default` when it is missing or of a different JSON type than `default`."""
    value = load().get(key, default)
    if default is not None and value is not None and not isinstance(value, type(default)):
        if not (isinstance(default, (list, tuple)) and isinstance(value, (list, tuple))):
            return default
    return value


def hosts() -> dict:
    """name -> {"role": ..., "os": ..., "limits": {...}} for every host whose name is a plain string."""
    raw = get("hosts", {})
    return {str(k): (v if isinstance(v, dict) else {}) for k, v in raw.items() if isinstance(k, str) and k}


def host_names(*, os_name: str | None = None, role: str | None = None) -> tuple:
    """Host names, optionally only those whose `os` (e.g. "linux", "macos", "windows") or `role` matches."""
    out = []
    for name, info in hosts().items():
        if os_name is not None and str(info.get("os", "")).lower() != os_name:
            continue
        if role is not None and info.get("role") != role and role not in (info.get("roles") or ()):
            continue
        out.append(name)
    return tuple(out)


def str_list(key: str) -> tuple:
    """A list-of-strings key as a tuple, ignoring non-string entries."""
    return tuple(x for x in get(key, []) if isinstance(x, str) and x)


DEFAULT_LABEL_PREFIX = "com.agent-harness."


def label_prefix() -> str:
    """The launchd label prefix of the harness's own jobs (`launchd_label_prefix`, e.g. "com.example."); a value that
    is not a plain dotted prefix falls back to com.agent-harness."""
    import re  # noqa: PLC0415
    value = get("launchd_label_prefix", DEFAULT_LABEL_PREFIX)
    return value if re.fullmatch(r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.", value or "") else DEFAULT_LABEL_PREFIX


def label(name: str) -> str:
    """The launchd label for one of the harness's jobs, e.g. label("ahd") -> "com.agent-harness.ahd"."""
    return label_prefix() + name


def protected_label_prefixes() -> tuple:
    """Label prefixes whose jobs the kill guard protects: `protected_label_prefixes` plus the job label prefix."""
    out = [p for p in str_list("protected_label_prefixes")]
    if label_prefix() not in out:
        out.append(label_prefix())
    return tuple(out)
