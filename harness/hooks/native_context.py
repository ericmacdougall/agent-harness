"""Read-only native runtime origin evidence. This module never admits a main agent.

Kernel ancestry and running code can identify an OpenAI runtime, but cannot
authenticate a hook event or select a thread in a shared desktop process.
Environment and payload hints are used only to deny legacy-main fallback.
"""
from __future__ import annotations

import argparse
import ctypes as ct
import json
import os
import re
import sys
from dataclasses import asdict, dataclass

from safe_input import safe_json_loads

OPENAI_TEAM = "2DC432GLL2"
CODE_REQUIREMENT = 'anchor apple generic and identifier "codex" and certificate leaf[subject.OU] = "2DC432GLL2"'
NATIVE_MARKERS = ("CODEX_THREAD_ID", "CODEX_TOOL_CALL_ID", "CODEX_SANDBOX")
MAX_INPUT = 1024 * 1024


def decode_candidate_json(data):
    """Bound input first, then reject duplicate keys and non-JSON constants."""
    safe_json_loads(data, max_depth=32, max_bytes=MAX_INPUT)
    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result
    def constant(_):
        raise ValueError("non-JSON numeric constant")
    return json.loads(data, object_pairs_hook=pairs, parse_constant=constant)


@dataclass(frozen=True)
class ProcessIdentity:
    pid: int
    parent: int
    uid: int
    started: int  # kernel microseconds, not a date inferred from a message ID
    executable: str


@dataclass(frozen=True)
class CodeIdentity:
    identifier: str
    team: str
    cdhash: str
    executable: str


@dataclass(frozen=True)
class OriginObservation:
    origin: str
    native_lineage: bool
    reason: str
    runtime_pid: int | None = None
    code: CodeIdentity | None = None
    role: str = "unknown"
    main_authority: bool = False
    strong_user_source: bool = False


def _valid_process(value, pid):
    return (isinstance(value, ProcessIdentity) and type(value.pid) is int and value.pid == pid
            and 1 < pid < 2 ** 31 and type(value.parent) is int and 0 <= value.parent < 2 ** 31
            and type(value.started) is int and value.started > 0 and type(value.uid) is int and value.uid >= 0
            and isinstance(value.executable, str) and value.executable.startswith("/")
            and len(value.executable) <= 4096 and "\x00" not in value.executable)


def probe_runtime_origin(pid=None, *, backend=None):
    """Bounded origin-only probe; a supplied backend is an in-process test double."""
    pid = os.getpid() if pid is None else pid
    native = False
    try:
        if backend is None:
            if sys.platform != "darwin":
                return OriginObservation("unknown", False, "unsupported_platform")
            backend = DarwinBackend()
        chain, seen, barrier, candidate = [], set(), False, None
        current = pid
        for _ in range(32):
            if current <= 1:
                break
            if current in seen:
                return OriginObservation("unknown", native, "ancestry_cycle")
            seen.add(current)
            process = backend.process(current)
            if not _valid_process(process, current):
                return OriginObservation("unknown", native, "invalid_process_identity")
            chain.append(process)
            name = os.path.basename(process.executable)
            if name in {"claude", "kimi"}:
                barrier = True  # an outer Codex process is not this nearer runtime's author
            if name == "codex":
                native = True
                if not barrier:
                    candidate = process
                break
            current = process.parent
        else:
            return OriginObservation("unknown", native, "ancestry_limit")
        if candidate is None:
            return OriginObservation("unknown", native, "nearer_other_runtime" if native else "no_native_runtime")
        first = backend.signature(candidate.pid)
        for previous in chain:
            if backend.process(previous.pid) != previous:
                return OriginObservation("unknown", True, "process_changed")
        second = backend.signature(candidate.pid)
        for previous in chain:
            if backend.process(previous.pid) != previous:
                return OriginObservation("unknown", True, "process_changed")
        if (not isinstance(first, CodeIdentity) or first != second or first.identifier != "codex"
                or first.team != OPENAI_TEAM or not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", first.cdhash)
                or os.path.realpath(first.executable) != os.path.realpath(candidate.executable)):
            return OriginObservation("unknown", True, "code_identity_unverified")
        return OriginObservation("openai", True, "running_code_verified", candidate.pid, first)
    except (OSError, ValueError, TypeError, AttributeError, OverflowError):
        return OriginObservation("unknown", native, "probe_failed")


def native_deny_reason(payload):
    """Deny only. Hints never establish identity, and origin never grants main."""
    if any(os.environ.get(key) for key in NATIVE_MARKERS):
        return "native_environment_hint"
    path = payload.get("transcript_path") if isinstance(payload, dict) else None
    if isinstance(path, str) and "/.codex/" in path.replace("\\", "/"):
        return "native_transcript_hint"
    observation = probe_runtime_origin()
    if observation.native_lineage or observation.origin == "openai":
        return "native_origin_has_no_main_admission"
    if observation.reason not in {"unsupported_platform", "no_native_runtime", "nearer_other_runtime"}:
        return "runtime_origin_uncertain"
    return None


class DarwinBackend:
    """macOS kernel process facts plus Security.framework running-guest checks."""
    class BSDInfo(ct.Structure):
        _fields_ = [(name, ct.c_uint32) for name in (
            "flags", "status", "xstatus", "pid", "ppid", "uid", "gid", "ruid", "rgid", "svuid", "svgid", "reserved")]
        _fields_ += [("comm", ct.c_char * 16), ("name", ct.c_char * 32)]
        _fields_ += [(name, ct.c_uint32) for name in ("nfiles", "pgid", "pjobc", "tdev", "tpgid")]
        _fields_ += [("nice", ct.c_int32), ("start_sec", ct.c_uint64), ("start_usec", ct.c_uint64)]

    def __init__(self):
        if sys.platform != "darwin":
            raise OSError("Darwin backend unavailable")
        self.proc = ct.CDLL("/usr/lib/libproc.dylib")
        self.proc.proc_pidinfo.argtypes = [ct.c_int, ct.c_int, ct.c_uint64, ct.c_void_p, ct.c_int]
        self.proc.proc_pidinfo.restype = ct.c_int
        self.proc.proc_pidpath.argtypes = [ct.c_int, ct.c_void_p, ct.c_uint32]
        self.proc.proc_pidpath.restype = ct.c_int
        self.cf = ct.CDLL("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")
        self.sec = ct.CDLL("/System/Library/Frameworks/Security.framework/Security")
        signatures = {
            "CFStringCreateWithCString": ([ct.c_void_p, ct.c_char_p, ct.c_uint32], ct.c_void_p),
            "CFNumberCreate": ([ct.c_void_p, ct.c_int, ct.c_void_p], ct.c_void_p),
            "CFDictionaryCreate": ([ct.c_void_p, ct.c_void_p, ct.c_void_p, ct.c_long, ct.c_void_p, ct.c_void_p], ct.c_void_p),
            "CFDictionaryGetValue": ([ct.c_void_p, ct.c_void_p], ct.c_void_p),
            "CFStringGetCString": ([ct.c_void_p, ct.c_void_p, ct.c_long, ct.c_uint32], ct.c_bool),
            "CFURLCopyFileSystemPath": ([ct.c_void_p, ct.c_int], ct.c_void_p),
            "CFDataGetLength": ([ct.c_void_p], ct.c_long),
            "CFDataGetBytePtr": ([ct.c_void_p], ct.c_void_p),
            "CFRelease": ([ct.c_void_p], None),
        }
        for name, (args, result) in signatures.items():
            function = getattr(self.cf, name); function.argtypes = args; function.restype = result
        for name, args in {
            "SecCodeCopyGuestWithAttributes": [ct.c_void_p, ct.c_void_p, ct.c_uint32, ct.c_void_p],
            "SecRequirementCreateWithString": [ct.c_void_p, ct.c_uint32, ct.c_void_p],
            "SecCodeCheckValidity": [ct.c_void_p, ct.c_uint32, ct.c_void_p],
            "SecCodeCopySigningInformation": [ct.c_void_p, ct.c_uint32, ct.c_void_p],
        }.items():
            function = getattr(self.sec, name); function.argtypes = args; function.restype = ct.c_int32

    def process(self, pid):
        info = self.BSDInfo()
        if self.proc.proc_pidinfo(pid, 3, 0, ct.byref(info), ct.sizeof(info)) != ct.sizeof(info):
            raise OSError("kernel process identity unavailable")
        path = ct.create_string_buffer(4096)
        if self.proc.proc_pidpath(pid, path, len(path)) <= 0 or info.start_usec >= 1000000:
            raise OSError("kernel executable identity unavailable")
        return ProcessIdentity(info.pid, info.ppid, info.uid, info.start_sec * 1000000 + info.start_usec,
                               path.value.decode("utf-8", "strict"))

    def _constant(self, name):
        return ct.c_void_p.in_dll(self.sec, name).value

    def _text(self, value):
        if not value:
            raise OSError("signing information missing")
        buffer = ct.create_string_buffer(4096)
        if not self.cf.CFStringGetCString(value, buffer, len(buffer), 0x08000100):
            raise OSError("signing string unavailable")
        return buffer.value.decode("utf-8", "strict")

    def signature(self, pid):
        owned = []
        def hold(value):
            if not value: raise OSError("Security framework allocation failed")
            owned.append(value); return value
        def check(status):
            if status != 0: raise OSError("running code verification refused")
        try:
            number = ct.c_int64(pid)
            pid_number = hold(self.cf.CFNumberCreate(None, 4, ct.byref(number)))
            keys = (ct.c_void_p * 1)(self._constant("kSecGuestAttributePid"))
            values = (ct.c_void_p * 1)(pid_number)
            attributes = hold(self.cf.CFDictionaryCreate(None, keys, values, 1, None, None))
            guest = ct.c_void_p()
            check(self.sec.SecCodeCopyGuestWithAttributes(None, attributes, 0, ct.byref(guest)))
            hold(guest.value)
            rule = hold(self.cf.CFStringCreateWithCString(None, CODE_REQUIREMENT.encode(), 0x08000100))
            requirement = ct.c_void_p()
            check(self.sec.SecRequirementCreateWithString(rule, 0, ct.byref(requirement)))
            hold(requirement.value)
            check(self.sec.SecCodeCheckValidity(guest, 0, requirement))
            information = ct.c_void_p()
            check(self.sec.SecCodeCopySigningInformation(guest, 2, ct.byref(information)))
            hold(information.value)
            def field(name):
                return self.cf.CFDictionaryGetValue(information, self._constant(name))
            unique = field("kSecCodeInfoUnique")
            if not unique: raise OSError("code hash unavailable")
            length = self.cf.CFDataGetLength(unique)
            if length not in (20, 32): raise OSError("unsupported code hash")
            cdhash = ct.string_at(self.cf.CFDataGetBytePtr(unique), length).hex()
            executable = field("kSecCodeInfoMainExecutable")
            if not executable: raise OSError("signed executable unavailable")
            path = hold(self.cf.CFURLCopyFileSystemPath(executable, 0))
            return CodeIdentity(self._text(field("kSecCodeInfoIdentifier")),
                                self._text(field("kSecCodeInfoTeamIdentifier")), cdhash, self._text(path))
        finally:
            for value in reversed(owned): self.cf.CFRelease(value)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["probe"])
    parser.parse_args()
    print(json.dumps(asdict(probe_runtime_origin()), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
