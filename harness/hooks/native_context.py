"""Read-only runtime origin evidence. This module never admits a main agent.

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
_CLAUDE_IDENTIFIER = "com.anthropic.claude-code"
_CLAUDE_TEAM = "Q6L2SF6YDW"
_CLAUDE_REQUIREMENT = (f'anchor apple generic and identifier "{_CLAUDE_IDENTIFIER}" '
                       f'and certificate leaf[subject.OU] = "{_CLAUDE_TEAM}"')
NATIVE_MARKERS = ("CODEX_THREAD_ID", "CODEX_TOOL_CALL_ID", "CODEX_SANDBOX")
MAX_INPUT = 1024 * 1024
# Security/CSCommon.h: the running guest is unsigned or does not satisfy this
# pinned requirement. Other verification errors remain ambiguous and fail closed.
NOT_APPROVED_SIGNATURE = {-67062, -67050}  # errSecCSUnsigned, errSecCSReqFailed


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
class KernelGeneration:
    pid: int
    unique_id: int
    parent_unique_id: int
    id_version: int
    original_parent_version: int
    executable_uuid: bytes


@dataclass(frozen=True)
class TerminalBoundary:
    pid: int
    parent: int
    uid: int
    executable: str
    unique_id: int
    parent_unique_id: int
    id_version: int
    original_parent_version: int
    executable_uuid: bytes


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


def _approved_code(code, process):
    return _matches_signed_executable(code, process, "codex", OPENAI_TEAM)


def _matches_signed_executable(code, process, identifier, team):
    return (isinstance(code, CodeIdentity) and code.identifier == identifier and code.team == team
            and isinstance(code.cdhash, str) and bool(re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", code.cdhash))
            and isinstance(code.executable, str)
            and os.path.realpath(code.executable) == os.path.realpath(process.executable))


def _valid_boundary(value, pid):
    return (isinstance(value, TerminalBoundary) and type(value.pid) is int and value.pid == pid
            and 1 < pid < 2 ** 31 and type(value.parent) is int
            and 0 < value.parent < 2 ** 31 and value.parent != pid
            and type(value.uid) is int and value.uid == 0 and value.executable == "/usr/bin/login"
            and all(type(n) is int and 0 < n < 2 ** 64 for n in (value.unique_id, value.parent_unique_id))
            and type(value.id_version) is int and -(2 ** 31) <= value.id_version < 2 ** 31
            and value.id_version != 0 and type(value.original_parent_version) is int
            and -(2 ** 31) <= value.original_parent_version < 2 ** 31
            and type(value.executable_uuid) is bytes
            and len(value.executable_uuid) == 16 and any(value.executable_uuid))


def _chain_change(backend, chain, codes):
    for previous in chain:
        if backend.process(previous.pid) != previous:
            return "process_changed"
    for previous, code in zip(chain, codes):
        if backend.signature(previous.pid) != code:
            return "code_identity_unverified"
    for previous in chain:
        if backend.process(previous.pid) != previous:
            return "process_changed"
    return None


def _valid_generation(value, pid):
    return (isinstance(value, KernelGeneration) and type(value.pid) is int and value.pid == pid
            and 1 <= pid < 2 ** 31 and type(value.unique_id) is int and 0 < value.unique_id < 2 ** 64
            and type(value.parent_unique_id) is int and 0 <= value.parent_unique_id < 2 ** 64
            and (value.parent_unique_id == 0 if pid == 1 else value.parent_unique_id > 0)
            and type(value.id_version) is int and -(2 ** 31) <= value.id_version < 2 ** 31
            and value.id_version != 0 and type(value.original_parent_version) is int
            and -(2 ** 31) <= value.original_parent_version < 2 ** 31
            and type(value.executable_uuid) is bytes and len(value.executable_uuid) == 16
            and any(value.executable_uuid))


def _mixed_chain_change(backend, chain, codes, generations, links, boundaries):
    changed = _chain_change(backend, chain, codes)
    if changed or not generations:
        return changed
    for previous in boundaries:
        current = backend.terminal_login_identity(previous.pid)
        if not _valid_boundary(current, previous.pid) or current != previous:
            return "process_changed"
    for pid, previous in generations.items():
        current = backend.process_generation(pid)
        if not _valid_generation(current, pid) or current != previous:
            return "process_changed"
    for parent, unique_id in links:
        if parent not in generations or generations[parent].unique_id != unique_id:
            return "parent_identity_unverified"
    return _chain_change(backend, chain, codes)


def probe_runtime_origin(pid=None, *, backend=None):
    """Bounded origin-only probe; a supplied backend is an in-process test double."""
    return _probe_origin(pid, backend=backend, commit_attribution=False)


def probe_commit_runtime_origin(pid=None, *, backend=None):
    """Read-only proof for a current commit's author claim."""
    return _probe_origin(pid, backend=backend, commit_attribution=True)


def _probe_origin(pid, *, backend, commit_attribution):
    pid = os.getpid() if pid is None else pid
    native = False
    try:
        if backend is None:
            if sys.platform != "darwin":
                return OriginObservation("unknown", False, "unsupported_platform")
            backend = _CommitDarwinBackend() if commit_attribution else DarwinBackend()
        chain, codes, seen, barrier, candidate = [], [], set(), False, None
        candidate_origin = "openai"
        boundaries, generations, links = [], {}, []
        upper_unique, previous_node, ended_at_init = None, None, False
        current = pid
        for _ in range(32):
            if current <= 1:
                if boundaries:
                    if current != 1:
                        raise OSError("upper ancestry did not reach init")
                    generation = backend.process_generation(1)
                    if not _valid_generation(generation, 1) or generation.unique_id != upper_unique:
                        raise OSError("init parent identity unavailable")
                    generations[1] = generation
                    ended_at_init = True
                break
            if current in seen:
                return OriginObservation("unknown", native, "ancestry_cycle")
            seen.add(current)
            generation = None
            if boundaries:
                generation = backend.process_generation(current)
                if not _valid_generation(generation, current) or generation.unique_id != upper_unique:
                    raise OSError("upper parent identity unavailable")
                generations[current] = generation
            try:
                process = backend.process(current)
            except OSError:
                # Full BSD info is same-user restricted. The smaller kernel APIs
                # can bind a root login to a stable process and executable generation.
                if current == pid or previous_node is None or previous_node.parent != current:
                    raise
                boundary = backend.terminal_login_identity(current)
                if not _valid_boundary(boundary, current):
                    raise OSError("terminal boundary identity unavailable")
                boundary_generation = KernelGeneration(boundary.pid, boundary.unique_id,
                    boundary.parent_unique_id, boundary.id_version,
                    boundary.original_parent_version, boundary.executable_uuid)
                if generation is not None and generation != boundary_generation:
                    raise OSError("login generation changed")
                generations[current] = boundary_generation
                boundaries.append(boundary)
                links.append((boundary.parent, boundary.parent_unique_id))
                upper_unique, previous_node, current = boundary.parent_unique_id, boundary, boundary.parent
                continue  # A genuine login does not prove who launched it.
            if not _valid_process(process, current):
                return OriginObservation("unknown", native, "invalid_process_identity")
            chain.append(process)
            name = os.path.basename(process.executable)
            # A basename is only a deny hint. Signed code may be renamed, so
            # query the running guest for every ancestor before classifying it.
            native = native or name == "codex"
            first = backend.signature(current)
            if first is not None and not isinstance(first, CodeIdentity):
                raise OSError("running code observation unavailable")
            codes.append(first)
            if generation is not None:
                repeated = backend.process_generation(current)
                if not _valid_generation(repeated, current) or repeated != generation:
                    raise OSError("upper process generation changed")
            if _approved_code(first, process):
                native = True
                if not barrier:
                    candidate = process
                break
            if commit_attribution and first is not None:
                if not _matches_signed_executable(first, process, _CLAUDE_IDENTIFIER, _CLAUDE_TEAM):
                    return OriginObservation("unknown", native, "code_identity_unverified")
                if barrier:
                    return OriginObservation("unknown", native, "nearer_other_runtime")
                candidate = process
                candidate_origin = "claude"
                break
            if name in {"claude", "kimi"}:
                barrier = True  # an outer Codex process is not this nearer runtime's author
            if name == "codex":
                return OriginObservation("unknown", True, "code_identity_unverified")
            if generation is not None:
                links.append((process.parent, generation.parent_unique_id))
                upper_unique = generation.parent_unique_id
            previous_node = process
            current = process.parent
        else:
            return OriginObservation("unknown", native, "ancestry_limit")
        if boundaries and not native and not ended_at_init and candidate is None:
            raise OSError("upper ancestry incomplete")
        changed = _mixed_chain_change(backend, chain, codes, generations, links, boundaries)
        if changed:
            return OriginObservation("unknown", native, changed)
        if boundaries:
            for _ in range(2):
                changed = _mixed_chain_change(backend, chain, codes, generations, links, boundaries)
                if changed:
                    return OriginObservation("unknown", native, changed)
        if candidate is None:
            return OriginObservation("unknown", native, "nearer_other_runtime" if native else "no_native_runtime")
        if candidate_origin == "claude":
            if not _matches_signed_executable(codes[-1], candidate, _CLAUDE_IDENTIFIER, _CLAUDE_TEAM):
                return OriginObservation("unknown", native, "code_identity_unverified")
            return OriginObservation("claude", False, "running_claude_code_verified", candidate.pid, codes[-1])
        if not _approved_code(codes[-1], candidate):
            return OriginObservation("unknown", True, "code_identity_unverified")
        return OriginObservation("openai", True, "running_code_verified", candidate.pid, codes[-1])
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

    class ShortBSDInfo(ct.Structure):
        _fields_ = [(name, ct.c_uint32) for name in ("pid", "ppid", "pgid", "status")]
        _fields_ += [("comm", ct.c_char * 16)]
        _fields_ += [(name, ct.c_uint32) for name in
                    ("flags", "uid", "gid", "ruid", "rgid", "svuid", "svgid", "reserved")]

    class UniqueInfo(ct.Structure):
        _fields_ = [("uuid", ct.c_ubyte * 16), ("uniqueid", ct.c_uint64),
                    ("parent_uniqueid", ct.c_uint64), ("idversion", ct.c_int32),
                    ("original_parent_version", ct.c_int32), ("reserve2", ct.c_uint64),
                    ("reserve3", ct.c_uint64)]

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

    def terminal_login_identity(self, pid):
        # Apple proc_info.h/proc_info_private.h: flavors 13 and 17. Unlike
        # full BSD info, these do not require the target to have our UID.
        if (type(pid) is not int or not 1 < pid < 2 ** 31
                or ct.sizeof(self.ShortBSDInfo) != 64 or ct.sizeof(self.UniqueInfo) != 56):
            raise OSError("terminal boundary ABI unavailable")
        def unique():
            info = self.UniqueInfo()
            if self.proc.proc_pidinfo(pid, 17, 0, ct.byref(info), 56) != 56:
                raise OSError("kernel process generation unavailable")
            return info
        before = unique()
        info = self.ShortBSDInfo()
        if self.proc.proc_pidinfo(pid, 13, 0, ct.byref(info), 64) != 64:
            raise OSError("kernel short process identity unavailable")
        path = ct.create_string_buffer(4096)
        path_size = self.proc.proc_pidpath(pid, path, len(path))
        if path_size <= 0 or path_size != len(path.value) or path_size >= len(path):
            raise OSError("kernel executable identity unavailable")
        after = unique()
        meaningful = lambda value: (bytes(value.uuid), value.uniqueid, value.parent_uniqueid,
                                    value.idversion, value.original_parent_version)
        if meaningful(before) != meaningful(after):
            raise OSError("kernel process generation changed")
        value = TerminalBoundary(info.pid, info.ppid, info.uid, path.value.decode("utf-8", "strict"),
                                 before.uniqueid, before.parent_uniqueid, before.idversion,
                                 before.original_parent_version, bytes(before.uuid))
        if not _valid_boundary(value, pid):
            raise OSError("terminal boundary identity unavailable")
        return value

    def process_generation(self, pid):
        if type(pid) is not int or not 1 <= pid < 2 ** 31 or ct.sizeof(self.UniqueInfo) != 56:
            raise OSError("kernel generation ABI unavailable")
        info = self.UniqueInfo()
        if self.proc.proc_pidinfo(pid, 17, 0, ct.byref(info), 56) != 56:
            raise OSError("kernel process generation unavailable")
        value = KernelGeneration(pid, info.uniqueid, info.parent_uniqueid, info.idversion,
                                 info.original_parent_version, bytes(info.uuid))
        if not _valid_generation(value, pid):
            raise OSError("kernel generation identity unavailable")
        return value

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
        return self._signature(pid, (CODE_REQUIREMENT,))

    def _signature(self, pid, requirements):
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
            for text in requirements:
                rule = hold(self.cf.CFStringCreateWithCString(None, text.encode(), 0x08000100))
                requirement = ct.c_void_p()
                check(self.sec.SecRequirementCreateWithString(rule, 0, ct.byref(requirement)))
                hold(requirement.value)
                status = self.sec.SecCodeCheckValidity(guest, 0, requirement)
                if status in NOT_APPROVED_SIGNATURE:
                    continue
                check(status)
                break
            else:
                return None
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


class _CommitDarwinBackend(DarwinBackend):
    def signature(self, pid):
        return self._signature(pid, (CODE_REQUIREMENT, _CLAUDE_REQUIREMENT))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["probe"])
    parser.parse_args()
    print(json.dumps(asdict(probe_runtime_origin()), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
