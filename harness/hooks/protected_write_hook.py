#!/usr/bin/env python3
"""PreToolUse hook for Write, Edit, MultiEdit and NotebookEdit: refuses a call that would change a protected
instruction, settings, hook, transcript or WAL file (goodqa#17155). The list and the check are in protected_paths.py.

Covers the four file-edit tools only; shell writes are not covered yet (PR B).

Run by the launcher in hooks_manifest.json as `/usr/bin/python3 -I -S SCRIPT hook`. Exit 0 allows, exit 2 refuses with
the reason on descriptor 2. An agent chooses the input, so no input buys an allow: the deadline timer starts first, and
everything after it (the standard imports, the load, reading stdin, the check) runs inside one handler for
BaseException that ends in 2. Only a missing, unreadable, unparsable or unimportable protected_paths.py or
safe_input.py gives a note and 0, so a half-copied install never locks the file tools out. The standard modules are
imported before those two, so a failure of the interpreter's own files is not taken for a broken module.
"""

DEADLINE = 5.0
MODULES = ("safe_input", "protected_paths")
STANDARD = ("errno", "json", "os", "posixpath", "pwd", "re", "stat", "sys", "time", "types", "unicodedata")
MAX_STDIN = 64 * 1024 * 1024
MAX_SOURCE = 4 * 1024 * 1024
MAX_TEXT = 400


class Broken(Exception):
    """One of the two modules is missing, unreadable, does not parse or cannot be imported."""


def text_line(text):
    return ("protected_write: " + text).encode("ascii", "backslashreplace")[:MAX_TEXT - 1] + b"\n"


def say(text):
    """One ASCII line on descriptor 2. A failure to write changes nothing."""
    try:
        import posix
        posix.write(2, text_line(text))
    except BaseException:  # noqa: BLE001 - the verdict must not depend on stderr
        pass


def leave(code, text=""):
    if text:
        say(text)
    import posix
    posix._exit(code)


def start_timer(seconds):
    import _signal

    def late(_number, _frame):
        leave(2, "the call could not be checked in time, so it is refused.")

    _signal.signal(_signal.SIGALRM, late)
    _signal.setitimer(_signal.ITIMER_REAL, seconds)


def load_module(name, folder):
    """The module from its file beside this script, without sys.path and without cached bytecode."""
    import os
    import types
    path = os.path.join(folder, name + ".py")
    try:
        fd = os.open(path, os.O_RDONLY)
    except FileNotFoundError:
        raise Broken(name + ".py is missing") from None
    except PermissionError as error:
        import errno
        if error.errno != errno.EACCES:
            raise
        raise Broken(name + ".py is unreadable") from None
    try:
        data = b""
        while len(data) <= MAX_SOURCE:
            chunk = os.read(fd, 1 << 20)
            if not chunk:
                break
            data += chunk
    finally:
        os.close(fd)
    if len(data) > MAX_SOURCE:
        raise ValueError("module too large")
    try:
        code = compile(data, path, "exec", 0, True)
    except SyntaxError:
        raise Broken(name + ".py does not parse") from None
    module = types.ModuleType(name)
    module.__file__ = path
    try:
        exec(code, module.__dict__)  # noqa: S102 - this is the module loader
    except ImportError:
        raise Broken(name + ".py cannot be imported") from None
    return module


def check(safe_input, protected_paths):
    """(code, text) for the payload on stdin."""
    try:
        raw = safe_input.read_stdin_bounded(MAX_STDIN)
        payload = safe_input.safe_json_loads(raw.decode("utf-8"), max_bytes=MAX_STDIN)
    except (ValueError, safe_input.InputRejected):
        return 2, "the call could not be read, so it is refused."
    try:
        return protected_paths.judge_payload(payload, safe_input.safe_json_loads)
    except protected_paths.Unjudgeable as error:
        return 2, "%s, so this write is refused." % error


def main(script, judge=check, deadline=DEADLINE):
    code, text = 2, "the call could not be checked, so it is refused."
    try:
        start_timer(deadline)
        for name in STANDARD:
            __import__(name)
        import os
        folder = os.path.dirname(os.path.abspath(script))
        try:
            modules = [load_module(name, folder) for name in MODULES]
        except Broken as error:
            code, text = 0, "note: %s; nothing was checked and the call is allowed." % error
        else:
            code, text = judge(*modules)
    except BaseException as error:  # noqa: BLE001 - an error must never be an allow
        code, text = 2, "the call could not be checked (%s), so it is refused." % error.__class__.__name__
    leave(code, text)


if __name__ == "__main__":
    main(__file__)
