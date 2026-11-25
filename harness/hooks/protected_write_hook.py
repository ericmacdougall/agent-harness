#!/usr/bin/env python3
"""PreToolUse hook for Write, Edit, MultiEdit and NotebookEdit: refuse a write to a protected instruction or
configuration file (goodqa#17155). The list lives in protected_paths.py. Reads are never touched.

Exit 2 with the reason on stderr refuses the call. An internal error or unreadable input allows the call with a note
on stderr: this hook covers file-edit tools only and must never become a lockout (goodqa#17145). Bash writes are the
command guard's job."""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

EDIT_TOOLS = {"write", "edit", "multiedit", "notebookedit"}
PATH_KEYS = ("file_path", "notebook_path", "path")


def target_paths(payload):
    tool = str(payload.get("tool_name") or payload.get("toolName") or "").casefold()
    if tool not in EDIT_TOOLS:
        return []
    tool_input = payload.get("tool_input") or payload.get("toolInput") or {}
    if not isinstance(tool_input, dict):
        return []
    return [tool_input[k] for k in PATH_KEYS if isinstance(tool_input.get(k), str)]


def main():
    try:
        payload = json.loads(sys.stdin.read())
        if not isinstance(payload, dict):
            raise ValueError("payload is not an object")
        import protected_paths
        cwd = payload.get("cwd") if isinstance(payload.get("cwd"), str) else None
        for path in target_paths(payload):
            reason = protected_paths.protected_write_refusal(path, cwd=cwd)
            if reason:
                print("protected_write BLOCKED: " + reason, file=sys.stderr)
                return 2
    except Exception as exc:  # noqa: BLE001 - fail open on our own errors, never lock out the file tools
        print("protected_write: internal error (%s); allowed" % exc.__class__.__name__, file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
