#!/usr/bin/env python3
"""STUB: the old harness behavior (no merge gate). Every merge is allowed. Replaced by the real gate in the next commit;
it exists so the failing-first run fails on assertions instead of ImportError."""

import sys

CALL_TIMEOUT_MAX = 10
DEADLINE_SECONDS = 40
MAX_COMMAND_CHARS = 200000
MAX_STDIN_BYTES = 8 * 1024 * 1024
WAIVER_FILE = "merge-gate-waivers.jsonl"
AUDIT_FILE = "merge-gate-audit.jsonl"


def find_merges(command, cwd=None):
    return []


def decide(payload, runner, state_dir, now=None):
    return 0, ""


def evaluate_merge(*args, **kwargs):
    return 0, ""


def add_waiver(state_dir, repo, pr, head, ticket, reason, approved_by, source="asserted"):
    return {"id": "stub"}


def consume_waiver(state_dir, repo, pr, head, command_hash):
    return None


def report_text(state_dir):
    return ""


def main(argv=None, runner=None, stdin=None, stdout=None, stderr=None):
    return 0


if __name__ == "__main__":
    sys.exit(main())
