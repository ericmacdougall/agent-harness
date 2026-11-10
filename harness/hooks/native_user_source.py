"""List weak native user-message candidates; there is no strong provider here.

Imported app snapshots, files and injected providers cannot authenticate human
origin or event time. These citations are discovery evidence, never stop approval.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from typing import Protocol

from native_context import MAX_INPUT, decode_candidate_json
from redact import find, redact
from safe_input import InputRejected, read_stdin_bounded

LABEL = re.compile(r"[A-Za-z0-9_.:-]{1,160}\Z")
MAX_TURNS = 200
MAX_ITEMS = 1000
MAX_TEXT = 16384


class CandidateProvider(Protocol):
    """An untrusted discovery source, including in-process test fixtures."""
    def snapshot(self) -> dict: ...


def _label(value):
    if not isinstance(value, str) or not LABEL.fullmatch(value) or find(value):
        raise ValueError("invalid native identity label")
    return value


def _messages(snapshot):
    if not isinstance(snapshot, dict) or not isinstance(snapshot.get("thread"), dict):
        raise ValueError("native snapshot requires thread metadata")
    thread = snapshot["thread"]
    host, thread_id = _label(thread.get("hostId")), _label(thread.get("id"))
    turns = snapshot.get("turns")
    if not isinstance(turns, list) or len(turns) > MAX_TURNS:
        raise ValueError("invalid native turns")
    seen_turns, seen_items, result = set(), set(), []
    count = 0
    for turn in turns:
        if not isinstance(turn, dict):
            raise ValueError("invalid native turn")
        turn_id = _label(turn.get("id"))
        if turn_id in seen_turns:
            raise ValueError("duplicate native turn")
        seen_turns.add(turn_id)
        items = turn.get("items")
        if not isinstance(items, list):
            raise ValueError("invalid native items")
        count += len(items)
        if count > MAX_ITEMS:
            raise ValueError("too many native items")
        for item in items:
            if not isinstance(item, dict):
                raise ValueError("invalid native item")
            item_id = _label(item.get("id"))
            if item_id in seen_items:
                raise ValueError("duplicate native item")
            seen_items.add(item_id)
            if item.get("type") != "userMessage":
                continue
            # An explicit non-human source is not even a human candidate. A
            # claimed human source is still weak: this JSON is not authenticated.
            if item.get("origin") not in (None, "human"):
                continue
            content = item.get("content")
            if not isinstance(content, list) or len(content) > 64:
                raise ValueError("invalid native user content")
            parts = []
            for part in content:
                if not isinstance(part, dict):
                    raise ValueError("invalid native content part")
                if part.get("type") == "text":
                    text = part.get("text")
                    if not isinstance(text, str) or len(text) > MAX_TEXT:
                        raise ValueError("invalid native text")
                    parts.append(text)
            text = "\n".join(parts)
            if len(text) > MAX_TEXT:
                raise ValueError("native text too large")
            if text:
                result.append((host, thread_id, turn_id, item_id, text))
    return result


def _candidate(message, excerpt=None):
    host, thread, turn, item, text = message
    return {"citation": f"codex:{host}/{thread}/{turn}/{item}",
            "platform": "codex", "host": host, "thread": thread,
            "turn": turn, "item": item, "excerpt": redact(text[:256] if excerpt is None else excerpt),
            "evidence_class": "untrusted_candidate", "weak": True,
            "event_time": None, "human_origin": "unverified",
            "main_authority": False, "strong_user_source": False,
            "missing_proof": ["authenticated_app_provider", "human_origin", "event_time"]}


def list_candidates(snapshot):
    """No supplied fields, claimed origin or provider can upgrade these results."""
    return [_candidate(message) for message in _messages(snapshot)]


def list_from_provider(provider: CandidateProvider):
    return list_candidates(provider.snapshot())


def resolve_candidate(snapshot, citation, excerpt):
    """Exact native identity and literal excerpt match, still weak evidence."""
    if not isinstance(excerpt, str) or not excerpt or len(excerpt) > 256:
        raise ValueError("invalid native excerpt")
    for message in _messages(snapshot):
        candidate = _candidate(message)
        if candidate["citation"] == citation and excerpt in message[-1]:
            return _candidate(message, excerpt)
    raise ValueError("native candidate does not match")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["list"])
    parser.parse_args()
    try:
        snapshot = decode_candidate_json(read_stdin_bounded(MAX_INPUT))
        print(json.dumps(list_candidates(snapshot), sort_keys=True))
    except (InputRejected, ValueError, TypeError):
        print("native candidate input rejected", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
