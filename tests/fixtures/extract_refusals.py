#!/usr/bin/env python3
"""Counts-and-shapes extraction of commit-policy refusals from Claude transcripts (read-only; no message text kept).

For every tool_result that contains "Commit blocked by the Agent Harness commit policy" it records the policy's
problem lines and, when the triggering tool_use command can be found, a MASKED SHAPE of the message that was refused:
subject type/scope presence and length, which sections were present, the form of the Testing and Refs lines.
Output: refusals.jsonl (one shape per refusal) and summary.json (problem categories with counts).
"""
import json
import os
import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path.home() / ".claude" / "projects"
OUT = Path(__file__).resolve().parent
MARK = "Commit blocked by the Agent Harness commit policy"
SUBJECT = re.compile(r"^(?P<type>[a-z]+)(?:\((?P<scope>[^)]*)\))?(?P<bang>!)?: (?P<summary>.+)$")


def category(problem: str) -> str:
    p = re.sub(r"\d+", "N", problem)
    p = re.sub(r"'[^']*'", "'X'", p)
    p = re.sub(r"`[^`]*`", "`X`", p)
    return p[:140]


def extract_message(command: str):
    """The commit message text from a git commit command (-m pieces, -F - heredoc, $(cat <<EOF)), else None."""
    m = re.search(r"<<-?\s*'?\"?(\w+)'?\"?\n(.*?)\n\s*\1\b", command, re.S)
    if m:
        return m.group(2)
    pieces = re.findall(r"""-m\s+(?:'([^']*)'|"([^"]*)")""", command)
    if pieces:
        return "\n\n".join(a or b for a, b in pieces)
    return None


def shape(message: str) -> dict:
    lines = message.split("\n")
    subject = lines[0] if lines else ""
    sm = SUBJECT.match(subject)
    body = "\n".join(lines[1:])
    sections = {}
    for name in ("Why", "What", "Testing", "Refs", "Risk"):
        m = re.search(rf"(?m)^{name}:[ \t]*(.*)$", body)
        sections[name] = (len(m.group(1)) if m else None)
    testing = re.search(r"(?m)^Testing:[ \t]*(.*)$", body)
    refs = re.search(r"(?m)^Refs:[ \t]*(.*)$", body)
    return {
        "subject_len": len(subject), "type": sm.group("type") if sm else None,
        "has_scope": bool(sm and sm.group("scope")), "subject_parses": bool(sm),
        "sections": sections,
        "testing_has_backticks": bool(testing and "`" in testing.group(1)),
        "testing_not_run": bool(testing and testing.group(1).lower().startswith("not run")),
        "refs_form": (re.sub(r"\d+", "N", re.sub(r"[A-Za-z_-]+#", "P#", refs.group(1)))[:40] if refs else None),
        "has_trailer": bool(re.search(r"(?m)^Co-Authored-By:", body)),
        "blank_after_subject": len(lines) > 1 and lines[1] == "",
        "body_chars": len(body),
    }


def main():
    uses = {}
    found, problems = [], Counter()
    files = [p for p in ROOT.rglob("*.jsonl")]
    for path in files:
        try:
            with open(path, "rb") as fh:
                for raw in fh:
                    if b"tool_use" not in raw and MARK.encode() not in raw:
                        continue
                    try:
                        rec = json.loads(raw)
                    except ValueError:
                        continue
                    content = (rec.get("message") or {}).get("content")
                    if not isinstance(content, list):
                        continue
                    for block in content:
                        if not isinstance(block, dict):
                            continue
                        if block.get("type") == "tool_use" and isinstance(block.get("input"), dict):
                            cmd = block["input"].get("command")
                            if isinstance(cmd, str) and "commit" in cmd:
                                uses[block.get("id")] = cmd
                        if block.get("type") == "tool_result":
                            text = block.get("content")
                            if isinstance(text, list):
                                text = " ".join(x.get("text", "") for x in text if isinstance(x, dict))
                            if isinstance(text, str) and MARK in text:
                                found.append((block.get("tool_use_id"), text))
        except OSError:
            continue
    out = open(OUT / "refusals.jsonl", "w")
    n_shape = 0
    for tool_id, text in found:
        plist = re.findall(r"(?m)^\s+- (.+)$", text.split("Problems:", 1)[-1].split("Write the message", 1)[0])
        cats = [category(x) for x in plist]
        for c in cats:
            problems[c] += 1
        cmd = uses.get(tool_id)
        msg = extract_message(cmd) if cmd else None
        rec = {"problems": cats, "shape": shape(msg) if msg else None}
        n_shape += bool(msg)
        out.write(json.dumps(rec) + "\n")
    out.close()
    summary = {"transcripts": len(files), "refusals": len(found), "with_message_shape": n_shape,
               "problem_categories": problems.most_common(40)}
    (OUT / "summary.json").write_text(json.dumps(summary, indent=1))
    print(json.dumps({k: summary[k] for k in ("transcripts", "refusals", "with_message_shape")}))
    for c, n in problems.most_common(25):
        print(f"{n:5d}  {c}")


if __name__ == "__main__":
    main()
