#!/usr/bin/env python3
"""ahc_packet: the coordinator's deterministic packet fixer (GoodQA goodqa#16034 AC-4, NEG-4).

peer_review.py signs a packet byte for byte and `review_diagnostics.lint_packet` refuses a pr/code-inspection packet
unless one command line has its exit status and a positive count inside the command's own fenced block. Owners often
write the right evidence in the wrong layout: the command above a label, the output in a fence, the
`Result: ... exit 0` line after the fence. This module repairs only that layout.

Invariant (evidence conservation): the fixer may MOVE fence lines and rewrite a wholly backticked command line as a
`$ ` line. It never adds, drops, edits or reorders an evidence line, and it never writes an exit status, a count or a
SHA. A packet whose evidence is genuinely missing (no exit status, no count, no full head SHA) stays unfixable and goes
back to the owner with the lint text. `conserved()` checks every rewrite, including any later LLM reformat.

The one non-move action is removing Python `ResourceWarning` noise lines inside fenced output, and only when the
layout fix alone still fails lint because the noise pushes the evidence out of the lint window. Every removal is
disclosed by a fixed-template note line in the packet header that states the count and the original packet's
SHA-256; `conserved()` verifies that the removed lines are exactly such noise and that the note is truthful.

Stdlib only. The owner's packet file is never modified; callers write the result to a daemon-owned path.
"""

from __future__ import annotations

import collections
import hashlib
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import review_diagnostics  # noqa: E402

_FENCE = review_diagnostics._FENCE
_EXIT = review_diagnostics._EXIT
_COMMAND = review_diagnostics._COMMAND
_HEAD_PROBLEM = 'The packet must contain the full expected HEAD'
_PROBE_HEAD = '0' * 40

_BACKTICK_CMD = re.compile(r'^\s*`([^`\n]{2,})`\s*$')
_DOLLAR_CMD = re.compile(r'^\s*(?:> ?)?\$ (.+)$')
_HEADING = re.compile(r'^#{1,6} \S')
# Python's warnings.formatwarning line "<file>:<line>: ResourceWarning: <msg>" and the interpreter's "ResourceWarning: Enable tracemalloc ..." hint.
_RW_LOCATED = re.compile(r'^\s*\S[^\n]*:\d+: ResourceWarning: ')
_RW_HINT = re.compile(r'^\s*ResourceWarning: Enable tracemalloc to get the object allocation traceback\s*$')
NOTE_RE = re.compile(r'^> ahc-fixer: removed (\d+) Python ResourceWarning noise line\(s\) from fenced output; '
                     r'original packet sha256 ([0-9a-f]{64}) at ([A-Za-z0-9_./~+-]{1,512}|\(unnamed\))$')
NOTE_TEMPLATE = ('> ahc-fixer: removed {n} Python ResourceWarning noise line(s) from fenced output; '
                 'original packet sha256 {sha} at {path}')
# The note sits outside every fence, so a path with a backtick or a "$ " could look like a command to lint.
_SAFE_PATH = re.compile(r'^[A-Za-z0-9_./~+-]{1,512}$')


def _note_path(path):
    text = str(path) if path else ''
    return text if _SAFE_PATH.match(text) else '(unnamed)'


LOOKBEHIND = 4   # non-blank lines searched above a fence for its command


def sha256_text(text):
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


def _canon(line):
    """Comparison form of an evidence line: markup that only says 'this is a command' is ignored."""
    text = line.strip()
    match = _DOLLAR_CMD.match(text)
    if match:
        text = match.group(1).strip()
    match = _BACKTICK_CMD.match(text)
    if match:
        text = match.group(1).strip()
    return text


def _normalize(line):
    """Comparison form of one line, or None for a blank or fence line (which conservation ignores)."""
    if not line.strip() or _FENCE.match(line):
        return None
    return _canon(line)


def _content_lines(text):
    return [line for line in text.split('\n') if line.strip() and not _FENCE.match(line)]


def _fence_states(lines):
    """Fence character open before each line (None outside a fence), plus the list of closed blocks."""
    fence, start, before, blocks = None, None, [], []
    for index, line in enumerate(lines):
        before.append(fence)
        marker = _FENCE.match(line)
        if not marker:
            continue
        char = marker.group(0).strip()[0]
        if fence is None:
            fence, start = char, index
        elif fence == char:
            blocks.append((start, index))
            fence = None
    return before, blocks


def _noise_indexes(lines):
    """Indexes of ResourceWarning noise lines inside fenced blocks. Only lines that name ResourceWarning qualify:
    the indented source line Python prints after a warning is kept, because it cannot be told apart from output."""
    before, _ = _fence_states(lines)
    return [index for index, line in enumerate(lines)
            if before[index] is not None and not _FENCE.match(line)
            and (_RW_LOCATED.match(line) or _RW_HINT.match(line))]


def noise_lines(text):
    lines = text.split('\n')
    return [lines[i] for i in _noise_indexes(lines)]


def conserved(before, after):
    """True when `after` holds exactly the evidence lines of `before`, in the same order.

    Blank lines and fence lines are ignored, and a command's `$ ` or backtick markup is ignored. Anything else that
    differs (a changed count, exit status, SHA or command; an added, dropped or reordered line) is a violation. The
    only permitted removal is disclosed ResourceWarning noise, checked against a truthful header note.
    """
    after_lines = _content_lines(after)
    notes = [line for line in after_lines if NOTE_RE.match(line.strip())]
    if len(notes) > 1:
        return False
    expected = [_canon(line) for line in _content_lines(before)]
    got = [_canon(line) for line in after_lines if not NOTE_RE.match(line.strip())]
    if not notes:
        return got == expected
    match = NOTE_RE.match(notes[0].strip())
    count, sha = int(match.group(1)), match.group(2)
    if sha != sha256_text(before) or count <= 0:
        return False
    before_lines = before.split('\n')
    noise = set(_noise_indexes(before_lines))
    if len(noise) != count:
        return False
    kept = [_canon(line) for index, line in enumerate(before_lines)
            if index not in noise and line.strip() and not _FENCE.match(line)]
    return got == kept


def evidence_problems(text):
    """lint_packet's evidence problems, ignoring the head check (which the fixer can never repair)."""
    problems = review_diagnostics.lint_packet('pr', text, _PROBE_HEAD)
    return [problem for problem in problems if not problem.startswith(_HEAD_PROBLEM)]


def _command_text(line):
    match = _BACKTICK_CMD.match(line) or _DOLLAR_CMD.match(line)
    return match.group(1).strip() if match else None


def _block_has_command(lines, start, end):
    return any(_COMMAND.search(line) for line in lines[start + 1:end] if not _FENCE.match(line))


def _find_command(lines, before, start):
    seen = 0
    for index in range(start - 1, -1, -1):
        line = lines[index]
        if before[index] is not None or _FENCE.match(line):
            return None
        if not line.strip():
            continue
        if _HEADING.match(line) or _EXIT.search(line):
            return None
        if _command_text(line):
            return index
        seen += 1
        if seen >= LOOKBEHIND:
            return None
    return None


def _find_result(lines, end):
    """The result line must be the first non-blank line after the fence, so prose further down (an earlier run's
    "exit 0", say) is never associated with this command."""
    for index in range(end + 1, len(lines)):
        line = lines[index]
        if not line.strip():
            continue
        if _FENCE.match(line) or _HEADING.match(line) or _COMMAND.search(line) or not _EXIT.search(line):
            return None
        return index
    return None


def _move_once(lines):
    """Apply the first available fence move; None when no block qualifies."""
    before, blocks = _fence_states(lines)
    for start, end in blocks:
        if _block_has_command(lines, start, end):
            continue
        command = _find_command(lines, before, start)
        if command is None:
            continue
        result = _find_result(lines, end)
        if result is None:
            continue
        opener, closer = lines[start], lines[end]
        indent = re.match(r'^\s*', lines[command]).group(0)
        return (lines[:command] + [opener, indent + '$ ' + _command_text(lines[command])]
                + lines[command + 1:start] + lines[start + 1:end]
                + lines[end + 1:result + 1] + [closer] + lines[result + 1:])
    return None


def _insert_note(lines, note):
    if lines and _HEADING.match(lines[0]):
        return [lines[0], note] + lines[1:]
    return [note] + lines


def fix_packet(text, expected_head=None, source_path=None):
    """Repair the packet layout. Returns a dict:

    status   'clean' (already passes), 'fixed' (repaired, conserved, passes) or 'unfixable'
    text     the packet to sign (None when unfixable)
    actions  human-readable list of what moved
    problems the remaining lint problems when unfixable (with the real head when given)
    """
    def real_problems(candidate):
        if expected_head:
            return review_diagnostics.lint_packet('pr', candidate, expected_head)
        return evidence_problems(candidate)

    if not evidence_problems(text):
        problems = real_problems(text)
        if problems:
            return {'status': 'unfixable', 'text': None, 'actions': [], 'problems': problems}
        return {'status': 'clean', 'text': text, 'actions': [], 'problems': []}

    lines, actions = text.split('\n'), []
    for _ in range(64):  # each move consumes one fenced block; bounded regardless
        moved = _move_once(lines)
        if moved is None:
            break
        lines = moved
        actions.append('moved a command line and its result line into the output fence')
    candidate = '\n'.join(lines)
    if evidence_problems(candidate):
        noise = _noise_indexes(text.split('\n'))
        if noise:
            stripped_lines = [line for index, line in enumerate(text.split('\n')) if index not in set(noise)]
            lines, moves = stripped_lines, 0
            for _ in range(64):
                moved = _move_once(lines)
                if moved is None:
                    break
                lines, moves = moved, moves + 1
            note = NOTE_TEMPLATE.format(n=len(noise), sha=sha256_text(text), path=_note_path(source_path))
            candidate = '\n'.join(_insert_note(lines, note))
            actions = ['moved a command line and its result line into the output fence'] * moves
            actions.append('removed %d ResourceWarning noise line(s), disclosed in the header' % len(noise))
    if not conserved(text, candidate):
        return {'status': 'unfixable', 'text': None, 'actions': actions,
                'problems': ['internal: the layout fix failed the conservation check; nothing was changed']}
    problems = real_problems(candidate)
    if problems or not actions:
        return {'status': 'unfixable', 'text': None, 'actions': actions, 'problems': problems or real_problems(text)}
    return {'status': 'fixed', 'text': candidate, 'actions': actions, 'problems': []}


def fix_layout(text):
    """The repaired packet text, the same text when it already passes, or None when it cannot be fixed."""
    result = fix_packet(text)
    return result['text']


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(description='Check or repair a review packet layout (never edits the input).')
    parser.add_argument('packet')
    parser.add_argument('--expected-head', required=True)
    parser.add_argument('--output', help='write the repaired packet here (must not be the input)')
    args = parser.parse_args(argv)
    source = Path(args.packet)
    import ahc_core
    try:
        text = ahc_core.read_regular(source, ahc_core.PACKET_MAX_BYTES).decode('utf-8')
    except (ahc_core.Unreadable, UnicodeDecodeError) as error:
        print('status: unreadable (%s)' % error)
        return 2
    result = fix_packet(text, args.expected_head, source_path=str(source.resolve()))
    print('status: %s' % result['status'])
    for action in result['actions']:
        print('action: %s' % action)
    for problem in result['problems']:
        print('problem: %s' % problem)
    if result['text'] is not None and args.output:
        out = Path(args.output)
        if out.resolve() == source.resolve():
            print('refused: --output must differ from the input packet', file=sys.stderr)
            return 2
        out.write_text(result['text'], encoding='utf-8')
    return 0 if result['status'] in ('clean', 'fixed') else 1


if __name__ == '__main__':
    sys.exit(main())
