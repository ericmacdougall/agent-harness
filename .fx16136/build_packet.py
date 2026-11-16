"""Assemble a PR packet from head, a diff and tail, then lint it. Usage: build_packet.py HEAD_MD DIFF TAIL_MD OUT HEADSHA"""
import hashlib
import sys

sys.path.insert(0, '/Users/eric/.claude/hooks')
import review_diagnostics as r  # noqa: E402

head, diff, tail, out, sha = sys.argv[1:6]
text = open(head).read() + '```diff\n' + open(diff).read() + '```\n' + open(tail).read()
open(out, 'w').write(text)
print(r.lint_packet('pr', text, sha))
print('sha256', hashlib.sha256(text.encode()).hexdigest(), 'bytes', len(text.encode()))
