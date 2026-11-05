#!/usr/bin/env python3
"""Shared secret redaction: one high-recall shape list for WAL notes, scans and (later) every other redactor.

Stdlib only, linear-time patterns with bounded repetition, so hostile input cannot trigger catastrophic
backtracking. `redact(text)` replaces each secret with `[REDACTED:<kind>]`; `find(text)` returns the kinds and
offsets WITHOUT the values, which is what scanners must print.

Recall over precision: a false positive costs a placeholder in a note, a false negative leaks a credential into
a transcript that is never deleted. Shapes cover Dropbox/rclone OAuth blobs, Anthropic, OpenAI, GitHub, AWS,
Google, Slack and npm tokens, JWTs, PEM blocks, Bearer headers, URL userinfo and generic NAME=value credentials.
"""

from __future__ import annotations

import re

MAX_CHUNK = 256 * 1024  # inputs are processed in chunks of this size (with an overlap) to bound regex work
OVERLAP = 4096

_KEYS = (r'(?:[a-z0-9]+[_-])*(?:password|passwd|passphrase|secret|token|api[_-]?key|access[_-]?key|'
         r'private[_-]?key|credentials?|client[_-]?secret|refresh[_-]?token|access[_-]?token|id[_-]?token)'
         r'(?:[_-]value)?')

# (kind, compiled pattern). Order matters: specific shapes first so the kind label is the most useful one.
PATTERNS = [
    ('pem', re.compile(r'-----BEGIN [A-Z0-9 ]{0,40}(?:PRIVATE KEY|ENCRYPTED PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----'
                       r'(?:[\s\S]{0,16384}?-----END [A-Z0-9 ]{0,40}-----|[\s\S]{0,16384})')),
    ('rclone-token', re.compile(r'(?im)^\s*token\s*=\s*\{[^\n]{0,8192}')),
    ('oauth-json', re.compile(r'(?is)\{[^{}]{0,2048}?[\x22\x27](?:access_token|refresh_token|id_token)[\x22\x27]'
                              r'\s*:[^{}]{0,4096}\}')),
    ('anthropic', re.compile(r'\bsk-ant-[A-Za-z0-9_-]{8,}')),
    ('openai', re.compile(r'\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}')),
    ('github', re.compile(r'\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})')),
    # an access key id followed by its 40-character secret (CSV exports, `aws configure` echoes)
    ('aws-key-pair', re.compile(r'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b[\s,:;=\x22\x27]{1,20}[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+=])')),
    ('aws-key', re.compile(r'\b(?:AKIA|ASIA|AGPA|AIDA|AROA)[A-Z0-9]{16}\b')),
    ('aws-secret', re.compile(r'(?i)\baws[_-]?secret[_-]?(?:access[_-]?)?key[\x22\x27]?\s*[:=]\s*[\x22\x27]?'
                              r'[A-Za-z0-9/+]{40}')),
    ('google-oauth', re.compile(r'\bya29\.[A-Za-z0-9_-]{20,}')),
    ('google-api', re.compile(r'\bAIza[A-Za-z0-9_-]{30,}')),
    ('google-refresh', re.compile(r'\b1//[A-Za-z0-9_-]{30,}')),
    ('dropbox', re.compile(r'\bsl\.[A-Za-z0-9_-]{40,}')),
    ('slack', re.compile(r'\bxox[abposr]-[A-Za-z0-9-]{6,}')),
    ('npm', re.compile(r'\bnpm_[A-Za-z0-9]{30,}')),
    ('jwt', re.compile(r'\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{0,512}')),
    ('bearer', re.compile(r'(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}')),
    ('url-userinfo', re.compile(r'(?i)\b[a-z][a-z0-9+.-]*://[^\s/?#@]{1,256}@[^\s/?#]{1,256}')),
    ('named-credential', re.compile(r'(?i)\b' + _KEYS + r'[\x22\x27]?\s*[:=]\s*[\x22\x27]?[^\s\x22\x27,;}]{3,512}')),
    ('named-credential', re.compile(r'\b[a-z][a-z0-9]*(?:Secret|Token|Password|ApiKey|AccessKey|PrivateKey|Credentials?)'
                                    r'[\x22\x27]?\s*[:=]\s*[\x22\x27]?[^\s\x22\x27,;}]{3,512}')),
]


def _chunks(text):
    if len(text) <= MAX_CHUNK:
        yield 0, text
        return
    start = 0
    while start < len(text):
        yield start, text[start:start + MAX_CHUNK + OVERLAP]
        start += MAX_CHUNK


def find(text):
    """[(kind, start, end)] for every secret-shaped span. Values are never returned."""
    hits = []
    seen = set()
    for base, chunk in _chunks(str(text)):
        for kind, pattern in PATTERNS:
            for match in pattern.finditer(chunk):
                if '[REDACTED:' in match.group(0):
                    continue
                span = (base + match.start(), base + match.end())
                if span in seen:
                    continue
                seen.add(span)
                hits.append((kind, span[0], span[1]))
    return sorted(hits, key=lambda hit: (hit[1], hit[2]))


def redact(text):
    """Return text with every secret-shaped span replaced by [REDACTED:<kind>]. Idempotent."""
    text = str(text)
    spans = []
    for kind, start, end in find(text):
        spans.append((start, end, kind))
    if not spans:
        return text
    spans.sort(key=lambda item: (item[0], -(item[1] - item[0])))
    out = []
    cursor = 0
    for start, end, kind in spans:
        if start < cursor:  # overlaps a span already replaced (nested shapes): the outer one wins
            if end > cursor:
                cursor = max(cursor, end)  # swallow the tail so no secret fragment survives
            continue
        out.append(text[cursor:start])
        out.append('[REDACTED:' + kind + ']')
        cursor = end
    out.append(text[cursor:])
    return ''.join(out)


def has_secret(text):
    return bool(find(text))
