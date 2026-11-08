#!/usr/bin/env python3
"""Static side-effect scan for third-party installers (goodqa#15253, rule R9).

    python3 installer_scan.py <dir-or-file> [--json]

Reads shell and Python installer files (*.sh, *.py, install*, setup*, Makefile) as text, never executes or imports
them, and reports side effects by category with file:line. Exit 0 = at least one file scanned, no findings and
nothing left unscanned; 1 = findings, a skipped or unscanned executable-looking file, no file scanned, or the file
limit reached; 2 = bad usage. A brief can gate on the exit code before a vendor installer is ever run. The scan is
regex matching on source text, so the rule is scan, then read: exit 0 is not a safety proof.
"""

import json
import os
from pathlib import Path
import re
import sys

MAX_BYTES = 2 * 1024 * 1024
MAX_FILES = 5000
SKIP_DIRS = {'.git', 'node_modules', '__pycache__', '.venv', 'venv'}
# Review F5: files that can run code but that this scan does not parse. They are listed, never silently ignored.
UNSCANNED_SUFFIXES = ('.js', '.mjs', '.cjs', '.ts', '.plist', '.ps1', '.psm1', '.bat', '.cmd', '.rb', '.pl', '.php',
                      '.command', '.applescript', '.scpt')
UNSCANNED_NAMES = ('package.json', 'gemfile', 'rakefile', 'cmakelists.txt', 'build.gradle', 'cargo.toml',
                   'pyproject.toml', 'setup.cfg')
READ_RULE = 'scan, then read: a clean scan is regex matching on source text, not a safety proof'

try:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import safe_input
except Exception:  # standalone copy: fall back to a plain bounded read
    safe_input = None

_WRITE_RE = re.compile(r'(?:\bcp\b|\bmv\b|\binstall\b|\btee\b|>|\bln\b|\bmkdir\b|\bchmod\b|\bchown\b|\brm\b|write|copy|\bsed\s+-i)')
_OUTSIDE = 'path outside the target dir'

# category -> (pattern, label) rules. Order is the report order.
RULES = [
    ('mcp', [
        (r'\b(?:claude|codex)\b.{0,40}\bmcp\b.{0,20}\badd\b', 'agent CLI MCP registration'),
        (r'''["']mcp["']\s*,\s*["']add["']''', 'agent CLI MCP registration (argv list)'),
        (r'\[mcp_servers\.', 'MCP server in agent TOML config'),
        (r'mcpServers', 'MCP server in JSON config'),
    ]),
    ('agent-rules', [
        (r'CLAUDE\.md|AGENTS\.md', 'agent rule file'),
        (r'settings(?:\.local)?\.json', 'agent settings file'),
        (r'config\.toml', 'agent config.toml'),
        (r'''["']permissions["']''', 'agent permission grants'),
    ]),
    ('launchd', [
        (r'\blaunchctl\b|LaunchAgents|LaunchDaemons', 'launch agent/daemon'),
        (r'\bsystemctl\b', 'systemd unit'),
        (r'\bcrontab\b|/etc/cron', 'cron entry'),
        (r'\bschtasks\b', 'scheduled task'),
    ]),
    ('shell-rc', [
        # `.profile` only as a file name (after / ~ quote space or =), never an attribute such as args.profile
        (r'''\.zshrc|\.zprofile|\.bashrc|\.bash_profile|(?:^|[\s/~"'=])\.profile\b''', 'shell startup file'),
        (r'''(?:^|[\s;"'])(?:export\s+)?PATH=''', 'PATH assignment'),
    ]),
    ('network-exec', [
        (r'\b(?:curl|wget)\b[^|\n]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b', 'download piped to a shell'),
        (r'\bwget\b', 'network download'),
        (r'\bpip3?\s+install\b|-m\s+pip\s+install\b', 'pip install'),
        (r'\bnpm\s+(?:install|i)\s+(?:-g|--global)\b', 'global npm install'),
        (r'\bbrew\s+install\b', 'brew install'),
    ]),
    ('credentials', [
        (r'security\s+add-generic-password|add-internet-password|SecItemAdd|SecItemUpdate', 'keychain write'),
        (r'\bkeyring\b', 'keyring access'),
        (r'~/\.ssh|\.ssh/|~/\.aws|\.aws/|\.kimi-code', 'credential directory'),
    ]),
    ('privileged', [
        (r'\bsudo\b', 'sudo'),
        (r'chmod\s+(?:[ugoa]*\+[rwx]*s|[2-7]7[0-7]{2}\b)', 'setuid/setgid bit'),
        (r'/usr/(?:local|lib|share|sbin)|/etc/|/Library/', _OUTSIDE),
    ]),
]
_COMPILED = [(cat, [(re.compile(p), label) for p, label in rules]) for cat, rules in RULES]


def wanted(name: str) -> bool:
    low = name.lower()
    return low.endswith(('.sh', '.py')) or low.startswith(('install', 'setup')) or low == 'makefile'


def unscanned_kind(path: Path):
    """Why an executable-looking file is not scanned, or None for a plain data file."""
    low = path.name.lower()
    if low.endswith(UNSCANNED_SUFFIXES) or low in UNSCANNED_NAMES:
        return 'not scanned: %s can run code (read it)' % (path.suffix or path.name)
    try:
        if path.is_file() and not path.is_symlink():
            if os.access(path, os.X_OK):
                return 'not scanned: executable file (read it)'
            with open(path, 'rb') as handle:
                if handle.read(2) == b'#!':
                    return 'not scanned: script with a #! line (read it)'
    except OSError as error:
        return 'not scanned: unreadable (%s)' % error.__class__.__name__
    return None


def collect(target: Path):
    """(files to scan, unscanned [(path, reason)], truncated). Stops at MAX_FILES and says so (review F5)."""
    if target.is_file():
        return [target], [], False
    out, unscanned, seen = [], [], 0
    for root, dirs, files in os.walk(target, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for name in sorted(files):
            seen += 1
            if seen > MAX_FILES:
                return out, unscanned, True
            path = Path(root) / name
            if wanted(name):
                out.append(path)
            else:
                why = unscanned_kind(path)
                if why:
                    unscanned.append((path, why))
    return out, unscanned, False


def read_text(path: Path) -> str:
    if safe_input is not None:
        data = safe_input.read_bounded(path, MAX_BYTES)
    else:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_BYTES:
            raise ValueError('not a regular file within the size cap')
        data = path.read_bytes()
    return data.decode('utf-8', 'replace')


def scan_text(text: str, shown: str):
    findings = []
    for number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped or (stripped.startswith('#') and not stripped.startswith('#!')):
            continue
        for cat, rules in _COMPILED:
            for rx, label in rules:
                if not rx.search(line):
                    continue
                if label == _OUTSIDE and not _WRITE_RE.search(line):
                    continue
                findings.append({'category': cat, 'file': shown, 'line': number, 'label': label, 'text': stripped[:200]})
                break  # one hit per category per line
    return findings


def scan(target: Path):
    findings, skipped = [], []
    files, unscanned, truncated = collect(target)
    base = target if target.is_dir() else target.parent
    for path, why in unscanned:
        skipped.append({'file': str(path.relative_to(base)), 'reason': why})
    for path in files:
        shown = str(path.relative_to(base))
        try:
            text = read_text(path)
        except Exception as error:
            skipped.append({'file': shown, 'reason': str(error)[:120]})
            continue
        findings.extend(scan_text(text, shown))
    order = {cat: i for i, (cat, _) in enumerate(RULES)}
    findings.sort(key=lambda f: (order[f['category']], f['file'], f['line']))
    read_failures = len(skipped) - len(unscanned)
    skipped.sort(key=lambda x: x['file'])
    return {'target': str(target), 'files_scanned': len(files) - read_failures, 'findings': findings,
            'skipped': skipped, 'truncated': truncated, 'max_files': MAX_FILES, 'rule': READ_RULE}


def exit_code(report) -> int:
    """0 only when something was scanned, nothing was found and nothing was left unscanned (review F5, 50bca42)."""
    if report['findings'] or report['skipped'] or report['truncated'] or report['files_scanned'] == 0:
        return 1
    return 0


def main(argv):
    args = [a for a in argv if a != '--json']
    if len(args) != 1 or not Path(args[0]).exists():
        print('usage: installer_scan.py <dir-or-file> [--json]', file=sys.stderr)
        return 2
    report = scan(Path(args[0]))
    if '--json' in argv:
        print(json.dumps(report, indent=1))
    else:
        for f in report['findings']:
            print(f"{f['category']:<13} {f['file']}:{f['line']:<5} {f['label']}: {f['text']}")
        for s in report['skipped']:
            print(f"skipped       {s['file']}: {s['reason']}")
        if report['truncated']:
            print(f"truncated     stopped after {report['max_files']} files; the rest were not looked at")
        if report['files_scanned'] == 0:
            print("nothing       no installer-shaped file was scanned")
        print(f"{len(report['findings'])} finding(s) in {report['files_scanned']} file(s); {READ_RULE}")
    return exit_code(report)


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
