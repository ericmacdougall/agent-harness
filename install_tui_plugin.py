#!/usr/bin/env python3
"""Preview or install the local TUI plugin without changing agent permissions."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import secrets
import selectors
import shlex
import signal
import stat
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from install import DirectoryPins, atomic_write, read_regular, safe_unlink


ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / 'plugins' / 'harness-tui'
HOST_NAME = 'com.agentharness.tui'
EXTENSION_ID = 'gdpiohlkkniinkfhlbhcjoimlcnhnkgj'


def check_binary_contract(binary: Path, *, timeout=5, limit=65536):
    """Read a trusted executable's help with bounded memory, time and children.

    This checks its declared flags, not whether its implementation honors them.
    Actual offline UI testing remains a separate release check.
    """
    process = subprocess.Popen([str(binary), 'tui', '--help'], stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               start_new_session=True)
    reaped = False
    output = bytearray()
    deadline = time.monotonic() + timeout
    try:
        with selectors.DefaultSelector() as poller:
            poller.register(process.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not poller.select(remaining):
                    raise ValueError('TUI reference capability help exceeded its deadline')
                chunk = os.read(process.stdout.fileno(), min(4096, limit + 1 - len(output)))
                if not chunk:
                    break
                output.extend(chunk)
                if len(output) > limit:
                    raise ValueError('TUI reference capability help exceeded its output limit')
        try:
            code = process.wait(timeout=max(0, deadline - time.monotonic()))
            reaped = True
        except subprocess.TimeoutExpired as error:
            raise ValueError('TUI reference capability help exceeded its deadline') from error
    finally:
        if not reaped:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=2)
        process.stdout.close()
    help_text = output.decode('utf-8', errors='replace')
    flags = ('reference-only', 'reference-file', 'reference-sha256')
    if code not in {0, 2} or any(not re.search(r'(?<!\S)--?' + flag + r'(?=\s|$)', help_text)
                               for flag in flags):
        raise ValueError('TUI executable does not declare the required reference flags; update it before installing')


def native_directory(home: Path, browser: str, platform: str) -> Path:
    if platform == 'darwin':
        brand = {'chrome': 'Google/Chrome', 'chromium': 'Chromium', 'edge': 'Microsoft Edge'}[browser]
        return home / 'Library' / 'Application Support' / brand / 'NativeMessagingHosts'
    if platform.startswith('linux'):
        brand = {'chrome': 'google-chrome', 'chromium': 'chromium', 'edge': 'microsoft-edge'}[browser]
        return home / '.config' / brand / 'NativeMessagingHosts'
    raise ValueError('Native host registration supports macOS and Linux only')


def merge_desktop(data: bytes, server: dict) -> bytes:
    value = json.loads(data) if data else {}
    if not isinstance(value, dict):
        raise ValueError('Claude Desktop config must be an object')
    servers = value.setdefault('mcpServers', {})
    if not isinstance(servers, dict):
        raise ValueError('Claude Desktop mcpServers must be an object')
    existing = servers.get('harness-tui')
    if existing is not None and existing != server:
        # Equal args do not prove ownership of command/env/disabled user edits.
        raise ValueError('Claude Desktop already has a different harness-tui server; resolve it explicitly')
    servers['harness-tui'] = server
    return (json.dumps(value, indent=2) + '\n').encode()


def install(home: Path, binary: Path, apply: bool, *, browsers=(), claude_desktop=False):
    if set(browsers) - {'chrome', 'chromium', 'edge'}:
        raise ValueError('Unsupported browser registration target')
    home = home.expanduser().resolve()
    binary = binary.expanduser().resolve(strict=True)
    info = binary.stat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid not in {0, os.getuid()}
            or info.st_mode & 0o022 or not os.access(binary, os.X_OK)):
        raise ValueError('TUI binary must be a trusted executable regular file')
    check_binary_contract(binary)
    base = home / '.agent-harness'
    destination = base / 'tui-plugin' / 'plugin'
    launcher = destination / 'launcher.py'
    server = {'command': sys.executable, 'args': [str(launcher), 'serve']}
    payloads = {}
    paths = sorted(SOURCE.rglob('*'))
    for path in paths:
        if '__pycache__' in path.parts or path.suffix == '.pyc':
            continue
        if path.is_symlink():
            raise ValueError('Plugin source cannot contain symlinks')
        if path.is_file():
            payloads[destination / path.relative_to(SOURCE)] = path.read_bytes()
    if len(payloads) > 128 or sum(map(len, payloads.values())) > 2 * 1024 * 1024:
        raise ValueError('Plugin payload exceeds the installer bounds')
    if not (SOURCE / 'launcher.py').is_file():
        raise ValueError('Plugin source is incomplete')
    manifest = json.loads((SOURCE / 'browser' / 'manifest.json').read_text())
    public = base64.b64decode(manifest['key'], validate=True)
    encoded_id = ''.join(chr(ord('a') + int(c, 16)) for c in hashlib.sha256(public).hexdigest()[:32])
    if encoded_id != EXTENSION_ID:
        raise ValueError('Browser public key does not match the pinned extension ID')
    payloads[destination / '.mcp.json'] = (json.dumps({'mcpServers': {'harness-tui': server}}, indent=2) + '\n').encode()
    payloads[destination / 'mcp.json'] = (json.dumps({
        '$schema': 'https://agent-plugins.org/schemas/1.0.0/mcp.schema.json',
        'mcpServers': {'harness-tui': {'type': 'stdio', **server}}}, indent=2) + '\n').encode()
    config_path = base / 'tui-launcher.json'
    payloads[config_path] = (json.dumps({'schema': 1, 'binary': str(binary)}, indent=2) + '\n').encode()
    entry = base / 'tui-plugin' / 'native-host'
    script = '#!/bin/sh\nexec ' + ' '.join(shlex.quote(x) for x in [
        sys.executable, str(launcher), 'native-host']) + ' "$@"\n'
    payloads[entry] = script.encode()
    host = {'name': HOST_NAME, 'description': 'Agent Harness local reference TUI launcher',
            'path': str(entry), 'type': 'stdio',
            'allowed_origins': [f'chrome-extension://{EXTENSION_ID}/']}
    for browser in sorted(set(browsers)):
        payloads[native_directory(home, browser, sys.platform) / (HOST_NAME + '.json')] = (
            json.dumps(host, indent=2) + '\n').encode()
    desktop_path = None
    if claude_desktop:
        if sys.platform != 'darwin':
            raise ValueError('Automatic Claude Desktop config merging currently supports macOS only')
        desktop_path = home / 'Library' / 'Application Support' / 'Claude' / 'claude_desktop_config.json'
        payloads[desktop_path] = b''  # Merge after taking a pinned snapshot.
    catalog = {'name': 'agent-harness-local', 'owner': {'name': 'Agent Harness contributors'},
               'plugins': [{'name': 'harness-tui', 'source': './plugin',
                            'description': 'Open the local reference TUI', 'version': '0.1.1'}]}
    marketplace = base / 'tui-plugin'
    payloads[marketplace / '.claude-plugin' / 'marketplace.json'] = (json.dumps(catalog, indent=2) + '\n').encode()
    payloads[marketplace / '.agents' / 'plugins' / 'marketplace.json'] = (json.dumps(catalog, indent=2) + '\n').encode()
    backups = base / 'tui-plugin-backups'
    directories = {home, base, backups}
    for target in payloads:
        parent = target.parent
        while parent != home:
            if home not in parent.parents:
                raise ValueError('Installer destination must remain inside the chosen home')
            directories.add(parent)
            parent = parent.parent
    directories = sorted(directories, key=lambda p: (len(p.parts), str(p)))
    if any(path.is_symlink() for path in [*directories, *payloads]):
        raise ValueError('Refusing a symlinked plugin destination')
    pins = DirectoryPins()
    try:
        for directory in directories:
            pins.capture(directory)
        originals = {path: read_regular(path, pinned_parent=pins.fd(path.parent), retain_fd=pins.file_fds)
                     for path in payloads}
        previous = originals[config_path]
        if previous:
            old = json.loads(previous[0])
            if (not isinstance(old, dict) or set(old) != {'schema', 'binary'}
                    or type(old['schema']) is not int or old['schema'] != 1):
                raise ValueError('Existing TUI launcher config is not a known schema; preserve and resolve it')
        if desktop_path:
            old = originals[desktop_path]
            payloads[desktop_path] = merge_desktop(old[0] if old else b'', server)
        changes = [str(path) for path in payloads]
        if not apply:
            return changes
        for directory in directories:
            if directory != home:
                pins.create(directory)
        for directory in (base, marketplace, destination, backups):
            os.fchmod(pins.fd(directory), 0o700)
            pins.verify(directory)
        backup = backups / (datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ') + '-' + secrets.token_hex(4))
        pins.create(backup)
        saved = []
        for index, (path, original) in enumerate(originals.items()):
            if original:
                name = f'{index:03d}-{path.name}'
                atomic_write(backup / name, original[0], 0o600,
                             pinned_parent=pins.fd(backup), expected_target=None)
                saved.append({'path': str(path), 'backup': name, 'mode': original[1]})
        atomic_write(backup / 'manifest.json', (json.dumps(saved, indent=2) + '\n').encode(),
                     pinned_parent=pins.fd(backup), expected_target=None)
        published = {}
        modes = {path: (0o700 if path == entry else
                       original[1] if path == desktop_path and original else 0o600)
                 for path, original in originals.items()}
        try:
            for path, data in payloads.items():
                old = originals[path]
                atomic_write(path, data, modes[path], pinned_parent=pins.fd(path.parent),
                             expected_target=old[2] if old else None,
                             expected_data=old[0] if old else None,
                             expected_mode=old[1] if old else None,
                             published=published, retain_published_fd=pins.file_fds)
        except BaseException as error:
            failed = []
            for path in reversed(published):
                try:
                    old = originals[path]
                    if old:
                        atomic_write(path, old[0], old[1], pinned_parent=pins.fd(path.parent),
                                     expected_target=published[path], expected_data=payloads[path],
                                     expected_mode=modes[path])
                    else:
                        safe_unlink(path, pinned_parent=pins.fd(path.parent), expected_target=published[path],
                                    expected_data=payloads[path], expected_mode=modes[path])
                except OSError:
                    failed.append(str(path))
            if failed:
                raise RuntimeError('TUI plugin install failed; rollback incomplete; restore private backup at ' + str(backup)) from error
            raise
        return changes
    finally:
        pins.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--home', type=Path, default=Path.home())
    parser.add_argument('--binary', type=Path, required=True, help='Trusted Go executable supporting tui --reference-only')
    parser.add_argument('--browser', action='append', choices=['chrome', 'chromium', 'edge'], default=[])
    parser.add_argument('--claude-desktop', action='store_true', help='Merge one local server into Claude Desktop config')
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    try:
        changes = install(args.home, args.binary, args.apply, browsers=args.browser, claude_desktop=args.claude_desktop)
    except (OSError, ValueError, RuntimeError) as error:
        print('TUI plugin install refused or failed: ' + str(error)[:1024], file=sys.stderr)
        return 1
    print(('Installed' if args.apply else 'Preview: would write') + f' {len(changes)} files:')
    print('\n'.join(changes))
    if not args.apply:
        print('Run with --apply after reviewing the paths. Existing agent permissions are not modified.')
    installed = args.home.expanduser().resolve() / '.agent-harness/tui-plugin/plugin/launcher.py'
    print('Local stdio command: ' + shlex.join([sys.executable, str(installed), 'serve']))
    print('For Codex, register that absolute command with: codex mcp add harness-tui -- COMMAND ARGS')
    print('Client/plugin activation and unpacked browser-extension activation are separate; see docs/tui-plugin.md.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
