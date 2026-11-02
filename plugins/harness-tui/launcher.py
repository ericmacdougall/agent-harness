#!/usr/bin/env python3
"""Open a local Go TUI with a private, inert current-conversation reference.

The stdio/native transports receive supplied text, never arbitrary paths or
commands. They expose no history discovery, network listener or background job.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import shlex
import stat
import struct
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit


MAX_BYTES = 262144
MAX_BODY_BYTES = 131072
EXTENSION_ID = 'gdpiohlkkniinkfhlbhcjoimlcnhnkgj'
NATIVE_ORIGIN = f'chrome-extension://{EXTENSION_ID}/'
HOST_NAME = 'com.agentharness.tui'
PACKAGE = Path(__file__).resolve().parent
REFERENCE_REQUIRED = {'schema', 'client', 'captured_at', 'title', 'kind', 'body', 'truncated'}
REFERENCE_OPTIONAL = {'session_id', 'source_url'}
UTC_PATTERN = re.compile(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|\+00:00)\Z')
HEX_ID = re.compile(r'[0-9a-f]{32}\Z')
SHA = re.compile(r'[0-9a-f]{64}\Z')


class InvalidReference(ValueError):
    """A bounded caller-visible error containing no supplied content."""


def object_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise InvalidReference('Duplicate JSON object fields are not supported')
        result[key] = value
    return result


def decode_json(data: bytes):
    if len(data) > MAX_BYTES:
        raise InvalidReference('Input exceeds the 256 KiB limit')
    try:
        text = data.decode('utf-8', errors='strict')
        return json.loads(text, object_pairs_hook=object_pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(
                              InvalidReference('Non-finite JSON numbers are not supported')))
    except (UnicodeError, ValueError, RecursionError) as error:
        raise InvalidReference('Input must be one bounded UTF-8 JSON object') from error


def validate_reference(value):
    if not isinstance(value, dict) or not REFERENCE_REQUIRED <= value.keys():
        raise InvalidReference('Reference is missing required fields')
    if value.keys() - REFERENCE_REQUIRED - REFERENCE_OPTIONAL:
        raise InvalidReference('Reference contains unsupported fields')
    if type(value['schema']) is not int or value['schema'] != 1:
        raise InvalidReference('Reference schema must be integer 1')
    if type(value['truncated']) is not bool:
        raise InvalidReference('Reference truncated must be a boolean')
    limits = {'client': 64, 'title': 512, 'session_id': 128, 'source_url': 2048}
    for key in (REFERENCE_REQUIRED | REFERENCE_OPTIONAL) - {'schema', 'truncated'}:
        if key not in value:
            continue
        text = value[key]
        if not isinstance(text, str):
            raise InvalidReference('Reference text fields must be strings')
        try:
            encoded = text.encode('utf-8', errors='strict')
        except UnicodeError as error:
            raise InvalidReference('Reference text contains an unpaired Unicode surrogate') from error
        if key in limits and len(text) > limits[key]:
            raise InvalidReference('Reference metadata exceeds its character limit')
        if key in {'client', 'title', 'body'} and not text.strip():
            raise InvalidReference('Reference client, title and body must be nonempty')
        if key == 'body' and len(encoded) > MAX_BODY_BYTES:
            raise InvalidReference('Reference body exceeds 128 KiB UTF-8')
    if value['kind'] not in {'summary', 'excerpt', 'transcript'}:
        raise InvalidReference('Reference kind must be summary, excerpt or transcript')
    timestamp = value['captured_at']
    if not UTC_PATTERN.fullmatch(timestamp):
        raise InvalidReference('Reference captured_at must be a UTC RFC3339 timestamp')
    try:
        # Parse the calendar portion separately so Python 3.10 also accepts
        # the shared contract's nine fractional digits without rounding.
        datetime.strptime(timestamp[:19], '%Y-%m-%dT%H:%M:%S')
    except ValueError as error:
        raise InvalidReference('Reference captured_at is not a valid date') from error
    try:
        encoded = json.dumps(value, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
    except (UnicodeError, RecursionError) as error:
        raise InvalidReference('Reference cannot be encoded safely') from error
    if len(encoded) + 1 > MAX_BYTES:
        raise InvalidReference('Encoded reference exceeds 256 KiB')
    return dict(value)


def read_reference(data: bytes):
    return validate_reference(decode_json(data))


def redact_text(text: str) -> str:
    # This is defensive secret filtering, not complete PII/secret detection.
    text = re.sub(r'-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----',
                  '[REDACTED PRIVATE KEY]', text, flags=re.S)
    text = re.sub(r'\bsk-[A-Za-z0-9_-]{12,}', '[REDACTED API KEY]', text)
    text = re.sub(r'(?i)\bBearer\s+[A-Za-z0-9._~+/-]{8,}=*', 'Bearer [REDACTED]', text)
    prefix = r'(?i)(\b(?:api[_-]?key|password|access[_-]?token|secret)\s*[:=]\s*)'
    text = re.sub(prefix + r'([\"\'])([^\r\n]*?)\2', r'\1[REDACTED]', text)
    return re.sub(prefix + r'(?!\[REDACTED\])[^\s,;]+', r'\1[REDACTED]', text)


def private_root() -> Path:
    return Path.home().resolve() / '.agent-harness'


def open_directory(path: Path, *, create: bool = False) -> int:
    """Walk without symlinks; callers separately enforce private leaf modes."""
    path = path.absolute()
    fd = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in path.parts[1:]:
            if create:
                try:
                    os.mkdir(part, mode=0o700, dir_fd=fd)
                except FileExistsError:
                    pass
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def private_directory(path: Path, *, create: bool = False) -> int:
    fd = open_directory(path, create=create)
    info = os.fstat(fd)
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        os.close(fd)
        raise InvalidReference('Reference storage directories must be user-owned mode 0700')
    return fd


def write_private(directory: int, name: str, data: bytes, mode=0o600):
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                 mode, dir_fd=directory)
    with os.fdopen(fd, 'wb') as handle:
        handle.write(data)
        handle.flush()
        os.fchmod(handle.fileno(), mode)
        os.fsync(handle.fileno())
    os.fsync(directory)


def read_private(directory: int, name: str, limit: int = MAX_BYTES) -> bytes:
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    with os.fdopen(fd, 'rb') as handle:
        info = os.fstat(handle.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_size > limit):
            raise InvalidReference('Reference/config files must be private regular files within size limits')
        data = handle.read(limit + 1)
        if len(data) > limit:
            raise InvalidReference('Reference/config file exceeds its size limit')
        return data


def prepare_reference(reference):
    value = validate_reference(reference)
    for key, text in list(value.items()):
        if isinstance(text, str):
            value[key] = redact_text(text)
    if value.get('source_url'):
        try:
            url = urlsplit(value['source_url'])
            if url.username or url.password:
                raise ValueError('credentials in URL')
            value['source_url'] = urlunsplit((url.scheme, url.netloc, url.path, '', ''))
        except ValueError as error:
            raise InvalidReference('Source URL is invalid or contains credentials') from error
    value = validate_reference(value)
    encoded = (json.dumps(value, ensure_ascii=False, separators=(',', ':')) + '\n').encode('utf-8')
    root = private_root()
    fd = private_directory(root, create=True)
    os.close(fd)
    storage = root / 'tui-references'
    storage_fd = private_directory(storage, create=True)
    identifier = secrets.token_hex(16)
    try:
        os.mkdir(identifier, mode=0o700, dir_fd=storage_fd)
        bundle = storage / identifier
        fd = private_directory(bundle)
        try:
            write_private(fd, 'reference.json', encoded)
        finally:
            os.close(fd)
    finally:
        os.close(storage_fd)
    return {'status': 'PREPARED', 'reference_id': identifier,
            'reference_file': str(bundle / 'reference.json'),
            'sha256': hashlib.sha256(encoded).hexdigest()}


def load_config():
    fd = private_directory(private_root())
    try:
        value = decode_json(read_private(fd, 'tui-launcher.json', 16384))
    finally:
        os.close(fd)
    if (not isinstance(value, dict) or set(value) != {'schema', 'binary'}
            or type(value['schema']) is not int or value['schema'] != 1
            or not isinstance(value['binary'], str) or not Path(value['binary']).is_absolute()):
        raise InvalidReference('TUI launcher config requires schema 1 and one absolute binary path')
    binary = Path(value['binary'])
    info = binary.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid not in {0, os.getuid()}
            or info.st_mode & 0o022 or not os.access(binary, os.X_OK)):
        raise InvalidReference('Configured TUI must be a trusted executable regular file')
    return value


def open_reference(reference):
    prepared = prepare_reference(reference)
    result = {**prepared, 'status': 'NOT_LAUNCHED'}
    try:
        load_config()
        if sys.platform != 'darwin':
            result['reason'] = 'Automatic Terminal opening supports macOS; use the foreground command here'
            return result
        bundle = Path(prepared['reference_file']).parent
        fd = private_directory(bundle)
        try:
            script = '#!/bin/sh\nexec ' + ' '.join(shlex.quote(part) for part in [
                sys.executable, str(PACKAGE / 'launcher.py'), 'run',
                '--id', prepared['reference_id'], '--sha256', prepared['sha256']]) + '\n'
            write_private(fd, 'open.command', script.encode(), 0o700)
        finally:
            os.close(fd)
        try:
            dispatch = subprocess.run(['/usr/bin/open', '-a', 'Terminal', str(bundle / 'open.command')],
                                      capture_output=True, timeout=10, check=False)
        except subprocess.TimeoutExpired:
            result.update(status='UNKNOWN', reason='Terminal dispatch timed out; inspect before retrying')
            return result
        if dispatch.returncode:
            result.update(status='DISPATCH_FAILED', reason='Terminal rejected the launch request')
            return result
        result.update(status='LAUNCH_REQUESTED', note='Terminal accepted the request; UI readiness is not confirmed')
    except (OSError, ValueError):
        result['reason'] = 'Local launcher configuration or private file validation failed; run the installer preview'
    return result


def run_reference(identifier: str, digest: str):
    if not HEX_ID.fullmatch(identifier) or not SHA.fullmatch(digest):
        raise InvalidReference('Invalid reference identifier or SHA-256')
    config = load_config()
    bundle = private_root() / 'tui-references' / identifier
    fd = private_directory(bundle)
    try:
        data = read_private(fd, 'reference.json')
        if hashlib.sha256(data).hexdigest() != digest:
            raise InvalidReference('Reference content no longer matches its launch digest')
        read_reference(data)
        write_private(fd, 'run-intent.json', b'{"status":"PROCESS_START_REQUESTED"}\n')
        argv = [config['binary'], 'tui', '--reference-only', '--reference-file',
                str(bundle / 'reference.json'), '--reference-sha256', digest]
        process = subprocess.Popen(argv)
        write_private(fd, 'process-started.json',
                      (json.dumps({'status': 'PROCESS_STARTED', 'pid': process.pid}) + '\n').encode())
        code = process.wait()
        write_private(fd, 'process-exited.json',
                      (json.dumps({'status': 'PROCESS_EXITED', 'exit_code': code}) + '\n').encode())
        return code
    finally:
        os.close(fd)


def read_bounded(stream, limit=MAX_BYTES):
    data = stream.read(limit + 1)
    if len(data) > limit:
        raise InvalidReference('Input exceeds 256 KiB')
    return data


def native_host(origin: str, incoming, outgoing):
    if origin != NATIVE_ORIGIN:
        raise InvalidReference('Unregistered native messaging origin')
    prefix = incoming.read(4)
    if len(prefix) != 4:
        raise InvalidReference('Native message has no complete length prefix')
    size = struct.unpack('<I', prefix)[0]
    if not 0 < size <= MAX_BYTES:
        raise InvalidReference('Native message exceeds its size limit')
    chunks, remaining = [], size
    while remaining:
        chunk = incoming.read(remaining)
        if not chunk:
            raise InvalidReference('Native message ended before its declared length')
        chunks.append(chunk)
        remaining -= len(chunk)
    value = decode_json(b''.join(chunks))
    if (not isinstance(value, dict) or set(value) != {'action', 'reference'}
            or value['action'] != 'open_tui'):
        raise InvalidReference('Unsupported native message shape or action')
    result = open_reference(validate_reference(value['reference']))
    encoded = json.dumps(result, separators=(',', ':')).encode('utf-8')
    outgoing.write(struct.pack('<I', len(encoded)) + encoded)
    outgoing.flush()


def tool_schema():
    string = lambda maximum: {'type': 'string', 'maxLength': maximum}
    return {'type': 'object', 'additionalProperties': False, 'required': ['reference'],
            'properties': {'reference': {'type': 'object', 'additionalProperties': False,
                'required': sorted(REFERENCE_REQUIRED - {'captured_at'}), 'properties': {
                    'schema': {'type': 'integer', 'const': 1}, 'client': string(64),
                    'captured_at': {'type': 'string', 'description': 'UTC RFC3339 capture time; local receipt time is used when omitted'},
                    'title': string(512), 'kind': {'enum': ['summary', 'excerpt', 'transcript']},
                    'body': {'type': 'string', 'description': 'Inert reference text, at most 128 KiB UTF-8'},
                    'truncated': {'type': 'boolean'}, 'session_id': string(128), 'source_url': string(2048)}}}}


def mcp_server(incoming, outgoing):
    """Small stdio MCP server with no sampling, resources or hidden side effects."""
    cache = {}
    initialized = False
    while True:
        line = incoming.readline(MAX_BYTES + 1)
        if not line:
            return
        response = None
        request = None
        try:
            if len(line) > MAX_BYTES:
                raise InvalidReference('MCP line exceeds 256 KiB')
            request = decode_json(line)
            if (not isinstance(request, dict) or request.get('jsonrpc') != '2.0'
                    or not isinstance(request.get('method'), str)):
                raise InvalidReference('Invalid JSON-RPC request')
            if 'id' not in request:
                continue  # Notifications never launch the TUI.
            identifier = request['id']
            if type(identifier) not in {str, int}:
                raise InvalidReference('Invalid JSON-RPC request identifier')
            cache_key = (type(identifier).__name__, identifier)
            fingerprint = hashlib.sha256(line).hexdigest()
            if cache_key in cache:
                prior, response = cache[cache_key]
                if prior != fingerprint:
                    raise InvalidReference('JSON-RPC identifier was reused with different input')
            else:
                method = request['method']
                if method == 'initialize':
                    requested = request.get('params', {}).get('protocolVersion')
                    version = requested if requested in {'2024-11-05', '2025-03-26', '2025-06-18', '2025-11-25'} else '2025-11-25'
                    result = {'protocolVersion': version, 'capabilities': {'tools': {}},
                              'serverInfo': {'name': 'agent-harness-tui', 'version': '0.1.0'}}
                    initialized = True
                elif method == 'ping':
                    result = {}
                elif not initialized:
                    raise InvalidReference('MCP initialization is required before tool use')
                elif method == 'tools/list':
                    result = {'tools': [{'name': 'open_tui', 'description':
                        'Open the local Go TUI with supplied current-chat reference text. No job is submitted. '
                        'Use kind summary for agent context or excerpt for partial transcript; never imply hidden history access.',
                        'inputSchema': tool_schema(), 'annotations': {'readOnlyHint': False,
                            'destructiveHint': False, 'idempotentHint': False, 'openWorldHint': False}}]}
                elif method == 'tools/call':
                    params = request.get('params')
                    if (not isinstance(params, dict) or params.get('name') != 'open_tui'
                            or not isinstance(params.get('arguments'), dict)
                            or set(params['arguments']) != {'reference'}):
                        raise InvalidReference('Unsupported tool or arguments')
                    supplied = params['arguments']['reference']
                    if isinstance(supplied, dict) and 'captured_at' not in supplied:
                        supplied = {**supplied, 'captured_at': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')}
                    opened = open_reference(validate_reference(supplied))
                    result = {'content': [{'type': 'text', 'text': json.dumps(opened)}],
                              'structuredContent': opened,
                              'isError': opened['status'] != 'LAUNCH_REQUESTED'}
                else:
                    response = {'jsonrpc': '2.0', 'id': identifier,
                                'error': {'code': -32601, 'message': 'Method not found'}}
                if response is None:
                    response = {'jsonrpc': '2.0', 'id': identifier, 'result': result}
                if len(cache) >= 64:
                    cache.pop(next(iter(cache)))
                cache[cache_key] = (fingerprint, response)
        except (InvalidReference, OSError, TypeError, AttributeError, RecursionError):
            identifier = request.get('id') if isinstance(request, dict) else None
            if type(identifier) not in {str, int}:
                identifier = None
            response = {'jsonrpc': '2.0', 'id': identifier,
                        'error': {'code': -32602, 'message': 'Invalid or unsafe bounded request; no supplied content is logged'}}
        outgoing.write((json.dumps(response, ensure_ascii=True) + '\n').encode('utf-8'))
        outgoing.flush()
        if len(line) > MAX_BYTES:
            return  # Never treat the remainder of an oversized frame as another request.


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='action', required=True)
    for name in ('prepare', 'open', 'foreground', 'serve'):
        commands.add_parser(name)
    native = commands.add_parser('native-host')
    native.add_argument('origin')
    run = commands.add_parser('run')
    run.add_argument('--id', required=True)
    run.add_argument('--sha256', required=True)
    args = parser.parse_args(argv)
    try:
        if args.action == 'serve':
            mcp_server(sys.stdin.buffer, sys.stdout.buffer)
            return 0
        if args.action == 'native-host':
            native_host(args.origin, sys.stdin.buffer, sys.stdout.buffer)
            return 0
        if args.action == 'run':
            return run_reference(args.id, args.sha256)
        reference = read_reference(read_bounded(sys.stdin.buffer))
        if args.action == 'prepare':
            result = prepare_reference(reference)
        elif args.action == 'open':
            result = open_reference(reference)
        else:
            prepared = prepare_reference(reference)
            return run_reference(prepared['reference_id'], prepared['sha256'])
        print(json.dumps(result))
        return 0 if result['status'] in {'PREPARED', 'LAUNCH_REQUESTED'} else 1
    except (OSError, InvalidReference, ValueError):
        print('TUI reference operation failed: invalid input, private storage or local configuration.', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
