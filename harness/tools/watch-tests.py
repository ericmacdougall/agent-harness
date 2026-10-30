#!/usr/bin/env python3
"""Rerun a test command when source files change; no extra dependencies."""

import argparse
import os
import stat
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'hooks'))
from process import run as run_process


SKIP = {'.git', '.claude', 'node_modules', 'vendor', '.venv', 'venv', 'dist', 'build',
        '__pycache__', '.pytest_cache', 'coverage', 'test-results',
        'playwright-report', '.next'}
DEFAULT_EXTENSIONS = {'.py', '.go', '.ts', '.tsx', '.js', '.mjs', '.json', '.html', '.css'}
DEFAULT_FILENAMES = {'pyproject.toml', 'requirements.txt', 'poetry.lock', 'uv.lock',
                     'go.mod', 'go.sum', 'go.work', 'go.work.sum',
                     'pnpm-lock.yaml', 'yarn.lock'}


def snapshot(root, extensions):
    found = {}
    pending = [root]
    while pending:
        folder = pending.pop()
        try:
            with os.scandir(folder) as entries:
                for entry in entries:
                    if entry.name in SKIP:
                        continue
                    try:
                        is_dir = entry.is_dir(follow_symlinks=False)
                    except FileNotFoundError:
                        continue
                    path = folder / entry.name
                    if is_dir:
                        pending.append(path)
                    elif path.suffix in extensions or entry.name in DEFAULT_FILENAMES:
                        try:
                            info = entry.stat(follow_symlinks=False)
                        except FileNotFoundError:
                            continue
                        if not stat.S_ISREG(info.st_mode):
                            continue
                        found[str(path.relative_to(root))] = (
                            info.st_dev, info.st_ino, info.st_mode, info.st_size,
                            info.st_mtime_ns, info.st_ctime_ns)
        except FileNotFoundError as error:
            if folder == root:
                raise OSError('source scan failed') from error
            # A child directory can disappear between classification and traversal.
            continue
        except OSError as error:
            raise OSError('source scan failed') from error
    return found


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path('.'), help='project checkout to watch')
    parser.add_argument('--extensions', default=','.join(sorted(DEFAULT_EXTENSIONS)),
                        help='comma-separated suffixes; core dependency filenames are always watched')
    parser.add_argument('--interval', type=float, default=0.75)
    parser.add_argument('--timeout', type=int, default=600, help='seconds allowed for each test run')
    parser.add_argument('--once', action='store_true', help='run once and exit (also checks command setup)')
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ['--'] else args.command
    try:
        root = args.root.resolve()
        valid_root = root.is_dir()
    except (OSError, RuntimeError):
        print('[watch] project root unavailable', file=sys.stderr, flush=True)
        return 2
    if not valid_root or not command or args.interval < 0.1 or args.timeout <= 0:
        parser.error('provide an existing --root, a test command after --, interval >= 0.1, and timeout > 0')
    extensions = {item.strip() for item in args.extensions.split(',') if item.strip()}
    try:
        previous = snapshot(root, extensions)
        run_number = 0
        while True:
            run_number += 1
            started = time.monotonic()
            print(f'\n[watch] run {run_number}: running test command (arguments hidden)', flush=True)
            try:
                result = run_process(command, cwd=root, timeout=args.timeout, stream=True)
            except KeyboardInterrupt:
                print('\n[watch] stopped during test run', flush=True)
                return 130
            except subprocess.TimeoutExpired:
                print(f'[watch] test command exceeded {args.timeout} seconds and was stopped', flush=True)
                result = subprocess.CompletedProcess(command, 124)
            except OSError:
                print(f'[watch] run {run_number}: command could not start', flush=True)
                return 127
            elapsed = time.monotonic() - started
            print(f'[watch] exit {result.returncode}; run {run_number} took {elapsed:.2f}s; '
                  f'watching {len(previous)} source files (Ctrl-C to stop)', flush=True)
            if args.once:
                return result.returncode
            after_run = snapshot(root, extensions)
            if after_run != previous:
                previous = after_run
                continue
            previous = after_run
            try:
                while True:
                    time.sleep(args.interval)
                    current = snapshot(root, extensions)
                    if current != previous:
                        time.sleep(0.25)
                        previous = snapshot(root, extensions)
                        break
            except KeyboardInterrupt:
                print('\n[watch] stopped', flush=True)
                return 0
    except OSError:
        print('[watch] source scan failed', file=sys.stderr, flush=True)
        return 2


if __name__ == '__main__':
    sys.exit(main())
