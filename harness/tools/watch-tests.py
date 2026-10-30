#!/usr/bin/env python3
"""Rerun a test command when source files change; no extra dependencies."""

import argparse
import os
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'hooks'))
from process import run as run_process


SKIP = {'.git', '.claude', 'node_modules', '.venv', 'venv', 'dist', 'build', '__pycache__', '.pytest_cache'}
DEFAULT_EXTENSIONS = {'.py', '.go', '.ts', '.tsx', '.js', '.mjs', '.json', '.html', '.css'}


def snapshot(root, extensions):
    found = {}
    for folder, dirs, files in os.walk(root):
        dirs[:] = [name for name in dirs if name not in SKIP]
        for name in files:
            path = Path(folder) / name
            if path.suffix not in extensions:
                continue
            try:
                stat = path.stat()
                found[str(path.relative_to(root))] = (stat.st_mtime_ns, stat.st_size)
            except FileNotFoundError:
                continue
    return found


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path.cwd(), help='project checkout to watch')
    parser.add_argument('--extensions', default=','.join(sorted(DEFAULT_EXTENSIONS)))
    parser.add_argument('--interval', type=float, default=0.75)
    parser.add_argument('--timeout', type=int, default=600, help='seconds allowed for each test run')
    parser.add_argument('--once', action='store_true', help='run once and exit (also checks command setup)')
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ['--'] else args.command
    root = args.root.resolve()
    if not root.is_dir() or not command or args.interval < 0.1 or args.timeout <= 0:
        parser.error('provide an existing --root, a test command after --, interval >= 0.1, and timeout > 0')
    extensions = {item.strip() for item in args.extensions.split(',') if item.strip()}
    previous = snapshot(root, extensions)
    while True:
        print(f'\n[watch] {root} $ {" ".join(command)}', flush=True)
        try:
            result = run_process(command, cwd=root, timeout=args.timeout, stream=True)
        except KeyboardInterrupt:
            print('\n[watch] stopped during test run', flush=True)
            return 130
        except subprocess.TimeoutExpired:
            print(f'[watch] test command exceeded {args.timeout} seconds and was stopped', flush=True)
            result = subprocess.CompletedProcess(command, 124)
        except OSError as error:
            print(f'[watch] command could not start: {error}', flush=True)
            return 127
        print(f'[watch] exit {result.returncode}; watching {len(previous)} source files (Ctrl-C to stop)', flush=True)
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


if __name__ == '__main__':
    sys.exit(main())
