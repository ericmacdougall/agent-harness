"""Regenerate tests/data/lsof_unix_macos.json from the real macOS lsof (goodqa#15565, receipt r8 F1).

    python3 tests/data/capture_lsof_unix.py > tests/data/lsof_unix_macos.json

It starts its own short `sleep` with fd 1 and fd 2 on two socketpairs whose other ends this process holds (the shape
Claude Code gives a hook), runs `lsof -n -P -a -p PID [-d 1,2] -F ftdn` exactly as kill_guard.Probe does, and
sanitises the result: real pids become 1111 (session process) and 2222 (hook), and every kernel socket address is
renamed in order of appearance (0x00000000000a0001, ...) so pairing is preserved but nothing machine-specific is kept. Only
the unix-socket records and a couple of non-socket records (to keep the parser honest) are retained. The child exits
by itself; nothing is signalled.
"""

import json
import os
import platform
import re
import socket
import subprocess
import sys


def lsof(pid, fds=None):
    argv = ['lsof', '-n', '-P', '-a', '-p', str(pid)] + (['-d', fds] if fds else []) + ['-F', 'ftdn']
    return subprocess.run(argv, capture_output=True, text=True, timeout=10).stdout


def records(text):
    """Split -F output into [header lines, [record lines]...]; a record starts at an f line."""
    head, recs = [], []
    for line in text.splitlines():
        if line.startswith('f'):
            recs.append([line])
        elif recs:
            recs[-1].append(line)
        else:
            head.append(line)
    return head, recs


def main():
    if sys.platform != 'darwin':
        sys.stderr.write('macOS only\n')
        return 2
    a1, b1 = socket.socketpair()
    a2, b2 = socket.socketpair()
    child = subprocess.Popen(['sleep', '3'], stdin=subprocess.DEVNULL, stdout=a1.fileno(), stderr=a2.fileno(),
                             start_new_session=True)
    a1.close()
    a2.close()
    raw_child, raw_parent = lsof(child.pid, '1,2'), lsof(os.getpid())
    keep = {str(b1.fileno()), str(b2.fileno())}
    child.wait()
    names = {}

    def addr(match):
        return names.setdefault(match.group(0), '0x%016x' % (0xa0000 + len(names) + 1))

    def clean(text, pid, new_pid, keep_fds=None):
        head, recs = records(text)
        out = ['p%d' % new_pid if line.startswith('p') else line for line in head]
        others = 0
        for rec in recs:
            fd = rec[0][1:]
            is_unix = 't' + 'unix' in rec
            if keep_fds is not None and not is_unix:
                if fd not in ('cwd', '0') or others >= 2:
                    continue
                others += 1
            elif keep_fds is not None and fd not in keep_fds:
                continue
            for line in rec:
                if line.startswith('n') and not is_unix:
                    line = 'n/sanitised/path'
                out.append(re.sub(r'0x[0-9a-f]+', addr, line))
        return '\n'.join(out) + '\n'

    hook = clean(raw_child, child.pid, 2222)
    session = clean(raw_parent, os.getpid(), 1111, keep_fds=keep)
    result = {'captured_on': 'macOS %s (%s), lsof -F ftdn' % (platform.mac_ver()[0], platform.machine()),
              'hook_pid': 2222, 'session_pid': 1111, 'hook_stdio': hook, 'session_all': session}
    if len(sys.argv) > 2 and sys.argv[1] == '--claude-session':
        # The unix-socket records of a real Claude Code session process (same uid), every path name replaced
        head, recs = records(lsof(int(sys.argv[2])))
        lines = ['p3333']
        for rec in recs:
            if 't' + 'unix' not in rec:
                continue
            for line in rec:
                if line.startswith('n') and not line.startswith('n->'):
                    line = 'n/sanitised/listening.sock'
                lines.append(re.sub(r'0x[0-9a-f]+', addr, line))
        result['claude_session_pid'] = 3333
        result['claude_session_unix'] = '\n'.join(lines) + '\n'
    print(json.dumps(result, indent=1))
    return 0


if __name__ == '__main__':
    sys.exit(main())
