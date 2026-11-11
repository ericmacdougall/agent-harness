"""A stand-in for the Claude Code session process, used by the real-topology record-bg tests (goodqa#15565, r8 F1).

It reproduces, with real processes and real file descriptors, the topology measured on macOS 2026-11-09 for Claude
Code (tests/data/lsof_unix_macos.json; .r8 observation of the installed hook in the PR): this process plays the
session process P, and

  * a run_in_background tool shell is a direct child of P, started as a new session and process-group leader, with
    stdin on /dev/null, stdout and stderr on <HOME>/tasks/<id>.output, and ONE socketpair to P (fd number in {sock});
  * a hook is a direct child of P in a new session, with stdin, stdout and stderr on three distinct socketpairs whose
    other ends P holds; P writes the hook payload JSON to stdin and closes it.

Nothing is faked: the recorder under test reads these facts through its production Probe (ps, lsof). This process
signals nothing; the test that starts it owns every process here and stops them by process group at the end.

Protocol: one JSON object per line on stdin, one JSON reply per line on stdout.
  {"op": "bg", "task": ID, "cmd": SH}            start a background tool shell running `sh -c SH`; reply {"pid"}
  {"op": "tool", "cmd": SH, "payload": {...}}     run a foreground tool shell `sh -c SH` (same topology, its stdout
                                                  on tasks/fg.output, the payload in {payload} as a file path), wait
  {"op": "hook", "argv": [...], "payload": {...}} run a hook with the payload on stdin, wait; reply rc/out/err
  EOF                                             exit (children are left to the caller)
"""

import json
import os
import socket
import subprocess
import sys


def main():
    home = os.environ['HOME']
    tasks = os.path.join(home, 'tasks')
    os.makedirs(tasks, exist_ok=True)
    held = []  # P keeps its ends of every socketpair open, as Claude Code does while a call or hook runs

    def tool_shell(cmd, outfile, payload=None, wait=False):
        mine, theirs = socket.socketpair()
        held.append(mine)
        path = None
        if payload is not None:
            path = os.path.join(home, 'payload.json')
            with open(path, 'w') as handle:
                json.dump(payload, handle)
        out = open(outfile, 'ab')
        child = subprocess.Popen(['/bin/sh', '-c', cmd.format(sock=theirs.fileno(), payload=path or '')],
                                 stdin=subprocess.DEVNULL, stdout=out, stderr=out, start_new_session=True,
                                 pass_fds=[theirs.fileno()], cwd=home)
        out.close()
        theirs.close()
        if wait:
            rc = child.wait(timeout=60)
            with open(outfile, 'rb') as handle:
                return {'pid': child.pid, 'rc': rc, 'out': handle.read().decode('utf-8', 'replace')[-4000:]}
        return {'pid': child.pid}

    def hook(argv, payload):
        pairs = [socket.socketpair() for _ in range(3)]
        child = subprocess.Popen(argv, stdin=pairs[0][1].fileno(), stdout=pairs[1][1].fileno(),
                                 stderr=pairs[2][1].fileno(), start_new_session=True, close_fds=True)
        for _mine, theirs in pairs:
            theirs.close()
        pairs[0][0].sendall(json.dumps(payload).encode())
        pairs[0][0].shutdown(socket.SHUT_WR)
        chunks = {1: b'', 2: b''}
        for fd in (1, 2):
            while True:
                data = pairs[fd][0].recv(65536)
                if not data:
                    break
                chunks[fd] += data
        rc = child.wait(timeout=60)
        for mine, _theirs in pairs:
            mine.close()
        return {'pid': child.pid, 'rc': rc, 'out': chunks[1].decode('utf-8', 'replace'),
                'err': chunks[2].decode('utf-8', 'replace')}

    for line in sys.stdin:
        req = json.loads(line)
        if req['op'] == 'bg':
            reply = tool_shell(req['cmd'], os.path.join(tasks, req['task'] + '.output'))
        elif req['op'] == 'tool':
            reply = tool_shell(req['cmd'], os.path.join(tasks, 'fg.output'), req.get('payload'), wait=True)
        elif req['op'] == 'hook':
            reply = hook(req['argv'], req['payload'])
        else:
            reply = {'error': 'unknown op'}
        sys.stdout.write(json.dumps(reply) + '\n')
        sys.stdout.flush()
    return 0


if __name__ == '__main__':
    sys.exit(main())
