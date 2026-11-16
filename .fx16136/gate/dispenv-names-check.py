"""goodqa#16148: read-only presence check of nine intelligence-worker key NAMES in the app VM's dispatcher.env.

Streamed to the VM as `sudo python3 -I - [--env-dir DIR]` (default /etc/goodqa). Writes nothing. Output, and nothing else:
    <NAME> present nonempty | present empty | absent      (one line per name below, in this order)
    duplicates <N>                                        (how many distinct keys in the file appear on more than one line)
or a single `UNREADABLE <exception type>` line. Never prints the file, a value, a value length or a hash.
Parsing follows compose `env_file: format: raw`: `#` lines are comments, leading whitespace before the key is dropped, a
line splits on its first `=`, a final CR is stripped.
"""
import os
import sys

NAMES = (
    'JOB_ENV_INTELLIGENCE_WORKER__DATABASE_URL',
    'JOB_ENV_INTELLIGENCE_WORKER__NODE_ENV',
    'JOB_ENV_INTELLIGENCE_WORKER__OPENROUTER_API_KEY',
    'JOB_ENV_INTELLIGENCE_WORKER__SPACES_ACCESS_KEY_ID',
    'JOB_ENV_INTELLIGENCE_WORKER__SPACES_BUCKET',
    'JOB_ENV_INTELLIGENCE_WORKER__SPACES_ENDPOINT',
    'JOB_ENV_INTELLIGENCE_WORKER__SPACES_REGION',
    'JOB_ENV_INTELLIGENCE_WORKER__SPACES_SECRET_ACCESS_KEY',
    'JOB_ENV_INTELLIGENCE_WORKER__STORAGE_DRIVER',
)


def main():
    env_dir = '/etc/goodqa'
    if sys.argv[1:2] == ['--env-dir'] and len(sys.argv) == 3:
        env_dir = sys.argv[2]
    elif sys.argv[1:]:
        print('UNREADABLE usage'); return 2
    try:
        fd = os.open(os.path.join(env_dir, 'dispatcher.env'), os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, 'rb') as f:
            data = f.read()
    except Exception as e:
        print('UNREADABLE ' + type(e).__name__); return 1
    counts = {}
    nonempty = {}
    for raw in data.split(b'\n'):
        line = raw[:-1] if raw.endswith(b'\r') else raw
        line = line.lstrip(b' \t')
        if not line or line.startswith(b'#') or b'=' not in line:
            continue
        key, _, val = line.partition(b'=')
        k = key.decode('ascii', 'replace')
        counts[k] = counts.get(k, 0) + 1
        nonempty[k] = len(val) > 0          # the last line wins, as in compose
        del val
    del data
    for n in NAMES:
        if n not in counts:
            print(n + ' absent')
        else:
            print(n + (' present nonempty' if nonempty[n] else ' present empty'))
    print('duplicates %d' % sum(1 for c in counts.values() if c > 1))
    return 0


if __name__ == '__main__':
    sys.exit(main())
