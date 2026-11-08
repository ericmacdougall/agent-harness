"""Pack the t2-course media prefixes into deterministic <=240 MiB tar parts and write media-manifest.json.
usage: mediapack.py <repo-checkout> <out-dir>
Deterministic: sorted paths, mtime 0, uid/gid 0, no names. Part key = media/v1/part-NNNN-<sha12>.tar
"""
import sys, os, tarfile, hashlib, json
repo, out = sys.argv[1], sys.argv[2]
PREFIXES = ['public/audio/', 'public/engineering-videos/', 'public/data-audio/', 'power-user/public/audio/']
LIMIT = 240 * 1024 * 1024
os.makedirs(out, exist_ok=True)
files = []
import subprocess
tracked = subprocess.run(['git', '-C', repo, 'ls-files', '-z'], capture_output=True).stdout.split(b'\0')
for p in sorted(x.decode() for x in tracked if x):
    if p.startswith(tuple(PREFIXES)):
        files.append((p, os.path.getsize(os.path.join(repo, p))))
parts, cur, size = [], [], 0
for p, s in files:
    if cur and size + s > LIMIT:
        parts.append(cur); cur, size = [], 0
    cur.append((p, s)); size += s
if cur:
    parts.append(cur)
manifest = {'version': 1, 'bucket': 'learnai-field-lab-media', 'prefixes': PREFIXES, 'parts': []}
for i, part in enumerate(parts, 1):
    tmp = os.path.join(out, 'part-%04d.tar' % i)
    with tarfile.open(tmp, 'w', format=tarfile.PAX_FORMAT) as t:
        for p, s in part:
            ti = tarfile.TarInfo(p); ti.size = s; ti.mtime = 0; ti.uid = ti.gid = 0; ti.uname = ti.gname = ''; ti.mode = 0o644
            with open(os.path.join(repo, p), 'rb') as f:
                t.addfile(ti, f)
    h = hashlib.sha256()
    with open(tmp, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    sha = h.hexdigest()
    key = 'media/v1/part-%04d-%s.tar' % (i, sha[:12])
    os.rename(tmp, os.path.join(out, os.path.basename(key)))
    manifest['parts'].append({'key': key, 'sha256': sha, 'bytes': os.path.getsize(os.path.join(out, os.path.basename(key))), 'files': len(part), 'content_bytes': sum(s for _, s in part), 'first': part[0][0], 'last': part[-1][0]})
    print(key, len(part), flush=True)
manifest['totals'] = {'files': len(files), 'content_bytes': sum(s for _, s in files), 'parts': len(parts)}
json.dump(manifest, open(os.path.join(out, 'media-manifest.json'), 'w'), indent=1)
print(manifest['totals'])
