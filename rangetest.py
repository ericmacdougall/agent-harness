import urllib.request, hashlib, os, sys
B = 'http://127.0.0.1:18789'
R = os.path.expanduser('~/gq-branch-clean/tc/work/')
files = ['public/engineering-videos/bc01-080e5fc6c243c528.mp3', 'public/engineering-videos/bc11-f32c8ff9cd9ee78e.mp4', 'public/audio/crash/cr-08-88f2a396eade7955959ead342d0780ae45d2830ebd9a7ef91fdd6b5eb70b0e8e.mp3']


def get(path, rng=None):
    h = {'Range': rng} if rng else {}
    r = urllib.request.urlopen(urllib.request.Request(B + '/' + path.replace('public/', '', 1), headers=h), timeout=60)
    return r.status, dict(r.headers), r.read()


for p in files:
    disk = open(R + p, 'rb').read()
    st, hd, body = get(p)
    print(p.split('/')[-1][:30], 'FULL', st, len(body), 'bytes-equal-disk', body == disk, 'sha-prefix', hashlib.sha256(body).hexdigest()[:16], 'ct', hd.get('Content-Type'))
    st, hd, body = get(p, 'bytes=0-1023')
    print('   RANGE 0-1023', st, len(body), 'Content-Range', hd.get('Content-Range'), 'equal', body == disk[:1024])
    a = len(disk) // 2
    st, hd, body = get(p, 'bytes=%d-%d' % (a, a + 4095))
    print('   RANGE mid', st, len(body), 'Content-Range', hd.get('Content-Range'), 'equal', body == disk[a:a + 4096])
