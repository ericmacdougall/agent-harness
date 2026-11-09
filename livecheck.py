"""Live check of the t2-course deploy (runs on t2-dev; sizes come from the deployed dist/client). 10 media URLs (seed 11) plus one lesson page and the home page."""
import os, random, urllib.request, urllib.error, mimetypes, collections
H = 'https://learnai.ericmacdougall.com'
D = '/home/eric/gq-branch-clean/dep/t2c/dist/client/'
EXT = {'.mp3': 'audio/mpeg', '.mp4': 'video/mp4', '.m4a': 'audio/mp4', '.ts': 'video/mp2t', '.vtt': 'text/vtt', '.srt': None, '.jpg': 'image/jpeg', '.m3u8': None, '.zip': 'application/zip'}
files = []
for sub in ('audio', 'engineering-videos', 'data-audio'):
    for dp, dn, fn in os.walk(D + sub):
        for f in fn:
            files.append(os.path.relpath(os.path.join(dp, f), D))
random.seed(11)
byext = collections.defaultdict(list)
for f in files:
    byext[os.path.splitext(f)[1]].append(f)
pick = []
for ext in ('.mp3', '.mp4', '.m4a', '.ts', '.vtt', '.mp3', '.ts', '.mp3', '.mp4', '.m4a'):
    if byext.get(ext):
        pick.append(random.choice(byext[ext]))
pick = list(dict.fromkeys(pick))
while len(pick) < 10:
    f = random.choice(files)
    if f not in pick:
        pick.append(f)
bad = 0


def get(path):
    req = urllib.request.Request(H + '/' + path.lstrip('/').replace(' ', '%20'), headers={'User-Agent': 'tc-livecheck/1.0'})
    try:
        r = urllib.request.urlopen(req, timeout=60)
        return r.status, r.headers.get('Content-Type', ''), r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.headers.get('Content-Type', ''), b''


for f in pick[:10]:
    exp = os.path.getsize(D + f)
    st, ct, body = get(f)
    ext = os.path.splitext(f)[1]
    want = EXT.get(ext)
    ok = st == 200 and len(body) == exp and (want is None or ct.split(';')[0] == want or ct.startswith(want.split('/')[0]))
    bad += 0 if ok else 1
    print('OK  ' if ok else 'FAIL', st, ct.split(';')[0], len(body), 'expected', exp, f[:90])
for page in ('/', '/learn', '/power-user'):
    st, ct, body = get(page)
    print('page', page, st, ct.split(';')[0], len(body))
print('MEDIA_FAILURES', bad)
