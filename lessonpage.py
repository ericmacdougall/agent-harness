import re, urllib.request, urllib.error
H = 'https://learnai.ericmacdougall.com'


def get(p):
    try:
        r = urllib.request.urlopen(urllib.request.Request(H + p, headers={'User-Agent': 'tc-livecheck/1.0'}), timeout=60)
        return r.status, r.headers.get('Content-Type', ''), r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.headers.get('Content-Type', ''), b''


st, ct, body = get('/')
html = body.decode('utf-8', 'replace')
links = sorted(set(re.findall(r'href="(/[^"#?]*)"', html)))
print('home links:', links[:25])
for p in links[:25]:
    if p.startswith(('/_next', '/audio', '/engineering', '/data-audio')) or p.endswith(('.js', '.css', '.png', '.ico', '.svg', '.xml', '.txt')):
        continue
    st, ct, b = get(p)
    print(p, st, ct.split(';')[0], len(b))
