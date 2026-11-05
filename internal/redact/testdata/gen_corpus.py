"""python3 -I gen_corpus.py <hooks-dir> > corpus.json: SECRET_PATTERN spans from CPython (seed 20261104)."""
import json, random, sys
sys.path.insert(0, sys.argv[1])
from wal_note import SECRET_PATTERN
rng = random.Random(20261104)
seeds = ["ghp_abcDEF123", "github_pat_11AA_bb", "sk-proj-abcdefghijkl", "AKIAABCDEFGHIJKL", "Bearer abc.def",
         "xoxb-123456-abc", "password=hunter2", 'api_key: "x"', "db-password = y", "token_count=5", "clientSecret:z",
         "myApiKey=1", "https://user:pw@host/x", "ssh://git@github.com:22/r", "a@b.c", "x/@y",
         "-----BEGIN PRIVATE KEY-----", "-----BEGIN OPENSSH PRIVATE KEY-----", "credentials = abc",
         "PASSWORD=Q", "secret_value=k"]
fillers = [" ", "\t", "\n", " ", " ", "　", "\x1c", "\x85", "​", "é", "_", "-", ":", "=", "\"",
           "'", "/", "@", "x", "Z", "9", "K", "ſ", "İ", "ı", "ß", "日"]
cases = []
for s in seeds:
    cases.append(s)
    for f in fillers:
        cases.append(f + s)
        cases.append(s.replace(" ", f).replace("=", f + "=" + f, 1))
for _ in range(3000):
    parts = [rng.choice(seeds + fillers) for _ in range(rng.randrange(1, 6))]
    s = "".join(parts)
    if rng.random() < 0.3:
        i = rng.randrange(len(s) + 1)
        s = s[:i] + rng.choice(fillers) + s[i:]
    cases.append(s)
out = {"source": SECRET_PATTERN.pattern,
       "cases": [[c, [list(m.span()) for m in SECRET_PATTERN.finditer(c)]] for c in cases]}
json.dump(out, sys.stdout, ensure_ascii=True, indent=0)
