import hashlib, io, json, os, shutil, subprocess, tarfile, tempfile
W = os.path.dirname(os.path.abspath(__file__))
PACKET = "/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/agent-ab8a7d1bf54ed3c9a/t2course-packet.txt"
SCRIPT = "".join(open(PACKET).readlines()[62:156])
SB = tempfile.mkdtemp(prefix="media-probe-")
LOG = os.path.join(SB, "stub.log")
os.chmod(W + "/stub/npx", 0o755)


def env(**k):
    e = dict(os.environ)
    e["PATH"] = W + "/stub:" + e["PATH"]
    e["STUB_LOG"] = LOG
    e.pop("MEDIA_SKIP", None)
    e.update(k)
    return e


FILES = {"public/audio/a.mp3": b"AAAA", "public/audio/b.mp3": b"BBBB", "public/audio/c.mp3": b"CCCC", "public/audio/d.mp3": b"DDDD"}


def mk(name, members=None, write_media=True):
    r = os.path.join(SB, name)
    os.makedirs(r + "/scripts")
    os.makedirs(r + "/.media-cache")
    open(r + "/scripts/media-sync.mjs", "w").write(SCRIPT)
    open(r + "/wrangler.cloudflare.jsonc", "w").write('{"account_id":"abc123"}')
    open(r + "/package.json", "w").write('{"name":"orig"}')
    t = r + "/.media-cache/part-0001-x.tar"
    with tarfile.open(t, "w", format=tarfile.PAX_FORMAT) as tf:
        for m in members or list(FILES.items()):
            ti = tarfile.TarInfo(m[0])
            if isinstance(m[1], bytes):
                ti.size = len(m[1])
                tf.addfile(ti, io.BytesIO(m[1]))
            else:
                ti.type = tarfile.SYMTYPE
                ti.linkname = m[1]["link"]
                tf.addfile(ti)
    b = open(t, "rb").read()
    man = {"version": 1, "bucket": "b", "prefixes": ["public/audio/"], "parts": [{"key": "media/v1/part-0001-x.tar", "sha256": hashlib.sha256(b).hexdigest(), "bytes": len(b), "files": 4, "content_bytes": 16, "first": "public/audio/a.mp3", "last": "public/audio/d.mp3"}], "totals": {"files": 4, "content_bytes": 16, "parts": 1}}
    open(r + "/media-manifest.json", "w").write(json.dumps(man))
    if write_media:
        for p, c in FILES.items():
            os.makedirs(os.path.dirname(r + "/" + p), exist_ok=True)
            open(r + "/" + p, "wb").write(c)
    return r


def run(r, cmd, **k):
    p = subprocess.run(["node", "scripts/media-sync.mjs", cmd], cwd=r, env=env(**k), capture_output=True, text=True, timeout=60)
    lines = (p.stdout + p.stderr).strip().splitlines()
    return p.returncode, [l[:170] for l in lines if "Error" in l or "media ok" in l or "INCOMPLETE" in l or "nothing" in l or "pushed" in l or "tar:" in l or "Option" in l or "failed" in l][:4]


def show(i, desc, res):
    print(f"{i}: {desc} -> exit={res[0]} {res[1]}", flush=True)


r = mk("s0"); show("S0", "clean control", run(r, "verify"))
r = mk("s1"); os.remove(r + "/public/audio/b.mp3"); open(r + "/public/audio/.DS_Store", "w").write("x"); show("S1", "mid-part file gone, .DS_Store fills the count", run(r, "verify"))
r = mk("s2"); open(r + "/public/audio/d.mp3", "w").close(); show("S2", "last sentinel truncated to 0 bytes", run(r, "verify"))
r = mk("s3"); open(r + "/public/audio/b.mp3", "wb").write(b"XXXXXXXX"); show("S3", "content corrupted", run(r, "verify"))
r = mk("s4", write_media=False); show("S4a", "no media, no skip", run(r, "verify")); show("S4b", "no media, MEDIA_SKIP=1", run(r, "verify", MEDIA_SKIP="1"))
r = mk("s5"); os.remove(r + "/wrangler.cloudflare.jsonc"); show("S5a", "wrangler config absent, verify", run(r, "verify")); show("S5b", "same with MEDIA_SKIP=1", run(r, "verify", MEDIA_SKIP="1"))

base = list(FILES.items())
r = mk("s6a", base + [("package.json", b'{"name":"EVIL"}'), ("scripts/media-sync.mjs", b"//EVIL")], write_media=False)
show("S6a", "pinned part with members outside prefixes", run(r, "pull"))
print("    package.json =", open(r + "/package.json").read(), "| script overwritten =", open(r + "/scripts/media-sync.mjs").read().startswith("//EVIL"))
r = mk("s6b", base + [("../escape-rel.txt", b"E")], write_media=False); show("S6b", "../ member", run(r, "pull")); print("    escaped =", os.path.exists(os.path.join(SB, "escape-rel.txt")))
absp = os.path.join(SB, "escape-abs.txt")
r = mk("s6c", base + [(absp, b"E")], write_media=False); show("S6c", "absolute member", run(r, "pull")); print("    escaped =", os.path.exists(absp))
os.makedirs(SB + "/outside", exist_ok=True)
r = mk("s6d", base + [("public/audio/lnk", {"link": SB + "/outside"}), ("public/audio/lnk/through.txt", b"E")], write_media=False); show("S6d", "symlink then write through it", run(r, "pull"))
print("    wrote-through =", os.path.exists(SB + "/outside/through.txt"), "| symlink kept =", os.path.islink(r + "/public/audio/lnk"))
r = mk("s6e", base + [("public/audio/hosts-link", {"link": "/etc/hosts"})], write_media=False); show("S6e", "symlink to /etc/hosts into assets dir", run(r, "pull")); print("    symlink kept =", os.path.islink(r + "/public/audio/hosts-link"))

r = mk("s7"); open(r + "/public/audio/b.mp3", "wb").write(b"NEW-VERSION"); show("S7", "push after changing an existing file", run(r, "push")); print("    parts =", len(json.load(open(r + "/media-manifest.json"))["parts"]))
r = mk("s8"); open(r + "/public/audio/e.mp3", "wb").write(b"EEEE"); open(r + "/public/audio/.DS_Store", "wb").write(b"junk"); open(LOG, "w").close(); show("S8", "push new file with host tar", run(r, "push"))
m = json.load(open(r + "/media-manifest.json")); print("    stub =", open(LOG).read().strip()[:150], "| parts =", len(m["parts"]), "| last part =", m["parts"][-1]["first"], m["parts"][-1]["files"])

r = mk("s9", write_media=False); os.remove(r + "/.media-cache/part-0001-x.tar"); show("S9", "download returns garbage", run(r, "pull", STUB_MODE="garbage")); print("    cache left =", os.listdir(r + "/.media-cache"))
r = mk("s10", write_media=False); open(r + "/.media-cache/part-0001-x.tar", "ab").write(b"z"); show("S10", "poisoned cache plus garbage redownload", run(r, "pull", STUB_MODE="garbage")); print("    extracted =", os.path.exists(r + "/public/audio/a.mp3"))
r = mk("s11"); open(r + "/public/audio/b.mp3", "wb").write(b"LOCAL-EDIT"); open(r + "/public/audio/stale.mp3", "wb").write(b"S"); show("S11", "pull over a local edit and a stale extra", run(r, "pull")); print("    b =", open(r + "/public/audio/b.mp3").read(), "| stale kept =", os.path.exists(r + "/public/audio/stale.mp3"))
r = mk("s12", write_media=False); os.remove(r + "/.media-cache/part-0001-x.tar"); show("S12", "wrangler fails (no login)", run(r, "pull", STUB_MODE="fail"))
shutil.rmtree(SB)
