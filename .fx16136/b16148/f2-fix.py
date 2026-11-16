"""goodqa#16148 code review F2: on a post-rename mismatch, remove NAME so it fails closed. Run in infra/selfhost/app."""
p = 'derive-job-secrets.py'
s = open(p).read()
old = """        if not _is_reg(now.st_mode) or (now.st_dev, now.st_ino) != (own.st_dev, own.st_ino):
            raise Refused('the secret file changed during the write')
"""
new = """        if not _is_reg(now.st_mode) or (now.st_dev, now.st_ino) != (own.st_dev, own.st_ino):
            # The rename already put the foreign file or link at NAME: remove that name (never what it points
            # to), so the dispatcher sees the key as missing instead of using it (code review F2).
            try:
                os.unlink(NAME, dir_fd=dfd)
            except FileNotFoundError:
                pass
            raise Refused('the secret file changed during the write')
"""
assert s.count(old) == 1
s = s.replace(old, new)
open(p, 'w').write(s)
print('source patched')
