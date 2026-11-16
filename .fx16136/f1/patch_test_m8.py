"""Add the unreadable-process tests (mutants M8 and M9): the holder is readable, ANOTHER process of the socket owner is
not. As root that must refuse; skipping it (the unprivileged rule) would return the holder's root. Usage: <file>"""
import sys

p = sys.argv[1]
t = open(p).read()
new = '''def test_f1_unreadable_process_refuses_as_root(F1, monkeypatch):
    # on the VM the ctl is root: the holder is readable, but another process of the socket owner is not, and it might
    # hold the socket too, so the gate refuses instead of trusting the one holder it could see
    F1.ctd('ctd.sock', ['--root', str(F1.st / 'containerd-root')]); F1.put('ctd-address', F1.sock('ctd.sock'))
    other = F1.run('other', None, [])
    assert F1.measured() == F1.root()                       # unprivileged: the hidden process does not change the answer
    real = os.listdir

    def listdir(d):
        if str(d) == '/proc/%d/fd' % other.pid: raise PermissionError(13, 'denied')
        return real(d)
    monkeypatch.setattr(F1.M.os, 'listdir', listdir); monkeypatch.setattr(F1.M.os, 'geteuid', lambda: 0)
    _refused(F1, 'cannot inspect process ')               # `other`, or any other unreadable process of this owner


def test_f1_unreadable_processes_without_a_holder_refuse_unprivileged(F1, monkeypatch):
    # unprivileged (the test suite) a process that cannot be read is skipped, but if no readable process holds the
    # socket, the gate refuses instead of guessing
    F1.ctd('ctd.sock', ['--root', str(F1.st / 'containerd-root')]); F1.put('ctd-address', F1.sock('ctd.sock'))
    real = os.listdir

    def listdir(d):
        if str(d).startswith('/proc/') and str(d).endswith('/fd'): raise PermissionError(13, 'denied')
        return real(d)
    monkeypatch.setattr(F1.M.os, 'listdir', listdir); monkeypatch.setattr(F1.M.os, 'geteuid', lambda: 1000)
    _refused(F1, 'no holder of')
'''
assert 'def test_f1_unreadable' not in t
t = t.rstrip('\n') + '\n\n\n' + new
open(p, 'w').write(t)
print('patched', p)
