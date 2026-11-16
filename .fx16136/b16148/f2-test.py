"""goodqa#16148 code review F2: both derive swap tests assert what is left at the target. Run in infra/selfhost/app."""
p = 'test_derive_job_secrets.py'
s = open(p).read()
old_link = """        word, code = self.h.run(hooks={'before_rename': swap})
        self.assertEqual((word, code), ('REFUSED the secret file changed during the write', 2))
        self.assertEqual(self.h.sentinel_state(), before)
        self.assertEqual(self.h.run()[1], 2)  # the link at the target is refused next time too
"""
new_link = """        word, code = self.h.run(hooks={'before_rename': swap})
        self.assertEqual((word, code), ('REFUSED the secret file changed during the write', 2))
        self.assertEqual(self.h.sentinel_state(), before)
        # F2: the swapped-in link is not left as the live secret; the dispatcher fails closed as missing.
        self.assertFalse(os.path.lexists(self.h.secret()))
        self.assertEqual(self.h.run(), ('written', 0))  # the next run writes the real file
        self.assert_file_ok(MARKER)
"""
old_hard = """        self.assertEqual(self.h.run(hooks={'before_rename': swap}), ('REFUSED the secret file changed during the write', 2))
        self.assertEqual(open(other, 'rb').read(), b'other-bytes')
"""
new_hard = """        self.assertEqual(self.h.run(hooks={'before_rename': swap}), ('REFUSED the secret file changed during the write', 2))
        self.assertEqual(open(other, 'rb').read(), b'other-bytes')
        # F2: the foreign inode is not left at the target name.
        self.assertFalse(os.path.lexists(self.h.secret()))
"""
for o, n in ((old_link, new_link), (old_hard, new_hard)):
    assert s.count(o) == 1, o
    s = s.replace(o, n)
open(p, 'w').write(s)

# F2 source fix (applied by f2-fix.py separately, so the tests can fail first).
print('tests patched')
