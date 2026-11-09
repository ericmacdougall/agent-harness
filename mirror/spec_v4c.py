import re
p = '../spec-15561-v4.md'
s = open(p).read()
m = re.search(r"and `operator` and `pairing` are refused unless S0 finds that the token the live desktop uses has one of them \(then main decides, Q9; refusing is the safe default but would end that desktop's session on deploy\)", s)
assert m
s = s.replace(m.group(0), "and `pairing` are refused; `operator` is ADMITTED (the Q9 deviation in the decisions block, which is the one statement of this rule: the operator script mints it with `desktop_signin`, and refusing it could end the live desktop's session)")
old = "preset half gated on Q2"
assert s.count(old) == 1
s = s.replace(old, "Q2 is answered yes")
m = re.search(r"If main says no, AC-9 becomes \"unchanged\"[^.]*\.", s)
assert m, 'q2 body'
s = s.replace(m.group(0), "Main answered yes, so AC-9, the presets and the D6 requirement stand as written.")
open(p, 'w').write(s)
print('ok')
