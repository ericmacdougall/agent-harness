p = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/agent-aaef3bc78b40c0c22/spec-15561-v4.1.md'
s = open(p).read()
old = "- AC-16 with the platform switch"
assert s.count(old) == 1
s = s.replace(old, "- The AC-12 sign-in (a token without `machines`) removes the mini's machine and remote-session routes for as long as it is signed in (D6, NEG-20), whatever kind the previous token was: the live proof therefore runs as a separate desktop sign-in that is not the mini's working session, or re-signing the mini in with its working token afterwards is a registered human step (it joins ask wc27c825f054).\n" + old)
open(p, 'w').write(s)
print('ok')
