p = '../spec-15561-v4.md'
s = open(p).read()


def rep(old, new):
    global s
    assert s.count(old) == 1, (s.count(old), old[:70])
    s = s.replace(old, new)


rep("an ALLOWED polling read of the app, `DESKTOP_POLL_ROUTES` in `lib/desktop-token-session.ts`, takes the zero-write observation policy; a REFUSED poll is still written;",
    "a polling read of the app on `DESKTOP_POLL_ROUTES` in `lib/desktop-token-session.ts` is THROTTLED: it stays unwritten only while the same session, address and user agent already wrote within five minutes and it answers 2xx, so a first poll, a new address or agent (a stolen session) and any non-2xx write the row and the last-use update; a REFUSED poll is always written;")
rep("Exception: an allowed read on `DESKTOP_POLL_ROUTES` writes no row and no last-use update (measured:",
    "Exception: a 2xx read on `DESKTOP_POLL_ROUTES` by a session, address and user agent that already wrote within five minutes writes no row and no last-use update (measured:")
rep("only an ALLOWED poll on `DESKTOP_POLL_ROUTES` is quiet)",
    "only a 2xx poll on `DESKTOP_POLL_ROUTES` inside the five-minute same-session, same-address, same-user-agent window is quiet; a new address or user agent, or a non-2xx, is written)")
rep("Flipping it is one word in `BOUND_ALLOWED_CREATED_VIA`.",
    "A session bound to an operator token gets the base reads and the delegated CRM door but NO host waivers (W1-W3), so it reaches no machine route that the token is refused by bearer (second delta red-team F1). Flipping the kind list is one word in `BOUND_ALLOWED_CREATED_VIA`.")
open(p, 'w').write(s)
print('ok')
