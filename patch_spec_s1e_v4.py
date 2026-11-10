p = 'spec-15561-s1e.md'
s = open(p).read()


def sub(old, new):
    global s
    assert s.count(old) == 1, (s.count(old), old[:70])
    s = s.replace(old, new)


sub("No settings screen is built here (a ticket follows); the override is an entitlement-override key read directly from the org row (no registration needed) and is set by a platform operator through the existing override mechanism; an org admin cannot yet set it themselves (a stated limit).",
    "TARGET_MISMATCH (stated): no org-admin control exists yet. The key is read directly from the org row; the org entitlement route rejects unknown keys, so only a platform operator (admin org update route or a database write) can set it today. An org-admin route mirroring the session-actions opt-in is a follow-up ticket. Until then the \"default with an org-level off switch\" reading is delivered for platform operators only.")
sub("D6. Controls:", """D7. Hidden-match oracle closed (red-team N1, confirmed by a live probe): withholding runs after paging, so for a desktop-session reader `q` and `pinned` on the contact timeline are refused (400 `user_token_filter_unsupported`) and `nextCursor` (and the contact detail's `timelineNextCursor`) is derived from the last entry the reader can see, null when a page shows none (a stated limit: a page that is entirely withheld ends paging). Signed-in persons and bearer session actions keep today's behaviour (the same personal/busy_only oracle exists there today and gets its own ticket). Source: ticket:GoodQA goodqa#15561
D6. Controls:""")
sub("## Resource budget", """- NEG-13 (AC-4): for a bound session, `q` and `pinned` on the contact timeline answer 400 `user_token_filter_unsupported` and never echo a withheld entry's id; with a colleague's `personal` entry as the newest row and `limit=1`, the page has no entry, `nextCursor` is null, and neither the timeline nor the contact detail contains that entry's id or its timestamp; the colleague's own signed-in session still finds it with `q`. Source: ticket:GoodQA goodqa#15561

## Resource budget""")
sub("a stated limit).\n- NEG-12", "a stated limit).\n- NEG-12") if False else None
open(p, 'w').write(s)
print('ok')
