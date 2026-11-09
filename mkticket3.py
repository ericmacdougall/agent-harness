import sys, json, uuid
T = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/ticket-cleanup/'
sys.path.insert(0, T)
import gq
P = {p['slug']: p for p in json.load(open(T + 'projects.json'))}['goodqa']
desc = """Non-material findings F7-F14 from the independent red-team pass on t2-course branch chore/media-to-r2 (media moved to R2, goodqa#14977). The material ones (F1-F4) are fixed at head 91d65011; F5 is handled separately before the history rewrite.

Status of each against the current scripts/media-sync.mjs:
- F6 (a sha-pinned part could overwrite non-media files, symlinks kept): FIXED in 91d65011 (pull rejects non-regular members and members outside the media prefixes).
- F7: `push` has no recorded proof on GNU tar and fails on macOS bsdtar (--mtime=@0 unsupported). Open: add a GNU-tar test of push and fail early on bsdtar.
- F8: `push` picks up junk under the media prefixes (.DS_Store etc.). Open: allow only known media extensions.
- F9: parallel pushes from two branches collide on the same part index and totals. It fails closed. Open: compute totals from the parts and fail on duplicate paths.
- F10: FIXED (the new part now stays in the cache under its key name).
- F11: no part-size split in `push`; wrangler may reject a very large single part (not checked). Open: split at about 250 MB.
- F12: no disk preflight (cache plus extracted media is about 12.5 GB). Partly fixed: pull now removes each part after extracting unless MEDIA_KEEP_CACHE=1. Open: free-space check up front.
- F13: verify reads the wrangler config eagerly. FIXED (read lazily for pull and push only).
- F14: npx may auto-install wrangler. FIXED (--no-install).
Also open: tar listing parser in listPart is written for GNU tar output and will not parse bsdtar output (found while attempting a macOS run).
Verify by: run media-sync push against a part with a changed file, a junk file, and two parallel branches, on GNU tar, and check each is refused or merged as described."""
r = gq.call('create_issue', dict(orgId=P['orgId'], projectId=P['id'], title='t2-course media-sync follow-ups F7-F14 (push hardening, disk preflight, bsdtar)', description=desc, type='task', priority='low', labels=['t2-course', 'lessons'], operationId=str(uuid.uuid4())))
print(json.dumps({k: (r.get('issue') or r).get(k) for k in ('number', 'id', 'error')}))
