import sys, json, uuid
T = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/ticket-cleanup/'
sys.path.insert(0, T)
import gq
P = {p['slug']: p for p in json.load(open(T + 'projects.json'))}['goodqa']
desc = """Found while proving the t2-course media move to R2 (goodqa#14977), on t2-dev with `wrangler dev --local` at t2-course head 4cfa2843.

Observed: a Range request (bytes=0-1023 and a mid-file range) for public/audio/crash/cr-08-88f2a396...mp3 (9,133,706 bytes) returns 200 with the full body and no Content-Range. The same request against /engineering-videos/*.mp3 and *.mp4 (6-7 MB) returns 206 with correct Content-Range and bytes.

Cause (read from code, not yet confirmed by a patch): worker/public-media-ranges.mjs caps reads at MAX_BYTES = 8 MiB and wrangler.cloudflare.jsonc only sets run_worker_first for /engineering-videos/*, so /audio/* and /data-audio/* never pass through the range wrapper at all. Players that seek in long lesson audio get full downloads.

Expected: 206 for Range on every public audio and video path, for files above 8 MiB too (stream the slice instead of buffering).
Verify by: Range bytes=0-1023 and a mid-file range on a >8 MiB mp3 under /audio/crash return 206 with correct Content-Range and equal bytes.
Not caused by the R2 move; it predates it."""
r = gq.call('create_issue', dict(orgId=P['orgId'], projectId=P['id'], title='t2-course: Range requests return 200 for audio over 8 MiB and for /audio and /data-audio paths', description=desc, type='bug', priority='medium', labels=['t2-course', 'lessons'], operationId=str(uuid.uuid4())))
print(json.dumps({k: (r.get('issue') or r).get(k) for k in ('number', 'id', 'error')}))
