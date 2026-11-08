Moves 38,218 media files (6.23 GB) out of git into R2 bucket learnai-field-lab-media as 25 sha256-pinned tar parts listed in media-manifest.json.

Changes: scripts/media-sync.mjs (pull, verify, push), prebuild runs media:verify, media paths gitignored and removed from the index, DEPLOYMENT.md section.

Proof on t2-dev at head 4cfa2843:
- npm ci, then media:pull restored 38,218 files, byte-identical to the originals (diff -r, no differences)
- npm run build exit 0 (prebuild printed "media ok: 38218 files")
- wrangler dev --local: full 200 and Range 206 with correct Content-Range and bytes for an mp3 and an mp4 under /engineering-videos
- Note: a 9.1 MB crash mp3 under /audio/crash returns 200 for Range requests. The existing range worker caps at 8 MiB and covers /engineering-videos only; that behaviour predates this change.

Not part of this PR: the history rewrite that actually shrinks the repo. It lands in the freeze window together with this merge; collaborators must re-clone.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
