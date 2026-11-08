"""Run in the t2-course checkout: apply the media-to-R2 change. usage: applymedia.py <manifest.json> <media-sync.mjs>"""
import json, sys, shutil, subprocess, re
man, sync = sys.argv[1], sys.argv[2]
shutil.copy(man, 'media-manifest.json')
shutil.copy(sync, 'scripts/media-sync.mjs')
p = json.load(open('package.json'))
sc = p['scripts']
new = {}
for k, v in sc.items():
    new[k] = v
    if k == 'install:ci':
        new['media:pull'] = 'node scripts/media-sync.mjs pull'
        new['media:verify'] = 'node scripts/media-sync.mjs verify'
        new['media:push'] = 'node scripts/media-sync.mjs push'
new['prebuild'] = 'node scripts/media-sync.mjs verify'
p['scripts'] = new
open('package.json', 'w').write(json.dumps(p, indent=2) + '\n')
g = open('.gitignore').read().rstrip('\n')
g += '\n\n# Course media lives in R2 (see media-manifest.json and DEPLOYMENT.md); restore with `npm run media:pull`\n/public/audio/\n/public/engineering-videos/\n/public/data-audio/\n/power-user/public/audio/\n/.media-cache/\n'
open('.gitignore', 'w').write(g)
d = open('DEPLOYMENT.md').read().rstrip('\n')
d += """

## Course media (R2)

Audio, HLS segments and engineering videos (about 6 GB, 38k files) are no longer stored in git. They live in the private R2 bucket `learnai-field-lab-media` as deterministic tar parts listed, with sha256, in `media-manifest.json`.

- Restore before building, testing or auditing: `npm run media:pull` (uses the logged-in `wrangler`; parts are cached in `.media-cache/` and verified by sha256).
- `npm run build` runs `media:verify` first and fails if media is missing, so a deploy cannot silently ship a site without audio. `MEDIA_SKIP=1` bypasses it only for builds that must not ship media.
- Adding or changing media: put the new files under the same prefixes, run `npm run media:push` (uploads a new part and appends it to the manifest), then commit `media-manifest.json`.
- Production still serves the media as Worker static assets built from the pulled files, so URLs and caching are unchanged.
"""
open('DEPLOYMENT.md', 'w').write(d + '\n')
for pre in ['public/audio/', 'public/engineering-videos/', 'public/data-audio/', 'power-user/public/audio/']:
    subprocess.run(['git', 'rm', '-r', '-q', '--cached', pre], check=True)
print('applied')
