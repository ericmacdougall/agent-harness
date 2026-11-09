#!/bin/sh
# Push the nav-host working copy to the t2-dev preview tree ~/mobile-nav (public/ gets the staged videos.* files).
set -e
SRC="$(dirname "$0")/nav-host"
rsync -a "$SRC/videos.css" "$SRC/videos.mjs" t2-dev:mobile-nav/public/
sed 's|<!-- optional-downloads -->|<p class="study-downloads"><a href="Implementation%20Guide.html">Read the implementation guide</a> · <a href="Implementation%20Lab.zip">Download the runnable implementation lab</a></p>|' "$SRC/videos.html" | ssh -o BatchMode=yes t2-dev 'cat > mobile-nav/public/videos.html.new && mv mobile-nav/public/videos.html.new mobile-nav/public/videos.html'
rsync -a "$SRC/videos.css" "$SRC/videos.mjs" "$SRC/videos.html" t2-dev:mobile-nav/
rsync -a "$SRC/test/" t2-dev:mobile-nav/test/
echo synced
