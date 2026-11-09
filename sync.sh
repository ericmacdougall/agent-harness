#!/bin/sh
# Push the working copy of the host repo to the t2-dev preview tree (~/mobile-ui). Run from the directory holding mobile-host.
set -e
SRC="$(dirname "$0")/mobile-host"
rsync -a "$SRC/videos.css" "$SRC/videos.mjs" t2-dev:mobile-ui/public/
# The staged videos.html carries the study-downloads line in place of the optional-downloads marker.
sed 's|<!-- optional-downloads -->|<p class="study-downloads"><a href="Implementation%20Guide.html">Read the implementation guide</a> · <a href="Implementation%20Lab.zip">Download the runnable implementation lab</a></p>|' "$SRC/videos.html" | ssh -o BatchMode=yes t2-dev 'cat > mobile-ui/public/videos.html.new && mv mobile-ui/public/videos.html.new mobile-ui/public/videos.html'
rsync -a "$SRC/videos.css" "$SRC/videos.mjs" "$SRC/videos.html" t2-dev:mobile-ui/
rsync -a "$SRC/test/" t2-dev:mobile-ui/test/
echo synced
