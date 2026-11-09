#!/bin/bash
# on t2-dev. PREP ONLY, no push. fresh mirror -> N1 name check -> filter-repo -> secret scan -> build the rebased branch. Stops (exit 3) on any N1 hit.
set -u
W=/home/eric/gq-branch-clean/tcr; mkdir -p $W; cd $W
rm -rf mirror.git work;
git clone --mirror -q git@github.com:ericmacdougall/t2-course.git mirror.git || { echo CLONE_FAILED; exit 1; }
OLDMAIN=$(git -C mirror.git rev-parse main); echo "OLD_MAIN $OLDMAIN"
[ "$OLDMAIN" = "c68f57e5a8fa0a956da720e876b4ad3d002fd365" ] || { echo "MAIN_MOVED: expected c68f57e5, stopping"; exit 2; }
echo "--- N1 name check over every file under the four media prefixes at main"
git -C mirror.git ls-tree -r --name-only -z main | python3 -I -c '
import sys
P=("public/audio/","public/engineering-videos/","public/data-audio/","power-user/public/audio/")
names=[n for n in sys.stdin.buffer.read().split(b"\0") if n]
media=[n for n in names if n.decode("utf-8","replace").startswith(P)]
bad=[n for n in media if any(c==0x5c or c<0x20 or c==0x7f or c>0x7e for c in n)]
print("total files",len(names),"media files",len(media),"N1 hits",len(bad))
for n in bad[:10]: print("  HIT",repr(n))
sys.exit(3 if bad else 0)' || { echo "N1_HITS_STOPPING"; exit 3; }
echo "--- size before"; du -sh mirror.git | cut -f1; git -C mirror.git count-objects -vH | grep size-pack
echo "--- filter-repo"
python3 /home/eric/gq-size/git-filter-repo --version 2>&1 | head -1
cd mirror.git
python3 /home/eric/gq-size/git-filter-repo --invert-paths --path public/audio/ --path public/engineering-videos/ --path public/data-audio/ --path power-user/public/audio/ --force 2>&1 | tail -3
git gc --prune=now -q
cd ..
echo "--- size after"; du -sh mirror.git | cut -f1; git -C mirror.git count-objects -vH | grep size-pack
git -C mirror.git for-each-ref refs/heads refs/tags --format='%(refname) %(objectname)'
NEWMAIN=$(git -C mirror.git rev-parse main); echo "NEW_MAIN $NEWMAIN"
echo "--- media still in any head/tag tip?"
for r in $(git -C mirror.git for-each-ref refs/heads refs/tags --format='%(refname)'); do echo "$r media_files=$(git -C mirror.git ls-tree -r --name-only $r | grep -cE '^(public/audio/|public/engineering-videos/|public/data-audio/|power-user/public/audio/)')"; done
echo "--- secret scan (patterns only, matched text is never printed)"
PATS='AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----|ghp_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|sk-[A-Za-z0-9]{32,}|xox[baprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{35}|re_[A-Za-z0-9]{20,}|eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}|CLOUDFLARE_API_TOKEN\s*=\s*[A-Za-z0-9_-]{20,}|RESEND_API_KEY\s*=\s*re_'
cd mirror.git
hits=0
for rev in $(git rev-list main --first-parent | head -400); do
  n=$(git grep -I -l -E "$PATS" $rev -- . ':!package-lock.json' 2>/dev/null | wc -l); hits=$((hits+n))
  [ "$n" -gt 0 ] && git grep -I -l -E "$PATS" $rev -- . ':!package-lock.json' 2>/dev/null | head -3 | sed "s/^/  FILE@/"
done
echo "SECRET_SCAN revisions_scanned=$(git rev-list main --first-parent | head -400 | wc -l) files_with_hits=$hits"
cd ..
echo "--- rebased branch build"
git clone -q mirror.git work 2>&1 | tail -1
cd work
git checkout -q -b chore/media-to-r2-v2 origin/chore/media-to-r2 2>&1 | tail -1
git log --oneline -3
df -h / | tail -1
echo PREP_DONE
