#!/bin/bash
# on t2-dev. Deletes hidden refs (archive/backup/gorunner) that are >=14 days old AND present with identical sha in the verified full-mirror bundle refs list.
cd ~/gq-branch-clean/bt
cut=$(( $(date +%s) - 14*86400 ))
git -C bugtracker.git for-each-ref --format='%(refname) %(objectname) %(committerdate:unix)' refs/archive refs/backup refs/gorunner > hid-all.txt
awk -v c=$cut '$3<=c{print $1" "$2}' hid-all.txt | sort > hid-old.txt
awk '{print $2" "$1}' refs-bugtracker-0035.txt | sort > /dev/null
# keep only refs whose exact "sha ref" appears in the bundle refs list
awk '{print $1" "$2}' refs-bugtracker-0035.txt | sort > bundle-sharef.txt
awk '{print $2" "$1}' hid-old.txt | sort > hid-old-sharef.txt
comm -12 bundle-sharef.txt hid-old-sharef.txt | awk '{print $2" "$1}' > hid-del.txt
echo "hidden total $(wc -l < hid-all.txt), old $(wc -l < hid-old.txt), deletable-and-backed-up $(wc -l < hid-del.txt)"
