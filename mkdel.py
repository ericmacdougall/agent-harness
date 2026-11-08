import sys
# usage: mkdel.py <repo> <keep-comma-list>  -> del-<repo>.txt  (branch sha), from c-<repo>.tsv, minus keepers
repo = sys.argv[1]
keep = set(sys.argv[2].split(',')) | {"main", "master"}
rows = [l.rstrip('\n').split('\t') for l in open(f'c-{repo}.tsv')]
d = [(r[0], r[1]) for r in rows if r[0] not in keep]
open(f'del-{repo}.txt', 'w').write(''.join(f"{b} {s}\n" for b, s in d))
print(len(d), 'to delete;', len(rows) - len(d), 'kept (plus default branch)')
