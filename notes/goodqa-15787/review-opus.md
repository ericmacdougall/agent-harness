# Opus adversarial review, goodqa#15787 (agent a0c568dfa08e7eb86)

At d2581f46: BLOCK. FP1 (-A or -u with an explicit path was flagged), G1 (--gpg-sign consumed the next word and hid -a), G2 (a commit with a whole-tree pathspec), G3 (exclusion-only pathspec list), G4 (whole-tree magic forms), G5 (--no-ignore-removal), G6 (an alias that nests git inside sh -c). All fixed at bed8f968 with tests that failed first.
At bed8f968: ACCEPT (static read; the isolation guard refused probes containing git text). Lows, ticketed: L1 match-all globs other than * and ** ('**/*', '*/', '?*'), L2 magic plus . (':(icase).', ':(glob).'), L3 the ! alias search misses global options with a separate value (--work-tree DIR, --git-dir DIR, -p, -P), L4 the abbreviations --n and --no match --no-ignore-removal (negligible). Stated limits: opaque ! scripts, persistent aliases, --pathspec-from-file, $VAR paths, separate-git-dir.
Verdict: ACCEPT
