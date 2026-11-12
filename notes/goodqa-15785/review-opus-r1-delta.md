# Opus adversarial review, goodqa#15785 PR 221 receipt r1 delta (agent a0c568dfa08e7eb86)

At 3c2f6549: BLOCK. H1 (Medium, secret exposure): a recursive search with no path operand searches the working directory (cd ~/.config/goodqa && rg ., cd ~ && grep -r tok) and was not judged; M1 cpio fed by a pipe; M2 bsdtar, pax and gzip -rc not covered; M3 find piped to xargs. Fixed or stated at f7dcb5b7 (cwd judged, archive set and dispatch extended, limits stated).
At f7dcb5b7: ACCEPT (about 45 forms: cd forms, pushd, a bare cd, a variable target, a subshell, $(...), flags; the key directory; bsdtar, pax -w, gzip -rc, xz -c, zstd -c). Lows: L1 a piped GNU grep -r was exempt wrongly, L2 rg --files refused, L3 cd - unknown directory (stated limit). L1 and L2 fixed at 41a7c1e0 with tests and mutants.
Verdict: ACCEPT
