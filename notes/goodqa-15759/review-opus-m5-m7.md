# Opus adversarial review, goodqa#15759 at 126aa692 (agent a0c568dfa08e7eb86)

Read-only: unit suite plus about 70 extra forms through check().
M5 (cluster-final value flags, unknown long options), M6 (host: is the home) and M7 (scp -r proj host:~/ allowed) fixed. Remote paths under other homes, ~user, quoting, globs, braces, url forms and directory copies into the hooks directory stay refused; downloads, /tmp, .claudex and real value flags stay allowed.
Lows (ticket tc-e781904934c29ed0fa07a389c1770427): L8 scp trailing slash, L9 rsync d/ to home unprobed, L10 remote-looking option value. Stated limits: t2-dev:$D allowed, sftp heredoc not seen.
Verdict: ACCEPT
