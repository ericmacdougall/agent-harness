
## Risks
- F4: the residue scan now sees only the first 4096 chars of the redacted line. That is safe because the output is at most the first 200 chars of that same line, and those 200 are scanned again.
- F2: a root attacker who re-swaps between the stat and the unlink can make the unlink remove a different name. Only root can stage this; the directory is root 0711 and its parent is root-owned. Either way the result fails closed: no secret at the name.
- F3: the boolean set (d, i, t, P) follows docker run's shorthand flags. A future boolean shorthand would end the chain early and could miss an e after it. The dispatcher builds its own argv, and AC-1 is enforced in code.
- Not fixed here, ticketed: goodqa#16195 (F1, write order; a spec change) and goodqa#16196 (F5, CI wiring for the root-only tests).
- Nothing is merged or deployed.
