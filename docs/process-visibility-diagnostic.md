# Process visibility diagnostic prototype

This standalone Linux prototype reports `RELATED` for a stable direct filesystem
object match and `UNKNOWN` otherwise. Every result has `diagnostic_only: true`
and `clearance: false`. It is not registered by an installer, consumed by the
command guard, or accepted as permission for retirement. Do not feed its output
to a remover or reinterpret an unmatched reference as idle clearance.

The request contains one exact target and at most nine PID:start tuples already
identified as unreadable by a normal same-account scan. The prototype validates
all four kernel UID fields and snapshots process identity before and after its
observation. It inventories source metadata without reading file contents,
following links, or crossing filesystems. A direct device/inode match through
a bind alias can establish use; unmatched, deleted, foreign, partial or
unsupported relationships never establish non-use. It does not prove all
processes have been enumerated, map arbitrary namespaces, or close the race
against a new noncooperating writer.

Limits are 20,000 source identities, 32 directory levels, 512 references per
process and a five-second cooperative observation budget. The entry envelope
allows a previously observed approximately 11,000-file tree plus directory
metadata, with a conservative 32 MB Python metadata envelope; this is not a
measured performance guarantee. Caps report incomplete evidence. Blocking kernel
operations are not hard-cancelled. No broad fleet scan is performed. The source
object count, reference count and completeness are reported without raw paths,
file contents, command lines, environment values or FD names.

## Deployment plan; not an installation instruction

Privileged execution is blocked until two independent reviews of the exact
source and deployment plan pass. An existing administrative route is a
prerequisite, not permission to run unreviewed code. No new sudoers privilege is
required or created by this prototype.

The reviewed plan installs exact bytes as root-owned0644 at the fixed path
`/usr/local/lib/agent-harness/process-visibility.py`, under protected root-owned
parents. The helper and its parents must not be writable by the caller. Invoke
the exact protected `/usr/bin/python3.12` with `-I -S -B`, fixed arguments, cwd
`/` and a clean fixed environment, retaining only the native sudo caller fields
needed for account validation. Never run a user-writable script or arbitrary
Python module as root. Verify the exact interpreter and all loaded dependencies,
including native loader/shared-library ownership and hashes as applicable, by
an independent installation readback. Runtime module-path ownership checks
alone are not full native dependency-integrity proof.

An administrator provisions the fixed root-owned0600 single-link file
`/usr/local/lib/agent-harness/process-visibility.json`. It is not shipped with
account-specific data and cannot be selected through an argument or environment.
Its exact schema is `v`, `caller_uid`, `caller_name`, and `targets`, where targets
maps reviewed canonical nonhidden paths under that account's `/home` to pinned
`[device, inode]` pairs. No paths, numeric account identities or cloud names from
an operator's environment belong in the public source. The helper opens and pins
the target itself; caller-supplied paths and PID tuples do not grant authority.
Missing, writable, linked, malformed or oversized policy refuses. The actual
sudo caller must match the reviewed account. No account credential is needed.

Keep previous installed bytes and the private provisioning manifest. Upgrade
only through the same reviewed administration route with fresh hash, owner,
mode and dependency readback. A disposable real Linux metadata canary is a
separate deployment phase; it may legitimately return UNKNOWN. Any future
guard consumer requires its own plan, failure-first tests and independent
security review. Offline fixtures are not a live or privileged canary.
