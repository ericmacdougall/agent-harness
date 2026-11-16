## Risks
- F1: a log that is truncated at its start, or rotated mid-request, now gives INCONCLUSIVE instead of PASS. That is intended: the operator re-reads a complete window.
- F2: a docker that reports a `null` DriverStatus (some drivers) now refuses the disk gate and pin. That fails closed; containerd stores always report the snapshotter.
- 73-F1: a compose that keeps JOB_IMAGE_* keys under the guard's environment through a list form (`- KEY=V`) is refused by job_lines, as before; only the mapping form is supported.
- The 1371 copy (bff96cc5) and the gate branch carry the same three bugs. The gate PR ports F1, F2 and 73-F1 onto them; it is sent separately.
- Nothing is merged or deployed.
