## Risks
- The threshold is now in bytes, so more values get window checks: any value of at least 8 UTF-8 bytes. A short non-ASCII base value (for example 3 CJK characters, 9 bytes) can now drop an allow-listed line to the category-only head. That fails closed: the message loses its line, never gains a value.
- The scan cost is unchanged in kind: SCAN_LIMIT 4096 still bounds the line (F4).
- Nothing is merged or deployed.
