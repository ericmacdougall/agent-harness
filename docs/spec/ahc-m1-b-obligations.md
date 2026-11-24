# ahc M-1 slice (b) obligations

Slice (b) must meet these obligations before it closes. They were ruled onto it during slice (a) review
(goodqa#16049, goodqa#16204). Each line names the test that proves it, as `OBL.<test id>`. The id resolves like
a spec test id: an exact test name, or the name plus a `_suffix`, in any `tests/test_ahc*.py` class.
`StateMachineTests.test_every_slice_b_obligation_resolves_or_is_pinned` keeps the unresolved ids pinned in
`PENDING_B`, so the list can only shrink: removing a line here, or dropping a pin before its test exists, fails
that test.

| Obligation | Source | Test |
|---|---|---|
| The review scheduler skips a row whose item is terminal or merged, so it never takes an attempt slot or loops on the start_attempt refusal. Over N scheduler ticks, no attempt is made. A variant that drops the filter fails. | spec owner ruling on goodqa#16204, item 2 | OBL.test_b_scheduler_skips_rows_of_a_finished_item |
| Status and the digest show such a row as "inert: item <state>", not as queued. | spec owner ruling on goodqa#16204, item 3 | OBL.test_b_status_and_digest_show_inert_rows |
| The findings result producer writes the receipt's `finding_ids` list (a list of non-empty strings), which W3's escalation names. Without it, W3 records "finding ids missing". | spec owner ruling on goodqa#16204, item 4 (the W3 assumption) | OBL.test_b_findings_producer_writes_finding_ids |

Spec amendment note: R12, or a new row, should name W20 as a successor-less end for a cancelled item's required
and queued rows. Until then the code follows the ruling above: such rows stay as they are and are inert, and
start_attempt refuses them. No table edge is added in slice (a).
