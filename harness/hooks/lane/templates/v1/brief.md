# Brief for {{lane_id}}

Ticket: {{ticket}}
Branch: {{branch}}
Stream key: {{stream_key}}

Gates for this kit version:

- G1 briefed: a holder is bound and its plan checkpoint exists.
- G2 spec attached: a verified spec with both required reviews is on the ticket.
- G3 building: a confirmed pushed commit exists on the lane branch after G2.

Rules that always apply: write a plan checkpoint before editing; push the feature branch at least every 30 minutes;
post each checkpoint on the ticket; never put credentials in a command, note or ticket; the click-test runs on the
headed desktop instance and is recorded by someone who is not the author. This kit writes no review verdict,
evidence record, click-test result, sign-off or done state.
