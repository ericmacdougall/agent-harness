Why: The private video curriculum is hard to use on a phone (GoodQA #15486): the lesson list is 226 items below the lesson, the player scrolls away, links and chapter rows are 20-26 px tall, and a long title overflows sideways by thousands of pixels.

What:
- Phones (width up to 780 px, or short landscape): the lesson list is a bottom-sheet dialog opened from a bar that stays at the top with Lessons, Previous and Next. Filters collapse behind a "Filters: ..." summary. Opening the sheet locks and inerts the page; Escape, Close or the backdrop close it and focus returns to Lessons; the list keeps its scroll position; choosing a lesson closes it and scrolls to the player.
- The player is sticky and compact in portrait; the page scrolls as one with no nested scroll panes outside the sheet.
- Every control is at least 44 px; long titles wrap; safe-area insets are used (`viewport-fit=cover`).
- Desktop: same DOM order, styles and focus order (drawer wrappers are `display: contents`, bar hidden).
- No new external resources; Worker and auth untouched.

Testing:
- `test/mobile/mobile_check.py` (Playwright, t2-dev preview of the staged build, synthetic password): before 43 passed / 32 failed (exit 1); after 186 passed / 0 failed.
- `npm test`: 139 passed (136 existing + 3 new layout guards, including a seeded failing control).
- `python3 -m unittest discover -s test -p '*_test.py'`: 57 OK.
- Before/after screenshots: GoodQA #15486.

Refs: GoodQA #15486

Not deployed. Deploy, stage and live probe are owned by the lessons owner; click-test on a real mobile viewport is pending (independent tester).
