### Added

- The web app has a **Queue** page (`/queue`, beside Escalations in the
  menu): one dense list of what needs a person, soonest deadline first, built
  from the console v2 design (`docs/design/console-v2/`).
  - **More on one screen:** 22 rows at 1440 by 900 in the default density
    (25 in Dense), against 6 to 7 on the Escalations page. Three row
    densities (Dense, Compact, Two lines), remembered per user.
  - **Each row** shows the deadline (overdue and under ten minutes are marked
    in words), the severity as bars and a word, what the item is and why it
    needs a person, and what the analysis made of it so far.
  - **Views** are tabs with counts: Needs a person, Mine, Unassigned,
    Deadline under 15 min, Likely malicious. "Save view" keeps the current
    view, filters and density under a name, per user in the browser.
  - **Preview:** the highlighted row opens beside the list, which stays in
    view.
  - **Keyboard:** `J` and `K` move, `Enter` opens the item, `Space` shows or
    hides the preview, `X` selects, `C` claims.
  - **Bulk:** selected rows can be claimed together. Deciding several at once
    is offered only for look-alike alerts, which the API does not group yet,
    so the Look-alikes view stays hidden until it does.
  - The queue shows the tenant you are acting on. The Escalations page is
    unchanged.
