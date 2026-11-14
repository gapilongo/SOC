### Changed

- The Overview follows the console v2 design: flat, with rules instead of
  cards, and in a new order.
  - **Needs you now** comes first, one line and one action each: what you
    hold and its first deadline, the response actions your role may approve,
    what nobody has claimed, and the sampled AI closes waiting for a
    blind-audit label. An item opens its investigation view.
  - **Closed without a person** says in one sentence how many of the
    window's finished alerts no person touched and how many reached one,
    with a bar and the table it is drawn from.
  - **How the AI's closes are verified** shows the blind audit of the last
    30 days: closes eligible, sampled, labelled, and labelled malicious by
    an analyst who could not see the AI's verdict, with the missed-threat
    rate and its 95% interval once the sample carries one.
  - Then the next deadlines and, for admins, platform health.
- Every figure still says what it counts and over which window, and a share,
  a rate or a mean over too few observations is withheld in words. A figure
  the API does not report yet (who or what closed each alert, planted
  attacks, the safety net) reads "not measured yet" and shows no number.
- The severity strips and the six window tiles are gone from the Overview;
  alerts by status moved into platform health. Switching the window keeps
  the page on screen while the new figures load.
- On a phone the Overview's tables become stacked records, so nothing
  scrolls sideways.
