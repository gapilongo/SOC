### Changed

- The whole console takes the look of the console v2 design
  (`docs/design/console-v2`), on every page at once:
  - **A flat sheet.** Content sits on the page and hairlines carry the
    structure; sections have a title over a rule and no box. The dark theme
    is graphite, not black. Corners are 3 px on controls and 2 px on tags.
  - **Denser lists.** A row is 28 px by default (it was 44 px) and 44 px with
    "Comfortable rows" (it was 56 px), so the alert list shows about half as
    many rows again on a screen. Buttons and fields are 28 px high, 24 px
    inside a table row, and still grow to 44 px on touch screens.
  - **Severity is four bars and the word**, critical and high in bold; it was
    a coloured square. A state is a mark whose shape says what kind it is
    (waiting, waiting for approval, running, done, failed) and the state in
    words; it was a grey pill with a coloured dot.
  - **Labels read as sentences.** A status such as `waiting_human` reads
    "Waiting human", not "Waiting Human", and a label such as "Needs your
    input" keeps its own capitals. The words are written by the app, not
    title-cased by the stylesheet, so a screen reader and a copy get the same
    text as the screen.
  - **Column headings and section labels** are small monospace capitals; what
    a tool returned (JSON, an observation) is monospace on a recessed surface
    with a double rule on its left.
  - Segmented choices and pressed toggles are inverted (dark on light, light
    on dark); the selected tab is underlined in the text colour; notices sit
    on a tint; toasts appear at the bottom centre.
- **The theme follows your system setting by default.** It was dark by
  default. Your own choice (System, Light or Dark, in the header) is
  remembered as before, so nothing changes for anyone who already chose one.
- The accent, link, focus and selection colours are now read from one brand
  block of the design tokens; their default values are unchanged.
- For developers of the web app: `src/lg_front/src/theme/tokens.css` now holds the type scale, the radii,
  the control heights and the row densities next to the colours, and
  `npm run lint` refuses a raw hex colour or an arbitrary size utility
  (`h-[34px]`, `text-[13.5px]`, `rounded-[3px]`) in the web app. Two files of
  the layout shell are exempt from the size rule until the new shell
  replaces them.
