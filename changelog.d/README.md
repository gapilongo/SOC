# Changelog fragments

Don't edit `CHANGELOG.md` in a pull request. Add one file here instead, so
parallel pull requests never conflict on the changelog.

- **Name:** the story ID or branch topic, e.g. `AI-E1.3.md` or
  `fix-login-redirect.md`.
- **Content:** one or more Keep a Changelog headings, each followed by
  bullets written for an operator:

  ```markdown
  ### Added

  - The investigation trace: every LLM and tool step of a run is stored and
    listed in the evidence pack.

  ### Security

  - The trace stores hashes and a redacted digest, never raw inputs.
  ```

- **Allowed headings:** `Added`, `Changed`, `Deprecated`, `Removed`,
  `Fixed`, `Security`. No other headings, and no text before the first one.

`python scripts/changelog.py check` validates the fragments; the deploy tests
run it. At release time, `python scripts/changelog.py fold` moves every
fragment into `## [Unreleased]` in `CHANGELOG.md` and deletes the files.
