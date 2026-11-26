### Changed

- CI on a pull request is faster and says only what matters. Nothing a
  release is gated on changed: a push to `main` still runs every job, and the
  release train reads the same gates.
  - The whole test suite on four workers is now the backend gate of a pull
    request. The serial run with coverage no longer runs there; it runs on
    every push to `main`, on the weekly schedule and on a manual run, and is
    still a release gate. The coverage floors are therefore checked after the
    merge.
  - A pull request skips the jobs its change cannot affect. A change of
    prose only (`docs/`, `changelog.d/`, top-level Markdown) skips the
    backend suites, the image builds and the browser suite; a change of the
    web UI only skips the backend suites; anything else runs everything.
    `python3 scripts/ci/changed_areas.py <paths>` shows what a change runs
    (docs/testing.md, "What a pull request runs").
  - Advisory jobs (the parallel and serial comparison, the Wazuh live
    contract tests, the Claude review) report a warning on a green check
    instead of a red one. A green pull request page means it can merge.

### Security

- The image CVE gate (Trivy, fixable critical and high) still blocks on every
  push to `main` and so for every release. On a pull request it now blocks
  only when the pull request changes an image input (a Dockerfile, a lock
  file, `.trivyignore`, a workflow); on any other pull request the same scan
  reports its findings as a warning. A CVE published overnight no longer
  blocks pull requests that cannot fix it; `main` stays red, with no new
  image and no release, until the fix merges (docs/security.md, section 9).

### Fixed

- The search field (Ctrl+K) keeps the keyboard focus when it is opened right
  after a click on a link. The page of the link could arrive a moment later
  and take the focus out of the open dialog, so typing went nowhere until the
  field was clicked. A navigation no longer moves the focus while a dialog is
  open.
- Tests that capture log events no longer fail depending on which tests ran
  before them in the same process. Logging configured by one test (the CLI
  entry points configure it) left module loggers bound to that test's
  configuration, and a later capture saw no event; this failed the parallel
  run on `test_every_llm_call_records_prompt_hash_and_model_id` and on two
  trace tests. The suite now isolates logging around every test.
- The test of the escalation grouping lock counted advisory locks in the
  whole PostgreSQL cluster, so it failed when another parallel worker held
  the same lock in its own database. It now counts its own database's locks.
