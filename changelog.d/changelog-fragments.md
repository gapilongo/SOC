### Changed

- Pull requests now add a changelog fragment in `changelog.d/` instead of
  editing `CHANGELOG.md`, so parallel pull requests no longer conflict.
  `python scripts/changelog.py fold` moves the fragments into the changelog at
  release time; `check` validates them.
