### Added

- Release trains. Every Thursday, the head of `main` becomes a partner
  release candidate `vX.Y.Z-rc.N`, and the `:partner` image tags move to it.
  From Actions > *Release train*, a candidate is promoted to the stable
  `vX.Y.Z` and, if chosen, to the LTS channel (git tag `lts-X.Y`, image tags
  `:lts` and `:lts-X.Y`). A commit is tagged only when its CI passed,
  including the N-1 upgrade rehearsal and the install rehearsal, and when
  its images pass the same signature and provenance checks as a deploy.
  Channel tags only ever move to verified digests. Releases with a Security
  changelog entry say so in their GitHub release title. See
  docs/releases.md for the channels, cadence, support windows and backports,
  and for how to pin and verify a release.

### Changed

- CI now also rehearses the upgrade from the latest LTS release, when that
  is not the previous release: `scripts/ci/upgrade_rehearsal.sh --from lts`.
  The upgrade rehearsal's previous release is the latest `v*` tag, which can
  now be a release candidate.
- *Release images* and *Deploy* accept release-candidate tags
  (`vX.Y.Z-rc.N`). Their GitHub releases are created as pre-releases.
