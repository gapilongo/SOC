# Releases and channels

LG-SOTF ships on release trains. Every week, the head of `main` becomes a
partner release candidate. Once a month, a candidate that has run on the
partner channel is promoted to a stable release, which is also the new LTS
release. Security fixes do not wait for either train.

Nothing is built for a release. A release tag points at the commit whose
images `main` already built, signed and attested (see
[security.md](security.md#9-supply-chain-and-build)). A channel tag moves
only to digests that pass the same signature and provenance checks as a
deploy.

## Channels

| Channel | Git tag | Image tags | Cadence | For |
|---|---|---|---|---|
| **Partner** | `vX.Y.Z-rc.N` | `:vX.Y.Z-rc.N`, moving `:partner` | Weekly, Thursday 09:00 UTC | Design partners and evaluation installs that want each week's work |
| **Stable** | `vX.Y.Z` | `:vX.Y.Z` | When a candidate is promoted, usually monthly | Production |
| **LTS** | moving `lts-X.Y` | moving `:lts` and `:lts-X.Y` | Monthly: the promoted release, when it becomes the LTS release | Production installs that upgrade monthly or less often |
| **Security** | `vX.Y.Z-rc.N`, then `vX.Y.Z` | as above | Out of band, within the patch SLA | Everyone: see [Security-relevant releases](#security-relevant-releases) |

`vX.Y.Z` and `vX.Y.Z-rc.N` tags never move. `lts-X.Y`, `:partner`, `:lts`
and `:lts-X.Y` move, and only forward. `sha-<7 hex>` and `main` image tags
are `main` builds: they are deployed to dev, but they are not releases.

`__version__` in `src/lg_sotf/__init__.py` on `main` is the version that the
next train ships. While `vX.Y.Z` is not released yet, each weekly train is
the next `vX.Y.Z-rc.N`. When `vX.Y.Z` is released, the weekly train stops
with a notice until a pull request bumps `__version__`. That bump opens the
next train, and it is also when `python scripts/changelog.py fold` moves
the fragments into `CHANGELOG.md`.

## What every release has passed

The **Release train** workflow (`.github/workflows/release-train.yml`) tags
a commit only when all of the following are true:

1. Its CI run on `main` succeeded. That includes these jobs:
   * the upgrade rehearsal (`scripts/ci/upgrade_rehearsal.sh`). Runs that
     the previous release (N-1, the latest `v*` tag, a candidate included)
     left waiting must resume and close after the migration. The rehearsal
     runs again from the latest LTS release when that is not N-1.
   * the full test suite, which includes the install rehearsal
     (`tests/integration/e2e/test_first_run.py`): from an empty database
     to the first triaged alert through the setup wizard.
   * the image job: the CVE gate and the stack smoke test on the built
     image.
2. The *Release images* run that built its images succeeded.
3. Both image digests are built from that commit and pass `cosign verify`
   and `gh attestation verify`. The signer identity and issuer are exact,
   the same ones that `deploy.yml` requires.

Then it creates the tag and its GitHub release. A candidate is created as a
pre-release, and a security-relevant release says so in its title. The
workflow then starts *Release images* on the tag. *Release images* points
`:vX.Y.Z[-rc.N]` at the same digests, attaches the attested SBOMs and the
VEX document, and deploys uat. Last, the workflow moves the channel tags.

## Running the trains

* **Weekly partner train:** runs on its own every Thursday. To run it at
  another time, go to Actions > *Release train* > Run workflow and leave
  `promote` empty. If a gate fails, the run is red, nothing is tagged, and
  the log names the failed gate.
* **Promote a candidate:** Run workflow with `promote` set to
  `vX.Y.Z-rc.N`. This creates the stable `vX.Y.Z` on the candidate's
  commit, even if `main` has moved on. Tick `lts` to make it the LTS release
  too. The candidate's commit must still pass every gate, and
  `__version__` there must be `X.Y.Z`. Promote a candidate that has been
  on the partner channel for at least a week with no open release blocker.
  A security release can be promoted sooner (see below).
* **Pushing a tag by hand** still works: `git push origin vX.Y.Z` takes the
  same *Release images* path (docs/cicd.md, section 10). It does not check
  the gates or move any channel, so use the workflow.

Set up once, in the repository settings:

* Settings > Environments > `release`: under *Deployment branches and tags*,
  allow the branch `main` only. Add required reviewers if promotion should
  need a second person. A scheduled train then also waits for approval.
* Tag rulesets: restrict creating, updating and deleting `v*` tags to
  maintainers and the GitHub Actions app. Restrict updating `lts-*` tags to
  the GitHub Actions app.

## Support windows

| Line | Supported until | Fixes |
|---|---|---|
| Partner (`:partner`) | The next weekly candidate | Fixed forward in the next candidate |
| Stable `vX.Y.Z` | The next stable release | Fixed forward in the next release |
| LTS `lts-X.Y` | 3 months after the next LTS release | Security fixes and fixes for data loss, broken upgrades and tenant isolation, as patch releases (see below) |

Only the latest release of each line is supported. Upgrade to it before you
report a problem.

### Backports to the LTS line

These fixes are backported to the current LTS line:

* security fixes rated critical, high or medium, in LG-SOTF or in a
  dependency or base image;
* fixes for data loss or corruption, a broken upgrade path, or a tenant
  isolation fault.

Features, refactors and fixes rated low are not backported. They reach LTS
users in the next LTS release.

The signed build path builds only from `main`. It signs as
`release-images.yml@refs/heads/main`, and deployments and customers verify
that identity exactly. So a fix reaches the LTS line in one of two ways:

* While `main`'s `__version__` is still on `X.Y`, the fix ships as patch
  release `vX.Y.(Z+1)`, promoted to the LTS channel.
* Once `main` has moved to a newer minor version, the fix ships in the next
  release of that version, promoted to LTS early. On every change, CI checks
  the upgrade from the latest LTS release to `main`, so the upgrade from the
  old LTS line is the tested path.

Release-branch builds, with their own exact signer identity, come when a
customer contract requires patches on an older LTS line without a minor
upgrade.

## Security-relevant releases

A release is **security-relevant** if, since the previous release of the
same kind, it adds at least one entry under `### Security` in
`CHANGELOG.md` or `changelog.d/`. The previous release of the same kind is
the previous tag for a candidate, and the previous stable release for a
stable release. Such entries cover:

* a fix for a vulnerability in LG-SOTF;
* a dependency or base-image update that fixes a vulnerability affecting
  LG-SOTF, including one that a VEX statement no longer covers;
* a change to an authentication, authorisation, tenant-isolation,
  response-guardrail or supply-chain control that changes how an operator
  must configure or verify it.

The release workflow marks such a release in its GitHub release title
(`vX.Y.Z (security fixes)`). Watch the repository's releases, or its
security advisories, to be told.

A security fix never waits for Thursday:

1. Merge the fix through the normal review and CI.
2. Run the workflow with `promote` empty to cut a candidate now.
3. Promote that candidate as soon as its gates pass. Tick `lts` if the
   current LTS line needs the fix (see the backport rules above).

The gates are never skipped, for a security release either. Vulnerabilities
reported to us follow [SECURITY.md](../SECURITY.md).

## Pin and verify a release

Pin by digest, not by a tag. Use a channel tag only to find out which
digest to move to next:

```sh
CHANNEL=lts        # or partner, lts-1.3, v1.3.0
for repo in ghcr.io/gapilongo/lg-sotf ghcr.io/gapilongo/lg-sotf-frontend; do
  docker buildx imagetools inspect "$repo:$CHANNEL" --format '{{json .Manifest}}' | jq -r .digest
done
```

Verify each digest as shown in
[security.md](security.md#verify-an-image-yourself), with the same `SIGNER`
and `ISSUER`. Every channel points at an image that `main` built and
signed. Then pin:

* **Helm:** `image.digest` and `frontend.image.digest` in your values.
* **Compose:** `APP_IMAGE=ghcr.io/gapilongo/lg-sotf@sha256:...` and
  `FRONTEND_IMAGE=ghcr.io/gapilongo/lg-sotf-frontend@sha256:...`.
* **Air-gapped:** bundle the verified digests
  ([air-gapped.md](air-gapped.md)).

To see what a release contains, read its GitHub release: the notes, the
SBOMs and the VEX document. The SBOMs and the VEX document are attested for
the tag (security.md, "SBOMs and VEX"). The `lts-X.Y` git tag shows which
commit the LTS line is on.
