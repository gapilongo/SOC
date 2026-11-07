# Dependency policy

LG-SOTF runs with access to security telemetry and can trigger containment.
Each dependency is code that runs with those rights. This page sets out:

* when a new dependency may be added;
* how updates and advisories are triaged;
* how fast a vulnerable dependency must be patched.

The pinning and scanning that enforce it are described in
[security.md](security.md#9-supply-chain-and-build), section 9.

It covers every input of a build or a running install:

* Python packages (`requirements.txt`, `requirements-dev.txt`,
  `docker/requirements-build.txt` and the CI tool locks in `scripts/ci/`);
* the web app's npm packages (`src/lg_front/package.json` and its lock);
* base and service images;
* GitHub Actions;
* tools that CI downloads.

## Adding a dependency

Prefer the standard library or a dependency already in the lock. If neither
will do, the pull request that adds a dependency ticks **New dependency**
in its template and answers every item below in its description. The
reviewer checks the answers, not only the code.

Admission checklist:

1. **Need.** What it does that the standard library and the current
   dependencies cannot do in a few dozen lines, and what else was
   considered.
2. **Licence.** Allowed: MIT, BSD-2-Clause, BSD-3-Clause, Apache-2.0, ISC,
   PSF-2.0, 0BSD, Unlicense and Zlib. MPL-2.0 is allowed when used
   unmodified. Not allowed: GPL, AGPL, SSPL, BUSL, "non-commercial" terms,
   or no licence at all. LGPL needs the maintainer's written approval in
   the pull request. Check the licence of every new transitive dependency
   too: LG-SOTF is MIT-licensed and sold with paid editions.
3. **Maintenance.** A release in the last 12 months. More than one
   maintainer, or an organisation behind it. Issues and security reports
   get answers. Look at its OpenSSF Scorecard (on deps.dev or
   securityscorecards.dev) and note the score; below 5 needs a reason.
4. **Size and transitive dependencies.** How many packages the lock gains
   (`git diff --stat requirements.txt` after `make lock`, or the
   `package-lock.json` diff), and the effect on the image size. A Python
   package must ship wheels or a pure-Python sdist for linux/amd64,
   linux/arm64 and macOS, because the locks carry hashes for every
   platform. An npm package with `install` or `postinstall` scripts needs a
   reason.
5. **Security history.** Its advisories in OSV (osv.dev) or the GitHub
   Advisory Database over the last 2 years, and how fast they were fixed.
   It must be clean in `pip-audit` or `npm audit` at the version added.
6. **Hash-locked.** Add Python packages to `pyproject.toml` with a
   supported range, then run `make lock`. Never edit the `.txt` locks by
   hand. Add npm packages with `npm install --save-exact` so that
   `package-lock.json` records the integrity hash. Pin an image by digest
   and an action by commit SHA, with the version as a comment.

Extra scrutiny: a new dependency, or a major version bump, in any of these
areas needs a second look at its changelog and its permissions:

* the LLM and agent stack (LangChain, LangGraph, model provider SDKs);
* the MCP SDK;
* authentication, cryptography, and parsing untrusted alert or email
  content.

These areas decide what reaches the model and what runs a response.

Removing a dependency needs no checklist. Do it whenever you can.

## Patch SLAs

A known vulnerability in a dependency must be fixed, or shown not to
affect LG-SOTF, within these times:

| Severity | Patched release within |
|---|---|
| Critical | 7 days |
| High | 14 days |
| Medium | 30 days |
| Low | The next minor release |

The clock starts when the advisory is published, or when we learn of it if
that is later. Severity is the advisory's CVSS rating. Triage may lower it
only by showing that the vulnerable code cannot be reached in LG-SOTF.

"Patched release" means a release on the stable channel and, for critical,
high and medium, on the current LTS line ([releases.md](releases.md)). A
critical or high fix ships out of band as a security release. It does not
wait for the weekly train.

When the vulnerable code is not reachable, the finding is closed with a
`not_affected` statement in `security/vex.json` and, for image findings, a
`.trivyignore` entry that expires within 90 days. Both are reviewed in a
pull request, within the same SLA.

Vulnerabilities in LG-SOTF's own code are reported and disclosed as
described in [SECURITY.md](../SECURITY.md).

## Updates and triage

Advisories reach us from these sources:

* **Dependabot version updates.** Weekly, on Monday, for every ecosystem
  (`.github/dependabot.yml`). Merged updates ship on Thursday's partner
  train. Minor and patch updates of Python and production npm packages come
  grouped. Their major updates come one per pull request, because each one
  is a migration to review. GitHub Actions and the web app's development
  tooling are grouped at every level.
* **Dependabot security updates.** Turn them on in Settings > Code security.
  They open a pull request as soon as an advisory is published, whatever the
  weekly schedule says, and they are never grouped.
* **CI gates on every change.** `pip-audit` over every lock, `npm audit` for
  the production packages, and Trivy on both images (fixable critical and
  high fail the build).
* **The weekly scheduled CI run** (Monday). It runs the same audits against
  the newest advisory data, so a new advisory against an unchanged lock
  turns `main` red.

Triage: within **2 business days** of a Dependabot pull request, a red
audit or a published advisory, the maintainer on duty does three things:

1. Rates the finding with the severity of its advisory.
2. Decides how to handle it:
   * merge the update;
   * re-lock with `make lock ARGS="--upgrade-package NAME"`;
   * bump a base-image digest;
   * or write a VEX statement, with the reason.
3. Records the decision and the SLA due date on the pull request or issue,
   with the label `security` for any finding rated medium or above.

Two business days fit inside the shortest SLA (7 days), and the weekly
schedule plus the immediate security updates mean that no fixed version
waits more than a week to be proposed.

A held update, in an `ignore` entry of `.github/dependabot.yml`, names its
reason next to it. Drop the entry when the reason is gone. If an advisory
names a held package, the SLA still applies. Fix it by hand (re-lock or
migrate) or close it with a VEX statement.
