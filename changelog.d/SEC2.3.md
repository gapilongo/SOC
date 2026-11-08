### Security

- A dependency policy, `docs/dependency-policy.md`. A new Python, npm,
  image or action dependency must pass an admission checklist: need,
  licence allowlist, maintenance, size and transitive dependencies,
  security history, and hash-locking with `make lock`. The pull request
  template now has a "New dependency" checkbox for it. Vulnerable
  dependencies are patched within these times: critical 7 days, high 14,
  medium 30, low the next minor release. Advisories are triaged within 2
  business days. Dependabot now runs every Monday for every ecosystem, so
  merged updates ship on Thursday's partner train. It labels its pull
  requests and groups minor and patch updates of Python and production npm
  packages. The dependency files and the Dependabot configuration need the
  code owner's review.
