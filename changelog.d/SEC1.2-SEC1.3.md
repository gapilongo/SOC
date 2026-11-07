### Security

- Builds now verify every input. Every Python requirements file is
  hash-locked for all platforms and installed with `pip install
  --require-hashes` in the image build, CI and `make dev`; re-lock with
  `make lock`. Every base image is pinned by digest, including the
  Dockerfiles' `# syntax=` line and the PostgreSQL, Redis and Caddy defaults
  in the compose files. `PYTHON_BASE_IMAGE`, `NODE_IMAGE` and `NGINX_IMAGE`
  now default to the pinned images; set them only to use a mirror. The
  frontend runs on `nginx-unprivileged:1.30-alpine-slim`. The old
  `1.28-alpine` tag no longer receives updates and carried fixable critical
  CVEs.
- CI now scans both images with Trivy and fails on any critical or high CVE
  that has a fix. Reviewed exceptions live in `.trivyignore`, and each one
  expires within 90 days. `pip-audit` now also checks the build and CI tool
  locks. See `docs/security.md`, section 9.
- Every release now carries CycloneDX SBOMs as assets: the Python lock, the
  frontend's production npm packages, and both images for amd64 and arm64,
  made from the release digests. It also carries an OpenVEX document
  (`security/vex.json`) that lists the CVEs scanners report in the images
  but that do not affect LG-SOTF, with the reason for each. Every asset is
  validated against its schema (here and on every change in CI) and has a
  build-provenance attestation; `docs/security.md` (section 9) shows how to
  download and verify them and how to use the VEX document with Grype or
  Trivy. If the GitHub release does not exist when the tag is pushed, it is
  created with generated notes.
