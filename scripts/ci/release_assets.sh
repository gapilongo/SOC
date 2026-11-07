#!/usr/bin/env bash
# Builds the supply-chain assets of a release and validates each against its schema
# (docs/security.md, "SBOMs and VEX"):
#
#   lg-sotf-VERSION-python.cdx.json        CycloneDX SBOM of requirements.txt: every Python package the
#                                          backend image installs, with the hashes the build verifies
#   lg-sotf-VERSION-frontend-npm.cdx.json  CycloneDX SBOM of the web app's production npm packages
#   NAME-VERSION-image[-OS-ARCH].cdx.json  CycloneDX SBOM of each image: OS packages and libraries
#   lg-sotf-VERSION.openvex.json           OpenVEX: CVEs triaged as not affecting the product
#   SHA256SUMS                             SHA-256 of every file above
#
#   scripts/ci/release_assets.sh OUTDIR VERSION [NAME=IMAGE ...]
#
# IMAGE is a local tag or repo@sha256:digest. With PLATFORMS set (e.g. "linux/amd64 linux/arm64")
# a multi-arch image gets one SBOM per platform. Needs cyclonedx-py and the validator's libraries
# (pip install --require-hashes -r scripts/ci/requirements-tools.txt), npm 10.1+ and trivy.
set -euo pipefail
cd "$(dirname "$0")/../.."

[ "$#" -ge 2 ] || { sed -n '2,17p' "$0" >&2; exit 2; }
out="$1"
version="$2"
shift 2
[[ "$version" =~ ^[A-Za-z0-9._+-]+$ ]] || { echo "unexpected version '$version'" >&2; exit 2; }
mkdir -p "$out"

python_sbom="$out/lg-sotf-$version-python.cdx.json"
cyclonedx-py requirements --pyproject pyproject.toml --sv 1.6 --of JSON --output-reproducible \
  -o "$python_sbom" requirements.txt
# pyproject.toml's version is dynamic, so cyclonedx-py leaves the root component without one.
python3 - "$python_sbom" "$version" <<'EOF'
import json, sys
path, version = sys.argv[1], sys.argv[2]
with open(path) as f:
    bom = json.load(f)
bom["metadata"]["component"]["version"] = version
with open(path, "w") as f:
    json.dump(bom, f, indent=2)
    f.write("\n")
EOF

(cd src/lg_front && npm sbom --sbom-format cyclonedx --omit dev --package-lock-only) \
  >"$out/lg-sotf-$version-frontend-npm.cdx.json"

for pair in "$@"; do
  name="${pair%%=*}"
  ref="${pair#*=}"
  [[ "$name" =~ ^[a-z0-9-]+$ && -n "$ref" && "$ref" != "$pair" ]] || { echo "expected NAME=IMAGE, got '$pair'" >&2; exit 2; }
  if [ -n "${PLATFORMS:-}" ]; then
    for platform in $PLATFORMS; do
      trivy image --quiet --format cyclonedx --platform "$platform" \
        -o "$out/$name-$version-image-${platform//\//-}.cdx.json" "$ref"
    done
  else
    trivy image --quiet --format cyclonedx -o "$out/$name-$version-image.cdx.json" "$ref"
  fi
done

cp security/vex.json "$out/lg-sotf-$version.openvex.json"

python3 scripts/ci/validate_sbom.py "$out"/*.json
(cd "$out" && sha256sum -- *.json >SHA256SUMS)
echo "assets in $out:"
ls -1 "$out"
