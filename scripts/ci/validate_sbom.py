"""Validate release SBOMs and VEX documents against their published schemas.

    python scripts/ci/validate_sbom.py dist/*.cdx.json security/vex.json

* CycloneDX JSON (``"bomFormat": "CycloneDX"``): the strict CycloneDX JSON schema of the file's own
  ``specVersion`` (cyclonedx-python-lib's bundled copy), and at least one component.
* OpenVEX (``"@context": "https://openvex.dev/ns/v0.2.0"``): the OpenVEX 0.2.0 JSON schema vendored in
  ``security/schemas/``, with format checks (date-time, IRI), and no duplicate vulnerability/product pair.

Exits 1 and prints every error when a file does not validate. Needs the tools in
scripts/ci/requirements-tools.txt (``pip install --require-hashes -r scripts/ci/requirements-tools.txt``).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, List

OPENVEX_CONTEXT = "https://openvex.dev/ns/v0.2.0"
OPENVEX_SCHEMA = Path(__file__).resolve().parents[2] / "security" / "schemas" / "openvex-0.2.0.schema.json"


def validate_cyclonedx(doc: Dict[str, Any], text: str) -> List[str]:
    from cyclonedx.schema import OutputFormat, SchemaVersion
    from cyclonedx.validation.json import JsonStrictValidator

    try:
        version = SchemaVersion.from_version(str(doc.get("specVersion")))
    except ValueError:
        return [f"unsupported CycloneDX specVersion {doc.get('specVersion')!r}"]
    validator = JsonStrictValidator(version)
    assert validator.output_format is OutputFormat.JSON
    error = validator.validate_str(text)
    errors = [f"CycloneDX {version.to_version()}: {error}"] if error else []
    if not doc.get("components"):
        errors.append("no components: an empty SBOM describes nothing")
    return errors


def validate_openvex(doc: Dict[str, Any]) -> List[str]:
    from jsonschema import Draft202012Validator

    schema = json.loads(OPENVEX_SCHEMA.read_text())
    validator = Draft202012Validator(schema, format_checker=Draft202012Validator.FORMAT_CHECKER)
    errors = [f"OpenVEX: {'/'.join(map(str, e.absolute_path)) or '<root>'}: {e.message}"
              for e in sorted(validator.iter_errors(doc), key=lambda e: list(map(str, e.absolute_path)))]
    seen = set()
    for statement in doc.get("statements", []):
        for product in statement.get("products", []):
            key = (statement.get("vulnerability", {}).get("name"), product.get("@id"))
            if key in seen:
                errors.append(f"OpenVEX: duplicate statement for {key[0]} on {key[1]}")
            seen.add(key)
    return errors


def validate(path: Path) -> List[str]:
    text = path.read_text()
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as exc:
        return [f"not JSON: {exc}"]
    if not isinstance(doc, dict):
        return ["not a JSON object"]
    if doc.get("bomFormat") == "CycloneDX":
        return validate_cyclonedx(doc, text)
    if doc.get("@context") == OPENVEX_CONTEXT:
        return validate_openvex(doc)
    return ["neither a CycloneDX SBOM nor an OpenVEX 0.2.0 document"]


def main(argv: List[str]) -> int:
    if not argv:
        print(__doc__, file=sys.stderr)
        return 2
    failed = 0
    for name in argv:
        errors = validate(Path(name))
        if errors:
            failed += 1
            for error in errors:
                print(f"FAIL  {name}: {error}")
        else:
            print(f"ok    {name}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
