"""Alert fingerprints: a stable key for "the same detection on the same things".

``fingerprint = sha256(json({"v", "source_type", "rule", "entities"}))`` where

* ``source_type`` is the source's type (``splunk``, ``crowdstrike``...), so
  the same rule name from two products is never merged;
* ``rule`` is the detection/rule name (falling back to the title), lowercased
  with whitespace collapsed;
* ``entities`` are the key entities - hosts, users, IPs, hashes and domains -
  each lowercased, de-duplicated and sorted.

Timestamps, vendor ids, severities, descriptions and free text are excluded,
so repeats of one detection (re-fires, overlapping polls, updates) share a
fingerprint, while a different host or user produces a different one.
Correlation and suppression use it through the
``(tenant_id, fingerprint, ingested_at)`` index. Bump ``VERSION`` if the
recipe changes; old and new fingerprints then simply never match.
"""

from __future__ import annotations

import hashlib
import json
from typing import Dict, List

from lg_sotf.models.alert import CanonicalAlert

VERSION = 1
KEY_ENTITY_KINDS = ("hosts", "users", "ips", "hashes", "domains")


def _norm(text: str) -> str:
    return " ".join(text.lower().split())


def fingerprint_parts(alert: CanonicalAlert) -> Dict[str, object]:
    entities: Dict[str, List[str]] = {}
    for kind in KEY_ENTITY_KINDS:
        values = sorted({_norm(v) for v in getattr(alert.entities, kind) if v.strip()})
        if values:
            entities[kind] = values
    return {
        "v": VERSION,
        "source_type": alert.source_type.lower(),
        "rule": _norm(alert.rule_name or alert.title),
        "entities": entities,
    }


def compute_fingerprint(alert: CanonicalAlert) -> str:
    """Lowercase hex sha256 (64 characters)."""
    payload = json.dumps(fingerprint_parts(alert), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
