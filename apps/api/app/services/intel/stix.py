"""STIX 2.1 bundle export for indicators.

Produces a standards-compliant bundle of Indicator SDOs (STIX patterns,
labels, confidence, valid_from) marked TLP:CLEAR — importable by MISP,
OpenCTI, and other TIPs.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone
from typing import Any

_NS = uuid.uuid5(uuid.NAMESPACE_DNS, "threatforge.intel")
# Standard STIX 2.1 TLP:CLEAR marking-definition id.
TLP_CLEAR = "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487"

_CONFIDENCE = {"high": 85, "medium": 60, "low": 30, "none": 15}


def _ts(value: str | None) -> str:
    if value:
        txt = value.strip().replace(" ", "T")
        if not txt.endswith("Z") and "+" not in txt:
            txt += "Z"
        try:
            datetime.fromisoformat(txt.replace("Z", "+00:00"))
            return txt
        except ValueError:
            pass
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _pattern(ioc_type: str, value: str) -> str | None:
    v = value.replace("'", "\\'")
    if ioc_type == "ip":
        kind = "ipv6-addr" if ":" in v else "ipv4-addr"
        return f"[{kind}:value = '{v}']"
    if ioc_type == "domain":
        return f"[domain-name:value = '{v}']"
    if ioc_type == "url":
        return f"[url:value = '{v}']"
    if ioc_type == "hash":
        algo = {32: "MD5", 40: "SHA-1", 64: "SHA-256"}.get(len(value.strip()))
        if not algo:
            return None
        return f"[file:hashes.'{algo}' = '{v}']"
    return None


def indicator_sdo(ind: dict[str, Any]) -> dict[str, Any] | None:
    pattern = _pattern(ind["ioc_type"], ind.get("normalized") or ind["ioc"])
    if not pattern:
        return None
    created = _ts(ind.get("first_seen"))
    oid = "indicator--" + str(uuid.uuid5(_NS, f"{ind['ioc_type']}:{ind.get('normalized')}"))
    labels = [ind.get("category", "malicious-activity")]
    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": oid,
        "created": created,
        "modified": _ts(ind.get("last_seen")),
        "name": f"{ind['ioc_type'].upper()} {ind['ioc']}"[:250],
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": created,
        "labels": labels,
        "confidence": _CONFIDENCE.get((ind.get("confidence") or "medium").lower(), 60),
        "object_marking_refs": [TLP_CLEAR],
        "x_metasec_score": ind.get("threat_score"),
        "x_metasec_severity": ind.get("severity"),
        "x_metasec_sources": ind.get("sources", []),
        "x_metasec_tags": ind.get("tags", []),
    }


def bundle(indicators: list[dict[str, Any]]) -> dict[str, Any]:
    objects = [TLP_CLEAR_MARKING]
    for ind in indicators:
        sdo = indicator_sdo(ind)
        if sdo:
            objects.append(sdo)
    seed = "".join(o["id"] for o in objects)[:512]
    bundle_id = "bundle--" + str(uuid.uuid5(_NS, "bundle:" + hashlib.sha1(seed.encode()).hexdigest()))
    return {"type": "bundle", "id": bundle_id, "objects": objects}


TLP_CLEAR_MARKING = {
    "type": "marking-definition",
    "spec_version": "2.1",
    "id": TLP_CLEAR,
    "created": "2022-10-01T00:00:00.000Z",
    "name": "TLP:CLEAR",
    "definition_type": "tlp",
    "definition": {"tlp": "clear"},
}
