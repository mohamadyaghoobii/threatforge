"""Modifier expansion.

Turns a Sigma ``field|mod1|mod2`` key plus its value(s) into a list of
``MatchSpec`` objects and a connector. This is where every Sigma value
modifier is implemented exactly once, independent of target.

Supported modifiers:
  contains, startswith, endswith, all, cased,
  re, base64, base64offset, wide/utf16/utf16le/utf16be,
  windash, lt/lte/gt/gte, cidr, exists/null (handled in detection.py)
"""

from __future__ import annotations

import base64 as _b64
from dataclasses import dataclass

from .ast import MatchKind, MatchSpec
from .warnings import CompilerWarning, warn

# Modifiers that change how a single value is matched (string shape).
_STRING_SHAPE = {"contains", "startswith", "endswith", "re"}
# Numeric comparisons.
_NUMERIC = {"lt", "lte", "gt", "gte"}
_NUMERIC_KIND = {
    "lt": MatchKind.LT,
    "lte": MatchKind.LTE,
    "gt": MatchKind.GT,
    "gte": MatchKind.GTE,
}
# Encoding modifiers handled specially.
_ENCODING = {"base64", "base64offset", "wide", "utf16", "utf16le", "utf16be"}


@dataclass
class ExpansionResult:
    specs: list[MatchSpec]
    connector: str  # "or" | "and"
    warnings: list[CompilerWarning]


def split_field(raw_key: str) -> tuple[str, list[str]]:
    """``CommandLine|contains|all`` -> ("CommandLine", ["contains", "all"])."""
    parts = raw_key.split("|")
    return parts[0], [p.strip().lower() for p in parts[1:] if p.strip()]


def _as_list(value) -> list:
    if isinstance(value, list):
        return value
    return [value]


def _b64_variants_offset(text: str) -> list[str]:
    """base64offset: the 3 base64 encodings depending on byte offset.

    Mirrors pySigma's base64offset: encode with 0/1/2 byte prefix padding,
    then trim partial leading/trailing chars so the substring survives
    regardless of alignment.
    """
    raw = text.encode("utf-8")
    variants: list[str] = []
    for offset in range(3):
        prefixed = (b"\x00" * offset) + raw
        encoded = _b64.b64encode(prefixed).decode("ascii")
        # Trim the bytes contributed by the padding prefix and the trailing
        # partial group so the result is a stable substring.
        start = (offset * 8 + 5) // 6 if offset else 0
        # Drop trailing '=' padding and the last (possibly partial) char.
        trimmed = encoded.rstrip("=")
        if offset:
            trimmed = trimmed[start:]
        # Remove the final char which may be partial for non-aligned input.
        if len(trimmed) > 1:
            trimmed = trimmed[:-1]
        variants.append(trimmed)
    # De-dup while preserving order.
    seen: set[str] = set()
    out: list[str] = []
    for v in variants:
        if v and v not in seen:
            seen.add(v)
            out.append(v)
    return out


def _windash_variants(text: str) -> list[str]:
    """windash: a flag may use -, /, or unicode dashes interchangeably."""
    dashes = ["-", "/", "–", "—"]  # - / – —
    variants = {text}
    for d in dashes:
        # Replace each leading-dash style at word boundaries pragmatically:
        # swap any of the dash characters for each candidate.
        for src in dashes:
            if src in text:
                variants.add(text.replace(src, d))
    return sorted(variants)


def expand(raw_key: str, value, field_name: str) -> ExpansionResult:
    """Expand one ``field|mods: value`` entry into match specs."""
    _, mods = split_field(raw_key)
    warnings: list[CompilerWarning] = []
    values = _as_list(value)
    connector = "and" if "all" in mods else "or"
    cased = "cased" in mods

    # Numeric comparison modifiers.
    numeric_mod = next((m for m in mods if m in _NUMERIC), None)
    if numeric_mod:
        specs = []
        for item in values:
            specs.append(MatchSpec(kind=_NUMERIC_KIND[numeric_mod], value=item, cased=cased))
        return ExpansionResult(specs, connector, warnings)

    # CIDR.
    if "cidr" in mods:
        specs = [MatchSpec(kind=MatchKind.CIDR, value=item, cased=cased) for item in values]
        return ExpansionResult(specs, connector, warnings)

    # Regex.
    if "re" in mods:
        specs = [MatchSpec(kind=MatchKind.REGEX, value=str(item), cased=cased) for item in values]
        return ExpansionResult(specs, connector, warnings)

    # Encoding modifiers.
    if "base64offset" in mods:
        specs = []
        for item in values:
            for variant in _b64_variants_offset(str(item)):
                specs.append(
                    MatchSpec(
                        kind=MatchKind.CONTAINS,
                        value=variant,
                        cased=cased,
                        note="base64offset expansion",
                    )
                )
        warnings.append(
            warn(
                "MODIFIER_EMULATED_LOSSY",
                field=field_name,
                message="base64offset expanded to candidate substrings; review for false positives.",
            )
        )
        return ExpansionResult(specs, "or", warnings)

    if "base64" in mods:
        specs = []
        for item in values:
            encoded = _b64.b64encode(str(item).encode("utf-8")).decode("ascii")
            specs.append(MatchSpec(kind=MatchKind.CONTAINS, value=encoded, cased=cased, note="base64"))
        return ExpansionResult(specs, connector, warnings)

    # wide / utf16* — byte-level encodings most query languages cannot
    # express. Match the plain value but flag it lossy.
    if any(m in {"wide", "utf16", "utf16le", "utf16be"} for m in mods):
        warnings.append(
            warn(
                "MODIFIER_EMULATED_LOSSY",
                field=field_name,
                message="wide/utf16 modifier cannot be expressed natively; matched as plain text.",
            )
        )

    # String-shape modifiers.
    shape = next((m for m in mods if m in _STRING_SHAPE), None)
    specs = []
    for item in values:
        text = str(item)
        if shape == "contains":
            kind = MatchKind.CONTAINS
        elif shape == "startswith":
            kind = MatchKind.STARTSWITH
        elif shape == "endswith":
            kind = MatchKind.ENDSWITH
        else:
            # Plain equality; if the value itself has wildcards Sigma treats
            # them as glob, which most backends render as wildcards directly.
            kind = MatchKind.EQUALS
        # windash variant expansion (applies to the matched substring).
        if "windash" in mods:
            for variant in _windash_variants(text):
                specs.append(MatchSpec(kind=kind, value=variant, cased=cased, note="windash"))
        else:
            specs.append(MatchSpec(kind=kind, value=item if kind == MatchKind.EQUALS else text, cased=cased))

    if "windash" in mods:
        connector = "or"  # the dash variants are alternatives

    return ExpansionResult(specs, connector, warnings)
