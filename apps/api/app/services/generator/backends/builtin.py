"""Built-in backend — AST-based Sigma compiler (G2).

Uses ``detectionforge_rule_engine.compiler.compile_rule`` for the full
Sigma modifier + condition support. Falls back to the legacy
``converters.build_query`` only for output formats the compiler does not
yet wrap (e.g. Splunk ``savedsearches`` stanza), which G4 replaces with a
proper formatter.
"""

from __future__ import annotations

from typing import Any

import yaml
from detectionforge_rule_engine.compiler import compile_rule
from detectionforge_rule_engine.converters import build_query

from app.services.generator.profiles import profile_base_selector, profile_field_overrides
from app.services.generator.warnings import (
    GeneratorWarning,
    from_compiler_warnings,
    from_legacy_strings,
)

# Output formats whose body is still produced by the legacy converter.
_LEGACY_FORMATS = {"savedsearches"}


def convert(
    raw_yaml: str,
    target: str,
    *,
    profile: str | None,
    output_format: str,
) -> tuple[str, list[GeneratorWarning]]:
    rule_data: dict[str, Any] = yaml.safe_load(raw_yaml) or {}

    if output_format in _LEGACY_FORMATS:
        query, legacy = build_query(rule_data, target, profile=profile, output_format=output_format)
        return query, from_legacy_strings(legacy, target=target, profile=profile, output_format=output_format)

    # profile_base_selector returns None unless the profile declares an
    # index/sourcetype/table/leading_filter, so this is safe for any target.
    profile_base = profile_base_selector(profile, target)
    field_overrides = profile_field_overrides(profile)
    query, compiler_warnings = compile_rule(
        rule_data, target, profile_base=profile_base, field_overrides=field_overrides
    )
    return query, from_compiler_warnings(
        compiler_warnings, target=target, profile=profile, output_format=output_format
    )


def is_available() -> bool:
    return True
