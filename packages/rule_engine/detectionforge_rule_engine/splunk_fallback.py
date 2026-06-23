from typing import Any
from detectionforge_rule_engine.converters import build_query


def build_splunk_query(rule: dict[str, Any], profile: str | None = None) -> tuple[str, list[str]]:
    return build_query(rule, "splunk", profile=profile)
