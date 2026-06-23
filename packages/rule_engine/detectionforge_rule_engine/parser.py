from typing import Any
import yaml
from detectionforge_rule_engine.models import ParsedRule


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value if item is not None]
    return [str(value)]


def _as_str(value: Any) -> str | None:
    """Coerce scalars (incl. YAML date/datetime) to str; keep None as None."""
    if value is None:
        return None
    return str(value)


def parse_rule_yaml(raw_yaml: str) -> ParsedRule:
    data = yaml.safe_load(raw_yaml) or {}
    if not isinstance(data, dict):
        raise ValueError("Rule YAML must be a mapping")
    return ParsedRule(
        title=str(data.get("title") or data.get("name") or "Untitled rule"),
        rule_id=_as_str(data.get("id")),
        status=_as_str(data.get("status")),
        description=_as_str(data.get("description")),
        author=_as_str(data.get("author")),
        date=_as_str(data.get("date")),
        modified=_as_str(data.get("modified")),
        references=_as_list(data.get("references")),
        tags=_as_list(data.get("tags")),
        logsource=data.get("logsource") or {},
        detection=data.get("detection") or {},
        falsepositives=_as_list(data.get("falsepositives")),
        level=data.get("level"),
        raw=data,
    )
