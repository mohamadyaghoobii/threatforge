"""Parse the Sigma ``detection:`` block into named AST search expressions.

Each key (other than ``condition``) becomes a named search that the
condition parser then composes. A search value can be:

  - a mapping        -> AND of field matches
  - a list of maps   -> OR of (AND of field matches)
  - a list of scalars-> keyword OR search
"""

from __future__ import annotations

from typing import Any

from .ast import (
    AndNode,
    FieldNode,
    KeywordNode,
    MatchKind,
    MatchSpec,
    Node,
    NotNode,
    NullNode,
    OrNode,
    TrueNode,
)
from .values import expand, split_field
from .warnings import CompilerWarning


def _is_null(value: Any) -> bool:
    return value is None


def _field_node(raw_key: str, value: Any, warnings: list[CompilerWarning]) -> Node:
    field_name, mods = split_field(raw_key)

    # field: null  / field|exists style
    if _is_null(value):
        # `field: null` -> field is absent. `<field>|exists: true` would be
        # handled here too, but plain Sigma uses null.
        return NullNode(field=field_name, negated=False)

    result = expand(raw_key, value, field_name)
    warnings.extend(result.warnings)
    return FieldNode(field=field_name, specs=result.specs, connector=result.connector)


def _map_to_node(mapping: dict[str, Any], warnings: list[CompilerWarning]) -> Node:
    children: list[Node] = []
    for key, value in mapping.items():
        children.append(_field_node(str(key), value, warnings))
    if not children:
        return TrueNode()
    if len(children) == 1:
        return children[0]
    return AndNode(children=children)


def _keyword_node(values: list[Any], warnings: list[CompilerWarning]) -> Node:
    specs = [MatchSpec(kind=MatchKind.KEYWORD, value=str(v)) for v in values]
    return KeywordNode(specs=specs)


def parse_search(name: str, value: Any, warnings: list[CompilerWarning]) -> Node:
    """Parse one named selection into a Node."""
    if isinstance(value, dict):
        return _map_to_node(value, warnings)
    if isinstance(value, list):
        # List of maps -> OR of ANDs. List of scalars -> keyword OR.
        if all(isinstance(item, dict) for item in value) and value:
            return OrNode(children=[_map_to_node(item, warnings) for item in value])
        return _keyword_node(value, warnings)
    # A bare scalar selection is treated as a single keyword.
    return _keyword_node([value], warnings)


def parse_detection(detection: dict[str, Any], warnings: list[CompilerWarning]) -> dict[str, Node]:
    """Return ``{search_name: Node}`` for every key except ``condition``."""
    searches: dict[str, Node] = {}
    for key, value in detection.items():
        if key == "condition":
            continue
        if key == "timeframe":
            continue
        searches[str(key)] = parse_search(str(key), value, warnings)
    return searches
