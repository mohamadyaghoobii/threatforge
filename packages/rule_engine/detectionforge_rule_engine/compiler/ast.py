"""Sigma detection AST.

The detection block and the condition string are parsed into a single
boolean tree of these nodes. Target backends walk the tree and render
their own syntax. Keeping the tree target-independent is what lets one
parser feed every SIEM.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class MatchKind(str, Enum):
    EQUALS = "equals"
    CONTAINS = "contains"
    STARTSWITH = "startswith"
    ENDSWITH = "endswith"
    REGEX = "regex"
    GT = "gt"
    GTE = "gte"
    LT = "lt"
    LTE = "lte"
    CIDR = "cidr"
    EXISTS = "exists"  # field is not null
    KEYWORD = "keyword"  # free-text term, no field


@dataclass
class MatchSpec:
    """A single concrete comparison produced after modifier expansion."""

    kind: MatchKind
    value: Any
    cased: bool = False  # case-sensitive comparison requested
    lossy: bool = False  # emulated (e.g. wide/utf16); review needed
    note: str | None = None  # human note attached during expansion


# --- Leaf nodes -----------------------------------------------------------


@dataclass
class FieldNode:
    """One Sigma field with its expanded match specs.

    ``connector`` is how the specs combine:
      - "or"  : default (Sigma list under a field = OR)
      - "and" : the ``all`` modifier was applied
    """

    field: str
    specs: list[MatchSpec]
    connector: str = "or"
    negated: bool = False


@dataclass
class KeywordNode:
    """Free-text keyword search (a bare list under a selection)."""

    specs: list[MatchSpec]
    connector: str = "or"
    negated: bool = False


@dataclass
class NullNode:
    """``field: null`` — field absent / null."""

    field: str
    negated: bool = False  # negated => field exists


# --- Boolean composites ---------------------------------------------------


@dataclass
class AndNode:
    children: list["Node"] = field(default_factory=list)


@dataclass
class OrNode:
    children: list["Node"] = field(default_factory=list)


@dataclass
class NotNode:
    child: "Node"


@dataclass
class TrueNode:
    """Always-true placeholder (used when a selection is empty)."""


@dataclass
class RefNode:
    """Reference to a named search; resolved by the compiler at render time."""

    name: str


# --- Aggregation ----------------------------------------------------------


@dataclass
class Aggregation:
    """Sigma aggregation tail: ``| count() by field > N``.

    ``func`` in {count, sum, min, max, avg}. ``op`` in {>, >=, <, <=, ==}.
    ``near`` carries timeframe-correlation info when present.
    """

    func: str = "count"
    agg_field: str | None = None
    group_by: list[str] = field(default_factory=list)
    op: str | None = None
    threshold: float | None = None
    timeframe: str | None = None


Node = (
    FieldNode
    | KeywordNode
    | NullNode
    | AndNode
    | OrNode
    | NotNode
    | TrueNode
    | RefNode
)


@dataclass
class DetectionAST:
    """Full compiled detection: a boolean tree plus optional aggregation."""

    root: Node
    aggregation: Aggregation | None = None
    timeframe: str | None = None
