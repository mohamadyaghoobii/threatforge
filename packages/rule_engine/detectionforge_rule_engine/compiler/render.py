"""Render a DetectionAST into a target-specific query string.

A ``Renderer`` walks the boolean tree and emits target syntax. Field
mapping and base-selector logic live here per target. Backends that only
need light differences subclass ``Renderer`` and override the clause
methods.

G2 focuses on Splunk, Sentinel (KQL), and Elastic/OpenSearch (KQL/Lucene)
fidelity; QRadar, Chronicle, and LogScale get correct-but-simpler
rendering and inherit the same AST so G6/G7 can deepen them.
"""

from __future__ import annotations

from typing import Any

from .ast import (
    AndNode,
    DetectionAST,
    FieldNode,
    KeywordNode,
    MatchKind,
    MatchSpec,
    Node,
    NotNode,
    NullNode,
    OrNode,
    RefNode,
    TrueNode,
)
from .field_maps import FIELD_MAPPINGS
from .warnings import CompilerWarning, warn


class Renderer:
    target = "elastic"
    and_op = " AND "
    or_op = " OR "
    not_prefix = "NOT "
    wildcard = "*"

    def __init__(
        self,
        searches: dict[str, Node],
        warnings: list[CompilerWarning],
        field_overrides: dict[str, str] | None = None,
    ):
        self.searches = searches
        self.warnings = warnings
        # Profile-supplied field map takes precedence over target defaults.
        self.field_overrides = field_overrides or {}

    # --- field name mapping ---
    def map_field(self, field: str) -> str:
        if field in self.field_overrides:
            return self.field_overrides[field]
        mapping = FIELD_MAPPINGS.get(self.target) or {}
        if field not in mapping and field not in mapping.values():
            self.warnings.append(
                warn(
                    "FIELD_FALLBACK_USED",
                    field=field,
                    message=f"No {self.target} mapping for field {field!r}; passed through.",
                )
            )
        return mapping.get(field, field)

    # --- escaping ---
    def quote(self, value: Any) -> str:
        text = str(value).replace("\\", "\\\\").replace('"', '\\"')
        return f'"{text}"'

    def glob_to_wildcard(self, text: str) -> str:
        return text  # Sigma uses * already; most targets accept it.

    # --- per-spec clause ---
    def field_clause(self, field: str, spec: MatchSpec) -> str:
        mapped = self.map_field(field)
        v = spec.value
        if spec.kind == MatchKind.EQUALS:
            return f"{mapped}={self.quote(v)}"
        if spec.kind == MatchKind.CONTAINS:
            return f"{mapped}={self.quote('*' + str(v) + '*')}"
        if spec.kind == MatchKind.STARTSWITH:
            return f"{mapped}={self.quote(str(v) + '*')}"
        if spec.kind == MatchKind.ENDSWITH:
            return f"{mapped}={self.quote('*' + str(v))}"
        if spec.kind == MatchKind.REGEX:
            return self.regex_clause(mapped, str(v))
        if spec.kind in (MatchKind.GT, MatchKind.GTE, MatchKind.LT, MatchKind.LTE):
            return self.numeric_clause(mapped, spec)
        if spec.kind == MatchKind.CIDR:
            return self.cidr_clause(mapped, str(v))
        if spec.kind == MatchKind.EXISTS:
            return self.exists_clause(mapped)
        if spec.kind == MatchKind.KEYWORD:
            return self.keyword_clause(str(v))
        return f"{mapped}={self.quote(v)}"

    def regex_clause(self, field: str, pattern: str) -> str:
        return f'{field}=/{pattern}/'

    def numeric_clause(self, field: str, spec: MatchSpec) -> str:
        op = {MatchKind.GT: ">", MatchKind.GTE: ">=", MatchKind.LT: "<", MatchKind.LTE: "<="}[spec.kind]
        return f"{field}{op}{spec.value}"

    def cidr_clause(self, field: str, cidr: str) -> str:
        self.warnings.append(
            warn("MODIFIER_EMULATED_LOSSY", field=field, message=f"CIDR match {cidr} rendered as prefix wildcard.")
        )
        prefix = cidr.split("/")[0].rsplit(".", 1)[0]
        return f'{field}={self.quote(prefix + ".*")}'

    def exists_clause(self, field: str) -> str:
        return f'{field}=*'

    def keyword_clause(self, value: str) -> str:
        return self.quote(value)

    # --- node combinators ---
    def render_field(self, node: FieldNode) -> str:
        clauses = [self.field_clause(node.field, spec) for spec in node.specs]
        if not clauses:
            return ""
        joiner = self.and_op if node.connector == "and" else self.or_op
        body = clauses[0] if len(clauses) == 1 else "(" + joiner.join(clauses) + ")"
        if node.negated:
            body = f"{self.not_prefix}{body}"
        return body

    def render_keyword(self, node: KeywordNode) -> str:
        clauses = [self.keyword_clause(str(spec.value)) for spec in node.specs]
        if not clauses:
            return ""
        body = clauses[0] if len(clauses) == 1 else "(" + self.or_op.join(clauses) + ")"
        if node.negated:
            body = f"{self.not_prefix}{body}"
        return body

    def render_null(self, node: NullNode) -> str:
        mapped = self.map_field(node.field)
        clause = f'NOT {mapped}=*'
        if node.negated:
            clause = f"{mapped}=*"
        return clause

    def render(self, node: Node) -> str:
        if isinstance(node, RefNode):
            target = self.searches.get(node.name)
            if target is None:
                self.warnings.append(
                    warn("CONDITION_AMBIGUOUS", message=f"Condition references unknown selection {node.name!r}.")
                )
                return ""
            return self.render(target)
        if isinstance(node, FieldNode):
            return self.render_field(node)
        if isinstance(node, KeywordNode):
            return self.render_keyword(node)
        if isinstance(node, NullNode):
            return self.render_null(node)
        if isinstance(node, NotNode):
            inner = self.render(node.child)
            return f"{self.not_prefix}({inner})" if inner else ""
        if isinstance(node, AndNode):
            parts = [p for p in (self.render(c) for c in node.children) if p]
            if not parts:
                return ""
            return "(" + self.and_op.join(parts) + ")" if len(parts) > 1 else parts[0]
        if isinstance(node, OrNode):
            parts = [p for p in (self.render(c) for c in node.children) if p]
            if not parts:
                return ""
            return "(" + self.or_op.join(parts) + ")" if len(parts) > 1 else parts[0]
        if isinstance(node, TrueNode):
            return ""
        return ""
