"""Per-target renderer subclasses.

Each overrides only what differs from the generic ``Renderer``: operator
spelling, clause syntax for contains/startswith/regex/numeric, and the
base-selector style.
"""

from __future__ import annotations

from typing import Any

from .ast import MatchKind, MatchSpec
from .render import Renderer


class SplunkRenderer(Renderer):
    target = "splunk"
    and_op = " "  # Splunk implicit AND between terms
    or_op = " OR "
    not_prefix = "NOT "

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
            return f'match({mapped}, "{v}")'
        if spec.kind in (MatchKind.GT, MatchKind.GTE, MatchKind.LT, MatchKind.LTE):
            return self.numeric_clause(mapped, spec)
        if spec.kind == MatchKind.CIDR:
            return f'{mapped}={self.quote(str(v))}'
        if spec.kind == MatchKind.KEYWORD:
            return self.quote(v)
        return f"{mapped}={self.quote(v)}"

    def regex_clause(self, field: str, pattern: str) -> str:
        return f'match({field}, "{pattern}")'

    def render_null(self, node) -> str:
        mapped = self.map_field(node.field)
        return f'isnotnull({mapped})' if node.negated else f'isnull({mapped})'


class SentinelRenderer(Renderer):
    target = "sentinel"
    and_op = " and "
    or_op = " or "
    not_prefix = "not "

    def field_clause(self, field: str, spec: MatchSpec) -> str:
        mapped = self.map_field(field)
        v = spec.value
        if spec.kind == MatchKind.EQUALS:
            if isinstance(v, int):
                return f"{mapped} == {v}"
            return f"{mapped} =~ {self.quote(v)}"
        if spec.kind == MatchKind.CONTAINS:
            return f"{mapped} contains {self.quote(v)}"
        if spec.kind == MatchKind.STARTSWITH:
            return f"{mapped} startswith {self.quote(v)}"
        if spec.kind == MatchKind.ENDSWITH:
            return f"{mapped} endswith {self.quote(v)}"
        if spec.kind == MatchKind.REGEX:
            return f"{mapped} matches regex {self.quote(v)}"
        if spec.kind in (MatchKind.GT, MatchKind.GTE, MatchKind.LT, MatchKind.LTE):
            op = {MatchKind.GT: ">", MatchKind.GTE: ">=", MatchKind.LT: "<", MatchKind.LTE: "<="}[spec.kind]
            return f"{mapped} {op} {v}"
        if spec.kind == MatchKind.CIDR:
            return f"ipv4_is_in_range({mapped}, {self.quote(v)})"
        if spec.kind == MatchKind.KEYWORD:
            return f"* contains {self.quote(v)}"
        return f"{mapped} =~ {self.quote(v)}"

    def render_null(self, node) -> str:
        mapped = self.map_field(node.field)
        return f"isnotempty({mapped})" if node.negated else f"isempty({mapped})"


class ElasticRenderer(Renderer):
    """Kibana KQL."""

    target = "elastic"
    and_op = " and "
    or_op = " or "
    not_prefix = "not "

    def field_clause(self, field: str, spec: MatchSpec) -> str:
        mapped = self.map_field(field)
        v = spec.value
        if spec.kind == MatchKind.EQUALS:
            return f"{mapped} : {self.quote(v)}"
        if spec.kind == MatchKind.CONTAINS:
            return f"{mapped} : {self.quote('*' + str(v) + '*')}"
        if spec.kind == MatchKind.STARTSWITH:
            return f"{mapped} : {self.quote(str(v) + '*')}"
        if spec.kind == MatchKind.ENDSWITH:
            return f"{mapped} : {self.quote('*' + str(v))}"
        if spec.kind == MatchKind.REGEX:
            self.warnings_regex_note(mapped)
            return f"{mapped} : {self.quote('*' + str(v) + '*')}"
        if spec.kind in (MatchKind.GT, MatchKind.GTE, MatchKind.LT, MatchKind.LTE):
            op = {MatchKind.GT: ">", MatchKind.GTE: ">=", MatchKind.LT: "<", MatchKind.LTE: "<="}[spec.kind]
            return f"{mapped} {op} {v}"
        if spec.kind == MatchKind.CIDR:
            return f"{mapped} : {self.quote(v)}"
        if spec.kind == MatchKind.KEYWORD:
            return self.quote(v)
        return f"{mapped} : {self.quote(v)}"

    def warnings_regex_note(self, field: str) -> None:
        from .warnings import warn

        self.warnings.append(
            warn("MODIFIER_EMULATED_LOSSY", field=field, message="KQL has no regex; approximated with wildcard contains.")
        )

    def render_null(self, node) -> str:
        mapped = self.map_field(node.field)
        return f"{mapped} : *" if node.negated else f"not {mapped} : *"

    def quote(self, value: Any) -> str:
        text = str(value).replace("\\", "\\\\").replace('"', '\\"')
        return f'"{text}"'


class LuceneRenderer(ElasticRenderer):
    """Elastic Lucene query string."""

    def field_clause(self, field: str, spec: MatchSpec) -> str:
        mapped = self.map_field(field)
        v = spec.value
        if spec.kind == MatchKind.EQUALS:
            return f"{mapped}:{self.quote(v)}"
        if spec.kind == MatchKind.CONTAINS:
            return f"{mapped}:*{self._lucene_escape(v)}*"
        if spec.kind == MatchKind.STARTSWITH:
            return f"{mapped}:{self._lucene_escape(v)}*"
        if spec.kind == MatchKind.ENDSWITH:
            return f"{mapped}:*{self._lucene_escape(v)}"
        if spec.kind == MatchKind.REGEX:
            return f"{mapped}:/{v}/"
        if spec.kind in (MatchKind.GT, MatchKind.GTE, MatchKind.LT, MatchKind.LTE):
            if spec.kind == MatchKind.GT:
                return f"{mapped}:{{{v} TO *}}"
            if spec.kind == MatchKind.GTE:
                return f"{mapped}:[{v} TO *]"
            if spec.kind == MatchKind.LT:
                return f"{mapped}:{{* TO {v}}}"
            return f"{mapped}:[* TO {v}]"
        if spec.kind == MatchKind.KEYWORD:
            return self.quote(v)
        return f"{mapped}:{self.quote(v)}"

    def _lucene_escape(self, value: Any) -> str:
        return str(value).replace(" ", r"\ ")


class OpenSearchRenderer(ElasticRenderer):
    target = "opensearch"


class QRadarRenderer(Renderer):
    target = "qradar"
    and_op = " AND "
    or_op = " OR "
    not_prefix = "NOT "

    def field_clause(self, field: str, spec: MatchSpec) -> str:
        mapped = self.map_field(field)
        v = spec.value
        q = f'"{mapped}"'
        if spec.kind == MatchKind.EQUALS:
            if isinstance(v, int):
                return f"{q} = {v}"
            return f"{q} = {self.quote(v)}"
        if spec.kind == MatchKind.CONTAINS:
            return f"{q} ILIKE {self.quote('%' + str(v) + '%')}"
        if spec.kind == MatchKind.STARTSWITH:
            return f"{q} ILIKE {self.quote(str(v) + '%')}"
        if spec.kind == MatchKind.ENDSWITH:
            return f"{q} ILIKE {self.quote('%' + str(v))}"
        if spec.kind == MatchKind.REGEX:
            return f"{q} IMATCHES {self.quote(v)}"
        if spec.kind in (MatchKind.GT, MatchKind.GTE, MatchKind.LT, MatchKind.LTE):
            op = {MatchKind.GT: ">", MatchKind.GTE: ">=", MatchKind.LT: "<", MatchKind.LTE: "<="}[spec.kind]
            return f"{q} {op} {v}"
        if spec.kind == MatchKind.KEYWORD:
            return f"payload ILIKE {self.quote('%' + str(v) + '%')}"
        return f"{q} = {self.quote(v)}"

    def render_null(self, node) -> str:
        mapped = f'"{self.map_field(node.field)}"'
        return f"{mapped} IS NOT NULL" if node.negated else f"{mapped} IS NULL"


class ChronicleRenderer(Renderer):
    target = "chronicle"
    and_op = " and "
    or_op = " or "
    not_prefix = "not "

    def field_clause(self, field: str, spec: MatchSpec) -> str:
        mapped = self.map_field(field)
        v = spec.value
        if spec.kind == MatchKind.EQUALS:
            return f"{mapped} = {self.quote(v)}"
        if spec.kind == MatchKind.CONTAINS:
            return f"{mapped} = /.*{v}.*/ nocase"
        if spec.kind == MatchKind.STARTSWITH:
            return f"{mapped} = /{v}.*/ nocase"
        if spec.kind == MatchKind.ENDSWITH:
            return f"{mapped} = /.*{v}/ nocase"
        if spec.kind == MatchKind.REGEX:
            return f"re.regex({mapped}, `{v}`)"
        if spec.kind in (MatchKind.GT, MatchKind.GTE, MatchKind.LT, MatchKind.LTE):
            op = {MatchKind.GT: ">", MatchKind.GTE: ">=", MatchKind.LT: "<", MatchKind.LTE: "<="}[spec.kind]
            return f"{mapped} {op} {v}"
        if spec.kind == MatchKind.KEYWORD:
            return f"$e = /.*{v}.*/ nocase"
        return f"{mapped} = {self.quote(v)}"

    def render_null(self, node) -> str:
        mapped = self.map_field(node.field)
        return f'{mapped} != ""' if node.negated else f'{mapped} = ""'


class LogScaleRenderer(Renderer):
    target = "logscale"
    and_op = " "
    or_op = " or "
    not_prefix = "!"

    def field_clause(self, field: str, spec: MatchSpec) -> str:
        mapped = self.map_field(field)
        v = spec.value
        if spec.kind == MatchKind.EQUALS:
            return f"{mapped}={self.quote(v)}"
        if spec.kind == MatchKind.CONTAINS:
            return f"{mapped}=*{v}*"
        if spec.kind == MatchKind.STARTSWITH:
            return f"{mapped}={v}*"
        if spec.kind == MatchKind.ENDSWITH:
            return f"{mapped}=*{v}"
        if spec.kind == MatchKind.REGEX:
            return f"{mapped}=/{v}/"
        if spec.kind in (MatchKind.GT, MatchKind.GTE, MatchKind.LT, MatchKind.LTE):
            op = {MatchKind.GT: ">", MatchKind.GTE: ">=", MatchKind.LT: "<", MatchKind.LTE: "<="}[spec.kind]
            return f"{mapped}{op}{v}"
        if spec.kind == MatchKind.KEYWORD:
            return f"/{v}/"
        return f"{mapped}={self.quote(v)}"


RENDERERS = {
    "splunk": SplunkRenderer,
    "sentinel": SentinelRenderer,
    "elastic": ElasticRenderer,
    "opensearch": OpenSearchRenderer,
    "qradar": QRadarRenderer,
    "chronicle": ChronicleRenderer,
    "logscale": LogScaleRenderer,
}


def get_renderer(target: str, searches, warnings, field_overrides=None) -> Renderer:
    cls = RENDERERS.get(target, ElasticRenderer)
    return cls(searches, warnings, field_overrides=field_overrides)
