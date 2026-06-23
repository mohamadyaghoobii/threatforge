"""Tokenize and parse a Sigma ``condition`` string into a boolean AST.

Grammar (precedence low -> high):

    expr      := or_expr ( '|' aggregation )?
    or_expr   := and_expr ( 'or' and_expr )*
    and_expr  := not_expr ( 'and' not_expr )*
    not_expr  := 'not' not_expr | primary
    primary   := '(' or_expr ')'
               | quantifier
               | identifier
    quantifier:= ('1'|'all') 'of' ( pattern | 'them' )

Aggregation tail (optional):
    '|' func '(' field? ')' ( 'by' field (',' field)* )? op number
where op in > >= < <= ==
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .ast import Aggregation, AndNode, Node, NotNode, OrNode, RefNode, TrueNode
from .warnings import CompilerWarning, warn

_TOKEN_RE = re.compile(
    r"""
    \s*(?:
      (?P<lparen>\() |
      (?P<rparen>\)) |
      (?P<pipe>\|) |
      (?P<op>>=|<=|==|>|<) |
      (?P<comma>,) |
      (?P<number>\d+(?:\.\d+)?) |
      (?P<word>[A-Za-z0-9_*\.\-]+)
    )
    """,
    re.VERBOSE,
)

_KEYWORDS = {"and", "or", "not", "of", "them", "by"}
_QUANTIFIERS = {"1", "all", "any"}
_AGG_FUNCS = {"count", "sum", "min", "max", "avg"}


@dataclass
class Token:
    kind: str
    value: str


def tokenize(condition: str) -> list[Token]:
    tokens: list[Token] = []
    pos = 0
    while pos < len(condition):
        m = _TOKEN_RE.match(condition, pos)
        if not m or m.end() == pos:
            # Skip an unrecognized char to stay resilient.
            if condition[pos].isspace():
                pos += 1
                continue
            pos += 1
            continue
        pos = m.end()
        kind = m.lastgroup
        value = m.group()
        stripped = value.strip()
        if kind == "word":
            low = stripped.lower()
            if low in _KEYWORDS:
                tokens.append(Token(low, low))
            else:
                tokens.append(Token("ident", stripped))
        else:
            tokens.append(Token(kind, stripped))
    return tokens


class ConditionParser:
    def __init__(self, search_names: list[str], warnings: list[CompilerWarning]):
        self.search_names = search_names
        self.warnings = warnings
        self.tokens: list[Token] = []
        self.i = 0
        self.aggregation: Aggregation | None = None

    # --- token helpers ---
    def _peek(self) -> Token | None:
        return self.tokens[self.i] if self.i < len(self.tokens) else None

    def _next(self) -> Token | None:
        tok = self._peek()
        if tok is not None:
            self.i += 1
        return tok

    def _accept(self, kind: str) -> Token | None:
        tok = self._peek()
        if tok and tok.kind == kind:
            return self._next()
        return None

    # --- entry ---
    def parse(self, condition: str) -> tuple[Node, Aggregation | None]:
        self.tokens = tokenize(condition)
        self.i = 0
        if not self.tokens:
            return self._all_and(), None
        node = self._parse_or()
        # Aggregation tail.
        if self._peek() and self._peek().kind == "pipe":
            self._next()
            self.aggregation = self._parse_aggregation()
        return node, self.aggregation

    # --- expressions ---
    def _parse_or(self) -> Node:
        children = [self._parse_and()]
        while self._peek() and self._peek().kind == "or":
            self._next()
            children.append(self._parse_and())
        if len(children) == 1:
            return children[0]
        return OrNode(children=children)

    def _parse_and(self) -> Node:
        children = [self._parse_not()]
        while self._peek() and self._peek().kind == "and":
            self._next()
            children.append(self._parse_not())
        if len(children) == 1:
            return children[0]
        return AndNode(children=children)

    def _parse_not(self) -> Node:
        if self._peek() and self._peek().kind == "not":
            self._next()
            return NotNode(child=self._parse_not())
        return self._parse_primary()

    def _parse_primary(self) -> Node:
        tok = self._peek()
        if tok is None:
            return self._all_and()
        if tok.kind == "lparen":
            self._next()
            node = self._parse_or()
            self._accept("rparen")
            return node
        # Quantifiers: "1 of ...", "all of ...", "any of ...". Note "1" is
        # tokenized as a number, so accept it here as well.
        if (tok.kind == "number" and tok.value == "1") or (tok.kind == "ident" and tok.value in _QUANTIFIERS):
            return self._parse_quantifier()
        if tok.kind == "ident":
            self._next()
            return self._resolve_ref(tok.value)
        # Unexpected token; consume and continue.
        self._next()
        return self._resolve_ref(tok.value)

    def _parse_quantifier(self) -> Node:
        quant = self._next().value  # '1' or 'all'
        # expect 'of'
        if self._peek() and self._peek().kind == "of":
            self._next()
        target = self._peek()
        names: list[str]
        if target and target.kind == "them":
            self._next()
            names = list(self.search_names)
        elif target and target.kind == "ident":
            self._next()
            names = self._match_pattern(target.value)
        else:
            names = list(self.search_names)
        if not names:
            self.warnings.append(
                warn(
                    "CONDITION_AMBIGUOUS",
                    message=f"Quantifier pattern matched no selections: {quant} of ...",
                )
            )
            return TrueNode()
        nodes = [self._resolve_ref(n) for n in names]
        if quant == "all":
            return AndNode(children=nodes) if len(nodes) > 1 else nodes[0]
        # "1 of" / "any of" => OR
        return OrNode(children=nodes) if len(nodes) > 1 else nodes[0]

    def _match_pattern(self, pattern: str) -> list[str]:
        if "*" in pattern:
            regex = re.compile("^" + re.escape(pattern).replace(r"\*", ".*") + "$")
            return [n for n in self.search_names if regex.match(n)]
        if pattern in self.search_names:
            return [pattern]
        # Treat as prefix if it ends loosely.
        return [n for n in self.search_names if n.startswith(pattern)]

    def _resolve_ref(self, name: str) -> Node:
        return RefNode(name=name)

    def _all_and(self) -> Node:
        if not self.search_names:
            return TrueNode()
        if len(self.search_names) == 1:
            return RefNode(name=self.search_names[0])
        return AndNode(children=[RefNode(name=n) for n in self.search_names])

    def _parse_aggregation(self) -> Aggregation:
        agg = Aggregation()
        tok = self._peek()
        if tok and tok.kind == "ident" and tok.value.lower() in _AGG_FUNCS:
            agg.func = tok.value.lower()
            self._next()
        # optional ( field )
        if self._accept("lparen"):
            ftok = self._peek()
            if ftok and ftok.kind == "ident":
                agg.agg_field = self._next().value
            self._accept("rparen")
        # by field, field
        if self._peek() and self._peek().kind == "by":
            self._next()
            while self._peek() and self._peek().kind == "ident":
                agg.group_by.append(self._next().value)
                if self._peek() and self._peek().kind == "comma":
                    self._next()
                    continue
                break
        # op number
        if self._peek() and self._peek().kind == "op":
            agg.op = self._next().value
            ntok = self._peek()
            if ntok and ntok.kind == "number":
                agg.threshold = float(self._next().value)
        return agg


def parse_condition(
    condition: str | None,
    search_names: list[str],
    warnings: list[CompilerWarning],
) -> tuple[Node, Aggregation | None]:
    parser = ConditionParser(search_names, warnings)
    if not condition or not str(condition).strip():
        return parser._all_and(), None
    return parser.parse(str(condition))
