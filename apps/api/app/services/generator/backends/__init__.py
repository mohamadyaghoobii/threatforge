"""Conversion backends.

Each backend takes a parsed Sigma-shaped rule and produces a query string
for a given (target, profile, output_format). Backends are tried in priority
order; the first one to succeed wins. See ``engine.convert``.

Priority order today (G1 / G2):

1. ``sigma_cli`` — if the binary is on PATH (legacy compatibility)
2. ``builtin`` — the in-tree fallback converter

G3 adds ``pysigma_runtime`` at the top of the chain (in-process pySigma).
"""
