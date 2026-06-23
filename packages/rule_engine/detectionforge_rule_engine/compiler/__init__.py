"""AST-based Sigma compiler (Generator V2 core).

Replaces the string-matching converter with a real parse -> AST -> render
pipeline that supports the full Sigma modifier and condition set.
"""

from .api import SUPPORTED_TARGETS, compile_rule
from .warnings import CompilerWarning

__all__ = ["compile_rule", "SUPPORTED_TARGETS", "CompilerWarning"]
