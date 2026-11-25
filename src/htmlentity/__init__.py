"""Public interface for the sec-html-entity exercise."""

from .core import (
    canonicalize,
    decode,
    decode_all,
    encode,
    is_safe_text,
    strip_tags,
)

__all__ = [
    "decode",
    "decode_all",
    "encode",
    "canonicalize",
    "strip_tags",
    "is_safe_text",
]