"""HTML entity handling for a comment sanitizer.

The sanitizer needs one predictable representation of user text: entities are
decoded once, output is escaped, unsafe markup is detected after every layer of
encoding has been peeled away, and tag stripping must not be fooled by quoted
attribute values.
"""

from __future__ import annotations

from typing import Dict, List, Optional

REPLACEMENT = "\ufffd"

_NAMED: Dict[str, str] = {
    "amp": "&",
    "lt": "<",
    "gt": ">",
    "quot": '"',
    "apos": "'",
    "nbsp": "\u00a0",
    "copy": "\u00a9",
    "reg": "\u00ae",
    "trade": "\u2122",
    "hellip": "\u2026",
    "mdash": "\u2014",
    "ndash": "\u2013",
    "laquo": "\u00ab",
    "raquo": "\u00bb",
    "lsaquo": "\u2039",
    "rsaquo": "\u203a",
    "euro": "\u20ac",
    "pound": "\u00a3",
    "yen": "\u00a5",
    "cent": "\u00a2",
    "sect": "\u00a7",
    "para": "\u00b6",
    "middot": "\u00b7",
    "bull": "\u2022",
    "deg": "\u00b0",
    "plusmn": "\u00b1",
    "times": "\u00d7",
    "divide": "\u00f7",
    "frac12": "\u00bd",
    "sup2": "\u00b2",
    "micro": "\u00b5",
    "ensp": "\u2002",
    "emsp": "\u2003",
    "thinsp": "\u2009",
    "zwnj": "\u200c",
    "zwj": "\u200d",
    "lrm": "\u200e",
    "rlm": "\u200f",
}

_ENCODE: Dict[str, str] = {
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
}


def _numeric(body: str) -> Optional[str]:
    """Decode a ``#`` entity body (without the leading ``&`` and trailing ``;``)."""
    if len(body) < 2 or body[0] != "#":
        return None

    if body[1] in ("x", "X"):
        digits = body[2:]
        if not digits or any(
            char not in "0123456789abcdefABCDEF" for char in digits
        ):
            return None
        base = 16
        normalized = digits.lstrip("0") or "0"
        if len(normalized) > 6 or (
            len(normalized) == 6 and normalized.upper() > "10FFFF"
        ):
            return REPLACEMENT
    else:
        digits = body[1:]
        if not digits or any(char not in "0123456789" for char in digits):
            return None
        base = 10
        normalized = digits.lstrip("0") or "0"
        if len(normalized) > 7 or (
            len(normalized) == 7 and normalized > "1114111"
        ):
            return REPLACEMENT

    code = int(normalized, base)
    if code == 0 or code > 0x10FFFF or 0xD800 <= code <= 0xDFFF:
        return REPLACEMENT
    return chr(code)


def decode_once(text: str) -> str:
    """Replace every well-formed entity once, leaving anything else untouched."""
    out: List[str] = []
    index = 0
    length = len(text)
    while index < length:
        if text[index] != "&":
            out.append(text[index])
            index += 1
            continue
        semi = text.find(";", index + 1)
        if semi == -1:
            out.append(text[index])
            index += 1
            continue
        body = text[index + 1:semi]
        if not body:
            out.append(text[index])
            index += 1
            continue
        if body.startswith("#"):
            replacement = _numeric(body)
        else:
            replacement = _NAMED.get(body)
        if replacement is None:
            out.append(text[index])
            index += 1
            continue
        out.append(replacement)
        index = semi + 1
    return "".join(out)


def decode(text: str) -> str:
    """Decode entities exactly once."""
    return decode_once(text)


def decode_all(text: str, max_rounds: Optional[int] = None) -> str:
    """Decode repeatedly until the text stops changing.

    Pass ``max_rounds`` to retain an explicit upper bound on decoding rounds.
    """
    current = text
    rounds = 0
    while max_rounds is None or rounds < max_rounds:
        nxt = decode_once(current)
        if nxt == current:
            return current
        current = nxt
        rounds += 1
    return current


def encode(text: str, quote: bool = True) -> str:
    """Escape markup characters; quotes are escaped only when ``quote`` is true."""
    out: List[str] = []
    for char in text:
        if char in "&<>" or (quote and char in "\"'"):
            out.append(_ENCODE[char])
        else:
            out.append(char)
    return "".join(out)


def canonicalize(text: str) -> str:
    """Return the single canonical representation used for comparisons."""
    return encode(decode(text))


def strip_tags(text: str) -> str:
    """Remove tags while honouring quoted attribute values."""
    out: List[str] = []
    index = 0
    length = len(text)
    while index < length:
        if text[index] != "<":
            out.append(text[index])
            index += 1
            continue
        cursor = index + 1
        quote = ""
        while cursor < length:
            char = text[cursor]
            if quote:
                if char == quote:
                    quote = ""
            elif char in "\"'":
                quote = char
            elif char == ">":
                break
            cursor += 1
        if cursor < length:
            index = cursor + 1
            continue
        out.append(text[index])
        index += 1
    return "".join(out)


def is_safe_text(text: str) -> bool:
    """Return whether text is inert after every encoding layer is removed."""
    decoded = decode_all(text)
    if "<" in decoded or ">" in decoded:
        return False
    lowered = decoded.lower().replace("\x00", "")
    for scheme in ("javascript:", "vbscript:", "data:text/html"):
        if scheme in lowered:
            return False
    return True