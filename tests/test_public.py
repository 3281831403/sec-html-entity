"""Public smoke tests for HTML entity handling."""

from __future__ import annotations

from htmlentity import canonicalize, decode, encode, strip_tags


def test_decimal_entity_decodes_to_character() -> None:
    assert decode("&#65;") == "A"


def test_double_quote_is_escaped() -> None:
    assert encode('say "hi"') == "say &quot;hi&quot;"


def test_strip_tags_respects_quoted_attribute() -> None:
    assert strip_tags('<a title=">">x</a>') == "x"


def test_canonical_form_round_trip_is_stable() -> None:
    assert canonicalize("&amp;lt;") == "&amp;lt;"


def test_named_entities_are_case_sensitive() -> None:
    assert decode("&AMP;") == "&AMP;"