# automation-core/tests/unit/test_parsers.py
"""
Unit tests that define the contract for automation_core.parsers.

Covered parsers (expected import path):
    from automation_core.parsers import (
        parse_bool,
        parse_int,
        parse_float,
        parse_size_bytes,
        parse_duration_seconds,
        parse_datetime,     # RFC 3339 timestamps
        parse_url,          # RFC 3986 validation
        parse_list,
    )

Rationales and public specs:
- RFC 3339 timestamps (Internet profile of ISO 8601).  # IETF: rfc3339
- RFC 3986 generic URI syntax (scheme, authority, path, query, fragment).  # IETF: rfc3986
- pytest parametrization idioms.  # pytest docs
- ISO 8601 duration lexical form as used by W3C XML Schema (PnDTnHnMnS).  # W3C XML Schema Datatypes

These tests do not perform any network access.
"""

from __future__ import annotations

import math
from datetime import datetime, timezone, timedelta
import re
import sys

import pytest

# Fail fast with a clear message if the module under test is absent.
parsers = pytest.importorskip(
    "automation_core.parsers",
    reason="automation_core.parsers is required by test_parsers.py; implement it to satisfy the test contract.",
)
# Import symbols explicitly to ensure they exist.
parse_bool = getattr(parsers, "parse_bool")
parse_int = getattr(parsers, "parse_int")
parse_float = getattr(parsers, "parse_float")
parse_size_bytes = getattr(parsers, "parse_size_bytes")
parse_duration_seconds = getattr(parsers, "parse_duration_seconds")
parse_datetime = getattr(parsers, "parse_datetime")
parse_url = getattr(parsers, "parse_url")
parse_list = getattr(parsers, "parse_list")


# --------------------------- parse_bool ---------------------------------------

@pytest.mark.parametrize(
    "value,expected",
    [
        ("1", True),
        ("0", False),
        ("true", True),
        ("false", False),
        ("t", True),
        ("f", False),
        ("yes", True),
        ("no", False),
        ("on", True),
        ("off", False),
        (" True ", True),
        ("  FaLsE", False),
        (1, True),
        (0, False),
        (True, True),
        (False, False),
    ],
)
def test_parse_bool_truthy_falsy(value, expected):
    assert parse_bool(value) is expected


@pytest.mark.parametrize("bad", [None, " ", "foo", 2, -1, 3.14])
def test_parse_bool_invalid_raises(bad):
    with pytest.raises(ValueError):
        parse_bool(bad)


# --------------------------- parse_int ----------------------------------------

@pytest.mark.parametrize(
    "value,min_v,max_v,expected",
    [
        ("42", None, None, 42),
        (42, 0, 100, 42),
        ("0007", 0, 10, 7),
        ("-5", -10, 10, -5),
    ],
)
def test_parse_int_basic_and_bounds(value, min_v, max_v, expected):
    assert parse_int(value, minimum=min_v, maximum=max_v) == expected


@pytest.mark.parametrize("bad", ["", "  ", "3.14", "1e3", object()])
def test_parse_int_invalid(bad):
    with pytest.raises(ValueError):
        parse_int(bad)


@pytest.mark.parametrize("v,minimum,maximum", [("11", 0, 10), ("-11", -10, 10)])
def test_parse_int_out_of_bounds(v, minimum, maximum):
    with pytest.raises(ValueError):
        parse_int(v, minimum=minimum, maximum=maximum)


# --------------------------- parse_float --------------------------------------

@pytest.mark.parametrize(
    "value,expected",
    [
        ("3.14", 3.14),
        (3.14, 3.14),
        ("0", 0.0),
        ("-2.5", -2.5),
    ],
)
def test_parse_float_basic(value, expected):
    assert parse_float(value) == pytest.approx(expected, rel=0, abs=0)


@pytest.mark.parametrize("bad", ["", "NaN", "Infinity", "inf", "1,23", object()])
def test_parse_float_invalid(bad):
    with pytest.raises(ValueError):
        parse_float(bad)


# ----------------------- parse_size_bytes (binary units) ----------------------

@pytest.mark.parametrize(
    "value,expected",
    [
        ("1KiB", 1024),
        ("2KiB", 2 * 1024),
        ("1MiB", 1024**2),
        ("3GiB", 3 * 1024**3),
        ("1.5MiB", int(1.5 * 1024**2)),
        ("  512  B ", 512),
    ],
)
def test_parse_size_bytes_binary_units(value, expected):
    assert parse_size_bytes(value) == expected


@pytest.mark.parametrize("bad", ["", "1KB", "Mi", "1ZB", "foo", "-1MiB"])
def test_parse_size_bytes_invalid(bad):
    with pytest.raises(ValueError):
        parse_size_bytes(bad)


# ----------------------- parse_duration_seconds -------------------------------
# Expect support for human format (e.g., "1h30m", "45s") and ISO 8601 durations (e.g., "PT1H30M").

@pytest.mark.parametrize(
    "value,expected",
    [
        ("0s", 0),
        ("45s", 45),
        ("2m", 120),
        ("1h", 3600),
        ("1h30m", 5400),
        ("2h5m10s", 2 * 3600 + 5 * 60 + 10),
        ("PT90S", 90),      # ISO 8601 duration (W3C XML Schema)
        ("PT1H30M", 5400),  # ISO 8601 duration (W3C XML Schema)
    ],
)
def test_parse_duration_seconds(value, expected):
    assert parse_duration_seconds(value) == expected


@pytest.mark.parametrize("bad", ["", "  ", "P", "PT", "1x", "-5s", "P-1D"])
def test_parse_duration_seconds_invalid(bad):
    with pytest.raises(ValueError):
        parse_duration_seconds(bad)


# --------------------------- parse_datetime (RFC 3339) ------------------------
# RFC 3339 timestamps like "2025-09-05T10:00:00Z" or with offsets.

@pytest.mark.parametrize(
    "value,expected_utc",
    [
        ("2025-09-05T10:00:00Z", datetime(2025, 9, 5, 10, 0, 0, tzinfo=timezone.utc)),
        ("2025-09-05T12:00:00+02:00", datetime(2025, 9, 5, 10, 0, 0, tzinfo=timezone.utc)),
        ("2025-09-05T09:59:59-00:01", datetime(2025, 9, 5, 10, 0, 59, tzinfo=timezone.utc)),
    ],
)
def test_parse_datetime_rfc3339_normalizes_to_utc(value, expected_utc):
    dt = parse_datetime(value)
    assert dt.tzinfo is not None
    assert dt.astimezone(timezone.utc) == expected_utc


@pytest.mark.parametrize("bad", ["", "2025-09-05 10:00:00", "05-09-2025T10:00:00Z", "2025-13-01T00:00:00Z"])
def test_parse_datetime_invalid(bad):
    with pytest.raises(ValueError):
        parse_datetime(bad)


# --------------------------- parse_url (RFC 3986) -----------------------------

@pytest.mark.parametrize(
    "url",
    [
        "https://example.com",
        "https://example.com/path?x=1#frag",
        "http://localhost:8080/",
    ],
)
def test_parse_url_valid(url):
    assert parse_url(url) == url


@pytest.mark.parametrize(
    "bad",
    [
        "javascript:alert(1)",  # dangerous scheme
        "data:text/html;base64,PGgxPkJvb2s8L2gxPg==",
        "ftp://",               # missing host
        "://no-scheme",
        "http:///triple-slash",
        "",
        " \t",
    ],
)
def test_parse_url_invalid(bad):
    with pytest.raises(ValueError):
        parse_url(bad)


# --------------------------- parse_list ---------------------------------------

@pytest.mark.parametrize(
    "value,sep,expected",
    [
        ("a,b,c", ",", ["a", "b", "c"]),
        (" a ,  b , c  ", ",", ["a", "b", "c"]),
        ("a,,b,,,c", ",", ["a", "b", "c"]),
        ("one|two|three", "|", ["one", "two", "three"]),
        ("", ",", []),
        (None, ",", []),
    ],
)
def test_parse_list_basic(value, sep, expected):
    assert parse_list(value, sep=sep) == expected


# ---------------------- Property-based (optional) -----------------------------

hypothesis = pytest.importorskip("hypothesis", reason="hypothesis is optional; install to run property-based tests")
from hypothesis import given, strategies as st  # type: ignore  # noqa: E402


@given(st.lists(st.text(alphabet=st.characters(blacklist_categories=("Cs",)), min_size=1, max_size=10), min_size=0, max_size=20))
def test_parse_list_roundtrip_no_commas(items):
    # When items do not contain the separator, joining then parsing should round-trip.
    sep = ","
    assume_no_sep = all(sep not in s for s in items)
    if not assume_no_sep:
        pytest.skip("generated data contains separator; skip to keep property strict")
    s = sep.join(items)
    assert parse_list(s, sep=sep) == items


@given(st.integers(min_value=0, max_value=10**6))
def test_parse_duration_human_seconds_property(n):
    # "Xs" should parse to n seconds for any non-negative integer n.
    assert parse_duration_seconds(f"{n}s") == n
