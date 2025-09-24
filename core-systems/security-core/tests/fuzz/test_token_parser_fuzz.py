# File: tests/unit/test_token_parser_fuzz.py
# Purpose: Industrial fuzz/property tests for a token parser (JWT/JOSE/opaque).
# Python: 3.10+

from __future__ import annotations

import base64
import importlib
import inspect
import io
import json
import os
import random
import re
import sys
import types
from dataclasses import dataclass
from typing import Any, Callable, Optional

import pytest

# Hypothesis (property-based)
hyp = None
st = None
settings = None
HealthCheck = None
try:  # soft dependency to keep CI flexible
    import hypothesis as hyp  # type: ignore
    from hypothesis import strategies as st  # type: ignore
    from hypothesis import settings, HealthCheck  # type: ignore
except Exception:  # pragma: no cover
    pass

# Optional coverage-guided fuzzer
_have_atheris = False
try:
    import atheris  # type: ignore
    _have_atheris = True
except Exception:  # pragma: no cover
    pass


# =========================
# Locate parser under test
# =========================

@dataclass
class ParserHandle:
    call: Callable[[str | bytes], Any]
    name: str


def _import_first(*mods: str) -> Optional[types.ModuleType]:
    for m in mods:
        try:
            return importlib.import_module(m)
        except Exception:
            continue
    return None


def _discover_parser() -> Optional[ParserHandle]:
    """
    Try to locate a callable that parses token strings.
    Supported targets (by name): parse, parse_token, parse_jwt, decode, decode_token, parse_any, safe_parse.
    Also supports a class with .parse(self, token).
    """
    mod = _import_first(
        "security.tokens.parser",
        "security_core.security.tokens.parser",
        "security.tokens",
        "security_core.security.tokens",
    )
    if not mod:
        return None

    # 1) Direct function candidates
    candidates = ["parse", "parse_token", "parse_jwt", "decode", "decode_token", "parse_any", "safe_parse"]
    for fn in candidates:
        if hasattr(mod, fn) and callable(getattr(mod, fn)):
            f = getattr(mod, fn)
            return ParserHandle(_wrap_callable(f), f"{mod.__name__}.{fn}")

    # 2) Class with .parse
    class_candidates = ["Parser", "TokenParser", "JWTParser"]
    for cls_name in class_candidates:
        if hasattr(mod, cls_name):
            cls = getattr(mod, cls_name)
            try:
                obj = cls()  # best-effort no-arg constructor
                if hasattr(obj, "parse") and callable(getattr(obj, "parse")):
                    return ParserHandle(_wrap_method(obj.parse), f"{mod.__name__}.{cls_name}.parse")
            except Exception:
                continue

    # 3) Fallback: any callable named like *parse*
    for name, attr in inspect.getmembers(mod):
        if callable(attr) and "parse" in name.lower():
            return ParserHandle(_wrap_callable(attr), f"{mod.__name__}.{name}")

    return None


def _to_text(x: str | bytes) -> str:
    if isinstance(x, str):
        return x
    try:
        return x.decode("utf-8")
    except Exception:
        return x.decode("utf-8", errors="ignore")


def _wrap_callable(fn: Callable[..., Any]) -> Callable[[str | bytes], Any]:
    def _call(token: str | bytes) -> Any:
        t = _to_text(token)
        # common parse call shapes: fn(token) or fn(token=...)
        try:
            return fn(t)  # type: ignore
        except TypeError:
            return fn(token=t)  # type: ignore
    return _call


def _wrap_method(m: Callable[..., Any]) -> Callable[[str | bytes], Any]:
    def _call(token: str | bytes) -> Any:
        t = _to_text(token)
        try:
            return m(t)  # type: ignore
        except TypeError:
            return m(token=t)  # type: ignore
    return _call


PARSER = _discover_parser()
if not PARSER:
    pytest.skip("Token parser module not found; skipping fuzz suite", allow_module_level=True)


# =========================
# Helpers and invariants
# =========================

_BAD_EXC = (MemoryError, RecursionError, SystemExit, KeyboardInterrupt)

_b64u_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"


def b64u_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _is_probably_jwt(s: str) -> bool:
    return s.count(".") >= 2 and all(len(part) >= 0 for part in s.split("."))


def _safe_call(token: str | bytes) -> tuple[bool, Optional[Any], Optional[BaseException]]:
    """
    Returns (ok, result, exc)
    ok=True  -> parser returned a value (result non-None)
    ok=False -> parser raised an exception (exc set)
    """
    try:
        res = PARSER.call(token)
        return True, res, None
    except _BAD_EXC as e:
        # Catastrophic exception: re-raise to fail tests
        raise
    except BaseException as e:
        return False, None, e


def _repr_str_json(obj: Any) -> None:
    # Basic sanity on returned objects: repr/str/jsonable where applicable.
    _ = repr(obj)
    _ = str(obj)
    try:
        json.dumps(obj, default=lambda x: getattr(x, "__dict__", str(x)))
    except Exception:
        # not all objects are json-serializable; that is OK
        pass


# =========================
# Hypothesis strategies
# =========================

if hyp is not None:

    @st.composite
    def jwt_like(draw) -> str:
        # Generate header/payload JSON with common JOSE fields
        alg = draw(st.sampled_from(["RS256", "ES256", "EdDSA", "HS256", "none"]))
        typ = draw(st.sampled_from(["JWT", "JOSE", ""]))
        hdr = {"alg": alg}
        if typ:
            hdr["typ"] = typ
        # payload
        iat = draw(st.integers(min_value=0, max_value=2**31 - 1))
        exp = draw(st.integers(min_value=iat, max_value=min(iat + 10**6, 2**31 - 1)))
        sub = draw(st.text(min_size=0, max_size=32))
        aud = draw(st.one_of(st.text(min_size=0, max_size=16), st.lists(st.text(min_size=0, max_size=8), max_size=3)))
        pl = {"iat": iat, "exp": exp, "sub": sub, "aud": aud}
        # optional nested fields and arrays for cardinality
        if draw(st.booleans()):
            pl["scope"] = " ".join(draw(st.lists(st.sampled_from(["read", "write", "admin", "profile"]), min_size=0, max_size=4)))
        # parts
        h = b64u_encode(json.dumps(hdr, separators=(",", ":")).encode())
        p = b64u_encode(json.dumps(pl, separators=(",", ":")).encode())
        # signature: may be empty or random
        sig_len = draw(st.integers(min_value=0, max_value=128))
        sig = "".join(draw(st.lists(st.sampled_from(list(_b64u_alphabet)), min_size=sig_len, max_size=sig_len)))
        return f"{h}.{p}.{sig}"

    def weird_unicode() -> st.SearchStrategy[str]:
        return st.text(
            alphabet=st.characters(
                blacklist_categories=("Cs",),  # no surrogates
                min_codepoint=0,
                max_codepoint=0x10FFFF,
            ),
            min_size=0,
            max_size=1024,
        )

    def b64u_fragment(min_len=0, max_len=512) -> st.SearchStrategy[str]:
        return st.text(alphabet=list(_b64u_alphabet), min_size=min_len, max_size=max_len)

    def random_token_like() -> st.SearchStrategy[str]:
        # Mix of jwt-like, b64u junk, many dots, binary-ish, and unicode chaos
        return st.one_of(
            jwt_like(),
            st.builds(lambda a, b, c: f"{a}.{b}.{c}", b64u_fragment(0, 256), b64u_fragment(0, 256), b64u_fragment(0, 256)),
            st.builds(lambda a, b: a + "." * b + a, b64u_fragment(1, 32), st.integers(min_value=1, max_value=100)),
            weird_unicode(),
            st.binary(min_size=0, max_size=4096).map(lambda b: _to_text(b)),
            st.just(""),
            st.just("."),
            st.just(".."),
            st.just(" "),
            st.builds(lambda n: "a" * n, st.integers(min_value=0, max_value=10000)),
        )

    def _hypo_settings():
        # Reasonable deadlines to catch hangs; suppress too_slow spam in CI.
        return settings(
            max_examples=int(os.getenv("FUZZ_MAX_EXAMPLES", "400")),
            deadline=int(os.getenv("FUZZ_DEADLINE_MS", "200")),
            suppress_health_check=[HealthCheck.too_slow, HealthCheck.filter_too_much],
        )


# =========================
# Property tests
# =========================

@pytest.mark.skipif(hyp is None, reason="hypothesis not installed")
@_hypo_settings()
@hyp.given(token=random_token_like())
def test_parser_never_catastrophically_crashes(token: str):
    """
    For any input string, parser must not raise 'bad' exceptions.
    It's OK to raise a domain-specific parse error.
    """
    ok, res, exc = _safe_call(token)
    # Either returns or raises a non-catastrophic exception
    if ok:
        _repr_str_json(res)


@pytest.mark.skipif(hyp is None, reason="hypothesis not installed")
@_hypo_settings()
@hyp.given(token=jwt_like())
def test_jwt_like_inputs_do_not_hang_and_optionally_parse(token: str):
    """
    For JWT-shaped inputs, parser should either parse or reject fast.
    If parsed, and result carries header/payload, they must have sane types.
    """
    ok, res, exc = _safe_call(token)
    if ok and res is not None:
        # Probe common shapes without coupling to exact schema
        # Accept dict-like or object with attributes
        hdr = getattr(res, "header", None) if not isinstance(res, dict) else res.get("header")
        pl = getattr(res, "payload", None) if not isinstance(res, dict) else res.get("payload")
        if hdr is not None:
            assert isinstance(hdr, (dict, types.MappingProxyType))
        if pl is not None:
            assert isinstance(pl, (dict, types.MappingProxyType))
        _repr_str_json(res)


@pytest.mark.skipif(hyp is None, reason="hypothesis not installed")
@_hypo_settings()
@hyp.given(a=st.integers(min_value=0, max_value=4096), b=st.integers(min_value=0, max_value=4096))
def test_large_inputs_of_dots_and_nulls(a: int, b: int):
    """
    Stress long pathological strings: many dots and null bytes.
    """
    s = ("\x00" * a) + ("." * b) + ("\x00" * a)
    ok, res, exc = _safe_call(s)
    if ok and res is not None:
        _repr_str_json(res)


@pytest.mark.skipif(hyp is None, reason="hypothesis not installed")
@_hypo_settings()
@hyp.given(prefix=b64u_fragment(0, 2048), middle=b64u_fragment(0, 2048), suffix=b64u_fragment(0, 2048))
def test_extreme_segment_sizes(prefix: str, middle: str, suffix: str):
    token = f"{prefix}.{middle}.{suffix}"
    ok, res, exc = _safe_call(token)
    if ok and res is not None:
        _repr_str_json(res)


@pytest.mark.skipif(hyp is None, reason="hypothesis not installed")
@_hypo_settings()
@hyp.given(raw=st.binary(min_size=0, max_size=8192))
def test_binary_data_coerced_to_text(raw: bytes):
    ok, res, exc = _safe_call(raw)
    if ok and res is not None:
        _repr_str_json(res)


# =========================
# Atheris harness (optional)
# =========================

def _atheris_one(data: bytes) -> None:
    """
    Coverage-guided fuzz entrypoint. Reproduces the same invariants:
    never crash with catastrophic exceptions for arbitrary bytes.
    """
    if not PARSER:
        return
    try:
        _safe_call(data)
    except _BAD_EXC:
        raise


if __name__ == "__main__" and _have_atheris:
    # Run as: python tests/unit/test_token_parser_fuzz.py -atheris_runs=100000
    atheris.Setup(sys.argv, _atheris_one)
    atheris.Fuzz()
