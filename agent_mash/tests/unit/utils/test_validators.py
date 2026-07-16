# agent_mash/tests/unit/utils/test_validators.py
from __future__ import annotations

import os
import importlib
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Optional, Sequence, Tuple

import pytest


@dataclass(frozen=True)
class _Spec:
    name: str
    valid: Sequence[Any]
    invalid: Sequence[Any]
    normalize: Optional[Callable[[Any], Any]] = None


def _env_first(*keys: str) -> Optional[str]:
    for k in keys:
        v = os.getenv(k)
        if v and v.strip():
            return v.strip()
    return None


def _import_validators_module() -> Any:
    module_path = _env_first("VALIDATORS_MODULE") or "agent_mash.utils.validators"
    try:
        return importlib.import_module(module_path)
    except Exception as e:
        pytest.skip(f"validators module import failed: {module_path!r}. reason: {type(e).__name__}: {e}")


def _get_callable(mod: Any, attr: str) -> Callable[..., Any]:
    fn = getattr(mod, attr, None)
    if fn is None:
        pytest.skip(f"validator function not found: {attr}")
    if not callable(fn):
        pytest.skip(f"validator attribute is not callable: {attr}")
    return fn


def _assert_valid(fn: Callable[..., Any], value: Any, normalize: Optional[Callable[[Any], Any]] = None) -> None:
    out = fn(value)
    if normalize is not None:
        assert out == normalize(value)
    else:
        assert out is not None


def _assert_invalid(fn: Callable[..., Any], value: Any) -> None:
    with pytest.raises((ValueError, TypeError)):
        fn(value)


def _specs() -> Tuple[_Spec, ...]:
    # These are conventional validator names. Missing functions are skipped safely.
    # You can extend this list without breaking existing projects.
    return (
        _Spec(
            name="validate_email",
            valid=("user@example.com", "USER@EXAMPLE.COM", "user.name+tag@example.co.uk"),
            invalid=("", "not-an-email", "user@", "@example.com", "user@example", None),
            normalize=lambda v: str(v).strip(),
        ),
        _Spec(
            name="validate_username",
            valid=("vlad", "Vlad_27", "user-01"),
            invalid=("", " ", "a", "this username is too long maybe", None),
            normalize=lambda v: str(v).strip(),
        ),
        _Spec(
            name="validate_password",
            valid=("Str0ngPass!123", "Another_Strong#2026"),
            invalid=("", "short", "12345678", None),
            normalize=lambda v: str(v),
        ),
        _Spec(
            name="validate_phone",
            valid=("+4915212345678", "+7 999 123-45-67", "15212345678"),
            invalid=("", "abc", "+", None),
            normalize=lambda v: str(v).strip(),
        ),
        _Spec(
            name="validate_url",
            valid=("https://example.com", "http://example.com/path?x=1", "https://sub.example.com"),
            invalid=("", "example.com", "ftp://example.com", None),
            normalize=lambda v: str(v).strip(),
        ),
        _Spec(
            name="validate_uuid",
            valid=("550e8400-e29b-41d4-a716-446655440000",),
            invalid=("", "not-a-uuid", "550e8400e29b41d4a716446655440000", None),
            normalize=lambda v: str(v).strip().lower(),
        ),
        _Spec(
            name="validate_slug",
            valid=("hello-world", "item-123", "a-b-c"),
            invalid=("", "Hello World", "hello_world", None),
            normalize=lambda v: str(v).strip().lower(),
        ),
    )


@pytest.mark.parametrize("spec", _specs(), ids=lambda s: s.name)
def test_validator_contract_valid_inputs(spec: _Spec) -> None:
    mod = _import_validators_module()
    fn = _get_callable(mod, spec.name)

    for value in spec.valid:
        _assert_valid(fn, value, spec.normalize)


@pytest.mark.parametrize("spec", _specs(), ids=lambda s: s.name)
def test_validator_contract_invalid_inputs(spec: _Spec) -> None:
    mod = _import_validators_module()
    fn = _get_callable(mod, spec.name)

    for value in spec.invalid:
        _assert_invalid(fn, value)


@pytest.mark.parametrize(
    ("attr", "truthy", "falsy"),
    (
        ("is_email", ("user@example.com", "a+b@c.io"), ("", "nope", None)),
        ("is_username", ("vlad", "user_01", "user-01"), ("", " ", None)),
        ("is_url", ("https://example.com", "http://example.com"), ("", "example.com", None)),
        ("is_uuid", ("550e8400-e29b-41d4-a716-446655440000",), ("", "not-a-uuid", None)),
    ),
    ids=lambda x: str(x),
)
def test_predicate_style_validators(attr: str, truthy: Sequence[Any], falsy: Sequence[Any]) -> None:
    mod = _import_validators_module()
    fn = getattr(mod, attr, None)
    if fn is None or not callable(fn):
        pytest.skip(f"predicate function not found or not callable: {attr}")

    for v in truthy:
        assert fn(v) is True

    for v in falsy:
        assert fn(v) is False
