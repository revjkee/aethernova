# agent_mash/tests/unit/utils/test_serializers.py
from __future__ import annotations

import base64
import datetime as dt
import importlib
import json
import os
import typing as t
import uuid
from dataclasses import dataclass
from decimal import Decimal

import pytest


TEST_SERIALIZERS_IMPORT = os.getenv("TEST_SERIALIZERS_IMPORT", "").strip()
# Example:
# TEST_SERIALIZERS_IMPORT="agent_mash.utils.serializers"


def _import_module(name: str):
    try:
        return importlib.import_module(name)
    except Exception as e:
        raise RuntimeError(f'Cannot import module "{name}".') from e


def _resolve_serializers_module():
    """
    Resolve serializers module deterministically.

    Priority:
      1) TEST_SERIALIZERS_IMPORT env var
      2) common candidates
    If not found, raise RuntimeError with an explicit instruction.
    """
    if TEST_SERIALIZERS_IMPORT:
        return _import_module(TEST_SERIALIZERS_IMPORT)

    candidates = (
        "agent_mash.utils.serializers",
        "agent_mash.utils.serialization",
        "agent_mash.core.utils.serializers",
        "agent_mash.core.serialization",
        "agent_mash.shared.serializers",
        "agent_mash.shared.serialization",
    )

    last_err: Exception | None = None
    for mod_name in candidates:
        try:
            return _import_module(mod_name)
        except Exception as e:
            last_err = e
            continue

    raise RuntimeError(
        "Cannot resolve serializers module for tests. "
        "Set environment variable TEST_SERIALIZERS_IMPORT to the correct module path, "
        'for example: TEST_SERIALIZERS_IMPORT="agent_mash.utils.serializers".'
    ) from last_err


def _get_callable(mod, names: tuple[str, ...]) -> t.Callable[..., t.Any] | None:
    for n in names:
        v = getattr(mod, n, None)
        if callable(v):
            return t.cast(t.Callable[..., t.Any], v)
    return None


@dataclass(frozen=True)
class SerializersAPI:
    dumps: t.Callable[..., t.Any] | None
    loads: t.Callable[..., t.Any] | None
    to_jsonable: t.Callable[..., t.Any] | None
    encode: t.Callable[..., t.Any] | None


@pytest.fixture(scope="session")
def serializers_module():
    return _resolve_serializers_module()


@pytest.fixture(scope="session")
def api(serializers_module) -> SerializersAPI:
    """
    Collect only реально существующие функции модуля, без предположений.
    """
    dumps = _get_callable(serializers_module, ("dumps", "json_dumps", "dump_json", "to_json", "serialize", "dumps_json"))
    loads = _get_callable(serializers_module, ("loads", "json_loads", "load_json", "from_json", "deserialize", "loads_json"))
    to_jsonable = _get_callable(
        serializers_module,
        ("to_jsonable", "jsonable", "to_primitive", "to_dict", "to_json_ready", "encode_jsonable"),
    )
    encode = _get_callable(
        serializers_module,
        ("encode", "default", "encoder", "json_default", "default_encoder"),
    )
    return SerializersAPI(dumps=dumps, loads=loads, to_jsonable=to_jsonable, encode=encode)


def _is_json_compatible(value: t.Any) -> bool:
    """
    JSON-compatible means json.dumps(value) succeeds in stdlib json.
    """
    try:
        json.dumps(value, ensure_ascii=False, separators=(",", ":"))
        return True
    except TypeError:
        return False


def _assert_valid_json_text(s: str) -> t.Any:
    """
    Assert s is valid JSON string; returns parsed object.
    """
    assert isinstance(s, str)
    parsed = json.loads(s)
    return parsed


def _make_payload():
    """
    Deterministic payload with common "hard" types.
    We do not assume your serializer supports all of them; tests will gate by available API.
    """
    now = dt.datetime(2026, 2, 2, 12, 34, 56, tzinfo=dt.timezone.utc)
    today = dt.date(2026, 2, 2)
    uid = uuid.UUID("12345678-1234-5678-1234-567812345678")
    dec = Decimal("12345.6789")
    raw = b"binary\x00data"

    return {
        "str": "hello",
        "int": 123,
        "float": 1.25,
        "bool": True,
        "none": None,
        "list": [1, "x", False, None],
        "dict": {"a": 1, "b": "y"},
        "datetime": now,
        "date": today,
        "uuid": uid,
        "decimal": dec,
        "bytes": raw,
    }


@pytest.mark.parametrize(
    "simple",
    [
        {"a": 1, "b": "x", "c": True, "d": None, "e": [1, 2, 3]},
        [1, "x", False, None],
        "text",
        42,
        3.14,
        True,
        None,
    ],
)
def test_stdlib_json_compatibility_baseline(simple):
    """
    Baseline: stdlib json can serialize basic JSON types.
    """
    json.dumps(simple, ensure_ascii=False)


def test_api_presence_minimum(api: SerializersAPI):
    """
    Industrial guard: module must provide at least one of dumps/to_jsonable/encode to be testable.
    If not present, fail explicitly so the contract is fixed rather than silently skipped.
    """
    if api.dumps is None and api.to_jsonable is None and api.encode is None:
        raise AssertionError(
            "Serializers module does not expose any known serialization API. "
            "Expected at least one of: dumps/json_dumps/serialize or to_jsonable/to_primitive or encode/default."
        )


def test_dumps_produces_valid_json_when_available(api: SerializersAPI):
    if api.dumps is None:
        pytest.skip("No dumps-like function exposed by serializers module.")

    payload = _make_payload()

    # dumps may accept various kwargs; we call minimally.
    out = api.dumps(payload)

    # Some implementations return bytes; normalize.
    if isinstance(out, (bytes, bytearray)):
        out = out.decode("utf-8")

    parsed = _assert_valid_json_text(out)

    # Should at least preserve core fields
    assert isinstance(parsed, dict)
    assert parsed.get("str") == "hello"
    assert parsed.get("int") == 123
    assert parsed.get("bool") is True
    assert parsed.get("none") is None


def test_loads_round_trip_when_available(api: SerializersAPI):
    if api.dumps is None or api.loads is None:
        pytest.skip("No dumps+loads pair exposed by serializers module.")

    payload = {
        "a": 1,
        "b": "x",
        "c": True,
        "d": None,
        "e": [1, 2, 3],
        "f": {"k": "v"},
    }

    out = api.dumps(payload)
    if isinstance(out, (bytes, bytearray)):
        out = out.decode("utf-8")

    parsed = api.loads(out)
    assert parsed == payload


def test_to_jsonable_returns_json_compatible_object_when_available(api: SerializersAPI):
    if api.to_jsonable is None:
        pytest.skip("No to_jsonable-like function exposed by serializers module.")

    payload = _make_payload()
    obj = api.to_jsonable(payload)

    # Must be JSON-compatible for stdlib json
    assert _is_json_compatible(obj), "to_jsonable must return an object compatible with stdlib json.dumps"

    # Ensure basic invariants
    if isinstance(obj, dict):
        assert obj.get("str") == "hello"
        assert obj.get("int") == 123


def test_encode_default_handles_common_types_when_available(api: SerializersAPI):
    """
    If module exposes encode/default/encoder callable, validate it can convert known hard types
    into JSON-compatible representations (not necessarily a specific format).
    """
    if api.encode is None:
        pytest.skip("No encode/default/encoder function exposed by serializers module.")

    payload = _make_payload()

    # We only validate that each hard type becomes JSON-compatible after encode.
    hard_values = {
        "datetime": payload["datetime"],
        "date": payload["date"],
        "uuid": payload["uuid"],
        "decimal": payload["decimal"],
        "bytes": payload["bytes"],
    }

    encoded: dict[str, t.Any] = {}
    for k, v in hard_values.items():
        ev = api.encode(v)
        encoded[k] = ev
        assert _is_json_compatible(ev), f"Encoded value for {k} is not JSON-compatible"

    # Specific minimal checks that do not assume a strict format:
    # bytes commonly become base64 or hex or utf-8 string; ensure it is a string.
    b = encoded["bytes"]
    assert isinstance(b, (str, int, float, bool, type(None), list, dict)), "Encoded bytes must be JSON-compatible"

    # If it is a string and looks like base64, ensure it decodes (best-effort, no strict requirement).
    if isinstance(b, str):
        try:
            base64.b64decode(b.encode("utf-8"), validate=True)
        except Exception:
            # Not base64; acceptable. We do not enforce a specific encoding format.
            pass


def test_dumps_respects_custom_encoder_if_supported(api: SerializersAPI):
    """
    Some serializers accept default= or option= for custom types.
    We do not assume signature; we only run this test if dumps is present and accepts a 'default' parameter.
    """
    if api.dumps is None:
        pytest.skip("No dumps-like function exposed by serializers module.")

    import inspect

    sig = None
    try:
        sig = inspect.signature(api.dumps)
    except Exception:
        pytest.skip("Cannot introspect dumps signature; skipping optional encoder test.")

    if "default" not in sig.parameters:
        pytest.skip("dumps does not accept 'default' parameter; skipping optional encoder test.")

    def _default(o: t.Any):
        if isinstance(o, Decimal):
            return str(o)
        raise TypeError(f"Unsupported type: {type(o)!r}")

    out = api.dumps({"d": Decimal("1.5")}, default=_default)
    if isinstance(out, (bytes, bytearray)):
        out = out.decode("utf-8")
    parsed = _assert_valid_json_text(out)
    assert parsed == {"d": "1.5"}
