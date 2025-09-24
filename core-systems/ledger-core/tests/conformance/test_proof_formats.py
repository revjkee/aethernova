# -*- coding: utf-8 -*-
"""
Conformance tests for proof formats in ledger-core.

This suite validates that every registered Proof Adapter implements a robust,
predictable, and secure interface:
 - Metadata contract (name, version, algorithm identifiers, context binding)
 - Verification correctness on valid/invalid inputs
 - Stable, canonical JSON and bytes round-trips
 - Versioning policy (SemVer)
 - Hash strength policy (reject weak hashes)
 - Optional: external test vectors per adapter

If an adapter or optional dependency is missing, tests will SKIP with a clear reason.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import inspect
import io
import json
import os
import random
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union

import pytest

# Optional Hypothesis support
try:
    from hypothesis import HealthCheck, given, settings
    from hypothesis import strategies as st

    HYP_AVAILABLE = True
except Exception:
    HYP_AVAILABLE = False

# Optional: packaging for SemVer validation
try:
    from packaging.version import Version, InvalidVersion
    PACKAGING_AVAILABLE = True
except Exception:
    PACKAGING_AVAILABLE = False


# -------------------------------
# Discovery of Proof Adapters
# -------------------------------

def _discover_adapters_via_registry() -> List[Any]:
    """
    Try to discover adapters via an internal registry:
    Expected API (duck-typing):
        from ledger_core.proofs import registry
        registry.discover_adapters() -> Iterable[adapter]
    """
    try:
        from ledger_core.proofs import registry  # type: ignore
    except Exception:
        return []
    try:
        adapters = list(registry.discover_adapters())  # type: ignore[attr-defined]
    except Exception:
        return []
    return adapters


def _discover_adapters_via_entrypoints() -> List[Any]:
    """
    Discover adapters via Python entry points group: 'ledger_core.proof_adapters'.
    Each entry point should provide either an adapter instance or a zero-arg factory.
    """
    adapters: List[Any] = []
    try:
        from importlib.metadata import entry_points  # py3.10+
    except Exception:
        try:
            # Backport for older Python
            from importlib_metadata import entry_points  # type: ignore
        except Exception:
            return []

    try:
        eps = entry_points(group="ledger_core.proof_adapters")
    except TypeError:
        # Older importlib_metadata API
        all_eps = entry_points()
        eps = all_eps.get("ledger_core.proof_adapters", [])  # type: ignore

    for ep in eps:
        try:
            obj = ep.load()
            if inspect.isclass(obj):
                adapters.append(obj())  # instantiate
            else:
                adapters.append(obj)
        except Exception:
            # Do not fail discovery if a single EP is broken
            continue
    return adapters


def discover_proof_adapters() -> List[Any]:
    """
    Unified discovery: registry first, then entry points.
    """
    adapters = _discover_adapters_via_registry()
    if not adapters:
        adapters = _discover_adapters_via_entrypoints()
    return adapters


# -------------------------------
# Adapter Contract Helpers
# -------------------------------

REQUIRED_METHODS = [
    "name",            # str
    "version",         # str (SemVer)
    "verify",          # callable(proof, statement, context=None) -> bool
    "to_bytes",        # callable(proof) -> bytes
    "from_bytes",      # callable(b: bytes) -> proof
    "to_json",         # callable(proof) -> Union[str, dict]
    "from_json",       # callable(s: Union[str, dict]) -> proof
]

OPTIONAL_METHODS = [
    "hash_id",         # str identifier of hash algorithm, e.g. "sha256"
    "hash_name",       # alias
    "algorithm",       # general algorithm name
    "canonicalize_json",  # callable(obj) -> str (RFC8785-like)
    "examples",        # callable() -> Iterable[Example], to supply test vectors
    "supports_context",# bool
    "generate",        # callable(statement, context=None, **kw) -> proof (for property tests)
]


def has_attr(obj: Any, name: str) -> bool:
    try:
        getattr(obj, name)
        return True
    except Exception:
        return False


def call_json_dump(obj: Union[str, Dict[str, Any]]) -> str:
    if isinstance(obj, str):
        # assume it is a JSON string already
        return obj
    return json.dumps(obj, separators=(",", ":"), sort_keys=True, ensure_ascii=False)


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def unb64(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def flip_random_bit(data: bytes) -> bytes:
    if not data:
        return data
    idx = random.randrange(len(data))
    bit = 1 << random.randrange(8)
    mutated = bytearray(data)
    mutated[idx] ^= bit
    return bytes(mutated)


def mutate_json_string(js: str) -> str:
    # Try to minimally mutate without breaking JSON syntax too often
    if not js:
        return js
    pos = random.randrange(len(js))
    ch = js[pos]
    # Replace a digit/letter with a different char
    repl = "Z" if ch != "Z" else "Y"
    return js[:pos] + repl + js[pos + 1:]


def _get_hash_label(adapter: Any) -> Optional[str]:
    for attr in ("hash_id", "hash_name", "algorithm"):
        if has_attr(adapter, attr):
            try:
                val = getattr(adapter, attr)
                if isinstance(val, str) and val:
                    return val.lower()
            except Exception:
                pass
    return None


# -------------------------------
# External Test Vectors Support
# -------------------------------

@dataclass
class Example:
    statement: Any
    context: Optional[Any]
    proof: Any


def _load_examples_from_adapter(adapter: Any) -> List[Example]:
    examples: List[Example] = []
    if has_attr(adapter, "examples"):
        try:
            for ex in adapter.examples():
                # duck-typing: allow tuple or dict
                if isinstance(ex, Example):
                    examples.append(ex)
                elif isinstance(ex, dict):
                    examples.append(
                        Example(
                            statement=ex.get("statement"),
                            context=ex.get("context"),
                            proof=ex.get("proof"),
                        )
                    )
                elif isinstance(ex, (tuple, list)) and len(ex) >= 2:
                    # (statement, proof) or (statement, context, proof)
                    if len(ex) == 2:
                        stmnt, prf = ex
                        examples.append(Example(statement=stmnt, context=None, proof=prf))
                    else:
                        stmnt, ctx, prf = ex[0], ex[1], ex[2]
                        examples.append(Example(statement=stmnt, context=ctx, proof=prf))
        except Exception:
            pass

    # Also check file-based vectors: tests/vectors/<adapter.name>/*
    base = Path(__file__).resolve().parent.parent / "vectors" / str(getattr(adapter, "name", "unknown"))
    if base.exists() and base.is_dir():
        for p in sorted(base.glob("*.json")):
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
            except Exception:
                continue
            if isinstance(data, dict) and "cases" in data and isinstance(data["cases"], list):
                for case in data["cases"]:
                    try:
                        examples.append(
                            Example(
                                statement=case.get("statement"),
                                context=case.get("context"),
                                proof=case.get("proof"),
                            )
                        )
                    except Exception:
                        continue
    return examples


# -------------------------------
# pytest configuration
# -------------------------------

ADAPTERS = discover_proof_adapters()

if not ADAPTERS:
    pytest.skip("No proof adapters discovered (registry or entry points).", allow_module_level=True)


# -------------------------------
# Tests: Metadata and Contract
# -------------------------------

@pytest.mark.parametrize("adapter", ADAPTERS, ids=lambda a: getattr(a, "name", repr(a)))
def test_adapter_contract(adapter: Any) -> None:
    missing = [m for m in REQUIRED_METHODS if not has_attr(adapter, m)]
    assert not missing, f"Adapter {getattr(adapter, 'name', repr(adapter))} missing methods: {missing}"

    assert isinstance(adapter.name, str) and adapter.name.strip(), "Adapter.name must be non-empty string"

    assert isinstance(adapter.version, str) and adapter.version.strip(), "Adapter.version must be non-empty string"
    if PACKAGING_AVAILABLE:
        try:
            Version(adapter.version)
        except InvalidVersion:
            pytest.fail(f"Adapter {adapter.name} has non-SemVer version string: {adapter.version}")

    # verify must be callable
    assert callable(adapter.verify), "Adapter.verify must be callable"
    assert callable(adapter.to_bytes), "Adapter.to_bytes must be callable"
    assert callable(adapter.from_bytes), "Adapter.from_bytes must be callable"
    assert callable(adapter.to_json), "Adapter.to_json must be callable"
    assert callable(adapter.from_json), "Adapter.from_json must be callable"

    # Optional flags sanity
    if has_attr(adapter, "supports_context"):
        assert isinstance(adapter.supports_context, bool), "supports_context must be bool if provided"


@pytest.mark.parametrize("adapter", ADAPTERS, ids=lambda a: getattr(a, "name", repr(a)))
def test_hash_strength_policy(adapter: Any) -> None:
    label = _get_hash_label(adapter)
    if not label:
        pytest.skip(f"{adapter.name}: hash identifier not provided; skipping strength policy check.")
    weak = {"md5", "sha1"}
    assert all(w not in label for w in weak), f"{adapter.name}: weak hash algorithm is not allowed ({label})"


# -------------------------------
# Tests: Round-trip and Validity on Examples
# -------------------------------

@pytest.mark.parametrize("adapter", ADAPTERS, ids=lambda a: getattr(a, "name", repr(a)))
def test_examples_roundtrip_and_verify(adapter: Any) -> None:
    examples = _load_examples_from_adapter(adapter)
    if not examples:
        pytest.skip(f"{adapter.name}: no examples provided by adapter or vectors directory.")

    for ex in examples:
        # Serialize to bytes and back
        b = adapter.to_bytes(ex.proof)
        assert isinstance(b, (bytes, bytearray)) and len(b) >= 0
        restored_from_bytes = adapter.from_bytes(bytes(b))

        # Serialize to JSON (string or dict) and back
        j = adapter.to_json(ex.proof)
        js = call_json_dump(j)
        try:
            parsed = json.loads(js)
        except Exception:
            pytest.fail(f"{adapter.name}: to_json did not produce valid JSON string/dict.")

        restored_from_json = adapter.from_json(parsed)

        # Cross-compare structural equality via bytes representation
        b_bytes = adapter.to_bytes(ex.proof)
        b_from_bytes = adapter.to_bytes(restored_from_bytes)
        b_from_json = adapter.to_bytes(restored_from_json)
        assert b_bytes == b_from_bytes == b_from_json, f"{adapter.name}: proof mismatch after round-trips."

        # Verify should accept the original triplets
        ok = adapter.verify(ex.proof, ex.statement, ex.context if has_attr(adapter, "supports_context") else None)
        assert ok is True, f"{adapter.name}: verify failed on a provided valid example."


@pytest.mark.parametrize("adapter", ADAPTERS, ids=lambda a: getattr(a, "name", repr(a)))
def test_verify_rejects_mutated_proof_and_statement(adapter: Any) -> None:
    examples = _load_examples_from_adapter(adapter)
    if not examples:
        pytest.skip(f"{adapter.name}: no examples provided by adapter or vectors directory.")

    # Take a single reasonable example (or a few) to test negative paths
    for ex in examples[:10]:
        # Mutate proof bytes
        b = adapter.to_bytes(ex.proof)
        if not b:
            # If empty bytes are used, try JSON mutation
            js = call_json_dump(adapter.to_json(ex.proof))
            js_mut = mutate_json_string(js)
            try:
                mutated_proof = adapter.from_json(json.loads(js_mut))
            except Exception:
                # If JSON ends up invalid, create a bytes mutation anyway
                mutated_proof = adapter.from_bytes(b + b"\x00")
        else:
            b_mut = flip_random_bit(b)
            try:
                mutated_proof = adapter.from_bytes(b_mut)
            except Exception:
                # If decoding fails, that's acceptable; create a minimal structurally valid mutation if possible
                mutated_proof = adapter.from_bytes(b + b"\x00")

        # Verify should fail on mutated proof
        ok = adapter.verify(mutated_proof, ex.statement, ex.context if has_attr(adapter, "supports_context") else None)
        assert ok is False, f"{adapter.name}: verify accepted a mutated proof."

        # Mutate statement (if statement is bytes or str or JSON-serializable)
        mutated_statement = None
        stmnt = ex.statement
        if isinstance(stmnt, (bytes, bytearray)):
            mutated_statement = flip_random_bit(bytes(stmnt))
        elif isinstance(stmnt, str):
            mutated_statement = mutate_json_string(stmnt)
        else:
            try:
                js = json.dumps(stmnt, separators=(",", ":"), sort_keys=True, ensure_ascii=False)
                mutated_statement = json.loads(mutate_json_string(js))
            except Exception:
                mutated_statement = None

        if mutated_statement is not None:
            ok2 = adapter.verify(ex.proof, mutated_statement, ex.context if has_attr(adapter, "supports_context") else None)
            assert ok2 is False, f"{adapter.name}: verify accepted a mutated statement."


@pytest.mark.parametrize("adapter", ADAPTERS, ids=lambda a: getattr(a, "name", repr(a)))
def test_context_binding_if_supported(adapter: Any) -> None:
    if not has_attr(adapter, "supports_context") or not getattr(adapter, "supports_context"):
        pytest.skip(f"{getattr(adapter, 'name', repr(adapter))}: context binding not declared; skipping.")

    examples = _load_examples_from_adapter(adapter)
    if not examples:
        pytest.skip(f"{adapter.name}: no examples available for context binding check.")

    for ex in examples[:10]:
        # use a wrong context variant
        wrong_context = "conformance-test-wrong-context"
        if ex.context == wrong_context:
            wrong_context = "conformance-test-wrong-context-2"

        ok = adapter.verify(ex.proof, ex.statement, wrong_context)
        assert ok is False, f"{adapter.name}: verify accepted proof under wrong context."


@pytest.mark.parametrize("adapter", ADAPTERS, ids=lambda a: getattr(a, "name", repr(a)))
def test_json_canonicalization_stability(adapter: Any) -> None:
    if not has_attr(adapter, "canonicalize_json"):
        pytest.skip(f"{adapter.name}: no canonicalize_json provided; skipping.")

    examples = _load_examples_from_adapter(adapter)
    if not examples:
        pytest.skip(f"{adapter.name}: no examples available for canonicalization check.")

    for ex in examples[:10]:
        raw = adapter.to_json(ex.proof)
        js1 = call_json_dump(raw)
        can1 = adapter.canonicalize_json(json.loads(js1))

        # Re-parse and re-canonicalize; must be byte-identical
        can2 = adapter.canonicalize_json(json.loads(can1))
        assert isinstance(can1, str) and isinstance(can2, str) and can1 == can2, \
            f"{adapter.name}: canonical JSON is not stable across re-parsing."


# -------------------------------
# Property-based tests (Hypothesis)
# -------------------------------

@pytest.mark.skipif(not HYP_AVAILABLE, reason="Hypothesis is not available.")
@pytest.mark.parametrize("adapter", ADAPTERS, ids=lambda a: getattr(a, "name", repr(a)))
@settings(deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(
    payload=st.one_of(
        st.binary(min_size=0, max_size=256),
        st.text(min_size=0, max_size=256),
        st.dictionaries(keys=st.text(min_size=0, max_size=24), values=st.integers(min_value=0, max_value=1_000_000), max_size=16),
        st.lists(st.integers(min_value=0, max_value=2**32 - 1), max_size=64),
    )
)
def test_property_generate_roundtrip_and_mutations(adapter: Any, payload: Any) -> None:
    """
    If adapter exposes generate(statement, context=None), validate rapid round-trips and mutation resistance.
    """
    if not has_attr(adapter, "generate") or not callable(getattr(adapter, "generate")):
        pytest.skip(f"{adapter.name}: no generate() available for property-based tests.")

    # Randomly decide if we pass a context (only if supported)
    context = None
    if has_attr(adapter, "supports_context") and getattr(adapter, "supports_context"):
        ctx_variant = random.choice([None, "ctx-A", {"ns": "test", "v": 1}, b"context-bytes"])
        context = ctx_variant

    # Generate proof
    proof = adapter.generate(payload, context=context)

    # Round-trip bytes
    b = adapter.to_bytes(proof)
    proof_b = adapter.from_bytes(b)
    assert adapter.to_bytes(proof) == adapter.to_bytes(proof_b), "Bytes round-trip mismatch."

    # Round-trip JSON
    j = adapter.to_json(proof)
    js = call_json_dump(j)
    proof_j = adapter.from_json(json.loads(js))
    assert adapter.to_bytes(proof) == adapter.to_bytes(proof_j), "JSON round-trip mismatch."

    # Verify positive
    ok = adapter.verify(proof, payload, context if getattr(adapter, "supports_context", False) else None)
    assert ok is True, "Verification failed on fresh generated proof."

    # Verify must fail on mutations
    mutated_proof = adapter.from_bytes(flip_random_bit(adapter.to_bytes(proof)))
    assert adapter.verify(mutated_proof, payload, context if getattr(adapter, "supports_context", False) else None) is False, \
        "Verification accepted mutated proof."

    # Mutate statement (if JSON-serializable)
    mutated_statement = None
    try:
        js_payload = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        mutated_statement = json.loads(mutate_json_string(js_payload))
    except Exception:
        if isinstance(payload, (bytes, bytearray)):
            mutated_statement = flip_random_bit(bytes(payload))
        elif isinstance(payload, str):
            mutated_statement = mutate_json_string(payload)

    if mutated_statement is not None:
        assert adapter.verify(proof, mutated_statement, context if getattr(adapter, "supports_context", False) else None) is False, \
            "Verification accepted mutated statement."


# -------------------------------
# Robustness tests for deserialization errors
# -------------------------------

@pytest.mark.parametrize("adapter", ADAPTERS, ids=lambda a: getattr(a, "name", repr(a)))
def test_from_bytes_and_json_rejects_garbage(adapter: Any) -> None:
    garbage_bytes = os.urandom(64)
    try:
        _ = adapter.from_bytes(garbage_bytes)
        # If no exception, at least verify fails
        assert adapter.verify(_, None, None) is False, f"{adapter.name}: from_bytes accepted garbage without failing verify."
    except Exception:
        # Expected path: robust decoders raise
        pass

    garbage_json = '{"this":"is", "not":"a valid proof", "rand": %d}' % random.randint(0, 10**9)
    try:
        _ = adapter.from_json(json.loads(garbage_json))
        assert adapter.verify(_, None, None) is False, f"{adapter.name}: from_json accepted garbage without failing verify."
    except Exception:
        pass


# -------------------------------
# Version policy (SemVer major-only breaking changes)
# -------------------------------

SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$")

@pytest.mark.parametrize("adapter", ADAPTERS, ids=lambda a: getattr(a, "name", repr(a)))
def test_version_semver_pattern(adapter: Any) -> None:
    v = getattr(adapter, "version", "")
    assert isinstance(v, str) and v.strip(), "Empty version string."
    assert SEMVER_RE.match(v), f"{adapter.name}: version must follow SemVer (got {v})."
    if PACKAGING_AVAILABLE:
        # Extra parse validation
        Version(v)  # will raise if invalid


# -------------------------------
# Determinism (if adapter declares determinism)
# -------------------------------

@pytest.mark.parametrize("adapter", ADAPTERS, ids=lambda a: getattr(a, "name", repr(a)))
def test_deterministic_encoding_if_promised(adapter: Any) -> None:
    """
    If adapter encodings are promised to be deterministic, multiple to_bytes/to_json calls
    on the same proof must match byte-for-byte.
    """
    examples = _load_examples_from_adapter(adapter)
    if not examples:
        pytest.skip(f"{adapter.name}: no examples for determinism check.")
    if not has_attr(adapter, "deterministic_encoding") or not getattr(adapter, "deterministic_encoding"):
        pytest.skip(f"{adapter.name}: no deterministic_encoding contract; skipping.")

    for ex in examples[:10]:
        p = ex.proof
        b1 = adapter.to_bytes(p)
        b2 = adapter.to_bytes(p)
        assert b1 == b2, f"{adapter.name}: to_bytes not deterministic."

        j1 = call_json_dump(adapter.to_json(p))
        j2 = call_json_dump(adapter.to_json(p))
        assert j1 == j2, f"{adapter.name}: to_json not deterministic."


# -------------------------------
# Utilities: ensure reproducible RNG for tests that use randomness
# -------------------------------

def pytest_configure(config: pytest.Config) -> None:
    # Make test randomness reproducible unless PYTEST_RANDOM_SEED provided
    seed_env = os.environ.get("PYTEST_RANDOM_SEED")
    seed = int(seed_env) if seed_env and seed_env.isdigit() else 1337
    random.seed(seed)
