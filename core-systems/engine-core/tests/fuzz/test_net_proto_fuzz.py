# engine-core/engine/tests/fuzz/test_net_proto_fuzz.py
# Industrial fuzz tests for binary network protocol.
# Frameworks: pytest, hypothesis
#
# EXPECTED SUT (engine/net/proto.py):
#   encode_message(msg: dict) -> bytes
#   decode_message(frame: bytes) -> dict                  # raises ValueError on invalid frames
#   validate_frame(frame: bytes) -> bool                  # True if well-formed
#   MAX_FRAME_SIZE: int                                   # hard safety ceiling in bytes
#   # Optional stream API (if implemented):
#   class StreamReassembler:
#       def __init__(self): ...
#       def feed(self, chunk: bytes) -> list[dict]        # returns list of decoded messages (may be empty)
#
# OPTIONAL REFERENCE (for differential testing, if present):
#   engine/net/proto_ref.py with compatible encode/decode
#
# All tests skip gracefully if SUT isn't present.

from __future__ import annotations

import importlib
import os
import random
import struct
from typing import Any, Dict, List, Optional, Tuple

import pytest
from hypothesis import HealthCheck, given, settings, strategies as st

# -----------------------------
# Runtime knobs (env overrides)
# -----------------------------
HYP_MAX_EXAMPLES = int(os.environ.get("FUZZ_MAX_EXAMPLES", "300"))          # bump in CI if needed
HYP_DEADLINE_MS  = int(os.environ.get("FUZZ_DEADLINE_MS", "200"))           # None to disable deadlines
HYP_SEED         = os.environ.get("FUZZ_SEED")                              # optional fixed seed


# -----------------------------
# SUT / REF import (soft)
# -----------------------------
def _import_sut():
    try:
        return importlib.import_module("engine.net.proto")
    except Exception as e:  # pragma: no cover
        pytest.skip(f"Не найден SUT engine.net.proto: {e}", allow_module_level=True)

SUT = _import_sut()

try:
    REF = importlib.import_module("engine.net.proto_ref")  # optional reference
except Exception:
    REF = None


# -----------------------------
# Strategies
# -----------------------------
# Message schema heuristic: produce dicts with type + payload.
# If your proto expects another shape, adapt here to keep fuzzer meaningful.

def _scalar():
    return st.one_of(
        st.integers(min_value=-(2**31), max_value=2**31-1),
        st.floats(allow_nan=False, allow_infinity=False, width=32),
        st.booleans(),
        st.text(min_size=0, max_size=64),
        st.binary(min_size=0, max_size=64),
    )

def _payload():
    return st.recursive(
        _scalar(),
        lambda children: st.lists(children, max_size=8) | st.dictionaries(st.text(min_size=1, max_size=16), children, max_size=8),
        max_leaves=20,
    )

MSG_TYPES = st.sampled_from(["ping", "pong", "data", "ack", "nack", "event", "control"])
MESSAGE = st.fixed_dictionaries({
    "type": MSG_TYPES,
    "id": st.integers(min_value=0, max_value=2**31-1),
    "payload": _payload(),
    # allow optional metadata
}).map(lambda d: d)

# Adversarial raw frames: random bytes in a broad length range up to (MAX_FRAME_SIZE * 2)
def RAW_BYTES():
    max_sz = getattr(SUT, "MAX_FRAME_SIZE", 1 << 20)
    # Cap to 256 KiB for fuzz speed
    cap = min(max_sz * 2, 256 * 1024)
    return st.binary(min_size=0, max_size=cap)

# Mutator: bit/byte flips, truncation, expansion, splice
def mutate(data: bytes, max_frame_size: int) -> bytes:
    if not data:
        return os.urandom(random.randint(0, min(64, max_frame_size)))
    choice = random.randint(0, 5)
    ba = bytearray(data)
    if choice == 0:  # bit flip
        for _ in range(random.randint(1, min(8, len(ba)))):
            i = random.randrange(len(ba))
            ba[i] ^= 1 << random.randrange(8)
        return bytes(ba)
    if choice == 1:  # byte flip
        for _ in range(random.randint(1, min(4, len(ba)))):
            ba[random.randrange(len(ba))] = random.randrange(256)
        return bytes(ba)
    if choice == 2:  # truncate
        k = random.randint(0, len(ba))
        return bytes(ba[:k])
    if choice == 3:  # pad (but limit by MAX_FRAME_SIZE * 2)
        pad = os.urandom(random.randint(1, 16))
        return (bytes(ba) + pad)[: max_frame_size * 2]
    if choice == 4:  # duplicate slice
        if len(ba) >= 2:
            i = random.randrange(len(ba) - 1)
            j = random.randrange(i + 1, len(ba))
            return bytes(ba[:j] + ba[i:j] + ba[j:])
    # splice with random junk
    junk = os.urandom(random.randint(0, min(32, max_frame_size)))
    mid = random.randrange(len(ba) + 1)
    return bytes(ba[:mid] + junk + ba[mid:])


# -----------------------------
# Hypothesis settings
# -----------------------------
common_settings = settings(
    max_examples=HYP_MAX_EXAMPLES,
    deadline=None if HYP_DEADLINE_MS <= 0 else HYP_DEADLINE_MS,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large],
    derandomize=False if HYP_SEED else True,
)

if HYP_SEED:
    common_settings = common_settings.__class__(**{**common_settings.__dict__, "phases": common_settings.phases})
    # Hypothesis seed is set via env var HYPOTHESIS_PROFILE or seed() in tests; we rely on default RNG unless provided.


# -----------------------------
# Tests
# -----------------------------

@common_settings
@given(MESSAGE)
def test_roundtrip_lossless_for_valid_messages(msg: Dict[str, Any]):
    """
    For well-formed messages, decode(encode(msg)) == msg (up to canonicalization order if any).
    """
    encoded = SUT.encode_message(msg)
    assert isinstance(encoded, (bytes, bytearray))
    assert len(encoded) > 0
    assert len(encoded) <= getattr(SUT, "MAX_FRAME_SIZE", 1 << 20)

    assert SUT.validate_frame(encoded) is True

    decoded = SUT.decode_message(encoded)
    assert isinstance(decoded, dict)

    # Allow codec to reorder dict keys; compare semantically
    assert decoded.get("type") == msg.get("type")
    assert int(decoded.get("id", -1)) == int(msg.get("id", -2))
    # payload equivalence: some codecs coerce bytes<->base64 or floats precision
    def _norm(x):
        if isinstance(x, bytes):
            return ("bytes", x)
        if isinstance(x, float):
            # tolerance for 32-bit codec
            return round(x, 6)
        if isinstance(x, list):
            return [_norm(i) for i in x]
        if isinstance(x, dict):
            return {k: _norm(v) for k, v in x.items()}
        return x
    assert _norm(decoded.get("payload")) == _norm(msg.get("payload"))


@common_settings
@given(RAW_BYTES())
def test_decoder_never_crashes_on_garbage(raw: bytes):
    """
    Decoder must never crash (ValueError only) and validator must be consistent.
    """
    is_valid = False
    try:
        is_valid = SUT.validate_frame(raw)
    except Exception as e:  # validator must not throw
        pytest.fail(f"validate_frame выбросил исключение: {e}")

    try:
        out = SUT.decode_message(raw)
        assert is_valid, "decode_message успешно распарсил, но validate_frame=False"
        assert isinstance(out, dict)
    except ValueError:
        # invalid input path
        assert not is_valid or len(raw) == 0
    except Exception as e:
        pytest.fail(f"decode_message должен кидать только ValueError на невалидных входах: {e}")


@common_settings
@given(MESSAGE, st.integers(min_value=1, max_value=32))
def test_stream_reassembly_with_arbitrary_chunking(msg: Dict[str, Any], chunks: int):
    """
    StreamReassembler must reassemble a frame from arbitrary chunking boundaries.
    """
    if not hasattr(SUT, "StreamReassembler"):
        pytest.skip("StreamReassembler не реализован в SUT")
    buf = SUT.encode_message(msg)
    # Split into 'chunks' slices (some may be empty), then feed
    total = len(buf)
    if chunks > total:
        chunks = total or 1
    cut_points = sorted(random.sample(range(1, total), k=max(0, chunks - 1)))
    parts: List[bytes] = []
    start = 0
    for cp in cut_points + [total]:
        parts.append(buf[start:cp])
        start = cp
    # Shuffle some chance to simulate network reordering? For TCP we keep order.
    r = SUT.StreamReassembler()
    decoded: List[Dict[str, Any]] = []
    for p in parts:
        decoded.extend(r.feed(p))
    # A single message in this test
    assert len(decoded) >= 1
    out = decoded[0]
    assert out.get("type") == msg.get("type")
    assert int(out.get("id", -1)) == int(msg.get("id", -2))


@common_settings
@given(MESSAGE, st.integers(min_value=1, max_value=8))
def test_corruption_detection_and_bounds(msg: Dict[str, Any], n_mut: int):
    """
    After mutating a valid frame, either (a) validator rejects, or (b) decoder raises ValueError,
    but never accepts a frame that decodes into a *different* semantic message silently.
    """
    frame = SUT.encode_message(msg)
    max_sz = getattr(SUT, "MAX_FRAME_SIZE", 1 << 20)
    mutated = frame
    for _ in range(n_mut):
        mutated = mutate(mutated, max_sz)

    if len(mutated) > max_sz * 2:
        mutated = mutated[: max_sz * 2]

    valid = SUT.validate_frame(mutated)
    if valid:
        try:
            out = SUT.decode_message(mutated)
        except ValueError:
            # acceptable: validator optimistic, decoder strict
            return
        # If decoder accepted, it must NOT silently change semantics
        def _pick(d): return (d.get("type"), int(d.get("id", -1)))
        assert _pick(out) == _pick(msg), "Поврежденный кадр принят декодером и изменил смысловое содержимое"
    else:
        with pytest.raises(ValueError):
            SUT.decode_message(mutated)


@pytest.mark.skipif(REF is None, reason="Нет референсной реализации для дифф‑теста")
@common_settings
@given(MESSAGE)
def test_differential_with_reference_codec(msg: Dict[str, Any]):
    """
    Differential: SUT and REF must agree on wire format or at least semantics on decode(SUT.encode()).
    """
    sut_bytes = SUT.encode_message(msg)
    ref_bytes = REF.encode_message(msg)

    # If wire formats differ, both must decode each other's frames to the same semantics.
    sut_from_ref = SUT.decode_message(ref_bytes)
    ref_from_sut = REF.decode_message(sut_bytes)

    def _sig(d: Dict[str, Any]) -> Tuple[Any, Any]:
        return (d.get("type"), int(d.get("id", -1)))

    assert _sig(sut_from_ref) == _sig(ref_from_sut) == _sig(msg)


def test_max_frame_size_enforced():
    """
    SUT must enforce MAX_FRAME_SIZE in validate/decode to prevent resource abuse.
    """
    max_sz = getattr(SUT, "MAX_FRAME_SIZE", None)
    if not isinstance(max_sz, int) or max_sz <= 0:
        pytest.skip("MAX_FRAME_SIZE не определен корректно в SUT")

    # Construct a length-prefixed oversized frame if protocol is length-prefixed; otherwise feed a big junk.
    junk = os.urandom(max_sz + 1024)
    try:
        ok = SUT.validate_frame(junk)
        # Either validator rejects or decode raises
        if ok:
            with pytest.raises(ValueError):
                SUT.decode_message(junk)
    except Exception as e:
        # No other exceptions allowed
        if not isinstance(e, ValueError):
            pytest.fail(f"Ожидался ValueError на декодировании слишком большого кадра: {e}")
