# path: tests/unit/fuzz/test_schema_fuzz.py
import math
import random
from typing import Any, Dict, Tuple, List, Optional

import pytest

# --- обязательная зависимость для fuzz
hyp = pytest.importorskip("hypothesis", reason="Hypothesis is required for fuzz tests")
from hypothesis import given, strategies as st, settings, HealthCheck

# --- опциональные зависимости/интеграции
try:
    # встроенная в проект валидация через serde (см. datafabric/utils/serde.py)
    from datafabric.utils import serde as df_serde  # type: ignore
except Exception:
    df_serde = None  # type: ignore

# jsonschema — либо напрямую, либо через df_serde.validate_json_schema
try:
    import jsonschema  # type: ignore
except Exception:
    jsonschema = None  # type: ignore

# --- попытка найти модуль схем проекта (инференс/валидация)
_SCHEMA_MODULE = None
for modname in (
    "datafabric.schema",
    "datafabric.schemas",
    "datafabric.processing.schema",
    "datafabric.meta.schema",
):
    try:
        _MODULE = __import__(modname, fromlist=["*"])
        _SCHEMA_MODULE = _MODULE
        break
    except Exception:
        continue


def _pick_fn(module, names: List[str]):
    if not module:
        return None
    for n in names:
        f = getattr(module, n, None)
        if callable(f):
            return f
    return None


DF_INFER = _pick_fn(_SCHEMA_MODULE, ["infer_schema", "infer", "derive_schema", "from_samples"])
DF_VALIDATE = _pick_fn(_SCHEMA_MODULE, ["validate", "validate_instance", "validate_record", "check", "is_valid"])


# =========================================================
# Стратегии Hypothesis: генерация (schema, instance)
# Поддерживаем контролируемую рекурсию: object / array / примитивы
# =========================================================

PRIMITIVE_TYPES = st.sampled_from(["string", "integer", "number", "boolean", "null"])


@st.composite
def json_scalar(draw):
    # JSON-safe скаляры
    t = draw(PRIMITIVE_TYPES)
    if t == "string":
        return draw(st.text(max_size=40))
    if t == "integer":
        # ограничим диапазон для стабильности и скорости
        return draw(st.integers(min_value=-10**9, max_value=10**9))
    if t == "number":
        return draw(st.floats(allow_nan=False, allow_infinity=False, width=32))
    if t == "boolean":
        return draw(st.booleans())
    return None  # null


@st.composite
def schema_and_instance(draw, depth: int = 0) -> Tuple[Dict[str, Any], Any]:
    """
    Возвращает пару (JSON Schema, instance), где instance соответствует схеме.
    Глубина ограничена 0..2 для стабильности.
    """
    # распределение типов в зависимости от глубины
    if depth >= 2:
        # только примитивы на листьях
        t = draw(PRIMITIVE_TYPES)
    else:
        t = draw(st.sampled_from(["object", "array"]).filter(lambda x: True) | PRIMITIVE_TYPES)

    if t == "object":
        # 1..4 свойств
        nprops = draw(st.integers(min_value=1, max_value=4))
        props = {}
        inst = {}
        required: List[str] = []
        for i in range(nprops):
            name = draw(st.text(alphabet=st.characters(min_codepoint=97, max_codepoint=122), min_size=1, max_size=8))
            # избегаем конфликтов ключей
            if name in props or name in ("",):
                name = f"f{i}"
            sub_schema, sub_inst = draw(schema_and_instance(depth=depth + 1))
            props[name] = sub_schema
            inst[name] = sub_inst
            if draw(st.booleans()):
                required.append(name)
        schema = {"type": "object", "properties": props}
        if required:
            schema["required"] = sorted(set(required))
        return schema, inst

    if t == "array":
        # элементы — примитивы или неглубокие объекты
        sub_schema, sub_inst_example = draw(schema_and_instance(depth=depth + 1))
        schema = {"type": "array", "items": sub_schema}
        # длина массива 0..5
        length = draw(st.integers(min_value=0, max_value=5))
        items = []
        for _ in range(length):
            # генерируем ещё элемент по той же под-схеме
            _, item_val = draw(schema_and_instance(depth=depth + 1))
            items.append(item_val)
        return schema, items

    # Примитивы
    if t == "string":
        # опционально minLength/maxLength
        min_len = draw(st.integers(min_value=0, max_value=4))
        max_len = draw(st.integers(min_value=min_len, max_value=16))
        val = draw(st.text(min_size=min_len, max_size=max_len))
        schema = {"type": "string", "minLength": min_len, "maxLength": max_len}
        return schema, val

    if t == "integer":
        lo = draw(st.integers(min_value=-10**6, max_value=10**3))
        hi = draw(st.integers(min_value=lo, max_value=10**6))
        val = draw(st.integers(min_value=lo, max_value=hi))
        schema = {"type": "integer", "minimum": lo, "maximum": hi}
        return schema, val

    if t == "number":
        lo = draw(st.floats(allow_nan=False, allow_infinity=False, width=32, min_value=-1e6, max_value=1e6))
        hi = draw(st.floats(allow_nan=False, allow_infinity=False, width=32, min_value=float(lo), max_value=1e6))
        # гарантируем lo<=val<=hi с буфером
        val = draw(st.floats(allow_nan=False, allow_infinity=False, width=32, min_value=float(lo), max_value=float(hi)))
        schema = {"type": "number", "minimum": float(lo), "maximum": float(hi)}
        return schema, val

    if t == "boolean":
        val = draw(st.booleans())
        schema = {"type": "boolean"}
        return schema, val

    # null
    return {"type": "null"}, None


# =========================================================
# Мутации: целенаправленный отход от схемы
# =========================================================

def make_invalid_instance(schema: Dict[str, Any], instance: Any) -> Any:
    t = schema.get("type")
    if t == "object" and isinstance(instance, dict):
        props = schema.get("properties", {}) or {}
        required = list(schema.get("required", []))
        # если есть required — удалим одно поле
        if required and all(k in instance for k in required):
            bad = dict(instance)
            bad.pop(random.choice(required), None)
            return bad
        # иначе испортим тип одного свойства
        if props:
            k = random.choice(list(props.keys()))
            return {**instance, k: make_invalid_instance({"type": "string"}, instance.get(k))}
        # деградация
        return 123
    if t == "array" and isinstance(instance, list):
        # заменим элемент на заведомо неверный по типу
        return instance + [object()]
    if t == "string":
        return 12345
    if t == "integer":
        return "not-int"
    if t == "number":
        return "not-number"
    if t == "boolean":
        return 2
    if t == "null":
        return "not-null"
    # неизвестное — вернём что-то несовместимое
    return object()


# =========================================================
# Валидация через jsonschema либо df_serde.validate_json_schema
# =========================================================

def _validate_with_jsonschema(schema: Dict[str, Any], instance: Any) -> Optional[str]:
    """
    Возвращает None, если валидно; строку ошибки — если не валидно.
    """
    if df_serde is not None:
        try:
            df_serde.validate_json_schema(instance, schema)  # type: ignore[attr-defined]
            return None
        except Exception as e:
            return str(e)
    if jsonschema is not None:
        try:
            jsonschema.validate(instance=instance, schema=schema)  # type: ignore
            return None
        except Exception as e:
            return str(e)
    pytest.skip("Neither jsonschema nor df_serde.validate_json_schema available")


# =========================================================
# Тесты
# =========================================================

COMMON_SETTINGS = settings(
    max_examples=60,
    deadline=1000,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.filter_too_much],
)


@given(schema_and_instance())
@COMMON_SETTINGS
def test_valid_instances_are_accepted(pair):
    schema, inst = pair
    err = _validate_with_jsonschema(schema, inst)
    assert err is None, f"expected valid, got error: {err}"


@given(schema_and_instance())
@COMMON_SETTINGS
def test_invalid_mutations_are_rejected(pair):
    schema, inst = pair
    bad = make_invalid_instance(schema, inst)
    err = _validate_with_jsonschema(schema, bad)
    assert err is not None, "expected invalid mutation to be rejected"


@pytest.mark.skipif(df_serde is None, reason="datafabric.utils.serde not available")
@given(schema_and_instance())
@COMMON_SETTINGS
def test_serde_roundtrip_preserves_json(pair):
    schema, inst = pair
    # только JSON-совместимые типы, стратегия уже ограничивает значения
    blob = df_serde.encode(inst, fmt=df_serde.Format.JSON, compression=df_serde.Compression.NONE)  # type: ignore
    back = df_serde.decode(blob)  # type: ignore
    # JSON не различает -0.0 и 0.0 — нормализуем числа для устойчивого сравнения
    def _norm(x):
        if isinstance(x, float) and x == 0.0:
            return 0.0
        if isinstance(x, list):
            return [_norm(v) for v in x]
        if isinstance(x, dict):
            return {k: _norm(v) for k, v in x.items()}
        return x
    assert _norm(inst) == _norm(back)
    # дополнительно проверим, что roundtrip остаётся валидным по схеме
    err = _validate_with_jsonschema(schema, back)
    assert err is None, f"roundtrip invalid: {err}"


# --- Интеграционные свойства для модуля схем проекта (если есть)

@pytest.mark.skipif(DF_INFER is None, reason="schema inference API not found in datafabric")
@given(st.lists(schema_and_instance().map(lambda p: p[1]), min_size=1, max_size=12))
@COMMON_SETTINGS
def test_inferred_schema_validates_all_samples(samples):
    """
    Если в проекте есть API инференса, схема на основе сэмплов должна валидировать сами сэмплы.
    """
    schema = DF_INFER(samples)  # type: ignore[misc]
    # валидация — либо через DF_VALIDATE, либо через jsonschema (если инференс выдаёт JSON Schema-совместный dict)
    for inst in samples:
        if DF_VALIDATE:
            try:
                res = DF_VALIDATE(inst, schema)  # type: ignore[misc]
                if isinstance(res, bool):
                    assert res, "DF_VALIDATE returned False"
            except Exception as e:
                pytest.fail(f"DF_VALIDATE raised: {e}")
        else:
            # fallback: jsonschema-совместная проверка
            err = _validate_with_jsonschema(schema, inst)
            assert err is None, f"inferred schema rejected sample: {err}"


@pytest.mark.skipif(DF_INFER is None, reason="schema inference API not found in datafabric")
@given(schema_and_instance())
@COMMON_SETTINGS
def test_inferred_schema_rejects_targeted_mutation(pair):
    """
    Схема из одного сэмпла должна отклонять целевую мутацию (хотя бы часто).
    """
    schema, inst = pair
    inferred = DF_INFER([inst])  # type: ignore[misc]
    bad = make_invalid_instance(schema, inst)
    # используем DF_VALIDATE или jsonschema
    if DF_VALIDATE:
        try:
            res = DF_VALIDATE(bad, inferred)  # type: ignore[misc]
            # если валидатор возвращает bool — ожидаем False; если он исключения — поймаем ниже
            if isinstance(res, bool):
                assert not res, "mutation unexpectedly accepted by DF_VALIDATE"
                return
        except Exception:
            return  # отклонение через исключение — приемлемо
        pytest.fail("mutation accepted by DF_VALIDATE without error/False")
    else:
        err = _validate_with_jsonschema(inferred, bad)
        assert err is not None, "mutation unexpectedly accepted by inferred schema"
