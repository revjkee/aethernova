# physical-integration-core/tests/unit/test_mqtt_parser.py
# Контрактные тесты для physical_integration.messaging.mqtt_parser
# API контракта, который должна предоставить реализация:
#
#   parse_topic(template: str, topic: str) -> dict | None
#       Шаблон использует {name} для одного сегмента и {name+} для "хвоста" (может содержать '/').
#       Возвращает отображение name -> значение (с percent-decoding) или None, если не совпало.
#
#   make_topic(template: str, params: dict[str, str]) -> str
#       Генерирует тему из шаблона и параметров; значения сегментов экранируются (percent-encoding),
#       так что '/' внутри значений не ломает сегментацию. Для {name+} допускаются '/' без экранирования.
#
#   decode_payload(payload: bytes, content_type: str | None) -> object
#       content_type:
#         - "application/json[; charset=utf-8]"  -> dict/list/primitive; ValueError при неверном JSON
#         - "text/plain[; charset=...]"         -> str (по указанной кодировке, по умолчанию utf-8)
#         - "application/octet-stream"          -> bytes (как есть)
#         - "application/octet-stream; encoding=base64" -> bytes (base64-декодирование); ValueError при ошибке
#       None или неизвестный тип -> bytes (как есть)
#
#   compile_template(template: str) -> Compiled
#       Compiled.match(topic: str) -> dict | None  (эквивалент parse_topic)
#       Compiled.make(params: dict[str,str]) -> str (эквивалент make_topic)
#
# Поведение ошибок:
#   - Неверный шаблон -> ValueError (как в compile_template, так и в parse_topic/make_topic)
#   - Недостаточные параметры для make_topic -> KeyError
#   - Недопустимые значения (например, пустой сегмент при {name}) -> ValueError
#
# Примечание: Это спецификация тестов. Реализация может иметь дополнительные функции,
# но не должна нарушать описанное поведение.
#
# I cannot verify this.

import base64
import json
import pytest

# Требуемый модуль
import importlib

mqtt_parser = importlib.import_module("physical_integration.messaging.mqtt_parser")


# ------------- Вспомогательные проверки -------------

def assert_dicts_equal(a: dict, b: dict):
    assert a == b, f"expected {b}, got {a}"


# ------------- Тесты parse_topic -------------

@pytest.mark.parametrize(
    "template,topic,expected",
    [
        ("v1/devices/{device_id}/events/{event}",
         "v1/devices/motor-01/events/overheat",
         {"device_id": "motor-01", "event": "overheat"}),

        ("tenant/{tenant}/site/{site}/v1/devices/{device_id}/twin/{path+}",
         "tenant/acme/site/plant-7/v1/devices/motor-01/twin/cfg/limits/max",
         {"tenant": "acme", "site": "plant-7", "device_id": "motor-01", "path": "cfg/limits/max"}),

        ("a/{x}/b/{y}/c", "a/one/b/two/c", {"x": "one", "y": "two"}),
    ],
)
def test_parse_topic_basic(template, topic, expected):
    got = mqtt_parser.parse_topic(template, topic)
    assert got is not None
    assert_dicts_equal(got, expected)


def test_parse_topic_no_match():
    tpl = "v1/devices/{device_id}/events/{event}"
    topic = "v1/devices/motor-01/overheat"
    assert mqtt_parser.parse_topic(tpl, topic) is None


def test_parse_topic_percent_decoding():
    tpl = "v1/devices/{device_id}/events/{event}"
    topic = "v1/devices/motor%2F01/events/overheat%20alarm"
    got = mqtt_parser.parse_topic(tpl, topic)
    assert got == {"device_id": "motor/01", "event": "overheat alarm"}


def test_parse_topic_tail_captures_empty_segment_disallowed():
    # {name+} может быть пустым только если это пустая строка без сегментов? Решение теста: пустая строка не допускается.
    tpl = "a/{x+}"
    assert mqtt_parser.parse_topic(tpl, "a/") is None


@pytest.mark.parametrize(
    "bad_template",
    [
        "",  # пусто
        "v1//devices/{id}",  # двойной слэш
        "v1/{a+}/x/{b+}",  # несколько хвостов
        "v1/{bad}/x/#",    # запрещенные символы MQTT шаблона в контракте тестов
        "v1/{1bad}/x",     # имя не может начинаться с цифры (ожидаемая политика)
        "v1/{a}/x/{a}",    # дублирующееся имя плейсхолдера
        "v1/{a+}/x/{b}",   # после хвоста не может быть сегментов
    ],
)
def test_parse_topic_invalid_templates_raise(bad_template):
    with pytest.raises(ValueError):
        mqtt_parser.parse_topic(bad_template, "v1/devices/x")


# ------------- Тесты make_topic -------------

@pytest.mark.parametrize(
    "template,params,expected",
    [
        ("v1/devices/{device_id}/events/{event}",
         {"device_id": "motor-01", "event": "overheat"},
         "v1/devices/motor-01/events/overheat"),

        ("v1/devices/{device}/twin/{path+}",
         {"device": "motor-01", "path": "cfg/limits/max"},
         "v1/devices/motor-01/twin/cfg/limits/max"),
    ],
)
def test_make_topic_basic(template, params, expected):
    out = mqtt_parser.make_topic(template, params)
    assert out == expected
    # round-trip
    back = mqtt_parser.parse_topic(template, out)
    assert back == params


def test_make_topic_escapes_slash_in_segment():
    tpl = "v1/devices/{device_id}/events/{event}"
    topic = mqtt_parser.make_topic(tpl, {"device_id": "motor/01", "event": "overheat alarm"})
    # device_id сегмент должен быть percent-encoded, пробелы тоже
    assert topic == "v1/devices/motor%2F01/events/overheat%20alarm"
    # и обратный парсинг восстанавливает значения
    assert mqtt_parser.parse_topic(tpl, topic) == {"device_id": "motor/01", "event": "overheat alarm"}


def test_make_topic_missing_param_raises():
    tpl = "a/{x}/b/{y}"
    with pytest.raises(KeyError):
        mqtt_parser.make_topic(tpl, {"x": "one"})


def test_make_topic_tail_allows_slashes_without_encoding():
    tpl = "a/{tail+}"
    out = mqtt_parser.make_topic(tpl, {"tail": "p/q/r"})
    assert out == "a/p/q/r"


# ------------- Тесты compile_template -------------

def test_compile_template_equivalence_and_roundtrip():
    tpl = "tenant/{t}/site/{s}/v1/devices/{id}/events/{e}"
    comp = mqtt_parser.compile_template(tpl)
    topic = "tenant/acme/site/plant-7/v1/devices/m01/events/overheat"
    expected = {"t": "acme", "s": "plant-7", "id": "m01", "e": "overheat"}

    # match
    assert comp.match(topic) == expected
    # make
    assert comp.make(expected) == topic
    # Согласованность с функциями верхнего уровня
    assert mqtt_parser.parse_topic(tpl, topic) == expected
    assert mqtt_parser.make_topic(tpl, expected) == topic


@pytest.mark.parametrize(
    "bad_template",
    [
        "v1/{a+}/x",      # сегменты после хвоста
        "v1/{a}/b/{a}",   # дублирующиеся имена
    ],
)
def test_compile_template_invalid(bad_template):
    with pytest.raises(ValueError):
        mqtt_parser.compile_template(bad_template)


# ------------- Тесты decode_payload -------------

@pytest.mark.parametrize(
    "payload,ctype,expected",
    [
        (b'{"a":1,"b":[2,3]}', "application/json", {"a": 1, "b": [2, 3]}),
        (b"hello", "text/plain", "hello"),
        ("caf\xe9".encode("latin1"), "text/plain; charset=latin-1", "café"),
        (b"\x00\x01\x02", "application/octet-stream", b"\x00\x01\x02"),
    ],
)
def test_decode_payload_basic(payload, ctype, expected):
    got = mqtt_parser.decode_payload(payload, ctype)
    assert got == expected


def test_decode_payload_octet_base64():
    raw = b"\x01\x02\x03\xff"
    b64 = base64.b64encode(raw)
    got = mqtt_parser.decode_payload(b64, "application/octet-stream; encoding=base64")
    assert got == raw


def test_decode_payload_unknown_type_returns_bytes():
    raw = b"whatever"
    got = mqtt_parser.decode_payload(raw, "application/x-custom")
    assert got == raw


def test_decode_payload_none_type_returns_bytes():
    raw = b"whatever"
    got = mqtt_parser.decode_payload(raw, None)
    assert got == raw


def test_decode_payload_bad_json_raises():
    with pytest.raises(ValueError):
        mqtt_parser.decode_payload(b"{bad json", "application/json")


def test_decode_payload_bad_base64_raises():
    with pytest.raises(ValueError):
        mqtt_parser.decode_payload(b"***notb64***", "application/octet-stream; encoding=base64")


# ------------- Тесты отказоустойчивости и краевых случаев -------------

@pytest.mark.parametrize(
    "template,topic",
    [
        ("a/{x}", "a/"),            # пустой сегмент не допускается
        ("a/{x}/b", "a//b"),        # пустой сегмент
        ("a/{x}/b/{y}", "a/1/b/"),  # пустой y
    ],
)
def test_parse_topic_empty_segments_fail(template, topic):
    assert mqtt_parser.parse_topic(template, topic) is None


def test_large_tail_is_supported():
    tpl = "v1/devices/{id}/blob/{path+}"
    path = "a/" + "/".join([f"p{i}" for i in range(200)])
    topic = f"v1/devices/m1/blob/{path}"
    res = mqtt_parser.parse_topic(tpl, topic)
    assert res == {"id": "m1", "path": path}


def test_make_topic_rejects_illegal_characters_in_segment():
    tpl = "a/{x}"
    with pytest.raises(ValueError):
        # Управляющие символы в сегменте — запрещены (контракт).
        mqtt_parser.make_topic(tpl, {"x": "bad\x00char"})


def test_template_reserved_symbols_rejected():
    for bad in ["#", "+"]:  # MQTT wildcard символы не используются в этом DSL
        with pytest.raises(ValueError):
            mqtt_parser.compile_template(f"a/{bad}/b")


# ------------- Жизненный цикл/регрессии -------------

def test_roundtrip_many_values_and_json_payload():
    tpl = "tenant/{tenant}/site/{site}/v1/devices/{device}/events/{event}"
    params = {
        "tenant": "acme",
        "site": "plant-7",
        "device": "motor-01",
        "event": "overheat alarm",  # пробел → percent-encode
    }
    topic = mqtt_parser.make_topic(tpl, params)
    assert topic == "tenant/acme/site/plant-7/v1/devices/motor-01/events/overheat%20alarm"
    parsed = mqtt_parser.parse_topic(tpl, topic)
    assert parsed == params

    payload = {"ok": True, "ts": 1730000000}
    decoded = mqtt_parser.decode_payload(json.dumps(payload).encode("utf-8"), "application/json")
    assert decoded == payload
