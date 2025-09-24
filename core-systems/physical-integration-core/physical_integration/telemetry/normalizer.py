# physical_integration/telemetry/normalizer.py
# Промышленная нормализация телеметрии в Envelope/Event (см. protobuf/GraphQL контракты).
# Возможности:
# - JSONPath-подобное извлечение ($.a.b[0].c), без внешних зависимостей
# - Обязательные поля, SLA по времени события и допустимому будущему/прошлому
# - Метрики: типобезопасные значения (double/int/bool/string), единицы и конверсии
# - PII-редакция: удаление/маскирование по путям
# - Обогащение из реестра устройств (расширяемый интерфейс)
# - Идемпотентность: детерминированный content_hash + envelope_id/event_id (UUID4)
# - Опциональная JSON Schema валидация (если установлен jsonschema)
# - Наблюдаемость: Prometheus (если доступен) и OpenTelemetry (если доступен)
# - Безопасная обработка ошибок: NormalizationError с кодом и деталями для DLQ

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import ipaddress
import json
import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple, Union

# -------- Опциональные зависимости (автовключение) --------
try:
    import jsonschema  # type: ignore
    _HAS_JSONSCHEMA = True
except Exception:  # pragma: no cover
    _HAS_JSONSCHEMA = False

try:
    from prometheus_client import Counter, Histogram  # type: ignore
    _HAS_PROM = True
except Exception:  # pragma: no cover
    _HAS_PROM = False

try:
    from opentelemetry import trace  # type: ignore
    _TRACER = trace.get_tracer(__name__)
    _HAS_OTEL = True
except Exception:  # pragma: no cover
    _HAS_OTEL = False
    class _Dummy:
        def __enter__(self): return self
        def __exit__(self, *a): return False
    class _Tr:
        def start_as_current_span(self, *a, **k): return _Dummy()
    _TRACER = _Tr()

__all__ = [
    "NormalizationSpec",
    "UnitRule",
    "DeviceRegistry",
    "InMemoryDeviceRegistry",
    "SchemaValidator",
    "TelemetryNormalizer",
    "NormalizationError",
]

# -------- Ошибки --------
class NormalizationError(Exception):
    def __init__(self, code: str, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details or {}

    def as_error_info(self) -> Dict[str, Any]:
        # Совместимо с ErrorInfo из protobuf/GraphQL
        return {"code": self.code, "message": self.message, "details": json.dumps(self.details)[:2000]}

# -------- JSON утилиты --------
_JSONPATH_RE = re.compile(r"^\$((?:\.[A-Za-z0-9_\-]+|\[\d+\])*)$")

def _jsonpath_get(data: Any, path: str) -> Any:
    """
    Очень лёгкий JSONPath:
      $.a.b[0].c  -> data["a"]["b"][0]["c"]
    Без wildcard/фильтров. Возвращает None, если что-то отсутствует.
    """
    if path in ("", "$"):  # корень
        return data
    m = _JSONPATH_RE.match(path.strip())
    if not m:
        return None
    cur = data
    tokens = re.findall(r"\.([A-Za-z0-9_\-]+)|\[(\d+)\]", m.group(1))
    for key, idx in tokens:
        try:
            if key:
                if isinstance(cur, Mapping) and key in cur:
                    cur = cur[key]
                else:
                    return None
            else:
                i = int(idx)
                if isinstance(cur, list) and 0 <= i < len(cur):
                    cur = cur[i]
                else:
                    return None
        except Exception:
            return None
    return cur

def _json_delete_inplace(data: Any, path: str) -> None:
    """
    Удаляет ключ по простому пути вида $.a.b[0].c. Пропускает, если нет.
    """
    if path in ("", "$"):
        return
    m = _JSONPATH_RE.match(path.strip())
    if not m:
        return
    cur = data
    parents: List[Tuple[Any, Union[str, int]]] = []
    tokens = re.findall(r"\.([A-Za-z0-9_\-]+)|\[(\d+)\]", m.group(1))
    for t_key, t_idx in tokens:
        parents.append((cur, t_key if t_key else int(t_idx)))
        if t_key:
            if isinstance(cur, Mapping) and t_key in cur:
                cur = cur[t_key]
            else:
                return
        else:
            i = int(t_idx)
            if isinstance(cur, list) and 0 <= i < len(cur):
                cur = cur[i]
            else:
                return
    if parents:
        parent, last = parents[-1]
        try:
            if isinstance(last, str) and isinstance(parent, dict):
                parent.pop(last, None)
            elif isinstance(last, int) and isinstance(parent, list) and 0 <= last < len(parent):
                parent.pop(last)
        except Exception:
            pass

def _canonical_json(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))

def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def _now_utc() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)

def _parse_ts(value: Any) -> Optional[dt.datetime]:
    """
    Принимает:
      - int/float (секунды Unix)
      - int миллисекунды/микросекунды (распознаётся по величине)
      - ISO 8601 строки
    Возвращает timezone-aware UTC.
    """
    if value is None:
        return None
    if isinstance(value, (int, float)):
        # эвристика масштаба
        v = float(value)
        if v > 1e14:  # наносекунды -> сек
            v = v / 1e9
        elif v > 1e11:  # микросекунды
            v = v / 1e6
        elif v > 1e10:  # миллисекунды
            v = v / 1e3
        # иначе считаем секундами
        return dt.datetime.fromtimestamp(v, tz=dt.timezone.utc)
    if isinstance(value, str):
        s = value.strip()
        # Популярные форматы ISO
        for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d %H:%M:%S%z"):
            try:
                return dt.datetime.strptime(s, fmt).astimezone(dt.timezone.utc)
            except Exception:
                pass
        # Без таймзоны -> считаем UTC
        try:
            # datetime.fromisoformat понимает "YYYY-mm-ddTHH:MM:SS.ssssss+/-HH:MM" и без зоны
            d = dt.datetime.fromisoformat(s)
            if d.tzinfo is None:
                d = d.replace(tzinfo=dt.timezone.utc)
            return d.astimezone(dt.timezone.utc)
        except Exception:
            return None
    return None

def _rfc3339(dt_obj: dt.datetime) -> str:
    return dt_obj.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")

# -------- Конверсия единиц --------
@dataclass
class UnitRule:
    from_unit: str
    to_unit: str
    factor: float  # value_in_to_unit = value_in_from_unit * factor

# Небольшой стандартный набор (можно расширять через spec.unit_rules)
_DEFAULT_UNIT_RULES: Dict[Tuple[str, str], float] = {
    ("kPa", "Pa"): 1000.0,
    ("Pa", "kPa"): 0.001,
    ("C", "K"): 1.0,  # обработка K=C+273.15 — отдельно
    ("K", "C"): 1.0,
}

def _convert_value(val: Any, src_unit: Optional[str], dst_unit: Optional[str], extra_rules: Dict[Tuple[str, str], float]) -> Tuple[Any, Optional[str]]:
    if src_unit is None or dst_unit is None or src_unit == dst_unit:
        return val, src_unit or dst_unit
    # Температура — особая
    if src_unit == "C" and dst_unit == "K":
        try: return float(val) + 273.15, "K"
        except Exception: return val, src_unit
    if src_unit == "K" and dst_unit == "C":
        try: return float(val) - 273.15, "C"
        except Exception: return val, src_unit
    factor = extra_rules.get((src_unit, dst_unit)) or _DEFAULT_UNIT_RULES.get((src_unit, dst_unit))
    if factor is None:
        # неизвестная пара — не конвертируем
        return val, src_unit
    try:
        return float(val) * factor, dst_unit
    except Exception:
        return val, src_unit

# -------- Спецификация нормализации --------
@dataclass
class NormalizationSpec:
    name: str
    device_id_path: str  # JSONPath к device_id
    ts_field_path: str   # JSONPath к времени события
    required_paths: List[str] = field(default_factory=list)  # JSONPath обязательных полей
    ts_tolerance_seconds: int = 3600  # допустимое отклонение (|now - ts|)
    metrics_map: Dict[str, str] = field(default_factory=dict)  # имя -> JSONPath
    metrics_units: Dict[str, str] = field(default_factory=dict)  # имя -> единица (нормализованная)
    tags: Dict[str, str] = field(default_factory=dict)  # дополнительные теги
    redact_paths: List[str] = field(default_factory=list)  # пути, которые нужно удалить из исходного raw
    schema: Optional[Dict[str, Any]] = None  # JSON Schema (опционально)
    unit_rules: List[UnitRule] = field(default_factory=list)  # дополнительные правила конверсии
    severity: Optional[str] = None  # TRACE|DEBUG|INFO|WARN|ERROR|FATAL
    type: str = "TELEMETRY"  # тип события

# -------- Устройства / реестр --------
class DeviceRegistry:
    def get(self, device_id: str) -> Optional[Dict[str, Any]]:
        raise NotImplementedError

class InMemoryDeviceRegistry(DeviceRegistry):
    def __init__(self, items: Optional[Dict[str, Dict[str, Any]]] = None):
        self._items = items or {}
    def get(self, device_id: str) -> Optional[Dict[str, Any]]:
        return self._items.get(device_id)

# -------- JSON Schema валидатор --------
class SchemaValidator:
    def __init__(self, schema: Dict[str, Any]):
        if not _HAS_JSONSCHEMA:
            raise RuntimeError("jsonschema is not installed")
        self._schema = schema
        self._validator = jsonschema.Draft202012Validator(schema)  # type: ignore
    def validate(self, payload: Dict[str, Any]) -> None:
        errors = sorted(self._validator.iter_errors(payload), key=lambda e: e.path)  # type: ignore
        if errors:
            first = errors[0]
            raise NormalizationError(
                code="SCHEMA_VALIDATION_FAILED",
                message="Schema validation error",
                details={"path": list(first.path), "message": first.message},
            )

# -------- Метрики --------
if _HAS_PROM:
    _N_OK = Counter("pic_norm_ok_total", "Normalized events", ["route"])
    _N_DROP = Counter("pic_norm_drop_total", "Dropped events", ["route", "code"])
    _N_ERROR = Counter("pic_norm_error_total", "Errors during normalization", ["route", "code"])
    _T_LAT = Histogram("pic_norm_duration_seconds", "Normalization duration", ["route"], buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2))
else:
    class _DummyMetric:
        def labels(self, *a, **k): return self
        def inc(self, *a, **k): return None
        def observe(self, *a, **k): return None
    _N_OK = _N_DROP = _N_ERROR = _T_LAT = _DummyMetric()

# -------- Нормализатор --------
class TelemetryNormalizer:
    def __init__(self, device_registry: Optional[DeviceRegistry] = None):
        self._reg = device_registry
        # Подготовка таблицы доп. конверсий
        self._extra_rules: Dict[Tuple[str, str], float] = {}

    def register_unit_rules(self, rules: Iterable[UnitRule]) -> None:
        for r in rules:
            self._extra_rules[(r.from_unit, r.to_unit)] = r.factor

    def normalize(
        self,
        raw: Dict[str, Any],
        spec: NormalizationSpec,
        context: Optional[Dict[str, Any]] = None,
    ) -> Tuple[Dict[str, Any], Optional[Dict[str, Any]]]:
        """
        Возвращает (envelope, dlq_reason). Если dlq_reason не None — envelope содержит флаг dlq=true и причину.
        """
        route = spec.name
        t0 = time.perf_counter()
        context = context or {}

        with _TRACER.start_as_current_span("normalize"):
            try:
                # 1) Валидация обязательных путей
                missing = [p for p in [spec.device_id_path, spec.ts_field_path, *spec.required_paths] if _jsonpath_get(raw, p) is None]
                if missing:
                    raise NormalizationError("MISSING_REQUIRED", "Required paths are missing", {"paths": missing})

                # 2) Извлечение device_id и времени
                device_id = str(_jsonpath_get(raw, spec.device_id_path))
                ts_raw = _jsonpath_get(raw, spec.ts_field_path)
                event_time = _parse_ts(ts_raw)
                if event_time is None:
                    raise NormalizationError("INVALID_TS", "Unable to parse event timestamp", {"value": ts_raw})
                now = _now_utc()
                if abs((now - event_time).total_seconds()) > max(0, spec.ts_tolerance_seconds):
                    raise NormalizationError("TS_OUT_OF_TOLERANCE", "Event time outside tolerance", {
                        "event_time": _rfc3339(event_time), "now": _rfc3339(now), "tolerance_sec": spec.ts_tolerance_seconds
                    })

                # 3) Редакция PII в сыром сообщении
                raw_redacted = json.loads(_canonical_json(raw))  # копия
                for path in spec.redact_paths:
                    _json_delete_inplace(raw_redacted, path)

                # 4) Метрики
                metrics: List[Dict[str, Any]] = []
                for name, jpath in spec.metrics_map.items():
                    val = _jsonpath_get(raw, jpath)
                    if val is None:
                        # Метрики могут быть опциональны — пропускаем отсутствующие
                        continue
                    m_unit = spec.metrics_units.get(name) if spec.metrics_units else None
                    # Если значение строковое, пытаемся привести
                    v_coerced, v_type = _coerce_metric_value(val)
                    # Единицы
                    v_conv, unit_final = _convert_value(v_coerced.value, getattr(v_coerced, "unit", None), m_unit, self._extra_rules)
                    metrics.append({
                        "name": name,
                        "unit": unit_final,
                        "valueType": v_coerced.value_type,
                        "value": _emit_metric_value(v_conv, v_coerced.value_type),
                        "labels": None,
                        "sampleTime": _rfc3339(event_time),
                        "quality": {"valid": True, "flags": [], "uncertainty": None},
                    })

                # 5) Обогащение устройства
                device_obj: Optional[Dict[str, Any]] = None
                if self._reg:
                    device_obj = self._reg.get(device_id)
                device = {
                    "device_id": device_id,
                    "model": device_obj.get("model") if device_obj else None,
                    "firmware": device_obj.get("firmware") if device_obj else None,
                    "site": device_obj.get("site") if device_obj else None,
                    "line": device_obj.get("line") if device_obj else None,
                    "tags": device_obj.get("tags") if device_obj else None,
                }

                # 6) Доп. теги с подстановками из контекста (например, topic/env)
                tags = {}
                for k, v in spec.tags.items():
                    if isinstance(v, str):
                        tags[k] = v.format(**context)
                    else:
                        tags[k] = v

                # 7) Normalized payload (по умолчанию — пусто; при желании можно включить часть полей)
                normalized_payload: Dict[str, Any] = {"tags": tags} if tags else {}

                # 8) JSON Schema (если задана и библиотека доступна)
                if spec.schema and _HAS_JSONSCHEMA:
                    SchemaValidator(spec.schema).validate(raw_redacted)

                # 9) Сборка Event
                event_id = str(uuid.uuid4())
                observed_time = now
                event = {
                    "id": event_id,
                    "type": spec.type,
                    "source": context.get("source"),
                    "subject": context.get("subject") or context.get("topic"),
                    "device": {
                        "id": device["device_id"],
                        "model": device["model"],
                        "firmware": device["firmware"],
                        "site": device["site"],
                        "line": device["line"],
                        "tags": device["tags"],
                        "createdAt": None,
                        "updatedAt": None,
                        "lastSeenAt": _rfc3339(observed_time),
                        "status": "UNKNOWN",
                    },
                    "metrics": metrics,
                    "attributes": tags or None,
                    "normalizedPayload": normalized_payload or None,
                    "eventTime": _rfc3339(event_time),
                    "observedTime": _rfc3339(observed_time),
                    "severity": spec.severity or "INFO",
                    "schemaVersion": "1.0.0",
                    "revision": 0,
                    "parentEventId": None,
                    "contentHash": None,  # заполним ниже
                }

                # 10) Контент‑хэш (идемпотентность)
                content_hash = _sha256_hex(_canonical_json({"device": device_id, "ts": _rfc3339(event_time), "metrics": metrics, "attrs": tags}))
                event["contentHash"] = content_hash

                # 11) Сборка Envelope
                envelope_id = str(uuid.uuid4())
                envelope = {
                    "envelope_id": envelope_id,
                    "partition_key": device_id,
                    "ingest_time": _rfc3339(now),
                    "correlation_id": context.get("correlation_id"),
                    "trace": {
                        "trace_id": context.get("trace_id"),
                        "span_id": context.get("span_id"),
                        "parent_span_id": context.get("parent_span_id"),
                        "sampled": context.get("sampled"),
                        "baggage": None,
                    },
                    "audit": {
                        "tenant_id": context.get("tenant_id"),
                        "created_by": context.get("created_by"),
                        "source_ip": context.get("source_ip"),
                        "labels": None,
                    },
                    "event": {
                        # Перекладываем в формат Event для шин/GraphQL (ключи ниже в camelCase ожидаются на внешних API)
                        "id": event["id"],
                        "type": event["type"],
                        "source": event["source"],
                        "subject": event["subject"],
                        "device": event["device"],
                        "metrics": event["metrics"],
                        "attributes": event["attributes"],
                        "normalizedPayload": event["normalizedPayload"],
                        "eventTime": event["eventTime"],
                        "observedTime": event["observedTime"],
                        "severity": event["severity"],
                        "schemaVersion": event["schemaVersion"],
                        "revision": event["revision"],
                        "parentEventId": event["parentEventId"],
                        "contentHash": event["contentHash"],
                    },
                    "payload": None,  # сырые данные можно приложить отдельно при необходимости
                    "payload_content_type": "application/json",
                    "payload_encoding": "JSON",
                    "payload_compression": "NONE",
                    "payload_hash": _sha256_hex(_canonical_json(raw_redacted)),
                    "dlq": False,
                    "dlq_reason": None,
                    "routing": {"topics": None, "priority": "normal", "headers": None},
                }

                # 12) Метрики
                _N_OK.labels(route).inc()
                _T_LAT.labels(route).observe(max(0.0, time.perf_counter() - t0))
                return envelope, None

            except NormalizationError as ne:
                _N_ERROR.labels(route, ne.code).inc()
                _T_LAT.labels(route).observe(max(0.0, time.perf_counter() - t0))
                envelope = {
                    "envelope_id": str(uuid.uuid4()),
                    "partition_key": "dlq",
                    "ingest_time": _rfc3339(_now_utc()),
                    "event": None,
                    "payload": base64.b64encode(_canonical_json(raw).encode("utf-8")).decode("ascii"),
                    "payload_content_type": "application/json",
                    "payload_encoding": "JSON",
                    "payload_compression": "NONE",
                    "payload_hash": _sha256_hex(_canonical_json(raw)),
                    "dlq": True,
                    "dlq_reason": ne.as_error_info(),
                }
                return envelope, ne.as_error_info()
            except Exception as e:
                _N_ERROR.labels(route, "UNHANDLED").inc()
                _T_LAT.labels(route).observe(max(0.0, time.perf_counter() - t0))
                ne = NormalizationError("UNHANDLED", "Unhandled normalization error", {"error": str(e)})
                envelope = {
                    "envelope_id": str(uuid.uuid4()),
                    "partition_key": "dlq",
                    "ingest_time": _rfc3339(_now_utc()),
                    "event": None,
                    "payload": base64.b64encode(_canonical_json(raw).encode("utf-8")).decode("ascii"),
                    "payload_content_type": "application/json",
                    "payload_encoding": "JSON",
                    "payload_compression": "NONE",
                    "payload_hash": _sha256_hex(_canonical_json(raw)),
                    "dlq": True,
                    "dlq_reason": ne.as_error_info(),
                }
                return envelope, ne.as_error_info()

# -------- Вспомогательные преобразования метрик --------
@dataclass
class _CoercedValue:
    value: Any
    value_type: str  # DOUBLE|INT64|BOOL|STRING|BYTES
    unit: Optional[str] = None

def _coerce_metric_value(v: Any) -> _CoercedValue:
    if isinstance(v, bool):
        return _CoercedValue(v, "BOOL")
    if isinstance(v, (int,)):
        return _CoercedValue(int(v), "INT64")
    if isinstance(v, float):
        return _CoercedValue(float(v), "DOUBLE")
    if isinstance(v, (bytes, bytearray)):
        return _CoercedValue(bytes(v), "BYTES")
    if isinstance(v, str):
        s = v.strip()
        # Попытки приведения строки к числам/булю
        if s.lower() in ("true", "false"):
            return _CoercedValue(s.lower() == "true", "BOOL")
        try:
            if "." in s or "e" in s.lower():
                return _CoercedValue(float(s), "DOUBLE")
            return _CoercedValue(int(s), "INT64")
        except Exception:
            return _CoercedValue(s, "STRING")
    # Остальное — сериализуем в строку
    try:
        return _CoercedValue(float(v), "DOUBLE")
    except Exception:
        return _CoercedValue(str(v), "STRING")

def _emit_metric_value(value: Any, vtype: str) -> Dict[str, Any]:
    if vtype == "DOUBLE": return {"double": float(value)}
    if vtype == "INT64":  return {"int": int(value)}
    if vtype == "BOOL":   return {"bool": bool(value)}
    if vtype == "BYTES":  return {"bytesBase64": base64.b64encode(value if isinstance(value, (bytes, bytearray)) else bytes(str(value), "utf-8")).decode("ascii")}
    return {"string": str(value)}

# -------- Пример спецификации (для справки; не влияет на выполнение) --------
EXAMPLE_SPEC = NormalizationSpec(
    name="mqtt-raw",
    device_id_path="$.device_id",
    ts_field_path="$.ts",
    required_paths=["$.payload"],
    ts_tolerance_seconds=600,
    metrics_map={
        "temperature_c": "$.payload.tempC",
        "pressure_kpa": "$.payload.pressure",
        "online": "$.payload.online",
    },
    metrics_units={
        "temperature_c": "C",
        "pressure_kpa": "kPa",
    },
    tags={"source": "mqtt", "topic": "{topic}", "env": "{env}"},
    redact_paths=["$.credentials", "$.payload.secret"],
    schema=None,
    unit_rules=[UnitRule("bar", "kPa", 100.0)],
    severity="INFO",
    type="TELEMETRY",
)
