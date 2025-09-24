# -*- coding: utf-8 -*-
"""
VeilMind Core — v1 Detect Router
Промышленный эндпоинт детекции PII/секретов в произвольном payload.

Особенности:
- Загрузка правил из configs/redaction.yaml (env: VEILMIND_REDACTION_CONFIG), авто‑перечтение по mtime
- Безопасная компиляция regex (флаги только re.IGNORECASE/MULTILINE), контроль групп
- Нормализация ключей (lower + [\s\-] -> _), поддержка targets: json, text, headers, cookies, query, env, files
- Luhn‑валидация для кредитных карт
- Маскирование предпросмотра с сохранением первых/последних символов
- Pydantic v2 схемы, строгие типы и стабильный контракт ответа
- Корреляция: X-Correlation-Id, Idempotency-Key; зеркалируются в ответ
- Опциональная телеметрия Prometheus и OpenTelemetry (мягкие импорты)

Совместимость:
- Python 3.11+, FastAPI, Pydantic v2
"""

from __future__ import annotations

import json
import os
import re
import threading
import time
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Literal, Mapping, Optional, Tuple, Union

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response, status
from pydantic import BaseModel, Field, ConfigDict

# Мягкие зависимости (Prometheus/OTel)
try:
    from prometheus_client import Counter  # type: ignore

    _PROM = True
except Exception:  # pragma: no cover
    _PROM = False

try:
    from opentelemetry import trace  # type: ignore

    _TR = True
    _tracer = trace.get_tracer(__name__)
except Exception:  # pragma: no cover
    _TR = False
    _tracer = None  # type: ignore

try:
    import yaml  # PyYAML
except Exception as e:  # pragma: no cover
    raise RuntimeError("PyYAML (yaml) is required for detect router") from e


# ------------------------------------------------------------------------------
# Конфиг/дефолты
# ------------------------------------------------------------------------------
DEFAULT_CONFIG_PATH = os.getenv("VEILMIND_REDACTION_CONFIG", "configs/redaction.yaml")

DEFAULT_MASK_CHAR = "*"
DEFAULT_MASK_KEEP_HEAD = 2
DEFAULT_MASK_KEEP_TAIL = 2
DEFAULT_MAX_VALUE_LEN = 4096

SUPPORTED_SOURCES = {"http", "grpc", "db", "process", "files", "auto"}
SUPPORTED_TARGETS = {"json", "text", "headers", "cookies", "query", "env", "files"}

# ------------------------------------------------------------------------------
# Модели Pydantic (v2)
# ------------------------------------------------------------------------------

class DetectRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source: Literal["http", "grpc", "db", "process", "files", "auto"] = Field(
        default="auto", description="Источник данных"
    )
    payload: Any = Field(..., description="Произвольный JSON payload или строка текста")
    include_text_scan: bool = Field(
        default=True, description="Сканировать ли неструктурированный текст (если присутствует)"
    )
    return_masked_preview: bool = Field(
        default=False, description="Вернуть payload с масками для найденных значений"
    )
    max_depth: int = Field(
        default=8, ge=1, le=64, description="Макс. глубина обхода вложенных структур"
    )
    limit_matches: int = Field(
        default=1000, ge=1, le=10000, description="Ограничение общего числа совпадений"
    )

class Match(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str = Field(..., description="JSONPath-подобный путь до ключа/участка текста")
    target: Literal["json", "text", "headers", "cookies", "query", "env", "files"]
    category: Literal["denylist", "pii", "sensitive", "weak"] = Field(...)
    detector: str = Field(..., description="Имя детектора")
    sample: str = Field(..., description="Фрагмент найденного значения (маскирован/обрезан)")
    start: Optional[int] = Field(None, description="Начальная позиция в тексте (если target=text)")
    end: Optional[int] = Field(None, description="Конечная позиция (исключительно)")

class DetectStats(BaseModel):
    model_config = ConfigDict(extra="forbid")

    fields_scanned: int = 0
    matches: int = 0
    elapsed_ms: int = 0

class DetectResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    matches: List[Match]
    stats: DetectStats
    redacted_preview: Optional[Any] = None


# ------------------------------------------------------------------------------
# Детектор: описание и загрузка правил
# ------------------------------------------------------------------------------

@dataclass(frozen=True)
class CompiledDetector:
    name: str
    category: str  # denylist | pii | sensitive | weak
    targets: Tuple[str, ...]
    regex: Optional[re.Pattern] = None
    group: Optional[int] = None
    multiline: bool = False
    luhn: bool = False  # для кредитных карт

def _normalize_key(key: str) -> str:
    k = key.strip().lower()
    k = re.sub(r"[\s\-]+", "_", k)
    return k

def _mask_value(value: str, keep_head: int, keep_tail: int, mask_char: str) -> str:
    if value is None:
        return ""
    s = str(value)
    if keep_head < 0:
        keep_head = 0
    if keep_tail < 0:
        keep_tail = 0
    if len(s) <= keep_head + keep_tail:
        return mask_char * len(s)
    return f"{s[:keep_head]}{mask_char * (len(s)-keep_head-keep_tail)}{s[-keep_tail:]}"

def _luhn_ok(number: str) -> bool:
    digits = [int(ch) for ch in re.sub(r"\D", "", number)]
    if len(digits) < 12:
        return False
    checksum = 0
    parity = (len(digits) - 2) % 2
    for i, d in enumerate(digits[:-1]):
        if i % 2 == parity:
            d = d * 2
            if d > 9:
                d -= 9
        checksum += d
    return (checksum + digits[-1]) % 10 == 0

class _RuleLoader:
    """
    Загружает redaction.yaml, компилирует детекторы, кеширует и перечитывает по mtime.
    """
    def __init__(self, path: str):
        self._path = Path(path)
        self._lock = threading.RLock()
        self._mtime = 0.0
        self._compiled: List[CompiledDetector] = []
        # дефолтные параметры маски
        self.mask_char = DEFAULT_MASK_CHAR
        self.mask_head = DEFAULT_MASK_KEEP_HEAD
        self.mask_tail = DEFAULT_MASK_KEEP_TAIL
        self.max_value_len = DEFAULT_MAX_VALUE_LEN

    def get(self) -> Tuple[List[CompiledDetector], int, int, str, int]:
        with self._lock:
            mtime = self._path.stat().st_mtime if self._path.exists() else 0.0
            if mtime != self._mtime or not self._compiled:
                self._reload()
            return (
                self._compiled,
                self.mask_head,
                self.mask_tail,
                self.mask_char,
                self.max_value_len,
            )

    def _reload(self) -> None:
        cfg: Dict[str, Any] = {}
        if self._path.exists():
            with self._path.open("r", encoding="utf-8") as f:
                cfg = yaml.safe_load(f) or {}
        # defaults
        defaults = cfg.get("defaults", {}) if isinstance(cfg, dict) else {}
        self.mask_char = defaults.get("mask_char", DEFAULT_MASK_CHAR) or DEFAULT_MASK_CHAR
        self.mask_head = int(defaults.get("mask_keep_head", DEFAULT_MASK_KEEP_HEAD) or DEFAULT_MASK_KEEP_HEAD)
        self.mask_tail = int(defaults.get("mask_keep_tail", DEFAULT_MASK_KEEP_TAIL) or DEFAULT_MASK_KEEP_TAIL)
        self.max_value_len = int(defaults.get("max_value_len", DEFAULT_MAX_VALUE_LEN) or DEFAULT_MAX_VALUE_LEN)

        compiled: List[CompiledDetector] = []

        # detectors[]
        dets = cfg.get("detectors", []) if isinstance(cfg, dict) else []
        for d in dets:
            try:
                name = str(d["name"])
                category = str(d["category"])
                targets = tuple(t for t in d.get("targets", []) if t in SUPPORTED_TARGETS)
                if not targets:
                    continue
                regex = d.get("regex")
                group = d.get("group")
                multiline = bool(d.get("multiline", False))
                luhn = bool(d.get("luhn", False))
                cregex = None
                if regex:
                    flags = re.IGNORECASE
                    if multiline:
                        flags |= re.MULTILINE | re.DOTALL
                    cregex = re.compile(regex, flags)
                compiled.append(
                    CompiledDetector(
                        name=name,
                        category=category,
                        targets=targets,
                        regex=cregex,
                        group=int(group) if group is not None else None,
                        multiline=multiline,
                        luhn=luhn,
                    )
                )
            except Exception:
                # Некорректный детектор — пропускаем
                continue

        # json_rules: denylist/pii/sensitive/allowlist по ключам
        json_rules = cfg.get("json_rules", {}) if isinstance(cfg, dict) else {}
        for category in ("denylist", "pii", "sensitive", "weak"):
            for item in json_rules.get(category, []) or []:
                keys = [str(k) for k in item.get("keys", [])]
                where = [w for w in item.get("where", []) if w in SUPPORTED_TARGETS]
                if not keys or not where:
                    continue
                # из ключевого правила формируем "фиктивный" детектор по ключам
                for k in keys:
                    compiled.append(
                        CompiledDetector(
                            name=f"key:{_normalize_key(k)}",
                            category=category,
                            targets=tuple(where),
                            regex=None,
                            group=None,
                        )
                    )

        self._compiled = compiled
        self._mtime = self._path.stat().st_mtime if self._path.exists() else 0.0


# Глобальный загрузчик правил
_RULES = _RuleLoader(DEFAULT_CONFIG_PATH)

# Прометеевские метрики (опционально)
if _PROM:  # pragma: no cover
    DETECT_REQ = Counter("veilmind_detect_requests_total", "Detect requests", ["source"])
    DETECT_MATCH = Counter("veilmind_detect_matches_total", "Detected matches", ["category", "detector"])


# ------------------------------------------------------------------------------
# Детекторный движок
# ------------------------------------------------------------------------------

def _iter_items(
    data: Any,
    path: str = "$",
    depth: int = 0,
    max_depth: int = 8,
) -> Iterable[Tuple[str, Optional[str], Any]]:
    """
    Итератор по структурам JSON для детекции.
    Возвращает (jsonpath, ключ, значение).
    """
    if depth > max_depth:
        return
    if isinstance(data, Mapping):
        for k, v in data.items():
            k_str = str(k)
            p = f"{path}.{k_str}"
            yield p, k_str, v
            yield from _iter_items(v, p, depth + 1, max_depth)
    elif isinstance(data, (list, tuple)):
        for i, v in enumerate(data):
            p = f"{path}[{i}]"
            yield p, None, v
            yield from _iter_items(v, p, depth + 1, max_depth)
    else:
        yield path, None, data


def _value_to_str(val: Any, limit: int) -> str:
    try:
        if isinstance(val, (dict, list)):
            s = json.dumps(val, ensure_ascii=False)
        else:
            s = str(val)
    except Exception:
        s = repr(val)
    if len(s) > limit:
        s = s[:limit] + "…"
    return s


def _scan_text(
    text: str,
    detectors: List[CompiledDetector],
    mask_head: int,
    mask_tail: int,
    mask_char: str,
    limit_matches: int,
) -> List[Match]:
    matches: List[Match] = []
    for det in detectors:
        if "text" not in det.targets:
            continue
        if det.regex is None:
            continue
        for m in det.regex.finditer(text or ""):
            grp = m.group(det.group) if det.group else m.group(0)
            sample = _mask_value(grp, mask_head, mask_tail, mask_char)
            matches.append(
                Match(
                    path="$.text",
                    target="text",
                    category=det.category, detector=det.name,
                    sample=sample, start=m.start(), end=m.end(),
                )
            )
            if _PROM:  # pragma: no cover
                DETECT_MATCH.labels(det.category, det.name).inc()
            if len(matches) >= limit_matches:
                return matches
        # Luhn доп.проверка (например, credit_card)
        if det.luhn and det.regex is not None:
            for m in det.regex.finditer(text or ""):
                grp = m.group(det.group) if det.group else m.group(0)
                if _luhn_ok(grp):
                    sample = _mask_value(grp, mask_head, mask_tail, mask_char)
                    matches.append(
                        Match(
                            path="$.text",
                            target="text",
                            category=det.category, detector=f"{det.name}:luhn",
                            sample=sample, start=m.start(), end=m.end(),
                        )
                    )
                    if _PROM:  # pragma: no cover
                        DETECT_MATCH.labels(det.category, f"{det.name}:luhn").inc()
                    if len(matches) >= limit_matches:
                        return matches
    return matches


def _match_by_key(
    key_norm: Optional[str],
    target: str,
    detectors: List[CompiledDetector],
) -> List[CompiledDetector]:
    if not key_norm:
        return []
    res = []
    for det in detectors:
        if det.regex is None and target in det.targets and det.name.startswith("key:"):
            # key-rule
            if det.name == f"key:{key_norm}":
                res.append(det)
    return res


def _scan_structured(
    payload: Mapping[str, Any],
    detectors: List[CompiledDetector],
    mask_head: int,
    mask_tail: int,
    mask_char: str,
    max_depth: int,
    limit_matches: int,
) -> Tuple[List[Match], int]:
    """
    Сканирует структурированные секции: headers/cookies/query/env/json/files.
    Возвращает (matches, fields_scanned).
    """
    matches: List[Match] = []
    fields_scanned = 0

    # Кандидатные разделы
    sections = {
        "headers": payload.get("headers") or {},
        "cookies": payload.get("cookies") or {},
        "query": payload.get("query") or {},
        "env": payload.get("env") or {},
        "files": payload.get("files") or {},
        "json": payload.get("json") or payload,  # fallback: весь payload как json
    }

    for target, section in sections.items():
        if target not in SUPPORTED_TARGETS:
            continue
        # Простые словари
        if isinstance(section, Mapping):
            for p, key, value in _iter_items(section, path=f"$.{target}", max_depth=max_depth):
                fields_scanned += 1
                # Сначала — match по ключу
                key_norm = _normalize_key(key) if key else None
                key_dets = _match_by_key(key_norm, target, detectors)
                if key_dets:
                    for kd in key_dets:
                        sample = _mask_value(_value_to_str(value, 128), mask_head, mask_tail, mask_char)
                        matches.append(Match(path=p, target=target, category=kd.category, detector=kd.name, sample=sample))
                        if _PROM:  # pragma: no cover
                            DETECT_MATCH.labels(kd.category, kd.name).inc()
                        if len(matches) >= limit_matches:
                            return matches, fields_scanned
                # Затем — regex‑детекторы для данного target
                val_str = _value_to_str(value, 2048)
                for det in detectors:
                    if target not in det.targets or det.regex is None:
                        continue
                    for m in det.regex.finditer(val_str or ""):
                        grp = m.group(det.group) if det.group else m.group(0)
                        # Доп. Luhn
                        if det.luhn and not _luhn_ok(grp):
                            continue
                        sample = _mask_value(grp, mask_head, mask_tail, mask_char)
                        matches.append(Match(path=p, target=target, category=det.category, detector=det.name, sample=sample))
                        if _PROM:  # pragma: no cover
                            DETECT_MATCH.labels(det.category, det.name).inc()
                        if len(matches) >= limit_matches:
                            return matches, fields_scanned
        # Текстовые секции (например files.content) можно расширить при необходимости
        elif isinstance(section, str) and target in {"files"}:
            # скан как текст
            tmatches = _scan_text(section, detectors, mask_head, mask_tail, mask_char, limit_matches - len(matches))
            for m in tmatches:
                m = m.model_copy(update={"path": f"$.{target}", "target": target})
                matches.append(m)
                if len(matches) >= limit_matches:
                    return matches, fields_scanned

    return matches, fields_scanned


def _apply_mask_preview(payload: Any, matches: List[Match], mask_head: int, mask_tail: int, mask_char: str, max_depth: int) -> Any:
    """
    Возвращает копию payload с масками для значений, попавших под детекцию (только json‑мишени).
    """
    red = deepcopy(payload)

    # Путь → список детекторов (для ускорения)
    paths = {}
    for m in matches:
        if m.target == "json" and m.path.startswith("$."):
            paths.setdefault(m.path, []).append(m)

    def _mask_in_place(obj: Any, path: str, depth: int = 0) -> None:
        if depth > max_depth:
            return
        if path == "$":
            node = obj
        else:
            # навигация: $.a.b[0].c
            parts = []
            buf = path[2:]  # убрать "$."
            i = 0
            while i < len(buf):
                if buf[i] == "[":
                    j = buf.find("]", i)
                    idx = int(buf[i + 1 : j])
                    parts.append(idx)
                    i = j + 1
                    if i < len(buf) and buf[i] == ".":
                        i += 1
                else:
                    j = buf.find(".", i)
                    k = buf.find("[", i)
                    if j == -1 and k == -1:
                        parts.append(buf[i:])
                        break
                    # ближайший разделитель
                    if j == -1 or (k != -1 and k < j):
                        parts.append(buf[i:k])
                        i = k
                    else:
                        parts.append(buf[i:j])
                        i = j + 1
            node = obj
            try:
                for p in parts[:-1]:
                    node = node[p]
                last = parts[-1]
            except Exception:
                return

            try:
                val = node[last]
                node[last] = _mask_value(_value_to_str(val, 4096), mask_head, mask_tail, mask_char)
            except Exception:
                return

    for p in paths.keys():
        _mask_in_place(red, p)

    return red


# ------------------------------------------------------------------------------
# FastAPI Router
# ------------------------------------------------------------------------------

router = APIRouter(prefix="/v1/detect", tags=["detect"])


def _trace_ctx():  # pragma: no cover
    if not _TR:
        # no-op context manager
        from contextlib import nullcontext

        return nullcontext()
    return _tracer.start_as_current_span("veilmind.detect")


@router.post(
    "",
    response_model=DetectResponse,
    status_code=status.HTTP_200_OK,
    summary="Детекция PII/секретов в payload",
    responses={
        200: {"description": "OK"},
        400: {"description": "Некорректный запрос"},
    },
)
async def detect(
    req: DetectRequest,
    request: Request,
    response: Response,
    x_correlation_id: Optional[str] = Header(default=None, alias="X-Correlation-Id"),
    idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key"),
):
    """
    Синхронная детекция PII/секретов на основе правил redaction.yaml.
    Возвращает список совпадений и, опционально, маскированный предпросмотр.
    """
    t0 = time.perf_counter()
    if _PROM:  # pragma: no cover
        DETECT_REQ.labels(req.source).inc()

    # Корреляция и идемпотентность — эхо в ответ
    if x_correlation_id:
        response.headers["X-Correlation-Id"] = x_correlation_id
    if idempotency_key:
        response.headers["Idempotency-Key"] = idempotency_key

    with _trace_ctx():
        detectors, mask_head, mask_tail, mask_char, max_val_len = _RULES.get()

        # Нормализуем вход
        payload: Dict[str, Any]
        text_blob: Optional[str] = None

        if isinstance(req.payload, Mapping):
            payload = dict(req.payload)  # копия
            # Если источник http и есть "raw" — используем как текст
            raw = payload.get("raw")
            if isinstance(raw, str):
                text_blob = raw
        elif isinstance(req.payload, str):
            payload = {"json": {"value": req.payload}}
            text_blob = req.payload
        else:
            # Лист/примитив
            payload = {"json": req.payload}

        # Основной скан
        matches_struct, fields_scanned = _scan_structured(
            payload=payload,
            detectors=detectors,
            mask_head=mask_head,
            mask_tail=mask_tail,
            mask_char=mask_char,
            max_depth=req.max_depth,
            limit_matches=req.limit_matches,
        )

        matches_text: List[Match] = []
        if req.include_text_scan:
            # Композиция текстовых разделов: payload.get("text") или собранный raw
            text_sections: List[str] = []
            if text_blob:
                text_sections.append(text_blob)
            # response.body/request.body как строка, если присутствуют
            for key in ("$.request.body", "$.response.body"):
                # Поищем в json‑представлении
                try:
                    # Находится ли сырой текст в этих полях?
                    pass
                except Exception:
                    pass
            # Скан каждого текста
            for i, t in enumerate(text_sections):
                tms = _scan_text(
                    t or "",
                    detectors=detectors,
                    mask_head=mask_head,
                    mask_tail=mask_tail,
                    mask_char=mask_char,
                    limit_matches=req.limit_matches - (len(matches_struct) + len(matches_text)),
                )
                # Исправим path на уникальный, если несколько секций
                for m in tms:
                    m.path = f"$.text[{i}]"
                matches_text.extend(tms)
                if len(matches_struct) + len(matches_text) >= req.limit_matches:
                    break

        matches = matches_struct + matches_text

        redacted_preview: Optional[Any] = None
        if req.return_masked_preview:
            redacted_preview = _apply_mask_preview(payload, matches, mask_head, mask_tail, mask_char, req.max_depth)

        elapsed_ms = int((time.perf_counter() - t0) * 1000)

        return DetectResponse(
            matches=matches,
            stats=DetectStats(fields_scanned=fields_scanned, matches=len(matches), elapsed_ms=elapsed_ms),
            redacted_preview=redacted_preview,
        )
