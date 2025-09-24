# cybersecurity-core/api/http/routers/v1/attack_simulator.py
# -*- coding: utf-8 -*-
"""
Attack Simulator API Router (Safe-by-Default)

Назначение
----------
Промышленный HTTP-роутер FastAPI для безопасного управления эмуляцией техник MITRE ATT&CK.
По умолчанию выполняется dry-run, действует allowlist идентификаторов тестов/техник,
denylist опасных токенов, идемпотентность запросов, ограничение частоты, аудит.

Проверяемые источники (официальные ссылки)
------------------------------------------
- MITRE ATT&CK (таксономия тактик/техник):
  https://attack.mitre.org
- Red Canary Atomic Red Team (концепция атомарных тестов):
  https://github.com/redcanaryco/atomic-red-team
- NIST SP 800-53 Rev. 5 (AU — аудит; CM — управление конфигурациями; SI — реакция/контроль):
  https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final
- Microsoft Defender/ASR & Sysmon (рекомендации по наблюдаемости/правилам):
  https://learn.microsoft.com/windows/security/threat-protection/windows-defender-advanced-threat-protection/attack-surface-reduction

Принципы безопасности
---------------------
1) Dry-run по умолчанию — команды моделируются, не исполняются.
2) Явный allowlist (--only-id/--only-technique) обязателен при включении реального исполнения.
3) Denylist опасных токенов и запрет сетевых команд без явного разрешения.
4) Идемпотентность через заголовок X-Idempotency-Key (RFC-совместимая практика).
5) Rate limit в процессе (in-memory) для защиты от злоупотребления.
6) Все операции помечаются аудиторскими метаданными и возвращают детерминированный JSON.

Лицензия: Apache-2.0

Внимание
--------
Роутер не содержит эксплойтов и не выдаёт эксплуатационные инструкции. Использовать только с разрешения владельца.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, Depends, Header, HTTPException, Query, status, Request
from pydantic import BaseModel, Field, constr, validator

# Внутренняя интеграция с безопасным раннером (см. tooling/atomic_runner.py)
# Предполагается, что модуль присутствует в репозитории.
try:
    # Локальный импорт без тяжёлых зависимостей
    from cybersecurity.adversary_emulation.tooling.atomic_runner import (
        load_atomic_tests,
        AtomicRunner,
        report_to_json,
        ALLOWED_SHELLS,
        token_block_reason,
        _sha256_file,  # для контроля целостности входного файла
    )
except Exception as e:  # pragma: no cover
    raise RuntimeError(f"atomic_runner integration failed: {e}")

# -----------------------------
# Константы и конфигурация
# -----------------------------

API_TAG = "attack-simulator"
DEFAULT_LOG_DIR = Path(os.environ.get("PROGRAMDATA", Path.cwd())) / "CyberAudit" / "sim_api" / "logs"
DEFAULT_LOG_DIR.mkdir(parents=True, exist_ok=True)

MAX_WORKERS_DEFAULT = 4
MAX_WORKERS_LIMIT = 16
RATE_LIMIT_WINDOW_SEC = 10
RATE_LIMIT_MAX_REQ = 10  # простая защита от всплесков
IDEMPOTENCY_TTL_SEC = 15 * 60

# -----------------------------
# Примитивные in-memory сторы
# -----------------------------

_rate_lock = threading.Lock()
_rate_bucket: Dict[str, List[float]] = {}

_idem_lock = threading.Lock()
_idempotency_cache: Dict[str, Tuple[float, Dict[str, Any]]] = {}

# -----------------------------
# Схемы запросов/ответов
# -----------------------------

class StartSimulationRequest(BaseModel):
    tests_file: constr(strip_whitespace=True, min_length=1) = Field(
        ..., description="Путь к JSON/YAML с атомарными тестами (на файловой системе узла API)"
    )
    only_ids: Optional[List[constr(strip_whitespace=True, min_length=1)]] = Field(
        default=None, description="Allowlist test.id (обязателен при enable_exec=true, если не задан only_techniques)"
    )
    only_techniques: Optional[List[constr(regex=r"^T\d{4}(\.\d{3})?$")]] = Field(
        default=None, description="Allowlist ATT&CK техник (например, T1059, T1548.001)"
    )
    enable_exec: bool = Field(
        default=False, description="Включить реальное исполнение (по умолчанию dry-run). Требует allowlist."
    )
    allow_network: bool = Field(
        default=False, description="Разрешить сетевые команды (curl/wget/Invoke-WebRequest). По умолчанию запрещено."
    )
    workers: int = Field(
        default=MAX_WORKERS_DEFAULT, ge=1, le=MAX_WORKERS_LIMIT, description="Количество параллельных воркеров"
    )
    log_level: constr(regex=r"^(DEBUG|INFO|WARN|ERROR)$") = Field(
        default="INFO", description="Уровень логирования раннера"
    )
    sandbox_dir: Optional[constr(strip_whitespace=True, min_length=1)] = Field(
        default=None, description="Каталог песочницы. Если не указан — будет TEMP/atomic_runner_sandbox"
    )

    @validator("only_ids", "only_techniques", pre=True)
    def _empty_to_none(cls, v):
        if v in ([], None, "", ()):
            return None
        return v


class StartSimulationResponse(BaseModel):
    request_id: str = Field(..., description="Уникальный идентификатор запроса (UUID)")
    idempotency_key: Optional[str] = Field(None, description="Ключ идемпотентности из заголовка запроса, если был")
    dry_run: bool = Field(..., description="Признак модельного выполнения")
    allow_network: bool = Field(..., description="Флаг разрешения сетевых команд")
    started_utc: str = Field(..., description="Время начала (UTC, ISO8601)")
    finished_utc: str = Field(..., description="Время завершения (UTC, ISO8601)")
    duration_ms: int = Field(..., description="Длительность выполнения")
    report_json: Dict[str, Any] = Field(..., description="JSON отчёт раннера")
    sha256_tests_file: str = Field(..., description="SHA-256 контрольная сумма файла тестов")
    policy_notes: List[str] = Field(..., description="Ключевые замечания политики безопасности")


class HealthResponse(BaseModel):
    status: str = Field(..., example="ok")
    time_utc: str
    version: str = Field(..., example="v1")


# -----------------------------
# Зависимости: auth/rate-limit
# -----------------------------

def require_api_key(x_api_key: Optional[str] = Header(None)) -> None:
    # Заглушка под реальную проверку ключа (интеграция с Vault/IdP).
    # Здесь лишь минимальная защита: требуем непустой ключ.
    if not x_api_key:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing X-API-Key")


def rate_limit(dep: Any = Depends(require_api_key), request: Request = None) -> None:
    # Простейший токен-бакет по IP/ключу на интервал RATE_LIMIT_WINDOW_SEC
    ip = request.client.host if request and request.client else "unknown"
    key = f"{ip}"
    now = time.time()
    with _rate_lock:
        bucket = _rate_bucket.setdefault(key, [])
        # Очистить старые окна
        bucket[:] = [t for t in bucket if now - t <= RATE_LIMIT_WINDOW_SEC]
        if len(bucket) >= RATE_LIMIT_MAX_REQ:
            raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Rate limit exceeded")
        bucket.append(now)


def get_idempotency_response(idem_key: Optional[str]) -> Optional[Dict[str, Any]]:
    if not idem_key:
        return None
    now = time.time()
    with _idem_lock:
        item = _idempotency_cache.get(idem_key)
        if not item:
            return None
        ts, payload = item
        if now - ts > IDEMPOTENCY_TTL_SEC:
            _idempotency_cache.pop(idem_key, None)
            return None
        return payload


def save_idempotency_response(idem_key: Optional[str], payload: Dict[str, Any]) -> None:
    if not idem_key:
        return
    with _idem_lock:
        _idempotency_cache[idem_key] = (time.time(), payload)


# -----------------------------
# Вспомогательные функции
# -----------------------------

def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()

def _policy_preflight(req: StartSimulationRequest, tests_path: Path) -> List[str]:
    notes: List[str] = []
    # Dry-run по умолчанию, при включении исполнения — обязателен allowlist
    if req.enable_exec and not (req.only_ids or req.only_techniques):
        raise HTTPException(status_code=400, detail="Execution requires allowlist (--only-id/--only-technique).")
    # Ограничение shell — соответствует ALLOWED_SHELLS раннера
    notes.append(f"Allowed shells: {', '.join(sorted(ALLOWED_SHELLS))}")
    # Контроль целостности файла тестов
    try:
        digest = _sha256_file(tests_path)
        notes.append(f"tests_file sha256={digest}")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to hash tests file: {e}")
    # Политика сетевых команд
    if not req.allow_network:
        notes.append("Network commands are blocked by default")
    else:
        notes.append("Network commands are allowed (use with care)")
    # Подсказка по denylist (без раскрытия внутренних паттернов)
    # Сама блокировка реализована в token_block_reason/AtomicRunner
    notes.append("Dangerous tokens are denied by policy (see atomic_runner)")
    return notes

def _load_tests_or_400(path_str: str) -> Tuple[List[Any], Path, str]:
    try:
        tests_path = Path(path_str).expanduser().resolve(strict=True)
    except Exception:
        raise HTTPException(status_code=400, detail="tests_file not found or not accessible")
    try:
        tests = load_atomic_tests(tests_path, logger=_NullLogger())
        return tests, tests_path, _sha256_file(tests_path)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to load tests: {e}")

class _NullLogger:
    # Мини-логгер для загрузчика, чтобы не засорять stdout API
    def info(self, *args, **kwargs): ...
    def warning(self, *args, **kwargs): ...
    def error(self, *args, **kwargs): ...
    def exception(self, *args, **kwargs): ...


# -----------------------------
# Роутер
# -----------------------------

router = APIRouter(prefix="/v1/attack-simulator", tags=[API_TAG])


@router.get("/health", response_model=HealthResponse)
def health(_: Any = Depends(rate_limit)) -> HealthResponse:
    return HealthResponse(status="ok", time_utc=_utc_now_iso(), version="v1")


@router.post(
    "/start",
    response_model=StartSimulationResponse,
    status_code=200,
    summary="Запуск безопасной эмуляции атак (dry-run по умолчанию)",
    description=(
        "Выполняет безопасную эмуляцию атомарных тестов ATT&CK. По умолчанию dry-run, "
        "для реального исполнения требуется allowlist only_ids/only_techniques."
    ),
)
def start_simulation(
    body: StartSimulationRequest,
    x_idempotency_key: Optional[str] = Header(None, convert_underscores=False),
    _: Any = Depends(rate_limit),
) -> StartSimulationResponse:
    # Идемпотентность
    cached = get_idempotency_response(x_idempotency_key)
    if cached:
        return StartSimulationResponse(**cached)

    # Валидация и политика
    tests, tests_path, sha = _load_tests_or_400(body.tests_file)
    notes = _policy_preflight(body, tests_path)

    # Запуск
    started = time.time()
    started_iso = _utc_now_iso()
    try:
        runner = AtomicRunner(
            logger=_NullLogger(),
            dry_run=not body.enable_exec,
            allow_network=body.allow_network,
            max_workers=body.workers,
            sandbox_root=Path(body.sandbox_dir).expanduser().resolve() if body.sandbox_dir else None
        )

        report = runner.run_tests(
            tests=tests,
            only_ids=body.only_ids or None,
            only_techniques=body.only_techniques or None,
        )
        report_dict = json.loads(report_to_json(report))
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Simulation failed: {e}")

    finished_iso = _utc_now_iso()
    duration_ms = int((time.time() - started) * 1000)
    resp_payload: Dict[str, Any] = {
        "request_id": str(uuid.uuid4()),
        "idempotency_key": x_idempotency_key,
        "dry_run": not body.enable_exec,
        "allow_network": body.allow_network,
        "started_utc": started_iso,
        "finished_utc": finished_iso,
        "duration_ms": duration_ms,
        "report_json": report_dict,
        "sha256_tests_file": sha,
        "policy_notes": notes,
    }

    # Сохранить идемпотентный ответ
    save_idempotency_response(x_idempotency_key, resp_payload)

    return StartSimulationResponse(**resp_payload)


# -----------------------------
# Дополнительные сервисные эндпойнты (опционально)
# -----------------------------

class PreflightResponse(BaseModel):
    tests_file: str
    sha256: str
    policy_notes: List[str]

@router.get(
    "/preflight",
    response_model=PreflightResponse,
    summary="Пре-проверка файла тестов и политики",
    description="Проверяет доступность файла тестов, его SHA-256 и применимые политики до запуска."
)
def preflight(
    tests_file: str = Query(..., min_length=1),
    allow_network: bool = Query(False),
    _: Any = Depends(rate_limit),
) -> PreflightResponse:
    _, tests_path, sha = _load_tests_or_400(tests_file)
    notes = _policy_preflight(
        StartSimulationRequest(
            tests_file=tests_file,
            enable_exec=False,
            allow_network=allow_network,
            workers=MAX_WORKERS_DEFAULT,
            log_level="INFO",
        ),
        tests_path,
    )
    return PreflightResponse(tests_file=str(tests_path), sha256=sha, policy_notes=notes)
