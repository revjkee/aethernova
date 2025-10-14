# -*- coding: utf-8 -*-
"""
Great Expectations Bridge for DataFabric
---------------------------------------

Промышленный мост между DataFabric и Great Expectations (GE), обеспечивающий:
- Унифицированный асинхронный интерфейс валидации данных через GE
- Поддержку pandas, PySpark и SQL-источников
- Нормализацию результатов и метрик в стандартный формат DataFabric
- Политику отказов (hard/soft), ретраи, таймауты
- Кэширование контекста и потокобезопасность
- Расширяемые адаптеры BatchRequest

Внешние зависимости: great_expectations (GE).
GE не импортируется на модульном уровне для ускорения старта и повышения устойчивости
в отсутствие пакета. Импорт выполняется лениво внутри класса.

© DataFabric Core. MIT License.
"""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Sequence, Tuple, Union, Callable, Iterable, Literal, List

# Типы для источников данных
try:
    import pandas as _pd  # type: ignore
except Exception:  # pragma: no cover
    _pd = None  # мягкая зависимость

try:
    from pyspark.sql import DataFrame as _SparkDF  # type: ignore
except Exception:  # pragma: no cover
    _SparkDF = None  # мягкая зависимость


logger = logging.getLogger("datafabric.quality.ge_bridge")
if not logger.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(name)s | %(message)s"))
    logger.addHandler(_h)
logger.setLevel(logging.INFO)


# --------------------------- Исключения моста --------------------------------

class GEBrideError(Exception):
    """Базовая ошибка GE-бриджа."""


class GEUnavailableError(GEBrideError):
    """Great Expectations не установлен/недоступен."""


class GEContextError(GEBrideError):
    """Ошибка инициализации DataContext."""


class GEValidationError(GEBrideError):
    """Ошибка выполнения валидации."""


class SourceBuildError(GEBrideError):
    """Ошибка сборки BatchRequest/Validator из источника."""


# --------------------------- Конфигурация/результаты -------------------------

FailurePolicy = Literal["hard", "soft"]


@dataclass(frozen=True)
class GEBridgeConfig:
    # Путь к каталогу GE (great_expectations/), None — использовать get_context() по-умолчанию
    context_root_dir: Optional[str] = None
    # Имя Checkpoint по-умолчанию; если отсутствует — будет создан временный в рантайме
    default_checkpoint_name: Optional[str] = None
    # Таймаут одной валидации
    timeout_seconds: float = 600.0
    # Количество повторов при временных ошибках
    retry_attempts: int = 1
    # Пауза между повторами
    retry_backoff_seconds: float = 1.0
    # Политика отказа: "hard" — ошибка при провале; "soft" — вернуть статус failed
    failure_policy: FailurePolicy = "soft"
    # Доп. флаги
    enable_metrics_collection: bool = True
    # Встроенный флаг нормализации ключевых payload'ов
    compact_payload: bool = True


@dataclass(frozen=True)
class GEBridgeRequest:
    # Обязательные атрибуты задачи
    suite_name: str
    action: str                            # логическое действие (например, "ingest_validation")
    resource: str                          # целевой ресурс (например, "s3://bucket/table")
    run_id: str = field(default_factory=lambda: f"ge-run-{uuid.uuid4()}")
    # Источник данных (один из вариантов ниже)
    pandas_df: Optional[" _pd.DataFrame "] = None          # noqa: F722 (строка для подсветки типов)
    spark_df: Optional[" _SparkDF "] = None                # noqa: F722
    sql_query: Optional[str] = None
    sql_connection_string: Optional[str] = None
    # Явный batch_identifiers (опционально)
    batch_identifiers: Optional[Dict[str, Any]] = None
    # Произвольный контекст/теги
    tags: Tuple[str, ...] = tuple()
    params: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class GEBridgeDecision:
    # Нормализованное решение
    suite_name: str
    action: str
    resource: str
    run_id: str
    passed: bool
    total_expectations: int
    successful_expectations: int
    unsuccessful_expectations: int
    success_percent: float
    # Плоские метрики (по возможности)
    metrics: Dict[str, Any]
    # Короткие детали по провалам
    failed_expectations: Tuple[Dict[str, Any], ...]
    # Сырые артефакты (сжатые/усечённые)
    raw_summary: Dict[str, Any] = field(default_factory=dict)
    # Технические атрибуты
    started_at: float = field(default_factory=lambda: time.time())
    finished_at: float = field(default_factory=lambda: time.time())


# ------------------------------ Утилиты --------------------------------------

def _ensure_ge() -> Any:
    """
    Ленивый импорт GE. Возвращает модуль great_expectations.
    """
    try:
        import great_expectations as ge  # type: ignore
        return ge
    except Exception as exc:  # pragma: no cover
        raise GEUnavailableError(
            "great_expectations не установлен или недоступен. "
            "Установите пакет: pip install great_expectations"
        ) from exc


def _is_dataframe(obj: Any) -> bool:
    if _pd is not None and isinstance(obj, _pd.DataFrame):
        return True
    if _SparkDF is not None and isinstance(obj, _SparkDF):
        return True
    return False


def _shorten(obj: Any, limit: int = 2048) -> Any:
    """Безопасное усечение больших артефактов для логов/хранилища."""
    try:
        s = json.dumps(obj, ensure_ascii=False, default=str)
    except Exception:
        s = str(obj)
    if len(s) <= limit:
        return obj
    # Возвращаем короткую строку, если объект слишком велик
    return f"{s[:limit]}...[truncated {len(s)-limit} chars]"


def _sleep(backoff: float) -> asyncio.Future:
    return asyncio.sleep(max(0.0, backoff))


# ------------------------------ Адаптеры источников --------------------------

class _BatchAdapter:
    """Базовый адаптер сборки BatchRequest/Validator для разных источников."""

    async def build(self, ge_context: Any, req: GEBridgeRequest) -> Tuple[Any, Any]:
        """
        Возвращает (validator, checkpoint_name_or_none).
        Дочерние адаптеры должны реализовать метод.
        """
        raise NotImplementedError


class _PandasAdapter(_BatchAdapter):
    async def build(self, ge_context: Any, req: GEBridgeRequest) -> Tuple[Any, Any]:
        if req.pandas_df is None:
            raise SourceBuildError("pandas_df не задан.")
        ge = _ensure_ge()
        # RuntimeBatchRequest для in-memory DataFrame
        try:
            # Начиная с GE 0.13+ используем Validator через get_validator
            batch_request = {
                "runtime_parameters": {"batch_data": req.pandas_df},
                "batch_identifiers": req.batch_identifiers or {"default_identifier": "pandas"},
            }
            validator = ge_context.get_validator(
                batch_request=batch_request,
                expectation_suite_name=req.suite_name,
            )
            return validator, None
        except Exception as exc:
            raise SourceBuildError(f"Ошибка построения Validator для pandas: {exc}") from exc


class _SparkAdapter(_BatchAdapter):
    async def build(self, ge_context: Any, req: GEBridgeRequest) -> Tuple[Any, Any]:
        if req.spark_df is None:
            raise SourceBuildError("spark_df не задан.")
        ge = _ensure_ge()
        try:
            batch_request = {
                "runtime_parameters": {"batch_data": req.spark_df},
                "batch_identifiers": req.batch_identifiers or {"default_identifier": "spark"},
            }
            validator = ge_context.get_validator(
                batch_request=batch_request,
                expectation_suite_name=req.suite_name,
            )
            return validator, None
        except Exception as exc:
            raise SourceBuildError(f"Ошибка построения Validator для Spark: {exc}") from exc


class _SQLAdapter(_BatchAdapter):
    async def build(self, ge_context: Any, req: GEBridgeRequest) -> Tuple[Any, Any]:
        if not req.sql_query or not req.sql_connection_string:
            raise SourceBuildError("sql_query и sql_connection_string обязательны для SQL-источника.")
        ge = _ensure_ge()
        try:
            # Регистрируем временный datasource/asset через runtime query
            datasource_name = f"df_sql_ds_{uuid.uuid4().hex[:8]}"
            asset_name = f"df_sql_asset_{uuid.uuid4().hex[:8]}"

            # Для универсальности используем add_or_update_* если доступно
            with contextlib.suppress(Exception):
                ge_context.sources.add_sql(datasource_name, connection_string=req.sql_connection_string)

            # Если новая API недоступна, fallback: используем RuntimeBatchRequest
            runtime_parameters = {"query": req.sql_query}
            batch_request = {
                "datasource_name": datasource_name,
                "data_asset_name": asset_name,
                "runtime_parameters": runtime_parameters,
                "batch_identifiers": req.batch_identifiers or {"default_identifier": "sql"},
            }
            validator = ge_context.get_validator(
                batch_request=batch_request,
                expectation_suite_name=req.suite_name,
            )
            return validator, None
        except Exception as exc:
            raise SourceBuildError(f"Ошибка построения Validator для SQL: {exc}") from exc


# ------------------------------- Основной мост --------------------------------

class GreatExpectationsBridge:
    """
    Асинхронный мост для запуска GE-валидаций по унифицированному API.

    Пример использования:
        bridge = GreatExpectationsBridge(GEBridgeConfig(context_root_dir="./great_expectations"))
        decision = await bridge.validate(
            GEBridgeRequest(
                suite_name="my_suite",
                action="ingest_validation",
                resource="s3://bucket/table",
                pandas_df=df,
            )
        )
    """

    def __init__(self, config: Optional[GEBridgeConfig] = None) -> None:
        self._cfg = config or GEBridgeConfig()
        self._context: Optional[Any] = None
        self._ctx_lock = asyncio.Lock()
        self._adapters: Dict[str, _BatchAdapter] = {
            "pandas": _PandasAdapter(),
            "spark": _SparkAdapter(),
            "sql": _SQLAdapter(),
        }

    # ------------------------- Публичный API -------------------------------

    async def validate(self, request: GEBridgeRequest) -> GEBridgeDecision:
        """
        Выполняет валидацию согласно request и возвращает нормализованный результат.
        Таймаут/ретраи/политика отказа управляются конфигурацией.
        """
        started = time.time()
        attempt = 0
        last_exc: Optional[Exception] = None

        while attempt <= self._cfg.retry_attempts:
            try:
                return await asyncio.wait_for(self._validate_once(request, started), timeout=self._cfg.timeout_seconds)
            except (asyncio.TimeoutError, GEContextError, SourceBuildError) as exc:
                # Неретрайабельные либо контролируемые ошибки
                logger.error("GE validate fail (no-retry): %r", exc)
                last_exc = exc
                break
            except Exception as exc:
                # Возможный транзиент — ретраим
                last_exc = exc
                attempt += 1
                if attempt > self._cfg.retry_attempts:
                    logger.exception("GE validate failed after retries: %r", exc)
                    break
                logger.warning("GE validate transient error: %r; retry %d/%d", exc, attempt, self._cfg.retry_attempts)
                await _sleep(self._cfg.retry_backoff_seconds)

        # Пост-обработка согласно failure_policy
        if self._cfg.failure_policy == "soft":
            finished = time.time()
            return GEBridgeDecision(
                suite_name=request.suite_name,
                action=request.action,
                resource=request.resource,
                run_id=request.run_id,
                passed=False,
                total_expectations=0,
                successful_expectations=0,
                unsuccessful_expectations=0,
                success_percent=0.0,
                metrics={},
                failed_expectations=tuple(({"error": str(last_exc or "unknown error")},)),
                raw_summary={"error": str(last_exc or "unknown error")},
                started_at=started,
                finished_at=finished,
            )
        # hard
        raise GEValidationError(str(last_exc or "Unknown GE validation failure"))

    # ------------------------ Внутренние функции ---------------------------

    async def _get_context(self) -> Any:
        """
        Ленивая и потокобезопасная инициализация GE DataContext.
        """
        if self._context is not None:
            return self._context
        async with self._ctx_lock:
            if self._context is not None:
                return self._context
            ge = _ensure_ge()
            try:
                if self._cfg.context_root_dir:
                    # Файловый контекст из каталога проекта GE
                    context = ge.get_context(context_root_dir=self._cfg.context_root_dir)  # type: ignore
                else:
                    # Эфемерный/дефолтный контекст (в новой API это тоже get_context)
                    context = ge.get_context()  # type: ignore
            except Exception as exc:
                raise GEContextError(f"Не удалось инициализировать GE DataContext: {exc}") from exc
            self._context = context
            return self._context

    async def _select_adapter(self, req: GEBridgeRequest) -> _BatchAdapter:
        has_pd = _is_dataframe(req.pandas_df) if req.pandas_df is not None else False
        has_sp = (_SparkDF is not None) and isinstance(req.spark_df, _SparkDF) if req.spark_df is not None else False
        has_sql = bool(req.sql_query and req.sql_connection_string)

        count = int(has_pd) + int(has_sp) + int(has_sql)
        if count != 1:
            raise SourceBuildError("Должен быть указан ровно один источник: pandas_df ИЛИ spark_df ИЛИ (sql_query + sql_connection_string).")

        if has_pd:
            return self._adapters["pandas"]
        if has_sp:
            return self._adapters["spark"]
        return self._adapters["sql"]

    async def _ensure_suite(self, ge_context: Any, suite_name: str) -> None:
        """
        Гарантирует существование expectation suite (создаёт пустой, если его нет).
        """
        try:
            with contextlib.suppress(Exception):
                ge_context.get_expectation_suite(suite_name)  # type: ignore
                return
            ge_context.add_or_update_expectation_suite(expectation_suite_name=suite_name)  # type: ignore
        except Exception as exc:
            raise GEContextError(f"Не удалось получить/создать suite '{suite_name}': {exc}") from exc

    async def _run_with_validator(self, ge_context: Any, validator: Any, req: GEBridgeRequest) -> Dict[str, Any]:
        """
        Пытается выполнить валидацию через Checkpoint (если доступен), иначе — напрямую у validator.
        Возвращает dictionary result (validation_result_dict).
        """
        checkpoint_name = self._cfg.default_checkpoint_name
        # Если чекпойнт задан и существует — используем его
        if checkpoint_name:
            with contextlib.suppress(Exception):
                cp = ge_context.get_checkpoint(checkpoint_name)  # type: ignore
                result = cp.run(validations=[{"batch_request": validator.active_batch_request, "expectation_suite_name": req.suite_name}], run_name=req.run_id)  # type: ignore
                return getattr(result, "to_json_dict", lambda: result)()  # type: ignore

        # Иначе — создаём временный Checkpoint на лету, если возможно
        with contextlib.suppress(Exception):
            tmp_cp_name = f"df_runtime_cp_{uuid.uuid4().hex[:8]}"
            ge_context.add_or_update_checkpoint(  # type: ignore
                name=tmp_cp_name,
                validations=[{"batch_request": validator.active_batch_request, "expectation_suite_name": req.suite_name}],
            )
            cp = ge_context.get_checkpoint(tmp_cp_name)  # type: ignore
            result = cp.run(run_name=req.run_id)  # type: ignore
            return getattr(result, "to_json_dict", lambda: result)()  # type: ignore

        # Фоллбек — прямой запуск у validator
        try:
            run_result = validator.validate()  # type: ignore
            # В старых версиях возвращается ValidationResult; пробуем сериализовать
            if hasattr(run_result, "to_json_dict"):
                return run_result.to_json_dict()  # type: ignore
            if isinstance(run_result, dict):
                return run_result
            # Последний шанс — обертка
            return {"success": bool(getattr(run_result, "success", False)), "results": []}
        except Exception as exc:
            raise GEValidationError(f"Не удалось выполнить validator.validate(): {exc}") from exc

    async def _validate_once(self, request: GEBridgeRequest, started_ts: float) -> GEBridgeDecision:
        ge_context = await self._get_context()
        await self._ensure_suite(ge_context, request.suite_name)

        adapter = await self._select_adapter(request)
        validator, _ = await adapter.build(ge_context, request)

        # Валидация
        raw_dict = await self._run_with_validator(ge_context, validator, request)

        # Нормализация результата
        dec = self._normalize_result(request, raw_dict, started_ts)
        # Политика отказа при успехе=false
        if not dec.passed and self._cfg.failure_policy == "hard":
            raise GEValidationError("Validation failed and failure_policy='hard'.")
        return dec

    def _normalize_result(self, req: GEBridgeRequest, raw: Dict[str, Any], started_ts: float) -> GEBridgeDecision:
        """
        Нормализация GE ValidationResult JSON в компактный GEBridgeDecision.
        Структуры в GE слегка отличаются между версиями; используем устойчивые поля.
        """
        # Определяем success
        success = bool(raw.get("success", False))
        # Извлечение деталей результатов
        results: List[Dict[str, Any]] = []
        if "results" in raw and isinstance(raw["results"], list):
            results = raw["results"]

        total = len(results)
        successful = sum(1 for r in results if bool(r.get("success", False)))
        unsuccessful = total - successful
        success_pct = (successful / total * 100.0) if total > 0 else (100.0 if success else 0.0)

        # Метрики и краткие детали провалов
        metrics: Dict[str, Any] = {}
        failed_details: List[Dict[str, Any]] = []
        if self._cfg.enable_metrics_collection:
            # Пробуем собрать распространённые метрики (row_count, distinct, nulls)
            for r in results:
                tr = r.get("result", {})
                ev_type = r.get("expectation_config", {}).get("expectation_type", "unknown")
                # Популярные ключи: "observed_value", "unexpected_percent", "element_count", "unexpected_count"
                if "observed_value" in tr:
                    metrics_key = f"{ev_type}__observed_value"
                    metrics[metrics_key] = tr["observed_value"]
                if "unexpected_percent" in tr:
                    metrics_key = f"{ev_type}__unexpected_percent"
                    metrics[metrics_key] = tr["unexpected_percent"]
                if "element_count" in tr:
                    metrics_key = f"{ev_type}__element_count"
                    metrics[metrics_key] = tr["element_count"]
                if "unexpected_count" in tr:
                    metrics_key = f"{ev_type}__unexpected_count"
                    metrics[metrics_key] = tr["unexpected_count"]

        for r in results:
            if bool(r.get("success", False)):
                continue
            exp = r.get("expectation_config", {})
            res = r.get("result", {})
            failed_details.append({
                "expectation_type": exp.get("expectation_type", "unknown"),
                "kwargs": _shorten(exp.get("kwargs", {}), 1024),
                "observed": _shorten(res.get("observed_value", None), 512) if isinstance(res, dict) else None,
                "unexpected_percent": res.get("unexpected_percent") if isinstance(res, dict) else None,
                "unexpected_count": res.get("unexpected_count") if isinstance(res, dict) else None,
            })

        finished_ts = time.time()
        raw_summary: Dict[str, Any] = {}
        if not self._cfg.compact_payload:
            raw_summary = raw
        else:
            raw_summary = {
                "success": success,
                "statistics": _shorten(raw.get("statistics", {}), 4096),
                "evaluation_parameters": _shorten(raw.get("evaluation_parameters", {}), 2048),
            }

        return GEBridgeDecision(
            suite_name=req.suite_name,
            action=req.action,
            resource=req.resource,
            run_id=req.run_id,
            passed=success,
            total_expectations=total,
            successful_expectations=successful,
            unsuccessful_expectations=unsuccessful,
            success_percent=round(success_pct, 4),
            metrics=metrics,
            failed_expectations=tuple(failed_details),
            raw_summary=raw_summary,
            started_at=started_ts,
            finished_at=finished_ts,
        )


# ------------------------ Упрощённые фабрики/хелперы -------------------------

def build_request_for_pandas(
    suite_name: str,
    action: str,
    resource: str,
    df: " _pd.DataFrame ",
    *,
    run_id: Optional[str] = None,
    batch_identifiers: Optional[Dict[str, Any]] = None,
    tags: Optional[Iterable[str]] = None,
    params: Optional[Dict[str, Any]] = None,
) -> GEBridgeRequest:
    return GEBridgeRequest(
        suite_name=suite_name,
        action=action,
        resource=resource,
        pandas_df=df,
        run_id=run_id or f"ge-run-{uuid.uuid4()}",
        batch_identifiers=batch_identifiers,
        tags=tuple(tags or ()),
        params=params or {},
    )


def build_request_for_spark(
    suite_name: str,
    action: str,
    resource: str,
    spark_df: " _SparkDF ",
    *,
    run_id: Optional[str] = None,
    batch_identifiers: Optional[Dict[str, Any]] = None,
    tags: Optional[Iterable[str]] = None,
    params: Optional[Dict[str, Any]] = None,
) -> GEBridgeRequest:
    return GEBridgeRequest(
        suite_name=suite_name,
        action=action,
        resource=resource,
        spark_df=spark_df,
        run_id=run_id or f"ge-run-{uuid.uuid4()}",
        batch_identifiers=batch_identifiers,
        tags=tuple(tags or ()),
        params=params or {},
    )


def build_request_for_sql(
    suite_name: str,
    action: str,
    resource: str,
    sql_query: str,
    sql_connection_string: str,
    *,
    run_id: Optional[str] = None,
    batch_identifiers: Optional[Dict[str, Any]] = None,
    tags: Optional[Iterable[str]] = None,
    params: Optional[Dict[str, Any]] = None,
) -> GEBridgeRequest:
    return GEBridgeRequest(
        suite_name=suite_name,
        action=action,
        resource=resource,
        sql_query=sql_query,
        sql_connection_string=sql_connection_string,
        run_id=run_id or f"ge-run-{uuid.uuid4()}",
        batch_identifiers=batch_identifiers,
        tags=tuple(tags or ()),
        params=params or {},
    )


# ------------------------------- Self-test -----------------------------------

async def _selftest() -> None:
    """
    Самотест выполняет только базовые проверки инфраструктуры без реального GE‑запуска.
    Он не требует установленного GE и служит для smoke‑проверки интерфейсов.
    """
    bridge = GreatExpectationsBridge()
    # Проверим сборку запросов
    if _pd is not None:
        import pandas as pd  # type: ignore
        df = pd.DataFrame({"a": [1, 2, 3]})
        req = build_request_for_pandas("suite_x", "demo", "mem://df", df)
        assert req.pandas_df is not None
    # SQL request shape
    req_sql = build_request_for_sql("suite_sql", "demo", "db://conn", "select 1 as x", "sqlite://")
    assert req_sql.sql_query and req_sql.sql_connection_string


if __name__ == "__main__":  # pragma: no cover
    try:
        asyncio.run(_selftest())
        print("GE Bridge selftest passed (interface).")
    except Exception as e:
        print(f"GE Bridge selftest failed: {e}")
