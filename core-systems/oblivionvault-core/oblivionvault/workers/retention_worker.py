# path: oblivionvault-core/oblivionvault/workers/retention_worker.py
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
from abc import ABC, abstractmethod
from enum import Enum
from typing import Any, AsyncIterator, Dict, Iterable, List, Optional, Sequence, Set, Tuple, Union, Callable

# -----------------------------
# Optional deps (safe fallbacks)
# -----------------------------
try:
    # Prefer Pydantic v2
    from pydantic import BaseModel, Field, ConfigDict, ValidationError
except Exception:  # pragma: no cover
    class BaseModel:  # minimal fallback
        def __init__(self, **kwargs):
            for k, v in kwargs.items():
                setattr(self, k, v)
        def model_dump(self) -> Dict[str, Any]:
            return dict(self.__dict__)
    def Field(default=None, **kwargs):  # type: ignore
        return default
    class ValidationError(Exception):  # type: ignore
        pass
    ConfigDict = dict  # type: ignore

try:
    from opentelemetry import trace as ot_trace  # type: ignore
    _OT = ot_trace.get_tracer(__name__)
except Exception:  # pragma: no cover
    _OT = None  # type: ignore

# -----------------------------
# Project deps
# -----------------------------
# Data fabric adapter (предоставлялся ранее)
try:
    from ..adapters.datafabric_adapter import (
        DataFabricAdapter,
        DataEnvelope,
        QuerySpec,
        AccessContext as DFContext,
        OperationResult,
        RetryPolicy as DFRetryPolicy,
        CircuitBreaker as DFCircuitBreaker,
        DataFabricUnavailable,
        DataFabricTimeout,
        DataFabricError,
    )
except Exception as e:  # pragma: no cover
    raise RuntimeError("datafabric_adapter is required") from e

# OPA/Rego evaluator (предоставлялся ранее)
try:
    from ..policy.evaluator_rego import (
        RegoPolicyEvaluator,
        AccessContext as PolicyContext,
        RetryPolicy as PolicyRetryPolicy,
        CircuitBreaker as PolicyCircuitBreaker,
        PolicyError,
        DecisionResult,
    )
except Exception as e:  # pragma: no cover
    raise RuntimeError("policy.evaluator_rego is required") from e


# -----------------------------
# Logging
# -----------------------------
LOG = logging.getLogger("oblivionvault.workers.retention")
if not LOG.handlers:
    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(name)s | %(message)s"))
    LOG.addHandler(h)
LOG.setLevel(logging.INFO)


# -----------------------------
# Errors
# -----------------------------
class RetentionError(Exception):
    """Base error for retention worker."""


class CircuitOpen(RetentionError):
    """Propagated from circuit breaker."""


# -----------------------------
# Models
# -----------------------------
class RetentionAction(str, Enum):
    DELETE = "delete"         # жёсткое удаление
    ARCHIVE = "archive"       # копия в архивный датасет + удаление исходника
    TOMBSONE = "tombstone"    # мягкое удаление (ставим tombstone-флаг)
    ANONYMIZE = "anonymize"   # обезличивание полей


class WORMMode(str, Enum):
    DISABLED = "disabled"
    GOVERNANCE = "governance"  # может быть снят авторизованным процессом по регламенту
    COMPLIANCE = "compliance"  # неснимаемый до истечения срока


class RetentionRule(BaseModel):
    """
    Правило ретенции для одного датасета.
    """
    model_config = ConfigDict(extra="forbid") if isinstance(ConfigDict, dict) else ConfigDict(extra="forbid")  # type: ignore

    dataset: str = Field(..., description="Имя датасета")
    timestamp_field: str = Field(..., description="Имя поля временной метки в payload (unix seconds или ISO8601, на усмотрение транспорта)")
    retain_days: int = Field(..., ge=0, description="Сколько дней хранить данные")
    action: RetentionAction = Field(..., description="Действие при истечении срока")
    # ARCHIVE:
    archive_dataset: Optional[str] = Field(default=None, description="Куда архивировать, если action=ARCHIVE")
    # ANONYMIZE:
    anonymize_fields: List[str] = Field(default_factory=list, description="Список полей для обнуления/хеширования")
    anonymize_with_hash: bool = Field(default=True, description="True: sha256, False: null")
    # WORM:
    worm_mode: WORMMode = Field(default=WORMMode.DISABLED, description="Режим WORM-блокировки")
    worm_lock_until_ts: Optional[float] = Field(default=None, description="UNIX-время, до которого блок удалений активен")
    # LEGAL HOLD:
    legal_hold_label: Optional[str] = Field(default=None, description="Метка legal hold; записи с ней нельзя трогать")
    # Отбор:
    extra_filter: Dict[str, Any] = Field(default_factory=dict, description="Дополнительный фильтр для QuerySpec.filter")
    # Параметры сканирования:
    batch_size: int = Field(default=500, ge=1, le=10_000, description="Сколько записей в батче")
    max_concurrency: int = Field(default=32, ge=1, le=512, description="Параллелизм обработки")
    max_rate_per_sec: Optional[float] = Field(default=None, description="Ограничение RPS на операции мутации")
    # Таймауты:
    read_timeout_s: float = Field(default=15.0)
    write_timeout_s: float = Field(default=20.0)
    # Политика OPA:
    opa_package: str = Field(default="oblivionvault.retention", description="OPA package")
    opa_rule: str = Field(default="allow", description="OPA rule (boolean)")


class RetentionConfig(BaseModel):
    """
    Набор правил + общие настройки воркера.
    """
    model_config = ConfigDict(extra="forbid") if isinstance(ConfigDict, dict) else ConfigDict(extra="forbid")  # type: ignore

    rules: List[RetentionRule]
    scan_interval_s: float = Field(default=300.0, description="Интервал между проходами по всем правилам")
    checkpoint_dataset: str = Field(default="_retention_checkpoints", description="Датасет для чекпойнтов")
    checkpoint_ttl_days: int = Field(default=180, description="Срок хранения чекпойнтов")
    # Ретраи/брейкеры по умолчанию:
    retry_policy: Optional[DFRetryPolicy] = None
    circuit_breaker: Optional[DFCircuitBreaker] = None


# -----------------------------
# Legal Hold Resolver
# -----------------------------
class LegalHoldResolver(ABC):
    @abstractmethod
    async def is_on_hold(self, tenant_id: str, dataset: str, key: str, payload: Dict[str, Any], rule: RetentionRule) -> bool:
        """
        Вернуть True, если запись под legal hold и не должна видоизменяться.
        """
        ...


class NoopLegalHoldResolver(LegalHoldResolver):
    async def is_on_hold(self, tenant_id: str, dataset: str, key: str, payload: Dict[str, Any], rule: RetentionRule) -> bool:
        return False


# -----------------------------
# Checkpoint Store
# -----------------------------
class Checkpoint(BaseModel):
    model_config = ConfigDict(extra="forbid") if isinstance(ConfigDict, dict) else ConfigDict(extra="forbid")  # type: ignore
    dataset: str
    last_processed_ts: float = 0.0
    updated_at: float = 0.0


class CheckpointStore(ABC):
    @abstractmethod
    async def load(self, ctx: DFContext, dataset: str) -> Optional[Checkpoint]:
        ...

    @abstractmethod
    async def save(self, ctx: DFContext, cp: Checkpoint) -> None:
        ...


class FabricCheckpointStore(CheckpointStore):
    """
    Чекпойнты в самом DataFabric (в датасете checkpoint_dataset).
    Ключ = dataset, payload содержит last_processed_ts.
    """
    def __init__(self, df: DataFabricAdapter, dataset_name: str):
        self._df = df
        self._dataset = dataset_name

    async def load(self, ctx: DFContext, dataset: str) -> Optional[Checkpoint]:
        try:
            envs = await self._df.get_records(ctx, self._dataset, keys=[dataset])
            if not envs:
                return None
            payload = envs[0].payload
            return Checkpoint(dataset=dataset, last_processed_ts=float(payload.get("last_processed_ts", 0.0)), updated_at=float(payload.get("updated_at", 0.0)))
        except DataFabricError:
            LOG.exception("checkpoint_load_failed dataset=%s", dataset)
            return None

    async def save(self, ctx: DFContext, cp: Checkpoint) -> None:
        body = {
            "dataset": cp.dataset,
            "last_processed_ts": cp.last_processed_ts,
            "updated_at": time.time(),
        }
        await self._df.upsert_records(
            ctx,
            dataset=self._dataset,
            records=[body],
            schema_version="1.0",
            id_key="dataset",
            idempotency_key=f"cp:{cp.dataset}:{int(body['updated_at'])}",
            timeout_s=10.0,
        )


# -----------------------------
# Utilities
# -----------------------------
def _stable_json(data: Any) -> str:
    return json.dumps(data, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _hash_str(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _now_ts() -> float:
    return time.time()


def _coerce_ts(value: Any) -> Optional[float]:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        # допускаем миллисекунды
        return float(value) / (1000.0 if value > 10_000_000_000 else 1.0)
    # ISO8601 делегируем транспорту; здесь допускаем числовое
    return None


async def _rate_limit(rps: Optional[float], last_tick: List[float]) -> None:
    if not rps or rps <= 0:
        return
    min_interval = 1.0 / rps
    now = _now_ts()
    wait = min_interval - (now - last_tick[0])
    if wait > 0:
        await asyncio.sleep(wait)
    last_tick[0] = _now_ts()


def _anonymize_payload(payload: Dict[str, Any], fields: List[str], use_hash: bool) -> Dict[str, Any]:
    clone = dict(payload)
    for f in fields:
        if f in clone:
            clone[f] = _hash_str(str(clone[f])) if use_hash else None
    return clone


# -----------------------------
# Retention Worker
# -----------------------------
class RetentionWorker:
    """
    Асинхронный воркер ретенции:
    - Сканирует датасеты по правилам, формирует QuerySpec с cutoff.
    - Учитывает WORM (dataset-level) и legal hold.
    - Делает OPA-проверку allow перед мутацией.
    - Поддерживает действия: DELETE, ARCHIVE, TOMBSONE, ANONYMIZE.
    - Чекпойнты прогресса для повторных запусков.
    - Конкурентная обработка с ограничением RPS.
    - Ретраи и circuit-breaker внутри DataFabric/OPA адаптеров.
    """
    def __init__(
        self,
        df: DataFabricAdapter,
        opa: RegoPolicyEvaluator,
        config: RetentionConfig,
        *,
        legal_hold_resolver: Optional[LegalHoldResolver] = None,
        checkpoint_store: Optional[CheckpointStore] = None,
    ):
        self._df = df
        self._opa = opa
        self._cfg = config
        self._lh = legal_hold_resolver or NoopLegalHoldResolver()
        self._cp = checkpoint_store or FabricCheckpointStore(df, config.checkpoint_dataset)
        self._stop = asyncio.Event()

    # ------- Lifecycle -------
    async def stop(self) -> None:
        self._stop.set()

    async def run_forever(self, ctx: DFContext) -> None:
        """
        Бесконечный цикл проходов по правилам с интервалом scan_interval_s.
        """
        while not self._stop.is_set():
            started = _now_ts()
            for rule in self._cfg.rules:
                try:
                    await self._process_rule(ctx, rule)
                except Exception:
                    LOG.exception("rule_processing_failed dataset=%s", rule.dataset)
            # Пауза до следующего прохода
            elapsed = _now_ts() - started
            delay = max(0.0, self._cfg.scan_interval_s - elapsed)
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=delay)
            except asyncio.TimeoutError:
                pass  # времени ожидания достаточно — новый цикл

    async def run_once(self, ctx: DFContext) -> None:
        for rule in self._cfg.rules:
            await self._process_rule(ctx, rule)

    # ------- Core processing -------
    async def _process_rule(self, ctx: DFContext, rule: RetentionRule) -> None:
        LOG.info("retention_rule_start dataset=%s action=%s", rule.dataset, rule.action.value)
        # 1) WORM gate (dataset-level)
        if not self._is_worm_pass(rule):
            LOG.info("worm_locked dataset=%s mode=%s until=%s", rule.dataset, rule.worm_mode.value, rule.worm_lock_until_ts)
            return

        # 2) Загрузка чекпойнта
        cp = await self._cp.load(ctx, rule.dataset)
        last_ts = cp.last_processed_ts if cp else 0.0

        # 3) Расчёт cutoff
        cutoff = _now_ts() - rule.retain_days * 24 * 3600

        # 4) Стрим кандидатов через query
        spec = self._build_query(rule, cutoff, last_ts)
        it = await self._open_query(ctx, spec)

        # 5) Конкурентная обработка
        sem = asyncio.Semaphore(rule.max_concurrency)
        rps_tick = [0.0]
        batch: List[DataEnvelope] = []
        processed = 0
        newest_ts_seen = last_ts

        async for env in it:
            batch.append(env)
            # трекаем последний ts
            ts = _coerce_ts(env.payload.get(rule.timestamp_field))
            if ts:
                newest_ts_seen = max(newest_ts_seen, ts)
            if len(batch) >= rule.batch_size:
                await self._process_batch(ctx, rule, batch, sem, rps_tick)
                processed += len(batch)
                batch = []
                # чекпойнтируем прогресс по времени, а не по количеству
                await self._save_checkpoint(ctx, rule.dataset, newest_ts_seen)

        if batch:
            await self._process_batch(ctx, rule, batch, sem, rps_tick)
            processed += len(batch)
            await self._save_checkpoint(ctx, rule.dataset, newest_ts_seen)

        LOG.info("retention_rule_done dataset=%s processed=%s last_ts=%.3f", rule.dataset, processed, newest_ts_seen)

    def _is_worm_pass(self, rule: RetentionRule) -> bool:
        if rule.worm_mode == WORMMode.DISABLED:
            return True
        if rule.worm_lock_until_ts is None:
            return True
        return _now_ts() >= float(rule.worm_lock_until_ts)

    def _build_query(self, rule: RetentionRule, cutoff_ts: float, last_ts: float) -> QuerySpec:
        """
        Формируем фильтр: timestamp_field < cutoff, и опционально > last_ts (чтобы не обрабатывать старые повторно).
        Структура фильтра — абстрактная; конкретный транспорт обязан понимать операторы.
        Пример (конвенция): {"and":[{"lt":{"field":"ts","value":cutoff}}, {"gt":{"field":"ts","value":last_ts}}], ...extra}
        """
        base = {
            "and": [
                {"lt": {"field": rule.timestamp_field, "value": cutoff_ts}},
                {"gt": {"field": rule.timestamp_field, "value": last_ts}},
            ]
        }
        flt = {"and": [base, rule.extra_filter]} if rule.extra_filter else base
        return QuerySpec(
            dataset=rule.dataset,
            filter=flt,
            limit=rule.batch_size,
            order_by=[rule.timestamp_field],  # возрастание для монотонного чекпойнта
        )

    async def _open_query(self, ctx: DFContext, spec: QuerySpec) -> AsyncIterator[DataEnvelope]:
        # Внутри DataFabricAdapter уже есть ретраи/брейкер/таймауты
        return self._df.query(ctx, spec, timeout_s=self._cfg.retry_policy.max_attempts * self._cfg.retry_policy.max_backoff_s if self._cfg.retry_policy else None)  # type: ignore

    async def _process_batch(self, ctx: DFContext, rule: RetentionRule, batch: List[DataEnvelope], sem: asyncio.Semaphore, rps_tick: List[float]) -> None:
        # Обрабатываем записи конкурентно
        async def _one(env: DataEnvelope) -> None:
            async with sem:
                await _rate_limit(rule.max_rate_per_sec, rps_tick)
                await self._process_one(ctx, rule, env)

        await asyncio.gather(*[_one(env) for env in batch], return_exceptions=False)

    async def _process_one(self, ctx: DFContext, rule: RetentionRule, env: DataEnvelope) -> None:
        # LEGAL HOLD
        if await self._lh.is_on_hold(ctx.tenant_id, env.dataset, env.key, env.payload, rule):
            LOG.info("skip_legal_hold dataset=%s key=%s", env.dataset, env.key)
            return

        # OPA allow?
        decision = await self._check_with_opa(ctx, rule, env)
        if not (decision.ok and (decision.allow is True or decision.result is True)):
            LOG.info("skip_opa_denied dataset=%s key=%s", env.dataset, env.key)
            return

        # Apply action
        if rule.action == RetentionAction.DELETE:
            await self._delete(ctx, env.dataset, [env.key], timeout_s=rule.write_timeout_s)
        elif rule.action == RetentionAction.ARCHIVE:
            if not rule.archive_dataset:
                LOG.warning("archive_dataset_missing dataset=%s key=%s", env.dataset, env.key)
                return
            await self._archive_then_delete(ctx, rule, env)
        elif rule.action == RetentionAction.TOMBSONE:
            await self._tombstone(ctx, env, timeout_s=rule.write_timeout_s)
        elif rule.action == RetentionAction.ANONYMIZE:
            await self._anonymize(ctx, rule, env, timeout_s=rule.write_timeout_s)

    async def _check_with_opa(self, ctx: DFContext, rule: RetentionRule, env: DataEnvelope) -> DecisionResult:
        pctx = PolicyContext(
            tenant_id=ctx.tenant_id,
            principal_id=ctx.principal_id,
            scopes=set(ctx.scopes or set()) | {"policy:evaluate"},
            trace_id=ctx.trace_id,
        )
        pkg = rule.opa_package
        rule_name = rule.opa_rule
        input_doc = {
            "tenant": ctx.tenant_id,
            "principal": ctx.principal_id,
            "scopes": sorted(list(ctx.scopes or [])),
            "dataset": env.dataset,
            "key": env.key,
            "payload": env.payload,
            "action": rule.action.value,
            "worm": {
                "mode": rule.worm_mode.value,
                "lock_until": rule.worm_lock_until_ts,
            },
            "legal_hold_label": rule.legal_hold_label,
        }
        try:
            return await self._opa.evaluate(pctx, package=pkg, rule=rule_name, input_doc=input_doc, timeout_s=5.0, cache=True)
        except PolicyError:
            LOG.exception("opa_evaluate_error dataset=%s key=%s", env.dataset, env.key)
            # В параноидальном режиме лучше не удалять при ошибке авторизации
            return DecisionResult(ok=False)

    # ------- Actions -------
    async def _delete(self, ctx: DFContext, dataset: str, keys: Sequence[str], *, timeout_s: float) -> None:
        await self._df.delete_records(
            ctx,
            dataset=dataset,
            keys=keys,
            idempotency_key=f"del:{dataset}:{','.join(keys)}",
            timeout_s=timeout_s,
        )

    async def _archive_then_delete(self, ctx: DFContext, rule: RetentionRule, env: DataEnvelope) -> None:
        # 1) Пишем в архивный датасет
        archival_payload = dict(env.payload)
        archival_payload["_archived_from"] = env.dataset
        archival_payload["_archived_key"] = env.key
        archival_payload["_archived_at"] = _now_ts()

        await self._df.upsert_records(
            ctx,
            dataset=rule.archive_dataset,  # type: ignore[arg-type]
            records=[archival_payload],
            schema_version=env.schema_version,
            id_key="_archived_key",
            idempotency_key=f"arch:{env.dataset}:{env.key}:{int(archival_payload['_archived_at'])}",
            timeout_s=rule.write_timeout_s,
        )
        # 2) Удаляем исходник
        await self._delete(ctx, env.dataset, [env.key], timeout_s=rule.write_timeout_s)

    async def _tombstone(self, ctx: DFContext, env: DataEnvelope, *, timeout_s: float) -> None:
        payload = dict(env.payload)
        payload["_tombstoned"] = True
        payload["_tombstoned_at"] = _now_ts()
        await self._df.upsert_records(
            ctx,
            dataset=env.dataset,
            records=[payload],
            schema_version=env.schema_version,
            id_key="id" if "id" in payload else "key",  # на случай разной схемы
            idempotency_key=f"tomb:{env.dataset}:{env.key}:{int(payload['_tombstoned_at'])}",
            timeout_s=timeout_s,
        )

    async def _anonymize(self, ctx: DFContext, rule: RetentionRule, env: DataEnvelope, *, timeout_s: float) -> None:
        if not rule.anonymize_fields:
            LOG.info("skip_anonymize_no_fields dataset=%s key=%s", env.dataset, env.key)
            return
        anon = _anonymize_payload(env.payload, rule.anonymize_fields, rule.anonymize_with_hash)
        anon["_anonymized_at"] = _now_ts()
        await self._df.upsert_records(
            ctx,
            dataset=env.dataset,
            records=[anon],
            schema_version=env.schema_version,
            id_key="id" if "id" in anon else "key",
            idempotency_key=f"anon:{env.dataset}:{env.key}:{int(anon['_anonymized_at'])}",
            timeout_s=timeout_s,
        )

    # ------- Checkpoints -------
    async def _save_checkpoint(self, ctx: DFContext, dataset: str, last_ts: float) -> None:
        if last_ts <= 0:
            return
        await self._cp.save(ctx, Checkpoint(dataset=dataset, last_processed_ts=last_ts, updated_at=_now_ts()))


# -----------------------------
# Small helper to build contexts
# -----------------------------
def make_df_context(*, tenant_id: str, principal_id: str, scopes: Optional[Set[str]] = None, trace_id: Optional[str] = None) -> DFContext:
    return DFContext(tenant_id=tenant_id, principal_id=principal_id, scopes=scopes or set(), trace_id=trace_id)


# -----------------------------
# Example factory (optional)
# -----------------------------
class RetentionWorkerFactory:
    """
    Удобный фабричный метод для сборки воркера с типовыми настройками ретраев/брейкеров.
    """
    @staticmethod
    def build(
        df: DataFabricAdapter,
        opa: RegoPolicyEvaluator,
        rules: List[RetentionRule],
        *,
        checkpoint_dataset: str = "_retention_checkpoints",
        scan_interval_s: float = 300.0,
        df_retry: Optional[DFRetryPolicy] = None,
        df_breaker: Optional[DFCircuitBreaker] = None,
        legal_hold_resolver: Optional[LegalHoldResolver] = None,
        checkpoint_store: Optional[CheckpointStore] = None,
    ) -> RetentionWorker:
        cfg = RetentionConfig(
            rules=rules,
            scan_interval_s=scan_interval_s,
            checkpoint_dataset=checkpoint_dataset,
            retry_policy=df_retry,
            circuit_breaker=df_breaker,
        )
        return RetentionWorker(
            df=df,
            opa=opa,
            config=cfg,
            legal_hold_resolver=legal_hold_resolver,
            checkpoint_store=checkpoint_store or FabricCheckpointStore(df, checkpoint_dataset),
        )
