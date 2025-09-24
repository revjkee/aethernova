# -*- coding: utf-8 -*-
"""
OmniMind Core — Planner Worker

Назначение:
- Фоновая обработка задач "план" из очереди Redis Streams.
- Генерация и валидация иерархического плана с помощью LLM по безопасному промпту.
- Идемпотентность по request_id, DLQ, ретраи, метрики и трассировка.

Зависимости (опционально, мягкие):
- redis.asyncio (через adapters.queue.redis_queue)
- httpx (HTTP клиент к LLM-провайдерам)
- prometheus_client (метрики)
- opentelemetry-api (трейсинг)

Контракты сообщений:
Вход (stream: settings.in_stream):
{
  "type": "plan.request",
  "request_id": "uuid-...",
  "goal": "строка",
  "constraints": "строка или null",
  "context": "строка или null",
  "locale": "ru|en",
  "response_stream": "omnimind:queue:plan_responses"  // опционально; если не задан, используется settings.out_stream
}

Выход (stream: response_stream или settings.out_stream):
{
  "type": "plan.response",
  "request_id": "...",
  "ok": true,
  "plan": [ { "id": "step-1", "title": "...", "depends_on": [], "estimate_minutes": 30, "inputs": {}, "outputs": {} }, ... ],
  "model": "provider/model",
  "duration_ms": 0,
  "usage": { "input_tokens": 0, "output_tokens": 0 }  // если доступно
}

При ошибке (DLQ или ответ с ok=false):
{
  "type": "plan.response",
  "request_id": "...",
  "ok": false,
  "error": { "code": "bad_request|llm_error|timeout|internal", "message": "..." }
}
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import signal
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Tuple

from pydantic import BaseModel, BaseSettings, Field, ValidationError, validator

# Мягкие зависимости
try:
    import httpx  # type: ignore
except Exception:  # pragma: no cover
    httpx = None  # type: ignore

try:
    from prometheus_client import Counter, Histogram  # type: ignore
    _PROM = True
except Exception:  # pragma: no cover
    _PROM = False
    class _Noop:
        def labels(self, *a, **k): return self
        def inc(self, *a, **k): pass
        def observe(self, *a, **k): pass
    Counter = Histogram = _Noop  # type: ignore

try:
    from opentelemetry import trace  # type: ignore
    _OTEL = True
except Exception:  # pragma: no cover
    _OTEL = False
    trace = None  # type: ignore

# Локальные компоненты
try:
    from omnimind.adapters.queue.redis_queue import (
        RedisStreamQueue,
        RedisQueueSettings,
        QueueWorker,
        QueueMessage,
    )
except Exception as e:  # pragma: no cover
    raise RuntimeError("Queue adapter not available: omnimind.adapters.queue.redis_queue") from e

try:
    from omnimind.nlp.prompts import get_default_registry, build_chatml  # типы и конструкторы промптов
except Exception as e:  # pragma: no cover
    raise RuntimeError("Prompts module not available: omnimind.nlp.prompts") from e


# -----------------------------------------------------------------------------
# Метрики
# -----------------------------------------------------------------------------
PLAN_REQS = Counter("omnimind_planner_requests_total", "Planner tasks", ["result"]) if _PROM else Counter()
PLAN_LAT = Histogram("omnimind_planner_duration_seconds", "Planner task duration") if _PROM else Histogram()


# -----------------------------------------------------------------------------
# Настройки
# -----------------------------------------------------------------------------
class LLMSettings(BaseSettings):
    provider: str = Field("openai", env="LLM_PROVIDER")  # openai|anthropic
    timeout_s: float = Field(40.0, env="LLM_TIMEOUT_S")
    retries: int = Field(2, env="LLM_RETRIES")
    backoff_s: float = Field(0.4, env="LLM_BACKOFF_S")
    temperature: float = Field(0.2, env="LLM_TEMPERATURE")

    # OpenAI
    openai_api_key: Optional[str] = Field(None, env="OPENAI_API_KEY")
    openai_base_url: str = Field("https://api.openai.com", env="OPENAI_BASE_URL")
    openai_model: str = Field("gpt-4o-mini", env="OPENAI_MODEL")

    # Anthropic
    anthropic_api_key: Optional[str] = Field(None, env="ANTHROPIC_API_KEY")
    anthropic_base_url: str = Field("https://api.anthropic.com", env="ANTHROPIC_BASE_URL")
    anthropic_model: str = Field("claude-3-5-sonnet-20240620", env="ANTHROPIC_MODEL")
    anthropic_max_tokens: int = Field(2048, env="ANTHROPIC_MAX_TOKENS")

    class Config:
        env_file = os.environ.get("ENV_FILE", None)
        case_sensitive = False


class PlannerSettings(BaseSettings):
    app_env: str = Field("production", env="APP_ENV")

    # Очереди
    in_stream: str = Field("omnimind:plan:requests", env="PLAN_IN_STREAM")
    out_stream: str = Field("omnimind:plan:responses", env="PLAN_OUT_STREAM")
    group: str = Field("planner-consumers", env="PLAN_GROUP")
    consumer: str = Field("planner-1", env="PLAN_CONSUMER")
    concurrency: int = Field(8, env="PLAN_CONCURRENCY")

    # Идемпотентность/ключи
    processed_prefix: str = Field("plan:processed:", env="PLAN_PROCESSED_PREFIX")
    processed_ttl_s: int = Field(24 * 3600, env="PLAN_PROCESSED_TTL_S")

    # Ограничения
    max_goal_len: int = Field(4000, env="PLAN_MAX_GOAL_LEN")
    max_ctx_len: int = Field(8000, env="PLAN_MAX_CTX_LEN")

    # Промпты
    prompt_id: str = Field("plan", env="PLAN_PROMPT_ID")
    prompt_version: Optional[str] = Field("1.0", env="PLAN_PROMPT_VERSION")
    default_locale: str = Field("ru", env="PLAN_DEFAULT_LOCALE")

    # Поведение при ошибках
    max_attempts_before_dlq: int = Field(8, env="PLAN_MAX_ATTEMPTS_DLQ")

    class Config:
        env_file = os.environ.get("ENV_FILE", None)
        case_sensitive = False


# -----------------------------------------------------------------------------
# Валидация входного сообщения
# -----------------------------------------------------------------------------
class PlanRequest(BaseModel):
    type: str
    request_id: str
    goal: str
    constraints: Optional[str] = None
    context: Optional[str] = None
    locale: Optional[str] = None
    response_stream: Optional[str] = None

    @validator("type")
    def _vt(cls, v):
        if v != "plan.request":
            raise ValueError("type must be 'plan.request'")
        return v

    @validator("goal")
    def _vg(cls, v):
        v = (v or "").strip()
        if not v:
            raise ValueError("goal must be non-empty")
        return v


# -----------------------------------------------------------------------------
# LLM-клиент
# -----------------------------------------------------------------------------
class LLMClient:
    def __init__(self, cfg: LLMSettings):
        self.cfg = cfg
        if httpx is None:
            raise RuntimeError("httpx is not installed for LLMClient")

    async def chat(self, messages: List[Dict[str, str]], *, provider: Optional[str] = None) -> Tuple[str, Dict[str, Any]]:
        """
        Возвращает (text, usage). Использует OpenAI или Anthropic в зависимости от настроек.
        """
        prov = (provider or self.cfg.provider).lower()
        if prov == "openai":
            return await self._chat_openai(messages)
        elif prov == "anthropic":
            return await self._chat_anthropic(messages)
        raise ValueError(f"Unsupported provider: {prov}")

    async def _chat_openai(self, messages: List[Dict[str, str]]) -> Tuple[str, Dict[str, Any]]:
        if not self.cfg.openai_api_key:
            raise RuntimeError("OPENAI_API_KEY is not set")
        url = self.cfg.openai_base_url.rstrip("/") + "/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.cfg.openai_api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.cfg.openai_model,
            "messages": messages,
            "temperature": self.cfg.temperature,
        }
        timeout = httpx.Timeout(self.cfg.timeout_s)
        async with httpx.AsyncClient(timeout=timeout) as client:
            attempt = 0
            while True:
                attempt += 1
                try:
                    resp = await client.post(url, headers=headers, json=payload)
                    if resp.status_code >= 400:
                        raise RuntimeError(f"OpenAI HTTP {resp.status_code}")
                    data = resp.json()
                    text = data["choices"][0]["message"]["content"]
                    usage = data.get("usage") or {}
                    return text, usage
                except Exception:
                    if attempt > self.cfg.retries:
                        raise
                    await asyncio.sleep(self.cfg.backoff_s * attempt)

    async def _chat_anthropic(self, messages: List[Dict[str, str]]) -> Tuple[str, Dict[str, Any]]:
        if not self.cfg.anthropic_api_key:
            raise RuntimeError("ANTHROPIC_API_KEY is not set")
        # Разделяем system и user для Anthropic
        system = ""
        conv: List[Dict[str, str]] = []
        for m in messages:
            if m["role"] == "system":
                system += (m["content"] + "\n\n")
            else:
                conv.append({"role": m["role"], "content": m["content"]})

        url = self.cfg.anthropic_base_url.rstrip("/") + "/v1/messages"
        headers = {
            "x-api-key": self.cfg.anthropic_api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        payload = {
            "model": self.cfg.anthropic_model,
            "max_tokens": self.cfg.anthropic_max_tokens,
            "system": system.strip(),
            "messages": conv,
            "temperature": self.cfg.temperature,
        }
        timeout = httpx.Timeout(self.cfg.timeout_s)
        async with httpx.AsyncClient(timeout=timeout) as client:
            attempt = 0
            while True:
                attempt += 1
                try:
                    resp = await client.post(url, headers=headers, json=payload)
                    if resp.status_code >= 400:
                        raise RuntimeError(f"Anthropic HTTP {resp.status_code}")
                    data = resp.json()
                    # формат: {"content":[{"type":"text","text":"..."}], ...}
                    blocks = data.get("content") or []
                    text = ""
                    for b in blocks:
                        if isinstance(b, dict) and b.get("type") == "text":
                            text += b.get("text", "")
                    usage = data.get("usage") or {}
                    return text, usage
                except Exception:
                    if attempt > self.cfg.retries:
                        raise
                    await asyncio.sleep(self.cfg.backoff_s * attempt)


# -----------------------------------------------------------------------------
# Утилиты
# -----------------------------------------------------------------------------
def _truncate(s: Optional[str], limit: int) -> str:
    s = (s or "").strip()
    if len(s) > limit:
        return s[:limit]
    return s

def _safe_json_extract(s: str) -> List[Dict[str, Any]]:
    """
    Выделяет первый корректный JSON-массив из ответа.
    Допустимы обёртки и текст вокруг; если парсинг не удался — возбуждает ValueError.
    """
    # быстрый путь — попытка распарсить весь текст
    try:
        val = json.loads(s)
        if isinstance(val, list):
            return val
        if isinstance(val, dict) and "plan" in val and isinstance(val["plan"], list):
            return val["plan"]
    except Exception:
        pass

    # поиск первого массива по скобочкам
    start = s.find("[")
    while start != -1:
        depth = 0
        for i in range(start, len(s)):
            ch = s[i]
            if ch == "[":
                depth += 1
            elif ch == "]":
                depth -= 1
                if depth == 0:
                    chunk = s[start:i+1]
                    try:
                        val = json.loads(chunk)
                        if isinstance(val, list):
                            return val
                    except Exception:
                        break
        start = s.find("[", start + 1)
    raise ValueError("No JSON array found in LLM output")

def _validate_plan(plan: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Минимальная валидация структуры шага.
    """
    out = []
    for idx, step in enumerate(plan, start=1):
        if not isinstance(step, dict):
            raise ValueError("plan item must be object")
        sid = step.get("id") or f"step-{idx}"
        title = step.get("title") or "Untitled"
        depends_on = step.get("depends_on") or []
        estimate = step.get("estimate_minutes") or 0
        inputs = step.get("inputs") or {}
        outputs = step.get("outputs") or {}
        out.append({
            "id": str(sid),
            "title": str(title),
            "depends_on": list(depends_on),
            "estimate_minutes": int(estimate),
            "inputs": dict(inputs),
            "outputs": dict(outputs),
        })
    return out


# -----------------------------------------------------------------------------
# Воркер
# -----------------------------------------------------------------------------
class PlannerWorker:
    def __init__(self, planner_cfg: PlannerSettings, queue_cfg: RedisQueueSettings, llm_cfg: LLMSettings):
        self.pcfg = planner_cfg
        # Переопределяем stream/group/consumer из PlannerSettings
        self.qcfg = queue_cfg.copy(update={
            "stream": planner_cfg.in_stream,
            "group": planner_cfg.group,
            "consumer": planner_cfg.consumer,
        })
        self.lcfg = llm_cfg
        self._queue = RedisStreamQueue(self.qcfg)
        self._reg = get_default_registry()
        self._llm = LLMClient(self.lcfg)
        self._stop = asyncio.Event()

    async def run(self) -> None:
        worker = QueueWorker(self._queue, self._handle, concurrency=self.pcfg.concurrency)
        await worker.run()

    async def _handle(self, msg: "QueueMessage") -> bool:
        """
        Возврат True -> ACK, False -> DLQ. Исключение -> requeue (повторный опрос).
        """
        t0 = time.perf_counter()
        span = None
        if _OTEL:
            tracer = trace.get_tracer("omnimind.planner")  # type: ignore
            span = tracer.start_as_current_span("plan.handle", attributes={"msg_id": msg.id, "attempt": msg.attempt})  # type: ignore
            span.__enter__()  # type: ignore

        try:
            # Валидация payload
            try:
                task = PlanRequest(**msg.payload)
            except ValidationError as e:
                await self._emit_error(msg, code="bad_request", message="invalid payload", details=e.errors())
                PLAN_REQS.labels("bad_request").inc()
                return False  # DLQ

            # Идемпотентность по request_id
            processed = await self._mark_processed(task.request_id)
            if not processed:
                # Уже обработано ранее — ACK и пропуск
                PLAN_REQS.labels("duplicate").inc()
                return True

            # Промпт и LLM
            goal = _truncate(task.goal, self.pcfg.max_goal_len)
            constraints = _truncate(task.constraints, self.pcfg.max_goal_len)
            ctx = _truncate(task.context, self.pcfg.max_ctx_len)
            locale = (task.locale or self.pcfg.default_locale).lower()

            messages = build_chatml(
                self._reg,
                id=self.pcfg.prompt_id,
                version=self.pcfg.prompt_version,
                locale=locale,
                vars={
                    "goal": goal,
                    "constraints": constraints or "—",
                    "context": ctx or "—",
                },
            )

            text, usage = await self._llm.chat(messages)

            # Парсинг и валидация плана
            plan_raw = _safe_json_extract(text)
            plan = _validate_plan(plan_raw)

            # Ответ
            duration_ms = int(1000 * (time.perf_counter() - t0))
            out_stream = task.response_stream or self.pcfg.out_stream
            payload = {
                "type": "plan.response",
                "request_id": task.request_id,
                "ok": True,
                "plan": plan,
                "model": f"{self.lcfg.provider}/{self._model_name()}",
                "duration_ms": duration_ms,
                "usage": usage,
            }
            # Дедуп ключ ответа — тот же request_id
            await self._queue.enqueue(payload, message_key=task.request_id)
            PLAN_REQS.labels("ok").inc()
            PLAN_LAT.observe(time.perf_counter() - t0)
            return True

        except Exception as e:
            # Поведение: если попыток слишком много — DLQ, иначе requeue
            if msg.attempt >= self.pcfg.max_attempts_before_dlq:
                await self._emit_error(msg, code="internal", message=str(e))
                PLAN_REQS.labels("dlq").inc()
                return False  # DLQ
            PLAN_REQS.labels("retry").inc()
            raise  # requeue
        finally:
            if span:
                span.__exit__(None, None, None)  # type: ignore

    def _model_name(self) -> str:
        if self.lcfg.provider == "openai":
            return self.lcfg.openai_model
        if self.lcfg.provider == "anthropic":
            return self.lcfg.anthropic_model
        return "unknown"

    async def _mark_processed(self, request_id: str) -> bool:
        """
        Пометка идемпотентности. True — пометили впервые, False — уже было.
        """
        key = (self.pcfg.processed_prefix + request_id).encode("utf-8")
        try:
            # используем нативный клиент из очереди
            ok = await self._queue._r.set(key, b"1", ex=self.pcfg.processed_ttl_s, nx=True)  # type: ignore
            return bool(ok)
        except Exception:
            # при недоступности Redis обрабатываем как «не обработано» (риски дубликатов)
            return True

    async def _emit_error(self, msg: "QueueMessage", *, code: str, message: str, details: Any = None) -> None:
        """
        Публикация ответа с ошибкой в выходной стрим и ACK исходного сообщения (вызывается перед DLQ).
        """
        try:
            req_id = (msg.payload.get("request_id") if isinstance(msg.payload, dict) else None) or "n/a"
            out_stream = msg.payload.get("response_stream") if isinstance(msg.payload, dict) else None
            payload = {
                "type": "plan.response",
                "request_id": req_id,
                "ok": False,
                "error": {"code": code, "message": message, "details": details},
            }
            # используем ключ идемпотентности по request_id, если есть
            await self._queue.enqueue(payload, message_key=req_id if req_id != "n/a" else None)
        except Exception:
            # заглушка: ошибки публикации ответа не должны ронять воркер
            pass


# -----------------------------------------------------------------------------
# Bootstrap
# -----------------------------------------------------------------------------
def _configure_logging() -> None:
    level = os.getenv("LOG_LEVEL", "INFO").upper()
    logging.basicConfig(
        level=level if level in {"DEBUG", "INFO", "WARNING", "ERROR"} else "INFO",
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    )


async def main():
    _configure_logging()
    logger = logging.getLogger("omnimind.planner.main")

    # Настройки
    planner_cfg = PlannerSettings()
    queue_cfg = RedisQueueSettings(
        stream=planner_cfg.in_stream,
        group=planner_cfg.group,
        consumer=planner_cfg.consumer,
    )
    llm_cfg = LLMSettings()

    logger.info(
        "starting planner worker env=%s provider=%s in=%s group=%s",
        planner_cfg.app_env, llm_cfg.provider, planner_cfg.in_stream, planner_cfg.group,
    )

    worker = PlannerWorker(planner_cfg, queue_cfg, llm_cfg)

    # Корректное завершение по сигналам
    loop = asyncio.get_running_loop()
    stop_event = asyncio.Event()

    def _stop():
        logger.info("termination signal received")
        stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(NotImplementedError):
            loop.add_signal_handler(sig, _stop)  # type: ignore

    # Запуск
    runner = asyncio.create_task(worker.run())
    await stop_event.wait()
    runner.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await runner
    logger.info("planner worker stopped")


# Узкий fallback на отсутствие contextlib.suppress в окружении (защита импорта)
try:
    import contextlib  # noqa: E402
except Exception:  # pragma: no cover
    class contextlib:  # type: ignore
        class suppress:
            def __init__(self, *args, **kwargs): pass
            def __enter__(self): pass
            def __exit__(self, *a): return False

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
