# engine-core/engine/mocks/ai_mock.py
"""
AIMock — промышленный мок LLM/Embedding/Reranking сервиса.

Назначение:
- Интеграционные тесты без реальных LLM API.
- Нагрузочные испытания (latency/throughput), деградации и ретраи.
- Контрольный/детерминированный вывод (seed) для воспроизводимости.

Возможности:
- Профили моделей: контекстное окно, лимит токенов вывода, токены/сек, базовая латентность.
- Счётчик токенов (приближённый BPE-подобный), truncate стратегий: "head", "tail", "middle".
- Чат-комплишн: sync ответ и async стрим по токенам.
- Имитация tool_calls (по шаблонам или по ключевым словам).
- Эмбеддинги: стабильные по seed векторы, L2-нормализация по желанию.
- Реранк: скоринг по простому семантическому совпадению с noise.
- Rate limiting: token-bucket (RPS/TPM/TPH), burst.
- Chaos: вероятности ошибок, таймаутов, джиттер.
- Безопасность: простые контент-флаги (allow/deny), redaction.
- Наблюдаемость: Prometheus-метрики, OpenTelemetry спаны через ObservabilityAdapter (если доступен).

Зависимости:
- Нет обязательных. При наличии engine.adapters.observability_adapter получаем метрики/трейсинг, иначе no-op.

Пример:
    mock = AIMock()  # с настройками по умолчанию
    out = await mock.chat_complete(messages=[{"role":"user","content":"Hello"}])
    async for token in mock.chat_stream(messages=[...]):
        ...

SPDX-License-Identifier: Apache-2.0 OR MIT
"""

from __future__ import annotations

import asyncio
import math
import os
import random
import string
import time
from dataclasses import dataclass, field
from typing import Any, AsyncGenerator, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

# ------------------------ Наблюдаемость (опционально) -------------------

try:
    from engine.adapters.observability_adapter import get_observability
    _OBS = get_observability()
    _MET = True
except Exception:
    _OBS = None
    _MET = False

def _log(level: str, msg: str, **fields) -> None:
    if _OBS:
        getattr(_OBS, f"log_{level}")(msg, **fields)

def _trace(name: str):
    if _OBS:
        return _OBS.trace_span(name)
    def deco(fn): return fn
    return deco

def _metric_counter(name: str, doc: str, labels: Sequence[str] = ()):
    if _MET:
        return _OBS.counter(name, doc, labelnames=labels)  # type: ignore
    class _No:
        def labels(self, **_): return self
        def inc(self, *_a, **_k): ...
    return _No()

def _metric_hist(name: str, doc: str, labels: Sequence[str] = ()):
    if _MET:
        return _OBS.histogram(name, doc, labelnames=labels)  # type: ignore
    class _No:
        def labels(self, **_): return self
        def observe(self, *_a, **_k): ...
    return _No()

_MET_REQS = _metric_counter("aimock_requests_total", "Total AI mock requests", labels=("op","model","code"))
_MET_LAT  = _metric_hist("aimock_latency_seconds", "AI mock latency", labels=("op","model"))
_MET_TOKS = _metric_counter("aimock_tokens_total", "AI mock tokens", labels=("op","model","kind"))  # kind=in|out
_MET_RATE = _metric_counter("aimock_rate_limited_total", "AI mock rate limited", labels=("op","model"))

# ------------------------------ Конфиг ----------------------------------

@dataclass(frozen=True)
class AIMockModelProfile:
    name: str = "mock-3.5"
    context_window: int = 8192
    max_output_tokens: int = 1024
    base_latency_ms: float = 50.0
    tokens_per_second: float = 200.0

@dataclass(frozen=True)
class AIMockChaos:
    enabled: bool = False
    seed: Optional[int] = None
    error_rate: float = 0.0
    timeout_rate: float = 0.0
    max_extra_latency_ms: float = 200.0
    jitter_ms: float = 10.0

@dataclass(frozen=True)
class AIMockRateLimit:
    rps: float = 50.0         # запросов в секунду (token-bucket)
    burst: int = 100
    tpm: int = 100_000        # tokens per minute (input + output)
    tph: int = 2_000_000      # tokens per hour

@dataclass(frozen=True)
class AIMockSafety:
    allowlist: Tuple[str, ...] = ()
    denylist: Tuple[str, ...] = ("<script>", "DROP TABLE", "rm -rf",)
    redact_placeholders: bool = True  # заменить обнаруженные паттерны на ███

@dataclass
class AIMockConfig:
    profile: AIMockModelProfile = field(default_factory=AIMockModelProfile)
    chaos: AIMockChaos = field(default_factory=AIMockChaos)
    rate: AIMockRateLimit = field(default_factory=AIMockRateLimit)
    safety: AIMockSafety = field(default_factory=AIMockSafety)
    seed: Optional[int] = 1337
    normalize_embeddings: bool = True
    stream_chunk_tokens: int = 16
    truncate_strategy: str = "tail"  # head|tail|middle

# ---------------------------- Утилиты токенизации -----------------------

class _Tokenizer:
    """
    Приближённый токенайзер: разбивает по не-буквенно-цифровым и длина/4.
    Достаточно для тестов относительных лимитов.
    """
    def count(self, text: str) -> int:
        if not text:
            return 0
        # быстрый upper bound
        n = max(1, len(text) // 4)
        # бонус за пробелы/пунктуацию
        bonus = text.count(" ") // 2 + sum(text.count(ch) for ch in ".!,?:;") // 2
        return max(1, n - bonus)

    def split_tokens(self, text: str, chunk: int) -> List[str]:
        # Грубая нарезка по символам с шагом ~4*chunk
        if chunk <= 0:
            return [text]
        approx_chars = max(1, chunk * 4)
        return [text[i:i+approx_chars] for i in range(0, len(text), approx_chars)]

_TOKENIZER = _Tokenizer()

# -------------------------- Ограничение скорости ------------------------

class _TokenBucket:
    def __init__(self, rate_per_sec: float, burst: int):
        self.rate = rate_per_sec
        self.capacity = burst
        self.tokens = burst
        self.last = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self, cost: float = 1.0) -> bool:
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self.last
            self.last = now
            self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
            if self.tokens >= cost:
                self.tokens -= cost
                return True
            return False

# ------------------------------ AIMock ----------------------------------

class AIMock:
    """
    Высокоточый мок ИИ‑сервиса с чат‑ответами, стримингом, эмбеддингами и реранком.
    """

    def __init__(self, cfg: AIMockConfig | None = None) -> None:
        self.cfg = cfg or AIMockConfig()
        self._rng = random.Random(self.cfg.seed)
        self._bucket_rps = _TokenBucket(self.cfg.rate.rps, self.cfg.rate.burst)
        self._tpm_window: List[Tuple[float, int]] = []  # (ts, tokens)
        self._tph_window: List[Tuple[float, int]] = []
        _log("info", "AIMock initialized",
             model=self.cfg.profile.name,
             ctx=self.cfg.profile.context_window,
             tps=self.cfg.profile.tokens_per_second)

    # ----------------------------- Вспомогательные ----------------------

    def _rng_local(self) -> random.Random:
        return random.Random(self.cfg.seed)

    def _count_tokens_messages(self, messages: Sequence[Mapping[str, Any]]) -> int:
        tot = 0
        for m in messages:
            tot += _TOKENIZER.count(str(m.get("content", "")))
            tot += _TOKENIZER.count(str(m.get("name", "")))
            tot += 3  # роль/разметка
        return tot

    def _truncate_messages(self, messages: Sequence[Mapping[str, Any]], budget: int) -> List[Mapping[str, Any]]:
        if budget <= 0:
            return []
        toks = [(_TOKENIZER.count(str(m.get("content",""))) + 3) for m in messages]
        total = sum(toks)
        if total <= budget:
            return list(messages)

        if self.cfg.truncate_strategy == "head":
            # Сохраняем начало
            out = []
            acc = 0
            for m, t in zip(messages, toks):
                if acc + t > budget:
                    break
                out.append(m)
                acc += t
            return out

        if self.cfg.truncate_strategy == "middle":
            # Оставляем голову и хвост, выкидываем середину
            half = budget // 2
            head, tail = [], []
            acc = 0
            for m, t in zip(messages, toks):
                if acc + t <= half:
                    head.append(m); acc += t
                else:
                    break
            acc2 = 0
            for m, t in zip(reversed(messages), reversed(toks)):
                if acc2 + t <= (budget - acc):
                    tail.append(m); acc2 += t
                else:
                    break
            tail.reverse()
            return head + [{"role":"system","content":"[...truncated...]"}] + tail

        # tail (по умолчанию): сохраняем конец (актуальный контекст)
        out = []
        acc = 0
        for m, t in zip(reversed(messages), reversed(toks)):
            if acc + t > budget:
                break
            out.append(m)
            acc += t
        out.reverse()
        return out

    async def _sleep_for_tokens(self, tokens: int) -> None:
        # Эмуляция скорости вывода
        tps = max(1.0, self.cfg.profile.tokens_per_second)
        await asyncio.sleep(tokens / tps)

    def _apply_safety(self, text: str) -> Tuple[bool, str]:
        s = self.cfg.safety
        if s.allowlist:
            allowed = any(a.lower() in text.lower() for a in s.allowlist)
            if not allowed:
                return False, "[blocked: allowlist]"
        for d in s.denylist:
            if d.lower() in text.lower():
                if s.redact_placeholders:
                    text = text.replace(d, "█" * len(d))
                else:
                    return False, "[blocked: denylist]"
        return True, text

    def _maybe_chaos(self) -> Tuple[bool, Optional[str], float]:
        c = self.cfg.chaos
        if not c.enabled:
            return False, None, 0.0
        rng = random.Random(c.seed)
        # jitter
        extra = rng.random() * c.max_extra_latency_ms + (rng.random()*2-1)*c.jitter_ms
        # error/timeout
        r = rng.random()
        if r < c.error_rate:
            return True, "error", extra
        if r < c.error_rate + c.timeout_rate:
            return True, "timeout", extra
        return False, None, extra

    def _update_token_windows(self, tokens: int) -> None:
        now = time.monotonic()
        self._tpm_window.append((now, tokens))
        self._tph_window.append((now, tokens))
        # очистка окон
        self._tpm_window = [(t, n) for (t, n) in self._tpm_window if now - t <= 60.0]
        self._tph_window = [(t, n) for (t, n) in self._tph_window if now - t <= 3600.0]

    def _check_rate_limits(self, op: str, model: str, in_tokens: int, out_tokens: int = 0) -> None:
        # RPS
        ok = True
        if not asyncio.get_event_loop().is_closed():
            # token-bucket на 1 запрос
            ok = asyncio.get_event_loop().run_until_complete(self._bucket_rps.acquire(1.0)) \
                if not asyncio.get_event_loop().is_running() else True
        if not ok:
            _MET_RATE.labels(op=op, model=model).inc()
            raise RuntimeError("rate_limited: rps")

        # TPM/TPH
        total = in_tokens + out_tokens
        self._update_token_windows(total)
        if sum(n for _, n in self._tpm_window) > self.cfg.rate.tpm:
            _MET_RATE.labels(op=op, model=model).inc()
            raise RuntimeError("rate_limited: tpm")
        if sum(n for _, n in self._tph_window) > self.cfg.rate.tph:
            _MET_RATE.labels(op=op, model=model).inc()
            raise RuntimeError("rate_limited: tph")

    # ------------------------------ Публичный API ------------------------

    @_trace("aimock.chat_complete")
    async def chat_complete(
        self,
        messages: Sequence[Mapping[str, Any]],
        tools: Optional[Sequence[Mapping[str, Any]]] = None,
        temperature: float = 0.2,
        max_tokens: Optional[int] = None,
        model: Optional[str] = None,
        system_prompt: Optional[str] = None,
        tool_choice: Optional[str] = None,
        seed: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Имитация chat completion (один ответ).
        """
        t0 = time.perf_counter()
        prof = self.cfg.profile
        model = model or prof.name
        rng = random.Random(seed if seed is not None else self.cfg.seed)

        # Контекст и усечение
        msgs = list(messages)
        if system_prompt:
            msgs = [{"role":"system","content":system_prompt}] + msgs
        in_tokens = self._count_tokens_messages(msgs)
        budget = max(0, prof.context_window - (max_tokens or prof.max_output_tokens))
        msgs = self._truncate_messages(msgs, budget)
        in_tokens_after = self._count_tokens_messages(msgs)

        # Chaos
        ch, kind, extra = self._maybe_chaos()
        await asyncio.sleep((prof.base_latency_ms + max(0.0, extra)) / 1000.0)

        # Rate limits
        self._check_rate_limits("chat", model, in_tokens_after)

        # Генерация ответа
        user_txt = ""
        for m in reversed(msgs):
            if m.get("role") in ("user","tool","system","assistant"):
                user_txt = str(m.get("content",""))
                if user_txt:
                    break

        # tool-calls: простая эвристика
        tool_calls = []
        if tools and tool_choice != "none":
            for tool in tools:
                name = tool.get("name","")
                if name and name.lower() in user_txt.lower():
                    args = {"query": user_txt[:128]}
                    tool_calls.append({"id": f"call_{rng.randint(1000,9999)}", "type":"function",
                                       "function":{"name":name,"arguments":args}})
                    break

        # Текст: псевдо-детерминированный шаблон
        base = f"[{model}] Reply: " + user_txt[::-1][:256]
        temp_noise = "" if temperature <= 0 else "".join(
            rng.choice(string.ascii_lowercase + "     ") for _ in range(min(64, int(temperature*64)))
        )
        out_text = (base + " " + temp_noise).strip()

        ok, out_text = self._apply_safety(out_text)
        if not ok:
            out_text = out_text  # уже редактировано

        out_tokens = min(max_tokens or prof.max_output_tokens, max(1, _TOKENIZER.count(out_text)))
        # Ограничиваем скорость
        await self._sleep_for_tokens(out_tokens)

        # Chaos error/timeout после вычислений
        if ch and kind == "error":
            _MET_REQS.labels(op="chat", model=model, code="error").inc()
            raise RuntimeError("chaos: simulated error")
        if ch and kind == "timeout":
            _MET_REQS.labels(op="chat", model=model, code="timeout").inc()
            raise asyncio.TimeoutError("chaos: simulated timeout")

        # Метрики
        _MET_REQS.labels(op="chat", model=model, code="ok").inc()
        _MET_LAT.labels(op="chat", model=model).observe(max(0.0, time.perf_counter() - t0))
        _MET_TOKS.labels(op="chat", model=model, kind="in").inc(in_tokens_after)
        _MET_TOKS.labels(op="chat", model=model, kind="out").inc(out_tokens)

        return {
            "model": model,
            "usage": {"prompt_tokens": in_tokens_after, "completion_tokens": out_tokens, "total_tokens": in_tokens_after+out_tokens},
            "choices": [{
                "index": 0,
                "finish_reason": "stop",
                "message": {
                    "role": "assistant",
                    "content": out_text,
                    "tool_calls": tool_calls or None,
                },
            }],
        }

    @_trace("aimock.chat_stream")
    async def chat_stream(
        self,
        messages: Sequence[Mapping[str, Any]],
        **kw,
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """
        Имитация потокового вывода токенов (делта‑чанки).
        """
        resp = await self.chat_complete(messages, **kw)
        text = resp["choices"][0]["message"]["content"] or ""
        model = resp["model"]
        chunks = _TOKENIZER.split_tokens(text, max(1, self.cfg.stream_chunk_tokens))
        # предварительный заголовок
        yield {"model": model, "delta": "", "index": 0}
        for part in chunks:
            await self._sleep_for_tokens(max(1, _TOKENIZER.count(part)))
            yield {"model": model, "delta": part, "index": 0}
        yield {"model": model, "delta": None, "finish_reason": "stop", "index": 0}

    @_trace("aimock.embed")
    async def embed(self, inputs: Sequence[str], model: Optional[str] = None) -> Dict[str, Any]:
        """
        Имитация эмбеддингов: стабильные по seed векторы (dimension=384).
        """
        t0 = time.perf_counter()
        model = model or "mock-embed-1"
        dim = 384
        out: List[List[float]] = []
        in_tok = 0
        for text in inputs:
            in_tok += _TOKENIZER.count(text)
            rng = random.Random((self.cfg.seed or 0) ^ hash(text) ^ hash(model))
            vec = [rng.uniform(-1.0, 1.0) for _ in range(dim)]
            if self.cfg.normalize_embeddings:
                norm = math.sqrt(sum(v*v for v in vec)) or 1.0
                vec = [v / norm for v in vec]
            out.append(vec)

        # rate limits
        self._check_rate_limits("embed", model, in_tok)
        await asyncio.sleep(0.001 * len(inputs))  # минимальная имитация задержки

        _MET_REQS.labels(op="embed", model=model, code="ok").inc()
        _MET_LAT.labels(op="embed", model=model).observe(max(0.0, time.perf_counter() - t0))
        _MET_TOKS.labels(op="embed", model=model, kind="in").inc(in_tok)
        return {"model": model, "data": [{"index": i, "embedding": out[i]} for i in range(len(inputs))]}

    @_trace("aimock.rerank")
    async def rerank(self, query: str, documents: Sequence[str], top_k: Optional[int] = None, model: Optional[str] = None) -> Dict[str, Any]:
        """
        Имитация реранка: грубое семантическое совпадение + шум.
        """
        t0 = time.perf_counter()
        model = model or "mock-rerank-1"
        rng = random.Random((self.cfg.seed or 0) ^ hash(query) ^ 0x9E3779B97F4A7C15)
        q_tokens = set(query.lower().split())
        scored = []
        in_tok = _TOKENIZER.count(query) + sum(_TOKENIZER.count(d) for d in documents)
        for i, doc in enumerate(documents):
            overlap = len(q_tokens & set(doc.lower().split()))
            score = overlap + rng.random() * 0.1
            scored.append((i, score))
        scored.sort(key=lambda x: x[1], reverse=True)
        k = min(len(scored), top_k or len(scored))
        self._check_rate_limits("rerank", model, in_tok)
        await asyncio.sleep(0.001 * len(documents))

        _MET_REQS.labels(op="rerank", model=model, code="ok").inc()
        _MET_LAT.labels(op="rerank", model=model).observe(max(0.0, time.perf_counter() - t0))
        _MET_TOKS.labels(op="rerank", model=model, kind="in").inc(in_tok)
        return {
            "model": model,
            "results": [{"index": i, "relevance": float(s)} for (i, s) in scored[:k]]
        }

    # Утилиты
    def count_tokens(self, text: str) -> int:
        return _TOKENIZER.count(text)

    def count_messages_tokens(self, messages: Sequence[Mapping[str, Any]]) -> int:
        return self._count_tokens_messages(messages)

# ------------------------------ Пример (комментарии) --------------------
# async def _demo():
#     mock = AIMock()
#     resp = await mock.chat_complete([{"role":"user","content":"Привет, дай план"}])
#     print(resp["choices"][0]["message"]["content"])
#     async for ch in mock.chat_stream([{"role":"user","content":"Стриминг тест"}], temperature=0.5):
#         print(ch, end="")
