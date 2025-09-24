# -*- coding: utf-8 -*-
"""
Mythos Core — Dialogue Precompute Worker (industrial)

Назначение:
    Фоновый воркер для предвычисления признаков диалогов:
      - компактные сводки (rolling summaries) по последним N ходам
      - эмбеддинги текстов ходов/окон контекста (батчами)
      - базовые метрики (оценка токенов/стоимости)
      - публикация событий в шину для последующей индексации/аналитики

Архитектура:
    - Порты/протоколы: Repository, EmbeddingService, Summarizer, TokenCounter, MessageBus, KVStore (идемпотентность)
    - Worker: асинхронный цикл fetch→process→store с ограничением конкурентности, бэк-оффом и graceful shutdown
    - Идемпотентность: fingerprint содержимого (контент ходов + версии моделей/правил) в KV с TTL
    - Конфиг: через ENV/CLI-параметры; значение по умолчанию безопасные

Зависимости: только стандартная библиотека Python 3.11+.
Внешние реализации (БД, эмбеддинги, суммаризация) подключаются через Protocol.

CLI:
    python -m mythos.workers.dialogue_precompute --help
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import dataclasses
import json
import logging
import os
import random
import signal
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import (
    Any,
    AsyncGenerator,
    Awaitable,
    Dict,
    Iterable,
    List,
    Mapping,
    MutableMapping,
    Optional,
    Protocol,
    Sequence,
    Tuple,
)

# -------------------------
# DTO / Domain
# -------------------------

@dataclass(frozen=True)
class Turn:
    id: str
    dialogue_id: str
    index: int
    role: str               # "user"|"assistant"|"tool"
    input_text: Optional[str] = None
    output_text: Optional[str] = None
    created_at: Optional[datetime] = None
    meta: Dict[str, Any] = field(default_factory=dict)

    def text_for_embedding(self) -> str:
        # Правило: для user берём input_text, для assistant — output_text, иначе обе
        if self.role == "user":
            return (self.input_text or "").strip()
        if self.role == "assistant":
            return (self.output_text or "").strip()
        a = (self.input_text or "").strip()
        b = (self.output_text or "").strip()
        return (a + ("\n" if a and b else "") + b).strip()


@dataclass(frozen=True)
class DialogueTask:
    dialogue_id: str
    pending_turn_ids: Tuple[str, ...]             # ходы, требующие пересчёта
    last_turns: Tuple[Turn, ...]                  # окно последних ходов (для сводки)
    policy_version: str                           # версионирование правил/схем
    embedding_space: str                          # имя пространства/модели эмбеддингов
    summary_window: int                           # размер окна в ходах
    requested_at: datetime


@dataclass(frozen=True)
class PrecomputeResult:
    dialogue_id: str
    summary_text: Optional[str]
    per_turn_embeddings: Dict[str, List[float]]   # turn_id -> vector
    window_embedding: Optional[List[float]]
    token_metrics: Dict[str, Any]                 # агрегаты по токенам/стоимости
    fingerprint: str                              # идемпотентный ключ контента
    computed_at: datetime = field(default_factory=lambda: datetime.now(tz=timezone.utc))


# -------------------------
# Ports / Protocols
# -------------------------

class Repository(Protocol):
    async def fetch_pending(self, *, limit: int, partition: Optional[int] = None, partitions: Optional[int] = None) -> List[DialogueTask]: ...
    async def load_turns(self, dialogue_id: str, *, since_turn_index: Optional[int] = None, limit: int = 1000) -> List[Turn]: ...
    async def upsert_precompute(self, result: PrecomputeResult) -> None: ...
    async def mark_done(self, dialogue_id: str, fingerprint: str) -> None: ...
    async def heartbeat(self) -> None: ...


class EmbeddingService(Protocol):
    async def embed_texts(self, *, texts: Sequence[str], space: str, batch_size: int = 32) -> List[List[float]]: ...


class Summarizer(Protocol):
    async def summarize(self, *, turns: Sequence[Turn], max_chars: int = 1200) -> str: ...


class TokenCounter(Protocol):
    def count_text(self, text: str) -> int: ...
    def price(self, *, input_tokens: int, output_tokens: int) -> float: ...


class MessageBus(Protocol):
    async def publish(self, topic: str, payload: Mapping[str, Any]) -> None: ...


class KVStore(Protocol):
    """Для идемпотентности и эпизодического кеша."""
    async def get(self, key: str) -> Optional[str]: ...
    async def set_if_absent(self, key: str, value: str, ttl_seconds: int) -> bool: ...
    async def set(self, key: str, value: str, ttl_seconds: int) -> None: ...


# -------------------------
# Defaults / Fallbacks
# -------------------------

class NaiveTokenCounter:
    def __init__(self, chars_per_token: float = 4.0, in_price_per_1k: float = 0.0005, out_price_per_1k: float = 0.0015) -> None:
        self._cpt = max(1e-6, float(chars_per_token))
        self._in = float(in_price_per_1k)
        self._out = float(out_price_per_1k)

    def count_text(self, text: str) -> int:
        return int((len(text) + self._cpt - 1) // self._cpt)

    def price(self, *, input_tokens: int, output_tokens: int) -> float:
        return (input_tokens * self._in + output_tokens * self._out) / 1000.0


class SimpleSummarizer:
    """Простой эвристический суммаризатор как безопасный фолбэк (обрезка+пульсация ключевых фраз)."""
    def __init__(self, max_chars: int = 1200) -> None:
        self._max = max_chars

    async def summarize(self, *, turns: Sequence[Turn], max_chars: int = 1200) -> str:
        buf: List[str] = []
        for t in turns:
            head = "U:" if t.role == "user" else "A:" if t.role == "assistant" else "T:"
            txt = t.text_for_embedding().replace("\n", " ").strip()
            if not txt:
                continue
            buf.append(f"{head} {txt}")
            if sum(len(x) for x in buf) > max_chars:
                break
        s = " | ".join(buf)
        return s[:max_chars]


class InMemoryKV(KVStore):
    def __init__(self) -> None:
        self._store: MutableMapping[str, Tuple[float, str]] = {}
        self._lock = asyncio.Lock()

    async def get(self, key: str) -> Optional[str]:
        async with self._lock:
            rec = self._store.get(key)
            if not rec:
                return None
            exp, val = rec
            if exp < time.monotonic():
                self._store.pop(key, None)
                return None
            return val

    async def set_if_absent(self, key: str, value: str, ttl_seconds: int) -> bool:
        async with self._lock:
            if key in self._store and self._store[key][0] >= time.monotonic():
                return False
            self._store[key] = (time.monotonic() + ttl_seconds, value)
            return True

    async def set(self, key: str, value: str, ttl_seconds: int) -> None:
        async with self._lock:
            self._store[key] = (time.monotonic() + ttl_seconds, value)


# -------------------------
# Utils
# -------------------------

def _sha256(obj: Any) -> str:
    import hashlib
    raw = json.dumps(obj, sort_keys=True, ensure_ascii=False, default=str).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _fingerprint(dialogue_id: str, turns: Sequence[Turn], policy_version: str, embedding_space: str) -> str:
    payload = {
        "d": dialogue_id,
        "p": policy_version,
        "e": embedding_space,
        "t": [
            {
                "id": t.id,
                "i": t.index,
                "r": t.role,
                "in": (t.input_text or "")[-2048:],     # ограничим вклад до последних символов
                "out": (t.output_text or "")[-2048:],
            }
            for t in turns
        ],
    }
    return _sha256(payload)


async def _bounded_gather(sem: asyncio.Semaphore, coros: Iterable[Awaitable[Any]]) -> List[Any]:
    async def wrap(coro: Awaitable[Any]) -> Any:
        async with sem:
            return await coro
    return await asyncio.gather(*(wrap(c) for c in coros))


def _setup_logging(level: str = "INFO") -> None:
    lvl = getattr(logging, level.upper(), logging.INFO)
    logging.basicConfig(
        level=lvl,
        format="%(asctime)s.%(msecs)03dZ %(levelname)s %(name)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )


# -------------------------
# Worker
# -------------------------

@dataclass
class WorkerConfig:
    concurrency: int = int(os.getenv("DF_WORKER_CONCURRENCY", "8"))
    batch_limit: int = int(os.getenv("DF_WORKER_BATCH_LIMIT", "64"))
    summary_window: int = int(os.getenv("DF_SUMMARY_WINDOW", "8"))
    summary_max_chars: int = int(os.getenv("DF_SUMMARY_MAX_CHARS", "1200"))
    embed_batch_size: int = int(os.getenv("DF_EMBED_BATCH", "32"))
    idle_sleep_s: float = float(os.getenv("DF_IDLE_SLEEP_S", "1.0"))
    backoff_max_s: float = float(os.getenv("DF_BACKOFF_MAX_S", "5.0"))
    idem_ttl_s: int = int(os.getenv("DF_IDEM_TTL_S", "3600"))
    partitions: Optional[int] = int(os.getenv("DF_PARTITIONS", "0")) or None
    partition: Optional[int] = int(os.getenv("DF_PARTITION", "0")) if os.getenv("DF_PARTITIONS") else None
    embedding_space: str = os.getenv("DF_EMBED_SPACE", "mythos-dialogue-v1")
    policy_version: str = os.getenv("DF_POLICY_VERSION", "v1")
    log_level: str = os.getenv("DF_LOG_LEVEL", "INFO")
    publish_topic: str = os.getenv("DF_PUBLISH_TOPIC", "dialogue.precomputed")


class DialoguePrecomputeWorker:
    def __init__(
        self,
        repo: Repository,
        embed: EmbeddingService,
        summarizer: Summarizer | None = None,
        tokens: TokenCounter | None = None,
        bus: MessageBus | None = None,
        kv: KVStore | None = None,
        cfg: WorkerConfig | None = None,
    ) -> None:
        self.repo = repo
        self.embed = embed
        self.summarizer = summarizer or SimpleSummarizer()
        self.tokens = tokens or NaiveTokenCounter()
        self.bus = bus
        self.kv = kv or InMemoryKV()
        self.cfg = cfg or WorkerConfig()
        self.log = logging.getLogger("mythos.worker.dialogue_precompute")
        _setup_logging(self.cfg.log_level)
        self._shutdown = asyncio.Event()

    # ---- lifecycle ----

    async def run(self) -> None:
        self.log.info("worker.start concurrency=%s batch=%s partitions=%s partition=%s",
                      self.cfg.concurrency, self.cfg.batch_limit, self.cfg.partitions, self.cfg.partition)
        loop = asyncio.get_running_loop()
        with contextlib.suppress(NotImplementedError):
            loop.add_signal_handler(signal.SIGINT, self._shutdown.set)
            loop.add_signal_handler(signal.SIGTERM, self._shutdown.set)

        backoff = 0.2
        sem = asyncio.Semaphore(self.cfg.concurrency)

        while not self._shutdown.is_set():
            try:
                await self.repo.heartbeat()
            except Exception as e:
                self.log.warning("heartbeat.error err=%s", type(e).__name__)

            tasks = await self.repo.fetch_pending(
                limit=self.cfg.batch_limit,
                partition=self.cfg.partition,
                partitions=self.cfg.partitions,
            )

            if not tasks:
                await asyncio.sleep(self.cfg.idle_sleep_s)
                continue

            started = time.monotonic()
            try:
                await _bounded_gather(sem, (self._process_task(t) for t in tasks))
                backoff = 0.2  # reset
            except Exception as e:
                self.log.exception("batch.process.error err=%s", type(e).__name__)
                backoff = min(self.cfg.backoff_max_s, backoff * 2.0 + random.uniform(0, 0.2))
                await asyncio.sleep(backoff)
            finally:
                self.log.info("batch.done n=%s elapsed_ms=%s", len(tasks), int((time.monotonic() - started) * 1000))

        self.log.info("worker.stop")

    async def stop(self) -> None:
        self._shutdown.set()

    # ---- task processing ----

    async def _process_task(self, task: DialogueTask) -> None:
        # Сбор исходных данных
        window_turns = list(task.last_turns)[-max(1, self.cfg.summary_window):]
        idem_key = self._idem_key(task.dialogue_id, window_turns, task.policy_version, task.embedding_space)

        # Идемпотентность
        taken = await self.kv.set_if_absent(idem_key, "1", ttl_seconds=self.cfg.idem_ttl_s)
        if not taken:
            self.log.debug("skip.idempotent dialogue_id=%s", task.dialogue_id)
            return

        # Суммаризация
        summary_text = await self.summarizer.summarize(turns=window_turns, max_chars=self.cfg.summary_max_chars)

        # Эмбеддинги по ходам
        per_turn: Dict[str, List[float]] = {}
        embed_inputs: List[Tuple[str, str]] = []  # (turn_id, text)
        for t in window_turns:
            txt = t.text_for_embedding()
            if not txt:
                continue
            embed_inputs.append((t.id, txt))

        vectors: List[List[float]] = []
        if embed_inputs:
            vectors = await self._embed_batched([txt for _, txt in embed_inputs], task.embedding_space)
            for (turn_id, _), vec in zip(embed_inputs, vectors):
                per_turn[turn_id] = vec

        # Эмбеддинг окна (конкат)
        window_text = "\n".join(t.text_for_embedding() for t in window_turns if t.text_for_embedding())
        window_embedding: Optional[List[float]] = None
        if window_text:
            emb = await self._embed_batched([window_text], task.embedding_space)
            window_embedding = emb[0]

        # Оценка токенов и стоимости
        total_in = sum(self.tokens.count_text(t.text_for_embedding()) for t in window_turns)
        token_metrics = {
            "input_tokens": total_in,
            "output_tokens": 0,
            "estimated_cost_usd": round(self.tokens.price(input_tokens=total_in, output_tokens=0), 6),
            "window_size": len(window_turns),
            "embedding_space": task.embedding_space,
        }

        fp = _fingerprint(task.dialogue_id, window_turns, task.policy_version, task.embedding_space)
        result = PrecomputeResult(
            dialogue_id=task.dialogue_id,
            summary_text=summary_text,
            per_turn_embeddings=per_turn,
            window_embedding=window_embedding,
            token_metrics=token_metrics,
            fingerprint=fp,
        )

        # Запись результатов и публикация
        await self.repo.upsert_precompute(result)
        await self.repo.mark_done(task.dialogue_id, fp)

        if self.bus:
            await self.bus.publish(
                topic=os.getenv("DF_PUBLISH_TOPIC", "dialogue.precomputed"),
                payload={
                    "dialogue_id": task.dialogue_id,
                    "fingerprint": fp,
                    "computed_at": result.computed_at.isoformat(),
                    "window_size": len(window_turns),
                },
            )
        self.log.debug("task.ok dialogue_id=%s window=%s embeds=%s", task.dialogue_id, len(window_turns), len(per_turn))

    async def _embed_batched(self, texts: Sequence[str], space: str) -> List[List[float]]:
        out: List[List[float]] = []
        bs = max(1, self.cfg.embed_batch_size)
        for i in range(0, len(texts), bs):
            chunk = texts[i : i + bs]
            vecs = await self.embed.embed_texts(texts=chunk, space=space, batch_size=bs)
            out.extend(vecs)
        return out

    @staticmethod
    def _idem_key(dialogue_id: str, turns: Sequence[Turn], policy_version: str, space: str) -> str:
        return "idem:" + _fingerprint(dialogue_id, turns, policy_version, space)


# -------------------------
# CLI wiring (example)
# -------------------------

class _NoopBus(MessageBus):
    async def publish(self, topic: str, payload: Mapping[str, Any]) -> None:
        logging.getLogger("mythos.worker.bus").debug("publish topic=%s payload=%s", topic, dict(payload))


class _EchoEmbed(EmbeddingService):
    """Безопасный фолбэк: псевдо-эмбеддинг (хэш→вектор фиксированной длины). Для продакшна подмените реализацией."""
    def __init__(self, dim: int = 64) -> None:
        self.dim = dim

    async def embed_texts(self, *, texts: Sequence[str], space: str, batch_size: int = 32) -> List[List[float]]:
        import hashlib
        out: List[List[float]] = []
        for t in texts:
            h = hashlib.sha256(t.encode("utf-8")).digest()
            # растянем до dim
            vec = [(h[i % len(h)] / 255.0) for i in range(self.dim)]
            out.append(vec)
        await asyncio.sleep(0)  # уступить цикл
        return out


class _DemoRepo(Repository):
    """Демонстрационный репозиторий (in-memory). Для реального использования реализуйте поверх БД."""
    def __init__(self) -> None:
        self._dialogues: Dict[str, List[Turn]] = {}
        self._pending: List[DialogueTask] = []
        self._store: Dict[str, Any] = {}
        self._log = logging.getLogger("mythos.worker.demo.repo")
        # заполним тестовые данные
        did = "dlg_1"
        turns = [
            Turn(id=f"{did}_t0", dialogue_id=did, index=0, role="user", input_text="Привет, кто ты?"),
            Turn(id=f"{did}_t1", dialogue_id=did, index=1, role="assistant", output_text="Я помощник Mythos."),
            Turn(id=f"{did}_t2", dialogue_id=did, index=2, role="user", input_text="Расскажи о Стражах Севера."),
            Turn(id=f"{did}_t3", dialogue_id=did, index=3, role="assistant", output_text="Стражи Севера охраняют рубеж."),
        ]
        self._dialogues[did] = turns
        self._pending.append(
            DialogueTask(
                dialogue_id=did,
                pending_turn_ids=tuple(t.id for t in turns),
                last_turns=tuple(turns),
                policy_version="v1",
                embedding_space="demo",
                summary_window=4,
                requested_at=datetime.now(tz=timezone.utc),
            )
        )

    async def fetch_pending(self, *, limit: int, partition: Optional[int] = None, partitions: Optional[int] = None) -> List[DialogueTask]:
        res = self._pending[:limit]
        self._pending = self._pending[limit:]
        return res

    async def load_turns(self, dialogue_id: str, *, since_turn_index: Optional[int] = None, limit: int = 1000) -> List[Turn]:
        return list(self._dialogues.get(dialogue_id, []))

    async def upsert_precompute(self, result: PrecomputeResult) -> None:
        self._store[result.dialogue_id] = dataclasses.asdict(result)
        self._log.info("precompute.upsert dialogue_id=%s fp=%s", result.dialogue_id, result.fingerprint[:8])

    async def mark_done(self, dialogue_id: str, fingerprint: str) -> None:
        self._log.info("precompute.done dialogue_id=%s fp=%s", dialogue_id, fingerprint[:8])

    async def heartbeat(self) -> None:
        return


async def _main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Mythos Core — Dialogue Precompute Worker")
    parser.add_argument("--concurrency", type=int, default=int(os.getenv("DF_WORKER_CONCURRENCY", "8")))
    parser.add_argument("--batch", type=int, default=int(os.getenv("DF_WORKER_BATCH_LIMIT", "64")))
    parser.add_argument("--log-level", type=str, default=os.getenv("DF_LOG_LEVEL", "INFO"))
    parser.add_argument("--demo", action="store_true", help="Run with in-memory demo repo/embed/bus")
    args = parser.parse_args(argv)

    _setup_logging(args.log_level)

    if args.demo:
        repo: Repository = _DemoRepo()
        embed: EmbeddingService = _EchoEmbed(dim=64)
        bus: MessageBus = _NoopBus()
        cfg = WorkerConfig(concurrency=args.concurrency, batch_limit=args.batch, log_level=args.log_level)
        worker = DialoguePrecomputeWorker(repo=repo, embed=embed, bus=bus, cfg=cfg)
        await worker.run()
        return 0

    # В боевом режиме здесь должен быть wiring ваших адаптеров:
    # repo = PgRepository(...)
    # embed = OpenAIEmbeddingService(...)
    # bus = KafkaBus(...)
    # summarizer = LLMOrHeuristicSummarizer(...)
    # tokens = VendorTokenCounter(...)
    # cfg = WorkerConfig(concurrency=args.concurrency, batch_limit=args.batch, log_level=args.log_level)
    # worker = DialoguePrecomputeWorker(repo=repo, embed=embed, bus=bus, summarizer=summarizer, tokens=tokens, cfg=cfg)
    # await worker.run()
    logging.getLogger("mythos.worker").error("No adapters wired. Use --demo or provide wiring.")
    return 2


if __name__ == "__main__":
    try:
        raise SystemExit(asyncio.run(_main()))
    except KeyboardInterrupt:
        raise SystemExit(130)
