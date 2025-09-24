# omnimind-core/omnimind/tools/../adapters/llm/local_ggml_adapter.py
from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import logging
import os
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, Generator, Iterable, List, Literal, Optional, Tuple, Union

# Опциональная pydantic-конфигурация (строгая валидация, но не обязательная зависимость)
try:
    from pydantic import BaseModel, Field, validator  # type: ignore
except Exception:  # pragma: no cover
    BaseModel = object  # type: ignore
    Field = lambda *args, **kwargs: None  # type: ignore
    def validator(*args, **kwargs):  # type: ignore
        def _wrap(fn):
            return fn
        return _wrap

LOG = logging.getLogger("omnimind.adapters.local_ggml")
if not LOG.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    LOG.addHandler(_h)
LOG.setLevel(logging.INFO)


# -------------------------
# Ошибки адаптера
# -------------------------
class GGMLAdapterError(Exception):
    pass


class GGMLNotInstalledError(GGMLAdapterError):
    pass


class GGMLModelNotLoadedError(GGMLAdapterError):
    pass


class GGMLTimeoutError(GGMLAdapterError):
    pass


class GGMLCapacityError(GGMLAdapterError):
    pass


# -------------------------
# Конфигурация
# -------------------------
@dataclass(slots=True)
class SamplingParams:
    max_tokens: int = 512
    temperature: float = 0.7
    top_p: float = 0.95
    top_k: int = 40
    min_p: float = 0.0
    typical_p: float = 1.0
    tfs_z: float = 1.0
    repeat_penalty: float = 1.1
    presence_penalty: float = 0.0
    frequency_penalty: float = 0.0
    mirostat: int = 0
    mirostat_tau: float = 5.0
    mirostat_eta: float = 0.1
    seed: int = -1  # -1 = random


@dataclass(slots=True)
class LocalGGMLConfig:
    model_path: str
    n_ctx: int = 8192
    n_threads: Optional[int] = None
    n_batch: int = 512
    n_gpu_layers: int = 0
    rope_freq_base: float = 0.0  # 0 = по умолчанию
    rope_freq_scale: float = 0.0
    use_mlock: bool = False
    use_mmap: bool = True
    low_vram: bool = False
    chat_format: Optional[str] = None  # например, "llama-2", "llama-3"
    # Ограничения/безопасность
    stop: Tuple[str, ...] = field(default_factory=tuple)
    max_input_chars: int = 300_000
    # Порог контекста: стратегия "truncate_left" | "error"
    overflow_strategy: Literal["truncate_left", "error"] = "truncate_left"
    # Лимиты времени и параллелизма
    default_timeout_s: Optional[float] = 120.0
    max_concurrent_calls: int = 1  # llama.cpp состояние непросто параллелить; по умолчанию 1
    # Эмбеддинги
    embeddings: bool = True


# Pydantic-обертка (если доступна) — полезно для внешних конфигов
class LocalGGMLSettings(BaseModel):  # type: ignore[misc]
    model_path: str
    n_ctx: int = 8192
    n_threads: Optional[int] = None
    n_batch: int = 512
    n_gpu_layers: int = 0
    rope_freq_base: float = 0.0
    rope_freq_scale: float = 0.0
    use_mlock: bool = False
    use_mmap: bool = True
    low_vram: bool = False
    chat_format: Optional[str] = None
    stop: List[str] = []
    max_input_chars: int = 300000
    overflow_strategy: Literal["truncate_left", "error"] = "truncate_left"
    default_timeout_s: Optional[float] = 120.0
    max_concurrent_calls: int = 1
    embeddings: bool = True

    @validator("model_path")
    def _must_exist(cls, v: str):  # type: ignore[override]
        if not v or not isinstance(v, str):
            raise ValueError("model_path must be a non-empty string")
        return v

    def to_dataclass(self) -> LocalGGMLConfig:
        return LocalGGMLConfig(
            model_path=self.model_path,
            n_ctx=self.n_ctx,
            n_threads=self.n_threads,
            n_batch=self.n_batch,
            n_gpu_layers=self.n_gpu_layers,
            rope_freq_base=self.rope_freq_base,
            rope_freq_scale=self.rope_freq_scale,
            use_mlock=self.use_mlock,
            use_mmap=self.use_mmap,
            low_vram=self.low_vram,
            chat_format=self.chat_format,
            stop=tuple(self.stop),
            max_input_chars=self.max_input_chars,
            overflow_strategy=self.overflow_strategy,
            default_timeout_s=self.default_timeout_s,
            max_concurrent_calls=self.max_concurrent_calls,
            embeddings=self.embeddings,
        )


# -------------------------
# Метрики
# -------------------------
@dataclass(slots=True)
class AdapterStats:
    loaded: bool = False
    model_path: Optional[str] = None
    t_loaded: Optional[float] = None
    calls_total: int = 0
    tokens_prompt_total: int = 0
    tokens_gen_total: int = 0
    last_latency_ms: float = 0.0
    errors_total: int = 0

    def snapshot(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


# -------------------------
# Адаптер
# -------------------------
class LocalGGMLAdapter:
    """
    Промышленная обертка над llama-cpp-python (ggml/gguf).
    Потокобезопасна за счет глобального lock и семафора параллелизма.
    """

    def __init__(self, cfg: Union[LocalGGMLConfig, LocalGGMLSettings]):
        if isinstance(cfg, LocalGGMLSettings):
            cfg = cfg.to_dataclass()
        self.cfg = cfg
        self._llama = None  # type: ignore
        self._lock = threading.RLock()
        self._sema = asyncio.Semaphore(self.cfg.max_concurrent_calls)
        self._stats = AdapterStats()
        self._loaded_event = threading.Event()

    # ------------- Жизненный цикл -------------
    def load(self) -> None:
        """
        Синхронная загрузка модели. Безопасна к многократным вызовам.
        """
        with self._lock:
            if self._llama is not None:
                return
            try:
                from llama_cpp import Llama  # type: ignore
            except Exception as e:
                raise GGMLNotInstalledError(
                    "llama-cpp-python is not installed. Please install `pip install llama-cpp-python`"
                ) from e

            init_kwargs: Dict[str, Any] = dict(
                model_path=self.cfg.model_path,
                n_ctx=self.cfg.n_ctx,
                n_threads=self.cfg.n_threads or os.cpu_count() or 4,
                n_batch=self.cfg.n_batch,
                n_gpu_layers=self.cfg.n_gpu_layers,
                use_mlock=self.cfg.use_mlock,
                use_mmap=self.cfg.use_mmap,
                low_vram=self.cfg.low_vram,
                logits_all=False,
                vocab_only=False,
            )
            if self.cfg.rope_freq_base:
                init_kwargs["rope_freq_base"] = self.cfg.rope_freq_base
            if self.cfg.rope_freq_scale:
                init_kwargs["rope_freq_scale"] = self.cfg.rope_freq_scale
            if self.cfg.chat_format:
                init_kwargs["chat_format"] = self.cfg.chat_format

            t0 = time.perf_counter()
            self._llama = Llama(**init_kwargs)
            self._stats.loaded = True
            self._stats.model_path = self.cfg.model_path
            self._stats.t_loaded = time.time()
            self._loaded_event.set()
            LOG.info("Loaded ggml model: %s (ctx=%d, gpu_layers=%d) in %.2fs",
                     self.cfg.model_path, self.cfg.n_ctx, self.cfg.n_gpu_layers, time.perf_counter() - t0)

    def unload(self) -> None:
        with self._lock:
            self._llama = None
            self._stats.loaded = False
            self._loaded_event.clear()
            LOG.info("Unloaded ggml model")

    def health(self) -> Dict[str, Any]:
        ok = self._llama is not None
        return {
            "ok": ok,
            "loaded": self._stats.loaded,
            "model_path": self._stats.model_path,
            "since": self._stats.t_loaded,
            "stats": self._stats.snapshot(),
        }

    # ------------- Внутренняя утилита -------------
    def _ensure_loaded(self) -> None:
        if self._llama is None:
            raise GGMLModelNotLoadedError("Model is not loaded. Call .load() first.")

    def _truncate_if_needed(self, text: str) -> str:
        if len(text) <= self.cfg.max_input_chars:
            return text
        if self.cfg.overflow_strategy == "truncate_left":
            cut = len(text) - self.cfg.max_input_chars
            LOG.warning("Input truncated by %d chars due to max_input_chars=%d", cut, self.cfg.max_input_chars)
            return text[cut:]
        raise GGMLAdapterError("Input exceeds max_input_chars and overflow_strategy=error")

    # ------------- Токенизация -------------
    def tokenize(self, text: str, add_bos: bool = True) -> List[int]:
        self._ensure_loaded()
        text = self._truncate_if_needed(text)
        with self._lock:
            return self._llama.tokenize(text.encode("utf-8"), add_bos=add_bos)  # type: ignore

    def detokenize(self, tokens: Iterable[int]) -> str:
        self._ensure_loaded()
        with self._lock:
            return self._llama.detokenize(list(tokens)).decode("utf-8", errors="ignore")  # type: ignore

    # ------------- Эмбеддинги -------------
    def embed(self, texts: List[str]) -> List[List[float]]:
        """
        Возвращает эмбеддинги для списка текстов, если модель поддерживает.
        """
        if not self.cfg.embeddings:
            raise GGMLAdapterError("Embeddings disabled by config")
        self._ensure_loaded()
        clean = [self._truncate_if_needed(t) for t in texts]
        with self._lock:
            try:
                res = self._llama.create_embedding(input=clean)  # type: ignore
            except AttributeError as e:  # старые версии
                raise GGMLAdapterError("This llama-cpp-python build does not support embeddings") from e
        # Приводим к List[List[float]]
        data = res.get("data") or []
        return [row["embedding"] for row in data]

    # ------------- Генерация (completion) -------------
    def generate(
        self,
        prompt: str,
        sampling: Optional[SamplingParams] = None,
        *,
        stream: bool = False,
        timeout_s: Optional[float] = None,
        stop: Optional[Tuple[str, ...]] = None,
        logprobs: Optional[int] = None,
    ) -> Union[str, Generator[str, None, Dict[str, Any]]]:
        """
        Синхронная генерация. Если stream=True — возвращает генератор токенов и итоговую метаинформацию в .close().
        """
        self._ensure_loaded()
        sampling = sampling or SamplingParams()
        timeout = timeout_s if timeout_s is not None else self.cfg.default_timeout_s
        stop_ = list(stop or self.cfg.stop)

        prompt = self._truncate_if_needed(prompt)
        # простая защита от параллелизма
        if not self._sema.locked() and self.cfg.max_concurrent_calls < 1:
            raise GGMLCapacityError("max_concurrent_calls must be >= 1")

        def _call() -> Any:
            with self._lock:
                return self._llama.create_completion(  # type: ignore
                    prompt=prompt,
                    max_tokens=sampling.max_tokens,
                    temperature=sampling.temperature,
                    top_p=sampling.top_p,
                    top_k=sampling.top_k,
                    min_p=sampling.min_p,
                    typical_p=sampling.typical_p,
                    tfs_z=sampling.tfs_z,
                    repeat_penalty=sampling.repeat_penalty,
                    presence_penalty=sampling.presence_penalty,
                    frequency_penalty=sampling.frequency_penalty,
                    mirostat_mode=sampling.mirostat,
                    mirostat_tau=sampling.mirostat_tau,
                    mirostat_eta=sampling.mirostat_eta,
                    seed=sampling.seed,
                    stop=stop_,
                    stream=stream,
                    logprobs=logprobs,
                )

        @contextlib.contextmanager
        def _deadline_ctx():
            t0 = time.perf_counter()
            try:
                yield t0
            finally:
                self._stats.last_latency_ms = (time.perf_counter() - t0) * 1000.0

        if stream:
            # Генератор, который отдает куски текста
            def _gen() -> Generator[str, None, Dict[str, Any]]:
                nonlocal prompt
                meta: Dict[str, Any] = {}
                with self._sema:
                    with _deadline_ctx() as t0:
                        try:
                            it = _call()
                            text_accum = []
                            for part in it:
                                # структура: {"choices":[{"text": "..."}], "model": "...", ...}
                                chunk = (part.get("choices") or [{}])[0].get("text") or ""
                                if chunk:
                                    text_accum.append(chunk)
                                    yield chunk
                            full_text = "".join(text_accum)
                            meta = {
                                "model": part.get("model") if "part" in locals() else None,
                                "tokens_prompt": len(self.tokenize(prompt)),
                                "tokens_gen": len(self.tokenize(full_text, add_bos=False)),
                                "latency_ms": (time.perf_counter() - t0) * 1000.0,
                            }
                            self._stats.calls_total += 1
                            self._stats.tokens_prompt_total += meta["tokens_prompt"]
                            self._stats.tokens_gen_total += meta["tokens_gen"]
                        except Exception as e:
                            self._stats.errors_total += 1
                            LOG.error("generate(stream) failed: %s", e)
                            raise
                return meta

            return _gen()
        else:
            # Вызов с таймаутом
            with self._sema:
                with _deadline_ctx():
                    try:
                        if timeout and timeout > 0:
                            res = _run_with_timeout(_call, timeout)
                        else:
                            res = _call()
                    except TimeoutError as e:
                        self._stats.errors_total += 1
                        raise GGMLTimeoutError("generation timeout") from e

            # {"choices":[{"text": "..."}], "usage": {...}, ...}
            text = (res.get("choices") or [{}])[0].get("text") or ""
            try:
                usage = res.get("usage") or {}
                self._stats.calls_total += 1
                self._stats.tokens_prompt_total += int(usage.get("prompt_tokens") or 0)
                self._stats.tokens_gen_total += int(usage.get("completion_tokens") or 0)
            except Exception:
                pass
            return text

    # ------------- Чат -------------
    def chat(
        self,
        messages: List[Dict[str, str]],
        sampling: Optional[SamplingParams] = None,
        *,
        stream: bool = False,
        timeout_s: Optional[float] = None,
        stop: Optional[Tuple[str, ...]] = None,
    ) -> Union[str, Generator[str, None, Dict[str, Any]]]:
        """
        Формат messages: [{"role":"system|user|assistant", "content":"..."}]
        """
        self._ensure_loaded()
        sampling = sampling or SamplingParams()
        timeout = timeout_s if timeout_s is not None else self.cfg.default_timeout_s
        stop_ = list(stop or self.cfg.stop)

        # trim по суммарным символам
        total = sum(len(m.get("content", "")) for m in messages)
        if total > self.cfg.max_input_chars:
            if self.cfg.overflow_strategy == "truncate_left":
                # отсекаем самые ранние сообщения (кроме последнего system)
                cut_chars = total - self.cfg.max_input_chars
                trimmed: List[Dict[str, str]] = []
                acc = 0
                # оставим последний system, если он является первым
                last_system = next((i for i, m in enumerate(reversed(messages)) if m.get("role") == "system"), None)
                for m in reversed(messages):
                    c = len(m.get("content", ""))
                    if acc + c <= self.cfg.max_input_chars:
                        trimmed.append(m)
                        acc += c
                    else:
                        # частичное усечение по содержимому
                        remain = max(0, self.cfg.max_input_chars - acc)
                        if remain > 0:
                            trimmed.append({"role": m.get("role", "user"), "content": m.get("content", "")[-remain:]})
                            acc = self.cfg.max_input_chars
                        break
                messages = list(reversed(trimmed))
                LOG.warning("Chat context truncated to %d chars", self.cfg.max_input_chars)
            else:
                raise GGMLAdapterError("Chat input exceeds max_input_chars and overflow_strategy=error")

        def _call() -> Any:
            with self._lock:
                # если chat_format задан — используем create_chat_completion
                if getattr(self._llama, "create_chat_completion", None) and self.cfg.chat_format:
                    return self._llama.create_chat_completion(  # type: ignore
                        messages=messages,
                        max_tokens=sampling.max_tokens,
                        temperature=sampling.temperature,
                        top_p=sampling.top_p,
                        top_k=sampling.top_k,
                        min_p=sampling.min_p,
                        typical_p=sampling.typical_p,
                        tfs_z=sampling.tfs_z,
                        repeat_penalty=sampling.repeat_penalty,
                        presence_penalty=sampling.presence_penalty,
                        frequency_penalty=sampling.frequency_penalty,
                        mirostat_mode=sampling.mirostat,
                        mirostat_tau=sampling.mirostat_tau,
                        mirostat_eta=sampling.mirostat_eta,
                        seed=sampling.seed,
                        stop=stop_,
                        stream=stream,
                    )
                # иначе — вручную склеиваем
                prompt = _messages_to_prompt(messages)
                return self._llama.create_completion(  # type: ignore
                    prompt=prompt,
                    max_tokens=sampling.max_tokens,
                    temperature=sampling.temperature,
                    top_p=sampling.top_p,
                    top_k=sampling.top_k,
                    min_p=sampling.min_p,
                    typical_p=sampling.typical_p,
                    tfs_z=sampling.tfs_z,
                    repeat_penalty=sampling.repeat_penalty,
                    presence_penalty=sampling.presence_penalty,
                    frequency_penalty=sampling.frequency_penalty,
                    mirostat_mode=sampling.mirostat,
                    mirostat_tau=sampling.mirostat_tau,
                    mirostat_eta=sampling.mirostat_eta,
                    seed=sampling.seed,
                    stop=stop_,
                    stream=stream,
                )

        if stream:
            def _gen() -> Generator[str, None, Dict[str, Any]]:
                meta: Dict[str, Any] = {}
                with self._sema:
                    t0 = time.perf_counter()
                    try:
                        it = _call()
                        text_accum = []
                        for part in it:
                            chunk = (part.get("choices") or [{}])[0]
                            delta = (chunk.get("delta") or {}).get("content") if "delta" in chunk else chunk.get("text")
                            delta = delta or ""
                            if delta:
                                text_accum.append(delta)
                                yield delta
                        full_text = "".join(text_accum)
                        meta = {
                            "tokens_gen": len(self.tokenize(full_text, add_bos=False)),
                            "latency_ms": (time.perf_counter() - t0) * 1000.0,
                        }
                        self._stats.calls_total += 1
                        self._stats.tokens_gen_total += meta["tokens_gen"]
                    except Exception as e:
                        self._stats.errors_total += 1
                        LOG.error("chat(stream) failed: %s", e)
                        raise
                return meta
            return _gen()
        else:
            with self._sema:
                try:
                    if timeout and timeout > 0:
                        res = _run_with_timeout(_call, timeout)
                    else:
                        res = _call()
                except TimeoutError as e:
                    self._stats.errors_total += 1
                    raise GGMLTimeoutError("chat timeout") from e

            # формат может быть chat или completion
            choices = res.get("choices") or [{}]
            msg = choices[0].get("message")
            if msg and isinstance(msg, dict):
                return msg.get("content") or ""
            return choices[0].get("text") or ""

    # ------------- Метрики/статистика -------------
    def stats(self) -> Dict[str, Any]:
        return self._stats.snapshot()


# -------------------------
# Утилиты
# -------------------------
def _run_with_timeout(fn: Any, timeout_s: float) -> Any:
    """
    Выполняет синхронную функцию с тайм-аутом (в отдельном потоке).
    """
    import concurrent.futures as _fut

    with _fut.ThreadPoolExecutor(max_workers=1) as pool:
        fut = pool.submit(fn)
        try:
            return fut.result(timeout=timeout_s)
        except _fut.TimeoutError as e:
            raise TimeoutError() from e


def _messages_to_prompt(messages: List[Dict[str, str]]) -> str:
    """
    Простая fallback-конкатенация, если chat_format недоступен.
    """
    parts: List[str] = []
    for m in messages:
        role = m.get("role", "user")
        content = m.get("content", "")
        if role == "system":
            parts.append(f"<|system|>\n{content}\n")
        elif role == "assistant":
            parts.append(f"<|assistant|>\n{content}\n")
        else:
            parts.append(f"<|user|>\n{content}\n")
    parts.append("<|assistant|>\n")
    return "".join(parts)


# -------------------------
# Пример использования (локальный smoke-test)
# -------------------------
if __name__ == "__main__":
    # Пример: выполните `pip install llama-cpp-python` и укажите путь к gguf/ggml модели через ENV
    model_path = os.getenv("GGML_MODEL", "/path/to/model.gguf")
    cfg = LocalGGMLConfig(model_path=model_path, n_gpu_layers=int(os.getenv("GGML_GPU_LAYERS", "0")))
    adapter = LocalGGMLAdapter(cfg)
    try:
        adapter.load()
        print("Health:", adapter.health())
        # Completion
        out = adapter.generate("Write a one-line haiku about the sun: ", SamplingParams(max_tokens=32))
        print("GEN:", out)
        # Stream chat
        msgs = [{"role": "system", "content": "You are a concise assistant."},
                {"role": "user", "content": "Say hello in one sentence."}]
        for tok in adapter.chat(msgs, stream=True):  # type: ignore
            print(tok, end="", flush=True)
        print()
        # Embeddings (если поддерживается)
        if cfg.embeddings:
            vec = adapter.embed(["hello world"])
            print("EMB len:", len(vec[0]))
    except GGMLNotInstalledError as e:
        LOG.error(str(e))
    except GGMLAdapterError as e:
        LOG.error("Adapter error: %s", e)
