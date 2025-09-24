# tests/unit/test_llm_adapters.py
import sys
import time
import types
import json
import builtins
import pytest

# Импортируем тестируемый адаптер
from omnimind.adapters.llm.local_ggml_adapter import (
    LocalGGMLAdapter,
    LocalGGMLConfig,
    SamplingParams,
    GGMLTimeoutError,
    GGMLModelNotLoadedError,
    GGMLAdapterError,
)

# ---------- Фикстуры: фейковый llama_cpp и адаптер ----------

@pytest.fixture(autouse=True)
def fake_llama_module(monkeypatch):
    """
    Подменяет модуль llama_cpp фейковой реализацией класса Llama.
    Эмулируются:
      - create_completion(..., stream=bool, stop=[...])
      - create_chat_completion(..., stream=bool)
      - create_embedding(input=[...])
      - tokenize(bytes), detokenize(list[int])
    """
    class _FakeLlama:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

        # простая токенизация: список байт
        def tokenize(self, b, add_bos=True):
            if isinstance(b, str):
                b = b.encode("utf-8")
            return list(b)

        def detokenize(self, tokens):
            tokens = [int(t) & 0xFF for t in tokens]
            return bytes(tokens)

        def _sleep_if_requested(self, prompt=None, messages=None):
            # если в prompt есть "SLEEP", притормозим для проверки тайм-аутов
            s = ""
            if prompt is not None:
                s = str(prompt)
            elif messages is not None:
                s = json.dumps(messages, ensure_ascii=False)
            if "SLEEP" in s:
                time.sleep(0.2)

        def _apply_stop(self, text, stop):
            if not stop:
                return text
            for s in stop:
                idx = text.find(s)
                if idx >= 0:
                    return text[:idx]
            return text

        def create_completion(self, prompt, stream=False, stop=None, **kwargs):
            self._sleep_if_requested(prompt=prompt)
            full = "hello world"
            full = self._apply_stop(full, stop or [])
            if stream:
                # Эмулируем поток кусочками
                parts = ["hello", " ", "world"]
                # учтём стопы в потоке
                accum = ""
                for p in parts:
                    if stop:
                        nxt = accum + p
                        cut = self._apply_stop(nxt, stop)
                        delta = cut[len(accum):]
                        accum = cut
                        if delta:
                            yield {"choices": [{"text": delta}]}
                        if cut != nxt:
                            return
                    else:
                        yield {"choices": [{"text": p}]}
                return
            return {
                "choices": [{"text": full}],
                "usage": {"prompt_tokens": 3, "completion_tokens": 2},
                "model": "fake-llama",
            }

        def create_chat_completion(self, messages, stream=False, stop=None, **kwargs):
            self._sleep_if_requested(messages=messages)
            text = "hi user"
            if stream:
                for p in ["hi", " ", "user"]:
                    yield {"choices": [{"delta": {"content": p}}]}
                return
            return {"choices": [{"message": {"role": "assistant", "content": text}}], "model": "fake-llama-chat"}

        def create_embedding(self, input):
            data = []
            for i, _ in enumerate(input):
                data.append({"embedding": [float(i), float(i + 1)]})
            return {"data": data}

    mod = types.ModuleType("llama_cpp")
    mod.Llama = _FakeLlama
    monkeypatch.setitem(sys.modules, "llama_cpp", mod)
    yield
    # teardown не требуется: monkeypatch сам восстанавливает


@pytest.fixture
def adapter():
    """
    Готовый загруженный адаптер с безопасной подменой семафора
    (т.к. в адаптере используется синхронный контекст).
    """
    cfg = LocalGGMLConfig(
        model_path="/path/to/fake.gguf",
        n_ctx=1024,
        chat_format="llama-2",
        max_input_chars=64,  # оставим небольшой лимит, чтобы проверить усечение
    )
    a = LocalGGMLAdapter(cfg)
    a.load()

    # Подменяем семафор на безопасный контекст-менеджер (no-op)
    class _DummySema:
        def __enter__(self): return self
        def __exit__(self, exc_type, exc, tb): return False
    a._sema = _DummySema()  # type: ignore[attr-defined]

    return a


# ---------- Тесты: базовая функциональность ----------

def test_health_and_stats(adapter):
    health = adapter.health()
    assert health["ok"] is True
    assert health["loaded"] is True
    stats = adapter.stats()
    assert "calls_total" in stats

def test_generate_basic(adapter):
    out = adapter.generate("Say hi", SamplingParams(max_tokens=8))
    assert out == "hello world"

def test_generate_with_stop(adapter):
    out = adapter.generate("Anything", SamplingParams(max_tokens=8), stop=("world",))
    assert out == "hello "

def test_generate_streaming(adapter):
    gen = adapter.generate("Stream it", SamplingParams(max_tokens=8), stream=True)
    chunks = []
    try:
        while True:
            chunks.append(next(gen))
    except StopIteration as fin:
        meta = fin.value
    assert "".join(chunks) == "hello world"
    assert isinstance(meta, dict)
    assert meta["tokens_gen"] > 0

def test_chat_with_chat_format(adapter):
    msg = [{"role": "system", "content": "Be brief"}, {"role": "user", "content": "Hello"}]
    out = adapter.chat(msg, SamplingParams(max_tokens=8))
    assert out == "hi user"

def test_chat_fallback_without_chat_format(adapter):
    adapter.cfg.chat_format = None
    msg = [{"role": "user", "content": "Fallback"}]
    out = adapter.chat(msg, SamplingParams(max_tokens=8))
    # В фоллбэке используется completion, отдаём "hello world"
    assert out == "hello world"

def test_embeddings_enabled(adapter):
    vecs = adapter.embed(["a", "b", "c"])
    assert len(vecs) == 3 and len(vecs[0]) == 2

def test_embeddings_disabled(fake_llama_module):
    cfg = LocalGGMLConfig(model_path="/x.gguf", embeddings=False)
    a = LocalGGMLAdapter(cfg)
    a.load()
    # подмена семафора
    class _DummySema:
        def __enter__(self): return self
        def __exit__(self, exc_type, exc, tb): return False
    a._sema = _DummySema()  # type: ignore
    with pytest.raises(GGMLAdapterError):
        a.embed(["x"])

def test_tokenize_detokenize_roundtrip(adapter):
    tokens = adapter.tokenize("abc", add_bos=True)
    text = adapter.detokenize(tokens)
    assert text == "abc"

# ---------- Тесты: ограничения и ошибки ----------

def test_truncate_input_in_tokenize(adapter):
    # Лимит 64 символа в конфиге; проверим, что длинный ввод был усечён
    long = "1234567890" * 10  # 100 символов
    tokens = adapter.tokenize(long)
    assert len(tokens) == adapter.cfg.max_input_chars

def test_timeout_in_generate(adapter):
    with pytest.raises(GGMLTimeoutError):
        adapter.generate("SLEEP", SamplingParams(max_tokens=8), timeout_s=0.05)

def test_timeout_in_chat(adapter):
    with pytest.raises(GGMLTimeoutError):
        adapter.chat([{"role": "user", "content": "SLEEP"}], SamplingParams(max_tokens=8), timeout_s=0.05)

def test_error_when_not_loaded(fake_llama_module):
    cfg = LocalGGMLConfig(model_path="/not/loaded.gguf")
    a = LocalGGMLAdapter(cfg)
    with pytest.raises(GGMLModelNotLoadedError):
        a.generate("hi")

def test_embeddings_not_supported(monkeypatch, fake_llama_module):
    # Уберём create_embedding у фейка, чтобы адаптер сообщил об отсутствии поддержки
    mod = sys.modules["llama_cpp"]
    orig = mod.Llama
    class _NoEmbLlama(orig):  # type: ignore
        def create_embedding(self, input):
            raise AttributeError("no embeddings")
    mod.Llama = _NoEmbLlama  # type: ignore
    cfg = LocalGGMLConfig(model_path="/x.gguf")
    a = LocalGGMLAdapter(cfg)
    a.load()
    class _DummySema:
        def __enter__(self): return self
        def __exit__(self, exc_type, exc, tb): return False
    a._sema = _DummySema()  # type: ignore
    with pytest.raises(GGMLAdapterError):
        a.embed(["x"])
    # восстановим
    mod.Llama = orig  # type: ignore
