# -*- coding: utf-8 -*-
"""
neuroforge.inference.tokenizer
Единый промышленный интерфейс токенизации для инференса и обучения.

Возможности:
- Бэкенды: HuggingFace (transformers), SentencePiece, TikToken (OpenAI), RegexFallback.
- Универсальный интерфейс: encode/decode, encode_batch/decode_batch, count_tokens,
  split_into_token_chunks (с overlap), special tokens, model_max_length.
- Детерминированная нормализация текста (NFKC, trim, collapse whitespace, lowercase).
- Мягкие зависимости: каждый бэкенд подключается, если библиотека доступна.
- Кэширование токенайзеров и потокобезопасная инициализация.
- Вывод в numpy или torch (если torch доступен).
"""

from __future__ import annotations

import json
import logging
import re
import threading
import unicodedata
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Protocol, Sequence, Tuple, Union

import numpy as np

logger = logging.getLogger("neuroforge.inference.tokenizer")
logger.setLevel(logging.INFO)

# Опциональные зависимости
try:
    import torch  # type: ignore
    _HAS_TORCH = True
except Exception:
    torch = None  # type: ignore
    _HAS_TORCH = False

try:
    from transformers import AutoTokenizer, PreTrainedTokenizerBase  # type: ignore
    _HAS_TRANSFORMERS = True
except Exception:
    AutoTokenizer = None  # type: ignore
    PreTrainedTokenizerBase = object  # type: ignore
    _HAS_TRANSFORMERS = False

try:
    import sentencepiece as spm  # type: ignore
    _HAS_SENTENCEPIECE = True
except Exception:
    spm = None  # type: ignore
    _HAS_SENTENCEPIECE = False

try:
    import tiktoken  # type: ignore
    _HAS_TIKTOKEN = True
except Exception:
    tiktoken = None  # type: ignore
    _HAS_TIKTOKEN = False


# ===========================
# Конфигурация и протокол
# ===========================

@dataclass(frozen=True)
class NormalizerConfig:
    nfkc: bool = True
    strip: bool = True
    collapse_whitespace: bool = True
    lowercase: bool = False
    # пользовательские regex замены: [(pattern, repl)]
    regex_subs: Tuple[Tuple[str, str], ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class TokenizerConfig:
    backend: str  # "hf"|"sentencepiece"|"tiktoken"|"regex"|"auto"
    name_or_path: Optional[str] = None        # для hf/spm
    revision: Optional[str] = None            # для hf
    use_fast: bool = True                     # для hf
    tiktoken_encoding: Optional[str] = None   # для tiktoken
    spm_model_file: Optional[str] = None      # для sentencepiece .model
    add_prefix_space: Optional[bool] = None   # для некоторых BPE (roberta)
    model_max_length: Optional[int] = None
    pad_to_multiple_of: Optional[int] = None  # выравнивание
    normalizer: NormalizerConfig = field(default_factory=NormalizerConfig)
    # спец-токены (если не заданы — берем из бэкенда)
    bos_token: Optional[str] = None
    eos_token: Optional[str] = None
    pad_token: Optional[str] = None
    unk_token: Optional[str] = None


@dataclass
class SpecialTokens:
    bos_id: Optional[int] = None
    eos_id: Optional[int] = None
    pad_id: Optional[int] = None
    unk_id: Optional[int] = None


@dataclass
class TokenizedBatch:
    input_ids: Union[np.ndarray, "torch.Tensor"]
    attention_mask: Union[np.ndarray, "torch.Tensor"]
    lengths: List[int]
    special: SpecialTokens
    # опционально
    token_type_ids: Optional[Union[np.ndarray, "torch.Tensor"]] = None


class BaseTokenizer(Protocol):
    cfg: TokenizerConfig

    def encode(
        self,
        text: str,
        add_special_tokens: bool = True,
        max_length: Optional[int] = None,
        truncation: bool = True,
        padding: Optional[Union[bool, str, int]] = False,
        return_tensors: str = "np",  # "np" | "pt"
    ) -> TokenizedBatch:
        ...

    def encode_batch(
        self,
        texts: Sequence[str],
        add_special_tokens: bool = True,
        max_length: Optional[int] = None,
        truncation: bool = True,
        padding: Optional[Union[bool, str, int]] = "longest",
        return_tensors: str = "np",
    ) -> TokenizedBatch:
        ...

    def decode(self, ids: Sequence[int], skip_special_tokens: bool = True) -> str:
        ...

    def decode_batch(self, batch_ids: Sequence[Sequence[int]], skip_special_tokens: bool = True) -> List[str]:
        ...

    def count_tokens(self, text: str, add_special_tokens: bool = True) -> int:
        ...

    def split_into_token_chunks(
        self, text: str, max_tokens: int, overlap: int = 0, add_special_tokens: bool = True
    ) -> List[List[int]]:
        ...

    def special_tokens(self) -> SpecialTokens:
        ...

    def max_length(self) -> Optional[int]:
        ...


# ===========================
# Нормализация
# ===========================

class Normalizer:
    def __init__(self, cfg: NormalizerConfig) -> None:
        self.cfg = cfg
        self._regex_subs = [(re.compile(p, flags=re.MULTILINE), r) for p, r in cfg.regex_subs]

    def __call__(self, text: str) -> str:
        t = text
        if self.cfg.nfkc:
            t = unicodedata.normalize("NFKC", t)
        if self.cfg.strip:
            t = t.strip()
        if self.cfg.collapse_whitespace:
            t = re.sub(r"\s+", " ", t)
        if self.cfg.lowercase:
            t = t.lower()
        for pat, repl in self._regex_subs:
            t = pat.sub(repl, t)
        return t


# ===========================
# Утилиты преобразования
# ===========================

def _to_tensor(arr: np.ndarray, return_tensors: str):
    if return_tensors == "pt" and _HAS_TORCH:
        return torch.from_numpy(arr)
    return arr

def _pad_to_multiple(length: int, multiple: Optional[int]) -> int:
    if not multiple or multiple <= 1:
        return length
    rem = length % multiple
    return length if rem == 0 else length + (multiple - rem)


# ===========================
# Реализации бэкендов
# ===========================

class HFTokenizerWrapper(BaseTokenizer):
    def __init__(self, cfg: TokenizerConfig):
        if not _HAS_TRANSFORMERS:
            raise RuntimeError("HuggingFace transformers не установлен")
        self.cfg = cfg
        self._norm = Normalizer(cfg.normalizer)
        # Потокобезопасная инициализация
        self._lock = threading.Lock()
        self._tok: PreTrainedTokenizerBase = AutoTokenizer.from_pretrained(
            cfg.name_or_path, revision=cfg.revision, use_fast=cfg.use_fast, add_prefix_space=cfg.add_prefix_space
        )
        # Переопределение спец-токенов, если заданы
        if cfg.bos_token:
            self._tok.bos_token = cfg.bos_token
        if cfg.eos_token:
            self._tok.eos_token = cfg.eos_token
        if cfg.pad_token:
            self._tok.pad_token = cfg.pad_token
        if cfg.unk_token:
            self._tok.unk_token = cfg.unk_token

    def special_tokens(self) -> SpecialTokens:
        return SpecialTokens(
            bos_id=getattr(self._tok, "bos_token_id", None),
            eos_id=getattr(self._tok, "eos_token_id", None),
            pad_id=getattr(self._tok, "pad_token_id", None),
            unk_id=getattr(self._tok, "unk_token_id", None),
        )

    def max_length(self) -> Optional[int]:
        return self.cfg.model_max_length or getattr(self._tok, "model_max_length", None)

    def encode(self, text: str, add_special_tokens=True, max_length=None, truncation=True, padding=False, return_tensors="np") -> TokenizedBatch:
        norm = self._norm(text)
        with self._lock:
            out = self._tok(
                norm,
                add_special_tokens=add_special_tokens,
                max_length=max_length or self.max_length(),
                truncation=truncation,
                padding=padding,
                return_attention_mask=True,
            )
        ids = np.array(out["input_ids"], dtype=np.int64)
        attn = np.array(out["attention_mask"], dtype=np.int64)
        if ids.ndim == 1:
            ids = ids[None, :]
            attn = attn[None, :]
        # выравнивание
        if self.cfg.pad_to_multiple_of:
            new_len = _pad_to_multiple(ids.shape[1], self.cfg.pad_to_multiple_of)
            if new_len != ids.shape[1]:
                pad_id = self.special_tokens().pad_id if self.special_tokens().pad_id is not None else 0
                pad_width = new_len - ids.shape[1]
                ids = np.pad(ids, ((0, 0), (0, pad_width)), constant_values=pad_id)
                attn = np.pad(attn, ((0, 0), (0, pad_width)), constant_values=0)
        return TokenizedBatch(
            input_ids=_to_tensor(ids, return_tensors),
            attention_mask=_to_tensor(attn, return_tensors),
            lengths=[int(x) for x in attn.sum(axis=1).tolist()],
            special=self.special_tokens(),
            token_type_ids=_to_tensor(np.array(out.get("token_type_ids") or [[0]*ids.shape[1]], dtype=np.int64), return_tensors),
        )

    def encode_batch(self, texts, add_special_tokens=True, max_length=None, truncation=True, padding="longest", return_tensors="np") -> TokenizedBatch:
        norms = [self._norm(t) for t in texts]
        with self._lock:
            out = self._tok(
                norms,
                add_special_tokens=add_special_tokens,
                max_length=max_length or self.max_length(),
                truncation=truncation,
                padding=padding,
                return_attention_mask=True,
            )
        ids = np.array(out["input_ids"], dtype=np.int64)
        attn = np.array(out["attention_mask"], dtype=np.int64)
        if self.cfg.pad_to_multiple_of:
            new_len = _pad_to_multiple(ids.shape[1], self.cfg.pad_to_multiple_of)
            if new_len != ids.shape[1]:
                pad_id = self.special_tokens().pad_id if self.special_tokens().pad_id is not None else 0
                pad_width = new_len - ids.shape[1]
                ids = np.pad(ids, ((0, 0), (0, pad_width)), constant_values=pad_id)
                attn = np.pad(attn, ((0, 0), (0, pad_width)), constant_values=0)
        return TokenizedBatch(
            input_ids=_to_tensor(ids, return_tensors),
            attention_mask=_to_tensor(attn, return_tensors),
            lengths=[int(x) for x in attn.sum(axis=1).tolist()],
            special=self.special_tokens(),
            token_type_ids=_to_tensor(np.array(out.get("token_type_ids") or np.zeros_like(ids), dtype=np.int64), return_tensors),
        )

    def decode(self, ids: Sequence[int], skip_special_tokens: bool = True) -> str:
        with self._lock:
            return self._tok.decode(ids, skip_special_tokens=skip_special_tokens)

    def decode_batch(self, batch_ids: Sequence[Sequence[int]], skip_special_tokens: bool = True) -> List[str]:
        with self._lock:
            return self._tok.batch_decode(batch_ids, skip_special_tokens=skip_special_tokens)

    def count_tokens(self, text: str, add_special_tokens: bool = True) -> int:
        with self._lock:
            return int(len(self._tok(self._norm(text), add_special_tokens=add_special_tokens)["input_ids"]))

    def split_into_token_chunks(self, text: str, max_tokens: int, overlap: int = 0, add_special_tokens: bool = True) -> List[List[int]]:
        if max_tokens <= 0:
            return []
        # Используем encode без padding
        ids: List[int] = self.encode(text, add_special_tokens=add_special_tokens, truncation=False, padding=False).input_ids
        ids = ids[0].tolist() if _HAS_TORCH else np.asarray(ids)[0].tolist()
        chunks: List[List[int]] = []
        i = 0
        step = max(1, max_tokens - overlap)
        while i < len(ids):
            chunk = ids[i:i + max_tokens]
            if not chunk:
                break
            chunks.append(chunk)
            i += step
        return chunks


class SentencePieceTokenizer(BaseTokenizer):
    def __init__(self, cfg: TokenizerConfig):
        if not _HAS_SENTENCEPIECE:
            raise RuntimeError("sentencepiece не установлен")
        if not cfg.spm_model_file:
            raise ValueError("spm_model_file обязателен для sentencepiece")
        self.cfg = cfg
        self._norm = Normalizer(cfg.normalizer)
        self._lock = threading.Lock()
        self._sp = spm.SentencePieceProcessor(model_file=cfg.spm_model_file)
        # спец-токены (если заданы вручную)
        self._special = SpecialTokens(
            bos_id=self._sp.bos_id() if self._sp.bos_id() >= 0 else None,
            eos_id=self._sp.eos_id() if self._sp.eos_id() >= 0 else None,
            pad_id=0 if cfg.pad_token else None,  # SPM часто не имеет pad; можно настроить снаружи
            unk_id=self._sp.unk_id() if self._sp.unk_id() >= 0 else None,
        )

    def special_tokens(self) -> SpecialTokens:
        return self._special

    def max_length(self) -> Optional[int]:
        return self.cfg.model_max_length

    def _pad_pack(self, seqs: List[List[int]], return_tensors: str, pad_id: int = 0) -> TokenizedBatch:
        max_len = max(len(s) for s in seqs) if seqs else 0
        if self.cfg.pad_to_multiple_of:
            max_len = _pad_to_multiple(max_len, self.cfg.pad_to_multiple_of)
        n = len(seqs)
        ids = np.full((n, max_len), pad_id, dtype=np.int64)
        attn = np.zeros((n, max_len), dtype=np.int64)
        lengths: List[int] = []
        for i, s in enumerate(seqs):
            L = min(len(s), max_len)
            ids[i, :L] = s[:L]
            attn[i, :L] = 1
            lengths.append(L)
        return TokenizedBatch(input_ids=_to_tensor(ids, return_tensors), attention_mask=_to_tensor(attn, return_tensors), lengths=lengths, special=self._special)

    def encode(self, text: str, add_special_tokens=True, max_length=None, truncation=True, padding=False, return_tensors="np") -> TokenizedBatch:
        t = self._norm(text)
        with self._lock:
            ids = self._sp.encode(t, out_type=int, enable_sampling=False)
        if add_special_tokens:
            if self._special.bos_id is not None:
                ids = [self._special.bos_id] + ids
            if self._special.eos_id is not None:
                ids = ids + [self._special.eos_id]
        if truncation and max_length:
            ids = ids[:max_length]
        if padding:
            pad_to = max_length if isinstance(padding, bool) and max_length else (padding if isinstance(padding, int) else len(ids))
            return self._pad_pack([ids], return_tensors, pad_id=(self._special.pad_id or 0))
        arr = np.array([ids], dtype=np.int64)
        attn = np.ones_like(arr, dtype=np.int64)
        return TokenizedBatch(input_ids=_to_tensor(arr, return_tensors), attention_mask=_to_tensor(attn, return_tensors), lengths=[arr.shape[1]], special=self._special)

    def encode_batch(self, texts, add_special_tokens=True, max_length=None, truncation=True, padding="longest", return_tensors="np") -> TokenizedBatch:
        seqs: List[List[int]] = []
        with self._lock:
            for t in texts:
                ids = self._sp.encode(self._norm(t), out_type=int, enable_sampling=False)
                if add_special_tokens:
                    if self._special.bos_id is not None:
                        ids = [self._special.bos_id] + ids
                    if self._special.eos_id is not None:
                        ids = ids + [self._special.eos_id]
                if truncation and max_length:
                    ids = ids[:max_length]
                seqs.append(ids)
        if padding in (True, "longest") or isinstance(padding, int) or max_length:
            return self._pad_pack(seqs, return_tensors, pad_id=(self._special.pad_id or 0))
        # без паддинга — складываем разной длины (неудобно для тензоров)
        max_len = max(len(s) for s in seqs) if seqs else 0
        ids = np.full((len(seqs), max_len), (self._special.pad_id or 0), dtype=np.int64)
        attn = np.zeros_like(ids)
        lengths: List[int] = []
        for i, s in enumerate(seqs):
            ids[i, :len(s)] = s
            attn[i, :len(s)] = 1
            lengths.append(len(s))
        return TokenizedBatch(input_ids=_to_tensor(ids, return_tensors), attention_mask=_to_tensor(attn, return_tensors), lengths=lengths, special=self._special)

    def decode(self, ids: Sequence[int], skip_special_tokens: bool = True) -> str:
        filt = list(ids)
        if skip_special_tokens:
            st = {x for x in (self._special.bos_id, self._special.eos_id, self._special.pad_id) if x is not None}
            filt = [i for i in filt if i not in st]
        with self._lock:
            return self._sp.decode(filt)

    def decode_batch(self, batch_ids: Sequence[Sequence[int]], skip_special_tokens: bool = True) -> List[str]:
        return [self.decode(s, skip_special_tokens=skip_special_tokens) for s in batch_ids]

    def count_tokens(self, text: str, add_special_tokens: bool = True) -> int:
        t = self._norm(text)
        with self._lock:
            ids = self._sp.encode(t, out_type=int, enable_sampling=False)
        n = len(ids)
        if add_special_tokens:
            n += int(self._special.bos_id is not None) + int(self._special.eos_id is not None)
        return int(n)

    def split_into_token_chunks(self, text: str, max_tokens: int, overlap: int = 0, add_special_tokens: bool = True) -> List[List[int]]:
        if max_tokens <= 0:
            return []
        ids = self.encode(text, add_special_tokens=add_special_tokens, truncation=False, padding=False).input_ids
        ids = ids[0].tolist() if _HAS_TORCH else np.asarray(ids)[0].tolist()
        chunks: List[List[int]] = []
        i = 0
        step = max(1, max_tokens - overlap)
        while i < len(ids):
            chunk = ids[i:i + max_tokens]
            if not chunk:
                break
            chunks.append(chunk)
            i += step
        return chunks


class TikTokenTokenizer(BaseTokenizer):
    def __init__(self, cfg: TokenizerConfig):
        if not _HAS_TIKTOKEN:
            raise RuntimeError("tiktoken не установлен")
        self.cfg = cfg
        self._norm = Normalizer(cfg.normalizer)
        name = cfg.tiktoken_encoding or cfg.name_or_path or "cl100k_base"
        self._enc = tiktoken.get_encoding(name)

        # TikToken не хранит BOS/EOS/PAD; задаем через конфиг или None
        self._special = SpecialTokens(bos_id=None, eos_id=None, pad_id=0 if cfg.pad_token else None, unk_id=None)

    def special_tokens(self) -> SpecialTokens:
        return self._special

    def max_length(self) -> Optional[int]:
        return self.cfg.model_max_length

    def _pack(self, seqs: List[List[int]], return_tensors: str) -> TokenizedBatch:
        max_len = max((len(s) for s in seqs), default=0)
        if self.cfg.pad_to_multiple_of:
            max_len = _pad_to_multiple(max_len, self.cfg.pad_to_multiple_of)
        pad_id = self._special.pad_id or 0
        n = len(seqs)
        ids = np.full((n, max_len), pad_id, dtype=np.int64)
        attn = np.zeros((n, max_len), dtype=np.int64)
        lens: List[int] = []
        for i, s in enumerate(seqs):
            L = min(len(s), max_len)
            ids[i, :L] = s[:L]
            attn[i, :L] = 1
            lens.append(L)
        return TokenizedBatch(input_ids=_to_tensor(ids, return_tensors), attention_mask=_to_tensor(attn, return_tensors), lengths=lens, special=self._special)

    def encode(self, text: str, add_special_tokens=True, max_length=None, truncation=True, padding=False, return_tensors="np") -> TokenizedBatch:
        ids = self._enc.encode(self._norm(text))
        if truncation and max_length:
            ids = ids[:max_length]
        if padding:
            return self._pack([ids], return_tensors)
        arr = np.array([ids], dtype=np.int64)
        attn = np.ones_like(arr, dtype=np.int64)
        return TokenizedBatch(input_ids=_to_tensor(arr, return_tensors), attention_mask=_to_tensor(attn, return_tensors), lengths=[arr.shape[1]], special=self._special)

    def encode_batch(self, texts, add_special_tokens=True, max_length=None, truncation=True, padding="longest", return_tensors="np") -> TokenizedBatch:
        seqs = [self._enc.encode(self._norm(t)) for t in texts]
        if truncation and max_length:
            seqs = [s[:max_length] for s in seqs]
        if padding in (True, "longest") or isinstance(padding, int) or max_length:
            return self._pack(seqs, return_tensors)
        max_len = max((len(s) for s in seqs), default=0)
        ids = np.zeros((len(seqs), max_len), dtype=np.int64)
        attn = np.zeros_like(ids)
        lens: List[int] = []
        for i, s in enumerate(seqs):
            ids[i, :len(s)] = s
            attn[i, :len(s)] = 1
            lens.append(len(s))
        return TokenizedBatch(input_ids=_to_tensor(ids, return_tensors), attention_mask=_to_tensor(attn, return_tensors), lengths=lens, special=self._special)

    def decode(self, ids: Sequence[int], skip_special_tokens: bool = True) -> str:
        return self._enc.decode(list(ids))

    def decode_batch(self, batch_ids: Sequence[Sequence[int]], skip_special_tokens: bool = True) -> List[str]:
        return [self.decode(s, skip_special_tokens=skip_special_tokens) for s in batch_ids]

    def count_tokens(self, text: str, add_special_tokens: bool = True) -> int:
        return int(len(self._enc.encode(self._norm(text))))

    def split_into_token_chunks(self, text: str, max_tokens: int, overlap: int = 0, add_special_tokens: bool = True) -> List[List[int]]:
        if max_tokens <= 0:
            return []
        ids = self._enc.encode(self._norm(text))
        chunks: List[List[int]] = []
        i = 0
        step = max(1, max_tokens - overlap)
        while i < len(ids):
            chunk = ids[i:i + max_tokens]
            if not chunk:
                break
            chunks.append(chunk)
            i += step
        return chunks


class RegexFallbackTokenizer(BaseTokenizer):
    """
    Безопасный фолбэк: whitespace + простая пунктуация.
    Не для прод-LLM, но выдержит отсутствие внешних зависимостей.
    """
    _VOCAB: Dict[str, int] = {"[PAD]": 0, "[UNK]": 1, "[BOS]": 2, "[EOS]": 3}

    def __init__(self, cfg: TokenizerConfig):
        self.cfg = cfg
        self._norm = Normalizer(cfg.normalizer)
        self._special = SpecialTokens(bos_id=2, eos_id=3, pad_id=0, unk_id=1)
        self._lock = threading.Lock()
        self._next_id = 4

    def special_tokens(self) -> SpecialTokens:
        return self._special

    def max_length(self) -> Optional[int]:
        return self.cfg.model_max_length

    def _tokenize(self, text: str) -> List[str]:
        # Разбиваем на "слова" и отдельные знаки
        return re.findall(r"[A-Za-z0-9_]+|[^\sA-Za-z0-9_]", text, flags=re.UNICODE)

    def _ids_from_tokens(self, toks: List[str]) -> List[int]:
        with self._lock:
            ids: List[int] = []
            for t in toks:
                if t not in self._VOCAB:
                    self._VOCAB[t] = self._next_id
                    self._next_id += 1
                ids.append(self._VOCAB.get(t, 1))
            return ids

    def encode(self, text: str, add_special_tokens=True, max_length=None, truncation=True, padding=False, return_tensors="np") -> TokenizedBatch:
        toks = self._tokenize(self._norm(text))
        ids = self._ids_from_tokens(toks)
        if add_special_tokens:
            ids = [self._special.bos_id] + ids + [self._special.eos_id]
        if truncation and max_length:
            ids = ids[:max_length]
        arr = np.array([ids], dtype=np.int64)
        if padding:
            target = max_length or arr.shape[1]
            if self.cfg.pad_to_multiple_of:
                target = _pad_to_multiple(target, self.cfg.pad_to_multiple_of)
            pad_len = max(0, target - arr.shape[1])
            if pad_len:
                arr = np.pad(arr, ((0, 0), (0, pad_len)), constant_values=self._special.pad_id or 0)
        attn = (arr != (self._special.pad_id or 0)).astype(np.int64)
        return TokenizedBatch(input_ids=_to_tensor(arr, return_tensors), attention_mask=_to_tensor(attn, return_tensors), lengths=[int(attn.sum())], special=self._special)

    def encode_batch(self, texts, add_special_tokens=True, max_length=None, truncation=True, padding="longest", return_tensors="np") -> TokenizedBatch:
        seqs = []
        for t in texts:
            toks = self._tokenize(self._norm(t))
            ids = self._ids_from_tokens(toks)
            if add_special_tokens:
                ids = [self._special.bos_id] + ids + [self._special.eos_id]
            if truncation and max_length:
                ids = ids[:max_length]
            seqs.append(ids)
        max_len = max(len(s) for s in seqs) if seqs else 0
        if isinstance(padding, int):
            max_len = max(max_len, padding)
        elif padding in (True, "longest") or max_length:
            max_len = max(max_len, max_length or 0)
        if self.cfg.pad_to_multiple_of:
            max_len = _pad_to_multiple(max_len, self.cfg.pad_to_multiple_of)
        ids_arr = np.full((len(seqs), max_len), self._special.pad_id or 0, dtype=np.int64)
        attn = np.zeros_like(ids_arr)
        lens: List[int] = []
        for i, s in enumerate(seqs):
            L = min(len(s), max_len)
            ids_arr[i, :L] = s[:L]
            attn[i, :L] = 1
            lens.append(L)
        return TokenizedBatch(input_ids=_to_tensor(ids_arr, return_tensors), attention_mask=_to_tensor(attn, return_tensors), lengths=lens, special=self._special)

    def decode(self, ids: Sequence[int], skip_special_tokens: bool = True) -> str:
        inv = {v: k for k, v in self._VOCAB.items()}
        toks = []
        for i in ids:
            if skip_special_tokens and i in {self._special.bos_id, self._special.eos_id, self._special.pad_id}:
                continue
            toks.append(inv.get(int(i), "[UNK]"))
        # Склеиваем с минимальными пробелами
        out = []
        for tok in toks:
            if re.fullmatch(r"[^\w\s]", tok):
                out.append(tok)
            else:
                if out and not re.fullmatch(r"[^\w\s]", out[-1]):
                    out.append(" ")
                out.append(tok)
        return "".join(out).strip()

    def decode_batch(self, batch_ids: Sequence[Sequence[int]], skip_special_tokens: bool = True) -> List[str]:
        return [self.decode(s, skip_special_tokens=skip_special_tokens) for s in batch_ids]

    def count_tokens(self, text: str, add_special_tokens: bool = True) -> int:
        n = len(self._tokenize(self._norm(text)))
        if add_special_tokens:
            n += 2
        return int(n)

    def split_into_token_chunks(self, text: str, max_tokens: int, overlap: int = 0, add_special_tokens: bool = True) -> List[List[int]]:
        if max_tokens <= 0:
            return []
        ids = self.encode(text, add_special_tokens=add_special_tokens, truncation=False, padding=False).input_ids
        ids = ids[0].tolist() if _HAS_TORCH else np.asarray(ids)[0].tolist()
        chunks: List[List[int]] = []
        i = 0
        step = max(1, max_tokens - overlap)
        while i < len(ids):
            chunk = ids[i:i + max_tokens]
            if not chunk:
                break
            chunks.append(chunk)
            i += step
        return chunks


# ===========================
# Фабрика и кэш
# ===========================

class _TokenizerCache:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._cache: Dict[str, BaseTokenizer] = {}

    def _key(self, cfg: TokenizerConfig) -> str:
        # Минимизируем ключ, сериализуя конфиг
        d = dict(cfg.__dict__)
        d["normalizer"] = dict(cfg.normalizer.__dict__)
        return json.dumps(d, sort_keys=True)

    def get_or_create(self, cfg: TokenizerConfig) -> BaseTokenizer:
        key = self._key(cfg)
        with self._lock:
            if key in self._cache:
                return self._cache[key]
        # вне блокировки создаем (дорого), затем кладем
        tok = build_tokenizer(cfg)
        with self._lock:
            self._cache[key] = tok
            return tok


_TOKENIZER_CACHE = _TokenizerCache()


def build_tokenizer(cfg: TokenizerConfig) -> BaseTokenizer:
    backend = (cfg.backend or "auto").lower()
    if backend == "auto":
        if _HAS_TRANSFORMERS and cfg.name_or_path:
            backend = "hf"
        elif _HAS_SENTENCEPIECE and cfg.spm_model_file:
            backend = "sentencepiece"
        elif _HAS_TIKTOKEN and (cfg.tiktoken_encoding or cfg.name_or_path):
            backend = "tiktoken"
        else:
            backend = "regex"

    if backend == "hf":
        if not cfg.name_or_path:
            raise ValueError("name_or_path обязателен для backend=hf")
        return HFTokenizerWrapper(cfg)
    if backend == "sentencepiece":
        return SentencePieceTokenizer(cfg)
    if backend == "tiktoken":
        return TikTokenTokenizer(cfg)
    if backend == "regex":
        return RegexFallbackTokenizer(cfg)
    raise ValueError(f"Неизвестный backend: {cfg.backend}")


def get_tokenizer(cfg: TokenizerConfig) -> BaseTokenizer:
    """
    Получить (кэшированный) токенайзер по конфигу.
    """
    return _TOKENIZER_CACHE.get_or_create(cfg)


# ===========================
# Утилиты высокого уровня
# ===========================

def chunk_text_by_tokens(
    tokenizer: BaseTokenizer,
    text: str,
    max_tokens: int,
    overlap: int = 0,
    add_special_tokens: bool = True,
) -> List[List[int]]:
    return tokenizer.split_into_token_chunks(text, max_tokens=max_tokens, overlap=overlap, add_special_tokens=add_special_tokens)


def ensure_max_length(tokenizer: BaseTokenizer, text: str, add_special_tokens: bool = True) -> bool:
    """
    Проверить, помещается ли текст в лимит модели (если известен).
    """
    ml = tokenizer.max_length()
    if not ml:
        return True
    return tokenizer.count_tokens(text, add_special_tokens=add_special_tokens) <= ml


__all__ = [
    "NormalizerConfig",
    "TokenizerConfig",
    "SpecialTokens",
    "TokenizedBatch",
    "BaseTokenizer",
    "HFTokenizerWrapper",
    "SentencePieceTokenizer",
    "TikTokenTokenizer",
    "RegexFallbackTokenizer",
    "build_tokenizer",
    "get_tokenizer",
    "chunk_text_by_tokens",
    "ensure_max_length",
]
