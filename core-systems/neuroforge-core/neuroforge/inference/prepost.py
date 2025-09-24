# neuroforge-core/neuroforge/inference/prepost.py
from __future__ import annotations

import base64
import dataclasses
import io
import json
import math
import os
import re
import unicodedata
import uuid
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any, Dict, Iterable, List, Literal, Optional, Sequence, Tuple, Union

# -------------------- Optional deps (graceful fallback) --------------------
try:
    import numpy as np  # type: ignore
    _HAVE_NUMPY = True
except Exception:
    np = None  # type: ignore
    _HAVE_NUMPY = False

try:
    import torch  # type: ignore
    _HAVE_TORCH = True
except Exception:
    torch = None  # type: ignore
    _HAVE_TORCH = False

try:
    from tokenizers import Tokenizer  # HuggingFace fast tokenizer
    _HAVE_HF_TOKENIZERS = True
except Exception:
    Tokenizer = None  # type: ignore
    _HAVE_HF_TOKENIZERS = False

try:
    import sentencepiece as spm  # type: ignore
    _HAVE_SPM = True
except Exception:
    spm = None  # type: ignore
    _HAVE_SPM = False

try:
    from PIL import Image  # type: ignore
    _HAVE_PIL = True
except Exception:
    Image = None  # type: ignore
    _HAVE_PIL = False

try:
    import librosa  # type: ignore
    _HAVE_LIBROSA = True
except Exception:
    librosa = None  # type: ignore
    _HAVE_LIBROSA = False

try:
    import soundfile as sf  # type: ignore
    _HAVE_SF = True
except Exception:
    sf = None  # type: ignore
    _HAVE_SF = False

# Pydantic v2-style; fall back to v1 if needed
try:
    from pydantic import BaseModel, Field, PositiveInt, ValidationError
except Exception:  # pragma: no cover
    # minimal fallback shim
    class BaseModel:  # type: ignore
        def __init__(self, **data): self.__dict__.update(data)
        def model_dump(self): return self.__dict__
    def Field(*args, **kwargs): return None
    PositiveInt = int
    class ValidationError(Exception): pass  # type: ignore

# =============================================================================
# Common utilities
# =============================================================================

RE_WHITESPACE = re.compile(r"\s+")
RE_CONTROL = re.compile(r"[\u0000-\u001F\u007F]")
RE_ZW = re.compile(r"[\u200B-\u200F\u2060\uFEFF]")  # zero-width class
RE_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}\b")
RE_PHONE = re.compile(r"(?:\+?\d{1,3}[\s-]?)?(?:\(?\d{2,4}\)?[\s-]?)?\d{3,4}[\s-]?\d{3,4}")
RE_CC = re.compile(r"\b(?:\d[ -]*?){13,19}\b")  # crude CC detector

def stable_hash(obj: Any) -> str:
    """Stable sha256 over canonical JSON serialization."""
    s = json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return sha256(s).hexdigest()

def norm_unicode(text: str, form: Literal["NFC","NFKC"]="NFKC") -> str:
    return unicodedata.normalize(form, text)

def redact_pii(text: str, replacement: str="[REDACTED]") -> str:
    text = RE_EMAIL.sub(replacement, text)
    text = RE_PHONE.sub(replacement, text)
    text = RE_CC.sub(replacement, text)
    return text

def collapse_ws(text: str) -> str:
    return RE_WHITESPACE.sub(" ", text).strip()

def strip_control(text: str) -> str:
    return RE_CONTROL.sub(" ", RE_ZW.sub("", text))

def ensure_list(x: Union[Any, Sequence[Any]]) -> List[Any]:
    if x is None: return []
    if isinstance(x, (list, tuple)): return list(x)
    return [x]

# =============================================================================
# Config models
# =============================================================================

class TextConfig(BaseModel):
    normalize: Literal["NFC","NFKC"] = "NFKC"
    lower: bool = False
    strip: bool = True
    collapse_whitespace: bool = True
    remove_control: bool = True
    redact_pii: bool = False
    max_chars: Optional[int] = Field(default=None, ge=1)
    max_tokens: Optional[int] = Field(default=None, ge=1)
    add_bos: bool = False
    add_eos: bool = False
    # tokenizer setup
    tokenizer_kind: Optional[Literal["hf","spm"]] = None
    tokenizer_path: Optional[str] = None
    truncation_strategy: Literal["head","tail"] = "tail"

class ImageConfig(BaseModel):
    target_size: Tuple[int,int] = (224, 224)
    channels: Literal[1,3] = 3
    mode: Literal["RGB","L"] = "RGB"
    letterbox: bool = False
    center_crop: bool = True
    to_float32: bool = True
    scale: bool = True
    mean: Optional[Tuple[float,float,float]] = (0.485, 0.456, 0.406)
    std: Optional[Tuple[float,float,float]] = (0.229, 0.224, 0.225)

class AudioConfig(BaseModel):
    sample_rate: PositiveInt = 16000
    mono: bool = True
    max_duration_sec: Optional[float] = Field(default=None, ge=0.1)
    normalize_db: Optional[float] = None  # e.g., -20 dBFS target
    # features
    use_log_mel: bool = True
    n_mels: PositiveInt = 80
    frame_length: PositiveInt = 400
    hop_length: PositiveInt = 160
    fmin: float = 0.0
    fmax: Optional[float] = None

class CollateConfig(BaseModel):
    pad_token_id: int = 0
    pad_to_multiple_of: Optional[int] = None
    return_tensors: Literal["np","pt"] = "pt"

class SafetyConfig(BaseModel):
    redact_pii_input: bool = False
    redact_pii_output: bool = True
    remove_control_input: bool = True
    remove_control_output: bool = True
    max_output_chars: Optional[int] = Field(default=20000, ge=1)

class PrePostConfig(BaseModel):
    text: TextConfig = TextConfig()
    image: ImageConfig = ImageConfig()
    audio: AudioConfig = AudioConfig()
    collate: CollateConfig = CollateConfig()
    safety: SafetyConfig = SafetyConfig()

# =============================================================================
# Tokenizer wrappers (HF / SPM / fallback)
# =============================================================================

class BaseTokenizer:
    def tokenize(self, text: str) -> List[int]: raise NotImplementedError
    def detokenize(self, ids: List[int]) -> str: raise NotImplementedError
    @property
    def bos_id(self) -> Optional[int]: return None
    @property
    def eos_id(self) -> Optional[int]: return None

class HfFastTokenizer(BaseTokenizer):
    def __init__(self, path: str):
        if not _HAVE_HF_TOKENIZERS: raise RuntimeError("tokenizers not installed")
        self.tk = Tokenizer.from_file(path)  # type: ignore
        self._bos = self.tk.get_special_tokens().get("bos", None)
        self._eos = self.tk.get_special_tokens().get("eos", None)

    def tokenize(self, text: str) -> List[int]:
        return list(self.tk.encode(text).ids)

    def detokenize(self, ids: List[int]) -> str:
        return self.tk.decode(ids)

    @property
    def bos_id(self) -> Optional[int]:
        return self._bos

    @property
    def eos_id(self) -> Optional[int]:
        return self._eos

class SentencePieceTokenizer(BaseTokenizer):
    def __init__(self, path: str):
        if not _HAVE_SPM: raise RuntimeError("sentencepiece not installed")
        self.sp = spm.SentencePieceProcessor(model_file=path)  # type: ignore
        self._bos = 1 if self.sp.bos_id() >= 0 else None
        self._eos = 2 if self.sp.eos_id() >= 0 else None

    def tokenize(self, text: str) -> List[int]:
        return list(self.sp.encode(text, out_type=int))

    def detokenize(self, ids: List[int]) -> str:
        return self.sp.decode(ids)

    @property
    def bos_id(self) -> Optional[int]:
        return self.sp.bos_id() if self.sp.bos_id() >= 0 else None

    @property
    def eos_id(self) -> Optional[int]:
        return self.sp.eos_id() if self.sp.eos_id() >= 0 else None

class WhitespaceTokenizer(BaseTokenizer):
    """Fallback tokenizer for environments without external tokenizers."""
    def tokenize(self, text: str) -> List[int]:
        # Not reversible; hash tokens into a stable space (only for limits/length)
        return [int(sha256(tok.encode()).hexdigest()[:8], 16) for tok in text.split()]

    def detokenize(self, ids: List[int]) -> str:
        return "<detokenization-unavailable>"

# =============================================================================
# Text preprocessor
# =============================================================================

class TextPreprocessor:
    def __init__(self, cfg: TextConfig):
        self.cfg = cfg
        self.tok: Optional[BaseTokenizer] = None
        if cfg.tokenizer_kind == "hf" and cfg.tokenizer_path:
            self.tok = HfFastTokenizer(cfg.tokenizer_path)
        elif cfg.tokenizer_kind == "spm" and cfg.tokenizer_path:
            self.tok = SentencePieceTokenizer(cfg.tokenizer_path)
        else:
            self.tok = WhitespaceTokenizer()

    def normalize_text(self, text: str) -> str:
        if self.cfg.remove_control: text = strip_control(text)
        if self.cfg.normalize: text = norm_unicode(text, self.cfg.normalize)
        if self.cfg.lower: text = text.lower()
        if self.cfg.collapse_whitespace: text = collapse_ws(text)
        if self.cfg.redact_pii: text = redact_pii(text)
        if self.cfg.max_chars and len(text) > self.cfg.max_chars:
            if self.cfg.truncation_strategy == "tail":
                text = text[: self.cfg.max_chars]
            else:
                text = text[-self.cfg.max_chars :]
        if self.cfg.strip: text = text.strip()
        return text

    def tokenize(self, text: str) -> List[int]:
        ids = self.tok.tokenize(text) if self.tok else []
        if self.cfg.add_bos and getattr(self.tok, "bos_id", None):
            bid = self.tok.bos_id  # type: ignore
            if isinstance(bid, int): ids = [bid] + ids
        if self.cfg.add_eos and getattr(self.tok, "eos_id", None):
            eid = self.tok.eos_id  # type: ignore
            if isinstance(eid, int): ids = ids + [eid]
        if self.cfg.max_tokens and len(ids) > self.cfg.max_tokens:
            if self.cfg.truncation_strategy == "tail":
                ids = ids[: self.cfg.max_tokens]
            else:
                ids = ids[-self.cfg.max_tokens :]
        return ids

# =============================================================================
# Image preprocessor
# =============================================================================

class ImagePreprocessor:
    def __init__(self, cfg: ImageConfig):
        self.cfg = cfg
        if not _HAVE_PIL:
            raise RuntimeError("Pillow is required for image preprocessing")

    def _load(self, x: Union[str, Path, bytes, Image.Image]) -> Image.Image:
        if isinstance(x, Image.Image):
            img = x
        elif isinstance(x, (str, Path)):
            img = Image.open(x)  # type: ignore
        elif isinstance(x, (bytes, bytearray)):
            img = Image.open(io.BytesIO(x))  # type: ignore
        else:
            raise TypeError("Unsupported image input type")
        return img.convert(self.cfg.mode)

    def _resize_crop(self, img: Image.Image) -> Image.Image:
        w, h = img.size
        tw, th = self.cfg.target_size
        if self.cfg.center_crop:
            # scale preserving aspect, then center crop
            scale = max(tw / w, th / h)
            nw, nh = int(w * scale), int(h * scale)
            img = img.resize((nw, nh), Image.BICUBIC)
            left = (nw - tw) // 2
            top = (nh - th) // 2
            img = img.crop((left, top, left + tw, top + th))
            return img
        if self.cfg.letterbox:
            # pad to desired aspect
            scale = min(tw / w, th / h)
            nw, nh = int(w * scale), int(h * scale)
            img2 = Image.new(self.cfg.mode, (tw, th), (0,) if self.cfg.mode == "L" else (0, 0, 0))
            img = img.resize((nw, nh), Image.BICUBIC)
            left = (tw - nw) // 2
            top = (th - nh) // 2
            img2.paste(img, (left, top))
            return img2
        # simple resize
        return img.resize((tw, th), Image.BICUBIC)

    def to_array(self, img: Image.Image) -> Union["np.ndarray", "torch.Tensor"]:
        arr = np.asarray(img) if _HAVE_NUMPY else None
        if self.cfg.channels == 1:
            # HxW
            pass
        else:
            # HxWxC
            pass
        if self.cfg.to_float32:
            if _HAVE_TORCH and isinstance(arr, np.ndarray) and self.cfg.mean and self.cfg.std and self.cfg.channels == 3:
                # convert to torch CHW float32 for speed
                t = torch.from_numpy(arr).to(torch.float32) / 255.0  # type: ignore
                t = t.permute(2, 0, 1)  # CHW
                if self.cfg.mean and self.cfg.std:
                    mean = torch.tensor(self.cfg.mean).view(3, 1, 1)  # type: ignore
                    std = torch.tensor(self.cfg.std).view(3, 1, 1)   # type: ignore
                    t = (t - mean) / std
                return t
            if isinstance(arr, np.ndarray):
                arr = arr.astype("float32") / 255.0
                if self.cfg.mean and self.cfg.std and arr.ndim == 3 and arr.shape[2] == 3:
                    arr = (arr - np.array(self.cfg.mean, dtype="float32")) / np.array(self.cfg.std, dtype="float32")
        return arr  # type: ignore

    def preprocess(self, x: Union[str, Path, bytes, Image.Image]) -> Dict[str, Any]:
        img = self._load(x)
        img = self._resize_crop(img)
        arr = self.to_array(img)
        return {"image": arr, "size": img.size}

# =============================================================================
# Audio preprocessor
# =============================================================================

class AudioPreprocessor:
    def __init__(self, cfg: AudioConfig):
        self.cfg = cfg
        if not (_HAVE_LIBROSA or _HAVE_SF):
            raise RuntimeError("librosa or soundfile required for audio preprocessing")

    def _load(self, x: Union[str, Path, bytes]) -> Tuple["np.ndarray", int]:
        if isinstance(x, (str, Path)):
            if _HAVE_LIBROSA:
                y, sr = librosa.load(x, sr=self.cfg.sample_rate, mono=self.cfg.mono)  # type: ignore
                return y, sr
            if _HAVE_SF:
                y, sr = sf.read(x)  # type: ignore
            else:
                raise RuntimeError("No audio loader available")
        else:
            if not _HAVE_SF:
                raise RuntimeError("soundfile required for byte input")
            with io.BytesIO(x) as bio:
                y, sr = sf.read(bio)  # type: ignore
        if self.cfg.mono and y.ndim > 1:
            y = y.mean(axis=1)
        if sr != self.cfg.sample_rate and _HAVE_LIBROSA:
            y = librosa.resample(y, orig_sr=sr, target_sr=self.cfg.sample_rate)  # type: ignore
            sr = self.cfg.sample_rate
        return y.astype("float32"), sr  # type: ignore

    def _normalize_db(self, y: "np.ndarray", target_db: float) -> "np.ndarray":
        rms = np.sqrt(np.mean(y ** 2) + 1e-9)  # type: ignore
        db = 20 * math.log10(rms + 1e-9)
        gain = 10 ** ((target_db - db) / 20.0)
        return np.clip(y * gain, -1.0, 1.0)  # type: ignore

    def _log_mel(self, y: "np.ndarray", sr: int) -> "np.ndarray":
        if not _HAVE_LIBROSA:
            raise RuntimeError("librosa required for log-mel features")
        S = librosa.feature.melspectrogram(  # type: ignore
            y=y, sr=sr, n_fft=self.cfg.frame_length, hop_length=self.cfg.hop_length,
            n_mels=self.cfg.n_mels, fmin=self.cfg.fmin, fmax=self.cfg.fmax
        )
        logS = librosa.power_to_db(S, ref=np.max)  # type: ignore
        return logS.astype("float32")  # type: ignore

    def preprocess(self, x: Union[str, Path, bytes]) -> Dict[str, Any]:
        y, sr = self._load(x)
        if self.cfg.max_duration_sec:
            max_samples = int(self.cfg.sample_rate * self.cfg.max_duration_sec)
            if y.shape[0] > max_samples:
                y = y[:max_samples]
        if self.cfg.normalize_db is not None:
            y = self._normalize_db(y, self.cfg.normalize_db)
        if self.cfg.use_log_mel:
            feat = self._log_mel(y, sr)
            return {"audio": y, "features": feat, "sr": sr}
        return {"audio": y, "sr": sr}

# =============================================================================
# Collation / batching
# =============================================================================

def pad_to_multiple(length: int, multiple: int) -> int:
    return (length + multiple - 1) // multiple * multiple

class Collator:
    def __init__(self, cfg: CollateConfig):
        self.cfg = cfg

    def texts_to_batch(self, batch_ids: List[List[int]]) -> Dict[str, Any]:
        max_len = max((len(x) for x in batch_ids), default=0)
        if self.cfg.pad_to_multiple_of:
            max_len = pad_to_multiple(max_len, self.cfg.pad_to_multiple_of)
        if _HAVE_TORCH and self.cfg.return_tensors == "pt":
            input_ids = torch.full((len(batch_ids), max_len), self.cfg.pad_token_id, dtype=torch.long)  # type: ignore
            attention_mask = torch.zeros((len(batch_ids), max_len), dtype=torch.bool)  # type: ignore
            for i, ids in enumerate(batch_ids):
                L = len(ids)
                if L > 0:
                    input_ids[i, :L] = torch.tensor(ids, dtype=torch.long)  # type: ignore
                    attention_mask[i, :L] = True
            return {"input_ids": input_ids, "attention_mask": attention_mask, "lengths": [len(x) for x in batch_ids]}
        # numpy fallback
        if not _HAVE_NUMPY:
            raise RuntimeError("numpy required for non-torch collator")
        input_ids = np.full((len(batch_ids), max_len), self.cfg.pad_token_id, dtype=np.int64)  # type: ignore
        attention_mask = np.zeros((len(batch_ids), max_len), dtype=np.bool_)  # type: ignore
        for i, ids in enumerate(batch_ids):
            L = len(ids)
            if L > 0:
                input_ids[i, :L] = np.array(ids, dtype=np.int64)  # type: ignore
                attention_mask[i, :L] = True
        return {"input_ids": input_ids, "attention_mask": attention_mask, "lengths": [len(x) for x in batch_ids]}

    def images_to_batch(self, imgs: List[Union["np.ndarray","torch.Tensor"]]) -> Dict[str, Any]:
        if _HAVE_TORCH and isinstance(imgs[0], torch.Tensor):  # type: ignore
            x = torch.stack(imgs, dim=0)  # type: ignore
            return {"pixel_values": x}
        if not _HAVE_NUMPY:
            raise RuntimeError("numpy required for non-torch image batch")
        x = np.stack(imgs, axis=0)  # type: ignore
        return {"pixel_values": x}

    def audio_to_batch(self, arrs: List["np.ndarray"]) -> Dict[str, Any]:
        if not _HAVE_NUMPY:
            raise RuntimeError("numpy required for audio batch")
        max_len = max(a.shape[0] for a in arrs)
        batch = np.zeros((len(arrs), max_len), dtype="float32")  # type: ignore
        lengths = []
        for i, a in enumerate(arrs):
            L = a.shape[0]
            batch[i, :L] = a
            lengths.append(L)
        if _HAVE_TORCH and self.cfg.return_tensors == "pt":
            return {"audio": torch.from_numpy(batch), "lengths": lengths}  # type: ignore
        return {"audio": batch, "lengths": lengths}

# =============================================================================
# Safety filter for outputs
# =============================================================================

class OutputSanitizer:
    def __init__(self, cfg: SafetyConfig):
        self.cfg = cfg

    def sanitize(self, text: str) -> str:
        if self.cfg.remove_control_output:
            text = strip_control(text)
        if self.cfg.redact_pii_output:
            text = redact_pii(text)
        if self.cfg.max_output_chars and len(text) > self.cfg.max_output_chars:
            text = text[: self.cfg.max_output_chars]
        return text

# =============================================================================
# Public pre-processing orchestrators
# =============================================================================

class Preprocessor:
    def __init__(self, cfg: PrePostConfig):
        self.cfg = cfg
        self.text = TextPreprocessor(cfg.text)
        self.collate = Collator(cfg.collate)
        self.image = ImagePreprocessor(cfg.image) if _HAVE_PIL else None
        self.audio = AudioPreprocessor(cfg.audio) if (_HAVE_LIBROSA or _HAVE_SF) else None

    # Text
    def prepare_texts(self, inputs: Sequence[str]) -> Dict[str, Any]:
        norm = [self.text.normalize_text(s) for s in inputs]
        if self.cfg.safety.redact_pii_input:
            norm = [redact_pii(s) for s in norm]
        token_ids = [self.text.tokenize(s) for s in norm]
        batch = self.collate.texts_to_batch(token_ids)
        batch["raw_text"] = norm
        batch["cache_key"] = stable_hash({"t": "txt", "cfg": self.cfg.text.model_dump(), "in": norm})
        return batch

    # Images
    def prepare_images(self, inputs: Sequence[Union[str, Path, bytes, "Image.Image"]]) -> Dict[str, Any]:
        if not self.image:
            raise RuntimeError("Image preprocessor is not available")
        items = [self.image.preprocess(x) for x in inputs]
        tensors = [it["image"] for it in items]
        batch = self.collate.images_to_batch(tensors)
        batch["sizes"] = [it["size"] for it in items]
        batch["cache_key"] = stable_hash({"t": "img", "cfg": self.cfg.image.model_dump(), "n": len(inputs)})
        return batch

    # Audio
    def prepare_audio(self, inputs: Sequence[Union[str, Path, bytes]]) -> Dict[str, Any]:
        if not self.audio:
            raise RuntimeError("Audio preprocessor is not available")
        items = [self.audio.preprocess(x) for x in inputs]
        arrs = [it["features"] if "features" in it else it["audio"] for it in items]
        batch = self.collate.audio_to_batch(arrs)  # type: ignore
        batch["sr"] = [it.get("sr") for it in items]
        batch["cache_key"] = stable_hash({"t": "aud", "cfg": self.cfg.audio.model_dump(), "n": len(inputs)})
        return batch

# =============================================================================
# Post-processing utilities
# =============================================================================

def softmax_logits(logits: Union["np.ndarray","torch.Tensor"], axis: int = -1) -> Union["np.ndarray","torch.Tensor"]:
    if _HAVE_TORCH and isinstance(logits, torch.Tensor):  # type: ignore
        m = logits.max(dim=axis, keepdim=True).values
        e = (logits - m).exp()
        return e / e.sum(dim=axis, keepdim=True)
    if not _HAVE_NUMPY:
        raise RuntimeError("numpy required")
    m = np.max(logits, axis=axis, keepdims=True)  # type: ignore
    e = np.exp(logits - m)  # type: ignore
    return e / np.sum(e, axis=axis, keepdims=True)  # type: ignore

def l2_normalize(x: Union["np.ndarray","torch.Tensor"], axis: int = -1, eps: float = 1e-12):
    if _HAVE_TORCH and isinstance(x, torch.Tensor):  # type: ignore
        n = torch.linalg.norm(x, dim=axis, keepdim=True).clamp_min(eps)
        return x / n
    if not _HAVE_NUMPY:
        raise RuntimeError("numpy required")
    n = np.linalg.norm(x, axis=axis, keepdims=True)
    n = np.maximum(n, eps)
    return x / n  # type: ignore

class LlmPostprocessor:
    def __init__(self, tokenizer: Optional[BaseTokenizer], safety: OutputSanitizer):
        self.tk = tokenizer
        self.safety = safety

    def detok(self, ids: List[int]) -> str:
        if self.tk is None:
            return "<no-tokenizer>"
        try:
            return self.tk.detokenize(ids)
        except Exception:
            return "<decode-error>"

    def format_chat_completion(
        self,
        model_name: str,
        sequences: List[List[int]],
        finish_reasons: Optional[List[str]] = None,
        usage: Optional[Dict[str, int]] = None,
    ) -> Dict[str, Any]:
        choices = []
        for i, ids in enumerate(sequences):
            text = self.detok(ids)
            text = self.safety.sanitize(text)
            choices.append({
                "index": i,
                "message": {"role": "assistant", "content": text},
                "finish_reason": (finish_reasons[i] if finish_reasons and i < len(finish_reasons) else "stop"),
            })
        return {
            "id": str(uuid.uuid4()),
            "model": model_name,
            "choices": choices,
            "created": int(uuid.uuid4().int % 10**10),  # placeholder monotonic-ish
            "usage": usage or {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        }

class EmbeddingsPostprocessor:
    def __init__(self, normalize: bool = True):
        self.normalize = normalize

    def format_embeddings(self, model_name: str, batch_embeddings: Union["np.ndarray","torch.Tensor"]) -> Dict[str, Any]:
        if self.normalize:
            batch_embeddings = l2_normalize(batch_embeddings, axis=-1)
        if _HAVE_TORCH and isinstance(batch_embeddings, torch.Tensor):  # type: ignore
            arr = batch_embeddings.detach().cpu().tolist()  # type: ignore
            dim = batch_embeddings.shape[-1]  # type: ignore
        else:
            arr = batch_embeddings.tolist()  # type: ignore
            dim = len(arr[0]) if arr else 0
        return {"model": model_name, "embeddings": arr, "dim": dim}

class ClassificationPostprocessor:
    def __init__(self, labels: List[str], top_k: int = 5):
        self.labels = labels
        self.top_k = top_k

    def format_classification(
        self, logits: Union["np.ndarray","torch.Tensor"]
    ) -> List[Dict[str, Union[str, float]]]:
        probs = softmax_logits(logits, axis=-1)
        if _HAVE_TORCH and isinstance(probs, torch.Tensor):  # type: ignore
            topv, topi = torch.topk(probs, k=min(self.top_k, probs.shape[-1]))  # type: ignore
            topv = topv.cpu().tolist()  # type: ignore
            topi = topi.cpu().tolist()  # type: ignore
        else:
            # numpy path
            idx = np.argsort(-probs, axis=-1)[..., : self.top_k]  # type: ignore
            vals = np.take_along_axis(probs, idx, axis=-1)  # type: ignore
            topi, topv = idx.tolist(), vals.tolist()  # type: ignore
        out = []
        for i, v in zip(topi[0], topv[0]):  # assume batch=1 for formatting
            out.append({"label": self.labels[i] if i < len(self.labels) else str(i), "prob": float(v)})
        return out

# =============================================================================
# High-level convenience
# =============================================================================

class PrePost:
    """Facade to combine preprocessing and postprocessing in one object."""
    def __init__(self, cfg: Optional[PrePostConfig] = None):
        self.cfg = cfg or PrePostConfig()
        self.pre = Preprocessor(self.cfg)
        self.out = OutputSanitizer(self.cfg.safety)
        # expose tokenizer if available (for detokenization)
        self.tokenizer = self.pre.text.tok

    # TEXT
    def prepare_chat_messages(self, messages: Sequence[Dict[str, str]]) -> Dict[str, Any]:
        # Join messages into a single string if no chat template is provided
        joined = []
        for m in messages:
            role = m.get("role", "user")
            content = m.get("content", "")
            s = f"[{role}]: {content}"
            joined.append(s)
        return self.pre.prepare_texts(["\n".join(joined)])

    def post_chat(self, model_name: str, sequences: List[List[int]], usage: Optional[Dict[str, int]] = None) -> Dict[str, Any]:
        return LlmPostprocessor(self.tokenizer, self.out).format_chat_completion(model_name, sequences, usage=usage)

    # EMBEDDINGS
    def prepare_embeddings(self, inputs: Sequence[str]) -> Dict[str, Any]:
        return self.pre.prepare_texts(inputs)

    def post_embeddings(self, model_name: str, batch_embeddings: Union["np.ndarray","torch.Tensor"]) -> Dict[str, Any]:
        return EmbeddingsPostprocessor(normalize=True).format_embeddings(model_name, batch_embeddings)

    # IMAGES
    def prepare_images(self, inputs: Sequence[Union[str, Path, bytes, "Image.Image"]]) -> Dict[str, Any]:
        return self.pre.prepare_images(inputs)

    # AUDIO
    def prepare_audio(self, inputs: Sequence[Union[str, Path, bytes]]) -> Dict[str, Any]:
        return self.pre.prepare_audio(inputs)

# =============================================================================
# Example minimal usage (commented)
# =============================================================================
"""
cfg = PrePostConfig(
    text=TextConfig(
        tokenizer_kind="hf", tokenizer_path="tokenizer.json",
        max_tokens=2048, add_bos=False, add_eos=True, redact_pii=True
    ),
    image=ImageConfig(target_size=(224,224)),
    audio=AudioConfig(sample_rate=16000, use_log_mel=True),
    collate=CollateConfig(pad_token_id=0, pad_to_multiple_of=8, return_tensors="pt"),
    safety=SafetyConfig(redact_pii_output=True)
)
pp = PrePost(cfg)
# Prepare chat
batch = pp.prepare_chat_messages([{"role":"user","content":"Привет, мой email test@example.com"}])
# ... run model -> sequences (List[List[int]])
resp = pp.post_chat(model_name="nv-llm", sequences=[[1,2,3]])
# Prepare embeddings
emb_in = pp.prepare_embeddings(["текст 1", "текст 2"])
# Prepare images
img_in = pp.prepare_images(["/path/to/img.jpg"])
# Prepare audio
aud_in = pp.prepare_audio(["/path/to/audio.wav"])
"""
