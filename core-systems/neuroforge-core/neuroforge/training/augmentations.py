# -*- coding: utf-8 -*-
"""
neuroforge.training.augmentations
Промышленный модуль аугментаций для CV/NLP/Audio.

Ключевые возможности:
- Единый интерфейс Augmentation(sample, rng) -> sample (dict с ключами image|text|audio и метаданными).
- Воспроизводимость: RNG с seed, worker_init_fn, контроль детерминизма.
- Compose/RandomApply/Conditional, вероятности и отключение.
- Гибкая конфигурация: build_pipeline(config, modality) из dict/списка/omegaconf.
- Безопасная работа без torchvision/torchaudio: деградация до PIL/NumPy.
- Обработка изображений: Resize, CenterCrop, RandomResizedCrop, HFlip, ColorJitter, RandomErasing, Normalize, ToTensor.
- Обработка текста: Lowercase, Strip, WordDropout, CharNoise, Truncate.
- Обработка аудио: AddNoise, TimeShift, Volume, TimeMask (без torchaudio).
- Валидация размеров, защита от слишком больших входов.
- Расширяемость: реестр аугментаций и @register.

Пример конфигурации:
config = [
  {"name": "ImageRandomResizedCrop", "params": {"size": [224,224], "scale": [0.6, 1.0]}, "p": 1.0},
  {"name": "ImageHorizontalFlip", "params": {"p": 0.5}},
  {"name": "ImageColorJitter", "params": {"brightness": 0.2, "contrast": 0.2, "saturation": 0.2}, "p": 0.8},
  {"name": "ImageNormalize", "params": {"mean": [0.485,0.456,0.406], "std": [0.229,0.224,0.225]}},
]

pipeline = build_pipeline(config, modality="image", seed=1337)
sample = {"image": np.ndarray|PIL.Image.Image, "label": 1}
sample = pipeline(sample)  # применит аугментации
"""

from __future__ import annotations

import json
import logging
import math
import random
import warnings
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, List, Mapping, MutableMapping, Optional, Protocol, Sequence, Tuple, Union

import numpy as np

try:
    import torch  # type: ignore
    _HAS_TORCH = True
except Exception:
    torch = None  # type: ignore
    _HAS_TORCH = False

try:
    from PIL import Image, ImageEnhance  # type: ignore
    _HAS_PIL = True
except Exception:
    Image = None  # type: ignore
    ImageEnhance = None  # type: ignore
    _HAS_PIL = False

logger = logging.getLogger("neuroforge.training.augmentations")
logger.setLevel(logging.INFO)

Sample = Dict[str, Any]

# -------------------------
# RNG и воспроизводимость
# -------------------------

@dataclass
class RNG:
    """
    Универсальный генератор случайностей.
    """
    seed: int
    np_rng: np.random.Generator = field(init=False)
    torch_gen: Optional["torch.Generator"] = field(init=False, default=None)

    def __post_init__(self) -> None:
        self.np_rng = np.random.default_rng(self.seed)
        if _HAS_TORCH:
            g = torch.Generator()
            g.manual_seed(self.seed)
            self.torch_gen = g
        random.seed(self.seed)

    def rand(self) -> float:
        return float(self.np_rng.random())

    def randint(self, low: int, high: int) -> int:
        return int(self.np_rng.integers(low, high))

    def choice(self, seq: Sequence[Any]) -> Any:
        idx = self.randint(0, len(seq))
        return seq[idx]

    def normal(self, mean: float = 0.0, std: float = 1.0) -> float:
        return float(self.np_rng.normal(mean, std))

    def uniform(self, low: float, high: float) -> float:
        return float(self.np_rng.uniform(low, high))


def seed_everything(seed: int) -> None:
    random.seed(seed)
    np.random.seed(seed)
    if _HAS_TORCH:
        torch.manual_seed(seed)
        torch.cuda.manual_seed_all(seed)  # pragma: no cover
        torch.backends.cudnn.deterministic = True  # pragma: no cover
        torch.backends.cudnn.benchmark = False  # pragma: no cover


def worker_init_fn(worker_id: int) -> None:
    base_seed = int(np.random.SeedSequence().entropy)
    s = base_seed + worker_id
    seed_everything(s)


# -------------------------
# Базовый интерфейс и Compose
# -------------------------

class Augmentation(Protocol):
    def __call__(self, sample: Sample, rng: RNG) -> Sample: ...


@dataclass
class Compose(Augmentation):
    transforms: List[Augmentation]

    def __call__(self, sample: Sample, rng: RNG) -> Sample:
        for t in self.transforms:
            sample = t(sample, rng)
        return sample


@dataclass
class RandomApply(Augmentation):
    transform: Augmentation
    p: float = 0.5

    def __call__(self, sample: Sample, rng: RNG) -> Sample:
        if rng.rand() < self.p:
            return self.transform(sample, rng)
        return sample


# -------------------------
# Вспомогательные функции для изображений
# -------------------------

def _to_pil(img: Any) -> "Image.Image":
    if not _HAS_PIL:
        raise RuntimeError("Pillow (PIL) не установлен")
    if isinstance(img, Image.Image):
        return img
    arr = _to_numpy_image(img)
    if arr.dtype != np.uint8:
        arr = np.clip(arr, 0, 255).astype(np.uint8)
    return Image.fromarray(arr)

def _to_numpy_image(img: Any) -> np.ndarray:
    if isinstance(img, np.ndarray):
        return img
    if _HAS_PIL and isinstance(img, Image.Image):
        return np.array(img)
    if _HAS_TORCH and torch is not None and torch.is_tensor(img):  # type: ignore
        t = img.detach().cpu()
        if t.ndim == 3 and t.shape[0] in (1, 3):
            t = t.permute(1, 2, 0)  # CHW -> HWC
        arr = t.numpy()
        if arr.dtype in (np.float32, np.float64):
            arr = np.clip(arr * 255.0, 0, 255).astype(np.uint8)
        return arr
    raise TypeError(f"Unsupported image type: {type(img)}")

def _resize_pil(img: "Image.Image", size: Tuple[int, int]) -> "Image.Image":
    return img.resize(size, Image.BILINEAR)

def _center_crop_pil(img: "Image.Image", size: Tuple[int, int]) -> "Image.Image":
    w, h = img.size
    tw, th = size
    i = max(0, int(round((h - th) / 2.0)))
    j = max(0, int(round((w - tw) / 2.0)))
    return img.crop((j, i, j + tw, i + th))

def _random_resized_crop_pil(img: "Image.Image", size: Tuple[int, int], scale: Tuple[float, float], ratio: Tuple[float, float], rng: RNG) -> "Image.Image":
    w, h = img.size
    area = h * w
    for _ in range(10):
        target_area = area * rng.uniform(scale[0], scale[1])
        log_ratio = (math.log(ratio[0]), math.log(ratio[1]))
        aspect = math.exp(rng.uniform(log_ratio[0], log_ratio[1]))
        nw = int(round(math.sqrt(target_area * aspect)))
        nh = int(round(math.sqrt(target_area / aspect)))
        if 0 < nw <= w and 0 < nh <= h:
            i = 0 if h == nh else rng.randint(0, h - nh + 1)
            j = 0 if w == nw else rng.randint(0, w - nw + 1)
            return img.crop((j, i, j + nw, i + nh)).resize(size, Image.BILINEAR)
    return _center_crop_pil(_resize_pil(img, size), size)

def _hflip_pil(img: "Image.Image") -> "Image.Image":
    return img.transpose(Image.FLIP_LEFT_RIGHT)

def _color_jitter_pil(img: "Image.Image", brightness: float, contrast: float, saturation: float, rng: RNG) -> "Image.Image":
    out = img
    if brightness > 0:
        b = 1.0 + rng.uniform(-brightness, brightness)
        out = ImageEnhance.Brightness(out).enhance(max(0, b))
    if contrast > 0:
        c = 1.0 + rng.uniform(-contrast, contrast)
        out = ImageEnhance.Contrast(out).enhance(max(0, c))
    if saturation > 0:
        s = 1.0 + rng.uniform(-saturation, saturation)
        out = ImageEnhance.Color(out).enhance(max(0, s))
    return out


# -------------------------
# Изображения: аугментации
# -------------------------

@dataclass
class ImageResize(Augmentation):
    size: Tuple[int, int]

    def __call__(self, sample: Sample, rng: RNG) -> Sample:
        img = _to_pil(sample["image"])
        sample["image"] = _resize_pil(img, self.size)
        return sample

@dataclass
class ImageCenterCrop(Augmentation):
    size: Tuple[int, int]

    def __call__(self, sample: Sample, rng: RNG) -> Sample:
        img = _to_pil(sample["image"])
        sample["image"] = _center_crop_pil(img, self.size)
        return sample

@dataclass
class ImageRandomResizedCrop(Augmentation):
    size: Tuple[int, int]
    scale: Tuple[float, float] = (0.8, 1.0)
    ratio: Tuple[float, float] = (3.0 / 4.0, 4.0 / 3.0)

    def __call__(self, sample: Sample, rng: RNG) -> Sample:
        img = _to_pil(sample["image"])
        sample["image"] = _random_resized_crop_pil(img, self.size, self.scale, self.ratio, rng)
        return sample

@dataclass
class ImageHorizontalFlip(Augmentation):
    p: float = 0.5

    def __call__(self, sample: Sample, rng: RNG) -> Sample:
        img = _to_pil(sample["image"])
        if rng.rand() < self.p:
            img = _hflip_pil(img)
        sample["image"] = img
        return sample

@dataclass
class ImageColorJitter(Augmentation):
    brightness: float = 0.0
    contrast: float = 0.0
    saturation: float = 0.0

    def __call__(self, sample: Sample, rng: RNG) -> Sample:
        img = _to_pil(sample["image"])
        sample["image"] = _color_jitter_pil(img, self.brightness, self.contrast, self.saturation, rng)
        return sample

@dataclass
class ImageRandomErasing(Augmentation):
    p: float = 0.5
    scale: Tuple[float, float] = (0.02, 0.33)
    ratio: Tuple[float, float] = (0.3, 3.3)
    value: Optional[Union[int, Tuple[int, int, int]]] = None  # None -> random

    def __call__(self, sample: Sample, rng: RNG) -> Sample:
        if rng.rand() >= self.p:
            return sample
        arr = _to_numpy_image(sample["image"])
        h, w = arr.shape[:2]
        area = h * w
        for _ in range(10):
            target_area = rng.uniform(self.scale[0], self.scale[1]) * area
            log_ratio = (math.log(self.ratio[0]), math.log(self.ratio[1]))
            aspect = math.exp(rng.uniform(log_ratio[0], log_ratio[1]))
            eh = int(round(math.sqrt(target_area / aspect)))
            ew = int(round(math.sqrt(target_area * aspect)))
            if eh < h and ew < w and eh > 0 and ew > 0:
                i = rng.randint(0, h - eh + 1)
                j = rng.randint(0, w - ew + 1)
                if arr.ndim == 3:
                    if self.value is None:
                        v = np.array([rng.randint(0, 256), rng.randint(0, 256), rng.randint(0, 256)], dtype=arr.dtype)
                    elif isinstance(self.value, tuple):
                        v = np.array(self.value, dtype=arr.dtype)
                    else:
                        v = np.array([self.value] * 3, dtype=arr.dtype)
                    arr[i:i+eh, j:j+ew, :] = v
                else:
                    v = rng.randint(0, 256) if self.value is None else int(self.value)
                    arr[i:i+eh, j:j+ew] = v
                break
        sample["image"] = Image.fromarray(arr) if _HAS_PIL else arr
        return sample

@dataclass
class ImageNormalize(Augmentation):
    mean: Sequence[float]
    std: Sequence[float]

    def __call__(self, sample: Sample, rng: RNG) -> Sample:
        arr = _to_numpy_image(sample["image"]).astype(np.float32) / 255.0
        if arr.ndim == 2:
            arr = np.expand_dims(arr, -1)
        if len(self.mean) != arr.shape[-1] or len(self.std) != arr.shape[-1]:
            raise ValueError("mean/std channels mismatch")
        arr = (arr - np.array(self.mean)) / np.array(self.std)
        sample["image"] = arr  # хранить в float32 HWC
        return sample

@dataclass
class ImageToTensor(Augmentation):
    channels_first: bool = True

    def __call__(self, sample: Sample, rng: RNG) -> Sample:
        arr = _to_numpy_image(sample["image"])
        if arr.dtype != np.float32 and arr.max() > 1.0:
            arr = arr.astype(np.float32) / 255.0
        if arr.ndim == 2:
            arr = np.expand_dims(arr, -1)
        if self.channels_first:
            arr = np.transpose(arr, (2, 0, 1))  # HWC -> CHW
        if _HAS_TORCH:
            sample["image"] = torch.from_numpy(arr)
        else:
            sample["image"] = arr
        return sample


# -------------------------
# Текст: аугментации
# -------------------------

@dataclass
class TextLowercase(Augmentation):
    def __call__(self, sample: Sample, rng: RNG) -> Sample:
        t = sample.get("text")
        if isinstance(t, str):
            sample["text"] = t.lower()
        return sample

@dataclass
class TextStrip(Augmentation):
    def __call__(self, sample: Sample, rng: RNG) -> Sample:
        t = sample.get("text")
        if isinstance(t, str):
            sample["text"] = " ".join(t.strip().split())
        return sample

@dataclass
class TextWordDropout(Augmentation):
    p: float = 0.1
    min_len: int = 1

    def __call__(self, sample: Sample, rng: RNG) -> Sample:
        t = sample.get("text")
        if not isinstance(t, str):
            return sample
        words = t.split()
        if len(words) <= self.min_len:
            return sample
        kept = [w for w in words if rng.rand() > self.p]
        if len(kept) == 0:
            kept = [rng.choice(words)]
        sample["text"] = " ".join(kept)
        return sample

@dataclass
class TextCharNoise(Augmentation):
    p: float = 0.02
    alphabet: str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

    def __call__(self, sample: Sample, rng: RNG) -> Sample:
        t = sample.get("text")
        if not isinstance(t, str) or not t:
            return sample
        out = []
        for ch in t:
            r = rng.rand()
            if r < self.p / 3:
                # удаление
                continue
            elif r < 2 * self.p / 3:
                # заменa
                out.append(rng.choice(self.alphabet))
            elif r < self.p:
                # вставка
                out.append(ch)
                out.append(rng.choice(self.alphabet))
            else:
                out.append(ch)
        sample["text"] = "".join(out)
        return sample

@dataclass
class TextTruncate(Augmentation):
    max_len: int

    def __call__(self, sample: Sample, rng: RNG) -> Sample:
        t = sample.get("text")
        if isinstance(t, str) and len(t) > self.max_len:
            sample["text"] = t[: self.max_len]
        return sample


# -------------------------
# Аудио: аугментации (NumPy)
# -------------------------

@dataclass
class AudioAdditiveNoise(Augmentation):
    snr_db: float = 20.0  # целевой SNR
    clip: bool = True

    def __call__(self, sample: Sample, rng: RNG) -> Sample:
        x = sample.get("audio")
        if not isinstance(x, np.ndarray):
            return sample
        power = float(np.mean(x**2) + 1e-12)
        noise_power = power / (10 ** (self.snr_db / 10.0))
        noise = rng.np_rng.normal(0.0, math.sqrt(noise_power), size=x.shape).astype(x.dtype)
        y = x + noise
        if self.clip:
            y = np.clip(y, -1.0, 1.0)
        sample["audio"] = y
        return sample

@dataclass
class AudioTimeShift(Augmentation):
    max_shift: float = 0.1  # как доля длины, [-max,+max]

    def __call__(self, sample: Sample, rng: RNG) -> Sample:
        x = sample.get("audio")
        if not isinstance(x, np.ndarray) or x.ndim == 0:
            return sample
        n = x.shape[-1]
        k = int((rng.uniform(-self.max_shift, self.max_shift)) * n)
        sample["audio"] = np.roll(x, k, axis=-1)
        return sample

@dataclass
class AudioVolume(Augmentation):
    min_gain: float = 0.8
    max_gain: float = 1.2
    clip: bool = True

    def __call__(self, sample: Sample, rng: RNG) -> Sample:
        x = sample.get("audio")
        if not isinstance(x, np.ndarray):
            return sample
        g = rng.uniform(self.min_gain, self.max_gain)
        y = x * g
        if self.clip:
            y = np.clip(y, -1.0, 1.0)
        sample["audio"] = y
        return sample

@dataclass
class AudioTimeMask(Augmentation):
    max_mask_frac: float = 0.1  # доля длины, 0..1
    num_masks: int = 1
    value: float = 0.0

    def __call__(self, sample: Sample, rng: RNG) -> Sample:
        x = sample.get("audio")
        if not isinstance(x, np.ndarray):
            return sample
        n = x.shape[-1]
        y = x.copy()
        L = max(1, int(n * self.max_mask_frac))
        for _ in range(self.num_masks):
            if L <= 1:
                break
            start = rng.randint(0, max(1, n - L + 1))
            length = rng.randint(1, L + 1)
            y[..., start : start + length] = self.value
        sample["audio"] = y
        return sample


# -------------------------
# Регистрация и билдер
# -------------------------

_REGISTRY: Dict[str, Callable[..., Augmentation]] = {}

def register(name: str) -> Callable[[Callable[..., Augmentation]], Callable[..., Augmentation]]:
    def deco(cls_or_fn: Callable[..., Augmentation]) -> Callable[..., Augmentation]:
        _REGISTRY[name] = cls_or_fn
        return cls_or_fn
    return deco

# Регистрируем классы
register("Compose")(Compose)
register("RandomApply")(RandomApply)

register("ImageResize")(ImageResize)
register("ImageCenterCrop")(ImageCenterCrop)
register("ImageRandomResizedCrop")(ImageRandomResizedCrop)
register("ImageHorizontalFlip")(ImageHorizontalFlip)
register("ImageColorJitter")(ImageColorJitter)
register("ImageRandomErasing")(ImageRandomErasing)
register("ImageNormalize")(ImageNormalize)
register("ImageToTensor")(ImageToTensor)

register("TextLowercase")(TextLowercase)
register("TextStrip")(TextStrip)
register("TextWordDropout")(TextWordDropout)
register("TextCharNoise")(TextCharNoise)
register("TextTruncate")(TextTruncate)

register("AudioAdditiveNoise")(AudioAdditiveNoise)
register("AudioTimeShift")(AudioTimeShift)
register("AudioVolume")(AudioVolume)
register("AudioTimeMask")(AudioTimeMask)


def _instantiate(spec: Mapping[str, Any]) -> Augmentation:
    """
    Создает аугментацию из спецификации:
    - {"name": "ImageHorizontalFlip", "params": {"p": 0.5}}
    - {"name": "ImageColorJitter", "params": {...}, "p": 0.8}  (обернется RandomApply)
    """
    name = str(spec.get("name"))
    params = spec.get("params") or {}
    if name not in _REGISTRY:
        raise KeyError(f"Unknown augmentation: {name}")
    aug = _REGISTRY[name](**params)  # type: ignore
    p = spec.get("p", None)
    if p is not None and not isinstance(aug, RandomApply):
        aug = RandomApply(aug, float(p))
    return aug


def build_pipeline(config: Union[Mapping[str, Any], Sequence[Mapping[str, Any]]], modality: str, seed: int = 1337) -> Callable[[Sample], Sample]:
    """
    Строит пайплайн аугментаций.
    - config: dict или список dict'ов. Если dict и name=Compose, params.transforms=...
    - modality: "image"|"text"|"audio" (не влияет на выполнение, только для логов).
    - seed: детерминизм.

    Возвращает функцию apply(sample) -> sample.
    """
    if isinstance(config, Mapping):
        # Поддержка OmegaConf/DictConfig
        try:
            cfg_json = json.loads(json.dumps(config, default=lambda o: o.__dict__))  # нормализация
        except Exception:
            cfg_json = dict(config)
        config_list = [cfg_json] if "name" in cfg_json else cfg_json.get("transforms", [])
    else:
        config_list = list(config)

    transforms: List[Augmentation] = []
    for spec in config_list:
        try:
            transforms.append(_instantiate(spec))
        except Exception as e:
            logger.error("Failed to instantiate augmentation %s: %s", spec, e)
            raise

    compose = Compose(transforms)
    rng = RNG(seed=seed)

    def apply(sample: Sample) -> Sample:
        try:
            return compose(sample, rng)
        except Exception as e:
            # Безопасный лог ошибки; не выбрасываем секретные данные
            logger.exception("Augmentation error in modality=%s: %s", modality, e)
            raise
    return apply


# -------------------------
# Ограничители и валидация
# -------------------------

def ensure_image_within(sample: Sample, max_hw: Tuple[int, int] = (4096, 4096)) -> Sample:
    """
    Грубая защита от слишком больших изображений (OOM).
    """
    try:
        arr = _to_numpy_image(sample["image"])
        h, w = arr.shape[:2]
        if h > max_hw[0] or w > max_hw[1]:
            scale = min(max_hw[0] / float(h), max_hw[1] / float(w))
            nh, nw = max(1, int(h * scale)), max(1, int(w * scale))
            if _HAS_PIL:
                sample["image"] = _resize_pil(Image.fromarray(arr), (nw, nh))
            else:
                # nearest neighbor
                ys = np.linspace(0, h - 1, nh).astype(np.int32)
                xs = np.linspace(0, w - 1, nw).astype(np.int32)
                sample["image"] = arr[ys][:, xs]
    except Exception:
        pass
    return sample


__all__ = [
    "RNG", "seed_everything", "worker_init_fn",
    "Augmentation", "Compose", "RandomApply",
    # image
    "ImageResize", "ImageCenterCrop", "ImageRandomResizedCrop", "ImageHorizontalFlip",
    "ImageColorJitter", "ImageRandomErasing", "ImageNormalize", "ImageToTensor",
    # text
    "TextLowercase", "TextStrip", "TextWordDropout", "TextCharNoise", "TextTruncate",
    # audio
    "AudioAdditiveNoise", "AudioTimeShift", "AudioVolume", "AudioTimeMask",
    # build
    "build_pipeline", "ensure_image_within",
]
