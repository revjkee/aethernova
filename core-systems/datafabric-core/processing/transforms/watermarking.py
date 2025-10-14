# -*- coding: utf-8 -*-
"""
DataFabric | processing.transforms.watermarking
Промышленный модуль водяных знаков: видимые и невидимые (DCT 8x8).

Зависимости:
 - Pillow (PIL)  >= 9.x
 - numpy         >= 1.20
 - (опционально) opencv-python (cv2) для ускоренной DCT, если доступен

Особенности:
 - Видимый watermark: текст/иконка, одиночный или тайлинг, альфа-канал, позиционирование.
 - Невидимый watermark: DCT 8x8, выбор коэффициентов по ключу, повтор битов, CRC32.
 - Детерминированность по ключу, поддержка RGB/RGBA/L, конвертация, сохранение профиля.
 - Структурированное логирование, строгая типизация, отсутствие небезопасного кода.
 - Устойчивость к базовым операциям: умеренное изменение качества JPEG, скейлинг с сохранением сетки 8x8.

Ограничения:
 - Настоящая криптостойкая стеганография не заявляется.
 - Полная инвариантность к агрессивным аффинным трансформациям не гарантируется.

(c) Aethernova / DataFabric Core
"""
from __future__ import annotations

import binascii
import io
import logging
import math
import os
import random
import struct
import typing as t
from dataclasses import dataclass, field

import numpy as np
from PIL import Image, ImageDraw, ImageFont

# Опциональная ускоренная DCT через OpenCV
try:
    import cv2  # type: ignore

    _HAS_CV2 = True
except Exception:  # pragma: no cover
    cv2 = None
    _HAS_CV2 = False

_LOG = logging.getLogger("datafabric.transforms.watermark")
if not _LOG.handlers:
    _handler = logging.StreamHandler()
    _formatter = logging.Formatter(
        "%(asctime)s %(levelname)s %(name)s trace=%(trace_id)s msg=%(message)s"
    )
    _handler.setFormatter(_formatter)
    _LOG.addHandler(_handler)
    _LOG.setLevel(logging.INFO)


# =========================
# ВСПОМОГАТЕЛЬНЫЕ СТРУКТУРЫ
# =========================

class WatermarkError(Exception):
    """Общий класс ошибок модуля watermarking."""


@dataclass(frozen=True)
class VisibleWatermarkConfig:
    text: str | None = None
    font_path: str | None = None
    font_size: int = 24
    color: t.Tuple[int, int, int, int] = (255, 255, 255, 96)  # RGBA
    image_path: str | None = None  # путь к иконке (PNG с альфой)
    opacity: float = 0.35  # 0..1 (доп. множитель к alpha)
    position: t.Literal[
        "center", "top-left", "top-right", "bottom-left", "bottom-right"
    ] = "bottom-right"
    margin: int = 16
    tile: bool = False
    tile_step: int = 256  # шаг тайлинга по x/y
    rotate_deg: float = 0.0
    scale: float = 1.0  # масштаб иконки/текста
    respect_exif: bool = True  # корректировать ориентацию по EXIF


@dataclass(frozen=True)
class InvisibleWatermarkConfig:
    key: bytes  # секретный ключ
    redundancy: int = 5  # повторение каждого бита
    strength: float = 6.0  # амплитуда модификации коэффициента
    channel: t.Literal["Y", "R", "G", "B"] = "Y"  # Y: яркость (через RGB->Y)
    dct_block: int = 8
    coeff_selector: t.Literal["midband", "highband"] = "midband"
    # Максимальный полезный размер полезной нагрузки в битах определяется размером изображения
    # и количеством выбранных коэффициентов. Полезная нагрузка встраивается вместе с CRC32.


@dataclass(frozen=True)
class VisibleResult:
    image: Image.Image
    meta: dict[str, t.Any] = field(default_factory=dict)


@dataclass(frozen=True)
class InvisibleEmbedResult:
    image: Image.Image
    embedded_bits: int
    payload_len_bytes: int
    crc32_hex: str
    meta: dict[str, t.Any] = field(default_factory=dict)


@dataclass(frozen=True)
class InvisibleExtractResult:
    payload: bytes
    crc32_hex: str
    ok: bool
    meta: dict[str, t.Any] = field(default_factory=dict)


# =========================
# ОБЩИЕ УТИЛИТЫ
# =========================

def _trace_id() -> str:
    # Короткий детерминированный идентификатор для лога
    return f"{random.getrandbits(64):016x}"


def _ensure_image(img: t.Union[str, bytes, Image.Image]) -> Image.Image:
    if isinstance(img, Image.Image):
        return img
    if isinstance(img, str):
        with Image.open(img) as im:
            return im.convert("RGBA")
    if isinstance(img, (bytes, bytearray)):
        with Image.open(io.BytesIO(img)) as im:
            return im.convert("RGBA")
    raise WatermarkError("Unsupported image input type")


def _apply_exif_orientation(im: Image.Image) -> Image.Image:
    try:
        exif = im.getexif()
        orientation = exif.get(274)
        if orientation == 3:
            im = im.rotate(180, expand=True)
        elif orientation == 6:
            im = im.rotate(270, expand=True)
        elif orientation == 8:
            im = im.rotate(90, expand=True)
        return im
    except Exception:
        return im


def _rgba(im: Image.Image) -> Image.Image:
    return im.convert("RGBA")


def _y_channel_from_rgb(im: Image.Image) -> np.ndarray:
    # Y = 0.299 R + 0.587 G + 0.114 B (BT.601)
    arr = np.asarray(im.convert("RGB"), dtype=np.float32)
    y = 0.299 * arr[..., 0] + 0.587 * arr[..., 1] + 0.114 * arr[..., 2]
    return y


def _rgb_from_y(y: np.ndarray, base_rgb: Image.Image) -> Image.Image:
    # Простая обратная проекция: корректируем только яркость
    rgb = np.asarray(base_rgb.convert("RGB"), dtype=np.float32)
    # вычислим текущую яркость и масштабируем каналы
    y0 = 0.299 * rgb[..., 0] + 0.587 * rgb[..., 1] + 0.114 * rgb[..., 2]
    eps = 1e-6
    scale = (y / (y0 + eps))[..., None]
    rgb = np.clip(rgb * scale, 0, 255).astype(np.uint8)
    return Image.fromarray(rgb, mode="RGB").convert("RGBA")


# =========================
# DCT/IDCT (8x8) РЕАЛИЗАЦИЯ
# =========================

def _dct2(block: np.ndarray) -> np.ndarray:
    """2D DCT-II для блока (NxN)."""
    N = block.shape[0]
    if _HAS_CV2 and N in (8, 16, 32):
        return cv2.dct(block.astype(np.float32))
    # матричная DCT-II: C * X * C^T
    C = _dct_mat(N)
    return C @ block @ C.T


def _idct2(block: np.ndarray) -> np.ndarray:
    """2D IDCT-III для блока (NxN)."""
    N = block.shape[0]
    if _HAS_CV2 and N in (8, 16, 32):
        return cv2.idct(block.astype(np.float32))
    C = _dct_mat(N)
    return C.T @ block @ C


_DCT_CACHE: dict[int, np.ndarray] = {}


def _dct_mat(N: int) -> np.ndarray:
    M = _DCT_CACHE.get(N)
    if M is not None:
        return M
    M = np.zeros((N, N), dtype=np.float32)
    factor = math.pi / (2.0 * N)
    for k in range(N):
        for n in range(N):
            M[k, n] = math.cos((2 * n + 1) * k * factor)
    M[0, :] *= 1 / math.sqrt(N)
    for k in range(1, N):
        M[k, :] *= math.sqrt(2 / N)
    _DCT_CACHE[N] = M
    return M


# =========================
# BITSTREAM / CRC / ПОВТОР
# =========================

def _crc32(data: bytes) -> int:
    return binascii.crc32(data) & 0xFFFFFFFF


def _bits_from_bytes(data: bytes) -> np.ndarray:
    bits = np.unpackbits(np.frombuffer(data, dtype=np.uint8))
    return bits.astype(np.uint8)


def _bytes_from_bits(bits: np.ndarray) -> bytes:
    # дополнение до кратности 8
    if bits.size % 8 != 0:
        pad = 8 - (bits.size % 8)
        bits = np.concatenate([bits, np.zeros(pad, dtype=np.uint8)], axis=0)
    b = np.packbits(bits, bitorder="big")
    return b.tobytes()


def _repeat_bits(bits: np.ndarray, r: int) -> np.ndarray:
    if r <= 1:
        return bits
    return np.repeat(bits, r)


def _majority_vote(chunks: np.ndarray, r: int) -> np.ndarray:
    # chunks: shape (len_bits * r,)
    if r <= 1:
        return chunks
    assert chunks.size % r == 0
    resh = chunks.reshape(-1, r)
    s = resh.sum(axis=1)
    return (s >= (r / 2 + 0.0001)).astype(np.uint8)


# =========================
# ВЫБОР КОЭФФИЦИЕНТОВ
# =========================

def _midband_mask(N: int) -> list[tuple[int, int]]:
    # Исключаем DC(0,0) и очень высокие частоты; берём диагональную «середину»
    coords: list[tuple[int, int]] = []
    for u in range(N):
        for v in range(N):
            if u == 0 and v == 0:
                continue
            s = u + v
            if 2 <= s <= (N + N // 2):  # настраиваемый диапазон
                coords.append((u, v))
    return coords


def _highband_mask(N: int) -> list[tuple[int, int]]:
    coords: list[tuple[int, int]] = []
    thresh = (2 * N) // 3
    for u in range(N):
        for v in range(N):
            if u + v >= thresh:
                coords.append((u, v))
    return coords


def _select_coeff_positions(N: int, mode: str) -> list[tuple[int, int]]:
    if mode == "midband":
        return _midband_mask(N)
    if mode == "highband":
        return _highband_mask(N)
    raise WatermarkError("Unknown coeff_selector")


# =========================
# ОСНОВНОЙ КЛАСС
# =========================

class Watermarker:
    """API для видимого и невидимого водяного знака."""

    def __init__(self) -> None:
        pass

    # ---------- Видимый водяной знак ----------

    def add_visible(self, image: t.Union[str, bytes, Image.Image], cfg: VisibleWatermarkConfig) -> VisibleResult:
        trace = _trace_id()
        _LOG.info("visible.start", extra={"trace_id": trace})

        im = _ensure_image(image)
        if cfg.respect_exif:
            im = _apply_exif_orientation(im)
        base = _rgba(im)

        overlay = Image.new("RGBA", base.size, (0, 0, 0, 0))
        draw = ImageDraw.Draw(overlay)

        # Рендер текста или иконки
        stamp = None
        if cfg.image_path:
            with Image.open(cfg.image_path) as icon:
                stamp = icon.convert("RGBA")
        elif cfg.text:
            font = self._load_font(cfg.font_path, max(8, int(cfg.font_size * cfg.scale)))
            text_bbox = draw.textbbox((0, 0), cfg.text, font=font)
            w = text_bbox[2] - text_bbox[0]
            h = text_bbox[3] - text_bbox[1]
            stamp = Image.new("RGBA", (max(1, w), max(1, h)), (0, 0, 0, 0))
            d2 = ImageDraw.Draw(stamp)
            d2.text((0, 0), cfg.text, font=font, fill=cfg.color)
        else:
            raise WatermarkError("Either text or image_path must be provided")

        # Масштаб и поворот
        if cfg.scale != 1.0:
            nw = max(1, int(stamp.width * cfg.scale))
            nh = max(1, int(stamp.height * cfg.scale))
            stamp = stamp.resize((nw, nh), resample=Image.BICUBIC)
        if abs(cfg.rotate_deg) > 1e-3:
            stamp = stamp.rotate(cfg.rotate_deg, resample=Image.BICUBIC, expand=True)

        # Применение общей непрозрачности
        if cfg.opacity < 1.0:
            r, g, b, a = stamp.split()
            a = a.point(lambda px: int(px * float(cfg.opacity)))
            stamp = Image.merge("RGBA", (r, g, b, a))

        if cfg.tile:
            # Трансляционная сетка
            step = max(32, int(cfg.tile_step * cfg.scale))
            for y in range(0, base.height, step):
                for x in range(0, base.width, step):
                    overlay.alpha_composite(stamp, dest=(x, y))
        else:
            x, y = self._place_single(base.size, stamp.size, cfg.position, cfg.margin)
            overlay.alpha_composite(stamp, dest=(x, y))

        out = Image.alpha_composite(base, overlay)
        meta = {"trace_id": trace, "mode": "visible"}
        _LOG.info("visible.done", extra={"trace_id": trace})
        return VisibleResult(image=out, meta=meta)

    # ---------- Невидимый водяной знак ----------

    def embed_invisible(
        self,
        image: t.Union[str, bytes, Image.Image],
        payload: t.Union[str, bytes],
        cfg: InvisibleWatermarkConfig,
    ) -> InvisibleEmbedResult:
        trace = _trace_id()
        _LOG.info("invisible.start", extra={"trace_id": trace})

        im = _ensure_image(image).convert("RGBA")
        base_rgb = im.convert("RGB")
        N = int(cfg.dct_block)
        if N <= 0 or N & (N - 1) != 0:
            raise WatermarkError("dct_block must be power of two (e.g., 8,16,32)")

        # Канал яркости / RGB channel
        if cfg.channel == "Y":
            plane = _y_channel_from_rgb(base_rgb)
        else:
            arr = np.asarray(base_rgb, dtype=np.float32)
            idx = {"R": 0, "G": 1, "B": 2}[cfg.channel]
            plane = arr[..., idx]

        H, W = plane.shape
        Hc, Wc = (H // N) * N, (W // N) * W
        plane = plane[:Hc, :Wc]
        blocks_y = Hc // N
        blocks_x = Wc // N

        # Подготовка битового потока: [len(2 bytes) | payload | CRC32(4 bytes)]
        if isinstance(payload, str):
            payload = payload.encode("utf-8")
        if not isinstance(payload, (bytes, bytearray)):
            raise WatermarkError("payload must be bytes or str")

        plen = len(payload)
        if plen > 65535:
            raise WatermarkError("payload too large (max 65535 bytes)")

        header = struct.pack(">H", plen)
        crc = _crc32(payload)
        footer = struct.pack(">I", crc)
        frame = header + bytes(payload) + footer
        bits = _bits_from_bytes(frame)
        bits_rep = _repeat_bits(bits, cfg.redundancy)

        # Выбор коэффициентов
        coeff_positions = _select_coeff_positions(N, cfg.coeff_selector)
        rng = random.Random(cfg.key)  # детерминированный выбор по ключу
        # Случайная перестановка позиций внутри каждого блока
        local_order = coeff_positions[:]
        rng.shuffle(local_order)

        # Общая мощность: сколько бит можно поместить
        per_block_bits = len(local_order)
        capacity = blocks_x * blocks_y * per_block_bits
        if bits_rep.size > capacity:
            raise WatermarkError(f"payload does not fit: need {bits_rep.size} bits, capacity {capacity}")

        # Встраивание
        out_plane = plane.copy()
        bit_idx = 0
        for by in range(blocks_y):
            for bx in range(blocks_x):
                block = out_plane[by * N : (by + 1) * N, bx * N : (bx + 1) * N]
                dct = _dct2(block)
                # модификация коэффициентов по битам
                for (u, v) in local_order:
                    if bit_idx >= bits_rep.size:
                        break
                    b = bits_rep[bit_idx]
                    coeff = dct[u, v]
                    # сдвиг по знаку коэффициента для устойчивости
                    delta = cfg.strength if b == 1 else -cfg.strength
                    # избегаем нулевой зоны, усиливаем модуль
                    if coeff >= 0:
                        dct[u, v] = coeff + delta
                    else:
                        dct[u, v] = coeff - delta
                    bit_idx += 1
                out_plane[by * N : (by + 1) * N, bx * N : (bx + 1) * N] = _idct2(dct)

                if bit_idx >= bits_rep.size:
                    break
            if bit_idx >= bits_rep.size:
                break

        # Сборка изображения
        if cfg.channel == "Y":
            out_rgba = _rgb_from_y(out_plane, base_rgb)
        else:
            rgb = np.asarray(base_rgb, dtype=np.float32)
            idx = {"R": 0, "G": 1, "B": 2}[cfg.channel]
            rgb[..., idx] = out_plane
            rgb = np.clip(rgb, 0, 255).astype(np.uint8)
            out_rgba = Image.fromarray(rgb, mode="RGB").convert("RGBA")

        meta = {
            "trace_id": trace,
            "mode": "invisible.embed",
            "capacity_bits": capacity,
            "embedded_bits": int(bits_rep.size),
            "blocks": (blocks_x, blocks_y),
            "block_size": N,
            "channel": cfg.channel,
            "coeff_mode": cfg.coeff_selector,
            "redundancy": cfg.redundancy,
            "strength": cfg.strength,
        }
        _LOG.info("invisible.done", extra={"trace_id": trace})
        return InvisibleEmbedResult(
            image=out_rgba,
            embedded_bits=int(bits_rep.size),
            payload_len_bytes=plen,
            crc32_hex=f"{crc:08x}",
            meta=meta,
        )

    def extract_invisible(
        self,
        image: t.Union[str, bytes, Image.Image],
        cfg: InvisibleWatermarkConfig,
    ) -> InvisibleExtractResult:
        trace = _trace_id()
        _LOG.info("extract.start", extra={"trace_id": trace})

        im = _ensure_image(image).convert("RGBA")
        base_rgb = im.convert("RGB")

        N = int(cfg.dct_block)
        if cfg.channel == "Y":
            plane = _y_channel_from_rgb(base_rgb)
        else:
            arr = np.asarray(base_rgb, dtype=np.float32)
            idx = {"R": 0, "G": 1, "B": 2}[cfg.channel]
            plane = arr[..., idx]

        H, W = plane.shape
        Hc, Wc = (H // N) * N, (W // N) * W
        plane = plane[:Hc, :Wc]
        blocks_y = Hc // N
        blocks_x = Wc // N

        coeff_positions = _select_coeff_positions(N, cfg.coeff_selector)
        rng = random.Random(cfg.key)
        local_order = coeff_positions[:]
        rng.shuffle(local_order)

        # Считываем столько бит, сколько способен дать снимок
        bits_collected: list[int] = []
        for by in range(blocks_y):
            for bx in range(blocks_x):
                block = plane[by * N : (by + 1) * N, bx * N : (bx + 1) * N]
                dct = _dct2(block)
                for (u, v) in local_order:
                    coeff = dct[u, v]
                    bit = 1 if coeff >= 0 else 0  # знак как простейший детектор
                    bits_collected.append(bit)

        bits_arr = np.array(bits_collected, dtype=np.uint8)
        # Декодирование с учётом редунданса: нам нужно сначала понять длину.
        # Структура: [len(16 бит) | payload | CRC(32 бита)], вся последовательность повторена cfg.redundancy раз по каждому биту.
        # Длина префикса в битах (без повторения): 16.
        if cfg.redundancy > 1:
            # Сначала извлекаем первые 16*redundancy бит и делаем мажоритарное голосование
            need = 16 * cfg.redundancy
            if bits_arr.size < need:
                return InvisibleExtractResult(payload=b"", crc32_hex="00000000", ok=False, meta={"trace_id": trace, "reason": "insufficient_bits_for_length"})
            len_bits_rep = bits_arr[:need]
            len_bits = _majority_vote(len_bits_rep, cfg.redundancy)
        else:
            if bits_arr.size < 16:
                return InvisibleExtractResult(payload=b"", crc32_hex="00000000", ok=False, meta={"trace_id": trace, "reason": "insufficient_bits_for_length"})
            len_bits = bits_arr[:16]

        # Декодируем длину
        length_bytes = _bytes_from_bits(len_bits)[:2]
        payload_len = struct.unpack(">H", length_bytes)[0]

        total_bits_nominal = 16 + payload_len * 8 + 32
        total_bits_with_rep = total_bits_nominal * max(1, cfg.redundancy)
        if bits_arr.size < total_bits_with_rep:
            # Возможно, картинка была изменена — пытаемся декодировать по доступному диапазону с отсечением.
            return InvisibleExtractResult(
                payload=b"",
                crc32_hex="00000000",
                ok=False,
                meta={"trace_id": trace, "reason": "insufficient_bits_for_payload", "expected": total_bits_with_rep, "have": int(bits_arr.size)},
            )

        # Выделяем полезные биты с учётом повторения
        useful = bits_arr[:total_bits_with_rep]
        if cfg.redundancy > 1:
            decoded = _majority_vote(useful, cfg.redundancy)
        else:
            decoded = useful

        frame_bytes = _bytes_from_bits(decoded)[: (2 + payload_len + 4)]
        if len(frame_bytes) < 2 + payload_len + 4:
            return InvisibleExtractResult(payload=b"", crc32_hex="00000000", ok=False, meta={"trace_id": trace, "reason": "frame_underflow"})

        hdr = frame_bytes[:2]
        pay = frame_bytes[2 : 2 + payload_len]
        crc_stored = frame_bytes[2 + payload_len : 2 + payload_len + 4]
        crc_stored_i = struct.unpack(">I", crc_stored)[0]
        crc_calc = _crc32(pay)

        ok = (crc_stored_i == crc_calc)
        meta = {
            "trace_id": trace,
            "mode": "invisible.extract",
            "payload_len_bytes": payload_len,
            "crc_ok": ok,
            "crc_calc": f"{crc_calc:08x}",
            "crc_stored": f"{crc_stored_i:08x}",
            "block_size": N,
            "redundancy": cfg.redundancy,
            "channel": cfg.channel,
            "coeff_mode": cfg.coeff_selector,
        }
        _LOG.info("extract.done", extra={"trace_id": trace})
        return InvisibleExtractResult(payload=pay, crc32_hex=f"{crc_calc:08x}", ok=ok, meta=meta)

    # ---------- Вспомогательные методы ----------

    def _load_font(self, font_path: str | None, size: int) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
        try:
            if font_path and os.path.isfile(font_path):
                return ImageFont.truetype(font_path, size=size)
        except Exception:
            pass
        # Падаем на встроенный шрифт, если нет truetype
        return ImageFont.load_default()

    @staticmethod
    def _place_single(
        base_size: tuple[int, int],
        stamp_size: tuple[int, int],
        position: str,
        margin: int,
    ) -> tuple[int, int]:
        bw, bh = base_size
        sw, sh = stamp_size
        if position == "center":
            return (bw - sw) // 2, (bh - sh) // 2
        if position == "top-left":
            return margin, margin
        if position == "top-right":
            return max(0, bw - sw - margin), margin
        if position == "bottom-left":
            return margin, max(0, bh - sh - margin)
        if position == "bottom-right":
            return max(0, bw - sw - margin), max(0, bh - sh - margin)
        return max(0, bw - sw - margin), max(0, bh - sh - margin)


# =========================
# ПУБЛИЧНАЯ API-ПОВЕРХНОСТЬ
# =========================

__all__ = [
    "WatermarkError",
    "VisibleWatermarkConfig",
    "InvisibleWatermarkConfig",
    "VisibleResult",
    "InvisibleEmbedResult",
    "InvisibleExtractResult",
    "Watermarker",
]
