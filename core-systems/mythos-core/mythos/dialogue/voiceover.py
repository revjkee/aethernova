# mythos-core/mythos/dialogue/voiceover.py
# -*- coding: utf-8 -*-
"""
Промышленный модуль синтеза речи (voiceover) для Mythos Core.

Ключевые возможности:
- Единый интерфейс TTS-адаптеров и оркестратор VoiceoverService.
- Нормализация текста и поддержка SSML; сегментация длинных реплик.
- Параллельный синтез сегментов с дисковым кэшем по SHA-256.
- Таймауты, ограничение параллелизма, трассировка, структурные логи.
- Склейка WAV с межсегментной паузой и опциональной RMS-нормализацией.
- Тестовый адаптер LocalWaveAdapter (синус для CI) и каркас CloudTTSAdapter.

Совместимость: Python 3.10+
Внешние зависимости: отсутствуют (опционально structlog; graceful fallback).
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import io
import json
import math
import os
import re
import struct
import time
import wave
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple, Union
from uuid import uuid4

# ---------- Логи: structlog -> logging fallback ----------
try:
    import structlog

    def _configure_logging():
        structlog.configure(
            processors=[
                structlog.processors.TimeStamper(fmt="iso", utc=True),
                structlog.processors.add_log_level,
                structlog.processors.StackInfoRenderer(),
                structlog.processors.format_exc_info,
                structlog.processors.JSONRenderer(),
            ]
        )
        return structlog.get_logger("mythos.voiceover")

    log = _configure_logging()
except Exception:  # pragma: no cover
    import logging

    logging.basicConfig(level="INFO", format="%(asctime)s %(levelname)s %(name)s %(message)s")
    log = logging.getLogger("mythos.voiceover")


# ---------- Ошибки ----------
class VoiceoverError(RuntimeError):
    pass


class ValidationError(VoiceoverError):
    pass


class EngineError(VoiceoverError):
    pass


class TimeoutError(VoiceoverError):  # noqa: A001
    pass


# ---------- Модели ----------
@dataclass(frozen=True)
class VoiceProfile:
    voice_id: str = "default"
    language: str = "ru-RU"  # BCP-47
    gender: Optional[str] = None
    style: Optional[str] = None
    speaking_rate: float = 1.0  # 0.5..2.0
    pitch_semitones: float = 0.0  # -12..+12
    volume_gain_db: float = 0.0  # -96..+16


@dataclass(frozen=True)
class SynthesisRequest:
    text: Optional[str] = None
    ssml: Optional[str] = None
    profile: VoiceProfile = field(default_factory=VoiceProfile)
    sample_rate_hz: int = 22050
    channels: int = 1
    fmt: str = "wav"
    # Оркестрация
    gap_silence_ms: int = 50
    normalize_rms: bool = True
    target_rms_dbfs: float = -20.0
    # Ограничители
    max_chars_per_chunk: int = 800
    max_segments: int = 200
    max_concurrency: int = 4
    request_timeout_sec: float = 30.0
    # Трассировка
    trace_id: str = field(default_factory=lambda: str(uuid4()))

    def __post_init__(self):
        if (self.text is None and self.ssml is None) or (self.text and self.ssml):
            raise ValidationError("Укажите либо text, либо ssml.")
        if self.sample_rate_hz not in (16000, 22050, 24000, 44100, 48000):
            raise ValidationError("Недопустимая частота дискретизации.")
        if self.channels not in (1, 2):
            raise ValidationError("Поддерживаются 1 или 2 канала.")
        if not (0.5 <= self.profile.speaking_rate <= 2.0):
            raise ValidationError("speaking_rate должен быть 0.5..2.0")
        if not (-12.0 <= self.profile.pitch_semitones <= 12.0):
            raise ValidationError("pitch_semitones должен быть -12..+12")
        if self.fmt.lower() != "wav":
            raise ValidationError("Базовый движок поддерживает только WAV.")


@dataclass(frozen=True)
class SynthesisSegment:
    text: Optional[str]
    ssml: Optional[str]
    index: int


@dataclass
class SynthesisResult:
    output_path: Path
    duration_sec: float
    sample_rate_hz: int
    channels: int
    trace_id: str
    from_cache: bool
    segments: List[Dict[str, Any]] = field(default_factory=list)


# ---------- Интерфейс адаптера ----------
class TTSAdapter(ABC):
    @abstractmethod
    async def synthesize_segment(
        self, seg: SynthesisSegment, req: SynthesisRequest, *, cache_key: str
    ) -> Tuple[Path, float]:
        """
        Должен вернуть путь к WAV-файлу сегмента и его длительность, сек.
        Оркестратор сам выполнит кэширование финального результата.
        """
        raise NotImplementedError

    @property
    def name(self) -> str:
        return self.__class__.__name__


# ---------- Тестовый адаптер ----------
class LocalWaveAdapter(TTSAdapter):
    """
    Генератор WAV-сигнала (синус) на основе содержания — для тестов/CI.
    """

    def __init__(self, base_cache_dir: Union[str, Path]):
        self.base = Path(base_cache_dir)

    async def synthesize_segment(
        self, seg: SynthesisSegment, req: SynthesisRequest, *, cache_key: str
    ) -> Tuple[Path, float]:
        content = seg.ssml or seg.text or ""
        length = max(1, len(_strip_tags(content)))
        duration = max(0.25, length / 90.0)
        freq = 200.0 + (hash(content) % 300)  # 200..500 Гц
        path = self._segment_path(cache_key, seg.index, req)
        if path.exists():
            return path, _wav_duration(path)
        _ensure_dir(path.parent)
        _generate_sine_wav(
            path,
            duration_sec=duration,
            sr=req.sample_rate_hz,
            ch=req.channels,
            freq=freq,
            gain_db=req.profile.volume_gain_db,
        )
        return path, duration

    def _segment_path(self, key: str, index: int, req: SynthesisRequest) -> Path:
        sub = key[:2]
        return self.base / "segments" / sub / key / f"{index:06d}_{req.sample_rate_hz}Hz_{req.channels}ch.wav"


# ---------- Оркестратор ----------
class VoiceoverService:
    def __init__(
        self,
        adapter: TTSAdapter,
        *,
        cache_dir: Union[str, Path] = ".cache/voiceover",
        max_parallel_default: int = 4,
    ) -> None:
        self.adapter = adapter
        self.cache_dir = Path(cache_dir)
        self.max_parallel_default = max_parallel_default
        _ensure_dir(self.cache_dir)

    async def synthesize_to_file(
        self,
        req: SynthesisRequest,
        *,
        output_path: Optional[Union[str, Path]] = None,
    ) -> SynthesisResult:
        started = time.time()
        cache_key = self._request_cache_key(req)
        out_path = Path(output_path) if output_path else self._final_path(cache_key, req)

        # Хит финального кэша
        if out_path.exists():
            dur = _wav_duration(out_path)
            log.info(
                "voiceover.cache.hit",
                where="final",
                adapter=self.adapter.name,
                path=str(out_path),
                trace_id=req.trace_id,
                duration=dur,
            )
            return SynthesisResult(
                output_path=out_path,
                duration_sec=dur,
                sample_rate_hz=req.sample_rate_hz,
                channels=req.channels,
                trace_id=req.trace_id,
                from_cache=True,
                segments=self._load_segments_meta(cache_key),
            )

        # Сегментация
        segments = self._segmentize(req)
        if len(segments) > req.max_segments:
            raise ValidationError(f"Слишком много сегментов: {len(segments)} > {req.max_segments}")

        sem = asyncio.Semaphore(max(1, min(req.max_concurrency, self.max_parallel_default)))

        async def synth_one(seg: SynthesisSegment) -> Tuple[Path, float, SynthesisSegment]:
            async with sem:
                with _timeout(req.request_timeout_sec):
                    p, d = await self.adapter.synthesize_segment(seg, req, cache_key=cache_key)
                    return p, d, seg

        try:
            seg_paths = await asyncio.gather(*[synth_one(s) for s in segments])
        except asyncio.TimeoutError as ex:
            raise TimeoutError("Превышен таймаут синтеза сегмента") from ex
        except Exception as ex:  # noqa: BLE001
            raise EngineError(f"Сбой адаптера {self.adapter.name}: {ex}") from ex

        # Склейка WAV
        sr = req.sample_rate_hz
        ch = req.channels
        wav_inputs = [p for p, _d, _s in seg_paths]
        silence_ms = max(0, int(req.gap_silence_ms))
        _ensure_dir(out_path.parent)
        duration = _concat_wavs(wav_inputs, out_path, sr, ch, inter_gap_ms=silence_ms)

        # RMS-нормализация итогового файла при необходимости
        if req.normalize_rms:
            _normalize_wav_rms_inplace(out_path, sr, ch, target_dbfs=req.target_rms_dbfs)

        # Метаданные сегментов
        seg_meta = [
            {
                "index": s.index,
                "path": str(p),
                "duration": float(d if d > 0 else _wav_duration(p)),
                "text": s.text,
                "ssml": s.ssml,
            }
            for (p, d, s) in seg_paths
        ]
        self._save_segments_meta(cache_key, seg_meta)

        log.info(
            "voiceover.done",
            adapter=self.adapter.name,
            trace_id=req.trace_id,
            duration=duration,
            segments=len(seg_paths),
            out=str(out_path),
            elapsed=round(time.time() - started, 3),
        )

        return SynthesisResult(
            output_path=out_path,
            duration_sec=duration,
            sample_rate_hz=sr,
            channels=ch,
            trace_id=req.trace_id,
            from_cache=False,
            segments=seg_meta,
        )

    # ---------- Внутренние вспомогательные ----------

    def _segmentize(self, req: SynthesisRequest) -> List[SynthesisSegment]:
        if req.ssml:
            chunks = _split_ssml(req.ssml, max_chars=req.max_chars_per_chunk)
            return [SynthesisSegment(text=None, ssml=c, index=i) for i, c in enumerate(chunks)]
        assert req.text is not None
        clean = _normalize_text(req.text)
        chunks = _split_text(clean, max_chars=req.max_chars_per_chunk)
        # Оборачиваем в SSML при наличии темпа/тона
        if req.profile.speaking_rate != 1.0 or req.profile.pitch_semitones != 0.0 or req.profile.volume_gain_db != 0.0:
            ssml_chunks = [
                _wrap_ssml(
                    c,
                    rate=req.profile.speaking_rate,
                    pitch_semitones=req.profile.pitch_semitones,
                    gain_db=req.profile.volume_gain_db,
                    lang=req.profile.language,
                )
                for c in chunks
            ]
            return [SynthesisSegment(text=None, ssml=s, index=i) for i, s in enumerate(ssml_chunks)]
        return [SynthesisSegment(text=c, ssml=None, index=i) for i, c in enumerate(chunks)]

    def _request_cache_key(self, req: SynthesisRequest) -> str:
        payload = {
            "adapter": self.adapter.name,
            "text": req.text,
            "ssml": req.ssml,
            "profile": asdict(req.profile),
            "sr": req.sample_rate_hz,
            "ch": req.channels,
            "fmt": req.fmt.lower(),
            "chunk": req.max_chars_per_chunk,
            "gap": req.gap_silence_ms,
            "norm": req.normalize_rms,
            "target": req.target_rms_dbfs,
        }
        raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()

    def _final_path(self, key: str, req: SynthesisRequest) -> Path:
        sub = key[:2]
        name = f"{key}_{req.sample_rate_hz}Hz_{req.channels}ch.{req.fmt.lower()}"
        return self.cache_dir / "final" / sub / name

    def _segments_meta_path(self, key: str) -> Path:
        sub = key[:2]
        return self.cache_dir / "final" / sub / f"{key}.segments.json"

    def _save_segments_meta(self, key: str, meta: List[Dict[str, Any]]) -> None:
        p = self._segments_meta_path(key)
        _ensure_dir(p.parent)
        p.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")

    def _load_segments_meta(self, key: str) -> List[Dict[str, Any]]:
        p = self._segments_meta_path(key)
        if p.exists():
            try:
                return json.loads(p.read_text(encoding="utf-8"))
            except Exception:
                return []
        return []


# ---------- Нормализация, сегментация, SSML ----------

_WS_RE = re.compile(r"\s+")
_SENT_SPLIT_RE = re.compile(r"(?<=[\.\?\!\u2026][\"”»\)]?)(\s+)")

def _normalize_text(text: str) -> str:
    t = text.strip()
    t = _WS_RE.sub(" ", t)
    return t

def _split_text(text: str, max_chars: int) -> List[str]:
    if len(text) <= max_chars:
        return [text]
    parts: List[str] = []
    sentences = [s.strip() for s in _SENT_SPLIT_RE.split(text) if s.strip() and not s.isspace()]
    buf = ""
    for s in sentences:
        if len(buf) + (1 if buf else 0) + len(s) <= max_chars:
            buf = f"{buf} {s}".strip()
        else:
            if buf:
                parts.append(buf)
            if len(s) <= max_chars:
                buf = s
            else:
                # делим по словам
                cur = ""
                for w in s.split(" "):
                    if len(cur) + (1 if cur else 0) + len(w) <= max_chars:
                        cur = f"{cur} {w}".strip()
                    else:
                        if cur:
                            parts.append(cur)
                        cur = w
                if cur:
                    buf = cur
                else:
                    buf = ""
    if buf:
        parts.append(buf)
    return parts

def _wrap_ssml(text: str, rate: float, pitch_semitones: float, gain_db: float, lang: str) -> str:
    rate_pct = f"{int(round((rate - 1.0) * 100)):+d}%"
    pitch_st = f"{pitch_semitones:+.1f}st"
    gain = f"{gain_db:+.1f}dB"
    esc = _xml_escape(text)
    return f'<speak xml:lang="{lang}"><prosody rate="{rate_pct}" pitch="{pitch_st}" volume="{gain}">{esc}</prosody></speak>'

def _split_ssml(ssml: str, max_chars: int) -> List[str]:
    s = ssml.strip()
    if len(s) <= max_chars:
        return [s]
    # грубая сегментация по </p> либо по длине
    chunks: List[str] = []
    buf = ""
    for part in re.split(r"(?i)</p>", s):
        if not part.strip():
            continue
        if "</p>" not in part.lower():
            part = part + "</p>"
        if len(buf) + len(part) <= max_chars:
            buf += part
        else:
            if buf:
                chunks.append(buf)
            if len(part) <= max_chars:
                buf = part
            else:
                # fallback по длине
                for i in range(0, len(part), max_chars):
                    chunks.append(part[i : i + max_chars])
                buf = ""
    if buf:
        chunks.append(buf)
    return chunks

def _xml_escape(s: str) -> str:
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&apos;")
    )

def _strip_tags(s: str) -> str:
    return re.sub(r"<[^>]+>", "", s or "")


# ---------- WAV утилиты ----------

def _ensure_dir(p: Union[str, Path]) -> None:
    Path(p).mkdir(parents=True, exist_ok=True)

def _wav_duration(path: Path) -> float:
    with contextlib.closing(wave.open(str(path), "rb")) as w:
        frames = w.getnframes()
        rate = w.getframerate()
        return frames / float(rate or 1)

def _generate_sine_wav(
    path: Path,
    duration_sec: float,
    sr: int,
    ch: int,
    freq: float,
    *,
    gain_db: float = 0.0,
) -> None:
    nframes = int(duration_sec * sr)
    amplitude = int(max(100, min(30000, 30000 * (10 ** (gain_db / 20.0)))))
    with contextlib.closing(wave.open(str(path), "wb")) as w:
        w.setnchannels(ch)
        w.setsampwidth(2)  # 16-bit PCM
        w.setframerate(sr)
        for i in range(nframes):
            sample = int(amplitude * math.sin(2.0 * math.pi * freq * (i / sr)))
            frame = struct.pack("<h", sample)
            if ch == 2:
                frame = frame * 2
            w.writeframes(frame)

def _concat_wavs(
    inputs: List[Path],
    output: Path,
    sr: int,
    ch: int,
    *,
    inter_gap_ms: int = 0,
) -> float:
    """
    Склеивает WAV-файлы с одинаковыми параметрами.
    Вставляет тишину inter_gap_ms между сегментами для исключения щелчков.
    """
    _ensure_dir(output.parent)
    total_frames = 0
    silence_frames = int((max(0, inter_gap_ms) / 1000.0) * sr)
    silence = b"\x00\x00" * ch * silence_frames if silence_frames > 0 else b""
    with contextlib.closing(wave.open(str(output), "wb")) as out_w:
        out_w.setnchannels(ch)
        out_w.setsampwidth(2)
        out_w.setframerate(sr)
        first = True
        for inp in inputs:
            with contextlib.closing(wave.open(str(inp), "rb")) as in_w:
                if in_w.getframerate() != sr or in_w.getnchannels() != ch or in_w.getsampwidth() != 2:
                    raise EngineError(f"Несовместимые параметры WAV: {inp}")
                frames = in_w.readframes(in_w.getnframes())
                if not first and silence:
                    out_w.writeframes(silence)
                    total_frames += silence_frames
                out_w.writeframes(frames)
                total_frames += len(frames) // (2 * ch)
                first = False
    return total_frames / float(sr or 1)

def _normalize_wav_rms_inplace(path: Path, sr: int, ch: int, *, target_dbfs: float = -20.0) -> None:
    """
    Простая RMS-нормализация итогового WAV к целевому уровню dBFS.
    Не заменяет EBU R128, но даёт предсказуемую громкость.
    """
    # читаем весь файл
    with contextlib.closing(wave.open(str(path), "rb")) as w:
        if w.getframerate() != sr or w.getnchannels() != ch or w.getsampwidth() != 2:
            return
        n = w.getnframes()
        raw = w.readframes(n)
    if not raw:
        return
    # вычисляем RMS
    samples = struct.unpack("<" + "h" * (len(raw) // 2), raw)
    # моно или стерео — RMS считаем по всем сэмплам
    sq_sum = 0.0
    for s in samples:
        sq_sum += float(s) * float(s)
    rms = math.sqrt(sq_sum / max(1, len(samples)))
    if rms <= 0.0:
        return
    # текущий dBFS
    current_dbfs = 20.0 * math.log10(rms / 32768.0)
    gain_db = float(target_dbfs) - current_dbfs
    factor = 10.0 ** (gain_db / 20.0)
    # применяем коэффициент с клиппингом
    new_samples = []
    for s in samples:
        v = int(round(float(s) * factor))
        v = max(-32768, min(32767, v))
        new_samples.append(v)
    new_raw = struct.pack("<" + "h" * len(new_samples), *new_samples)
    # перезаписываем
    with contextlib.closing(wave.open(str(path), "wb")) as w:
        w.setnchannels(ch)
        w.setsampwidth(2)
        w.setframerate(sr)
        w.writeframes(new_raw)


# ---------- Таймауты ----------
@contextlib.asynccontextmanager
async def _timeout(seconds: float):
    if seconds is None or seconds <= 0:
        yield
        return
    try:
        task = asyncio.current_task()
        assert task is not None
        done = asyncio.Event()

        async def _watch():
            try:
                await asyncio.wait_for(done.wait(), timeout=seconds)
            except asyncio.TimeoutError:
                if not task.done():
                    task.cancel()

        watcher = asyncio.create_task(_watch())
        try:
            yield
        finally:
            done.set()
            with contextlib.suppress(asyncio.CancelledError):
                await watcher
    except asyncio.CancelledError as ex:
        raise asyncio.TimeoutError() from ex


# ---------- Пример использования ----------
"""
Пример:

    import asyncio
    from mythos.dialogue.voiceover import VoiceoverService, LocalWaveAdapter, VoiceProfile, SynthesisRequest

    async def main():
        adapter = LocalWaveAdapter(".cache/voiceover")
        svc = VoiceoverService(adapter, cache_dir=".cache/voiceover", max_parallel_default=4)

        req = SynthesisRequest(
            text="Добро пожаловать в Mythos Core. Это демонстрация озвучки.",
            profile=VoiceProfile(voice_id="test", language="ru-RU", speaking_rate=1.0),
            sample_rate_hz=22050,
            channels=1,
            fmt="wav",
            gap_silence_ms=60,
            normalize_rms=True,
            target_rms_dbfs=-20.0,
            max_chars_per_chunk=120,
            max_concurrency=4,
            request_timeout_sec=15.0,
        )

        res = await svc.synthesize_to_file(req)
        print("Готово:", res.output_path, res.duration_sec, "сек")

    if __name__ == "__main__":
        asyncio.run(main())
"""

# ---------- Каркас для облачного адаптера ----------
# class CloudTTSAdapter(TTSAdapter):
#     def __init__(self, base_cache_dir: Union[str, Path], endpoint: str, api_key: str):
#         self.base = Path(base_cache_dir)
#         self.endpoint = endpoint
#         self.api_key = api_key
#     async def synthesize_segment(self, seg: SynthesisSegment, req: SynthesisRequest, *, cache_key: str):
#         path = self.base / "segments" / cache_key[:2] / cache_key / f"{seg.index:06d}_{req.sample_rate_hz}Hz_{req.channels}ch.wav"
#         if path.exists():
#             return path, _wav_duration(path)
#         _ensure_dir(path.parent)
#         # Вызов REST/gRPC провайдера с таймаутом и записью в path
#         # with open(path, "wb") as f: f.write(audio_bytes)
#         return path, _wav_duration(path)
