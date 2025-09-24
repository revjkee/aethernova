# physical_integration/video/ffmpeg_bridge.py
# Python 3.10+
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import shlex
import shutil
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, AsyncIterator, Awaitable, Callable, Dict, Iterable, List, Literal, Optional, Sequence, Tuple, Union

log = logging.getLogger(__name__)
log.addHandler(logging.NullHandler())

# =========================
# Exceptions
# =========================

class FFmpegError(RuntimeError):
    def __init__(self, message: str, *, args_line: Optional[str] = None, returncode: Optional[int] = None, stderr_tail: Optional[str] = None) -> None:
        super().__init__(message)
        self.args_line = args_line
        self.returncode = returncode
        self.stderr_tail = stderr_tail

class FFprobeError(RuntimeError):
    pass

class BinaryNotFoundError(RuntimeError):
    pass

class ValidationError(ValueError):
    pass

# =========================
# Dataclasses (configs)
# =========================

@dataclass(frozen=True)
class BridgeConfig:
    ffmpeg_path: Optional[Union[str, Path]] = None
    ffprobe_path: Optional[Union[str, Path]] = None
    env: Dict[str, str] = field(default_factory=dict)
    # Глобальные ограничения (страховочные)
    max_wall_seconds: int = 60 * 30            # 30 минут по умолчанию
    kill_grace_seconds: float = 3.0
    read_buffer_bytes: int = 1024 * 32
    # Ограничение ввода: что разрешено использовать как источник (безопасность)
    allowed_input_schemes: Tuple[str, ...] = ("file", "http", "https", "rtsp", "rtmp", "s3")
    # Максимальный размер превью по стороне (для скейла)
    thumbnail_max_px: int = 960

@dataclass(frozen=True)
class TranscodeConfig:
    video_codec: str = "libx264"
    audio_codec: str = "aac"
    crf: int = 23
    preset: str = "veryfast"
    tune: Optional[str] = None
    pix_fmt: str = "yuv420p"
    audio_bitrate: str = "128k"
    max_muxrate: Optional[str] = None
    movflags_faststart: bool = True
    copy_if_compatible: bool = True  # если исходные кодеки подходящие — только ремультиплексирование

@dataclass(frozen=True)
class HLSConfig:
    segment_time: int = 6
    playlist_size: int = 10
    fmp4: bool = False
    hls_flags: Tuple[str, ...] = ("independent_segments",)
    delete_segments: bool = False
    master_name: str = "master.m3u8"
    # вариант одного рендера (можно расширить до ABR-вариантов)
    variant_name: str = "index.m3u8"

@dataclass(frozen=True)
class ThumbnailConfig:
    interval_seconds: int = 10
    width: Optional[int] = None          # если None — масштаб по высоте/максимальной стороне
    height: Optional[int] = None
    pattern: str = "thumb-%06d.jpg"
    quality: int = 2                     # для mjpeg/автовыбора
    start_offset_seconds: int = 0

# =========================
# Helpers
# =========================

def _which(bin_name: str, explicit: Optional[Union[str, Path]] = None, env: Optional[Dict[str, str]] = None) -> str:
    # приоритет: явный путь -> env var -> PATH
    if explicit:
        p = Path(explicit)
        if p.exists():
            return str(p)
    env = env or os.environ
    for var in ("FFMPEG_BIN", "FFPROBE_BIN"):
        if bin_name in ("ffmpeg", "ffprobe") and var.startswith(bin_name.upper()):
            v = env.get(var)
            if v and Path(v).exists():
                return v
    found = shutil.which(bin_name)
    if not found:
        raise BinaryNotFoundError(f"{bin_name} not found in PATH and not provided explicitly")
    return found

def _is_allowed_source(src: Union[str, Path], allowed: Tuple[str, ...]) -> bool:
    s = str(src)
    if "://" not in s:
        scheme = "file"
    else:
        scheme = s.split(":", 1)[0].lower()
    return scheme in allowed

def _quote_args(args: Sequence[Union[str, Path]]) -> str:
    return " ".join(shlex.quote(str(a)) for a in args)

def _tail(data: bytes, n: int = 4096) -> str:
    s = data[-n:].decode("utf-8", "ignore") if data else ""
    return s

# =========================
# Bridge
# =========================

class FFmpegBridge:
    def __init__(self, cfg: Optional[BridgeConfig] = None) -> None:
        self.cfg = cfg or BridgeConfig()
        self._ffmpeg = _which("ffmpeg", self.cfg.ffmpeg_path, self.cfg.env)
        self._ffprobe = _which("ffprobe", self.cfg.ffprobe_path, self.cfg.env)
        log.debug("Using ffmpeg at %s; ffprobe at %s", self._ffmpeg, self._ffprobe)

    # -------- Public API: Probe --------

    async def probe(self, src: Union[str, Path], *, select_streams: Optional[str] = None, timeout: Optional[int] = 15) -> Dict[str, Any]:
        if not _is_allowed_source(src, self.cfg.allowed_input_schemes):
            raise ValidationError("Source scheme is not allowed")
        args = [
            self._ffprobe, "-v", "error",
            "-print_format", "json",
            "-show_format", "-show_streams",
        ]
        if select_streams:
            args += ["-select_streams", select_streams]
        args += ["-i", str(src)]
        stdout, stderr = await self._run(args, timeout=timeout, capture_stdout=True, capture_stderr=True)
        try:
            return json.loads(stdout.decode("utf-8"))
        except Exception as e:
            raise FFprobeError(f"ffprobe JSON parse failed: {e}") from e

    # -------- Public API: Transcode/Remux --------

    async def transcode_to_mp4(
        self,
        src: Union[str, Path],
        dst: Union[str, Path],
        *,
        tcfg: Optional[TranscodeConfig] = None,
        start_at: Optional[float] = None,
        duration: Optional[float] = None,
        progress_cb: Optional[Callable[[Dict[str, Any]], None]] = None,
        wall_timeout: Optional[int] = None,
    ) -> None:
        tcfg = tcfg or TranscodeConfig()
        if not _is_allowed_source(src, self.cfg.allowed_input_schemes):
            raise ValidationError("Source scheme is not allowed")
        dst_path = Path(dst)
        dst_path.parent.mkdir(parents=True, exist_ok=True)

        copy_video = copy_audio = False
        if tcfg.copy_if_compatible:
            try:
                meta = await self.probe(src, timeout=20)
                vcodec = next((s.get("codec_name") for s in meta.get("streams", []) if s.get("codec_type") == "video"), None)
                acodec = next((s.get("codec_name") for s in meta.get("streams", []) if s.get("codec_type") == "audio"), None)
                # Совместимые кодеки для MP4
                copy_video = vcodec in {"h264", "hevc", "mpeg4", "vp9"} and tcfg.video_codec in {"copy", "libx264", "libx265"}
                copy_audio = acodec in {"aac", "mp3", "opus", "ac3"} and tcfg.audio_codec in {"copy", "aac"}
            except Exception:
                copy_video = copy_audio = False

        args: List[Union[str, Path]] = [self._ffmpeg, "-hide_banner", "-y"]
        if start_at is not None:
            args += ["-ss", f"{start_at}"]
        args += ["-i", str(src)]
        if duration is not None:
            args += ["-t", f"{duration}"]

        # Видео
        if copy_video:
            args += ["-c:v", "copy"]
        else:
            args += ["-c:v", tcfg.video_codec, "-preset", tcfg.preset, "-crf", str(tcfg.crf)]
            if tcfg.tune:
                args += ["-tune", tcfg.tune]
            args += ["-pix_fmt", tcfg.pix_fmt]
        # Аудио
        if copy_audio:
            args += ["-c:a", "copy"]
        else:
            args += ["-c:a", tcfg.audio_codec, "-b:a", tcfg.audio_bitrate]

        if tcfg.movflags_faststart:
            args += ["-movflags", "+faststart"]
        if tcfg.max_muxrate:
            args += ["-max_muxing_queue_size", "1024", "-muxrate", tcfg.max_muxrate]

        args += [str(dst_path)]

        await self._run_with_progress(args, progress_cb=progress_cb, timeout=wall_timeout)

    # -------- Public API: HLS (single-variant) --------

    async def hls_segment(
        self,
        src: Union[str, Path],
        dst_dir: Union[str, Path],
        *,
        tcfg: Optional[TranscodeConfig] = None,
        hcfg: Optional= None,
        wall_timeout: Optional[int] = None,
        progress_cb: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> Path:
        """
        Создает HLS плейлист и сегменты в dst_dir. Возвращает путь к мастеру.
        """
        tcfg = tcfg or TranscodeConfig()
        hcfg = hcfg or HLSConfig()
        if not _is_allowed_source(src, self.cfg.allowed_input_schemes):
            raise ValidationError("Source scheme is not allowed")
        out_dir = Path(dst_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        index_path = out_dir / hcfg.variant_name

        args: List[Union[str, Path]] = [self._ffmpeg, "-hide_banner", "-y", "-i", str(src)]

        # Кодеки
        args += ["-c:v", tcfg.video_codec, "-preset", tcfg.preset, "-crf", str(tcfg.crf), "-pix_fmt", tcfg.pix_fmt]
        args += ["-c:a", tcfg.audio_codec, "-b:a", tcfg.audio_bitrate]

        # HLS опции
        args += [
            "-f", "hls",
            "-hls_time", str(hcfg.segment_time),
            "-hls_list_size", str(hcfg.playlist_size),
            "-hls_flags", "+".join(hcfg.hls_flags + (("delete_segments",) if hcfg.delete_segments else ())),
        ]
        if hcfg.fmp4:
            args += ["-hls_segment_type", "fmp4", "-movflags", "frag_keyframe+empty_moov"]

        args += [str(index_path)]

        await self._run_with_progress(args, progress_cb=progress_cb, timeout=wall_timeout)
        # Простейший мастер указывает один вариант
        master_path = out_dir / hcfg.master_name
        master_path.write_text(f"#EXTM3U\n#EXT-X-STREAM-INF:BANDWIDTH=2500000\n{hcfg.variant_name}\n", encoding="utf-8")
        return master_path

    # -------- Public API: Thumbnails --------

    async def thumbnails(
        self,
        src: Union[str, Path],
        dst_dir: Union[str, Path],
        *,
        tcfg: Optional[ThumbnailConfig] = None,
        wall_timeout: Optional[int] = None,
    ) -> List[Path]:
        tcfg = tcfg or ThumbnailConfig()
        if not _is_allowed_source(src, self.cfg.allowed_input_schemes):
            raise ValidationError("Source scheme is not allowed")
        out_dir = Path(dst_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        scale_expr = self._thumbnail_scale_expr(width=tcfg.width, height=tcfg.height)

        args: List[Union[str, Path]] = [
            self._ffmpeg, "-hide_banner", "-y",
            "-ss", str(max(0, tcfg.start_offset_seconds)),
            "-i", str(src),
            "-vf", f"fps=1/{max(1, tcfg.interval_seconds)},scale={scale_expr}",
            "-q:v", str(tcfg.quality),
            str(out_dir / tcfg.pattern),
        ]
        await self._run(args, timeout=wall_timeout)
        # Соберем список результатов
        files = sorted(out_dir.glob(self._glob_from_pattern(tcfg.pattern)))
        return files

    # -------- Public API: RTSP -> RTMP push --------

    async def rtsp_to_rtmp(
        self,
        rtsp_url: str,
        rtmp_url: str,
        *,
        copy_codecs: bool = True,
        wall_timeout: Optional[int] = None,
        progress_cb: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> None:
        if not _is_allowed_source(rtsp_url, self.cfg.allowed_input_schemes):
            raise ValidationError("RTSP source not allowed")
        if not _is_allowed_source(rtmp_url, self.cfg.allowed_input_schemes):
            raise ValidationError("RTMP destination not allowed")

        args: List[Union[str, Path]] = [
            self._ffmpeg, "-hide_banner", "-rtsp_transport", "tcp",
            "-i", rtsp_url,
        ]
        if copy_codecs:
            args += ["-c:v", "copy", "-c:a", "copy"]
        else:
            args += ["-c:v", "libx264", "-preset", "veryfast", "-c:a", "aac", "-b:a", "128k"]
        args += ["-f", "flv", rtmp_url]
        await self._run_with_progress(args, progress_cb=progress_cb, timeout=wall_timeout)

    # =========================
    # Core runners
    # =========================

    async def _run(
        self,
        args: Sequence[Union[str, Path]],
        *,
        timeout: Optional[int] = None,
        capture_stdout: bool = False,
        capture_stderr: bool = True,
    ) -> Tuple[bytes, bytes]:
        """
        Унифицированный запуск процесса. Не использует shell=True.
        """
        full_timeout = min(timeout or self.cfg.max_wall_seconds, self.cfg.max_wall_seconds)
        stdout_pipe = asyncio.subprocess.PIPE if capture_stdout else asyncio.subprocess.DEVNULL
        stderr_pipe = asyncio.subprocess.PIPE if capture_stderr else asyncio.subprocess.DEVNULL

        args_str = _quote_args(args)
        log.debug("Executing: %s", args_str)

        proc = await asyncio.create_subprocess_exec(
            *[str(a) for a in args],
            stdout=stdout_pipe,
            stderr=stderr_pipe,
            env={**os.environ, **self.cfg.env},
        )
        try:
            out, err = await asyncio.wait_for(proc.communicate(), timeout=full_timeout)
        except asyncio.TimeoutError:
            await self._terminate(proc)
            raise FFmpegError("Process timeout", args_line=args_str)
        rc = proc.returncode
        if rc != 0:
            raise FFmpegError(f"Process failed with code {rc}", args_line=args_str, returncode=rc, stderr_tail=_tail(err))
        return out or b"", err or b""

    async def _run_with_progress(
        self,
        args: Sequence[Union[str, Path]],
        *,
        progress_cb: Optional[Callable[[Dict[str, Any]], None]] = None,
        timeout: Optional[int] = None,
    ) -> None:
        """
        Запуск ffmpeg с прогрессом: добавляет "-progress", "pipe:1" и парсит ключ-значение строки.
        """
        # В отдельной копии аргументов добавляем progress
        args_list: List[Union[str, Path]] = list(args)
        args_list[0:1] = [args[0], "-progress", "pipe:1", "-nostats"]
        full_timeout = min(timeout or self.cfg.max_wall_seconds, self.cfg.max_wall_seconds)
        args_str = _quote_args(args_list)
        log.debug("Executing (progress): %s", args_str)

        proc = await asyncio.create_subprocess_exec(
            *[str(a) for a in args_list],
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env={**os.environ, **self.cfg.env},
        )

        async def _read_progress(reader: asyncio.StreamReader) -> None:
            # Формат: key=value, заканчивается "progress=end"
            buf: Dict[str, Any] = {}
            try:
                while True:
                    line = await reader.readline()
                    if not line:
                        break
                    try:
                        s = line.decode("utf-8", "ignore").strip()
                    except Exception:
                        continue
                    if not s:
                        continue
                    if "=" in s:
                        k, v = s.split("=", 1)
                        buf[k] = v
                        if k == "progress":
                            if progress_cb:
                                # нормализуем некоторые поля
                                payload = {
                                    "frame": int(buf.get("frame", "0") or "0"),
                                    "fps": float(buf.get("fps", "0") or "0"),
                                    "bitrate": buf.get("bitrate"),
                                    "total_size": int(buf.get("total_size", "0") or "0"),
                                    "out_time_ms": int(buf.get("out_time_ms", "0") or "0"),
                                    "speed": buf.get("speed"),
                                    "progress": buf.get("progress"),
                                }
                                progress_cb(payload)
                            buf.clear()
            except Exception as e:
                log.debug("progress reader error: %s", e)

        async def _read_stderr(reader: asyncio.StreamReader) -> bytes:
            chunks: List[bytes] = []
            while True:
                b = await reader.read(self.cfg.read_buffer_bytes)
                if not b:
                    break
                chunks.append(b)
            return b"".join(chunks)

        try:
            done, pending = await asyncio.wait(
                {
                    asyncio.create_task(_read_progress(proc.stdout)),  # type: ignore[arg-type]
                    asyncio.create_task(_read_stderr(proc.stderr)),    # type: ignore[arg-type]
                    asyncio.create_task(proc.wait()),
                },
                timeout=full_timeout,
                return_when=asyncio.FIRST_COMPLETED,
            )
            if not any(t for t in done if getattr(t, "result", None) is not None):
                # Ничего не завершилось — таймаут
                await self._terminate(proc)
                raise FFmpegError("Process timeout", args_line=args_str)
            # Дождемся остальных
            for t in pending:
                t.cancel()
            rc = proc.returncode
            if rc != 0:
                err = b""
                for t in done:
                    if isinstance(t.result(), bytes):  # stderr task
                        err = t.result()
                raise FFmpegError(f"Process failed with code {rc}", args_line=args_str, returncode=rc, stderr_tail=_tail(err))
        finally:
            if proc.returncode is None:
                await self._terminate(proc)

    async def _terminate(self, proc: asyncio.subprocess.Process) -> None:
        try:
            if proc.returncode is None:
                proc.terminate()
                try:
                    await asyncio.wait_for(proc.wait(), timeout=self.cfg.kill_grace_seconds)
                except asyncio.TimeoutError:
                    proc.kill()
        except ProcessLookupError:
            pass

    # =========================
    # Utilities (private)
    # =========================

    def _thumbnail_scale_expr(self, *, width: Optional[int], height: Optional[int]) -> str:
        # Масштаб по большей стороне, сохраняя аспект
        max_side = self.cfg.thumbnail_max_px
        if width and height:
            return f"scale={width}:{height}:force_original_aspect_ratio=decrease"
        if width:
            return f"scale={width}:-2"
        if height:
            return f"scale=-2:{height}"
        return f"scale='min(iw,ih,{max_side})':'-2'"

    @staticmethod
    def _glob_from_pattern(pattern: str) -> str:
        # Преобразует printf-стиль %06d в звездочку для glob
        if "%" in pattern and "d" in pattern:
            return re.sub(r"%0?\d*d", "*", pattern)
        return pattern

# =========================
# Example (commented)
# =========================
# async def _example():
#     bridge = FFmpegBridge()
#     meta = await bridge.probe("input.mp4")
#     await bridge.transcode_to_mp4("input.mp4", "out/output.mp4", progress_cb=lambda p: log.info("progress: %s", p))
#     master = await bridge.hls_segment("input.mp4", "out/hls")
#     thumbs = await bridge.thumbnails("input.mp4", "out/thumbs")
#     await bridge.rtsp_to_rtmp("rtsp://cam/stream", "rtmp://live/app/stream")

