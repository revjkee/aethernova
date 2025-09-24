# -*- coding: utf-8 -*-
"""
Video Segment Worker — промышленный асинхронный воркер сегментации видеопотоков
для physical-integration-core.

Возможности:
- Очередь задач на файловой системе: inbox/ → processing/ → done/ | failed/ (атомарные перемещения).
- Два режима сегментации: HLS (m3u8 + .ts) и file-segment (MP4/TS куски по времени).
- Поддержка источников: файлы и RTSP/HTTP(S) (прозрачно для FFmpeg).
- Управление FFmpeg: asyncio subprocess, -progress pipe:1, парсинг прогресса, таймауты.
- Надёжность: экспоненциальный backoff, ограничение параллелизма, ретраи, очистка зомби-процессов.
- Метаданные: SHA256 для сегментов, ffprobe медиапрофиль, sidecar JSON.
- Наблюдаемость: структурные JSON-логи, базовые метрики (кадры/байты/время/ошибки).
- Без внешних зависимостей (только стандартная библиотека). Требуется установленный ffmpeg/ffprobe в PATH либо через ENV.

ENV (по умолчанию):
  VIDEO_QUEUE_DIR=./queue
  VIDEO_OUTPUT_DIR=./output
  VIDEO_WORKER_CONCURRENCY=2
  VIDEO_MAX_RETRIES=5
  VIDEO_BACKOFF_BASE=0.5
  VIDEO_BACKOFF_MAX=30
  VIDEO_HEARTBEAT_INTERVAL=10
  FFMPEG_BIN=ffmpeg
  FFPROBE_BIN=ffprobe

Task JSON schema (минимум):
{
  "task_id": "uuid-или-любой-идентификатор",
  "source": "rtsp://... | file.mp4 | http(s)://...",
  "segmenter": "hls" | "file",
  "segment_time": 6,
  "duration": 60,                # опционально (сек), если нужно ограничить запись
  "start_time": "00:00:05.0",    # опционально
  "profile": {
    "vcodec": "libx264",
    "acodec": "aac",
    "bitrate": "2000k",
    "width": 1280,
    "height": 720,
    "fps": 30,
    "gop": 60,
    "threads": 2,
    "preset": "veryfast",
    "movflags": "+faststart"
  },
  "filters": "format=yuv420p",
  "hls": {
    "playlist_name": "index.m3u8",
    "flags": "independent_segments+delete_segments+program_date_time"
  },
  "file_segment": {
    "pattern": "seg_%Y%m%d_%H%M%S_%06d.mp4",
    "format": "mp4"
  },
  "output_root": "camera01/2025-08-22T14-00-00Z",   # опционально; иначе WORKER сам сформирует
  "attempts": 0
}

Результат:
- В каталоге вывода появляются сегменты/плейлисты.
- Создаётся sidecar "<task_id>.meta.json" с медиаинфо и хэшами.
- Задание переносится из processing/ в done/ либо failed/ с описанием ошибки.
"""

from __future__ import annotations

import asyncio
import dataclasses
import enum
import hashlib
import json
import logging
import os
import re
import shlex
import signal
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# -------------------------
# Конфигурация и константы
# -------------------------

@dataclass(frozen=True)
class WorkerConfig:
    queue_dir: Path = field(default_factory=lambda: Path(os.getenv("VIDEO_QUEUE_DIR", "./queue")).resolve())
    output_dir: Path = field(default_factory=lambda: Path(os.getenv("VIDEO_OUTPUT_DIR", "./output")).resolve())
    concurrency: int = int(os.getenv("VIDEO_WORKER_CONCURRENCY", "2"))
    max_retries: int = int(os.getenv("VIDEO_MAX_RETRIES", "5"))
    backoff_base: float = float(os.getenv("VIDEO_BACKOFF_BASE", "0.5"))
    backoff_max: float = float(os.getenv("VIDEO_BACKOFF_MAX", "30"))
    heartbeat_interval: float = float(os.getenv("VIDEO_HEARTBEAT_INTERVAL", "10"))
    ffmpeg_bin: str = os.getenv("FFMPEG_BIN", "ffmpeg")
    ffprobe_bin: str = os.getenv("FFPROBE_BIN", "ffprobe")

    # Безопасность/санитайзинг
    allow_relative_output: bool = False  # запрет на выход из корневого OUTPUT_DIR


class SegmenterKind(str, enum.Enum):
    HLS = "hls"
    FILE = "file"


# -------------------------
# Модели данных
# -------------------------

@dataclass
class TaskProfile:
    vcodec: str = "libx264"
    acodec: str = "aac"
    bitrate: str = "2000k"
    width: Optional[int] = None
    height: Optional[int] = None
    fps: Optional[int] = None
    gop: Optional[int] = None
    threads: Optional[int] = None
    preset: Optional[str] = None
    movflags: Optional[str] = None


@dataclass
class HlsOpts:
    playlist_name: str = "index.m3u8"
    flags: str = "independent_segments+delete_segments+program_date_time"


@dataclass
class FileSegmentOpts:
    pattern: str = "seg_%Y%m%d_%H%M%S_%06d.mp4"
    format: str = "mp4"  # mp4 | mpegts


@dataclass
class VideoTask:
    task_id: str
    source: str
    segmenter: SegmenterKind
    segment_time: int
    duration: Optional[int] = None
    start_time: Optional[str] = None
    profile: TaskProfile = field(default_factory=TaskProfile)
    filters: Optional[str] = None
    hls: HlsOpts = field(default_factory=HlsOpts)
    file_segment: FileSegmentOpts = field(default_factory=FileSegmentOpts)
    output_root: Optional[str] = None
    attempts: int = 0

    @staticmethod
    def from_json(d: Dict[str, Any]) -> "VideoTask":
        try:
            seg_kind = SegmenterKind(d["segmenter"])
        except Exception:
            raise ValueError("segmenter must be 'hls' or 'file'")
        prof = TaskProfile(**d.get("profile", {}))
        hls = HlsOpts(**d.get("hls", {}))
        fs = FileSegmentOpts(**d.get("file_segment", {}))
        return VideoTask(
            task_id=str(d.get("task_id") or _gen_task_id()),
            source=str(d["source"]),
            segmenter=seg_kind,
            segment_time=int(d.get("segment_time", 6)),
            duration=(int(d["duration"]) if d.get("duration") is not None else None),
            start_time=(str(d["start_time"]) if d.get("start_time") is not None else None),
            profile=prof,
            filters=d.get("filters"),
            hls=hls,
            file_segment=fs,
            output_root=str(d.get("output_root")) if d.get("output_root") else None,
            attempts=int(d.get("attempts", 0)),
        )

    def to_json(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


@dataclass
class SegmentInfo:
    path: str
    bytes: int
    sha256: str
    media: Dict[str, Any]


@dataclass
class TaskResult:
    task_id: str
    status: str
    started_at: float
    finished_at: float
    elapsed_s: float
    segmenter: str
    source: str
    output_dir: str
    segments: List[SegmentInfo]
    ffmpeg_cmd: List[str]
    error: Optional[str] = None


@dataclass
class WorkerMetrics:
    started_at: float = field(default_factory=time.time)
    tasks_ok: int = 0
    tasks_fail: int = 0
    tasks_retried: int = 0
    bytes_out: int = 0
    segments_out: int = 0
    last_heartbeat: float = field(default_factory=time.time)


# -------------------------
# Файловая очередь
# -------------------------

class FileQueue:
    """
    Durable-очередь задач. Структура:
      queue/
        inbox/       <- сюда кладут .json задачи
        processing/  <- сюда атомарно переноси задачу при взятии
        done/        <- результаты (копия исходной задачи + result.json)
        failed/      <- ошибка (копия задачи + error.json)
    """

    def __init__(self, root: Path) -> None:
        self.root = root
        self.inbox = root / "inbox"
        self.processing = root / "processing"
        self.done = root / "done"
        self.failed = root / "failed"
        for p in (self.inbox, self.processing, self.done, self.failed):
            p.mkdir(parents=True, exist_ok=True)

    def list_inbox(self) -> List[Path]:
        return sorted([p for p in self.inbox.glob("*.json") if p.is_file()])

    def claim(self) -> Optional[Tuple[Path, Path]]:
        """
        Берём первую задачу из inbox и атомарно переносим в processing.
        Возвращает (src_processing_path, dst_processing_path), где dst == src (совместимость).
        """
        for src in self.list_inbox():
            try:
                dst = self.processing / src.name
                os.replace(src, dst)  # атомарно
                return (dst, dst)
            except FileNotFoundError:
                continue
            except PermissionError:
                continue
        return None

    def complete(self, proc_path: Path, result: TaskResult) -> None:
        base = proc_path.stem
        dst_dir = self.done / base
        dst_dir.mkdir(parents=True, exist_ok=True)
        # Сохраняем исходную задачу и результат
        _safe_copy(proc_path, dst_dir / proc_path.name)
        (dst_dir / "result.json").write_text(_dumps_json(dataclasses.asdict(result)), encoding="utf-8")
        # Удаляем из processing
        with _suppress(Exception):
            proc_path.unlink(missing_ok=True)

    def fail(self, proc_path: Path, task: VideoTask, error_msg: str) -> None:
        base = proc_path.stem
        dst_dir = self.failed / base
        dst_dir.mkdir(parents=True, exist_ok=True)
        # Пересохраняем задачу с увеличенным attempts
        task_dict = task.to_json()
        task_dict["error"] = error_msg
        (dst_dir / proc_path.name).write_text(_dumps_json(task_dict), encoding="utf-8")
        (dst_dir / "error.json").write_text(_dumps_json({"error": error_msg}), encoding="utf-8")
        with _suppress(Exception):
            proc_path.unlink(missing_ok=True)

    def requeue(self, proc_path: Path, task: VideoTask) -> None:
        """Возвращаем задачу в inbox с увеличением attempts."""
        task.attempts += 1
        # Пишем как новый файл (на случай, если имя было не task_id)
        name = f"{task.task_id}.json"
        (self.inbox / name).write_text(_dumps_json(task.to_json()), encoding="utf-8")
        with _suppress(Exception):
            proc_path.unlink(missing_ok=True)


# -------------------------
# Воркер
# -------------------------

class VideoSegmentWorker:
    def __init__(self, cfg: WorkerConfig, *, logger: Optional[logging.Logger] = None) -> None:
        self.cfg = cfg
        self.queue = FileQueue(cfg.queue_dir)
        self.metrics = WorkerMetrics()
        self._logger = logger or logging.getLogger("physical_integration.video_worker")
        self._logger.setLevel(logging.INFO)
        self._stop = asyncio.Event()
        self._sem = asyncio.Semaphore(cfg.concurrency)
        self._tasks: set[asyncio.Task] = set()

        try:
            for sig in (signal.SIGTERM, signal.SIGINT):
                signal.signal(sig, self._on_signal)
        except Exception:
            pass

    def _on_signal(self, signum, frame) -> None:
        self._json_log("signal_received", signum=signum)
        self.stop()

    def stop(self) -> None:
        self._stop.set()

    async def run(self) -> None:
        self._json_log("worker_start", queue=str(self.cfg.queue_dir), output=str(self.cfg.output_dir), conc=self.cfg.concurrency)
        hb_task = asyncio.create_task(self._heartbeat_loop(), name="heartbeat")
        try:
            while not self._stop.is_set():
                claim = self.queue.claim()
                if not claim:
                    await asyncio.sleep(0.2)
                    continue
                proc_path, _ = claim
                await self._sem.acquire()
                t = asyncio.create_task(self._process_task_file(proc_path))
                self._tasks.add(t)
                t.add_done_callback(lambda _t: (self._tasks.discard(_t), self._sem.release()))
        finally:
            self._json_log("worker_stopping")
            hb_task.cancel()
            with _suppress(asyncio.CancelledError):
                await hb_task
            # Дождаться завершения активных задач
            if self._tasks:
                with _suppress(asyncio.CancelledError):
                    await asyncio.gather(*list(self._tasks), return_exceptions=True)
            self._json_log("worker_stopped")

    async def _process_task_file(self, proc_path: Path) -> None:
        started = time.time()
        # Загружаем JSON
        try:
            d = json.loads(proc_path.read_text(encoding="utf-8"))
            task = VideoTask.from_json(d)
        except Exception as e:
            self._json_log("task_parse_error", level="ERROR", path=str(proc_path), error=str(e))
            # Перемещаем в failed
            dummy = TaskResult(
                task_id=proc_path.stem, status="failed", started_at=started, finished_at=time.time(),
                elapsed_s=0.0, segmenter="unknown", source="unknown", output_dir=str(self.cfg.output_dir),
                segments=[], ffmpeg_cmd=[], error=f"parse error: {e}"
            )
            self.queue.complete(proc_path, dummy)  # поместим в done/<id>/ для трассировки
            return

        # Проверка попыток
        if task.attempts >= self.cfg.max_retries:
            self.metrics.tasks_fail += 1
            self._json_log("task_max_retries_reached", level="ERROR", task_id=task.task_id, attempts=task.attempts)
            self.queue.fail(proc_path, task, "max retries reached")
            return

        # Сегментация с ретраями
        attempt = task.attempts + 1
        backoff = min(self.cfg.backoff_base * (2 ** (task.attempts)), self.cfg.backoff_max)
        try:
            result = await self._run_segmentation(task)
            self.metrics.tasks_ok += 1
            self.metrics.bytes_out += sum(s.bytes for s in result.segments)
            self.metrics.segments_out += len(result.segments)
            self.queue.complete(proc_path, result)
            self._json_log("task_done", task_id=task.task_id, elapsed=result.elapsed_s, segments=len(result.segments), bytes=result.ffmpeg_cmd and sum(s.bytes for s in result.segments))
        except asyncio.CancelledError:
            raise
        except Exception as e:
            self.metrics.tasks_retried += 1
            self._json_log("task_failed", level="ERROR", task_id=task.task_id, error=str(e), backoff=backoff, attempt=attempt)
            await asyncio.sleep(backoff)
            self.queue.requeue(proc_path, task)

    async def _run_segmentation(self, task: VideoTask) -> TaskResult:
        started = time.time()
        # Формируем выходной каталог
        out_dir = self._make_output_dir(task)
        out_dir.mkdir(parents=True, exist_ok=True)

        # Сборка команды
        if task.segmenter == SegmenterKind.HLS:
            cmd = self._build_ffmpeg_hls(task, out_dir)
        else:
            cmd = self._build_ffmpeg_file(task, out_dir)

        self._json_log("ffmpeg_start", task_id=task.task_id, cmd=" ".join(map(shlex.quote, cmd)))
        # Запуск FFmpeg
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,   # для -progress pipe:1
            stderr=asyncio.subprocess.PIPE,   # на случай логов об ошибках
        )

        # Чтение прогресса и stderr параллельно
        progress: Dict[str, Any] = {}
        async def read_stdout():
            if not proc.stdout:
                return
            while True:
                line = await proc.stdout.readline()
                if not line:
                    break
                _parse_ffmpeg_progress_line(line.decode("utf-8", "ignore").strip(), progress)
                if progress and progress.get("progress") == "end":
                    # прогресс сообщает окончание
                    pass

        async def read_stderr():
            if not proc.stderr:
                return
            buff = []
            while True:
                line = await proc.stderr.readline()
                if not line:
                    break
                s = line.decode("utf-8", "ignore").rstrip()
                if s:
                    buff.append(s)
                    # Иногда FFmpeg пишет полезные предупреждения сюда
                    if len(buff) > 1000:
                        buff.pop(0)
            return "\n".join(buff)

        stdout_task = asyncio.create_task(read_stdout(), name=f"ffmpeg-progress-{task.task_id}")
        stderr_task = asyncio.create_task(read_stderr(), name=f"ffmpeg-stderr-{task.task_id}")

        rc = await proc.wait()
        with _suppress(asyncio.CancelledError):
            await asyncio.gather(stdout_task, stderr_task)
        stderr_last = None
        if stderr_task.done():
            stderr_last = stderr_task.result()

        if rc != 0:
            raise RuntimeError(f"ffmpeg exit {rc}, stderr_tail={stderr_last[-1000:] if stderr_last else ''}")

        # Индексация результата
        segments = self._collect_segments(task, out_dir)
        metas: List[SegmentInfo] = []
        for seg in segments:
            # Хэш
            sha256 = _sha256_file(seg)
            size = os.path.getsize(seg)
            media = await _ffprobe(self.cfg.ffprobe_bin, seg)
            metas.append(SegmentInfo(path=str(Path(seg).resolve()), bytes=size, sha256=sha256, media=media))

        finished = time.time()
        result = TaskResult(
            task_id=task.task_id,
            status="ok",
            started_at=started,
            finished_at=finished,
            elapsed_s=finished - started,
            segmenter=task.segmenter.value,
            source=task.source,
            output_dir=str(out_dir),
            segments=metas,
            ffmpeg_cmd=cmd,
            error=None,
        )
        # Sidecar
        sidecar = out_dir / f"{task.task_id}.meta.json"
        sidecar.write_text(_dumps_json(dataclasses.asdict(result)), encoding="utf-8")
        return result

    def _build_ffmpeg_hls(self, task: VideoTask, out_dir: Path) -> List[str]:
        playlist = _sanitize_filename(task.hls.playlist_name)
        seg_t = max(1, int(task.segment_time))
        seg_t = min(seg_t, 60 * 60)  # не более часа

        seg_filename = out_dir / "seg_%06d.ts"
        cmd: List[str] = [self.cfg.ffmpeg_bin, "-y", "-hide_banner", "-loglevel", "error", "-progress", "pipe:1"]

        # Источник
        cmd += _src_common_opts(task.source)
        if task.start_time:
            cmd += ["-ss", str(task.start_time)]
        if task.duration:
            cmd += ["-t", str(int(task.duration))]

        cmd += ["-i", task.source]

        # Кодеки/профиль
        cmd += _codec_profile_args(task.profile)

        # Фильтры
        if task.filters:
            cmd += ["-vf", task.filters]

        # HLS параметры
        hls_flags = task.hls.flags
        cmd += [
            "-f", "hls",
            "-hls_time", str(seg_t),
            "-hls_segment_filename", str(seg_filename),
            "-hls_flags", hls_flags,
            "-hls_playlist_type", "event",
            str(out_dir / playlist),
        ]
        return cmd

    def _build_ffmpeg_file(self, task: VideoTask, out_dir: Path) -> List[str]:
        seg_t = max(1, int(task.segment_time))
        seg_t = min(seg_t, 60 * 60)
        pattern = _sanitize_filename(task.file_segment.pattern)
        fmt = task.file_segment.format.lower()
        allowed_fmt = {"mp4", "mpegts"}
        if fmt not in allowed_fmt:
            fmt = "mp4"

        out_pattern = out_dir / pattern
        cmd: List[str] = [self.cfg.ffmpeg_bin, "-y", "-hide_banner", "-loglevel", "error", "-progress", "pipe:1"]

        # Источник
        cmd += _src_common_opts(task.source)
        if task.start_time:
            cmd += ["-ss", str(task.start_time)]
        if task.duration:
            cmd += ["-t", str(int(task.duration))]

        cmd += ["-i", task.source]

        # Кодеки/профиль
        cmd += _codec_profile_args(task.profile)

        # Фильтры
        if task.filters:
            cmd += ["-vf", task.filters]

        # Сегментация файла
        cmd += [
            "-f", "segment",
            "-segment_time", str(seg_t),
            "-reset_timestamps", "1",
            "-strftime", "1",
            "-segment_format", "mp4" if fmt == "mp4" else "mpegts",
            str(out_pattern),
        ]
        # Для MP4 полезно faststart при записи (если поддерживается профилем)
        return cmd

    def _collect_segments(self, task: VideoTask, out_dir: Path) -> List[str]:
        if task.segmenter == SegmenterKind.HLS:
            # Сегменты .ts
            return sorted([str(p) for p in out_dir.glob("seg_*.ts") if p.is_file()])
        else:
            # Собираем по шаблону — берём все mp4/ts, исключая sidecar/manifest
            files = []
            for ext in ("*.mp4", "*.ts"):
                files.extend(out_dir.glob(ext))
            return sorted([str(p) for p in files if p.is_file()])

    def _make_output_dir(self, task: VideoTask) -> Path:
        # Если задан output_root — используем как подкаталог; иначе динамически по времени
        root = task.output_root or f"{_now_utc_compact()}/{task.task_id}"
        # Санитайз против path traversal
        rel = Path(_sanitize_rel_path(root))
        out_dir = (self.cfg.output_dir / rel).resolve()
        if not self.cfg.allow_relative_output:
            # Гарантируем, что out_dir внутри корня
            if not str(out_dir).startswith(str(self.cfg.output_dir.resolve())):
                raise ValueError("output path escapes OUTPUT_DIR")
        return out_dir

    async def _heartbeat_loop(self) -> None:
        try:
            while True:
                await asyncio.sleep(self.cfg.heartbeat_interval)
                self.metrics.last_heartbeat = time.time()
                self._json_log(
                    "heartbeat",
                    uptime=int(self.metrics.last_heartbeat - self.metrics.started_at),
                    tasks_ok=self.metrics.tasks_ok,
                    tasks_fail=self.metrics.tasks_fail,
                    tasks_retried=self.metrics.tasks_retried,
                    segments_out=self.metrics.segments_out,
                    bytes_out=self.metrics.bytes_out,
                    in_progress=len(self._tasks),
                )
        except asyncio.CancelledError:
            return

    def _json_log(self, event: str, level: str = "INFO", **fields: Any) -> None:
        rec = {"event": event, "level": level, **fields, "ts": _now_iso()}
        if level == "ERROR":
            self._logger.error(json.dumps(rec, ensure_ascii=False))
        elif level == "WARNING":
            self._logger.warning(json.dumps(rec, ensure_ascii=False))
        else:
            self._logger.info(json.dumps(rec, ensure_ascii=False))


# -------------------------
# Утилиты: ffprobe, прогресс, хэши, путь
# -------------------------

async def _ffprobe(ffprobe_bin: str, file_path: str) -> Dict[str, Any]:
    """
    Возвращает компактный медиапрофиль для сегмента.
    """
    cmd = [
        ffprobe_bin, "-v", "error",
        "-select_streams", "v:0",
        "-show_entries", "stream=codec_name,codec_type,width,height,avg_frame_rate,bit_rate",
        "-show_entries", "format=format_name,duration,size,bit_rate",
        "-of", "json",
        file_path,
    ]
    proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    out, _ = await proc.communicate()
    if proc.returncode != 0:
        return {}
    try:
        j = json.loads(out.decode("utf-8", "ignore"))
    except Exception:
        return {}
    # Уплотнение
    fmt = j.get("format", {})
    streams = j.get("streams", [])
    v = streams[0] if streams else {}
    return {
        "format": fmt.get("format_name"),
        "duration": _try_float(fmt.get("duration")),
        "size": _try_int(fmt.get("size")),
        "bit_rate": _try_int(fmt.get("bit_rate")),
        "vcodec": v.get("codec_name"),
        "width": _try_int(v.get("width")),
        "height": _try_int(v.get("height")),
        "avg_frame_rate": v.get("avg_frame_rate"),
        "vbit_rate": _try_int(v.get("bit_rate")),
    }


def _parse_ffmpeg_progress_line(line: str, acc: Dict[str, Any]) -> None:
    # Формат: key=value, например out_time_ms=..., speed=..., progress=continue|end
    if "=" not in line:
        return
    k, v = line.split("=", 1)
    acc[k.strip()] = v.strip()


def _codec_profile_args(p: TaskProfile) -> List[str]:
    args: List[str] = []
    if p.vcodec:
        args += ["-c:v", p.vcodec]
    if p.acodec:
        args += ["-c:a", p.acodec]
    if p.bitrate:
        args += ["-b:v", p.bitrate]
    if p.width and p.height:
        # Можно через фильтр scale, но упростим — через -vf в общем пайплайне
        pass
    if p.fps:
        args += ["-r", str(p.fps)]
    if p.gop:
        args += ["-g", str(p.gop)]
    if p.threads:
        args += ["-threads", str(p.threads)]
    if p.preset:
        args += ["-preset", p.preset]
    if p.movflags:
        args += ["-movflags", p.movflags]
    # Аудио базово:
    # Можно добавить громкость/частоту дискретизации: -ar 48000 -ac 2
    return args


def _src_common_opts(source: str) -> List[str]:
    # Для RTSP полезно принудить TCP и таймауты
    if source.startswith("rtsp://"):
        return ["-rtsp_transport", "tcp", "-stimeout", "5000000"]  # ~5 сек
    return []


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _sanitize_filename(name: str) -> str:
    # Убираем опасные символы; допускаем буквы, цифры, тире, подчёркивание, процентные форматеры и точки
    allowed = re.compile(r"[^A-Za-z0-9._%\-]+")
    s = allowed.sub("_", name)
    return s[:255] if s else "out"


def _sanitize_rel_path(p: str) -> str:
    s = p.replace("\\", "/")
    s = s.strip().lstrip("./")
    s = re.sub(r"\.\.+", ".", s)
    s = re.sub(r"[^A-Za-z0-9._/\-]+", "_", s)
    return s.strip("/") or "out"


def _safe_copy(src: Path, dst: Path) -> None:
    data = src.read_bytes()
    dst.write_bytes(data)


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _now_utc_compact() -> str:
    return time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())


def _dumps_json(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=False)


def _try_int(v: Any) -> Optional[int]:
    try:
        return int(v)
    except Exception:
        return None


def _try_float(v: Any) -> Optional[float]:
    try:
        return float(v)
    except Exception:
        return None


def _gen_task_id() -> str:
    return f"vtask-{int(time.time()*1000)}"


class _suppress:
    def __init__(self, *exc):
        self.exc = exc or (Exception,)
    def __enter__(self):
        return None
    def __exit__(self, et, ev, tb):
        return et is not None and issubclass(et, self.exc)


# -------------------------
# Точка входа
# -------------------------

async def _amain() -> None:
    # Базовая инициализация логгера
    logging.basicConfig(stream=sys.stdout, level=logging.INFO)
    cfg = WorkerConfig()
    worker = VideoSegmentWorker(cfg)
    await worker.run()


def main() -> None:
    try:
        asyncio.run(_amain())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
