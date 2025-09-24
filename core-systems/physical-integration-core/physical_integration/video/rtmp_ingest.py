# physical_integration/video/rtmp_ingest.py
# Промышленный RTMP ingest manager на базе FFmpeg.
# Возможности:
# - RTMP pull (источник) -> tee: RTMP push (доставка) + HLS сегментация (локально)
# - Асинхронная загрузка HLS сегментов в S3 (опционально)
# - Экспоненциальный backoff перезапусков FFmpeg с джиттером
# - Парсинг ffmpeg -progress для метрик (fps, bitrate, out_time_ms)
# - Контроль дискового бюджета каталога сегментов и ретенции
# - Prometheus-метрики и health-флаги
# - Опциональные OTel-спаны (если установлен opentelemetry)
# Требования: Python 3.10+, ffmpeg в PATH.
from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import logging
import math
import os
import random
import re
import shutil
import signal
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from prometheus_client import Counter, Gauge, Histogram, start_http_server

try:
    import boto3  # опционально для S3
    _HAS_BOTO3 = True
except Exception:
    _HAS_BOTO3 = False

# Опциональный OTel
try:
    from opentelemetry import trace
    _TRACER = trace.get_tracer(__name__)
    _HAS_OTEL = True
except Exception:  # pragma: no cover
    _HAS_OTEL = False
    class _DummyCtx:  # noqa
        def __enter__(self): return self
        def __exit__(self, *a): return False
    def _noop_span(*a, **k): return _DummyCtx()
    class _DummyTracer:  # noqa
        def start_as_current_span(self, *a, **k): return _noop_span()
    _TRACER = _DummyTracer()

LOG = logging.getLogger("rtmp-ingest")
logging.basicConfig(
    level=getattr(logging, os.getenv("LOG_LEVEL", "INFO").upper(), logging.INFO),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)

# ---------------- Prometheus ----------------
FFMPEG_RESTARTS = Counter("rtmp_ingest_ffmpeg_restarts_total", "FFmpeg restarts", ["source"])
FFMPEG_EXITS = Counter("rtmp_ingest_ffmpeg_exits_total", "FFmpeg exits (non-restart)", ["source", "code"])
FFMPEG_FRAMES = Counter("rtmp_ingest_frames_total", "Encoded frames (video)", ["source"])
FFMPEG_BYTES = Counter("rtmp_ingest_bytes_total", "Output bytes total (mux)", ["source"])
FFMPEG_UP = Gauge("rtmp_ingest_up", "Ingest running flag (1/0)", ["source"])
FFMPEG_FPS = Gauge("rtmp_ingest_fps", "Current FPS", ["source"])
FFMPEG_BITRATE = Gauge("rtmp_ingest_bitrate_kbps", "Current bitrate kb/s", ["source"])
FFMPEG_OUTTIME = Gauge("rtmp_ingest_out_time_sec", "Out time seconds", ["source"])
HLS_SEGMENTS = Gauge("rtmp_ingest_hls_segments", "Segments count in directory", ["source"])
HLS_DIR_BYTES = Gauge("rtmp_ingest_hls_dir_bytes", "Directory size (bytes)", ["source"])
S3_UPLOADS = Counter("rtmp_ingest_s3_uploads_total", "Uploaded HLS files to S3", ["bucket"])
S3_ERRORS = Counter("rtmp_ingest_s3_errors_total", "S3 upload/delete errors", ["bucket"])
HEALTH_READY = Gauge("rtmp_ingest_ready", "Readiness flag", ["source"])

# ---------------- Конфигурация ----------------
def _bool(v: str | None, default: bool = False) -> bool:
    if v is None:
        return default
    return str(v).strip().lower() in {"1", "true", "yes", "on", "y"}

@dataclass
class IngestConfig:
    # Источник RTMP
    source_url: str
    # Точка назначения RTMP (push), опционально
    rtmp_push_url: Optional[str] = None
    # HLS сегментация локально
    hls_dir: Optional[Path] = None
    hls_segment_time: int = 2
    hls_list_size: int = 6
    hls_delete: bool = True
    hls_master_name: str = "index.m3u8"

    # Кодеки/транскодирование
    video_codec: str = "copy"   # copy|h264|hevc|...
    audio_codec: str = "copy"   # copy|aac|...
    hwaccel: Optional[str] = None  # "cuda"|"vaapi"|None

    # Ретрай/ресурсы
    max_restarts: int = 0          # 0 = бесконечно
    backoff_initial: float = 1.0
    backoff_max: float = 30.0

    # Метрики/health
    metrics_port: int = 0          # 0=не поднимать HTTP
    source_name: str = "cam01"

    # S3 (опционально)
    s3_enabled: bool = False
    s3_bucket: Optional[str] = None
    s3_prefix: str = "hls/"
    s3_endpoint: Optional[str] = None
    s3_region: Optional[str] = None
    s3_access_key: Optional[str] = None
    s3_secret_key: Optional[str] = None
    s3_force_path_style: bool = True
    s3_delete_local_after_upload: bool = False

    # Дисковый бюджет и ретенция
    hls_max_dir_mb: int = 1024
    hls_retention_minutes: int = 60

    # Прочее
    extra_input: List[str] = None
    extra_output: List[str] = None

    def __post_init__(self):
        self.extra_input = self.extra_input or []
        self.extra_output = self.extra_output or []
        if self.hls_dir:
            self.hls_dir = Path(self.hls_dir)
        if self.s3_enabled and not _HAS_BOTO3:
            raise RuntimeError("S3 enabled but boto3 not installed")
        if self.s3_enabled and not (self.s3_bucket and self.hls_dir):
            raise RuntimeError("S3 requires s3_bucket and hls_dir")
        if self.metrics_port and not (0 < self.metrics_port < 65536):
            raise ValueError("metrics_port out of range")


# ---------------- Утилиты ----------------
_PROGRESS_RE = re.compile(r"(?P<key>\w+)=(?P<val>.*)")

def _parse_progress_line(line: str) -> Dict[str, str]:
    m = _PROGRESS_RE.match(line.strip())
    return {m.group("key"): m.group("val")} if m else {}

def _dir_size_bytes(path: Path) -> int:
    total = 0
    for p in path.rglob("*"):
        if p.is_file():
            total += p.stat().st_size
    return total

def _now() -> float:
    return time.monotonic()

# ---------------- Основной менеджер ----------------
class FFmpegIngestManager:
    def __init__(self, cfg: IngestConfig):
        self.cfg = cfg
        self._proc: Optional[asyncio.subprocess.Process] = None
        self._stop = asyncio.Event()
        self._restart_count = 0
        self._hls_uploader_task: Optional[asyncio.Task] = None
        self._hls_housekeeper_task: Optional[asyncio.Task] = None
        FFMPEG_UP.labels(cfg.source_name).set(0)
        HEALTH_READY.labels(cfg.source_name).set(0)

    def _ffmpeg_cmd(self, progress_fd: int) -> List[str]:
        """
        Собирает команду FFmpeg с tee‑muxer:
        вход: RTMP, выходы: rtmp_push (flv) и/или HLS каталог.
        """
        out_specs: List[str] = []
        # RTMP push
        if self.cfg.rtmp_push_url:
            out_specs.append(f"[f=flv]{self.cfg.rtmp_push_url}")
        # HLS
        if self.cfg.hls_dir:
            hls_flags = f"hls_time={self.cfg.hls_segment_time}:hls_list_size={self.cfg.hls_list_size}"
            if self.cfg.hls_delete:
                hls_flags += ":hls_flags=delete_segments+program_date_time"
            hls_flags += f":master_pl_name={self.cfg.hls_master_name}"
            # FFmpeg создаст плейлисты и сегменты в целевом каталоге
            out_specs.append(f"[f=hls:{hls_flags}]{self.cfg.hls_dir.as_posix()}/{self.cfg.source_name}.m3u8")

        if not out_specs:
            raise ValueError("No outputs configured (rtmp_push_url and hls_dir are both empty)")

        tee_arg = "|".join(out_specs)

        cmd = [
            "ffmpeg",
            "-hide_banner",
            "-loglevel", "error",
            "-nostdin",
            # Прогресс в pipe: каждые ~0.5с
            "-progress", f"pipe:{progress_fd}",
            "-reconnect", "1",
            "-reconnect_streamed", "1",
            "-reconnect_delay_max", "5",
        ]

        # Аппаратное ускорение
        if self.cfg.hwaccel:
            cmd += ["-hwaccel", self.cfg.hwaccel]

        # Источник
        cmd += self.cfg.extra_input
        cmd += ["-i", self.cfg.source_url]

        # Транскодирование/копирование
        vcodec = ["-c:v", self.cfg.video_codec]
        acodec = ["-c:a", self.cfg.audio_codec]

        # Tee мультиплексирование
        cmd += vcodec + acodec + self.cfg.extra_output + ["-f", "tee", tee_arg]
        return cmd

    async def _spawn_ffmpeg(self) -> Tuple[asyncio.subprocess.Process, asyncio.StreamReader]:
        # создаём пайп для -progress
        progress_r, progress_w = os.pipe()
        # Важно: pass_fds только для POSIX
        cmd = self._ffmpeg_cmd(progress_w)
        LOG.info("Starting FFmpeg: %s", " ".join(cmd))
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            pass_fds=(progress_w,),
        )
        os.close(progress_w)
        # Привязываем reader к progress_r
        progress_reader = await asyncio.get_event_loop().connect_read_pipe(
            asyncio.StreamReader, os.fdopen(progress_r, "rb", buffering=0)
        )
        return proc, progress_reader

    async def _monitor_progress(self, reader: asyncio.StreamReader):
        """
        Читает key=value из -progress и обновляет метрики.
        Ключевые поля: out_time_ms, fps, bitrate, total_size.
        """
        src = self.cfg.source_name
        while not reader.at_eof() and not self._stop.is_set():
            line = await reader.readline()
            if not line:
                await asyncio.sleep(0.05)
                continue
            try:
                kv = _parse_progress_line(line.decode("utf-8", "ignore"))
                if not kv:
                    continue
                if "fps" in kv:
                    try:
                        FFMPEG_FPS.labels(src).set(float(kv["fps"]))
                    except Exception:
                        pass
                if "bitrate" in kv:
                    # bitrate формат: "1234.5kbits/s" или "N/A"
                    b = kv["bitrate"]
                    if b != "N/A" and b.endswith("kbits/s"):
                        try:
                            FFMPEG_BITRATE.labels(src).set(float(b.replace("kbits/s", "")))
                        except Exception:
                            pass
                if "out_time_ms" in kv:
                    try:
                        FFMPEG_OUTTIME.labels(src).set(int(kv["out_time_ms"]) / 1_000_000.0)
                    except Exception:
                        pass
                if "total_size" in kv:
                    try:
                        FFMPEG_BYTES.labels(src).inc(int(kv["total_size"]))
                    except Exception:
                        pass
                if "frame" in kv:
                    try:
                        FFMPEG_FRAMES.labels(src).inc(int(kv["frame"]))
                    except Exception:
                        pass
            except Exception:
                LOG.debug("progress parse error", exc_info=True)

    async def _hls_housekeeper(self):
        """
        Следит за каталoгом HLS: метрики, бюджет, ретенция.
        """
        if not self.cfg.hls_dir:
            return
        src = self.cfg.source_name
        hls_path = self.cfg.hls_dir
        retention_sec = self.cfg.hls_retention_minutes * 60
        max_bytes = self.cfg.hls_max_dir_mb * 1024 * 1024

        while not self._stop.is_set():
            try:
                if not hls_path.exists():
                    await asyncio.sleep(1.0)
                    continue
                # Кол-во сегментов и размер
                files = list(hls_path.rglob("*.ts")) + list(hls_path.rglob("*.m4s"))
                HLS_SEGMENTS.labels(src).set(len(files))
                dir_bytes = _dir_size_bytes(hls_path)
                HLS_DIR_BYTES.labels(src).set(dir_bytes)

                # Ретенция по времени
                now = time.time()
                for p in files:
                    try:
                        if now - p.stat().st_mtime > retention_sec:
                            p.unlink(missing_ok=True)
                    except Exception:
                        LOG.debug("retention delete error: %s", p, exc_info=True)

                # Принудительный бюджет: если превышен — удаляем старые
                if dir_bytes > max_bytes:
                    # сортировка по времени изменения (старые первыми)
                    files_sorted = sorted(files, key=lambda p: p.stat().st_mtime)
                    for p in files_sorted:
                        try:
                            p.unlink(missing_ok=True)
                            dir_bytes -= p.stat().st_size if p.exists() else 0
                            if dir_bytes <= max_bytes:
                                break
                        except Exception:
                            pass
            except Exception:
                LOG.debug("housekeeper error", exc_info=True)

            await asyncio.sleep(2.0)

    async def _s3_uploader(self):
        """
        Отслеживает новые HLS файлы и загружает их в S3. После загрузки
        может удалять локальные файлы (опционально).
        """
        if not (self.cfg.s3_enabled and self.cfg.hls_dir and _HAS_BOTO3):
            return

        session_kwargs = {}
        if self.cfg.s3_access_key and self.cfg.s3_secret_key:
            session_kwargs["aws_access_key_id"] = self.cfg.s3_access_key
            session_kwargs["aws_secret_access_key"] = self.cfg.s3_secret_key
        if self.cfg.s3_region:
            session_kwargs["region_name"] = self.cfg.s3_region
        s3 = boto3.client("s3", endpoint_url=self.cfg.s3_endpoint, **session_kwargs)
        bucket = self.cfg.s3_bucket or ""

        seen: set[Path] = set()
        while not self._stop.is_set():
            try:
                for p in self.cfg.hls_dir.rglob("*"):
                    if not p.is_file():
                        continue
                    if p.suffix not in {".m3u8", ".ts", ".m4s", ".mp4"}:
                        continue
                    if p in seen:
                        continue
                    # Ждём стабилизации размера (файл дописывается ffmpeg)
                    size0 = p.stat().st_size
                    await asyncio.sleep(0.2)
                    size1 = p.stat().st_size
                    if size1 != size0:
                        continue
                    key = f"{self.cfg.s3_prefix.rstrip('/')}/{p.relative_to(self.cfg.hls_dir).as_posix()}"
                    try:
                        s3.upload_file(str(p), bucket, key)
                        S3_UPLOADS.labels(bucket).inc()
                        seen.add(p)
                        if self.cfg.s3_delete_local_after_upload and p.suffix != ".m3u8":
                            p.unlink(missing_ok=True)
                    except Exception as e:
                        S3_ERRORS.labels(bucket).inc()
                        LOG.warning("S3 upload failed: %s -> s3://%s/%s (%s)", p, bucket, key, e)
            except Exception:
                LOG.debug("s3 uploader iteration error", exc_info=True)

            await asyncio.sleep(0.5)

    async def run(self):
        """
        Главный цикл: запуск ffmpeg, мониторинг прогресса, бэкофф‑перезапуски.
        """
        if self.cfg.metrics_port:
            start_http_server(self.cfg.metrics_port)
            LOG.info("Prometheus metrics on :%d/metrics", self.cfg.metrics_port)

        if self.cfg.hls_dir:
            self.cfg.hls_dir.mkdir(parents=True, exist_ok=True)

        self._hls_housekeeper_task = asyncio.create_task(self._hls_housekeeper())
        if self.cfg.s3_enabled:
            self._hls_uploader_task = asyncio.create_task(self._s3_uploader())

        restart = 0
        backoff = self.cfg.backoff_initial
        src = self.cfg.source_name

        while not self._stop.is_set():
            with _TRACER.start_as_current_span("ffmpeg.run"):
                try:
                    proc, progress_reader = await self._spawn_ffmpeg()
                except Exception as e:
                    LOG.error("FFmpeg spawn failed: %s", e)
                    await self._sleep_backoff(backoff)
                    backoff = min(self.cfg.backoff_max, backoff * 2.0 + random.uniform(0, 0.5))
                    continue

                FFMPEG_UP.labels(src).set(1)
                HEALTH_READY.labels(src).set(1)
                restart += 1 if self._restart_count else 0
                self._restart_count += 1
                FFMPEG_RESTARTS.labels(src).inc()

                # Мониторинг прогресса и stderr (на случай ошибок)
                progress_task = asyncio.create_task(self._monitor_progress(progress_reader))
                stderr_task = asyncio.create_task(self._drain_stream(proc.stderr))

                # Ожидание завершения процесса или запроса остановки
                done, pending = await asyncio.wait(
                    {asyncio.create_task(proc.wait()), progress_task, stderr_task, asyncio.create_task(self._stop.wait())},
                    return_when=asyncio.FIRST_COMPLETED,
                )

                # Если пришёл сигнал на остановку — завершаем FFmpeg
                if self._stop.is_set():
                    await self._terminate_proc(proc)
                    break

                # Процесс завершился сам — читаем код
                code = proc.returncode
                FFMPEG_UP.labels(src).set(0)
                HEALTH_READY.labels(src).set(0)

                # Очищаем задания
                for t in (progress_task, stderr_task):
                    with contextlib.suppress(Exception):
                        t.cancel()

                if code == 0:
                    FFMPEG_EXITS.labels(src, str(code)).inc()
                    LOG.info("FFmpeg exited normally (code=0)")
                    break  # нормальное завершение
                else:
                    FFMPEG_EXITS.labels(src, str(code)).inc()
                    LOG.warning("FFmpeg crashed (code=%s), scheduling restart", code)

                    # лимит перезапусков
                    if self.cfg.max_restarts and self._restart_count >= self.cfg.max_restarts:
                        LOG.error("Max restarts reached (%d), giving up", self.cfg.max_restarts)
                        break

                    await self._sleep_backoff(backoff)
                    backoff = min(self.cfg.backoff_max, backoff * 2.0 + random.uniform(0, 0.5))

        # Завершение фона
        for t in (self._hls_uploader_task, self._hls_housekeeper_task):
            if t:
                with contextlib.suppress(Exception):
                    t.cancel()

    async def _drain_stream(self, stream: asyncio.StreamReader):
        """
        Читает stderr FFmpeg и выводит строки в лог (на уровне warning).
        """
        while not stream.at_eof() and not self._stop.is_set():
            line = await stream.readline()
            if not line:
                break
            LOG.warning("ffmpeg: %s", line.decode("utf-8", "ignore").rstrip())

    async def _sleep_backoff(self, seconds: float):
        await asyncio.sleep(max(0.5, seconds))

    async def _terminate_proc(self, proc: asyncio.subprocess.Process):
        if proc.returncode is not None:
            return
        with contextlib.suppress(ProcessLookupError):
            proc.terminate()
        try:
            await asyncio.wait_for(proc.wait(), timeout=5.0)
        except asyncio.TimeoutError:
            with contextlib.suppress(ProcessLookupError):
                proc.kill()
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(proc.wait(), timeout=3.0)

    async def stop(self):
        self._stop.set()

# ---------------- CLI/entrypoint ----------------
def _env(key: str, default: Optional[str] = None) -> Optional[str]:
    return os.getenv(key, default)

def _int(key: str, default: int) -> int:
    try:
        return int(_env(key, str(default)) or default)
    except Exception:
        return default

def _float(key: str, default: float) -> float:
    try:
        return float(_env(key, str(default)) or default)
    except Exception:
        return default

async def _main():
    """
    Пример самостоятельного запуска:
    Переменные окружения (пример):
      INGEST_SOURCE=rtmp://upstream/live/cam01
      INGEST_RTMP_PUSH=rtmp://edge/live/cam01
      INGEST_HLS_DIR=/var/hls/cam01
      INGEST_HLS_SEG_TIME=2
      INGEST_HLS_LIST_SIZE=6
      METRICS_PORT=9103
      S3_ENABLED=true
      S3_BUCKET=pic-archive
      S3_ENDPOINT=http://minio.dev.svc:9000
      S3_ACCESS_KEY=minio
      S3_SECRET_KEY=minio123
    """
    hls_dir = _env("INGEST_HLS_DIR")
    cfg = IngestConfig(
        source_url=_env("INGEST_SOURCE", "rtmp://localhost/live/cam01"),
        rtmp_push_url=_env("INGEST_RTMP_PUSH"),
        hls_dir=Path(hls_dir) if hls_dir else None,
        hls_segment_time=_int("INGEST_HLS_SEG_TIME", 2),
        hls_list_size=_int("INGEST_HLS_LIST_SIZE", 6),
        hls_delete=_bool(_env("INGEST_HLS_DELETE", "true"), True),
        video_codec=_env("INGEST_V_CODEC", "copy"),
        audio_codec=_env("INGEST_A_CODEC", "copy"),
        hwaccel=_env("INGEST_HWACCEL"),
        max_restarts=_int("INGEST_MAX_RESTARTS", 0),
        backoff_initial=_float("INGEST_BACKOFF_INITIAL", 1.0),
        backoff_max=_float("INGEST_BACKOFF_MAX", 30.0),
        metrics_port=_int("METRICS_PORT", 0),
        source_name=_env("SOURCE_NAME", "cam01"),
        s3_enabled=_bool(_env("S3_ENABLED"), False),
        s3_bucket=_env("S3_BUCKET"),
        s3_prefix=_env("S3_PREFIX", "hls/"),
        s3_endpoint=_env("S3_ENDPOINT"),
        s3_region=_env("S3_REGION"),
        s3_access_key=_env("S3_ACCESS_KEY"),
        s3_secret_key=_env("S3_SECRET_KEY"),
        s3_force_path_style=_bool(_env("S3_FORCE_PATH_STYLE", "true"), True),
        s3_delete_local_after_upload=_bool(_env("S3_DELETE_LOCAL_AFTER_UPLOAD", "false"), False),
        hls_max_dir_mb=_int("HLS_MAX_DIR_MB", 1024),
        hls_retention_minutes=_int("HLS_RETENTION_MIN", 60),
    )

    mgr = FFmpegIngestManager(cfg)

    loop = asyncio.get_running_loop()
    stop_event = asyncio.Event()

    def _on_signal(*_):
        stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(NotImplementedError):
            loop.add_signal_handler(sig, _on_signal)

    run_task = asyncio.create_task(mgr.run())
    await stop_event.wait()
    await mgr.stop()
    with contextlib.suppress(asyncio.CancelledError):
        await run_task

if __name__ == "__main__":
    try:
        asyncio.run(_main())
    except KeyboardInterrupt:
        pass
