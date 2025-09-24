# physical-integration-core/physical_integration/video/rtsp_ingest.py
"""
Industrial-grade async RTSP ingester for NeuroCity / physical-integration-core.

Features:
- Async ffmpeg-based ingest from RTSP with TCP/UDP transport.
- ffprobe preflight (width/height/fps) with safe fallbacks.
- Raw frame extraction over stdout pipe (bgr24), zero-copy reshape with NumPy.
- Watchdog for stalled streams; automatic restarts with exponential backoff.
- Pluggable sinks (FrameSink protocol): QueueSink, DiskSink; easy to extend.
- Structured logging with credential redaction in URLs.
- Prometheus metrics (optional): frames, drops, bytes, restarts, last ts, interframe latency.
- Graceful shutdown handling (SIGINT/SIGTERM), resource cleanup.
- Configuration via Pydantic settings (env or ctor).

Dependencies (recommended):
- Python 3.10+
- ffmpeg, ffprobe in PATH
- numpy
- pydantic>=1.10
- prometheus_client (optional, auto-disabled if not installed)
- imageio (optional, for DiskSink only)

Example (module entrypoint):
    python -m physical_integration.video.rtsp_ingest

Environment (examples):
    RTSP_URL="rtsp://camera.local/stream1"
    RTSP_USERNAME="user"
    RTSP_PASSWORD="pass"
    METRICS_PORT=9308
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import signal
import sys
import time
from dataclasses import dataclass
from typing import Optional, Protocol, runtime_checkable, List, Tuple

import numpy as np

try:
    # Optional metrics
    from prometheus_client import Counter, Gauge, Histogram, start_http_server

    _PROM_AVAILABLE = True
except Exception:  # pragma: no cover
    _PROM_AVAILABLE = False

    class _NoopMetric:
        def __init__(self, *_, **__): ...
        def labels(self, *_, **__): return self
        def inc(self, *_): ...
        def set(self, *_): ...
        def observe(self, *_): ...

    def start_http_server(*_, **__): ...
    Counter = Gauge = Histogram = _NoopMetric  # type: ignore


try:
    from pydantic import BaseSettings, Field, SecretStr, validator
except Exception as e:
    raise RuntimeError(
        "pydantic is required for configuration. Install pydantic>=1.10"
    ) from e


# ----------------------------- Utilities ------------------------------------


def _sanitize_rtsp(url: str) -> str:
    """Mask credentials in RTSP URLs for safe logging."""
    # rtsp://user:pass@host -> rtsp://***:***@host
    if "://" not in url:
        return url
    scheme, rest = url.split("://", 1)
    if "@" not in rest or ":" not in rest.split("@", 1)[0]:
        return url
    cred, host = rest.split("@", 1)
    return f"{scheme}://***:***@{host}"


def _now_monotonic() -> float:
    return time.monotonic()


# ----------------------------- Configuration --------------------------------


class RTSPIngestSettings(BaseSettings):
    # Core RTSP
    rtsp_url: str = Field(..., env="RTSP_URL")
    username: Optional[str] = Field(default=None, env="RTSP_USERNAME")
    password: Optional[SecretStr] = Field(default=None, env="RTSP_PASSWORD")
    transport: str = Field(default="tcp", env="RTSP_TRANSPORT")  # "tcp" or "udp"

    # Binary paths
    ffmpeg_path: str = Field(default="ffmpeg", env="FFMPEG_PATH")
    ffprobe_path: str = Field(default="ffprobe", env="FFPROBE_PATH")

    # Decode/output
    width: Optional[int] = Field(default=None, env="FRAME_WIDTH")
    height: Optional[int] = Field(default=None, env="FRAME_HEIGHT")
    pix_fmt: str = Field(default="bgr24", env="PIX_FMT")
    output_format: str = Field(default="rawvideo", env="OUTPUT_FORMAT")  # fixed

    # Performance
    target_fps: Optional[float] = Field(default=None, env="TARGET_FPS")
    drop_to_fps: Optional[float] = Field(default=None, env="DROP_TO_FPS")
    read_chunk_timeout_sec: float = Field(default=15.0, env="READ_TIMEOUT_SEC")
    watchdog_timeout_sec: float = Field(default=10.0, env="WATCHDOG_TIMEOUT_SEC")
    max_queue: int = Field(default=4, env="MAX_QUEUE")

    # Reliability
    reconnect_initial_delay: float = Field(default=1.5, env="RECONNECT_DELAY_SEC")
    reconnect_max_delay: float = Field(default=30.0, env="RECONNECT_MAX_DELAY_SEC")
    max_restarts: int = Field(default=0, env="MAX_RESTARTS")  # 0 = unlimited

    # HW accel (e.g., "cuda", "qsv", "vaapi") or None
    hwaccel: Optional[str] = Field(default=None, env="HWACCEL")

    # Logging & metrics
    log_level: str = Field(default="INFO", env="LOG_LEVEL")
    redact_credentials_in_logs: bool = Field(default=True, env="REDACT_CREDS")
    metrics_port: Optional[int] = Field(default=None, env="METRICS_PORT")

    # Optional frame save (debug)
    save_every_nth_frame: int = Field(default=0, env="SAVE_EVERY_NTH")
    save_dir: Optional[str] = Field(default=None, env="SAVE_DIR")

    class Config:
        env_file = os.environ.get("RTSP_INGEST_ENV", ".env")
        env_file_encoding = "utf-8"
        case_sensitive = False

    @validator("transport")
    def _validate_transport(cls, v: str) -> str:
        if v not in ("tcp", "udp"):
            raise ValueError("transport must be 'tcp' or 'udp'")
        return v

    @validator("log_level")
    def _validate_log_level(cls, v: str) -> str:
        v_up = v.upper()
        if v_up not in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"):
            raise ValueError("log_level must be a valid logging level")
        return v_up

    def build_rtsp_url(self) -> str:
        if (self.username and self.password) and ("@" not in self.rtsp_url.split("://", 1)[-1]):
            # Inject credentials if not included already
            scheme, rest = self.rtsp_url.split("://", 1)
            return f"{scheme}://{self.username}:{self.password.get_secret_value()}@{rest}"
        return self.rtsp_url

    def safe_rtsp_url_for_logs(self) -> str:
        url = self.build_rtsp_url()
        return _sanitize_rtsp(url) if self.redact_credentials_in_logs else url


# ----------------------------- Prometheus ------------------------------------


class Metrics:
    def __init__(self) -> None:
        self.frames_total = Counter(
            "rtsp_frames_total", "Total frames ingested"
        )
        self.frames_dropped_total = Counter(
            "rtsp_frames_dropped_total", "Total frames dropped due to backpressure or errors"
        )
        self.bytes_total = Counter(
            "rtsp_bytes_total", "Total bytes received from ffmpeg stdout"
        )
        self.restarts_total = Counter(
            "rtsp_restarts_total", "Total ffmpeg restarts"
        )
        self.last_frame_ts = Gauge(
            "rtsp_last_frame_timestamp_seconds", "Monotonic timestamp of the last received frame"
        )
        self.interframe_latency = Histogram(
            "rtsp_interframe_latency_seconds", "Time between consecutive frames",
            buckets=(0.0, 0.01, 0.02, 0.033, 0.05, 0.1, 0.2, 0.5, 1.0)
        )
        self.watchdog_triggered_total = Counter(
            "rtsp_watchdog_triggered_total", "Watchdog triggers due to no frames"
        )


# ----------------------------- Frame sinks -----------------------------------


@runtime_checkable
class FrameSink(Protocol):
    async def on_frame(self, frame: np.ndarray, ts_monotonic: float) -> None: ...


class NullSink:
    async def on_frame(self, frame: np.ndarray, ts_monotonic: float) -> None:
        return


class QueueSink:
    """Push frames into an asyncio.Queue[(np.ndarray, float)]."""

    def __init__(self, queue: asyncio.Queue):
        self.queue = queue

    async def on_frame(self, frame: np.ndarray, ts_monotonic: float) -> None:
        await self.queue.put((frame, ts_monotonic))


class DiskSink:
    """Save every Nth frame as JPEG to disk (debug/forensics)."""

    def __init__(self, save_dir: str, every_nth: int = 30):
        import pathlib

        self.save_dir = pathlib.Path(save_dir)
        self.save_dir.mkdir(parents=True, exist_ok=True)
        if every_nth < 1:
            every_nth = 1
        self.every_nth = every_nth
        self._counter = 0

    async def on_frame(self, frame: np.ndarray, ts_monotonic: float) -> None:
        self._counter += 1
        if self._counter % self.every_nth != 0:
            return
        # Lazy import to avoid hard dep in non-debug setups
        try:
            import imageio.v3 as iio  # type: ignore
        except Exception as e:  # pragma: no cover
            # fallback to OpenCV if available
            try:
                import cv2  # type: ignore

                fname = f"frame_{int(ts_monotonic * 1000)}.jpg"
                cv2.imwrite(str(self.save_dir / fname), frame)
                return
            except Exception:
                raise RuntimeError(
                    "Install imageio or opencv-python to enable DiskSink"
                ) from e

        fname = f"frame_{int(ts_monotonic * 1000)}.jpg"
        # frame is BGR; convert to RGB for correct JPEG colors
        rgb = frame[:, :, ::-1]
        iio.imwrite(self.save_dir / fname, rgb, quality=90)


# ----------------------------- ffprobe helper --------------------------------


async def ffprobe_stream_dims(
    settings: RTSPIngestSettings, logger: logging.Logger
) -> Tuple[int, int, Optional[float]]:
    """
    Probe width/height/fps via ffprobe. Returns (w, h, fps or None).
    """
    url = settings.build_rtsp_url()
    cmd = [
        settings.ffprobe_path, "-v", "error",
        "-select_streams", "v:0",
        "-show_entries", "stream=width,height,r_frame_rate",
        "-of", "default=nw=1",
        "-rtsp_transport", settings.transport,
        url,
    ]

    redacted_cmd = [settings.ffprobe_path if i == 0 else (settings.safe_rtsp_url_for_logs() if i == len(cmd) - 1 else v)  # type: ignore
                    for i, v in enumerate(cmd)]

    logger.debug("ffprobe command", extra={"cmd": redacted_cmd})

    proc = await asyncio.create_subprocess_exec(
        *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    out, err = await proc.communicate()
    if proc.returncode != 0:
        logger.warning(
            "ffprobe failed; will rely on provided dimensions",
            extra={"code": proc.returncode, "stderr": err.decode(errors="ignore")}
        )
        if settings.width and settings.height:
            return settings.width, settings.height, settings.target_fps
        raise RuntimeError("ffprobe failed and width/height not provided")

    w = h = None
    fps: Optional[float] = None
    for line in out.decode().splitlines():
        if line.startswith("width="):
            w = int(line.split("=", 1)[1])
        elif line.startswith("height="):
            h = int(line.split("=", 1)[1])
        elif line.startswith("r_frame_rate="):
            val = line.split("=", 1)[1].strip()
            if "/" in val:
                num, den = val.split("/", 1)
                try:
                    numf, denf = float(num), float(den)
                    if denf != 0:
                        fps = numf / denf
                except Exception:
                    pass
            else:
                try:
                    fps = float(val)
                except Exception:
                    pass
    if w is None or h is None:
        raise RuntimeError("ffprobe did not return width/height")
    return w, h, fps


# ----------------------------- Ingester --------------------------------------


@dataclass
class IngestState:
    width: int
    height: int
    frame_size: int  # width * height * 3
    last_frame_ts: float = 0.0
    running: bool = True


class RTSPIngester:
    def __init__(
        self,
        settings: RTSPIngestSettings,
        sinks: Optional[List[FrameSink]] = None,
        metrics: Optional[Metrics] = None,
        logger: Optional[logging.Logger] = None,
    ):
        self.settings = settings
        self.sinks = sinks or [NullSink()]
        self.metrics = metrics or Metrics()
        self.log = logger or logging.getLogger("rtsp_ingest")
        self.log.setLevel(getattr(logging, settings.log_level))

        self._proc: Optional[asyncio.subprocess.Process] = None
        self._reader_task: Optional[asyncio.Task] = None
        self._watchdog_task: Optional[asyncio.Task] = None
        self._shutdown = asyncio.Event()
        self._restarts = 0

        # Backpressure control
        self._frame_queue: asyncio.Queue[Tuple[np.ndarray, float]] = asyncio.Queue(
            maxsize=max(1, settings.max_queue)
        )
        self._dispatcher_task: Optional[asyncio.Task] = None

        # FPS limiter
        self._emit_interval = (
            1.0 / self.settings.drop_to_fps if self.settings.drop_to_fps else None
        )
        self._next_emit_time: Optional[float] = None

    async def start(self) -> None:
        # Metrics server
        if _PROM_AVAILABLE and self.settings.metrics_port:
            start_http_server(self.settings.metrics_port)
            self.log.info(
                "Prometheus metrics server started",
                extra={"port": self.settings.metrics_port},
            )

        # Determine dimensions
        width = self.settings.width
        height = self.settings.height
        fps_hint = self.settings.target_fps

        if width is None or height is None:
            width, height, fps_probe = await ffprobe_stream_dims(self.settings, self.log)
            if fps_hint is None:
                fps_hint = fps_probe

        state = IngestState(width=width, height=height, frame_size=width * height * 3)
        self.log.info(
            "RTSP ingester starting",
            extra={
                "url": self.settings.safe_rtsp_url_for_logs(),
                "width": width,
                "height": height,
                "fps_hint": fps_hint,
                "transport": self.settings.transport,
                "hwaccel": self.settings.hwaccel or "cpu",
            },
        )

        # Launch tasks
        self._dispatcher_task = asyncio.create_task(self._dispatcher_loop(), name="dispatcher")
        await self._start_ffmpeg(state)
        self._watchdog_task = asyncio.create_task(self._watchdog_loop(state), name="watchdog")

    async def _start_ffmpeg(self, state: IngestState) -> None:
        url = self.settings.build_rtsp_url()
        cmd = [
            self.settings.ffmpeg_path,
            "-loglevel", "error",
            "-rtsp_transport", self.settings.transport,
            "-rw_timeout", str(int(self.settings.read_chunk_timeout_sec * 1_000_000)),
            "-stimeout", str(int(self.settings.read_chunk_timeout_sec * 1_000_000)),
            "-i", url,
            "-an", "-sn", "-dn",
            "-threads", "1",
            "-vsync", "0",
        ]

        vf_filters: List[str] = []
        if self.settings.target_fps:
            vf_filters.append(f"fps={self.settings.target_fps:.3f}")
        if self.settings.width and self.settings.height:
            vf_filters.append(f"scale={self.settings.width}:{self.settings.height}:flags=bilinear")
        if vf_filters:
            cmd += ["-vf", ",".join(vf_filters)]

        if self.settings.hwaccel:
            cmd = [
                self.settings.ffmpeg_path,
                "-hide_banner",
                "-loglevel", "error",
                "-hwaccel", self.settings.hwaccel,
                "-rtsp_transport", self.settings.transport,
                "-rw_timeout", str(int(self.settings.read_chunk_timeout_sec * 1_000_000)),
                "-stimeout", str(int(self.settings.read_chunk_timeout_sec * 1_000_000)),
                "-i", url,
                "-an", "-sn", "-dn",
                "-threads", "1",
                "-vsync", "0",
            ] + (["-vf", ",".join(vf_filters)] if vf_filters else [])

        cmd += [
            "-pix_fmt", self.settings.pix_fmt,
            "-f", self.settings.output_format,
            "pipe:1",
        ]

        redacted_cmd = cmd[:]
        # redact the URL for logs
        try:
            url_index = redacted_cmd.index(url)
            redacted_cmd[url_index] = self.settings.safe_rtsp_url_for_logs()
        except ValueError:
            pass

        self.log.info("Starting ffmpeg", extra={"cmd": redacted_cmd})

        self._proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        self._reader_task = asyncio.create_task(self._reader_loop(state), name="reader")

    async def _reader_loop(self, state: IngestState) -> None:
        assert self._proc and self._proc.stdout
        stdout = self._proc.stdout

        buf = bytearray()
        frame_size = state.frame_size
        last_ts = _now_monotonic()

        try:
            while not self._shutdown.is_set():
                chunk = await stdout.read(frame_size)
                if not chunk:
                    # EOF
                    raise EOFError("ffmpeg stdout closed")
                buf += chunk
                self.metrics.bytes_total.inc(len(chunk))
                while len(buf) >= frame_size:
                    frame_bytes = buf[:frame_size]
                    del buf[:frame_size]
                    ts = _now_monotonic()
                    self.metrics.interframe_latency.observe(ts - last_ts)
                    last_ts = ts

                    frame = np.frombuffer(frame_bytes, dtype=np.uint8)
                    try:
                        frame = frame.reshape((state.height, state.width, 3))
                    except ValueError:
                        # malformed chunk; drop
                        self.metrics.frames_dropped_total.inc()
                        continue

                    # FPS limiter (optional)
                    if self._emit_interval is not None:
                        if self._next_emit_time is None:
                            self._next_emit_time = ts
                        if ts < self._next_emit_time:
                            # drop frame
                            self.metrics.frames_dropped_total.inc()
                            continue
                        self._next_emit_time += self._emit_interval

                    # Backpressure-aware queue put_nowait
                    try:
                        self._frame_queue.put_nowait((frame, ts))
                    except asyncio.QueueFull:
                        self.metrics.frames_dropped_total.inc()
                        continue

                    state.last_frame_ts = ts
                    self.metrics.last_frame_ts.set(ts)
                    self.metrics.frames_total.inc()

        except asyncio.CancelledError:
            pass
        except Exception as e:
            self.log.warning("Reader loop error", extra={"error": repr(e)})
        finally:
            # Ensure process is reaped if reader exits first
            await self._terminate_ffmpeg()

    async def _dispatcher_loop(self) -> None:
        """Dispatch frames to all sinks."""
        try:
            while not self._shutdown.is_set():
                frame, ts = await self._frame_queue.get()
                # Dispatch sequentially; for heavy sinks, make them internally async
                for sink in self.sinks:
                    try:
                        await sink.on_frame(frame, ts)
                    except Exception as e:
                        self.log.error(
                            "Sink error", extra={"sink": sink.__class__.__name__, "error": repr(e)}
                        )
        except asyncio.CancelledError:
            pass

    async def _watchdog_loop(self, state: IngestState) -> None:
        """Monitor frame flow and restart ffmpeg on stalls."""
        delay = self.settings.reconnect_initial_delay
        try:
            while not self._shutdown.is_set():
                await asyncio.sleep(self.settings.watchdog_timeout_sec)
                elapsed = _now_monotonic() - state.last_frame_ts
                if state.last_frame_ts == 0.0 or elapsed < self.settings.watchdog_timeout_sec:
                    # healthy
                    delay = self.settings.reconnect_initial_delay
                    continue

                self.metrics.watchdog_triggered_total.inc()
                self.log.warning(
                    "Watchdog: no frames; restarting ffmpeg",
                    extra={"elapsed_sec": round(elapsed, 3)}
                )
                await self._restart_ffmpeg(state)
                # exponential backoff
                await asyncio.sleep(delay)
                delay = min(self.settings.reconnect_max_delay, delay * 2.0)
        except asyncio.CancelledError:
            pass

    async def _restart_ffmpeg(self, state: IngestState) -> None:
        if self.settings.max_restarts and self._restarts >= self.settings.max_restarts:
            self.log.error("Max restarts reached; stopping ingester", extra={"restarts": self._restarts})
            await self.stop()
            return
        self._restarts += 1
        self.metrics.restarts_total.inc()
        await self._terminate_ffmpeg()
        await self._start_ffmpeg(state)

    async def _terminate_ffmpeg(self) -> None:
        proc = self._proc
        self._proc = None
        if not proc:
            return
        with contextlib.suppress(Exception):
            if proc.returncode is None:
                proc.terminate()
                try:
                    await asyncio.wait_for(proc.wait(), timeout=3.0)
                except asyncio.TimeoutError:
                    proc.kill()
                    with contextlib.suppress(Exception):
                        await proc.wait()

        # Cancel reader if still alive
        if self._reader_task and not self._reader_task.done():
            self._reader_task.cancel()
            with contextlib.suppress(Exception):
                await self._reader_task
        self._reader_task = None

    async def stop(self) -> None:
        self._shutdown.set()
        await self._terminate_ffmpeg()
        if self._watchdog_task and not self._watchdog_task.done():
            self._watchdog_task.cancel()
            with contextlib.suppress(Exception):
                await self._watchdog_task
        if self._dispatcher_task and not self._dispatcher_task.done():
            self._dispatcher_task.cancel()
            with contextlib.suppress(Exception):
                await self._dispatcher_task


# ----------------------------- Entrypoint ------------------------------------


def _configure_logging(level: str) -> logging.Logger:
    logger = logging.getLogger("rtsp_ingest")
    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter(
        fmt="%(asctime)sZ %(levelname)s %(name)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.propagate = False
    logger.setLevel(getattr(logging, level))
    return logger


async def _run_from_env() -> None:
    settings = RTSPIngestSettings()  # reads env/.env
    logger = _configure_logging(settings.log_level)

    # Sinks configuration
    sinks: List[FrameSink] = []
    if settings.save_every_nth_frame > 0 and settings.save_dir:
        sinks.append(DiskSink(settings.save_dir, settings.save_every_nth_frame))
    if not sinks:
        sinks.append(NullSink())

    ing = RTSPIngester(settings=settings, sinks=sinks, logger=logger)

    # Graceful signals
    loop = asyncio.get_running_loop()
    stop_ev = asyncio.Event()

    def _on_signal(signame: str):
        logger.info("Received signal; shutting down", extra={"signal": signame})
        stop_ev.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(NotImplementedError):
            loop.add_signal_handler(sig, _on_signal, sig.name)

    await ing.start()
    await stop_ev.wait()
    await ing.stop()


def main() -> None:
    try:
        asyncio.run(_run_from_env())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
