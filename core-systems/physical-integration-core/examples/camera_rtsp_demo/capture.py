#!/usr/bin/env python3
# examples/camera_rtsp_demo/capture.py
# Промышленный RTSP-демо граббер: переподключение, ограничение FPS, детекция движения,
# снимки и MP4 сегменты, Prometheus-метрики, аккуратный shutdown.
from __future__ import annotations

import argparse
import cv2  # type: ignore
import json
import logging
import math
import os
import queue
import signal
import sys
import threading
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Deque, Dict, Optional, Tuple

# ---- Опциональные зависимости ----
try:
    from prometheus_client import Counter, Gauge, Histogram, Summary, start_http_server
    _HAS_PROM = True
except Exception:
    _HAS_PROM = False

LOG = logging.getLogger("rtsp-capture")

# =========================
# Метрики Prometheus
# =========================
if _HAS_PROM:
    CAPTURE_UP = Gauge("pic_cam_capture_up", "Capture running flag (1/0)", ["name"])
    CAPTURE_FPS = Gauge("pic_cam_capture_fps", "Decoded FPS", ["name"])
    CAPTURE_QUEUE = Gauge("pic_cam_capture_queue", "Capture queue size", ["name"])
    CAPTURE_RESTARTS = Counter("pic_cam_capture_restarts_total", "Reconnect attempts", ["name"])
    CAPTURE_ERRORS = Counter("pic_cam_capture_errors_total", "Capture errors", ["name", "type"])
    MOTION_SCORE = Gauge("pic_cam_motion_score", "Motion score (0..1)", ["name"])
    SNAPSHOTS = Counter("pic_cam_snapshots_total", "Saved snapshots (JPEG)", ["name", "reason"])
    SEGMENTS = Counter("pic_cam_segments_total", "Saved MP4 segments", ["name", "reason"])
    IO_BYTES = Counter("pic_cam_io_bytes_total", "Bytes written to disk", ["name", "kind"])  # kind: jpeg|mp4
    WRITE_LAT = Histogram("pic_cam_write_duration_seconds", "Write durations", ["name", "kind"], buckets=(0.01, 0.05, 0.1, 0.25, 0.5,1,2,5))
else:
    class _Dummy:
        def labels(self, *a, **k): return self
        def set(self, *a, **k): pass
        def inc(self, *a, **k): pass
        def observe(self, *a, **k): pass
    CAPTURE_UP = CAPTURE_FPS = CAPTURE_QUEUE = CAPTURE_RESTARTS = CAPTURE_ERRORS = MOTION_SCORE = SNAPSHOTS = SEGMENTS = IO_BYTES = WRITE_LAT = _Dummy()

# =========================
# Утилиты
# =========================
def utc_now() -> datetime:
    return datetime.now(timezone.utc)

def ts_str(dt: Optional[datetime] = None) -> str:
    d = dt or utc_now()
    return d.strftime("%Y%m%dT%H%M%SZ")

def ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)

def clamp(v: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, v))

# =========================
# Захват кадров (в отдельном потоке)
# =========================
class RTSPCapture(threading.Thread):
    def __init__(
        self,
        name: str,
        rtsp_url: str,
        q: queue.Queue[Tuple[float, any]],
        *,
        transport: str = "tcp",
        width: Optional[int] = None,
        height: Optional[int] = None,
        fps_limit: Optional[float] = None,
        max_restarts: int = 0,  # 0 = бесконечно
        backoff_initial: float = 1.0,
        backoff_max: float = 15.0,
        read_timeout_sec: float = 10.0,
    ):
        super().__init__(daemon=True)
        self.name_ = name
        self.rtsp_url = self._add_transport(rtsp_url, transport)
        self.q = q
        self.width = width
        self.height = height
        self.fps_limit = fps_limit
        self.max_restarts = max_restarts
        self.backoff_initial = backoff_initial
        self.backoff_max = backoff_max
        self.read_timeout_sec = read_timeout_sec
        self._stop = threading.Event()

    @staticmethod
    def _add_transport(url: str, transport: str) -> str:
        if "rtsp_transport" in url:
            return url
        sep = "&" if "?" in url else "?"
        return f"{url}{sep}rtsp_transport={transport}"

    def stop(self):
        self._stop.set()

    def run(self):
        LOG.info("Capture thread starting for %s", self.name_)
        backoff = self.backoff_initial
        restarts = 0
        last_emit = 0.0
        frame_count = 0
        CAPTURE_UP.labels(self.name_).set(0)

        while not self._stop.is_set():
            cap = None
            try:
                cap = cv2.VideoCapture(self.rtsp_url, cv2.CAP_FFMPEG)
                if not cap.isOpened():
                    raise RuntimeError("VideoCapture open failed")

                # Параметры
                if self.width: cap.set(cv2.CAP_PROP_FRAME_WIDTH, self.width)
                if self.height: cap.set(cv2.CAP_PROP_FRAME_HEIGHT, self.height)
                if self.fps_limit:  # это именно «желание»; реальный FPS ограничим программно
                    cap.set(cv2.CAP_PROP_FPS, self.fps_limit)

                LOG.info("Capture opened: %s (w=%s h=%s)", self.name_, self.width, self.height)
                CAPTURE_UP.labels(self.name_).set(1)
                backoff = self.backoff_initial  # успешное подключение — сброс бэкоффа
                t_last_frame = time.monotonic()
                fps_ema = None

                # Основной цикл чтения
                while not self._stop.is_set():
                    ok, frame = cap.read()
                    now = time.monotonic()

                    if not ok or frame is None:
                        raise RuntimeError("read() failed or empty frame")

                    # Ограничение FPS (sleep если нужно)
                    if self.fps_limit:
                        dt = now - t_last_frame
                        min_dt = 1.0 / float(self.fps_limit)
                        if dt < min_dt:
                            time.sleep(min_dt - dt)
                            now = time.monotonic()

                    t_last_frame = now
                    frame_count += 1

                    # FPS EMA
                    if fps_ema is None:
                        fps_ema = 0.0
                    else:
                        dt = max(now - last_emit, 1e-6)
                        fps_inst = 1.0 / max(now - t_last_frame, 1e-3)
                        fps_ema = 0.9 * fps_ema + 0.1 * fps_inst

                    # Кладём в очередь (timestamp, frame)
                    try:
                        self.q.put_nowait((now, frame))
                        CAPTURE_QUEUE.labels(self.name_).set(self.q.qsize())
                    except queue.Full:
                        CAPTURE_ERRORS.labels(self.name_, "queue_full").inc()
                        # выкидываем самый старый кадр из очереди (backpressure)
                        try:
                            self.q.get_nowait()
                            self.q.put_nowait((now, frame))
                        except Exception:
                            pass

                    # Обновляем метрику FPS раз в ~1 сек
                    if now - last_emit > 1.0:
                        if fps_ema is not None:
                            CAPTURE_FPS.labels(self.name_).set(clamp(fps_ema, 0.0, 120.0))
                        last_emit = now

            except Exception as e:
                CAPTURE_UP.labels(self.name_).set(0)
                CAPTURE_ERRORS.labels(self.name_, "capture_error").inc()
                LOG.warning("Capture error for %s: %s", self.name_, e)
                restarts += 1
                CAPTURE_RESTARTS.labels(self.name_).inc()
                if self.max_restarts and restarts >= self.max_restarts:
                    LOG.error("Max restarts reached for %s; stopping", self.name_)
                    break
                time.sleep(backoff)
                backoff = min(self.backoff_max, backoff * 2.0)
            finally:
                try:
                    if cap is not None:
                        cap.release()
                except Exception:
                    pass

        CAPTURE_UP.labels(self.name_).set(0)
        LOG.info("Capture thread stopped for %s", self.name_)

# =========================
# Детектор движения и запись
# =========================
class MotionAndRecorder:
    def __init__(
        self,
        name: str,
        out_dir: Path,
        *,
        snapshot_interval_sec: float = 10.0,
        motion_threshold: float = 0.02,  # доля пикселей (0..1)
        pre_seconds: float = 3.0,
        post_seconds: float = 5.0,
        ring_seconds: float = 8.0,
        jpeg_quality: int = 90,
        mp4_fps: int = 15,
        mp4_width: Optional[int] = None,
        mp4_height: Optional[int] = None,
    ):
        self.name = name
        self.out_dir = out_dir
        self.snapshot_interval = snapshot_interval_sec
        self.motion_threshold = motion_threshold
        self.pre_seconds = pre_seconds
        self.post_seconds = post_seconds
        self.jpeg_quality = int(jpeg_quality)
        self.mp4_fps = int(mp4_fps)
        self.mp4_width = mp4_width
        self.mp4_height = mp4_height

        self.bg = cv2.createBackgroundSubtractorMOG2(history=500, varThreshold=16, detectShadows=False)
        self.last_snapshot_ts = 0.0
        self.trigger_active_until = 0.0

        # кольцевой буфер: (t_monotonic, frame)
        self.ring: Deque[Tuple[float, any]] = deque(maxlen=max(1, int(ring_seconds * max(5, self.mp4_fps))))
        self.lock = threading.RLock()

        # воркер записи
        self.write_pool = threading.Thread(target=self._writer_loop, daemon=True)
        self.write_q: queue.Queue[Tuple[str, dict]] = queue.Queue(maxsize=256)
        self._stop = threading.Event()
        self.write_pool.start()

    def stop(self):
        self._stop.set()
        try:
            self.write_q.put_nowait(("__stop__", {}))
        except Exception:
            pass
        self.write_pool.join(timeout=3.0)

    def _writer_loop(self):
        while not self._stop.is_set():
            try:
                kind, payload = self.write_q.get(timeout=0.5)
            except queue.Empty:
                continue
            if kind == "__stop__":
                break
            try:
                if kind == "jpeg":
                    self._save_jpeg(**payload)
                elif kind == "mp4":
                    self._save_mp4(**payload)
            except Exception as e:
                LOG.warning("writer error: %s", e)

    def _dst_paths(self, suffix: str) -> Tuple[Path, Path]:
        now = utc_now()
        root = self.out_dir / self.name / now.strftime("%Y-%m-%d")
        ensure_dir(root)
        base = f"{ts_str(now)}_{self.name}.{suffix}"
        meta = f"{ts_str(now)}_{self.name}.json"
        return root / base, root / meta

    def _save_jpeg(self, frame, reason: str):
        t0 = time.perf_counter()
        p_img, p_meta = self._dst_paths("jpg")
        ok, buf = cv2.imencode(".jpg", frame, [int(cv2.IMWRITE_JPEG_QUALITY), self.jpeg_quality])
        if not ok:
            return
        p_img.write_bytes(buf.tobytes())
        IO_BYTES.labels(self.name, "jpeg").inc(len(buf))
        SNAPSHOTS.labels(self.name, reason).inc()
        meta = {"kind": "snapshot", "name": self.name, "reason": reason, "time": utc_now().isoformat(), "file": str(p_img.name)}
        p_meta.write_text(json.dumps(meta, ensure_ascii=False))
        WRITE_LAT.labels(self.name, "jpeg").observe(max(0.0, time.perf_counter() - t0))

    def _save_mp4(self, frames, reason: str, size: Tuple[int, int], fps: int):
        t0 = time.perf_counter()
        p_vid, p_meta = self._dst_paths("mp4")
        w, h = size
        # fourcc 'mp4v' (без аппаратных кодеков). Для h264 используйте 'avc1' при наличии.
        fourcc = cv2.VideoWriter_fourcc(*"mp4v")
        vw = cv2.VideoWriter(str(p_vid), fourcc, fps, (w, h))
        bytes_count = 0
        try:
            for f in frames:
                vw.write(f)
                bytes_count += f.nbytes if hasattr(f, "nbytes") else 0
        finally:
            vw.release()
        IO_BYTES.labels(self.name, "mp4").inc(bytes_count)
        SEGMENTS.labels(self.name, reason).inc()
        meta = {
            "kind": "segment",
            "name": self.name,
            "reason": reason,
            "time": utc_now().isoformat(),
            "file": str(p_vid.name),
            "frames": len(frames),
            "fps": fps,
            "size": {"w": w, "h": h},
        }
        p_meta.write_text(json.dumps(meta, ensure_ascii=False))
        WRITE_LAT.labels(self.name, "mp4").observe(max(0.0, time.perf_counter() - t0))

    # ---- публичные методы ----
    def on_frame(self, t_mono: float, frame) -> None:
        # Обновляем кольцевой буфер
        with self.lock:
            self.ring.append((t_mono, frame.copy()))

        # Снимок по интервалу
        if t_mono - self.last_snapshot_ts > self.snapshot_interval:
            self.last_snapshot_ts = t_mono
            self._enqueue_jpeg(frame, "interval")

        # Оценка движения
        m = self._motion_score(frame)
        MOTION_SCORE.labels(self.name).set(m)
        if m >= self.motion_threshold:
            # триггер сегмента
            self.trigger_active_until = max(self.trigger_active_until, t_mono + self.post_seconds)
            self._enqueue_jpeg(frame, "motion")

        # Если триггер активен и только что истек — собираем сегмент
        if self.trigger_active_until and t_mono >= self.trigger_active_until:
            self._emit_segment(reason="motion", fps=self.mp4_fps)
            self.trigger_active_until = 0.0

    def flush(self):
        # По запросу можно дослать сегмент из буфера
        if self.trigger_active_until:
            self._emit_segment(reason="flush", fps=self.mp4_fps)
            self.trigger_active_until = 0.0

    # ---- внутренние ----
    def _motion_score(self, frame) -> float:
        try:
            gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        except Exception:
            gray = frame
        fg = self.bg.apply(gray)
        # бинаризация
        _, th = cv2.threshold(fg, 32, 255, cv2.THRESH_BINARY)
        nonzero = float(cv2.countNonZero(th))
        score = nonzero / float(th.size)
        return clamp(score, 0.0, 1.0)

    def _enqueue_jpeg(self, frame, reason: str):
        try:
            self.write_q.put_nowait(("jpeg", {"frame": frame.copy(), "reason": reason}))
        except queue.Full:
            pass

    def _emit_segment(self, reason: str, fps: int):
        # Собираем кадры из кольцевого буфера за pre_seconds + post_seconds
        with self.lock:
            if not self.ring:
                return
            t_end = self.ring[-1][0]
            t_start = t_end - (self.pre_seconds + self.post_seconds)
            frames = [f for (t_m, f) in list(self.ring) if t_m >= t_start]
            if not frames:
                return

        # Масштабирование при необходимости
        if self.mp4_width and self.mp4_height:
            frames = [cv2.resize(f, (self.mp4_width, self.mp4_height)) for f in frames]
            size = (self.mp4_width, self.mp4_height)
        else:
            h, w = frames[0].shape[:2]
            size = (w, h)

        try:
            self.write_q.put_nowait(("mp4", {"frames": frames, "reason": reason, "size": size, "fps": fps}))
        except queue.Full:
            pass

# =========================
# Главный скрипт
# =========================
def parse_args(argv=None):
    p = argparse.ArgumentParser(description="RTSP capture demo with motion and Prometheus")
    p.add_argument("--rtsp", required=True, help="RTSP URL (rtsp://user:pass@host/...)")
    p.add_argument("--name", default="cam01", help="Camera name for files/metrics")
    p.add_argument("--out", default="./captures", help="Output directory for images/videos")
    p.add_argument("--transport", choices=["tcp", "udp"], default=os.getenv("RTSP_TRANSPORT", "tcp"), help="RTSP interleaved transport")
    p.add_argument("--width", type=int, default=None, help="Requested frame width")
    p.add_argument("--height", type=int, default=None, help="Requested frame height")
    p.add_argument("--fps-limit", type=float, default=None, help="Limit decoding FPS (software throttling)")
    p.add_argument("--max-queue", type=int, default=100, help="Max frames in queue (backpressure)")
    p.add_argument("--snapshot-interval", type=float, default=10.0, help="Seconds between periodic snapshots")
    p.add_argument("--motion-threshold", type=float, default=0.02, help="Fraction of pixels considered motion (0..1)")
    p.add_argument("--pre-sec", type=float, default=3.0, help="Seconds before trigger in MP4 segment")
    p.add_argument("--post-sec", type=float, default=5.0, help="Seconds after trigger in MP4 segment")
    p.add_argument("--ring-sec", type=float, default=8.0, help="Ring buffer length (seconds)")
    p.add_argument("--jpeg-quality", type=int, default=90, help="JPEG quality (1..100)")
    p.add_argument("--mp4-fps", type=int, default=15, help="MP4 output FPS")
    p.add_argument("--mp4-size", default=None, help="Force MP4 WxH, e.g. 1280x720")
    p.add_argument("--metrics-port", type=int, default=int(os.getenv("METRICS_PORT", "9105")), help="Prometheus metrics port (0=disabled)")
    p.add_argument("--log-level", default=os.getenv("LOG_LEVEL", "INFO"))
    return p.parse_args(argv)

def main(argv=None):
    args = parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, str(args.log_level).upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    # Размер MP4
    mp4_w = mp4_h = None
    if args.mp4_size:
        try:
            mp4_w, mp4_h = [int(x) for x in str(args.mp4_size).lower().split("x", 1)]
        except Exception:
            LOG.warning("Invalid --mp4-size value, ignoring")

    out_dir = Path(args.out)
    ensure_dir(out_dir / args.name)

    # Метрики
    if _HAS_PROM and args.metrics_port:
        try:
            start_http_server(args.metrics_port)
            LOG.info("Metrics on :%d/metrics", args.metrics_port)
        except Exception as e:
            LOG.warning("metrics server failed: %s", e)

    # Очередь и потоки
    q_frames: queue.Queue[Tuple[float, any]] = queue.Queue(maxsize=max(1, args.max_queue))
    capt = RTSPCapture(
        args.name, args.rtsp, q_frames,
        transport=args.transport, width=args.width, height=args.height, fps_limit=args.fps_limit
    )
    rec = MotionAndRecorder(
        args.name, out_dir,
        snapshot_interval_sec=args.snapshot_interval,
        motion_threshold=float(args.motion_threshold),
        pre_seconds=args.pre_sec, post_seconds=args.post_sec, ring_seconds=args.ring_sec,
        jpeg_quality=args.jpeg_quality, mp4_fps=args.mp4_fps, mp4_width=mp4_w, mp4_height=mp4_h
    )

    stop = threading.Event()

    def _on_signal(signum, frame):
        LOG.info("Signal %s received, stopping...", signum)
        stop.set()

    for s in (signal.SIGINT, signal.SIGTERM):
        try: signal.signal(s, _on_signal)
        except Exception: pass

    capt.start()
    LOG.info("Capture started; processing loop... (press Ctrl+C to stop)")

    last_proc_ts = time.monotonic()
    try:
        while not stop.is_set():
            try:
                t_mono, frame = q_frames.get(timeout=0.5)
            except queue.Empty:
                continue
            # Обработка кадра
            rec.on_frame(t_mono, frame)
            last_proc_ts = t_mono
    except KeyboardInterrupt:
        stop.set()
    finally:
        LOG.info("Flushing and shutting down...")
        try:
            rec.flush()
        except Exception:
            pass
        try:
            capt.stop()
        except Exception:
            pass
        try:
            rec.stop()
        except Exception:
            pass
        capt.join(timeout=5.0)
        LOG.info("Stopped")

if __name__ == "__main__":
    main()
