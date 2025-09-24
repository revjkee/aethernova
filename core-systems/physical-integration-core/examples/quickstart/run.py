# -*- coding: utf-8 -*-
"""
Quickstart runner for physical-integration-core.

Сценарии:
  1) veilmind-demo  — демонстрация подключения VeilMindAdapter, отправка тестовых кадров, обработка входящих.
  2) video-worker   — запуск промышленного VideoSegmentWorker (очередь inbox -> processing -> done/failed).
  3) enqueue-task   — постановка задач сегментации (RTSP/файл) в файловую очередь.

Зависимости: стандартная библиотека Python 3.10+ и установленный ffmpeg/ffprobe в PATH.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import shutil
import signal
import sys
import time
from pathlib import Path
from typing import Any, Dict, Optional

# -------------------------------------------------
# Настройка sys.path для импорта project-пакета
# -------------------------------------------------

def _ensure_project_path() -> None:
    """
    Добавляет корень проекта physical-integration-core в sys.path.
    Этот файл расположен в: <repo>/examples/quickstart/run.py
    Путь к пакету:          <repo>/physical_integration/...
    """
    here = Path(__file__).resolve()
    repo_root = here.parents[2]  # .../physical-integration-core
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))

_ensure_project_path()

# Импорты из пакета (без внешних зависимостей)
from physical_integration.adapters.veilmind_adapter import (  # type: ignore
    VeilMindAdapter,
    VeilMindConfig,
)
from physical_integration.workers.video_segment_worker import (  # type: ignore
    WorkerConfig,
    VideoSegmentWorker,
    VideoTask,
    SegmenterKind,
    TaskProfile,
    HlsOpts,
    FileSegmentOpts,
)

# -------------------------------------------------
# Общие утилиты: логи, окружение, сигналы
# -------------------------------------------------

def setup_logging(level: str = "INFO") -> None:
    """
    Структурные JSON-логи в stdout.
    """
    class JsonFormatter(logging.Formatter):
        def format(self, record: logging.LogRecord) -> str:
            base = {
                "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(getattr(record, "created", time.time()))),
                "level": record.levelname,
                "logger": record.name,
                "msg": record.getMessage(),
            }
            # Включаем экстра-поля при наличии
            if hasattr(record, "extra") and isinstance(record.extra, dict):
                base.update(record.extra)
            return json.dumps(base, ensure_ascii=False)

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(getattr(logging, level.upper(), logging.INFO))


class GracefulExit(Exception):
    pass


def install_signal_handlers(loop: asyncio.AbstractEventLoop) -> None:
    """
    Устанавливает обработчики SIGINT/SIGTERM для корректного завершения.
    """
    def _handler(sig):
        logging.getLogger("quickstart").warning(json.dumps({"event": "signal", "sig": sig.name}))
        for task in asyncio.all_tasks(loop):
            if task is not asyncio.current_task(loop=loop):
                task.cancel()

    try:
        loop.add_signal_handler(signal.SIGINT, lambda: _handler(signal.SIGINT))
        loop.add_signal_handler(signal.SIGTERM, lambda: _handler(signal.SIGTERM))
    except NotImplementedError:
        # Windows / embedded окружения могут не поддерживать
        pass


def require_binary(name: str) -> None:
    """
    Проверяет наличие бинаря в PATH.
    """
    if shutil.which(name) is None:
        raise RuntimeError(f"Required binary '{name}' not found in PATH")


# -------------------------------------------------
# Команда: veilmind-demo
# -------------------------------------------------

async def run_veilmind_demo(args: argparse.Namespace) -> None:
    """
    Подключается к VeilMind шине/устройству, шлёт тестовые кадры, логирует входящие.
    """
    logger = logging.getLogger("quickstart.veilmind")
    cfg = VeilMindConfig(
        host=args.host,
        port=args.port,
        device_id=args.device_id,
        secret_key=args.secret_key,
        use_tls=not args.no_tls,
        ca_file=args.ca_file,
        client_cert=args.client_cert,
        client_key=args.client_key,
        allow_insecure=args.allow_insecure,
        environment=args.environment,
    )

    stop_event = asyncio.Event()

    async def on_message(payload: Dict[str, Any]) -> None:
        logger.info(json.dumps({"event": "incoming", "payload": payload}))

    async def on_status(state: str) -> None:
        logger.info(json.dumps({"event": "state", "state": state}))

    adapter = VeilMindAdapter(cfg, on_message=on_message, on_status=on_status, logger=logging.getLogger("veilmind"))

    async def sender_task() -> None:
        """
        Периодически посылает тестовые кадры.
        """
        seq = 0
        try:
            while not stop_event.is_set():
                payload = {
                    "op": "telemetry",
                    "sensor": "quickstart",
                    "seq": seq,
                    "timestamp": int(time.time() * 1000),
                }
                await adapter.send(payload)
                seq += 1
                await asyncio.sleep(args.send_interval)
        except asyncio.CancelledError:
            return

    await adapter.start()
    task = asyncio.create_task(sender_task(), name="demo-sender")

    try:
        # Живём до сигналов
        while True:
            await asyncio.sleep(3600)
    except asyncio.CancelledError:
        stop_event.set()
        task.cancel()
        with _suppress(asyncio.CancelledError):
            await task
        await adapter.stop()


# -------------------------------------------------
# Команда: video-worker
# -------------------------------------------------

async def run_video_worker(args: argparse.Namespace) -> None:
    """
    Запуск промышленного воркера сегментации видео.
    """
    # Проверяем наличие ffmpeg/ffprobe
    require_binary(os.getenv("FFMPEG_BIN", "ffmpeg"))
    require_binary(os.getenv("FFPROBE_BIN", "ffprobe"))

    cfg = WorkerConfig(
        queue_dir=Path(args.queue_dir).resolve(),
        output_dir=Path(args.output_dir).resolve(),
        concurrency=args.concurrency,
        max_retries=args.max_retries,
    )
    worker = VideoSegmentWorker(cfg, logger=logging.getLogger("video_worker"))

    loop = asyncio.get_running_loop()
    stop = asyncio.Event()

    def _stopper():
        logging.getLogger("quickstart").warning(json.dumps({"event": "signal", "target": "video-worker"}))
        stop.set()

    try:
        loop.add_signal_handler(signal.SIGINT, _stopper)
        loop.add_signal_handler(signal.SIGTERM, _stopper)
    except NotImplementedError:
        pass

    runner = asyncio.create_task(worker.run(), name="video-worker-main")
    await stop.wait()
    # worker.run() сам корректно завершится по сигналу; дожидаемся
    runner.cancel()
    with _suppress(asyncio.CancelledError):
        await runner


# -------------------------------------------------
# Команда: enqueue-task
# -------------------------------------------------

def enqueue_task(args: argparse.Namespace) -> None:
    """
    Создаёт JSON‑задачу в очереди inbox/ для обработки видео воркером.
    """
    queue_root = Path(args.queue_dir).resolve()
    inbox = queue_root / "inbox"
    inbox.mkdir(parents=True, exist_ok=True)

    # Формируем профиль и опции
    profile = TaskProfile(
        vcodec=args.vcodec,
        acodec=args.acodec,
        bitrate=args.bitrate,
        width=args.width,
        height=args.height,
        fps=args.fps,
        gop=args.gop,
        threads=args.threads,
        preset=args.preset,
        movflags=args.movflags,
    )
    hls = HlsOpts(
        playlist_name=args.playlist_name,
        flags=args.hls_flags,
    )
    fs = FileSegmentOpts(
        pattern=args.pattern,
        format=args.file_format,
    )

    task = VideoTask(
        task_id=args.task_id or f"vtask-{int(time.time()*1000)}",
        source=args.source,
        segmenter=SegmenterKind(args.segmenter),
        segment_time=args.segment_time,
        duration=args.duration,
        start_time=args.start_time,
        profile=profile,
        filters=args.filters,
        hls=hls,
        file_segment=fs,
        output_root=args.output_root,
        attempts=0,
    )
    path = inbox / f"{task.task_id}.json"
    path.write_text(json.dumps(task.to_json(), ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    logging.getLogger("quickstart").info(json.dumps({"event": "enqueue", "path": str(path), "task_id": task.task_id}))


# -------------------------------------------------
# CLI
# -------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="physical-integration-core quickstart runner")
    p.add_argument("--log-level", default=os.getenv("LOG_LEVEL", "INFO"), help="Logging level (DEBUG|INFO|WARNING|ERROR)")

    sub = p.add_subparsers(dest="cmd", required=True)

    # veilmind-demo
    d = sub.add_parser("veilmind-demo", help="Run VeilMind adapter demo (send/receive frames)")
    d.add_argument("--host", default=os.getenv("VM_HOST", "127.0.0.1"))
    d.add_argument("--port", type=int, default=int(os.getenv("VM_PORT", "7001")))
    d.add_argument("--device-id", default=os.getenv("VM_DEVICE_ID", "demo-device"))
    d.add_argument("--secret-key", default=os.getenv("VM_SECRET", "demo-secret"))
    d.add_argument("--no-tls", action="store_true", help="Disable TLS")
    d.add_argument("--ca-file", default=os.getenv("VM_CA_FILE") or None)
    d.add_argument("--client-cert", default=os.getenv("VM_CLIENT_CERT") or None)
    d.add_argument("--client-key", default=os.getenv("VM_CLIENT_KEY") or None)
    d.add_argument("--allow-insecure", action="store_true", help="Disable TLS verification (DEBUG)")
    d.add_argument("--environment", default=os.getenv("ENVIRONMENT", "dev"))
    d.add_argument("--send-interval", type=float, default=float(os.getenv("VM_SEND_INTERVAL", "2.0")))
    d.set_defaults(func_async=run_veilmind_demo)

    # video-worker
    w = sub.add_parser("video-worker", help="Run video segment worker (FFmpeg)")
    w.add_argument("--queue-dir", default=os.getenv("VIDEO_QUEUE_DIR", "./queue"))
    w.add_argument("--output-dir", default=os.getenv("VIDEO_OUTPUT_DIR", "./output"))
    w.add_argument("--concurrency", type=int, default=int(os.getenv("VIDEO_WORKER_CONCURRENCY", "2")))
    w.add_argument("--max-retries", type=int, default=int(os.getenv("VIDEO_MAX_RETRIES", "5")))
    w.set_defaults(func_async=run_video_worker)

    # enqueue-task
    e = sub.add_parser("enqueue-task", help="Enqueue a segmentation task into file queue")
    e.add_argument("--queue-dir", default=os.getenv("VIDEO_QUEUE_DIR", "./queue"))
    e.add_argument("--task-id", default=None)
    e.add_argument("--source", required=True, help="RTSP/HTTP URL or local file path")
    e.add_argument("--segmenter", choices=[s.value for s in SegmenterKind], default="file")
    e.add_argument("--segment-time", type=int, default=6)
    e.add_argument("--duration", type=int, default=None)
    e.add_argument("--start-time", default=None)
    e.add_argument("--filters", default=None)
    e.add_argument("--output-root", default=None)
    # profile
    e.add_argument("--vcodec", default="libx264")
    e.add_argument("--acodec", default="aac")
    e.add_argument("--bitrate", default="2000k")
    e.add_argument("--width", type=int, default=None)
    e.add_argument("--height", type=int, default=None)
    e.add_argument("--fps", type=int, default=None)
    e.add_argument("--gop", type=int, default=None)
    e.add_argument("--threads", type=int, default=None)
    e.add_argument("--preset", default=None)
    e.add_argument("--movflags", default="+faststart")
    # hls
    e.add_argument("--playlist-name", default="index.m3u8")
    e.add_argument("--hls-flags", default="independent_segments+delete_segments+program_date_time")
    # file segment
    e.add_argument("--pattern", default="seg_%Y%m%d_%H%M%S_%06d.mp4")
    e.add_argument("--file-format", choices=["mp4", "mpegts"], default="mp4")
    e.set_defaults(func_sync=enqueue_task)

    return p


# -------------------------------------------------
# Main
# -------------------------------------------------

class _suppress:
    def __init__(self, *exc):
        self.exc = exc or (Exception,)
    def __enter__(self):
        return None
    def __exit__(self, et, ev, tb):
        return et is not None and issubclass(et, self.exc)

def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    setup_logging(args.log_level)

    # Выполнение сабкоманд
    if hasattr(args, "func_sync"):
        # Синхронная команда (enqueue-task)
        try:
            args.func_sync(args)  # type: ignore
        except Exception as e:
            logging.getLogger("quickstart").error(json.dumps({"event": "error", "error": str(e)}))
            sys.exit(1)
        return

    if hasattr(args, "func_async"):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        install_signal_handlers(loop)
        try:
            loop.run_until_complete(args.func_async(args))  # type: ignore
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logging.getLogger("quickstart").error(json.dumps({"event": "error", "error": str(e)}))
            sys.exit(2)
        finally:
            with _suppress(Exception):
                pending = [t for t in asyncio.all_tasks(loop) if not t.done()]
                for t in pending:
                    t.cancel()
                if pending:
                    loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
            loop.run_until_complete(loop.shutdown_asyncgens())
            loop.close()
        return

    parser.print_help()
    sys.exit(0)


if __name__ == "__main__":
    main()
